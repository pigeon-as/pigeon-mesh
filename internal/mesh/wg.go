package mesh

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	addr "github.com/pigeon-as/pigeon-addr-plan"
	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/hkdf"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LoadOrGenerateKey loads a WireGuard private key from dataDir/privkey,
// or generates a new one and persists it. If dataDir is empty, a fresh
// keypair is generated without persistence.
func LoadOrGenerateKey(dataDir string) (wgtypes.Key, wgtypes.Key, error) {
	if dataDir == "" {
		priv, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("generate key: %w", err)
		}
		return priv, priv.PublicKey(), nil
	}
	keyPath := filepath.Join(dataDir, "privkey")

	data, err := os.ReadFile(keyPath)
	if err == nil {
		if fi, serr := os.Stat(keyPath); serr == nil && fi.Mode().Perm()&0077 != 0 {
			slog.Warn("key file has loose permissions", "path", keyPath, "mode", fmt.Sprintf("%04o", fi.Mode().Perm()))
		}
		key, err := wgtypes.ParseKey(strings.TrimSpace(string(data)))
		if err != nil {
			return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("parse stored key: %w", err)
		}
		return key, key.PublicKey(), nil
	}
	if !os.IsNotExist(err) {
		return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("read key file: %w", err)
	}

	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("generate key: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("create data dir: %w", err)
	}
	if err := atomicWriteFile(keyPath, []byte(priv.String()+"\n"), 0600); err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("save key: %w", err)
	}
	return priv, priv.PublicKey(), nil
}

// atomicWriteFile writes data to path via a temp file + rename.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// OverlayAddr computes the WireGuard overlay address from a hostname.
// Returns the app-view address fdaa:0:0:HHHH:HHHH::1/128. nftables on wg0
// transposes to wire-view for WireGuard cryptokey routing.
func OverlayAddr(hostname string) (string, error) {
	host, err := addr.HashPrefix(addr.PigeonULARange(), addr.NetworkBits, hostname)
	if err != nil {
		return "", fmt.Errorf("hash host prefix: %w", err)
	}
	ip, err := addr.HostAddr(host, 1)
	if err != nil {
		return "", fmt.Errorf("host addr: %w", err)
	}
	ip, ok := addr.TransposePigeonULA(ip)
	if !ok {
		return "", fmt.Errorf("transpose %s: not a pigeon ULA address", ip)
	}
	return netip.PrefixFrom(ip, 128).String(), nil
}

// SetupInterface creates and configures the WireGuard interface.
// If the interface already exists, it reconfigures it.
func SetupInterface(iface string, privKey wgtypes.Key, overlayAddr string, listenPort int) error {
	// Create interface if it doesn't exist.
	link, err := netlink.LinkByName(iface)
	if err != nil {
		wg := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: iface}}
		if err := netlink.LinkAdd(wg); err != nil {
			return fmt.Errorf("create interface: %w", err)
		}
		link, err = netlink.LinkByName(iface)
		if err != nil {
			return fmt.Errorf("find new interface: %w", err)
		}
	}

	// Configure WireGuard via wgctrl netlink.
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl client: %w", err)
	}
	defer client.Close()

	if err := client.ConfigureDevice(iface, wgtypes.Config{
		PrivateKey: &privKey,
		ListenPort: &listenPort,
	}); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}

	// Flush existing addresses.
	addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
	for i := range addrs {
		netlink.AddrDel(link, &addrs[i])
	}

	// Add overlay address.
	nlAddr, err := netlink.ParseAddr(overlayAddr)
	if err != nil {
		return fmt.Errorf("parse overlay addr: %w", err)
	}
	if err := netlink.AddrAdd(link, nlAddr); err != nil {
		return fmt.Errorf("add address: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up: %w", err)
	}

	// Catch-all route for app-view pigeon traffic. More-specific routes
	// (bridge /80s from pigeon-cni) take precedence for local VMs.
	_, dst, _ := net.ParseCIDR("fdaa::/16")
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
	}); err != nil {
		return fmt.Errorf("add mesh route: %w", err)
	}

	return nil
}

// DerivePairPSK derives a per-pair WireGuard PresharedKey from the fleet PSK
// and both peers' public keys using HKDF-SHA256 with domain separation.
// Keys are sorted as raw 32-byte values; the fleet secret never enters the kernel.
func DerivePairPSK(fleetPSK wgtypes.Key, localPub, remotePub wgtypes.Key) (wgtypes.Key, error) {
	a, b := localPub[:], remotePub[:]
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	salt := make([]byte, 0, 64)
	salt = append(salt, a...)
	salt = append(salt, b...)

	r := hkdf.New(sha256.New, fleetPSK[:], salt, []byte("pigeon-mesh wireguard pairwise psk v1"))
	var key wgtypes.Key
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return wgtypes.Key{}, fmt.Errorf("hkdf read: %w", err)
	}
	return key, nil
}

// ReconcilePeers sets WireGuard peers to match the given list, removing stale ones.
// If fleetPSK is non-nil, a per-pair PSK is derived via HKDF for each tunnel.
func ReconcilePeers(iface string, peers []Node, localPub wgtypes.Key, fleetPSK *wgtypes.Key) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl client: %w", err)
	}
	defer client.Close()

	desired := make(map[wgtypes.Key]struct{}, len(peers))
	keepalive := 25 * time.Second

	var peerConfigs []wgtypes.PeerConfig
	for _, p := range peers {
		pubKey, err := wgtypes.ParseKey(p.PubKey)
		if err != nil {
			return fmt.Errorf("parse peer key %s: %w", p.Name, err)
		}
		desired[pubKey] = struct{}{}

		// The peer's /48 in wire-view covers overlay + all VM traffic.
		route, err := peerRoute(p.Name)
		if err != nil {
			return fmt.Errorf("peer route %s: %w", p.Name, err)
		}
		_, routeNet, err := net.ParseCIDR(route)
		if err != nil {
			return fmt.Errorf("parse peer route %s: %w", p.Name, err)
		}
		allowedIPs := []net.IPNet{*routeNet}

		port := p.WgPort
		if port == 0 {
			port = 51820
		}
		endpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", p.Endpoint, port))
		if err != nil {
			return fmt.Errorf("resolve endpoint %s: %w", p.Name, err)
		}

		var psk *wgtypes.Key
		if fleetPSK != nil {
			k, err := DerivePairPSK(*fleetPSK, localPub, pubKey)
			if err != nil {
				return fmt.Errorf("derive psk for %s: %w", p.Name, err)
			}
			psk = &k
		}

		peerConfigs = append(peerConfigs, wgtypes.PeerConfig{
			PublicKey:                   pubKey,
			PresharedKey:                psk,
			Endpoint:                    endpoint,
			AllowedIPs:                  allowedIPs,
			PersistentKeepaliveInterval: &keepalive,
			ReplaceAllowedIPs:           true,
		})
	}

	// Get current peers to find stale ones.
	dev, err := client.Device(iface)
	if err != nil {
		return fmt.Errorf("get device: %w", err)
	}
	for _, existingPeer := range dev.Peers {
		if _, ok := desired[existingPeer.PublicKey]; !ok {
			peerConfigs = append(peerConfigs, wgtypes.PeerConfig{
				PublicKey: existingPeer.PublicKey,
				Remove:    true,
			})
		}
	}

	if err := client.ConfigureDevice(iface, wgtypes.Config{
		Peers: peerConfigs,
	}); err != nil {
		return fmt.Errorf("configure peers: %w", err)
	}

	return nil
}

// DetectEndpoint returns the first non-loopback, non-private IPv4 address.
func DetectEndpoint() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
			continue
		}
		if ipNet.IP.IsPrivate() {
			continue
		}
		return ipNet.IP.String(), nil
	}
	return "", fmt.Errorf("no public IPv4 address found")
}

// peerRoute derives the host route (AllowedIPs) for a peer.
// Returns fdaa:HHHH:HHHH::/48 — the full host prefix for WireGuard routing.
func peerRoute(name string) (string, error) {
	host, err := addr.HashPrefix(addr.PigeonULARange(), addr.NetworkBits, name)
	if err != nil {
		return "", fmt.Errorf("hash host prefix for %s: %w", name, err)
	}
	return host.String(), nil
}
