//go:build linux

package mesh

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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

const (
	defaultWgPort = 51820
	keepalive     = 25 * time.Second
	hkdfPSKInfo   = "pigeon-mesh wireguard pairwise psk v1"
)

// LoadOrGenerateKey loads a WireGuard private key from dataDir/privkey,
// or generates a new one if not found. If dataDir is empty, generates
// an ephemeral key (not persisted).
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

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pigeon-mesh-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// SetupInterface creates (or reconfigures) the WireGuard interface.
func SetupInterface(iface string, privKey wgtypes.Key, overlayAddr string, listenPort int) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return fmt.Errorf("lookup interface: %w", err)
		}
		wg := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: iface}}
		if err := netlink.LinkAdd(wg); err != nil {
			return fmt.Errorf("create interface: %w", err)
		}
		link, err = netlink.LinkByName(iface)
		if err != nil {
			return fmt.Errorf("find new interface: %w", err)
		}
	}

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

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	for i := range addrs {
		if err := netlink.AddrDel(link, &addrs[i]); err != nil {
			return fmt.Errorf("delete address %s: %w", addrs[i].IP, err)
		}
	}

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

	meshPrefix := addr.PigeonULARange()
	dst := &net.IPNet{
		IP:   meshPrefix.Addr().AsSlice(),
		Mask: net.CIDRMask(meshPrefix.Bits(), 128),
	}
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
	}); err != nil {
		return fmt.Errorf("add mesh route: %w", err)
	}

	return nil
}

// DerivePairPSK derives a per-pair PresharedKey from the fleet PSK and both
// peers' public keys via HKDF-SHA256.
func DerivePairPSK(fleetPSK wgtypes.Key, localPub, remotePub wgtypes.Key) (wgtypes.Key, error) {
	a, b := localPub[:], remotePub[:]
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	salt := make([]byte, 0, 64)
	salt = append(salt, a...)
	salt = append(salt, b...)

	r := hkdf.New(sha256.New, fleetPSK[:], salt, []byte(hkdfPSKInfo))
	var key wgtypes.Key
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return wgtypes.Key{}, fmt.Errorf("hkdf read: %w", err)
	}
	return key, nil
}

// ReconcilePeers sets WireGuard peers to match the given list, removing stale ones.
func ReconcilePeers(iface string, peers []Node, localPub wgtypes.Key, fleetPSK *wgtypes.Key) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl client: %w", err)
	}
	defer client.Close()

	desired := make(map[wgtypes.Key]struct{}, len(peers))

	var peerConfigs []wgtypes.PeerConfig
	for _, p := range peers {
		pubKey, err := wgtypes.ParseKey(p.PubKey)
		if err != nil {
			return fmt.Errorf("parse peer key %s: %w", p.Name, err)
		}
		desired[pubKey] = struct{}{}

		wirePrefix, err := addr.PigeonHostRoute(p.Name)
		if err != nil {
			return fmt.Errorf("peer route %s: %w", p.Name, err)
		}
		ones := wirePrefix.Bits()
		ipAddr := wirePrefix.Addr()
		ipBytes := ipAddr.As16()
		allowedIPs := []net.IPNet{{
			IP:   net.IP(ipBytes[:]),
			Mask: net.CIDRMask(ones, 128),
		}}

		port := p.WgPort
		if port == 0 {
			port = defaultWgPort
		}
		endpoint, err := net.ResolveUDPAddr("udp", net.JoinHostPort(p.Endpoint, fmt.Sprintf("%d", port)))
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

		ka := keepalive
		peerConfigs = append(peerConfigs, wgtypes.PeerConfig{
			PublicKey:                   pubKey,
			PresharedKey:                psk,
			Endpoint:                    endpoint,
			AllowedIPs:                  allowedIPs,
			PersistentKeepaliveInterval: &ka,
			ReplaceAllowedIPs:           true,
		})
	}

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

// resolveInterfaceIP returns the first IPv4 address on the named interface.
func resolveInterfaceIP(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", fmt.Errorf("interface %s: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("addresses for %s: %w", name, err)
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.To4() == nil {
			continue
		}
		return ipNet.IP.String(), nil
	}
	return "", fmt.Errorf("no IPv4 address on interface %s", name)
}

// resolveDefaultRouteIP returns the source IPv4 address the kernel would use
// for outbound traffic. Uses the standard net.Dial("udp4") trick — no packets
// are sent; the kernel just resolves the route.
func resolveDefaultRouteIP() (string, error) {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return "", fmt.Errorf("resolve default route: %w", err)
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return "", fmt.Errorf("parse local addr: %w", err)
	}
	return host, nil
}
