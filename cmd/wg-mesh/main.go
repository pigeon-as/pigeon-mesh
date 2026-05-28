//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"slices"
	"syscall"

	sockaddr "github.com/hashicorp/go-sockaddr/template"
	"github.com/pigeon-as/wg-mesh/internal/mesh"
	"github.com/pigeon-as/wg-mesh/internal/sdnotify"
	"github.com/pigeon-as/wg-mesh/internal/wg"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	iface := flag.String("interface", "", "existing WireGuard interface (required)")
	endpoint := flag.String("endpoint", "", "this node's Endpoint as host:port; hostnames resolved at startup; go-sockaddr templates evaluated (required)")
	address := flag.String("address", "", "this node's overlay IP; go-sockaddr templates evaluated; auto-detected from --interface if unset")
	extraAllowedIPs := flag.String("extra-allowed-ips", "", "extra CIDRs to advertise alongside this node's host route, comma-separated")
	gossipPort := flag.Int("gossip-port", 7946, "port to listen on for gossip (TCP and UDP)")
	gossipKeyFile := flag.String("gossip-key-file", "", "JSON file of base64-encoded gossip encryption keys")
	persistentKeepalive := flag.Int("persistent-keepalive", 0, "PersistentKeepalive interval in seconds advertised to peers (0 disables)")
	profile := flag.String("profile", "wan", "memberlist timing profile: lan, wan, or local")
	peerPolicy := flag.String("peer-policy", "", "expr predicate (returns bool) evaluated per peer at admission; false rejects. In scope: peer (Peer), peers() (other members), cidrContains(cidr, addr) bool. See docs/quickstart.md.")
	flag.Parse()

	if *iface == "" || *endpoint == "" {
		slog.Error("missing required flag", "need", "--interface --endpoint")
		os.Exit(2)
	}
	if *persistentKeepalive < 0 || *persistentKeepalive > 65535 {
		slog.Error("persistent-keepalive out of range", "got", *persistentKeepalive, "range", "0-65535")
		os.Exit(2)
	}

	endpointStr, err := sockaddr.Parse(*endpoint)
	if err != nil {
		slog.Error("endpoint template", "err", err)
		os.Exit(1)
	}
	var ip net.IP
	if *address == "" {
		ip, err = mesh.InterfaceAddress(*iface)
		if err != nil {
			slog.Error("address", "err", err)
			os.Exit(1)
		}
	} else {
		addressStr, err := sockaddr.Parse(*address)
		if err != nil {
			slog.Error("address template", "err", err)
			os.Exit(1)
		}
		ip = net.ParseIP(addressStr)
		if ip == nil {
			slog.Error("address", "err", fmt.Errorf("--address %q resolved to %q, not an IP", *address, addressStr))
			os.Exit(1)
		}
	}
	host := mesh.HostRoute(ip)
	allowed := []string{host.String()}
	if *extraAllowedIPs != "" {
		extras, err := mesh.ParseAllowedIPs(*extraAllowedIPs)
		if err != nil {
			slog.Error("extra-allowed-ips", "err", err)
			os.Exit(1)
		}
		for _, e := range extras {
			if !slices.Contains(allowed, e) {
				allowed = append(allowed, e)
			}
		}
	}

	wgc, err := wg.New()
	if err != nil {
		slog.Error("open wgctrl", "err", err)
		os.Exit(1)
	}
	defer wgc.Close()

	publicKey, err := wgc.PublicKey(*iface)
	if err != nil {
		slog.Error("wireguard device", "err", err)
		os.Exit(1)
	}

	ep, err := mesh.NormalizeEndpoint(endpointStr)
	if err != nil {
		slog.Error("endpoint", "err", err)
		os.Exit(1)
	}

	self := mesh.Peer{
		PublicKey:           publicKey.String(),
		Endpoint:            ep,
		AllowedIPs:          allowed,
		PersistentKeepalive: *persistentKeepalive,
	}

	cfg := mesh.Config{
		Iface:      *iface,
		GossipPort: *gossipPort,
		BindAddr:   ip.String(),
		Profile:    *profile,
		Self:       self,
		WG:         wgc,
	}
	if *gossipKeyFile != "" {
		cfg.Keyring, err = mesh.LoadKeyring(*gossipKeyFile)
		if err != nil {
			slog.Error("gossip key", "err", err)
			os.Exit(1)
		}
	}
	if *peerPolicy != "" {
		cfg.PeerPolicy, err = mesh.ParsePeerPolicy(*peerPolicy)
		if err != nil {
			slog.Error("peer-policy", "err", err)
			os.Exit(1)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	m, err := mesh.New(cfg)
	if err != nil {
		slog.Error("mesh", "err", err)
		os.Exit(1)
	}

	go sdnotify.Run(ctx)
	go reloadKeyringOnSIGHUP(ctx, m, *gossipKeyFile)

	slog.Info("wg-mesh up", "interface", *iface, "endpoint", ep, "address", ip.String())
	if err := m.Run(ctx); err != nil {
		slog.Error("wg-mesh stopped", "err", err)
		os.Exit(1)
	}
	slog.Info("wg-mesh stopped")
}

func reloadKeyringOnSIGHUP(ctx context.Context, m *mesh.Mesh, path string) {
	if path == "" {
		return
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	defer signal.Stop(sig)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sig:
			n, err := m.ReloadKeyringFromFile(path)
			if err != nil {
				slog.Error("keyring reload", "err", err)
				continue
			}
			slog.Info("keyring reloaded", "keys", n)
		}
	}
}
