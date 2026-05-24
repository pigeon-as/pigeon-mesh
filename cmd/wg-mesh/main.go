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

	"github.com/pigeon-as/wg-mesh/internal/mesh"
	"github.com/pigeon-as/wg-mesh/internal/sdnotify"
	"github.com/pigeon-as/wg-mesh/internal/wg"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	iface := flag.String("interface", "", "existing WireGuard interface (required)")
	endpoint := flag.String("endpoint", "", "this node's Endpoint as host:port (required)")
	address := flag.String("address", "", "this node's overlay IP (auto-detected from --interface if unset)")
	extraAllowedIPs := flag.String("extra-allowed-ips", "", "extra CIDRs to advertise alongside this node's host route, comma-separated")
	gossipPort := flag.Int("gossip-port", 7946, "port to listen on for gossip (TCP and UDP)")
	gossipKeyFile := flag.String("gossip-key-file", "", "JSON file of base64-encoded gossip encryption keys")
	persistentKeepalive := flag.Int("persistent-keepalive", 0, "PersistentKeepalive interval in seconds advertised to peers (0 disables)")
	flag.Parse()

	if *iface == "" || *endpoint == "" {
		slog.Error("missing required flag", "need", "--interface --endpoint")
		os.Exit(2)
	}
	if *persistentKeepalive < 0 || *persistentKeepalive > 65535 {
		slog.Error("persistent-keepalive out of range", "got", *persistentKeepalive, "range", "0-65535")
		os.Exit(2)
	}

	ip, err := resolveAddress(*address, *iface)
	if err != nil {
		slog.Error("resolve address", "err", err)
		os.Exit(1)
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

	ep, err := mesh.NormalizeEndpoint(*endpoint)
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
	m.Run(ctx)
	slog.Info("wg-mesh stopped")
}

func resolveAddress(override, iface string) (net.IP, error) {
	if override == "" {
		return mesh.InterfaceAddress(iface)
	}
	ip := net.ParseIP(override)
	if ip == nil {
		return nil, fmt.Errorf("invalid --address %q", override)
	}
	return ip, nil
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
