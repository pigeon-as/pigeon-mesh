//go:build linux

package main

import (
	"context"
	"flag"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	sockaddr "github.com/hashicorp/go-sockaddr/template"
	"github.com/pigeon-as/pigeon-mesh/internal/mesh"
	"github.com/pigeon-as/pigeon-mesh/internal/sdnotify"
	"github.com/pigeon-as/pigeon-mesh/internal/wg"
)

const defaultDNSZone = "mesh.internal"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "status" {
		os.Exit(runStatus(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "leave" {
		os.Exit(runLeave(os.Args[2:]))
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	iface := flag.String("interface", "", "existing WireGuard interface (required); bootstrap peers need a /128 or /32 first in AllowedIPs")
	endpoint := flag.String("endpoint", "", "this node's Endpoint as host:port; hostnames resolved at startup; go-sockaddr templates evaluated (required)")
	address := flag.String("address", "", "this node's overlay IP; go-sockaddr templates evaluated; auto-detected from --interface if unset")
	advertiseRoutes := flag.String("advertise-routes", "", "extra routes this node advertises to peers beyond its own /128, comma-separated")
	gossipPort := flag.Int("gossip-port", 7946, "port to listen on for gossip (TCP and UDP)")
	gossipKeyFile := flag.String("gossip-key-file", "", "JSON file of base64-encoded gossip encryption keys")
	persistentKeepalive := flag.Int("persistent-keepalive", 0, "PersistentKeepalive interval in seconds advertised to peers (0 disables)")
	profile := flag.String("profile", "wan", "memberlist timing profile: lan, wan, or local")
	socket := flag.String("socket", mesh.DefaultSocketPath, "path to the status query socket served for the status command; empty disables")
	var dnsZone dnsZoneFlag
	flag.Var(&dnsZone, "dns", "serve AAAA records for peers' name= tag and program systemd-resolved split-DNS; bare --dns uses the "+defaultDNSZone+" zone, --dns=zone overrides; requires --prefix")
	prefix := flag.String("prefix", "", "optional byte-aligned IPv6 ULA prefix (e.g. fdcc::/16); when set, the daemon derives this node's overlay address from its key and assigns it to the interface, and requires every peer's address to be the same derivation of its key (self-certifying)")
	reconnectTimeout := flag.Duration("reconnect-timeout", 10*time.Minute, "grace window to keep a failed peer's tunnel before reaping it; survives restarts and brief partitions")
	var tagFlags []string
	flag.Func("tag", "tag for this node, repeatable as k=v", func(v string) error {
		tagFlags = append(tagFlags, v)
		return nil
	})
	flag.Parse()

	if flag.NArg() > 0 {
		slog.Error("unexpected arguments; set a custom DNS zone with --dns=zone (note the =)", "args", flag.Args())
		os.Exit(2)
	}
	if *iface == "" {
		slog.Error("missing required flag --interface")
		os.Exit(2)
	}
	if *endpoint == "" {
		slog.Error("missing required flag --endpoint")
		os.Exit(2)
	}
	if *persistentKeepalive < 0 || *persistentKeepalive > 65535 {
		slog.Error("persistent-keepalive out of range", "got", *persistentKeepalive, "range", "0-65535")
		os.Exit(2)
	}
	if dnsZone.zone != "" && *prefix == "" {
		slog.Error("--dns requires --prefix")
		os.Exit(2)
	}

	endpointStr, err := sockaddr.Parse(*endpoint)
	if err != nil {
		slog.Error("endpoint template", "err", err)
		os.Exit(1)
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

	var ip netip.Addr
	var overlayPrefix netip.Prefix
	switch {
	case *prefix != "":
		overlayPrefix, err = netip.ParsePrefix(*prefix)
		if err != nil {
			slog.Error("prefix", "err", err)
			os.Exit(2)
		}
		ip, err = mesh.DeriveAddr(publicKey.String(), overlayPrefix)
		if err != nil {
			slog.Error("prefix", "err", err)
			os.Exit(2)
		}
		if err = wgc.SetAddr(*iface, ip); err != nil {
			slog.Error("set address", "err", err)
			os.Exit(1)
		}
	case *address != "":
		addressStr, perr := sockaddr.Parse(*address)
		if perr != nil {
			slog.Error("address template", "err", perr)
			os.Exit(1)
		}
		ip, err = netip.ParseAddr(addressStr)
		if err != nil {
			slog.Error("address template resolved to non-IP", "address", *address, "resolved", addressStr, "err", err)
			os.Exit(1)
		}
	default:
		ip, err = mesh.InterfaceAddress(*iface)
		if err != nil {
			slog.Error("address", "err", err)
			os.Exit(1)
		}
	}

	host := mesh.HostRoute(ip)
	allowed := []string{host.String()}
	if *advertiseRoutes != "" {
		extras, err := mesh.ParseAllowedIPs(*advertiseRoutes)
		if err != nil {
			slog.Error("advertise-routes", "err", err)
			os.Exit(1)
		}
		for _, e := range extras {
			if !slices.Contains(allowed, e) {
				allowed = append(allowed, e)
			}
		}
	}

	ep, err := mesh.NormalizeEndpoint(endpointStr)
	if err != nil {
		slog.Error("endpoint", "err", err)
		os.Exit(1)
	}

	tags, err := mesh.ParseTags(tagFlags)
	if err != nil {
		slog.Error("tag", "err", err)
		os.Exit(2)
	}
	if _, ok := tags["name"]; !ok {
		if h, herr := os.Hostname(); herr == nil {
			if label := mesh.SanitizeLabel(h); label != "" {
				if tags == nil {
					tags = mesh.Tags{}
				}
				tags["name"] = label
			}
		}
	}

	self := mesh.Peer{
		PublicKey:           publicKey.String(),
		Endpoint:            ep,
		AllowedIPs:          allowed,
		PersistentKeepalive: *persistentKeepalive,
		Tags:                tags,
	}

	cfg := mesh.Config{
		Iface:            *iface,
		GossipPort:       *gossipPort,
		BindAddr:         ip.String(),
		Profile:          *profile,
		SocketPath:       *socket,
		Self:             self,
		Prefix:           overlayPrefix,
		DNSZone:          dnsZone.zone,
		ReconnectTimeout: *reconnectTimeout,
		WG:               wgc,
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
	if *gossipKeyFile != "" {
		go reloadKeyringOnSIGHUP(ctx, m, *gossipKeyFile)
	}

	slog.Info("pigeon-mesh up", "interface", *iface, "endpoint", ep, "address", ip.String())
	if err := m.Run(ctx); err != nil {
		slog.Error("pigeon-mesh stopped", "err", err)
		os.Exit(1)
	}
	slog.Info("pigeon-mesh stopped")
}

func reloadKeyringOnSIGHUP(ctx context.Context, m *mesh.Mesh, path string) {
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

type dnsZoneFlag struct {
	zone string
}

func (f *dnsZoneFlag) String() string {
	if f == nil {
		return ""
	}
	return f.zone
}

func (f *dnsZoneFlag) Set(v string) error {
	if v == "" || v == "true" {
		f.zone = defaultDNSZone
	} else {
		f.zone = v
	}
	return nil
}

func (f *dnsZoneFlag) IsBoolFlag() bool { return true }
