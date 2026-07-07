//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/pigeon-as/pigeon-mesh/internal/mesh"
	"github.com/pigeon-as/pigeon-mesh/internal/sdnotify"
	"github.com/pigeon-as/pigeon-mesh/internal/signature"
	"github.com/pigeon-as/pigeon-mesh/internal/wg"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-version":
			os.Exit(runVersion(os.Args[2:]))
		case "status":
			os.Exit(runStatus(os.Args[2:]))
		case "leave":
			os.Exit(runLeave(os.Args[2:]))
		case "keygen":
			os.Exit(runKeygen(os.Args[2:]))
		case "pubkey":
			os.Exit(runPubkey(os.Args[2:]))
		case "sign":
			os.Exit(runSign(os.Args[2:]))
		}
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	iface := flag.String("interface", "", "existing WireGuard interface (required); kernel peers need a /128 or /32 first in AllowedIPs")
	allowedIPs := flag.String("allowed-ips", "", "additional AllowedIPs this node advertises to peers beyond its auto overlay /128, comma-separated")
	peerPolicy := flag.String("peer-policy", "", "expr predicate accept(peer, route) bool, evaluated per advertised CIDR including a peer's identity /128 (no exemption); true installs the route, false drops it (empty accepts all). Block a peer with 'peer.key != \"K=\"', a route with 'route != \"C\"'; reachability-only is 'route == peer.address'. In scope: peer (.key/.endpoint/.address/.allowedips/.tags, where .tags are operator-signed), route, cidrSubset(outer,inner). Inline or @file (SIGHUP-reloadable)")
	gossipPort := flag.Int("gossip-port", 7946, "port to listen on for gossip (TCP and UDP)")
	profile := flag.String("profile", "wan", "memberlist timing profile: lan, wan, or local")
	socket := flag.String("socket", mesh.DefaultSocketPath, "path to the status query socket served for the status command; empty disables")
	dnsZone := flag.String("dns", "", "serve AAAA records for peers' operator-signed sign --name and program systemd-resolved split-DNS for this zone (e.g. mesh.internal)")
	prefix := flag.String("prefix", "fdcc::/48", "byte-aligned IPv6 ULA prefix; the daemon derives this node's overlay address from its key (sha512) and assigns it to the interface, and requires every peer's address to be the same derivation of its key (self-certifying)")
	signers := flag.String("signers", "", "trusted operator signer key(s) to verify peers against: a base64 key, comma-separated, or @file (SIGHUP-reloadable). Defaults to the key that signed this node's own --signature; set it explicitly only to pin multiple operators or to rotate signers")
	signatureFile := flag.String("signature", "", "path to this node's base64 operator-signed grant (required); advertised to peers for admission (SIGHUP-reloadable for hitless renewal)")
	revoked := flag.String("revoked", "", "path to a denylist file of base64 node public keys, one per line; each listed key is denied at admission while present. SIGHUP reloads; remove a line to re-admit")
	reconnectTimeout := flag.Duration("reconnect-timeout", 10*time.Minute, "grace window to keep a failed peer's tunnel before reaping it; survives restarts and brief partitions")
	disableFirewall := flag.Bool("disable-firewall", false, "turn pigeon's nftables firewall off entirely, including the gossip-port guard, and manage nftables yourself")
	firewallRules := flag.String("firewall-rules", "", "expr returning a list of allow(proto, ports, cond?) rules for which overlay traffic to this node to accept; default-deny once set. e.g. '[allow(\"tcp\", 5432, peer.tags[\"role\"] == \"db\"), allow(\"tcp\", [22, 179])]'. ports is an int, a \"lo-hi\" string, or a list; peer exposes .key/.address/.endpoint/.tags (operator-signed). ICMPv6, gossip, and established flows are always allowed. Inline or @file (SIGHUP-reloadable). The gossip guard stays on unless --disable-firewall")
	flag.Parse()

	if flag.NArg() > 0 {
		slog.Error("unexpected arguments", "args", flag.Args())
		os.Exit(2)
	}
	if *iface == "" {
		slog.Error("missing required flag --interface")
		os.Exit(2)
	}
	if *signatureFile == "" {
		slog.Error("missing required flag --signature (every node presents its own operator-signed grant)")
		os.Exit(2)
	}
	if *disableFirewall && *firewallRules != "" {
		slog.Error("--disable-firewall turns the firewall off entirely; it cannot be combined with --firewall-rules")
		os.Exit(2)
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

	overlayPrefix, err := netip.ParsePrefix(*prefix)
	if err != nil {
		slog.Error("prefix", "err", err)
		os.Exit(2)
	}
	ip, err := mesh.DeriveAddr(publicKey.String(), overlayPrefix)
	if err != nil {
		slog.Error("prefix", "err", err)
		os.Exit(2)
	}
	if err = wgc.SetAddr(*iface, ip); err != nil {
		slog.Error("set address", "err", err)
		os.Exit(1)
	}
	if err = wgc.SetRoute(*iface, overlayPrefix); err != nil {
		slog.Error("set route", "err", err)
		os.Exit(1)
	}

	host := mesh.HostRoute(ip)
	allowed := []string{host.String()}
	if *allowedIPs != "" {
		extras, err := mesh.ParseAllowedIPs(*allowedIPs)
		if err != nil {
			slog.Error("allowed-ips", "err", err)
			os.Exit(1)
		}
		for _, e := range extras {
			if !slices.Contains(allowed, e) {
				allowed = append(allowed, e)
			}
		}
	}

	sig, err := signature.LoadSignature(*signatureFile)
	if err != nil {
		slog.Error("signature file", "err", err)
		os.Exit(1)
	}

	self := mesh.Peer{
		PublicKey:  publicKey.String(),
		AllowedIPs: allowed,
		Signature:  sig,
	}

	// The daemon-added-peers record lives next to the socket under /run, so it clears on reboot like the
	// kernel peers; only an in-session restart needs it for leave's teardown.
	sockForState := *socket
	if sockForState == "" {
		sockForState = mesh.DefaultSocketPath
	}
	cfg := mesh.Config{
		Iface:            *iface,
		GossipPort:       *gossipPort,
		BindAddr:         ip.String(),
		Profile:          *profile,
		SocketPath:       *socket,
		StatePath:        strings.TrimSuffix(sockForState, ".sock") + ".peers",
		Self:             self,
		Prefix:           overlayPrefix,
		DNSZone:          *dnsZone,
		Firewall:         !*disableFirewall,
		ReconnectTimeout: *reconnectTimeout,
		WG:               wgc,
	}
	if *peerPolicy != "" {
		cfg.Policy, err = mesh.ParsePeerPolicyFlag(*peerPolicy)
		if err != nil {
			slog.Error("peer-policy", "err", err)
			os.Exit(2)
		}
	}
	if *firewallRules != "" {
		cfg.FirewallRules, err = mesh.ParseFirewallRulesFlag(*firewallRules)
		if err != nil {
			slog.Error("firewall-rules", "err", err)
			os.Exit(2)
		}
	}
	if *signers != "" {
		cfg.Signers, err = signature.ParseSigners(*signers)
		if err != nil {
			slog.Error("signers", "err", err)
			os.Exit(1)
		}
	} else {
		signer, derr := signature.SignerKey(sig)
		if derr != nil {
			slog.Error("derive trust anchor from --signature", "err", derr)
			os.Exit(1)
		}
		cfg.Signers = []ed25519.PublicKey{signer}
	}
	if *revoked != "" {
		cfg.Revoked, err = mesh.LoadRevoked(*revoked)
		if err != nil {
			slog.Error("revoked", "err", err)
			os.Exit(1)
		}
	}
	g, err := signature.Verify(cfg.Signers, self.PublicKey, sig, time.Now())
	if err != nil {
		slog.Error("this node's own grant is not signed by a trusted signer key", "err", err)
		os.Exit(1)
	}
	if err := mesh.CheckSelfRoutes(self.AllowedIPs, ip, g.Routes); err != nil {
		slog.Error("re-sign this node's grant with --route for every route it advertises", "err", err)
		os.Exit(1)
	}
	if g.Endpoint == "" {
		slog.Error("this node's grant carries no endpoint; re-sign it with sign --endpoint <host:port>")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	m, err := mesh.New(cfg)
	if err != nil {
		slog.Error("mesh", "err", err)
		os.Exit(1)
	}

	go sdnotify.Run(ctx, m.Ready())
	signersFile := ""
	if path, ok := strings.CutPrefix(*signers, "@"); ok {
		signersFile = path
	}
	policyFile := ""
	if path, ok := strings.CutPrefix(*peerPolicy, "@"); ok {
		policyFile = path
	}
	firewallFile := ""
	if path, ok := strings.CutPrefix(*firewallRules, "@"); ok {
		firewallFile = path
	}
	go reloadOnSIGHUP(ctx, m, *signatureFile, signersFile, policyFile, firewallFile, *revoked)

	slog.Info("pigeon-mesh up", "interface", *iface, "endpoint", g.Endpoint, "address", ip.String())
	if err := m.Run(ctx); err != nil {
		slog.Error("pigeon-mesh stopped", "err", err)
		os.Exit(1)
	}
	slog.Info("pigeon-mesh stopped")
}

func reloadOnSIGHUP(ctx context.Context, m *mesh.Mesh, signaturePath, signersPath, policyPath, firewallPath, revokedPath string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	defer signal.Stop(sig)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sig:
			if signersPath != "" {
				if n, err := m.ReloadSignersFromFile(signersPath); err != nil {
					slog.Error("signers reload", "err", err)
				} else {
					slog.Info("signers reloaded", "keys", n)
				}
			}
			if firewallPath != "" {
				if err := m.ReloadFirewallRulesFromFile(firewallPath); err != nil {
					slog.Error("firewall-rules reload", "err", err)
				} else {
					slog.Info("firewall-rules reloaded")
				}
			}
			if revokedPath != "" {
				if n, err := m.ReloadRevokedFromFile(revokedPath); err != nil {
					slog.Error("revoked reload", "err", err)
				} else {
					slog.Info("revoked reloaded", "count", n)
				}
			}
			if policyPath != "" {
				if err := m.ReloadPolicyFromFile(policyPath); err != nil {
					slog.Error("peer-policy reload", "err", err)
				} else {
					slog.Info("peer-policy reloaded")
				}
			}
			if err := m.ReloadSignatureFromFile(signaturePath); err != nil {
				slog.Error("signature reload", "err", err)
			} else {
				slog.Info("signature reloaded")
			}
		}
	}
}
