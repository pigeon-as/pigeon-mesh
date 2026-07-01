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

	sockaddr "github.com/hashicorp/go-sockaddr/template"
	"github.com/pigeon-as/pigeon-mesh/internal/dns"
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
		case "revoke":
			os.Exit(runRevoke(os.Args[2:]))
		case "keygen":
			os.Exit(runKeygen(os.Args[2:]))
		case "pubkey":
			os.Exit(runPubkey(os.Args[2:]))
		case "sign":
			os.Exit(runSign(os.Args[2:]))
		case "sign-revocation":
			os.Exit(runSignRevocation(os.Args[2:]))
		}
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	iface := flag.String("interface", "", "existing WireGuard interface (required); kernel peers need a /128 or /32 first in AllowedIPs")
	endpoint := flag.String("endpoint", "", "this node's Endpoint as host:port; hostnames resolved at startup; go-sockaddr templates evaluated (required)")
	allowedIPs := flag.String("allowed-ips", "", "additional AllowedIPs this node advertises to peers beyond its auto overlay /128, comma-separated")
	peerPolicy := flag.String("peer-policy", "", "expr predicate accept(peer, route) bool, evaluated per advertised CIDR including a peer's identity /128 (no exemption); true installs the route, false drops it (empty accepts all). Block a peer with 'peer.key != \"K=\"', a route with 'route != \"C\"'; reachability-only is 'route == peer.address'. In scope: peer (.key/.endpoint/.address/.allowedips), route, cidrSubset(outer,inner). Inline or @file (SIGHUP-reloadable)")
	gossipPort := flag.Int("gossip-port", 7946, "port to listen on for gossip (TCP and UDP)")
	persistentKeepalive := flag.Int("persistent-keepalive", 0, "PersistentKeepalive interval in seconds advertised to peers (0 disables)")
	profile := flag.String("profile", "wan", "memberlist timing profile: lan, wan, or local")
	socket := flag.String("socket", mesh.DefaultSocketPath, "path to the status query socket served for the status command; empty disables")
	dnsZone := flag.String("dns", "", "serve AAAA records for peers' name= tag and program systemd-resolved split-DNS for this zone (e.g. mesh.internal)")
	prefix := flag.String("prefix", "fdcc::/48", "byte-aligned IPv6 ULA prefix; the daemon derives this node's overlay address from its key (sha512) and assigns it to the interface, and requires every peer's address to be the same derivation of its key (self-certifying)")
	signers := flag.String("signers", "", "trusted operator signer key(s) to verify peers against: a base64 key, comma-separated, or @file (SIGHUP-reloadable). Defaults to the key that signed this node's own --signature; set it explicitly only to pin multiple operators or to rotate signers")
	signatureFile := flag.String("signature", "", "path to this node's base64 operator-signed grant (required); advertised to peers for admission (SIGHUP-reloadable for hitless renewal)")
	revoked := flag.String("revoked", "", "path to a file of base64 anti-grants denying compromised keys at admission (SIGHUP-reloadable); the config-managed completeness floor under gossip revocation")
	reconnectTimeout := flag.Duration("reconnect-timeout", 10*time.Minute, "grace window to keep a failed peer's tunnel before reaping it; survives restarts and brief partitions")
	var tagFlags []string
	flag.Func("tag", "tag for this node, repeatable as k=v", func(v string) error {
		tagFlags = append(tagFlags, v)
		return nil
	})
	flag.Parse()

	if flag.NArg() > 0 {
		slog.Error("unexpected arguments", "args", flag.Args())
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
	if *signatureFile == "" {
		slog.Error("missing required flag --signature (every node presents its own operator-signed grant)")
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
			if label := dns.SanitizeLabel(h); label != "" {
				if tags == nil {
					tags = mesh.Tags{}
				}
				tags["name"] = label
			}
		}
	}

	sig, err := signature.LoadSignature(*signatureFile)
	if err != nil {
		slog.Error("signature file", "err", err)
		os.Exit(1)
	}

	self := mesh.Peer{
		PublicKey:           publicKey.String(),
		Endpoint:            ep,
		AllowedIPs:          allowed,
		PersistentKeepalive: *persistentKeepalive,
		Tags:                tags,
		Signature:           sig,
	}

	cfg := mesh.Config{
		Iface:            *iface,
		GossipPort:       *gossipPort,
		BindAddr:         ip.String(),
		Profile:          *profile,
		SocketPath:       *socket,
		Self:             self,
		Prefix:           overlayPrefix,
		DNSZone:          *dnsZone,
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
		cfg.Revoked, err = mesh.LoadRevoked(*revoked, cfg.Signers)
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	m, err := mesh.New(cfg)
	if err != nil {
		slog.Error("mesh", "err", err)
		os.Exit(1)
	}

	go sdnotify.Run(ctx)
	signersFile := ""
	if path, ok := strings.CutPrefix(*signers, "@"); ok {
		signersFile = path
	}
	policyFile := ""
	if path, ok := strings.CutPrefix(*peerPolicy, "@"); ok {
		policyFile = path
	}
	go reloadOnSIGHUP(ctx, m, *signatureFile, signersFile, policyFile, *revoked)

	slog.Info("pigeon-mesh up", "interface", *iface, "endpoint", ep, "address", ip.String())
	if err := m.Run(ctx); err != nil {
		slog.Error("pigeon-mesh stopped", "err", err)
		os.Exit(1)
	}
	slog.Info("pigeon-mesh stopped")
}

func reloadOnSIGHUP(ctx context.Context, m *mesh.Mesh, signaturePath, signersPath, policyPath, revokedPath string) {
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
