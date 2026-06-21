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
	"strings"
	"syscall"
	"time"

	sockaddr "github.com/hashicorp/go-sockaddr/template"
	"github.com/pigeon-as/pigeon-mesh/internal/mesh"
	"github.com/pigeon-as/pigeon-mesh/internal/sdnotify"
	"github.com/pigeon-as/pigeon-mesh/internal/wg"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "status" {
		os.Exit(runStatus(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "leave" {
		os.Exit(runLeave(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		os.Exit(runKeygen(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "pubkey" {
		os.Exit(runPubkey(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "sign" {
		os.Exit(runSign(os.Args[2:]))
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	iface := flag.String("interface", "", "existing WireGuard interface (required); bootstrap peers need a /128 or /32 first in AllowedIPs")
	endpoint := flag.String("endpoint", "", "this node's Endpoint as host:port; hostnames resolved at startup; go-sockaddr templates evaluated (required)")
	address := flag.String("address", "", "this node's overlay IP; go-sockaddr templates evaluated; auto-detected from --interface if unset")
	allowedIPs := flag.String("allowed-ips", "", "additional AllowedIPs this node advertises to peers beyond its auto overlay /128, comma-separated")
	peerPolicy := flag.String("peer-policy", "", "expr predicate accept(peer, allowedip) bool, evaluated per advertised CIDR; false drops only that route (identity /128 always installs; empty accepts all). In scope: peer (.key/.endpoint/.allowedips), allowedip, cidrSubset(outer,inner). Inline or @file (SIGHUP-reloadable)")
	gossipPort := flag.Int("gossip-port", 7946, "port to listen on for gossip (TCP and UDP)")
	gossipKeyFile := flag.String("gossip-key-file", "", "JSON file of base64-encoded gossip encryption keys")
	persistentKeepalive := flag.Int("persistent-keepalive", 0, "PersistentKeepalive interval in seconds advertised to peers (0 disables)")
	profile := flag.String("profile", "wan", "memberlist timing profile: lan, wan, or local")
	socket := flag.String("socket", mesh.DefaultSocketPath, "path to the status query socket served for the status command; empty disables")
	dns := flag.String("dns", "", "serve AAAA records for peers' name= tag and program systemd-resolved split-DNS for this zone (e.g. mesh.internal)")
	prefix := flag.String("prefix", "", "optional byte-aligned IPv6 ULA prefix (e.g. fdcc::/16); when set, the daemon derives this node's overlay address from its key and assigns it to the interface, and requires every peer's address to be the same derivation of its key (self-certifying)")
	signers := flag.String("signers", "", "trusted signer public key(s): a base64 key, comma-separated keys, or @file (one per line, SIGHUP-reloadable); enables signature verification")
	signatureFile := flag.String("signature", "", "path to this node's base64 signature; advertised to peers for admission")
	requireSignature := flag.Bool("require-signature", false, "reject any peer that does not present a valid signature (needs --signers)")
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
	if *requireSignature && *signers == "" {
		slog.Error("--require-signature needs --signers")
		os.Exit(2)
	}
	if *requireSignature && *signatureFile == "" {
		slog.Error("--require-signature needs this node to present its own --signature")
		os.Exit(2)
	}
	if *signatureFile != "" && *signers == "" {
		slog.Warn("--signature has no effect without --signers; this node verifies no peers")
	}
	if *signers != "" && !*requireSignature {
		slog.Warn("--signers is set without --require-signature; unsigned peers are still admitted (pass --require-signature to reject them)")
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
		if err = wgc.SetRoute(*iface, overlayPrefix); err != nil {
			slog.Error("set route", "err", err)
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
			if label := mesh.SanitizeLabel(h); label != "" {
				if tags == nil {
					tags = mesh.Tags{}
				}
				tags["name"] = label
			}
		}
	}

	var signature []byte
	if *signatureFile != "" {
		signature, err = mesh.LoadSignature(*signatureFile)
		if err != nil {
			slog.Error("signature file", "err", err)
			os.Exit(1)
		}
	}

	self := mesh.Peer{
		PublicKey:           publicKey.String(),
		Endpoint:            ep,
		AllowedIPs:          allowed,
		PersistentKeepalive: *persistentKeepalive,
		Tags:                tags,
		Signature:           signature,
	}

	cfg := mesh.Config{
		Iface:            *iface,
		GossipPort:       *gossipPort,
		BindAddr:         ip.String(),
		Profile:          *profile,
		SocketPath:       *socket,
		Self:             self,
		Prefix:           overlayPrefix,
		DNSZone:          *dns,
		RequireSignature: *requireSignature,
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
	if *gossipKeyFile != "" {
		cfg.Keyring, err = mesh.LoadKeyring(*gossipKeyFile)
		if err != nil {
			slog.Error("gossip key", "err", err)
			os.Exit(1)
		}
	}
	if *signers != "" {
		cfg.Signers, err = mesh.ParseSigners(*signers)
		if err != nil {
			slog.Error("signers", "err", err)
			os.Exit(1)
		}
	}
	if len(signature) > 0 && len(cfg.Signers) > 0 {
		if err := mesh.VerifySignature(cfg.Signers, self.PublicKey, signature, time.Now()); err != nil {
			slog.Error("own signature rejected by pinned signer keys", "err", err)
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
	signersFile := ""
	if path, ok := strings.CutPrefix(*signers, "@"); ok {
		signersFile = path
	}
	policyFile := ""
	if path, ok := strings.CutPrefix(*peerPolicy, "@"); ok {
		policyFile = path
	}
	if *gossipKeyFile != "" || signersFile != "" || policyFile != "" {
		go reloadOnSIGHUP(ctx, m, *gossipKeyFile, signersFile, policyFile)
	}

	slog.Info("pigeon-mesh up", "interface", *iface, "endpoint", ep, "address", ip.String())
	if err := m.Run(ctx); err != nil {
		slog.Error("pigeon-mesh stopped", "err", err)
		os.Exit(1)
	}
	slog.Info("pigeon-mesh stopped")
}

func reloadOnSIGHUP(ctx context.Context, m *mesh.Mesh, keyringPath, signersPath, policyPath string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	defer signal.Stop(sig)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sig:
			if keyringPath != "" {
				if n, err := m.ReloadKeyringFromFile(keyringPath); err != nil {
					slog.Error("keyring reload", "err", err)
				} else {
					slog.Info("keyring reloaded", "keys", n)
				}
			}
			if signersPath != "" {
				if n, err := m.ReloadSignersFromFile(signersPath); err != nil {
					slog.Error("signers reload", "err", err)
				} else {
					slog.Info("signers reloaded", "keys", n)
				}
			}
			if policyPath != "" {
				if err := m.ReloadPolicyFromFile(policyPath); err != nil {
					slog.Error("peer-policy reload", "err", err)
				} else {
					slog.Info("peer-policy reloaded")
				}
			}
		}
	}
}
