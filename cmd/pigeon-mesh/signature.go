//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/pigeon-as/pigeon-mesh/internal/signature"
)

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func runKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	fs.Parse(args)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "signer: "+base64.StdEncoding.EncodeToString(pub))
	fmt.Println(base64.StdEncoding.EncodeToString(priv))
	return 0
}

func runPubkey(args []string) int {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	keyFile := fs.String("key", "", "signing key file from 'keygen'")
	fs.Parse(args)
	priv, err := loadSigningKey(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
	return 0
}

func runSign(args []string) int {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyFile := fs.String("key", "", "signing key file from 'keygen'")
	ttl := fs.Duration("ttl", 0, "validity duration from now (required); renew before it lapses")
	skew := fs.Duration("not-before-skew", time.Minute, "tolerance before now to absorb clock skew")
	var routeFlags stringList
	fs.Var(&routeFlags, "route", "a transit CIDR the node may advertise beyond its identity /128; repeatable")
	fs.Parse(args)

	node := fs.Arg(0)
	if *keyFile == "" || node == "" || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: pigeon-mesh sign --key <key> --ttl <dur> [--route <cidr> ...] <node-wg-pubkey> (flags before the pubkey)")
		return 2
	}
	if *ttl <= 0 {
		fmt.Fprintln(os.Stderr, "sign: --ttl is required and must be positive (every grant carries an expiry)")
		return 2
	}
	routes := make([]netip.Prefix, 0, len(routeFlags))
	for _, r := range routeFlags {
		p, err := netip.ParsePrefix(strings.TrimSpace(r))
		if err != nil {
			fmt.Fprintf(os.Stderr, "sign: --route %q: %v\n", r, err)
			return 1
		}
		routes = append(routes, p)
	}
	priv, err := loadSigningKey(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	subRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(node))
	if err != nil || len(subRaw) != 32 {
		fmt.Fprintln(os.Stderr, "node must be a base64 32-byte WireGuard public key")
		return 1
	}
	now := time.Now()
	notAfter := now.Add(*ttl).Unix()
	blob, err := signature.Sign(priv, subRaw, now.Add(-*skew).Unix(), notAfter, routes...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(base64.StdEncoding.EncodeToString(blob))
	return 0
}

func runSignRevocation(args []string) int {
	fs := flag.NewFlagSet("sign-revocation", flag.ExitOnError)
	keyFile := fs.String("key", "", "signing key file from 'keygen'")
	grantFile := fs.String("grant", "", "the operator-signed grant being revoked (required); its expiry is the reap horizon")
	fs.Parse(args)

	node := fs.Arg(0)
	if *keyFile == "" || *grantFile == "" || node == "" || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: pigeon-mesh sign-revocation --key <key> --grant <grant-file> <node-wg-pubkey> (flags before the pubkey)")
		return 2
	}
	priv, err := loadSigningKey(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	sub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(node))
	if err != nil || len(sub) != 32 {
		fmt.Fprintln(os.Stderr, "node must be a base64 32-byte WireGuard public key")
		return 1
	}
	grant, err := signature.LoadSignature(*grantFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "grant file:", err)
		return 1
	}
	// Horizon = the grant's own expiry, never operator-chosen: reaping while the grant still verifies
	// would re-admit the key. Cross-check the grant's subject against <node> to catch a wrong --grant.
	gsub, err := signature.Subject(grant)
	if err != nil {
		fmt.Fprintln(os.Stderr, "grant file:", err)
		return 1
	}
	if !bytes.Equal(gsub, sub) {
		fmt.Fprintln(os.Stderr, "the --grant is not for this node key")
		return 1
	}
	horizon := signature.NotAfter(grant)
	if horizon == 0 {
		fmt.Fprintln(os.Stderr, "the --grant carries no expiry; cannot bound the revocation")
		return 1
	}
	// notBefore is 0: a revocation carries no valid-from window, it applies the moment any node sees it.
	blob, err := signature.SignRevocation(priv, sub, 0, horizon)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(base64.StdEncoding.EncodeToString(blob))
	return 0
}

func loadSigningKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("--key is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key must be %d bytes, got %d", ed25519.PrivateKeySize, len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}
