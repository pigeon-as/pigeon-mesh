//go:build linux

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/pigeon-as/pigeon-mesh/internal/dns"
	"github.com/pigeon-as/pigeon-mesh/internal/mesh"
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
	keyFile := fs.String("key", "", "signing key file from 'keygen' (local signing)")
	pubkey := fs.String("pubkey", "", "external signer's base64 public key instead of --key: prints the to-be-signed body for that signer (e.g. Vault Transit) to sign, then complete it with --signature")
	sig := fs.String("signature", "", "base64 signature over a to-be-signed body read from stdin: prints the finished grant")
	ttl := fs.Duration("ttl", 0, "validity duration from now (required); renew before it lapses")
	name := fs.String("name", "", "DNS name to bind to this node (signed); empty means no name. Use \"$(hostname)\" when signing on the node")
	skew := fs.Duration("not-before-skew", time.Minute, "tolerance before now to absorb clock skew")
	var routeFlags stringList
	fs.Var(&routeFlags, "route", "a transit CIDR the node may advertise beyond its identity /128; repeatable")
	var tagFlags stringList
	fs.Var(&tagFlags, "tag", "an operator-signed tag k=v bound into the grant; repeatable. Verified at every peer, unlike a self-declared label")
	fs.Parse(args)

	if *sig != "" {
		if *keyFile != "" || *pubkey != "" || *ttl != 0 || *name != "" || len(routeFlags) > 0 || len(tagFlags) > 0 {
			fmt.Fprintln(os.Stderr, "sign: --signature only completes a --pubkey body read from stdin; it takes no --key/--pubkey/--ttl/--name/--route/--tag")
			return 2
		}
		return runAttach(*sig)
	}
	node := fs.Arg(0)
	if node == "" || fs.NArg() != 1 || (*keyFile == "") == (*pubkey == "") {
		fmt.Fprintln(os.Stderr, "usage: pigeon-mesh sign (--key <key> | --pubkey <b64>) --ttl <dur> [--name <n>] [--route <cidr> ...] [--tag <k=v> ...] <node-wg-pubkey>")
		return 2
	}
	if *ttl <= 0 {
		fmt.Fprintln(os.Stderr, "sign: --ttl is required and must be positive (every grant carries an expiry)")
		return 2
	}
	if *name != "" && dns.SanitizeLabel(*name) == "" {
		fmt.Fprintf(os.Stderr, "sign: --name %q is not a usable DNS label (a-z 0-9 and -, <=63 chars, no leading/trailing -)\n", *name)
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
	tags, err := mesh.ParseTags(tagFlags)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		return 1
	}
	subRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(node))
	if err != nil || len(subRaw) != 32 {
		fmt.Fprintln(os.Stderr, "node must be a base64 32-byte WireGuard public key")
		return 1
	}
	now := time.Now()
	notAfter := now.Add(*ttl).Unix()

	if *pubkey != "" {
		pub, err := parsePubkey(*pubkey)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		body, err := signature.SigningBody(pub, subRaw, now.Add(-*skew).Unix(), notAfter, *name, tags, routes...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(base64.StdEncoding.EncodeToString(body))
		return 0
	}
	priv, err := loadSigningKey(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	blob, err := signature.Sign(priv, subRaw, now.Add(-*skew).Unix(), notAfter, *name, tags, routes...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(base64.StdEncoding.EncodeToString(blob))
	return 0
}

// runAttach completes a detached signing: it wraps the base64 signature over a to-be-signed body read
// from stdin into the finished grant. Used by sign --signature.
func runAttach(sigB64 string) int {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		fmt.Fprintln(os.Stderr, "--attach: signature is not base64:", err)
		return 1
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read signing body from stdin:", err)
		return 1
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "the signing body on stdin must be base64:", err)
		return 1
	}
	blob, err := signature.Attach(body, sig)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(base64.StdEncoding.EncodeToString(blob))
	return 0
}

func parsePubkey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("--pubkey must be a base64 32-byte ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
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
