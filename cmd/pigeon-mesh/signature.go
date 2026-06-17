//go:build linux

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"time"

	"github.com/pigeon-as/pigeon-mesh/internal/mesh"
)

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
	ttl := fs.Duration("ttl", 0, "validity duration from now (0 = no expiry)")
	skew := fs.Duration("not-before-skew", time.Minute, "tolerance before now to absorb clock skew")
	fs.Parse(args)

	node := fs.Arg(0)
	if *keyFile == "" || node == "" {
		fmt.Fprintln(os.Stderr, "usage: pigeon-mesh sign --key <key> [--ttl <dur>] <node-wg-pubkey>")
		return 2
	}
	if *ttl < 0 {
		fmt.Fprintln(os.Stderr, "sign: --ttl must be >= 0 (0 = no expiry)")
		return 2
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
	var notAfter int64
	if *ttl > 0 {
		jitter := time.Duration(rand.Int64N(int64(*ttl/10 + 1)))
		notAfter = now.Add(*ttl - jitter).Unix()
	}
	blob, err := mesh.Sign(priv, subRaw, now.Add(-*skew).Unix(), notAfter)
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
