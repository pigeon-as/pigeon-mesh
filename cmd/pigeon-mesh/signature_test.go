//go:build linux

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pigeon-as/pigeon-mesh/internal/signature"
	"github.com/shoenig/test/must"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	must.NoError(t, err)
	os.Stdout = w
	fn()
	must.NoError(t, w.Close())
	os.Stdout = old
	out, err := io.ReadAll(r)
	must.NoError(t, err)
	return string(out)
}

func writeSignerKey(t *testing.T) (path string, signerPub ed25519.PublicKey, node string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	path = filepath.Join(t.TempDir(), "signer.key")
	must.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600))
	nodeRaw := make([]byte, 32)
	nodeRaw[0] = 7
	return path, pub, base64.StdEncoding.EncodeToString(nodeRaw)
}

func TestRunSign_TTLExactNoJitter(t *testing.T) {
	keyPath, signerPub, node := writeSignerKey(t)
	before := time.Now()
	out := captureStdout(t, func() {
		must.EqOp(t, 0, runSign([]string{"--key", keyPath, "--ttl", "1h", node}))
	})
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	must.NoError(t, err)

	signers := []ed25519.PublicKey{signerPub}
	// notAfter == now+ttl exactly, no jitter (a jittered grant would push expiry minutes out).
	_, err = signature.Verify(signers, node, raw, before.Add(time.Hour-time.Second))
	must.NoError(t, err, must.Sprint("valid just before now+ttl"))
	_, err = signature.Verify(signers, node, raw, before.Add(time.Hour+2*time.Second))
	must.Error(t, err, must.Sprint("expired just after now+ttl => notAfter is exact, no jitter"))
	_, err = signature.Verify(signers, node, raw, before.Add(time.Minute))
	must.NoError(t, err, must.Sprint("valid for this node now"))
}

func TestRunSign_RequiresTTL(t *testing.T) {
	keyPath, _, node := writeSignerKey(t)
	must.EqOp(t, 2, runSign([]string{"--key", keyPath, node}), must.Sprint("sign without --ttl is refused"))
	must.EqOp(t, 2, runSign([]string{"--key", keyPath, "--ttl", "0s", node}), must.Sprint("sign with zero --ttl is refused"))
}

func TestRunSign_Routes(t *testing.T) {
	keyPath, signerPub, node := writeSignerKey(t)
	out := captureStdout(t, func() {
		must.EqOp(t, 0, runSign([]string{"--key", keyPath, "--ttl", "1h", "--route", "10.0.0.0/8", "--route", "192.168.0.0/16", node}))
	})
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	must.NoError(t, err)
	g, err := signature.Verify([]ed25519.PublicKey{signerPub}, node, raw, time.Now())
	must.NoError(t, err)
	must.Eq(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16")}, g.Routes, must.Sprint("the grant carries the authorized routes"))

	must.EqOp(t, 2, runSign([]string{"--key", keyPath, "--route", "10.0.0.0/8", node}), must.Sprint("a grant without --ttl is refused"))
	must.EqOp(t, 1, runSign([]string{"--key", keyPath, "--ttl", "1h", "--route", "not-a-cidr", node}), must.Sprint("a malformed --route exits 1"))
}

func loadSignerPriv(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(path)
	must.NoError(t, err)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	must.NoError(t, err)
	return ed25519.PrivateKey(raw)
}

func captureIO(t *testing.T, stdin string, fn func()) string {
	t.Helper()
	oldIn := os.Stdin
	r, w, err := os.Pipe()
	must.NoError(t, err)
	os.Stdin = r
	go func() { io.WriteString(w, stdin); w.Close() }()
	out := captureStdout(t, fn)
	os.Stdin = oldIn
	return out
}

func TestRunSign_Detached(t *testing.T) {
	keyPath, signerPub, node := writeSignerKey(t)
	pub := base64.StdEncoding.EncodeToString(signerPub)

	// --pubkey emits the to-be-signed body; an external signer (here the raw key) signs it as-is.
	tbs := strings.TrimSpace(captureStdout(t, func() {
		must.EqOp(t, 0, runSign([]string{"--pubkey", pub, "--ttl", "1h", "--name", "alpha", node}))
	}))
	body, err := base64.StdEncoding.DecodeString(tbs)
	must.NoError(t, err)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(loadSignerPriv(t, keyPath), body))

	// --signature wraps the signature (body on stdin) into a grant that verifies like a local one.
	out := strings.TrimSpace(captureIO(t, tbs, func() {
		must.EqOp(t, 0, runSign([]string{"--signature", sig}))
	}))
	raw, err := base64.StdEncoding.DecodeString(out)
	must.NoError(t, err)
	g, err := signature.Verify([]ed25519.PublicKey{signerPub}, node, raw, time.Now())
	must.NoError(t, err)
	must.EqOp(t, "alpha", g.Name, must.Sprint("the signed name survives the detached flow"))

	// exactly one of --key / --pubkey is required.
	must.EqOp(t, 2, runSign([]string{"--ttl", "1h", node}), must.Sprint("neither --key nor --pubkey is a usage error"))
	must.EqOp(t, 2, runSign([]string{"--key", keyPath, "--pubkey", pub, "--ttl", "1h", node}), must.Sprint("both is a usage error"))
}

func TestRunSign_Rejects(t *testing.T) {
	keyPath, _, node := writeSignerKey(t)
	must.EqOp(t, 2, runSign([]string{"--key", keyPath, "--ttl", "-1s", node}), must.Sprint("negative ttl"))
	must.EqOp(t, 2, runSign([]string{"--key", keyPath}), must.Sprint("missing node arg"))
	must.EqOp(t, 2, runSign([]string{node}), must.Sprint("missing --key"))
	must.EqOp(t, 1, runSign([]string{"--key", keyPath, "--ttl", "1h", "not-base64!"}), must.Sprint("node not base64"))
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	must.EqOp(t, 1, runSign([]string{"--key", keyPath, "--ttl", "1h", short}), must.Sprint("node wrong byte length"))
}
