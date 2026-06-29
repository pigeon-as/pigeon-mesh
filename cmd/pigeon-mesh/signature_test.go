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

func TestRunSign_NoExpiry(t *testing.T) {
	keyPath, signerPub, node := writeSignerKey(t)
	out := captureStdout(t, func() {
		must.EqOp(t, 0, runSign([]string{"--key", keyPath, node}))
	})
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	must.NoError(t, err)
	_, err = signature.Verify([]ed25519.PublicKey{signerPub}, node, raw, time.Now().Add(100*365*24*time.Hour))
	must.NoError(t, err)
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

	must.EqOp(t, 2, runSign([]string{"--key", keyPath, "--route", "10.0.0.0/8", node}), must.Sprint("a route grant without --ttl is refused"))
	must.EqOp(t, 1, runSign([]string{"--key", keyPath, "--ttl", "1h", "--route", "not-a-cidr", node}), must.Sprint("a malformed --route exits 1"))
}

func TestRunSign_Rejects(t *testing.T) {
	keyPath, _, node := writeSignerKey(t)
	must.EqOp(t, 2, runSign([]string{"--key", keyPath, "--ttl", "-1s", node}), must.Sprint("negative ttl"))
	must.EqOp(t, 2, runSign([]string{"--key", keyPath}), must.Sprint("missing node arg"))
	must.EqOp(t, 2, runSign([]string{node}), must.Sprint("missing --key"))
	must.EqOp(t, 1, runSign([]string{"--key", keyPath, "not-base64!"}), must.Sprint("node not base64"))
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	must.EqOp(t, 1, runSign([]string{"--key", keyPath, short}), must.Sprint("node wrong byte length"))
}
