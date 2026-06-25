//go:build linux

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
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
	// Valid just before now+ttl and expired just after => notAfter == now+ttl exactly,
	// with no random jitter added (a jittered grant would push expiry minutes out).
	must.NoError(t, signature.Verify(signers, node, raw, before.Add(time.Hour-time.Second)))
	must.Error(t, signature.Verify(signers, node, raw, before.Add(time.Hour+2*time.Second)))
	// And it is a valid grant for this node right now.
	must.NoError(t, signature.Verify(signers, node, raw, before.Add(time.Minute)))
}

func TestRunSign_NoExpiry(t *testing.T) {
	keyPath, signerPub, node := writeSignerKey(t)
	out := captureStdout(t, func() {
		must.EqOp(t, 0, runSign([]string{"--key", keyPath, node})) // ttl defaults to 0 = no expiry
	})
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	must.NoError(t, err)
	must.NoError(t, signature.Verify([]ed25519.PublicKey{signerPub}, node, raw, time.Now().Add(100*365*24*time.Hour)))
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
