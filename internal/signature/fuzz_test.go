package signature

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/netip"
	"testing"
	"time"
)

// Verify and VerifyRevocation eat attacker-controlled grant/anti-grant blobs off gossip; they must
// never panic on arbitrary bytes.
func FuzzVerify(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sub := make([]byte, ed25519.PublicKeySize)
	now := time.Now()
	if blob, err := Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), "alpha", netip.MustParsePrefix("10.0.0.0/8")); err == nil {
		f.Add(blob)
	}
	if rev, err := SignRevocation(priv, sub, now.Add(time.Hour).Unix()); err == nil {
		f.Add(rev)
	}
	f.Add([]byte{})
	f.Add([]byte{0xff, 0x00, 0x80})

	signers := []ed25519.PublicKey{pub}
	subKey := base64.StdEncoding.EncodeToString(sub)
	f.Fuzz(func(t *testing.T, blob []byte) {
		_, _ = Verify(signers, subKey, blob, now)
		_, _, _ = VerifyRevocation(signers, blob)
	})
}
