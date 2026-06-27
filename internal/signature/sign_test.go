package signature

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

func TestSignerKey(t *testing.T) {
	priv, pub, sub := newSigner(t)
	blob, err := Sign(priv, sub, time.Now().Add(-time.Minute).Unix(), 0)
	must.NoError(t, err)

	got, err := SignerKey(blob)
	must.NoError(t, err)
	must.True(t, bytes.Equal(got, pub), must.Sprint("SignerKey returns the key that signed the grant"))

	_, err = SignerKey([]byte{0, 1, 2})
	must.Error(t, err, must.Sprint("a malformed grant has no signer key"))
}

const testKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func newSigner(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	sub, err := base64.StdEncoding.DecodeString(testKey)
	must.NoError(t, err)
	return priv, pub, sub
}

func mint(t *testing.T, priv ed25519.PrivateKey, c claims) signedClaims {
	t.Helper()
	blob, err := signClaims(priv, c)
	must.NoError(t, err)
	s, err := parse(blob)
	must.NoError(t, err)
	return s
}

func TestRoundTrip(t *testing.T) {
	priv, pub, sub := newSigner(t)
	c := claims{Sub: sub, NotBefore: time.Now().Add(-time.Minute).Unix(), NotAfter: time.Now().Add(time.Hour).Unix()}
	s := mint(t, priv, c)
	must.NoError(t, s.verify([]ed25519.PublicKey{pub}, testKey, time.Now()))
}

func TestNoExpiry(t *testing.T) {
	priv, pub, sub := newSigner(t)
	s := mint(t, priv, claims{Sub: sub, NotBefore: time.Now().Add(-time.Minute).Unix()})
	must.NoError(t, s.verify([]ed25519.PublicKey{pub}, testKey, time.Now()))
	must.NoError(t, s.verify([]ed25519.PublicKey{pub}, testKey, time.Now().Add(100*365*24*time.Hour)))
}

func TestRejections(t *testing.T) {
	priv, pub, sub := newSigner(t)
	valid := claims{Sub: sub, NotBefore: time.Now().Add(-time.Minute).Unix(), NotAfter: time.Now().Add(time.Hour).Unix()}

	otherPub, _, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	must.ErrorContains(t, mint(t, priv, valid).verify([]ed25519.PublicKey{otherPub}, testKey, time.Now()), "unknown signer")

	tampered := mint(t, priv, valid)
	tampered.Sig[0] ^= 0xff
	must.ErrorContains(t, tampered.verify([]ed25519.PublicKey{pub}, testKey, time.Now()), "bad signature")

	expired := valid
	expired.NotAfter = time.Now().Add(-time.Second).Unix()
	must.ErrorContains(t, mint(t, priv, expired).verify([]ed25519.PublicKey{pub}, testKey, time.Now()), "expired")

	future := valid
	future.NotBefore = time.Now().Add(time.Hour).Unix()
	must.ErrorContains(t, mint(t, priv, future).verify([]ed25519.PublicKey{pub}, testKey, time.Now()), "not yet valid")

	otherKey := base64.StdEncoding.EncodeToString(otherPub)
	must.ErrorContains(t, mint(t, priv, valid).verify([]ed25519.PublicKey{pub}, otherKey, time.Now()), "not for this node key")

	wrong := valid
	wrong.Ctx = "other-context"
	wrong.KeyID = pub
	body, err := enc.Marshal(wrong)
	must.NoError(t, err)
	ws := signedClaims{Claims: wrong, Sig: ed25519.Sign(priv, body)}
	must.ErrorContains(t, ws.verify([]ed25519.PublicKey{pub}, testKey, time.Now()), "wrong signature domain")
}

func TestExpiryBoundary(t *testing.T) {
	priv, pub, sub := newSigner(t)
	signers := []ed25519.PublicKey{pub}
	const nb, na = int64(1_000_000), int64(2_000_000)
	s := mint(t, priv, claims{Sub: sub, NotBefore: nb, NotAfter: na})

	// expiry is inclusive: valid strictly before NotAfter, expired at and after it.
	must.NoError(t, s.verify(signers, testKey, time.Unix(na-1, 0)), must.Sprint("valid one second before expiry"))
	must.ErrorContains(t, s.verify(signers, testKey, time.Unix(na, 0)), "expired", must.Sprint("expired exactly at NotAfter (>=)"))
	must.ErrorContains(t, s.verify(signers, testKey, time.Unix(na+1, 0)), "expired")

	// not-before is exclusive: valid at NotBefore, not-yet-valid strictly before it.
	must.NoError(t, s.verify(signers, testKey, time.Unix(nb, 0)), must.Sprint("valid exactly at NotBefore"))
	must.ErrorContains(t, s.verify(signers, testKey, time.Unix(nb-1, 0)), "not yet valid")
}

// NotAfter is the exported accessor mesh relies on for expiry; a non-parseable blob must
// read as 0 (no expiry), never as expired.
func TestNotAfter(t *testing.T) {
	priv, _, sub := newSigner(t)
	blob, err := Sign(priv, sub, 1_000, 2_000)
	must.NoError(t, err)
	must.EqOp(t, int64(2_000), NotAfter(blob))
	must.EqOp(t, int64(0), NotAfter([]byte{0, 1, 2}), must.Sprint("garbage is not read as expiry"))
	must.EqOp(t, int64(0), NotAfter(nil))
}
