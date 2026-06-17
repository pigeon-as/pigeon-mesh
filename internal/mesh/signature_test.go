package mesh

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

func mkSig(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	sub, err := base64.StdEncoding.DecodeString(testKey)
	must.NoError(t, err)
	return priv, pub, sub
}

func mint(t *testing.T, priv ed25519.PrivateKey, c sigClaims) signedSig {
	t.Helper()
	blob, err := signClaims(priv, c)
	must.NoError(t, err)
	s, err := parseSignedSig(blob)
	must.NoError(t, err)
	return s
}

func TestSignature_RoundTrip(t *testing.T) {
	priv, pub, sub := mkSig(t)
	c := sigClaims{
		Sub:       sub,
		NotBefore: time.Now().Add(-time.Minute).Unix(),
		NotAfter:  time.Now().Add(time.Hour).Unix(),
	}
	s := mint(t, priv, c)
	must.NoError(t, s.verify([]ed25519.PublicKey{pub}, testKey, time.Now()))
}

func TestSignature_NoExpiry(t *testing.T) {
	priv, pub, sub := mkSig(t)
	s := mint(t, priv, sigClaims{Sub: sub, NotBefore: time.Now().Add(-time.Minute).Unix()})
	must.NoError(t, s.verify([]ed25519.PublicKey{pub}, testKey, time.Now()))
	must.NoError(t, s.verify([]ed25519.PublicKey{pub}, testKey, time.Now().Add(100*365*24*time.Hour)))
}

func TestSignature_Rejections(t *testing.T) {
	priv, pub, sub := mkSig(t)
	valid := sigClaims{
		Sub:       sub,
		NotBefore: time.Now().Add(-time.Minute).Unix(),
		NotAfter:  time.Now().Add(time.Hour).Unix(),
	}

	otherPub, _, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	must.ErrorContains(t,
		mint(t, priv, valid).verify([]ed25519.PublicKey{otherPub}, testKey, time.Now()),
		"unknown signer")

	tampered := mint(t, priv, valid)
	tampered.Sig[0] ^= 0xff
	must.ErrorContains(t,
		tampered.verify([]ed25519.PublicKey{pub}, testKey, time.Now()),
		"bad signature")

	expired := valid
	expired.NotAfter = time.Now().Add(-time.Second).Unix()
	must.ErrorContains(t, mint(t, priv, expired).verify([]ed25519.PublicKey{pub}, testKey, time.Now()), "expired")

	future := valid
	future.NotBefore = time.Now().Add(time.Hour).Unix()
	must.ErrorContains(t, mint(t, priv, future).verify([]ed25519.PublicKey{pub}, testKey, time.Now()), "not yet valid")

	otherKey := base64.StdEncoding.EncodeToString(otherPub)
	must.ErrorContains(t,
		mint(t, priv, valid).verify([]ed25519.PublicKey{pub}, otherKey, time.Now()),
		"not for this node key")

	wrong := valid
	wrong.Ctx = "other-context"
	wrong.KeyID = pub
	body, err := sigEnc.Marshal(wrong)
	must.NoError(t, err)
	ws := signedSig{Claims: wrong, Sig: ed25519.Sign(priv, body)}
	must.ErrorContains(t, ws.verify([]ed25519.PublicKey{pub}, testKey, time.Now()), "wrong signature domain")
}

func TestSelfReject(t *testing.T) {
	priv, pub, sub := mkSig(t)
	signers := []ed25519.PublicKey{pub}
	now := time.Unix(1_000_000, 0)
	mk := func(notAfter int64) []byte {
		blob, err := signClaims(priv, sigClaims{Sub: sub, NotBefore: now.Add(-time.Hour).Unix(), NotAfter: notAfter})
		must.NoError(t, err)
		return blob
	}

	must.EqOp(t, "signature expired", selfReject(Peer{Signature: mk(now.Add(-time.Minute).Unix())}, signers, now), must.Sprint("an expired self grant is surfaced"))
	must.EqOp(t, "", selfReject(Peer{Signature: mk(now.Add(time.Hour).Unix())}, signers, now), must.Sprint("a valid self grant is not flagged"))
	must.EqOp(t, "", selfReject(Peer{Signature: mk(now.Add(-time.Minute).Unix())}, nil, now), must.Sprint("no signers: nothing to enforce"))
	must.EqOp(t, "", selfReject(Peer{}, signers, now), must.Sprint("no signature: nothing to flag"))
}
