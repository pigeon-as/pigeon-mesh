package signature

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"net/netip"
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

const testKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func newSigner(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	sub, err := base64.StdEncoding.DecodeString(testKey)
	must.NoError(t, err)
	return priv, pub, sub
}

// mint hand-signs arbitrary claims under a chosen domain, for crafting blobs Sign/SignRevocation would refuse.
func mint(t *testing.T, priv ed25519.PrivateKey, c claims, dom string) []byte {
	t.Helper()
	blob, err := signClaims(priv, c, dom)
	must.NoError(t, err)
	return blob
}

func TestSignerKey(t *testing.T) {
	priv, pub, sub := newSigner(t)
	blob, err := Sign(priv, sub, time.Now().Add(-time.Minute).Unix(), time.Now().Add(time.Hour).Unix())
	must.NoError(t, err)

	got, err := SignerKey(blob)
	must.NoError(t, err)
	must.True(t, bytes.Equal(got, pub), must.Sprint("SignerKey returns the key that signed the grant"))

	_, err = SignerKey([]byte{0, 1, 2})
	must.Error(t, err, must.Sprint("a malformed grant has no signer key"))
}

func TestVerify_RoundTrip(t *testing.T) {
	priv, pub, sub := newSigner(t)
	now := time.Now()
	blob, err := Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix())
	must.NoError(t, err)
	g, err := Verify([]ed25519.PublicKey{pub}, testKey, blob, now)
	must.NoError(t, err)
	must.EqOp(t, now.Add(time.Hour).Unix(), g.NotAfter)
}

func TestVerify_Rejections(t *testing.T) {
	priv, pub, sub := newSigner(t)
	signers := []ed25519.PublicKey{pub}
	now := time.Now()
	good := func() claims {
		return claims{Sub: sub, NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(time.Hour).Unix()}
	}

	otherPub, _, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	_, err = Verify([]ed25519.PublicKey{otherPub}, testKey, mint(t, priv, good(), domain), now)
	must.ErrorContains(t, err, "unknown signer")

	tampered := mint(t, priv, good(), domain)
	tampered[len(tampered)-1] ^= 0xff
	_, err = Verify(signers, testKey, tampered, now)
	must.ErrorContains(t, err, "bad signature")

	expired := good()
	expired.NotAfter = now.Add(-time.Second).Unix()
	_, err = Verify(signers, testKey, mint(t, priv, expired, domain), now)
	must.ErrorContains(t, err, "expired")

	future := good()
	future.NotBefore = now.Add(time.Hour).Unix()
	_, err = Verify(signers, testKey, mint(t, priv, future, domain), now)
	must.ErrorContains(t, err, "not yet valid")

	_, err = Verify(signers, base64.StdEncoding.EncodeToString(otherPub), mint(t, priv, good(), domain), now)
	must.ErrorContains(t, err, "not for this node key")

	// a grant minted under the revocation domain must not verify as a grant
	_, err = Verify(signers, testKey, mint(t, priv, good(), revocationDomain), now)
	must.ErrorContains(t, err, "wrong signature domain")
}

func TestVerify_RequiresExpiry(t *testing.T) {
	priv, pub, sub := newSigner(t)
	now := time.Now()

	_, err := Sign(priv, sub, now.Add(-time.Minute).Unix(), 0)
	must.ErrorContains(t, err, "expiry", must.Sprint("Sign refuses a no-expiry grant"))

	// defense in depth: a hand-minted no-expiry grant is rejected by Verify too.
	blob := mint(t, priv, claims{Sub: sub, NotBefore: now.Add(-time.Minute).Unix(), NotAfter: 0}, domain)
	_, err = Verify([]ed25519.PublicKey{pub}, testKey, blob, now)
	must.ErrorContains(t, err, "expiry", must.Sprint("Verify rejects a no-expiry grant"))
}

func TestExpiryBoundary(t *testing.T) {
	priv, pub, sub := newSigner(t)
	signers := []ed25519.PublicKey{pub}
	const nb, na = int64(1_000_000), int64(2_000_000)
	blob, err := Sign(priv, sub, nb, na)
	must.NoError(t, err)

	// expiry is inclusive: valid strictly before NotAfter, expired at and after it.
	_, err = Verify(signers, testKey, blob, time.Unix(na-1, 0))
	must.NoError(t, err, must.Sprint("valid one second before expiry"))
	_, err = Verify(signers, testKey, blob, time.Unix(na, 0))
	must.ErrorContains(t, err, "expired", must.Sprint("expired exactly at NotAfter (>=)"))

	// not-before is inclusive: valid at NotBefore, not-yet-valid strictly before it.
	_, err = Verify(signers, testKey, blob, time.Unix(nb, 0))
	must.NoError(t, err, must.Sprint("valid exactly at NotBefore"))
	_, err = Verify(signers, testKey, blob, time.Unix(nb-1, 0))
	must.ErrorContains(t, err, "not yet valid")
}

func TestSignRoutes(t *testing.T) {
	priv, pub, sub := newSigner(t)
	signers := []ed25519.PublicKey{pub}
	now := time.Now()
	r1 := netip.MustParsePrefix("10.0.0.0/24")
	r2 := netip.MustParsePrefix("192.168.0.0/16")

	// unordered + duplicate input; the grant stores them masked, deduped, and bytewise-sorted.
	blob, err := Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), r2, r1, r1)
	must.NoError(t, err)
	g, err := Verify(signers, testKey, blob, now)
	must.NoError(t, err)
	must.Eq(t, []netip.Prefix{r1, r2}, g.Routes, must.Sprint("routes are masked, deduped, and sorted"))
}

func TestVerifyRoutes_TamperBreaksSignature(t *testing.T) {
	priv, pub, sub := newSigner(t)
	signers := []ed25519.PublicKey{pub}
	now := time.Now()
	blob, err := Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), netip.MustParsePrefix("10.0.0.0/8"))
	must.NoError(t, err)

	s, err := parse(blob)
	must.NoError(t, err)
	s.Claims.Routes[0][0] ^= 0xff // widen/move the authorized route
	tampered, err := enc.Marshal(s)
	must.NoError(t, err)
	_, err = Verify(signers, testKey, tampered, now)
	must.ErrorContains(t, err, "bad signature", must.Sprint("tampering with the routes breaks the signature; routes are never returned unverified"))
}

func TestNotAfter(t *testing.T) {
	priv, _, sub := newSigner(t)
	blob, err := Sign(priv, sub, 1_000, 2_000)
	must.NoError(t, err)
	must.EqOp(t, int64(2_000), NotAfter(blob))
	must.EqOp(t, int64(0), NotAfter([]byte{0, 1, 2}), must.Sprint("garbage is not read as expiry"))
	must.EqOp(t, int64(0), NotAfter(nil))
}

func TestRevocation_RoundTrip(t *testing.T) {
	priv, pub, sub := newSigner(t)
	now := time.Now()
	horizon := now.Add(time.Hour).Unix()
	blob, err := SignRevocation(priv, sub, now.Add(-time.Minute).Unix(), horizon)
	must.NoError(t, err)
	gotSub, gotHorizon, err := VerifyRevocation([]ed25519.PublicKey{pub}, blob, now)
	must.NoError(t, err)
	must.True(t, bytes.Equal(sub, gotSub), must.Sprint("revocation names the revoked node key"))
	must.EqOp(t, horizon, gotHorizon)
}

func TestRevocation_PastHorizonStillVerifies(t *testing.T) {
	// NotAfter is the reap horizon, not an expiry: a revocation past horizon must keep verifying so it
	// can propagate until every node reaps it. Dropping it on receive would re-admit the revoked key.
	priv, pub, sub := newSigner(t)
	now := time.Now()
	blob, err := SignRevocation(priv, sub, now.Add(-2*time.Hour).Unix(), now.Add(-time.Hour).Unix())
	must.NoError(t, err)
	_, horizon, err := VerifyRevocation([]ed25519.PublicKey{pub}, blob, now)
	must.NoError(t, err, must.Sprint("a past-horizon revocation still verifies"))
	must.EqOp(t, now.Add(-time.Hour).Unix(), horizon)
}

func TestRevocation_Rejections(t *testing.T) {
	priv, pub, sub := newSigner(t)
	now := time.Now()
	blob, err := SignRevocation(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix())
	must.NoError(t, err)

	otherPub, _, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	_, _, err = VerifyRevocation([]ed25519.PublicKey{otherPub}, blob, now)
	must.ErrorContains(t, err, "unknown signer")

	tampered := bytes.Clone(blob)
	tampered[len(tampered)-1] ^= 0xff
	_, _, err = VerifyRevocation([]ed25519.PublicKey{pub}, tampered, now)
	must.ErrorContains(t, err, "bad signature")

	future := mint(t, priv, claims{Sub: sub, NotBefore: now.Add(time.Hour).Unix(), NotAfter: now.Add(2 * time.Hour).Unix()}, revocationDomain)
	_, _, err = VerifyRevocation([]ed25519.PublicKey{pub}, future, now)
	must.ErrorContains(t, err, "not yet valid")
}

func TestSignRevocation_RequiresHorizon(t *testing.T) {
	priv, _, sub := newSigner(t)
	_, err := SignRevocation(priv, sub, time.Now().Unix(), 0)
	must.ErrorContains(t, err, "horizon", must.Sprint("a revocation must carry a reap horizon so the tombstone is bounded"))
}

func TestDomainSeparation(t *testing.T) {
	// The distinct domain is what stops a grant blob from replaying as a revocation of the same key,
	// and vice versa. Without it, a valid grant for X would double as "revoke X".
	priv, pub, sub := newSigner(t)
	signers := []ed25519.PublicKey{pub}
	now := time.Now()

	grant, err := Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix())
	must.NoError(t, err)
	revocation, err := SignRevocation(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix())
	must.NoError(t, err)

	_, _, err = VerifyRevocation(signers, grant, now)
	must.ErrorContains(t, err, "wrong signature domain", must.Sprint("a grant blob does not verify as a revocation"))
	_, err = Verify(signers, testKey, revocation, now)
	must.ErrorContains(t, err, "wrong signature domain", must.Sprint("a revocation blob does not verify as a grant"))
}
