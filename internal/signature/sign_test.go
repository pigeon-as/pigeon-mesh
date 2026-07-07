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

// mint hand-signs arbitrary claims under a chosen domain, for crafting blobs Sign would refuse.
func mint(t *testing.T, priv ed25519.PrivateKey, c claims, dom string) []byte {
	t.Helper()
	blob, err := signClaims(priv, c, dom)
	must.NoError(t, err)
	return blob
}

func TestAttach_RejectsNonCanonicalBody(t *testing.T) {
	priv, pub, sub := newSigner(t)
	body, err := SigningBody(pub, sub, time.Now().Add(-time.Minute).Unix(), time.Now().Add(time.Hour).Unix(), GrantClaims{Name: "web01"})
	must.NoError(t, err)
	if _, err := Attach(body, ed25519.Sign(priv, body)); err != nil {
		t.Fatalf("a canonical SigningBody must attach: %v", err)
	}
	// A body with trailing bytes is non-canonical; Attach must reject it at the source rather than let
	// it fail far away at every daemon's Verify.
	mangled := append(append([]byte{}, body...), 0x00)
	_, err = Attach(mangled, ed25519.Sign(priv, mangled))
	must.Error(t, err, must.Sprint("a non-canonical body is rejected at attach time"))
}

func TestSignerKey(t *testing.T) {
	priv, pub, sub := newSigner(t)
	blob, err := Sign(priv, sub, time.Now().Add(-time.Minute).Unix(), time.Now().Add(time.Hour).Unix(), GrantClaims{})
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
	blob, err := Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), GrantClaims{})
	must.NoError(t, err)
	g, err := Verify([]ed25519.PublicKey{pub}, testKey, blob, now)
	must.NoError(t, err)
	must.EqOp(t, now.Add(time.Hour).Unix(), g.NotAfter)
}

func TestVerify_Name(t *testing.T) {
	priv, pub, sub := newSigner(t)
	now := time.Now()
	blob, err := Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), GrantClaims{Name: "alpha"})
	must.NoError(t, err)

	g, err := Verify([]ed25519.PublicKey{pub}, testKey, blob, now)
	must.NoError(t, err)
	must.EqOp(t, "alpha", g.Name, must.Sprint("the signed name round-trips through Verify"))
	must.EqOp(t, "alpha", Name(blob), must.Sprint("the Name accessor reads the signed name"))

	// the name is signed, so an admitted node cannot forge it: tampering breaks the signature.
	s, err := parse(blob)
	must.NoError(t, err)
	s.Claims.Name = "impostor"
	tampered, err := enc.Marshal(s)
	must.NoError(t, err)
	_, err = Verify([]ed25519.PublicKey{pub}, testKey, tampered, now)
	must.ErrorContains(t, err, "bad signature", must.Sprint("forging the name is rejected"))
}

func TestVerify_Endpoint(t *testing.T) {
	priv, pub, sub := newSigner(t)
	now := time.Now()
	blob, err := Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), GrantClaims{Endpoint: "203.0.113.7:51820"})
	must.NoError(t, err)

	g, err := Verify([]ed25519.PublicKey{pub}, testKey, blob, now)
	must.NoError(t, err)
	must.EqOp(t, "203.0.113.7:51820", g.Endpoint, must.Sprint("the signed endpoint round-trips through Verify"))
	must.EqOp(t, "203.0.113.7:51820", GrantEndpoint(blob), must.Sprint("the GrantEndpoint accessor reads the signed endpoint"))

	// the endpoint is signed, so a peer cannot redirect a node's tunnel: tampering breaks the signature.
	s, err := parse(blob)
	must.NoError(t, err)
	s.Claims.Endpoint = "198.51.100.1:51820"
	tampered, err := enc.Marshal(s)
	must.NoError(t, err)
	_, err = Verify([]ed25519.PublicKey{pub}, testKey, tampered, now)
	must.ErrorContains(t, err, "bad signature", must.Sprint("forging the endpoint is rejected"))
}

func TestVerify_Tags(t *testing.T) {
	priv, pub, sub := newSigner(t)
	now := time.Now()
	tags := map[string]string{"role": "db", "region": "eu"}
	blob, err := Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), GrantClaims{Tags: tags})
	must.NoError(t, err)

	g, err := Verify([]ed25519.PublicKey{pub}, testKey, blob, now)
	must.NoError(t, err)
	must.MapEq(t, tags, g.Tags, must.Sprint("signed tags round-trip through Verify"))
	must.MapEq(t, tags, GrantTags(blob), must.Sprint("the GrantTags accessor reads the signed tags"))

	// tags are signed, so an admitted node cannot forge them: tampering breaks the signature.
	s, err := parse(blob)
	must.NoError(t, err)
	s.Claims.Tags["role"] = "admin"
	tampered, err := enc.Marshal(s)
	must.NoError(t, err)
	_, err = Verify([]ed25519.PublicKey{pub}, testKey, tampered, now)
	must.ErrorContains(t, err, "bad signature", must.Sprint("forging a tag is rejected"))
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

	// a grant minted under a different domain must not verify as a grant
	_, err = Verify(signers, testKey, mint(t, priv, good(), "wg-mesh-other-v1"), now)
	must.ErrorContains(t, err, "wrong signature domain")
}

func TestVerify_RequiresExpiry(t *testing.T) {
	priv, pub, sub := newSigner(t)
	now := time.Now()

	_, err := Sign(priv, sub, now.Add(-time.Minute).Unix(), 0, GrantClaims{})
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
	blob, err := Sign(priv, sub, nb, na, GrantClaims{})
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
	blob, err := Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), GrantClaims{Routes: []netip.Prefix{r2, r1, r1}})
	must.NoError(t, err)
	g, err := Verify(signers, testKey, blob, now)
	must.NoError(t, err)
	must.Eq(t, []netip.Prefix{r1, r2}, g.Routes, must.Sprint("routes are masked, deduped, and sorted"))
}

func TestDetachedSigning(t *testing.T) {
	priv, pub, sub := newSigner(t)
	now := time.Now()

	// emit the to-be-signed body for an external signer holding pub, sign it as-is (pure ed25519, as
	// Vault Transit does), and assemble: the result must verify exactly like a locally-signed grant.
	body, err := SigningBody(pub, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), GrantClaims{Name: "alpha", Routes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	must.NoError(t, err)
	grant, err := Attach(body, ed25519.Sign(priv, body))
	must.NoError(t, err)
	g, err := Verify([]ed25519.PublicKey{pub}, testKey, grant, now)
	must.NoError(t, err)
	must.EqOp(t, "alpha", g.Name)
	must.Eq(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, g.Routes)

	// Attach rejects a signature that does not match the signer key named in the body.
	otherPriv, _, _ := newSigner(t)
	_, err = Attach(body, ed25519.Sign(otherPriv, body))
	must.ErrorContains(t, err, "does not verify")
}

func TestVerifyRoutes_TamperBreaksSignature(t *testing.T) {
	priv, pub, sub := newSigner(t)
	signers := []ed25519.PublicKey{pub}
	now := time.Now()
	blob, err := Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), GrantClaims{Routes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
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
	blob, err := Sign(priv, sub, 1_000, 2_000, GrantClaims{})
	must.NoError(t, err)
	must.EqOp(t, int64(2_000), NotAfter(blob))
	must.EqOp(t, int64(0), NotAfter([]byte{0, 1, 2}), must.Sprint("garbage is not read as expiry"))
	must.EqOp(t, int64(0), NotAfter(nil))
}
