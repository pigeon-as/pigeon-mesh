package signature

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	domain           = "wg-mesh-signature-v1"
	revocationDomain = "wg-mesh-revocation-v1"
)

type claims struct {
	Ctx       string   `cbor:"1,keyasint"`
	Sub       []byte   `cbor:"2,keyasint"`
	KeyID     []byte   `cbor:"3,keyasint"`
	NotBefore int64    `cbor:"4,keyasint"`
	NotAfter  int64    `cbor:"5,keyasint"`
	Routes    [][]byte `cbor:"6,keyasint,omitempty"` // transit CIDRs as Prefix.MarshalBinary
}

type Grant struct {
	Sub      []byte
	NotAfter int64
	Routes   []netip.Prefix
}

type signedClaims struct {
	Claims claims `cbor:"1,keyasint"`
	Sig    []byte `cbor:"2,keyasint"`
}

var (
	enc = mustEnc()
	dec = mustDec()
)

func mustEnc() cbor.EncMode {
	em, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return em
}

func mustDec() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DupMapKey:       cbor.DupMapKeyEnforcedAPF,
		IndefLength:     cbor.IndefLengthForbidden,
		TagsMd:          cbor.TagsForbidden,
		MaxNestedLevels: 4,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}

// Every grant carries an expiry; both passive de-authorization and the revocation reap horizon are bounded by it.
func Sign(key ed25519.PrivateKey, sub []byte, notBefore, notAfter int64, routes ...netip.Prefix) ([]byte, error) {
	if notAfter == 0 {
		return nil, errors.New("a grant must carry an expiry")
	}
	encRoutes, err := encodeRoutes(routes)
	if err != nil {
		return nil, err
	}
	return signClaims(key, claims{Sub: sub, NotBefore: notBefore, NotAfter: notAfter, Routes: encRoutes}, domain)
}

// SignRevocation signs an anti-grant: a terminal statement that the grant for sub is dead. notAfter is
// the reap horizon (the revoked grant's expiry); required so the tombstone is bounded.
func SignRevocation(key ed25519.PrivateKey, sub []byte, notBefore, notAfter int64) ([]byte, error) {
	if notAfter == 0 {
		return nil, errors.New("a revocation must carry a reap horizon")
	}
	return signClaims(key, claims{Sub: sub, NotBefore: notBefore, NotAfter: notAfter}, revocationDomain)
}

// Canonical (masked, deduped, bytewise-sorted) so the signed body is stable regardless of input order.
func encodeRoutes(routes []netip.Prefix) ([][]byte, error) {
	if len(routes) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(routes))
	out := make([][]byte, 0, len(routes))
	for _, r := range routes {
		b, err := r.Masked().MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", r, err)
		}
		if seen[string(b)] {
			continue
		}
		seen[string(b)] = true
		out = append(out, b)
	}
	slices.SortFunc(out, bytes.Compare)
	return out, nil
}

func decodeRoutes(raw [][]byte) ([]netip.Prefix, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, b := range raw {
		var p netip.Prefix
		if err := p.UnmarshalBinary(b); err != nil {
			return nil, fmt.Errorf("decode route: %w", err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func signClaims(key ed25519.PrivateKey, c claims, dom string) ([]byte, error) {
	c.Ctx = dom
	c.KeyID = key.Public().(ed25519.PublicKey)
	body, err := enc.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("encode signature: %w", err)
	}
	return enc.Marshal(signedClaims{Claims: c, Sig: ed25519.Sign(key, body)})
}

func parse(b []byte) (signedClaims, error) {
	var s signedClaims
	if err := dec.Unmarshal(b, &s); err != nil {
		return signedClaims{}, fmt.Errorf("decode signature: %w", err)
	}
	return s, nil
}

// Verify returns the grant only if signed by a trusted signer, bound to node pubkey, carrying an
// expiry, and unexpired. Routes are decoded only after the signature passes, so an unauthenticated
// reader never obtains them.
func Verify(signers []ed25519.PublicKey, pubkey string, blob []byte, now time.Time) (Grant, error) {
	c, err := verifySig(signers, blob, domain, now, true)
	if err != nil {
		return Grant{}, err
	}
	sub, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil || !bytes.Equal(sub, c.Sub) {
		return Grant{}, errors.New("signature not for this node key")
	}
	if c.NotAfter == 0 {
		return Grant{}, errors.New("grant must carry an expiry")
	}
	if now.Unix() >= c.NotAfter {
		return Grant{}, errors.New("signature expired")
	}
	routes, err := decodeRoutes(c.Routes)
	if err != nil {
		return Grant{}, err
	}
	return Grant{Sub: c.Sub, NotAfter: c.NotAfter, Routes: routes}, nil
}

// VerifyRevocation returns the revoked node key and reap horizon from an anti-grant. A revocation is a
// terminal fact, accepted on receipt regardless of the receiver's clock: NotBefore is not enforced (a
// time-behind or clock-skewed node must still honor it, else it fails open), and NotAfter is the reap
// horizon, not a reject (a past-horizon revocation still propagates until every node reaps it).
func VerifyRevocation(signers []ed25519.PublicKey, blob []byte, now time.Time) (sub []byte, horizon int64, err error) {
	c, err := verifySig(signers, blob, revocationDomain, now, false)
	if err != nil {
		return nil, 0, err
	}
	return c.Sub, c.NotAfter, nil
}

// verifySig checks domain, signer-set membership, and signature, returning the authenticated claims. The
// distinct domain stops a grant blob replaying as a revocation. NotBefore is enforced only for grants
// (enforceNotBefore); a revocation carries no valid-from window since it applies the moment it is seen.
func verifySig(signers []ed25519.PublicKey, blob []byte, dom string, now time.Time, enforceNotBefore bool) (claims, error) {
	s, err := parse(blob)
	if err != nil {
		return claims{}, err
	}
	if s.Claims.Ctx != dom {
		return claims{}, errors.New("wrong signature domain")
	}
	var signer ed25519.PublicKey
	for _, k := range signers {
		if bytes.Equal(k, s.Claims.KeyID) {
			signer = k
			break
		}
	}
	if signer == nil {
		return claims{}, errors.New("unknown signer")
	}
	body, err := enc.Marshal(s.Claims)
	if err != nil {
		return claims{}, err
	}
	if len(s.Sig) != ed25519.SignatureSize || !ed25519.Verify(signer, body, s.Sig) {
		return claims{}, errors.New("bad signature")
	}
	if enforceNotBefore && now.Unix() < s.Claims.NotBefore {
		return claims{}, errors.New("signature not yet valid")
	}
	return s.Claims, nil
}

// grant expiry in unix seconds; 0 if absent or unparseable.
func NotAfter(blob []byte) int64 {
	if len(blob) == 0 {
		return 0
	}
	s, err := parse(blob)
	if err != nil {
		return 0
	}
	return s.Claims.NotAfter
}

// The grant's subject (the node key it authorizes); unverified, used by sign-revocation to derive the
// anti-grant's subject and reap horizon, which it then re-signs under the operator's own key.
func Subject(blob []byte) ([]byte, error) {
	s, err := parse(blob)
	if err != nil {
		return nil, err
	}
	if len(s.Claims.Sub) != ed25519.PublicKeySize {
		return nil, errors.New("grant has no subject key")
	}
	return s.Claims.Sub, nil
}

// The grant's claimed (unverified) signer key; caller must still Verify.
func SignerKey(blob []byte) (ed25519.PublicKey, error) {
	s, err := parse(blob)
	if err != nil {
		return nil, err
	}
	if len(s.Claims.KeyID) != ed25519.PublicKeySize {
		return nil, errors.New("grant has no signer key")
	}
	return ed25519.PublicKey(s.Claims.KeyID), nil
}
