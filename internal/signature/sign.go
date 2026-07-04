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

const domain = "wg-mesh-signature-v1"

type claims struct {
	Ctx       string   `cbor:"1,keyasint"`
	Sub       []byte   `cbor:"2,keyasint"`
	KeyID     []byte   `cbor:"3,keyasint"`
	NotBefore int64    `cbor:"4,keyasint"`
	NotAfter  int64    `cbor:"5,keyasint"`
	Routes    [][]byte `cbor:"6,keyasint,omitempty"` // transit CIDRs as Prefix.MarshalBinary
	Name      string   `cbor:"7,keyasint,omitempty"` // operator-attested DNS name
}

type Grant struct {
	Sub      []byte
	NotAfter int64
	Routes   []netip.Prefix
	Name     string
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

// Every grant carries an expiry so passive de-authorization is bounded without an explicit denylist entry.
func Sign(key ed25519.PrivateKey, sub []byte, notBefore, notAfter int64, name string, routes ...netip.Prefix) ([]byte, error) {
	if notAfter == 0 {
		return nil, errors.New("a grant must carry an expiry")
	}
	encRoutes, err := encodeRoutes(routes)
	if err != nil {
		return nil, err
	}
	return signClaims(key, claims{Sub: sub, NotBefore: notBefore, NotAfter: notAfter, Routes: encRoutes, Name: name}, domain)
}

// SigningBody builds a grant's to-be-signed body for an external signer (e.g. Vault Transit) that holds
// pubkey. The bytes are signed as-is with pure ed25519; pass the signature to Attach. This is the seam
// for sign-as-a-service: the operator key never has to leave the vault.
func SigningBody(pubkey ed25519.PublicKey, sub []byte, notBefore, notAfter int64, name string, routes ...netip.Prefix) ([]byte, error) {
	if notAfter == 0 {
		return nil, errors.New("a grant must carry an expiry")
	}
	encRoutes, err := encodeRoutes(routes)
	if err != nil {
		return nil, err
	}
	c := claims{Ctx: domain, Sub: sub, KeyID: pubkey, NotBefore: notBefore, NotAfter: notAfter, Routes: encRoutes, Name: name}
	return enc.Marshal(c)
}

// Attach wraps an external signature over a SigningBody into the finished grant, after checking the body
// is canonical and the signature verifies against the signer key named in it.
func Attach(body, sig []byte) ([]byte, error) {
	var c claims
	if err := dec.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("decode signing body: %w", err)
	}
	if len(c.KeyID) != ed25519.PublicKeySize {
		return nil, errors.New("signing body carries no signer key")
	}
	// The daemon verifies the canonical re-encoding of decoded claims, so a non-canonical body would sign
	// here yet fail at every daemon. Reject it now, at the source, rather than far from the cause.
	canon, err := enc.Marshal(c)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canon, body) {
		return nil, errors.New("signing body is not canonical; regenerate it with sign --pubkey")
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(c.KeyID), body, sig) {
		return nil, errors.New("signature does not verify against the signing body")
	}
	return enc.Marshal(signedClaims{Claims: c, Sig: sig})
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

// ErrMalformed marks a blob that could not be decoded at all, distinct from one that decodes but does
// not verify (unknown signer or bad signature). Callers can fail closed on the former (corruption) and
// tolerate the latter (an inert, untrusted blob).
var ErrMalformed = errors.New("malformed signature blob")

func parse(b []byte) (signedClaims, error) {
	var s signedClaims
	if err := dec.Unmarshal(b, &s); err != nil {
		return signedClaims{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return s, nil
}

// Verify returns the grant only if signed by a trusted signer, bound to node pubkey, carrying an
// expiry, and unexpired. Routes are decoded only after the signature passes, so an unauthenticated
// reader never obtains them.
func Verify(signers []ed25519.PublicKey, pubkey string, blob []byte, now time.Time) (Grant, error) {
	c, err := verifySig(signers, blob, domain)
	if err != nil {
		return Grant{}, err
	}
	if now.Unix() < c.NotBefore {
		return Grant{}, errors.New("signature not yet valid")
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
	return Grant{Sub: c.Sub, NotAfter: c.NotAfter, Routes: routes, Name: c.Name}, nil
}

// verifySig checks domain, signer-set membership, and signature, returning the authenticated claims.
// Time policy is the caller's: Verify gates a grant on NotBefore/NotAfter.
func verifySig(signers []ed25519.PublicKey, blob []byte, dom string) (claims, error) {
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

// The grant's signed DNS name; "" if absent or unparseable. Unverified accessor: a node reads its own
// already-verified grant, and peers get the name from Verify.
func Name(blob []byte) string {
	s, err := parse(blob)
	if err != nil {
		return ""
	}
	return s.Claims.Name
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
