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

// notAfter 0 = no expiry. A route grant must carry an expiry: route capability narrows only by lapsing.
func Sign(key ed25519.PrivateKey, sub []byte, notBefore, notAfter int64, routes ...netip.Prefix) ([]byte, error) {
	if len(routes) > 0 && notAfter == 0 {
		return nil, errors.New("a route grant must carry an expiry")
	}
	encRoutes, err := encodeRoutes(routes)
	if err != nil {
		return nil, err
	}
	return signClaims(key, claims{Sub: sub, NotBefore: notBefore, NotAfter: notAfter, Routes: encRoutes})
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

func signClaims(key ed25519.PrivateKey, c claims) ([]byte, error) {
	c.Ctx = domain
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

// Routes are decoded only after the signature passes, so an unauthenticated reader never obtains them.
func Verify(signers []ed25519.PublicKey, pubkey string, blob []byte, now time.Time) (Grant, error) {
	s, err := parse(blob)
	if err != nil {
		return Grant{}, err
	}
	if err := s.verify(signers, pubkey, now); err != nil {
		return Grant{}, err
	}
	// verified above, so claims are authenticated; a route grant must carry an expiry.
	if len(s.Claims.Routes) > 0 && s.Claims.NotAfter == 0 {
		return Grant{}, errors.New("route grant must carry an expiry")
	}
	routes, err := decodeRoutes(s.Claims.Routes)
	if err != nil {
		return Grant{}, err
	}
	return Grant{Sub: s.Claims.Sub, NotAfter: s.Claims.NotAfter, Routes: routes}, nil
}

func (s signedClaims) verify(signers []ed25519.PublicKey, pubkey string, now time.Time) error {
	if s.Claims.Ctx != domain {
		return errors.New("wrong signature domain")
	}
	var signer ed25519.PublicKey
	for _, k := range signers {
		if bytes.Equal(k, s.Claims.KeyID) {
			signer = k
			break
		}
	}
	if signer == nil {
		return errors.New("unknown signer")
	}
	body, err := enc.Marshal(s.Claims)
	if err != nil {
		return err
	}
	if len(s.Sig) != ed25519.SignatureSize || !ed25519.Verify(signer, body, s.Sig) {
		return errors.New("bad signature")
	}
	sub, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil || !bytes.Equal(sub, s.Claims.Sub) {
		return errors.New("signature not for this node key")
	}
	switch ts := now.Unix(); {
	case ts < s.Claims.NotBefore:
		return errors.New("signature not yet valid")
	case s.Claims.NotAfter != 0 && ts >= s.Claims.NotAfter:
		return errors.New("signature expired")
	}
	return nil
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
