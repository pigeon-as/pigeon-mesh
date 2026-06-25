// Package signature implements operator-signed admission grants: an operator signs a
// short-lived grant for a node's WireGuard public key; peers verify it against trusted
// signer keys. Pure functions of their inputs, no daemon state or lock.
package signature

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const domain = "wg-mesh-signature-v1"

type claims struct {
	Ctx       string `cbor:"1,keyasint"`
	Sub       []byte `cbor:"2,keyasint"`
	KeyID     []byte `cbor:"3,keyasint"`
	NotBefore int64  `cbor:"4,keyasint"`
	NotAfter  int64  `cbor:"5,keyasint"`
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

// Sign issues a grant for node key sub, valid in [notBefore, notAfter); notAfter 0 = no expiry.
func Sign(key ed25519.PrivateKey, sub []byte, notBefore, notAfter int64) ([]byte, error) {
	return signClaims(key, claims{Sub: sub, NotBefore: notBefore, NotAfter: notAfter})
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

// Verify checks a grant against the trusted signer keys for node pubkey at time now.
func Verify(signers []ed25519.PublicKey, pubkey string, blob []byte, now time.Time) error {
	s, err := parse(blob)
	if err != nil {
		return err
	}
	return s.verify(signers, pubkey, now)
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

// NotAfter returns a grant's expiry (unix seconds; 0 if absent or unparseable).
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

// SignerKey returns the grant's claimed signer key (embedded KeyID), so a node can trust
// whoever signed its own grant without a --signers flag. Unverified: caller must still Verify.
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
