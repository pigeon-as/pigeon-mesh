package mesh

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const sigContext = "wg-mesh-signature-v1"

type sigClaims struct {
	Ctx       string `cbor:"1,keyasint"`
	Sub       []byte `cbor:"2,keyasint"`
	KeyID     []byte `cbor:"3,keyasint"`
	NotBefore int64  `cbor:"4,keyasint"`
	NotAfter  int64  `cbor:"5,keyasint"`
	Nonce     []byte `cbor:"6,keyasint,omitempty"`
}

type signedSig struct {
	Claims sigClaims `cbor:"1,keyasint"`
	Sig    []byte    `cbor:"2,keyasint"`
}

var sigEnc = mustSigEnc()
var sigDec = mustSigDec()

func mustSigEnc() cbor.EncMode {
	em, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return em
}

func mustSigDec() cbor.DecMode {
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

func Sign(key ed25519.PrivateKey, sub []byte, notBefore, notAfter int64) ([]byte, error) {
	return signClaims(key, sigClaims{Sub: sub, NotBefore: notBefore, NotAfter: notAfter})
}

func signClaims(key ed25519.PrivateKey, c sigClaims) ([]byte, error) {
	c.Ctx = sigContext
	c.KeyID = key.Public().(ed25519.PublicKey)
	body, err := sigEnc.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("encode signature: %w", err)
	}
	return sigEnc.Marshal(signedSig{Claims: c, Sig: ed25519.Sign(key, body)})
}

func parseSignedSig(b []byte) (signedSig, error) {
	var s signedSig
	if err := sigDec.Unmarshal(b, &s); err != nil {
		return signedSig{}, fmt.Errorf("decode signature: %w", err)
	}
	return s, nil
}

func VerifySignature(signers []ed25519.PublicKey, pubkey string, blob []byte, now time.Time) error {
	s, err := parseSignedSig(blob)
	if err != nil {
		return err
	}
	return s.verify(signers, pubkey, now)
}

func (s signedSig) verify(signers []ed25519.PublicKey, pubkey string, now time.Time) error {
	if s.Claims.Ctx != sigContext {
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
	body, err := sigEnc.Marshal(s.Claims)
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

func signatureNotAfter(blob []byte) int64 {
	if len(blob) == 0 {
		return 0
	}
	s, err := parseSignedSig(blob)
	if err != nil {
		return 0
	}
	return s.Claims.NotAfter
}

func ParseSigners(spec string) ([]ed25519.PublicKey, error) {
	if path, ok := strings.CutPrefix(spec, "@"); ok {
		return LoadSigners(path)
	}
	var keys []ed25519.PublicKey
	for _, s := range strings.Split(spec, ",") {
		k, err := parseSignerKey(s)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, errors.New("no signer keys")
	}
	return keys, nil
}

func LoadSigners(path string) ([]ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := parseSignerKey(line)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, errors.New("no signer keys in file")
	}
	return keys, nil
}

func parseSignerKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("signer key %q: %w", s, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signer key %q: want %d bytes, got %d", s, ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func LoadSignature(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("signature file is empty")
	}
	if _, err := parseSignedSig(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
