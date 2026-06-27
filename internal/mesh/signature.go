//go:build linux

package mesh

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/pigeon-as/pigeon-mesh/internal/signature"
)

// Operator-grant admission gate: admitted peers must present a signed grant verifying against the
// pinned signer set. No open mode; signers always non-empty.

var errSignatureExpired = errors.New("signature expired")

// signatureError returns why a peer's grant is invalid, or nil if admitted.
func signatureError(p Peer, name string, signers []ed25519.PublicKey, now time.Time) error {
	if len(p.Signature) == 0 {
		return errors.New("no signature")
	}
	return signature.Verify(signers, name, p.Signature, now)
}

// selfSignatureError checks this node's own grant; self is not in the member table.
func selfSignatureError(self Peer, now time.Time) error {
	na := signature.NotAfter(self.Signature)
	if na != 0 && now.Unix() >= na {
		return errSignatureExpired
	}
	return nil
}

func (m *Mesh) ReloadSignersFromFile(path string) (int, error) {
	keys, err := signature.LoadSigners(path)
	if err != nil {
		return 0, err
	}
	m.signers.Store(&keys)
	m.reevaluate(time.Now())
	return len(keys), nil
}
