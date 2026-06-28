//go:build linux

package mesh

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/pigeon-as/pigeon-mesh/internal/signature"
)

// Operator-grant admission gate: admitted peers must present a signed grant verifying against the
// pinned signer set. No open mode; signers always non-empty.

var errSignatureExpired = errors.New("signature expired")

// verifyGrant returns the verified grant for a peer, or the reason it is not admitted.
func verifyGrant(p Peer, name string, signers []ed25519.PublicKey, now time.Time) (signature.Grant, error) {
	if len(p.Signature) == 0 {
		return signature.Grant{}, errors.New("no signature")
	}
	return signature.Verify(signers, name, p.Signature, now)
}

// selfSignatureError reports whether this node's own grant has expired (self is not in the member set).
func selfSignatureError(grant []byte, now time.Time) error {
	na := signature.NotAfter(grant)
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

// applySelfGrant verifies a freshly-read grant for this node and swaps it in as the advertised grant
// if it is valid and unexpired. It does not re-advertise (the caller does). Identity is pinned:
// Verify binds the grant to our own public key, from which the overlay address derives.
func (m *Mesh) applySelfGrant(grant []byte) error {
	g, err := signature.Verify(*m.signers.Load(), m.cfg.Self.PublicKey, grant, time.Now())
	if err != nil {
		return fmt.Errorf("grant rejected: %w", err)
	}
	if err := CheckSelfRoutes(m.cfg.Self.AllowedIPs, m.selfAddr, g.Routes); err != nil {
		return fmt.Errorf("self grant: %w; re-sign with --route", err)
	}
	self := m.cfg.Self
	self.Signature = grant
	meta, err := encodeMeta(self)
	if err != nil {
		return err
	}
	if len(meta) > memberlist.MetaMaxSize {
		return fmt.Errorf("encoded self meta %d bytes exceeds limit %d", len(meta), memberlist.MetaMaxSize)
	}
	m.meta.Store(&meta)
	m.selfGrant.Store(&grant)
	m.selfExpired.Store(false)
	return nil
}

// ReloadSignatureFromFile re-reads this node's grant from path and, if it verifies, re-advertises it
// over gossip. Hitless: no restart, and no tunnel teardown (the WireGuard key is unchanged). An
// invalid or expired grant is rejected and the running grant is kept.
func (m *Mesh) ReloadSignatureFromFile(path string) error {
	grant, err := signature.LoadSignature(path)
	if err != nil {
		return err
	}
	if err := m.applySelfGrant(grant); err != nil {
		return err
	}
	if err := m.memberlist.UpdateNode(grantUpdateTimeout); err != nil {
		slog.Warn("re-advertise renewed grant", "err", err)
	}
	return nil
}
