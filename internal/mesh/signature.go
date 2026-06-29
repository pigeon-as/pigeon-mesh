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

// no open mode; signers always non-empty.

var errSignatureExpired = errors.New("signature expired")

func verifyGrant(p Peer, name string, signers []ed25519.PublicKey, now time.Time) (signature.Grant, error) {
	if len(p.Signature) == 0 {
		return signature.Grant{}, errors.New("no signature")
	}
	return signature.Verify(signers, name, p.Signature, now)
}

func (m *Mesh) selfGrantExpiry() int64 {
	return signature.NotAfter(*m.selfGrant.Load())
}

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

// identity pinned: Verify binds the grant to our own key.
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

// hitless: WireGuard key unchanged, so no tunnel teardown.
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
