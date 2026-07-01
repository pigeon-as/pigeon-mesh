//go:build linux

package mesh

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-msgpack/v2/codec"
	"github.com/hashicorp/memberlist"
	"github.com/pigeon-as/pigeon-mesh/internal/signature"
)

var errRevoked = errors.New("revoked")

// revokeReapSkew keeps a tombstone past its horizon so a laggard clock cannot still serve the near-dead grant.
const revokeReapSkew = time.Minute

// revocation is a verified anti-grant: the raw signed blob (re-shipped over gossip) and its reap horizon.
type revocation struct {
	blob    []byte
	horizon int64
}

// LoadRevoked reads a file of base64 anti-grants, verifies each against signers, and keys them by the
// revoked node pubkey. The file is the config-managed completeness floor (serf's keyring pattern: the
// authoritative copy is on disk; gossip is the fast layer on top).
func LoadRevoked(path string, signers []ed25519.PublicKey, now time.Time) (map[string]revocation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseRevoked(strings.Split(string(data), "\n"), signers, now)
}

// parseRevoked is strict: a malformed or unverifiable line fails the whole load, so a config mistake in
// the trusted floor is surfaced rather than silently dropping a revocation.
func parseRevoked(lines []string, signers []ed25519.PublicKey, now time.Time) (map[string]revocation, error) {
	out := map[string]revocation{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("revocation: %w", err)
		}
		key, rev, err := verifyRevocation(blob, signers, now)
		if err != nil {
			return nil, fmt.Errorf("revocation: %w", err)
		}
		setRevocation(out, key, rev)
	}
	return out, nil
}

func verifyRevocation(blob []byte, signers []ed25519.PublicKey, now time.Time) (string, revocation, error) {
	sub, horizon, err := signature.VerifyRevocation(signers, blob, now)
	if err != nil {
		return "", revocation{}, err
	}
	return base64.StdEncoding.EncodeToString(sub), revocation{blob: blob, horizon: horizon}, nil
}

// setRevocation adds rev under key if new or carrying a later horizon (grow-only; a later horizon wins).
func setRevocation(set map[string]revocation, key string, rev revocation) bool {
	if cur, ok := set[key]; ok && rev.horizon <= cur.horizon {
		return false
	}
	set[key] = rev
	return true
}

// mergeRevocations unions incoming into the revoked set under the mutation lock (copy-on-write so
// concurrent writers do not lose updates; readers stay lock-free), then reevaluates if anything changed.
func (m *Mesh) mergeRevocations(incoming map[string]revocation) bool {
	m.revokedMu.Lock()
	next := maps.Clone(*m.revoked.Load())
	changed := false
	for key, rev := range incoming {
		if setRevocation(next, key, rev) {
			changed = true
		}
	}
	if changed {
		m.revoked.Store(&next)
	}
	m.revokedMu.Unlock()
	if changed {
		m.reevaluate(time.Now())
	}
	return changed
}

// mergeRevocationBlobs verifies untrusted blobs (gossip or the socket) against the signer set and unions
// the valid ones. An unverifiable blob is dropped, not errored: the transport is untrusted.
func (m *Mesh) mergeRevocationBlobs(blobs [][]byte, now time.Time) bool {
	signers := *m.signers.Load()
	incoming := map[string]revocation{}
	for _, blob := range blobs {
		if key, rev, err := verifyRevocation(blob, signers, now); err == nil {
			setRevocation(incoming, key, rev)
		}
	}
	return m.mergeRevocations(incoming)
}

// reapRevocations drops tombstones whose horizon (plus skew) has passed; by then the revoked grant is
// itself expired, so the entry can never again flip an admission.
func (m *Mesh) reapRevocations(now time.Time) bool {
	skew := int64(revokeReapSkew / time.Second)
	m.revokedMu.Lock()
	defer m.revokedMu.Unlock()
	cur := *m.revoked.Load()
	var next map[string]revocation
	for key, rev := range cur {
		if now.Unix() >= rev.horizon+skew {
			if next == nil {
				next = maps.Clone(cur)
			}
			delete(next, key)
		}
	}
	if next == nil {
		return false
	}
	m.revoked.Store(&next)
	return true
}

func (m *Mesh) ReloadRevokedFromFile(path string) (int, error) {
	set, err := LoadRevoked(path, *m.signers.Load(), time.Now())
	if err != nil {
		return 0, err
	}
	m.mergeRevocations(set)
	return len(*m.revoked.Load()), nil
}

// Gossip carries revocations on two channels, mirroring serf's tombstone handling: push/pull anti-entropy
// (LocalState/MergeRemoteState) ships the whole set so a node that missed the broadcast still converges,
// and a TransmitLimitedQueue epidemically broadcasts a freshly learned one. A revocation never invalidates
// another (grow-only G-set), so each blob is a UniqueBroadcast.
type revocationBroadcast struct{ msg []byte }

func (*revocationBroadcast) Invalidates(memberlist.Broadcast) bool { return false }
func (*revocationBroadcast) UniqueBroadcast()                      {}
func (b *revocationBroadcast) Message() []byte                     { return b.msg }
func (*revocationBroadcast) Finished()                             {}

// queueRevocation enqueues a blob for epidemic broadcast. Called only on local origination (the socket
// verb) and on first receipt of a new one, never from push/pull: anti-entropy already self-heals.
func (m *Mesh) queueRevocation(blob []byte) {
	if m.revocationBroadcasts == nil {
		return
	}
	m.revocationBroadcasts.QueueBroadcast(&revocationBroadcast{msg: blob})
}

// handleRevocationMsg is the broadcast receive path (delegate.NotifyMsg): verify+merge a single blob, and
// if it is new to us, rebroadcast it onward (serf's rebroadcast). The buffer is copied since memberlist
// may reuse it, and the copy is what we store and re-ship.
func (m *Mesh) handleRevocationMsg(buf []byte) {
	if len(buf) == 0 {
		return
	}
	blob := bytes.Clone(buf)
	if m.mergeRevocationBlobs([][]byte{blob}, time.Now()) {
		m.queueRevocation(blob)
	}
}

// revocationState is the push/pull local state (delegate.LocalState): every current anti-grant blob, so a
// peer reconciles its set against ours each anti-entropy round.
func (m *Mesh) revocationState() []byte {
	cur := *m.revoked.Load()
	if len(cur) == 0 {
		return nil
	}
	blobs := make([][]byte, 0, len(cur))
	for _, rev := range cur {
		blobs = append(blobs, rev.blob)
	}
	var buf bytes.Buffer
	if err := codec.NewEncoder(&buf, msgpackHandle).Encode(blobs); err != nil {
		slog.Warn("encode revocation state", "err", err)
		return nil
	}
	return buf.Bytes()
}

// applyRevoke is the operator origination path (the socket revoke verb): verify the injected anti-grant
// against the signer set, surfacing a rejection to the operator (unlike the silent-drop gossip paths),
// merge it, and broadcast it onward if new.
func (m *Mesh) applyRevoke(b64 string) error {
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	key, rev, err := verifyRevocation(blob, *m.signers.Load(), time.Now())
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	if m.mergeRevocations(map[string]revocation{key: rev}) {
		m.queueRevocation(blob)
	}
	return nil
}

// mergeRevocationState is the push/pull merge path (delegate.MergeRemoteState): decode a peer's set and
// union the verifiable blobs. No rebroadcast: push/pull is itself the convergence mechanism.
func (m *Mesh) mergeRevocationState(buf []byte) {
	if len(buf) == 0 {
		return
	}
	var blobs [][]byte
	if err := codec.NewDecoder(bytes.NewReader(buf), msgpackHandle).Decode(&blobs); err != nil {
		slog.Warn("decode revocation state", "err", err)
		return
	}
	m.mergeRevocationBlobs(blobs, time.Now())
}
