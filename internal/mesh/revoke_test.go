//go:build linux

package mesh

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/pigeon-as/pigeon-mesh/internal/signature"
	"github.com/shoenig/test/must"
)

func withBroadcastQueue(m *Mesh) {
	m.revocationBroadcasts = &memberlist.TransmitLimitedQueue{
		NumNodes:       func() int { return 1 },
		RetransmitMult: 4,
	}
}

// revokedSetup mints a signer, an admittable advertisement for testKey, and a signed revocation of it.
func revokedSetup(t *testing.T, now time.Time) (signers []ed25519.PublicKey, peer Peer, antiGrant []byte) {
	t.Helper()
	priv, pub, sub := mkSig(t)
	derived, err := DeriveAddr(testKey, testPrefix)
	must.NoError(t, err)
	grant, err := signature.Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix())
	must.NoError(t, err)
	antiGrant, err = signature.SignRevocation(priv, sub, now.Add(time.Hour).Unix())
	must.NoError(t, err)
	peer = Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{HostRoute(derived).String()}, Signature: grant}
	return []ed25519.PublicKey{pub}, peer, antiGrant
}

func TestAdmit_Revoked(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	signers, peer, _ := revokedSetup(t, now)
	// a valid grant is still rejected: the revoked gate sits before verifyGrant, so it overrides admission.
	revoked := map[string]revocation{testKey: {horizon: now.Add(time.Hour).Unix()}}
	r := admit(peer, testKey, signers, revoked, testPrefix, nil, now)
	must.ErrorIs(t, r.admitErr, errRevoked)
	must.False(t, r.admitted())
	must.SliceEmpty(t, r.wgPeer.routes, must.Sprint("a revoked peer installs nothing, identity /128 included"))
}

func TestReevaluate_RevokedEvicts(t *testing.T) {
	now := time.Now() // mergeRevocations/reevaluate read time.Now() internally
	signers, peer, antiGrant := revokedSetup(t, now)
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, signers, nil)
	m.members[testKey] = member{
		peer:   peer,
		wgPeer: wgPeer{key: testKey, endpoint: peer.Endpoint, routes: peer.AllowedIPs},
		meta:   []byte("m"),
	}
	must.True(t, m.mergeRevocationBlobs([][]byte{antiGrant}), must.Sprint("a fresh revocation changes the set"))
	got := m.members[testKey]
	must.False(t, got.admitted(), must.Sprint("a revoked member is no longer admitted"))
	must.SliceEmpty(t, got.wgPeer.routes, must.Sprint("a revoked member installs nothing, so reconcile removes its kernel peer"))
}

func TestMergeRevocationBlobs_DropsUnverifiable(t *testing.T) {
	now := time.Now()
	signers, _, antiGrant := revokedSetup(t, now)
	m := newTestMesh()
	storeConfig(m, signers, nil)

	// the gossip transport is untrusted: garbage and wrong-signer blobs are dropped, never merged.
	must.False(t, m.mergeRevocationBlobs([][]byte{{0, 1, 2}}), must.Sprint("garbage does not enter the set"))
	must.MapLen(t, 0, *m.revoked.Load())

	otherPriv, _, sub := mkSig(t)
	wrong, err := signature.SignRevocation(otherPriv, sub, now.Add(time.Hour).Unix())
	must.NoError(t, err)
	must.False(t, m.mergeRevocationBlobs([][]byte{wrong}), must.Sprint("a wrong-signer revocation is dropped"))
	must.MapLen(t, 0, *m.revoked.Load())

	// the genuine one merges, and re-merging it is a no-op (grow-only).
	must.True(t, m.mergeRevocationBlobs([][]byte{antiGrant}))
	must.MapLen(t, 1, *m.revoked.Load())
	must.False(t, m.mergeRevocationBlobs([][]byte{antiGrant}), must.Sprint("re-merging an existing revocation is a no-op"))
}

func TestReapRevocations(t *testing.T) {
	now := time.Now()
	m := newTestMesh()
	set := map[string]revocation{
		"live":  {horizon: now.Add(time.Hour).Unix()},
		"stale": {horizon: now.Add(-2 * revokeReapSkew).Unix()},
	}
	m.revoked.Store(&set)

	must.True(t, m.reapRevocations(now), must.Sprint("a tombstone past horizon+skew is reaped"))
	got := *m.revoked.Load()
	_, liveOK := got["live"]
	_, staleOK := got["stale"]
	must.True(t, liveOK, must.Sprint("a tombstone before its horizon is kept"))
	must.False(t, staleOK, must.Sprint("the past-horizon tombstone is gone"))
	must.False(t, m.reapRevocations(now), must.Sprint("nothing to reap is no change"))
}

func TestLoadRevoked(t *testing.T) {
	now := time.Now()
	signers, _, antiGrant := revokedSetup(t, now)
	dir := t.TempDir()

	path := filepath.Join(dir, "revoked")
	content := "# operator blocklist\n\n" + base64.StdEncoding.EncodeToString(antiGrant) + "\n"
	must.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	set, err := LoadRevoked(path, signers)
	must.NoError(t, err)
	must.MapLen(t, 1, set, must.Sprint("the floor loads the revocation, skipping comments and blanks"))
	_, ok := set[testKey]
	must.True(t, ok)

	// the file is the trusted floor: a malformed or unverifiable line fails the whole load (no silent hole).
	bad := filepath.Join(dir, "bad")
	must.NoError(t, os.WriteFile(bad, []byte("not-base64!\n"), 0o600))
	_, err = LoadRevoked(bad, signers)
	must.Error(t, err, must.Sprint("a malformed line fails the load"))

	wrong := filepath.Join(dir, "wrong")
	otherPriv, _, sub := mkSig(t)
	w, err := signature.SignRevocation(otherPriv, sub, now.Add(time.Hour).Unix())
	must.NoError(t, err)
	must.NoError(t, os.WriteFile(wrong, []byte(base64.StdEncoding.EncodeToString(w)+"\n"), 0o600))
	_, err = LoadRevoked(wrong, signers)
	must.ErrorContains(t, err, "unknown signer", must.Sprint("an unverifiable line fails the load"))
}

func TestReloadRevokedFromFile_Unions(t *testing.T) {
	// File reload is grow-only: it unions into the set and never drops a gossip-received revocation.
	now := time.Now()
	priv, pub, sub := mkSig(t)
	signers := []ed25519.PublicKey{pub}
	m := newTestMesh()
	storeConfig(m, signers, nil)

	gossiped, err := signature.SignRevocation(priv, sub, now.Add(time.Hour).Unix())
	must.NoError(t, err)
	must.True(t, m.mergeRevocationBlobs([][]byte{gossiped}))

	otherNode := base64.StdEncoding.EncodeToString(append([]byte{9}, make([]byte, 31)...))
	otherSub, err := base64.StdEncoding.DecodeString(otherNode)
	must.NoError(t, err)
	fileRev, err := signature.SignRevocation(priv, otherSub, now.Add(time.Hour).Unix())
	must.NoError(t, err)
	path := filepath.Join(t.TempDir(), "revoked")
	must.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(fileRev)+"\n"), 0o600))

	n, err := m.ReloadRevokedFromFile(path)
	must.NoError(t, err)
	must.EqOp(t, 2, n, must.Sprint("file reload unions with the gossip-received revocation"))
	got := *m.revoked.Load()
	_, gossipedOK := got[testKey]
	_, fileOK := got[otherNode]
	must.True(t, gossipedOK, must.Sprint("the gossip-received revocation survives a file reload"))
	must.True(t, fileOK)
}

func TestRevocationState_RoundTrip(t *testing.T) {
	now := time.Now()
	signers, _, antiGrant := revokedSetup(t, now)

	a := newTestMesh()
	storeConfig(a, signers, nil)
	must.True(t, a.mergeRevocationBlobs([][]byte{antiGrant}))
	state := a.revocationState()
	must.SliceNotEmpty(t, state, must.Sprint("a node ships its anti-grant set in push/pull local state"))

	b := newTestMesh()
	storeConfig(b, signers, nil)
	b.mergeRevocationState(state)
	got := *b.revoked.Load()
	must.MapLen(t, 1, got, must.Sprint("push/pull carries the revocation to a peer that never saw the broadcast"))
	_, ok := got[testKey]
	must.True(t, ok)

	// an empty set ships nothing; undecodable remote state is ignored, never a panic or a bogus entry.
	must.SliceEmpty(t, newTestMesh().revocationState(), must.Sprint("an empty set has no state to ship"))
	b.mergeRevocationState([]byte{0xc1})
	must.MapLen(t, 1, *b.revoked.Load(), must.Sprint("undecodable remote state is ignored"))
}

func TestHandleRevocationMsg_RebroadcastsNewOnly(t *testing.T) {
	now := time.Now()
	signers, _, antiGrant := revokedSetup(t, now)
	m := newTestMesh()
	storeConfig(m, signers, nil)
	withBroadcastQueue(m)

	// a freshly learned revocation is merged and re-queued for epidemic spread (serf's rebroadcast).
	m.handleRevocationMsg(antiGrant)
	must.MapLen(t, 1, *m.revoked.Load())
	must.EqOp(t, 1, m.revocationBroadcasts.NumQueued(), must.Sprint("a new revocation is rebroadcast"))

	// the same one is already known, so it is not rebroadcast again (no broadcast storm).
	m.handleRevocationMsg(antiGrant)
	must.EqOp(t, 1, m.revocationBroadcasts.NumQueued(), must.Sprint("a known revocation is not rebroadcast"))

	// garbage from the untrusted transport neither merges nor rebroadcasts.
	m.handleRevocationMsg([]byte{1, 2, 3})
	must.EqOp(t, 1, m.revocationBroadcasts.NumQueued())
	must.MapLen(t, 1, *m.revoked.Load())

	// the delegate drains the queue: the exact blob goes out on the wire.
	d := &delegate{mesh: m}
	out := d.GetBroadcasts(0, 1<<20)
	must.SliceLen(t, 1, out)
	must.Eq(t, antiGrant, out[0])
}

func TestApplyRevoke(t *testing.T) {
	now := time.Now()
	signers, _, antiGrant := revokedSetup(t, now)
	m := newTestMesh()
	storeConfig(m, signers, nil)
	withBroadcastQueue(m)

	b64 := base64.StdEncoding.EncodeToString(antiGrant)
	must.NoError(t, m.applyRevoke(b64))
	must.MapLen(t, 1, *m.revoked.Load())
	must.EqOp(t, 1, m.revocationBroadcasts.NumQueued(), must.Sprint("operator origination is broadcast"))

	// idempotent: a re-injection is accepted but not rebroadcast.
	must.NoError(t, m.applyRevoke(b64))
	must.EqOp(t, 1, m.revocationBroadcasts.NumQueued(), must.Sprint("a known revocation is not rebroadcast"))

	// unlike the silent-drop gossip paths, the socket surfaces a verification failure to the operator.
	otherPriv, _, sub := mkSig(t)
	wrong, err := signature.SignRevocation(otherPriv, sub, now.Add(time.Hour).Unix())
	must.NoError(t, err)
	must.Error(t, m.applyRevoke(base64.StdEncoding.EncodeToString(wrong)), must.Sprint("an untrusted signer is refused"))
	must.Error(t, m.applyRevoke("not-base64!"), must.Sprint("garbage is refused"))
}

func TestHandleStatus_Revoke(t *testing.T) {
	now := time.Now()
	signers, _, antiGrant := revokedSetup(t, now)
	m := newTestMesh()
	storeConfig(m, signers, nil)
	withBroadcastQueue(m)

	// the revoke verb plus a base64 anti-grant exceeds the old 64-byte line limit; it must round-trip.
	must.StrContains(t, socketRoundtrip(t, m, "revoke "+base64.StdEncoding.EncodeToString(antiGrant)+"\n"), "ok")
	must.MapLen(t, 1, *m.revoked.Load())

	must.StrContains(t, socketRoundtrip(t, m, "revoke not-base64!\n"), "error")
	must.StrContains(t, socketRoundtrip(t, m, "bogus\n"), "unknown request")
}

func TestCheckSelfRevoked(t *testing.T) {
	m := newTestMesh()
	m.cfg = Config{Self: Peer{PublicKey: testKey}}

	m.checkSelfRevoked()
	must.False(t, m.selfRevoked.Load(), must.Sprint("with no anti-grant for itself a node advertises normally"))

	set := map[string]revocation{testKey: {horizon: time.Now().Add(time.Hour).Unix()}}
	m.revoked.Store(&set)
	m.checkSelfRevoked()
	must.True(t, m.selfRevoked.Load(), must.Sprint("a node honors its own anti-grant"))

	// the latch lifts only when the tombstone is reaped at the grant horizon.
	empty := map[string]revocation{}
	m.revoked.Store(&empty)
	m.checkSelfRevoked()
	must.False(t, m.selfRevoked.Load())
}

func TestMergeRevocations_ConcurrentFanIn(t *testing.T) {
	// The set is copy-on-write under revokedMu; N concurrent merges must all land, none lost to a race.
	now := time.Now()
	priv, pub, _ := mkSig(t)
	m := newTestMesh()
	storeConfig(m, []ed25519.PublicKey{pub}, nil)

	const N = 12
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		sub := make([]byte, 32)
		sub[0], sub[1] = byte(i), 0xa5
		blob, err := signature.SignRevocation(priv, sub, now.Add(time.Hour).Unix())
		must.NoError(t, err)
		wg.Go(func() { m.mergeRevocationBlobs([][]byte{blob}) })
	}
	wg.Wait()

	must.MapLen(t, N, *m.revoked.Load(), must.Sprint("every concurrent merge lands; none is lost to a racing writer"))
}

func socketRoundtrip(t *testing.T, m *Mesh, req string) string {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { m.handleStatus(server); close(done) }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := io.WriteString(client, req)
	must.NoError(t, err)
	data, _ := io.ReadAll(client)
	client.Close()
	<-done
	return string(data)
}
