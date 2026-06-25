//go:build linux

package mesh

import (
	"crypto/ed25519"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/pigeon-as/pigeon-mesh/internal/signature"
	"github.com/shoenig/test/must"
)

// newTestMesh builds a Mesh with its membership maps initialized, for tests that construct it
// without New (which needs a real wgctrl client).
func newTestMesh() *Mesh {
	return &Mesh{
		members:           map[string]member{},
		applied:           map[string]wgPeer{},
		kernelPeers:       map[string]bool{},
		contested:         map[string][]string{},
		keyConflicts:      map[string]string{},
		warnedKernelPeers: map[string]bool{},
		reconcileCh:       make(chan struct{}, 1),
	}
}

func TestReapDead(t *testing.T) {
	m := newTestMesh()
	m.cfg = Config{ReconnectTimeout: time.Minute}
	now := time.Now()
	m.members["live"] = member{failed: false}
	m.members["recent"] = member{failed: true, leaveTime: now.Add(-30 * time.Second)}
	m.members["old"] = member{failed: true, leaveTime: now.Add(-2 * time.Minute)}
	m.keyConflicts["old"] = "dup"

	must.True(t, m.reapDead(now), must.Sprint("a member failed past --reconnect-timeout is reaped"))
	must.MapContainsKey(t, m.members, "live", must.Sprint("a live member is never reaped"))
	must.MapContainsKey(t, m.members, "recent", must.Sprint("within the window, a failed member is kept"))
	must.MapNotContainsKey(t, m.members, "old", must.Sprint("past the window, a failed member is reaped"))
	must.MapNotContainsKey(t, m.keyConflicts, "old", must.Sprint("a reaped member's key-conflict alert is dropped too"))

	must.False(t, m.reapDead(now), must.Sprint("a steady state reaps nothing"))
}

func reconcileTriggered(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// storeConfig sets the hot-reloadable trust config (signers + policy) on a test Mesh built without
// New, which is where those atomics are normally initialized.
func storeConfig(m *Mesh, signers []ed25519.PublicKey, policy *PeerPolicy) {
	m.signers.Store(&signers)
	m.policy.Store(policy)
}

var testPrefix = netip.MustParsePrefix("fdcc::/48")

// signedFixture returns the single trust-model fixtures for testKey: a signers list trusting a
// fresh operator key, testKey's derived overlay /128 under testPrefix, and a grant for testKey
// valid in a one-hour window around now. The collapse made --signers and --prefix mandatory, so
// every resolve/setMember test peer must be signed and advertise its key-derived address.
func signedFixture(t *testing.T, now time.Time) (signers []ed25519.PublicKey, ownRoute string, grant []byte) {
	t.Helper()
	priv, pub, sub := mkSig(t)
	derived, err := DeriveAddr(testKey, testPrefix)
	must.NoError(t, err)
	grant, err = signature.Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix())
	must.NoError(t, err)
	return []ed25519.PublicKey{pub}, HostRoute(derived).String(), grant
}

func TestReevaluate_StricterPolicyEvictsRoute(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	signers, ownRoute, grant := signedFixture(t, now)
	deny, err := ParsePeerPolicy(`false`)
	must.NoError(t, err)
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, signers, deny)
	m.members[testKey] = member{
		peer:   Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute, "10.0.0.0/8"}, Signature: grant},
		wgPeer: wgPeer{key: testKey, endpoint: "203.0.113.1:51820", routes: []string{ownRoute, "10.0.0.0/8"}},
		meta:   []byte("m"),
	}
	m.reevaluate(now)
	got := m.members[testKey]
	must.Eq(t, []string{ownRoute}, got.wgPeer.routes, must.Sprint("identity /128 survives a deny-all policy reload"))
	must.Eq(t, []string{"10.0.0.0/8"}, got.refusedRoutes)
	must.True(t, reconcileTriggered(m.reconcileCh), must.Sprint("an eviction must trigger a reconcile"))
}

func TestReevaluate_LooserPolicyRestoresRoute(t *testing.T) {
	// Removing the policy (reload to empty => nil) must restore a route it had refused.
	now := time.Unix(1_000_000, 0)
	signers, ownRoute, grant := signedFixture(t, now)
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, signers, nil) // policy removed -> nil
	m.members[testKey] = member{
		peer:          Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute, "10.0.0.0/8"}, Signature: grant},
		wgPeer:        wgPeer{key: testKey, endpoint: "203.0.113.1:51820", routes: []string{ownRoute}},
		refusedRoutes: []string{"10.0.0.0/8"}, // previously refused under a since-removed policy
		meta:          []byte("m"),
	}
	m.reevaluate(now)
	got := m.members[testKey]
	must.Eq(t, []string{ownRoute, "10.0.0.0/8"}, got.wgPeer.routes, must.Sprint("a removed policy restores the full route set"))
	must.SliceEmpty(t, got.refusedRoutes)
	must.True(t, reconcileTriggered(m.reconcileCh))
}

func TestReevaluate_NoopWhenConsistent(t *testing.T) {
	// An already-consistent member must not churn.
	now := time.Unix(1_000_000, 0)
	signers, ownRoute, grant := signedFixture(t, now)
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, signers, nil)
	in := member{
		peer:   Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute}, Signature: grant},
		wgPeer: wgPeer{key: testKey, endpoint: "203.0.113.1:51820", routes: []string{ownRoute}},
		meta:   []byte("m"),
	}
	m.members[testKey] = in
	m.reevaluate(now)
	must.Eq(t, in.wgPeer.routes, m.members[testKey].wgPeer.routes)
	must.NoError(t, m.members[testKey].admitErr)
	must.False(t, reconcileTriggered(m.reconcileCh), must.Sprint("no change => no reconcile churn"))
}

func TestSetMember_RoamReresolvesEndpoint(t *testing.T) {
	now := time.Now()
	signers, ownRoute, grant := signedFixture(t, now)
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, signers, nil)

	advertise := func(endpoint string) *memberlist.Node {
		meta, err := encodeMeta(Peer{Endpoint: endpoint, AllowedIPs: []string{ownRoute}, Signature: grant})
		must.NoError(t, err)
		return &memberlist.Node{Name: testKey, Meta: meta}
	}

	m.setMember(advertise("203.0.113.1:51820"))
	must.EqOp(t, "203.0.113.1:51820", m.members[testKey].wgPeer.endpoint)
	must.True(t, reconcileTriggered(m.reconcileCh), must.Sprint("a first advertisement triggers a reconcile"))

	// A re-advertisement that only roams the endpoint changes the meta, so unchanged() must not
	// suppress it: the member re-resolves and the kernel config carries the new endpoint.
	m.setMember(advertise("203.0.113.2:51820"))
	must.EqOp(t, "203.0.113.2:51820", m.members[testKey].wgPeer.endpoint, must.Sprint("a roamed endpoint is re-resolved into the kernel config"))
	must.True(t, reconcileTriggered(m.reconcileCh), must.Sprint("an endpoint roam triggers a reconcile"))

	// The same advertisement again is unchanged: skipped, with no reconcile churn.
	m.setMember(advertise("203.0.113.2:51820"))
	must.False(t, reconcileTriggered(m.reconcileCh), must.Sprint("an unchanged advertisement is skipped"))
}

func TestSetMember_ReannounceClearsFailed(t *testing.T) {
	now := time.Now()
	signers, ownRoute, grant := signedFixture(t, now)
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, signers, nil)

	meta, err := encodeMeta(Peer{Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute}, Signature: grant})
	must.NoError(t, err)
	node := &memberlist.Node{Name: testKey, Meta: meta}

	m.setMember(node)
	must.False(t, m.members[testKey].failed)
	must.True(t, reconcileTriggered(m.reconcileCh))

	m.removeMember(&memberlist.Node{Name: testKey, State: memberlist.StateDead})
	must.True(t, m.members[testKey].failed, must.Sprint("the peer is now SWIM-failed"))

	// The same node re-announcing byte-identical meta must not count as unchanged (it is failed),
	// so setMember re-resolves it and the peer recovers to alive -- not stranded failed.
	m.setMember(node)
	must.False(t, m.members[testKey].failed, must.Sprint("a failed peer re-announcing identical meta recovers to alive"))
	must.True(t, reconcileTriggered(m.reconcileCh), must.Sprint("recovery re-resolves and triggers a reconcile"))
}

func TestExpireGrants(t *testing.T) {
	m := newTestMesh()
	now := time.Now()
	m.members["accepted-noexpiry"] = member{grantExpiry: 0}
	m.members["accepted-valid"] = member{grantExpiry: now.Add(time.Hour).Unix()}
	m.members["accepted-expired"] = member{grantExpiry: now.Add(-time.Second).Unix()}
	m.members["already-rejected"] = member{admitErr: errors.New("no signature")}
	m.members["failed-expired"] = member{failed: true, grantExpiry: now.Add(-time.Hour).Unix()}

	must.True(t, m.expireGrants(now), must.Sprint("an expiry reports a change, so maintain can trigger a reconcile"))

	must.NoError(t, m.members["accepted-noexpiry"].admitErr, must.Sprint("a member with no expiry stays admitted"))
	must.NoError(t, m.members["accepted-valid"].admitErr, must.Sprint("a member with a future expiry stays admitted"))
	must.EqOp(t, "signature expired", errText(m.members["accepted-expired"].admitErr))
	must.EqOp(t, "no signature", errText(m.members["already-rejected"].admitErr))
	must.EqOp(t, "signature expired", errText(m.members["failed-expired"].admitErr), must.Sprint("expiry is enforced even for offline/failed peers"))
}

func TestCheckSelfExpiry(t *testing.T) {
	priv, pub, sub := mkSig(t)
	now := time.Now()
	blob, err := signature.Sign(priv, sub, now.Add(-time.Hour).Unix(), now.Add(-time.Minute).Unix())
	must.NoError(t, err)
	m := &Mesh{cfg: Config{Self: Peer{PublicKey: "self", Signature: blob}}}
	storeConfig(m, []ed25519.PublicKey{pub}, nil)
	must.False(t, m.selfExpired.Load())

	m.checkSelfExpiry(now)
	must.True(t, m.selfExpired.Load(), must.Sprint("an expired own signature halts self participation"))

	valid, err := signature.Sign(priv, sub, now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix())
	must.NoError(t, err)
	ok := &Mesh{cfg: Config{Self: Peer{PublicKey: "self", Signature: valid}}}
	storeConfig(ok, []ed25519.PublicKey{pub}, nil)
	ok.checkSelfExpiry(now)
	must.False(t, ok.selfExpired.Load(), must.Sprint("a valid signature keeps the node live"))
}

func TestAdmit(t *testing.T) {
	prefix := netip.MustParsePrefix("fdcc::/16")
	derived, err := DeriveAddr(testKey, prefix)
	must.NoError(t, err)
	ownRoute := HostRoute(derived).String()

	priv, pub, sub := mkSig(t)
	signers := []ed25519.PublicKey{pub}
	now := time.Unix(1_000_000, 0)
	sign := func(notBefore, notAfter int64) []byte {
		blob, err := signature.Sign(priv, sub, notBefore, notAfter)
		must.NoError(t, err)
		return blob
	}
	validSig := sign(now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix())
	expiredSig := sign(now.Add(-time.Hour).Unix(), now.Add(-time.Minute).Unix())

	otherPub, _, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)

	prefixPeer := func(sig []byte, routes ...string) Peer {
		if len(routes) == 0 {
			routes = []string{ownRoute}
		}
		return Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: routes, Signature: sig}
	}

	cases := []struct {
		name       string
		signers    []ed25519.PublicKey
		peer       Peer
		wantReject string
		wantAddr   bool
		wantExpiry bool
	}{
		{name: "valid signature and derived route accepted", signers: signers, peer: prefixPeer(validSig), wantAddr: true, wantExpiry: true},
		{name: "unsigned peer rejected", signers: signers, peer: prefixPeer(nil), wantReject: "no signature"},
		{name: "expired signature rejected", signers: signers, peer: prefixPeer(expiredSig), wantReject: "expired"},
		{name: "unknown signer rejected", signers: []ed25519.PublicKey{otherPub}, peer: prefixPeer(validSig), wantReject: "unknown signer"},
		{name: "non-derived route rejected", signers: signers, peer: prefixPeer(validSig, "fdcc::dead/128"), wantReject: "derives"},
		{name: "malformed endpoint rejected", signers: signers, peer: Peer{PublicKey: testKey, AllowedIPs: []string{ownRoute}, Signature: validSig}, wantReject: "invalid peer config"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := admit(tc.peer, testKey, tc.signers, prefix, nil, now)
			if tc.wantReject == "" {
				must.NoError(t, r.admitErr)
			} else {
				must.StrContains(t, errText(r.admitErr), tc.wantReject)
			}
			must.EqOp(t, tc.wantReject == "", r.wgPeer.key != "", must.Sprint("admitted peers carry a kernel config; rejected ones leave it zero"))
			must.EqOp(t, tc.wantAddr, r.addr.IsValid())
			must.EqOp(t, tc.wantExpiry, r.grantExpiry != 0)
		})
	}
}

func TestAdmit_PolicyFiltersRoutes(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	signers, ownRoute, grant := signedFixture(t, now)
	pol, err := ParsePeerPolicy(`cidrSubset("10.0.0.0/8", route)`)
	must.NoError(t, err)
	p := Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute, "10.1.0.0/16", "192.168.0.0/16"}, Signature: grant}

	r := admit(p, testKey, signers, testPrefix, pol, now)
	must.NoError(t, r.admitErr)
	must.True(t, r.addr.IsValid())
	must.Eq(t, []string{ownRoute, "10.1.0.0/16"}, r.wgPeer.routes, must.Sprint("identity exempt; 10/8 subnet accepted"))
	must.Eq(t, []string{"192.168.0.0/16"}, r.refusedRoutes)

	// nil policy keeps everything, refuses nothing
	r = admit(p, testKey, signers, testPrefix, nil, now)
	must.Eq(t, p.AllowedIPs, r.wgPeer.routes)
	must.SliceEmpty(t, r.refusedRoutes)
}

func TestHandleConflictRecordsKeyConflict(t *testing.T) {
	m := newTestMesh()
	m.cfg = Config{Self: Peer{PublicKey: "selfKey"}}
	m.members["aliveKey"] = member{}
	m.members["roamKey"] = member{failed: true}

	// A live member advertised from a second address is a genuine duplicate key.
	m.handleConflict(
		&memberlist.Node{Name: "aliveKey", Addr: net.ParseIP("10.0.0.1"), Port: 51820},
		&memberlist.Node{Name: "aliveKey", Addr: net.ParseIP("10.0.0.2"), Port: 51820},
	)
	must.MapContainsKey(t, m.keyConflicts, "aliveKey", must.Sprint("a live peer's key collision is recorded for status"))

	// A failed/unknown member re-announcing from a new address is a restart/roam, not a duplicate key.
	m.handleConflict(
		&memberlist.Node{Name: "roamKey", Addr: net.ParseIP("10.0.0.1"), Port: 51820},
		&memberlist.Node{Name: "roamKey", Addr: net.ParseIP("10.0.0.2"), Port: 51820},
	)
	must.MapNotContainsKey(t, m.keyConflicts, "roamKey", must.Sprint("a restart/roam is not a duplicate-key alarm"))

	// A collision on our own key is always recorded.
	m.handleConflict(
		&memberlist.Node{Name: "selfKey", Addr: net.ParseIP("10.0.0.1"), Port: 51820},
		&memberlist.Node{Name: "selfKey", Addr: net.ParseIP("10.0.0.3"), Port: 51820},
	)
	must.MapContainsKey(t, m.keyConflicts, "selfKey", must.Sprint("a collision on our own key is recorded too"))
}

// TestStoreDropsKernelPeers guards the load-bearing store() -> delete(m.kernelPeers): once a peer gossips
// it must leave the kernel-peers set, or reconcile would fold it back from applied after it is rejected
// or leaves, and never remove it from the kernel (a security/correctness bug the e2e did not catch).
func TestStoreDropsKernelPeers(t *testing.T) {
	m := newTestMesh()
	m.kernelPeers["seed"] = true
	m.store("seed", member{})
	must.MapNotContainsKey(t, m.kernelPeers, "seed", must.Sprint("a peer that gossips leaves the kernel-peers set, so a later reject/leave removes it instead of folding it back"))
	must.MapContainsKey(t, m.members, "seed", must.Sprint("the gossiped peer is now a member"))
}

func TestShouldProbe(t *testing.T) {
	must.False(t, shouldProbe(0, 10, 0.5), must.Sprint("no failures: do not probe"))
	must.True(t, shouldProbe(10, 0, 0.5), must.Sprint("total outage (alive 0): always probe"))
	must.True(t, shouldProbe(5, 10, 0.4), must.Sprint("sample below the failed/alive ratio probes"))
	must.False(t, shouldProbe(5, 10, 0.6), must.Sprint("sample above the ratio skips"))
}
