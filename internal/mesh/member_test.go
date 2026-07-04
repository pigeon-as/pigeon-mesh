//go:build linux

package mesh

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/pigeon-as/pigeon-mesh/internal/signature"
	"github.com/shoenig/test/must"
)

func newTestMesh() *Mesh {
	m := &Mesh{
		members:     map[string]member{},
		applied:     map[string]wgPeer{},
		kernelPeers: map[string]bool{},
		contested:   map[string][]string{},
		reconcileCh: make(chan struct{}, 1),
	}
	revoked := map[string]struct{}{}
	m.revoked.Store(&revoked)
	return m
}

func TestReapDead(t *testing.T) {
	m := newTestMesh()
	m.cfg = Config{ReconnectTimeout: time.Minute}
	now := time.Now()
	m.members["live"] = member{failed: false}
	m.members["recent"] = member{failed: true, leaveTime: now.Add(-30 * time.Second)}
	m.members["old"] = member{failed: true, leaveTime: now.Add(-2 * time.Minute)}

	must.True(t, m.reapDead(now), must.Sprint("a member failed past --reconnect-timeout is reaped"))
	must.MapContainsKey(t, m.members, "live", must.Sprint("a live member is never reaped"))
	must.MapContainsKey(t, m.members, "recent", must.Sprint("within the window, a failed member is kept"))
	must.MapNotContainsKey(t, m.members, "old", must.Sprint("past the window, a failed member is reaped"))

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

func storeConfig(m *Mesh, signers []ed25519.PublicKey, policy *PeerPolicy) {
	m.signers.Store(&signers)
	m.policy.Store(policy)
	if m.revoked.Load() == nil {
		revoked := map[string]struct{}{}
		m.revoked.Store(&revoked)
	}
}

var testPrefix = netip.MustParsePrefix("fdcc::/48")

// signers trusting a fresh operator key, testKey's derived /128, and a grant valid for one hour around now.
func signedFixture(t *testing.T, now time.Time, routes ...netip.Prefix) (signers []ed25519.PublicKey, ownRoute string, grant []byte) {
	t.Helper()
	priv, pub, sub := mkSig(t)
	derived, err := DeriveAddr(testKey, testPrefix)
	must.NoError(t, err)
	grant, err = signature.Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), "", routes...)
	must.NoError(t, err)
	return []ed25519.PublicKey{pub}, HostRoute(derived).String(), grant
}

func TestReevaluate_StricterPolicyEvictsRoute(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	signers, ownRoute, grant := signedFixture(t, now, netip.MustParsePrefix("10.0.0.0/8"))
	pol, err := ParsePeerPolicy(`route == peer.address`) // reachability-only: keep /128, drop extras
	must.NoError(t, err)
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, signers, pol)
	m.members[testKey] = member{
		peer:   Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute, "10.0.0.0/8"}, Signature: grant},
		wgPeer: wgPeer{key: testKey, endpoint: "203.0.113.1:51820", routes: []string{ownRoute, "10.0.0.0/8"}},
		meta:   []byte("m"),
	}
	m.reevaluate(now)
	got := m.members[testKey]
	must.Eq(t, []string{ownRoute}, got.wgPeer.routes, must.Sprint("identity /128 kept by matching peer.address, the extra route evicted"))
	must.Eq(t, []string{"10.0.0.0/8"}, got.refusedRoutes)
	must.True(t, reconcileTriggered(m.reconcileCh), must.Sprint("an eviction must trigger a reconcile"))
}

func TestReevaluate_BlockPeerEvictsAll(t *testing.T) {
	// Blocking a peer by key refuses every route incl its /128, but membership stays intact.
	now := time.Unix(1_000_000, 0)
	signers, ownRoute, grant := signedFixture(t, now, netip.MustParsePrefix("10.0.0.0/8"))
	pol, err := ParsePeerPolicy(`peer.key != "` + testKey + `"`)
	must.NoError(t, err)
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, signers, pol)
	m.members[testKey] = member{
		peer:   Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute, "10.0.0.0/8"}, Signature: grant},
		wgPeer: wgPeer{key: testKey, endpoint: "203.0.113.1:51820", routes: []string{ownRoute, "10.0.0.0/8"}},
		meta:   []byte("m"),
	}
	m.reevaluate(now)
	got := m.members[testKey]
	must.True(t, got.admitted(), must.Sprint("a key-blocked peer stays admitted; membership is untouched"))
	must.SliceEmpty(t, got.wgPeer.routes, must.Sprint("a key-blocked peer installs nothing, including its /128"))
	must.Eq(t, []string{ownRoute, "10.0.0.0/8"}, got.refusedRoutes)
}

func TestReevaluate_LooserPolicyRestoresRoute(t *testing.T) {
	// Removing the policy (=> nil) must restore a refused route.
	now := time.Unix(1_000_000, 0)
	signers, ownRoute, grant := signedFixture(t, now, netip.MustParsePrefix("10.0.0.0/8"))
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, signers, nil)
	m.members[testKey] = member{
		peer:          Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute, "10.0.0.0/8"}, Signature: grant},
		wgPeer:        wgPeer{key: testKey, endpoint: "203.0.113.1:51820", routes: []string{ownRoute}},
		refusedRoutes: []string{"10.0.0.0/8"},
		meta:          []byte("m"),
	}
	m.reevaluate(now)
	got := m.members[testKey]
	must.Eq(t, []string{ownRoute, "10.0.0.0/8"}, got.wgPeer.routes, must.Sprint("a removed policy restores the full route set"))
	must.SliceEmpty(t, got.refusedRoutes)
	must.True(t, reconcileTriggered(m.reconcileCh))
}

func TestReevaluate_NamePropagatesOnReadmit(t *testing.T) {
	// A peer first seen while rejected carries no name; when a SIGHUP re-admits it, reevaluate must
	// install the grant's DNS name so it enters the zone without waiting for a re-gossip.
	now := time.Unix(1_000_000, 0)
	priv, pub, sub := mkSig(t)
	derived, err := DeriveAddr(testKey, testPrefix)
	must.NoError(t, err)
	ownRoute := HostRoute(derived).String()
	grant, err := signature.Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), "web01")
	must.NoError(t, err)

	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, []ed25519.PublicKey{pub}, nil)
	// Stored as if previously rejected: no name, no routes, an admit error.
	m.members[testKey] = member{
		peer:     Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute}, Signature: grant},
		admitErr: errors.New("unknown signer"),
		meta:     []byte("m"),
	}
	m.reevaluate(now)
	got := m.members[testKey]
	must.True(t, got.admitted(), must.Sprint("the peer re-admits under the now-trusted signer"))
	must.EqOp(t, "web01", got.name, must.Sprint("the grant's DNS name is installed on re-admit, not left stale"))
}

func TestReevaluate_RejectReasonRefreshes(t *testing.T) {
	// Stays rejected across a reload but for a DIFFERENT reason: must show the fresh reason.
	now := time.Now()
	priv, pub, sub := mkSig(t)
	grant, err := signature.Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), "")
	must.NoError(t, err)
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, []ed25519.PublicKey{pub}, nil)
	// signed-valid but advertises a non-derived /128: re-admission rejects for address mismatch, not the seeded "unknown signer".
	m.members[testKey] = member{
		peer:     Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{"fdcc::dead/128"}, Signature: grant},
		admitErr: errors.New("unknown signer"),
		meta:     []byte("m"),
	}
	m.reevaluate(now)
	got := m.members[testKey]
	must.False(t, got.admitted(), must.Sprint("still rejected: the advertised address is not its key derivation"))
	must.StrContains(t, got.admitErr.Error(), "derives", must.Sprint("the reject reason refreshes to the address mismatch"))
}

func TestReevaluate_RejectClearsUnauthorizedRoutes(t *testing.T) {
	// Admitted with an unauthorized route, then rejected by a signer reload: must drop the stale unauthorized route.
	now := time.Unix(1_000_000, 0)
	signers, ownRoute, grant := signedFixture(t, now) // grant authorizes only the identity /128
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, signers, nil)
	m.members[testKey] = member{
		peer:               Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute, "10.0.0.0/8"}, Signature: grant},
		wgPeer:             wgPeer{key: testKey, endpoint: "203.0.113.1:51820", routes: []string{ownRoute}},
		unauthorizedRoutes: []string{"10.0.0.0/8"},
		meta:               []byte("m"),
	}
	_, otherPub, _ := mkSig(t)
	storeConfig(m, []ed25519.PublicKey{otherPub}, nil) // reload to a key that doesn't trust the grant
	m.reevaluate(now)
	got := m.members[testKey]
	must.False(t, got.admitted(), must.Sprint("a peer signed by an untrusted key is rejected"))
	must.SliceEmpty(t, got.unauthorizedRoutes, must.Sprint("a rejected peer reports no unauthorized routes"))
}

func TestReevaluate_NoopWhenConsistent(t *testing.T) {
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

	// A roam changes the meta, so unchanged() must not suppress it: the member re-resolves with the new endpoint.
	m.setMember(advertise("203.0.113.2:51820"))
	must.EqOp(t, "203.0.113.2:51820", m.members[testKey].wgPeer.endpoint, must.Sprint("a roamed endpoint is re-resolved into the kernel config"))
	must.True(t, reconcileTriggered(m.reconcileCh), must.Sprint("an endpoint roam triggers a reconcile"))

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

	// A failed peer re-announcing identical meta must not be treated as unchanged: it re-resolves and recovers to alive.
	m.setMember(node)
	must.False(t, m.members[testKey].failed, must.Sprint("a failed peer re-announcing identical meta recovers to alive"))
	must.True(t, reconcileTriggered(m.reconcileCh), must.Sprint("recovery re-resolves and triggers a reconcile"))
}

func TestExpireGrants(t *testing.T) {
	m := newTestMesh()
	now := time.Now()
	m.members["accepted-noexpiry"] = member{grantExpiry: 0}
	m.members["accepted-valid"] = member{grantExpiry: now.Add(time.Hour).Unix()}
	m.members["accepted-expired"] = member{grantExpiry: now.Add(-time.Second).Unix(), refusedRoutes: []string{"192.168.0.0/16"}, unauthorizedRoutes: []string{"10.0.0.0/8"}}
	m.members["already-rejected"] = member{admitErr: errors.New("no signature")}
	m.members["failed-expired"] = member{failed: true, grantExpiry: now.Add(-time.Hour).Unix()}

	must.True(t, m.expireGrants(now), must.Sprint("an expiry reports a change, so maintain can trigger a reconcile"))

	must.NoError(t, m.members["accepted-noexpiry"].admitErr, must.Sprint("a member with no expiry stays admitted"))
	must.NoError(t, m.members["accepted-valid"].admitErr, must.Sprint("a member with a future expiry stays admitted"))
	must.EqOp(t, "signature expired", m.members["accepted-expired"].admitErr.Error())
	must.SliceEmpty(t, m.members["accepted-expired"].unauthorizedRoutes, must.Sprint("expiry clears the unauthorized-route register"))
	must.SliceEmpty(t, m.members["accepted-expired"].refusedRoutes, must.Sprint("expiry clears the refused-route register"))
	must.EqOp(t, "no signature", m.members["already-rejected"].admitErr.Error())
	must.EqOp(t, "signature expired", m.members["failed-expired"].admitErr.Error(), must.Sprint("expiry is enforced even for offline/failed peers"))
}

func TestCheckSelfExpiry(t *testing.T) {
	priv, pub, sub := mkSig(t)
	now := time.Now()
	blob, err := signature.Sign(priv, sub, now.Add(-time.Hour).Unix(), now.Add(-time.Minute).Unix(), "")
	must.NoError(t, err)
	m := &Mesh{cfg: Config{Self: Peer{PublicKey: "self", Signature: blob}}}
	storeConfig(m, []ed25519.PublicKey{pub}, nil)
	m.selfGrant.Store(&blob)
	must.False(t, m.selfExpired.Load())

	m.checkSelfExpiry(now)
	must.True(t, m.selfExpired.Load(), must.Sprint("an expired own signature halts self participation"))

	valid, err := signature.Sign(priv, sub, now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix(), "")
	must.NoError(t, err)
	ok := &Mesh{cfg: Config{Self: Peer{PublicKey: "self", Signature: valid}}}
	storeConfig(ok, []ed25519.PublicKey{pub}, nil)
	ok.selfGrant.Store(&valid)
	ok.checkSelfExpiry(now)
	must.False(t, ok.selfExpired.Load(), must.Sprint("a valid signature keeps the node live"))

	// self-heal: a latch left set by a renewal that raced a tick clears once the tick re-reads the valid grant.
	healed := &Mesh{cfg: Config{Self: Peer{PublicKey: "self", Signature: valid}}}
	storeConfig(healed, []ed25519.PublicKey{pub}, nil)
	healed.selfGrant.Store(&valid)
	healed.selfExpired.Store(true)
	healed.checkSelfExpiry(now)
	must.False(t, healed.selfExpired.Load(), must.Sprint("a tick re-reading a valid grant clears a stuck latch"))
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
		blob, err := signature.Sign(priv, sub, notBefore, notAfter, "")
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
			r := admit(member{}, tc.peer, testKey, &tc.signers, nil, prefix, nil, now)
			if tc.wantReject == "" {
				must.NoError(t, r.admitErr)
			} else {
				must.StrContains(t, r.admitErr.Error(), tc.wantReject)
			}
			must.EqOp(t, tc.wantReject == "", r.wgPeer.key != "", must.Sprint("admitted peers carry a kernel config; rejected ones leave it zero"))
			must.EqOp(t, tc.wantAddr, r.addr.IsValid())
			must.EqOp(t, tc.wantExpiry, r.grantExpiry != 0)
		})
	}
}

func TestAdmit_PolicyFiltersRoutes(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	signers, ownRoute, grant := signedFixture(t, now, netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16"))
	pol, err := ParsePeerPolicy(`route == peer.address || cidrSubset("10.0.0.0/8", route)`)
	must.NoError(t, err)
	p := Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute, "10.1.0.0/16", "192.168.0.0/16"}, Signature: grant}

	r := admit(member{}, p, testKey, &signers, nil, testPrefix, pol, now)
	must.NoError(t, r.admitErr)
	must.True(t, r.addr.IsValid())
	must.Eq(t, []string{ownRoute, "10.1.0.0/16"}, r.wgPeer.routes, must.Sprint("identity kept by matching peer.address; 10/8 subnet accepted"))
	must.Eq(t, []string{"192.168.0.0/16"}, r.refusedRoutes)

	// nil policy keeps everything
	r = admit(member{}, p, testKey, &signers, nil, testPrefix, nil, now)
	must.Eq(t, p.AllowedIPs, r.wgPeer.routes)
	must.SliceEmpty(t, r.refusedRoutes)
}

func TestAdmit_AuthorizesRoutes(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	// grant authorizes only 10.0.0.0/8
	signers, ownRoute, grant := signedFixture(t, now, netip.MustParsePrefix("10.0.0.0/8"))
	p := Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute, "10.1.0.0/16", "192.168.0.0/16"}, Signature: grant}

	r := admit(member{}, p, testKey, &signers, nil, testPrefix, nil, now)
	must.True(t, r.admitted(), must.Sprint("an unauthorized extra route does not reject the peer"))
	must.Eq(t, []string{ownRoute, "10.1.0.0/16"}, r.wgPeer.routes, must.Sprint("identity /128 and the 10/8 sub-prefix install"))
	must.Eq(t, []string{"192.168.0.0/16"}, r.unauthorizedRoutes, must.Sprint("a route outside the grant is dropped as unauthorized"))
}

func TestAdmit_BroadGrantAuthorizesSubprefixes(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	// a 0.0.0.0/0 grant authorizes the default and any sub-prefix by containment.
	signers, ownRoute, grant := signedFixture(t, now, netip.MustParsePrefix("0.0.0.0/0"))
	p := Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute, "0.0.0.0/0", "10.0.0.0/8"}, Signature: grant}
	r := admit(member{}, p, testKey, &signers, nil, testPrefix, nil, now)
	must.Eq(t, []string{ownRoute, "0.0.0.0/0", "10.0.0.0/8"}, r.wgPeer.routes, must.Sprint("a default-route grant authorizes the default and any sub-prefix"))
	must.SliceEmpty(t, r.unauthorizedRoutes)
}

// TestNodeMetaHeadroom pins how much room the 512-byte NodeMeta cap leaves for advertised routes and tags
// once a realistic named, route-authorizing grant is packed in, so a regression that bloats the encoding
// (or the documented operator limit drifting from reality) fails here. The numbers are logged with -v.
func TestNodeMetaHeadroom(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	priv, _, sub := mkSig(t)
	// A grant with a hostname-length name and two authorized transit routes (identity + an exit).
	grant, err := signature.Sign(priv, sub, now.Add(-time.Minute).Unix(), now.Add(720*time.Hour).Unix(),
		"node-worstcase.example.internal", netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("0.0.0.0/0"))
	must.NoError(t, err)
	derived, err := DeriveAddr(testKey, testPrefix)
	must.NoError(t, err)
	base := Peer{Endpoint: "203.0.113.1:51820", AllowedIPs: []string{HostRoute(derived).String()}, Signature: grant}
	bmeta, err := encodeMeta(base)
	must.NoError(t, err)
	t.Logf("baseline NodeMeta (named 2-route grant + identity /128) = %d / %d bytes", len(bmeta), memberlist.MetaMaxSize)

	fits := func(p Peer) bool {
		m, err := encodeMeta(p)
		must.NoError(t, err)
		return len(m) <= memberlist.MetaMaxSize
	}

	// Extra advertised /24 routes that still fit.
	routes := 0
	for {
		p := base
		p.AllowedIPs = slices.Clone(base.AllowedIPs)
		for i := 0; i <= routes; i++ {
			p.AllowedIPs = append(p.AllowedIPs, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
		}
		if !fits(p) {
			break
		}
		routes++
	}
	t.Logf("extra advertised /24 routes beyond the baseline that fit: %d", routes)

	// Short tags (k=v) that still fit.
	tags := 0
	for {
		p := base
		p.Tags = Tags{}
		for i := 0; i <= tags; i++ {
			p.Tags[fmt.Sprintf("k%d", i)] = "v"
		}
		if !fits(p) {
			break
		}
		tags++
	}
	t.Logf("short tags beyond the baseline that fit: %d", tags)

	must.True(t, routes >= 10, must.Sprintf("NodeMeta headroom shrank: only %d extra /24 routes fit past a named 2-route grant (was ~17)", routes))
}

func TestReuseGrant(t *testing.T) {
	sig := []byte("signature-bytes")
	ptr := &[]ed25519.PublicKey{}
	now := time.Unix(1000, 0)
	base := member{
		peer:          Peer{Signature: sig},
		grantExpiry:   now.Add(time.Hour).Unix(),
		name:          "alpha",
		grantRoutes:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		verifiedUnder: ptr,
	}

	g, ok := reuseGrant(base, sig, ptr, now)
	must.True(t, ok, must.Sprint("same signer pointer + signature + unexpired reuses the verified grant, skipping ed25519"))
	must.EqOp(t, "alpha", g.Name)
	must.Eq(t, base.grantRoutes, g.Routes)

	_, ok = reuseGrant(base, []byte("different"), ptr, now)
	must.False(t, ok, must.Sprint("a changed signature forces a fresh verify"))

	_, ok = reuseGrant(base, sig, &[]ed25519.PublicKey{}, now)
	must.False(t, ok, must.Sprint("a different signer-set pointer (rotation) forces a fresh verify"))

	rejected := base
	rejected.admitErr = errRevoked
	_, ok = reuseGrant(rejected, sig, ptr, now)
	must.False(t, ok, must.Sprint("a previously-rejected member has no cached grant to reuse"))

	_, ok = reuseGrant(base, sig, ptr, time.Unix(base.grantExpiry, 0))
	must.False(t, ok, must.Sprint("an expired grant forces a fresh verify for the proper error"))
}

// Guards setMember -> delete(m.kernelPeers): once a peer gossips it must leave the kernel-peers set, else
// reconcile folds it back from applied and never removes it (e2e missed this).
func TestSetMemberDropsKernelPeers(t *testing.T) {
	now := time.Now()
	signers, ownRoute, grant := signedFixture(t, now)
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, signers, nil)
	m.kernelPeers[testKey] = true

	meta, err := encodeMeta(Peer{Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute}, Signature: grant})
	must.NoError(t, err)
	m.setMember(&memberlist.Node{Name: testKey, Meta: meta})

	must.MapNotContainsKey(t, m.kernelPeers, testKey, must.Sprint("a peer that gossips leaves the kernel-peers set, so a later reject/leave removes it instead of folding it back"))
	must.MapContainsKey(t, m.members, testKey, must.Sprint("the gossiped peer is now a member"))
}
