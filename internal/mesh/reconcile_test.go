//go:build linux

package mesh

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"github.com/shoenig/test/must"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestDiff(t *testing.T) {
	genKey := func() string {
		pk, err := wgtypes.GeneratePrivateKey()
		must.NoError(t, err)
		return pk.PublicKey().String()
	}
	makePeer := func(key, cidr string) wgPeer {
		return wgPeer{key: key, endpoint: "203.0.113.1:51820", routes: []string{cidr}}
	}
	x, y, z, w := genKey(), genKey(), genKey(), genKey()

	prev := map[string]wgPeer{
		x: makePeer(x, "fd00::1/128"),
		y: makePeer(y, "fd00::2/128"),
		w: makePeer(w, "fd00::4/128"),
	}
	cur := map[string]wgPeer{
		x: makePeer(x, "fd00::1/128"),
		z: makePeer(z, "fd00::3/128"),
		w: makePeer(w, "fd00::5/128"),
	}

	changes := diff(prev, cur, kernelSet(prev))
	must.SliceLen(t, 3, changes)
	must.True(t, slices.IsSortedFunc(changes, func(a, b wgtypes.PeerConfig) int {
		return bytes.Compare(a.PublicKey[:], b.PublicKey[:])
	}), must.Sprint("diff output is deterministically sorted by pubkey"))
	var adds, removes int
	for _, c := range changes {
		if c.Remove {
			removes++
		} else {
			adds++
		}
	}
	must.EqOp(t, 2, adds, must.Sprint("new Z and changed W are applied"))
	must.EqOp(t, 1, removes, must.Sprint("Y is removed"))

	must.SliceEmpty(t, diff(cur, cur, kernelSet(cur)))
}

func kernelSet(ms ...map[string]wgPeer) map[string]bool {
	set := map[string]bool{}
	for _, mp := range ms {
		for k := range mp {
			set[k] = true
		}
	}
	return set
}

func TestDiff_EndpointChange(t *testing.T) {
	pk, err := wgtypes.GeneratePrivateKey()
	must.NoError(t, err)
	key := pk.PublicKey().String()

	peerAt := func(ep, cidr string) map[string]wgPeer {
		return map[string]wgPeer{key: {key: key, endpoint: ep, routes: []string{cidr}}}
	}

	prev := peerAt("203.0.113.1:51820", "fd00::1/128")
	inKernel := kernelSet(prev)
	changes := diff(prev, peerAt("203.0.113.2:51820", "fd00::1/128"), inKernel)
	must.SliceLen(t, 1, changes)
	must.True(t, changes[0].UpdateOnly, must.Sprint("a known peer is an update, not a re-add"))
	must.NotNil(t, changes[0].Endpoint, must.Sprint("a changed endpoint is re-applied to the kernel"))

	changes = diff(prev, peerAt("203.0.113.1:51820", "fd00::2/128"), inKernel)
	must.SliceLen(t, 1, changes)
	must.True(t, changes[0].UpdateOnly)
	must.Nil(t, changes[0].Endpoint, must.Sprint("an unchanged endpoint is left to WireGuard's own roaming"))

	changes = diff(prev, prev, map[string]bool{})
	must.SliceLen(t, 1, changes)
	must.False(t, changes[0].UpdateOnly, must.Sprint("a peer missing from the kernel is re-added in full"))
	must.NotNil(t, changes[0].Endpoint)
}

func TestDropContestedRoutes(t *testing.T) {
	peers := map[string]wgPeer{
		"a": {key: "a", routes: []string{"fd00::a/128"}},
		"b": {key: "b", routes: []string{"fd00::b/128"}},
		"c": {key: "c", routes: []string{"fd00::c/128", "fd00::b/128"}},
	}

	effective, conflicts := dropContestedRoutes(peers, nil)

	must.Eq(t, []string{"fd00::a/128"}, effective["a"].routes)
	must.Eq(t, []string{"fd00::c/128"}, effective["c"].routes, must.Sprint("c keeps its unconflicting route"))
	must.MapNotContainsKey(t, effective, "b", must.Sprint("b's only route conflicts, so b is dropped"))
	must.MapLen(t, 1, conflicts)
	must.Eq(t, []string{"b", "c"}, conflicts["fd00::b/128"], must.Sprint("conflicting route lists both claimants, sorted"))
}

func TestDropContestedRoutes_SelfClaimWins(t *testing.T) {
	selfRoutes := []string{"fd00::1/128"}
	peers := map[string]wgPeer{
		"impostor": {key: "impostor", routes: []string{"fd00::1/128"}},
		"honest":   {key: "honest", routes: []string{"fd00::9/128"}},
	}

	effective, conflicts := dropContestedRoutes(peers, selfRoutes)

	must.MapNotContainsKey(t, effective, "impostor", must.Sprint("a peer claiming a route we serve loses it"))
	must.Eq(t, []string{"fd00::9/128"}, effective["honest"].routes, must.Sprint("an unrelated peer is unaffected"))
	must.MapEmpty(t, conflicts, must.Sprint("a self-collision is not a peer-vs-peer contest, so it is not reported"))
	for _, w := range effective {
		must.SliceNotContains(t, w.routes, "fd00::1/128", must.Sprint("the self route is never installed for a peer"))
	}
}

func TestDropContestedRoutes_SelfMoreSpecific(t *testing.T) {
	// A peer route more specific than one of our own served routes is dropped (it would LPM-steal our
	// traffic); a peer supernet is not dropped, so exit-node / aggregate topologies stay valid.
	selfRoutes := []string{"10.1.2.0/24"}
	peers := map[string]wgPeer{
		"carver": {key: "carver", routes: []string{"10.1.2.0/25"}}, // more specific: dropped
		"exit":   {key: "exit", routes: []string{"0.0.0.0/0"}},     // supernet: kept
	}
	effective, conflicts := dropContestedRoutes(peers, selfRoutes)
	must.MapEmpty(t, conflicts, must.Sprint("a self-collision is not a peer-vs-peer contest"))
	must.MapNotContainsKey(t, effective, "carver", must.Sprint("a peer carve-out of our served route is dropped"))
	must.Eq(t, []string{"0.0.0.0/0"}, effective["exit"].routes, must.Sprint("a peer supernet / exit route is not dropped"))
}

func TestStaleKernelPeers(t *testing.T) {
	m := &Mesh{kernelPeers: map[string]bool{"seedA": true, "seedB": true}}

	must.SliceEmpty(t, m.staleKernelPeers(), must.Sprint("never flag a kernel peer before the mesh is joined"))

	m.joinedAt.Store(time.Now().UnixNano())
	must.SliceEmpty(t, m.staleKernelPeers(), must.Sprint("kernel peers get a settle window after join to gossip"))

	m.joinedAt.Store(time.Now().Add(-2 * kernelSettle).UnixNano())
	must.Eq(t, []string{"seedA", "seedB"}, m.staleKernelPeers(), must.Sprint("after the settle window, never-gossiped kernel peers are stale, sorted"))

	delete(m.kernelPeers, "seedA") // seedA gossiped, so setMember dropped it from the set
	must.Eq(t, []string{"seedB"}, m.staleKernelPeers(), must.Sprint("a kernel peer that gossiped is no longer stale"))
}
