//go:build linux

package mesh

import (
	"net"
	"testing"

	"github.com/hashicorp/memberlist"
	"github.com/shoenig/test/must"
)

func nodeFor(name, addr string, port uint16) *memberlist.Node {
	return &memberlist.Node{Name: name, Addr: net.ParseIP(addr), Port: port}
}

func newMeshForConflictTest(selfPubkey string) *Mesh {
	return &Mesh{
		cfg:        Config{Self: Peer{PublicKey: selfPubkey}},
		shutdownCh: make(chan struct{}),
	}
}

func shutdownSignaled(m *Mesh) bool {
	select {
	case <-m.shutdownCh:
		return true
	default:
		return false
	}
}

func TestMesh_HandleNodeConflict_OtherNodes(t *testing.T) {
	m := newMeshForConflictTest("self-pubkey")
	m.handleNodeConflict(
		nodeFor("other-pubkey", "fd00::1", 7946),
		nodeFor("other-pubkey", "fd00::2", 7946),
	)
	must.False(t, shutdownSignaled(m),
		must.Sprint("shutdown must not fire for a conflict between other nodes"))
}

func TestMesh_HandleNodeConflict_SelfNode(t *testing.T) {
	m := newMeshForConflictTest("self-pubkey")
	m.handleNodeConflict(
		nodeFor("self-pubkey", "fd00::1", 7946),
		nodeFor("self-pubkey", "fd00::99", 7946),
	)
	must.True(t, shutdownSignaled(m),
		must.Sprint("shutdown must fire when our own name is in conflict"))
}

func TestMesh_HandleNodeConflict_Idempotent(t *testing.T) {
	m := newMeshForConflictTest("self-pubkey")
	m.handleNodeConflict(
		nodeFor("self-pubkey", "fd00::1", 7946),
		nodeFor("self-pubkey", "fd00::99", 7946),
	)
	m.handleNodeConflict(
		nodeFor("self-pubkey", "fd00::1", 7946),
		nodeFor("self-pubkey", "fd00::99", 7946),
	)
	must.True(t, shutdownSignaled(m))
}

func TestDelegate_NotifyConflict_DispatchesToMesh(t *testing.T) {
	m := newMeshForConflictTest("self-pubkey")
	d := &delegate{mesh: m}
	d.NotifyConflict(
		nodeFor("self-pubkey", "fd00::1", 7946),
		nodeFor("self-pubkey", "fd00::99", 7946),
	)
	must.True(t, shutdownSignaled(m),
		must.Sprint("delegate.NotifyConflict must dispatch self-conflicts to Mesh.handleNodeConflict"))
}

func peerNode(t *testing.T, pubkey, addr, hostRouteCIDR string) *memberlist.Node {
	t.Helper()
	p := Peer{
		PublicKey:  pubkey,
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []string{hostRouteCIDR},
	}
	meta, err := encodeMeta(p)
	must.NoError(t, err)
	return &memberlist.Node{Name: pubkey, Meta: meta, Addr: net.ParseIP(addr), Port: 7946}
}

func TestDelegate_NotifyAlive_NilPolicyAccepts(t *testing.T) {
	m := &Mesh{cfg: Config{Self: Peer{PublicKey: "self"}}}
	d := &delegate{mesh: m}
	err := d.NotifyAlive(peerNode(t, testKey, "fdcc::1", "fdcc::dead/128"))
	must.NoError(t, err)
}

func TestDelegate_NotifyAlive_PolicyAccepts(t *testing.T) {
	policy, err := ParsePeerPolicy(`all(peer.AllowedIPs, cidrContains("fdcc::/16", #))`)
	must.NoError(t, err)
	m := &Mesh{cfg: Config{Self: Peer{PublicKey: "self"}, PeerPolicy: policy}}
	d := &delegate{mesh: m}
	err = d.NotifyAlive(peerNode(t, testKey, "fdcc::1", "fdcc::dead/128"))
	must.NoError(t, err)
}

func TestDelegate_NotifyAlive_PolicyRejects(t *testing.T) {
	policy, err := ParsePeerPolicy(`all(peer.AllowedIPs, cidrContains("fdcc::/16", #))`)
	must.NoError(t, err)
	m := &Mesh{cfg: Config{Self: Peer{PublicKey: "self"}, PeerPolicy: policy}}
	d := &delegate{mesh: m}
	err = d.NotifyAlive(peerNode(t, testKey, "10.0.0.1", "10.0.0.1/32"))
	must.ErrorContains(t, err, "rejected by policy")
}

func TestDelegate_NotifyAlive_SkipsSelf(t *testing.T) {
	policy, err := ParsePeerPolicy("false")
	must.NoError(t, err)
	m := &Mesh{cfg: Config{Self: Peer{PublicKey: testKey}, PeerPolicy: policy}}
	d := &delegate{mesh: m}
	err = d.NotifyAlive(peerNode(t, testKey, "fdcc::1", "fdcc::dead/128"))
	must.NoError(t, err, must.Sprint("self must not be subjected to policy"))
}
