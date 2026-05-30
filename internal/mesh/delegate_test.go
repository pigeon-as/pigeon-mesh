//go:build linux

package mesh

import (
	"testing"

	"github.com/hashicorp/memberlist"
	"github.com/shoenig/test/must"
)

func peerNode(t *testing.T, pubkey, hostRouteCIDR string) *memberlist.Node {
	t.Helper()
	p := Peer{
		PublicKey:  pubkey,
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []string{hostRouteCIDR},
	}
	meta, err := encodeMeta(p)
	must.NoError(t, err)
	return &memberlist.Node{Name: pubkey, Meta: meta}
}

func TestDelegate_NotifyAlive_NilPolicyAccepts(t *testing.T) {
	m := &Mesh{cfg: Config{Self: Peer{PublicKey: "self"}}}
	d := &delegate{mesh: m}
	err := d.NotifyAlive(peerNode(t, testKey, "fdcc::dead/128"))
	must.NoError(t, err)
}

func TestDelegate_NotifyAlive_PolicyAccepts(t *testing.T) {
	policy, err := ParsePeerPolicy(`all(peer.AllowedIPs, cidrSubset("fdcc::/16", #))`)
	must.NoError(t, err)
	m := &Mesh{cfg: Config{Self: Peer{PublicKey: "self"}, PeerPolicy: policy}}
	d := &delegate{mesh: m}
	err = d.NotifyAlive(peerNode(t, testKey, "fdcc::dead/128"))
	must.NoError(t, err)
}

func TestDelegate_NotifyAlive_PolicyRejects(t *testing.T) {
	policy, err := ParsePeerPolicy(`all(peer.AllowedIPs, cidrSubset("fdcc::/16", #))`)
	must.NoError(t, err)
	m := &Mesh{cfg: Config{Self: Peer{PublicKey: "self"}, PeerPolicy: policy}}
	d := &delegate{mesh: m}
	err = d.NotifyAlive(peerNode(t, testKey, "10.0.0.1/32"))
	must.ErrorContains(t, err, "rejected by policy")
}

func TestDelegate_NotifyAlive_SkipsSelf(t *testing.T) {
	policy, err := ParsePeerPolicy("false")
	must.NoError(t, err)
	m := &Mesh{cfg: Config{Self: Peer{PublicKey: testKey}, PeerPolicy: policy}}
	d := &delegate{mesh: m}
	err = d.NotifyAlive(peerNode(t, testKey, "fdcc::dead/128"))
	must.NoError(t, err, must.Sprint("self must not be subjected to policy"))
}
