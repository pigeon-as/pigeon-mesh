package mesh

import (
	"testing"

	"github.com/shoenig/test/must"
)

func noPeers() []Peer { return nil }

func TestParsePeerPolicy_EmptyReturnsNil(t *testing.T) {
	p, err := ParsePeerPolicy("")
	must.NoError(t, err)
	must.Nil(t, p)
}

func TestParsePeerPolicy_BadSyntax(t *testing.T) {
	_, err := ParsePeerPolicy("???")
	must.ErrorContains(t, err, "peer-policy")
}

func TestParsePeerPolicy_NonBoolRejected(t *testing.T) {
	_, err := ParsePeerPolicy(`"a string"`)
	must.ErrorContains(t, err, "peer-policy")
}

func TestPeerPolicy_AcceptTrue(t *testing.T) {
	p, err := ParsePeerPolicy("true")
	must.NoError(t, err)
	ok, err := p.accept(Peer{}, noPeers)
	must.NoError(t, err)
	must.True(t, ok)
}

func TestPeerPolicy_RejectFalse(t *testing.T) {
	p, err := ParsePeerPolicy("false")
	must.NoError(t, err)
	ok, err := p.accept(Peer{}, noPeers)
	must.NoError(t, err)
	must.False(t, ok)
}

func TestPeerPolicy_AllowedIPsInCIDR(t *testing.T) {
	p, err := ParsePeerPolicy(`all(peer.AllowedIPs, cidrSubset("fdcc::/16", #))`)
	must.NoError(t, err)

	ok, err := p.accept(Peer{AllowedIPs: []string{"fdcc::dead/128"}}, noPeers)
	must.NoError(t, err)
	must.True(t, ok, must.Sprint("inside fdcc::/16 must accept"))

	ok, err = p.accept(Peer{AllowedIPs: []string{"fd00::dead/128"}}, noPeers)
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("outside fdcc::/16 must reject"))

	ok, err = p.accept(Peer{AllowedIPs: []string{"fdcc::dead/128", "fd00::dead/128"}}, noPeers)
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("any outside must reject when 'all' is the predicate"))
}

func TestPeerPolicy_ContainmentAcceptsImpersonation(t *testing.T) {
	p, err := ParsePeerPolicy(`all(peer.AllowedIPs, cidrSubset("fdcc::/16", #))`)
	must.NoError(t, err)

	ok, err := p.accept(Peer{AllowedIPs: []string{"fdcc::1111/128", "fdcc::2222/128"}}, noPeers)
	must.NoError(t, err)
	must.True(t, ok, must.Sprint("both inside fdcc::/16, so containment accepts even if one is a victim's address"))
}

func TestPeerPolicy_PeersRejectsDuplicateRoute(t *testing.T) {
	p, err := ParsePeerPolicy(`all(peer.AllowedIPs, let r = #; none(peers(), r in #.AllowedIPs))`)
	must.NoError(t, err)

	established := func() []Peer {
		return []Peer{{PublicKey: "established", AllowedIPs: []string{"fdcc::1/128"}}}
	}

	ok, err := p.accept(Peer{AllowedIPs: []string{"fdcc::1/128"}}, established)
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("a route already claimed by another peer must be rejected"))

	ok, err = p.accept(Peer{AllowedIPs: []string{"fdcc::2/128"}}, established)
	must.NoError(t, err)
	must.True(t, ok, must.Sprint("an unclaimed route must be accepted"))
}

func TestPeerPolicy_PeerFields(t *testing.T) {
	p, err := ParsePeerPolicy(`peer.PublicKey == "trusted"`)
	must.NoError(t, err)

	ok, err := p.accept(Peer{PublicKey: "trusted"}, noPeers)
	must.NoError(t, err)
	must.True(t, ok)

	ok, err = p.accept(Peer{PublicKey: "other"}, noPeers)
	must.NoError(t, err)
	must.False(t, ok)
}

func TestCIDRSubset(t *testing.T) {
	must.True(t, cidrSubset("fdcc::/16", "fdcc::1"))
	must.True(t, cidrSubset("fdcc::/16", "fdcc::dead/128"))
	must.True(t, cidrSubset("fdcc::/16", "fdcc::/16"))
	must.True(t, cidrSubset("fdcc::/16", "fdcc::/32"))
	must.False(t, cidrSubset("fdcc::/16", "fdcc::/8"))
	must.False(t, cidrSubset("fdcc::/16", "fdcc::/4"))
	must.False(t, cidrSubset("fdcc::/16", "fd00::1"))
	must.False(t, cidrSubset("not-a-cidr", "fdcc::1"))
	must.False(t, cidrSubset("fdcc::/16", "not-an-ip"))
	must.True(t, cidrSubset("10.0.0.0/8", "10.1.2.3"))
	must.False(t, cidrSubset("10.0.0.0/8", "192.168.1.1"))
	must.False(t, cidrSubset("10.0.0.0/24", "10.0.0.0/8"))
}
