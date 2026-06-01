package mesh

import (
	"testing"

	"github.com/shoenig/test/must"
)

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

func TestParsePeerPolicy_PeersRemoved(t *testing.T) {
	_, err := ParsePeerPolicy("peers()")
	must.ErrorContains(t, err, "peer-policy", must.Sprint("peers() is no longer in scope"))
}

func TestPeerPolicy_AcceptTrue(t *testing.T) {
	p, err := ParsePeerPolicy("true")
	must.NoError(t, err)
	ok, err := p.accept(Peer{}, Peer{})
	must.NoError(t, err)
	must.True(t, ok)
}

func TestPeerPolicy_RejectFalse(t *testing.T) {
	p, err := ParsePeerPolicy("false")
	must.NoError(t, err)
	ok, err := p.accept(Peer{}, Peer{})
	must.NoError(t, err)
	must.False(t, ok)
}

func TestPeerPolicy_AllowedIPsInCIDR(t *testing.T) {
	p, err := ParsePeerPolicy(`all(peer.AllowedIPs, cidrSubset("fdcc::/16", #))`)
	must.NoError(t, err)

	ok, err := p.accept(Peer{AllowedIPs: []string{"fdcc::dead/128"}}, Peer{})
	must.NoError(t, err)
	must.True(t, ok, must.Sprint("inside fdcc::/16 must accept"))

	ok, err = p.accept(Peer{AllowedIPs: []string{"fd00::dead/128"}}, Peer{})
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("outside fdcc::/16 must reject"))

	ok, err = p.accept(Peer{AllowedIPs: []string{"fdcc::dead/128", "fd00::dead/128"}}, Peer{})
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("any outside must reject when 'all' is the predicate"))
}

func TestPeerPolicy_SelfRelative(t *testing.T) {
	p, err := ParsePeerPolicy(`peer.Tags["region"] == self.Tags["region"]`)
	must.NoError(t, err)

	self := Peer{Tags: Tags{"region": "eu"}}

	ok, err := p.accept(Peer{Tags: Tags{"region": "eu"}}, self)
	must.NoError(t, err)
	must.True(t, ok, must.Sprint("same region must accept"))

	ok, err = p.accept(Peer{Tags: Tags{"region": "us"}}, self)
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("different region must reject"))
}

func TestPeerPolicy_PeerFields(t *testing.T) {
	p, err := ParsePeerPolicy(`peer.PublicKey == "trusted"`)
	must.NoError(t, err)

	ok, err := p.accept(Peer{PublicKey: "trusted"}, Peer{})
	must.NoError(t, err)
	must.True(t, ok)

	ok, err = p.accept(Peer{PublicKey: "other"}, Peer{})
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
