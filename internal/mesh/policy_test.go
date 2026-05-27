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

func TestPeerPolicy_AcceptTrue(t *testing.T) {
	p, err := ParsePeerPolicy("true")
	must.NoError(t, err)
	ok, err := p.accept(Peer{}, "")
	must.NoError(t, err)
	must.True(t, ok)
}

func TestPeerPolicy_RejectFalse(t *testing.T) {
	p, err := ParsePeerPolicy("false")
	must.NoError(t, err)
	ok, err := p.accept(Peer{}, "")
	must.NoError(t, err)
	must.False(t, ok)
}

func TestPeerPolicy_AllowedIPsInCIDR(t *testing.T) {
	p, err := ParsePeerPolicy(`all(peer.AllowedIPs, cidrContains("fdcc::/16", #))`)
	must.NoError(t, err)

	ok, err := p.accept(Peer{AllowedIPs: []string{"fdcc::dead/128"}}, "")
	must.NoError(t, err)
	must.True(t, ok, must.Sprint("inside fdcc::/16 must accept"))

	ok, err = p.accept(Peer{AllowedIPs: []string{"fd00::dead/128"}}, "")
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("outside fdcc::/16 must reject"))

	ok, err = p.accept(Peer{AllowedIPs: []string{"fdcc::dead/128", "fd00::dead/128"}}, "")
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("any outside must reject when 'all' is the predicate"))
}

func TestPeerPolicy_SrcAddr(t *testing.T) {
	p, err := ParsePeerPolicy(`cidrContains("fdcc::/16", srcAddr)`)
	must.NoError(t, err)

	ok, err := p.accept(Peer{}, "fdcc::1")
	must.NoError(t, err)
	must.True(t, ok)

	ok, err = p.accept(Peer{}, "10.0.0.1")
	must.NoError(t, err)
	must.False(t, ok)
}

func TestPeerPolicy_PeerFields(t *testing.T) {
	p, err := ParsePeerPolicy(`peer.PublicKey == "trusted"`)
	must.NoError(t, err)

	ok, err := p.accept(Peer{PublicKey: "trusted"}, "")
	must.NoError(t, err)
	must.True(t, ok)

	ok, err = p.accept(Peer{PublicKey: "other"}, "")
	must.NoError(t, err)
	must.False(t, ok)
}

func TestParseIPOrCIDR(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "fdcc::1", "10.0.0.1/32", "fdcc::1/128", "10.0.0.0/8"} {
		must.NotNil(t, parseIPOrCIDR(s), must.Sprintf("input %q", s))
	}
	for _, s := range []string{"", "not an ip", "fdcc::/", "10.0.0.300"} {
		must.Nil(t, parseIPOrCIDR(s), must.Sprintf("input %q", s))
	}
}

func TestCIDRContains(t *testing.T) {
	must.True(t, cidrContains("fdcc::/16", "fdcc::1"))
	must.True(t, cidrContains("fdcc::/16", "fdcc::dead/128"))
	must.False(t, cidrContains("fdcc::/16", "fd00::1"))
	must.False(t, cidrContains("not-a-cidr", "fdcc::1"))
	must.False(t, cidrContains("fdcc::/16", "not-an-ip"))
	must.True(t, cidrContains("10.0.0.0/8", "10.1.2.3"))
	must.False(t, cidrContains("10.0.0.0/8", "192.168.1.1"))
}
