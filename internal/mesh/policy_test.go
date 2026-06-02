package mesh

import (
	"encoding/base64"
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

func TestHostbits(t *testing.T) {
	must.EqOp(t, "aaaabbbbccccddddeeeeffff1111", hostbits("fdcc::/16", "fdcc:aaaa:bbbb:cccc:dddd:eeee:ffff:1111/128"))
	must.EqOp(t, hostbits("fdcc::/16", "fdcc::1/128"), hostbits("fdcc::/16", "fdcc::1"), must.Sprint("/128 suffix optional"))
	must.EqOp(t, "", hostbits("fdcc::/60", "fdcc::1/128"), must.Sprint("non-byte-aligned prefix rejected"))
	must.EqOp(t, "", hostbits("bad", "fdcc::1"))
	must.EqOp(t, "", hostbits("fdcc::/16", "not-an-addr"))
	must.EqOp(t, "", hostbits("fdcc::/16", "10.0.0.1"), must.Sprint("family mismatch rejected"))
}

func TestPeerPolicy_SelfCert(t *testing.T) {
	p, err := ParsePeerPolicy(`all(peer.AllowedIPs, hostbits("fdcc::/16", #) == sha256(base64decode(peer.PublicKey))[0:28])`)
	must.NoError(t, err)

	pk := base64.StdEncoding.EncodeToString([]byte("example key material"))
	h := sha256Hex(b64decode(pk))
	want := "fdcc:" + h[0:4] + ":" + h[4:8] + ":" + h[8:12] + ":" + h[12:16] + ":" + h[16:20] + ":" + h[20:24] + ":" + h[24:28] + "/128"

	ok, err := p.accept(Peer{PublicKey: pk, AllowedIPs: []string{want}}, Peer{})
	must.NoError(t, err)
	must.True(t, ok, must.Sprint("address derived from the key must accept"))

	ok, err = p.accept(Peer{PublicKey: pk, AllowedIPs: []string{"fdcc::dead/128"}}, Peer{})
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("a different address must reject"))

	ok, err = p.accept(Peer{PublicKey: pk, AllowedIPs: []string{want, "fdcc::/64"}}, Peer{})
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("derived address plus an appended uncertified route must reject"))

	other := base64.StdEncoding.EncodeToString([]byte("a different key value"))
	ok, err = p.accept(Peer{PublicKey: other, AllowedIPs: []string{want}}, Peer{})
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("another key cannot certify this address"))
}

func TestBase64decode(t *testing.T) {
	must.EqOp(t, "hi", b64decode(base64.StdEncoding.EncodeToString([]byte("hi"))))
	must.EqOp(t, "", b64decode("not valid base64 !!!"))
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
