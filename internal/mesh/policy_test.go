package mesh

import (
	"net/netip"
	"testing"

	"github.com/shoenig/test/must"
)

func TestParsePeerPolicy(t *testing.T) {
	p, err := ParsePeerPolicy("")
	must.NoError(t, err)
	must.Nil(t, p, must.Sprint("empty policy compiles to nil = accept all"))

	_, err = ParsePeerPolicy("&&")
	must.Error(t, err, must.Sprint("a malformed predicate fails to compile"))

	_, err = ParsePeerPolicy(`peer.key`)
	must.Error(t, err, must.Sprint("a non-bool result is rejected at compile (expr.AsBool)"))
}

func TestPeerPolicy_Accept(t *testing.T) {
	pol, err := ParsePeerPolicy(`peer.key == "gw" && cidrSubset("10.0.0.0/8", allowedip)`)
	must.NoError(t, err)

	gw := Peer{PublicKey: "gw", AllowedIPs: []string{"10.1.2.0/24"}}
	ok, err := pol.accept(gw, "10.1.2.0/24")
	must.NoError(t, err)
	must.True(t, ok, must.Sprint("gw may advertise a 10/8 subnet"))

	ok, err = pol.accept(Peer{PublicKey: "other"}, "10.1.2.0/24")
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("only gw may advertise 10/8"))

	ok, err = pol.accept(gw, "192.168.0.0/16")
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("gw's non-10/8 route is refused"))

	// peer.allowedips list is in scope
	pol2, err := ParsePeerPolicy(`len(peer.allowedips) <= 2`)
	must.NoError(t, err)
	ok, err = pol2.accept(Peer{AllowedIPs: []string{"a", "b"}}, "a")
	must.NoError(t, err)
	must.True(t, ok)
}

func TestPolicyFilter(t *testing.T) {
	id := netip.MustParseAddr("fdcc::1")
	peer := Peer{PublicKey: "exit", AllowedIPs: []string{"fdcc::1/128", "0.0.0.0/0", "10.0.0.0/8"}}

	// only the exact default route(s) from "exit"; its 10/8 subnet is refused
	pol, err := ParsePeerPolicy(`peer.key == "exit" && allowedip in ["0.0.0.0/0", "::/0"]`)
	must.NoError(t, err)
	kept, refused := policyFilter(peer, id, pol)
	must.Eq(t, []string{"fdcc::1/128", "0.0.0.0/0"}, kept, must.Sprint("identity exempt; only the default route accepted from exit"))
	must.Eq(t, []string{"10.0.0.0/8"}, refused)

	// cidrSubset accepts any route within a prefix (so the default route, not a subset of 10/8, is refused)
	sub, err := ParsePeerPolicy(`cidrSubset("10.0.0.0/8", allowedip)`)
	must.NoError(t, err)
	kept, refused = policyFilter(peer, id, sub)
	must.Eq(t, []string{"fdcc::1/128", "10.0.0.0/8"}, kept)
	must.Eq(t, []string{"0.0.0.0/0"}, refused)

	// nil policy accepts everything, refuses nothing
	kept, refused = policyFilter(peer, id, nil)
	must.Eq(t, peer.AllowedIPs, kept)
	must.SliceEmpty(t, refused)

	// identity is kept even when the policy would refuse it
	deny, err := ParsePeerPolicy(`false`)
	must.NoError(t, err)
	kept, refused = policyFilter(peer, id, deny)
	must.Eq(t, []string{"fdcc::1/128"}, kept, must.Sprint("identity /128 always installs"))
	must.Eq(t, []string{"0.0.0.0/0", "10.0.0.0/8"}, refused)
}
