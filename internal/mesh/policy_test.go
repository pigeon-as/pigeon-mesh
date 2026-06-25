//go:build linux

package mesh

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/shoenig/test/must"
)

func TestCidrSubset(t *testing.T) {
	for _, tc := range []struct {
		outer, inner string
		want         bool
	}{
		{"10.0.0.0/8", "10.1.2.0/24", true},     // more specific, inside
		{"10.0.0.0/8", "10.1.2.3", true},        // bare IP treated as /32
		{"10.0.0.0/8", "10.0.0.0/8", true},      // equal prefixes are subsets
		{"::/0", "fd00::/8", true},              // v6 default contains the ULA block
		{"10.0.0.0/16", "10.0.0.0/8", false},    // inner less specific than outer
		{"10.0.0.0/8", "fd00::1", false},        // cross-family
		{"0.0.0.0/0", "fd00::/8", false},        // v4 default does not contain v6 (the e2e relies on this)
		{"10.0.0.0/8", "192.168.0.0/16", false}, // disjoint
		{"10.0.0.0/8", "not-a-cidr", false},     // garbage inner
		{"nope", "10.0.0.0/8", false},           // garbage outer
	} {
		must.EqOp(t, tc.want, cidrSubset(tc.outer, tc.inner), must.Sprintf("cidrSubset(%q, %q)", tc.outer, tc.inner))
	}
}

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
	pol, err := ParsePeerPolicy(`peer.key == "gw" && cidrSubset("10.0.0.0/8", route)`)
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

func TestPeerPolicy_WholePeerAllowedips(t *testing.T) {
	id := netip.MustParseAddr("fdcc::1")
	// A whole-peer rule via all()/any() over peer.allowedips returns the same verdict for every
	// route, so it behaves all-or-nothing: accept the extras only if every route is a ULA subnet.
	pol, err := ParsePeerPolicy(`all(peer.allowedips, cidrSubset("fd00::/8", #))`)
	must.NoError(t, err)

	ula := Peer{PublicKey: "a", AllowedIPs: []string{"fdcc::1/128", "fd12:3::/48"}}
	kept, refused := policyFilter(ula, id, pol)
	must.Eq(t, ula.AllowedIPs, kept, must.Sprint("all routes ULA => all kept"))
	must.SliceEmpty(t, refused)

	mixed := Peer{PublicKey: "b", AllowedIPs: []string{"fdcc::1/128", "10.0.0.0/8"}}
	kept, refused = policyFilter(mixed, id, pol)
	must.Eq(t, []string{"fdcc::1/128"}, kept, must.Sprint("one non-ULA route => extras refused, identity kept"))
	must.Eq(t, []string{"10.0.0.0/8"}, refused)
}

func TestPolicyFilter(t *testing.T) {
	id := netip.MustParseAddr("fdcc::1")
	peer := Peer{PublicKey: "exit", AllowedIPs: []string{"fdcc::1/128", "0.0.0.0/0", "10.0.0.0/8"}}

	// only the exact default route(s) from "exit"; its 10/8 subnet is refused
	pol, err := ParsePeerPolicy(`peer.key == "exit" && route in ["0.0.0.0/0", "::/0"]`)
	must.NoError(t, err)
	kept, refused := policyFilter(peer, id, pol)
	must.Eq(t, []string{"fdcc::1/128", "0.0.0.0/0"}, kept, must.Sprint("identity exempt; only the default route accepted from exit"))
	must.Eq(t, []string{"10.0.0.0/8"}, refused)

	// cidrSubset accepts any route within a prefix (so the default route, not a subset of 10/8, is refused)
	sub, err := ParsePeerPolicy(`cidrSubset("10.0.0.0/8", route)`)
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

func TestPolicyFilter_MalformedCIDRRefused(t *testing.T) {
	pol, err := ParsePeerPolicy(`cidrSubset("10.0.0.0/8", route)`)
	must.NoError(t, err)
	peer := Peer{PublicKey: "x", AllowedIPs: []string{"fdcc::1/128", "not-a-cidr", "10.0.0.0/8"}}
	kept, refused := policyFilter(peer, netip.MustParseAddr("fdcc::1"), pol)
	must.Eq(t, []string{"fdcc::1/128", "10.0.0.0/8"}, kept, must.Sprint("identity exempt + accepted; malformed never installs"))
	must.Eq(t, []string{"not-a-cidr"}, refused, must.Sprint("an unparseable route fails closed (refused), never crashes"))
}

func TestPolicyFilter_NoIdentityExemptionWhenInvalid(t *testing.T) {
	// Open tier (no --prefix): identity is the zero Addr, so nothing is auto-exempt.
	deny, err := ParsePeerPolicy(`false`)
	must.NoError(t, err)
	peer := Peer{AllowedIPs: []string{"fdcc::1/128", "10.0.0.0/8"}}
	kept, refused := policyFilter(peer, netip.Addr{}, deny)
	must.SliceEmpty(t, kept, must.Sprint("no overlay identity => nothing auto-kept under deny-all"))
	must.Eq(t, []string{"fdcc::1/128", "10.0.0.0/8"}, refused)
}

func TestPolicyFilter_OnlyExactHostRouteExempt(t *testing.T) {
	// A peer advertising the identity as a covering prefix (not the /128) is not exempt.
	deny, err := ParsePeerPolicy(`false`)
	must.NoError(t, err)
	peer := Peer{AllowedIPs: []string{"fdcc::/64"}}
	kept, refused := policyFilter(peer, netip.MustParseAddr("fdcc::1"), deny)
	must.SliceEmpty(t, kept, must.Sprint("only the exact /128 host route is exempt, not a covering prefix"))
	must.Eq(t, []string{"fdcc::/64"}, refused)
}

func TestParsePeerPolicyFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.expr")
	must.NoError(t, os.WriteFile(path, []byte("  peer.key == \"x\"\n"), 0o600))

	p, err := ParsePeerPolicyFlag("@" + path)
	must.NoError(t, err)
	must.NotNil(t, p, must.Sprint("@file is read, whitespace-trimmed, and compiled"))

	_, err = ParsePeerPolicyFlag("@" + filepath.Join(dir, "missing"))
	must.Error(t, err, must.Sprint("a missing @file errors"))

	p, err = ParsePeerPolicyFlag(`true`)
	must.NoError(t, err)
	must.NotNil(t, p, must.Sprint("an inline predicate compiles"))

	p, err = ParsePeerPolicyFlag("")
	must.NoError(t, err)
	must.Nil(t, p, must.Sprint("empty flag = nil policy = accept all"))
}

func TestParsePeerPolicy_UnknownIdentifierFailsCompile(t *testing.T) {
	// A typo must be caught at startup (exit 2), not silently refuse every route at runtime.
	_, err := ParsePeerPolicy(`peer.bogus == 1`)
	must.Error(t, err, must.Sprint("unknown field is caught by the typed env at compile"))
	_, err = ParsePeerPolicy(`nope(route)`)
	must.Error(t, err, must.Sprint("unknown function is caught at compile"))
}
