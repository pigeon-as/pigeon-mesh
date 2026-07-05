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
		{"10.0.0.0/8", "10.1.2.0/24", true},
		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.0.0.0/8", "10.0.0.0/8", true},
		{"::/0", "fd00::/8", true},
		{"10.0.0.0/16", "10.0.0.0/8", false},
		{"10.0.0.0/8", "fd00::1", false},
		{"0.0.0.0/0", "fd00::/8", false}, // v4 default must not contain v6 (e2e relies on this)
		{"10.0.0.0/8", "192.168.0.0/16", false},
		{"10.0.0.0/8", "not-a-cidr", false},
		{"nope", "10.0.0.0/8", false},
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
	ok, err := pol.accept(gw, nil, "10.1.2.0/24", "")
	must.NoError(t, err)
	must.True(t, ok, must.Sprint("gw may advertise a 10/8 subnet"))

	ok, err = pol.accept(Peer{PublicKey: "other"}, nil, "10.1.2.0/24", "")
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("only gw may advertise 10/8"))

	ok, err = pol.accept(gw, nil, "192.168.0.0/16", "")
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("gw's non-10/8 route is refused"))

	pol2, err := ParsePeerPolicy(`len(peer.allowedips) <= 2`)
	must.NoError(t, err)
	ok, err = pol2.accept(Peer{AllowedIPs: []string{"a", "b"}}, nil, "a", "")
	must.NoError(t, err)
	must.True(t, ok)

	idp, err := ParsePeerPolicy(`route == peer.address`)
	must.NoError(t, err)
	ok, err = idp.accept(gw, nil, "fdcc::ab/128", "fdcc::ab/128")
	must.NoError(t, err)
	must.True(t, ok, must.Sprint("route == peer.address holds for the identity /128"))
	ok, err = idp.accept(gw, nil, "10.1.2.0/24", "fdcc::ab/128")
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("an extra route is not peer.address"))
}

func TestPeerPolicy_Tags(t *testing.T) {
	// signed tags are verified, so a route policy can trust them: only db-role peers advertise the db subnet.
	pol, err := ParsePeerPolicy(`peer.tags["role"] == "db" || route == peer.address`)
	must.NoError(t, err)
	id := netip.MustParseAddr("fdcc::1")
	peer := Peer{PublicKey: "p", AllowedIPs: []string{"fdcc::1/128", "10.0.0.0/8"}}

	kept, refused := policyFilter(peer, map[string]string{"role": "db"}, peer.AllowedIPs, id, pol)
	must.Eq(t, peer.AllowedIPs, kept, must.Sprint("a db-tagged peer keeps its routes"))
	must.SliceEmpty(t, refused)

	kept, refused = policyFilter(peer, map[string]string{"role": "web"}, peer.AllowedIPs, id, pol)
	must.Eq(t, []string{"fdcc::1/128"}, kept, must.Sprint("a non-db peer keeps only its identity /128"))
	must.Eq(t, []string{"10.0.0.0/8"}, refused)

	// nil tags (an untagged peer, the common grant.Tags case) must not error the eval, just miss the key.
	kept, _ = policyFilter(peer, nil, peer.AllowedIPs, id, pol)
	must.Eq(t, []string{"fdcc::1/128"}, kept, must.Sprint("untagged peer keeps only its identity /128"))
}

func TestPeerPolicy_WholePeerAllowedips(t *testing.T) {
	id := netip.MustParseAddr("fdcc::1")
	// all()/any() over peer.allowedips gives the same verdict for every route: all-or-nothing.
	pol, err := ParsePeerPolicy(`all(peer.allowedips, cidrSubset("fd00::/8", #))`)
	must.NoError(t, err)

	ula := Peer{PublicKey: "a", AllowedIPs: []string{"fdcc::1/128", "fd12:3::/48"}}
	kept, refused := policyFilter(ula, nil, ula.AllowedIPs, id, pol)
	must.Eq(t, ula.AllowedIPs, kept, must.Sprint("all routes ULA => all kept"))
	must.SliceEmpty(t, refused)

	mixed := Peer{PublicKey: "b", AllowedIPs: []string{"fdcc::1/128", "10.0.0.0/8"}}
	kept, refused = policyFilter(mixed, nil, mixed.AllowedIPs, id, pol)
	must.SliceEmpty(t, kept, must.Sprint("one non-ULA route => all() is false for every route, nothing kept (no identity exemption)"))
	must.Eq(t, []string{"fdcc::1/128", "10.0.0.0/8"}, refused)
}

func TestPolicyFilter(t *testing.T) {
	id := netip.MustParseAddr("fdcc::1")
	peer := Peer{PublicKey: "exit", AllowedIPs: []string{"fdcc::1/128", "0.0.0.0/0", "10.0.0.0/8"}}

	deny, err := ParsePeerPolicy(`false`)
	must.NoError(t, err)
	kept, refused := policyFilter(peer, nil, peer.AllowedIPs, id, deny)
	must.SliceEmpty(t, kept, must.Sprint("false refuses everything, including the identity /128"))
	must.Eq(t, peer.AllowedIPs, refused)

	idOnly, err := ParsePeerPolicy(`route == peer.address`)
	must.NoError(t, err)
	kept, refused = policyFilter(peer, nil, peer.AllowedIPs, id, idOnly)
	must.Eq(t, []string{"fdcc::1/128"}, kept, must.Sprint("only the identity /128 matches peer.address"))
	must.Eq(t, []string{"0.0.0.0/0", "10.0.0.0/8"}, refused)

	// reproduce the old identity exemption via an explicit predicate
	keepID, err := ParsePeerPolicy(`route == peer.address || (peer.key == "exit" && route in ["0.0.0.0/0", "::/0"])`)
	must.NoError(t, err)
	kept, refused = policyFilter(peer, nil, peer.AllowedIPs, id, keepID)
	must.Eq(t, []string{"fdcc::1/128", "0.0.0.0/0"}, kept, must.Sprint("identity kept by matching peer.address; only the default extra accepted"))
	must.Eq(t, []string{"10.0.0.0/8"}, refused)

	block, err := ParsePeerPolicy(`peer.key != "exit"`)
	must.NoError(t, err)
	kept, refused = policyFilter(peer, nil, peer.AllowedIPs, id, block)
	must.SliceEmpty(t, kept, must.Sprint("peer.key != exit refuses all of exit's routes"))
	must.Eq(t, peer.AllowedIPs, refused)

	dropID, err := ParsePeerPolicy(`peer.key != "exit" || route != peer.address`)
	must.NoError(t, err)
	kept, refused = policyFilter(peer, nil, peer.AllowedIPs, id, dropID)
	must.Eq(t, []string{"0.0.0.0/0", "10.0.0.0/8"}, kept, must.Sprint("only the identity /128 is dropped"))
	must.Eq(t, []string{"fdcc::1/128"}, refused)

	kept, refused = policyFilter(peer, nil, peer.AllowedIPs, id, nil)
	must.Eq(t, peer.AllowedIPs, kept)
	must.SliceEmpty(t, refused)
}

func TestPolicyFilter_MalformedCIDRRefused(t *testing.T) {
	pol, err := ParsePeerPolicy(`cidrSubset("10.0.0.0/8", route)`)
	must.NoError(t, err)
	peer := Peer{PublicKey: "x", AllowedIPs: []string{"fdcc::1/128", "not-a-cidr", "10.0.0.0/8"}}
	kept, refused := policyFilter(peer, nil, peer.AllowedIPs, netip.MustParseAddr("fdcc::1"), pol)
	must.Eq(t, []string{"10.0.0.0/8"}, kept, must.Sprint("only the 10/8 subnet matches; no identity exemption"))
	must.Eq(t, []string{"fdcc::1/128", "not-a-cidr"}, refused, must.Sprint("the identity is refused like any non-matching route; an unparseable route fails closed, never crashes"))
}

func TestPolicyFilter_EmptyAddressWhenNoPrefix(t *testing.T) {
	deny, err := ParsePeerPolicy(`false`)
	must.NoError(t, err)
	peer := Peer{AllowedIPs: []string{"fdcc::1/128", "10.0.0.0/8"}}
	kept, refused := policyFilter(peer, nil, peer.AllowedIPs, netip.Addr{}, deny)
	must.SliceEmpty(t, kept, must.Sprint("no overlay identity => nothing kept under deny-all"))
	must.Eq(t, []string{"fdcc::1/128", "10.0.0.0/8"}, refused)
}

func TestPolicyFilter_AddressMatchesOnlyExactHostRoute(t *testing.T) {
	idOnly, err := ParsePeerPolicy(`route == peer.address`)
	must.NoError(t, err)
	peer := Peer{AllowedIPs: []string{"fdcc::1/128", "fdcc::/64"}}
	kept, refused := policyFilter(peer, nil, peer.AllowedIPs, netip.MustParseAddr("fdcc::1"), idOnly)
	must.Eq(t, []string{"fdcc::1/128"}, kept, must.Sprint("route == peer.address matches only the exact /128"))
	must.Eq(t, []string{"fdcc::/64"}, refused, must.Sprint("a covering prefix is not the identity"))
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
	// a typo must fail at startup, not silently refuse every route at runtime
	_, err := ParsePeerPolicy(`peer.bogus == 1`)
	must.Error(t, err, must.Sprint("unknown field is caught by the typed env at compile"))
	_, err = ParsePeerPolicy(`nope(route)`)
	must.Error(t, err, must.Sprint("unknown function is caught at compile"))
}
