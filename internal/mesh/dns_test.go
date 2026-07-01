//go:build linux

package mesh

import (
	"net/netip"
	"testing"

	"github.com/shoenig/test/must"
)

func TestBuildDNSRecords(t *testing.T) {
	self := netip.MustParseAddr("fdcc::1")
	a := netip.MustParseAddr("fdcc::a")
	b := netip.MustParseAddr("fdcc::b")
	named := func(addr netip.Addr, name string) member {
		return member{
			addr:   addr,
			wgPeer: wgPeer{routes: []string{HostRoute(addr).String()}}, // identity /128 installed
			name:   name,
		}
	}

	t.Run("self and peers resolve by name", func(t *testing.T) {
		members := map[string]member{"A": named(a, "alpha"), "B": named(b, "beta")}
		got := buildDNSRecords(members, nil, self, "self")
		must.Eq(t, map[string]netip.Addr{"self": self, "alpha": a, "beta": b}, got)
	})

	t.Run("a name two peers claim resolves to nothing", func(t *testing.T) {
		members := map[string]member{"A": named(a, "dup"), "B": named(b, "dup")}
		got := buildDNSRecords(members, nil, netip.Addr{}, "")
		must.MapNotContainsKey(t, got, "dup", must.Sprint("a contested label is dropped, not resolved to one claimant"))
	})

	t.Run("a peer whose overlay address is contested does not resolve", func(t *testing.T) {
		members := map[string]member{"A": named(a, "alpha")}
		contested := map[string][]string{HostRoute(a).String(): {"A", "impostor"}}
		got := buildDNSRecords(members, contested, netip.Addr{}, "")
		must.MapEmpty(t, got)
	})

	t.Run("an expired self (invalid address) is omitted", func(t *testing.T) {
		got := buildDNSRecords(nil, nil, netip.Addr{}, "self")
		must.MapEmpty(t, got)
	})

	t.Run("a policy-blocked peer (its /128 not installed) does not resolve", func(t *testing.T) {
		blocked := member{addr: a, wgPeer: wgPeer{routes: nil}, name: "alpha"}
		members := map[string]member{"A": blocked}
		got := buildDNSRecords(members, nil, netip.Addr{}, "")
		must.MapEmpty(t, got, must.Sprint("no black-hole record for a peer this node does not route to"))
	})
}
