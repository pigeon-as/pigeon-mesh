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
		return member{addr: addr, peer: Peer{Tags: Tags{"name": name}}}
	}

	t.Run("self and peers resolve by name", func(t *testing.T) {
		members := map[string]member{"A": named(a, "alpha"), "B": named(b, "beta")}
		got := buildDNSRecords([]string{"A", "B"}, members, nil, self, Tags{"name": "self"})
		must.Eq(t, map[string]netip.Addr{"self": self, "alpha": a, "beta": b}, got)
	})

	t.Run("a name two peers claim resolves to nothing", func(t *testing.T) {
		members := map[string]member{"A": named(a, "dup"), "B": named(b, "dup")}
		got := buildDNSRecords([]string{"A", "B"}, members, nil, netip.Addr{}, nil)
		must.MapNotContainsKey(t, got, "dup", must.Sprint("a contested label is dropped, not resolved to one claimant"))
	})

	t.Run("a peer whose overlay address is contested does not resolve", func(t *testing.T) {
		members := map[string]member{"A": named(a, "alpha")}
		contested := map[string][]string{HostRoute(a).String(): {"A", "impostor"}}
		got := buildDNSRecords([]string{"A"}, members, contested, netip.Addr{}, nil)
		must.MapEmpty(t, got)
	})

	t.Run("an expired self (invalid address) is omitted", func(t *testing.T) {
		got := buildDNSRecords(nil, nil, nil, netip.Addr{}, Tags{"name": "self"})
		must.MapEmpty(t, got)
	})

	t.Run("an alive node with no accepted member entry is skipped", func(t *testing.T) {
		got := buildDNSRecords([]string{"ghost"}, map[string]member{}, nil, netip.Addr{}, nil)
		must.MapEmpty(t, got)
	})
}
