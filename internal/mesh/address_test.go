package mesh

import (
	"bytes"
	"encoding/base64"
	"net"
	"net/netip"
	"testing"

	"github.com/shoenig/test/must"
)

func TestNormalizeEndpoint_IPv4WithPort(t *testing.T) {
	got, err := NormalizeEndpoint("203.0.113.7:1234")
	must.NoError(t, err)
	must.EqOp(t, "203.0.113.7:1234", got)
}

func TestNormalizeEndpoint_IPv6WithPort(t *testing.T) {
	got, err := NormalizeEndpoint("[2001:db8::1]:1234")
	must.NoError(t, err)
	must.EqOp(t, "[2001:db8::1]:1234", got)
}

func TestNormalizeEndpoint_Rejected(t *testing.T) {
	for _, bad := range []string{
		"203.0.113.7",
		"2001:db8::1",
		"203.0.113.7:bad",
		"",
	} {
		_, err := NormalizeEndpoint(bad)
		must.Error(t, err, must.Sprintf("input %q", bad))
	}
}

func TestNormalizeEndpoint_ResolvesHostname(t *testing.T) {
	got, err := NormalizeEndpoint("localhost:51820")
	must.NoError(t, err)
	host, _, err := net.SplitHostPort(got)
	must.NoError(t, err)
	must.NotNil(t, net.ParseIP(host), must.Sprintf("localhost should resolve to an IP, got %q", got))
}

func TestPickEndpointAddr_PrefersIPv6(t *testing.T) {
	got, ok := pickEndpointAddr([]netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("2001:db8::1"),
	})
	must.True(t, ok)
	must.EqOp(t, "2001:db8::1", got.String())
}

func TestPickEndpointAddr_FallsBackToIPv4(t *testing.T) {
	got, ok := pickEndpointAddr([]netip.Addr{netip.MustParseAddr("1.2.3.4")})
	must.True(t, ok)
	must.EqOp(t, "1.2.3.4", got.String())
}

func TestPickEndpointAddr_LexicalWithinFamily(t *testing.T) {
	got, ok := pickEndpointAddr([]netip.Addr{
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("2001:db8::1"),
	})
	must.True(t, ok)
	must.EqOp(t, "2001:db8::1", got.String())
}

func TestPickEndpointAddr_4In6Unmapped(t *testing.T) {
	got, ok := pickEndpointAddr([]netip.Addr{netip.MustParseAddr("::ffff:1.2.3.4")})
	must.True(t, ok)
	must.EqOp(t, "1.2.3.4", got.String())
}

func TestPickEndpointAddr_Empty(t *testing.T) {
	_, ok := pickEndpointAddr(nil)
	must.False(t, ok)
}

func TestParseAllowedIPs_Single(t *testing.T) {
	out, err := ParseAllowedIPs("fd00::1/128")
	must.NoError(t, err)
	must.SliceLen(t, 1, out)
	must.EqOp(t, "fd00::1/128", out[0])
}

func TestParseAllowedIPs_Multiple(t *testing.T) {
	out, err := ParseAllowedIPs("fd00::1/128, 192.168.1.0/24 ,fd01::/64")
	must.NoError(t, err)
	must.SliceLen(t, 3, out)
	must.EqOp(t, "192.168.1.0/24", out[1])
}

func TestParseAllowedIPs_MasksHostBits(t *testing.T) {
	out, err := ParseAllowedIPs("fdcc::dead/64")
	must.NoError(t, err)
	must.SliceLen(t, 1, out)
	must.EqOp(t, "fdcc::/64", out[0])
}

func TestParseAllowedIPs_Rejected(t *testing.T) {
	for _, bad := range []string{
		"",
		"   ",
		"not-a-cidr",
		"192.168.1.0/24,not-a-cidr",
	} {
		_, err := ParseAllowedIPs(bad)
		must.Error(t, err, must.Sprintf("input %q", bad))
	}
}

func TestDeriveAddr_Deterministic(t *testing.T) {
	prefix := netip.MustParsePrefix("fdcc::/16")
	a, err := DeriveAddr(testKey, prefix)
	must.NoError(t, err)
	b, err := DeriveAddr(testKey, prefix)
	must.NoError(t, err)
	must.EqOp(t, a, b)
}

func TestDeriveAddr_InPrefixAndDistinct(t *testing.T) {
	prefix := netip.MustParsePrefix("fdcc::/16")
	a, err := DeriveAddr(testKey, prefix)
	must.NoError(t, err)
	must.True(t, prefix.Contains(a), must.Sprintf("derived %s not in %s", a, prefix))
	must.EqOp(t, 128, a.BitLen())

	other := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	b, err := DeriveAddr(other, prefix)
	must.NoError(t, err)
	must.NotEqOp(t, a, b)
}

func TestDeriveAddr_Rejected(t *testing.T) {
	for _, bad := range []struct {
		prefix string
		key    string
	}{
		{"10.0.0.0/8", testKey},
		{"fdcc::/17", testKey},
		{"fdcc::/96", testKey},
		{"fdcc::/16", "not base64"},
	} {
		_, err := DeriveAddr(bad.key, netip.MustParsePrefix(bad.prefix))
		must.Error(t, err, must.Sprintf("%+v", bad))
	}
}

func TestValidateOverlayAddr(t *testing.T) {
	prefix := netip.MustParsePrefix("fdcc::/16")
	want, err := DeriveAddr(testKey, prefix)
	must.NoError(t, err)
	self := HostRoute(want).String()

	addr, err := validateOverlayAddr(testKey, Peer{AllowedIPs: []string{self}}, prefix)
	must.NoError(t, err)
	must.EqOp(t, want, addr)
	_, err = validateOverlayAddr(testKey, Peer{AllowedIPs: []string{self, "10.0.0.0/24"}}, prefix)
	must.NoError(t, err, must.Sprint("out-of-prefix extra route is allowed"))

	for _, bad := range [][]string{
		{"fdcc::dead/128"},
		{"10.0.0.0/24"},
		{self, "fdcc:1::/64"},
		{self, "fd00::/8"},
		{self, "fc00::/7"},
		{self, "::/0"},
	} {
		_, err := validateOverlayAddr(testKey, Peer{AllowedIPs: bad}, prefix)
		must.Error(t, err, must.Sprintf("AllowedIPs %v", bad))
	}
}
