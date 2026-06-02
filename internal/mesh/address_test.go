package mesh

import (
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
