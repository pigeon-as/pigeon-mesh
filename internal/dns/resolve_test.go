package dns

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/shoenig/test/must"
)

func TestNormalizeZone(t *testing.T) {
	must.EqOp(t, "mesh.internal", normalizeZone("Mesh.Internal."))
	must.EqOp(t, "mesh.internal", normalizeZone("  mesh.internal  "))
	must.EqOp(t, "", normalizeZone(""))
	must.EqOp(t, "", normalizeZone("  "))
}

func TestSanitizeLabel(t *testing.T) {
	must.EqOp(t, "beta", SanitizeLabel("beta"))
	must.EqOp(t, "beta", SanitizeLabel("BETA"))
	must.EqOp(t, "web-1", SanitizeLabel("web-1"))
	must.EqOp(t, "a", SanitizeLabel(" a "))

	for _, bad := range []string{
		"",
		"-lead",
		"trail-",
		"under_score",
		"dot.ted",
		"spaces in",
		"héllo",
		"012345678901234567890123456789012345678901234567890123456789abcd",
	} {
		must.EqOp(t, "", SanitizeLabel(bad), must.Sprintf("input %q", bad))
	}

	must.EqOp(t, "012345678901234567890123456789012345678901234567890123456789abc",
		SanitizeLabel("012345678901234567890123456789012345678901234567890123456789abc"))
}

func TestQueryLabel(t *testing.T) {
	for _, tc := range []struct {
		qname, want string
		ok          bool
	}{
		{"beta.mesh.internal", "beta", true},
		{"mesh.internal", "", false},
		{"a.b.mesh.internal", "", false},
		{"beta.example.com", "", false},
	} {
		got, ok := queryLabel(tc.qname, "mesh.internal")
		must.EqOp(t, tc.ok, ok, must.Sprintf("qname %q", tc.qname))
		must.EqOp(t, tc.want, got, must.Sprintf("qname %q", tc.qname))
	}
}

func aaaaQuery(name string, qtype uint16) *dns.Msg {
	r := new(dns.Msg)
	r.SetQuestion(dns.Fqdn(name), qtype)
	return r
}

func TestReply_KnownAAAA(t *testing.T) {
	table := map[string]netip.Addr{"beta": netip.MustParseAddr("fdcc::1")}
	resp := reply(aaaaQuery("beta.mesh.internal", dns.TypeAAAA), "mesh.internal", table)

	must.EqOp(t, dns.RcodeSuccess, resp.Rcode)
	must.True(t, resp.Authoritative)
	must.SliceLen(t, 1, resp.Answer)
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	must.True(t, ok)
	must.EqOp(t, "fdcc::1", aaaa.AAAA.String())
	must.EqOp(t, uint32(dnsTTL), aaaa.Hdr.Ttl)
}

func TestReply_UnknownNXDOMAIN(t *testing.T) {
	table := map[string]netip.Addr{"beta": netip.MustParseAddr("fdcc::1")}
	resp := reply(aaaaQuery("nope.mesh.internal", dns.TypeAAAA), "mesh.internal", table)

	must.EqOp(t, dns.RcodeNameError, resp.Rcode)
	must.SliceLen(t, 0, resp.Answer)
	must.SliceLen(t, 1, resp.Ns)
	soa, ok := resp.Ns[0].(*dns.SOA)
	must.True(t, ok)
	must.EqOp(t, uint32(dnsTTL), soa.Minttl)
}

func TestReply_OutOfZoneRefused(t *testing.T) {
	resp := reply(aaaaQuery("foo.example.com", dns.TypeAAAA), "mesh.internal", nil)
	must.EqOp(t, dns.RcodeRefused, resp.Rcode)
	must.SliceLen(t, 0, resp.Answer)
}

func TestReply_KnownNameWrongTypeNODATA(t *testing.T) {
	table := map[string]netip.Addr{"beta": netip.MustParseAddr("fdcc::1")}
	resp := reply(aaaaQuery("beta.mesh.internal", dns.TypeA), "mesh.internal", table)

	must.EqOp(t, dns.RcodeSuccess, resp.Rcode)
	must.SliceLen(t, 0, resp.Answer)
	must.SliceLen(t, 1, resp.Ns)
}

func TestReply_ApexNXDOMAIN(t *testing.T) {
	resp := reply(aaaaQuery("mesh.internal", dns.TypeAAAA), "mesh.internal", nil)
	must.EqOp(t, dns.RcodeNameError, resp.Rcode)
	must.SliceLen(t, 1, resp.Ns)
}

func TestReply_KnownA_IPv4(t *testing.T) {
	table := map[string]netip.Addr{"beta": netip.MustParseAddr("10.0.0.5")}
	resp := reply(aaaaQuery("beta.mesh.internal", dns.TypeA), "mesh.internal", table)

	must.EqOp(t, dns.RcodeSuccess, resp.Rcode)
	must.SliceLen(t, 1, resp.Answer)
	a, ok := resp.Answer[0].(*dns.A)
	must.True(t, ok)
	must.EqOp(t, "10.0.0.5", a.A.String())
	must.EqOp(t, uint32(dnsTTL), a.Hdr.Ttl)

	// An AAAA query for an IPv4-only name is NODATA, not a malformed AAAA record.
	resp = reply(aaaaQuery("beta.mesh.internal", dns.TypeAAAA), "mesh.internal", table)
	must.EqOp(t, dns.RcodeSuccess, resp.Rcode)
	must.SliceLen(t, 0, resp.Answer)
	must.SliceLen(t, 1, resp.Ns)
	_, err := resp.Pack()
	must.NoError(t, err, must.Sprint("reply must always serialize"))
}

func TestReply_MultiQuestionFormErr(t *testing.T) {
	r := new(dns.Msg)
	r.Question = []dns.Question{
		{Name: dns.Fqdn("a.mesh.internal"), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		{Name: dns.Fqdn("b.mesh.internal"), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
	}
	resp := reply(r, "mesh.internal", nil)
	must.EqOp(t, dns.RcodeFormatError, resp.Rcode)
	must.SliceLen(t, 0, resp.Answer)
}

func TestReply_QnameCaseInsensitive(t *testing.T) {
	table := map[string]netip.Addr{"beta": netip.MustParseAddr("fdcc::1")}
	resp := reply(aaaaQuery("BeTa.MESH.Internal", dns.TypeAAAA), "mesh.internal", table)
	must.EqOp(t, dns.RcodeSuccess, resp.Rcode)
	must.SliceLen(t, 1, resp.Answer)
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	must.True(t, ok)
	must.EqOp(t, "fdcc::1", netip.MustParseAddr(aaaa.AAAA.String()).String())
	must.EqOp(t, "BeTa.MESH.Internal.", aaaa.Hdr.Name, must.Sprint("answer echoes the queried name's case"))
}

func TestReply_MappedV4IsARecord(t *testing.T) {
	// A v4-in-v6 mapped address resolves as an A record, not a bogus AAAA.
	table := map[string]netip.Addr{"beta": netip.MustParseAddr("::ffff:10.0.0.5")}
	resp := reply(aaaaQuery("beta.mesh.internal", dns.TypeA), "mesh.internal", table)
	must.EqOp(t, dns.RcodeSuccess, resp.Rcode)
	must.SliceLen(t, 1, resp.Answer)
	a, ok := resp.Answer[0].(*dns.A)
	must.True(t, ok)
	must.EqOp(t, "10.0.0.5", a.A.String())

	resp = reply(aaaaQuery("beta.mesh.internal", dns.TypeAAAA), "mesh.internal", table)
	must.SliceLen(t, 0, resp.Answer, must.Sprint("AAAA for a mapped-v4 name is NODATA"))
	must.SliceLen(t, 1, resp.Ns)
	_, err := resp.Pack()
	must.NoError(t, err)
}
