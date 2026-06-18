package mesh

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

func TestBuildReply_KnownAAAA(t *testing.T) {
	table := map[string]netip.Addr{"beta": netip.MustParseAddr("fdcc::1")}
	reply := buildReply(aaaaQuery("beta.mesh.internal", dns.TypeAAAA), "mesh.internal", table)

	must.EqOp(t, dns.RcodeSuccess, reply.Rcode)
	must.True(t, reply.Authoritative)
	must.SliceLen(t, 1, reply.Answer)
	aaaa, ok := reply.Answer[0].(*dns.AAAA)
	must.True(t, ok)
	must.EqOp(t, "fdcc::1", aaaa.AAAA.String())
	must.EqOp(t, uint32(dnsTTL), aaaa.Hdr.Ttl)
}

func TestBuildReply_UnknownNXDOMAIN(t *testing.T) {
	table := map[string]netip.Addr{"beta": netip.MustParseAddr("fdcc::1")}
	reply := buildReply(aaaaQuery("nope.mesh.internal", dns.TypeAAAA), "mesh.internal", table)

	must.EqOp(t, dns.RcodeNameError, reply.Rcode)
	must.SliceLen(t, 0, reply.Answer)
	must.SliceLen(t, 1, reply.Ns)
	soa, ok := reply.Ns[0].(*dns.SOA)
	must.True(t, ok)
	must.EqOp(t, uint32(dnsTTL), soa.Minttl)
}

func TestBuildReply_OutOfZoneRefused(t *testing.T) {
	reply := buildReply(aaaaQuery("foo.example.com", dns.TypeAAAA), "mesh.internal", nil)
	must.EqOp(t, dns.RcodeRefused, reply.Rcode)
	must.SliceLen(t, 0, reply.Answer)
}

func TestBuildReply_KnownNameWrongTypeNODATA(t *testing.T) {
	table := map[string]netip.Addr{"beta": netip.MustParseAddr("fdcc::1")}
	reply := buildReply(aaaaQuery("beta.mesh.internal", dns.TypeA), "mesh.internal", table)

	must.EqOp(t, dns.RcodeSuccess, reply.Rcode)
	must.SliceLen(t, 0, reply.Answer)
	must.SliceLen(t, 1, reply.Ns)
}

func TestBuildReply_ApexNXDOMAIN(t *testing.T) {
	reply := buildReply(aaaaQuery("mesh.internal", dns.TypeAAAA), "mesh.internal", nil)
	must.EqOp(t, dns.RcodeNameError, reply.Rcode)
	must.SliceLen(t, 1, reply.Ns)
}

func TestBuildReply_KnownA_IPv4(t *testing.T) {
	table := map[string]netip.Addr{"beta": netip.MustParseAddr("10.0.0.5")}
	reply := buildReply(aaaaQuery("beta.mesh.internal", dns.TypeA), "mesh.internal", table)

	must.EqOp(t, dns.RcodeSuccess, reply.Rcode)
	must.SliceLen(t, 1, reply.Answer)
	a, ok := reply.Answer[0].(*dns.A)
	must.True(t, ok)
	must.EqOp(t, "10.0.0.5", a.A.String())
	must.EqOp(t, uint32(dnsTTL), a.Hdr.Ttl)

	// An AAAA query for an IPv4-only name is NODATA, not a malformed AAAA record.
	reply = buildReply(aaaaQuery("beta.mesh.internal", dns.TypeAAAA), "mesh.internal", table)
	must.EqOp(t, dns.RcodeSuccess, reply.Rcode)
	must.SliceLen(t, 0, reply.Answer)
	must.SliceLen(t, 1, reply.Ns)
	_, err := reply.Pack()
	must.NoError(t, err, must.Sprint("reply must always serialize"))
}

func TestBuildReply_MultiQuestionFormErr(t *testing.T) {
	r := new(dns.Msg)
	r.Question = []dns.Question{
		{Name: dns.Fqdn("a.mesh.internal"), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		{Name: dns.Fqdn("b.mesh.internal"), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
	}
	reply := buildReply(r, "mesh.internal", nil)
	must.EqOp(t, dns.RcodeFormatError, reply.Rcode)
	must.SliceLen(t, 0, reply.Answer)
}
