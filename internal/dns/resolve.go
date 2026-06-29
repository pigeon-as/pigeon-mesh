package dns

import (
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

const dnsTTL = 30

func normalizeZone(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

func SanitizeLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return ""
		}
	}
	return s
}

func inZone(qname, zone string) bool {
	return qname == zone || strings.HasSuffix(qname, "."+zone)
}

func queryLabel(qname, zone string) (string, bool) {
	suffix := "." + zone
	if !strings.HasSuffix(qname, suffix) {
		return "", false
	}
	head := qname[:len(qname)-len(suffix)]
	if head == "" || strings.Contains(head, ".") {
		return "", false
	}
	return head, true
}

func soa(zone string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone + ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: dnsTTL},
		Ns:      "ns." + zone + ".",
		Mbox:    "hostmaster." + zone + ".",
		Serial:  1,
		Refresh: 300,
		Retry:   60,
		Expire:  3600,
		Minttl:  dnsTTL,
	}
}

func reply(r *dns.Msg, zone string, records map[string]netip.Addr) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	if len(r.Question) != 1 {
		msg.Rcode = dns.RcodeFormatError
		return msg
	}
	q := r.Question[0]
	qn := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if !inZone(qn, zone) {
		msg.Rcode = dns.RcodeRefused
		return msg
	}
	label, ok := queryLabel(qn, zone)
	if !ok {
		msg.Rcode = dns.RcodeNameError
		msg.Ns = append(msg.Ns, soa(zone))
		return msg
	}
	addr, known := records[label]
	if !known {
		msg.Rcode = dns.RcodeNameError
		msg.Ns = append(msg.Ns, soa(zone))
		return msg
	}
	hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: dnsTTL}
	switch addr = addr.Unmap(); {
	case q.Qtype == dns.TypeAAAA && addr.Is6():
		hdr.Rrtype = dns.TypeAAAA
		msg.Answer = append(msg.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IP(addr.AsSlice())})
	case q.Qtype == dns.TypeA && addr.Is4():
		hdr.Rrtype = dns.TypeA
		msg.Answer = append(msg.Answer, &dns.A{Hdr: hdr, A: net.IP(addr.AsSlice())})
	default:
		msg.Ns = append(msg.Ns, soa(zone))
	}
	return msg
}
