package mesh

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

func buildReply(r *dns.Msg, zone string, table map[string]netip.Addr) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	for _, q := range r.Question {
		qn := strings.ToLower(strings.TrimSuffix(q.Name, "."))
		if !inZone(qn, zone) {
			msg.Rcode = dns.RcodeRefused
			continue
		}
		label, ok := queryLabel(qn, zone)
		if !ok {
			msg.Rcode = dns.RcodeNameError
			msg.Ns = append(msg.Ns, soa(zone))
			continue
		}
		addr, known := table[label]
		if known && q.Qtype == dns.TypeAAAA {
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: dnsTTL},
				AAAA: net.IP(addr.AsSlice()),
			})
			continue
		}
		if !known {
			msg.Rcode = dns.RcodeNameError
		}
		msg.Ns = append(msg.Ns, soa(zone))
	}
	return msg
}
