//go:build linux

package mesh

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/hashicorp/memberlist"
	"github.com/pigeon-as/pigeon-mesh/internal/dns"
)

// serveDNS runs the overlay DNS server, fed by dnsRecords. No-op unless --dns set a zone.
func (m *Mesh) serveDNS(ctx context.Context) {
	if m.cfg.DNSZone == "" {
		return
	}
	dns.Serve(ctx, dns.Config{Iface: m.cfg.Iface, Addr: m.selfAddr, Zone: m.cfg.DNSZone}, m.dnsRecords)
}

// dnsRecords is the live name->address set, called per query by the DNS server.
func (m *Mesh) dnsRecords() map[string]netip.Addr {
	members, contested := m.liveMembers()
	var alive []string
	for _, n := range m.memberlist.Members() {
		if n.Name != m.cfg.Self.PublicKey && n.State == memberlist.StateAlive {
			alive = append(alive, n.Name)
		}
	}
	self := m.selfAddr
	if m.selfExpired.Load() {
		self = netip.Addr{} // expired: invalid addr drops self from DNS
	}
	return buildDNSRecords(alive, members, contested, self, m.cfg.Self.Tags)
}

// buildDNSRecords maps each alive, accepted, uncontested member's name= tag to its address, plus
// self. Drops any label more than one peer claims. Pure.
func buildDNSRecords(alive []string, members map[string]member, contested map[string][]string, self netip.Addr, selfTags Tags) map[string]netip.Addr {
	records := make(map[string]netip.Addr, len(alive)+1)
	collided := make(map[string]bool)
	add := func(addr netip.Addr, tags Tags) {
		label := dns.SanitizeLabel(tags["name"])
		if label == "" || collided[label] || !addr.IsValid() {
			return
		}
		if existing, dup := records[label]; dup && existing != addr {
			delete(records, label)
			collided[label] = true
			slog.Warn("dns name claimed by more than one peer; not resolving it", "name", label)
			return
		}
		records[label] = addr
	}
	add(self, selfTags)
	for _, name := range alive {
		e, ok := members[name]
		if !ok {
			continue
		}
		if e.addr.IsValid() {
			if _, c := contested[HostRoute(e.addr).String()]; c {
				continue
			}
		}
		add(e.addr, e.peer.Tags)
	}
	return records
}
