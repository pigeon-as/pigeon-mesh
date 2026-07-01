//go:build linux

package mesh

import (
	"context"
	"net/netip"
	"slices"

	"github.com/pigeon-as/pigeon-mesh/internal/dns"
)

func (m *Mesh) serveDNS(ctx context.Context) {
	if m.cfg.DNSZone == "" {
		return
	}
	dns.Serve(ctx, dns.Config{Iface: m.cfg.Iface, Addr: m.selfAddr, Zone: m.cfg.DNSZone}, m.dnsRecords)
}

func (m *Mesh) dnsRecords() map[string]netip.Addr {
	members, contested := m.liveMembers()
	self := m.selfAddr
	// Expiry is a known-future event, so the maintain-tick latch lag is immaterial; a revocation arrives
	// unpredictably over gossip, so read it live (like status) to drop self from its own zone at once.
	if m.selfExpired.Load() {
		self = netip.Addr{}
	} else if _, revoked := (*m.revoked.Load())[m.cfg.Self.PublicKey]; revoked {
		self = netip.Addr{}
	}
	return buildDNSRecords(members, contested, self, m.cfg.Self.Tags)
}

func buildDNSRecords(members map[string]member, contested map[string][]string, self netip.Addr, selfTags Tags) map[string]netip.Addr {
	records := make(map[string]netip.Addr, len(members)+1)
	collided := make(map[string]bool)
	add := func(addr netip.Addr, tags Tags) {
		label := dns.SanitizeLabel(tags["name"])
		if label == "" || collided[label] || !addr.IsValid() {
			return
		}
		if existing, dup := records[label]; dup && existing != addr {
			delete(records, label) // contested name resolves to neither
			collided[label] = true
			return
		}
		records[label] = addr
	}
	add(self, selfTags)
	for _, e := range members {
		if !e.addr.IsValid() {
			continue
		}
		// no black-hole records: skip unrouted and contested
		host := HostRoute(e.addr).String()
		if !slices.Contains(e.wgPeer.routes, host) {
			continue
		}
		if _, c := contested[host]; c {
			continue
		}
		add(e.addr, e.peer.Tags)
	}
	return records
}
