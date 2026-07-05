//go:build linux

package mesh

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

const nftTable = "pigeon-mesh"

// l4proto numbers.
const (
	protoICMPv6 = 58
	protoTCP    = 6
	protoUDP    = 17
)

// reconcileFirewall rebuilds our dedicated ip6 nftables table to match the current rules and membership.
// With no --firewall-rules it is just the gossip guard (drop gossip to the overlay from off the wg device);
// with rules it is default-deny for traffic to this node's overlay address, allowing only what the predicate
// admits (plus ICMPv6, gossip, and established flows so the mesh and IPv6 keep working). The daemon only
// updates this table at reconcile; nftables enforces, so the daemon stays out of the datapath. Non-fatal.
func (m *Mesh) reconcileFirewall() {
	if !m.cfg.Firewall {
		return
	}
	rules := m.firewallRules.Load()
	fingerprint, ruleExprs := m.firewallRuleset(rules)
	if fingerprint == m.fwApplied {
		return
	}
	if err := m.applyFirewall(ruleExprs); err != nil {
		if !m.fwWarned { // warn once, then keep retrying quietly (e.g. nftables unavailable in a netns)
			slog.Warn("apply firewall", "err", err)
			m.fwWarned = true
		}
		return
	}
	m.fwWarned = false
	m.fwApplied = fingerprint
	if rules == nil {
		slog.Info("gossip firewall installed", "table", nftTable, "port", m.cfg.GossipPort)
	} else {
		slog.Info("firewall rules applied", "table", nftTable, "peers", strings.Count(fingerprint, "\n"))
	}
}

// firewallRuleset returns a stable fingerprint of the desired table and the ordered rule expressions to
// install. rules==nil is the gossip-guard-only mode; otherwise it is the microsegmentation ruleset.
func (m *Mesh) firewallRuleset(rules *FirewallPolicy) (string, [][]expr.Any) {
	self := m.selfAddr.As16()
	port := uint16(m.cfg.GossipPort)

	if rules == nil {
		var out [][]expr.Any
		for _, l4 := range []byte{protoUDP, protoTCP} {
			out = append(out, gossipGuardRule(m.cfg.Iface, self, l4, port))
		}
		return "guard:" + strconv.Itoa(m.cfg.GossipPort), out
	}

	// Preamble: leave non-overlay traffic alone, keep IPv6/return-path/gossip working, then default-deny.
	out := [][]expr.Any{
		acceptOtherDests(self),
		acceptEstablished(),
		acceptICMPv6(),
		acceptGossip(m.cfg.Iface, self, protoUDP, port),
		acceptGossip(m.cfg.Iface, self, protoTCP, port),
	}
	var fp strings.Builder
	fp.WriteString("microseg\n")
	for _, p := range m.firewallPeers(rules) {
		fp.WriteString(p.addr.String())
		for _, r := range p.rules.tcp {
			out = append(out, acceptPeerPort(p.addr.As16(), protoTCP, r))
			fmt.Fprintf(&fp, " t%d-%d", r.lo, r.hi)
		}
		for _, r := range p.rules.udp {
			out = append(out, acceptPeerPort(p.addr.As16(), protoUDP, r))
			fmt.Fprintf(&fp, " u%d-%d", r.lo, r.hi)
		}
		fp.WriteByte('\n')
	}
	out = append(out, defaultDeny(self))
	return fp.String(), out
}

type fwPeerRules struct {
	addr  netip.Addr
	rules peerRules
}

// firewallPeers compiles the rules for every admitted peer, sorted by address for a stable ruleset.
func (m *Mesh) firewallPeers(rules *FirewallPolicy) []fwPeerRules {
	members, _ := m.liveMembers()
	out := make([]fwPeerRules, 0, len(members))
	for name, e := range members {
		if !e.addr.IsValid() {
			continue
		}
		pr, err := rules.compilePeer(fwPeer{
			Key:      name,
			Address:  HostRoute(e.addr).String(),
			Endpoint: e.peer.Endpoint,
			Tags:     e.tags,
		})
		if err != nil {
			slog.Warn("compile firewall rule for peer", "pubkey", name, "err", err)
			continue
		}
		if pr.empty() {
			continue
		}
		out = append(out, fwPeerRules{addr: e.addr, rules: pr})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].addr.Less(out[j].addr) })
	return out
}

// applyFirewall rebuilds our table atomically: drop any prior instance in its OWN flush (DelTable of a
// nonexistent table returns ENOENT and would fail a combined create batch), then create table, chain, rules.
func (m *Mesh) applyFirewall(ruleExprs [][]expr.Any) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: nftTable})
	_ = c.Flush()

	t := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: nftTable})
	accept := nftables.ChainPolicyAccept
	ch := c.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    t,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &accept,
	})
	for _, ex := range ruleExprs {
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: ex})
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}
	return nil
}

// removeFirewall deletes our table on graceful leave, leaving the operator's nftables untouched.
func (m *Mesh) removeFirewall() {
	c, err := nftables.New()
	if err != nil {
		return
	}
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: nftTable})
	if err := c.Flush(); err != nil {
		slog.Warn("remove firewall on leave", "err", err)
	}
	m.fwApplied = ""
}

// gossipGuardRule drops gossip-port packets to the overlay address arriving on any interface but the wg
// device, so gossip is reachable through the tunnels, not over loopback. Chain policy is accept, so it drops
// only what it matches.
func gossipGuardRule(iface string, self [16]byte, l4proto byte, port uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(iface)},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16}, // ip6 daddr
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: self[:]},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{l4proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, // dport
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// acceptOtherDests accepts anything not destined to our overlay address, so the host's own traffic is untouched.
func acceptOtherDests(self [16]byte) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: self[:]},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// acceptEstablished accepts return traffic for this node's own outbound connections.
func acceptEstablished() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:  binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// acceptICMPv6 allows all ICMPv6 (RFC 4890): blocking ND or packet-too-big breaks IPv6 and PMTU.
func acceptICMPv6() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoICMPv6}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// acceptGossip always allows the gossip port arriving on the wg device, so membership keeps working.
func acceptGossip(iface string, self [16]byte, l4proto byte, port uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(iface)},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: self[:]},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{l4proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// acceptPeerPort allows one proto/port span from a specific peer's overlay /128.
func acceptPeerPort(saddr [16]byte, l4proto byte, r portRange) []expr.Any {
	ex := []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16}, // ip6 saddr
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: saddr[:]},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{l4proto}},
	}
	if r.lo > 0 || r.hi < maxPort { // omit the dport match for an all-ports span
		ex = append(ex, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
		if r.lo == r.hi {
			ex = append(ex, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(r.lo))})
		} else {
			ex = append(ex, &expr.Range{
				Op: expr.CmpOpEq, Register: 1,
				FromData: binaryutil.BigEndian.PutUint16(uint16(r.lo)),
				ToData:   binaryutil.BigEndian.PutUint16(uint16(r.hi)),
			})
		}
	}
	return append(ex, &expr.Verdict{Kind: expr.VerdictAccept})
}

// defaultDeny is the default-deny: everything to our overlay address not already accepted.
func defaultDeny(self [16]byte) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: self[:]},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// ifname renders an interface name as the fixed 16-byte NUL-padded form nftables matches IIFNAME against.
func ifname(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}
