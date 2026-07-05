//go:build linux

package mesh

import (
	"fmt"
	"log/slog"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

const nftTable = "pigeon-mesh"

// installGossipFirewall owns a dedicated IPv6 nftables table that drops packets to the overlay gossip
// address:port arriving on any interface other than the wg device, so the gossip control plane is reachable
// only through the tunnels and not from a local process over the loopback path. The chain policy is accept,
// so it drops ONLY what it explicitly matches and never the host's other traffic; it touches only its own
// table, never the operator's, and removeGossipFirewall deletes it on graceful leave (guest teardown). The
// rule is static (the gossip port and overlay /128 are fixed at startup), so it needs no reconcile.
func (m *Mesh) installGossipFirewall() error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	// Drop any prior instance in its OWN batch: deleting a table that does not exist (the first run) fails
	// with ENOENT, and batched with the create below it would fail the whole flush, so flush it separately.
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
	addr := m.selfAddr.As16()
	port := binaryutil.BigEndian.PutUint16(uint16(m.cfg.GossipPort))
	// ip6 daddr <overlay/128> meta l4proto {udp,tcp} th dport <gossipPort> iifname != wg0 drop
	for _, l4proto := range []byte{17, 6} { // UDP, TCP
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(m.cfg.Iface)},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16}, // ip6 daddr
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr[:]},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{l4proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, // dport
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}})
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}
	slog.Info("gossip firewall installed", "table", nftTable, "port", m.cfg.GossipPort)
	return nil
}

// removeGossipFirewall deletes our table on graceful leave, leaving the operator's nftables untouched.
func (m *Mesh) removeGossipFirewall() {
	c, err := nftables.New()
	if err != nil {
		return
	}
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: nftTable})
	if err := c.Flush(); err != nil {
		slog.Warn("remove gossip firewall on leave", "err", err)
	}
}

// ifname renders an interface name as the fixed 16-byte NUL-padded form nftables matches IIFNAME against.
func ifname(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}
