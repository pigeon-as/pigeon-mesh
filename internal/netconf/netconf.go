//go:build linux

package netconf

import (
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	addr "github.com/pigeon-as/pigeon-addr-plan"
	"golang.org/x/sys/unix"
)

const (
	tableNAT       = "pigeon-mesh-nat"
	tableTranspose = "pigeon-transpose"

	// IPv6 header byte offsets for src/dst address fields.
	ipv6SrcOffset = 8
	ipv6DstOffset = 24

	// Byte offsets within a 16-byte IPv6 address for pigeon's
	// 32-bit network and host fields (fdaa:[net32]:[host32]:...).
	addrNetField  = 2
	addrHostField = 6
	fieldLen      = 4
)

// SetupNftables creates CGNAT masquerade rules in its own table.
func SetupNftables(iface, egressCIDR string) error {
	cleanup := &nftables.Conn{}
	cleanup.DelTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableNAT,
	})
	_ = cleanup.Flush()

	if egressCIDR == "" {
		return nil
	}

	conn := &nftables.Conn{}

	_, ipNet, err := net.ParseCIDR(egressCIDR)
	if err != nil {
		return fmt.Errorf("parse egress CIDR: %w", err)
	}
	networkIP := ipNet.IP.Mask(ipNet.Mask)
	ip4 := networkIP.To4()
	if ip4 == nil {
		return fmt.Errorf("egress CIDR must be IPv4: %s", egressCIDR)
	}

	natTable := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableNAT,
	})
	chain := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	conn.AddRule(&nftables.Rule{
		Table: natTable,
		Chain: chain,
		Exprs: masqueradeExprs(iface, ip4, ipNet.Mask),
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}
	return nil
}

// masqueradeExprs: meta nfproto ipv4 oifname != <iface> ip saddr <cidr> masquerade
func masqueradeExprs(iface string, networkIP net.IP, mask net.IPMask) []expr.Any {
	ifaceBuf := make([]byte, 16)
	copy(ifaceBuf, iface)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifaceBuf},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte(mask), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(networkIP)},
		&expr.Masq{},
	}
}

// SetupTranspose creates netdev rules that swap network/host fields of fdaa::
// addresses (self-inverse) for WireGuard cryptokey routing.
func SetupTranspose(iface string) error {
	cleanup := &nftables.Conn{}
	cleanup.DelTable(&nftables.Table{
		Family: nftables.TableFamilyNetdev,
		Name:   tableTranspose,
	})
	_ = cleanup.Flush()

	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyNetdev,
		Name:   tableTranspose,
	})

	hooks := []struct {
		name string
		hook *nftables.ChainHook
	}{
		{"ingress", nftables.ChainHookIngress},
		{"egress", nftables.ChainHookEgress},
	}
	for _, h := range hooks {
		chain := conn.AddChain(&nftables.Chain{
			Name:     h.name,
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  h.hook,
			Priority: nftables.ChainPriorityFilter,
			Device:   iface,
		})

		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: transposeExprs(ipv6SrcOffset)})
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: transposeExprs(ipv6DstOffset)})
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush transpose: %w", err)
	}
	return nil
}

// transposeExprs swaps network ↔ host fields in a pigeon ULA address.
// No checksum fixup needed (16-bit-aligned swap).
func transposeExprs(addrOffset uint32) []expr.Any {
	ula := addr.PigeonULARange()
	prefixBytes := ula.Bits() / 8
	raw := ula.Addr().As16()

	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyPROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x86, 0xDD}}, // EtherType IPv6
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset, Len: uint32(prefixBytes)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: raw[:prefixBytes]},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset + addrNetField, Len: fieldLen},
		&expr.Payload{DestRegister: 2, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset + addrHostField, Len: fieldLen},
		&expr.Payload{OperationType: expr.PayloadWrite, SourceRegister: 2, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset + addrNetField, Len: fieldLen, CsumType: expr.CsumTypeNone},
		&expr.Payload{OperationType: expr.PayloadWrite, SourceRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset + addrHostField, Len: fieldLen, CsumType: expr.CsumTypeNone},
	}
}
