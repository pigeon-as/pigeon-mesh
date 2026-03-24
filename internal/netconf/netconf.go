// Package netconf manages nftables and sysctl configuration for the mesh overlay.
//
//go:build linux

package netconf

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// SetupNftables creates the pigeon-mesh NAT rules for CGNAT masquerade.
// Filter rules (WireGuard port, memberlist, wg0 accept, forward) are managed
// by pigeon-fence. Only masquerade stays here because NAT is not firewall
// policy — it's coupled to the WireGuard interface lifecycle.
//
// Uses its own table (pigeon-mesh-nat) to avoid colliding with other nftables
// users. Same own-table pattern as pigeon-fence (pigeon-fence) and Calico (calico).
func SetupNftables(iface, egressCIDR string) error {
	// Best-effort cleanup of stale table from previous run.
	cleanup := &nftables.Conn{}
	cleanup.DelTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "pigeon-mesh-nat",
	})
	_ = cleanup.Flush()

	// NAT rules (optional CGNAT masquerade for VM egress).
	if egressCIDR == "" {
		return nil
	}

	conn := &nftables.Conn{}

	_, ipNet, err := net.ParseCIDR(egressCIDR)
	if err != nil {
		return fmt.Errorf("parse egress CIDR: %w", err)
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("egress CIDR must be IPv4: %s", egressCIDR)
	}

	natTable := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "pigeon-mesh-nat",
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

// VerifySysctl checks that IP forwarding is enabled. These sysctls are set by
// the image sysctl.conf drop-in at boot — pigeon-mesh verifies them rather than
// setting them, to maintain clear responsibility boundaries.
func VerifySysctl() error {
	params := []struct {
		path  string
		value string
	}{
		{"net/ipv4/ip_forward", "1"},
		{"net/ipv6/conf/all/forwarding", "1"},
	}
	for _, p := range params {
		got, err := os.ReadFile(filepath.Join("/proc/sys", p.path))
		if err != nil {
			return fmt.Errorf("read sysctl %s: %w", p.path, err)
		}
		if strings.TrimSpace(string(got)) != p.value {
			return fmt.Errorf("sysctl %s = %q, want %q (check /etc/sysctl.d/ drop-in)", p.path, strings.TrimSpace(string(got)), p.value)
		}
	}
	return nil
}

// masqueradeExprs builds nftables expressions for:
//
//	oifname != "<iface>" ip saddr <cidr> masquerade
//
// The output interface check prevents masquerading cross-host mesh traffic.
func masqueradeExprs(iface string, networkIP net.IP, mask net.IPMask) []expr.Any {
	ifaceBuf := make([]byte, 16) // IFNAMSIZ
	copy(ifaceBuf, iface)
	return []expr.Any{
		// Gate on IPv4 (inet table may see IPv6 packets).
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		// Skip masquerade for traffic going to the WireGuard interface (cross-host mesh).
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifaceBuf},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte(mask), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(networkIP)},
		&expr.Masq{},
	}
}

// SetupTranspose creates nftables netdev rules on the WireGuard interface to
// transpose pigeon IPv6 addresses between app-view and wire-view. Swaps the
// network (bytes 2-5) and host (bytes 6-9) fields of fdaa:: addresses in both
// src and dst, for both ingress and egress. The transform is self-inverse.
func SetupTranspose(iface string) error {
	// Best-effort cleanup of stale table from previous run.
	cleanup := &nftables.Conn{}
	cleanup.DelTable(&nftables.Table{
		Family: nftables.TableFamilyNetdev,
		Name:   "pigeon-transpose",
	})
	_ = cleanup.Flush()

	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyNetdev,
		Name:   "pigeon-transpose",
	})

	// Create ingress and egress chains bound to the WireGuard device.
	// Both directions apply the same self-inverse transposition.
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

		// Rule 1: if src starts with fdaa::, swap src bytes 2-5 ↔ 6-9.
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: transposeExprs(8)})
		// Rule 2: if dst starts with fdaa::, swap dst bytes 2-5 ↔ 6-9.
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: transposeExprs(24)})
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush transpose: %w", err)
	}
	return nil
}

// transposeExprs builds expressions that check if an IPv6 address (at addrOffset
// from the network header: 8 for src, 24 for dst) starts with fdaa::, and swaps
// bytes 2-5 and 6-9. No checksum fixup needed — swapping 16-bit-aligned 32-bit
// words preserves the one's complement sum used by TCP/UDP pseudo-headers.
func transposeExprs(addrOffset uint32) []expr.Any {
	return []expr.Any{
		// Only process IPv6 packets (EtherType 0x86DD). Without this guard,
		// an IPv4 payload that coincidentally contains 0xfdaa at the same
		// offset would be corrupted.
		&expr.Meta{Key: expr.MetaKeyPROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x86, 0xDD}},

		// Check address prefix (bytes 0-1) == 0xfdaa.
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0xfd, 0xaa}},

		// Load field A (bytes 2-5) into reg1, field B (bytes 6-9) into reg2.
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset + 2, Len: 4},
		&expr.Payload{DestRegister: 2, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset + 6, Len: 4},

		// Write field B to bytes 2-5, field A to bytes 6-9.
		&expr.Payload{OperationType: expr.PayloadWrite, SourceRegister: 2, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset + 2, Len: 4, CsumType: expr.CsumTypeNone},
		&expr.Payload{OperationType: expr.PayloadWrite, SourceRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset + 6, Len: 4, CsumType: expr.CsumTypeNone},
	}
}
