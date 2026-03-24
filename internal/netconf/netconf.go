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

// SetupNftables creates CGNAT masquerade rules in its own table (pigeon-mesh-nat).
func SetupNftables(iface, egressCIDR string) error {
	cleanup := &nftables.Conn{}
	cleanup.DelTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "pigeon-mesh-nat",
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

// VerifySysctl checks that IP forwarding is enabled.
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
		Name:   "pigeon-transpose",
	})
	_ = cleanup.Flush()

	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyNetdev,
		Name:   "pigeon-transpose",
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

		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: transposeExprs(8)})  // src
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: transposeExprs(24)}) // dst
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush transpose: %w", err)
	}
	return nil
}

// transposeExprs: meta protocol ip6 → check fdaa:: prefix → swap bytes 2-5 ↔ 6-9.
// addrOffset: 8 for src, 24 for dst. No checksum fixup needed (16-bit-aligned swap).
func transposeExprs(addrOffset uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyPROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x86, 0xDD}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0xfd, 0xaa}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset + 2, Len: 4},
		&expr.Payload{DestRegister: 2, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset + 6, Len: 4},
		&expr.Payload{OperationType: expr.PayloadWrite, SourceRegister: 2, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset + 2, Len: 4, CsumType: expr.CsumTypeNone},
		&expr.Payload{OperationType: expr.PayloadWrite, SourceRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset + 6, Len: 4, CsumType: expr.CsumTypeNone},
	}
}
