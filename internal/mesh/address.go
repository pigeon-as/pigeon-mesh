package mesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

func InterfaceAddress(iface string) (netip.Addr, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("interface %q: %w", iface, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("interface %q addrs: %w", iface, err)
	}
	var found netip.Addr
	for _, a := range addrs {
		pfx, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		addr := pfx.Addr()
		if !addr.IsGlobalUnicast() {
			continue
		}
		if found.IsValid() {
			return netip.Addr{}, fmt.Errorf("interface %q has multiple global addresses; pass --address", iface)
		}
		found = addr
	}
	if !found.IsValid() {
		return netip.Addr{}, fmt.Errorf("interface %q has no global address; pass --address", iface)
	}
	return found, nil
}

func ParseAllowedIPs(s string) ([]string, error) {
	var out []string
	for c := range strings.SplitSeq(s, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, err := netip.ParsePrefix(c); err != nil {
			return nil, fmt.Errorf("allowed-ips %q: %w", c, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one CIDR required")
	}
	return out, nil
}

func HostRoute(a netip.Addr) netip.Prefix {
	return netip.PrefixFrom(a, a.BitLen())
}

func NormalizeEndpoint(s string) (string, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.String(), nil
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", s, err)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: resolve %q: %w", s, host, err)
	}
	pick, ok := pickEndpointAddr(addrs)
	if !ok {
		return "", fmt.Errorf("endpoint %q: %q resolved to no addresses", s, host)
	}
	ap, err := netip.ParseAddrPort(net.JoinHostPort(pick.String(), portStr))
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", s, err)
	}
	return ap.String(), nil
}

func pickEndpointAddr(addrs []netip.Addr) (netip.Addr, bool) {
	var v4, v6 []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsValid() {
			continue
		}
		if a.Is6() {
			v6 = append(v6, a)
		} else {
			v4 = append(v4, a)
		}
	}
	pick := v6
	if len(pick) == 0 {
		pick = v4
	}
	if len(pick) == 0 {
		return netip.Addr{}, false
	}
	slices.SortFunc(pick, func(a, b netip.Addr) int { return a.Compare(b) })
	return pick[0], true
}
