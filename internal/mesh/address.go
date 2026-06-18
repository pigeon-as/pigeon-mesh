package mesh

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

func DeriveAddr(pubkey string, prefix netip.Prefix) (netip.Addr, error) {
	if !prefix.Addr().Is6() || prefix.Bits()%8 != 0 {
		return netip.Addr{}, fmt.Errorf("overlay prefix %s must be a byte-aligned IPv6 prefix", prefix)
	}
	if prefix.Bits() > 64 {
		return netip.Addr{}, fmt.Errorf("overlay prefix %s is too long; use /64 or shorter so the key-derived host portion stays collision-resistant", prefix)
	}
	raw, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("pubkey %q: %w", pubkey, err)
	}
	sum := sha512.Sum512(raw)
	addr := prefix.Masked().Addr().As16()
	copy(addr[prefix.Bits()/8:], sum[:])
	return netip.AddrFrom16(addr), nil
}

func validateOverlayAddr(pubkey string, p Peer, prefix netip.Prefix) (netip.Addr, error) {
	want, err := DeriveAddr(pubkey, prefix)
	if err != nil {
		return netip.Addr{}, err
	}
	var claimsSelf bool
	for _, c := range p.AllowedIPs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("allowed-ip %q: %w", c, err)
		}
		if !prefix.Overlaps(pfx) {
			continue
		}
		if pfx.Bits() != pfx.Addr().BitLen() || pfx.Addr() != want {
			return netip.Addr{}, fmt.Errorf("claims overlay route %s but key derives %s", c, want)
		}
		claimsSelf = true
	}
	if !claimsSelf {
		return netip.Addr{}, fmt.Errorf("advertises no overlay address; key derives %s", want)
	}
	return want, nil
}

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
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("allowed-ips %q: %w", c, err)
		}
		out = append(out, pfx.Masked().String())
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
		if !a.IsValid() || !a.IsGlobalUnicast() {
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

// ParseAcceptRoutes parses the comma-separated CIDR list for --accept-routes
// into masked prefixes. It is the receive-side counterpart to --advertise-routes:
// the set of routes this node is willing to install from peers' advertisements.
func ParseAcceptRoutes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for c := range strings.SplitSeq(s, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("accept-routes %q: %w", c, err)
		}
		out = append(out, pfx.Masked())
	}
	if len(out) == 0 {
		return nil, errors.New("at least one CIDR required")
	}
	return out, nil
}

// clampAcceptedRoutes filters a peer's advertised routes down to the ones the
// local operator accepts via --accept-routes. The peer's own address (identity)
// always passes, since refusing it is an admission decision rather than a routing
// one; every other route must be contained in one of the accepted prefixes. An
// empty accept set accepts everything (the default, unrestricted behaviour). It
// returns the kept and dropped routes; inputs are assumed canonical (masked) as
// produced by decodeMeta.
func clampAcceptedRoutes(allowedIPs []string, identity netip.Addr, accept []netip.Prefix) (kept, dropped []string) {
	if len(accept) == 0 {
		return allowedIPs, nil
	}
	var id netip.Prefix
	if identity.IsValid() {
		id = HostRoute(identity)
	}
	for _, s := range allowedIPs {
		r, err := netip.ParsePrefix(s)
		if err != nil || (id.IsValid() && r == id) || routeWithinAny(r, accept) {
			kept = append(kept, s)
			continue
		}
		dropped = append(dropped, s)
	}
	return kept, dropped
}

// routeWithinAny reports whether r is a subset of any prefix in set, matching the
// semantics of Vault's cidrutil.Subset (the same check the removed peer-policy used):
// r must be at least as specific as the outer prefix and lie inside it.
func routeWithinAny(r netip.Prefix, set []netip.Prefix) bool {
	for _, a := range set {
		if r.Bits() >= a.Bits() && a.Contains(r.Addr()) {
			return true
		}
	}
	return false
}
