package mesh

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func InterfaceAddress(iface string) (net.IP, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, fmt.Errorf("interface %q addrs: %w", iface, err)
	}
	var found net.IP
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || !n.IP.IsGlobalUnicast() {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("interface %q has multiple global addresses; pass --address", iface)
		}
		found = n.IP
	}
	if found == nil {
		return nil, fmt.Errorf("interface %q has no global address; pass --address", iface)
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
		if _, _, err := net.ParseCIDR(c); err != nil {
			return nil, fmt.Errorf("allowed-ips %q: %w", c, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one CIDR required")
	}
	return out, nil
}

func HostRoute(ip net.IP) net.IPNet {
	bits := 128
	if v4 := ip.To4(); v4 != nil {
		ip = v4
		bits = 32
	}
	return net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
}

func NormalizeEndpoint(s string) (string, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", s, err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", s, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil {
			return "", fmt.Errorf("endpoint %q: resolve %q: %w", s, host, err)
		}
		if len(ips) == 0 {
			return "", fmt.Errorf("endpoint %q: %q resolved to no addresses", s, host)
		}
		ip = ips[0]
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func parseIPPort(s string) (net.IP, int, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, fmt.Errorf("endpoint %q: %w", s, err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, 0, fmt.Errorf("endpoint %q: %w", s, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("endpoint %q: host %q is not an IP address", s, host)
	}
	return ip, port, nil
}

func parsePort(s string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %d out of range", port)
	}
	return port, nil
}
