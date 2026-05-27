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
		return nil, fmt.Errorf("addrs %q: %w", iface, err)
	}
	var match net.IP
	var found []string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || !n.IP.IsGlobalUnicast() {
			continue
		}
		match = n.IP
		found = append(found, n.IP.String())
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("interface %q: want exactly 1 global address, got %d [%s]; pass --address <ip>", iface, len(found), strings.Join(found, ", "))
	}
	return match, nil
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
	ip, port, err := parseIPPort(s)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func parseIPPort(s string) (net.IP, int, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, fmt.Errorf("endpoint %q: %w", s, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, fmt.Errorf("endpoint %q: invalid port %q", s, portStr)
	}
	if port < 1 || port > 65535 {
		return nil, 0, fmt.Errorf("endpoint %q: port %d out of range", s, port)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("endpoint %q: host %q is not an IP address", s, host)
	}
	return ip, port, nil
}
