package mesh

import (
	"fmt"
	"net"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

type PeerPolicy struct{ program *vm.Program }

func ParsePeerPolicy(s string) (*PeerPolicy, error) {
	if s == "" {
		return nil, nil
	}
	prog, err := expr.Compile(s,
		expr.AsBool(),
		expr.Env(map[string]any{
			"peer":         Peer{},
			"peers":        func() []Peer { return nil },
			"cidrContains": cidrContains,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("peer-policy: %w", err)
	}
	return &PeerPolicy{program: prog}, nil
}

func (p *PeerPolicy) accept(peer Peer, peers func() []Peer) (bool, error) {
	out, err := expr.Run(p.program, map[string]any{
		"peer":         peer,
		"peers":        peers,
		"cidrContains": cidrContains,
	})
	if err != nil {
		return false, fmt.Errorf("peer-policy: %w", err)
	}
	return out.(bool), nil
}

func cidrContains(cidr, addr string) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ip := parseIPOrCIDR(addr)
	return ip != nil && n.Contains(ip)
}

func parseIPOrCIDR(s string) net.IP {
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip
	}
	return net.ParseIP(s)
}
