package mesh

import (
	"fmt"
	"net/netip"

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
			"peer":       Peer{},
			"peers":      func() []Peer { return nil },
			"cidrSubset": cidrSubset,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("peer-policy: %w", err)
	}
	return &PeerPolicy{program: prog}, nil
}

func (p *PeerPolicy) accept(peer Peer, peers func() []Peer) (bool, error) {
	out, err := expr.Run(p.program, map[string]any{
		"peer":       peer,
		"peers":      peers,
		"cidrSubset": cidrSubset,
	})
	if err != nil {
		return false, fmt.Errorf("peer-policy: %w", err)
	}
	b, ok := out.(bool)
	if !ok {
		return false, fmt.Errorf("peer-policy: result %T not bool", out)
	}
	return b, nil
}

// cidrSubset reports whether inner is a cidrSubset of outer, matching the semantics of
// Vault's cidrutil.Subset: inner's prefix must be at least as specific as
// outer's, and inner's network address must lie inside outer. A bare IP is
// treated as a /32 or /128 prefix.
func cidrSubset(outer, inner string) bool {
	o, err := netip.ParsePrefix(outer)
	if err != nil {
		return false
	}
	var i netip.Prefix
	if p, err := netip.ParsePrefix(inner); err == nil {
		i = p
	} else if a, err := netip.ParseAddr(inner); err == nil {
		i = netip.PrefixFrom(a, a.BitLen())
	} else {
		return false
	}
	return i.Bits() >= o.Bits() && o.Contains(i.Addr())
}
