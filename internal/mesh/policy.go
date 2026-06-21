package mesh

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// PeerPolicy is a compiled --peer-policy predicate, accept(peer, allowedip) -> bool,
// evaluated per advertised CIDR to decide whether this node installs that route. It
// governs route acceptance only: never admission (the signature/gossip-key tier),
// never cross-peer arbitration (resolveConflicts), and a peer's identity /128 is
// always kept (handled in policyFilter, not the predicate).
type PeerPolicy struct{ program *vm.Program }

type policyPeer struct {
	Key        string   `expr:"key"`
	Endpoint   string   `expr:"endpoint"`
	AllowedIPs []string `expr:"allowedips"`
}

type policyEnv struct {
	Peer       policyPeer                     `expr:"peer"`
	AllowedIP  string                         `expr:"allowedip"`
	CIDRSubset func(outer, inner string) bool `expr:"cidrSubset"`
}

// ParsePeerPolicyFlag compiles the --peer-policy flag value: an inline predicate,
// or @file to read the predicate from a file (SIGHUP-reloadable, like --signers).
func ParsePeerPolicyFlag(spec string) (*PeerPolicy, error) {
	if path, ok := strings.CutPrefix(spec, "@"); ok {
		return LoadPeerPolicy(path)
	}
	return ParsePeerPolicy(spec)
}

// LoadPeerPolicy reads and compiles a predicate from a file.
func LoadPeerPolicy(path string) (*PeerPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePeerPolicy(strings.TrimSpace(string(data)))
}

// ParsePeerPolicy compiles the predicate. An empty string returns nil (accept all).
func ParsePeerPolicy(s string) (*PeerPolicy, error) {
	if s == "" {
		return nil, nil
	}
	program, err := expr.Compile(s, expr.AsBool(), expr.Env(policyEnv{}))
	if err != nil {
		return nil, fmt.Errorf("peer-policy: %w", err)
	}
	return &PeerPolicy{program: program}, nil
}

func (p *PeerPolicy) accept(peer Peer, allowedip string) (bool, error) {
	out, err := expr.Run(p.program, policyEnv{
		Peer:       policyPeer{Key: peer.PublicKey, Endpoint: peer.Endpoint, AllowedIPs: peer.AllowedIPs},
		AllowedIP:  allowedip,
		CIDRSubset: cidrSubset,
	})
	if err != nil {
		return false, fmt.Errorf("peer-policy: %w", err)
	}
	b, ok := out.(bool)
	if !ok {
		return false, fmt.Errorf("peer-policy: result %T is not bool", out)
	}
	return b, nil
}

// policyFilter splits a peer's advertised AllowedIPs into the routes this node
// installs (kept) and the routes the policy refuses (refused). The identity /128 is
// always kept (auto-managed, exempt). A nil policy accepts everything.
func policyFilter(peer Peer, identity netip.Addr, policy *PeerPolicy) (kept, refused []string) {
	if policy == nil {
		return peer.AllowedIPs, nil
	}
	var id netip.Prefix
	if identity.IsValid() {
		id = HostRoute(identity)
	}
	for _, cidr := range peer.AllowedIPs {
		if r, err := netip.ParsePrefix(cidr); err == nil && id.IsValid() && r == id {
			kept = append(kept, cidr)
			continue
		}
		ok, err := policy.accept(peer, cidr)
		if err != nil {
			slog.Debug("peer-policy eval", "peer", peer.PublicKey, "route", cidr, "err", err)
			refused = append(refused, cidr)
			continue
		}
		if ok {
			kept = append(kept, cidr)
		} else {
			refused = append(refused, cidr)
		}
	}
	return kept, refused
}

// cidrSubset reports whether inner is a subset of outer (Vault cidrutil.Subset
// semantics): inner must be at least as specific as outer and lie inside it. A bare
// IP is treated as a /32 or /128.
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
