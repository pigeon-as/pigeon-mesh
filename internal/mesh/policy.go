//go:build linux

package mesh

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// PeerPolicy is a compiled --peer-policy predicate, accept(peer, route) -> bool, run per advertised
// CIDR including the peer's identity /128 (no exemption). Route acceptance only: never the
// signature/grant tier, never cross-peer arbitration.
type PeerPolicy struct{ program *vm.Program }

type policyPeer struct {
	Key        string   `expr:"key"`
	Endpoint   string   `expr:"endpoint"`
	Address    string   `expr:"address"` // the peer's key-derived overlay /128, in CIDR form
	AllowedIPs []string `expr:"allowedips"`
}

type policyEnv struct {
	Peer       policyPeer                     `expr:"peer"`
	Route      string                         `expr:"route"`
	CIDRSubset func(outer, inner string) bool `expr:"cidrSubset"`
}

// ParsePeerPolicyFlag compiles --peer-policy: inline predicate, or @file (SIGHUP-reloadable).
func ParsePeerPolicyFlag(spec string) (*PeerPolicy, error) {
	if path, ok := strings.CutPrefix(spec, "@"); ok {
		return LoadPeerPolicy(path)
	}
	return ParsePeerPolicy(spec)
}

func LoadPeerPolicy(path string) (*PeerPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePeerPolicy(strings.TrimSpace(string(data)))
}

// ParsePeerPolicy compiles the predicate. Empty string returns nil (accept all).
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

func (p *PeerPolicy) accept(peer Peer, route, address string) (bool, error) {
	out, err := expr.Run(p.program, policyEnv{
		Peer:       policyPeer{Key: peer.PublicKey, Endpoint: peer.Endpoint, Address: address, AllowedIPs: peer.AllowedIPs},
		Route:      route,
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

// policyFilter splits routes (the grant-authorized advertisements) into kept and refused. The predicate
// decides every route, including the peer's own identity /128 (no exemption); a nil policy accepts
// everything. identity is the peer's key-derived overlay address, exposed to the predicate as peer.address.
func policyFilter(peer Peer, routes []string, identity netip.Addr, policy *PeerPolicy) (kept, refused []string) {
	if policy == nil {
		return routes, nil
	}
	var address string
	if identity.IsValid() {
		address = HostRoute(identity).String()
	}
	for _, cidr := range routes {
		ok, err := policy.accept(peer, cidr, address)
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

// cidrSubset reports whether inner is a subset of outer: at least as specific and
// inside it. A bare IP is treated as a /32 or /128.
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

func (m *Mesh) ReloadPolicyFromFile(path string) error {
	policy, err := LoadPeerPolicy(path)
	if err != nil {
		return err
	}
	m.policy.Store(policy)
	m.reevaluate(time.Now())
	return nil
}
