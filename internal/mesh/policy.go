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

// PeerPolicy gates every advertised CIDR incl the identity /128 (no exemption); route acceptance
// only, never the signature/grant tier nor cross-peer arbitration.
type PeerPolicy struct{ program *vm.Program }

type policyPeer struct {
	Key        string   `expr:"key"`
	Endpoint   string   `expr:"endpoint"`
	Address    string   `expr:"address"`
	AllowedIPs []string `expr:"allowedips"`
}

type policyEnv struct {
	Peer       policyPeer                     `expr:"peer"`
	Route      string                         `expr:"route"`
	CIDRSubset func(outer, inner string) bool `expr:"cidrSubset"`
}

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

// Empty string returns nil = accept all.
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

// policyFilter splits routes into kept and refused; the predicate decides every route incl the
// identity /128 (no exemption). nil policy accepts everything; identity is exposed as peer.address.
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
			slog.Warn("peer-policy eval error; route refused", "peer", peer.PublicKey, "route", cidr, "err", err)
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
