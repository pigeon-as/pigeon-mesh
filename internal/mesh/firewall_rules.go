//go:build linux

package mesh

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

const maxPort = 65535

// fwPeer is the verified peer exposed to a firewall predicate; the selector side may use the whole language.
type fwPeer struct {
	Key      string            `expr:"key"`
	Address  string            `expr:"address"`
	Endpoint string            `expr:"endpoint"`
	Tags     map[string]string `expr:"tags"`
}

// fwEnv is the env a firewall predicate runs in. The predicate returns a list of allow(...) rules; evaluated
// per peer, each yields a proto and port set to accept from that peer.
type fwEnv struct {
	Peer       fwPeer                         `expr:"peer"`
	CIDRSubset func(outer, inner string) bool `expr:"cidrSubset"`
}

// FirewallPolicy is a compiled --firewall-rules predicate: an expr returning a list of allow(proto, ports,
// cond?) rules, evaluated per admitted peer at reconcile.
type FirewallPolicy struct {
	program *vm.Program
}

// portRange is an inclusive [lo, hi] port span.
type portRange struct{ lo, hi int }

// ruleSpec is one allow(...) result: accept this proto and port set from the peer being evaluated.
type ruleSpec struct {
	proto byte
	ports []portRange
}

// peerRules is the accepting set the predicate yields for one peer. ICMPv6 is allowed globally (RFC 4890),
// not per peer, so only tcp/udp ports are compiled here.
type peerRules struct {
	tcp []portRange
	udp []portRange
}

func (r peerRules) empty() bool { return len(r.tcp) == 0 && len(r.udp) == 0 }

func ParseFirewallRulesFlag(spec string) (*FirewallPolicy, error) {
	if path, ok := strings.CutPrefix(spec, "@"); ok {
		return LoadFirewallRules(path)
	}
	return ParseFirewallRules(spec)
}

func LoadFirewallRules(path string) (*FirewallPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseFirewallRules(strings.TrimSpace(string(data)))
}

// Empty string returns nil = no rules (the gossip guard still runs unless --disable-firewall).
func ParseFirewallRules(spec string) (*FirewallPolicy, error) {
	if spec == "" {
		return nil, nil
	}
	program, err := expr.Compile(spec, expr.Env(fwEnv{}), expr.Function("allow", allowFunc))
	if err != nil {
		return nil, fmt.Errorf("firewall-rules: %w", err)
	}
	fp := &FirewallPolicy{program: program}
	// Dry-run with an empty peer so a bad proto or port fails at startup, not on the first real peer.
	if _, err := fp.compilePeer(fwPeer{Tags: map[string]string{}}); err != nil {
		return nil, err
	}
	return fp, nil
}

// ReloadFirewallRulesFromFile swaps the rules on SIGHUP and triggers a reconcile to rebuild the table. An
// emptied file reverts to the gossip guard only. Never gossiped; a per-node file like --peer-policy.
func (m *Mesh) ReloadFirewallRulesFromFile(path string) error {
	rules, err := LoadFirewallRules(path)
	if err != nil {
		return err
	}
	m.firewallRules.Store(rules)
	m.triggerReconcile()
	return nil
}

// compilePeer evaluates the predicate for one peer and merges its allow(...) rules into a tcp/udp port set.
func (fp *FirewallPolicy) compilePeer(peer fwPeer) (peerRules, error) {
	out, err := expr.Run(fp.program, fwEnv{Peer: peer, CIDRSubset: cidrSubset})
	if err != nil {
		return peerRules{}, fmt.Errorf("firewall-rules: %w", err)
	}
	var list []any
	switch v := out.(type) {
	case []any:
		list = v
	case ruleSpec:
		list = []any{v} // a single allow(...) without the list brackets
	case nil:
		// empty: a single gated-off allow(...)
	default:
		return peerRules{}, fmt.Errorf("firewall-rules must evaluate to allow(...) or a list of them, got %T", out)
	}
	var r peerRules
	for _, item := range list {
		spec, ok := item.(ruleSpec)
		if !ok {
			continue // nil: an allow() gated off by its condition
		}
		switch spec.proto {
		case protoTCP:
			r.tcp = append(r.tcp, spec.ports...)
		case protoUDP:
			r.udp = append(r.udp, spec.ports...)
		}
	}
	r.tcp, r.udp = mergeRanges(r.tcp), mergeRanges(r.udp)
	return r, nil
}

// allowFunc implements the expr builtin allow(proto, ports[, cond]): a ruleSpec to accept proto's ports from
// the peer, or nil when cond is false. Ports parse regardless of cond so a bad port fails at parse time.
func allowFunc(args ...any) (any, error) {
	if len(args) < 2 || len(args) > 3 {
		return nil, fmt.Errorf("allow(proto, ports[, cond]) takes 2 or 3 arguments, got %d", len(args))
	}
	var l4 byte
	switch args[0] {
	case "tcp":
		l4 = protoTCP
	case "udp":
		l4 = protoUDP
	default:
		return nil, fmt.Errorf("allow: proto must be \"tcp\" or \"udp\", got %q", args[0])
	}
	ports, err := parsePorts(args[1])
	if err != nil {
		return nil, fmt.Errorf("allow: %w", err)
	}
	if len(args) == 3 {
		cond, ok := args[2].(bool)
		if !ok {
			return nil, fmt.Errorf("allow: the condition must be a bool, got %T", args[2])
		}
		if !cond {
			return nil, nil
		}
	}
	return ruleSpec{proto: l4, ports: ports}, nil
}

// parsePorts accepts an int (single port), a "lo-hi" or "n" string, or a list of either.
func parsePorts(v any) ([]portRange, error) {
	switch p := v.(type) {
	case int:
		return oneRange(p, p)
	case string:
		lo, hi, isRange := strings.Cut(p, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("bad port %q", p)
		}
		if !isRange {
			return oneRange(a, a)
		}
		b, err := strconv.Atoi(strings.TrimSpace(hi))
		if err != nil {
			return nil, fmt.Errorf("bad port range %q", p)
		}
		return oneRange(a, b)
	case []any:
		var out []portRange
		for _, e := range p {
			r, err := parsePorts(e)
			if err != nil {
				return nil, err
			}
			out = append(out, r...)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("ports must be an int, a \"lo-hi\" string, or a list, got %T", v)
	}
}

func oneRange(lo, hi int) ([]portRange, error) {
	if lo < 0 || hi > maxPort || lo > hi {
		return nil, fmt.Errorf("port range %d-%d out of 0..%d", lo, hi, maxPort)
	}
	return []portRange{{lo, hi}}, nil
}

// mergeRanges sorts and coalesces overlapping or adjacent spans.
func mergeRanges(rs []portRange) []portRange {
	if len(rs) == 0 {
		return nil
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo < rs[j].lo })
	out := []portRange{rs[0]}
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if r.lo <= last.hi+1 {
			last.hi = max(last.hi, r.hi)
		} else {
			out = append(out, r)
		}
	}
	return out
}
