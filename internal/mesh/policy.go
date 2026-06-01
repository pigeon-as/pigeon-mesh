package mesh

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	prog, err := expr.Compile(s, expr.AsBool(), expr.Env(policyEnv(Peer{}, Peer{})))
	if err != nil {
		return nil, fmt.Errorf("peer-policy: %w", err)
	}
	return &PeerPolicy{program: prog}, nil
}

func (p *PeerPolicy) accept(peer, self Peer) (bool, error) {
	out, err := expr.Run(p.program, policyEnv(peer, self))
	if err != nil {
		return false, fmt.Errorf("peer-policy: %w", err)
	}
	b, ok := out.(bool)
	if !ok {
		return false, fmt.Errorf("peer-policy: result %T not bool", out)
	}
	return b, nil
}

func policyEnv(peer, self Peer) map[string]any {
	return map[string]any{
		"peer":         peer,
		"self":         self,
		"cidrSubset":   cidrSubset,
		"sha256":       sha256Hex,
		"hostbits":     hostbits,
		"base64decode": b64decode,
	}
}

func sha256Hex(msg string) string {
	sum := sha256.Sum256([]byte(msg))
	return hex.EncodeToString(sum[:])
}

// b64decode decodes a standard-base64 string (such as a WireGuard public key)
// to its raw bytes, so a policy can hash the key material itself rather than
// its text, e.g. sha256(base64decode(peer.PublicKey)). Returns "" on bad input.
func b64decode(s string) string {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(raw)
}

// hostbits returns the host portion of addr (the bytes below a byte-aligned
// prefix) as lowercase hex, so a policy can compare an address against a hash
// of the key, e.g. hostbits("fdcc::/16", peer.AllowedIPs[0]) ==
// sha256(base64decode(peer.PublicKey))[0:28]. Returns "" on bad input or a
// prefix length that is not a multiple of 8.
func hostbits(prefix, addr string) string {
	pfx, err := netip.ParsePrefix(prefix)
	if err != nil || pfx.Bits()%8 != 0 {
		return ""
	}
	var a netip.Addr
	if p, e := netip.ParsePrefix(addr); e == nil {
		a = p.Addr()
	} else if ip, e := netip.ParseAddr(addr); e == nil {
		a = ip
	} else {
		return ""
	}
	if a.Is4() != pfx.Addr().Is4() {
		return ""
	}
	var full []byte
	if a.Is4() {
		v := a.As4()
		full = v[:]
	} else {
		v := a.As16()
		full = v[:]
	}
	return hex.EncodeToString(full[pfx.Bits()/8:])
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
