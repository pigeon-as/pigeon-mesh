//go:build linux

package mesh

import (
	"bytes"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (m *Mesh) peersInKernel() (map[string]bool, error) {
	peers, err := m.cfg.WG.Peers(m.cfg.Iface)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(peers))
	for _, p := range peers {
		set[p.PublicKey.String()] = true
	}
	return set, nil
}

// dropContestedRoutes installs a route for no one when more than one node claims the EXACT same prefix
// (returned as contested for status/logging). Overlap alone is NOT a conflict: WireGuard keeps every
// peer's AllowedIPs in one longest-prefix-match trie, so a broad route (an exit's 0.0.0.0/0, a hub's
// fdcc::/48) and a more-specific peer route coexist and the kernel routes each correctly, and a peer's
// identity /128 is the tightest match so no aggregate can ever swallow it. Only an exact-prefix
// collision is ambiguous. This node's own advertised routes (selfName) count as a claimant, so a peer
// re-advertising a route we already serve is surfaced and dropped like any other contest, never silently.
// Grant authorization, not route dropping, is what stops a peer carving into a subnet it was not granted.
func dropContestedRoutes(peers map[string]wgPeer, selfName string, selfRoutes []string) (map[string]wgPeer, map[string][]string) {
	claimants := make(map[string][]string)
	for name, w := range peers {
		for _, ip := range w.routes {
			claimants[routeKey(ip)] = append(claimants[routeKey(ip)], name)
		}
	}
	for _, ip := range selfRoutes {
		claimants[routeKey(ip)] = append(claimants[routeKey(ip)], selfName)
	}
	var contested map[string][]string
	for key, owners := range claimants {
		if len(owners) > 1 {
			if contested == nil {
				contested = make(map[string][]string)
			}
			slices.Sort(owners)
			contested[key] = owners
		}
	}
	if contested == nil {
		return peers, nil
	}
	effective := make(map[string]wgPeer, len(peers))
	for name, w := range peers {
		kept := slices.DeleteFunc(slices.Clone(w.routes), func(ip string) bool {
			return contested[routeKey(ip)] != nil
		})
		if len(kept) == 0 {
			continue
		}
		w.routes = kept
		effective[name] = w
	}
	return effective, contested
}

// routeKey normalizes a CIDR to a canonical masked-prefix string so an exact-prefix contest is detected
// regardless of host bits or formatting; an unparseable route keeps its raw string (still exact-matched).
func routeKey(ip string) string {
	if p, err := netip.ParsePrefix(ip); err == nil {
		return p.Masked().String()
	}
	return ip
}

func diff(prev, cur map[string]wgPeer, inKernel map[string]bool) []wgtypes.PeerConfig {
	var changes []wgtypes.PeerConfig
	for name, p := range cur {
		prevPeer, known := prev[name]
		present := inKernel[name]
		if known && present && prevPeer.equal(p) {
			continue
		}
		pc, err := p.toWG()
		if err != nil {
			slog.Warn("peer to wg", "node", name, "err", err)
			continue
		}
		if known && present {
			pc.UpdateOnly = true
			if prevPeer.endpoint == p.endpoint {
				pc.Endpoint = nil
			}
		}
		changes = append(changes, pc)
	}
	for name := range prev {
		if _, ok := cur[name]; ok {
			continue
		}
		if !inKernel[name] {
			continue
		}
		pk, err := wgtypes.ParseKey(name)
		if err != nil {
			slog.Warn("parse pubkey", "node", name, "err", err)
			continue
		}
		changes = append(changes, wgtypes.PeerConfig{PublicKey: pk, Remove: true})
	}
	slices.SortFunc(changes, func(a, b wgtypes.PeerConfig) int {
		return bytes.Compare(a.PublicKey[:], b.PublicKey[:])
	})
	return changes
}

func (m *Mesh) reconcile() error {
	inKernel, err := m.peersInKernel()
	if err != nil {
		return err
	}

	// Snapshot under read lock, apply lock-free (WG.Apply is slow I/O).
	m.mu.RLock()
	desired := make(map[string]wgPeer, len(m.members)+len(m.kernelPeers))
	memberDesired := make(map[string]bool) // admitted members with routes, to recount installs after contest drops
	admitted := 0
	for name, e := range m.members {
		if !e.admitted() {
			continue
		}
		admitted++
		// Omit policy-blocked members (no routes) so diff() removes them and toWG() isn't called on empty AllowedIPs.
		if len(e.wgPeer.routes) > 0 {
			desired[name] = e.wgPeer
			memberDesired[name] = true
		}
	}
	rev := *m.revoked.Load()
	for name := range m.kernelPeers {
		// Keep a kernel peer until it gossips; setMember drops gossiped ones. Skip revoked keys: a
		// not-yet-gossiped seed never reaches admit(), so this is the only place revocation cuts it.
		if _, ok := rev[name]; ok {
			continue
		}
		if _, ok := desired[name]; ok {
			continue
		}
		if w, ok := m.applied[name]; ok {
			desired[name] = w
		}
	}
	prev := maps.Clone(m.applied)
	m.mu.RUnlock()

	// Our own advertised routes are claimants too, so a peer re-advertising a route we serve is contested.
	effective, contested := dropContestedRoutes(desired, m.cfg.Self.PublicKey, m.cfg.Self.AllowedIPs)

	// Recount installs after the contest drop: a member whose only routes were contested away is not installed.
	installed := 0
	for name := range memberDesired {
		if _, ok := effective[name]; ok {
			installed++
		}
	}

	changes := diff(prev, effective, inKernel)
	if len(changes) > 0 {
		if err := m.cfg.WG.Apply(m.cfg.Iface, changes); err != nil {
			return err
		}
	}

	m.mu.Lock()
	if len(changes) > 0 {
		m.applied = effective
	}
	var newlyContested []string
	for route := range contested {
		if _, had := m.contested[route]; !had {
			newlyContested = append(newlyContested, route)
		}
	}
	m.contested = contested
	nowIsolated := admitted > 0 && installed == 0
	wasIsolated := m.isolated
	m.isolated = nowIsolated
	m.mu.Unlock()

	for _, route := range newlyContested {
		slog.Warn("route claimed by more than one node; installed for none until resolved", "route", route, "claimed_by", contested[route])
	}
	if nowIsolated && !wasIsolated {
		slog.Warn("this node installs no routes for any peer; now isolated (check --peer-policy and route conflicts)")
	}
	if len(changes) > 0 {
		m.persistManaged() // record daemon-added peers so leave stays correct across a restart
	}
	return nil
}

// adoptKernelPeers seeds each pre-existing kernel peer's derived overlay /128 so it is reachable before it gossips.
func (m *Mesh) adoptKernelPeers() error {
	peers, err := m.cfg.WG.Peers(m.cfg.Iface)
	if err != nil {
		return err
	}
	adopted := make(map[string]wgPeer, len(peers))
	revoked := *m.revoked.Load()
	var routes []wgtypes.PeerConfig
	for _, p := range peers {
		name := p.PublicKey.String()
		w := wgPeer{key: name}
		if _, isRevoked := revoked[name]; !isRevoked {
			if route, pc, ok := m.overlaySeed(p); ok {
				w.routes = []string{route}
				routes = append(routes, pc)
			}
		}
		adopted[name] = w
	}
	if len(routes) > 0 {
		if err := m.cfg.WG.Apply(m.cfg.Iface, routes); err != nil {
			slog.Warn("seed kernel-peer overlay addresses", "err", err)
		}
	}
	// A peer present at startup is an operator seed UNLESS a prior run of this daemon recorded that it
	// added it (gossip-discovered). Without this, an ungraceful restart would re-classify daemon-added
	// peers as operator config and a later leave would leak them. The record lives in /run, which clears
	// on reboot exactly as the kernel WireGuard peers do, so a fresh boot correctly treats survivors as seeds.
	managed := loadManaged(m.cfg.StatePath)
	m.mu.Lock()
	m.applied = adopted
	for name := range adopted {
		m.kernelPeers[name] = true
		if !managed[name] {
			m.seedPeers[name] = true // operator-provisioned; never torn down on leave
		}
	}
	m.mu.Unlock()
	return nil
}

// managedPeers returns the keys of kernel peers the daemon itself installed (everything it applied that is
// not an operator seed). Persisted to StatePath so leave can still tell its own additions from operator
// config after a restart.
func (m *Mesh) managedPeers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.applied))
	for name := range m.applied {
		if !m.seedPeers[name] {
			out = append(out, name)
		}
	}
	return out
}

// persistManaged writes the daemon-added peer set to StatePath (atomic rename), best-effort.
func (m *Mesh) persistManaged() {
	if m.cfg.StatePath == "" {
		return
	}
	names := m.managedPeers()
	slices.Sort(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte('\n')
	}
	tmp := m.cfg.StatePath + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		slog.Warn("persist managed peers", "err", err)
		return
	}
	if err := os.Rename(tmp, m.cfg.StatePath); err != nil {
		slog.Warn("persist managed peers", "err", err)
	}
}

// loadManaged reads the daemon-added peer set recorded by a prior run; a missing file (fresh boot or a
// reboot that cleared /run) yields the empty set, so every surviving kernel peer is treated as a seed.
func loadManaged(path string) map[string]bool {
	out := map[string]bool{}
	if path == "" {
		return out
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out[line] = true
		}
	}
	return out
}

// overlaySeed derives peer p's key-based overlay /128 route plus the WG config that installs it, or
// ok=false when there is no prefix, the key is underivable, or the peer already carries a host route.
func (m *Mesh) overlaySeed(p wgtypes.Peer) (route string, pc wgtypes.PeerConfig, ok bool) {
	if !m.cfg.Prefix.IsValid() || hasHostRoute(p.AllowedIPs) {
		return "", wgtypes.PeerConfig{}, false
	}
	addr, err := DeriveAddr(p.PublicKey.String(), m.cfg.Prefix)
	if err != nil {
		return "", wgtypes.PeerConfig{}, false
	}
	return HostRoute(addr).String(), wgtypes.PeerConfig{
		PublicKey:  p.PublicKey,
		UpdateOnly: true,
		AllowedIPs: []net.IPNet{{IP: addr.AsSlice(), Mask: net.CIDRMask(addr.BitLen(), addr.BitLen())}},
	}, true
}

// reseedUnrevokedKernelPeers re-derives the overlay /128 for any still-pre-gossip seed peer that was
// adopted while revoked (so it carries no route) and is no longer on the denylist, so removing a boot-time
// seed from --revoked and reloading restores its reachability at once, not only after it gossips or a restart.
func (m *Mesh) reseedUnrevokedKernelPeers() {
	revoked := *m.revoked.Load()
	// Skip the netlink dump entirely unless some pre-gossip seed is now un-revoked but still routeless.
	m.mu.RLock()
	need := false
	for name := range m.kernelPeers {
		if _, isRevoked := revoked[name]; isRevoked {
			continue
		}
		if w, ok := m.applied[name]; ok && len(w.routes) == 0 {
			need = true
			break
		}
	}
	m.mu.RUnlock()
	if !need {
		return
	}
	peers, err := m.cfg.WG.Peers(m.cfg.Iface)
	if err != nil {
		return
	}
	var routes []wgtypes.PeerConfig
	m.mu.Lock()
	for _, p := range peers {
		name := p.PublicKey.String()
		if _, isRevoked := revoked[name]; isRevoked || !m.kernelPeers[name] {
			continue
		}
		if w, ok := m.applied[name]; !ok || len(w.routes) > 0 {
			continue // already gossiped or already seeded
		}
		if route, pc, ok := m.overlaySeed(p); ok {
			m.applied[name] = wgPeer{key: name, routes: []string{route}}
			routes = append(routes, pc)
		}
	}
	m.mu.Unlock()
	if len(routes) > 0 {
		if err := m.cfg.WG.Apply(m.cfg.Iface, routes); err != nil {
			slog.Warn("reseed un-revoked kernel-peer overlay", "err", err)
		}
	}
}

// removeAddedPeers removes, on graceful leave, the kernel peers the daemon itself installed (gossip-
// discovered), leaving every operator-provisioned seed peer in place. pigeon-mesh is a guest on the
// operator's interface, so it cleans up its own additions but never the operator's kernel config.
func (m *Mesh) removeAddedPeers() {
	m.mu.RLock()
	var rm []wgtypes.PeerConfig
	for name := range m.applied {
		if m.seedPeers[name] {
			continue
		}
		key, err := wgtypes.ParseKey(name)
		if err != nil {
			continue
		}
		rm = append(rm, wgtypes.PeerConfig{PublicKey: key, Remove: true})
	}
	m.mu.RUnlock()
	if len(rm) > 0 {
		if err := m.cfg.WG.Apply(m.cfg.Iface, rm); err != nil {
			slog.Warn("remove daemon-added peers on leave", "err", err)
		}
	}
}

func (m *Mesh) staleKernelPeers() []string {
	t := m.joinedAt.Load()
	if t == 0 || time.Since(time.Unix(0, t)) <= kernelSettle {
		return nil
	}
	m.mu.RLock()
	names := slices.Collect(maps.Keys(m.kernelPeers))
	m.mu.RUnlock()
	slices.Sort(names)
	return names
}
