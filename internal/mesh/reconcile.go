//go:build linux

package mesh

import (
	"bytes"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
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

// dropContestedRoutes drops routes claimed by >1 peer (installed for none; returned as contested) and
// any peer route that falls inside a route this node itself serves (so a peer cannot take our traffic;
// a self-collision is not reported). The self check is directional: a peer route equal to or more
// specific than one of ours is dropped, but a peer supernet (exit route, aggregate) is not, so
// exit-node and supernet-override topologies still work.
func dropContestedRoutes(peers map[string]wgPeer, selfRoutes []string) (map[string]wgPeer, map[string][]string) {
	selfPfx := make([]netip.Prefix, 0, len(selfRoutes))
	for _, ip := range selfRoutes {
		if p, err := netip.ParsePrefix(ip); err == nil {
			selfPfx = append(selfPfx, p)
		}
	}
	selfServes := func(ip string) bool {
		r, err := netip.ParsePrefix(ip)
		if err != nil {
			return true // malformed: fail closed
		}
		for _, s := range selfPfx {
			if r.Bits() >= s.Bits() && s.Contains(r.Addr()) {
				return true
			}
		}
		return false
	}
	claimants := make(map[string][]string)
	for name, w := range peers {
		for _, ip := range w.routes {
			claimants[ip] = append(claimants[ip], name)
		}
	}
	var contested map[string][]string
	selfHit := false
	for ip, owners := range claimants {
		switch {
		case len(owners) > 1:
			if contested == nil {
				contested = make(map[string][]string)
			}
			slices.Sort(owners)
			contested[ip] = owners
		case selfServes(ip):
			selfHit = true
		}
	}
	if contested == nil && !selfHit {
		return peers, nil
	}
	effective := make(map[string]wgPeer, len(peers))
	for name, w := range peers {
		kept := slices.DeleteFunc(slices.Clone(w.routes), func(ip string) bool {
			return contested[ip] != nil || selfServes(ip)
		})
		if len(kept) == 0 {
			continue
		}
		w.routes = kept
		effective[name] = w
	}
	return effective, contested
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
	admitted, installed := 0, 0
	for name, e := range m.members {
		if !e.admitted() {
			continue
		}
		admitted++
		// Omit policy-blocked members (no routes) so diff() removes them and toWG() isn't called on empty AllowedIPs.
		if len(e.wgPeer.routes) > 0 {
			installed++
			desired[name] = e.wgPeer
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

	// Seed our full advertised set so a peer cannot hijack a route we advertise.
	effective, contested := dropContestedRoutes(desired, m.cfg.Self.AllowedIPs)

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
		slog.Warn("route claimed by more than one peer; installed for none until resolved", "route", route, "claimed_by", contested[route])
	}
	if nowIsolated && !wasIsolated {
		slog.Warn("--peer-policy installs no routes for any peer; this node is now isolated")
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
		if _, isRevoked := revoked[name]; !isRevoked && m.cfg.Prefix.IsValid() && !hasHostRoute(p.AllowedIPs) {
			if addr, derr := DeriveAddr(name, m.cfg.Prefix); derr == nil {
				w.routes = []string{HostRoute(addr).String()}
				routes = append(routes, wgtypes.PeerConfig{
					PublicKey:  p.PublicKey,
					UpdateOnly: true,
					AllowedIPs: []net.IPNet{{IP: addr.AsSlice(), Mask: net.CIDRMask(addr.BitLen(), addr.BitLen())}},
				})
			}
		}
		adopted[name] = w
	}
	if len(routes) > 0 {
		if err := m.cfg.WG.Apply(m.cfg.Iface, routes); err != nil {
			slog.Warn("seed kernel-peer overlay addresses", "err", err)
		}
	}
	m.mu.Lock()
	m.applied = adopted
	for name := range adopted {
		m.kernelPeers[name] = true
		m.seedPeers[name] = true // operator-provisioned; never torn down on leave
	}
	m.mu.Unlock()
	return nil
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
