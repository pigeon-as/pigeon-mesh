//go:build linux

package mesh

import (
	"bytes"
	"log/slog"
	"maps"
	"net"
	"slices"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// reconcile.go drives the kernel WireGuard peer set toward the gossip members.

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

// dropContestedRoutes removes routes a peer must not install and returns the survivors plus the
// contested routes (claimed by more than one peer, installed for none) for status. It also drops any
// route this node serves itself (selfRoutes) so a peer cannot be handed our traffic; that is not a
// contest (we still serve it), so it is not reported.
func dropContestedRoutes(peers map[string]wgPeer, selfRoutes []string) (map[string]wgPeer, map[string][]string) {
	self := make(map[string]bool, len(selfRoutes))
	for _, ip := range selfRoutes {
		self[ip] = true
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
		case self[ip]:
			selfHit = true
		}
	}
	if contested == nil && !selfHit {
		return peers, nil
	}
	effective := make(map[string]wgPeer, len(peers))
	for name, w := range peers {
		kept := slices.DeleteFunc(slices.Clone(w.routes), func(ip string) bool {
			return contested[ip] != nil || self[ip]
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

// reconcile diffs the desired set (accepted members + not-yet-gossiped kernel peers) against applied +
// kernel and applies the delta, then records contested routes and warns about silent kernel peers.
func (m *Mesh) reconcile() error {
	inKernel, err := m.peersInKernel()
	if err != nil {
		return err
	}

	// Snapshot under one read lock, then apply lock-free (WG.Apply is slow I/O).
	m.mu.RLock()
	desired := make(map[string]wgPeer, len(m.members)+len(m.kernelPeers))
	for name, e := range m.members {
		// A fully policy-blocked member is admitted but installs nothing; omit it so diff() removes
		// it from the kernel instead of toWG() failing on empty AllowedIPs every pass.
		if e.admitted() && len(e.wgPeer.routes) > 0 {
			desired[name] = e.wgPeer
		}
	}
	for name := range m.kernelPeers {
		// Keep a kernel peer until it gossips; store() drops gossiped ones from the set.
		if _, ok := desired[name]; ok {
			continue
		}
		if w, ok := m.applied[name]; ok {
			desired[name] = w
		}
	}
	prev := maps.Clone(m.applied)
	m.mu.RUnlock()

	// Seed our full advertised set (not just the overlay /128) so a peer cannot hijack a route we advertise.
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
	m.mu.Unlock()

	for _, route := range newlyContested {
		slog.Warn("route claimed by more than one peer; installed for none until resolved", "route", route, "claimed_by", contested[route])
	}
	return nil
}

// adoptKernelPeers records the operator's pre-existing kernel peers as the applied baseline and seeds
// each one's derived overlay /128 so it is reachable before it gossips.
func (m *Mesh) adoptKernelPeers() error {
	peers, err := m.cfg.WG.Peers(m.cfg.Iface)
	if err != nil {
		return err
	}
	adopted := make(map[string]wgPeer, len(peers))
	var routes []wgtypes.PeerConfig
	for _, p := range peers {
		name := p.PublicKey.String()
		w := wgPeer{key: name}
		if m.cfg.Prefix.IsValid() && !hasHostRoute(p.AllowedIPs) {
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
	}
	m.mu.Unlock()
	return nil
}

// staleKernelPeers returns the kernel peers that never gossiped after the settle window; nil before it.
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
