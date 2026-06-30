//go:build linux

package mesh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/hashicorp/memberlist"
)

type member struct {
	meta               []byte
	peer               Peer
	addr               netip.Addr
	wgPeer             wgPeer
	admitErr           error // nil = admitted
	refusedRoutes      []string
	unauthorizedRoutes []string
	grantExpiry        int64 // unix seconds; 0 = none
	failed             bool
	leaveTime          time.Time
}

func (m member) admitted() bool { return m.admitErr == nil }

func admit(p Peer, name string, signers []ed25519.PublicKey, prefix netip.Prefix, policy *PeerPolicy, now time.Time) member {
	grant, err := verifyGrant(p, name, signers, now)
	if err != nil {
		return member{admitErr: err}
	}
	addr, err := validateOverlayAddr(name, p, prefix)
	if err != nil {
		return member{admitErr: err}
	}
	// Authorize against the grant before policy; unauthorized routes drop but the peer stays admitted.
	authorized, unauthorized := authorizeRoutes(p.AllowedIPs, addr, grant.Routes)
	pc := wgPeer{key: name, endpoint: p.Endpoint, routes: authorized, keepalive: p.PersistentKeepalive}
	if _, err := pc.toWG(); err != nil {
		return member{admitErr: fmt.Errorf("invalid peer config: %w", err)}
	}
	kept, refused := policyFilter(p, authorized, addr, policy)
	pc.routes = kept
	return member{addr: addr, wgPeer: pc, refusedRoutes: refused, unauthorizedRoutes: unauthorized, grantExpiry: grant.NotAfter}
}

// identity /128 is self-certified (exempt from grant routes); other routes must be contained in a grant route.
func authorizeRoutes(allowedIPs []string, identity netip.Addr, grantRoutes []netip.Prefix) (authorized, unauthorized []string) {
	var id netip.Prefix
	if identity.IsValid() {
		id = HostRoute(identity)
	}
	for _, cidr := range allowedIPs {
		r, err := netip.ParsePrefix(cidr)
		if err != nil {
			unauthorized = append(unauthorized, cidr) // malformed: fail closed
			continue
		}
		if id.IsValid() && r == id {
			authorized = append(authorized, cidr)
			continue
		}
		if routeAuthorized(r, grantRoutes) {
			authorized = append(authorized, cidr)
		} else {
			unauthorized = append(unauthorized, cidr)
		}
	}
	return authorized, unauthorized
}

func routeAuthorized(r netip.Prefix, grantRoutes []netip.Prefix) bool {
	for _, g := range grantRoutes {
		if r.Bits() >= g.Bits() && g.Contains(r.Addr()) {
			return true
		}
	}
	return false
}

// Startup and SIGHUP fail fast on this: no control plane means no later approval.
func CheckSelfRoutes(allowedIPs []string, identity netip.Addr, grantRoutes []netip.Prefix) error {
	if _, unauthorized := authorizeRoutes(allowedIPs, identity, grantRoutes); len(unauthorized) > 0 {
		return fmt.Errorf("advertises routes its grant does not authorize: %v", unauthorized)
	}
	return nil
}

// Re-resolves if a SIGHUP swapped signers/policy under us, so no peer is accepted under stale trust.
func (m *Mesh) setMember(n *memberlist.Node) {
	if n.Name == m.cfg.Self.PublicKey || len(n.Meta) == 0 {
		return
	}
	if len(n.Meta) > memberlist.MetaMaxSize {
		slog.Warn("peer meta exceeds limit; ignoring", "node", n.Name, "size", len(n.Meta))
		return
	}
	if m.unchanged(n.Name, n.Meta) {
		return
	}
	p, err := decodePeer(n.Name, n.Meta)
	if err != nil {
		slog.Warn("decode peer", "node", n.Name, "err", err)
		return
	}
	sig, pol := m.signers.Load(), m.policy.Load()
	cur := admit(p, n.Name, *sig, m.cfg.Prefix, pol, time.Now())
	if m.signers.Load() != sig || m.policy.Load() != pol {
		cur = admit(p, n.Name, *m.signers.Load(), m.cfg.Prefix, m.policy.Load(), time.Now())
	}
	cur.meta, cur.peer = bytes.Clone(n.Meta), p
	old := m.store(n.Name, cur)
	if old.admitted() && !cur.admitted() {
		slog.Warn("peer rejected", "pubkey", n.Name, "reason", cur.admitErr.Error())
	}
	if len(old.refusedRoutes) == 0 && len(cur.refusedRoutes) > 0 {
		slog.Warn("peer routes refused by --peer-policy; not installed", "pubkey", n.Name, "routes", cur.refusedRoutes)
	}
	if len(old.unauthorizedRoutes) == 0 && len(cur.unauthorizedRoutes) > 0 {
		slog.Warn("peer advertises routes its grant does not authorize; not installed", "pubkey", n.Name, "routes", cur.unauthorizedRoutes)
	}
	m.triggerReconcile()
}

// A graceful leave deletes the member; a failure marks it failed (kept until reapDead) so a brief
// partition or restart does not churn its tunnel.
func (m *Mesh) removeMember(n *memberlist.Node) {
	if n.Name == m.cfg.Self.PublicKey {
		return
	}
	if n.State == memberlist.StateLeft {
		m.mu.Lock()
		_, existed := m.members[n.Name]
		delete(m.members, n.Name)
		m.mu.Unlock()
		if existed {
			m.triggerReconcile()
		}
		return
	}
	m.mu.Lock()
	if e, ok := m.members[n.Name]; ok && !e.failed {
		e.failed, e.leaveTime = true, time.Now()
		m.members[n.Name] = e
	}
	m.mu.Unlock()
}

// Same WireGuard key on two hosts: keep the first-seen endpoint (never pick a winner), log only.
func (m *Mesh) handleConflict(existing, other *memberlist.Node) {
	if existing.Name == m.cfg.Self.PublicKey {
		slog.Error("another node is advertising our WireGuard key; the same private key is on more than one host. staying up as the key holder, regenerate the key on the other host",
			"pubkey", existing.Name, "other_addr", other.Addr.String(), "other_port", other.Port)
		return
	}
	// memberlist also fires on restart/roam; only alarm if the peer is still alive in our table.
	m.mu.RLock()
	e, ok := m.members[existing.Name]
	alive := ok && !e.failed
	m.mu.RUnlock()
	if !alive {
		slog.Info("peer re-announced from a new address; treating as restart or roam, not a duplicate key",
			"pubkey", existing.Name, "old_addr", existing.Addr.String(), "new_addr", other.Addr.String())
		return
	}
	slog.Warn("two peers advertise the same WireGuard key; keeping the first-seen endpoint until the duplicate key is regenerated",
		"pubkey", existing.Name, "kept_addr", existing.Addr.String(), "kept_port", existing.Port,
		"other_addr", other.Addr.String(), "other_port", other.Port)
}

func (m *Mesh) unchanged(name string, meta []byte) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.members[name]
	return ok && !e.failed && bytes.Equal(e.meta, meta)
}

// Drops it from kernelPeers: it has gossiped, so its fate is now membership.
func (m *Mesh) store(name string, cur member) (old member) {
	m.mu.Lock()
	old = m.members[name]
	m.members[name] = cur
	delete(m.kernelPeers, name)
	m.mu.Unlock()
	return old
}

// Re-stores every verdict unconditionally (rare O(members) pass); must run even when the config is now
// empty, else removing a policy would never restore refused routes.
func (m *Mesh) reevaluate(now time.Time) {
	signers, policy := *m.signers.Load(), m.policy.Load()
	m.mu.Lock()
	changed := false
	for name, e := range m.members {
		nv := admit(e.peer, name, signers, m.cfg.Prefix, policy, now)
		if e.admitted() && !nv.admitted() {
			slog.Warn("peer rejected", "pubkey", name, "reason", nv.admitErr.Error())
		}
		if len(e.refusedRoutes) == 0 && len(nv.refusedRoutes) > 0 {
			slog.Warn("peer routes refused by --peer-policy; not installed", "pubkey", name, "routes", nv.refusedRoutes)
		}
		if len(e.unauthorizedRoutes) == 0 && len(nv.unauthorizedRoutes) > 0 {
			slog.Warn("peer advertises routes its grant does not authorize; not installed", "pubkey", name, "routes", nv.unauthorizedRoutes)
		}
		// Rejected => zero wgPeer, so reject<->admit flips and route changes both show here.
		if !e.wgPeer.equal(nv.wgPeer) {
			changed = true
		}
		e.addr, e.wgPeer, e.admitErr, e.refusedRoutes, e.unauthorizedRoutes, e.grantExpiry = nv.addr, nv.wgPeer, nv.admitErr, nv.refusedRoutes, nv.unauthorizedRoutes, nv.grantExpiry
		m.members[name] = e
	}
	m.mu.Unlock()
	if changed {
		m.triggerReconcile()
	}
}

func (m *Mesh) maintain(ctx context.Context) {
	ticker := time.NewTicker(reapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			m.checkSelfExpiry(now)
			expired, dead := m.expireGrants(now), m.reapDead(now)
			if expired || dead {
				m.triggerReconcile()
			}
		}
	}
}

// Local expiry, needs no gossip update.
func (m *Mesh) expireGrants(now time.Time) (changed bool) {
	ts := now.Unix()
	m.mu.Lock()
	for name, e := range m.members {
		if !e.admitted() || e.grantExpiry == 0 || ts < e.grantExpiry {
			continue
		}
		e.admitErr, e.wgPeer, e.refusedRoutes, e.unauthorizedRoutes = errSignatureExpired, wgPeer{}, nil, nil
		m.members[name] = e
		slog.Warn("peer grant expired; not installed", "pubkey", name)
		changed = true
	}
	m.mu.Unlock()
	return changed
}

func (m *Mesh) reapDead(now time.Time) (changed bool) {
	m.mu.Lock()
	for name, e := range m.members {
		if e.failed && now.Sub(e.leaveTime) > m.cfg.ReconnectTimeout {
			delete(m.members, name)
			changed = true
		}
	}
	m.mu.Unlock()
	return changed
}

// Sets and clears the latch from the current grant, so a renewal that raced a tick self-heals next tick.
func (m *Mesh) checkSelfExpiry(now time.Time) {
	expired := selfSignatureError(*m.selfGrant.Load(), now) != nil
	if was := m.selfExpired.Swap(expired); expired && !was {
		slog.Warn("this node's own operator signature has expired; halting self DNS until re-signed (SIGHUP reloads the grant) or restarted; signature-verifying peers will also drop this node")
	}
}

func (m *Mesh) join() (int, error) {
	peers, err := m.cfg.WG.Peers(m.cfg.Iface)
	if err != nil {
		return 0, err
	}
	targets := make([]string, 0, len(peers))
	for _, p := range peers {
		var added bool
		for _, ipnet := range p.AllowedIPs {
			ones, bits := ipnet.Mask.Size()
			if ones == bits {
				targets = append(targets, net.JoinHostPort(ipnet.IP.String(), strconv.Itoa(m.cfg.GossipPort)))
				added = true
				break
			}
		}
		if !added {
			slog.Warn("kernel peer has no host route in AllowedIPs; skipping", "pubkey", p.PublicKey.String())
		}
	}
	if len(targets) == 0 {
		return 0, nil
	}
	rand.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })
	if len(targets) > joinSeedCount {
		targets = targets[:joinSeedCount]
	}
	return m.memberlist.Join(targets)
}

func (m *Mesh) retryJoin(ctx context.Context) {
	backoff := time.Second
	for {
		if m.memberlist.NumMembers() > 1 {
			backoff = retryJoinInterval
		} else {
			switch n, err := m.join(); {
			case err != nil:
				slog.Warn("retry join", "err", err)
				backoff = min(2*backoff, joinBackoffMax)
			case n > 0:
				slog.Info("joined", "reached", n)
				m.joinedAt.CompareAndSwap(0, time.Now().UnixNano())
				backoff = retryJoinInterval
			default:
				slog.Info("no kernel peers")
				backoff = min(2*backoff, joinBackoffMax)
			}
		}
		wait := backoff/2 + time.Duration(rand.Int64N(int64(backoff/2)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (m *Mesh) reconnect(ctx context.Context) {
	ticker := time.NewTicker(reconnectInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.reconnectOnce()
		}
	}
}

func (m *Mesh) reconnectOnce() {
	var targets []string
	var failed, alive int
	m.mu.RLock()
	for _, e := range m.members {
		if !e.failed {
			alive++
			continue
		}
		failed++
		if addr, ok := hostAddr(e.peer.AllowedIPs); ok {
			targets = append(targets, net.JoinHostPort(addr.String(), strconv.Itoa(m.cfg.GossipPort)))
		}
	}
	m.mu.RUnlock()
	if len(targets) == 0 {
		return
	}
	// Probe with probability ~failed/alive, so a large cluster doesn't thundering-herd re-Joins.
	if alive == 0 {
		alive = 1
	}
	if rand.Float32() > float32(failed)/float32(alive) {
		return
	}
	target := targets[rand.IntN(len(targets))]
	if _, err := m.memberlist.Join([]string{target}); err != nil {
		slog.Debug("reconnect", "target", target, "err", err)
	}
}

func (m *Mesh) snapshot() (members map[string]member, contested map[string][]string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return maps.Clone(m.members), maps.Clone(m.contested)
}

func (m *Mesh) liveMembers() (members map[string]member, contested map[string][]string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]member, len(m.members))
	for name, e := range m.members {
		if e.admitted() && !e.failed {
			out[name] = e
		}
	}
	return out, maps.Clone(m.contested)
}
