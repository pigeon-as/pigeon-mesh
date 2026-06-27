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
	"slices"
	"strconv"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/pigeon-as/pigeon-mesh/internal/signature"
)

// member.go is the membership engine: the gossip-derived member set and everything that mutates it.

// member is the locally-tracked state for one gossip peer.
type member struct {
	meta          []byte
	peer          Peer       // gossip advertisement (wire format)
	addr          netip.Addr // key-derived overlay address
	wgPeer        wgPeer     // kernel config to install when admitted
	admitErr      error      // nil = admitted; else why not installed
	refusedRoutes []string   // advertised routes --peer-policy refused
	grantExpiry   int64      // operator-grant expiry, unix seconds (0 = none)
	failed        bool       // SWIM liveness
	leaveTime     time.Time  // set when failed; reaped at +ReconnectTimeout
}

func (m member) admitted() bool { return m.admitErr == nil }

// errText is err.Error(), or "" for nil.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// admit checks an advertisement's signature, identity, and policy and returns the member to track:
// admitted with its kernel config, or not admitted with admitErr set. Pure; holds no lock.
func admit(p Peer, name string, signers []ed25519.PublicKey, prefix netip.Prefix, policy *PeerPolicy, now time.Time) member {
	if err := signatureError(p, name, signers, now); err != nil {
		return member{admitErr: err}
	}
	addr, err := validateOverlayAddr(name, p, prefix)
	if err != nil {
		return member{admitErr: err}
	}
	pc := wgPeer{key: name, endpoint: p.Endpoint, routes: p.AllowedIPs, keepalive: p.PersistentKeepalive}
	if _, err := pc.toWG(); err != nil {
		return member{admitErr: fmt.Errorf("invalid peer config: %w", err)}
	}
	kept, refused := policyFilter(p, addr, policy)
	pc.routes = kept // policy-accepted routes, not the raw advertisement
	return member{addr: addr, wgPeer: pc, refusedRoutes: refused, grantExpiry: signature.NotAfter(p.Signature)}
}

// setMember resolves a gossiped advertisement and stores it. Re-resolves if a SIGHUP swapped
// signers/policy under us, so a peer is never accepted under stale trust.
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
		slog.Warn("peer rejected", "pubkey", n.Name, "reason", errText(cur.admitErr))
	}
	if len(old.refusedRoutes) == 0 && len(cur.refusedRoutes) > 0 {
		slog.Warn("peer routes refused by --peer-policy; not installed", "pubkey", n.Name, "routes", cur.refusedRoutes)
	}
	m.triggerReconcile()
}

// removeMember handles NotifyLeave: a graceful leave deletes the member; a failure marks it failed
// (kept until reapDead) so a brief partition or restart does not churn its tunnel.
func (m *Mesh) removeMember(n *memberlist.Node) {
	if n.Name == m.cfg.Self.PublicKey {
		return
	}
	if n.State == memberlist.StateLeft {
		m.mu.Lock()
		_, existed := m.members[n.Name]
		delete(m.members, n.Name)
		delete(m.keyConflicts, n.Name)
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

// handleConflict handles NotifyConflict: two hosts advertising the same WireGuard key. pigeon keeps
// the first-seen endpoint (never picks a winner) and records the clash for status.
func (m *Mesh) handleConflict(existing, other *memberlist.Node) {
	if existing.Name == m.cfg.Self.PublicKey {
		slog.Error("another node is advertising our WireGuard key; the same private key is on more than one host. staying up as the key holder, regenerate the key on the other host",
			"pubkey", existing.Name, "other_addr", other.Addr.String(), "other_port", other.Port)
		m.mu.Lock()
		m.keyConflicts[existing.Name] = "this node's key is also advertised from " + addrPort(other.Addr, other.Port)
		m.mu.Unlock()
		return
	}
	// memberlist also fires this on restart/roam; only alarm if our table still has the peer alive.
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
	m.mu.Lock()
	m.keyConflicts[existing.Name] = "kept " + addrPort(existing.Addr, existing.Port) + ", also advertised from " + addrPort(other.Addr, other.Port)
	m.mu.Unlock()
}

// unchanged reports that name already holds this exact advertisement and is not failed.
func (m *Mesh) unchanged(name string, meta []byte) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.members[name]
	return ok && !e.failed && bytes.Equal(e.meta, meta)
}

// store records a resolved member and drops it from kernelPeers: it has gossiped, so its fate is now
// membership (admitted kept, rejected/left removed). Returns the prior value.
func (m *Mesh) store(name string, cur member) (old member) {
	m.mu.Lock()
	old = m.members[name]
	m.members[name] = cur
	delete(m.kernelPeers, name)
	m.mu.Unlock()
	return old
}

// reevaluate re-resolves every member after a SIGHUP reload and reconciles if anything changed. Must
// run even when the config is now empty, or removing a policy would never restore refused routes.
func (m *Mesh) reevaluate(now time.Time) {
	signers, policy := *m.signers.Load(), m.policy.Load()
	m.mu.Lock()
	changed := false
	for name, e := range m.members {
		nv := admit(e.peer, name, signers, m.cfg.Prefix, policy, now)
		if errText(e.admitErr) == errText(nv.admitErr) && e.wgPeer.equal(nv.wgPeer) && slices.Equal(e.refusedRoutes, nv.refusedRoutes) {
			continue
		}
		if e.admitted() && !nv.admitted() {
			slog.Warn("peer rejected", "pubkey", name, "reason", errText(nv.admitErr))
		}
		if len(e.refusedRoutes) == 0 && len(nv.refusedRoutes) > 0 {
			slog.Warn("peer routes refused by --peer-policy; not installed", "pubkey", name, "routes", nv.refusedRoutes)
		}
		e.addr, e.wgPeer, e.admitErr, e.refusedRoutes, e.grantExpiry = nv.addr, nv.wgPeer, nv.admitErr, nv.refusedRoutes, nv.grantExpiry
		m.members[name] = e
		changed = true
	}
	m.mu.Unlock()
	if changed {
		m.triggerReconcile()
	}
}

// maintain ages out members each tick: checks our own grant, expires peers' lapsed grants, and reaps
// peers SWIM-failed past --reconnect-timeout.
func (m *Mesh) maintain(ctx context.Context) {
	// random phase offset so nodes sharing a grant expiry don't all reconcile at once
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Duration(rand.Int64N(int64(reapInterval)))):
	}
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

// expireGrants rejects members whose operator grant lapsed; runs on the maintain ticker so expiry
// needs no gossip update.
func (m *Mesh) expireGrants(now time.Time) (changed bool) {
	ts := now.Unix()
	m.mu.Lock()
	for name, e := range m.members {
		if !e.admitted() || e.grantExpiry == 0 || ts < e.grantExpiry {
			continue
		}
		e.admitErr, e.wgPeer, e.refusedRoutes = errSignatureExpired, wgPeer{}, nil
		m.members[name] = e
		slog.Warn("peer grant expired; not installed", "pubkey", name)
		changed = true
	}
	m.mu.Unlock()
	return changed
}

// reapDead deletes members SWIM-failed past --reconnect-timeout, dropping their key-conflict alert.
func (m *Mesh) reapDead(now time.Time) (changed bool) {
	m.mu.Lock()
	for name, e := range m.members {
		if e.failed && now.Sub(e.leaveTime) > m.cfg.ReconnectTimeout {
			delete(m.members, name)
			delete(m.keyConflicts, name)
			changed = true
		}
	}
	m.mu.Unlock()
	return changed
}

// checkSelfExpiry halts self DNS once this node's own grant expires (self is never in the member set).
func (m *Mesh) checkSelfExpiry(now time.Time) {
	if selfSignatureError(m.cfg.Self, now) != nil && m.selfExpired.CompareAndSwap(false, true) {
		slog.Warn("this node's own operator signature has expired; halting self DNS until re-signed and restarted (signature-verifying peers will also drop this node)")
	}
}

// join seeds the gossip cluster from the kernel's existing peers: up to joinSeedCount carrying a host route.
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

// retryJoin keeps attempting to join until the cluster is reached, then idles at retryJoinInterval.
func (m *Mesh) retryJoin(ctx context.Context) {
	backoff := time.Second
	for {
		// attempt before waiting: the first join is immediate
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

// reconnect periodically re-Joins a sampled SWIM-failed peer so a brief partition heals.
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
	if !shouldProbe(failed, alive, rand.Float32()) {
		return
	}
	target := targets[rand.IntN(len(targets))]
	if _, err := m.memberlist.Join([]string{target}); err != nil {
		slog.Debug("reconnect", "target", target, "err", err)
	}
}

// shouldProbe gates reconnect at ~failed/alive so a large cluster doesn't thundering-herd re-Joins.
func shouldProbe(failed, alive int, r float32) bool {
	if alive == 0 {
		alive = 1
	}
	return r <= float32(failed)/float32(alive)
}

// snapshot copies the member set, contested routes, and key conflicts under one read lock, for status.
func (m *Mesh) snapshot() (members map[string]member, contested map[string][]string, keyConflicts map[string]string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return maps.Clone(m.members), maps.Clone(m.contested), maps.Clone(m.keyConflicts)
}

// liveMembers copies the admitted, non-failed members plus contested routes, for the DNS bridge.
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
