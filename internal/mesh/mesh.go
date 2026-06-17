//go:build linux

package mesh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/pigeon-as/pigeon-mesh/internal/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	retryJoinInterval = 30 * time.Second
	reconcileInterval = 60 * time.Second
	retryFailInterval = 15 * time.Second
	reconnectInterval = 30 * time.Second
	reapInterval      = 15 * time.Second
	joinSeedCount     = 16

	routeReassertDebounce = 250 * time.Millisecond
)

type Config struct {
	Iface            string
	GossipPort       int
	BindAddr         string
	Profile          string
	SocketPath       string
	Self             Peer
	Keyring          *memberlist.Keyring
	Prefix           netip.Prefix
	DNSZone          string
	Signers          []ed25519.PublicKey
	RequireSignature bool
	ReconnectTimeout time.Duration
	WG               *wg.Client
}

type member struct {
	meta      []byte
	peer      Peer
	addr      netip.Addr
	reject    string
	notAfter  int64
	failed    bool
	leaveTime time.Time
}

type Mesh struct {
	cfg         Config
	meta        []byte
	memberlist  *memberlist.Memberlist
	mu          sync.RWMutex
	members     map[string]member
	peers       map[string]Peer
	conflicts    map[string][]string
	rejected     map[string]string
	keyConflicts map[string]string
	reconcileCh  chan struct{}
	leave       chan struct{}
	bootstrap   map[string]bool
	signers     []ed25519.PublicKey
	signersGen  uint64
}

func New(cfg Config) (*Mesh, error) {
	if cfg.WG == nil {
		return nil, errors.New("no wgctrl client configured")
	}
	if cfg.BindAddr == "" {
		return nil, errors.New("no bind addr configured")
	}
	meta, err := encodeMeta(cfg.Self)
	if err != nil {
		return nil, err
	}
	if len(meta) > memberlist.MetaMaxSize {
		return nil, fmt.Errorf("encoded self meta %d bytes exceeds limit %d", len(meta), memberlist.MetaMaxSize)
	}

	m := &Mesh{
		cfg:         cfg,
		meta:        meta,
		members:     make(map[string]member),
		peers:       make(map[string]Peer),
		conflicts:    make(map[string][]string),
		rejected:     make(map[string]string),
		keyConflicts: make(map[string]string),
		reconcileCh:  make(chan struct{}, 1),
		leave:       make(chan struct{}, 1),
		bootstrap:   make(map[string]bool),
		signers:     cfg.Signers,
	}

	d := &delegate{mesh: m}
	var mc *memberlist.Config
	switch cfg.Profile {
	case "", "wan":
		mc = memberlist.DefaultWANConfig()
	case "lan":
		mc = memberlist.DefaultLANConfig()
	case "local":
		mc = memberlist.DefaultLocalConfig()
	default:
		return nil, fmt.Errorf("profile %q: must be lan, wan, or local", cfg.Profile)
	}
	mc.Name = cfg.Self.PublicKey
	mc.Delegate = d
	mc.Events = d
	mc.Conflict = d
	mc.Keyring = cfg.Keyring
	mc.Logger = newMemberlistLogger()
	mc.DeadNodeReclaimTime = 30 * time.Second

	nt, err := memberlist.NewNetTransport(&memberlist.NetTransportConfig{
		BindAddrs: []string{cfg.BindAddr},
		BindPort:  cfg.GossipPort,
		Logger:    mc.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	mc.Transport = &wgTransport{nt}

	ml, err := memberlist.Create(mc)
	if err != nil {
		return nil, fmt.Errorf("memberlist: %w", err)
	}
	m.memberlist = ml
	return m, nil
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
			slog.Warn("bootstrap peer has no host route in AllowedIPs; skipping", "pubkey", p.PublicKey.String())
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

func diff(prev, cur map[string]Peer) []wgtypes.PeerConfig {
	var changes []wgtypes.PeerConfig
	for name, p := range cur {
		prevPeer, known := prev[name]
		if known && prevPeer.equal(p) {
			continue
		}
		pc, err := p.toWG()
		if err != nil {
			slog.Warn("peer to wg", "node", name, "err", err)
			continue
		}
		if known {
			pc.UpdateOnly = true
			if prevPeer.Endpoint == p.Endpoint {
				pc.Endpoint = nil
			}
		}
		changes = append(changes, pc)
	}
	for name := range prev {
		if _, ok := cur[name]; ok {
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

func (m *Mesh) setMember(n *memberlist.Node) {
	if n.Name == m.cfg.Self.PublicKey {
		return
	}
	if len(n.Meta) == 0 {
		return
	}
	if len(n.Meta) > memberlist.MetaMaxSize {
		slog.Warn("peer meta exceeds limit; ignoring", "node", n.Name, "size", len(n.Meta))
		return
	}
	m.mu.RLock()
	if existing, ok := m.members[n.Name]; ok && !existing.failed && bytes.Equal(existing.meta, n.Meta) {
		m.mu.RUnlock()
		return
	}
	signers := m.signers
	gen := m.signersGen
	require := m.cfg.RequireSignature
	prefix := m.cfg.Prefix
	m.mu.RUnlock()

	p, err := decodePeer(n.Name, n.Meta)
	if err != nil {
		slog.Warn("decode peer", "node", n.Name, "err", err)
		return
	}
	meta := bytes.Clone(n.Meta)
	addr, reject, notAfter := assess(p, n.Name, signers, require, prefix, time.Now())

	m.mu.Lock()
	if m.signersGen != gen {
		addr, reject, notAfter = assess(p, n.Name, m.signers, require, prefix, time.Now())
	}
	m.members[n.Name] = member{meta: meta, peer: p, addr: addr, reject: reject, notAfter: notAfter}
	delete(m.bootstrap, n.Name)
	m.mu.Unlock()
	m.triggerReconcile()
}

func assess(p Peer, name string, signers []ed25519.PublicKey, requireSig bool, prefix netip.Prefix, now time.Time) (netip.Addr, string, int64) {
	addr, reject := evaluate(p, name, signers, requireSig, prefix, now)
	var notAfter int64
	if reject == "" && len(signers) > 0 {
		notAfter = signatureNotAfter(p.Signature)
	}
	return addr, reject, notAfter
}

func evaluate(p Peer, name string, signers []ed25519.PublicKey, requireSig bool, prefix netip.Prefix, now time.Time) (netip.Addr, string) {
	if reason := signatureReject(p, name, signers, requireSig, now); reason != "" {
		return netip.Addr{}, reason
	}
	var addr netip.Addr
	if prefix.IsValid() {
		a, err := validateOverlayAddr(name, p, prefix)
		if err != nil {
			return netip.Addr{}, err.Error()
		}
		addr = a
	} else {
		addr = advertisedAddr(p)
	}
	if _, err := p.toWG(); err != nil {
		return netip.Addr{}, "invalid peer config: " + err.Error()
	}
	return addr, ""
}

func advertisedAddr(p Peer) netip.Addr {
	for _, c := range p.AllowedIPs {
		if pfx, err := netip.ParsePrefix(c); err == nil && pfx.Bits() == pfx.Addr().BitLen() {
			return pfx.Addr()
		}
	}
	return netip.Addr{}
}

func signatureReject(p Peer, name string, signers []ed25519.PublicKey, requireSig bool, now time.Time) string {
	if len(signers) == 0 {
		return ""
	}
	if len(p.Signature) == 0 {
		if requireSig {
			return "no signature"
		}
		return ""
	}
	if err := VerifySignature(signers, name, p.Signature, now); err != nil {
		return err.Error()
	}
	return ""
}

func (m *Mesh) reevaluate(now time.Time) {
	m.mu.RLock()
	signers := m.signers
	if len(signers) == 0 {
		m.mu.RUnlock()
		return
	}
	require := m.cfg.RequireSignature
	prefix := m.cfg.Prefix
	type snapshot struct {
		name     string
		meta     []byte
		peer     Peer
		addr     netip.Addr
		reject   string
		notAfter int64
	}
	snaps := make([]snapshot, 0, len(m.members))
	for name, e := range m.members {
		if !e.failed {
			snaps = append(snaps, snapshot{name, e.meta, e.peer, e.addr, e.reject, e.notAfter})
		}
	}
	m.mu.RUnlock()

	type change struct {
		name     string
		meta     []byte
		addr     netip.Addr
		reject   string
		notAfter int64
	}
	var changes []change
	for _, s := range snaps {
		addr, reject, notAfter := assess(s.peer, s.name, signers, require, prefix, now)
		if reject != s.reject || addr != s.addr || notAfter != s.notAfter {
			changes = append(changes, change{s.name, s.meta, addr, reject, notAfter})
		}
	}
	if len(changes) == 0 {
		return
	}

	m.mu.Lock()
	for _, c := range changes {
		e, ok := m.members[c.name]
		if !ok || e.failed || !bytes.Equal(e.meta, c.meta) {
			continue
		}
		e.addr = c.addr
		e.reject = c.reject
		e.notAfter = c.notAfter
		m.members[c.name] = e
	}
	m.mu.Unlock()
	m.triggerReconcile()
}

func (m *Mesh) sweepExpiry(now time.Time) {
	ts := now.Unix()
	m.mu.Lock()
	changed := false
	for name, e := range m.members {
		if e.reject != "" || e.notAfter == 0 {
			continue
		}
		if ts >= e.notAfter {
			e.reject = "signature expired"
			m.members[name] = e
			changed = true
		}
	}
	m.mu.Unlock()
	if changed {
		m.triggerReconcile()
	}
}

func (m *Mesh) removeMember(n *memberlist.Node) {
	if n.Name == m.cfg.Self.PublicKey {
		return
	}
	if n.State == memberlist.StateLeft {
		m.mu.Lock()
		_, ok := m.members[n.Name]
		delete(m.members, n.Name)
		m.mu.Unlock()
		if ok {
			m.triggerReconcile()
		}
		return
	}
	m.mu.Lock()
	if e, ok := m.members[n.Name]; ok && !e.failed {
		e.failed = true
		e.leaveTime = time.Now()
		m.members[n.Name] = e
	}
	m.mu.Unlock()
}

func (m *Mesh) handleNodeConflict(existing, other *memberlist.Node) {
	if existing.Name == m.cfg.Self.PublicKey {
		slog.Error("another node is advertising our WireGuard key; the same private key is on more than one host. staying up as the key holder, regenerate the key on the other host",
			"pubkey", existing.Name,
			"other_addr", other.Addr.String(), "other_port", other.Port)
		m.recordKeyConflict(existing.Name, fmt.Sprintf("this node's key is also advertised from %s:%d", other.Addr, other.Port))
		return
	}
	slog.Warn("two peers advertise the same WireGuard key; keeping the first-seen endpoint until the duplicate key is regenerated",
		"pubkey", existing.Name,
		"kept_addr", existing.Addr.String(), "kept_port", existing.Port,
		"other_addr", other.Addr.String(), "other_port", other.Port)
	m.recordKeyConflict(existing.Name, fmt.Sprintf("kept %s:%d, also advertised from %s:%d", existing.Addr, existing.Port, other.Addr, other.Port))
}

func (m *Mesh) recordKeyConflict(pubkey, detail string) {
	m.mu.Lock()
	m.keyConflicts[pubkey] = detail
	m.mu.Unlock()
}

func (m *Mesh) triggerReconcile() {
	select {
	case m.reconcileCh <- struct{}{}:
	default:
	}
}

func resolveConflicts(peers map[string]Peer) (map[string]Peer, map[string][]string) {
	claims := make(map[string][]string)
	for name, p := range peers {
		for _, ip := range p.AllowedIPs {
			claims[ip] = append(claims[ip], name)
		}
	}
	var conflicts map[string][]string
	for ip, owners := range claims {
		if len(owners) > 1 {
			if conflicts == nil {
				conflicts = make(map[string][]string)
			}
			slices.Sort(owners)
			conflicts[ip] = owners
		}
	}
	if conflicts == nil {
		return peers, nil
	}
	effective := make(map[string]Peer, len(peers))
	for name, p := range peers {
		kept := slices.DeleteFunc(slices.Clone(p.AllowedIPs), func(ip string) bool {
			return len(claims[ip]) > 1
		})
		if len(kept) == 0 {
			continue
		}
		p.AllowedIPs = kept
		effective[name] = p
	}
	return effective, conflicts
}

func (m *Mesh) setConflicts(conflicts map[string][]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for route, owners := range conflicts {
		if _, seen := m.conflicts[route]; !seen {
			slog.Warn("route claimed by more than one peer; installed for none until resolved",
				"route", route, "claimed_by", owners)
		}
	}
	m.conflicts = conflicts
}

func (m *Mesh) setRejected(rejected map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for pubkey, reason := range rejected {
		if _, seen := m.rejected[pubkey]; !seen {
			slog.Warn("peer rejected", "pubkey", pubkey, "reason", reason)
		}
	}
	m.rejected = rejected
}

func hasHostRoute(ips []net.IPNet) bool {
	for _, ipn := range ips {
		ones, bits := ipn.Mask.Size()
		if ones == bits {
			return true
		}
	}
	return false
}

func (m *Mesh) seedPeersFromKernel() error {
	peers, err := m.cfg.WG.Peers(m.cfg.Iface)
	if err != nil {
		return err
	}
	seeded := make(map[string]Peer, len(peers))
	var routes []wgtypes.PeerConfig
	m.mu.Lock()
	for _, p := range peers {
		name := p.PublicKey.String()
		sp := Peer{PublicKey: name}
		if m.cfg.Prefix.IsValid() && !hasHostRoute(p.AllowedIPs) {
			if addr, derr := DeriveAddr(name, m.cfg.Prefix); derr == nil {
				sp.AllowedIPs = []string{HostRoute(addr).String()}
				routes = append(routes, wgtypes.PeerConfig{
					PublicKey:  p.PublicKey,
					UpdateOnly: true,
					AllowedIPs: []net.IPNet{{IP: addr.AsSlice(), Mask: net.CIDRMask(addr.BitLen(), addr.BitLen())}},
				})
			}
		}
		seeded[name] = sp
		m.bootstrap[name] = true
	}
	m.mu.Unlock()
	if len(routes) > 0 {
		if err := m.cfg.WG.Apply(m.cfg.Iface, routes); err != nil {
			slog.Warn("seed bootstrap overlay addresses", "err", err)
		}
	}
	m.peers = seeded
	return nil
}

func (m *Mesh) reconcile() error {
	if m.cfg.Prefix.IsValid() {
		if err := m.cfg.WG.SetRoute(m.cfg.Iface, m.cfg.Prefix); err != nil {
			slog.Warn("overlay route", "err", err)
		}
	}
	m.mu.RLock()
	cur := make(map[string]Peer, len(m.members))
	rejected := make(map[string]string)
	for name, e := range m.members {
		if e.reject != "" {
			rejected[name] = e.reject
			continue
		}
		cur[name] = e.peer
	}
	bootstrap := make(map[string]struct{}, len(m.bootstrap))
	for name := range m.bootstrap {
		bootstrap[name] = struct{}{}
	}
	m.mu.RUnlock()

	m.setRejected(rejected)
	effective, conflicts := resolveConflicts(cur)
	m.setConflicts(conflicts)

	for name := range bootstrap {
		if _, ok := effective[name]; !ok {
			if p, ok := m.peers[name]; ok {
				effective[name] = p
			}
		}
	}

	changes := diff(m.peers, effective)
	if len(changes) > 0 {
		if err := m.cfg.WG.Apply(m.cfg.Iface, changes); err != nil {
			return err
		}
		m.peers = effective
	}
	return nil
}

func (m *Mesh) Run(ctx context.Context) error {
	defer func() {
		if err := m.memberlist.Shutdown(); err != nil {
			slog.Warn("memberlist shutdown", "err", err)
		}
	}()

	runCtx, cancel := context.WithCancel(ctx)
	var resolverWG sync.WaitGroup
	defer func() {
		cancel()
		resolverWG.Wait()
	}()

	if err := m.seedPeersFromKernel(); err != nil {
		slog.Warn("seed peers from kernel; departed peers may persist this run", "err", err)
	}

	go m.serveStatus(runCtx)
	go m.serveRouteMonitor(runCtx)
	resolverWG.Go(func() {
		m.serveResolver(runCtx)
	})

	n, err := m.join()
	if err != nil {
		slog.Warn("initial join", "err", err)
	}
	if n > 0 {
		slog.Info("joined", "reached", n)
	}
	go m.retryJoin(runCtx)
	go m.reconnect(runCtx)
	go m.reap(runCtx)

	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()

	retryAfter := func(err error) <-chan time.Time {
		if err != nil {
			slog.Warn("reconcile", "err", err)
			return time.After(retryFailInterval)
		}
		return nil
	}

	retry := retryAfter(m.reconcile())
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-m.leave:
			return nil
		case <-m.reconcileCh:
			retry = retryAfter(m.reconcile())
		case <-ticker.C:
			m.sweepExpiry(time.Now())
			retry = retryAfter(m.reconcile())
		case <-retry:
			retry = retryAfter(m.reconcile())
		}
	}
}

func (m *Mesh) ReloadKeyringFromFile(path string) (int, error) {
	kr, err := LoadKeyring(path)
	if err != nil {
		return 0, fmt.Errorf("load: %w", err)
	}
	if err := m.ReloadKeyring(kr); err != nil {
		return 0, fmt.Errorf("apply: %w", err)
	}
	return len(kr.GetKeys()), nil
}

func (m *Mesh) ReloadSignersFromFile(path string) (int, error) {
	keys, err := LoadSigners(path)
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	m.signers = keys
	m.signersGen++
	m.mu.Unlock()
	m.reevaluate(time.Now())
	return len(keys), nil
}

func (m *Mesh) ReloadKeyring(target *memberlist.Keyring) error {
	if m.cfg.Keyring == nil {
		return errors.New("no keyring configured")
	}
	targetKeys := target.GetKeys()
	if len(targetKeys) == 0 {
		return errors.New("target keyring is empty")
	}
	liveKeys := slices.Clone(m.cfg.Keyring.GetKeys())

	for _, k := range targetKeys {
		if !containsKey(liveKeys, k) {
			if err := m.cfg.Keyring.AddKey(k); err != nil {
				return fmt.Errorf("add key: %w", err)
			}
		}
	}
	if err := m.cfg.Keyring.UseKey(targetKeys[0]); err != nil {
		return fmt.Errorf("use primary: %w", err)
	}
	for _, k := range liveKeys {
		if !containsKey(targetKeys, k) {
			if err := m.cfg.Keyring.RemoveKey(k); err != nil {
				return fmt.Errorf("remove key: %w", err)
			}
		}
	}
	return nil
}

func (m *Mesh) retryJoin(ctx context.Context) {
	backoff := time.Second
	for {
		wait := backoff/2 + time.Duration(rand.Int64N(int64(backoff/2)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if m.memberlist.NumMembers() > 1 {
			backoff = retryJoinInterval
			continue
		}
		n, err := m.join()
		switch {
		case err != nil:
			slog.Warn("retry join", "err", err)
			backoff = nextJoinBackoff(backoff)
		case n > 0:
			slog.Info("joined", "reached", n)
			backoff = retryJoinInterval
		default:
			slog.Info("no bootstrap peers")
			backoff = nextJoinBackoff(backoff)
		}
	}
}

func (m *Mesh) reap(ctx context.Context) {
	ticker := time.NewTicker(reapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			var reaped bool
			m.mu.Lock()
			for name, e := range m.members {
				if shouldReap(e.failed, e.leaveTime, now, m.cfg.ReconnectTimeout) {
					delete(m.members, name)
					reaped = true
				}
			}
			m.mu.Unlock()
			if reaped {
				m.triggerReconcile()
			}
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
	m.mu.RLock()
	var targets []string
	var failed, alive int
	for _, e := range m.members {
		if !e.failed {
			alive++
			continue
		}
		failed++
		if t := gossipTarget(e.peer, m.cfg.GossipPort); t != "" {
			targets = append(targets, t)
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

func gossipTarget(p Peer, port int) string {
	for _, c := range p.AllowedIPs {
		if pfx, err := netip.ParsePrefix(c); err == nil && pfx.IsSingleIP() {
			return net.JoinHostPort(pfx.Addr().String(), strconv.Itoa(port))
		}
	}
	return ""
}

func shouldReap(failed bool, leaveTime, now time.Time, timeout time.Duration) bool {
	return failed && now.Sub(leaveTime) > timeout
}

func shouldProbe(failed, alive int, r float32) bool {
	if alive == 0 {
		alive = 1
	}
	return r <= float32(failed)/float32(alive)
}

func nextJoinBackoff(cur time.Duration) time.Duration {
	return min(2*cur, retryJoinInterval)
}

func (m *Mesh) requestLeave(timeout time.Duration) error {
	if err := m.memberlist.Leave(timeout); err != nil {
		return err
	}
	select {
	case m.leave <- struct{}{}:
	default:
	}
	return nil
}
