//go:build linux

package mesh

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/pigeon-as/pigeon-mesh/internal/wg"
)

const (
	retryJoinInterval = 30 * time.Second
	reconcileInterval = 60 * time.Second
	retryFailInterval = 15 * time.Second
	reconnectInterval = 30 * time.Second
	reapInterval      = 15 * time.Second
	joinSeedCount     = 16
	// Frequent retries until first peer reached, so we connect as soon as a seed tunnel warms.
	joinBackoffMax = 4 * time.Second

	routeReassertDebounce = 250 * time.Millisecond
	// Rate-limits triggered reconciles: a convergence wave (join storm, mass restart) fires many triggers,
	// and each reconcile does an O(N) netlink peer dump, so coalesce them into at most one run per window.
	reconcileDebounce = 250 * time.Millisecond

	kernelSettle = 30 * time.Second

	grantUpdateTimeout = 5 * time.Second
)

type Config struct {
	Iface            string
	GossipPort       int
	BindAddr         string
	Profile          string
	SocketPath       string
	StatePath        string // /run file recording daemon-added peers, so leave stays correct across a restart
	Self             Peer
	Prefix           netip.Prefix
	Policy           *PeerPolicy
	DNSZone          string
	Signers          []ed25519.PublicKey
	Revoked          map[string]struct{}
	ReconnectTimeout time.Duration
	WG               *wg.Client
}

type Mesh struct {
	cfg        Config // immutable after New; cfg's trust fields (Signers/Policy/Revoked/Self.Signature) are construction-only seeds, go stale on SIGHUP, read the atomics below
	meta       atomic.Pointer[[]byte]
	selfGrant  atomic.Pointer[[]byte]
	selfAddr   netip.Addr
	memberlist *memberlist.Memberlist

	mu          sync.RWMutex // guards the membership maps below
	members     map[string]member
	applied     map[string]wgPeer
	kernelPeers map[string]bool     // kernel peers awaiting first gossip; dropped once they gossip
	seedPeers   map[string]bool     // operator-provisioned kernel peers at startup; never torn down on leave (immutable after adoptKernelPeers)
	contested   map[string][]string // claimed by >1 peer, installed for none
	isolated    bool                // isolation warn-once latch

	signers atomic.Pointer[[]ed25519.PublicKey] // swapped whole on SIGHUP for lock-free reads
	policy  atomic.Pointer[PeerPolicy]
	revoked atomic.Pointer[map[string]struct{}] // operator denylist from --revoked; replaced whole on SIGHUP

	dnsCacheMu sync.Mutex // short-TTL cache so a DNS query flood does not rebuild the record map per packet
	dnsCache   map[string]netip.Addr
	dnsCacheAt time.Time

	reconcileCh chan struct{}
	leave       chan struct{}
	ready       chan struct{} // closed after the first successful reconcile; gates systemd READY
	joinedAt    atomic.Int64
	selfExpired atomic.Bool
	selfRevoked atomic.Bool
	shutdownMu  sync.Mutex
	shutdown    bool
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
		return nil, fmt.Errorf("this node's gossip metadata is %d bytes, over the %d-byte limit; trim advertised routes (--allowed-ips), tags (--tag), or the signed name", len(meta), memberlist.MetaMaxSize)
	}

	// Floor to 2 probe cycles: reaping sooner tears down a tunnel a brief partition/restart would restore.
	if floor := 2 * reconnectInterval; cfg.ReconnectTimeout < floor {
		if cfg.ReconnectTimeout > 0 {
			slog.Warn("--reconnect-timeout is shorter than the reconnect probe cycle; raising it so peers are not reaped before they can reconnect",
				"configured", cfg.ReconnectTimeout, "minimum", floor)
		}
		cfg.ReconnectTimeout = floor
	}

	selfAddr, err := netip.ParseAddr(cfg.BindAddr)
	if err != nil {
		return nil, fmt.Errorf("bind addr %q: %w", cfg.BindAddr, err)
	}
	m := &Mesh{
		cfg:         cfg,
		selfAddr:    selfAddr,
		members:     map[string]member{},
		applied:     map[string]wgPeer{},
		kernelPeers: map[string]bool{},
		seedPeers:   map[string]bool{},
		contested:   map[string][]string{},
		reconcileCh: make(chan struct{}, 1),
		leave:       make(chan struct{}, 1),
		ready:       make(chan struct{}),
	}
	m.meta.Store(&meta)
	grant := cfg.Self.Signature
	m.selfGrant.Store(&grant)
	sigs := cfg.Signers
	m.signers.Store(&sigs)
	m.policy.Store(cfg.Policy)
	revoked := cfg.Revoked
	if revoked == nil {
		revoked = map[string]struct{}{}
	}
	m.revoked.Store(&revoked)

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
	mc.Logger = newMemberlistLogger()
	// Name+addr key-derived and port fixed, so a same-key restart returns UNCHANGED: it never uses reclaim
	// (memberlist gates that on a changed addr/port) and, if it was marked dead, reconverges by refutation.
	// This 30s only bounds a restart that changes --gossip-port.
	mc.DeadNodeReclaimTime = 30 * time.Second

	// Must seed kernelPeers before Create: a remote join landing first makes setMember's delete a no-op,
	// leaving the peer un-removable on graceful leave. After the profile switch so an invalid profile returns untouched.
	if err := m.adoptKernelPeers(); err != nil {
		slog.Warn("adopt kernel peers; departed peers may persist this run", "err", err)
	}

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

func (m *Mesh) triggerReconcile() {
	select {
	case m.reconcileCh <- struct{}{}:
	default:
	}
}

func (m *Mesh) Run(ctx context.Context) error {
	leaving := false
	defer func() {
		if err := m.shutdownMemberlist(); err != nil {
			slog.Warn("memberlist shutdown", "err", err)
		}
		// Graceful leave only: undo what we added (interface not ours). Remove the kernel peers the daemon
		// installed (gossip-discovered), never the operator-provisioned seed peers, then undo the overlay
		// addr+route we assigned. After runCtx cancel so the route monitor won't re-assert it.
		if leaving {
			m.removeAddedPeers()
			if err := m.cfg.WG.DelRoute(m.cfg.Iface, m.cfg.Prefix); err != nil {
				slog.Warn("remove overlay route on leave", "err", err)
			}
			if err := m.cfg.WG.DelAddr(m.cfg.Iface, m.selfAddr); err != nil {
				slog.Warn("remove overlay address on leave", "err", err)
			}
		}
	}()

	runCtx, cancel := context.WithCancel(ctx)
	var resolverWG sync.WaitGroup
	defer func() {
		cancel()
		resolverWG.Wait()
	}()

	go m.serveStatus(runCtx)
	go m.guardOverlayRoute(runCtx)
	resolverWG.Go(func() {
		m.serveDNS(runCtx)
	})

	// Async: a synchronous join would block Run on a cold seed tunnel.
	go m.retryJoin(runCtx)
	go m.reconnect(runCtx)
	go m.maintain(runCtx)

	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()

	retryAfter := func(err error) <-chan time.Time {
		if err != nil {
			slog.Warn("reconcile", "err", err)
			return time.After(retryFailInterval)
		}
		return nil
	}

	var retry <-chan time.Time
	var readyOnce sync.Once
	var lastReconcile time.Time
	reconcile := func() {
		lastReconcile = time.Now()
		err := m.reconcile()
		if err == nil {
			readyOnce.Do(func() { close(m.ready) }) // signal systemd READY only once the kernel is programmed
		}
		retry = retryAfter(err)
	}
	reconcile()
	// A pending debounce timer coalesces a burst of triggers into one run per reconcileDebounce window.
	var debounce <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-m.leave:
			leaving = true
			return nil
		case <-m.reconcileCh:
			if debounce == nil {
				if d := debounceDelay(lastReconcile, time.Now(), reconcileDebounce); d > 0 {
					debounce = time.After(d)
				} else {
					reconcile()
				}
			}
		case <-debounce:
			debounce = nil
			reconcile()
		case <-ticker.C:
			reconcile()
		case <-retry:
			reconcile()
		}
	}
}

// debounceDelay returns how long to wait before the next triggered reconcile so runs stay at least
// interval apart, or 0 to run now when interval has already elapsed since the last run.
func debounceDelay(lastRun, now time.Time, interval time.Duration) time.Duration {
	if elapsed := now.Sub(lastRun); elapsed < interval {
		return interval - elapsed
	}
	return 0
}

// Ready is closed after the first successful reconcile; sdnotify waits on it before signaling READY.
func (m *Mesh) Ready() <-chan struct{} { return m.ready }

func (m *Mesh) requestLeave(timeout time.Duration) error {
	m.shutdownMu.Lock()
	if m.shutdown {
		m.shutdownMu.Unlock()
		return errors.New("shutting down")
	}
	err := m.memberlist.Leave(timeout)
	m.shutdownMu.Unlock()
	if err != nil {
		return err
	}
	select {
	case m.leave <- struct{}{}:
	default:
	}
	return nil
}

func (m *Mesh) shutdownMemberlist() error {
	m.shutdownMu.Lock()
	defer m.shutdownMu.Unlock()
	m.shutdown = true
	return m.memberlist.Shutdown()
}
