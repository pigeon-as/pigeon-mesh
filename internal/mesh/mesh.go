//go:build linux

package mesh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/pigeon-as/wg-mesh/internal/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	retryJoinInterval = 30 * time.Second
	reconcileInterval = 60 * time.Second
)

type Config struct {
	Iface      string
	GossipPort int
	BindAddr   string
	Profile    string
	PeersFile  string
	Self       Peer
	Keyring    *memberlist.Keyring
	WG         *wg.Client
	PeerPolicy *PeerPolicy
}

type member struct {
	meta []byte
	peer Peer
}

type Mesh struct {
	cfg         Config
	meta        []byte
	memberlist  *memberlist.Memberlist
	mu          sync.RWMutex
	members     map[string]member
	peers       map[string]member
	reconcileCh chan struct{}
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
		peers:       make(map[string]member),
		reconcileCh: make(chan struct{}, 1),
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
	mc.Alive = d
	mc.Events = d
	mc.Conflict = d
	mc.Keyring = cfg.Keyring
	mc.Logger = newMemberlistLogger()

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
	return m.memberlist.Join(targets)
}

func diff(prev, cur map[string]member) []wgtypes.PeerConfig {
	var changes []wgtypes.PeerConfig
	for name, e := range cur {
		if prevEntry, ok := prev[name]; ok && bytes.Equal(prevEntry.meta, e.meta) {
			continue
		}
		pc, err := e.peer.toWG()
		if err != nil {
			slog.Warn("peer to wg", "node", name, "err", err)
			continue
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
	return changes
}

func (m *Mesh) setMember(n *memberlist.Node) {
	if n.Name == m.cfg.Self.PublicKey {
		return
	}
	if len(n.Meta) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.members[n.Name]; ok && bytes.Equal(existing.meta, n.Meta) {
		return
	}
	p, err := decodePeer(n.Name, n.Meta)
	if err != nil {
		slog.Warn("decode peer", "node", n.Name, "err", err)
		return
	}
	m.members[n.Name] = member{meta: bytes.Clone(n.Meta), peer: p}
	m.triggerReconcile()
}

func (m *Mesh) removeMember(n *memberlist.Node) {
	if n.Name == m.cfg.Self.PublicKey {
		return
	}
	m.mu.Lock()
	delete(m.members, n.Name)
	m.mu.Unlock()
	m.triggerReconcile()
}

func (m *Mesh) handleNodeConflict(existing, other *memberlist.Node) {
	if existing.Name == m.cfg.Self.PublicKey {
		slog.Error("name conflict: another node claims our pubkey",
			"name", existing.Name,
			"other_addr", other.Addr.String(), "other_port", other.Port)
		return
	}
	slog.Warn("name conflict",
		"name", existing.Name,
		"existing_addr", existing.Addr.String(), "existing_port", existing.Port,
		"other_addr", other.Addr.String(), "other_port", other.Port)
}

func (m *Mesh) triggerReconcile() {
	select {
	case m.reconcileCh <- struct{}{}:
	default:
	}
}

func (m *Mesh) peerSnapshot(exclude string) []Peer {
	m.mu.RLock()
	snap := maps.Clone(m.members)
	m.mu.RUnlock()
	peers := make([]Peer, 0, len(snap))
	for name, e := range snap {
		if name == exclude {
			continue
		}
		peers = append(peers, e.peer)
	}
	return peers
}

func (m *Mesh) reconcile() error {
	m.mu.RLock()
	cur := maps.Clone(m.members)
	m.mu.RUnlock()
	changes := diff(m.peers, cur)
	if len(changes) > 0 {
		if err := m.cfg.WG.Apply(m.cfg.Iface, changes); err != nil {
			return err
		}
		m.peers = cur
	}
	return m.writePeersIfConfigured()
}

func (m *Mesh) writePeersIfConfigured() error {
	if m.cfg.PeersFile == "" {
		return nil
	}
	return writePeers(m.cfg.PeersFile, m.snapshot())
}

func (m *Mesh) snapshot() PeersFile {
	nodes := m.memberlist.Members()
	m.mu.RLock()
	snap := maps.Clone(m.members)
	m.mu.RUnlock()
	peers := make(map[string]PeerView, len(nodes))
	for _, n := range nodes {
		var p Peer
		if n.Name == m.cfg.Self.PublicKey {
			p = m.cfg.Self
		} else if e, ok := snap[n.Name]; ok {
			p = e.peer
		}
		peers[n.Name] = PeerView{
			Endpoint:   p.Endpoint,
			AllowedIPs: p.AllowedIPs,
			Tags:       p.Tags,
			Status:     peerStatus(n),
		}
	}
	return PeersFile{
		Self:      m.cfg.Self.PublicKey,
		UpdatedAt: nowStamp(),
		Peers:     peers,
	}
}

func (m *Mesh) Run(ctx context.Context) error {
	defer func() {
		if err := m.memberlist.Shutdown(); err != nil {
			slog.Warn("memberlist shutdown", "err", err)
		}
	}()

	n, err := m.join()
	if err != nil {
		slog.Warn("initial join", "err", err)
	}
	if n > 0 {
		slog.Info("joined", "reached", n)
	}
	go m.retryJoin(ctx)

	if err := m.reconcile(); err != nil {
		slog.Warn("reconcile", "err", err)
	}

	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-m.reconcileCh:
			if err := m.reconcile(); err != nil {
				slog.Warn("reconcile", "err", err)
			}
		case <-ticker.C:
			if err := m.reconcile(); err != nil {
				slog.Warn("reconcile", "err", err)
			}
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
			backoff = min(2*backoff, retryJoinInterval)
		case n > 0:
			slog.Info("joined", "reached", n)
			backoff = retryJoinInterval
		default:
			slog.Info("no bootstrap peers")
			backoff = min(2*backoff, retryJoinInterval)
		}
	}
}
