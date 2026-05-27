//go:build linux

package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"reflect"
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
	reconcileInterval = 30 * time.Second
	eventBuffer       = 2048
)

type Config struct {
	Iface      string
	GossipPort int
	BindAddr   string
	Profile    string
	Self       Peer
	Keyring    *memberlist.Keyring
	WG         *wg.Client
	PeerPolicy *PeerPolicy
}

type Mesh struct {
	cfg        Config
	meta       []byte
	memberlist *memberlist.Memberlist
	events     <-chan memberlist.NodeEvent
	peers      map[string]wgtypes.PeerConfig
	shutdownCh chan struct{}
	closeOnce  sync.Once
}

func (m *Mesh) shutdown() {
	m.closeOnce.Do(func() { close(m.shutdownCh) })
}

func (m *Mesh) handleNodeConflict(existing, other *memberlist.Node) {
	if existing.Name != m.cfg.Self.PublicKey {
		slog.Warn("node name conflict",
			"name", existing.Name,
			"existing", existing.Address(),
			"other", other.Address())
		return
	}
	slog.Error("self pubkey conflict", "other", other.Address())
	m.shutdown()
}

func New(cfg Config) (*Mesh, error) {
	if cfg.WG == nil {
		return nil, fmt.Errorf("no wgctrl client configured")
	}
	if cfg.BindAddr == "" {
		return nil, fmt.Errorf("no bind addr configured")
	}
	meta, err := encodeMeta(cfg.Self)
	if err != nil {
		return nil, err
	}
	if len(meta) > memberlist.MetaMaxSize {
		return nil, fmt.Errorf("encoded self meta %d bytes exceeds limit %d", len(meta), memberlist.MetaMaxSize)
	}

	events := make(chan memberlist.NodeEvent, eventBuffer)

	m := &Mesh{
		cfg:        cfg,
		meta:       meta,
		events:     events,
		peers:      make(map[string]wgtypes.PeerConfig),
		shutdownCh: make(chan struct{}),
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
	mc.BindAddr = cfg.BindAddr
	mc.BindPort = cfg.GossipPort
	mc.Delegate = d
	mc.Conflict = d
	mc.Alive = d
	mc.Events = &memberlist.ChannelEventDelegate{Ch: events}
	mc.Keyring = cfg.Keyring
	mc.Logger = newMemberlistLogger()

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
		for _, ipnet := range p.AllowedIPs {
			ones, bits := ipnet.Mask.Size()
			if ones == bits {
				targets = append(targets, net.JoinHostPort(ipnet.IP.String(), strconv.Itoa(m.cfg.GossipPort)))
				break
			}
		}
	}
	if len(targets) == 0 {
		return 0, nil
	}
	return m.memberlist.Join(targets)
}

func (m *Mesh) handleJoin(node *memberlist.Node) {
	pc, err := peerConfigFromNode(node)
	if err != nil {
		slog.Warn("decode meta", "node", node.Name, "err", err)
		return
	}
	if cached, ok := m.peers[node.Name]; ok && reflect.DeepEqual(cached, pc) {
		return
	}
	if err := m.cfg.WG.Apply(m.cfg.Iface, []wgtypes.PeerConfig{pc}); err != nil {
		slog.Warn("apply peer", "node", node.Name, "err", err)
		return
	}
	m.peers[node.Name] = pc
}

func (m *Mesh) handleLeave(node *memberlist.Node) {
	pk, err := wgtypes.ParseKey(node.Name)
	if err != nil {
		slog.Warn("parse pubkey", "node", node.Name, "err", err)
		return
	}
	if err := m.cfg.WG.Apply(m.cfg.Iface, []wgtypes.PeerConfig{{PublicKey: pk, Remove: true}}); err != nil {
		slog.Warn("apply leave", "node", node.Name, "err", err)
		return
	}
	delete(m.peers, node.Name)
}

func diff(applied, desired map[string]wgtypes.PeerConfig) []wgtypes.PeerConfig {
	var changes []wgtypes.PeerConfig
	for name, pc := range desired {
		if cached, ok := applied[name]; ok && reflect.DeepEqual(cached, pc) {
			continue
		}
		changes = append(changes, pc)
	}
	for name, prev := range applied {
		if _, ok := desired[name]; !ok {
			changes = append(changes, wgtypes.PeerConfig{PublicKey: prev.PublicKey, Remove: true})
		}
	}
	return changes
}

func (m *Mesh) reconcile() error {
	desired := make(map[string]wgtypes.PeerConfig)
	for _, n := range m.memberlist.Members() {
		if n.Name == m.cfg.Self.PublicKey {
			continue
		}
		pc, err := peerConfigFromNode(n)
		if err != nil {
			slog.Warn("decode meta", "node", n.Name, "err", err)
			continue
		}
		desired[n.Name] = pc
	}
	changes := diff(m.peers, desired)
	if len(changes) == 0 {
		return nil
	}
	if err := m.cfg.WG.Apply(m.cfg.Iface, changes); err != nil {
		return err
	}
	m.peers = desired
	return nil
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
	} else {
		slog.Info("starting retry join")
		go m.retryJoin(ctx)
	}

	reconcileTicker := time.NewTicker(reconcileInterval)
	defer reconcileTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-m.shutdownCh:
			return fmt.Errorf("self pubkey conflict")
		case <-reconcileTicker.C:
			if err := m.reconcile(); err != nil {
				slog.Warn("reconcile", "err", err)
			}
		case ev := <-m.events:
			if ev.Node.Name == m.cfg.Self.PublicKey {
				continue
			}
			switch ev.Event {
			case memberlist.NodeLeave:
				m.handleLeave(ev.Node)
			case memberlist.NodeJoin, memberlist.NodeUpdate:
				m.handleJoin(ev.Node)
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
		return fmt.Errorf("no keyring configured")
	}
	targetKeys := target.GetKeys()
	if len(targetKeys) == 0 {
		return fmt.Errorf("target keyring is empty")
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
		case <-m.shutdownCh:
			return
		case <-time.After(wait):
		}
		n, err := m.join()
		switch {
		case err != nil:
			slog.Warn("retry join", "err", err)
		case n > 0:
			slog.Info("joined", "reached", n)
			return
		default:
			slog.Info("no bootstrap peers")
		}
		backoff = min(2*backoff, retryJoinInterval)
	}
}
