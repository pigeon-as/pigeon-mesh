//go:build linux

package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/pigeon-as/wg-mesh/internal/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	leaveTimeout      = 5 * time.Second
	retryJoinInterval = 30 * time.Second
	eventBuffer       = 256
)

type Config struct {
	Iface      string
	GossipPort int
	Self       Peer
	Keyring    *memberlist.Keyring
	WG         *wg.Client
}

type Mesh struct {
	cfg        Config
	memberlist *memberlist.Memberlist
	events     <-chan memberlist.NodeEvent
}

func New(cfg Config) (*Mesh, error) {
	if cfg.WG == nil {
		return nil, fmt.Errorf("no wgctrl client configured")
	}
	meta, err := encodeMeta(cfg.Self)
	if err != nil {
		return nil, err
	}
	if len(meta) > memberlist.MetaMaxSize {
		return nil, fmt.Errorf("encoded self meta %d bytes exceeds limit %d", len(meta), memberlist.MetaMaxSize)
	}
	bindIP, err := firstHostRoute(cfg.Self.AllowedIPs)
	if err != nil {
		return nil, fmt.Errorf("self: %w", err)
	}

	events := make(chan memberlist.NodeEvent, eventBuffer)

	d := &delegate{meta: meta}
	mc := memberlist.DefaultWANConfig()
	mc.Name = cfg.Self.PublicKey
	mc.BindAddr = bindIP.String()
	mc.BindPort = cfg.GossipPort
	mc.Delegate = d
	mc.Conflict = d
	mc.Events = &memberlist.ChannelEventDelegate{Ch: events}
	mc.Keyring = cfg.Keyring
	mc.Logger = newMemberlistLogger()

	ml, err := memberlist.Create(mc)
	if err != nil {
		return nil, fmt.Errorf("memberlist: %w", err)
	}
	return &Mesh{cfg: cfg, memberlist: ml, events: events}, nil
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
	if len(node.Meta) == 0 {
		slog.Warn("empty meta", "node", node.Name)
		return
	}
	var p Peer
	if err := decodeMeta(node.Meta, &p); err != nil {
		slog.Warn("decode meta", "node", node.Name, "err", err)
		return
	}
	if p.PublicKey != node.Name {
		slog.Warn("meta pubkey mismatch", "node", node.Name, "meta", p.PublicKey)
		return
	}
	pc, err := p.peerConfig()
	if err != nil {
		slog.Warn("peer config", "node", node.Name, "err", err)
		return
	}
	if err := m.cfg.WG.Apply(m.cfg.Iface, []wgtypes.PeerConfig{pc}); err != nil {
		slog.Warn("apply", "node", node.Name, "err", err)
	}
}

func (m *Mesh) handleLeave(node *memberlist.Node) {
	pk, err := wgtypes.ParseKey(node.Name)
	if err != nil {
		slog.Warn("leave", "node", node.Name, "err", err)
		return
	}
	if err := m.cfg.WG.Apply(m.cfg.Iface, []wgtypes.PeerConfig{{PublicKey: pk, Remove: true}}); err != nil {
		slog.Warn("leave apply", "node", node.Name, "err", err)
	}
}

func (m *Mesh) Run(ctx context.Context) {
	defer func() {
		if err := m.memberlist.Leave(leaveTimeout); err != nil {
			slog.Warn("leave broadcast", "err", err)
		}
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
		go m.retryJoin(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			return
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
		case <-time.After(wait):
		}
		n, err := m.join()
		if err != nil {
			slog.Warn("retry join", "err", err)
		} else if n > 0 {
			slog.Info("rejoined", "reached", n)
			return
		}
		backoff = min(2*backoff, retryJoinInterval)
	}
}
