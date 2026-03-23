package mesh

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/hashicorp/memberlist"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Config configures the mesh.
type Config struct {
	Interface   string   // WireGuard interface name (default: wg0)
	Seeds       []string // Seed node addresses for memberlist
	GossipKey   string   // Base64-encoded AES-256 key for memberlist encryption
	WgPSK       string   // Base64-encoded 32-byte WireGuard PresharedKey (optional)
	ListenPort  int      // WireGuard listen port (default: 51820)
	Hostname    string   // FQDN hostname for memberlist node name
	OverlayAddr string   // Explicit overlay address (e.g. fdaa:0:0:abcd:ef01::1/128). Derived from hostname if empty.
	Endpoint    string   // Public IP for WireGuard endpoint (auto-detected if empty)
	DataDir     string   // Directory for persistent state (default: generate ephemeral keys)
}

// Mesh manages the WireGuard mesh via memberlist gossip.
type Mesh struct {
	list     *memberlist.Memberlist
	local    Node
	localPub wgtypes.Key
	events   chan struct{}
	logger   *slog.Logger
	iface    string
	psk      *wgtypes.Key
}

// New creates and starts a new mesh. It generates a WireGuard keypair,
// creates the WireGuard interface, and joins the memberlist cluster.
func New(logger *slog.Logger, cfg Config) (*Mesh, error) {
	// Load or generate WireGuard keypair (persisted to data-dir if set).
	privKey, pubKey, err := LoadOrGenerateKey(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("load/generate keypair: %w", err)
	}

	// Use explicit overlay address if provided, otherwise derive from hostname.
	overlayAddr := cfg.OverlayAddr
	if overlayAddr == "" {
		overlayAddr, err = OverlayAddr(cfg.Hostname)
		if err != nil {
			return nil, fmt.Errorf("derive overlay addr: %w", err)
		}
	}

	// Detect public endpoint.
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint, err = DetectEndpoint()
		if err != nil {
			return nil, fmt.Errorf("detect endpoint: %w", err)
		}
	}

	local := Node{
		Name:        cfg.Hostname,
		PubKey:      pubKey.String(),
		Endpoint:    endpoint,
		OverlayAddr: overlayAddr,
		WgPort:      cfg.ListenPort,
	}

	logger.Info("local node",
		"hostname", local.Name,
		"overlay", local.OverlayAddr,
		"endpoint", local.Endpoint,
	)

	// Parse optional WireGuard PSK.
	var psk *wgtypes.Key
	if cfg.WgPSK != "" {
		raw, err := base64.StdEncoding.DecodeString(cfg.WgPSK)
		if err != nil {
			return nil, fmt.Errorf("decode wg psk: %w", err)
		}
		if len(raw) != wgtypes.KeyLen {
			return nil, fmt.Errorf("wg psk must be %d bytes, got %d", wgtypes.KeyLen, len(raw))
		}
		k, err := wgtypes.NewKey(raw)
		if err != nil {
			return nil, fmt.Errorf("parse wg psk: %w", err)
		}
		psk = &k
	}

	// Setup WireGuard interface.
	if err := SetupInterface(cfg.Interface, privKey, overlayAddr, cfg.ListenPort); err != nil {
		return nil, fmt.Errorf("setup wireguard: %w", err)
	}

	// Encode metadata for memberlist gossip.
	meta, err := encodeNodeMeta(local)
	if err != nil {
		return nil, fmt.Errorf("encode metadata: %w", err)
	}

	events := make(chan struct{}, 1)

	// Configure memberlist (WAN defaults for cross-DC mesh).
	mlCfg := memberlist.DefaultWANConfig()
	mlCfg.Name = cfg.Hostname
	mlCfg.BindPort = 7946
	mlCfg.AdvertisePort = 7946
	mlCfg.Delegate = &delegate{meta: meta}
	mlCfg.Events = &eventDelegate{ch: events}
	mlCfg.LogOutput = io.Discard

	if cfg.GossipKey != "" {
		key, err := base64.StdEncoding.DecodeString(cfg.GossipKey)
		if err != nil {
			return nil, fmt.Errorf("decode gossip key: %w", err)
		}
		keyring, err := memberlist.NewKeyring([][]byte{key}, key)
		if err != nil {
			return nil, fmt.Errorf("create keyring: %w", err)
		}
		mlCfg.Keyring = keyring
	}

	list, err := memberlist.Create(mlCfg)
	if err != nil {
		return nil, fmt.Errorf("create memberlist: %w", err)
	}

	// Join seed nodes.
	if len(cfg.Seeds) > 0 {
		n, err := list.Join(cfg.Seeds)
		if err != nil {
			logger.Warn("join seeds", "err", err, "joined", n)
		} else {
			logger.Info("joined cluster", "peers", n)
		}
	}

	return &Mesh{
		list:     list,
		local:    local,
		localPub: pubKey,
		events:   events,
		logger:   logger,
		iface:    cfg.Interface,
		psk:      psk,
	}, nil
}

// Run processes membership events and reconciles WireGuard peers.
// It blocks until ctx is cancelled.
func (m *Mesh) Run(ctx context.Context) {
	// Initial reconcile.
	if err := ReconcilePeers(m.iface, m.Peers(), m.localPub, m.psk); err != nil {
		m.logger.Error("initial peer reconcile", "err", err)
	}

	// Periodic reconcile as safety net (same interval as Consul's Serf reconcile).
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.events:
			peers := m.Peers()
			m.logger.Info("membership changed", "peers", len(peers))
			if err := ReconcilePeers(m.iface, peers, m.localPub, m.psk); err != nil {
				m.logger.Error("peer reconcile", "err", err)
			}
		case <-ticker.C:
			if err := ReconcilePeers(m.iface, m.Peers(), m.localPub, m.psk); err != nil {
				m.logger.Error("periodic reconcile", "err", err)
			}
		}
	}
}

// Peers returns the current remote mesh peers.
func (m *Mesh) Peers() []Node {
	members := m.list.Members()
	peers := make([]Node, 0, len(members)-1)
	for _, member := range members {
		if member.Name == m.local.Name {
			continue
		}
		node, err := decodeNodeMeta(member.Meta)
		if err != nil {
			m.logger.Warn("decode peer meta", "peer", member.Name, "err", err)
			continue
		}
		peers = append(peers, node)
	}
	return peers
}

// Leave gracefully leaves the memberlist cluster.
func (m *Mesh) Leave() error {
	return m.list.Leave(5 * time.Second)
}

// delegate implements memberlist.Delegate for metadata broadcasting.
type delegate struct {
	meta []byte
}

func (d *delegate) NodeMeta(limit int) []byte {
	if len(d.meta) > limit {
		return nil
	}
	return d.meta
}

func (d *delegate) NotifyMsg([]byte)                           {}
func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte { return nil }
func (d *delegate) LocalState(join bool) []byte                { return nil }
func (d *delegate) MergeRemoteState(buf []byte, join bool)     {}

// eventDelegate implements memberlist.EventDelegate for join/leave notifications.
type eventDelegate struct {
	ch chan struct{}
}

func (e *eventDelegate) NotifyJoin(*memberlist.Node)   { e.notify() }
func (e *eventDelegate) NotifyLeave(*memberlist.Node)  { e.notify() }
func (e *eventDelegate) NotifyUpdate(*memberlist.Node) { e.notify() }

func (e *eventDelegate) notify() {
	select {
	case e.ch <- struct{}{}:
	default:
	}
}
