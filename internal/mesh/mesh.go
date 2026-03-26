//go:build linux

package mesh

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"time"

	"github.com/hashicorp/memberlist"
	addr "github.com/pigeon-as/pigeon-addr-plan"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	memberlistPort    = 7946
	reconcileInterval = 30 * time.Second
	leaveTimeout      = 5 * time.Second
)

type Config struct {
	Interface         string
	Seeds             []string
	GossipKey         string
	WgPSK             string
	ListenPort        int
	Hostname          string
	EndpointAddress   string
	EndpointInterface string
	DataDir           string
	TLSCACert         string
	TLSCAKey          string
}

type Mesh struct {
	list      *memberlist.Memberlist
	local     Node
	localPub  wgtypes.Key
	events    chan struct{}
	logger    *slog.Logger
	iface     string
	psk       *wgtypes.Key
	transport *TLSTransport
}

// New creates and starts a new mesh.
func New(logger *slog.Logger, cfg Config) (*Mesh, error) {
	privKey, pubKey, err := LoadOrGenerateKey(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("load/generate keypair: %w", err)
	}

	overlayIP, err := addr.PigeonHostIP(cfg.Hostname)
	if err != nil {
		return nil, fmt.Errorf("derive overlay addr: %w", err)
	}
	overlayAddr := netip.PrefixFrom(overlayIP, 128).String()

	endpoint := cfg.EndpointAddress
	if endpoint == "" && cfg.EndpointInterface != "" {
		endpoint, err = resolveInterfaceIP(cfg.EndpointInterface)
		if err != nil {
			return nil, fmt.Errorf("resolve endpoint from interface %s: %w", cfg.EndpointInterface, err)
		}
	}
	if endpoint == "" {
		endpoint, err = resolveDefaultRouteIP()
		if err != nil {
			return nil, fmt.Errorf("resolve endpoint via default route: %w", err)
		}
		logger.Info("endpoint resolved via default route", "ip", endpoint)
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

	if err := SetupInterface(cfg.Interface, privKey, overlayAddr, cfg.ListenPort); err != nil {
		return nil, fmt.Errorf("setup wireguard: %w", err)
	}

	meta, err := encodeNodeMeta(local)
	if err != nil {
		return nil, fmt.Errorf("encode metadata: %w", err)
	}

	events := make(chan struct{}, 1)

	mlCfg := memberlist.DefaultWANConfig()
	mlCfg.Name = cfg.Hostname
	mlCfg.BindPort = memberlistPort
	mlCfg.AdvertisePort = memberlistPort
	mlCfg.Delegate = &delegate{meta: meta}
	mlCfg.Events = &eventDelegate{ch: events}
	mlCfg.LogOutput = io.Discard

	var transport *TLSTransport

	if cfg.TLSCACert != "" {
		caCert, caKey, err := loadCA(cfg.TLSCACert, cfg.TLSCAKey)
		if err != nil {
			return nil, fmt.Errorf("load mesh CA: %w", err)
		}
		peerCert, err := generatePeerCert(caCert, caKey, cfg.Hostname, endpoint)
		if err != nil {
			return nil, fmt.Errorf("generate peer cert: %w", err)
		}
		serverTLS, clientTLS := newTLSConfigs(caCert, peerCert)

		transport, err = NewTLSTransport(logger, "0.0.0.0", memberlistPort, serverTLS, clientTLS)
		if err != nil {
			return nil, fmt.Errorf("create tls transport: %w", err)
		}
		mlCfg.Transport = transport
		logger.Info("tls transport enabled")
	}

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

	if len(cfg.Seeds) > 0 {
		n, err := list.Join(cfg.Seeds)
		if err != nil {
			logger.Warn("join seeds", "err", err, "joined", n)
		} else {
			logger.Info("joined cluster", "peers", n)
		}
	}

	return &Mesh{
		list:      list,
		local:     local,
		localPub:  pubKey,
		events:    events,
		logger:    logger,
		iface:     cfg.Interface,
		psk:       psk,
		transport: transport,
	}, nil
}

// Run processes membership events and reconciles WireGuard peers.
func (m *Mesh) Run(ctx context.Context) {
	if err := ReconcilePeers(m.iface, m.Peers(), m.localPub, m.psk); err != nil {
		m.logger.Error("initial peer reconcile", "err", err)
	}

	ticker := time.NewTicker(reconcileInterval)
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

func (m *Mesh) Peers() []Node {
	members := m.list.Members()
	peers := make([]Node, 0, max(len(members)-1, 0))
	for _, member := range members {
		if member.Name == m.local.Name {
			continue
		}
		node, err := decodeNodeMeta(member.Meta)
		if err != nil {
			m.logger.Warn("decode peer meta", "peer", member.Name, "err", err)
			continue
		}
		node.Name = member.Name
		peers = append(peers, node)
	}
	return peers
}

func (m *Mesh) Leave() error {
	return m.list.Leave(leaveTimeout)
}

func (m *Mesh) Shutdown() error {
	if m.transport != nil {
		return m.transport.Shutdown()
	}
	return nil
}

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
