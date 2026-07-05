//go:build linux

package mesh

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const DefaultSocketPath = "/run/pigeon-mesh.sock"

const wgHandshakeStale = 3*time.Minute + 30*time.Second

type PeerView struct {
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowed_ips"`
	Tags         Tags     `json:"tags,omitempty"`
	Status       string   `json:"status"`
	WGEndpoint   string   `json:"wg_endpoint,omitempty"`
	HandshakeAge *int64   `json:"handshake_age_s,omitempty"`
	RxBytes      int64    `json:"rx_bytes,omitempty"`
	TxBytes      int64    `json:"tx_bytes,omitempty"`
	WGAlive      *bool    `json:"wg_alive,omitempty"`
	GrantExpiry  *int64   `json:"grant_expiry_s,omitempty"`
}

type Status struct {
	Self               string              `json:"self"`
	UpdatedAt          string              `json:"updated_at"`
	Health             int                 `json:"health"`
	Peers              map[string]PeerView `json:"peers"`
	Conflicts          map[string][]string `json:"conflicts,omitempty"`
	Rejected           map[string]string   `json:"rejected,omitempty"`
	RefusedRoutes      map[string][]string `json:"refused_routes,omitempty"`
	UnauthorizedRoutes map[string][]string `json:"unauthorized_routes,omitempty"`
	StaleKernelPeers   []string            `json:"stale_kernel_peers,omitempty"`
}

// memberlist.Node.State is always Alive; derive status ourselves.
func memberStatus(accepted, failed bool) string {
	switch {
	case !accepted:
		return "rejected"
	case failed:
		return "failed"
	default:
		return "alive"
	}
}

func nowStamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func wgAlive(last, now time.Time) (*int64, *bool) {
	if last.IsZero() {
		return nil, nil
	}
	age := max(int64(now.Sub(last).Seconds()), 0)
	alive := !last.After(now) && now.Sub(last) <= wgHandshakeStale
	return &age, &alive
}

func (m *Mesh) serveStatus(ctx context.Context) {
	if m.cfg.SocketPath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(m.cfg.SocketPath), 0o755); err != nil {
		slog.Warn("status socket dir", "err", err)
		return
	}
	_ = os.Remove(m.cfg.SocketPath)
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", m.cfg.SocketPath)
	syscall.Umask(old)
	if err != nil {
		slog.Warn("status socket", "path", m.cfg.SocketPath, "err", err)
		return
	}
	if err := os.Chmod(m.cfg.SocketPath, 0o600); err != nil {
		slog.Warn("status socket chmod", "err", err)
	}
	defer os.Remove(m.cfg.SocketPath)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("status accept", "err", err)
			continue
		}
		go m.handleStatus(conn)
	}
}

// maxRequest bounds a socket line: only status and leave verbs, so a small DoS floor.
const maxRequest = 4 << 10

func (m *Mesh) handleStatus(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req, _ := bufio.NewReader(io.LimitReader(conn, maxRequest)).ReadString('\n')
	verb, _, _ := strings.Cut(strings.TrimSpace(req), " ")
	switch verb {
	case "status", "":
		data, err := json.Marshal(m.status())
		if err != nil {
			fmt.Fprintf(conn, "error: %v\n", err)
			return
		}
		conn.Write(append(data, '\n'))
	case "leave":
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		if err := m.requestLeave(5 * time.Second); err != nil {
			fmt.Fprintf(conn, "error: %v\n", err)
			return
		}
		conn.Write([]byte("ok\n"))
	default:
		fmt.Fprintf(conn, "error: unknown request %q\n", verb)
	}
}

func (m *Mesh) status() Status {
	kpeers := map[string]wgtypes.Peer{}
	if ps, err := m.cfg.WG.Peers(m.cfg.Iface); err != nil {
		slog.Debug("status wg peers", "err", err)
	} else {
		for _, kp := range ps {
			kpeers[kp.PublicKey.String()] = kp
		}
	}
	now := time.Now()
	fillWG := func(pv *PeerView, name string) {
		if kp, ok := kpeers[name]; ok {
			if kp.Endpoint != nil {
				pv.WGEndpoint = kp.Endpoint.String()
			}
			pv.RxBytes = kp.ReceiveBytes
			pv.TxBytes = kp.TransmitBytes
			pv.HandshakeAge, pv.WGAlive = wgAlive(kp.LastHandshakeTime, now)
		}
	}

	// our own member map: memberlist.Members() is always alive, drops failed-but-not-reaped peers
	members, contested := m.snapshot()
	peers := make(map[string]PeerView, len(members)+1)
	rejected := map[string]string{}
	refused := map[string][]string{}
	unauthorized := map[string][]string{}
	for name, e := range members {
		pv := PeerView{
			Endpoint:   e.peer.Endpoint,
			AllowedIPs: e.peer.AllowedIPs,
			Tags:       e.tags,
			Status:     memberStatus(e.admitted(), e.failed),
		}
		if !e.admitted() {
			rejected[name] = e.admitErr.Error()
		}
		if len(e.refusedRoutes) > 0 {
			refused[name] = e.refusedRoutes
		}
		if len(e.unauthorizedRoutes) > 0 {
			unauthorized[name] = e.unauthorizedRoutes
		}
		if e.grantExpiry > 0 {
			ge := e.grantExpiry
			pv.GrantExpiry = &ge
		}
		fillWG(&pv, name)
		peers[name] = pv
	}
	// self is never in the member table
	selfPV := PeerView{
		Endpoint:   m.cfg.Self.Endpoint,
		AllowedIPs: m.cfg.Self.AllowedIPs,
		Tags:       m.selfTags(),
		Status:     "alive",
	}
	if err := selfSignatureError(*m.selfGrant.Load(), now); err != nil {
		selfPV.Status = "rejected"
		rejected[m.cfg.Self.PublicKey] = err.Error()
	}
	if _, ok := (*m.revoked.Load())[m.cfg.Self.PublicKey]; ok {
		selfPV.Status = "rejected"
		rejected[m.cfg.Self.PublicKey] = errRevoked.Error()
	}
	if ge := m.selfGrantExpiry(); ge > 0 {
		selfPV.GrantExpiry = &ge
	}
	peers[m.cfg.Self.PublicKey] = selfPV
	return Status{
		Self:               m.cfg.Self.PublicKey,
		UpdatedAt:          nowStamp(),
		Health:             m.memberlist.GetHealthScore(),
		Peers:              peers,
		Conflicts:          contested,
		Rejected:           rejected,
		RefusedRoutes:      refused,
		UnauthorizedRoutes: unauthorized,
		StaleKernelPeers:   m.staleKernelPeers(),
	}
}
