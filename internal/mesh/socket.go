//go:build linux

package mesh

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (m *Mesh) serveStatus(ctx context.Context) {
	if m.cfg.SocketPath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(m.cfg.SocketPath), 0o755); err != nil {
		slog.Warn("status socket dir", "err", err)
		return
	}
	_ = os.Remove(m.cfg.SocketPath)
	ln, err := net.Listen("unix", m.cfg.SocketPath)
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

func (m *Mesh) handleStatus(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req, _ := bufio.NewReader(conn).ReadString('\n')
	switch strings.TrimSpace(req) {
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
		fmt.Fprintf(conn, "error: unknown request %q\n", strings.TrimSpace(req))
	}
}

func (m *Mesh) status() Status {
	nodes := m.memberlist.Members()
	peers := make(map[string]PeerView, len(nodes))
	m.mu.RLock()
	for _, n := range nodes {
		var p Peer
		if n.Name == m.cfg.Self.PublicKey {
			p = m.cfg.Self
		} else if e, ok := m.members[n.Name]; ok {
			p = e.peer
		}
		peers[n.Name] = PeerView{
			Endpoint:   p.Endpoint,
			AllowedIPs: p.AllowedIPs,
			Tags:       p.Tags,
			Status:     peerStatus(n),
		}
	}
	conflicts := maps.Clone(m.conflicts)
	rejected := maps.Clone(m.rejected)
	m.mu.RUnlock()
	return Status{
		Self:      m.cfg.Self.PublicKey,
		UpdatedAt: nowStamp(),
		Peers:     peers,
		Conflicts: conflicts,
		Rejected:  rejected,
	}
}
