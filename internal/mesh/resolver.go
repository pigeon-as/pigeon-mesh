//go:build linux

package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"syscall"

	"github.com/godbus/dbus/v5"
	"github.com/hashicorp/memberlist"
	"github.com/miekg/dns"
)

const (
	resolvedDest         = "org.freedesktop.resolve1"
	resolvedPath         = dbus.ObjectPath("/org/freedesktop/resolve1")
	resolvedManagerIface = "org.freedesktop.resolve1.Manager"
)

type resolvedLinkDNS struct {
	Family  int32
	Address []byte
}

type resolvedLinkDomain struct {
	Domain      string
	RoutingOnly bool
}

func (m *Mesh) serveResolver(ctx context.Context) {
	zone := normalizeZone(m.cfg.DNSZone)
	if zone == "" {
		return
	}
	if !m.cfg.Prefix.IsValid() {
		slog.Warn("--dns ignored: requires --prefix")
		return
	}
	addr := net.JoinHostPort(m.cfg.BindAddr, "53")
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(buildReply(r, zone, m.dnsTable()))
	})
	udp := &dns.Server{Addr: addr, Net: "udp", Handler: h}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: h}
	go func() {
		if err := udp.ListenAndServe(); err != nil && ctx.Err() == nil {
			slog.Warn("dns udp", "err", err)
		}
	}()
	go func() {
		if err := tcp.ListenAndServe(); err != nil && ctx.Err() == nil {
			slog.Warn("dns tcp", "err", err)
		}
	}()

	if err := m.programResolved(zone); err != nil {
		slog.Warn("resolved split-DNS not programmed; query the overlay address directly", "err", err)
	} else {
		defer m.revertResolved()
	}
	slog.Info("overlay dns up", "addr", addr, "zone", zone)

	<-ctx.Done()
	_ = udp.Shutdown()
	_ = tcp.Shutdown()
}

func (m *Mesh) dnsTable() map[string]netip.Addr {
	nodes := m.memberlist.Members()
	m.mu.RLock()
	defer m.mu.RUnlock()
	table := make(map[string]netip.Addr, len(nodes))
	collided := make(map[string]bool)
	add := func(pubkey string, tags Tags) {
		label := SanitizeLabel(tags["name"])
		if label == "" || collided[label] {
			return
		}
		addr, err := DeriveAddr(pubkey, m.cfg.Prefix)
		if err != nil {
			return
		}
		if existing, dup := table[label]; dup && existing != addr {
			delete(table, label)
			collided[label] = true
			slog.Warn("dns name claimed by more than one peer; not resolving it", "name", label)
			return
		}
		table[label] = addr
	}
	add(m.cfg.Self.PublicKey, m.cfg.Self.Tags)
	for _, n := range nodes {
		if n.Name == m.cfg.Self.PublicKey || n.State != memberlist.StateAlive {
			continue
		}
		e, ok := m.members[n.Name]
		if !ok || e.failed || e.reject != "" {
			continue
		}
		add(n.Name, e.peer.Tags)
	}
	return table
}

func (m *Mesh) programResolved(zone string) error {
	ifi, err := net.InterfaceByName(m.cfg.Iface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", m.cfg.Iface, err)
	}
	addr, err := netip.ParseAddr(m.cfg.BindAddr)
	if err != nil {
		return fmt.Errorf("bind addr %q: %w", m.cfg.BindAddr, err)
	}
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("system bus: %w", err)
	}
	mgr := conn.Object(resolvedDest, resolvedPath)
	idx := int32(ifi.Index)

	ip := addr.As16()
	servers := []resolvedLinkDNS{{Family: syscall.AF_INET6, Address: ip[:]}}
	if err := mgr.Call(resolvedManagerIface+".SetLinkDNS", 0, idx, servers).Store(); err != nil {
		return fmt.Errorf("SetLinkDNS: %w", err)
	}
	domains := []resolvedLinkDomain{{Domain: zone + ".", RoutingOnly: true}}
	if err := mgr.Call(resolvedManagerIface+".SetLinkDomains", 0, idx, domains).Store(); err != nil {
		return fmt.Errorf("SetLinkDomains: %w", err)
	}
	if err := mgr.Call(resolvedManagerIface+".SetLinkDefaultRoute", 0, idx, false).Store(); err != nil {
		return fmt.Errorf("SetLinkDefaultRoute: %w", err)
	}
	return nil
}

func (m *Mesh) revertResolved() {
	ifi, err := net.InterfaceByName(m.cfg.Iface)
	if err != nil {
		slog.Warn("revert resolved", "err", err)
		return
	}
	conn, err := dbus.SystemBus()
	if err != nil {
		slog.Warn("revert resolved", "err", err)
		return
	}
	mgr := conn.Object(resolvedDest, resolvedPath)
	if err := mgr.Call(resolvedManagerIface+".RevertLink", 0, int32(ifi.Index)).Store(); err != nil {
		slog.Warn("revert resolved", "err", err)
	}
}
