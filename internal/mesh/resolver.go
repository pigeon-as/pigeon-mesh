//go:build linux

package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/hashicorp/memberlist"
	"github.com/miekg/dns"
)

const (
	resolvedDest         = "org.freedesktop.resolve1"
	resolvedPath         = dbus.ObjectPath("/org/freedesktop/resolve1")
	resolvedManagerIface = "org.freedesktop.resolve1.Manager"

	dbusBroker       = "org.freedesktop.DBus"
	dbusBrokerPath   = dbus.ObjectPath("/org/freedesktop/DBus")
	nameOwnerChanged = "NameOwnerChanged"
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
	addr := net.JoinHostPort(m.cfg.BindAddr, "53")
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		slog.Error("dns bind", "addr", addr, "err", err)
		return
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		slog.Error("dns bind", "addr", addr, "err", err)
		return
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(buildReply(r, zone, m.dnsTable()))
	})
	udp := &dns.Server{PacketConn: pc, Handler: h}
	tcp := &dns.Server{Listener: l, Handler: h}
	go func() {
		if err := udp.ActivateAndServe(); err != nil && ctx.Err() == nil {
			slog.Warn("dns udp", "err", err)
		}
	}()
	go func() {
		if err := tcp.ActivateAndServe(); err != nil && ctx.Err() == nil {
			slog.Warn("dns tcp", "err", err)
		}
	}()

	if err := m.programResolved(zone); err != nil {
		slog.Warn("resolved split-DNS not programmed; query the overlay address directly", "err", err)
	}
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		m.watchResolved(ctx, zone)
	}()
	slog.Info("overlay dns up", "addr", addr, "zone", zone)

	<-ctx.Done()
	<-watchDone
	m.revertResolved()
	_ = udp.Shutdown()
	_ = tcp.Shutdown()
}

func (m *Mesh) watchResolved(ctx context.Context, zone string) {
	match := []dbus.MatchOption{
		dbus.WithMatchObjectPath(dbusBrokerPath),
		dbus.WithMatchInterface(dbusBroker),
		dbus.WithMatchMember(nameOwnerChanged),
		dbus.WithMatchArg(0, resolvedDest),
	}
	backoff := time.Second
	for {
		if err := m.watchResolvedOnce(ctx, zone, match); err != nil && ctx.Err() == nil {
			slog.Warn("resolved watch reconnect", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, reconnectInterval)
	}
}

func (m *Mesh) watchResolvedOnce(ctx context.Context, zone string, match []dbus.MatchOption) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return err
	}
	if err := conn.AddMatchSignal(match...); err != nil {
		slog.Warn("resolved watch filter", "err", err)
	}
	sig := make(chan *dbus.Signal, 16)
	conn.Signal(sig)
	defer func() {
		conn.RemoveSignal(sig)
		_ = conn.RemoveMatchSignal(match...)
	}()

	var owned bool
	if call := conn.BusObject().Call(dbusBroker+".NameHasOwner", 0, resolvedDest); call.Err == nil {
		_ = call.Store(&owned)
	}
	if owned {
		m.reprogramResolved(ctx, zone)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case s, ok := <-sig:
			if !ok {
				return fmt.Errorf("system bus signal channel closed")
			}
			if s.Path != dbusBrokerPath || s.Name != dbusBroker+"."+nameOwnerChanged || len(s.Body) != 3 {
				continue
			}
			name, _ := s.Body[0].(string)
			newOwner, _ := s.Body[2].(string)
			if name != resolvedDest || newOwner == "" {
				continue
			}
			slog.Info("systemd-resolved (re)started; reprogramming split-DNS")
			m.reprogramResolved(ctx, zone)
		}
	}
}

func (m *Mesh) reprogramResolved(ctx context.Context, zone string) {
	backoff := 200 * time.Millisecond
	for attempt := 0; ; attempt++ {
		if err := m.programResolved(zone); err == nil {
			return
		} else if attempt >= 2 {
			slog.Warn("resolved resync", "err", err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

func (m *Mesh) dnsTable() map[string]netip.Addr {
	nodes := m.memberlist.Members()
	m.mu.RLock()
	defer m.mu.RUnlock()
	table := make(map[string]netip.Addr, len(nodes))
	collided := make(map[string]bool)
	add := func(addr netip.Addr, tags Tags) {
		label := SanitizeLabel(tags["name"])
		if label == "" || collided[label] || !addr.IsValid() {
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
	if self, err := netip.ParseAddr(m.cfg.BindAddr); err == nil {
		add(self, m.cfg.Self.Tags)
	}
	for _, n := range nodes {
		if n.Name == m.cfg.Self.PublicKey || n.State != memberlist.StateAlive {
			continue
		}
		e, ok := m.members[n.Name]
		if !ok || e.failed || e.reject != "" {
			continue
		}
		add(e.addr, e.peer.Tags)
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
	conn, err := dbus.SystemBus()
	if err != nil {
		slog.Debug("revert resolved", "err", err)
		return
	}
	ifi, err := net.InterfaceByName(m.cfg.Iface)
	if err != nil {
		slog.Debug("revert resolved", "err", err)
		return
	}
	mgr := conn.Object(resolvedDest, resolvedPath)
	if err := mgr.Call(resolvedManagerIface+".RevertLink", 0, int32(ifi.Index)).Store(); err != nil {
		slog.Debug("revert resolved", "err", err)
	}
}
