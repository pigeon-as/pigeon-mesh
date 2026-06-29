//go:build linux

package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/miekg/dns"
)

const (
	resolvedDest         = "org.freedesktop.resolve1"
	resolvedPath         = dbus.ObjectPath("/org/freedesktop/resolve1")
	resolvedManagerIface = "org.freedesktop.resolve1.Manager"

	dbusBroker       = "org.freedesktop.DBus"
	dbusBrokerPath   = dbus.ObjectPath("/org/freedesktop/DBus")
	nameOwnerChanged = "NameOwnerChanged"

	resolvedCallTimeout = 2 * time.Second
	watchBackoffMax     = 30 * time.Second
)

type resolvedLinkDNS struct {
	Family  int32
	Address []byte
}

type resolvedLinkDomain struct {
	Domain      string
	RoutingOnly bool
}

// Empty Zone disables DNS.
type Config struct {
	Iface string
	Addr  netip.Addr
	Zone  string
}

func Serve(ctx context.Context, cfg Config, records func() map[string]netip.Addr) {
	zone := normalizeZone(cfg.Zone)
	if zone == "" {
		return
	}
	bind := net.JoinHostPort(cfg.Addr.String(), "53")
	pc, err := net.ListenPacket("udp", bind)
	if err != nil {
		slog.Error("dns bind", "addr", bind, "err", err)
		return
	}
	l, err := net.Listen("tcp", bind)
	if err != nil {
		_ = pc.Close()
		slog.Error("dns bind", "addr", bind, "err", err)
		return
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(reply(r, zone, records()))
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

	if err := program(cfg.Iface, cfg.Addr, zone); err != nil {
		slog.Warn("resolved split-DNS not programmed; query the overlay address directly", "err", err)
	}
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		watch(ctx, cfg.Iface, cfg.Addr, zone)
	}()
	slog.Info("overlay dns up", "addr", bind, "zone", zone)

	<-ctx.Done()
	<-watchDone
	revert(cfg.Iface)
	_ = udp.Shutdown()
	_ = tcp.Shutdown()
}

// resolved restart wipes our link config; reprogram on each (re)start.
func watch(ctx context.Context, iface string, addr netip.Addr, zone string) {
	match := []dbus.MatchOption{
		dbus.WithMatchObjectPath(dbusBrokerPath),
		dbus.WithMatchInterface(dbusBroker),
		dbus.WithMatchMember(nameOwnerChanged),
		dbus.WithMatchArg(0, resolvedDest),
	}
	backoff := time.Second
	for {
		if err := watchOnce(ctx, iface, addr, zone, match); err != nil && ctx.Err() == nil {
			slog.Warn("resolved watch reconnect", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, watchBackoffMax)
	}
}

func watchOnce(ctx context.Context, iface string, addr netip.Addr, zone string, match []dbus.MatchOption) error {
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
	nameCtx, nameCancel := context.WithTimeout(ctx, resolvedCallTimeout)
	if call := conn.BusObject().CallWithContext(nameCtx, dbusBroker+".NameHasOwner", 0, resolvedDest); call.Err == nil {
		_ = call.Store(&owned)
	}
	nameCancel()
	if owned {
		resync(ctx, iface, addr, zone)
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
			resync(ctx, iface, addr, zone)
		}
	}
}

func resync(ctx context.Context, iface string, addr netip.Addr, zone string) {
	backoff := 200 * time.Millisecond
	for attempt := 0; ; attempt++ {
		if err := program(iface, addr, zone); err == nil {
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

// Old resolved versions lack some of these calls; tolerated.
func program(iface string, addr netip.Addr, zone string) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", iface, err)
	}
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("system bus: %w", err)
	}
	mgr := conn.Object(resolvedDest, resolvedPath)
	idx := int32(ifi.Index)

	ctx, cancel := context.WithTimeout(context.Background(), resolvedCallTimeout)
	defer cancel()

	var servers []resolvedLinkDNS
	if a := addr.Unmap(); a.Is4() {
		ip := a.As4()
		servers = []resolvedLinkDNS{{Family: syscall.AF_INET, Address: ip[:]}}
	} else {
		ip := a.As16()
		servers = []resolvedLinkDNS{{Family: syscall.AF_INET6, Address: ip[:]}}
	}
	if err := mgr.CallWithContext(ctx, resolvedManagerIface+".SetLinkDNS", 0, idx, servers).Store(); err != nil {
		return fmt.Errorf("SetLinkDNS: %w", err)
	}
	domains := []resolvedLinkDomain{{Domain: zone + ".", RoutingOnly: true}}
	if err := mgr.CallWithContext(ctx, resolvedManagerIface+".SetLinkDomains", 0, idx, domains).Store(); err != nil {
		return fmt.Errorf("SetLinkDomains: %w", err)
	}
	if call := mgr.CallWithContext(ctx, resolvedManagerIface+".SetLinkDefaultRoute", 0, idx, false); call.Err != nil {
		// absent on old systemd-resolved (e.g. v237); tolerate
		if dbusErr, ok := call.Err.(dbus.Error); ok && dbusErr.Name == dbus.ErrMsgUnknownMethod.Name {
			slog.Debug("resolved SetLinkDefaultRoute unsupported; continuing", "err", call.Err)
		} else {
			return fmt.Errorf("SetLinkDefaultRoute: %w", call.Err)
		}
	}
	for _, h := range []struct{ method, value string }{
		{"SetLinkLLMNR", "no"},
		{"SetLinkMulticastDNS", "no"},
		{"SetLinkDNSSEC", "no"},
		{"SetLinkDNSOverTLS", "no"},
	} {
		if call := mgr.CallWithContext(ctx, resolvedManagerIface+"."+h.method, 0, idx, h.value); call.Err != nil {
			slog.Debug("resolved hardening call failed; continuing", "method", h.method, "err", call.Err)
		}
	}
	if call := mgr.CallWithContext(ctx, resolvedManagerIface+".FlushCaches", 0); call.Err != nil {
		slog.Debug("resolved flush caches failed; continuing", "err", call.Err)
	}
	return nil
}

func revert(iface string) {
	conn, err := dbus.SystemBus()
	if err != nil {
		slog.Debug("revert resolved", "err", err)
		return
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		slog.Debug("revert resolved", "err", err)
		return
	}
	// fresh ctx: run ctx already cancelled, must not wedge teardown.
	ctx, cancel := context.WithTimeout(context.Background(), resolvedCallTimeout)
	defer cancel()
	mgr := conn.Object(resolvedDest, resolvedPath)
	if err := mgr.CallWithContext(ctx, resolvedManagerIface+".RevertLink", 0, int32(ifi.Index)).Store(); err != nil {
		slog.Debug("revert resolved", "err", err)
	}
}
