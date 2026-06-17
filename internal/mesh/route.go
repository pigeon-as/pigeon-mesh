//go:build linux

package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

func (m *Mesh) serveRouteMonitor(ctx context.Context) {
	if !m.cfg.Prefix.IsValid() {
		return
	}
	backoff := time.Second
	for {
		if err := m.watchRoutesOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("route monitor reconnect", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, reconnectInterval)
	}
}

func (m *Mesh) watchRoutesOnce(ctx context.Context) error {
	ch := make(chan netlink.RouteUpdate, 16)
	done := make(chan struct{})
	defer close(done)
	if err := netlink.RouteSubscribe(ch, done); err != nil {
		return err
	}
	link, err := netlink.LinkByName(m.cfg.Iface)
	if err != nil {
		return err
	}
	idx := link.Attrs().Index
	want := m.cfg.Prefix.Masked()

	var pending atomic.Bool
	for {
		select {
		case <-ctx.Done():
			return nil
		case u, ok := <-ch:
			if !ok {
				return fmt.Errorf("route subscription closed")
			}
			if u.Type != syscall.RTM_DELROUTE || u.LinkIndex != idx || u.Dst == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(u.Dst.IP)
			if !ok {
				continue
			}
			ones, _ := u.Dst.Mask.Size()
			if netip.PrefixFrom(addr.Unmap(), ones).Masked() != want {
				continue
			}
			if pending.Swap(true) {
				continue
			}
			slog.Info("overlay route deleted externally; re-asserting", "route", want)
			time.AfterFunc(routeReassertDebounce, func() {
				pending.Store(false)
				if ctx.Err() != nil {
					return
				}
				if err := m.cfg.WG.SetRoute(m.cfg.Iface, m.cfg.Prefix); err != nil {
					slog.Warn("route re-assert", "err", err)
				}
			})
		}
	}
}
