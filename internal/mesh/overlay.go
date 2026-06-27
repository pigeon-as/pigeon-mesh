//go:build linux

package mesh

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

// DeriveAddr returns the key-derived overlay address: leftmost host bits of SHA-512(key) under
// prefix. Pure function of the key, so a node cannot claim another's address.
func DeriveAddr(pubkey string, prefix netip.Prefix) (netip.Addr, error) {
	if !prefix.Addr().Is6() || prefix.Bits()%8 != 0 {
		return netip.Addr{}, fmt.Errorf("overlay prefix %s must be a byte-aligned IPv6 prefix", prefix)
	}
	if prefix.Bits() > 64 {
		return netip.Addr{}, fmt.Errorf("overlay prefix %s is too long; use /64 or shorter so the key-derived host portion stays collision-resistant", prefix)
	}
	raw, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("pubkey %q: %w", pubkey, err)
	}
	sum := sha512.Sum512(raw)
	addr := prefix.Masked().Addr().As16()
	copy(addr[prefix.Bits()/8:], sum[:])
	return netip.AddrFrom16(addr), nil
}

// validateOverlayAddr checks a peer advertises its own key-derived address (and no other inside the
// prefix). A wrong or missing claim is rejected: identity is self-certifying, never contestable.
func validateOverlayAddr(pubkey string, p Peer, prefix netip.Prefix) (netip.Addr, error) {
	want, err := DeriveAddr(pubkey, prefix)
	if err != nil {
		return netip.Addr{}, err
	}
	var claimsSelf bool
	for _, c := range p.AllowedIPs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("allowed-ip %q: %w", c, err)
		}
		if !prefix.Overlaps(pfx) {
			continue
		}
		if pfx.Bits() < prefix.Bits() {
			continue // supernet of the overlay (e.g. ::/0): an aggregate/exit route, not an address claim; defer to --peer-policy
		}
		if pfx.Bits() != pfx.Addr().BitLen() || pfx.Addr() != want {
			return netip.Addr{}, fmt.Errorf("claims overlay route %s but key derives %s", c, want)
		}
		claimsSelf = true
	}
	if !claimsSelf {
		return netip.Addr{}, fmt.Errorf("advertises no overlay address; key derives %s", want)
	}
	return want, nil
}

// guardOverlayRoute is the sole owner of this node's overlay-prefix route: sets it on startup,
// re-asserts on each netlink resubscribe (covering deletes missed while down) and on external
// delete. reconcile must not touch this route. No-op without --prefix.
func (m *Mesh) guardOverlayRoute(ctx context.Context) {
	if !m.cfg.Prefix.IsValid() {
		return
	}
	backoff := time.Second
	for {
		if err := m.cfg.WG.SetRoute(m.cfg.Iface, m.cfg.Prefix); err != nil {
			slog.Warn("overlay route", "err", err)
		}
		if err := m.watchRouteDeletes(ctx); err != nil && ctx.Err() == nil {
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

func (m *Mesh) watchRouteDeletes(ctx context.Context) error {
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
