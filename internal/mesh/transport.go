//go:build linux

package mesh

import (
	"errors"
	"log/slog"
	"syscall"
	"time"

	"github.com/hashicorp/memberlist"
)

// Gossip rides inside the tunnels, so a cold tunnel returns ENOKEY until the first handshake;
// swallow that so memberlist retries instead of marking the peer failed.
type wgTransport struct {
	*memberlist.NetTransport
}

func (t *wgTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	ts, err := t.NetTransport.WriteTo(b, addr)
	return ts, tolerateColdTunnel(addr, err)
}

func (t *wgTransport) WriteToAddress(b []byte, a memberlist.Address) (time.Time, error) {
	ts, err := t.NetTransport.WriteToAddress(b, a)
	return ts, tolerateColdTunnel(a.Addr, err)
}

func tolerateColdTunnel(addr string, err error) error {
	if errors.Is(err, syscall.ENOKEY) {
		slog.Debug("gossip write to cold wg tunnel; handshake pending", "addr", addr)
		return nil
	}
	return err
}
