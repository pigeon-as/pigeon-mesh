//go:build linux

package sdnotify

import (
	"context"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
)

// Run signals systemd READY only after ready is closed (the daemon's first successful reconcile), so a
// Type=notify unit is not marked active before the mesh is actually programming the kernel.
func Run(ctx context.Context, ready <-chan struct{}) {
	select {
	case <-ready:
	case <-ctx.Done():
		return
	}
	daemon.SdNotify(false, daemon.SdNotifyReady)
	defer daemon.SdNotify(false, daemon.SdNotifyStopping)

	interval, err := daemon.SdWatchdogEnabled(false)
	if err != nil || interval == 0 {
		<-ctx.Done()
		return
	}
	t := time.NewTicker(interval / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			daemon.SdNotify(false, daemon.SdNotifyWatchdog)
		}
	}
}
