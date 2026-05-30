//go:build linux

package sdnotify

import (
	"context"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
)

func Run(ctx context.Context) {
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
