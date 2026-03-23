// pigeon-mesh manages the WireGuard mesh overlay for pigeon infrastructure.
//
// Usage:
//
//	pigeon-mesh --config=/etc/pigeon/mesh.json
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pigeon-as/pigeon-mesh/internal/config"
	"github.com/pigeon-as/pigeon-mesh/internal/mesh"
	"github.com/pigeon-as/pigeon-mesh/internal/netconf"
)

var (
	configFile = flag.String("config", "", "Path to JSON config file (required)")
	logLevel   = flag.String("log-level", "", "Log level override (debug, info, warn, error)")
	showVer    = flag.Bool("version", false, "Print version and exit")
)

func main() {
	flag.Parse()
	os.Exit(run())
}

func run() int {
	if *showVer {
		fmt.Println("pigeon-mesh v0.2.0")
		return 0
	}
	return runDaemon()
}

func runDaemon() int {
	if *configFile == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		return 1
	}

	cfg, err := config.Load(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLevel(cfg.LogLevel),
	}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hostname, err := os.Hostname()
	if err != nil {
		logger.Error("get hostname", "err", err)
		return 1
	}

	// 1. Verify sysctl (IP forwarding must be set by image sysctl.conf).
	if err := netconf.VerifySysctl(); err != nil {
		logger.Error("verify sysctl", "err", err)
		return 1
	}
	logger.Info("sysctl verified")

	// 2. Setup nftables BEFORE joining mesh — rules must be in place when wg0
	//    starts receiving traffic. Transpose is installed after mesh start
	//    because it needs the interface to exist.
	if err := netconf.SetupNftables(cfg.Interface, cfg.EgressCIDR); err != nil {
		logger.Error("setup nftables", "err", err)
		return 1
	}
	logger.Info("nftables configured", "egress_cidr", cfg.EgressCIDR)

	// 3. Start WireGuard mesh (creates interface, joins memberlist).
	m, err := mesh.New(logger, mesh.Config{
		Interface:   cfg.Interface,
		Seeds:       cfg.Seeds,
		GossipKey:   cfg.GossipKey,
		WgPSK:       cfg.WgPSK,
		ListenPort:  cfg.ListenPort,
		Hostname:    hostname,
		OverlayAddr: cfg.OverlayAddr,
		Endpoint:    cfg.Endpoint,
		DataDir:     cfg.DataDir,
	})
	if err != nil {
		logger.Error("start mesh", "err", err)
		return 1
	}
	defer m.Leave()

	// 4. Setup address transposition (needs wg0 interface to exist).
	if err := netconf.SetupTranspose(cfg.Interface); err != nil {
		logger.Error("setup transpose", "err", err)
		return 1
	}
	logger.Info("address transposition configured")

	// 5. Run mesh reconcile loop.
	go m.Run(ctx)

	// Wait for shutdown signal.
	<-ctx.Done()
	logger.Info("shutting down")
	return 0
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
