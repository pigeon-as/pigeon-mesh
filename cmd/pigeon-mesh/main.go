//go:build linux

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

	if *showVer {
		fmt.Println("pigeon-mesh v0.0.1-beta.1")
		return
	}

	if *configFile == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		os.Exit(1)
	}

	cfg, err := config.Load(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid log-level %q: %v\n", cfg.LogLevel, err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hostname, err := os.Hostname()
	if err != nil {
		logger.Error("get hostname", "err", err)
		os.Exit(1)
	}

	if err := netconf.VerifySysctl(); err != nil {
		logger.Error("verify sysctl", "err", err)
		os.Exit(1)
	}
	logger.Info("sysctl verified")

	if err := netconf.SetupNftables(cfg.Interface, cfg.EgressCIDR); err != nil {
		logger.Error("setup nftables", "err", err)
		os.Exit(1)
	}
	logger.Info("nftables configured", "egress_cidr", cfg.EgressCIDR)

	m, err := mesh.New(logger, mesh.Config{
		Interface:         cfg.Interface,
		Seeds:             cfg.Seeds,
		GossipKey:         cfg.GossipKey,
		WgPSK:             cfg.WgPSK,
		ListenPort:        cfg.ListenPort,
		Hostname:          hostname,
		EndpointAddress:   cfg.EndpointAddress,
		EndpointInterface: cfg.EndpointInterface,
		DataDir:           cfg.DataDir,
	})
	if err != nil {
		logger.Error("start mesh", "err", err)
		os.Exit(1)
	}
	defer m.Leave()

	if err := netconf.SetupTranspose(cfg.Interface); err != nil {
		logger.Error("setup transpose", "err", err)
		os.Exit(1)
	}
	logger.Info("address transposition configured")

	go m.Run(ctx)

	<-ctx.Done()
	logger.Info("shutting down")
}
