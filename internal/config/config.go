// Package config loads and validates the pigeon-mesh JSON configuration.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds the pigeon-mesh configuration.
type Config struct {
	Interface   string   `json:"interface"`
	Seeds       []string `json:"seeds"`
	GossipKey   string   `json:"gossip_key"`
	WgPSK       string   `json:"wg_psk"`
	ListenPort  int      `json:"listen_port"`
	OverlayAddr string   `json:"overlay_addr"`
	Endpoint    string   `json:"endpoint"`
	EgressCIDR  string   `json:"egress_cidr"`
	DataDir     string   `json:"data_dir"`
	LogLevel    string   `json:"log_level"`
}

// Load reads a JSON config file and returns a Config with defaults applied.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	applyDefaults(&cfg)
	return cfg, nil
}

// Defaults returns a Config with all default values applied.
func Defaults() Config {
	var cfg Config
	applyDefaults(&cfg)
	return cfg
}

func applyDefaults(cfg *Config) {
	if cfg.Interface == "" {
		cfg.Interface = "wg0"
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 51820
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "/var/lib/pigeon-mesh"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
}

// Validate checks required fields. Should be called after all overrides
// (CLI flags, env vars) have been applied.
func (c Config) Validate() error {
	if len(c.Seeds) == 0 {
		return fmt.Errorf("seeds is required")
	}
	if c.GossipKey == "" {
		return fmt.Errorf("gossip_key is required")
	}
	if c.WgPSK == "" {
		return fmt.Errorf("wg_psk is required")
	}
	return nil
}
