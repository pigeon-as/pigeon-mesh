package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

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

func (c Config) Validate() error {
	if len(c.Seeds) == 0 {
		return fmt.Errorf("seeds is required")
	}
	if c.GossipKey == "" {
		return fmt.Errorf("gossip_key is required")
	}
	gossipRaw, err := base64.StdEncoding.DecodeString(c.GossipKey)
	if err != nil {
		return fmt.Errorf("gossip_key: invalid base64: %w", err)
	}
	if l := len(gossipRaw); l != 16 && l != 24 && l != 32 {
		return fmt.Errorf("gossip_key: must be 16, 24, or 32 bytes, got %d", l)
	}
	if c.WgPSK == "" {
		return fmt.Errorf("wg_psk is required")
	}
	pskRaw, err := base64.StdEncoding.DecodeString(c.WgPSK)
	if err != nil {
		return fmt.Errorf("wg_psk: invalid base64: %w", err)
	}
	if len(pskRaw) != 32 {
		return fmt.Errorf("wg_psk: must be 32 bytes, got %d", len(pskRaw))
	}
	if len(c.Interface) > 15 {
		return fmt.Errorf("interface: name too long (%d chars, max 15)", len(c.Interface))
	}
	return nil
}
