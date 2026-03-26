package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
)

const (
	defaultInterface  = "wg0"
	defaultListenPort = 51820
	defaultDataDir    = "/var/lib/pigeon-mesh"
	defaultLogLevel   = "info"
	maxIfaceNameLen   = 15 // IFNAMSIZ - 1
	wgPSKLen          = 32 // Curve25519
)

type Config struct {
	Interface         string   `json:"interface"`
	Seeds             []string `json:"seeds"`
	GossipKey         string   `json:"gossip_key"`
	WgPSK             string   `json:"wg_psk"`
	ListenPort        int      `json:"listen_port"`
	EndpointAddress   string   `json:"endpoint_address"`
	EndpointInterface string   `json:"endpoint_interface"`
	EgressCIDR        string   `json:"egress_cidr"`
	DataDir           string   `json:"data_dir"`
	LogLevel          string   `json:"log_level"`
	TLSCACert         string   `json:"tls_ca_cert"`
	TLSCAKey          string   `json:"tls_ca_key"`
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
		cfg.Interface = defaultInterface
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = defaultListenPort
	}
	if cfg.DataDir == "" {
		cfg.DataDir = defaultDataDir
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = defaultLogLevel
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
	if len(pskRaw) != wgPSKLen {
		return fmt.Errorf("wg_psk: must be %d bytes, got %d", wgPSKLen, len(pskRaw))
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("listen_port: must be between 1 and 65535, got %d", c.ListenPort)
	}
	if len(c.Interface) > maxIfaceNameLen {
		return fmt.Errorf("interface: name too long (%d chars, max %d)", len(c.Interface), maxIfaceNameLen)
	}
	if c.EndpointAddress != "" && c.EndpointInterface != "" {
		return fmt.Errorf("endpoint_address and endpoint_interface are mutually exclusive")
	}
	if c.EndpointAddress != "" {
		if ip := net.ParseIP(c.EndpointAddress); ip == nil {
			return fmt.Errorf("endpoint_address: invalid IP %q", c.EndpointAddress)
		}
	}
	if c.EndpointInterface != "" && len(c.EndpointInterface) > maxIfaceNameLen {
		return fmt.Errorf("endpoint_interface: name too long (%d chars, max %d)", len(c.EndpointInterface), maxIfaceNameLen)
	}
	if (c.TLSCACert == "") != (c.TLSCAKey == "") {
		return fmt.Errorf("tls_ca_cert and tls_ca_key must both be set or both be empty")
	}
	if c.TLSCACert != "" {
		if _, err := os.Stat(c.TLSCACert); err != nil {
			return fmt.Errorf("tls_ca_cert: %w", err)
		}
		if _, err := os.Stat(c.TLSCAKey); err != nil {
			return fmt.Errorf("tls_ca_key: %w", err)
		}
	}
	return nil
}
