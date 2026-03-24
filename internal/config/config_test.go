package config

import (
	"os"
	"path/filepath"
	"testing"
)

// validKey32 is 32 zero bytes, base64-encoded. Valid for both
// gossip_key (16/24/32) and wg_psk (32).
const validKey32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestValidate_RequiresSeeds(t *testing.T) {
	cfg := Config{GossipKey: validKey32, WgPSK: validKey32}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing seeds")
	}
}

func TestValidate_RequiresGossipKey(t *testing.T) {
	cfg := Config{Seeds: []string{"1.2.3.4"}, WgPSK: validKey32}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing gossip_key")
	}
}

func TestValidate_RequiresWgPSK(t *testing.T) {
	cfg := Config{Seeds: []string{"1.2.3.4"}, GossipKey: validKey32}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing wg_psk")
	}
}

func TestValidate_OK(t *testing.T) {
	cfg := Config{Seeds: []string{"1.2.3.4"}, GossipKey: validKey32, WgPSK: validKey32, ListenPort: 51820, EndpointAddress: "10.0.0.1"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_OKWithInterface(t *testing.T) {
	cfg := Config{Seeds: []string{"1.2.3.4"}, GossipKey: validKey32, WgPSK: validKey32, ListenPort: 51820, EndpointInterface: "eth0"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_OKNoEndpoint(t *testing.T) {
	cfg := Config{Seeds: []string{"1.2.3.4"}, GossipKey: validKey32, WgPSK: validKey32, ListenPort: 51820}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v (neither endpoint field is required)", err)
	}
}

func TestValidate_EndpointMutuallyExclusive(t *testing.T) {
	cfg := Config{Seeds: []string{"1.2.3.4"}, GossipKey: validKey32, WgPSK: validKey32, ListenPort: 51820, EndpointAddress: "10.0.0.1", EndpointInterface: "eth0"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when both endpoint_address and endpoint_interface are set")
	}
}

func TestValidate_EndpointAddressInvalid(t *testing.T) {
	cfg := Config{Seeds: []string{"1.2.3.4"}, GossipKey: validKey32, WgPSK: validKey32, ListenPort: 51820, EndpointAddress: "not-an-ip"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid endpoint_address")
	}
}

func TestValidate_EndpointInterfaceTooLong(t *testing.T) {
	cfg := Config{Seeds: []string{"1.2.3.4"}, GossipKey: validKey32, WgPSK: validKey32, ListenPort: 51820, EndpointInterface: "this-name-is-way-too-long"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for endpoint_interface name > 15 chars")
	}
}

func TestValidate_PortRange(t *testing.T) {
	cfg := Config{Seeds: []string{"1.2.3.4"}, GossipKey: validKey32, WgPSK: validKey32, ListenPort: 0, EndpointAddress: "10.0.0.1"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for listen_port 0")
	}
	cfg.ListenPort = 70000
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for listen_port > 65535")
	}
}

func TestValidate_GossipKeyBadLength(t *testing.T) {
	cfg := Config{Seeds: []string{"1.2.3.4"}, GossipKey: "dGVzdA==", WgPSK: validKey32}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for 4-byte gossip_key")
	}
}

func TestValidate_WgPSKBadLength(t *testing.T) {
	// 16 zero bytes — valid for gossip but not for wg_psk.
	cfg := Config{Seeds: []string{"1.2.3.4"}, GossipKey: validKey32, WgPSK: "AAAAAAAAAAAAAAAAAAAAAA=="}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for 16-byte wg_psk")
	}
}

func TestValidate_InterfaceTooLong(t *testing.T) {
	cfg := Config{
		Seeds:           []string{"1.2.3.4"},
		GossipKey:       validKey32,
		WgPSK:           validKey32,
		ListenPort:      51820,
		EndpointAddress: "10.0.0.1",
		Interface:       "this-name-is-way-too-long",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for interface name > 15 chars")
	}
}

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Interface != "wg0" {
		t.Fatalf("Interface = %q, want wg0", cfg.Interface)
	}
	if cfg.ListenPort != 51820 {
		t.Fatalf("ListenPort = %d, want 51820", cfg.ListenPort)
	}
	if cfg.DataDir != "/var/lib/pigeon-mesh" {
		t.Fatalf("DataDir = %q, want /var/lib/pigeon-mesh", cfg.DataDir)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("LogLevel = %q, want info", cfg.LogLevel)
	}
}

func TestLoad_BadPath(t *testing.T) {
	_, err := Load("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestLoad_BadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestLoad_AppliesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(path, []byte(`{"gossip_key":"test"}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Interface != "wg0" {
		t.Fatalf("Interface = %q, want wg0", cfg.Interface)
	}
	if cfg.GossipKey != "test" {
		t.Fatalf("GossipKey = %q, want test", cfg.GossipKey)
	}
}
