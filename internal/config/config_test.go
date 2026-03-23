package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidate_RequiresSeeds(t *testing.T) {
	cfg := Config{GossipKey: "dGVzdA==", WgPSK: "dGVzdA=="}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing seeds")
	}
}

func TestValidate_RequiresGossipKey(t *testing.T) {
	cfg := Config{Seeds: []string{"1.2.3.4"}, WgPSK: "dGVzdA=="}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing gossip_key")
	}
}

func TestValidate_RequiresWgPSK(t *testing.T) {
	cfg := Config{Seeds: []string{"1.2.3.4"}, GossipKey: "dGVzdA=="}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing wg_psk")
	}
}

func TestValidate_OK(t *testing.T) {
	cfg := Config{Seeds: []string{"1.2.3.4"}, GossipKey: "dGVzdA==", WgPSK: "dGVzdA=="}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
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
