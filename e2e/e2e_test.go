//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	addr "github.com/pigeon-as/pigeon-addr-plan"
	"golang.zx2c4.com/wireguard/wgctrl"
)

var meshBin string

// validKey is 32 zero bytes base64-encoded, valid for both gossip_key and wg_psk.
var validKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

func TestMain(m *testing.M) {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "e2e tests require root, skipping")
		os.Exit(0)
	}

	// Check nftables kernel support.
	c := &nftables.Conn{}
	if _, err := c.ListTables(); err != nil {
		fmt.Fprintf(os.Stderr, "nftables not available: %v\n", err)
		os.Exit(0)
	}

	// Check WireGuard kernel support.
	wg, err := wgctrl.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgctrl not available: %v\n", err)
		os.Exit(0)
	}
	wg.Close()

	// Check IP forwarding (pigeon-mesh requires it).
	for _, path := range []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv6/conf/all/forwarding",
	} {
		v, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(v)) != "1" {
			fmt.Fprintf(os.Stderr, "IP forwarding not enabled (%s), skipping\n", path)
			os.Exit(0)
		}
	}

	// Find binary.
	meshBin = filepath.Join("..", "build", "pigeon-mesh")
	if _, err := os.Stat(meshBin); err != nil {
		p, err := exec.LookPath("pigeon-mesh")
		if err != nil {
			fmt.Fprintln(os.Stderr, "pigeon-mesh binary not found (run 'make build' first)")
			os.Exit(1)
		}
		meshBin = p
	}

	os.Exit(m.Run())
}

// baseConfig returns a minimal valid config with a temp data_dir.
func baseConfig(t *testing.T) map[string]interface{} {
	t.Helper()
	return map[string]interface{}{
		"interface":   "wg-e2e",
		"seeds":       []string{"127.0.0.1"},
		"gossip_key":  validKey,
		"wg_psk":      validKey,
		"listen_port": 51820,
		"endpoint":    "127.0.0.1",
		"data_dir":    filepath.Join(t.TempDir(), "data"),
		"log_level":   "debug",
	}
}

// writeConfig writes cfg as JSON to a temp file and returns its path.
func writeConfig(t *testing.T, cfg map[string]interface{}) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// startMesh starts pigeon-mesh with cfg, waits for readiness, and registers
// cleanup to stop the process and remove state.
func startMesh(t *testing.T, cfg map[string]interface{}) {
	t.Helper()

	iface := "wg-e2e"
	if v, ok := cfg["interface"]; ok {
		iface = v.(string)
	}

	cleanupState(iface)

	cfgPath := writeConfig(t, cfg)
	cmd := exec.Command(meshBin, "--config", cfgPath, "--log-level", "debug")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			<-done
		}
		cleanupState(iface)
	})

	waitForReady(t, iface)
}

// waitForReady polls until the WG interface exists and the transpose chains
// are configured (not just the table — chains are added asynchronously).
func waitForReady(t *testing.T, iface string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := net.InterfaceByName(iface); err == nil {
			c := &nftables.Conn{}
			chains, _ := c.ListChainsOfTableFamily(nftables.TableFamilyNetdev)
			for _, ch := range chains {
				if ch.Table.Name == "pigeon-transpose" && ch.Name == "ingress" {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("pigeon-mesh not ready after 10s (interface %s)", iface)
}

// cleanupState removes WG interface and nftables tables.
func cleanupState(iface string) {
	c := &nftables.Conn{}
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "pigeon-mesh-nat"})
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyNetdev, Name: "pigeon-transpose"})
	_ = c.Flush()
	exec.Command("ip", "link", "del", iface).Run()
}

// getTable returns the named nftables table, or nil if not found.
func getTable(name string, family nftables.TableFamily) *nftables.Table {
	c := &nftables.Conn{}
	tables, _ := c.ListTables()
	for _, tbl := range tables {
		if tbl.Name == name && tbl.Family == family {
			return tbl
		}
	}
	return nil
}

// getChains returns chains in the given table.
func getChains(t *testing.T, tbl *nftables.Table) []*nftables.Chain {
	t.Helper()
	c := &nftables.Conn{}
	chains, err := c.ListChainsOfTableFamily(tbl.Family)
	if err != nil {
		t.Fatal(err)
	}
	var result []*nftables.Chain
	for _, ch := range chains {
		if ch.Table.Name == tbl.Name {
			result = append(result, ch)
		}
	}
	return result
}

func TestBinaryExists(t *testing.T) {
	if _, err := os.Stat(meshBin); err != nil {
		t.Fatalf("binary not found at %s: %v", meshBin, err)
	}
}

func TestSingleNode(t *testing.T) {
	cfg := baseConfig(t)
	startMesh(t, cfg)

	// WireGuard interface exists with correct port.
	wg, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()

	dev, err := wg.Device("wg-e2e")
	if err != nil {
		t.Fatalf("wg device: %v", err)
	}
	if dev.ListenPort != 51820 {
		t.Fatalf("listen port = %d, want 51820", dev.ListenPort)
	}

	// Key file created with correct permissions.
	keyPath := filepath.Join(cfg["data_dir"].(string), "privkey")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("key perms = %04o, want 0600", perm)
	}
}

func TestOverlayAddress(t *testing.T) {
	cfg := baseConfig(t)
	startMesh(t, cfg)

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}

	// Compute expected overlay address.
	host, err := addr.HashPrefix(addr.PigeonULARange(), addr.NetworkBits, hostname)
	if err != nil {
		t.Fatal(err)
	}
	hostIP, err := addr.HostAddr(host, 1)
	if err != nil {
		t.Fatal(err)
	}
	transposed, ok := addr.TransposePigeonULA(hostIP)
	if !ok {
		t.Fatal("transpose failed")
	}
	expected := transposed.String()

	// Check interface addresses.
	iface, err := net.InterfaceByName("wg-e2e")
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, a := range addrs {
		prefix, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		if prefix.Addr().String() == expected {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("overlay address %s not found on wg-e2e (got %v)", expected, addrs)
	}
}

func TestNftablesNAT(t *testing.T) {
	cfg := baseConfig(t)
	cfg["egress_cidr"] = "100.64.0.0/24"
	startMesh(t, cfg)

	tbl := getTable("pigeon-mesh-nat", nftables.TableFamilyINet)
	if tbl == nil {
		t.Fatal("pigeon-mesh-nat table not found")
	}

	chains := getChains(t, tbl)
	if len(chains) == 0 {
		t.Fatal("no chains in pigeon-mesh-nat")
	}

	var found bool
	for _, ch := range chains {
		if ch.Name == "postrouting" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("postrouting chain not found")
	}
}

func TestNoEgressSkipsNAT(t *testing.T) {
	cfg := baseConfig(t)
	// No egress_cidr set.
	startMesh(t, cfg)

	tbl := getTable("pigeon-mesh-nat", nftables.TableFamilyINet)
	if tbl != nil {
		t.Fatal("pigeon-mesh-nat table should not exist without egress_cidr")
	}
}

func TestNftablesTranspose(t *testing.T) {
	cfg := baseConfig(t)
	startMesh(t, cfg)

	tbl := getTable("pigeon-transpose", nftables.TableFamilyNetdev)
	if tbl == nil {
		t.Fatal("pigeon-transpose table not found")
	}

	chains := getChains(t, tbl)
	chainNames := make(map[string]bool, len(chains))
	for _, ch := range chains {
		chainNames[ch.Name] = true
	}

	if !chainNames["ingress"] {
		t.Fatal("ingress chain not found in pigeon-transpose")
	}
	if !chainNames["egress"] {
		t.Fatal("egress chain not found in pigeon-transpose")
	}
}

func TestKeyPersistence(t *testing.T) {
	cfg := baseConfig(t)
	dataDir := cfg["data_dir"].(string)
	iface := cfg["interface"].(string)

	// First run.
	cfgPath := writeConfig(t, cfg)
	cmd1 := exec.Command(meshBin, "--config", cfgPath, "--log-level", "debug")
	cmd1.Stdout = os.Stdout
	cmd1.Stderr = os.Stderr
	if err := cmd1.Start(); err != nil {
		t.Fatal(err)
	}
	waitForReady(t, iface)

	keyPath := filepath.Join(dataDir, "privkey")
	key1, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Stop first run.
	cmd1.Process.Signal(syscall.SIGTERM)
	cmd1.Wait()
	cleanupState(iface)
	time.Sleep(500 * time.Millisecond) // let port release

	// Second run with same data_dir.
	cmd2 := exec.Command(meshBin, "--config", cfgPath, "--log-level", "debug")
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr
	if err := cmd2.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd2.Process.Signal(syscall.SIGTERM)
		cmd2.Wait()
		cleanupState(iface)
	})
	waitForReady(t, iface)

	key2, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(key1) != string(key2) {
		t.Fatal("private key changed across restarts")
	}
}
