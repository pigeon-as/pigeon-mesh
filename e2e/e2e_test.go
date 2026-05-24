//go:build e2e

package e2e

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

var meshBin string

func TestMain(m *testing.M) {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "e2e tests require root, skipping")
		os.Exit(0)
	}
	if err := exec.Command("ip", "link", "add", "wg-probe", "type", "wireguard").Run(); err != nil {
		fmt.Fprintf(os.Stderr, "wireguard not available: %v\n", err)
		os.Exit(0)
	}
	exec.Command("ip", "link", "del", "wg-probe").Run()

	meshBin = filepath.Join("..", "build", "wg-mesh")
	if _, err := os.Stat(meshBin); err != nil {
		p, err := exec.LookPath("wg-mesh")
		if err != nil {
			fmt.Fprintln(os.Stderr, "wg-mesh binary not found (run 'make build' first)")
			os.Exit(1)
		}
		meshBin = p
	}

	os.Exit(m.Run())
}

func TestRejectsMissingInterface(t *testing.T) {
	cmd := exec.Command(meshBin,
		"--interface", "wg-nonexistent",
		"--endpoint", "127.0.0.1:51820",
	)
	out, err := cmd.CombinedOutput()
	must.Error(t, err, must.Sprintf("expected non-zero exit; output: %s", out))
	must.StrContains(t, string(out), "wg-nonexistent")
}

func TestPreservesPrivateKey(t *testing.T) {
	const (
		iface  = "wg-e2e"
		addr   = "fd00:e2e::1"
		port   = 51899
		gossip = 7951
	)
	exec.Command("ip", "link", "del", iface).Run()
	t.Cleanup(func() { exec.Command("ip", "link", "del", iface).Run() })

	priv, _ := genKeypair(t)
	keyFile := writeFile(t, priv+"\n")
	run(t, "ip", "link", "add", iface, "type", "wireguard")
	run(t, "wg", "set", iface, "private-key", keyFile, "listen-port", fmt.Sprint(port))
	run(t, "ip", "-6", "addr", "add", addr+"/128", "dev", iface)
	run(t, "ip", "link", "set", iface, "up")

	_, peerPub := genKeypair(t)
	run(t, "wg", "set", iface, "peer", peerPub,
		"endpoint", "198.51.100.7:51820",
		"allowed-ips", "fd00:e2e::2/128")

	cmd := exec.Command(meshBin,
		"--interface", iface,
		"--endpoint", fmt.Sprintf("[%s]:%d", addr, port),
		"--gossip-port", fmt.Sprint(gossip),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	must.NoError(t, cmd.Start())
	t.Cleanup(func() { stop(cmd) })

	waitFor(t, "kernel peer installed", 10*time.Second, func() bool {
		out, _ := exec.Command("wg", "show", iface, "peers").CombinedOutput()
		return strings.Contains(string(out), peerPub)
	})
	must.StrContains(t, run(t, "wg", "show", iface, "peers"), peerPub)
	must.EqOp(t, priv, run(t, "wg", "show", iface, "private-key"))
}

func TestMesh_TwoNodes(t *testing.T) {
	skipIfNoNetns(t)
	newBridge(t, "wgm2-br")

	a := newNode(t, "wgm2-a", "10.123.0.1", "fd00:e2e:a::1", 51820, "wgm2-br")
	b := newNode(t, "wgm2-b", "10.123.0.2", "fd00:e2e:b::1", 51820, "wgm2-br")

	startMesh(t, a, []*node{b}, 51820)
	startMesh(t, b, []*node{a}, 51820)

	waitFor(t, "a sees b", 10*time.Second, func() bool {
		return strings.Contains(wgPeers(a), b.pub)
	})
	waitFor(t, "b sees a", 10*time.Second, func() bool {
		return strings.Contains(wgPeers(b), a.pub)
	})

	waitPing(t, a, b.overlay)
	waitPing(t, b, a.overlay)
}

func TestMesh_GossipKeyAndReload(t *testing.T) {
	skipIfNoNetns(t)
	newBridge(t, "wgmk-br")

	a := newNode(t, "wgmk-a", "10.126.0.1", "fd00:e2e4:a::1", 51820, "wgmk-br")
	b := newNode(t, "wgmk-b", "10.126.0.2", "fd00:e2e4:b::1", 51820, "wgmk-br")

	keyA := base64.StdEncoding.EncodeToString(append([]byte{0xa1}, make([]byte, 31)...))
	keyB := base64.StdEncoding.EncodeToString(append([]byte{0xb2}, make([]byte, 31)...))
	keyFile := filepath.Join(t.TempDir(), "keys.json")
	must.NoError(t, os.WriteFile(keyFile, []byte(`["`+keyA+`"]`), 0o600))

	cmdA := startMesh(t, a, []*node{b}, 51820, "--gossip-key-file", keyFile)
	cmdB := startMesh(t, b, []*node{a}, 51820, "--gossip-key-file", keyFile)

	waitFor(t, "converged with key A", 15*time.Second, func() bool {
		return strings.Contains(wgPeers(a), b.pub) && strings.Contains(wgPeers(b), a.pub)
	})

	must.NoError(t, os.WriteFile(keyFile, []byte(`["`+keyB+`","`+keyA+`"]`), 0o600))
	must.NoError(t, cmdA.Process.Signal(syscall.SIGHUP))
	must.NoError(t, cmdB.Process.Signal(syscall.SIGHUP))
	time.Sleep(2 * time.Second)
	must.StrContains(t, wgPeers(a), b.pub)
	must.StrContains(t, wgPeers(b), a.pub)

	must.NoError(t, os.WriteFile(keyFile, []byte(`["`+keyB+`"]`), 0o600))
	must.NoError(t, cmdA.Process.Signal(syscall.SIGHUP))
	must.NoError(t, cmdB.Process.Signal(syscall.SIGHUP))
	time.Sleep(2 * time.Second)
	must.StrContains(t, wgPeers(a), b.pub)
	must.StrContains(t, wgPeers(b), a.pub)
}

func TestMesh_ThreeNodes_TransitiveDiscovery(t *testing.T) {
	skipIfNoNetns(t)
	newBridge(t, "wgm3-br")

	a := newNode(t, "wgm3-a", "10.124.0.1", "fd00:e2e3:a::1", 51820, "wgm3-br")
	b := newNode(t, "wgm3-b", "10.124.0.2", "fd00:e2e3:b::1", 51820, "wgm3-br")
	c := newNode(t, "wgm3-c", "10.124.0.3", "fd00:e2e3:c::1", 51820, "wgm3-br")

	startMesh(t, a, []*node{b}, 51820)
	startMesh(t, b, []*node{a, c}, 51820)
	startMesh(t, c, []*node{b}, 51820)

	waitFor(t, "a discovers c via b", 30*time.Second, func() bool {
		return strings.Contains(wgPeers(a), c.pub) &&
			strings.Contains(wgPeers(c), a.pub)
	})

	runIn(t, a.ns, "ip", "-6", "route", "add", c.overlay+"/128", "dev", "wg0")
	runIn(t, c.ns, "ip", "-6", "route", "add", a.overlay+"/128", "dev", "wg0")
	waitPing(t, a, c.overlay)
}
