//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pigeon-as/pigeon-mesh/internal/mesh"
	"github.com/shoenig/test/must"
)

// profileArgs returns the --profile flag for a memberlist profile; "" is the WAN
// default (no flag), which is what most deployments run, so it must stay covered.
func profileArgs(p string) []string {
	if p == "" {
		return nil
	}
	return []string{"--profile", p}
}

// convergeTimeout bounds gossip convergence per profile. The LAN bound stays well under
// the WAN one so a LAN run that silently degrades to WAN timing still shows up as slow,
// but it carries enough headroom to survive cumulative netns load late in a full suite
// run. WAN allows a full ~30s push/pull cycle plus slack.
func convergeTimeout(p string) time.Duration {
	if p == "lan" {
		return 45 * time.Second
	}
	// WAN: a full push/pull cycle (~30s) plus generous headroom for WG-handshake establishment
	// under a loaded WSL2 virtual NIC late in a full suite run. Fast tests finish early, so this
	// only stretches the genuinely-slow ones; it does not slow the common case.
	return 75 * time.Second
}

// forEachProfile runs body under WAN (default) and LAN as subtests, so one scenario
// exercises both without duplication.
func forEachProfile(t *testing.T, body func(t *testing.T, profile string)) {
	t.Helper()
	for _, p := range []string{"", "lan"} {
		name := "wan"
		if p != "" {
			name = p
		}
		t.Run(name, func(t *testing.T) { body(t, p) })
	}
}

// decodeStatus reads the daemon's status socket and decodes it into mesh.Status, so
// tests assert exact fields (Peers[pub].Status, Conflicts, RefusedRoutes) instead of
// substring-matching the raw JSON blob. Fatals on error: use only after convergence,
// when the socket is up; use peerStatus for tolerant polling.
func decodeStatus(t *testing.T, sock string) mesh.Status {
	t.Helper()
	out, err := exec.Command(meshBin, "status", "--socket", sock, "--json").Output()
	must.NoError(t, err)
	var st mesh.Status
	must.NoError(t, json.Unmarshal(out, &st))
	return st
}

// peerStatus returns the SWIM status of pub, or "" if the socket/peer isn't available
// yet. Tolerant (never fatals), so it is safe inside a waitFor poll before the daemon is up.
func peerStatus(sock, pub string) string {
	out, err := exec.Command(meshBin, "status", "--socket", sock, "--json").Output()
	if err != nil {
		return ""
	}
	var st mesh.Status
	if json.Unmarshal(out, &st) != nil {
		return ""
	}
	return st.Peers[pub].Status
}

type node struct {
	ns       string
	underlay string
	overlay  string
	pub      string
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	must.NoError(t, err, must.Sprintf("command: %s %s, output: %s", name, strings.Join(args, " "), out))
	return strings.TrimSpace(string(out))
}

func runIn(t *testing.T, ns, name string, args ...string) string {
	t.Helper()
	return run(t, "ip", append([]string{"netns", "exec", ns, name}, args...)...)
}

func genKeypair(t *testing.T) (priv, pub string) {
	t.Helper()
	pk, err := exec.Command("wg", "genkey").Output()
	must.NoError(t, err)
	priv = strings.TrimSpace(string(pk))

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(priv + "\n")
	pkb, err := cmd.Output()
	must.NoError(t, err)
	return priv, strings.TrimSpace(string(pkb))
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	must.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func stop(cmd *exec.Cmd) {
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		<-done
	}
}

func skipIfNoNetns(t *testing.T) {
	t.Helper()
	probe := fmt.Sprintf("wgm-probe-%d", time.Now().UnixNano())
	if err := exec.Command("ip", "netns", "add", probe).Run(); err != nil {
		t.Skipf("requires netns privileges: %v", err)
	}
	exec.Command("ip", "netns", "del", probe).Run()
}

func newBridge(t *testing.T, name string) {
	t.Helper()
	exec.Command("ip", "link", "del", name).Run()
	run(t, "ip", "link", "add", name, "type", "bridge")
	run(t, "ip", "link", "set", name, "up")
	t.Cleanup(func() { exec.Command("ip", "link", "del", name).Run() })
}

func newPrefixNode(t *testing.T, name, underlay string, port int, bridge, prefix string) *node {
	t.Helper()
	hostVeth, nsVeth := name+"-vh", name+"-vn"
	exec.Command("ip", "netns", "del", name).Run()
	exec.Command("ip", "link", "del", hostVeth).Run()

	run(t, "ip", "netns", "add", name)
	runIn(t, name, "ip", "link", "set", "lo", "up")

	run(t, "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth)
	run(t, "ip", "link", "set", hostVeth, "master", bridge)
	run(t, "ip", "link", "set", hostVeth, "up")
	run(t, "ip", "link", "set", nsVeth, "netns", name)
	runIn(t, name, "ip", "addr", "add", underlay+"/24", "dev", nsVeth)
	runIn(t, name, "ip", "link", "set", nsVeth, "up")

	priv, pub := genKeypair(t)
	overlay, err := mesh.DeriveAddr(pub, netip.MustParsePrefix(prefix))
	must.NoError(t, err)
	keyFile := writeFile(t, priv+"\n")
	runIn(t, name, "ip", "link", "add", "wg0", "type", "wireguard")
	runIn(t, name, "wg", "set", "wg0", "private-key", keyFile, "listen-port", fmt.Sprint(port))
	runIn(t, name, "ip", "link", "set", "wg0", "up")

	t.Cleanup(func() {
		exec.Command("ip", "netns", "del", name).Run()
		exec.Command("ip", "link", "del", hostVeth).Run()
	})

	return &node{ns: name, underlay: underlay, overlay: overlay.String(), pub: pub}
}

func startMesh(t *testing.T, n *node, peers []*node, port int, extraArgs ...string) *exec.Cmd {
	t.Helper()
	// --signature is mandatory; the node derives its trust anchor from it (no --signers needed).
	// Provision a grant from the package signer unless the test manages signing itself.
	if !slices.Contains(extraArgs, "--signature") {
		extraArgs = append([]string{"--signature", grantFile(t, n.pub)}, extraArgs...)
	}
	// Prefix mode is the only addressing model: kernel peers carry just an endpoint, and the
	// daemon's adoptKernelPeers derives and installs each peer's overlay /128.
	for _, p := range peers {
		runIn(t, n.ns, "wg", "set", "wg0", "peer", p.pub,
			"endpoint", fmt.Sprintf("%s:%d", p.underlay, port))
	}

	args := []string{"netns", "exec", n.ns, meshBin,
		"--interface", "wg0",
		"--endpoint", fmt.Sprintf("%s:%d", n.underlay, port),
	}
	args = append(args, extraArgs...)
	cmd := exec.Command("ip", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	must.NoError(t, cmd.Start())
	t.Cleanup(func() { stop(cmd) })
	return cmd
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s (after %s)", what, timeout)
}

func wgPeers(n *node) string {
	out, _ := exec.Command("ip", "netns", "exec", n.ns, "wg", "show", "wg0", "peers").CombinedOutput()
	return string(out)
}

func wgAllowedIPs(n *node) string {
	out, _ := exec.Command("ip", "netns", "exec", n.ns, "wg", "show", "wg0", "allowed-ips").CombinedOutput()
	return string(out)
}

func waitPing(t *testing.T, src *node, dst string) {
	t.Helper()
	waitFor(t, fmt.Sprintf("ping %s → %s", src.ns, dst), 30*time.Second, func() bool {
		return exec.Command("ip", "netns", "exec", src.ns, "ping", "-6", "-c", "1", "-W", "2", dst).Run() == nil
	})
}
