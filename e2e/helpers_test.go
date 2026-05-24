//go:build e2e

package e2e

import (
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

func newNode(t *testing.T, name, underlay, overlay string, port int, bridge string) *node {
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
	keyFile := writeFile(t, priv+"\n")
	runIn(t, name, "ip", "link", "add", "wg0", "type", "wireguard")
	runIn(t, name, "wg", "set", "wg0", "private-key", keyFile, "listen-port", fmt.Sprint(port))
	runIn(t, name, "ip", "-6", "addr", "add", overlay+"/128", "dev", "wg0")
	runIn(t, name, "ip", "link", "set", "wg0", "up")

	t.Cleanup(func() {
		exec.Command("ip", "netns", "del", name).Run()
		exec.Command("ip", "link", "del", hostVeth).Run()
	})

	return &node{ns: name, underlay: underlay, overlay: overlay, pub: pub}
}

func startMesh(t *testing.T, n *node, peers []*node, port int, extraArgs ...string) *exec.Cmd {
	t.Helper()
	for _, p := range peers {
		runIn(t, n.ns, "wg", "set", "wg0", "peer", p.pub,
			"endpoint", fmt.Sprintf("%s:%d", p.underlay, port),
			"allowed-ips", p.overlay+"/128")
		runIn(t, n.ns, "ip", "-6", "route", "add", p.overlay+"/128", "dev", "wg0")
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

func waitPing(t *testing.T, src *node, dst string) {
	t.Helper()
	waitFor(t, fmt.Sprintf("ping %s → %s", src.ns, dst), 30*time.Second, func() bool {
		return exec.Command("ip", "netns", "exec", src.ns, "ping", "-6", "-c", "1", "-W", "2", dst).Run() == nil
	})
}
