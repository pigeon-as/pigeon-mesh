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

	"github.com/miekg/dns"
	"github.com/pigeon-as/pigeon-mesh/internal/mesh"
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

func TestPrefixSetsAddress(t *testing.T) {
	const (
		iface  = "wg-pfx"
		port   = 51898
		gossip = 7952
		prefix = "fdcc::/16"
	)
	exec.Command("ip", "link", "del", iface).Run()
	t.Cleanup(func() { exec.Command("ip", "link", "del", iface).Run() })

	priv, pub := genKeypair(t)
	keyFile := writeFile(t, priv+"\n")
	run(t, "ip", "link", "add", iface, "type", "wireguard")
	run(t, "wg", "set", iface, "private-key", keyFile, "listen-port", fmt.Sprint(port))
	run(t, "ip", "link", "set", iface, "up")

	want, err := mesh.DeriveAddr(pub, netip.MustParsePrefix(prefix))
	must.NoError(t, err)

	cmd := exec.Command(meshBin,
		"--interface", iface,
		"--endpoint", fmt.Sprintf("[%s]:%d", want, port),
		"--gossip-port", fmt.Sprint(gossip),
		"--prefix", prefix,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	must.NoError(t, cmd.Start())
	t.Cleanup(func() { stop(cmd) })

	waitFor(t, "daemon assigned derived address", 10*time.Second, func() bool {
		out, _ := exec.Command("ip", "-6", "addr", "show", iface).CombinedOutput()
		return strings.Contains(string(out), want.String())
	})
	must.StrContains(t, run(t, "ip", "-6", "addr", "show", iface), want.String())
}

func TestMesh_DNS(t *testing.T) {
	const (
		iface  = "wg-dns"
		port   = 51897
		gossip = 7953
		prefix = "fdcc::/16"
		zone   = "mesh.internal"
	)
	host, _ := os.Hostname()
	name := mesh.SanitizeLabel(host)
	if name == "" {
		t.Skip("hostname is not a usable DNS label")
	}
	exec.Command("ip", "link", "del", iface).Run()
	t.Cleanup(func() { exec.Command("ip", "link", "del", iface).Run() })

	priv, pub := genKeypair(t)
	keyFile := writeFile(t, priv+"\n")
	run(t, "ip", "link", "add", iface, "type", "wireguard")
	run(t, "wg", "set", iface, "private-key", keyFile, "listen-port", fmt.Sprint(port))
	run(t, "ip", "link", "set", iface, "up")

	want, err := mesh.DeriveAddr(pub, netip.MustParsePrefix(prefix))
	must.NoError(t, err)

	cmd := exec.Command(meshBin,
		"--interface", iface,
		"--endpoint", fmt.Sprintf("[%s]:%d", want, port),
		"--gossip-port", fmt.Sprint(gossip),
		"--prefix", prefix,
		"--dns",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	must.NoError(t, cmd.Start())
	t.Cleanup(func() { stop(cmd) })

	server := net.JoinHostPort(want.String(), "53")
	query := func(qname string) (*dns.Msg, error) {
		c := &dns.Client{Timeout: 2 * time.Second}
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(qname), dns.TypeAAAA)
		resp, _, err := c.Exchange(msg, server)
		return resp, err
	}

	waitFor(t, "resolver answers its own name", 15*time.Second, func() bool {
		resp, err := query(name + "." + zone)
		if err != nil || len(resp.Answer) == 0 {
			return false
		}
		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		return ok && aaaa.AAAA.String() == want.String()
	})

	resp, err := query("nope." + zone)
	must.NoError(t, err)
	must.EqOp(t, dns.RcodeNameError, resp.Rcode)
	must.SliceLen(t, 0, resp.Answer)
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

func TestMesh_RestartDoesNotDropPeers(t *testing.T) {
	skipIfNoNetns(t)
	newBridge(t, "wgmr-br")

	a := newNode(t, "wgmr-a", "10.132.0.1", "fd00:dead:a::1", 51820, "wgmr-br")
	b := newNode(t, "wgmr-b", "10.132.0.2", "fd00:dead:b::1", 51820, "wgmr-br")
	c := newNode(t, "wgmr-c", "10.132.0.3", "fd00:dead:c::1", 51820, "wgmr-br")

	dir := t.TempDir()
	sockA := filepath.Join(dir, "a.sock")
	sockC := filepath.Join(dir, "c.sock")
	startMesh(t, a, []*node{b, c}, 51820, "--socket", sockA)
	cmdB := startMesh(t, b, []*node{a, c}, 51820)
	startMesh(t, c, []*node{a, b}, 51820, "--socket", sockC)

	gossipHasB := func(sock string) bool {
		out, err := exec.Command(meshBin, "status", "--socket", sock, "--json").Output()
		return err == nil && strings.Contains(string(out), b.overlay)
	}
	waitFor(t, "A and C learn B over gossip", 30*time.Second, func() bool {
		return gossipHasB(sockA) && gossipHasB(sockC)
	})

	must.NoError(t, cmdB.Process.Signal(syscall.SIGTERM))
	cmdB.Wait()

	must.StrContains(t, wgPeers(a), b.pub, must.Sprint("A dropped B immediately after SIGTERM"))
	must.StrContains(t, wgPeers(c), b.pub, must.Sprint("C dropped B immediately after SIGTERM"))

	time.Sleep(3 * time.Second)
	must.StrContains(t, wgPeers(a), b.pub, must.Sprint("A dropped B during 3s gap"))
	must.StrContains(t, wgPeers(c), b.pub, must.Sprint("C dropped B during 3s gap"))

	startMesh(t, b, []*node{a, c}, 51820)
	time.Sleep(3 * time.Second)
	must.StrContains(t, wgPeers(a), b.pub, must.Sprint("A dropped B after restart"))
	must.StrContains(t, wgPeers(c), b.pub, must.Sprint("C dropped B after restart"))
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

func TestMesh_StatusSocket(t *testing.T) {
	skipIfNoNetns(t)
	newBridge(t, "wgmpf-br")

	a := newNode(t, "wgmpf-a", "10.140.0.1", "fd00:e2ef:a::1", 51820, "wgmpf-br")
	b := newNode(t, "wgmpf-b", "10.140.0.2", "fd00:e2ef:b::1", 51820, "wgmpf-br")

	sock := filepath.Join(t.TempDir(), "a.sock")
	startMesh(t, a, []*node{b}, 51820, "--socket", sock)
	startMesh(t, b, []*node{a}, 51820)

	status := func() ([]byte, error) {
		return exec.Command(meshBin, "status", "--socket", sock, "--json").Output()
	}
	waitFor(t, "status reports b", 30*time.Second, func() bool {
		out, err := status()
		return err == nil && strings.Contains(string(out), b.pub)
	})

	out, err := status()
	must.NoError(t, err)
	var st struct {
		Self  string                    `json:"self"`
		Peers map[string]map[string]any `json:"peers"`
	}
	must.NoError(t, json.Unmarshal(out, &st))
	must.EqOp(t, a.pub, st.Self)
	must.MapContainsKey(t, st.Peers, b.pub)
	must.EqOp(t, "alive", st.Peers[b.pub]["status"])
}

func TestMesh_DuplicateRouteDropped(t *testing.T) {
	skipIfNoNetns(t)
	newBridge(t, "wgmdup-br")

	a := newNode(t, "wgmdup-a", "10.144.0.1", "fd00:e2ed:a::1", 51820, "wgmdup-br")
	b := newNode(t, "wgmdup-b", "10.144.0.2", "fd00:e2ed:b::1", 51820, "wgmdup-br")
	c := newNode(t, "wgmdup-c", "10.144.0.3", "fd00:e2ed:c::1", 51820, "wgmdup-br")

	sock := filepath.Join(t.TempDir(), "a.sock")
	startMesh(t, a, []*node{b}, 51820, "--socket", sock)
	startMesh(t, b, []*node{a, c}, 51820)
	startMesh(t, c, []*node{b}, 51820, "--advertise-routes", b.overlay+"/128")

	gossipKnows := func(pub string) bool {
		out, err := exec.Command(meshBin, "status", "--socket", sock, "--json").Output()
		return err == nil && strings.Contains(string(out), pub)
	}
	waitFor(t, "a learns b and c over gossip", 30*time.Second, func() bool {
		return gossipKnows(b.pub) && gossipKnows(c.pub)
	})
	waitFor(t, "a drops b's contested route", 15*time.Second, func() bool {
		return !strings.Contains(wgPeers(a), b.pub)
	})

	out, err := exec.Command(meshBin, "status", "--socket", sock, "--json").Output()
	must.NoError(t, err)
	must.StrContains(t, string(out), b.overlay,
		must.Sprint("the conflicting route must be surfaced in status"))
}
