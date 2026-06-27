//go:build e2e

package e2e

import (
	"crypto/ed25519"
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
	meshdns "github.com/pigeon-as/pigeon-mesh/internal/dns"
	"github.com/pigeon-as/pigeon-mesh/internal/mesh"
	"github.com/pigeon-as/pigeon-mesh/internal/signature"
	"github.com/shoenig/test/must"
)

var (
	meshBin       string
	meshSigner    ed25519.PrivateKey // package operator signer; auto-provisioned nodes trust it
	meshSignerArg string             // the --signers flag value (base64 signer pubkey)
)

func TestMain(m *testing.M) {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "e2e tests require root, skipping")
		os.Exit(0)
	}
	signerPub, signerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate signer: %v\n", err)
		os.Exit(1)
	}
	meshSigner, meshSignerArg = signerPriv, base64.StdEncoding.EncodeToString(signerPub)
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
	_, pub := genKeypair(t)
	cmd := exec.Command(meshBin,
		"--interface", "wg-nonexistent",
		"--endpoint", "127.0.0.1:51820",
		"--signers", meshSignerArg,
		"--signature", grantFile(t, pub),
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

	priv, pub := genKeypair(t)
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
		"--signers", meshSignerArg,
		"--signature", grantFile(t, pub),
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
		"--signers", meshSignerArg,
		"--signature", grantFile(t, pub),
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
	name := meshdns.SanitizeLabel(host)
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
		"--dns", zone,
		"--signers", meshSignerArg,
		"--signature", grantFile(t, pub),
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

func TestMesh_RouteSelfHeal(t *testing.T) {
	const (
		iface  = "wg-rh"
		port   = 51896
		gossip = 7954
		prefix = "fdcc::/16"
	)
	exec.Command("ip", "link", "del", iface).Run()
	t.Cleanup(func() { exec.Command("ip", "link", "del", iface).Run() })

	priv, pub := genKeypair(t)
	keyFile := writeFile(t, priv+"\n")
	run(t, "ip", "link", "add", iface, "type", "wireguard")
	run(t, "wg", "set", iface, "private-key", keyFile, "listen-port", fmt.Sprint(port))
	run(t, "ip", "link", "set", iface, "up")

	cmd := exec.Command(meshBin,
		"--interface", iface,
		"--endpoint", "203.0.113.1:"+fmt.Sprint(port),
		"--gossip-port", fmt.Sprint(gossip),
		"--prefix", prefix,
		"--signers", meshSignerArg,
		"--signature", grantFile(t, pub),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	must.NoError(t, cmd.Start())
	t.Cleanup(func() { stop(cmd) })

	hasRoute := func() bool {
		out, _ := exec.Command("ip", "-6", "route", "show").CombinedOutput()
		return strings.Contains(string(out), prefix)
	}
	waitFor(t, "daemon installs covering route", 10*time.Second, hasRoute)

	run(t, "ip", "-6", "route", "del", prefix, "dev", iface)
	waitFor(t, "route self-heals within the monitor window, not the 60s reconcile", 3*time.Second, hasRoute)
}

func TestMesh_PrefixReachability(t *testing.T) {
	skipIfNoNetns(t)
	newBridge(t, "wgmpx-br")
	const prefix = "fdcc::/16"

	a := newPrefixNode(t, "wgmpx-a", "10.150.0.1", 51820, "wgmpx-br", prefix)
	b := newPrefixNode(t, "wgmpx-b", "10.150.0.2", 51820, "wgmpx-br", prefix)

	startMesh(t, a, []*node{b}, 51820, "--prefix", prefix)
	startMesh(t, b, []*node{a}, 51820, "--prefix", prefix)

	hasRoute := func(n *node) bool {
		out, _ := exec.Command("ip", "netns", "exec", n.ns, "ip", "-6", "route", "show").CombinedOutput()
		return strings.Contains(string(out), prefix)
	}
	waitFor(t, "daemon installs the covering overlay route, not the harness", 10*time.Second, func() bool {
		return hasRoute(a) && hasRoute(b)
	})

	waitPing(t, a, b.overlay)
	waitPing(t, b, a.overlay)
}

func TestMesh_TwoNodes(t *testing.T) {
	skipIfNoNetns(t)
	newBridge(t, "wgm2-br")
	const prefix = "fdcc::/16"

	a := newPrefixNode(t, "wgm2-a", "10.123.0.1", 51820, "wgm2-br", prefix)
	b := newPrefixNode(t, "wgm2-b", "10.123.0.2", 51820, "wgm2-br", prefix)

	startMesh(t, a, []*node{b}, 51820, "--prefix", prefix)
	startMesh(t, b, []*node{a}, 51820, "--prefix", prefix)

	waitFor(t, "a sees b", 10*time.Second, func() bool {
		return strings.Contains(wgPeers(a), b.pub)
	})
	waitFor(t, "b sees a", 10*time.Second, func() bool {
		return strings.Contains(wgPeers(b), a.pub)
	})

	waitPing(t, a, b.overlay)
	waitPing(t, b, a.overlay)
}

func TestMesh_RestartDoesNotDropPeers(t *testing.T) {
	skipIfNoNetns(t)
	newBridge(t, "wgmr-br")

	const prefix = "fdcc::/16"
	a := newPrefixNode(t, "wgmr-a", "10.132.0.1", 51820, "wgmr-br", prefix)
	b := newPrefixNode(t, "wgmr-b", "10.132.0.2", 51820, "wgmr-br", prefix)
	c := newPrefixNode(t, "wgmr-c", "10.132.0.3", 51820, "wgmr-br", prefix)

	dir := t.TempDir()
	sockA := filepath.Join(dir, "a.sock")
	sockC := filepath.Join(dir, "c.sock")
	startMesh(t, a, []*node{b, c}, 51820, "--socket", sockA, "--prefix", prefix)
	cmdB := startMesh(t, b, []*node{a, c}, 51820, "--prefix", prefix)
	startMesh(t, c, []*node{a, b}, 51820, "--socket", sockC, "--prefix", prefix)

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

	startMesh(t, b, []*node{a, c}, 51820, "--prefix", prefix)
	time.Sleep(3 * time.Second)
	must.StrContains(t, wgPeers(a), b.pub, must.Sprint("A dropped B after restart"))
	must.StrContains(t, wgPeers(c), b.pub, must.Sprint("C dropped B after restart"))
}

func TestMesh_ThreeNodes_TransitiveDiscovery(t *testing.T) {
	skipIfNoNetns(t)
	newBridge(t, "wgm3-br")

	const prefix = "fdcc::/16"
	a := newPrefixNode(t, "wgm3-a", "10.124.0.1", 51820, "wgm3-br", prefix)
	b := newPrefixNode(t, "wgm3-b", "10.124.0.2", 51820, "wgm3-br", prefix)
	c := newPrefixNode(t, "wgm3-c", "10.124.0.3", 51820, "wgm3-br", prefix)

	startMesh(t, a, []*node{b}, 51820, "--prefix", prefix)
	startMesh(t, b, []*node{a, c}, 51820, "--prefix", prefix)
	startMesh(t, c, []*node{b}, 51820, "--prefix", prefix)

	waitFor(t, "a discovers c via b", 30*time.Second, func() bool {
		return strings.Contains(wgPeers(a), c.pub) &&
			strings.Contains(wgPeers(c), a.pub)
	})

	waitPing(t, a, c.overlay)
}

func TestMesh_StatusSocket(t *testing.T) {
	skipIfNoNetns(t)
	newBridge(t, "wgmpf-br")

	const prefix = "fdcc::/16"
	a := newPrefixNode(t, "wgmpf-a", "10.140.0.1", 51820, "wgmpf-br", prefix)
	b := newPrefixNode(t, "wgmpf-b", "10.140.0.2", 51820, "wgmpf-br", prefix)

	sock := filepath.Join(t.TempDir(), "a.sock")
	startMesh(t, a, []*node{b}, 51820, "--socket", sock, "--prefix", prefix)
	startMesh(t, b, []*node{a}, 51820, "--prefix", prefix)

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

func signNode(t *testing.T, signer ed25519.PrivateKey, n *node, ttl time.Duration) string {
	t.Helper()
	sub, err := base64.StdEncoding.DecodeString(n.pub)
	must.NoError(t, err)
	var notAfter int64
	if ttl > 0 {
		notAfter = time.Now().Add(ttl).Unix()
	}
	blob, err := signature.Sign(signer, sub, time.Now().Add(-time.Minute).Unix(), notAfter)
	must.NoError(t, err)
	return writeFile(t, base64.StdEncoding.EncodeToString(blob))
}

// grantFile signs pub with the package signer and returns a --signature file path. Tests that build
// the daemon command directly (not via startMesh) use it together with meshSignerArg for --signers.
func grantFile(t *testing.T, pub string) string {
	t.Helper()
	sub, err := base64.StdEncoding.DecodeString(pub)
	must.NoError(t, err)
	blob, err := signature.Sign(meshSigner, sub, time.Now().Add(-time.Minute).Unix(), time.Now().Add(time.Hour).Unix())
	must.NoError(t, err)
	return writeFile(t, base64.StdEncoding.EncodeToString(blob))
}

func TestMesh_Signature(t *testing.T) {
	skipIfNoNetns(t)
	newBridge(t, "wgmag-br")
	const prefix = "fdcc::/16"

	a := newPrefixNode(t, "wgmag-a", "10.155.0.1", 51820, "wgmag-br", prefix)
	b := newPrefixNode(t, "wgmag-b", "10.155.0.2", 51820, "wgmag-br", prefix)
	c := newPrefixNode(t, "wgmag-c", "10.155.0.3", 51820, "wgmag-br", prefix)

	signerPub, signerPriv, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	signers := base64.StdEncoding.EncodeToString(signerPub)
	sigA := signNode(t, signerPriv, a, time.Hour)
	sigB := signNode(t, signerPriv, b, time.Hour)

	// Unsigned nodes cannot start at all now (--signature is mandatory), so the real admission
	// failure is an UNTRUSTED signer: c is internally consistent under its own rogue signer (so it
	// starts), but a and b trust only signerPub and must reject c's grant as "unknown signer".
	roguePub, roguePriv, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	sigC := signNode(t, roguePriv, c, time.Hour)
	rogueSigners := base64.StdEncoding.EncodeToString(roguePub)

	startMesh(t, a, []*node{b, c}, 51820, "--prefix", prefix, "--signers", signers, "--signature", sigA)
	startMesh(t, b, []*node{a, c}, 51820, "--prefix", prefix, "--signers", signers, "--signature", sigB)
	startMesh(t, c, []*node{a, b}, 51820, "--prefix", prefix, "--signers", rogueSigners, "--signature", sigC)

	waitFor(t, "a and b admit each other on a valid signature", 30*time.Second, func() bool {
		return strings.Contains(wgPeers(a), b.pub) && strings.Contains(wgPeers(b), a.pub)
	})
	waitPing(t, a, b.overlay)

	waitFor(t, "a and b evict c signed by an untrusted key", 30*time.Second, func() bool {
		return !strings.Contains(wgPeers(a), c.pub) && !strings.Contains(wgPeers(b), c.pub)
	})
	time.Sleep(2 * time.Second)
	must.StrNotContains(t, wgPeers(a), c.pub, must.Sprint("a re-admitted untrusted c"))
	must.StrNotContains(t, wgPeers(b), c.pub, must.Sprint("b re-admitted untrusted c"))
}

func TestMesh_SignatureRevocation(t *testing.T) {
	skipIfNoNetns(t)
	newBridge(t, "wgmrev-br")
	const prefix = "fdcc::/16"

	a := newPrefixNode(t, "wgmrev-a", "10.156.0.1", 51820, "wgmrev-br", prefix)
	b := newPrefixNode(t, "wgmrev-b", "10.156.0.2", 51820, "wgmrev-br", prefix)

	signer1pub, signer1priv, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	signer2pub, _, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)

	signersA := filepath.Join(t.TempDir(), "signersA")
	signersB := filepath.Join(t.TempDir(), "signersB")
	must.NoError(t, os.WriteFile(signersA, []byte(base64.StdEncoding.EncodeToString(signer1pub)+"\n"), 0o600))
	must.NoError(t, os.WriteFile(signersB, []byte(base64.StdEncoding.EncodeToString(signer1pub)+"\n"), 0o600))
	sigA := signNode(t, signer1priv, a, time.Hour)
	sigB := signNode(t, signer1priv, b, time.Hour)

	sock := filepath.Join(t.TempDir(), "a.sock")
	cmdA := startMesh(t, a, []*node{b}, 51820, "--prefix", prefix, "--socket", sock,
		"--signers", "@"+signersA, "--signature", sigA)
	startMesh(t, b, []*node{a}, 51820, "--prefix", prefix,
		"--signers", "@"+signersB, "--signature", sigB)

	waitFor(t, "a admits b under signer 1", 30*time.Second, func() bool {
		out, err := exec.Command(meshBin, "status", "--socket", sock, "--json").Output()
		return err == nil && strings.Contains(string(out), b.pub) && strings.Contains(wgPeers(a), b.pub)
	})

	must.NoError(t, os.WriteFile(signersA, []byte(base64.StdEncoding.EncodeToString(signer2pub)+"\n"), 0o600))
	must.NoError(t, cmdA.Process.Signal(syscall.SIGHUP))

	waitFor(t, "a evicts b once b's signer is rotated out", 15*time.Second, func() bool {
		return !strings.Contains(wgPeers(a), b.pub)
	})
}

func TestMesh_DuplicateRouteDropped(t *testing.T) {
	// Conflict resolution is profile-independent, so this 3-node transitive case runs under
	// LAN only. WAN gossip is covered by the 2-node StatusReportsFailedPeer/wan, PeerPolicy/wan
	// and PolicyReload/wan tests; a 3-node WAN transitive convergence needs two WG handshakes
	// to complete, which is unreliable under a loaded WSL2 virtual NIC (the kernel handshake,
	// not the logic). Keeping it on LAN keeps the suite deterministic without dropping WAN
	// coverage. Flip to forEachProfile to also exercise it under WAN on a clean network/CI.
	const profile = "lan"
	const prefix = "fdcc::/16"
	skipIfNoNetns(t)
	newBridge(t, "wgmdup-br")

	a := newPrefixNode(t, "wgmdup-a", "10.144.0.1", 51820, "wgmdup-br", prefix)
	b := newPrefixNode(t, "wgmdup-b", "10.144.0.2", 51820, "wgmdup-br", prefix)
	c := newPrefixNode(t, "wgmdup-c", "10.144.0.3", 51820, "wgmdup-br", prefix)

	// A self-certified identity address cannot be contested (a peer claiming another's derived
	// address is rejected outright at admission). The contestable claim is a SUBNET route two
	// peers both advertise: b and c each assert 10.77.0.0/24, so a installs it for neither.
	const route = "10.77.0.0/24"
	sock := filepath.Join(t.TempDir(), "a.sock")
	startMesh(t, a, []*node{b}, 51820, append([]string{"--prefix", prefix, "--socket", sock}, profileArgs(profile)...)...)
	startMesh(t, b, []*node{a, c}, 51820, append([]string{"--prefix", prefix, "--allowed-ips", route}, profileArgs(profile)...)...)
	startMesh(t, c, []*node{b}, 51820, append([]string{"--prefix", prefix, "--allowed-ips", route}, profileArgs(profile)...)...)

	// tolerant of the socket not being up yet during early polls (must not fatal).
	gossipKnows := func(pub string) bool {
		out, err := exec.Command(meshBin, "status", "--socket", sock, "--json").Output()
		return err == nil && strings.Contains(string(out), pub)
	}
	waitFor(t, "a learns b and c over gossip", convergeTimeout(profile), func() bool {
		return gossipKnows(b.pub) && gossipKnows(c.pub)
	})
	waitFor(t, "a surfaces the contested subnet route", convergeTimeout(profile), func() bool {
		_, ok := decodeStatus(t, sock).Conflicts[route]
		return ok
	})

	// 10.77.0.0/24 is claimed by both b and c; the daemon installs it for neither and surfaces
	// it under conflicts with both claimants.
	st := decodeStatus(t, sock)
	must.SliceContains(t, st.Conflicts[route], b.pub)
	must.SliceContains(t, st.Conflicts[route], c.pub)
	must.StrNotContains(t, wgAllowedIPs(a), route, must.Sprint("the contested route is installed for no peer"))
}

func TestMesh_PeerPolicyRefusesRoute(t *testing.T) {
	forEachProfile(t, func(t *testing.T, profile string) {
		skipIfNoNetns(t)
		newBridge(t, "wgmpol-br")

		const prefix = "fdcc::/16"
		a := newPrefixNode(t, "wgmpol-a", "10.145.0.1", 51820, "wgmpol-br", prefix)
		b := newPrefixNode(t, "wgmpol-b", "10.145.0.2", 51820, "wgmpol-br", prefix)

		sock := filepath.Join(t.TempDir(), "a.sock")
		// a installs only overlay (fd00::/8) routes, so it refuses any IPv4 transit route a peer advertises.
		startMesh(t, a, []*node{b}, 51820, append([]string{"--prefix", prefix, "--socket", sock, "--peer-policy", `cidrSubset("fd00::/8", route)`}, profileArgs(profile)...)...)
		// b advertises an extra IPv4 transit route beyond its identity /128.
		startMesh(t, b, []*node{a}, 51820, append([]string{"--prefix", prefix, "--allowed-ips", "10.99.0.0/24"}, profileArgs(profile)...)...)

		waitFor(t, "a refuses b's transit route", convergeTimeout(profile), func() bool {
			out, err := exec.Command(meshBin, "status", "--socket", sock, "--json").Output()
			return err == nil && strings.Contains(string(out), "10.99.0.0/24")
		})

		// The refused route is keyed under the advertising peer and never reaches the kernel;
		// the identity /128 is exempt from the policy and stays installed.
		st := decodeStatus(t, sock)
		must.SliceContains(t, st.RefusedRoutes[b.pub], "10.99.0.0/24", must.Sprint("refused route is keyed under the advertising peer"))
		must.StrNotContains(t, wgAllowedIPs(a), "10.99.0.0/24", must.Sprint("a route refused by --peer-policy must not reach the kernel"))
		must.StrContains(t, wgAllowedIPs(a), b.overlay, must.Sprint("b's identity route is exempt from policy and stays installed"))
	})
}

func TestMesh_StatusReportsFailedPeer(t *testing.T) {
	forEachProfile(t, func(t *testing.T, profile string) {
		skipIfNoNetns(t)
		newBridge(t, "wgmfail-br")

		prefix := "fdcc::/16"
		a := newPrefixNode(t, "wgmfail-a", "10.146.0.1", 51820, "wgmfail-br", prefix)
		b := newPrefixNode(t, "wgmfail-b", "10.146.0.2", 51820, "wgmfail-br", prefix)

		sock := filepath.Join(t.TempDir(), "a.sock")
		startMesh(t, a, []*node{b}, 51820, append([]string{"--prefix", prefix, "--socket", sock}, profileArgs(profile)...)...)
		bcmd := startMesh(t, b, []*node{a}, 51820, append([]string{"--prefix", prefix}, profileArgs(profile)...)...)

		waitFor(t, "a sees b alive", convergeTimeout(profile), func() bool {
			return peerStatus(sock, b.pub) == "alive"
		})

		// Ungraceful exit (SIGTERM, not a leave): b must be held as "failed", not deleted.
		// This is the whole point of reporting from m.members; memberlist.Members() (the old
		// source) only ever lists alive nodes and could never surface this.
		stop(bcmd)

		waitFor(t, "a marks b failed", convergeTimeout(profile), func() bool {
			return peerStatus(sock, b.pub) == "failed"
		})
		must.StrContains(t, wgPeers(a), b.pub, must.Sprint("a failed-but-not-reaped peer's tunnel is held through --reconnect-timeout"))
	})
}

func TestMesh_PolicyReloadEvictsAndRestores(t *testing.T) {
	forEachProfile(t, func(t *testing.T, profile string) {
		skipIfNoNetns(t)
		newBridge(t, "wgmrel-br")

		const prefix = "fdcc::/16"
		a := newPrefixNode(t, "wgmrel-a", "10.148.0.1", 51820, "wgmrel-br", prefix)
		b := newPrefixNode(t, "wgmrel-b", "10.148.0.2", 51820, "wgmrel-br", prefix)

		sock := filepath.Join(t.TempDir(), "a.sock")
		policyFile := filepath.Join(t.TempDir(), "policy")
		must.NoError(t, os.WriteFile(policyFile, []byte("true"), 0o600)) // accept all
		acmd := startMesh(t, a, []*node{b}, 51820, append([]string{"--prefix", prefix, "--socket", sock, "--peer-policy", "@" + policyFile}, profileArgs(profile)...)...)
		startMesh(t, b, []*node{a}, 51820, append([]string{"--prefix", prefix, "--allowed-ips", "10.77.0.0/24"}, profileArgs(profile)...)...)

		waitFor(t, "a installs b's transit route under accept-all", convergeTimeout(profile), func() bool {
			return strings.Contains(wgAllowedIPs(a), "10.77.0.0/24")
		})

		// Reload to a stricter policy that refuses IPv4: the route is evicted from the kernel
		// and surfaced as refused.
		must.NoError(t, os.WriteFile(policyFile, []byte(`cidrSubset("fd00::/8", route)`), 0o600))
		must.NoError(t, acmd.Process.Signal(syscall.SIGHUP))
		waitFor(t, "a stricter reload evicts the route", convergeTimeout(profile), func() bool {
			return !strings.Contains(wgAllowedIPs(a), "10.77.0.0/24")
		})
		must.SliceContains(t, decodeStatus(t, sock).RefusedRoutes[b.pub], "10.77.0.0/24")

		// Reload to an empty policy (=> nil): the previously-refused route must be restored.
		// Guards the reevaluate early-return fix at the e2e level.
		must.NoError(t, os.WriteFile(policyFile, []byte(""), 0o600))
		must.NoError(t, acmd.Process.Signal(syscall.SIGHUP))
		waitFor(t, "removing the policy restores the route", convergeTimeout(profile), func() bool {
			return strings.Contains(wgAllowedIPs(a), "10.77.0.0/24")
		})
	})
}

func TestMesh_LeaveRemovesOverlayButSigtermKeepsIt(t *testing.T) {
	// Graceful leave undoes the overlay address+route the daemon assigned under --prefix;
	// a restartable SIGTERM leaves them in place so a restart survives.
	prefix := "fdcc::/16"
	addrShow := func(n *node) string { return runIn(t, n.ns, "ip", "-6", "addr", "show", "wg0") }
	routeShow := func(n *node) string { return runIn(t, n.ns, "ip", "-6", "route", "show", "dev", "wg0") }

	t.Run("leave-removes", func(t *testing.T) {
		skipIfNoNetns(t)
		newBridge(t, "wgmlv-br")
		a := newPrefixNode(t, "wgmlv-a", "10.149.0.1", 51820, "wgmlv-br", prefix)
		b := newPrefixNode(t, "wgmlv-b", "10.149.0.2", 51820, "wgmlv-br", prefix)
		sock := filepath.Join(t.TempDir(), "a.sock")
		startMesh(t, a, []*node{b}, 51820, "--prefix", prefix, "--socket", sock)
		startMesh(t, b, []*node{a}, 51820, "--prefix", prefix)

		waitFor(t, "a assigns its overlay addr and prefix route", 15*time.Second, func() bool {
			return strings.Contains(addrShow(a), a.overlay) && strings.Contains(routeShow(a), prefix)
		})
		run(t, meshBin, "leave", "--socket", sock)
		waitFor(t, "leave removes the overlay addr and route", 10*time.Second, func() bool {
			return !strings.Contains(addrShow(a), a.overlay) && !strings.Contains(routeShow(a), prefix)
		})
	})

	t.Run("sigterm-keeps", func(t *testing.T) {
		skipIfNoNetns(t)
		newBridge(t, "wgmlv-br")
		a := newPrefixNode(t, "wgmlv-a", "10.149.0.1", 51820, "wgmlv-br", prefix)
		b := newPrefixNode(t, "wgmlv-b", "10.149.0.2", 51820, "wgmlv-br", prefix)
		acmd := startMesh(t, a, []*node{b}, 51820, "--prefix", prefix)
		startMesh(t, b, []*node{a}, 51820, "--prefix", prefix)

		waitFor(t, "a assigns its overlay addr and prefix route", 15*time.Second, func() bool {
			return strings.Contains(addrShow(a), a.overlay) && strings.Contains(routeShow(a), prefix)
		})
		stop(acmd) // SIGTERM + wait for exit
		must.StrContains(t, addrShow(a), a.overlay, must.Sprint("SIGTERM keeps the overlay addr so a restart survives"))
		must.StrContains(t, routeShow(a), prefix, must.Sprint("SIGTERM keeps the overlay route so a restart survives"))
	})
}

func TestMesh_SelfSignatureExpiryHaltsDNS(t *testing.T) {
	const (
		iface  = "wg-selfexp"
		port   = 51895
		gossip = 7957
		zone   = "mesh.internal"
		prefix = "fdcc::/16"
	)
	exec.Command("ip", "link", "del", iface).Run()
	t.Cleanup(func() { exec.Command("ip", "link", "del", iface).Run() })

	priv, pub := genKeypair(t)
	overlay, err := mesh.DeriveAddr(pub, netip.MustParsePrefix(prefix))
	must.NoError(t, err)
	keyFile := writeFile(t, priv+"\n")
	run(t, "ip", "link", "add", iface, "type", "wireguard")
	run(t, "wg", "set", iface, "private-key", keyFile, "listen-port", fmt.Sprint(port))
	run(t, "ip", "link", "set", iface, "up")

	signerPub, signerPriv, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	sub, err := base64.StdEncoding.DecodeString(pub)
	must.NoError(t, err)
	// short-lived self grant: valid now, expires in ~18s.
	blob, err := signature.Sign(signerPriv, sub, time.Now().Add(-time.Minute).Unix(), time.Now().Add(18*time.Second).Unix())
	must.NoError(t, err)
	sigFile := writeFile(t, base64.StdEncoding.EncodeToString(blob))

	sock := filepath.Join(t.TempDir(), "a.sock")
	cmd := exec.Command(meshBin,
		"--interface", iface,
		"--endpoint", fmt.Sprintf("[%s]:%d", overlay, port),
		"--prefix", prefix,
		"--gossip-port", fmt.Sprint(gossip),
		"--dns", zone,
		"--tag", "name=alpha",
		"--signers", base64.StdEncoding.EncodeToString(signerPub),
		"--signature", sigFile,
		"--socket", sock,
	)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	must.NoError(t, cmd.Start())
	t.Cleanup(func() { stop(cmd) })

	server := net.JoinHostPort(overlay.String(), "53")
	queryAAAA := func() *dns.Msg {
		c := &dns.Client{Timeout: 2 * time.Second}
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn("alpha."+zone), dns.TypeAAAA)
		resp, _, _ := c.Exchange(msg, server)
		return resp
	}

	// While the self grant is valid, the node serves its own name.
	waitFor(t, "self serves its own name while signed", 15*time.Second, func() bool {
		resp := queryAAAA()
		if resp == nil || len(resp.Answer) == 0 {
			return false
		}
		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		return ok && aaaa.AAAA.String() == overlay.String()
	})

	// After expiry the node flips itself to rejected in status AND stops serving its own
	// DNS name (status reflects selfReject immediately; DNS halts on the next expiry sweep).
	waitFor(t, "self signature expiry flips status and halts self DNS", 40*time.Second, func() bool {
		rejected := decodeStatus(t, sock).Rejected[pub] != ""
		resp := queryAAAA()
		silent := resp == nil || len(resp.Answer) == 0
		return rejected && silent
	})
}

// TestMesh_SelfGrantRenewal is the inverse of the expiry test: a node on a short grant that is
// re-signed and SIGHUP'd before expiry must stay healthy (admitted + serving its own DNS) past the
// point a non-renewed node would have halted -- hitless, no restart.
func TestMesh_SelfGrantRenewal(t *testing.T) {
	const (
		iface  = "wg-renew"
		port   = 51896
		gossip = 7958
		zone   = "mesh.internal"
		prefix = "fdcc::/16"
	)
	exec.Command("ip", "link", "del", iface).Run()
	t.Cleanup(func() { exec.Command("ip", "link", "del", iface).Run() })

	priv, pub := genKeypair(t)
	overlay, err := mesh.DeriveAddr(pub, netip.MustParsePrefix(prefix))
	must.NoError(t, err)
	keyFile := writeFile(t, priv+"\n")
	run(t, "ip", "link", "add", iface, "type", "wireguard")
	run(t, "wg", "set", iface, "private-key", keyFile, "listen-port", fmt.Sprint(port))
	run(t, "ip", "link", "set", iface, "up")

	signerPub, signerPriv, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	sub, err := base64.StdEncoding.DecodeString(pub)
	must.NoError(t, err)
	grant := func(ttl time.Duration) string {
		blob, err := signature.Sign(signerPriv, sub, time.Now().Add(-time.Minute).Unix(), time.Now().Add(ttl).Unix())
		must.NoError(t, err)
		return base64.StdEncoding.EncodeToString(blob)
	}
	// short-lived self grant: expires in ~15s; the file is rewritten on renewal.
	sigFile := writeFile(t, grant(15*time.Second))

	sock := filepath.Join(t.TempDir(), "a.sock")
	cmd := exec.Command(meshBin,
		"--interface", iface,
		"--endpoint", fmt.Sprintf("[%s]:%d", overlay, port),
		"--prefix", prefix,
		"--gossip-port", fmt.Sprint(gossip),
		"--dns", zone,
		"--tag", "name=alpha",
		"--signers", base64.StdEncoding.EncodeToString(signerPub),
		"--signature", sigFile,
		"--socket", sock,
	)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	must.NoError(t, cmd.Start())
	t.Cleanup(func() { stop(cmd) })

	server := net.JoinHostPort(overlay.String(), "53")
	servesSelf := func() bool {
		c := &dns.Client{Timeout: 2 * time.Second}
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn("alpha."+zone), dns.TypeAAAA)
		resp, _, _ := c.Exchange(msg, server)
		if resp == nil || len(resp.Answer) == 0 {
			return false
		}
		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		return ok && aaaa.AAAA.String() == overlay.String()
	}

	waitFor(t, "self serves its own name on the short grant", 15*time.Second, servesSelf)

	// renew well before expiry: overwrite the grant file with a long-lived one and SIGHUP.
	must.NoError(t, os.WriteFile(sigFile, []byte(grant(time.Hour)), 0o600))
	must.NoError(t, cmd.Process.Signal(syscall.SIGHUP))

	// Past the original 15s expiry and at least one maintain sweep, the renewed node never flips to
	// rejected (this is exactly when the expiry test halts) and still serves its own name.
	deadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		must.EqOp(t, "", decodeStatus(t, sock).Rejected[pub], must.Sprint("a renewed grant never flips self to expired"))
		time.Sleep(3 * time.Second)
	}
	waitFor(t, "renewed grant keeps self DNS serving past the original expiry", 5*time.Second, servesSelf)
}
