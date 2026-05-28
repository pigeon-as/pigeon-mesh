//go:build perf

package perf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

const staggerInterval = 25 * time.Millisecond

var (
	meshBin string
	clkTck  float64
)

func TestMain(m *testing.M) {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "perf tests require root, skipping")
		os.Exit(0)
	}
	for _, kv := range []struct{ k, v string }{
		{"net.bridge.bridge-nf-call-iptables", "0"},
		{"net.bridge.bridge-nf-call-ip6tables", "0"},
		{"net.ipv4.neigh.default.gc_thresh1", "8192"},
		{"net.ipv4.neigh.default.gc_thresh2", "16384"},
		{"net.ipv4.neigh.default.gc_thresh3", "32768"},
		{"net.ipv6.neigh.default.gc_thresh1", "8192"},
		{"net.ipv6.neigh.default.gc_thresh2", "16384"},
		{"net.ipv6.neigh.default.gc_thresh3", "32768"},
	} {
		if out, err := exec.Command("sysctl", "-w", kv.k+"="+kv.v).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "sysctl %s=%s: %v: %s\n", kv.k, kv.v, err, out)
		}
	}
	if err := exec.Command("ip", "link", "add", "wg-probe", "type", "wireguard").Run(); err != nil {
		fmt.Fprintf(os.Stderr, "wireguard not available: %v\n", err)
		os.Exit(0)
	}
	exec.Command("ip", "link", "del", "wg-probe").Run()

	exec.Command("modprobe", "sch_netem").Run()

	clkTck = 100
	if out, err := exec.Command("getconf", "CLK_TCK").Output(); err == nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64); err == nil && v > 0 {
			clkTck = v
		}
	}

	meshBin = filepath.Join("..", "build", "wg-mesh")
	if _, err := os.Stat(meshBin); err != nil {
		p, err := exec.LookPath("wg-mesh")
		if err != nil {
			fmt.Fprintln(os.Stderr, "wg-mesh binary not found (run 'make build' first)")
			os.Exit(1)
		}
		meshBin = p
	}

	sweepStaleClusters()

	os.Exit(m.Run())
}

func sweepStaleClusters() {
	exec.Command("pkill", "-9", "-f", meshBin).Run()

	out, _ := exec.Command("ip", "netns", "list").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && strings.HasPrefix(fields[0], "wgp") {
			exec.Command("ip", "netns", "del", fields[0]).Run()
		}
	}

	out, _ = exec.Command("ip", "-o", "link", "show").Output()
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			continue
		}
		if name, _, _ := strings.Cut(strings.TrimSpace(parts[1]), "@"); strings.HasPrefix(name, "wgp") {
			exec.Command("ip", "link", "del", name).Run()
		}
	}
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
	probe := fmt.Sprintf("perf-probe-%d", time.Now().UnixNano())
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
	runIn(t, name, "ip", "addr", "add", underlay+"/16", "dev", nsVeth)
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

func waitFor(t *testing.T, what string, timeout, interval time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(interval)
	}
	t.Fatalf("timeout waiting for: %s (after %s)", what, timeout)
}

func wgPeers(n *node) string {
	out, _ := exec.Command("ip", "netns", "exec", n.ns, "wg", "show", "wg0", "peers").CombinedOutput()
	return string(out)
}

func applyLatency(t *testing.T, n *node, ms int) {
	t.Helper()
	if ms <= 0 {
		return
	}
	runIn(t, n.ns, "tc", "qdisc", "add", "dev", n.ns+"-vn", "root", "netem", "delay", fmt.Sprintf("%dms", ms))
}

var clusterSeq atomic.Uint32

const (
	nodesPerCore = 25
	procBytes    = 16 << 20
	napiBytes    = 20 << 10
	memBudgetNum = 6
	memBudgetDen = 10
)

func safeMaxNodes() int {
	cpuCap := nodesPerCore * runtime.NumCPU()
	memKB := memTotalKB()
	if memKB <= 0 {
		return cpuCap
	}
	budget := int64(memKB) * 1024 * memBudgetNum / memBudgetDen
	memCap := 0
	for n := 1; ; n++ {
		need := int64(n)*procBytes + int64(n)*int64(n-1)*napiBytes
		if need > budget {
			break
		}
		memCap = n
	}
	if memCap < cpuCap {
		return memCap
	}
	return cpuCap
}

func memTotalKB() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			if f := strings.Fields(line); len(f) >= 2 {
				kb, _ := strconv.Atoi(f[1])
				return kb
			}
		}
	}
	return 0
}

func buildCluster(t *testing.T, port, n int) []*node {
	t.Helper()
	skipIfNoNetns(t)
	id := clusterSeq.Add(1)
	bridge := fmt.Sprintf("wgpbr%x", id)
	newBridge(t, bridge)

	nodes := make([]*node, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("wgp%x-%d", id, i)
		underlay := fmt.Sprintf("10.200.%d.%d", i/250, i%250+1)
		overlay := fmt.Sprintf("fd00:%x::%x", id, i+1)
		nodes[i] = newNode(t, name, underlay, overlay, port, bridge)
	}
	route := fmt.Sprintf("fd00:%x::/64", id)
	for _, nd := range nodes {
		runIn(t, nd.ns, "ip", "-6", "route", "replace", route, "dev", "wg0")
	}
	return nodes
}

func bootstrap(t *testing.T, nodes []*node, port, seedCount int, extraArgs ...string) []*exec.Cmd {
	t.Helper()
	seeds := nodes
	if len(nodes) > seedCount {
		seeds = nodes[:seedCount]
	}
	isSeed := make(map[*node]bool, len(seeds))
	for _, s := range seeds {
		isSeed[s] = true
	}
	cmds := make([]*exec.Cmd, len(nodes))
	for i, n := range nodes {
		var boot []*node
		if isSeed[n] {
			for _, other := range nodes {
				if other != n {
					boot = append(boot, other)
				}
			}
		} else {
			boot = seeds
		}
		cmds[i] = startMesh(t, n, boot, port, extraArgs...)
		time.Sleep(staggerInterval)
	}
	return cmds
}

func waitConverged(t *testing.T, nodes []*node, timeout time.Duration) {
	t.Helper()
	waitFor(t, fmt.Sprintf("all %d see all peers", len(nodes)), timeout, 2*time.Second, func() bool {
		peerLists := make([]string, len(nodes))
		var wg sync.WaitGroup
		for i, src := range nodes {
			wg.Add(1)
			go func(i int, src *node) {
				defer wg.Done()
				peerLists[i] = wgPeers(src)
			}(i, src)
		}
		wg.Wait()
		for i, src := range nodes {
			for _, dst := range nodes {
				if src == dst {
					continue
				}
				if !strings.Contains(peerLists[i], dst.pub) {
					return false
				}
			}
		}
		return true
	})
}

type measurement struct {
	n           int
	convergence time.Duration
	cpuAvg      float64
	cpuMax      float64
	rssAvgMB    float64
	rssMaxMB    float64
	rxKBps      float64
	txKBps      float64
	rxPps       float64
	txPps       float64
}

func (m measurement) String() string {
	return fmt.Sprintf("N=%d converge=%v cpu_avg=%.2f%% cpu_max=%.2f%% rss_avg=%.1fMB rss_max=%.1fMB rx_avg=%.2fKB/s rx_pps=%.1f tx_avg=%.2fKB/s tx_pps=%.1f",
		m.n, m.convergence, m.cpuAvg, m.cpuMax, m.rssAvgMB, m.rssMaxMB, m.rxKBps, m.rxPps, m.txKBps, m.txPps)
}

type nodeStat struct {
	cpu float64
	rss uint64
	rxB uint64
	txB uint64
	rxP uint64
	txP uint64
}

func readRSS(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("malformed VmRSS")
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, err
		}
		return kb * 1024, nil
	}
	return 0, fmt.Errorf("VmRSS not found")
}

type netStat struct {
	rxB, rxP, txB, txP uint64
}

func readWG0Stats(pid int) (netStat, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/dev", pid))
	if err != nil {
		return netStat{}, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "wg0:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 11 {
			return netStat{}, fmt.Errorf("malformed wg0 stat line")
		}
		var s netStat
		s.rxB, _ = strconv.ParseUint(fields[1], 10, 64)
		s.rxP, _ = strconv.ParseUint(fields[2], 10, 64)
		s.txB, _ = strconv.ParseUint(fields[9], 10, 64)
		s.txP, _ = strconv.ParseUint(fields[10], 10, 64)
		return s, nil
	}
	return netStat{}, fmt.Errorf("wg0 not found in /proc/%d/net/dev", pid)
}

func sampleNode(pid int, dur time.Duration) (nodeStat, error) {
	u1, s1, err := readProcStat(pid)
	if err != nil {
		return nodeStat{}, err
	}
	n1, err := readWG0Stats(pid)
	if err != nil {
		return nodeStat{}, err
	}
	time.Sleep(dur)
	u2, s2, err := readProcStat(pid)
	if err != nil {
		return nodeStat{}, err
	}
	n2, err := readWG0Stats(pid)
	if err != nil {
		return nodeStat{}, err
	}
	rss, err := readRSS(pid)
	if err != nil {
		return nodeStat{}, err
	}
	deltaJiffies := float64((u2 + s2) - (u1 + s1))
	cpu := (deltaJiffies / clkTck) / dur.Seconds() * 100.0
	return nodeStat{
		cpu: cpu,
		rss: rss,
		rxB: n2.rxB - n1.rxB,
		txB: n2.txB - n1.txB,
		rxP: n2.rxP - n1.rxP,
		txP: n2.txP - n1.txP,
	}, nil
}

func measureCluster(t *testing.T, cmds []*exec.Cmd, dur time.Duration) measurement {
	t.Helper()
	type result struct {
		idx int
		s   nodeStat
		err error
	}
	ch := make(chan result, len(cmds))
	for i, cmd := range cmds {
		go func(i, pid int) {
			s, err := sampleNode(pid, dur)
			ch <- result{i, s, err}
		}(i, cmd.Process.Pid)
	}
	var m measurement
	var sumCPU, sumRSS, sumRxB, sumTxB, sumRxP, sumTxP float64
	var maxCPU, maxRSS float64
	valid := 0
	for range cmds {
		r := <-ch
		if r.err != nil {
			t.Errorf("sample %d: %v", r.idx, r.err)
			continue
		}
		valid++
		sumCPU += r.s.cpu
		sumRSS += float64(r.s.rss)
		sumRxB += float64(r.s.rxB)
		sumTxB += float64(r.s.txB)
		sumRxP += float64(r.s.rxP)
		sumTxP += float64(r.s.txP)
		if r.s.cpu > maxCPU {
			maxCPU = r.s.cpu
		}
		if float64(r.s.rss) > maxRSS {
			maxRSS = float64(r.s.rss)
		}
	}
	if valid == 0 {
		return m
	}
	n := float64(valid)
	secs := dur.Seconds()
	m.cpuAvg = sumCPU / n
	m.cpuMax = maxCPU
	m.rssAvgMB = sumRSS / n / 1024 / 1024
	m.rssMaxMB = maxRSS / 1024 / 1024
	m.rxKBps = sumRxB / n / secs / 1024
	m.txKBps = sumTxB / n / secs / 1024
	m.rxPps = sumRxP / n / secs
	m.txPps = sumTxP / n / secs
	return m
}

func readProcStat(pid int) (utime, stime uint64, err error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0, err
	}
	s := string(data)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return 0, 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 14 {
		return 0, 0, fmt.Errorf("/proc/%d/stat: not enough fields", pid)
	}
	utime, err = strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	stime, err = strconv.ParseUint(fields[12], 10, 64)
	return
}
