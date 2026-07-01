//go:build perf

package perf

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/pigeon-as/pigeon-mesh/internal/mesh"
)

// announce goes to stderr so it survives a passing run; t.Logf does not without -v.
func announce(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[mass-restart] "+format+"\n", args...)
}

func daemonStatus(n *node) (mesh.Status, error) {
	out, err := exec.Command(meshBin, "status", "--socket", sockPath(n), "--json").Output()
	if err != nil {
		return mesh.Status{}, err
	}
	var s mesh.Status
	if err := json.Unmarshal(out, &s); err != nil {
		return mesh.Status{}, err
	}
	return s, nil
}

func pubs(nodes []*node) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.pub
	}
	return out
}

func seqIdx(start, end int) []int {
	out := make([]int, 0, end-start)
	for i := start; i < end; i++ {
		out = append(out, i)
	}
	return out
}

func indexNodes(nodes []*node, idx []int) []*node {
	out := make([]*node, 0, len(idx))
	for _, i := range idx {
		out = append(out, nodes[i])
	}
	return out
}

func complementNodes(nodes []*node, idx []int) []*node {
	in := make(map[int]bool, len(idx))
	for _, i := range idx {
		in[i] = true
	}
	var out []*node
	for i, n := range nodes {
		if !in[i] {
			out = append(out, n)
		}
	}
	return out
}

func jitter(rng *rand.Rand, max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(rng.Int63n(int64(max)))
}

// view is one membership matrix: observer -> target -> seen alive. A missing row means the observer
// was unqueryable (down) at that instant.
type view map[string]map[string]bool

func sampleView(observers []*node, targets []string) view {
	v := make(view, len(observers))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, o := range observers {
		wg.Add(1)
		go func(o *node) {
			defer wg.Done()
			st, err := daemonStatus(o)
			if err != nil {
				return
			}
			row := make(map[string]bool, len(targets))
			for _, tp := range targets {
				pv, ok := st.Peers[tp]
				row[tp] = ok && pv.Status == "alive"
			}
			mu.Lock()
			v[o.pub] = row
			mu.Unlock()
		}(o)
	}
	wg.Wait()
	return v
}

func allSeeAll(v view, observers []*node, targets []string) bool {
	for _, o := range observers {
		row, ok := v[o.pub]
		if !ok {
			return false
		}
		for _, tp := range targets {
			if o.pub == tp {
				continue
			}
			if !row[tp] {
				return false
			}
		}
	}
	return true
}

// survivorsSawAllDead is the #311 positive control: every survivor sees every restarted node not-alive
// (pigeon marks a member failed exactly when memberlist declares it dead), so the stuck-dead window is
// actually set up before the nodes return.
func survivorsSawAllDead(survivors []*node, restartPubs []string) bool {
	v := sampleView(survivors, restartPubs)
	for _, s := range survivors {
		row, ok := v[s.pub]
		if !ok {
			return false
		}
		for _, rp := range restartPubs {
			if row[rp] {
				return false
			}
		}
	}
	return true
}

type snap struct {
	at time.Duration
	v  view
}

// countFlaps counts alive<->not-alive transitions per cell. A gap resets the run (an observer's own
// restart is not a flap). A normal restart is ~2 (alive->down->alive); worst above that is #312 churn.
func countFlaps(tl []snap, observers []*node, targets []string) (total, worst int) {
	for _, o := range observers {
		for _, tp := range targets {
			if o.pub == tp {
				continue
			}
			cell, have, prev := 0, false, false
			for _, s := range tl {
				row, ok := s.v[o.pub]
				if !ok {
					have = false
					continue
				}
				cur := row[tp]
				if have && cur != prev {
					cell++
				}
				prev, have = cur, true
			}
			total += cell
			if cell > worst {
				worst = cell
			}
		}
	}
	return
}

// waitDaemonConverged reads each daemon's gossip view, not kernel peers (which persist across a
// restart), since the control plane is what a restart rebuilds.
func waitDaemonConverged(t *testing.T, nodes []*node, timeout time.Duration) {
	t.Helper()
	targets := pubs(nodes)
	waitFor(t, fmt.Sprintf("all %d daemons see all peers alive", len(nodes)), timeout, 2*time.Second, func() bool {
		return allSeeAll(sampleView(nodes, targets), nodes, targets)
	})
}

// applyNetem shapes egress to de-collapse arrival ordering, which one kernel's scheduler otherwise
// dominates on a single host. Best-effort: the magnitudes are still below memberlist's timers.
func applyNetem(t *testing.T, n *node, delayMs, jitterMs, lossPct int) {
	t.Helper()
	if delayMs <= 0 && lossPct <= 0 {
		return
	}
	args := []string{"qdisc", "add", "dev", n.ns + "-vn", "root", "netem"}
	if delayMs > 0 {
		args = append(args, "delay", fmt.Sprintf("%dms", delayMs))
		if jitterMs > 0 {
			args = append(args, fmt.Sprintf("%dms", jitterMs), "distribution", "normal")
		}
	}
	if lossPct > 0 {
		args = append(args, "loss", fmt.Sprintf("%d%%", lossPct))
	}
	runIn(t, n.ns, "tc", args...)
}

type stormParams struct {
	mode       string
	restartIdx []int
	downFor    time.Duration // correlated: fixed outage
	deadCap    time.Duration // partial: max wait for survivors to mark the set dead (0 = none)
	recoverBy  time.Duration
}

func restartStorm(t *testing.T, nodes []*node, cmds []*exec.Cmd, port, seedCount int, p stormParams, extraArgs ...string) {
	t.Helper()
	targets := pubs(nodes)
	boots := seedBoots(nodes, seedCount)
	restartSet := indexNodes(nodes, p.restartIdx)
	survivors := complementNodes(nodes, p.restartIdx)
	restartPubs := pubs(restartSet)
	rng := rand.New(rand.NewSource(int64(len(nodes)*1000 + len(p.restartIdx))))
	const (
		restartJitter  = 500 * time.Millisecond
		sampleInterval = time.Second
		settleFor      = 15 * time.Second
	)

	if p.mode == "correlated" {
		announce("FIDELITY N=%d correlated: total-fleet outage (DC power-loss). Cold re-formation time only; "+
			"does not set up #311/#312 (no survivor holds dead-state).", len(nodes))
	} else {
		announce("FIDELITY N=%d %s: %d/%d restart, %d survive the outage (#311 setup: they return at inc=1 on "+
			"the same key-derived addr:port). Single-host ordering is scheduler-dominated and netem "+
			"sufficiency is unproven, so a clean pass is INCONCLUSIVE; a stall or heavy flap is the signal. "+
			"#311 precondition verified before relaunch.", len(nodes), p.mode, len(restartSet), len(nodes), len(survivors))
	}

	var (
		mu             sync.Mutex
		tl             []snap
		disrupted      bool
		firstConverged time.Duration
		convergedSince time.Duration
	)
	t0 := time.Now()
	stopSampler := make(chan struct{})
	samplerDone := make(chan struct{})
	go func() {
		defer close(samplerDone)
		tick := time.NewTicker(sampleInterval)
		defer tick.Stop()
		for {
			select {
			case <-stopSampler:
				return
			case <-tick.C:
				at := time.Since(t0)
				v := sampleView(nodes, targets)
				conv := allSeeAll(v, nodes, targets)
				mu.Lock()
				tl = append(tl, snap{at, v})
				switch {
				case !conv:
					disrupted = true
					convergedSince = 0
				case disrupted: // only count convergence once the outage has broken all-see-all
					if firstConverged == 0 {
						firstConverged = at
					}
					if convergedSince == 0 {
						convergedSince = at
					}
				}
				mu.Unlock()
			}
		}
	}()

	var sw sync.WaitGroup
	for _, i := range p.restartIdx {
		sw.Add(1)
		go func(i int, d time.Duration) {
			defer sw.Done()
			time.Sleep(d)
			stop(cmds[i])
		}(i, jitter(rng, restartJitter))
	}
	sw.Wait()

	// Partial mode holds the set down until survivors have actually marked them dead, scaling the
	// outage with N; if that never lands, say so loudly so a clean pass is not read as a reproduction.
	if len(survivors) > 0 && p.deadCap > 0 {
		met := false
		deadline := time.Now().Add(p.deadCap)
		for time.Now().Before(deadline) {
			if survivorsSawAllDead(survivors, restartPubs) {
				met = true
				break
			}
			time.Sleep(sampleInterval)
		}
		if met {
			announce("#311 precondition MET (N=%d %s): %d survivors marked all %d restarted nodes dead.",
				len(nodes), p.mode, len(survivors), len(restartSet))
		} else {
			announce("#311 precondition NOT MET (N=%d %s): survivors did not mark the set dead within %v; a "+
				"clean pass below proves nothing about #311.", len(nodes), p.mode, p.deadCap)
		}
	} else {
		time.Sleep(p.downFor)
	}

	for _, i := range p.restartIdx {
		cmds[i] = startMesh(t, nodes[i], boots[i], port, extraArgs...)
		time.Sleep(staggerInterval)
	}
	backUp := time.Since(t0) // reference for recovery, isolating it from the deliberate outage

	deadline := t0.Add(p.recoverBy)
	recovered := false
	for time.Now().Before(deadline) {
		mu.Lock()
		cs := convergedSince
		mu.Unlock()
		if cs > 0 && time.Since(t0)-cs >= settleFor {
			recovered = true
			break
		}
		time.Sleep(sampleInterval)
	}
	close(stopSampler)
	<-samplerDone

	mu.Lock()
	fc, cs, snaps := firstConverged, convergedSince, tl
	mu.Unlock()
	total, worst := countFlaps(snaps, nodes, targets)

	if recovered {
		recovery := max(0, fc-backUp)
		announce("RESULT mode=%s N=%d reconverged=%v recovery=%v(from relaunch) settled=%v flaps_total=%d flaps_worst=%d samples=%d. "+
			"Single-host: INCONCLUSIVE for #311/#312; flaps_worst>2 or a stall is the real signal.",
			p.mode, len(nodes), fc, recovery, cs, total, worst, len(snaps))
	} else {
		t.Errorf("mass-restart mode=%s N=%d: no sustained all-see-all within %v (firstConverged=%v "+
			"flaps_total=%d flaps_worst=%d). Possible memberlist #311 stuck-dead, or a single-host "+
			"scheduling artifact; confirm on multi-host.", p.mode, len(nodes), p.recoverBy, fc, total, worst)
	}
}

func TestMassRestart(t *testing.T) {
	maxN := safeMaxNodes()
	const (
		delayMs  = 50
		jitterMs = 25
		lossPct  = 5
	)
	for _, n := range []int{10, 25, 50, 100, 150} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			if n > maxN {
				announce("SKIP N=%d over single-host ceiling %d; run on a bigger box or multi-host.", n, maxN)
				t.Skipf("N=%d over host ceiling %d", n, maxN)
			}
			survivors := max(seedCount, n/5)
			// Deadlines scale with N so a large cluster on one box is not failed for being slow. The
			// deadCap floor must clear worst-case probe-cycle + suspicion so survivors actually reach
			// StateDead (the #311 precondition), not just suspect.
			deadCap := 90*time.Second + time.Duration(n)*2*time.Second
			modes := []stormParams{
				{mode: "correlated", restartIdx: seqIdx(0, n), downFor: 2 * time.Second, recoverBy: 120*time.Second + time.Duration(n)*2*time.Second},
				{mode: "partial", restartIdx: seqIdx(survivors, n), deadCap: deadCap, recoverBy: deadCap + 180*time.Second + time.Duration(n)*3*time.Second},
			}
			for _, p := range modes {
				t.Run(p.mode, func(t *testing.T) {
					nodes := buildCluster(t, port, n)
					for _, nd := range nodes {
						applyNetem(t, nd, delayMs, jitterMs, lossPct)
					}
					cmds := bootstrap(t, nodes, port, seedCount, "--profile", "lan")
					waitConverged(t, nodes, 600*time.Second)
					waitDaemonConverged(t, nodes, 300*time.Second)
					restartStorm(t, nodes, cmds, port, seedCount, p, "--profile", "lan")
				})
			}
		})
	}
}
