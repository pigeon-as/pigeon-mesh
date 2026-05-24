//go:build perf

package perf

import (
	"fmt"
	"math"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/shoenig/test/must"
)

const (
	seedCount = 3
	port      = 51820
)

func TestScaling(t *testing.T) {
	for _, n := range []int{10, 20, 50, 75} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			nodes := buildCluster(t, fmt.Sprintf("a%x", n), port, n)
			joinStart := time.Now()
			cmds := bootstrap(t, nodes, port, seedCount)
			waitConverged(t, nodes, 600*time.Second)
			converge := time.Since(joinStart)

			m := measureCluster(t, cmds, 10*time.Second)
			m.n = n
			m.convergence = converge
			t.Log(m.String())
		})
	}
}

func TestScalingWAN(t *testing.T) {
	const latencyMs = 50
	for _, n := range []int{10, 20, 50} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			nodes := buildCluster(t, fmt.Sprintf("c%x", n), port, n)
			for _, node := range nodes {
				applyLatency(t, node, latencyMs)
			}
			joinStart := time.Now()
			cmds := bootstrap(t, nodes, port, seedCount)
			waitConverged(t, nodes, 600*time.Second)
			converge := time.Since(joinStart)

			m := measureCluster(t, cmds, 10*time.Second)
			m.n = n
			m.convergence = converge
			t.Logf("RTT=%dms %s", 2*latencyMs, m.String())
		})
	}
}

func TestFailureDetection(t *testing.T) {
	for _, n := range []int{10, 20, 50} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			nodes := buildCluster(t, fmt.Sprintf("b%x", n), port, n)
			cmds := bootstrap(t, nodes, port, seedCount)
			waitConverged(t, nodes, 600*time.Second)

			target := len(nodes) - 1
			targetPub := nodes[target].pub
			start := time.Now()
			must.NoError(t, cmds[target].Process.Kill())
			cmds[target].Wait()

			cfg := memberlist.DefaultWANConfig()
			maxSuspicion := time.Duration(cfg.SuspicionMult*cfg.SuspicionMaxTimeoutMult) * cfg.ProbeInterval
			timeout := 60*time.Second + time.Duration(math.Log10(float64(n))*float64(maxSuspicion))
			waitFor(t, "remove dead peer", timeout, func() bool {
				for i, src := range nodes {
					if i == target {
						continue
					}
					if strings.Contains(wgPeers(src), targetPub) {
						return false
					}
				}
				return true
			})
			t.Logf("N=%d failure detection: %v", n, time.Since(start))
		})
	}
}

func TestShutdown(t *testing.T) {
	const n = 20
	nodes := buildCluster(t, "5d", port, n)
	cmds := bootstrap(t, nodes, port, seedCount)
	waitConverged(t, nodes, 600*time.Second)

	target := len(nodes) - 1
	targetPub := nodes[target].pub
	start := time.Now()
	must.NoError(t, cmds[target].Process.Signal(syscall.SIGTERM))
	cmds[target].Wait()
	exitTime := time.Since(start)

	waitFor(t, "leave broadcast removed dead peer", 30*time.Second, func() bool {
		for i, src := range nodes {
			if i == target {
				continue
			}
			if strings.Contains(wgPeers(src), targetPub) {
				return false
			}
		}
		return true
	})
	t.Logf("N=%d SIGTERM exit=%v, leave propagated total=%v", n, exitTime, time.Since(start))
}
