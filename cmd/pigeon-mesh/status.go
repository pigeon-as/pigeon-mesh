//go:build linux

package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/pigeon-as/pigeon-mesh/internal/mesh"
)

const statusTimeout = 5 * time.Second

func runStatus(args []string) int {
	fs := flag.NewFlagSet("pigeon-mesh status", flag.ContinueOnError)
	socket := fs.String("socket", mesh.DefaultSocketPath, "path to the pigeon-mesh status socket")
	asJSON := fs.Bool("json", false, "print the raw JSON response")
	switch err := fs.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case err != nil:
		return 2
	}

	if err := showStatus(*socket, *asJSON); err != nil {
		fmt.Fprintln(os.Stderr, "pigeon-mesh status:", err)
		return 1
	}
	return 0
}

func showStatus(socket string, asJSON bool) error {
	conn, err := net.DialTimeout("unix", socket, statusTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(statusTimeout)); err != nil {
		return err
	}

	if _, err := io.WriteString(conn, "status\n"); err != nil {
		return err
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	text := strings.TrimSpace(string(data))
	if msg, isErr := strings.CutPrefix(text, "error:"); isErr {
		return errors.New(strings.TrimSpace(msg))
	}
	if asJSON {
		fmt.Println(text)
		return nil
	}

	var st mesh.Status
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	printStatus(st)
	return nil
}

func printStatus(st mesh.Status) {
	if st.Health > 0 {
		fmt.Printf("health %d (degraded; 0 is healthy)\n\n", st.Health)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	row := func(cols ...string) {
		for i, c := range cols {
			cols[i] = cmp.Or(c, "-")
		}
		fmt.Fprintln(w, strings.Join(cols, "\t"))
	}

	row("PUBKEY", "ENDPOINT", "ALLOWED-IPS", "STATUS", "WG", "HANDSHAKE", "GRANT", "TAGS")
	for _, k := range slices.Sorted(maps.Keys(st.Peers)) {
		p := st.Peers[k]
		name := k
		if k == st.Self {
			name += " (self)"
		}
		row(name, p.Endpoint, strings.Join(p.AllowedIPs, ","), p.Status, formatWGAlive(p.WGAlive), formatAge(p.HandshakeAge), formatExpiry(p.GrantExpiry), formatTags(p.Tags))
	}
	w.Flush()

	if len(st.Rejected) > 0 {
		fmt.Println("\nrejected peers (not installed):")
		for _, k := range slices.Sorted(maps.Keys(st.Rejected)) {
			fmt.Printf("  %s  %s\n", k, st.Rejected[k])
		}
	}

	if len(st.Conflicts) > 0 {
		fmt.Println("\nconflicting routes (installed for no peer):")
		for _, route := range slices.Sorted(maps.Keys(st.Conflicts)) {
			fmt.Printf("  %s  claimed by %s\n", route, strings.Join(st.Conflicts[route], ", "))
		}
	}

	if len(st.RefusedRoutes) > 0 {
		fmt.Println("\nrefused routes (rejected by --peer-policy, not installed):")
		for _, k := range slices.Sorted(maps.Keys(st.RefusedRoutes)) {
			fmt.Printf("  %s  %s\n", k, strings.Join(st.RefusedRoutes[k], ", "))
		}
	}

	if len(st.UnauthorizedRoutes) > 0 {
		fmt.Println("\nunauthorized routes (not authorized by the peer's grant, not installed):")
		for _, k := range slices.Sorted(maps.Keys(st.UnauthorizedRoutes)) {
			fmt.Printf("  %s  %s\n", k, strings.Join(st.UnauthorizedRoutes[k], ", "))
		}
	}

	if len(st.StaleKernelPeers) > 0 {
		fmt.Println("\nstale kernel peers (never gossiped since join; remove from the WireGuard config if decommissioned):")
		for _, k := range st.StaleKernelPeers {
			fmt.Printf("  %s\n", k)
		}
	}
}

func formatTags(t mesh.Tags) string {
	pairs := make([]string, 0, len(t))
	for _, k := range slices.Sorted(maps.Keys(t)) {
		pairs = append(pairs, k+"="+t[k])
	}
	return strings.Join(pairs, ",")
}

func formatWGAlive(b *bool) string {
	if b == nil {
		return "-"
	}
	if *b {
		return "yes"
	}
	return "no"
}

func formatAge(s *int64) string {
	if s == nil {
		return "-"
	}
	return fmt.Sprintf("%ds", *s)
}

func formatExpiry(unix *int64) string {
	if unix == nil {
		return "-"
	}
	d := time.Until(time.Unix(*unix, 0))
	switch {
	case d <= 0:
		return "expired"
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", d/time.Hour)
	default:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
}
