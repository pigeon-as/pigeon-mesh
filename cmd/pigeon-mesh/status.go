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
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	row := func(cols ...string) {
		for i, c := range cols {
			cols[i] = cmp.Or(c, "-")
		}
		fmt.Fprintln(w, strings.Join(cols, "\t"))
	}

	row("PUBKEY", "ENDPOINT", "ALLOWED-IPS", "STATUS", "TAGS")
	for _, k := range slices.Sorted(maps.Keys(st.Peers)) {
		p := st.Peers[k]
		name := k
		if k == st.Self {
			name += " (self)"
		}
		row(name, p.Endpoint, strings.Join(p.AllowedIPs, ","), p.Status, formatTags(p.Tags))
	}
}

func formatTags(t mesh.Tags) string {
	pairs := make([]string, 0, len(t))
	for _, k := range slices.Sorted(maps.Keys(t)) {
		pairs = append(pairs, k+"="+t[k])
	}
	return strings.Join(pairs, ",")
}
