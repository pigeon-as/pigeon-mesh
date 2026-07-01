//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pigeon-as/pigeon-mesh/internal/mesh"
)

const revokeTimeout = 10 * time.Second

func runRevoke(args []string) int {
	fs := flag.NewFlagSet("pigeon-mesh revoke", flag.ContinueOnError)
	socket := fs.String("socket", mesh.DefaultSocketPath, "path to the pigeon-mesh status socket")
	switch err := fs.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case err != nil:
		return 2
	}

	antiGrant := fs.Arg(0)
	if antiGrant == "" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pigeon-mesh revoke:", err)
			return 1
		}
		antiGrant = strings.TrimSpace(string(data))
	}
	if antiGrant == "" {
		fmt.Fprintln(os.Stderr, "usage: pigeon-mesh sign-revocation ... | pigeon-mesh revoke  (or: pigeon-mesh revoke <base64-anti-grant>)")
		return 2
	}
	if err := sendRevoke(*socket, antiGrant); err != nil {
		fmt.Fprintln(os.Stderr, "pigeon-mesh revoke:", err)
		return 1
	}
	// Gossip alone is fail-open until it converges; nudge the operator to persist the floor.
	fmt.Fprintln(os.Stderr, "revoked; also append this anti-grant to your --revoked file (SIGHUP to reload) so nodes that miss the gossip still converge")
	return 0
}

func sendRevoke(socket, antiGrant string) error {
	conn, err := net.DialTimeout("unix", socket, revokeTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(revokeTimeout)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "revoke "+antiGrant+"\n"); err != nil {
		return err
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if msg, isErr := strings.CutPrefix(strings.TrimSpace(string(data)), "error:"); isErr {
		return errors.New(strings.TrimSpace(msg))
	}
	return nil
}
