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

const leaveTimeout = 10 * time.Second

func runLeave(args []string) int {
	fs := flag.NewFlagSet("pigeon-mesh leave", flag.ContinueOnError)
	socket := fs.String("socket", mesh.DefaultSocketPath, "path to the pigeon-mesh status socket")
	switch err := fs.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case err != nil:
		return 2
	}
	if err := sendLeave(*socket); err != nil {
		fmt.Fprintln(os.Stderr, "pigeon-mesh leave:", err)
		return 1
	}
	return 0
}

func sendLeave(socket string) error {
	conn, err := net.DialTimeout("unix", socket, leaveTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(leaveTimeout)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "leave\n"); err != nil {
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
