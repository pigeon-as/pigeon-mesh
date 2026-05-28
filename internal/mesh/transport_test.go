//go:build linux

package mesh

import (
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/shoenig/test/must"
)

func udpWriteErr(errno syscall.Errno) error {
	return &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", errno)}
}

func TestTolerateColdTunnel_SwallowsENOKEY(t *testing.T) {
	must.NoError(t, tolerateColdTunnel("203.0.113.7:7946", udpWriteErr(syscall.ENOKEY)))
}

func TestTolerateColdTunnel_PassesOtherErrors(t *testing.T) {
	err := tolerateColdTunnel("203.0.113.7:7946", udpWriteErr(syscall.ECONNREFUSED))
	must.ErrorIs(t, err, syscall.ECONNREFUSED)
}

func TestTolerateColdTunnel_PassesNil(t *testing.T) {
	must.NoError(t, tolerateColdTunnel("203.0.113.7:7946", nil))
}
