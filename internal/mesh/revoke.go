//go:build linux

package mesh

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

var errRevoked = errors.New("revoked")

// LoadRevoked reads --revoked: a file of base64 node public keys, one per line (# comments and blanks
// skipped), returning the set denied at admission. Remove a line and SIGHUP to re-admit.
func LoadRevoked(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseRevoked(strings.Split(string(data), "\n"))
}

// parseRevoked is strict: a malformed line fails the whole load, so a mistake in the trusted denylist is
// surfaced rather than silently leaving a key admitted.
func parseRevoked(lines []string) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("revoked %q: %w", line, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("revoked %q: not a 32-byte node key", line)
		}
		out[line] = struct{}{}
	}
	return out, nil
}

// ReloadRevokedFromFile replaces the denylist (the file is authoritative: remove a line to re-admit)
// and re-runs admission so the change takes effect at once.
func (m *Mesh) ReloadRevokedFromFile(path string) (int, error) {
	set, err := LoadRevoked(path)
	if err != nil {
		return 0, err
	}
	m.revoked.Store(&set)
	m.reevaluate(time.Now())
	return len(set), nil
}
