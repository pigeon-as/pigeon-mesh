package mesh

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/shoenig/test/must"
)

func TestWritePeersFile_EmptyPathNoop(t *testing.T) {
	must.NoError(t, writePeers("", PeersFile{}))
}

func TestWritePeersFile_AtomicAndStructured(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run", "wg-mesh", "peers.json")

	p := PeersFile{
		Self:      "pubkey-self",
		UpdatedAt: "2026-05-30T00:00:00Z",
		Peers: map[string]PeerView{
			"pubkey-self": {
				Endpoint:   "[fdcc::1]:51820",
				AllowedIPs: []string{"fdcc::1/128"},
				Status:     "alive",
			},
			"pubkey-other": {
				Endpoint:   "[fdcc::2]:51820",
				AllowedIPs: []string{"fdcc::2/128"},
				Status:     "alive",
			},
		},
	}

	must.NoError(t, writePeers(path, p))

	data, err := os.ReadFile(path)
	must.NoError(t, err)
	var got PeersFile
	must.NoError(t, json.Unmarshal(data, &got))

	must.EqOp(t, "pubkey-self", got.Self)
	must.EqOp(t, "2026-05-30T00:00:00Z", got.UpdatedAt)
	must.MapLen(t, 2, got.Peers)
	must.EqOp(t, "[fdcc::1]:51820", got.Peers["pubkey-self"].Endpoint)
	must.EqOp(t, "alive", got.Peers["pubkey-self"].Status)
}

func TestWritePeersFile_MkdirAndPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "peers.json")

	must.NoError(t, writePeers(path, PeersFile{Self: "x"}))

	info, err := os.Stat(path)
	must.NoError(t, err)
	if runtime.GOOS != "windows" {
		must.EqOp(t, os.FileMode(0o644), info.Mode().Perm())
	}
}
