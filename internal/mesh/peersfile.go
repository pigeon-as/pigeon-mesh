package mesh

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/pigeon-as/wg-mesh/internal/atomicfile"
)

type PeerView struct {
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
	Tags       Tags     `json:"tags,omitempty"`
	Status     string   `json:"status"`
}

type PeersFile struct {
	Self      string              `json:"self"`
	UpdatedAt string              `json:"updated_at"`
	Peers     map[string]PeerView `json:"peers"`
}

func writePeers(path string, p PeersFile) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal peers: %w", err)
	}
	data = append(data, '\n')
	if err := atomicfile.Write(path, data, 0o644); err != nil {
		return fmt.Errorf("write peers %s: %w", path, err)
	}
	return nil
}

func peerStatus(n *memberlist.Node) string {
	switch n.State {
	case memberlist.StateAlive:
		return "alive"
	case memberlist.StateSuspect:
		return "suspect"
	case memberlist.StateDead:
		return "dead"
	case memberlist.StateLeft:
		return "left"
	default:
		return "unknown"
	}
}

func nowStamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
