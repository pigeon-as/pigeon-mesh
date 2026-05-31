package mesh

import (
	"time"

	"github.com/hashicorp/memberlist"
)

const DefaultSocketPath = "/run/wg-mesh.sock"

type PeerView struct {
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
	Tags       Tags     `json:"tags,omitempty"`
	Status     string   `json:"status"`
}

type Status struct {
	Self      string              `json:"self"`
	UpdatedAt string              `json:"updated_at"`
	Peers     map[string]PeerView `json:"peers"`
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
