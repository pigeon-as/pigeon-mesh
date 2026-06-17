package mesh

import (
	"time"

	"github.com/hashicorp/memberlist"
)

const DefaultSocketPath = "/run/pigeon-mesh.sock"

const wgHandshakeStale = 3*time.Minute + 30*time.Second

type PeerView struct {
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowed_ips"`
	Tags         Tags     `json:"tags,omitempty"`
	Status       string   `json:"status"`
	WGEndpoint   string   `json:"wg_endpoint,omitempty"`
	HandshakeAge *int64   `json:"handshake_age_s,omitempty"`
	RxBytes      int64    `json:"rx_bytes,omitempty"`
	TxBytes      int64    `json:"tx_bytes,omitempty"`
	WGAlive      *bool    `json:"wg_alive,omitempty"`
}

type Status struct {
	Self      string              `json:"self"`
	UpdatedAt string              `json:"updated_at"`
	Health    int                 `json:"health"`
	Peers     map[string]PeerView `json:"peers"`
	Conflicts    map[string][]string `json:"conflicts,omitempty"`
	Rejected     map[string]string   `json:"rejected,omitempty"`
	KeyConflicts map[string]string   `json:"key_conflicts,omitempty"`
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

func wgAlive(last, now time.Time) (*int64, *bool) {
	if last.IsZero() {
		return nil, nil
	}
	age := max(int64(now.Sub(last).Seconds()), 0)
	alive := !last.After(now) && now.Sub(last) <= wgHandshakeStale
	return &age, &alive
}
