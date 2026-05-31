package mesh

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/memberlist"
	"github.com/shoenig/test/must"
)

func TestPeerStatus(t *testing.T) {
	cases := map[memberlist.NodeStateType]string{
		memberlist.StateAlive:   "alive",
		memberlist.StateSuspect: "suspect",
		memberlist.StateDead:    "dead",
		memberlist.StateLeft:    "left",
	}
	for state, want := range cases {
		must.EqOp(t, want, peerStatus(&memberlist.Node{State: state}))
	}
}

func TestStatusJSON(t *testing.T) {
	s := Status{
		Self:      "pubkey-self",
		UpdatedAt: "2026-05-30T00:00:00Z",
		Peers: map[string]PeerView{
			"pubkey-self": {
				Endpoint:   "[fdcc::1]:51820",
				AllowedIPs: []string{"fdcc::1/128"},
				Tags:       Tags{"role": "trusted"},
				Status:     "alive",
			},
		},
	}

	data, err := json.Marshal(s)
	must.NoError(t, err)

	var got Status
	must.NoError(t, json.Unmarshal(data, &got))
	must.EqOp(t, "pubkey-self", got.Self)
	must.MapLen(t, 1, got.Peers)
	must.EqOp(t, "[fdcc::1]:51820", got.Peers["pubkey-self"].Endpoint)
	must.EqOp(t, "alive", got.Peers["pubkey-self"].Status)
	must.EqOp(t, "trusted", got.Peers["pubkey-self"].Tags["role"])
}
