package mesh

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

func TestWGAlive(t *testing.T) {
	now := time.Now()

	age, alive := wgAlive(time.Time{}, now)
	must.Nil(t, age, must.Sprint("never handshaked -> nil age"))
	must.Nil(t, alive, must.Sprint("never handshaked -> nil alive"))

	age, alive = wgAlive(now.Add(-30*time.Second), now)
	must.True(t, *alive, must.Sprint("fresh handshake is alive"))
	must.EqOp(t, int64(30), *age)

	_, alive = wgAlive(now.Add(-209*time.Second), now)
	must.True(t, *alive, must.Sprint("inside the 210s window is alive"))

	_, alive = wgAlive(now.Add(-211*time.Second), now)
	must.False(t, *alive, must.Sprint("past 210s is stale/dead"))

	age, alive = wgAlive(now.Add(5*time.Second), now)
	must.False(t, *alive, must.Sprint("future handshake (clock skew) is dead"))
	must.EqOp(t, int64(0), *age, must.Sprint("future age clamps to 0"))
}

func TestMemberStatus(t *testing.T) {
	must.EqOp(t, "alive", memberStatus("", false))
	must.EqOp(t, "failed", memberStatus("", true), must.Sprint("a peer in the reconnect window reports failed, not alive"))
	must.EqOp(t, "rejected", memberStatus("signature expired", false))
	must.EqOp(t, "rejected", memberStatus("signature expired", true), must.Sprint("rejection takes precedence over failed"))
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
