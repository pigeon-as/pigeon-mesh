//go:build linux

package mesh

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pigeon-as/pigeon-mesh/internal/wg"
	"github.com/shoenig/test/must"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestMesh_New_NilWG(t *testing.T) {
	_, err := New(Config{})
	must.ErrorContains(t, err, "wgctrl")
}

func TestMesh_New_NoBindAddr(t *testing.T) {
	_, err := New(Config{WG: &wg.Client{}})
	must.ErrorContains(t, err, "bind addr")
}

func TestMesh_New_InvalidProfile(t *testing.T) {
	_, err := New(Config{
		WG:       &wg.Client{},
		BindAddr: "fd00::1",
		Profile:  "garbage",
		Self:     Peer{PublicKey: testKey},
	})
	must.ErrorContains(t, err, "must be lan, wan, or local")
}

func TestMesh_New_OversizedMeta(t *testing.T) {
	manyAllowed := make([]string, 100)
	for i := range manyAllowed {
		manyAllowed[i] = fmt.Sprintf("fd00::%x/128", i)
	}
	_, err := New(Config{
		WG:       &wg.Client{},
		BindAddr: "fd00::1",
		Self: Peer{
			PublicKey:  testKey,
			Endpoint:   "203.0.113.1:51820",
			AllowedIPs: manyAllowed,
		},
	})
	must.ErrorContains(t, err, "over the 512-byte limit")
}

func encodedMeta(t *testing.T, pubkey, hostRouteCIDR string) []byte {
	t.Helper()
	meta, err := encodeMeta(Peer{
		PublicKey:  pubkey,
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []string{hostRouteCIDR},
	})
	must.NoError(t, err)
	return meta
}

func TestDecodePeer_Accepts(t *testing.T) {
	pk, err := wgtypes.GeneratePrivateKey()
	must.NoError(t, err)
	pubkey := pk.PublicKey().String()
	_, err = decodePeer(pubkey, encodedMeta(t, pubkey, "fdcc::dead/128"))
	must.NoError(t, err)
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	must.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestReloadPolicyFromFile(t *testing.T) {
	now := time.Now()
	signers, ownRoute, grant := signedFixture(t, now, netip.MustParsePrefix("10.0.0.0/8"))
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, signers, nil)
	m.members[testKey] = member{
		peer:   Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute, "10.0.0.0/8"}, Signature: grant},
		wgPeer: wgPeer{key: testKey, endpoint: "203.0.113.1:51820", routes: []string{ownRoute, "10.0.0.0/8"}},
		meta:   []byte("m"),
	}

	// success: reachability-only refuses the extra route, keeps identity.
	must.NoError(t, m.ReloadPolicyFromFile(writeTemp(t, "route == peer.address")))
	must.NotNil(t, m.policy.Load(), must.Sprint("a successful reload installs the new policy"))
	must.Eq(t, []string{ownRoute}, m.members[testKey].wgPeer.routes)
	must.Eq(t, []string{"10.0.0.0/8"}, m.members[testKey].refusedRoutes)

	// invalid policy: error, previous policy retained (fail-closed).
	prev := m.policy.Load()
	must.Error(t, m.ReloadPolicyFromFile(writeTemp(t, "&&")))
	must.EqOp(t, prev, m.policy.Load(), must.Sprint("a bad reload must not swap the policy"))
	must.NotNil(t, m.policy.Load(), must.Sprint("a bad reload keeps the previous policy, not open"))
	must.Eq(t, []string{"10.0.0.0/8"}, m.members[testKey].refusedRoutes, must.Sprint("route stays refused under the retained policy"))

	// missing file: error, policy untouched.
	must.Error(t, m.ReloadPolicyFromFile(filepath.Join(t.TempDir(), "nope")))
	must.NotNil(t, m.policy.Load())
}

func TestDebounceDelay(t *testing.T) {
	base := time.Unix(1000, 0)
	const interval = 250 * time.Millisecond
	must.EqOp(t, 150*time.Millisecond, debounceDelay(base, base.Add(100*time.Millisecond), interval), must.Sprint("mid-window: wait the remainder"))
	must.EqOp(t, time.Duration(0), debounceDelay(base, base.Add(interval), interval), must.Sprint("at the boundary: run now"))
	must.EqOp(t, time.Duration(0), debounceDelay(base, base.Add(time.Second), interval), must.Sprint("past the window: run now"))
	must.EqOp(t, time.Duration(0), debounceDelay(time.Time{}, base, interval), must.Sprint("no prior run: run now"))
}
