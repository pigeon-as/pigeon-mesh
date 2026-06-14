//go:build linux

package mesh

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/hashicorp/memberlist"
	"github.com/pigeon-as/pigeon-mesh/internal/wg"
	"github.com/shoenig/test/must"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func keyOf(b byte) []byte {
	k := make([]byte, 32)
	k[0] = b
	return k
}

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
	must.ErrorContains(t, err, "exceeds limit")
}

func TestReloadKeyring_NoKeyringConfigured(t *testing.T) {
	m := &Mesh{cfg: Config{}}
	target, err := memberlist.NewKeyring(nil, keyOf(0xaa))
	must.NoError(t, err)
	must.ErrorContains(t, m.ReloadKeyring(target), "no keyring configured")
}

func TestReloadKeyring_EmptyTarget(t *testing.T) {
	live, err := memberlist.NewKeyring(nil, keyOf(0xaa))
	must.NoError(t, err)
	m := &Mesh{cfg: Config{Keyring: live}}
	must.ErrorContains(t, m.ReloadKeyring(&memberlist.Keyring{}), "target keyring is empty")
}

func TestReloadKeyring_AddUseRemove(t *testing.T) {
	keyA, keyB := keyOf(0xa1), keyOf(0xb2)

	live, err := memberlist.NewKeyring(nil, keyA)
	must.NoError(t, err)
	m := &Mesh{cfg: Config{Keyring: live}}

	target, err := memberlist.NewKeyring([][]byte{keyA}, keyB)
	must.NoError(t, err)
	must.NoError(t, m.ReloadKeyring(target))

	keys := m.cfg.Keyring.GetKeys()
	must.SliceLen(t, 2, keys)
	must.True(t, bytes.Equal(keys[0], keyB), must.Sprintf("primary should be B"))
	must.True(t, slices.ContainsFunc(keys, func(k []byte) bool { return bytes.Equal(k, keyA) }))

	target2, err := memberlist.NewKeyring(nil, keyB)
	must.NoError(t, err)
	must.NoError(t, m.ReloadKeyring(target2))

	keys = m.cfg.Keyring.GetKeys()
	must.SliceLen(t, 1, keys)
	must.True(t, bytes.Equal(keys[0], keyB))
}

func TestReloadKeyringFromFile_HappyPath(t *testing.T) {
	keyA, keyB := keyOf(0xa1), keyOf(0xb2)

	live, err := memberlist.NewKeyring(nil, keyA)
	must.NoError(t, err)
	m := &Mesh{cfg: Config{Keyring: live}}

	body := `["` + base64.StdEncoding.EncodeToString(keyB) + `","` + base64.StdEncoding.EncodeToString(keyA) + `"]`
	path := filepath.Join(t.TempDir(), "keys.json")
	must.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	n, err := m.ReloadKeyringFromFile(path)
	must.NoError(t, err)
	must.EqOp(t, 2, n)

	keys := m.cfg.Keyring.GetKeys()
	must.SliceLen(t, 2, keys)
	must.True(t, bytes.Equal(keys[0], keyB), must.Sprintf("primary should be B"))
}

func TestReloadKeyringFromFile_LoadError(t *testing.T) {
	live, err := memberlist.NewKeyring(nil, keyOf(0xa1))
	must.NoError(t, err)
	m := &Mesh{cfg: Config{Keyring: live}}

	_, err = m.ReloadKeyringFromFile(filepath.Join(t.TempDir(), "missing.json"))
	must.ErrorContains(t, err, "load")
}

func TestReloadKeyringFromFile_ApplyError(t *testing.T) {
	body := `["` + base64.StdEncoding.EncodeToString(keyOf(0xa1)) + `"]`
	path := filepath.Join(t.TempDir(), "keys.json")
	must.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	m := &Mesh{cfg: Config{}}
	_, err := m.ReloadKeyringFromFile(path)
	must.ErrorContains(t, err, "apply")
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

func TestDiff(t *testing.T) {
	genKey := func() string {
		pk, err := wgtypes.GeneratePrivateKey()
		must.NoError(t, err)
		return pk.PublicKey().String()
	}
	makePeer := func(pubkey, cidr string) Peer {
		return Peer{PublicKey: pubkey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{cidr}}
	}
	x, y, z, w := genKey(), genKey(), genKey(), genKey()

	prev := map[string]Peer{
		x: makePeer(x, "fd00::1/128"),
		y: makePeer(y, "fd00::2/128"),
		w: makePeer(w, "fd00::4/128"),
	}
	cur := map[string]Peer{
		x: makePeer(x, "fd00::1/128"),
		z: makePeer(z, "fd00::3/128"),
		w: makePeer(w, "fd00::5/128"),
	}

	changes := diff(prev, cur)
	must.SliceLen(t, 3, changes)
	must.True(t, slices.IsSortedFunc(changes, func(a, b wgtypes.PeerConfig) int {
		return bytes.Compare(a.PublicKey[:], b.PublicKey[:])
	}), must.Sprint("diff output is deterministically sorted by pubkey"))
	var adds, removes int
	for _, c := range changes {
		if c.Remove {
			removes++
		} else {
			adds++
		}
	}
	must.EqOp(t, 2, adds, must.Sprint("new Z and changed W are applied"))
	must.EqOp(t, 1, removes, must.Sprint("Y is removed"))

	must.SliceEmpty(t, diff(cur, cur))
}

func TestResolveConflicts(t *testing.T) {
	peers := map[string]Peer{
		"a": {PublicKey: "a", AllowedIPs: []string{"fd00::a/128"}},
		"b": {PublicKey: "b", AllowedIPs: []string{"fd00::b/128"}},
		"c": {PublicKey: "c", AllowedIPs: []string{"fd00::c/128", "fd00::b/128"}},
	}

	effective, conflicts := resolveConflicts(peers)

	must.Eq(t, []string{"fd00::a/128"}, effective["a"].AllowedIPs)
	must.Eq(t, []string{"fd00::c/128"}, effective["c"].AllowedIPs, must.Sprint("c keeps its unconflicting route"))
	must.MapNotContainsKey(t, effective, "b", must.Sprint("b's only route conflicts, so b is dropped"))
	must.MapLen(t, 1, conflicts)
	must.Eq(t, []string{"b", "c"}, conflicts["fd00::b/128"], must.Sprint("conflicting route lists both claimants, sorted"))
}
