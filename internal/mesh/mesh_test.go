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
	"github.com/pigeon-as/wg-mesh/internal/wg"
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

func encodedPeerNode(t *testing.T, pubkey, hostRouteCIDR string) *memberlist.Node {
	t.Helper()
	p := Peer{
		PublicKey:  pubkey,
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []string{hostRouteCIDR},
	}
	meta, err := encodeMeta(p)
	must.NoError(t, err)
	return &memberlist.Node{Name: pubkey, Meta: meta}
}

func TestPeerConfigFromNode_Accepts(t *testing.T) {
	pk, err := wgtypes.GeneratePrivateKey()
	must.NoError(t, err)
	pubkey := pk.PublicKey().String()
	_, err = peerConfigFromNode(encodedPeerNode(t, pubkey, "fdcc::dead/128"))
	must.NoError(t, err)
}

func TestPeerConfigFromNode_PubkeyMismatch(t *testing.T) {
	pk, err := wgtypes.GeneratePrivateKey()
	must.NoError(t, err)
	pubkey := pk.PublicKey().String()
	node := encodedPeerNode(t, pubkey, "fdcc::dead/128")
	node.Name = "different-name"
	_, err = peerConfigFromNode(node)
	must.ErrorContains(t, err, "mismatch")
}

func TestDiff(t *testing.T) {
	build := func(hostRoute string) wgtypes.PeerConfig {
		pc, err := Peer{PublicKey: testKey, Endpoint: "203.0.113.7:51820", AllowedIPs: []string{hostRoute}}.toWG()
		must.NoError(t, err)
		return pc
	}
	stable := build("fd00::1/128")

	must.SliceLen(t, 0, diff(
		map[string]wgtypes.PeerConfig{"X": stable},
		map[string]wgtypes.PeerConfig{"X": stable},
	))

	pcY := build("fd00::2/128")
	pcZ := build("fd00::3/128")
	pcWold := build("fd00::4/128")
	pcWnew := build("fd00::5/128")
	changes := diff(
		map[string]wgtypes.PeerConfig{"X": stable, "Y": pcY, "W": pcWold},
		map[string]wgtypes.PeerConfig{"X": stable, "Z": pcZ, "W": pcWnew},
	)
	must.SliceLen(t, 3, changes)
	var removes, adds int
	for _, c := range changes {
		if c.Remove {
			removes++
		} else {
			adds++
		}
	}
	must.EqOp(t, 1, removes, must.Sprint("Y should be removed"))
	must.EqOp(t, 2, adds, must.Sprint("Z and updated W should be added"))
}
