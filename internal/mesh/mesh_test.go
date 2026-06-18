//go:build linux

package mesh

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

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

	changes := diff(prev, cur, kernelSet(prev))
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

	must.SliceEmpty(t, diff(cur, cur, kernelSet(cur)))
}

func kernelSet(ms ...map[string]Peer) map[string]bool {
	set := map[string]bool{}
	for _, mp := range ms {
		for k := range mp {
			set[k] = true
		}
	}
	return set
}

func TestSweepExpiry(t *testing.T) {
	m := &Mesh{
		members:     map[string]member{},
		reconcileCh: make(chan struct{}, 1),
	}
	now := time.Now()
	m.members["admitted-noexpiry"] = member{notAfter: 0}
	m.members["admitted-valid"] = member{notAfter: now.Add(time.Hour).Unix()}
	m.members["admitted-expired"] = member{notAfter: now.Add(-time.Second).Unix()}
	m.members["already-rejected"] = member{reject: "no signature"}
	m.members["failed-expired"] = member{failed: true, notAfter: now.Add(-time.Hour).Unix()}

	m.sweepExpiry(now)

	must.EqOp(t, "", m.members["admitted-noexpiry"].reject)
	must.EqOp(t, "", m.members["admitted-valid"].reject)
	must.EqOp(t, "signature expired", m.members["admitted-expired"].reject)
	must.EqOp(t, "no signature", m.members["already-rejected"].reject)
	must.EqOp(t, "signature expired", m.members["failed-expired"].reject, must.Sprint("expiry is enforced even for offline/failed peers"))

	select {
	case <-m.reconcileCh:
	default:
		t.Fatal("expected a reconcile trigger after eviction")
	}
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

func TestAdmission(t *testing.T) {
	prefix := netip.MustParsePrefix("fdcc::/16")
	derived, err := DeriveAddr(testKey, prefix)
	must.NoError(t, err)
	ownRoute := HostRoute(derived).String()

	priv, pub, sub := mkSig(t)
	signers := []ed25519.PublicKey{pub}
	now := time.Unix(1_000_000, 0)
	sign := func(notBefore, notAfter int64) []byte {
		blob, err := signClaims(priv, sigClaims{Sub: sub, NotBefore: notBefore, NotAfter: notAfter})
		must.NoError(t, err)
		return blob
	}
	validSig := sign(now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix())
	expiredSig := sign(now.Add(-time.Hour).Unix(), now.Add(-time.Minute).Unix())

	otherPub, _, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)

	advertised := Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{"fd00::1/128"}}
	prefixPeer := func(sig []byte) Peer {
		return Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute}, Signature: sig}
	}

	cases := []struct {
		name       string
		signers    []ed25519.PublicKey
		requireSig bool
		prefix     netip.Prefix
		peer       Peer
		wantReject string
		wantAddr   bool
		wantExpiry bool
	}{
		{name: "open tier admits any address", peer: advertised, wantAddr: true},
		{name: "prefix admits own derived route", prefix: prefix, peer: prefixPeer(nil), wantAddr: true},
		{name: "prefix rejects a non-derived route", prefix: prefix, peer: Peer{PublicKey: testKey, AllowedIPs: []string{"fdcc::dead/128"}}, wantReject: "derives"},
		{name: "valid overlay but malformed endpoint rejected", prefix: prefix, peer: Peer{PublicKey: testKey, AllowedIPs: []string{ownRoute}}, wantReject: "invalid peer config"},
		{name: "signers without require admits unsigned", signers: signers, prefix: prefix, peer: prefixPeer(nil), wantAddr: true},
		{name: "require-signature rejects unsigned", signers: signers, requireSig: true, prefix: prefix, peer: prefixPeer(nil), wantReject: "no signature"},
		{name: "valid signature admitted with expiry", signers: signers, requireSig: true, prefix: prefix, peer: prefixPeer(validSig), wantAddr: true, wantExpiry: true},
		{name: "expired signature rejected", signers: signers, prefix: prefix, peer: prefixPeer(expiredSig), wantReject: "expired"},
		{name: "unknown signer rejected", signers: []ed25519.PublicKey{otherPub}, prefix: prefix, peer: prefixPeer(validSig), wantReject: "unknown signer"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, reject, notAfter := assess(tc.peer, testKey, tc.signers, tc.requireSig, tc.prefix, now)
			if tc.wantReject == "" {
				must.EqOp(t, "", reject)
			} else {
				must.StrContains(t, reject, tc.wantReject)
			}
			must.EqOp(t, tc.wantAddr, addr.IsValid())
			must.EqOp(t, tc.wantExpiry, notAfter != 0)
		})
	}
}

func TestDiff_EndpointChange(t *testing.T) {
	pk, err := wgtypes.GeneratePrivateKey()
	must.NoError(t, err)
	key := pk.PublicKey().String()

	peerAt := func(ep, cidr string) map[string]Peer {
		return map[string]Peer{key: {PublicKey: key, Endpoint: ep, AllowedIPs: []string{cidr}}}
	}

	prev := peerAt("203.0.113.1:51820", "fd00::1/128")
	inKernel := kernelSet(prev)
	changes := diff(prev, peerAt("203.0.113.2:51820", "fd00::1/128"), inKernel)
	must.SliceLen(t, 1, changes)
	must.True(t, changes[0].UpdateOnly, must.Sprint("a known peer is an update, not a re-add"))
	must.NotNil(t, changes[0].Endpoint, must.Sprint("a changed endpoint is re-applied to the kernel"))

	changes = diff(prev, peerAt("203.0.113.1:51820", "fd00::2/128"), inKernel)
	must.SliceLen(t, 1, changes)
	must.True(t, changes[0].UpdateOnly)
	must.Nil(t, changes[0].Endpoint, must.Sprint("an unchanged endpoint is left to WireGuard's own roaming"))

	changes = diff(prev, prev, map[string]bool{})
	must.SliceLen(t, 1, changes)
	must.False(t, changes[0].UpdateOnly, must.Sprint("a peer missing from the kernel is re-added in full"))
	must.NotNil(t, changes[0].Endpoint)
}

func TestShouldReap(t *testing.T) {
	now := time.Unix(1000, 0)
	timeout := time.Minute
	must.False(t, shouldReap(false, now.Add(-time.Hour), now, timeout), must.Sprint("a live peer is never reaped"))
	must.False(t, shouldReap(true, now.Add(-30*time.Second), now, timeout), must.Sprint("within the window, a failed peer is kept"))
	must.True(t, shouldReap(true, now.Add(-2*time.Minute), now, timeout), must.Sprint("past the window, a failed peer is reaped"))
}

func TestShouldProbe(t *testing.T) {
	must.False(t, shouldProbe(0, 10, 0.5), must.Sprint("no failures: do not probe"))
	must.True(t, shouldProbe(10, 0, 0.5), must.Sprint("total outage (alive 0): always probe"))
	must.True(t, shouldProbe(5, 10, 0.4), must.Sprint("sample below the failed/alive ratio probes"))
	must.False(t, shouldProbe(5, 10, 0.6), must.Sprint("sample above the ratio skips"))
}

func TestNextJoinBackoff(t *testing.T) {
	must.EqOp(t, 2*time.Second, nextJoinBackoff(time.Second))
	must.EqOp(t, retryJoinInterval, nextJoinBackoff(retryJoinInterval))
	must.EqOp(t, retryJoinInterval, nextJoinBackoff(2*retryJoinInterval), must.Sprint("capped at the join interval"))
}

func TestHandleNodeConflictRecordsKeyConflict(t *testing.T) {
	m := &Mesh{cfg: Config{Self: Peer{PublicKey: "selfKey"}}, keyConflicts: map[string]string{}}

	m.handleNodeConflict(
		&memberlist.Node{Name: "peerKey", Addr: net.ParseIP("10.0.0.1"), Port: 51820},
		&memberlist.Node{Name: "peerKey", Addr: net.ParseIP("10.0.0.2"), Port: 51820},
	)
	must.MapContainsKey(t, m.keyConflicts, "peerKey", must.Sprint("a peer key collision is recorded for status"))

	m.handleNodeConflict(
		&memberlist.Node{Name: "selfKey", Addr: net.ParseIP("10.0.0.1"), Port: 51820},
		&memberlist.Node{Name: "selfKey", Addr: net.ParseIP("10.0.0.3"), Port: 51820},
	)
	must.MapContainsKey(t, m.keyConflicts, "selfKey", must.Sprint("a collision on our own key is recorded too"))
}
