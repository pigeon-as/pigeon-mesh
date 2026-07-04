//go:build linux

package mesh

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

func TestAdmit_Revoked(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	signers, ownRoute, grant := signedFixture(t, now)
	peer := Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute}, Signature: grant}
	// A valid grant is still rejected: the denylist gate sits before verifyGrant, so it overrides admission.
	r := admit(member{}, peer, testKey, &signers, map[string]struct{}{testKey: {}}, testPrefix, nil, now)
	must.ErrorIs(t, r.admitErr, errRevoked)
	must.SliceEmpty(t, r.wgPeer.routes, must.Sprint("a revoked peer installs nothing, identity /128 included"))
}

func TestLoadRevoked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked")
	must.NoError(t, os.WriteFile(path, []byte("# operator denylist\n\n"+testKey+"\n"), 0o600))
	set, err := LoadRevoked(path)
	must.NoError(t, err)
	must.MapLen(t, 1, set, must.Sprint("the denylist loads the key, skipping comments and blanks"))
	_, ok := set[testKey]
	must.True(t, ok)

	// The denylist is trusted config, so a malformed line fails the whole load (strict, like --signers).
	bad := filepath.Join(dir, "bad")
	must.NoError(t, os.WriteFile(bad, []byte("not-base64!\n"), 0o600))
	_, err = LoadRevoked(bad)
	must.Error(t, err, must.Sprint("bad base64 fails the load"))

	short := filepath.Join(dir, "short")
	must.NoError(t, os.WriteFile(short, []byte(base64.StdEncoding.EncodeToString([]byte("short"))+"\n"), 0o600))
	_, err = LoadRevoked(short)
	must.ErrorContains(t, err, "32-byte", must.Sprint("a non-32-byte key fails the load"))

	// A non-canonical encoding (nonzero trailing bits) loose-decodes to 32 bytes but is not the canonical
	// node-name form admit matches on, so it would load yet never deny; strict decoding rejects it (N1).
	noncanon := filepath.Join(dir, "noncanon")
	must.NoError(t, os.WriteFile(noncanon, []byte(strings.Repeat("A", 42)+"B=\n"), 0o600))
	_, err = LoadRevoked(noncanon)
	must.Error(t, err, must.Sprint("a non-canonical base64 key fails the load instead of silently not denying"))
}

func TestReloadRevokedFromFile_ReadmitsOnRemove(t *testing.T) {
	now := time.Now()
	signers, ownRoute, grant := signedFixture(t, now)
	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, signers, nil)
	m.members[testKey] = member{
		peer:   Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute}, Signature: grant},
		wgPeer: wgPeer{key: testKey, endpoint: "203.0.113.1:51820", routes: []string{ownRoute}},
		meta:   []byte("m"),
	}
	path := filepath.Join(t.TempDir(), "revoked")

	// Listing the key and reloading evicts it.
	must.NoError(t, os.WriteFile(path, []byte(testKey+"\n"), 0o600))
	_, err := m.ReloadRevokedFromFile(path)
	must.NoError(t, err)
	must.False(t, m.members[testKey].admitted(), must.Sprint("a listed key is evicted on reload"))

	// Removing the line and reloading re-admits it: the file is authoritative (the un-revoke flow).
	must.NoError(t, os.WriteFile(path, []byte("# empty\n"), 0o600))
	_, err = m.ReloadRevokedFromFile(path)
	must.NoError(t, err)
	must.True(t, m.members[testKey].admitted(), must.Sprint("removing the line re-admits the key on reload"))
	must.Eq(t, []string{ownRoute}, m.members[testKey].wgPeer.routes)
}
