//go:build linux

package mesh

import (
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/pigeon-as/pigeon-mesh/internal/signature"
	"github.com/shoenig/test/must"
)

func mkSig(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	sub, err := base64.StdEncoding.DecodeString(testKey)
	must.NoError(t, err)
	return priv, pub, sub
}

func TestSelfReject_MalformedSignatureNotExpired(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	// A non-parseable signature has signature.NotAfter()==0, which must NOT be read as expiry.
	must.NoError(t, selfSignatureError(Peer{Signature: []byte{0, 1, 2}}, now), must.Sprint("garbage signature is not treated as expired"))
}

func TestSelfReject(t *testing.T) {
	priv, _, sub := mkSig(t)
	now := time.Unix(1_000_000, 0)
	mk := func(notAfter int64) []byte {
		blob, err := signature.Sign(priv, sub, now.Add(-time.Hour).Unix(), notAfter)
		must.NoError(t, err)
		return blob
	}

	must.ErrorIs(t, selfSignatureError(Peer{Signature: mk(now.Add(-time.Minute).Unix())}, now), errSignatureExpired, must.Sprint("an expired self grant is surfaced"))
	must.NoError(t, selfSignatureError(Peer{Signature: mk(now.Add(time.Hour).Unix())}, now), must.Sprint("a valid self grant is not flagged"))
	must.NoError(t, selfSignatureError(Peer{}, now), must.Sprint("no signature: nothing to flag"))
}

func TestReloadSignersFromFile(t *testing.T) {
	priv, pub, sub := mkSig(t)
	blob, err := signature.Sign(priv, sub, time.Now().Add(-time.Hour).Unix(), time.Now().Add(time.Hour).Unix())
	must.NoError(t, err)
	otherPub, _, err := ed25519.GenerateKey(nil)
	must.NoError(t, err)
	derived, err := DeriveAddr(testKey, testPrefix)
	must.NoError(t, err)
	ownRoute := HostRoute(derived).String()

	m := newTestMesh()
	m.cfg = Config{Prefix: testPrefix}
	storeConfig(m, []ed25519.PublicKey{otherPub}, nil)
	m.members[testKey] = member{
		peer:   Peer{PublicKey: testKey, Endpoint: "203.0.113.1:51820", AllowedIPs: []string{ownRoute}, Signature: blob},
		wgPeer: wgPeer{key: testKey, endpoint: "203.0.113.1:51820", routes: []string{ownRoute}},
		meta:   []byte("m"),
	}

	// under the wrong signer the signed member is rejected
	m.reevaluate(time.Now())
	must.StrContains(t, errText(m.members[testKey].admitErr), "unknown signer", must.Sprint("a member signed by an untrusted key is rejected"))
	must.EqOp(t, "", m.members[testKey].wgPeer.key, must.Sprint("a rejected member installs no kernel config"))
	must.True(t, reconcileTriggered(m.reconcileCh))

	// rotating in the correct signer re-accepts it, and the re-resolution reaches reconcile
	n, err := m.ReloadSignersFromFile(writeTemp(t, base64.StdEncoding.EncodeToString(pub)))
	must.NoError(t, err)
	must.EqOp(t, 1, n)
	must.NoError(t, m.members[testKey].admitErr, must.Sprint("the member is re-admitted under the rotated-in signer"))
	must.EqOp(t, testKey, m.members[testKey].wgPeer.key)
	must.True(t, reconcileTriggered(m.reconcileCh))

	// a failed reload keeps the trusted set (fail-closed)
	prev := m.signers.Load()
	_, err = m.ReloadSignersFromFile(filepath.Join(t.TempDir(), "nope"))
	must.Error(t, err)
	must.EqOp(t, prev, m.signers.Load(), must.Sprint("a failed signer reload does not swap the signer set"))
	must.NoError(t, m.members[testKey].admitErr, must.Sprint("the member stays admitted under the retained signer"))
}
