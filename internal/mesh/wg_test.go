//go:build linux

package mesh

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	addr "github.com/pigeon-as/pigeon-addr-plan"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestDerivePairPSK_Deterministic(t *testing.T) {
	fleet := mustParseKey(t, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=")
	pubA := mustParseKey(t, "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=")
	pubB := mustParseKey(t, "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=")

	psk1, err := DerivePairPSK(fleet, pubA, pubB)
	if err != nil {
		t.Fatalf("DerivePairPSK: %v", err)
	}
	psk2, err := DerivePairPSK(fleet, pubA, pubB)
	if err != nil {
		t.Fatalf("DerivePairPSK: %v", err)
	}
	if psk1 != psk2 {
		t.Fatalf("PSK not deterministic: %s != %s", psk1, psk2)
	}
}

func TestDerivePairPSK_Symmetric(t *testing.T) {
	fleet := mustParseKey(t, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=")
	pubA := mustParseKey(t, "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=")
	pubB := mustParseKey(t, "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=")

	pskAB, err := DerivePairPSK(fleet, pubA, pubB)
	if err != nil {
		t.Fatalf("DerivePairPSK(A,B): %v", err)
	}
	pskBA, err := DerivePairPSK(fleet, pubB, pubA)
	if err != nil {
		t.Fatalf("DerivePairPSK(B,A): %v", err)
	}
	if pskAB != pskBA {
		t.Fatalf("PSK not symmetric: %s != %s", pskAB, pskBA)
	}
}

func TestDerivePairPSK_DifferentPeers(t *testing.T) {
	fleet := mustParseKey(t, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=")
	pubA := mustParseKey(t, "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=")
	pubB := mustParseKey(t, "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=")
	pubC := mustParseKey(t, "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M=")

	pskAB, err := DerivePairPSK(fleet, pubA, pubB)
	if err != nil {
		t.Fatalf("DerivePairPSK(A,B): %v", err)
	}
	pskAC, err := DerivePairPSK(fleet, pubA, pubC)
	if err != nil {
		t.Fatalf("DerivePairPSK(A,C): %v", err)
	}
	if pskAB == pskAC {
		t.Fatal("different peer pairs should produce different PSKs")
	}
}

func TestOverlayAddr(t *testing.T) {
	ip, err := addr.PigeonHostIP("worker-01")
	if err != nil {
		t.Fatalf("PigeonHostIP: %v", err)
	}
	got := netip.PrefixFrom(ip, 128).String()
	if got == "" {
		t.Fatal("overlay addr is empty")
	}
	// Must be within fdaa::/16.
	if !addr.IsPigeonIP(ip) {
		t.Fatalf("not in pigeon range: %s", got)
	}
	// Deterministic: same input → same output.
	ip2, err := addr.PigeonHostIP("worker-01")
	if err != nil {
		t.Fatalf("PigeonHostIP repeat: %v", err)
	}
	got2 := netip.PrefixFrom(ip2, 128).String()
	if got != got2 {
		t.Fatalf("not deterministic: %s != %s", got, got2)
	}
	// Different hostname → different address.
	otherIP, err := addr.PigeonHostIP("worker-02")
	if err != nil {
		t.Fatalf("PigeonHostIP other: %v", err)
	}
	other := netip.PrefixFrom(otherIP, 128).String()
	if got == other {
		t.Fatal("different hostnames should produce different addresses")
	}
}

func TestPeerRoute(t *testing.T) {
	got, err := addr.PigeonHostRoute("worker-01")
	if err != nil {
		t.Fatalf("PigeonHostRoute: %v", err)
	}
	if got == (netip.Prefix{}) {
		t.Fatal("PigeonHostRoute returned zero prefix")
	}
	// Deterministic.
	got2, err := addr.PigeonHostRoute("worker-01")
	if err != nil {
		t.Fatalf("PigeonHostRoute repeat: %v", err)
	}
	if got != got2 {
		t.Fatalf("not deterministic: %s != %s", got, got2)
	}
	// Different name → different route.
	other, err := addr.PigeonHostRoute("worker-02")
	if err != nil {
		t.Fatalf("PigeonHostRoute other: %v", err)
	}
	if got == other {
		t.Fatal("different names should produce different routes")
	}
}

func TestLoadOrGenerateKey_Ephemeral(t *testing.T) {
	priv, pub, err := LoadOrGenerateKey("")
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	if priv == (wgtypes.Key{}) {
		t.Fatal("private key is zero")
	}
	if pub != priv.PublicKey() {
		t.Fatal("public key does not match private key")
	}
}

func TestLoadOrGenerateKey_Persist(t *testing.T) {
	dir := t.TempDir()

	priv1, pub1, err := LoadOrGenerateKey(dir)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Second call should load the same key.
	priv2, pub2, err := LoadOrGenerateKey(dir)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if priv1 != priv2 {
		t.Fatal("key not persisted: private keys differ")
	}
	if pub1 != pub2 {
		t.Fatal("key not persisted: public keys differ")
	}

	// Key file should have 0600 permissions.
	fi, err := os.Stat(filepath.Join(dir, "privkey"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("key file perms = %04o, want 0600", fi.Mode().Perm())
	}
}

func TestNodeMetaRoundtrip(t *testing.T) {
	orig := Node{
		Name:        "worker-01",
		PubKey:      "abc123",
		Endpoint:    "1.2.3.4",
		OverlayAddr: "fdaa::1/128",
		WgPort:      51820,
	}
	data, err := encodeNodeMeta(orig)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodeNodeMeta(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded != orig {
		t.Fatalf("roundtrip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func mustParseKey(t *testing.T, b64 string) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.ParseKey(b64)
	if err != nil {
		t.Fatalf("parse key %q: %v", b64, err)
	}
	return k
}
