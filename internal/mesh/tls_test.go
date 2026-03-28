//go:build linux

package mesh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParsePrivateKey_Ed25519_PKCS8(t *testing.T) {
	_, caKey := testCA(t)
	der, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := parsePrivateKey(der)
	if err != nil {
		t.Fatalf("parsePrivateKey(Ed25519 PKCS#8): %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestParsePrivateKey_EC_SEC1(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := parsePrivateKey(der)
	if err != nil {
		t.Fatalf("parsePrivateKey(EC SEC1): %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestParsePrivateKey_InvalidDER(t *testing.T) {
	_, err := parsePrivateKey([]byte("not a key"))
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

func TestLoadCA_Valid(t *testing.T) {
	caCert, caKey := testCA(t)
	dir := t.TempDir()

	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")
	writePEM(t, certFile, "CERTIFICATE", caCert.Raw)

	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, keyFile, "PRIVATE KEY", keyDER)

	cert, key, err := loadCA(certFile, keyFile)
	if err != nil {
		t.Fatalf("loadCA: %v", err)
	}
	if cert == nil || key == nil {
		t.Fatal("expected non-nil cert and key")
	}
}

func TestLoadCA_Mismatch(t *testing.T) {
	caCert, _ := testCA(t)
	_, otherKey := testCA(t) // different key pair
	dir := t.TempDir()

	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")
	writePEM(t, certFile, "CERTIFICATE", caCert.Raw)

	keyDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, keyFile, "PRIVATE KEY", keyDER)

	_, _, err = loadCA(certFile, keyFile)
	if err == nil {
		t.Fatal("expected error for mismatched cert/key")
	}
}

func TestLoadCA_NotCA(t *testing.T) {
	// Create a non-CA certificate with its own keypair.
	caCert, caKey := testCA(t)
	_, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "leaf"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}

	certFile := filepath.Join(dir, "leaf.crt")
	keyFile := filepath.Join(dir, "leaf.key")
	writePEM(t, certFile, "CERTIFICATE", leafDER)

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, keyFile, "PRIVATE KEY", keyDER)

	_, _, err = loadCA(certFile, keyFile)
	if err == nil {
		t.Fatal("expected error for non-CA certificate")
	}
}

func writePEM(t *testing.T, path, blockType string, data []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: data}); err != nil {
		t.Fatal(err)
	}
}
