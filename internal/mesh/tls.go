//go:build linux

package mesh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

const notBeforeSkew = 5 * time.Minute

// loadCA reads a PEM-encoded CA certificate and private key from disk.
func loadCA(certFile, keyFile string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("ca cert: no PEM block found")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("ca key: no PEM block found")
	}
	caKey, err := parseECKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca key: %w", err)
	}

	return caCert, caKey, nil
}

// parseECKey tries SEC1 (EC PRIVATE KEY) then PKCS#8 (PRIVATE KEY).
func parseECKey(der []byte) (*ecdsa.PrivateKey, error) {
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("not SEC1 or PKCS#8: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PKCS#8 key is %T, not ECDSA", parsed)
	}
	return key, nil
}

// generatePeerCert creates an ephemeral P-256 certificate signed by the CA.
// The cert includes both ServerAuth and ClientAuth extended key usage for mTLS.
func generatePeerCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, hostname string, endpointIP string) (tls.Certificate, error) {
	peerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate peer key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    now.Add(-notBeforeSkew),
		NotAfter:     caCert.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{hostname},
	}

	if ip := net.ParseIP(endpointIP); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &peerKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sign peer cert: %w", err)
	}

	leafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse peer cert: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER, caCert.Raw},
		PrivateKey:  peerKey,
		Leaf:        leafCert,
	}, nil
}

// newTLSConfigs builds server and client TLS configs from a CA and peer cert.
// The peer cert is generated once at startup, valid until the CA expires.
// Process restart = new cert. CA rotation (Terraform) = mesh restart.
func newTLSConfigs(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, hostname, endpointIP string) (server *tls.Config, client *tls.Config, err error) {
	peerCert, err := generatePeerCert(caCert, caKey, hostname, endpointIP)
	if err != nil {
		return nil, nil, fmt.Errorf("generate peer cert: %w", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	server = &tls.Config{
		Certificates: []tls.Certificate{peerCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	client = &tls.Config{
		Certificates: []tls.Certificate{peerCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	return server, client, nil
}
