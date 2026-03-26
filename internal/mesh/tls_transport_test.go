//go:build linux

package mesh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"
)

// testCA generates a self-signed CA for tests.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert, caKey
}

// testTransport creates a TLSTransport for testing on a random port.
func testTransport(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, hostname string) *TLSTransport {
	t.Helper()
	peerCert, err := generatePeerCert(caCert, caKey, hostname, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS := newTLSConfigs(caCert, peerCert)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tr, err := NewTLSTransport(logger, "127.0.0.1", 0, serverTLS, clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Shutdown() })
	return tr
}

func TestTLSTransport_PacketRoundTrip(t *testing.T) {
	caCert, caKey := testCA(t)
	t1 := testTransport(t, caCert, caKey, "node-1")
	t2 := testTransport(t, caCert, caKey, "node-2")

	// Finalize advertise addresses.
	ip1, port1, err := t1.FinalAdvertiseAddr("127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	ip2, port2, err := t2.FinalAdvertiseAddr("127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}

	addr2 := fmt.Sprintf("%s:%d", ip2, port2)
	payload := []byte("hello from node-1")

	ts, err := t1.WriteTo(payload, addr2)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if ts.IsZero() {
		t.Fatal("expected non-zero timestamp")
	}

	select {
	case pkt := <-t2.PacketCh():
		if string(pkt.Buf) != string(payload) {
			t.Fatalf("payload mismatch: got %q, want %q", pkt.Buf, payload)
		}
		fromAddr := pkt.From.(*net.TCPAddr)
		if fromAddr.IP.String() != ip1.String() || fromAddr.Port != port1 {
			t.Fatalf("from address mismatch: got %s, want %s:%d", fromAddr, ip1, port1)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for packet")
	}
}

func TestTLSTransport_StreamRoundTrip(t *testing.T) {
	caCert, caKey := testCA(t)
	t1 := testTransport(t, caCert, caKey, "node-1")
	t2 := testTransport(t, caCert, caKey, "node-2")

	_, _, err := t1.FinalAdvertiseAddr("127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	_, port2, err := t2.FinalAdvertiseAddr("127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}

	addr2 := fmt.Sprintf("127.0.0.1:%d", port2)
	conn, err := t1.DialTimeout(addr2, 5*time.Second)
	if err != nil {
		t.Fatalf("DialTimeout: %v", err)
	}
	defer conn.Close()

	msg := []byte("stream data")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case stream := <-t2.StreamCh():
		defer stream.Close()
		buf := make([]byte, 256)
		n, err := stream.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if string(buf[:n]) != string(msg) {
			t.Fatalf("stream data mismatch: got %q, want %q", buf[:n], msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for stream")
	}
}

func TestTLSTransport_MultiplePackets(t *testing.T) {
	caCert, caKey := testCA(t)
	t1 := testTransport(t, caCert, caKey, "node-1")
	t2 := testTransport(t, caCert, caKey, "node-2")

	t1.FinalAdvertiseAddr("127.0.0.1", 0)
	_, port2, _ := t2.FinalAdvertiseAddr("127.0.0.1", 0)
	addr2 := fmt.Sprintf("127.0.0.1:%d", port2)

	const count = 10
	for i := range count {
		msg := fmt.Sprintf("msg-%d", i)
		if _, err := t1.WriteTo([]byte(msg), addr2); err != nil {
			t.Fatalf("WriteTo %d: %v", i, err)
		}
	}

	for i := range count {
		select {
		case pkt := <-t2.PacketCh():
			expected := fmt.Sprintf("msg-%d", i)
			if string(pkt.Buf) != expected {
				t.Fatalf("packet %d: got %q, want %q", i, pkt.Buf, expected)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for packet %d", i)
		}
	}
}

func TestTLSTransport_RejectUntrustedPeer(t *testing.T) {
	caCert1, caKey1 := testCA(t)
	caCert2, caKey2 := testCA(t)

	t1 := testTransport(t, caCert1, caKey1, "node-1")
	t2 := testTransport(t, caCert2, caKey2, "node-2") // Different CA

	t1.FinalAdvertiseAddr("127.0.0.1", 0)
	_, port2, _ := t2.FinalAdvertiseAddr("127.0.0.1", 0)
	addr2 := fmt.Sprintf("127.0.0.1:%d", port2)

	_, err := t1.WriteTo([]byte("should fail"), addr2)
	if err == nil {
		t.Fatal("expected TLS handshake error for untrusted peer")
	}
}

func TestGeneratePeerCert(t *testing.T) {
	caCert, caKey := testCA(t)

	cert, err := generatePeerCert(caCert, caKey, "test-host", "10.0.0.1")
	if err != nil {
		t.Fatalf("generatePeerCert: %v", err)
	}

	if cert.Leaf == nil {
		t.Fatal("expected Leaf to be populated")
	}
	if cert.Leaf.Subject.CommonName != "test-host" {
		t.Fatalf("CN: got %q, want %q", cert.Leaf.Subject.CommonName, "test-host")
	}
	if len(cert.Leaf.DNSNames) != 1 || cert.Leaf.DNSNames[0] != "test-host" {
		t.Fatalf("DNSNames: got %v, want [test-host]", cert.Leaf.DNSNames)
	}
	if len(cert.Leaf.IPAddresses) != 1 || cert.Leaf.IPAddresses[0].String() != "10.0.0.1" {
		t.Fatalf("IPAddresses: got %v, want [10.0.0.1]", cert.Leaf.IPAddresses)
	}

	// Verify the cert is signed by the CA.
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestWriteReadPacket(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	payload := []byte("test payload")
	from := "127.0.0.1:7946"

	go func() {
		if err := WritePacket(c1, payload, from); err != nil {
			t.Errorf("WritePacket: %v", err)
		}
	}()

	gotPayload, gotFrom, err := ReadPacket(c2)
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("payload: got %q, want %q", gotPayload, payload)
	}
	if gotFrom != from {
		t.Fatalf("from: got %q, want %q", gotFrom, from)
	}
}

func TestTLSTransport_ConnectionPool(t *testing.T) {
	caCert, caKey := testCA(t)
	t1 := testTransport(t, caCert, caKey, "node-1")
	t2 := testTransport(t, caCert, caKey, "node-2")

	t1.FinalAdvertiseAddr("127.0.0.1", 0)
	_, port2, _ := t2.FinalAdvertiseAddr("127.0.0.1", 0)
	addr2 := fmt.Sprintf("127.0.0.1:%d", port2)

	// Send two messages — second should reuse the pooled connection.
	if _, err := t1.WriteTo([]byte("first"), addr2); err != nil {
		t.Fatalf("WriteTo 1: %v", err)
	}
	if _, err := t1.WriteTo([]byte("second"), addr2); err != nil {
		t.Fatalf("WriteTo 2: %v", err)
	}

	// Drain both packets.
	for range 2 {
		select {
		case <-t2.PacketCh():
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
	}

	// Pool should have one entry for addr2.
	if t1.pool.Len() != 1 {
		t.Fatalf("pool size: got %d, want 1", t1.pool.Len())
	}
}
