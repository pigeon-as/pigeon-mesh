package mesh

import (
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

const testKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestPeer_PeerConfigIPv4(t *testing.T) {
	wp, err := Peer{PublicKey: testKey, Endpoint: "203.0.113.7:51820", AllowedIPs: []string{"fd00::1/128"}}.toWG()
	must.NoError(t, err)
	must.NotNil(t, wp.Endpoint)
	must.SliceLen(t, 1, wp.AllowedIPs)
}

func TestPeer_PeerConfigIPv6(t *testing.T) {
	wp, err := Peer{PublicKey: testKey, Endpoint: "[2001:db8::1]:51820", AllowedIPs: []string{"fd00::1/128"}}.toWG()
	must.NoError(t, err)
	must.NotNil(t, wp.Endpoint)
	must.SliceLen(t, 1, wp.AllowedIPs)
}

func TestPeer_PeerConfigKeepalive(t *testing.T) {
	wp, err := Peer{PublicKey: testKey, Endpoint: "203.0.113.7:51820", AllowedIPs: []string{"fd00::1/128"}, PersistentKeepalive: 25}.toWG()
	must.NoError(t, err)
	must.NotNil(t, wp.PersistentKeepaliveInterval)
	must.EqOp(t, 25*time.Second, *wp.PersistentKeepaliveInterval)
}

func TestPeer_PeerConfigBadPubkey(t *testing.T) {
	_, err := Peer{PublicKey: "not-base64", Endpoint: "203.0.113.7:51820", AllowedIPs: []string{"fd00::1/128"}}.toWG()
	must.ErrorContains(t, err, "public_key")
}

func TestPeer_PeerConfigNoPort(t *testing.T) {
	_, err := Peer{PublicKey: testKey, Endpoint: "203.0.113.7", AllowedIPs: []string{"fd00::1/128"}}.toWG()
	must.ErrorContains(t, err, "endpoint")
}

func TestPeer_PeerConfigBadPort(t *testing.T) {
	_, err := Peer{PublicKey: testKey, Endpoint: "203.0.113.7:0", AllowedIPs: []string{"fd00::1/128"}}.toWG()
	must.ErrorContains(t, err, "port")
}

func TestPeer_PeerConfigBadCIDR(t *testing.T) {
	_, err := Peer{PublicKey: testKey, Endpoint: "203.0.113.7:51820", AllowedIPs: []string{"not-a-cidr"}}.toWG()
	must.ErrorContains(t, err, "allowed_ip")
}

func TestPeer_PeerConfigEmptyAllowedIPsRejected(t *testing.T) {
	_, err := Peer{PublicKey: testKey, Endpoint: "203.0.113.7:51820"}.toWG()
	must.ErrorContains(t, err, "allowed_ips")
}

func TestEncodeDecodeMeta_RoundTrip(t *testing.T) {
	in := Peer{
		PublicKey:           testKey,
		Endpoint:            "203.0.113.7:51820",
		AllowedIPs:          []string{"fd00::1/128", "fd01::/64"},
		PersistentKeepalive: 25,
	}
	b, err := encodeMeta(in)
	must.NoError(t, err)
	must.Less(t, 512, len(b), must.Sprintf("meta exceeds memberlist MetaMaxSize=512: %d", len(b)))
	var out Peer
	must.NoError(t, decodeMeta(b, &out))
	must.EqOp(t, in.Endpoint, out.Endpoint)
	must.SliceLen(t, 2, out.AllowedIPs)
	must.EqOp(t, in.PersistentKeepalive, out.PersistentKeepalive)
}

func TestCanonicalizeAllowedIPs_MasksHostBits(t *testing.T) {
	ips := []string{"fdcc::dead/64", "fdcc::1/128", "192.168.1.5/24"}
	canonicalizeAllowedIPs(ips)
	must.Eq(t, []string{"fdcc::/64", "fdcc::1/128", "192.168.1.0/24"}, ips)
}
