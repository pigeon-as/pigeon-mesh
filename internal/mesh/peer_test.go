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

func TestNormalizeEndpoint_IPv4WithPort(t *testing.T) {
	got, err := NormalizeEndpoint("203.0.113.7:1234")
	must.NoError(t, err)
	must.EqOp(t, "203.0.113.7:1234", got)
}

func TestNormalizeEndpoint_IPv6WithPort(t *testing.T) {
	got, err := NormalizeEndpoint("[2001:db8::1]:1234")
	must.NoError(t, err)
	must.EqOp(t, "[2001:db8::1]:1234", got)
}

func TestParseAllowedIPs_Single(t *testing.T) {
	out, err := ParseAllowedIPs("fd00::1/128")
	must.NoError(t, err)
	must.SliceLen(t, 1, out)
	must.EqOp(t, "fd00::1/128", out[0])
}

func TestParseAllowedIPs_Multiple(t *testing.T) {
	out, err := ParseAllowedIPs("fd00::1/128, 192.168.1.0/24 ,fd01::/64")
	must.NoError(t, err)
	must.SliceLen(t, 3, out)
	must.EqOp(t, "192.168.1.0/24", out[1])
}

func TestParseAllowedIPs_Rejected(t *testing.T) {
	for _, bad := range []string{
		"",
		"   ",
		"not-a-cidr",
		"192.168.1.0/24,not-a-cidr",
	} {
		_, err := ParseAllowedIPs(bad)
		must.Error(t, err, must.Sprintf("input %q", bad))
	}
}

func TestNormalizeEndpoint_Rejected(t *testing.T) {
	for _, bad := range []string{
		"203.0.113.7",
		"2001:db8::1",
		"203.0.113.7:bad",
		"nonexistent.invalid:1234",
		"",
	} {
		_, err := NormalizeEndpoint(bad)
		must.Error(t, err, must.Sprintf("input %q", bad))
	}
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
	must.EqOp(t, in.PublicKey, out.PublicKey)
	must.EqOp(t, in.Endpoint, out.Endpoint)
	must.SliceLen(t, 2, out.AllowedIPs)
	must.EqOp(t, in.PersistentKeepalive, out.PersistentKeepalive)
}

