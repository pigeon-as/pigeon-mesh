package mesh

import (
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

const testKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

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

func TestWgPeer_ConfigIPv4(t *testing.T) {
	wp, err := wgPeer{key: testKey, endpoint: "203.0.113.7:51820", routes: []string{"fd00::1/128"}}.toWG()
	must.NoError(t, err)
	must.NotNil(t, wp.Endpoint)
	must.SliceLen(t, 1, wp.AllowedIPs)
}

func TestWgPeer_ConfigIPv6(t *testing.T) {
	wp, err := wgPeer{key: testKey, endpoint: "[2001:db8::1]:51820", routes: []string{"fd00::1/128"}}.toWG()
	must.NoError(t, err)
	must.NotNil(t, wp.Endpoint)
	must.SliceLen(t, 1, wp.AllowedIPs)
}

func TestWgPeer_ConfigKeepalive(t *testing.T) {
	wp, err := wgPeer{key: testKey, endpoint: "203.0.113.7:51820", routes: []string{"fd00::1/128"}, keepalive: 25}.toWG()
	must.NoError(t, err)
	must.NotNil(t, wp.PersistentKeepaliveInterval)
	must.EqOp(t, 25*time.Second, *wp.PersistentKeepaliveInterval)
}

func TestWgPeer_ConfigKeepaliveZeroClears(t *testing.T) {
	// keepalive 0 must still set a non-nil &0 so a previously-set interval is cleared.
	wp, err := wgPeer{key: testKey, endpoint: "203.0.113.7:51820", routes: []string{"fd00::1/128"}}.toWG()
	must.NoError(t, err)
	must.NotNil(t, wp.PersistentKeepaliveInterval, must.Sprint("0 keepalive is sent as &0, not nil"))
	must.EqOp(t, time.Duration(0), *wp.PersistentKeepaliveInterval)
}

// wgPeer carries no tags, so a tag-only change is structurally invisible to diff; equal
// compares the kernel fields.
func TestWgPeerEqual(t *testing.T) {
	base := wgPeer{key: testKey, endpoint: "203.0.113.7:51820", routes: []string{"fd00::1/128"}, keepalive: 25}
	must.True(t, base.equal(base))

	withEndpoint := base
	withEndpoint.endpoint = "203.0.113.8:51820"
	must.False(t, base.equal(withEndpoint))

	withKeepalive := base
	withKeepalive.keepalive = 0
	must.False(t, base.equal(withKeepalive))

	withRoutes := base
	withRoutes.routes = []string{"fd00::2/128"}
	must.False(t, base.equal(withRoutes))

	withKey := base
	withKey.key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
	must.False(t, base.equal(withKey))
}

func TestWgPeer_ConfigRejects(t *testing.T) {
	must.ErrorContains(t, configErr(wgPeer{key: "not-base64", endpoint: "203.0.113.7:51820", routes: []string{"fd00::1/128"}}), "public_key")
	must.ErrorContains(t, configErr(wgPeer{key: testKey, endpoint: "203.0.113.7", routes: []string{"fd00::1/128"}}), "endpoint")
	must.ErrorContains(t, configErr(wgPeer{key: testKey, endpoint: "203.0.113.7:0", routes: []string{"fd00::1/128"}}), "port")
	must.ErrorContains(t, configErr(wgPeer{key: testKey, endpoint: "203.0.113.7:51820", routes: []string{"not-a-cidr"}}), "allowed_ip")
	must.ErrorContains(t, configErr(wgPeer{key: testKey, endpoint: "203.0.113.7:51820"}), "allowed_ips")
}

func configErr(w wgPeer) error {
	_, err := w.toWG()
	return err
}
