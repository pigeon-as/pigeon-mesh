package mesh

import (
	"testing"

	"github.com/shoenig/test/must"
)

const testKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestEncodeDecodeMeta_RoundTrip(t *testing.T) {
	in := Peer{
		PublicKey:  testKey,
		AllowedIPs: []string{"fd00::1/128", "fd01::/64"},
	}
	b, err := encodeMeta(in)
	must.NoError(t, err)
	must.Less(t, 512, len(b), must.Sprintf("meta exceeds memberlist MetaMaxSize=512: %d", len(b)))
	var out Peer
	must.NoError(t, decodeMeta(b, &out))
	must.SliceLen(t, 2, out.AllowedIPs)
}

func TestCanonicalKey(t *testing.T) {
	must.True(t, canonicalKey(testKey), must.Sprint("a canonical 32-byte key passes"))
	// testKey is 43 'A' + '='; swapping the last data char to 'B' sets nonzero trailing bits: it still
	// decodes to 32 bytes under non-strict base64 but is not the canonical form.
	must.False(t, canonicalKey(testKey[:42]+"B="), must.Sprint("a non-canonical variant is rejected"))
	must.False(t, canonicalKey("not-base64!"), must.Sprint("non-base64 is rejected"))
	must.False(t, canonicalKey("AAAA"), must.Sprint("a non-32-byte key is rejected"))
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

// wgPeer carries no tags; a tag-only change is invisible to equal.
func TestWgPeerEqual(t *testing.T) {
	base := wgPeer{key: testKey, endpoint: "203.0.113.7:51820", routes: []string{"fd00::1/128"}}
	must.True(t, base.equal(base))

	withEndpoint := base
	withEndpoint.endpoint = "203.0.113.8:51820"
	must.False(t, base.equal(withEndpoint))

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
