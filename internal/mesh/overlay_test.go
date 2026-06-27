//go:build linux

package mesh

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/shoenig/test/must"
)

func TestDeriveAddr_Deterministic(t *testing.T) {
	prefix := netip.MustParsePrefix("fdcc::/16")
	a, err := DeriveAddr(testKey, prefix)
	must.NoError(t, err)
	b, err := DeriveAddr(testKey, prefix)
	must.NoError(t, err)
	must.EqOp(t, a, b)
}

func TestDeriveAddr_InPrefixAndDistinct(t *testing.T) {
	prefix := netip.MustParsePrefix("fdcc::/16")
	a, err := DeriveAddr(testKey, prefix)
	must.NoError(t, err)
	must.True(t, prefix.Contains(a), must.Sprintf("derived %s not in %s", a, prefix))
	must.EqOp(t, 128, a.BitLen())

	other := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	b, err := DeriveAddr(other, prefix)
	must.NoError(t, err)
	must.NotEqOp(t, a, b)
}

func TestDeriveAddr_Rejected(t *testing.T) {
	for _, bad := range []struct {
		prefix string
		key    string
	}{
		{"10.0.0.0/8", testKey},
		{"fdcc::/17", testKey},
		{"fdcc::/96", testKey},
		{"fdcc::/16", "not base64"},
	} {
		_, err := DeriveAddr(bad.key, netip.MustParsePrefix(bad.prefix))
		must.Error(t, err, must.Sprintf("%+v", bad))
	}
}

func TestValidateOverlayAddr(t *testing.T) {
	prefix := netip.MustParsePrefix("fdcc::/16")
	want, err := DeriveAddr(testKey, prefix)
	must.NoError(t, err)
	self := HostRoute(want).String()

	addr, err := validateOverlayAddr(testKey, Peer{AllowedIPs: []string{self}}, prefix)
	must.NoError(t, err)
	must.EqOp(t, want, addr)
	_, err = validateOverlayAddr(testKey, Peer{AllowedIPs: []string{self, "10.0.0.0/24"}}, prefix)
	must.NoError(t, err, must.Sprint("out-of-prefix extra route is allowed"))

	// A route broader than the overlay prefix (a supernet/exit) is deferred to --peer-policy, not
	// rejected: it claims no specific overlay address, and the on-link /48 route shields the overlay.
	for _, ok := range [][]string{
		{self, "::/0"},
		{self, "fd00::/8"},
		{self, "fc00::/7"},
	} {
		_, err := validateOverlayAddr(testKey, Peer{AllowedIPs: ok}, prefix)
		must.NoError(t, err, must.Sprintf("supernet route deferred to policy: %v", ok))
	}

	for _, bad := range [][]string{
		{"fdcc::dead/128"},    // claims an overlay address that is not ours
		{"10.0.0.0/24"},       // advertises no identity /128
		{self, "fdcc:1::/64"}, // claims an overlay subnet
	} {
		_, err := validateOverlayAddr(testKey, Peer{AllowedIPs: bad}, prefix)
		must.Error(t, err, must.Sprintf("AllowedIPs %v", bad))
	}
}
