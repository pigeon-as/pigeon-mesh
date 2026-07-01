//go:build linux

package mesh

import "testing"

// decodePeer must never panic on arbitrary untrusted meta bytes.
func FuzzDecodePeer(f *testing.F) {
	if meta, err := encodeMeta(Peer{Endpoint: "203.0.113.1:51820", AllowedIPs: []string{"fdcc::1/128"}, Tags: Tags{"name": "alpha"}, Signature: []byte{1, 2, 3}}); err == nil {
		f.Add(meta)
	}
	f.Add([]byte{})
	f.Add([]byte{0xff, 0x00, 0x80})
	f.Fuzz(func(t *testing.T, meta []byte) {
		_, _ = decodePeer("name", meta)
	})
}
