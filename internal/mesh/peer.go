package mesh

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/hashicorp/go-msgpack/v2/codec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PublicKey is identity, not encoded; it is the node name, filled in on decode.
type Peer struct {
	PublicKey           string   `codec:"-"`
	Endpoint            string   `codec:"ep"`
	AllowedIPs          []string `codec:"ai"`
	PersistentKeepalive int      `codec:"k,omitempty"`
	Tags                Tags     `codec:"t,omitempty"`
	Signature           []byte   `codec:"s,omitempty"`
}

var msgpackHandle = &codec.MsgpackHandle{}

func encodeMeta(p Peer) ([]byte, error) {
	var buf bytes.Buffer
	if err := codec.NewEncoder(&buf, msgpackHandle).Encode(p); err != nil {
		return nil, fmt.Errorf("encode meta: %w", err)
	}
	return buf.Bytes(), nil
}

func decodeMeta(b []byte, p *Peer) error {
	if err := codec.NewDecoder(bytes.NewReader(b), msgpackHandle).Decode(p); err != nil {
		return fmt.Errorf("decode meta: %w", err)
	}
	canonicalizeAllowedIPs(p.AllowedIPs)
	return nil
}

func canonicalizeAllowedIPs(ips []string) {
	for i, s := range ips {
		if pfx, err := netip.ParsePrefix(s); err == nil {
			ips[i] = pfx.Masked().String()
		}
	}
}

func decodePeer(name string, meta []byte) (Peer, error) {
	var p Peer
	if err := decodeMeta(meta, &p); err != nil {
		return Peer{}, err
	}
	p.PublicKey = name
	return p, nil
}

type wgPeer struct {
	key       string
	endpoint  string
	routes    []string
	keepalive int
}

func (w wgPeer) toWG() (wgtypes.PeerConfig, error) {
	key, err := wgtypes.ParseKey(w.key)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("public_key: %w", err)
	}
	ap, err := netip.ParseAddrPort(w.endpoint)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("endpoint %q: %w", w.endpoint, err)
	}
	if ap.Port() == 0 {
		return wgtypes.PeerConfig{}, fmt.Errorf("endpoint %q: port 0 invalid", w.endpoint)
	}
	if len(w.routes) == 0 {
		return wgtypes.PeerConfig{}, errors.New("allowed_ips required")
	}
	nets := make([]net.IPNet, 0, len(w.routes))
	for _, c := range w.routes {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("allowed_ip %q: %w", c, err)
		}
		nets = append(nets, net.IPNet{IP: pfx.Addr().AsSlice(), Mask: net.CIDRMask(pfx.Bits(), pfx.Addr().BitLen())})
	}
	d := time.Duration(w.keepalive) * time.Second
	return wgtypes.PeerConfig{
		PublicKey:                   key,
		Endpoint:                    net.UDPAddrFromAddrPort(ap),
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  nets,
		PersistentKeepaliveInterval: &d,
	}, nil
}

func (w wgPeer) equal(o wgPeer) bool {
	return w.key == o.key && w.endpoint == o.endpoint && w.keepalive == o.keepalive &&
		slices.Equal(w.routes, o.routes)
}
