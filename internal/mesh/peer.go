package mesh

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/hashicorp/go-msgpack/v2/codec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Peer struct {
	PublicKey           string   `codec:"-"`
	Endpoint            string   `codec:"ep"`
	AllowedIPs          []string `codec:"ai"`
	PersistentKeepalive int      `codec:"k,omitempty"`
	Tags                Tags     `codec:"t,omitempty"`
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

func (p Peer) toWG() (wgtypes.PeerConfig, error) {
	key, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("public_key: %w", err)
	}
	ap, err := netip.ParseAddrPort(p.Endpoint)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("endpoint %q: %w", p.Endpoint, err)
	}
	if ap.Port() == 0 {
		return wgtypes.PeerConfig{}, fmt.Errorf("endpoint %q: port 0 invalid", p.Endpoint)
	}
	if len(p.AllowedIPs) == 0 {
		return wgtypes.PeerConfig{}, errors.New("allowed_ips required")
	}
	nets := make([]net.IPNet, 0, len(p.AllowedIPs))
	for _, c := range p.AllowedIPs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("allowed_ip %q: %w", c, err)
		}
		nets = append(nets, net.IPNet{IP: pfx.Addr().AsSlice(), Mask: net.CIDRMask(pfx.Bits(), pfx.Addr().BitLen())})
	}
	cfg := wgtypes.PeerConfig{
		PublicKey:         key,
		Endpoint:          net.UDPAddrFromAddrPort(ap),
		ReplaceAllowedIPs: true,
		AllowedIPs:        nets,
	}
	if p.PersistentKeepalive > 0 {
		d := time.Duration(p.PersistentKeepalive) * time.Second
		cfg.PersistentKeepaliveInterval = &d
	}
	return cfg, nil
}

func (p Peer) equal(o Peer) bool {
	return p.PublicKey == o.PublicKey &&
		p.Endpoint == o.Endpoint &&
		p.PersistentKeepalive == o.PersistentKeepalive &&
		slices.Equal(p.AllowedIPs, o.AllowedIPs) &&
		maps.Equal(p.Tags, o.Tags)
}
