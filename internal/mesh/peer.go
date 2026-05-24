package mesh

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/go-msgpack/v2/codec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Peer struct {
	PublicKey           string   `codec:"public_key"`
	Endpoint            string   `codec:"endpoint"`
	AllowedIPs          []string `codec:"allowed_ips"`
	PersistentKeepalive int      `codec:"persistent_keepalive,omitempty"`
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
	return nil
}

func (p Peer) peerConfig() (wgtypes.PeerConfig, error) {
	key, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("public_key: %w", err)
	}
	ip, port, err := parseIPPort(p.Endpoint)
	if err != nil {
		return wgtypes.PeerConfig{}, err
	}
	if len(p.AllowedIPs) == 0 {
		return wgtypes.PeerConfig{}, fmt.Errorf("allowed_ips required")
	}
	nets := make([]net.IPNet, 0, len(p.AllowedIPs))
	for _, c := range p.AllowedIPs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("allowed_ip %q: %w", c, err)
		}
		nets = append(nets, *n)
	}
	cfg := wgtypes.PeerConfig{
		PublicKey:         key,
		Endpoint:          &net.UDPAddr{IP: ip, Port: port},
		ReplaceAllowedIPs: true,
		AllowedIPs:        nets,
	}
	if p.PersistentKeepalive > 0 {
		d := time.Duration(p.PersistentKeepalive) * time.Second
		cfg.PersistentKeepaliveInterval = &d
	}
	return cfg, nil
}

