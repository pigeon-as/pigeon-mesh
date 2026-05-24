//go:build linux

package wg

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Client struct {
	client *wgctrl.Client
}

func New() (*Client, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("open wgctrl: %w", err)
	}
	return &Client{client: c}, nil
}

func (c *Client) Close() error { return c.client.Close() }

func (c *Client) PublicKey(iface string) (wgtypes.Key, error) {
	d, err := c.client.Device(iface)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("read device %q: %w", iface, err)
	}
	if d.PrivateKey == (wgtypes.Key{}) {
		return wgtypes.Key{}, fmt.Errorf("device %q has no private key", iface)
	}
	return d.PublicKey, nil
}

func (c *Client) Peers(iface string) ([]wgtypes.Peer, error) {
	d, err := c.client.Device(iface)
	if err != nil {
		return nil, fmt.Errorf("read device %q: %w", iface, err)
	}
	return d.Peers, nil
}

func (c *Client) Apply(iface string, peers []wgtypes.PeerConfig) error {
	if err := c.client.ConfigureDevice(iface, wgtypes.Config{Peers: peers}); err != nil {
		return fmt.Errorf("apply %q: %w", iface, err)
	}
	return nil
}
