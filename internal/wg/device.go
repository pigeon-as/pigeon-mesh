//go:build linux

package wg

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
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

func (c *Client) SetAddr(iface string, ip netip.Addr) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link %q: %w", iface, err)
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(ip.BitLen(), ip.BitLen())}}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("set %s on %q: %w", ip, iface, err)
	}
	return nil
}

func (c *Client) SetRoute(iface string, prefix netip.Prefix) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link %q: %w", iface, err)
	}
	p := prefix.Masked()
	dst := &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
	route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Scope: netlink.SCOPE_LINK}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("set route %s dev %q: %w", prefix, iface, err)
	}
	return nil
}
