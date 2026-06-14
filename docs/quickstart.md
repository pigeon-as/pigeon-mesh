# Quickstart

Run as root, once per node. With `--prefix`, pigeon-mesh derives this node's
overlay address from its WireGuard key, assigns it to the interface, and rejects
any peer whose address isn't the same derivation of its own key. It then keeps
the kernel WireGuard peer set in sync with the gossip cluster.

```sh
prefix=fdcc
ip link add wg0 type wireguard
wg genkey | tee /etc/wireguard/wg0.key | wg set wg0 private-key /dev/stdin listen-port 51820
ip link set wg0 up

pigeon-mesh --interface wg0 \
  --endpoint '[{{ GetPublicInterfaces | include "type" "IPv6" | limit 1 | attr "address" }}]:51820' \
  --prefix ${prefix}::/16
```

## Adding a peer

Add one bootstrap peer to the kernel so gossip can start; pigeon-mesh discovers
the rest. Its `allowed-ips` is that node's overlay address (`ip -6 addr show wg0`
on it):

```sh
wg set wg0 peer <their-pubkey> endpoint <their-public-ip>:51820 allowed-ips <their-overlay-addr>/128
```
