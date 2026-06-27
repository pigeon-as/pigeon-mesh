# Quickstart

Run as root, once per node. pigeon-mesh derives this node's overlay address from
its WireGuard key (`--prefix`, default `fdcc::/48`), assigns it to the interface,
and rejects any peer whose address isn't the same derivation of its own key. It
then keeps the kernel WireGuard peer set in sync with the gossip cluster.

```sh
pigeon-mesh keygen > signer.key   # operator signing key, once per mesh

ip link add wg0 type wireguard
wg genkey | tee wg0.key | wg set wg0 private-key /dev/stdin listen-port 51820
ip link set wg0 up

pigeon-mesh sign --key signer.key "$(wg show wg0 public-key)" > node.sig
pigeon-mesh --interface wg0 --endpoint <public-ip>:51820 --prefix fdcc::/48 --signature node.sig
```

The node trusts whoever signed its grant, so no `--signers` is needed.

## Adding a peer

Add one peer to the kernel so gossip can start; pigeon-mesh derives its overlay
address from its key and discovers the rest:

```sh
wg set wg0 peer <base64-pubkey> endpoint <public-ip>:51820
```
