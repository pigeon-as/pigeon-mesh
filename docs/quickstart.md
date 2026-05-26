# Quickstart

Each node's IPv6 host address is derived from its WireGuard public key:
`HMAC-SHA256(prefix, pubkey)`, low 64 bits as the interface identifier.
The private key alone determines the overlay address, and any node can
compute any other node's address from public information.

Run once per node, as root:

```sh
prefix=fdcc
ip link add wg0 type wireguard
wg genkey | tee /etc/wireguard/wg0.key | wg set wg0 private-key /dev/stdin listen-port 51820

hex=$(wg show wg0 public-key | openssl dgst -sha256 -mac HMAC -macopt hexkey:$prefix -r | head -c 16)
ip -6 addr add "${prefix}::${hex:0:4}:${hex:4:4}:${hex:8:4}:${hex:12:4}/128" dev wg0
ip link set wg0 up

wg-mesh --interface wg0 \
  --endpoint '[{{ GetPublicInterfaces | include "type" "IPv6" | limit 1 | attr "address" }}]:51820'
```

All nodes in the same mesh must agree on `prefix`.

## Adding a peer

A peer's overlay address is the same derivation applied to their public
key:

```sh
prefix=fdcc
hex=$(echo <their-pubkey> | openssl dgst -sha256 -mac HMAC -macopt hexkey:$prefix -r | head -c 16)
wg set wg0 peer <their-pubkey> \
  endpoint <their-public-ip>:51820 \
  allowed-ips "${prefix}::${hex:0:4}:${hex:4:4}:${hex:8:4}:${hex:12:4}/128"
```

wg-mesh picks the peer up from `wg show` and the rest of the mesh
arrives via gossip.
