# Quickstart

Each node's overlay address is derived from its pubkey via
`HMAC-SHA256(prefix, pubkey)` so any node can compute any other's.
Run as root, once per node:

```sh
prefix=fdcc
ip link add wg0 type wireguard
wg genkey | tee /etc/wireguard/wg0.key | wg set wg0 private-key /dev/stdin listen-port 51820

hex=$(wg show wg0 public-key | openssl dgst -sha256 -mac HMAC -macopt hexkey:$prefix -r | head -c 16)
addr="${prefix}::${hex:0:4}:${hex:4:4}:${hex:8:4}:${hex:12:4}"
ip -6 addr add "$addr/128" dev wg0
ip link set wg0 up

pigeon-mesh --interface wg0 \
  --endpoint '[{{ GetPublicInterfaces | include "type" "IPv6" | limit 1 | attr "address" }}]:51820' \
  --peer-policy 'all(peer.AllowedIPs, cidrSubset("fdcc::/16", #))'
```

## Adding a peer

```sh
prefix=fdcc
hex=$(echo <their-pubkey> | openssl dgst -sha256 -mac HMAC -macopt hexkey:$prefix -r | head -c 16)
addr="${prefix}::${hex:0:4}:${hex:4:4}:${hex:8:4}:${hex:12:4}"
wg set wg0 peer <their-pubkey> \
  endpoint <their-public-ip>:51820 \
  allowed-ips "$addr/128"
```

pigeon-mesh picks the peer up from `wg show`.
