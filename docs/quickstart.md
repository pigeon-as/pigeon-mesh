# Quickstart

Run as root, once per node. Each node's address is the hash of its public key,
so the policy rejects any node claiming an address that isn't its own.

```sh
prefix=fdcc
ip link add wg0 type wireguard
wg genkey | tee /etc/wireguard/wg0.key | wg set wg0 private-key /dev/stdin listen-port 51820

hex=$(wg show wg0 public-key | base64 -d | sha256sum | head -c 28)
addr="${prefix}:${hex:0:4}:${hex:4:4}:${hex:8:4}:${hex:12:4}:${hex:16:4}:${hex:20:4}:${hex:24:4}"
ip -6 addr add "$addr/128" dev wg0
ip link set wg0 up

pigeon-mesh --interface wg0 \
  --endpoint '[{{ GetPublicInterfaces | include "type" "IPv6" | limit 1 | attr "address" }}]:51820' \
  --peer-policy 'hostbits("fdcc::/16", peer.AllowedIPs[0]) == sha256(base64decode(peer.PublicKey))[0:28]'
```

## Adding a peer

```sh
prefix=fdcc
hex=$(echo <their-pubkey> | base64 -d | sha256sum | head -c 28)
addr="${prefix}:${hex:0:4}:${hex:4:4}:${hex:8:4}:${hex:12:4}:${hex:16:4}:${hex:20:4}:${hex:24:4}"
wg set wg0 peer <their-pubkey> endpoint <their-public-ip>:51820 allowed-ips "$addr/128"
```
