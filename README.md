# wg-mesh

A peer-to-peer WireGuard full-mesh daemon. No central server. Nodes are
identified by WireGuard public key; the kernel WG peer set follows the
gossip cluster.

## Run

```sh
wg-mesh \
  --interface wg0 \
  --endpoint 203.0.113.1:51820 \
  --peer-policy 'all(peer.AllowedIPs, cidrSubset("fd00::/8", #))'
```

`wg-mesh --help` lists the full flag set.

`--endpoint` and `--address` accept
[go-sockaddr](https://github.com/hashicorp/go-sockaddr) templates for
runtime resolution:

```sh
--endpoint '[{{ GetPublicInterfaces | include "type" "IPv6" | limit 1 | attr "address" }}]:51820'
```

`--peer-policy` is an [expr](https://expr-lang.org) boolean predicate
evaluated per peer at admission. Anything expressible in expr (CIDR
range, identity binding, multi-attribute checks) works as policy.
Rejected peers are skipped; wg-mesh keeps running.

Runs as systemd `Type=notify`; honors `WatchdogSec=`.

See [docs/quickstart.md](docs/quickstart.md) for a setup that derives
each node's IPv6 overlay address from its WireGuard public key.

## Initial peers

Add bootstrap peers to the kernel first ([wg-quick](https://man.archlinux.org/man/wg-quick.8),
[systemd-networkd](https://www.freedesktop.org/software/systemd/man/systemd.netdev.html),
or `wg set`). Each peer needs a host route (`/32` or `/128`) first in
`AllowedIPs`:

```sh
wg set wg0 peer <base64-pubkey> \
  endpoint 203.0.113.2:51820 \
  allowed-ips fd00::2/128
```

Existing kernel peers are used to bootstrap the gossip cluster.

## Peer policy examples

```js
// containment: every advertised AllowedIP must be inside the overlay.
// Without this, a peer can advertise ::/0 and hijack default routes.
all(peer.AllowedIPs, cidrSubset("fd00::/8", #))

// no address theft: reject any route that overlaps with one another peer already claims.
all(peer.AllowedIPs, let r = #;
    none(peers(), any(#.AllowedIPs, cidrSubset(r, #) || cidrSubset(#, r))))
```

## Encrypted gossip

Pass `--gossip-key-file keys.json`:

```json
["base64-primary-key", "base64-old-key"]
```

Keys are 16/24/32 raw bytes (AES-128/192/256), base64-encoded. The first
key signs outgoing; all are accepted on receive. `SIGHUP` reloads.

## Trust model

- WireGuard's Noise handshake is the only transport security. wg-mesh
  never reads or persists the private key.
- Gossip is unencrypted unless `--gossip-key-file` is set.
- By default, peers are trusted with whatever `allowed_ips` they
  advertise. Optional `--peer-policy` enforces an operator-defined expr
  predicate per peer at admission.

## Operations

Live state: `wg show <interface>` for the kernel peers, or `wg-mesh status`
for the gossip view, showing each peer's endpoint, tags, and SWIM state
(alive/suspect/dead). `wg-mesh status --json` for scripting. Served on
demand over a unix socket (`--socket`, default `/run/wg-mesh.sock`; empty
disables; set it per instance to run several on one host).

Stop or crash the daemon; peers detect via SWIM probes (~30s in WAN
config) and remove the WG entry.

## Performance

A joining node is visible cluster-wide within seconds, and a failed node is
detected and dropped in a few seconds on the `lan` profile or ~30 s on the
`wan` default. Both grow only logarithmically with cluster size, so it should stay
responsive into the thousands.

## Limitations

Tags and extra AllowedIPs are limited to ~20 entries combined.

## Build

```sh
make build
make test
```
