# wg-mesh

A peer-to-peer WireGuard full-mesh daemon. It automatically adds and
removes peers on an existing WireGuard interface as nodes join or leave.
No central server.

Each node is identified by its WireGuard public key.

## Run

```
wg-mesh \
  --interface wg0 \
  --endpoint 203.0.113.1:51820
```

That's enough to start. Each node advertises its WireGuard IP to the
mesh; use `--extra-allowed-ips` to advertise additional CIDRs. Run
`wg-mesh --help` for the full flag list.

`--endpoint` and `--address` accept go-sockaddr templates (the same
syntax Consul, Nomad, and Vault use) for runtime resolution:

```
wg-mesh \
  --interface wg0 \
  --endpoint '[{{ GetDefaultInterfaces | include "type" "IPv6" | limit 1 | attr "address" }}]:51820'
```

Runs as systemd `Type=notify`; honors `WatchdogSec=`.

For a simple setup that generates the keypair, derives an IPv6 address
from the public key, and brings up the interface, see
[docs/quickstart.md](docs/quickstart.md).

## Initial peers

Add bootstrap peers to the kernel first (with `wg-quick`, networkd, or
`wg set`). Each peer needs a host route (`/32` or `/128`) in
`AllowedIPs`:

```
wg set wg0 peer <base64-pubkey> \
  endpoint 203.0.113.2:51820 \
  allowed-ips fd00:dead:beef::2/128
```

Existing kernel peers are used to bootstrap the gossip cluster.

## Encrypted gossip

Pass `--gossip-key-file keys.json` to encrypt gossip:

```json
["base64-primary-key", "base64-old-key"]
```

Keys are 16/24/32 raw bytes (AES-128/192/256), base64-encoded. The first
key signs outgoing; all are accepted on receive. `SIGHUP` reloads.

## Trust model

- WireGuard's Noise handshake is the only transport security. wg-mesh
  never reads or persists the private key.
- Gossip is unencrypted unless `--gossip-key-file` is set.
- A peer is trusted with whatever `allowed_ips` it advertises. wg-mesh
  has no admission control.

## Operations

Live state: `wg show <interface>`.

Stop the daemon to leave gracefully; peers see the Leave and drop the
WG entry. Crashed nodes are detected and removed automatically.

## Build

```
make build
make test
```
