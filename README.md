# pigeon-mesh

A peer-to-peer WireGuard full-mesh daemon. No central server. Nodes are
identified by WireGuard public key; the kernel WG peer set follows the
gossip cluster.

## Run

```sh
pigeon-mesh \
  --interface wg0 \
  --endpoint 203.0.113.1:51820
```

`pigeon-mesh --help` lists the full flag set.

`--endpoint` and `--address` accept
[go-sockaddr](https://github.com/hashicorp/go-sockaddr) templates for
runtime resolution:

```sh
--endpoint '[{{ GetPublicInterfaces | include "type" "IPv6" | limit 1 | attr "address" }}]:51820'
```

Runs as systemd `Type=notify`; honors `WatchdogSec=`.

See [docs/quickstart.md](docs/quickstart.md) for a setup that derives
each node's IPv6 overlay address from its WireGuard public key.

## Initial peers

Add bootstrap peers to the kernel first ([wg-quick](https://man.archlinux.org/man/wg-quick.8),
[systemd-networkd](https://www.freedesktop.org/software/systemd/man/systemd.netdev.html),
or `wg set`). With `--prefix`, a peer needs only its endpoint — the daemon
derives its overlay `/128` from its key and installs it:

```sh
wg set wg0 peer <base64-pubkey> endpoint 203.0.113.2:51820
```

Without `--prefix`, put the peer's host address (`/32` or `/128`) first in its
`AllowedIPs`; the daemon reads that host route as the peer's overlay address and
dials it to seed gossip (this is WireGuard cryptokey routing, not a kernel
route):

```sh
wg set wg0 peer <base64-pubkey> \
  endpoint 203.0.113.2:51820 \
  allowed-ips fd00::2/128
```

Existing kernel peers are used to bootstrap the gossip cluster.

## Self-certifying addresses

`--prefix fdcc::/16` (optional, off by default) makes each node's overlay `/128`
the leftmost host bits of `SHA-512(public key)` under the prefix (an RFC 4193
ULA). pigeon-mesh derives this node's address, assigns it to the interface as a
`/128`, and installs an on-link route for the prefix so every peer's `/128` is
reachable over WireGuard (cryptokey routing selects the peer). It rejects any
peer whose advertised route overlaps the prefix but isn't its own key-derived
`/128`; mismatches show in `status` under `rejected`. Without `--prefix`, the
daemon uses whatever address is already on the interface and installs no route —
provide overlay reachability yourself (an `ip route` to the prefix, or
networkd).

## Encrypted gossip

Pass `--gossip-key-file keys.json`:

```json
["base64-primary-key", "base64-old-key"]
```

Keys are 16/24/32 raw bytes (AES-128/192/256), base64-encoded. The first
key signs outgoing; all are accepted on receive. `SIGHUP` reloads.

## Operator signatures

Hold an offline signing key and admit a node only if it carries a signature the
operator made over its WireGuard key. Nodes hold the operator's public key and
their own signature; the signing key never touches a node, and compromising a node
can't admit new ones. A signature gates only *who* may join; addressing stays with
`--prefix`, routing with the conflict resolution above.

Create the signing key once; `keygen` prints the public key to pin:

```sh
pigeon-mesh keygen > signer.key   # secret, keep offline; prints "signer: <pubkey>"
```

Sign each node's WireGuard public key and hand it the result:

```sh
pigeon-mesh sign --key signer.key --ttl 720h <node-wg-pubkey> > node.sig
```

Run the node, trusting that signer and presenting its own signature:

```sh
pigeon-mesh --interface wg0 --endpoint ... --prefix fdcc::/16 \
  --signers <signer-pubkey> \
  --signature node.sig
```

`--signers` takes a base64 key, comma-separated keys, or `@file` (one per line,
`SIGHUP`-reloadable). Rotation is add-new, re-sign, remove-old.

A peer is admitted only if it presents a signature from a pinned signer, bound to
its own WireGuard key, and unexpired. It is verified against the pinned key, never
the key named in the signature. Signatures are re-checked continuously, so expiry
and signer rotation drop already-admitted peers too; `SIGHUP` reloads the pinned
keys. A node also checks its own signature at startup and won't run on a bad one.
Without `--require-signature` a peer with no signature still falls back to
`--prefix`/gossip-key admission while a bad signature is always rejected;
`--require-signature` demands a valid signature from every peer (a hand-added
bootstrap peer is trusted until its first gossip).

## Names

`--dns mesh.internal` serves AAAA records in that zone so peers are reachable by
name. A node's name defaults to its hostname, overridable with `--tag name=alpha`
(or `--tag name=` to opt out); the
resolver answers `<name>.<zone>` with that peer's overlay address — its key-derived
`/128` under `--prefix`, otherwise the address it advertises. It binds the overlay
address on port 53 (so needs root or `CAP_NET_BIND_SERVICE`) and programs
systemd-resolved so only the zone routes to it. Without systemd-resolved it still
answers on the overlay address directly.

## Trust model

- WireGuard's Noise handshake is the only transport security; gossip rides inside
  the tunnels. pigeon-mesh never reads or persists the WireGuard private key.
- Admission is a ladder; inside whichever rung you pick, members are trusted:
  - *Open* — the WireGuard peers you add by hand are the boundary.
  - *Shared secret* (`--gossip-key-file`) — whoever holds the key may join; it also
    encrypts the gossip.
  - *Operator signature* (`--signers`/`--signature`) — only keys an offline operator
    signed may join, and `--require-signature` makes that the only way in.
- Addresses and routes are pinned separately from admission. With `--prefix` a
  member's `/128` is its key-derived address, so it cannot claim another's; without
  it a member may claim any address. Any other route two members both advertise is
  one the daemon can't adjudicate, so it installs it for neither and shows it in
  `status`.

## Operations

Live state: `wg show <interface>` for the kernel peers, or `pigeon-mesh status`
for the gossip view, showing each peer's endpoint, tags, and SWIM state
(alive/suspect/dead), plus any conflicting routes. `pigeon-mesh status --json`
for scripting. Served on
demand over a unix socket (`--socket`, default `/run/pigeon-mesh.sock`; empty
disables; set it per instance to run several on one host).

`pigeon-mesh leave` gracefully departs the mesh (for decommission); peers drop it
immediately. A node that fails or restarts is held through `--reconnect-timeout`
so a brief partition doesn't churn peers, then reaped.

## Performance

A joining node is visible cluster-wide within seconds, and a failed node is
detected and dropped in a few seconds on the `lan` profile or ~30 s on the
`wan` default. Both grow only logarithmically with cluster size, so it should stay
responsive into the thousands.

## Limitations

Tags and advertised routes are limited to ~20 entries combined.

## Build

```sh
make build
make test
```
