# pigeon-mesh

A peer-to-peer WireGuard full-mesh daemon. No central server. Nodes are identified
by WireGuard public key, and the kernel WG peer set follows the gossip cluster.

> **Status:** early development, with breaking changes between v0.0.x versions.

## Run

You need a WireGuard interface and an operator signing key (`pigeon-mesh keygen >
signer.key`, once per mesh). Sign a node's key, then run it:

```sh
pigeon-mesh sign --key signer.key "$(wg show wg0 public-key)" > node.sig
pigeon-mesh --interface wg0 --endpoint 203.0.113.1:51820 --signature node.sig
```

The node derives its overlay address from its key (`--prefix`, default `fdcc::/48`)
and trusts whoever signed its grant. It runs as systemd `Type=notify`. `pigeon-mesh
--help` lists every flag.

`--endpoint` accepts [go-sockaddr](https://github.com/hashicorp/go-sockaddr)
templates for runtime resolution:

```sh
--endpoint '[{{ GetPublicInterfaces | include "type" "IPv6" | limit 1 | attr "address" }}]:51820'
```

## Initial peers

Add at least one peer to the kernel so gossip can start. The daemon
discovers the rest and derives each peer's overlay `/128` from its key:

```sh
wg set wg0 peer <base64-pubkey> endpoint 203.0.113.2:51820
```

## Self-certifying addresses

Each node's overlay `/128` is `SHA-512(public key)` under `--prefix` (default
`fdcc::/48`, an RFC 4193 ULA). The daemon assigns it and an on-link prefix route so
every peer is reachable over WireGuard. A peer advertising an address that isn't its
own key derivation is rejected (shown in `status`). Addresses are a pure function of
the key, so no node can claim another's and no coordinator hands them out.

## Operator signatures

A node joins only with a grant the operator signed over its WireGuard key. The
signing key stays offline, so compromising a node can't admit new ones. A node trusts
whoever signed its own grant, so `--signature` is all it needs. Pass `--signers`
(base64 key, comma-separated, or `@file`) only to pin multiple operators or to
rotate: add the new key, re-sign, then remove the old (`SIGHUP` reloads).

A peer is admitted only if its grant verifies against the trusted key, is bound to
its WireGuard key, and is unexpired. Grants are re-checked continuously, so expiry or
rotation drops admitted peers too. A node checks its own grant at startup and won't run
on a bad one. Renew before it expires by overwriting the `--signature` file and sending
`SIGHUP`: the node re-advertises the new grant over gossip with no restart and no tunnel
drop (the WireGuard key is unchanged). A grant that does lapse drops the node from DNS,
and signature-checking peers tear down its tunnels within seconds.

## Names

`--dns mesh.internal` serves AAAA records so peers resolve by name. A node's name is
its hostname, or set `--tag name=alpha` (`--tag name=` opts out). `<name>.<zone>`
resolves to that peer's key-derived `/128`. It binds port 53 on the overlay address
(needs root or `CAP_NET_BIND_SERVICE`) and programs systemd-resolved to route the
zone to it.

## Trust model

- **Transport:** WireGuard's Noise handshake is the only encryption, and gossip rides
  inside the tunnels. The private key is never read or persisted.
- **Membership:** no control plane, so addresses are key-derived (self-certifying)
  and every node carries an offline operator signature. A node cannot claim another's
  address. A route two members both claim is installed for neither and shown in
  `status`.
- **Routes:** members may advertise extra routes (an exit `0.0.0.0/0`, a subnet via
  `--allowed-ips`), and each node chooses which to install with
  [`--peer-policy`](#peer-policy).

## Peer policy

`--peer-policy` decides which routes this node installs from what peers advertise: an
[expr](https://expr-lang.org) predicate run once per advertised route. A node's own
identity `/128` always installs, so the policy gates only *extra* routes (subnets,
exits); a refused route drops locally and shows in `status`. It restricts only this
node, unset accepts everything, and it is inline or `@file` (`SIGHUP`-reloadable).

In scope: `peer.key`, `peer.endpoint`, the candidate `route`, the peer's full
`peer.allowedips`, and `cidrSubset(outer, inner)`. Match the single `route` for
per-route rules, or `any`/`all`/`len` over `peer.allowedips` for whole-peer ones.

```sh
# refuse every extra route, keep only identity /128s
--peer-policy 'false'

# per-route: accept only routes inside the mesh ULA, refuse the rest individually
--peer-policy 'cidrSubset("fdcc::/16", route)'

# per-route: only the exit node may advertise a default route, others accepted
--peer-policy 'route in ["0.0.0.0/0", "::/0"] ? peer.key == "<exit-pubkey>" : true'

# per-route: only the designated router may advertise a 10.0.0.0/8 subnet
--peer-policy 'cidrSubset("10.0.0.0/8", route) ? peer.key == "<router-pubkey>" : true'

# whole-peer: take a peer's extra routes only if every one is a mesh ULA subnet
--peer-policy 'all(peer.allowedips, cidrSubset("fdcc::/16", #))'
```

## Operations

`pigeon-mesh status` (`--json`) shows the gossip view (endpoints, tags, SWIM state,
conflicts) over a unix socket (`--socket`, default `/run/pigeon-mesh.sock`). `wg show
<iface>` shows the kernel peers. `pigeon-mesh leave` departs gracefully and peers drop
it at once. A node that fails or restarts is held through `--reconnect-timeout`, then
reaped.

## Performance

A joining node is visible cluster-wide within seconds. A failure is detected in a few
seconds (`lan`) or ~30s (`wan` default). Both grow only logarithmically with cluster
size, so it stays responsive into the thousands.

## Limitations

Tags and advertised routes are limited to ~20 entries combined.

## Build

```sh
make build
make test
```
