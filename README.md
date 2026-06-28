# pigeon-mesh

A peer-to-peer WireGuard full-mesh daemon. It automatically adds and removes
peers on an existing WireGuard interface as nodes join or leave the gossip
cluster. Nodes are identified by WireGuard public key. No central server.

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
--help` lists every flag. See the [quickstart](docs/quickstart.md).

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
rotate: add the new key, re-sign, then remove the old (`SIGHUP` reloads). Without
`--signers` a node is pinned to its startup grant's signer: it renews against that
signer fine, but following a signer rotation needs `--signers @file`, reloaded in the
same `SIGHUP`.

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
- **Routes:** a node may advertise extra routes (an exit `0.0.0.0/0`, a subnet via
  `--allowed-ips`) only if its grant authorizes them (`sign --route <cidr>`, which
  needs `--ttl`); an unauthorized route is dropped and shown in `status`. Each node
  then chooses which authorized routes to install with [`--peer-policy`](#peer-policy).

## Peer policy

`--peer-policy` is an [expr](https://expr-lang.org) predicate run once per advertised
route: true installs it, false drops it. It applies to every route, including a peer's
own identity `/128`, so even that can be blocked. A refused route drops locally and
shows in `status`. The policy applies only to this node. Leave it unset to install
everything; pass it inline or as `@file`, reloaded with `SIGHUP`.

In scope: `peer.key`, `peer.endpoint`, `peer.address` (the peer's identity `/128`),
`peer.allowedips`, the candidate `route`, and `cidrSubset(outer, inner)`. Only
`peer.key` and `peer.address` are trustworthy for blocking; `endpoint` and
`allowedips` are peer-advertised and forgeable.

```sh
# block a peer everywhere, including its overlay /128
--peer-policy 'peer.key != "<pubkey>"'

# block one advertised subnet, keep everything else
--peer-policy 'route != "10.0.0.0/24"'

# reachability-only: each peer's identity /128, no extra routes
--peer-policy 'route == peer.address'

# keep identity and gate extra routes to the mesh ULA
--peer-policy 'route == peer.address || cidrSubset("fdcc::/16", route)'

# only the exit node may advertise a default route
--peer-policy 'route in ["0.0.0.0/0", "::/0"] ? peer.key == "<exit-pubkey>" : true'
```

Blocking is local route installation, not membership: a blocked peer keeps its grant,
stays in gossip, and is removed mesh-wide only by unsigning it or letting the grant
expire. Because gossip rides inside the tunnels, blocking a peer's `/128` also severs
this node's gossip path to it; a policy that installs nothing for any peer isolates
this node, and the daemon warns.

## Operations

`pigeon-mesh status` (`--json`) shows the gossip view (endpoints, tags, SWIM state,
conflicts) over a unix socket (`--socket`, default `/run/pigeon-mesh.sock`). `wg show
<iface>` shows the kernel peers. `pigeon-mesh leave` departs gracefully and peers drop
it at once. A node that fails or restarts is held through `--reconnect-timeout`, then
reaped.

## Performance

A joining node is visible cluster-wide within seconds. A failed node is
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
