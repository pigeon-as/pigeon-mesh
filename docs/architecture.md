# Architecture

pigeon-mesh is a control-plane-less daemon that keeps a WireGuard full mesh in sync. There is no server, no address allocator, and no CA; the only authority is an offline operator signing key.

## Identity

A node's identity is its WireGuard public key. That key is its name everywhere in the mesh.

## Overlay addressing

Each node derives its own overlay IPv6 address from the sha512 of its public key under a ULA prefix (default `fdcc::/48`). The derivation is self-certifying: every peer's address must be the same function of its key, so no node can claim another's address and no allocator is needed.

## Grants and trust

An operator signs a grant (ed25519) that binds a node's key with a mandatory expiry, and optionally a DNS name and transit routes. Each node advertises its own grant, and peers admit each other by verifying grants against the trusted signer set (`--signers`, which defaults to the key that signed the node's own grant).

## Gossip and membership

Peers discover each other over HashiCorp memberlist running inside the WireGuard tunnels, seeded from the existing kernel peers. Each node gossips its endpoint, AllowedIPs, keepalive, tags, and signed grant; the gossip layer is hidden, with only `--gossip-port` and `--profile` (lan/wan/local timing) exposed.

## Route programming

A reconcile loop diffs the desired peer set against the kernel and applies the delta with wgctrl. A route claimed by more than one peer is installed for none and logged, and two nodes sharing a key never pick a winner.

## Failed peers

A peer that fails is held for `--reconnect-timeout` (default 10m) before it is reaped, so brief partitions and restarts do not tear down tunnels. A graceful `leave` removes the node at once.

## Transit routes

`sign --route <cidr>` authorizes a node to carry traffic for CIDRs beyond its identity `/128`. A peer's advertised route is installed only if a grant route contains it; unauthorized routes are dropped while the peer stays admitted, and a node that advertises a route its own grant does not authorize fails fast at startup.

## Peer policy

`--peer-policy` is an optional `accept(peer, route)` expr predicate evaluated per advertised CIDR, including the identity `/128`. It returns true to install a route and false to drop it, fails closed on error, and is loaded inline or from an `@file` that reloads on SIGHUP.

## Revocation

`sign-revocation` mints an operator-signed anti-grant, and `revoke` injects it over the socket; it gossips as a grow-only set and evicts the node within seconds. A revocation has no valid-from window, so a clock-skewed node still honors it, and the `--revoked` file is the on-disk floor for nodes that miss the gossip. Each anti-grant is reaped once the revoked grant would have expired anyway.

## DNS

`--dns <zone>` serves AAAA records so `<name>.<zone>` resolves to a peer's overlay address, and programs systemd-resolved split-DNS for the zone. It binds port 53 on the overlay address.

## Names

A node's name is the operator-signed `sign --name` carried in its grant, so a peer cannot spoof another's name and a node signed without one has no record. A name two nodes both claim resolves to neither. Unsigned `--tag k=v` metadata also gossips, but it is advisory.

## Key custody

`sign` and `sign-revocation` either sign locally with `--key`, or hand the to-be-signed body to an external signer with `--pubkey` and `--signature`. This lets OpenBao/Vault Transit sign with the operator key generated in the vault and never leaving it.

## Operating

The daemon adopts an existing WireGuard interface (`--interface`) that already holds a private key, and takes its endpoint (`--endpoint`) and its own grant (`--signature`); it assigns the overlay address itself. `status`, `leave`, and `revoke` talk to the running daemon over an owner-only Unix socket (`--socket`).

## Reload

SIGHUP reloads the node's own grant for hitless renewal, with no tunnel teardown, along with the `--revoked` file and the `@file` forms of `--signers` and `--peer-policy`.
