# Architecture

pigeon-mesh is a control-plane-less daemon that keeps a WireGuard full mesh in sync. There is no server, no address allocator, and no CA; the only authority is an offline operator signing key.

## Identity

A node's identity is its WireGuard public key. That key is its name everywhere in the mesh.

## Overlay addressing

Each node derives its own overlay IPv6 address from the sha512 of its public key under a ULA prefix (default `fdcc::/48`). The derivation is self-certifying: every peer's address must be the same function of its key, so no node can claim another's address and no allocator is needed. The prefix must be `/64` or shorter so at least 64 bits of the digest form the host portion, keeping the addresses collision-resistant.

## Grants and trust

An operator signs a grant (ed25519) that binds a node's key with a mandatory expiry, and optionally a DNS name and transit routes. Each node advertises its own grant, and peers admit each other by verifying grants against the trusted signer set (`--signers`, which defaults to the key that signed the node's own grant).

## Gossip and membership

Peers discover each other over HashiCorp memberlist running inside the WireGuard tunnels, seeded from the existing kernel peers. Each node gossips its AllowedIPs and signed grant (which carries its endpoint, name, tags, and authorized routes); the gossip layer is hidden, with only `--gossip-port` and `--profile` (lan/wan/local timing) exposed.

## Route programming

A reconcile loop diffs the desired peer set against the kernel and applies the delta with wgctrl. Only an exact-prefix collision is a contest: WireGuard routes overlapping prefixes by longest-prefix match, so a broad route and a more-specific one coexist and an identity `/128` is never swallowed. A prefix claimed by more than one node (this node's own routes included) is installed for none and logged, and two nodes sharing a key never pick a winner. Not electing a winner is deliberate: guessing an owner could install a spoofed route. Automatic failover among contested claimants is a conscious non-goal.

## Failed peers

A peer that fails is held for `--reconnect-timeout` (default 10m) before it is reaped, so brief partitions and restarts do not tear down tunnels. A graceful `leave` removes the node at once, tearing down only the peers the daemon itself added and never the operator's seed peers. That self-vs-operator distinction is recorded in a `/run` file so it survives a daemon restart; `/run` clears on reboot, exactly as the kernel WireGuard peers it shadows do.

## Transit routes

`sign --route <cidr>` authorizes a node to carry traffic for CIDRs beyond its identity `/128`. A peer's advertised route is installed only if a grant route contains it; unauthorized routes are dropped while the peer stays admitted, and a node that advertises a route its own grant does not authorize fails fast at startup.

## Peer policy

`--peer-policy` is an optional `accept(peer, route)` expr predicate evaluated per advertised CIDR, including the identity `/128`. It returns true to install a route and false to drop it, fails closed on error, and is loaded inline or from an `@file` that reloads on SIGHUP.

## Firewall

A dedicated `ip6` nftables table, on by default, scopes the gossip port to the wg device. `--firewall-rules` adds an expr returning `allow(proto, ports, cond?)` rules: traffic to this node's overlay address is default-deny except what the rules admit, compiled per admitted peer at reconcile. ICMPv6, gossip, and established flows stay open; `--disable-firewall` removes the table.

## Expiry

Expiry lapses only what the operator granted: past a grant's `NotAfter`, a node's routes, name, and tags stop being honored, but its self-certified `/128` persists, so the tunnel stays up and the node re-admits itself on renewal. Expiry lapses authorization; `--revoked` evicts the node. A full time-based cut is both.

## Revocation

`--revoked` is a denylist file of node public keys, one per line. A listed key is denied at admission and a `SIGHUP` reload evicts an already-admitted peer; remove the line and `SIGHUP` to re-admit.

## DNS

`--dns <zone>` serves AAAA records so `<name>.<zone>` resolves to a peer's overlay address, and programs systemd-resolved split-DNS for the zone. It binds port 53 on the overlay address.

## Names

A node's name and tags are operator-signed in its grant (`sign --name`, `sign --tag k=v`), so a peer cannot spoof them. A node signed without a name has no record, and a name two nodes both claim resolves to neither.

## Key custody

`sign` either signs locally with `--key`, or hands the to-be-signed body to an external signer with `--pubkey` and `--signature`. This lets OpenBao/Vault Transit sign with the operator key generated in the vault and never leaving it.

## Operating

The daemon adopts an existing WireGuard interface (`--interface`) that already holds a private key, and takes its own grant (`--signature`), which carries its WireGuard endpoint; it assigns the overlay address itself. `status` and `leave` talk to the running daemon over an owner-only Unix socket (`--socket`).

## Reload

SIGHUP reloads the node's own grant for hitless renewal, with no tunnel teardown, along with the `--revoked` file and the `@file` forms of `--signers`, `--peer-policy`, and `--firewall-rules`.

## Threat model

Trust rests on the offline operator key and the WireGuard transport; the daemon never sits in the datapath. Only admitted nodes reach the gossip layer, and a member cannot forge another's grant or describe another node (meta is self-reported). It can still relay SWIM suspicion about a peer, but that is bounded by memberlist's incarnation refutation and the `--reconnect-timeout` grace that holds a failed peer's tunnel rather than tearing it down, so the worst case is membership-status churn, not eviction. A compromised key is handled by expiry and `--revoked`.
