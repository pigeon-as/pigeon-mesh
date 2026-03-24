# pigeon-mesh

WireGuard mesh daemon for pigeon infrastructure. Manages the overlay network plane on every node:

- **WireGuard interface** — create `wg0`, generate/persist keypair, configure peers via `wgctrl`.
- **Memberlist gossip** — AES-256 encrypted peer discovery. Nodes broadcast their WG pubkey, endpoint, and overlay address. Peers are reconciled on membership changes.
- **Pairwise PSK** — fleet secret (`wg_psk`) is used to derive per-pair PresharedKeys via `HKDF-SHA256(fleet_psk, sort(pubA || pubB), "pigeon-mesh wireguard pairwise psk v1")`. The fleet secret stays in userspace; only derived per-pair keys enter the kernel.
- **Address transposition** — nftables netdev rules on `wg0` transpose network/host fields of pigeon addresses (`fdaa::/16`) so each host owns a non-overlapping `/48` for WireGuard cryptokey routing.
- **NAT masquerade** — optional CGNAT masquerade for VM egress via `egress_cidr`. Filter rules (WG port, memberlist, wg0 accept) are managed by pigeon-fence.
- **sysctl verification** — verifies IPv4/IPv6 forwarding is enabled (fail-fast). Does not set sysctl — image `sysctl.conf` owns that.

Runs as a systemd unit on all nodes. Must start before Consul/Vault/Nomad — the mesh is the foundation for all inter-node communication.

## Usage

```
pigeon-mesh --config=/etc/pigeon/mesh.json
```

Example config:

```json
{
  "seeds": ["10.0.0.1", "10.0.0.2"],
  "gossip_key": "base64...",
  "wg_psk": "base64...",
  "endpoint": "1.2.3.4",
  "egress_cidr": "100.64.0.0/24"
}
```

Required fields: `seeds`, `gossip_key`, `wg_psk`. Optional fields: `interface` (`wg0`), `listen_port` (`51820`), `data_dir` (`/var/lib/pigeon-mesh`), `log_level` (`info`), `endpoint`, `egress_cidr`.

WireGuard private keys are persisted to `<data_dir>/privkey` and reused across restarts. Overlay address is always derived from hostname via `pigeon-addr-plan.PigeonHostIP`.

## Build

```bash
make build    # Build binary → build/pigeon-mesh
make test     # Run unit tests
```
