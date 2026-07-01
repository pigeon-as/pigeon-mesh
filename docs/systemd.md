# systemd

networkd creates `wg0` and reads its key from a credential; pigeon-mesh consumes the grant
credential and assigns the overlay address. The node generates and signs nothing.

## Node

`/etc/systemd/network/50-wg0.netdev` (no `PrivateKey`: networkd takes it from credential
`network.wireguard.private.50-wg0`, the file's basename):

```ini
[NetDev]
Name=wg0
Kind=wireguard

[WireGuard]
ListenPort=51820

[WireGuardPeer]
PublicKey=<seed-peer-pubkey>
Endpoint=<seed-host>:51820
AllowedIPs=<seed-peer-overlay-/128>
```

`/etc/systemd/network/50-wg0.network` (wg0 has no address of its own, so don't gate
`network-online.target` on it or reset it):

```ini
[Match]
Name=wg0

[Link]
RequiredForOnline=no

[Network]
KeepConfiguration=yes
```

`/etc/systemd/system/pigeon-mesh.service` (`%d` is the credential dir):

```ini
[Unit]
Description=pigeon-mesh
Requires=systemd-networkd.service
After=systemd-networkd.service sys-subsystem-net-devices-wg0.device network-online.target
Wants=network-online.target
BindsTo=sys-subsystem-net-devices-wg0.device

[Service]
Type=notify
LoadCredentialEncrypted=pigeon-grant
ExecStart=/usr/local/bin/pigeon-mesh --interface wg0 --signature %d/pigeon-grant --endpoint '[{{ GetPublicInterfaces | include "type" "IPv6" | limit 1 | attr "address" }}]:51820'
Restart=on-failure
WatchdogSec=30

# NET_ADMIN drives WireGuard/routes; NET_BIND_SERVICE only matters with --dns on :53
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=multi-user.target
```

## Provisioning

On the node, generate its WireGuard key (it never leaves), sign its grant, and seal both
into the credential store:

```sh
umask 077
wg genkey | tee wg0.key | wg pubkey > wg0.pub
pigeon-mesh sign --key operator.key --ttl 720h --name "$(hostname)" "$(cat wg0.pub)" > node.grant
systemd-creds encrypt --name=network.wireguard.private.50-wg0 wg0.key /etc/credstore.encrypted/network.wireguard.private.50-wg0
systemd-creds encrypt --name=pigeon-grant node.grant /etc/credstore.encrypted/pigeon-grant
```

Keep `operator.key` in a vault and pipe it in rather than on disk ([OpenBao/Vault](openbao-vault.md)).
