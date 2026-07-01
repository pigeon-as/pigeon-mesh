# Operator key custody with OpenBao/Vault

pigeon-mesh either signs with a local `--key`, or hands the to-be-signed bytes to an
external signer with `--pubkey`/`--signature`. The second lets OpenBao/Vault Transit sign,
so the operator key is generated in the vault and never leaves it.

## Generate the key

```sh
bao secrets enable transit
bao write -f transit/keys/mesh type=ed25519
signers=$(bao read -format=json transit/keys/mesh | jq -r '.data.keys[].public_key')
```

`$signers` is your `--signers` value. The private key is not `exportable`, so it only ever
signs inside the vault.

## Sign a node

Emit the unsigned grant, have Transit sign it, and complete it with the signature:

```sh
unsigned=$(pigeon-mesh sign --pubkey "$signers" --ttl 720h --name "$(hostname)" "$(wg show wg0 public-key)")
signature=$(bao write -field=signature transit/sign/mesh input="$unsigned" | sed 's/^vault:v1://')
echo "$unsigned" | pigeon-mesh sign --signature "$signature" > node.sig
```

## Revoke a node

```sh
unsigned=$(pigeon-mesh sign-revocation --pubkey "$signers" --grant node.sig "<node-pubkey>")
signature=$(bao write -field=signature transit/sign/mesh input="$unsigned" | sed 's/^vault:v1://')
echo "$unsigned" | pigeon-mesh sign-revocation --signature "$signature" | tee -a revoked.txt | pigeon-mesh revoke
```

Use the node's longest-lived grant: the anti-grant reaps at that grant's expiry, and a grant that
outlives it would re-admit the key.

## Automate with Vault Agent

Two `template` stanzas in your Vault Agent config render the trust files, so rotation and revocation
need no operator:

```hcl
template {
  destination = "/etc/pigeon-mesh/signers"
  command     = "pkill -HUP pigeon-mesh"
  contents    = "{{ range (secret \"transit/keys/mesh\").Data.keys }}{{ .public_key }}\n{{ end }}"
}
template {
  destination = "/etc/pigeon-mesh/revoked"
  command     = "pkill -HUP pigeon-mesh"
  contents    = "{{ range secrets \"kv/metadata/mesh/revoked\" }}{{ with secret (printf \"kv/data/mesh/revoked/%s\" .) }}{{ .Data.data.antigrant }}\n{{ end }}{{ end }}"
}
```

Point the daemon at them with `--signers @/etc/pigeon-mesh/signers --revoked @/etc/pigeon-mesh/revoked`.
Rotate with `bao write -f transit/keys/mesh/rotate` (both keys verify until you `trim`). Revoke
fleet-wide by storing the anti-grant, which every agent renders into `--revoked`:

```sh
unsigned=$(pigeon-mesh sign-revocation --pubkey "$signers" --grant node.sig "<node-pubkey>")
signature=$(bao write -field=signature transit/sign/mesh input="$unsigned" | sed 's/^vault:v1://')
antigrant=$(echo "$unsigned" | pigeon-mesh sign-revocation --signature "$signature")
bao kv put kv/mesh/revoked/<node-name> antigrant="$antigrant"
```
