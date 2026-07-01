# Operator key custody with OpenBao/Vault

pigeon-mesh reads `--key` from a file, and a file can be a pipe, so OpenBao/Vault composes
with it directly.

## Generate the key

```sh
bao secrets enable transit
bao write -f transit/keys/mesh type=ed25519 exportable=true
bao read -format=json transit/keys/mesh | jq -r '.data.keys[].public_key'
```

The public key is your `--signers` value.

## Sign and revoke

```sh
pigeon-mesh sign \
  --key <(bao read -format=json transit/export/signing-key/mesh/latest | jq -r '.data.keys[]') \
  --ttl 720h "$(wg show wg0 public-key)" > node.sig

pigeon-mesh sign-revocation \
  --key <(bao read -format=json transit/export/signing-key/mesh/latest | jq -r '.data.keys[]') \
  --grant node.sig "<node-pubkey>" | tee -a revoked.txt | pigeon-mesh revoke
```

Scope the signing box's token to `transit/export/signing-key/mesh`.
