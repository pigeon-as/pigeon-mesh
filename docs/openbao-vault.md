# Operator key custody with OpenBao/Vault

pigeon-mesh either signs with a local `--key`, or hands the to-be-signed bytes to an
external signer with `--pubkey`/`--signature`. The second lets OpenBao/Vault Transit sign,
so the operator key is generated in the vault and never leaves it.

## Generate the key

```sh
bao secrets enable transit
bao write -f transit/keys/mesh type=ed25519
pubkey=$(bao read -format=json transit/keys/mesh | jq -r '.data.keys[].public_key')
```

`$pubkey` is your `--signers` value. The private key is not `exportable`, so it only ever
signs inside the vault.

## Sign a node

Emit the unsigned grant, have Transit sign it, and complete it with the signature:

```sh
unsigned=$(pigeon-mesh sign --pubkey "$pubkey" --ttl 720h --name "$(hostname)" "$(wg show wg0 public-key)")
sig=$(bao write -field=signature transit/sign/mesh input="$unsigned" | sed 's/^vault:v1://')
echo "$unsigned" | pigeon-mesh sign --signature "$sig" > node.sig
```

## Revoke a node

```sh
unsigned=$(pigeon-mesh sign-revocation --pubkey "$pubkey" --grant node.sig "<node-pubkey>")
sig=$(bao write -field=signature transit/sign/mesh input="$unsigned" | sed 's/^vault:v1://')
echo "$unsigned" | pigeon-mesh sign-revocation --signature "$sig" | tee -a revoked.txt | pigeon-mesh revoke
```

Scope the signing box's token to `transit/sign/mesh`.
