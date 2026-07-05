0.1.0 (Unreleased)
------------------

BREAKING CHANGES:

* Every grant must now carry an expiry: `sign --ttl` is required (previously optional, needed only for route grants). This bounds passive de-authorization.
* A node's DNS name is now the operator-signed `sign --name` carried in its grant, not the daemon `--tag name=` or hostname default (both removed). Names are unspoofable as a result; re-sign nodes with `--name` to keep them named.
* A node's tags are now operator-signed via `sign --tag k=v` in its grant, not the daemon `--tag` flag (removed). Verified at every peer like the signed name, so they can be trusted; re-sign nodes with `--tag` to keep them tagged.

FEATURES:

* Revocation via a `--revoked` denylist file of node public keys, one per line, loaded at boot and on `SIGHUP`: a listed key is denied at admission and an already-admitted peer is evicted on reload; remove the line to re-admit.
* External signing: `sign` accepts `--pubkey` (print the to-be-signed body) and `--signature` (attach a detached signature) instead of `--key`, so an external signer such as OpenBao/Vault Transit can sign a grant with the operator key never leaving the vault.

0.0.1 - 0.0.x
-------------

NOTES:

* Pre-release development; breaking changes between versions.
