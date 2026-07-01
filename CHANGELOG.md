0.1.0 (Unreleased)
------------------

BREAKING CHANGES:

* Every grant must now carry an expiry: `sign --ttl` is required (previously optional, needed only for route grants). This bounds the revocation reap horizon.
* A node's DNS name is now the operator-signed `sign --name` carried in its grant, not the daemon `--tag name=` or hostname default (both removed). Names are unspoofable as a result; re-sign nodes with `--name` to keep them named.

FEATURES:

* Active revocation: `sign-revocation` mints an operator-signed anti-grant and `revoke` injects it over the status socket. It gossips the mesh and evicts the node within seconds, and a `--revoked` file (loaded at boot and on `SIGHUP`) is the completeness floor for partitioned or late-joining nodes.
* External signing: `sign` and `sign-revocation` accept `--pubkey` (print the to-be-signed body) and `--signature` (attach a detached signature) instead of `--key`, so an external signer such as OpenBao/Vault Transit can sign with the operator key never leaving the vault.

0.0.1 - 0.0.x
-------------

NOTES:

* Pre-release development; breaking changes between versions.
