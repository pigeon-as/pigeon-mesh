0.1.0 (Unreleased)
------------------

BREAKING CHANGES:

* Every grant must now carry an expiry: `sign --ttl` is required (previously optional, needed only for route grants). This bounds the revocation reap horizon.

FEATURES:

* Active revocation: `sign-revocation` mints an operator-signed anti-grant and `revoke` injects it over the status socket. It gossips the mesh and evicts the node within seconds, and a `--revoked` file (loaded at boot and on `SIGHUP`) is the completeness floor for partitioned or late-joining nodes.

0.0.1 - 0.0.x
-------------

NOTES:

* Pre-release development; breaking changes between versions.
