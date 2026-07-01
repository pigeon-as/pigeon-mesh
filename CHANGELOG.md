# Changelog

## v0.1.0 (Unreleased)

- Initial release.
- Active revocation: `sign-revocation` mints an operator-signed anti-grant and `revoke`
  injects it on the status socket; it gossips the mesh and evicts the node within seconds.
  A `--revoked @file` floor (boot and `SIGHUP`) covers partitioned and late-joining nodes.
- Breaking: every grant must carry an expiry (`sign --ttl` is now required), which bounds
  the revocation reap horizon.

## v0.0.1 - v0.0.x

- Pre-release development; breaking changes between versions.
