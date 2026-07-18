# Native-v1 source provenance

`nexus-effect-peer-wire` is a repository-local extraction of the frozen native
effect-peer wire implementation. It is not imported from a third-party
project, and this file is not a binary or source-to-binary attestation.

## Lineage

- Extraction base: Nexus Git revision
  `a8c73f2f889825efa58e1fc43d9178ca06017882`.
- Original source: `crates/nexus-effect-peer/src/wire.rs`.
- Original source SHA-256:
  `bb28e9712e30a0c1812726ae6b5c520446c0540f7d37b7b1ed14a2a83d3fd97e`.
- Repository freeze contract: `status/effect-peer-native-v1.json`.
- Freeze contract SHA-256:
  `d9bec4547eb0d09a081033e619bb16179c36d992db2b754659594831e21737d2`.
- Frozen canonical snapshot SHA-256:
  `036bfa21c9c1359755d9cf9a8223e39b7ea1d4793bf4fa948efbf75c9fa52b08`.

The extraction moved the serde types, canonical compact-JSON helpers, receipt
digest helpers, and their unit tests without changing those definitions. The
new `frozen_v1` module makes the existing fixture population available to
independent consumers and verifies a byte-identical package-local copy of the
repository freeze contract.

## Licensing and consumption

The extracted source is covered by MPL-2.0. The license text is retained at
[`../../LICENSE-MPL-2.0`](../../LICENSE-MPL-2.0), and source files carry SPDX
identifiers. Dependencies keep their own licenses; this repository does not
relicense them.

The package is deliberately `publish = false`. A consumer must pin an exact
Nexus Git revision or a future immutable Nexus source artifact, verify the
freeze and snapshot hashes, and retain the corresponding MPL-2.0 source and
notices. No standalone crate release, immutable archive, signature,
attestation, or cross-repository qualification receipt exists yet.
