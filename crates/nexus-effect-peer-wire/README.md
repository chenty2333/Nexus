# `nexus-effect-peer-wire`

`nexus-effect-peer-wire` is the independently consumable Rust source contract
for the frozen `nexus-effect-peer-native-v1` protocol. It owns the exact serde
types, compact field-order JSON encoding, SHA-256 receipt-chain helpers, frozen
contract bytes, and canonical fixture corpus used by the same-boot production
effect peer.

The crate contains no production `EffectRegistry`, child-process server,
ownership log, neutral handoff mapping, kernel adapter, or transport security.
`nexus-effect-peer` depends on this crate and re-exports its public API while
remaining the sole owner of Registry execution and bounded JSON Lines stdio.

The package remains `publish = false`: it is not currently a crates.io API.
Consumers must pin an exact Nexus Git revision or a future immutable release
artifact and retain the corresponding source and license. Source files are
MPL-2.0-covered; the repository license text is
[`../../LICENSE-MPL-2.0`](../../LICENSE-MPL-2.0).

Native v1 is frozen. Compatibility-preserving implementation fixes may retain
the same contract only when the canonical corpus and snapshot digest remain
byte-identical. Any new operation, field, receipt kind, or semantic capability
requires native v2 or an explicitly versioned extension.
