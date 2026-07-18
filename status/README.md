# Current capability status

This directory records the moving implementation boundary without changing the
accepted `v0.1.0` manifest, release bundle, tag, DOI, or frozen evaluation
catalog. A current checkpoint is an exact-revision engineering observation. It
is not a release acceptance claim and it cannot inherit evidence from an older
or external checkpoint.

`current-capabilities.toml` is the machine-readable checkpoint ledger. Local
entries identify Nexus implementation observations. External entries identify
separately owned integration observations and pin the exact Nexus checkpoint
they consumed. External evidence never upgrades the corresponding Nexus-local
claim.

`effect-peer-native-v1.json` freezes the same-boot native JSON Lines protocol
used by `nexus-effect-peer`. Native v1 permits compatibility-preserving fixes
only. New commands, fields, receipt kinds, or semantics require native v2 or an
explicitly versioned extension with different schema identifiers.

The repository checker validates both files, and the effect-peer test suite
recomputes the canonical native-v1 serde snapshot:

```sh
./x test --quick
cargo test -p nexus-effect-peer-wire --test frozen_v1
cargo test -p nexus-effect-peer --test wire_v1_freeze
```

`crates/nexus-effect-peer-wire/contract/effect-peer-native-v1.json` is a
byte-identical consumer-package mirror. The wire-crate test checks that it has
not diverged from this status contract and exports the canonical fixture
population used to recompute the frozen digest. The mirror does not create a
second semantic authority: this status file remains the repository contract.

Updating a checkpoint requires a new exact revision, evidence boundary, and
non-claim list. Updating the frozen native-v1 snapshot is allowed only to repair
an accidental mismatch with the already published v1 wire; it must not be used
to add a capability to v1.
