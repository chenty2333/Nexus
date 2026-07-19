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

The causal-coverage evidence path is intentionally separate from release and
wire status. The byte-frozen v1 inventory and 66-cell prospective matrix remain
in `evaluation/production-identity/causal-coverage.toml` and
`evaluation/production-identity/causal-fault-matrix.toml`. Their additive v2
overlay is `evaluation/production-identity/causal-evidence-overlay.toml`. It
records the `root-owned-obligation` vocabulary and freezes the T0 population,
but its exact policy is `locked-empty-until-structured-v3`: the validator
rejects every promotion row without interpreting source or runtime fields.

Consequently v2 makes no source-mapping, call-reachability, QEMU-observation,
receipt, or closure claim. All 66 causal cells remain planned, none is
source-mapped or observed, and `complete` remains false. Opening promotion
requires a separately reviewed v3 schema and validator with the complete
production-target, projection, execution-receipt, retained-artifact, path
containment, date-order, and predecessor-chain gates specified by RFC 0003.

The repository checker validates both files, and the effect-peer test suite
recomputes the canonical native-v1 serde snapshot:

```sh
./x test --quick
cargo test -p nexus-effect-peer --test wire_v1_freeze
cargo test --manifest-path tools/xtask/Cargo.toml causal_evidence_overlay
```

Updating a checkpoint requires a new exact revision, evidence boundary, and
non-claim list. Updating the frozen native-v1 snapshot is allowed only to repair
an accidental mismatch with the already published v1 wire; it must not be used
to add a capability to v1.
