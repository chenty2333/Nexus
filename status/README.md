# Historical capability status

This directory preserves the exact-revision capability ledger and native-v1
wire corpus that predate the CSER Core Rebaseline. Its July 17 checkpoints are
historical observations, not the current implementation boundary. RFC 0001,
RFC 0005, the old Registry, and the live effect-peer service named below are
**Superseded** by
[`docs/rfcs/0006-cser-core-semantic-rebaseline.md`](../docs/rfcs/0006-cser-core-semantic-rebaseline.md).
Current replacement-seal status, historical receipt, and exact-CI disposition
are recorded in that RFC and
`docs/research/cser-core-production-cutover-release-ledger.md`.

`current-capabilities.toml` retains its filename for compatibility with the
accepted archive, but its classification and checkpoint statuses explicitly
mark it historical. External entries remain separately owned observations and
never upgrade either the old Nexus checkpoint or the rebaselined core.

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

The current repository checker preserves the wire bytes without rebuilding the
deleted live peer or invoking superseded research workflows:

```sh
./x test --quick
cargo test -p nexus-effect-peer-wire --test frozen_v1
```

`crates/nexus-effect-peer-wire/contract/effect-peer-native-v1.json` is a
byte-identical consumer-package mirror. The wire-crate test checks that it has
not diverged from this status contract and exports the canonical fixture
population used to recompute the frozen digest. The mirror does not create a
second semantic authority: this status file remains the repository contract.

Do not update this file to make an old checkpoint look current. New rebaseline
evidence requires a clean exact revision, its own evidence boundary and
non-claim list, and the RFC 0006 release ledger. Updating the frozen native-v1
snapshot is allowed only to repair an accidental mismatch with the already
published v1 wire; it must not be used to add a capability to v1.
