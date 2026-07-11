# CSER reference model

`cser-model` is the executable Rust oracle for Causally Scoped Effect
Revocation. It fixes the same linearization contract as
`specs/cser/Cser.tla` without depending on the legacy Nexus kernel.

The model covers:

- authority and supervisor binding epochs;
- `Register -> Prepare -> Commit -> Complete`;
- `RevokeBegin -> RevokeStep -> RevokeComplete`;
- supervisor `Crash -> FallbackPick -> Rebind -> Adopt`;
- per-scope live-effect indexes and proportional revocation work;
- single terminalization and scalar budget conservation.

`Commit` is the effect commit linearization point. `RevokeBegin` atomically
closes the old authority epoch. Effects that committed first must complete or
drain; effects for which revocation won must abort. The model does not promise
rollback after an external effect crossed its commit point.

Run the tests and canonical trace from the repository root:

```sh
cargo test -p cser-model --all-features
cargo check -p cser-model --no-default-features --lib
cargo run -p cser-model --bin cser-model
```

The library is `no_std + alloc` compatible and contains no unsafe code. Its
trace action names and fields are shared with the TLA+ model and the OSTD
scheduler spike under `experiments/ostd-cser-spike`.
