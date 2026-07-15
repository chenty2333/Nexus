# Handoff-admission first-round evaluation

This directory freezes the falsification contract for the prospective Nexus
handoff-admission profile in RFC 0002. It is not part of the accepted `v0.1.0`
evaluation bundle.

`fault-matrix.toml` is normative. Its ten ordered rows map one-to-one to TLA+
reachability witnesses and independent safe-Rust sequence tests. The research
runner rejects row, witness, test, invariant, TCB, or exclusion drift before it
runs the model.

The first round assumes a non-equivocating ownership log and no host reboot or
malicious rollback. The normative matrix remains the frozen contract for the
independent first-round model and therefore records
`production_registry_modified=false`. The later v2 receipt separately records
`production_registry_modified=true` for the production `EffectRegistry`
refinement. Each value describes its containing evidence layer; verifiers must
not reinterpret the historical matrix as the complete v2 gate.

The v2 research receipt additionally binds the dependency-free admission gate,
the production `EffectRegistry`, two substrate Loom races, and eleven production
Registry sequence tests. Those tests map the nine Nexus-owned matrix behaviors
and also pin full receipt identity, repeatable abort generations, abort
preservation of the same precommit effect, incremental abort progress,
empty-close failure atomicity, partial-error progress preservation, and
fail-closed device-precommit admission. A pending or enrolled but unpublished
device root rejects freeze before it linearizes; this round does not claim a
reversible predecision device reset. The remaining
durable-intent-before-call behavior belongs to the external ownership adapter.
This is an in-memory same-boot production-source refinement, not OSTD execution
or joint vISA/Nexus qualification.
