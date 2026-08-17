# Current CSER differential oracles

`cser-model` contains the independent normalized state machines used by
current `cser-core` differential and Loom tests.

- `core_rebaseline_oracle` models authority, recovery, commit, settlement,
  evidence ordering, and freshness without importing production commands.
- `composite_effect_oracle` models heterogeneous logical reply and physical
  DMA claim retirement, exact reuse gates, and bounded handoff-relevant custody.

These oracles establish agreement only for the schedules and projections
exercised by their tests. They are not whole-system proofs, production lock or
memory-order models, liveness proofs, physical DMA/IOMMU evidence, or power-loss
models.

Historical pager, personality, runtime, composition, production-identity,
TLA+, and TLC replay models remain available in the `v0.1.0` tag and subsequent
research-history commits. They are not maintained as current-main gates.
