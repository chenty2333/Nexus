# Current CSER differential oracles

`cser-model` contains the independent normalized state machines used by
current `cser-core` differential and Loom tests.

All current oracles import their coordinates from `identity`: an
`EffectId` is always `OperationId + non-zero sequence`, provider bindings are
the exact `WorldId + ProviderId + ProviderGeneration` tuple, and
`ComponentId`/`ArtifactId` are non-zero.  The shared definitions keep the
clean-room model independent from `cser-core` without allowing each oracle to
invent a different identity grammar.

- `composite_effect_oracle` models heterogeneous logical reply and physical
  DMA claim retirement, exact reuse gates, and bounded handoff-relevant
  custody. Its authority observations and bearers bind the complete effect
  coordinate and `ExecutorCoordinate` values.
- `provider_lifecycle_oracle` models provider-generation admission, fencing,
  settlement, and release.
- `recovery_artifact_oracle` models effect-driven recovery-artifact retention,
  exact evidence binding, and conflict detection.

These oracles establish agreement only for the schedules and projections
exercised by their tests. They are not whole-system proofs, production lock or
memory-order models, liveness proofs, physical DMA/IOMMU evidence, or power-loss
models.

Historical pager, personality, runtime, composition, production-identity,
TLA+, and TLC replay models remain available in the `v0.1.0` tag and subsequent
research-history commits. They are not maintained as current-main gates.
