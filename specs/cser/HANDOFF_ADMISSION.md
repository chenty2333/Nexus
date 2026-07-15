# Handoff-admission successor notes

This note records the bounded local semantics for RFC 0002. It does not report
a production `EffectRegistry` implementation or a joint vISA/Nexus execution.

## Fixed model

`HandoffAdmissionCser.tla` is a declarative TLA+ model with three finite effect
identities:

- one initially prepared effect for the freeze/first-commit winner;
- one initially committed effect for drain and tombstone behavior; and
- one absent effect for pre-freeze registration and post-freeze exclusion.

The model keeps `ScopePhase = Active | Closing | Revoked` separate from the
reversible `Open | Frozen` admission gate. A durable intent precedes freeze.
Abort and commit are typed, mutually exclusive decisions from an abstract
non-equivocating log. Committed-at-freeze effects may complete and publish under
closure ownership; destination activation is modeled only as an external
authorization that requires exact local closure.

## Complete configurations

With the pinned TLC snapshot and automatic workers:

| Configuration | Generated | Distinct | Depth | Boundary |
| --- | ---: | ---: | ---: | --- |
| `HandoffAdmissionCserSafetyMC.cfg` | 100,118 | 32,438 | 25 | complete safety graph with post-commit retention enabled |
| `HandoffAdmissionCserProgressMC.cfg` | 72,470 | 26,390 | 25 | two conditional temporal branches with post-commit retention disabled |

Both graphs leave zero states on the queue. The progress configuration checks
eventual closure after commit or honest retained classification, and eventual
source recovery after abort, under the named weak-fair local actions. It is not
a production liveness or network availability result.

## Fault witnesses

Ten separate reachability traversals bind the exact ordered rows in
`evaluation/handoff-admission/fault-matrix.toml`:

1. intent crash before freeze leaves source active;
2. freeze wins before first commit;
3. first commit wins before freeze;
4. a pre-decision tombstone blocks commit;
5. typed abort is required to thaw;
6. a lost commit acknowledgement replays one decision;
7. source crash rejects the old binding while frozen;
8. duplicate commit-close replays one closure;
9. conflicting abort after commit rejects; and
10. a post-commit retained effect blocks activation without ownership rollback.

## Independent Rust oracle

`cser_model::handoff_admission` independently models the same local contract.
Its first-round gate contains ten deterministic sequence tests, three property
tests, and three Loom schedules. The property tests substitute every decision
identity field and require full-state rejection atomicity. The Loom schedules
cover freeze/first-commit, abort/commit, and duplicate-close serialization under
one modeled outer mutex.

The oracle does not call or import the OSTD `EffectRegistry` transition source.
It uses deterministic finite digest projections, not cryptographic receipts.

## Explicit exclusions

The result assumes a non-equivocating, rollback-free ownership log and one
kernel boot. It does not establish host reboot recovery, malicious rollback
resistance, signature freshness, TEE/KMS correctness, real OSTD lock/IRQ/SMP
behavior, device-state migration, or vISA destination activation.
