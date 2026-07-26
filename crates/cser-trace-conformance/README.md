# cser-trace-conformance

A **checked trace-conformance witness between TLC traces and the Rust oracle
for two of the fourteen CSER specification families.**

This host-only crate runs the pinned TLA+ model checker on a specification
family, takes the counterexample behaviors it produces, and replays them step
by step against `crates/cser-model`. Every replayed step requires the Rust
reference model to accept the operation the specification took and to
independently produce a state that projects onto the state TLC printed.

Each family owns a module under `src/` holding its action catalog, its
projection, its replay engine, and its witness set. `src/trace.rs`,
`src/value.rs`, `src/tlc.rs`, `src/report.rs`, and `src/sha256.rs` are the
shared harness.

| Family | Module | Witnesses | Traces × transitions | Events covered |
| --- | --- | --- | --- | --- |
| Baseline | `src/cser/` | authored here | 7 × 28 | 11 of 11 |
| Production identity | `src/production_identity/` | released by the spec | 7 × 163 | 25 of 25 |

## What this lane establishes

For **each behavior listed under "Replayed witnesses" below**, and only for
those behaviors:

* Every transition resolves to exactly one specification operation, through a
  catalog derived from the specification source rather than hard-coded, and
  cross-checked against independently derived orderings (see "Fail-loud
  catalogs").
* The Rust oracle accepts that operation in that order. An operation the
  specification takes and the oracle rejects fails the lane.
* After every operation the oracle's full invariant audit passes
  (`Model::check_invariants` / `ProductionIdentityModel::check_invariants`).
* The projected specification variables, computed independently by the
  oracle, equal the values TLC printed. Each family classifies **every**
  declared variable as projected or documented-unprojected, and a test
  asserts that classification is total:
  * baseline: 14 of 18 variables projected;
  * production identity: 11 of 66 variables projected.
* The checker can fail. Both families have negative self-checks that mutate a
  replayed behavior and require rejection with a specific typed error.

## What this lane does NOT establish

* **It is not a refinement proof.** Nothing here quantifies over all
  behaviors of either artifact. It checks the finitely many behaviors the
  listed witnesses produce, which is a successor to prose correspondence, not
  a substitute for a refinement mapping. `NARRATIVE.md`'s statement that the
  specification families are "successors, not mechanically proved refinement
  mappings" remains accurate.
* **It covers two of fourteen specification families.** `specs/cser/`
  contains fourteen specifications. This lane replays `Cser.tla` and
  `ProductionIdentityCser.tla`. The other twelve — `PagerCser`, `IoCser`, the
  five `Personality*` families, `RuntimeFsCser`, `RuntimeNetCser`,
  `CompositionCser`, `LinuxIoCompositionCser`, and `HandoffAdmissionCser` —
  are untouched.
* **It covers only the listed configurations.** Behaviors come from the
  released base configuration of each family plus one witness invariant (and
  where noted a state constraint) each. TLC reports a shortest
  counterexample, so each behavior is one path to the witness state, not the
  set of all such paths.
* **For the production-identity family it says nothing about 55 of the 66
  specification variables.** They are enumerated with reasons in
  `production_identity::replay::UNPROJECTED_VARIABLES`: scenario selectors,
  workload ordering indices the specification itself says exist "only to keep
  the finite graph tractable", closure and receipt history, the reject audit
  trail, and the SMP actor/CPU obligations that the module's own header says
  do not model locks, interrupts, or a hardware memory model. The oracle is
  single-threaded and models none of them. In particular **domain closure
  receipts have no oracle counterpart at all**, so `ClosureReceiptDiscipline`
  is not corroborated here.
* **It says nothing about the kernel.** The oracle is `crates/cser-model`,
  not `kernel/`. Correspondence between the oracle and the kernel
  implementation is a separate question this lane does not touch.
* **It is not a TLA+ parser.** `src/value.rs` accepts only the value
  constructors these two modules use (integers, booleans, strings, model
  values, sets, and functions in either `:>`/`@@` or `[field |-> value]`
  form). Tuples and nested structures are rejected, not approximated.

## Fail-loud catalogs

Neither catalog hard-codes the mapping from a TLC transition to an operation;
both derive it from the specification and require independently derived
orderings to agree, so a spec edit fails construction rather than silently
mis-mapping a replayed behavior.

**Baseline.** `Cser.tla`'s translated `Environment` is a top-level
disjunction, so TLC prints the source line range of the individual disjunct.
`src/cser/actions.rs` pairs those disjunct start lines with the `\* name(...)`
branch comments of the PlusCal source and requires the two orderings to match.

**Production identity.** This module's translation reads
`Environment == /\ \/ ... /\ UNCHANGED <<...>>` — the top-level operator is a
conjunction, so TLC prints one line range spanning the whole definition and
the action label identifies only the *process*, not the operation. The
specification does record the operation, in its `lastEvent` ghost variable.
`src/production_identity/actions.rs` therefore resolves through `lastEvent`
and requires three derived orderings to agree: the `lastEvent := "..."`
assignments of the PlusCal algorithm, the `lastEvent' = "..."` conjuncts of
the checked-in translation, and the declared `ServiceEvents` / `KernelEvents`
/ `IrqEvents` sets cross-checked against each branch's `lastActorKind`. At
replay time the printed process and the recorded actor class must both
corroborate the resolved event.

## Replayed witnesses

Each witness follows the `expect_reachable` pattern of `specs/cser/check.sh`:
an invariant asserts that an interesting state is unreachable, and TLC is
required to refute it. The refutation is the replayed behavior. A witness
that stops failing is a coverage regression, and the lane fails.

### Baseline `Cser` — 7 behaviors, 28 transitions

`Cser.tla` releases no witnesses of its own, so these invariants are defined
in a generated module that extends it. They are the only TLA+ text this lane
authors.

| Witness | Reaches | Transitions |
| --- | --- | --- |
| `CommitAbsent` | an effect crosses its commit point | 3 |
| `CompletionAbsent` | a committed effect completes normally | 4 |
| `EmptyClosureAbsent` | revocation opens and closes with no live effect | 2 |
| `AbortClosureAbsent` | an uncommitted effect cancels, aborts, and returns its credit before closure | 5 |
| `DrainAbsent` | revocation wins after a commit and drains instead of cancelling | 5 |
| `RebindAbsent` | a crash fences the binding, fallback runs, and a replacement binds | 3 |
| `AdoptAbsent` | an orphan uncommitted effect is explicitly adopted by the replacement | 6 |

Their union exercises all eleven operations of `Cser.tla` — `register`,
`prepare`, `commit`, `complete`, `revoke_begin`, `revoke_step`,
`revoke_complete`, `crash`, `rebind`, `adopt`, and the `FallbackPick` process
step.

### `ProductionIdentityCser` — 7 behaviors, 163 transitions

This specification already releases its own reachability witnesses and
`check.sh` already runs them. This lane replays exactly those, under the
released `ProductionIdentityCserSafetyMC.cfg`, so the behaviors it checks are
the repository's own published coverage claims rather than ones this crate
invented.

| Witness (constraint) | Reaches | Transitions |
| --- | --- | --- |
| `IdentityPreservingReadAbsent` (`NormalWitnessScenario`) | workload identities survive one same-effect block read and root closure | 26 |
| `FilesystemCrashAdoptAbsent` (`CrashWitnessScenario`) | crash/snapshot/ready/rebind/adopt changes only the current domain binding | 13 |
| `CommitWinsRevokeRaceAbsent` (`CommitRaceWitnessScenario`) | device batch commit wins the shared root gate before revocation | 26 |
| `RevokeWinsCommitRaceAbsent` (`CommitRaceWitnessScenario`) | root revocation wins the gate and aborts every uncommitted descendant | 23 |
| `ResetIotlbSameEffectAbsent` (`TimeoutWitnessScenario`) | reset and IOTLB timeouts retain the same effect through retry and closure | 30 |
| `CrossRegistryGenerationRejectAbsent` (`RejectWitnessScenario`) | foreign-registry and stale-generation inputs reject without mutation | 19 |
| `ActorSeparationAbsent` (`ActorWitnessScenario`) | abstract service/kernel/IRQ roles retain one identity chain | 26 |

Their union exercises all twenty-five events of the family, covering the
derive chain across three domains, crash/snapshot/ready/rebind/explicit
adopt, device commit and backend publication, the revoke-wins and commit-wins
gate races, the reset and IOTLB timeout/retry/acknowledge paths, both reject
classes, leaf-first abort, domain receipts, and quiescent closure. No event is
uncovered.

## Documented abstraction mismatches

Full statements live in each family's `replay.rs` module documentation. In
summary:

**Both families.** Epoch origin (the specifications number the first epoch
`0`, the oracles number it `1`); effect identity (fixed model values versus
identifiers allocated at registration); and a closure schedule that the
specification leaves open but the oracle fixes deterministically — a
disagreement is reported as a typed divergence error rather than tolerated.

**Baseline only.** Supervisor identity is a boolean in the specification and
an identity in the oracle; `fallbackState` is three-valued against two oracle
booleans.

**Production identity only.** Three findings this lane pinned down that prose
had not stated:

1. **Atomicity divergence.** `acknowledge_iotlb` terminalizes the block
   request *and* all three DMA owners in one atomic oracle call, while the
   specification schedules those four terminalizations as separate
   transitions — and schedules them *after* `RevokeBegin`, whereas the oracle
   performs them at the acknowledgement. Symmetrically,
   `publish_guest_reply` terminalizes the filesystem read and the personality
   syscall together, while the specification splits them across
   `CompleteFilesystem` and `GuestReply`. So the oracle runs ahead of the
   specification in one window and behind it in the other.

   The replayer neither hides nor tolerates this. It maintains a
   desynchronized window naming exactly which effects the two artifacts
   currently disagree about and in which direction; those effects are excluded
   from the lifecycle comparison only while the window holds them, every other
   variable stays under lock-step comparison throughout, the lagging side's
   catch-up step *asserts* that the leading side had already performed exactly
   that terminalization, and the window must be empty when the behavior ends.
   A test that deletes one `CompleteDma` from a replayed behavior confirms the
   accounting is load-bearing.
2. **Credit recycling.** The specification's `freeCredits` counts a returned
   credit as free again; the oracle never recycles, moving credits into a
   separate `returned` bucket so the ledger records where each one went. The
   projection compares `free + returned`.
3. **Credit-class and phase refinement.** The oracle refines the
   specification's four credit types into six classes (a DMA owner takes both
   a `PinnedPage` and a `DmaMapping` credit; the syscall takes an extra
   `GuestReply` credit) and refines `"Committed"` into `Committed`,
   `BackendCompleted`, and `Tombstoned`. The projection folds both back.

Additionally, `ResetAck`, `RejectForeign`, `RejectStaleGeneration`, and
`DomainReceipt` have no oracle operation at all. The replayer applies nothing
for them and still requires the full projection to hold, which checks the
substantive claim that these transitions disturb no state the oracle models.

## Running

```sh
cargo test -p cser-trace-conformance
```

The lane requires `java` and the pinned model checker. It uses
`third_party/tlaplus/1.8.0-227f61b/tla2tools-227f61b.jar`, or the JAR named by
`TLA2TOOLS_JAR`, and refuses to run unless the bytes match the digest recorded
in that directory's `SHA256SUMS`. Each witness runs in its own temporary
directory with a single TLC worker, so behaviors do not depend on scheduling
and nothing is written into the working tree.

`tools/xtask` runs this lane in its unit-test section
(`test CSER trace conformance`) and lints it in its clippy section.
