# Project Status

## Project

Nexus is an experimental operating-system substrate. Its CSER work explores
how escaped effects, logical obligations, and allocator/device-visible resource
claims remain under enforceable custody after the executor that created them
has exited or been replaced. The sibling `nexus-hotos` repository contains the
bounded HotOS position-paper draft.

## Current Direction

The project is intentionally free to make breaking changes: there are no
external users or compatibility obligations. API and document stability are
subordinate to clearer semantics and stronger experiments. RFCs are editable
design notes, and only the evidence supporting the current research claim must
remain current; Git history is sufficient for older development states.

CSER's current safe unknown-evidence rule is deliberately narrow. Unknown
logical outcomes remain subject to reconciliation, while missing quiescence
evidence retains physical claims and refuses reuse. A programmable per-class
disposition algebra is not in current scope.

The evidence-driven asynchronous applicability and safe-scaling phase has
delivered its two primary features: a genuinely asynchronous trusted-local
reference endpoint and a source-labelled, drop-aware applicability trace. A
fresh-media vNext journal and whole-state checkpoint path are available behind
an explicit experimental scheme; the legacy journal remains the default.

Late-bound composition remains a falsification target rather than a presumed
CSER advantage. Kubernetes Job/DRA and NVMe Namespace Management were useful
Gate-0 counterexamples because their provider-native coordination already owns
first observation. Nexus now has a bounded `ChildDescriptorV1`, catalog-bound
single-hop core guard, CSER3 adapter verification, and matched real-QEMU
logical handoff lanes for CSER and a structurally independent strongest
baseline. Both arms complete the same five crash prefixes safely. This proves
the bounded mechanism and comparison path; it does not establish a CSER
advantage or justify a general workflow graph or dynamic component API.

Performance changes remain evidence-gated. The current data does not justify
a core copy-on-write rewrite or splitting the authoritative runtime mutex.
Remote endpoint authentication, multi-provider registries, multi-tenancy,
SDK/platform work, physical-hardware generalization, and paper publication are
deferred.

## Current State

The core contract coordinates are API profile 4, standard catalog 7,
projection 8, recovery snapshot 4, and journal schema 8. Whole-state checkpoint
records encode estates, composites, resources, accepted evidence, and bounded
single-hop roles; recovery validates the canonical projection and rebuilds
derived indexes before an anchored vNext replacement can become active. The
handoff rule is catalog-bound, the verifier receipt digest is durable, and
recovery exposes only a non-authorizing projection that requires revalidation.

The trusted-local endpoint now executes real asynchronous work. POST durably
creates `Accepted` plus a queue entry; leased workers persist `Pending`, execute
against an exact-key provider database, and commit immutable `Succeeded` or
`Failed` evidence. Infrastructure failures remain nonterminal. Recovery queries
the full identity before any same-key retry, 404 is the sole absence authority,
and 410 remains a fail-closed tombstone. The guest carries explicit terminal,
nonterminal, absent, expired, and protocol-failure observations and reports a
bounded deferred-retained result instead of manufacturing failure evidence.

The CSER3 endpoint can return a bounded, evidence-digested 187-byte
`ChildDescriptorV1`. The core and adapter verify its parent, route, catalog,
input, child product, claim class, and exact coordinate. Dedicated resolution
commands recover only the exact evidence-bound fenced parent or child whose
outcome became indeterminate. The matched logical-only QEMU lanes cover
descriptor discovery, durable parent acknowledgement, child installation,
atomic parent release plus child intent, and child first observation. All five
cuts complete in both arms through two stable recovery boots with exactly one
source and one child provider application per row. The baseline uses its own
fixed-record ATA+TPM protocol without calling the CSER engine or verifier
authority. These runs report `device_actions=0`; they are not DMA or physical
quiescence evidence.

The source-labelled trace pipeline uses per-study HMAC pseudonyms, independent
source status, bounded event counts, role-checked provenance, dropped-event
accounting, and right-censoring. A committed bounded sample contains one real
vNext Tool+DMA recovery: endpoint and provider both report the same durable
success; the exact DMA coordinate is rejected while live and admitted after
evidence-backed release; physical quiescence remains right-censored because no
structured device receipt is available. It is a pipeline/applicability sample,
not a workload-prevalence claim.

Phase-resolved real-QEMU measurements cover one control, delayed-provider, and
bounded endpoint-concurrency trial for each journal (`n=1` per point). vNext
compaction advances revision 24 to 25 and reduces the logical replay image from
6,673 to 2,615 bytes, costing 44 sector reads, 44 sector writes, and 10 flushes.
For this small workload its total journal cost is worse than legacy: 359 reads,
359 writes, and 85 flushes versus 153/153/30. The result supports bounded
fresh-media replacement and a smaller post-checkpoint image, not a small-log
performance advantage. Diagnostic TSC values are uncalibrated, and the measured
recovery scope contains no authoritative runtime transaction, so no mutex
contention conclusion follows. Core COW/incremental state and mutex splitting
remain deferred.

The full host discovery suite passes 131 tests with `ResourceWarning` promoted
to an error. The core all-feature tests and all-target Clippy gate, production
cutover assertion, both handoff experiment builds, the full project check, the
real PIO-journal gate, and the independent baseline-handoff ktest pass. The
strict matched handoff campaign passes all five cuts for both variants with
container-kill provenance, 20 terminal recovery receipts, and 20 exact
endpoint/provider ledgers. The prior GitHub quick and rebaseline jobs are
green. A further checkpoint-only reboot was not claimed: the saved trial media
lacked its matching TPM state, so combining it with a different artifact would
not be valid recovery evidence.

Local `main` is the continuing Nexus development branch. The sanitized
applicability and matched-handoff evidence bundles are source-bound to their
executable commits. The handoff bundle publishes the strict aggregate and
digests of the raw variant metrics; SQLite databases, logs, media, TPM state,
raw identities, provider records, and the HMAC key remain local. Per the
current user direction, the sibling `nexus-hotos` checkout and HotOS paper are
not being configured or published.

## Current Tasks

- [x] Align I3 and design text with live `(ResourceId, generation)` conflict coordinates, current-custodian conservation, and intentional per-sharer credit charging.
- [x] Distinguish evidence-backed retirement from pre-escape abort cleanup without forcing their terminal states into one abstraction.
- [x] Keep ReusePermit terminology out of the HotOS narrative while documenting durable pending-reservation authority precisely in code/design notes.
- [x] Remove `EvidenceCapability::settles_outcome()` and align Outcome/Quiescence wording with the separate runtime effect-fact and claim-retirement paths.
- [x] Make v6 unknown evidence explicitly core-wide fail-closed, reject unsupported automatic-retirement contracts, and add one failure-atomic `UnexpectedEvidence` regression.
- [x] Layer the I2 fence/drain evidence accurately; distinguish credit-unit-revisions from future resource-seconds; clarify QEMU/TCG versus physical claims; then capture one final catalog-v6 four-boot trace.
- [x] Add one complete Shared reuse lifecycle test and label Shared as an extension point rather than a standard production feature.
- [x] Stop mechanism expansion after the cleanup and make baseline, endpoint-applicability, agent-tool adapter, and real retention-cost experiments the next research phase.
- [x] Census representative endpoints by recoverable outcome and quiescence evidence, including the crash-recovery downgrade for ephemeral observations.
- [x] Implement the minimal recoverable tool-endpoint plus DMA composite adapter and a strongest workload-specific independent-finalizer baseline.
- [x] Run both variants across the same seven real-QEMU host crash cutpoints with isolated durable media and terminal recovery receipts.
- [x] Compare safety gaps, retained claims, reconciliation work, and the limits of the currently observable gate and delay metrics without manufacturing missing measurements.
- [x] Narrow volatile, legacy, and mutable persistence surfaces; repair automatic-retirement evidence contracts and align the README, CSER guide, RFCs, and HotOS paper.
- [x] Split the work into reviewable core, kernel, experiment, and documentation commits and produce a clean-tree production recovery seal.
- [x] Remove launcher pipe backpressure, separate nested recovery timeout budgets, clean complete recovery process groups, bound receipt parsing, and place the 27 host regressions on the public quick/full paths.
- [x] Fast-forward the completed CSER feature work into the local Nexus `main` branch and make it the continuing development branch.
- [x] Complete the trusted-local reference adapter with a versioned durable terminal-state contract, bound persistent identities, fail-closed retention/migration rules, focused crash tests, readiness, diagnostics, and basic metrics.
- [x] Supervise bridge/endpoint/UART/QEMU readiness and exits with bounded, stage-specific failure reports.
- [x] Make shared base media immutable or lock-protected and digest-checked under parallel baseline/CSER provisioning.
- [x] Replace COM2/COM3 busy-spin waits with bounded polling plus yield/backoff and phase timing while preserving fail-closed deadlines.
- [x] Run targeted long-duration soak, injected endpoint/bridge/journal/TPM failures, and SMP/concurrency validation after the focused paths stabilize.
- [x] Instrument full-state clone/invariant/digest work and replace it with verified incremental or copy-on-write paths only if measurement establishes it as material.
- [x] Measure ATA journal growth and, if dominant, implement an append-oriented segment/checkpoint layout without weakening readback, crash atomicity, or journal-before-anchor ordering.
- [x] Measure runtime mutex queue/hold time and reduce demonstrated serialization without exposing uncommitted state or effects.
- [x] Publish the reviewed local Nexus `main` source branch to GitHub after explicit authorization.
- [x] Correct the endpoint capability census so its adapter description matches the current trusted-local CSER2 and Store-layer contracts.
- [x] Audit Kubernetes Job/DRA and NVMe Namespace Management as primary-source late-bound workload candidates and record their Gate-0 No-Go result.
- [x] Apply the conditional Gate-0 rule before freezing G0/G1: discard the synthetic portable pilot and avoid dynamic-component or real-QEMU expansion when neither candidate establishes a custody gap.
- [x] Record the bounded evidence-availability result, including Pending Store recovery, terminal/expired/absent distinctions, component-local retirement, and the measurements that remain unavailable.
- [x] Repair the Rust 1.95 `unit_arg` CI regression and pass the corresponding local all-target Clippy gate.
- [x] Turn the trusted-local endpoint into a genuinely asynchronous Accepted/Pending worker/provider path and make guest recovery preserve nonterminal custody.
- [x] Implement the source-labelled applicability trace contract and capture one bounded real-QEMU endpoint/provider/gate sample without manufacturing quiescence or prevalence.
- [x] Add an evidence-bound `ChildDescriptorV1`, catalog-bound single-hop core guard, CSER3 adapter verification, and structurally independent portable baseline handoff tests.
- [x] Add the fresh-media vNext append/checkpoint path, phase telemetry, and matched legacy/vNext development measurements; record the small-log I/O regression as well as checkpoint shrinkage.
- [x] Publish a small source-bound, pseudonymized Nexus evidence bundle without raw media, identities, logs, databases, TPM state, or HMAC key.
- [x] Wire the CSER3 single-hop handoff into matched real-QEMU CSER and strongest-baseline runtime lanes before making an end-to-end handoff claim.
- [ ] Configure or publish the sibling `nexus-hotos` remote and paper commit — explicitly deferred by the user; do not perform.
