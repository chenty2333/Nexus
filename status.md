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

The catalog-v6 mechanism cleanup and the first endpoint experiment are
complete. Further core expansion now needs a compositional workload that can
distinguish CSER from a strong workload-specific independent finalizer; the
current fixed tool-plus-DMA experiment does not do so.

The trusted-local reference-adapter, orchestration-hardening, and measured-
performance phase is complete. Remote endpoint authentication, multi-provider
registries, multi-tenancy, and SDK/platform work remain deliberately deferred.
The next research step is the late-bound compositional workload described in
`task.md`, not further mechanism expansion on the fixed tool-plus-DMA topology.

## Current State

The local `main` branch contains the catalog-v6 cleanup, tool-plus-DMA adapters,
strong independent-finalizer baseline, trusted-local CSER2 endpoint contract,
and host-controlled crash matrix in reviewable commits. The reference adapter
uses durable `Accepted`/`Pending`/`Succeeded`/`Failed` states and binds terminal
records to namespace, authority, effect, run, operation, input, catalog, and
schema. Expired and migrated legacy records remain fail-closed tombstones;
only exact-identity absence permits one same-key retry. Initial and recovery
boots share a persisted random identity, and recovery validates that binding
against durable intent before any endpoint request.

The harness supervises endpoint, bridge, UART sink, and QEMU stages; streams
bounded logs; separates timeout budgets; cleans process groups; locks and
digest-checks shared base media; and paces bounded COM2/COM3 frames while the
guest records poll, first-byte, complete-frame, and endpoint timing points. All
55 host regressions pass with resource warnings promoted to errors. A bounded
60-second, 12-worker endpoint soak completed with 64 durable keys, 1,329
idempotent replays, 111 expected conflicts, and zero errors. Focused endpoint,
bridge, journal, TPM, Loom, and recovery fault paths also pass.

Fresh strict-CSER2 real-QEMU matrices use the same seven host-controlled crash
cutpoints and isolated durable ATA, RAM, TPM, and endpoint state for both arms.
The final baseline and CSER runs each complete 7/7 recoveries with totals of 14
evidence-retired components, zero retained claims, and seven reconciliation
steps. This is parity, not a demonstrated CSER safety advantage. Gate-rejection
counts, wall-clock reconciliation delay, permanent-retention proportion, and
administrative-disposition proportion remain explicitly unmeasured.

Measured full-state clone, canonical invariant checking, and projection digest
cost 4.390 ms total at 4,096 live claims in the current release profile, with a
comparable observed range of about 4.39--5.13 ms. The cached 64-KiB ATA fill
still performs 8,384 sector writes, 8,384 reads, and 256 flushes (about 65.5x
write amplification), while removing the old repeated active-bank validation
reads. Runtime mutex wait/hold telemetry is present, but the SMP smoke observes
only one BSP transaction and therefore no contention. These measurements do
not justify a copy-on-write core, segmented journal, or split authoritative
mutex yet; those changes require workload-level dominance or contention
evidence.

The public quick gate, both experiment builds, the production cutover check,
the real in-QEMU PIO-journal ktest, and the separate two-vCPU/multi-thread-TCG
SMP smoke pass. The SMP result proves a CPU1 IPI and CSER persistence smoke in
one boot while explicitly retaining the current BSP-only transaction boundary.
A prior clean-tree catalog-v6 four-boot seal remains the historical production
recovery seal; current generated QEMU receipts and comparison outputs are
Git-ignored evidence, not source-controlled release artifacts.

The HotOS draft now states the I2 evidence layers, exact I3 coordinates,
retirement/abort distinction, evidence-axis separation, Shared boundary,
counterfactual revision metric, and QEMU-versus-physical boundary. It builds as
five pages. RFC 0007 is explicitly the historical v5 baseline and RFC 0008 is
the current v6 amendment.

Local integration is complete: `main` was fast-forwarded to the reviewed CSER
work and is now the development branch. External publication remains
outstanding because local `main` is ahead of `origin/main`; the sibling
`nexus-hotos` checkout has no Git remote. Generated QEMU receipts and
comparison outputs are intentionally Git-ignored, so publishing source commits
alone will not publish the research evidence.

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
- [ ] Publish the local Nexus `main` branch and a small source-bound evidence bundle after external GitHub publication is explicitly authorized; configure a remote for `nexus-hotos` before publishing the paper commit.
