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

## Current State

The `cser-evidence-capability-and-conflict` branch contains the completed
catalog-v6 cleanup, tool-plus-DMA adapters, and host-controlled crash matrix in
four reviewable commits layered as core, kernel, experiment harness, and
documentation. It includes typed
Outcome/Quiescence and Recoverable/Ephemeral catalog fields, symmetric
Shared/Exclusive admission across both reverse indexes, last-custodian
conservation, global fail-closed unknown evidence, corrected persistence and
backpressure checks, catalog-v6 cutover wiring, and RFC 0008. The standard
catalog remains Exclusive-only; Shared is a tested extension point with one
complete discharge, reuse, activation, and generation-plus-one lifecycle.

Core all-feature suites, no-std checks, formatting, the production static
cutover, 23 host-harness tests, both experiment builds, and the HotOS PDF build
pass. A clean-tree catalog-v6, journal-schema-6 four-boot QEMU seal at commit
`6bdeae4429ec23145481be6bef17bbdc29f53e2a` records generation `1 -> 2` reuse,
stable repeated recovery, and zero retained claims; its receipt SHA-256 is
`839e821bf02cbdb63ae06503c1460eb32e9281fc95e41078e18ab0b1172f549b`.

The real-QEMU comparison uses the same seven host-controlled container-kill
cutpoints and durable ATA, RAM, TPM, and endpoint state for both variants. The
final reviewed baseline and CSER runs each complete 7/7 recoveries with totals
of 14 evidence-retired components, zero retained claims, and seven
reconciliation steps. This is parity, not a demonstrated CSER safety
advantage: the independent finalizer is deliberately the strongest baseline
for this fixed workload. Gate-rejection counts, wall-clock reconciliation
delay, permanent-retention proportion, and administrative-disposition
proportion remain explicitly unmeasured rather than inferred from the matrix.

The HotOS draft now states the I2 evidence layers, exact I3 coordinates,
retirement/abort distinction, evidence-axis separation, Shared boundary,
counterfactual revision metric, and QEMU-versus-physical boundary. It builds as
five pages. RFC 0007 is explicitly the historical v5 baseline and RFC 0008 is
the current v6 amendment.

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
