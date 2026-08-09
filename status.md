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
reviewable commits layered as core, kernel, experiment harness, and
documentation. It includes typed
Outcome/Quiescence and Recoverable/Ephemeral catalog fields, symmetric
Shared/Exclusive admission across both reverse indexes, last-custodian
conservation, global fail-closed unknown evidence, corrected persistence and
backpressure checks, catalog-v6 cutover wiring, and RFC 0008. The standard
catalog remains Exclusive-only; Shared is a tested extension point with one
complete discharge, reuse, activation, and generation-plus-one lifecycle.

Core all-feature suites, no-std checks, formatting, the production static
cutover, 27 host-harness tests, both experiment builds, and the HotOS PDF build
pass. A clean-tree catalog-v6, journal-schema-6 four-boot QEMU seal at commit
`1a8f75e319167077631ad1e8433d6ec1cfe0b15e` records generation `1 -> 2` reuse,
stable repeated recovery, and zero retained claims; its locally generated,
Git-ignored receipt SHA-256 is
`c94c66a2b272f8e3d0cc663e11a21127e23e92613f9e7fe6590fd39900e9ef8b`.

The host harness now streams launcher output directly to per-trial logs,
separates the 120-second recovery envelope from the guest's internal 90-second
budget, terminates complete recovery process groups, and parses terminal
receipts with bounded memory. These regressions run on the public quick and
full test paths. Fresh real-QEMU smoke rows for both CSER and the baseline at
`post_endpoint_apply` each recover with two evidence-retired components, zero
retained claims, and one reconciliation step.

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

Publication remains outstanding. This Nexus branch has no upstream and does
not exist on `origin`; the sibling `nexus-hotos` checkout has no Git remote.
Generated QEMU receipts and comparison outputs are intentionally Git-ignored,
so publishing source commits alone will not publish the research evidence.

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
- [ ] Publish the local Nexus branch and a small source-bound evidence bundle after external GitHub publication is explicitly authorized; configure a remote for `nexus-hotos` before publishing the paper commit.
