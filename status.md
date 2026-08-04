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

The catalog-v6 mechanism cleanup is complete. Further core expansion now needs
a concrete endpoint or experimental result; the active research direction is
baseline comparison, endpoint applicability, a minimal agent-tool adapter, and
measurement of real retention and operational disposition.

## Current State

The `cser-evidence-capability-and-conflict` branch contains the completed,
uncommitted catalog-v6 cleanup over four existing commits. It includes typed
Outcome/Quiescence and Recoverable/Ephemeral catalog fields, symmetric
Shared/Exclusive admission across both reverse indexes, last-custodian
conservation, global fail-closed unknown evidence, corrected persistence and
backpressure checks, catalog-v6 cutover wiring, and RFC 0008. The standard
catalog remains Exclusive-only; Shared is a tested extension point with one
complete discharge, reuse, activation, and generation-plus-one lifecycle.

Core and model all-feature suites, no-std core checks, formatting, and the
production static cutover pass. The current development artifact at
`kernel/nexus-ostd/artifacts/cser-production/combined-proof.txt` records a
catalog-v6, journal-schema-6 four-boot QEMU run with generation `1 -> 2` reuse,
stable repeated recovery, and zero retained claims. It is intentionally a
dirty-tree `NONSEALABLE` proof rather than a release seal; its SHA-256 is
`99b2f5694a7340df6d4fab0cc08c22336f9ba7b6a8f6b32a797009c962ed94d4`.

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
