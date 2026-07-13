# Related-work full-text preflight

Status date: 2026-07-14

This note records the bounded follow-up for the two Stage 7B rows that were previously metadata-only. It separates a resolved primary-text audit from an unresolved search; an abstract, citation record, search result, or related paper is not treated as full text.

## Shadow Drivers: resolved

The row was previously labeled `shadow-drivers.device-recovery` but cited the earlier Nooks paper, *Improving the Reliability of Commodity Operating Systems*. The primary-source follow-up corrected that bibliographic mismatch instead of treating Nooks as the Shadow Drivers paper. The exact OSDI 2004 paper, *Recovering Device Drivers* by Swift, Annamalai, Bershad, and Levy, is available from Michael Swift's author-hosted paper directory and has a matching USENIX conference record:

- full text: <https://pages.cs.wisc.edu/~swift/papers/recovering-drivers.pdf>
- USENIX record: <https://www.usenix.org/conference/osdi-04/recovering-device-drivers>
- observed form: 15-page PDF with the matching title and four authors
- SHA-256 of downloaded PDF bytes: `7489c8611bf48fe03cd84bc0c56757a7f95c2b8790cf95cb00106418e2c8a346`

The audit covered sections 3.2-4.5, with particular attention to passive monitoring, active recovery, and limitations. Shadow Drivers already establishes per-driver request/configuration tracking, recovery-time proxying, resource reattachment, interrupt disable, removal of I/O mappings to prevent DMA where supported, and replay or cancellation of outstanding requests. Most importantly for the CSER boundary, it explicitly recognizes the post-submit ambiguity: if a driver fails after submitting a request to a device but before reporting completion, the shadow cannot know whether the device processed it. The paper chooses class-specific replay or cancellation and admits duplication or loss risk; it does not expose a generational same-effect tombstone or an honest `IndeterminateAfterReset`-style closure result.

## Atomic RPC: unresolved

Target: Kwei-Jay Lin and John D. Gannon, *Atomic Remote Procedure Call*, IEEE Transactions on Software Engineering 11(10), 1985, pages 1126-1135, DOI <https://doi.org/10.1109/TSE.1985.231860>.

Search routes and outcomes:

- The DOI, IEEE Xplore document `1701928`, and the legacy IEEE Computer Society record expose bibliographic metadata and an abstract. The publisher marks the full article for sign-in or purchase; direct PDF and stamp endpoints did not return a PDF in this environment.
- Crossref exposes the citation and an IEEE similarity-checking link, not openly retrievable full text.
- Semantic Scholar identifies the matching DOI and reports closed access with no open-access PDF URL.
- IA Scholar's exact-title record says `No known archive`.
- Kwei-Jay Lin's current UC Irvine profile, faculty site, publications page, and curriculum-vitae page expose no copy of the target paper.
- University of Maryland's DRUM API returned no exact-title or exact-author item for the target.
- NUS handle `1900.100/1263` is a different work, *A Performance Evaluation of an Atomic Remote Procedure Call Manager*; its bitstream also reports that the requested file is unavailable. It is not substituted for the target.
- A ResearchGate record and search-result links exist, but no openly retrievable author-uploaded full text was obtained. They are not used as evidence.

The IEEE abstract mentions RPC atomicity in terms of totality and serializability and mentions backup processors, but that abstract is insufficient to audit the detailed protocol, failure model, invariants, or limitations. The `atomic-rpc` source card therefore remains `metadata-only-unavailable`, and no matrix mechanism detail is inferred from summaries.

## Comparison axes still requiring the Atomic RPC full text

| Axis | Full-text question |
| --- | --- |
| Authority scope | Is identity attached only to one RPC or transaction, or can it derive and close a recursive effect tree? |
| Async effects | Which outstanding calls, callbacks, participants, and delayed effects are tracked, and by what reverse index? |
| Commit ordering | What is the exact totality/serializability commit point, and how does it race with cancellation or failure? |
| Crash and replacement | Are old participants or replies fenced by generations, and can a replacement adopt the same operation identity? |
| Resource accounting | Are resources merely logged for recovery, or conserved in a typed per-authority ledger? |
| External effects | What happens after an effect is externally or device-visible and cannot honestly be rolled back? |
| Terminal result | Can the caller distinguish completed, aborted, and indeterminate-after-commit outcomes without double publication? |

## Falsifiable v0.2 contribution boundary

The v0.2 claim to test is deliberately compositional: within the fixed production workload, one causal-authority identity should span the personality syscall, filesystem read, block request, and device/DMA ownership; domain-local crash and replacement should preserve or reject that identity by generation; revoke should be ordered against first device commit; and post-commit reset plus IOTLB recovery should return an explicit closure result rather than claim rollback.

This does not claim generic capability revocation, driver isolation, resource tracking, atomic RPC, exactly-once execution, request cancellation, or device recovery separately.

The contribution boundary is refuted or must be narrowed if a primary full-text predecessor already combines, under one request-derived authority identity, recursive cross-service effect tracking, replacement-generation fencing, conserved resource ownership, revoke-versus-external-commit ordering, and an identity-preserving indeterminate/tombstone result through device reset and translation invalidation. Atomic RPC remains a live refutation candidate only until its full protocol can be audited against those concrete axes.
