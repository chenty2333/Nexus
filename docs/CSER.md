# CSER in two pages

This is the short technical statement of the accepted `v0.1.0` Causally Scoped
Effect Revocation (CSER) work. The release claims and evidence below remain
immutable historical material. For current engineering semantics,
[RFC 0006](rfcs/0006-cser-core-semantic-rebaseline.md) is authoritative;
conflicting roadmap, phase, Registry, and compatibility statements in this
page, [VISION.md](../VISION.md), [NARRATIVE.md](../NARRATIVE.md), and
[ARCHITECTURE.md](../ARCHITECTURE.md) are **Superseded**. Those documents do
not override RFC 0006 or describe the current production closure.

## The problem

Revoking a handle prevents *future* use of an authority. It does not account
for the work already *derived* from that authority: a request that crossed a
restartable scheduler, pager, Linux personality, filesystem, or network
service may still own a queue slot, a pinned frame, an in-flight device
request, or an externally visible result. Two complications make ordinary
handle invalidation insufficient:

1. **Service crash.** The replacement instance must reject stale work from the
   dead incarnation without losing obligations that were already committed.
2. **Irreversibility.** Once a device has observed a DMA write or a client has
   observed a reply, no kernel mechanism can honestly claim to undo it.

## The mechanism

One root authority owns a kernel-maintained **causal scope**. Every effect
derived through any service retains explicit ancestry, resource ownership, and
commit state inside that scope. Five ingredients carry the semantics:

- **Two orthogonal epochs.** An *authority epoch* fences a revoked authority
  generation; an independent *binding epoch* fences a crashed or replaced
  service incarnation. Revocation and crash recovery compose without aliasing
  each other's fences.
- **A kernel-owned commit gate.** `Commit` serializes against `RevokeBegin` at
  one linearization point. If revocation wins, old uncommitted work cannot
  first commit afterward; if commit wins, revocation must account for the
  committed effect rather than pretend it away.
- **Typed conserved credits.** Queue slots, frames, and device resources are
  typed budgets that must balance across every terminalization path, so
  closure cannot silently leak or double-release a resource.
- **Reverse-indexed closure.** Per-scope reverse indexes make the affected
  descendants and effects discoverable during closure without a global object
  scan.
- **Post-commit honesty.** Pre-commit work can abort. Post-commit work must
  complete, drain, reset, or retain an explicit tombstone
  (`IndeterminateAfterReset`); CSER never claims to roll back an external
  event. Rebinding never silently adopts stale work — adoption is explicit,
  and a minimal kernel fallback preserves bounded progress after service loss.

## The candidate contribution — and what it is not

No single ingredient above is novel. Capability revocation, epoch fencing,
reverse indexes, transactional commit/abort, typed budgets, and restartable
services are each established prior art (seL4, VINO, TxOS, Cornucopia, RIFL,
Shadow Drivers, Fuchsia/Starnix; see the audited source cards under
`evaluation/stage7b/prior-art-sources/`). The candidate contribution is
**compositional**: one kernel-enforced causal effect scope, with commit gates,
reverse-indexed closure, crash/rebind fencing, conserved credits, and honest
device quiescence, applied *uniformly across multiple restartable services*
beneath one root authority.

The sharpest single differentiator is against Shadow Drivers (OSDI '04), the
closest audited predecessor. Shadow Drivers acknowledges post-submit ambiguity
and chooses replay-or-cancel, accepting duplication or loss risk. CSER instead
exposes a generational same-effect tombstone and an explicit
`IndeterminateAfterReset` closure result: the client learns that the outcome
is indeterminate rather than receiving a silently replayed or dropped
operation. The recorded contribution decision for `v0.1.0` is `narrow` — a
bounded compositional result, not a novelty or firstness claim.

## What the released evidence establishes

The `v0.1.0` release binds twelve PlusCal/TLA+ specification families, an
independent safe-Rust reference model, an OSTD kernel prototype, retained
Linux pressure workloads, and mediated VirtIO/reset/IOMMU receipts into one
reproducible artifact. In the release's own evidence vocabulary:

- **Checked:** 14/14 concurrency harnesses (production transition source under
  a Loom-modeled outer mutex), 20/20 fault-injection cell contracts
  (case-local ledgers, single-vCPU QEMU), 14/14 finite structural-scale
  tuples.
- **Observed:** 29/29 guest-visible TSC measurement cases, with no threshold,
  baseline, or hardware-cycle claim.
- **Not established:** whole-system proof, SMP or production-lock correctness,
  lock freedom, low overhead, Linux/VFS/TCP breadth, rollback of durable
  external effects, a shared production fault scope, or identity-preserving
  same-boot composition with the real-DMA receipt.

The complete claim ledger, including every explicit non-claim, is
[NARRATIVE.md](../NARRATIVE.md); the reproduction boundary is
[ARTIFACT.md](../ARTIFACT.md).

## Where the work is now

RFC 0001, RFC 0005, and their phase numbering are historical inputs to
[RFC 0006](rfcs/0006-cser-core-semantic-rebaseline.md), not the active roadmap.
The implemented rebaseline uses `cser-core` as the portable semantic owner,
an independent safe-Rust oracle, domain-defined reply and DMA obligations and
claims, a versioned journal, ATA PIO journal/outbox providers, TPM2 NV
freshness/catalog binding, boot-time VirtIO/VT-d quarantine, and one recovered
production Registry shared by the NXP3 portal and core-v1 supervisor.

The retained historical receipt for `c06e9f4` covers focused real-task reply
and real-device DMA guests, then four production boots over the same journal,
outbox, and swtpm state. It establishes exact service reap and production
ingress closure, fresh Ready/Rebind tasks, a durable apply intent, a second
successor crash, reconciliation without a second intent, and stable replay
while retaining page and IOVA claims. Exact CI later exposed unsupported swtpm
0.7.3 state-lock and auto-shutdown-opt-out parameters in two successive
candidates. The runner now negotiates the latter capability, but requires a
replacement clean seal and exact-revision CI PASS before current release
closure. The QEMU/swtpm evidence does not establish physical TPM
anti-rollback, physical power-loss durability, crash-persistent PFN/IOVA
custody, SMP, or hardware-general DMA quiescence and does not authorize
resource reuse.
