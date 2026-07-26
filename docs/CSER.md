# CSER in two pages

This is the short technical statement of Causally Scoped Effect Revocation
(CSER). It is deliberately self-contained: a reader should be able to decide
from this page alone what the mechanism is, what the one candidate
contribution is, and what the released evidence does and does not establish.
The authoritative long-form documents remain [VISION.md](../VISION.md),
[NARRATIVE.md](../NARRATIVE.md), and [ARCHITECTURE.md](../ARCHITECTURE.md);
where this page and those documents disagree, those documents win.

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

Post-release work follows [RFC 0001](rfcs/0001-production-identity.md): does
one causal identity survive a real `pread64` from the Linux personality
through filesystem, block, VirtIO queue publication, and IOMMU ownership to a
guest reply, in one boot, across crash/rebind and root revocation? Bounded
one-vCPU checkpoints currently observe the filesystem-service crash before
device commit and a post-commit, pre-reply crash that closes through a
Registry-free trigger with honest retention. The next contracted step is the
post-commit *adoption* lane ([RFC 0005](rfcs/0005-postcommit-reply-adoption.md)):
whether a replacement incarnation can adopt a retained committed device flight
and publish the guest reply exactly once, or degrade honestly to the tombstone
lane. Real IRQ delivery, repeated crash, and SMP observation remain open
boundaries recorded in `status/current-capabilities.toml`.
