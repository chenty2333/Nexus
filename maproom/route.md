Maintenance constraint: the user decides when this file is updated. Unless the
user explicitly requests an update to `maproom/route.md`, treat it as read-only
rather than changing it merely because work progressed.

# Nexus route

Profile 6 is the new CSER Core baseline. The next route is to harden the entire
Nexus/CSER system before pursuing another round of aggressive optimization,
then reduce the measured costs of bounded records, persistence, and checkpoints
without weakening exact authority, crash recovery, or infallible prepared
publication.

Breaking APIs and on-disk formats remain acceptable during this pre-consumer
phase when a verified defect or measured benefit justifies them. Optimization
must not restore a compatibility model, a whole-state transition candidate, or
fallible work after durable authority advances.

## 1. Review the complete authority closure

Review the portable core, independent model, journal and checkpoint recovery,
provider and artifact retirement, bounded handoff, OSTD production owner,
reply and DMA adapters, TPM anchor, build gates, and their concurrency and
failure boundaries as one system. Pay particular attention to exact identity
and verifier provenance, delta completeness, derived-index conservation,
canonical projection reconstruction, hostile durable input, and every crash
cut around journal, anchor, and in-memory publication.

## 2. Resolve verified correctness findings

Fix concrete findings before changing storage granularity. Preserve failure
atomicity and fail-closed recovery, add focused regressions for each defect,
and keep full reconstruction and independent oracles as checks on the
incremental implementation. The review is not a claim that bugs are
absent; it establishes a better-understood baseline for optimization.

## 3. Measure the remaining cost structure

Separate bounded record cloning, persistent-map path allocation, journal
encoding and ownership, checkpoint encoding and hashing, recovery rebuilding,
and post-publication reclamation. Compare fixed touched effects across growing
unrelated state and across small, medium, and large bounded composites. Let the
measurements decide whether record layout, authenticated paths, batching, or a
single writer is the limiting factor.

## 4. Reduce bounded record cloning

Change record granularity only where measurements show that cloning a bounded
effect dominates ordinary transitions. A more local component or claim layout
may replace coarse composite cloning, but the authoritative grammar, atomic
multi-component transitions, canonical projection, and reconstructable derived
indexes remain unchanged.

## 5. Reduce persistence cost

Prepare ownership and serialization before entering the durable boundary.
Reduce redundant record and buffer copies, and consider streaming or vectored
encoding where it preserves canonical bytes. Journal append must still precede
trusted-anchor advancement, and the post-anchor suffix must remain an
assignment-only publication of already-owned values.

## 6. Reduce checkpoint cost

Prefer a canonical single-pass encoder and hasher, bounded scratch storage, and
direct publication to inactive durable storage before introducing a second
incremental checkpoint grammar. Checkpoints must remain self-validating and
recovery must still rebuild all derived indexes and the complete projection.

## 7. Re-establish clean-source evidence

After review and optimization stabilize, rerun the Core and independent
oracles, persistence and recovery cuts, production OSTD gates, bounded QEMU
workloads, and comparable performance profiles from one clean source. Keep
logical, emulated, durable-I/O, and physical-hardware claims distinct.

External Harness integration, plugin loading, dependency injection, provider
resolution, general workflow DAGs, remote trust, and physical evidence
production remain outside this route. The sibling HotOS paper also remains
outside repository authority unless the user separately authorizes it.
