# Bounded async/vNext applicability sample

> **Historical sample.** These files remain source-bound to the earlier COW
> vNext implementation at `59dee403...`; their performance numbers do not
> describe the final in-place append path. The current clean-source measurements
> and bounded optimization decision are in
> [`../cser-async-vnext-final/`](../cser-async-vnext-final/).

This directory is a sanitized, source-bound development sample generated from
Nexus commit `59dee4031ead7736275e5314c22a871bcf053aba` on 2026-08-10. It is
evidence that the reference path and exporter work together; it is not a
prevalence estimate, a physical-hardware result, or a product benchmark.

The applicability trace comes from one real-QEMU CSER Tool+DMA recovery using
the fresh-media vNext journal. The endpoint and provider independently expose
the same durable terminal outcome. The allocator gate reports one exact
`(resource, generation)` rejection while the claim is live and admission for
that same pseudonymous coordinate after evidence-backed retirement. The trace
does not infer DMA quiescence from the gate: no structured device receipt was
available, so the device observation is explicitly right-censored and the
device and guest sources are partial.

The performance summary contains six real-QEMU development trials: one each
for control, delayed-provider, and bounded endpoint-concurrency points on the
legacy and vNext journals. Every cell has `n=1`; percentile estimates are
therefore intentionally omitted. The vNext checkpoint reduced its logical
replay image from 6,673 to 2,615 bytes and advanced the anchored revision from
24 to 25. It required 44 sector reads, 44 sector writes, and 10 flushes for the
checkpoint/replace operation. Across this small trace, vNext used more total
journal I/O than legacy (359/359 sectors and 85 flushes versus 153/153 and 30),
so this sample does **not** support a small-log latency or I/O improvement
claim. Its demonstrated value here is bounded fresh-media capacity, atomic
replacement, and a smaller post-checkpoint replay image.

The diagnostic TSC counters are uncalibrated. Recovery-launcher durations mix
boot, QEMU, emulation, and recovery work. The vNext control initial launcher
also included a one-time build/cache delay and is not compared. No transaction
ran inside the measured recovery-scope runtime mutex, so the zero mutex samples
do not establish an absence of contention and do not justify splitting it.

The real-QEMU launcher used for this historical sample was CSER2. `ChildDescriptorV1`, CSER3
descriptor verification, the core single-hop guard, and the independent
portable baseline handoff are covered by focused core/adapter/kernel tests but
are not exercised by this sample. Consequently these files do not establish
descriptor discovery, parent-to-child custody transfer, child publication, or
handoff crash recovery in QEMU.

Files:

- `applicability.jsonl`: HMAC-pseudonymized source-labelled observations.
- `aggregate.json`: the corresponding bounded aggregate.
- `manifest.json`: SHA-256 digests and fixed roles for the local raw inputs.
- `source.json`: repository/source-tree binding recorded by the exporter.
- `performance-summary.json`: selected unit-labelled measurements and hashes
  of the local raw performance outputs.

Raw SQLite databases, serial logs, media, operation identities, absolute local
paths, TPM state, and the per-study HMAC key are intentionally not published.
