# Final asynchronous applicability and vNext development evidence

This bundle records the final bounded development measurements for Nexus
commit `e68a76ea14ec9962b93e9d365011c82fa54a2313`, captured on 2026-08-10 from
a clean worktree. It answers three narrow questions:

1. can one real-QEMU trial be retained locally as source-labelled raw events
   while publishing only a complete HMAC-pseudonymized projection;
2. what phase-resolved costs are visible around the asynchronous endpoint,
   runtime serialization, journal publication, and TPM anchor in the small
   Tool+DMA workload; and
3. does the final in-place vNext journal remove cumulative payload-write
   amplification without hiding its read, flush, and hashing costs.

This is not a product benchmark, workload-prevalence estimate, physical-device
result, power-loss claim, or statistically powered latency comparison.

## Measurement grain

- `performance.jsonl` contains exactly six sanitized real-QEMU/TCG rows:
  legacy and vNext journals crossed with control, a 25 ms provider delay, and a
  bounded two-worker/128-background-job endpoint-concurrency point. Every cell
  has `n=1`, uses the `post_endpoint_apply` crash cut, and records a real
  container kill followed by terminal recovery. The concurrency rows are
  accepted only when a background endpoint operation overlaps the primary
  Pending-to-provider interval; both reached `max_inflight=2`.
- `core-state-profile.jsonl` contains four release-build, nonpersistent
  portable-core rows with 1, 64, 512, and 4,096 live claims. Each reports the
  median of 11 samples after three warmups using host `std::time::Instant`.
- `journal-fill.json` contains the exact assertions exercised by the passing
  QEMU kernel ktest over `MemoryDisk`: 128 sequential 512-byte records, or
  65,536 logical bytes. These are journal-provider requested operations, not
  ATA completion counts or wall-clock timings.
- `applicability.jsonl` contains 15 HMAC-pseudonymized events from the vNext
  control trial. Its completion marker is the final publication pivot from a
  locally retained raw-authoritative trace.

## Results and limits

At the cut-3 initial marker, legacy requested 34 reads, 34 writes, and 18
flushes; vNext requested 125 reads, 45 writes, and 45 flushes. At terminal
recovery, the cumulative counts were 153/153/30 for legacy and 644/95/85 for
vNext. The vNext checkpoint advanced revision 24 to 25 and reduced the logical
replay image from 6,673 to 2,615 bytes. Its measured replacement delta was 74
reads, 20 writes, and 10 flushes. Thus this small real-QEMU workload does not
show an overall vNext I/O or latency advantage.

The controlled fill profile exposes the intended tradeoff more directly:

| journal | sector reads | sector writes | flushes | hash bytes |
| --- | ---: | ---: | ---: | ---: |
| legacy | 8,384 | 8,384 | 256 | 8,454,144 |
| vNext | 17,148 | 768 | 640 | 25,567,168 |

The final vNext layout therefore removes cumulative payload-copy write
amplification in this bounded fill, while increasing reads, flushes, and hash
work. It remains experimental; the legacy journal remains the default.

At 4,096 live claims the portable profile measured median candidate clone,
canonical-invariant, and projection-digest phases of 1.115058 ms, 1.629286 ms,
and 1.726071 ms. The independently measured complete nonpersistent transition
was 4.112267 ms; it must not be added to those component microbenchmarks. This
host-only profile establishes scaling visibility, not materiality in the small
integrated QEMU workload.

The evidence therefore supports these decisions:

- retain the bounded in-place append/checkpoint vNext experiment because it
  reduces controlled-fill writes and the post-checkpoint replay image;
- defer a core copy-on-write or incremental-state rewrite because the portable
  large-state cost has not been shown material in an integrated workload; and
- defer splitting the authoritative runtime mutex because these rows do not
  establish guest-side contention. The measured recovery scope has zero
  runtime transactions, and host endpoint-worker concurrency is not CSER
  runtime concurrency.

## Timing semantics

Endpoint phase durations come from durable SQLite monotonic timestamps.
Launcher durations come from the controller's explicit monotonic start/end
artifact and include boot, QEMU, emulation, and recovery work. Guest runtime,
mutex, journal, and TPM cycle values use uncalibrated guest TSC and are not
wall-clock latency.

The four journal publication intervals are derived from one
`last-complete-publication` receipt. In vNext,
`header_written_to_redundancy_flushed` includes staged-header validation, the
manifest authority pivot, and mirror-header restoration; it is not a pure
physical header-flush latency. Counts and byte totals are cumulative at their
initial or recovery marker, while checkpoint fields are explicit deltas.

## Publication and raw-evidence boundary

The committed rows contain no operation key, run ID, container ID, raw effect
or resource identity, descriptor/input/catalog digest, absolute path, database,
serial log, media image, TPM state, or HMAC key. `manifest.json` records the
SHA-256 of the local performance/profile inputs and fixed-role trial artifacts,
but does not publish them.

The raw source-labelled applicability trace and its 32-byte study key remain
under the ignored local `kernel/nexus-ostd/artifacts/` boundary. During
collection only the raw JSONL and an `incomplete` marker existed. Successful
close validated every raw-to-HMAC binding, derived the sanitized JSONL, synced
it, and atomically replaced the marker with the committed `complete` marker.
The marker carries a keyed raw commitment rather than an unsalted raw digest.
An aborted or interrupted workflow is rejected by the strict loader and cannot
be presented as this published set.

The applicability aggregate remains deliberately partial: endpoint/provider
outcome and exact allocator-gate facts are visible, while physical DMA
quiescence is right-censored because no structured device receipt was present.

## Files

- `performance.jsonl`: six unit/source/clock/scope-labelled sanitized QEMU
  measurement rows.
- `core-state-profile.jsonl`: four unit-labelled portable-core rows.
- `journal-fill.json`: exact bounded MemoryDisk fill counters and gate receipt.
- `applicability.jsonl`: HMAC-pseudonymized source-labelled events.
- `applicability.jsonl.publication.json`: raw-authoritative completion marker.
- `aggregate.json`: bounded applicability aggregate and censoring limits.
- `summary.json`: checked headline values, decisions, and caveats.
- `manifest.json`: published-artifact and local raw-input digests by fixed role.
- `source.json`: implementation commit, Git tree, producer versions, and clean
  source binding.

The focused checks used for the implementation were 39 Python trace/exporter/
performance tests, the Tool+DMA experiment build, and the QEMU PIO journal
gate (`1 passed; 0 failed`). The six performance rows and local raw trace were
then captured from the clean implementation commit named above.
