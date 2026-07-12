# OSTD mediated VirtIO CSER spike

This Stage 5B experiment is the first Nexus slice with a real device-visible
effect. It demonstrates, on one pinned QEMU/OSTD configuration, that a mediated
VirtIO block request can cross an explicit commit point, complete through
non-identity VT-d mappings, survive service crash as an indeterminate committed
effect, and release every request/queue DMA owner only after device reset and
the matching IOTLB completion.

Run the complete Docker-only receipt with:

```bash
./x test
```

The command rebuilds when any pinned source, patch, kernel module, fixture, or
oracle changes. Normal check/build/run steps have networking disabled, use
Cargo offline mode, and byte-check both project and cargo-osdk runner locks.
Artifacts are written to:

```text
artifacts/serial.log      raw build/firmware/guest stdout plus fixture receipt
artifacts/qemu-debug.log  raw cargo/QEMU stderr and trace events
artifacts/kernel.log      normalized serial suffix at the unique Stage 5B marker
artifacts/oracle.log      positive/negative oracle result
```

The serial and debug streams deliberately remain separate. The guest console
can emit one formatted receipt through several writes, so redirecting stderr
into stdout can splice a QEMU trace record into the middle of that receipt.
The oracle instead checks the exact guest receipt sequence in `kernel.log` and
an independently anchored QEMU trace sequence in `qemu-debug.log`. It compares
the three guest-owned IOVA-to-physical-address mappings across the two inputs,
but does not claim a total order between different file descriptors.

Root `../../x verify` first reruns this split-stream gate over both
`artifacts/kernel.log` and `artifacts/qemu-debug.log`. Only after that succeeds
does the system-composition gate consume the validated `kernel.log` as
independent prerequisite component evidence:

```bash
# after both OSTD spikes have produced their retained logs
../../x composition
```

That cross-experiment consistency oracle requires this receipt's audited
`avail.idx` Release commit, reset timeout, retained DMA owners, retry,
device-generation fence, IOTLB completion, and final release. It does not
preserve effect, ticket, or generation identity: this boot completes request 1
in generation 1 and fences generation 1 to 2, while the composition adapter
independently starts at generation 3 and advances its own envelope to 4 on
retry. It is not evidence that real VirtIO DMA and all five composition domains
executed together in one kernel run.

## Pinned boundary

- OSTD: crates.io `=0.18.0`
- OSTD archive SHA-256:
  `aa160b3c09e0471f85f76a069e327b3df0bc60d5191b2ce3a64cc15cd62038e1`
- OSTD tag commit: `253be4750d69810af7b7b020fe2fee40a8547e15`
- cargo-osdk: `=0.18.0`
- virtio-drivers: crates.io `=0.13.0`, default features disabled
- virtio-drivers archive SHA-256:
  `cfdc1c628cdd8ce7c3b9e65a8ed550d0338e9ef9f911e729666f1cce097de2f7`
- Rust: `nightly-2026-04-03`
- OSDK image: `asterinas/osdk:0.18.0-20260603`, pinned by amd64 digest in
  `Dockerfile`
- QEMU in that image: 10.2.1

The deterministic backend is a one-MiB readonly raw image. Its first 30 bytes
are `NEXUS-CSER-VIRTIO-BLK-STAGE5B\n`; all remaining bytes are zero.

```text
sector-0 SHA-256:
9cb83be92a4c9239752718e6e20ac00fe9e32842ea561ae7fedec94b620a05cc

full-image SHA-256:
27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254
```

The runner checks the full image before and after QEMU. Both the file and raw
block nodes are readonly; the experiment does not use a snapshot overlay that
could hide an accidental write.

## Reused and Nexus-owned pieces

The implementation directly reuses these `virtio-drivers` 0.13 pieces:

```text
PciRoot / ConfigurationAccess
PciTransport
VirtQueue<OstdHal, 16>
BlkReq / BlkResp
```

Nexus supplies only the boundaries needed for CSER:

```text
PIO PCI configuration serialization
unique BAR ownership and owner-bound MMIO translation
DMA owner ledger and fixed request bounce layout
authority/binding/device-generation gates
portal-gated commit and notify actions
reset and timeout tombstones
one-shot reset/closure receipts and IOTLB-completion-driven release
serial/trace evidence oracle
```

`VirtIOBlk` is intentionally not used. It combines queue publication and
notification and hides the queue/transport owners that the reset protocol must
retain. The experiment still reuses its public sector-0 wire types rather than
copying a block driver.

## Commit and completion

The mediated read has three fixed request descriptors in one DMA page:

```text
offset 0:   BlkReq,  16 bytes, driver -> device
offset 16:  data,   512 bytes, device -> driver
offset 528: BlkResp,  1 byte, device -> driver
```

The queue itself owns two more pages:

```text
descriptor + avail ring: one page
used ring:               one page
```

The CSER commit point is the successful return of `VirtQueue::add`. In
virtio-drivers 0.13 this path performs descriptor writes, the avail-ring entry,
a `SeqCst` fence, and finally `avail.idx.store(..., Release)`. Notification is
then issued separately through `PciTransport::notify(0)`. Therefore:

```text
before queue.add                 Prepared / cancellable
after avail.idx Release          Committed
after notify                     still Committed; notify is only a hint
after matching used descriptor   Completed
```

The typed readonly policy rejects a write before any `Session` or queue exists.
The receipt verifies that the portal effect count and next request identity are
unchanged. It does not claim a private `avail.idx` getter that the reused crate
does not expose.

The normal scenario observes:

```text
RO | VERSION_1 | ACCESS_PLATFORM = 0x0000000300000020
non-identity IOVA -> GPA translations for 00:05.0
one real sector-0 VirtIO read
used length 513 and BlkResp::OK
fixed magic, zero tail, and FNV-1a receipt
Completed terminal state
```

## Crash, reset, and tombstones

Generation 1 deliberately turns reset into a software-injected timeout before
the first status poll. The returned tombstone retains the transport, queue,
request page, two queue pages, epochs, and generation. It uses
`ManuallyDrop<Session>` so abandoning the recovery worker cannot run the
unbounded `PciTransport::drop` loop or release DMA before reset acknowledgement.

Retry must observe real VirtIO status zero, disable PCI bus mastering, read the
ISR, and only then drop the queue. `Hal::dma_dealloc` merely changes each queue
owner from active to retired; it cannot unmap or free it.

The first request IOTLB poll is also deterministically injected as pending. Its
tombstone owns the in-flight request unmap while the ledger retains both queue
owners. Retry observes a real queued global invalidation and ordered wait
descriptor for each of the three pages before returning backing memory.

Generation 2 publishes a request but does not notify it, then advances the
binding epoch to model I/O-service crash. Because notification is only a hint,
the request is not called cancelled. Whole-device reset terminalizes it as:

```text
IndeterminateAfterReset
```

Only after the same reset/IOTLB closure may the three pages be released. The
QEMU slice tracks DMA pages and owners; budget conservation remains a property
of the TLA+/Rust reference models, not a runtime claim from this receipt. Old
binding and device-generation completions are rejected, and the effect cannot
acquire a second terminal state.

`ResetAck` carries a non-forgeable DMA closure authority. `begin_closure`
consumes it, and `Portal::mark_quiesced` then consumes the non-copyable
`ClosureReceipt`; neither stage accepts a caller-supplied generation number.
The generation-2 crash path also makes a real late-notify call through the
portal and observes rejection before a PCI doorbell can be written.

## What the oracle requires

OVMF probes the block device before Nexus boots. The kernel therefore prints a
unique marker before touching PCI; guest-receipt counts and negative checks use
only the serial suffix beginning at that marker. The independently ordered QEMU
trace has no shared marker: its target control sequence is anchored by the
first translations of the three guest-owned IOVAs.

The oracle requires:

- the exact BDF, modern device ID, features, and three DMA owners;
- a real sector-0 read and successful QEMU completion, with one `vdev` across
  initialization, queue notification, read, completion, reset, and rebind, and
  one `req` across the read and both completion records;
- three distinct non-identity owner IOVAs, each observed in the `00:05.0` VT-d
  trace;
- exactly one target-sequence PCI doorbell followed by a queue notify on the
  completed read's `vdev`, and no second-generation doorbell;
- real status-zero reset writes in both generations;
- six global IOTLB invalidations and six ordered wait descriptors;
- reset and IOTLB timeout tombstones retaining all three pages;
- within the QEMU stream, no DMA translation after the generation-1 status-zero
  reset begins, no extra target notify/queue/block event, and no device activity
  after the generation-2 IOTLB acknowledgements;
- `Completed` for generation 1 and `IndeterminateAfterReset` for generation 2;
- stale/duplicate completion rejection;
- identical fixture hashes before and after QEMU.

It rejects any block write, backend write, VT-d fault, panic, premature success
claim, `Cancelled` terminal for the published request, or claim that the
injected timeout was a hardware timeout.

## OSTD patch and licensing

The repository stores only the MPL-2.0 OSTD patch in
`patches/ostd-0.18.0-dma-closure.patch`. Docker verifies the upstream archive,
applies the patch, and checks a clean reverse application. The patch provides:

- one-page ownership-carrying `begin_unmap_invalidate` / `poll_complete`;
- bounded runtime queued-IOTLB begin/poll paths;
- retained owners on pending or uncertain completion;
- owner-backed VT-d register MMIO;
- one narrow unsafe `DmaCoherent::as_non_null_ptr_exclusive` accessor whose raw
  pointer remains bound to a retained DMA owner;
- one narrow unsafe `IoMem<Insensitive>::as_non_null_ptr` accessor for a
  retained BAR owner.

Source assertions also pin the no-alloc `VirtQueue` Drop shape used by the
reset-without-`pop_used` boundary: queue destruction retires its DMA layout and
does not revisit the pinned request buffers. This is an audited dependency
boundary that should eventually become an upstream reset/abandon API.

The experiment directory is an MPL-2.0 package boundary and includes the full
MPL text. The derived OSTD patch stays MPL-2.0-covered. virtio-drivers is an
unmodified MIT dependency fetched from its checksummed crate archive and
locked by Cargo; no upstream source is copied into Nexus.

## Explicit non-claims

This receipt is deliberately narrower than a production I/O subsystem:

- QEMU reset with `dma-drain=on` is emulator evidence, not proof for arbitrary
  physical PCIe devices;
- reset and first-poll timeouts are software injections, not observed hardware
  timeouts;
- completion is polling, PCI INTx is masked, and MSI/MSI-X/IRQ quiescence is
  not proved;
- the run uses one CPU; SMP liveness is not proved;
- OSTD currently uses a shared IOMMU domain, so this proves lifecycle closure,
  not per-device DMA isolation;
- only a readonly block read is exercised; irreversible disk writes, network
  output, flush ordering, and persistence are not covered;
- the BAR registry and fixed three-buffer HAL are spike-specific mechanisms,
  not a general PCI subsystem;
- no real-time reset deadline, system-wide fault matrix, k/N revocation curve,
  or WorkProportionality claim is established here.
- the system-composition oracle treats this boot as independent prerequisite
  evidence; it neither establishes identity-preserving composition nor a
  same-boot five-service workload or SMP composition.
- completion-to-portal-terminal crash injection and a durable tombstone
  recovery registry remain future integrated-validation work.

Those boundaries remain gates for the later integrated validation stage. This
experiment supports a mediated-I/O feasibility result; it does not by itself
establish CSER as an original contribution.
