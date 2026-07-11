# OSTD 0.18 DMA invalidation ownership spike

This Stage 5A experiment answers one narrow question: can Nexus carry a small,
auditable OSTD 0.18 patch that removes a DMA PTE, submits a real VT-d IOTLB
invalidation, retains the backing owner across `Pending`, and releases the
IOVA/PADDR/backing allocation only after hardware completion?

Run the complete Docker-only receipt with:

```bash
./x test
```

The result is deliberately **not** mediated VirtIO closure. The probe never
publishes its IOVA to a device, so the device-quiescence precondition is true
vacuously. It proves neither device drain nor reset, and the required serial
receipt says `device_dma=false` and `device_reset=false`.

## Pinned source and build boundary

- OSTD: crates.io `=0.18.0`
- OSTD crate SHA-256:
  `aa160b3c09e0471f85f76a069e327b3df0bc60d5191b2ce3a64cc15cd62038e1`
- OSTD tag commit: `253be4750d69810af7b7b020fe2fee40a8547e15`
- cargo-osdk: `=0.18.0`
- Rust: `nightly-2026-04-03`
- OSDK image: `asterinas/osdk:0.18.0-20260603`, pinned by amd64 manifest
  digest in `Dockerfile`

The repository stores only the MPL-2.0 patch in
`patches/ostd-0.18.0-dma-closure.patch`. During the image build, Docker checks
the upstream crate archive hash, extracts it under `/opt/nexus-ostd`, applies
the patch, and verifies that the patch reverses cleanly. `.dockerignore`
excludes `patch-work`; a complete OSTD tree is never part of the final source
artifact.

The experiment directory is a local MPL-2.0 licensing boundary: its package
manifest declares `MPL-2.0`, and `LICENSE-MPL-2.0` contains the complete
license text. The OSTD-derived patch remains MPL-2.0-covered and is not
relicensed by Nexus's root Unlicense. The Docker image copies the same license
beside the extracted patched OSTD source.

Normal `./x` commands run with Docker networking disabled, Cargo offline mode,
the project lockfile read-only, and the committed cargo-osdk runner graph
read-only and byte-checked. The Docker image build is the only networked step.

## Runtime ownership protocol

The exported Stage 5A handle is intentionally restricted to one
page-sized `DmaCoherent`:

```text
device already quiesced (unsafe caller proof)
    -> begin_unmap_invalidate(one page)
       reserve sole generation
       remove exactly one second-stage PTE
       Release-publish global IOTLB + wait descriptors
    -> PendingDmaUnmap owns frame + IOVA + PADDR accounting
    -> poll_complete()
       Pending: return the same owning handle
       Complete: free IOVA, remove PADDR tracking, return UnmappedDma
       Failure/drop: retain or leak the owner as a fail-closed quarantine
```

`begin` and each `poll` perform bounded work and never wait for hardware while
holding OSTD's `LocalIrqDisabled` IOMMU-register lock. The reserve-to-submit
window is protected by an outer local-IRQ guard, so same-CPU interrupt-remap
re-entry cannot wait on the operation it interrupted. The guard covers one PTE
removal and descriptor publication only; completion is always polled later.

Other CPUs are serialized by a single generation slot. This spike runs with
`-smp 1`; it establishes the locking shape, not an SMP liveness proof. OSTD's
pre-existing init-time DMA/interrupt-remapping/queued-invalidation enable
handshakes remain synchronous. Those boot-only register-status loops are not
the runtime teardown API being evaluated.

The existing arbitrary-size `DmaCoherent`/`DmaStream` Drop contract is kept
separate: ordinary Drop synchronously processes one page at a time and polls
outside every IOMMU lock. It can take work proportional to the mapping size.
On uncertainty it spins fail-closed rather than releasing memory. An abandoned
explicit `PendingDmaUnmap` instead keeps its `DmaCoherent` in `ManuallyDrop`,
quarantining the real frame and IOVA. Deadline, tombstone persistence, and
recovery scheduling remain Nexus policy, not OSTD policy.

## Necessary VT-d MMIO mapping repair

OSTD 0.18 constructs VT-d register pointers with
`paddr_to_vaddr(base_address)`. Its post-boot linear map covers RAM only, so on
this QEMU configuration the first capability read at physical `0xfed90008`
faults before `#[ostd::main]`. The patch reserves the VT-d page through
`IoMemAllocatorBuilder`, retains an `IoMem<Sensitive>` owner in
`IommuRegisters`, and derives register pointers from that mapped virtual
window. This is a necessary OSTD 0.18 bring-up repair for the experiment, not
part of the CSER contribution claim.

## What the receipt observes

`./x test` requires all of the following:

- active VT-d remapping (`daddr != paddr`);
- successful one-page PTE removal and queued global IOTLB submission;
- QEMU `vtd_inv_desc_iotlb_global` and ordered wait-descriptor traces;
- one deliberately injected `Pending` result with frame, IOVA, and credit
  still retained;
- hardware completion before IOVA/PADDR/backing release;
- exact IOVA reuse by a fresh allocation only after the acknowledgement;
- no panic, retained-engine failure, or device/reset claim.

The injected `Pending` is a deterministic software fault-injection point; it
does not claim that QEMU delayed the hardware descriptor. The subsequent poll
must still observe the real VT-d completion bit. Stage 5B must add a real
VirtIO queue, `ACCESS_PLATFORM`, device stop/drain/reset, and timeout
tombstones before Nexus can make a mediated-I/O closure claim.
