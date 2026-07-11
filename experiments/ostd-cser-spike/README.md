# OSTD/OSDK 0.18 CSER spike

This experiment answers two narrow architecture questions without modifying
OSTD 0.18: can Nexus place a CSER-aware scheduler at OSTD's public scheduling
boundary, and can a kernel-owned fault continuation survive a user-space pager
crash and be explicitly adopted by a fresh pager? It is deliberately outside
the legacy Nexus workspace.

## Pinned environment

- OSTD: `=0.18.0` from crates.io
- cargo-osdk: `=0.18.0`
- cargo-osdk 0.18.0 crate SHA-256:
  `726c0c05c18c46b783bd86060f775560609a0bf4696bd0cc2d8f265d59aa3764`
- Rust: `nightly-2026-04-03`
- Official OSDK image: `asterinas/osdk:0.18.0-20260603`, pinned to the amd64
  manifest digest in `Dockerfile`
- Upstream source tag: `v0.18.0`, commit
  `253be4750d69810af7b7b020fe2fee40a8547e15`

The dependency keeps OSTD's default `cvm_guest` feature. In 0.18.0, the x86
crate does not compile with that feature disabled because `arch/x86/io` and
`io/io_mem` retain unconditional references to feature-gated CVM items.
The boot scheme follows cargo-osdk's generated x86 kernel template: GRUB
Multiboot2 on OVMF. `qemu-direct` with the template's `q35` machine faults in
OSTD boot before `#[ostd::main]` and is not treated as a supported combination.

Build and run the complete probe:

```bash
./x test
```

The narrower commands are `./x check`, `./x build`, `./x run`, and
`./x iommu-probe`. The serial transcript is written to
`artifacts/serial.log`; `scripts/assert-serial.sh` verifies both required
events and their ordering.

### Reproducible OSDK runner graph

Cargo-OSDK 0.18 generates a separate `*-run-base` Cargo workspace for
`build` and `run`. Its CLI does not propagate `--locked` to that generated
workspace, so relying on a project `Cargo.lock` alone would still resolve the
runner's transitive dependencies to the newest compatible versions.

`osdk-runner-base/` is a reviewed snapshot derived from the Run base emitted
by the pinned `cargo-osdk 0.18.0` tool (and therefore follows that tool's
MPL-2.0 provenance). It contains the generated manifest, entry point, linker
scripts, and its own lockfile; trailing whitespace in the linker scripts is
normalized for the repository. Before every build, `./x` installs the
snapshot at the path Cargo-OSDK would generate. Cargo-OSDK reuses it only when
its generated manifest and entry point are identical; after both `build` and
`run`, `./x` requires the complete directory to remain byte-for-byte
unchanged. The Docker image performs the same check while priming the
dependency graph.

If an OSDK upgrade legitimately changes this workspace, regenerate the
snapshot with that pinned version, review the full diff (including dependency
versions and linker scripts), and update the image key inputs together. Do not
refresh only the lockfile or accept a `Locking ... packages to latest
compatible versions` build as reproducible evidence.

The development image may use the network only while it is built. Normal
checks run as the invoking host UID with the project lockfile mounted
read-only, Cargo offline mode enabled, and Docker networking disabled.

## What is exercised

1. `CserScheduler` is injected through OSTD's public `Scheduler` and
   `LocalRunQueue` traits before any task is run.
2. A bootstrap proposal bound to `(authority_epoch=41, binding_epoch=1)`
   selects the user-mode policy task at `Commit`, the scheduling decision's
   linearization point.
3. The policy task activates a real `VmSpace`. Its x86 program returns via
   `UserSyscall` to submit a heartbeat/proposal, then via
   `UserException(CpuException::PageFault)` to model a real policy crash.
4. `Crash` immediately advances the binding epoch from 1 to 2 and closes the
   proposal gate. Task exit drives OSTD's scheduler path to `FallbackPick`; the
   test requires the FIFO pick within one timer tick. A 64-tick lease remains
   as the compiled stalled-policy fallback, but this run does not separately
   trigger that lease-expiry branch.
5. Before `Rebind`, even an epoch-2 proposal receives
   `REJECT_NO_SUPERVISOR`. Rebind attaches the replacement to epoch 2 without
   advancing it again, and a proposal from epoch 1 receives `REJECT_STALE`.
6. Thin wrappers around OSTD `Waiter`/`Waker` and `Jiffies` preserve an
   `EffectToken`; the wait pair is exercised at runtime.

### Pager crash/rebind slice

The pager probe runs while the scheduler remains in its kernel FIFO fallback;
the pager binding and pager fallback state are independent of the scheduler
binding and scheduler fallback policy. It exercises two scenarios:

- In `recover`, a client takes a real user-mode not-present read fault and
  blocks on a kernel-held continuation. Pager v1 prepares a kernel-owned zero
  frame and then takes its own real page fault. The crash advances only the
  pager binding epoch, closes the reply gate, and retains the prepared frame.
  A kernel predicate probe rejects the shape of a late v1 commit before VM
  mutation. A freshly constructed v2 task, `VmSpace`, and task-local `UserMode`
  exercise the experiment's boolean recovery-snapshot/ready handshake. Before
  `Rebind`, a kernel no-supervisor predicate probe rejects the current-binding
  commit shape. Rebind attaches v2 without a second epoch advance and returns
  the pager fallback to `Standby`; another kernel predicate probe rejects the
  old binding after rebind. V2 must explicitly `RecoverNext` and `Adopt` before
  it can map the retained frame into the client's address space. The kernel
  issues, dispatches, and synchronizes the local TLB flush, terminalizes the
  continuation once, and wakes the client outside the state lock. The unchanged
  fault RIP is retried and reads zero. The snapshot flag is an ordering witness,
  not serialized or reconstructed pager policy state, and the rejection probes
  are not replayed user-space capability messages.
- In `timeout`, no replacement pager is started. A kernel watchdog advances
  the authority epoch and first publishes only `Closing`: the reply gate is
  closed, the retained frame and waker are removed from shared state, cleanup
  is marked in flight, and the frame credit remains held. It then drops the
  frame outside the pager-state lock, publishes the single abort notification
  authorized by the `FaultPhase` gate, and immediately destroys the local waker
  object while the scope is still `Closing` and the credit is still held. Only a
  second locked transition may confirm both obligations, return the credit,
  clear the cleanup/wake markers, and publish `Revoked`; `RevokeComplete` is
  emitted after that transition. Thus `RevokeComplete` cannot precede either
  actual retained-resource cleanup or terminal wake publication. A client that
  is scheduled immediately after the wake waits for closure publication before
  announcing its cooperative exit.

The continuation's authoritative one-shot property is enforced by Nexus's
`FaultPhase`/terminalization gate, not by OSTD's `Waker`: OSTD permits a waiter
to be armed again after a wait consumes a wake. The serial oracle therefore
checks exactly one successful completion, exactly one timeout abort, and three
kernel predicate probes: post-crash stale, pre-rebind no-supervisor, and
post-rebind stale. It also forbids timeout commit/resume, panic, and unexpected
scheduler epoch advance.

This is evidence for API fit and the stated transitions, not a production
pager. It is single-CPU, uses one client and a zero-page mapping, and exercises
only a local TLB synchronization path. The fault-page address deliberately
shares an existing 2 MiB page-table region with the guest code; OSTD's public
map path can still `unwrap` if an intermediate page-table allocation runs out
of memory. The watchdog polls `Jiffies` rather than using a production timer.
OSTD exposes no arbitrary public task-kill/join primitive here, so pager v1
returns from its closure after the real fault and the aborted client exits
after it is woken. SMP shootdown, arbitrary pager policies, multi-client
recovery, swap/file-backed paging, and production multi-effect or cross-service
revocation remain outside this slice.

`./x` assembles the scheduler probe and three pager programs under `guest/`
before invoking OSDK. This intentionally avoids a Cargo build script:
cargo-osdk 0.18 recognizes a kernel only when its package has exactly one Cargo
target, so adding `build.rs` makes kernel discovery fail.

## IOMMU result: fail closed

OSTD 0.18's `src/mm/dma/util.rs::unmap_dma_remap` removes second-stage page
table entries without a synchronous IOTLB flush. It deliberately does not
free the device-address range (there is a TODO preventing IOVA reuse), but
`unprepare_dma` then lets the DMA object's backing physical frames continue
through destruction and eventual reuse. A stale IOTLB entry can therefore
retain access to repurposed physical memory. The source itself contains:

```text
FIXME: Flush IOTLBs to prevent any future DMA access to the frames.
```

The invalidation machinery is under crate-private `arch::iommu`; an external
Nexus adapter cannot safely share its VT-d queue/domain state. The existing
register fallback writes `iotlb_invalidate` but does not wait for IVT to clear;
the queued-invalidation descriptor module only implements interrupt-cache and
wait descriptors, not an IOTLB descriptor. Reimplementing VT-d invalidation
beside OSTD would create two owners and is not a minimal adapter. Therefore
`Ostd018FailClosed::unmap_invalidate_and_wait` always returns
`IotlbInvalidationUnavailable`, and the spike never reports DMA quiescence.
`./x iommu-probe` checks these upstream facts against the fetched, pinned
source; the kernel also compiles and runs the fail-closed path. Device-level
drain/reset must precede even a future synchronous IOTLB invalidation adapter.

Before mediated VirtIO I/O can claim revocation closure, Nexus must either
upstream a public synchronous unmap+IOTLB-invalidate API to OSTD, carry a small
audited OSTD patch, or reject OSTD as the DMA ownership layer.
