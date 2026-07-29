# Nexus OSTD `cser-production` kernel

This directory contains the maintained OSTD runtimes for the CSER Core
Rebaseline. `cser-production` is the only default and authoritative production
OSDK scheme. Two mutually exclusive, `--no-default-features`, test-only schemes
run focused real-guest reply and DMA recovery slices before the bounded
four-boot production recovery profile. The pre-rebaseline scheduler, pager,
personality, live Registry, portal, supervisor, and composition routes are
historical evidence, not live kernel alternatives.

The kernel is a research prototype. Naming the profile `production` identifies
the one authoritative cutover path; it does not claim production readiness or
hardware-general recovery.

## Production closure

`cser-core` is a non-optional dependency and the default kernel feature list is
exactly `cser-production`. During boot, one `ProductionCoreOwner` is installed
behind an `Arc` shared by:

- the stateless `NXP3` portal;
- the stateless `nexus.supervisor.core.v1` supervisor;
- the post-commit reply adapter and ATA PIO reply outbox; and
- the VirtIO DMA adapter and boot-quarantine owner.

Those adapters do not maintain a second lifecycle ledger. Client requests can
enter only the untrusted lifecycle prefix; fencing, recovery, adoption,
settlement, retirement, freshness, and reuse decisions remain trusted core or
domain transitions. There is no live dual-write or legacy Registry fallback.

[`cser-production-sources.txt`](cser-production-sources.txt) is the exact
production source manifest. The static cutover gate requires these twelve
files, requires each to be selected once by `cser-production`, and rejects old
Registry, portal, supervisor, and semantic-mirror sources:

```text
core_device_quarantine.rs
core_dma_adapter.rs
core_persistent_runtime.rs
core_pio_journal.rs
core_portal_vnext.rs
core_production_registry.rs
core_reboot.rs
core_reply_adapter.rs
core_reply_outbox.rs
core_runtime.rs
core_supervisor_vnext.rs
core_tpm_anchor.rs
```

The `cser-core-reply-recovery` and `cser-core-dma-recovery` OSDK schemes select
their matching features with default features disabled. They are mutually
exclusive, test-only evidence profiles: the harness runs their real task,
rebind, reply, and DMA guest slices before `cser-production`, but neither owns
the production Registry nor substitutes for the persistent cutover proof. The
`cser-core-tpm-anchor` feature remains a compile-only development profile. In
particular, `core_runtime_slice.rs`, `core_runtime_dev.rs`, and
`core_dma_runtime.rs` are excluded from the production manifest.

## Persistent recovery path

The public combined run first executes both focused test-only guest evidence
schemes. It then prepares one raw ATA journal, one separate raw ATA reply
outbox, and one swtpm state directory and boots the same `cser-production`
kernel four times without recreating those stores. Device quarantine is
established before journal replay and retains the linear device owner while
recovery is incomplete.

The acceptance parser requires the following sequence:

1. Boot 1 installs the single recovered owner, commits a reply through the
   secondary outbox, publishes one real VirtIO request, and exits with the
   reply plus queue/page/IOVA claims retained.
2. Boot 2 advances trusted freshness, replays the same journal, performs
   dynamic snapshot/ready/rebind recovery, persists the reply apply intent,
   and crashes a second time before acknowledgement. It consumes reset/ISR
   evidence sufficient to retire only the exact queue claim.
3. Boot 3 replays that second crash, claims reconciliation, applies and
   acknowledges the reply without minting a second intent, then settles and
   retires the reply obligation.
4. Boot 4 repeats recovery without duplicating evidence or settlement and
   demonstrates the stable retained state. Across all four boots, the host
   oracle requires boot, journal, and device freshness to increase strictly.

The pinned-page and IOVA claims remain retained. Activation stays blocked and
`resource_reuse_authorized=false`, because a boot-global IOTLB observation does
not prove crash-persistent custody or retirement of those resources.

The profile uses an ATA PIO journal with explicit flushes, a separate ATA PIO
reply outbox, and a TPM2 NV anchor bound to the compiled domain catalog. Early
quarantine performs the fixed PCI fence, VirtIO status reset, ISR drain, and
global VT-d IOTLB command before replay. Late/stale generations cannot release
a new claim.

An ordinary complete run writes `artifacts/cser-production/combined-proof.txt`
with `NONSEALABLE`; it is suitable for pre-commit integration but not release
evidence. `seal-core-persistent-recovery` first requires a clean source tree and
then writes `combined-receipt.txt` with `PASS` only if the tree remains clean
through the run. The archived production/focused ISOs, boot serial logs, QEMU
debug traces, raw media, and swtpm logs remain beside it. This README does not
assert that the final cutover receipt has been sealed.

## Workflow

The kernel backend is normally reached through the repository-root `./x`, but
its focused commands are also available here:

```bash
./x doctor
./x check
./x build
./x run-core-persistent-recovery
./x seal-core-persistent-recovery
./x clean
```

`check` verifies the pinned OSTD and VirtIO overlays (including negative
mutations), checks formatting, runs the static production-cutover assertion,
compiles the production profile, the two test-only evidence profiles, and the
TPM development profile, runs `cargo osdk check`, and applies strict Clippy to
the production feature. `build` and `build-core-persistent-recovery` build the
same `cser-production` kernel. `run`, `test`, and
`run-core-persistent-recovery` execute the combined sequence: focused reply and
DMA guest evidence first, then four persistent production boots. There are no
same-boot legacy composition, Stage 7B, alternate production Registry, or TPM
run routes.

The complete backend command set is:

```text
doctor image fmt check clippy build run test
build-core-persistent-recovery run-core-persistent-recovery
seal-core-persistent-recovery clean
```

Both recovery commands require Docker and host `swtpm`. The seal form also
requires tracked, staged, and nonignored untracked source state to be clean.
The pinned container supplies Rust, cargo-osdk, QEMU, OVMF, and the build
toolchain. Normal container execution is offline and mounts the project
lockfiles read-only; set `NEXUS_REBUILD=1` only for an intentional image
rebuild.

## Pinned environment

- Rust: `nightly-2026-04-03`, target `x86_64-unknown-none`.
- OSTD and cargo-osdk: `=0.18.0`.
- OSTD crate SHA-256:
  `aa160b3c09e0471f85f76a069e327b3df0bc60d5191b2ce3a64cc15cd62038e1`.
- OSTD overlay: `patches/ostd-0.18.0-cser.patch`, SHA-256
  `6167dc681e8f5e53c20e2ef2ccc40fc1924c722bb9ca37cc4ba4f70ba49b71db`.
- virtio-drivers: `=0.13.0`, crate SHA-256
  `cfdc1c628cdd8ce7c3b9e65a8ed550d0338e9ef9f911e729666f1cce097de2f7`.
- VirtIO overlay: `patches/virtio-drivers-0.13.0-cser.patch`, SHA-256
  `7576d6810af8ff4a2d4cbcd0dc02373946031aa2e3f7ae0528b0127b5ea33762`.
- OSDK image:
  `asterinas/osdk:0.18.0-20260603@sha256:a7540bfcd262ae52471f86353a87663d91941958e503557863738d13de4aace3`.

Cargo-OSDK generates a separate runner workspace and does not propagate
`--locked` to it. `osdk-runner-base/` is therefore a reviewed snapshot with
its own lockfile. Every build installs that snapshot and verifies it remains
byte-for-byte unchanged; dependency drift in the generated runner is a hard
failure.

## Evidence boundary

The combined harness is one-vCPU, single-thread-TCG QEMU. The four production
boots reuse one raw journal, reply outbox, and swtpm state directory; the host
oracle binds their restart trace and strictly increasing freshness coordinates.
The focused guest evidence can observe the configured VirtIO and VT-d events.
This evidence cannot establish:

- physical TPM anti-rollback or resistance to an attacker who can roll back
  all local state;
- physical power-loss durability or storage-controller ordering;
- hardware-general reset, IRQ, IOMMU, or DMA quiescence;
- crash-persistent PFN/IOVA custody or authorization to reuse retained pages
  and mappings;
- multi-queue, multi-device, multi-vCPU, SMP, liveness, or availability
  properties; or
- production filesystem, network, Linux compatibility, or operator recovery
  completeness.

The early fence, status reset, ISR drain, and global IOTLB command prove the
continued quarantine observed by this profile. They do not prove that an old
PFN/IOVA is retired. Historical component logs and released `v0.1.0` receipts
retain their original source, configuration, and non-claim boundaries.

## Provenance and license

The Nexus kernel glue is MPL-2.0. OSTD and the reviewed cargo-osdk runner
snapshot retain MPL-2.0 provenance. The virtio-drivers overlay and substrate
retain the upstream MIT boundary recorded beside the patch. See the repository
root notices before redistribution.
