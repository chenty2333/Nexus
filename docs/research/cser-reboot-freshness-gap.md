# CSER reboot freshness: historical OSTD provider-gap audit

Status: **Superseded implementation-gap audit. Provider implementation is
complete; a historical four-boot receipt is retained and the portable swtpm
harness replacement is awaiting its clean re-seal, 2026-07-30.**

This note originally recorded why the production-shaped boot coordinator had
no OSTD persistence provider on 2026-07-29. That inventory is retained as a
historical negative result, not as current repository status or an active
roadmap. RFC 0006 supersedes its task ordering.

## Current resolution and remaining boundary

The implemented bounded rebaseline provides the missing pinned-profile owners:

- `core_tpm_anchor.rs` drives the QEMU TIS TPM2 device and binds six
  pre-provisioned NV indices to the exact catalog, Registry binding, journal
  head, and issued/committed freshness coordinates;
- `core_pio_journal.rs` supplies the primary ATA PIO journal, while
  `core_reply_outbox.rs` owns a separate secondary ATA PIO reply record;
- `OSDK.toml` attaches those two raw media files and one persistent swtpm state
  directory to every production boot; and
- `core_device_quarantine.rs` fences VirtIO/PCI and observes reset, ISR drain,
  and global VT-d invalidation before journal replay.

The retained historical receipt passed four QEMU boots over those same owners:
commit, durable apply intent and second crash, reconciliation without a second
intent, then stable replay. Exact CI later exposed an optional swtpm 0.7.3
state-lock incompatibility before provisioning completed. Its correction and
replacement-seal status are recorded in the production cutover release ledger.

The provider proves only its pinned QEMU/swtpm/ATA protocol. swtpm state and raw
media remain host-rollbackable, so this is not physical malicious-rollback
resistance, physical power-loss evidence, crash-persistent PFN/IOVA custody, or
authorization to reuse retained resources. Reset/ISR/IOTLB observations justify
continued quarantine only.

## Historical audit snapshot (superseded)

## What is implemented

`kernel/nexus-ostd/src/cser/core_reboot.rs` enforces this order:

1. acquire a linear guard which physically quarantines every CSER-managed
   device;
2. read the durable journal;
3. atomically reserve a newer boot/journal epoch from an independent
   `TrustedAnchorBackend`;
4. recover only the journal prefix named by that anchor;
5. durably remove one torn or unanchored suffix, then reserve another strictly
   newer recovery epoch and replay again;
6. durably append `CheckpointRecovery` and compare-and-advance the trusted
   journal tip;
7. retain the hardware quarantine guard while any recovered device claim,
   journal repair, or ambiguous persistence result remains;
8. return a live device owner only when the core and trusted anchor name the
   same exact revision, head, and freshness vector and the provider explicitly
   releases the guard.

An activation failure returns the same quarantine guard. Dropping the guard is
required to remain fail-closed.

Four OSDK kernel tests cover checkpoint-before-activation, retained device
claims across replay, exact suffix repair followed by a newer recovery epoch,
and provider release failure retaining the guard.

## Why the audited tree had no production provider yet

The checked-in OSTD 0.18 integration has no TPM/NV, UEFI runtime-variable, or
QEMU `fw_cfg` persistence API. Its public `BootInfo` contains a bootloader name,
command line, initramfs, framebuffer, and memory regions only. The x86 boot
path is Multiboot/Multiboot2/Linux boot protocol, not a retained UEFI runtime
services owner.

The existing OVMF variable pflash in `kernel/nexus-ostd/OSDK.toml` is an
ordinary host file and is copied into a fresh temporary home by the run
workflow. It can be rolled back with VM state and therefore cannot satisfy the
core's non-rollback trusted-anchor contract. The QEMU schemes configure no
`-tpmdev` or `tpm-tis` device, and the kernel has no TPM driver even when a
host `swtpm` binary happens to be installed.

The only current block facade is intentionally a bounded VirtIO sector-zero
read path:

- `ProductionDevice` exposes `prepare_read_sector0` and its polling/IRQ
  variants, but no durable write, FUA, or flush operation;
- the runtime filesystem QEMU block node is configured `read-only=on`;
- `crates/nexus-ostd-virtio/README.md` explicitly says that the witness does
  not survive reboot or provide a persistent recovery loop.

Consequently, neither an ordinary file, OVMF variable file, `fw_cfg` input, nor
the present read-only VirtIO owner can honestly implement
`TrustedAnchorBackend` or `OstdBootJournal`.

The host `HostFileTrustedAnchor` remains useful protocol evidence for atomic
rename, barriers, failpoints, and cold reopen. Its own documentation correctly
states that a normal file is rollbackable and is not production
anti-rollback evidence.

## Provider work identified by the historical audit

A production integration needs all of the following:

- a TPM 2.0 NV or equivalent platform protocol which protects the exact
  catalog/Registry/binding tuple, committed freshness, journal revision and
  head, and a high-water issued epoch; its compare-and-advance and
  lost-acknowledgement behavior must be specified and tested;
- a writable journal owner with exact append plus an actual device durability
  barrier (FUA or flush), bounded storage layout, torn-write recovery, and no
  retry after an ambiguous result;
- a stable mapping from persistent `DeviceScopeId` values to physical reset
  domains, plus a boot constructor which owns those devices before bus
  mastering or interrupts can resume;
- reconstruction of reset/IOTLB tombstones without minting a fresh facade-local
  device generation of `1`;
- a multi-boot QEMU harness with persistent journal media and persistent
  software-TPM state, rollback-negative tests, and separate physical-platform
  evidence.

At the audited revision, those owners did not exist, so
`OSTD_018_RECOVERY_GAPS` was non-empty and the coordinator could not be cited as
reboot persistence, anti-rollback freshness, or production device-recovery
evidence. The current implementation and its narrower evidence boundary are
recorded above; this historical conclusion must not be applied to the new
source tree verbatim.

## Reproducible audit commands

From the repository root:

```sh
rg -n -i 'tpm|tpmdev|tpm-tis|fw_cfg|fwcfg|runtime_services|nvram' \
  kernel/nexus-ostd crates/nexus-ostd-virtio

rg -n 'prepare_read_sector0|read-only=on|flush|FUA|survive reboot' \
  kernel/nexus-ostd/OSDK.toml \
  crates/nexus-ostd-virtio/src \
  crates/nexus-ostd-virtio/README.md
```

For the pinned OSTD 0.18 source installed by the build image:

```sh
rg -n -i 'tpm|fw_cfg|fwcfg|runtime_services|variable_service|nvram|block device' \
  /opt/nexus-ostd/ostd-0.18.0/src
```

The last command currently finds only a QEMU-detection comment mentioning
`fw_cfg`; it finds no persistence provider.
