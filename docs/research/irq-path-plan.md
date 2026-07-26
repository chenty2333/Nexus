# Real IRQ path: inventory and phase plan

- Status: **planning inventory plus one recorded spike observation; no capability claim**
- Inventory date: 2026-07-26
- Phase A spike date: 2026-07-26
- Target: a possible successor to the current polling checkpoint
- Changes accepted `v0.1.0` claims: **no**

## Claim discipline

This note inventories the code sites that currently establish the polling
boundary, records what the pinned `ostd = 0.18.0` dependency offers for
interrupt delivery, and proposes obligations and phases for a real IRQ path. It
makes **no `Observed` and no `Checked` claim** in the RFC sense. Nothing here
reports a completed implementation or an RFC phase exit.

Section 7 records a Phase A spike that did execute in QEMU. That section reports
a spike observation, not a checkpoint: it is not in
`status/current-capabilities.toml`, it did not run under any verification path,
and its lane is not present in the repository (section 7.4 explains why). A
spike observation may be cited as a reason to expect something, never as
evidence that an obligation is discharged.

The current recorded boundary is `polling-with-intx-masked-no-real-irq`
(`status/current-capabilities.toml:41`). That boundary is unchanged by this
document. Where the inventory below names an API that exists but is unused, the
correct reading is that the surface is present and the evidence is absent; the
two must not be conflated.

Reading of the pinned OSTD source in this note is a static source reading of
the vendored crates.io archive, not an execution result.

## 1. Current polling boundary: exact inventory

### 1.1 Where INTx is masked

INTx masking is not a separate opt-in step in the primary lane. It is an
unconditional part of enabling the device for preparation:

- `crates/nexus-ostd-virtio/src/pci.rs:1029-1031` — `enable_device_for_prepare_checked`
  computes `command | Command::MEMORY_SPACE | Command::BUS_MASTER |
  Command::INTERRUPT_DISABLE` and writes it. Every preparation therefore leaves
  PCI Command `INTERRUPT_DISABLE` set.
- `crates/nexus-ostd-virtio/src/pci.rs:1027` — the same function first calls
  `internal_mask_allowed_checked`, so an owner which has already claimed an
  unmasked INTx token cannot be silently remasked behind that token's back.
- `crates/nexus-ostd-virtio/src/pci.rs:1034` and `:685` —
  `assert_intx_state_matches_command` keeps the software owner state and the
  observed PCI command in agreement after each write.
- `crates/nexus-ostd-virtio/src/pci.rs:321-327` — `decode_intx_route` reads the
  firmware-programmed interrupt line and pin from configuration offset `0x3c`
  (`INTERRUPT_CONFIG_OFFSET`, `pci.rs:36`) at discovery. This is descriptive
  routing information only; it grants no interrupt-controller authority.

A linear masked/unmasked token discipline already exists and is unused:

- `crates/nexus-ostd-virtio/src/pci.rs:436` — `Root::claim_masked_intx`
  claims the root's unique INTx lifecycle in the masked state.
- `crates/nexus-ostd-virtio/src/pci.rs:465` — `Root::unmask_intx` consumes a
  `MaskedIntx` and returns an `UnmaskedIntx`, refusing to unmask unless hardware
  readback agrees with the token's masked state.
- `crates/nexus-ostd-virtio/src/pci.rs:541` — `Root::mask_intx` is the reverse
  transition.
- `crates/nexus-ostd-virtio/src/pci.rs:595` —
  `Root::recover_masked_intx_fail_closed` is one-way; it can never authorize
  unmasking.

No caller of `claim_masked_intx`, `unmask_intx`, or `mask_intx` exists anywhere
in `kernel/`, `crates/`, or `experiments/`. The transition authority is
implemented and never exercised. The token API is consequently untested against
real hardware behaviour beyond its unit assertions at `pci.rs:1188-1215`.

### 1.2 Where completion is polled

Two distinct polling lanes exist, and they are not the same code path.

The primary same-boot filesystem lane drives a bounded probe loop from the
kernel rather than inside the facade:

- `kernel/nexus-ostd/src/personality/linux_fs.rs:4410` — the primary lane
  obtains its permit through `device.preflight_read_sector0(&mut root)`, the
  **polling** preflight. It does not call `preflight_read_sector0_irq`.
- `crates/nexus-ostd-virtio/src/production.rs:1543` — that preflight fixes
  `CompletionMode::Polling` before the queue becomes device-visible.
- `crates/nexus-ostd-virtio/src/production.rs:85-87` —
  `CompletionMode::device_notifications_enabled` returns `false` for `Polling`,
  so used-buffer notifications are suppressed at the queue level as well as at
  the PCI command level.
- `kernel/nexus-ostd/src/personality/linux_fs.rs:5291` — the flight machine
  calls `request.probe_completion_once()` once per turn, reinserting the
  unchanged owner and calling `spin_loop()` at `:5305`.

The legacy Stage 5B separate-boot experiment uses the facade's own loop:

- `crates/nexus-ostd-virtio/src/production.rs:3108-3125` —
  `PublishedRequest::poll_completion` spins up to `POLL_LIMIT` times. Its
  doc comment at `:3106-3107` states plainly that the method "does not establish
  an interrupt-delivery claim" and that "the future main adapter must select a
  real IRQ completion API instead".
- `experiments/ostd-virtio-cser-spike/src/lib.rs:161` — the spike's single call
  site.

Both lanes converge on one validator:

- `crates/nexus-ostd-virtio/src/production.rs:3129-3136` — `complete_once` is
  the sole descriptor-pop and response-validation implementation, shared by
  polling, the one-step probe, and the IRQ completion entry point.
- `tools/virtio/assert-production-substrate.sh:942` — a source gate fails the
  build if "polling and IRQ completion forked descriptor validation".

This shared validator is the single most useful precondition already in place:
an IRQ lane would not introduce a second completion semantics.

### 1.3 Where a deadline substitutes for interrupt latency

There is no timer-driven watchdog in the completion path. The substitute for
interrupt latency is a bounded spin count in both lanes:

- `kernel/nexus-ostd/src/personality/linux_fs.rs:254` —
  `SAME_BOOT_COMPLETION_PROBE_LIMIT: usize = 10_000_000`, consumed at `:5293`.
  Exhausting it does not fabricate success: `:5307-5314` sets
  `completion_label = "Pending"` with `result = -5`, and `:5316` moves to
  `preflight_reset`, i.e. the honest reset/tombstone path.
- `crates/nexus-ostd-virtio/src/production.rs:42` — `POLL_LIMIT: usize =
  10_000_000` for the facade loop, returning `CompletionProgress::Pending`
  at `:3122-3124` with the linear owner retained.

Both limits are iteration counts, not wall-clock deadlines. Neither is
calibrated against any device latency. RFC 0001 already requires that a
non-success timeout name its assumptions
(`docs/rfcs/0001-production-identity.md:461-463`); an iteration budget with no
clock is a weaker statement than a deadline, and this should be treated as a
known gap rather than as an existing deadline policy that IRQ work would
inherit.

### 1.4 The IRQ facade that already exists and is not wired

The facade has a complete, unused interrupt-mode surface:

- `crates/nexus-ostd-virtio/src/production.rs:77-82` — `CompletionMode` with a
  `Polling` and an `Interrupt` variant.
- `crates/nexus-ostd-virtio/src/production.rs:1549-1554` —
  `preflight_read_sector0_irq` selects `CompletionMode::Interrupt`.
- `crates/nexus-ostd-virtio/src/production.rs:1749` and `:1766` —
  `prepare_read_sector0_irq` and `prepare_read_sector0_irq_with_evidence`. The
  doc comment at `:1744-1748` records that these differ from the polling
  constructor "only in [the] pre-publication used-buffer notification mode" and
  that "PCI INTx remains masked until the owning kernel has installed its IRQ
  actor and explicitly consumes a `MaskedIntx` through `Root::unmask_intx`".
- `crates/nexus-ostd-virtio/src/production.rs:3021-3032` —
  `PublishedRequest::ack_interrupt`, the only method documented as intended for
  hard-IRQ context. It performs exactly one VirtIO ISR read and returns an
  `InterruptReceipt` carrying the attempt identity, the device-session identity,
  and a typed cause.
- `crates/nexus-ostd-virtio/src/production.rs:2699-2717` — `InterruptCause`
  distinguishes `Spurious`, `Queue`, `Configuration`, and
  `QueueAndConfiguration`; `includes_queue` is the only authorization to probe
  the used ring.
- `crates/nexus-ostd-virtio/src/production.rs:3043-3088` —
  `complete_after_interrupt` rejects a foreign attempt (`:3047`), a foreign
  device-session identity (`:3053`), a polling-mode request (`:3063`), and a
  non-queue cause (`:3069`) before reaching the shared validator, returning the
  unchanged linear owner in each case.
- `crates/nexus-ostd-virtio/src/production.rs:2777-2794` —
  `InterruptCompletionProgress::NotReady` deliberately returns the exact
  `PublishedRequest` rather than the polling timeout typestate, so an actor may
  reinsert it and retry on a later interrupt.

No Nexus code constructs an `InterruptReceipt`. `kernel/nexus-ostd/src/personality/virtio_cser_adapter.rs`
(213 lines) imports only `PreparationReceipt`, `PreparationIndeterminate`,
`PreparationRollbackReceipt`, and `ProductionClosureReceipt`
(`virtio_cser_adapter.rs:17-20`); it has no interrupt vocabulary. The crate's
own summary is explicit: the facade "does not itself install an OSTD IRQ actor
or establish interrupt delivery" (`crates/nexus-ostd-virtio/src/lib.rs:11-13`),
and the witness "remains polling-only with INTx masked: it does not install an
OSTD `IrqLine`" (`crates/nexus-ostd-virtio/README.md:145-148`).

### 1.5 Exact boundary vocabulary in ledgers and receipts

An IRQ lane must not reuse or overwrite these strings. They are quoted here so
that any successor vocabulary can be chosen to be visibly distinct.

Ledger boundary, `status/current-capabilities.toml`:

- `:34` — capability `"same-boot-virtio-iommu-dma-polling-normal-lane"`
- `:41` — boundary `"polling-with-intx-masked-no-real-irq"`
- `:88` — external boundary `"no-real-service-death-ostd-irq-or-smp"`

Serial receipts, exact text:

- `tools/xtask/src/evidence.rs:1310` —
  `LINUX_FS_SAME_BOOT PASS same_boot=true identity_preserving=true real_dma=true polling=true irq=false smp=1`
- `kernel/nexus-ostd/src/personality/linux_fs_postcommit.rs:211` and `:362` —
  both `LINUX_FS_POSTCOMMIT` lines end `polling=true irq=false smp=1`
- `experiments/ostd-virtio-cser-spike/src/lib.rs:77` —
  `VIRTIO_CSER BEGIN device=blk mode=polling irq_masked=true smp=not_proven hardware=QEMU`
- `experiments/ostd-virtio-cser-spike/src/lib.rs:369` —
  `VIRTIO_CSER PASS ... polling=true smp=not_proven portal_type_state=true`
- `tools/xtask/src/causal_coverage.rs:9` — scope
  `"bounded-same-boot-single-vcpu-polling-checkpoint"`

These strings are asserted verbatim by
`experiments/ostd-virtio-cser-spike/scripts/assert-serial.sh:14,49` and
`kernel/nexus-ostd/scripts/assert-composition.sh:30,70`, and the postcommit
scope note at `tools/xtask/src/production_identity_postcommit.rs:331` names IRQ
explicitly as open.

Prose boundaries which would need revision, not deletion, if an IRQ lane were
accepted: `ARCHITECTURE.md:611`, `VISION.md:449-451`, `NARRATIVE.md:592`,
`REWORK.md:325`, `docs/rfcs/0001-production-identity.md:52`, and
`docs/research/v0.2-preflight-decision.md:71`.

### 1.6 Pinned platform configuration

The QEMU invocation is part of the boundary and must be read as such:

- `kernel/nexus-ostd/OSDK.toml:33`, `:70`, `:107` —
  `-machine q35,kernel-irqchip=split,default-bus-bypass-iommu=off`
- `kernel/nexus-ostd/OSDK.toml:46`, `:83`, `:120` —
  `-device intel-iommu,intremap=on,caching-mode=on,dma-drain=on`
- `kernel/nexus-ostd/OSDK.toml:49`, `:86`, `:123` — the block device carries
  `disable-legacy=on,iommu_platform=on,...,vectors=0`

`vectors=0` disables the MSI-X vector table on this function. Under the pinned
line the device therefore has no MSI-X path at all, and legacy INTx is the only
delivery mechanism available. `intremap=on` means any interrupt that is
delivered passes through VT-d interrupt remapping.

## 2. What OSTD 0.18.0 offers for IRQ

The pinned crate source was read at
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ostd-0.18.0`
(`kernel/nexus-ostd/Cargo.lock` pins `ostd` version `0.18.0` from crates.io).
Paths below are relative to that root.

### 2.1 The IRQ line surface is public

`src/irq/top_half.rs` exposes, as crate-root-reachable `pub` items:

- `:21` — `pub type IrqCallbackFunction = dyn Fn(&TrapFrame) + Sync + Send + 'static`
- `:36` — `pub struct IrqLine`
- `:43` — `pub fn alloc() -> Result<Self>`
- `:52` — `pub fn alloc_specific(irq_num: u8) -> Result<Self>`
- `:71` — `pub fn num(&self) -> u8`
- `:78` — `pub fn on_active<F>(&mut self, callback: F)`
- `:107` — `pub fn remapping_index(&self) -> Option<u16>`

`src/lib.rs:41` declares `pub mod irq`. Callbacks run with local IRQs disabled
on the handling CPU, which the module documentation states directly
(`src/irq/mod.rs:12-18`).

### 2.2 The I/O APIC routing surface is public

`src/lib.rs:32` declares `pub mod arch`; `src/arch/x86/mod.rs:10` declares
`pub mod irq`. Within `src/arch/x86/irq/chip/mod.rs`:

- `:29` — `pub struct IrqChip`
- `:49` — `pub fn map_gsi_pin_to(...) -> Result<MappedIrqLine>`
- `:92` — `pub fn map_isa_pin_to(...)`
- `:117` — `pub fn count_io_apics(&self) -> usize`
- `:125` — `pub struct MappedIrqLine`
- `:161` — `pub static IRQ_CHIP: Once<IrqChip>`

`disable_gsi` is not public; teardown is RAII through `MappedIrqLine`'s `Drop`.
That is an acceptable shape for the linear-ownership style already used by the
facade, not a blocker.

### 2.3 The hash-bound patch already carries the level-triggered overlay

This is the material finding. Stock `map_gsi_pin_to` programs an edge-triggered,
active-high redirection entry, which is wrong for legacy PCI INTx (level, active
low). The vendored patch already fixes exactly this:

- `patches/ostd-0.18.0-cser.patch` touches `src/arch/x86/irq/chip/ioapic.rs`,
  `src/arch/x86/irq/chip/mod.rs`, `src/arch/x86/irq/mod.rs`,
  `src/arch/x86/irq/remapping.rs`, and `src/irq/top_half.rs` among its 24 files
  and 85 hunks (1695 lines total).
- It adds `pub enum GsiPolarity`, `pub enum GsiTriggerMode`, `pub struct
  GsiConfig` with `pub const EDGE_HIGH`, and a new
  `pub fn map_gsi_pin_to_with_config(irq_line, gsi_index, config)`. The stock
  `map_gsi_pin_to` is preserved as a delegation to `GsiConfig::EDGE_HIGH`, so no
  existing behaviour changes.
- It writes RTE bits 13 (active low) and 15 (level triggered) in
  `IoApic::enable`, and synchronizes the interrupt-remapping table entry's
  trigger-mode bit through `IrqRemapping::set_trigger_mode` and
  `IrtEntry::new_enabled(vector, level_triggered)`.
- It adds a reference-counted `claim_remapping_trigger_mode` /
  `release_remapping_trigger_mode` pair on `IrqLine` so two mappings cannot
  disagree about a shared line's trigger mode, released in `MappedIrqLine::drop`.
- `src/arch/x86/irq/mod.rs` re-exports `GsiConfig, GsiPolarity, GsiTriggerMode`
  alongside `IRQ_CHIP, IrqChip, MappedIrqLine`.

The overlay is already hash-bound and asserted:
`tools/ostd/assert-cser-patch.sh:5` pins `expected_patch_sha=6167dc68...`,
`:1231-1268` assert each of the fragments above by exact text, and `:1275`
records `gsi=edge+level/high+low ioapic_bits=13+15 irte_tm_bit=4
legacy=edge-high` in the pass line. It landed in commit `2769638`
("refactor(ostd): share audited DMA and GSI overlay").

No Nexus code references `GsiConfig`, `map_gsi_pin_to`, `IrqLine`, or
`IRQ_CHIP`. The OSTD-side enabler exists; the Nexus-side consumer does not.

### 2.4 MSI-X is not offered by OSTD 0.18 at all

`src/bus.rs` is the entire `ostd::bus` module in 0.18.0: fourteen lines
containing only `pub enum BusProbeError`, alongside an upstream comment noting
that a bus component is not yet implemented. There is no `ostd::bus::pci`, no
`PciDeviceLocation`, no `CapabilityMsixData`, and no MSI or MSI-X capability
support of any kind. This is why `nexus-ostd-virtio` performs its own PCI
enumeration and BAR ownership in `crates/nexus-ostd-virtio/src/pci.rs:876`.

An MSI-X path would therefore have to program the capability from Nexus code,
using `IrqLine::alloc()` for the vector and `IrqLine::remapping_index()`
(`src/irq/top_half.rs:107`, public) to compose a remappable-format MSI address
and data. That is possible in principle without patching OSTD, but it is
substantially more new unsafe PCI capability code than the INTx route, and it is
blocked in any case by `vectors=0` in the pinned QEMU line (section 1.6).

### 2.5 Answer to the patch-growth question

**For legacy INTx, no growth of the hash-bound patch is required.** Every API
the Nexus side needs is already public: `IrqLine::alloc_specific`,
`IrqLine::on_active`, `IRQ_CHIP`, and the patch's own
`map_gsi_pin_to_with_config` with `GsiTriggerMode::Level` and
`GsiPolarity::ActiveLow`. There is no analogue here of the Stage 5B IOMMU
negative result, where the required state was crate-private in stock 0.18: the
IRQ surface was already public, and the one genuine gap (level/active-low
routing plus IRTE trigger-mode synchronization) was closed by a previous,
already-audited patch revision.

**For MSI-X, the blocker is not visibility but absence** — OSTD 0.18 has no PCI
capability layer to make private. The work would land in Nexus's own PCI module,
and the pinned device line would have to change first.

## 3. Why the IRQ path matters here

**Measurement.** RFC 0001's Phase 5 requires steady-state read latency,
completion cost, and crash-to-resume latency against predeclared baselines
(`docs/rfcs/0001-production-identity.md:561-572`). Every one of those numbers
collected under the current lane would measure a ten-million-iteration spin
budget (`linux_fs.rs:254`) rather than a completion mechanism. Polling does not
merely add overhead; it changes which quantity is being measured, so a polling
figure cannot be narrowed into an IRQ figure by any later caveat. RFC 0001
already forbids the substitution directly: "Polling-only or software-only
timeout evidence may remain diagnostic but cannot silently satisfy an IRQ or
hardware-acknowledgement requirement" (`:420-423`).

**The CSER question.** Under polling, every completion is consumed by the task
that is already holding the flight and already inside the causal path; there is
exactly one entry point. An interrupt is a second, asynchronous entry point into
the commit and closure path, taken on whatever CPU the I/O APIC selects, at a
moment the service does not choose. The binding-epoch fence which today rejects
a stale incarnation's prepare, commit, and reply
(`kernel/nexus-ostd/src/cser/infrastructure/device.rs:1260-1266`,
`reply.rs:66`, `continuation.rs:79`) must hold on that path too: a crashed
incarnation's still-armed interrupt handler must not commit, must not publish a
second time, and must not resurrect an effect the replacement has already
adopted. RFC 0001 lists exactly this cell — "root revoke while an IRQ/completion
executes on another CPU" (`:487`) — and requires that a lock reachable from a
local interrupt either exclude that interrupt or use a documented non-reentrant
scheme (`:449-451`). The facade's split between `ack_interrupt` (hard-IRQ, ISR
read only) and `complete_after_interrupt` (task context, takes the DMA ledger
lock) is a proposed answer to that requirement, but it has never been executed.

## 4. Obligations

Each obligation is stated so that a specific observation would falsify it. None
is currently discharged.

1. **IRQ-path fence enforcement.** An interrupt delivered after the owning
   domain's binding epoch has advanced must be rejected without semantic
   mutation, by the same registry predicates that fence the polling path
   (`device.rs:1260-1266`). The test is a deliberate stale-incarnation
   interrupt: the handler runs, `ack_interrupt` succeeds at the transport level,
   and the registry transition still returns `StaleBinding` with the complete
   before/after projection unchanged. An IRQ-local shortcut that bypasses the
   registry gate, however small, refutes this obligation.

2. **Exactly-once completion delivery against the existing polling lane.** The
   two lanes must not both be able to consume one used descriptor. Since
   `complete_once` (`production.rs:3129`) is the sole validator and consumes the
   linear `PublishedRequest`, ownership already excludes double consumption
   within one process; the obligation is to show that the IRQ actor's slot and
   the flight machine's `take_flight`/`put_flight`
   (`linux_fs.rs:1120,1124`) cannot both hold a claim to the same request across
   a preemption. `reply_wakeups` must remain exactly `1`
   (`linux_fs.rs:2829,2853`), and `terminalization count` and `publication
   count` must each remain `1` in the fault-cell record.

3. **Deadline and watchdog interaction.** With interrupts armed, the iteration
   budgets of section 1.3 no longer describe the waiting policy. The IRQ lane
   must state what happens when no interrupt arrives: which named non-success
   state is returned, what retains the device session, queue, mappings, and
   typed credits, and on what clock. A watchdog that fires and reports
   `Revoked`, or that fabricates a completion, refutes this obligation
   (RFC 0001 `:523-524`). A watchdog that never fires because it has no clock is
   not a deadline and must not be described as one.

4. **Masked-to-unmasked transition honesty.** Unmasking must go through
   `Root::unmask_intx` (`pci.rs:465`), consuming the `MaskedIntx` token, and
   must occur only after the IRQ actor is installed and the request is published
   — the ordering already documented at `production.rs:1744-1748`. The observed
   PCI command must agree with the token state at every step
   (`pci.rs:685`), a readback mismatch must return the typed error rather than
   leave software and hardware disagreeing, and teardown must remask or
   fail closed via `recover_masked_intx_fail_closed` (`pci.rs:595`). Since these
   paths have never executed against hardware, their first execution is itself
   the evidence being sought, and a failure there is a result, not a bug to be
   worked around.

5. **Receipt vocabulary separation.** No existing polling receipt may be
   relabelled. The strings in section 1.5 are asserted verbatim by
   `assert-serial.sh` and `assert-composition.sh`; an IRQ lane must emit its own
   distinct line and leave `polling=true irq=false smp=1` attached to the
   polling lane that actually produced it. Rewriting `irq=false` to `irq=true`
   in a line whose scope is `bounded-same-boot-single-vcpu-polling-checkpoint`
   (`causal_coverage.rs:9`) would be exactly the relabelling that
   `docs/rfcs/0001-production-identity.md:26-27` forbids. The ledger boundary
   `polling-with-intx-masked-no-real-irq` is replaced by an explicit
   exact-revision supersession entry (`status/current-capabilities.toml:14`), not
   edited in place.

## 5. Phases

Each phase is small and ends with an artifact whose wording is bounded by what
was executed. A later phase may not inherit an earlier phase's caveats as if
they had been discharged.

### Phase A — spike: one observed interrupt, no claims

Allocate an `IrqLine` for the GSI corresponding to the block function's INTA#
pin, map it with `map_gsi_pin_to_with_config(..., GsiConfig::new(ActiveLow,
Level))`, register a callback that does nothing but record a counter, prepare
the request through `prepare_read_sector0_irq`, unmask via `unmask_intx`, and
observe whether the callback fires at all in the pinned QEMU configuration.

Exit: a serial line reporting that an interrupt was or was not delivered, in a
lane clearly named as a spike. No completion is taken from the IRQ path; the
existing polling probe still resolves the request. No capability entry, no
change to the ledger boundary.

### Phase B — fence lane: stale-incarnation IRQ rejected

Move completion onto `ack_interrupt` plus `complete_after_interrupt`, keeping
the polling lane intact and separately invocable. Then inject the fault cell
that matters: advance the owning domain's binding epoch while an interrupt is in
flight, and show the registry rejecting the stale completion with the full
semantic projection unchanged.

Exit: bounded single-vCPU `Observed` evidence for obligations 1, 2, and 4, with
its own receipt vocabulary. This does not close RFC 0001 Phase 3 or Phase 4, and
it says nothing about 2-vCPU or 4-vCPU behaviour, where the interesting version
of this race lives.

### Phase C — primary lane replacement with a declared boundary change

Only after Phase B: switch the primary same-boot filesystem lane from
`preflight_read_sector0` to `preflight_read_sector0_irq`, state the deadline
policy required by obligation 3, and record the measurement-boundary change
explicitly — that every latency figure before this point measured a polling
artifact and is not comparable to figures after it.

Exit: a superseding `status/current-capabilities.toml` checkpoint whose boundary
list no longer contains `polling-with-intx-masked-no-real-irq` and whose
capability list names the exact lane observed. The prose boundaries listed in
section 1.5 are revised, and the Stage 5B polling receipts are left untouched as
historical evidence.

### Stop and pivot conditions

Recorded in the style of the Stage 5B negative result: a boundary that is found
is a result to be published, not an obstacle to be patched around.

1. **Patch growth.** Section 2.5 concludes that the INTx path needs no new
   OSTD patch. If implementation contradicts that — if any required IRQ,
   I/O APIC, or interrupt-remapping state turns out to be crate-private in a way
   that stock 0.18 plus the current `6167dc68...` overlay cannot reach — stop and
   record the exact private item and the hunk that would be required. The
   overlay must not grow silently. Concretely: if closing the gap would add more
   than a single file to the patch's 24-file surface, or would touch OSTD state
   that the existing assertions in `tools/ostd/assert-cser-patch.sh:1231-1268` do
   not already pin, the growth is reported as a finding before any patch edit is
   proposed.

2. **No delivery in the pinned configuration.** If Phase A observes no interrupt
   under `q35,kernel-irqchip=split` with `intremap=on` and `vectors=0`, record
   that as a platform boundary. Changing the pinned QEMU line to obtain a
   delivery is itself a boundary change and cannot be made quietly inside a
   spike; RFC 0001 `:626-627` already contemplates the pinned platform being
   unable to expose the required interrupt path.

3. **Fence cannot hold.** If no documented lock and IRQ-exclusion scheme gives a
   total commit/revoke winner with the interrupt handler as a second entry
   point, this is RFC 0001 kill criterion 4 (`:621-622`), and the result is a
   negative one about the mechanism rather than a reason to keep polling and
   describe it differently.

4. **Deadline dishonesty.** If the only way to make the IRQ lane terminate is a
   watchdog that reports a success or a `Revoked` it did not establish, stop.
   Retaining the session and returning a named non-success state is required
   (`:445`); there is no acceptable weaker version.

## 6. Open questions

Questions 1 and 2 were answered by the Phase A spike and are recorded in
section 7.2. The remainder stay unresolved rather than guessed.

3. **INTx line sharing.** `IrqLine::alloc_specific` and the patch's
   reference-counted trigger-mode claim both anticipate a shared line. Whether
   any other function in the pinned machine shares this GSI, and what a spurious
   interrupt from that other function would do to `ack_interrupt`'s
   `InterruptCause::Spurious` path, is not established.

4. **Which clock Phase C's deadline should use.** OSTD's timer surface was not
   inventoried for this note. Obligation 3 states what the deadline must
   guarantee, not how it is sourced.

5. **Whether the one-step actor slot is preemption-safe.** Obligation 2 asserts
   that linear ownership prevents double consumption. The argument was made from
   type signatures, not from an examination of every path by which the flight
   machine and a future IRQ actor could both reach a `PublishedRequest`. It
   needs checking before it is relied upon.

## 7. Phase A spike outcome (2026-07-26)

An interrupt was delivered and observed. This section records what was executed,
what it answered, and why the lane is not in the repository.

The run was a separate-boot experiment built on `experiments/ostd-virtio-cser-spike`
under its default QEMU line — the same pinned machine as section 1.6, including
`q35,kernel-irqchip=split`, `intel-iommu,intremap=on`, and `vectors=0`. It
prepared through `prepare_read_sector0_irq`, published, unmasked INTx through
`Root::unmask_intx`, waited for a delivery counter, remasked through
`Root::mask_intx`, and took completion from the polling probe. It made no
registry, identity, or capability claim.

### 7.1 What executed

The kernel receipt tail, from the spike's own vocabulary (deliberately disjoint
from the polling strings in section 1.5):

```text
IRQ_SPIKE Route bdf=00:05.0 firmware_line=10 pin=1 source=pci_config_0x3c
IRQ_SPIKE Masked stage=claimed line=10
IRQ_SPIKE Armed gsi=10 vector=35 remapping_index=Some(0) trigger=edge polarity=active_high
IRQ_SPIKE Armed gsi=21 vector=41 remapping_index=Some(6) trigger=edge polarity=active_high
IRQ_SPIKE Prepared session=0x4e58505200280001 generation=1 queue=0 descriptor=0 notifications_enabled=true
IRQ_SPIKE Published commit_point=avail_idx_release notification=Kicked
IRQ_SPIKE Unmasking stage=window_open line=10 isr_unread=true reentry_expected=true
IRQ_SPIKE Remasked stage=window_closed line=10 iterations=0 deliveries=2
IRQ_SPIKE Candidate gsi=10 vector=35 remapping_index=Some(0) deliveries=1
IRQ_SPIKE Candidate gsi=21 vector=41 remapping_index=Some(6) deliveries=1
IRQ_SPIKE Completion source=polling observed=true used_len=513
IRQ_SPIKE PASS delivery=observed deliveries=2 firmware_line=10 firmware_line_delivered=true pirq_gsi=Some(21) iterations=0 candidates=9 intremap=on trigger=edge polarity=active_high completion=polling completion_observed=true claim=none
```

Nine candidate Global System Interrupts were armed: the firmware-programmed
line, and the whole PIRQA..PIRQH block (GSI 16..23). Arming the block rather
than trusting one number is what made the routing answer an observation instead
of an assumption.

### 7.2 Answers to open questions 1 and 2

**Open question 1 — GSI resolution — answered, and the assumption it was
guarding turned out to be only half right.** The firmware-programmed interrupt
line at configuration offset `0x3c` is `10`, and GSI 10 *did* deliver. But it
was not the only one: GSI 21 delivered as well, from the same single INTA#
assertion. GSI 21 is the PIRQ entry for this function (`16 + (5 % 8)`, device
`00:05.0`). Under q35 the assertion reaches the I/O APIC by two routes at once —
the ISA-compatibility line the firmware wrote into `0x3c`, and the PCI link
entry in the PIRQ block.

The consequence for Phase B is concrete: reading `IntxRoute::line`
(`pci.rs:321-327`) and mapping that one GSI is *sufficient to receive
interrupts*, so the fallback contemplated in the original open question works.
But a driver that arms both routes takes two interrupts per assertion. Phase B
must choose one route and leave the other unmapped, and should prefer the PIRQ
entry, since that is what the ACPI `_PRT` would name in APIC mode and what the
`0x3c` value only coincidentally tracks. Neither route can be discovered from
`AcpiInfo` (`src/arch/x86/kernel/acpi/mod.rs:104-113` still exposes no routing
data), so whichever is chosen is a pinned-platform assumption that must be
stated rather than derived.

**Open question 2 — IRTE allocation ordering under `intremap=on` — answered
affirmatively, from source and then from execution.** `IrqLine::new` calls
`inner.remapping.init(index + IRQ_NUM_MIN)` at allocation time
(`src/irq/top_half.rs:62`), before any mapping call, so the interrupt-remapping
table entry always exists by the time `map_gsi_pin_to_with_config` runs and the
patch's `set_trigger_mode` can never take its early-return path for a line that
is about to be mapped. The spike confirms this at runtime: every armed candidate
reported a concrete `remapping_index=Some(n)` with `n` allocated densely from
`0`, and delivery occurred with remapping active. No patch growth and no
ordering workaround is needed for the IRTE.

### 7.3 A finding that was not anticipated: level-triggered livelock

The lane was first written the electrically correct way for legacy PCI INTx —
`GsiPolarity::ActiveLow` with `GsiTriggerMode::Level`, exactly what the patch's
overlay exists to provide. **That configuration livelocks.** Two consecutive
runs hung at the identical point, immediately after unmasking, and were killed
by the harness timeout; the last line emitted in both was the pre-unmask
announcement, and QEMU's trace confirmed the device had already completed the
request (`virtio_blk_req_complete ... status 0`) before the window opened.

The cause is not in doubt. Nothing in Phase A reads the VirtIO ISR — the spike
deliberately did not call `ack_interrupt`, because deasserting is the completion
actor's job and that actor is Phase B work. A level-triggered line whose ISR is
never read stays asserted, so the handler re-enters on every `IRET` and the
guest makes no observable forward progress. The delivery observation above was
therefore taken with an **edge**-triggered mapping, which fires once per
assertion and terminates.

This is a real constraint on Phase B, and it sharpens obligation 1. An
interrupt-driven completion lane on this platform is not optional about
acknowledgement: the hard-IRQ top half must call `ack_interrupt`
(`production.rs:3021`) on *every* delivery, including deliveries it will go on
to reject. A stale-incarnation interrupt that the registry fences must still
have had its ISR read, or the fence will be correct and the machine will still
livelock. The facade's split between `ack_interrupt` and
`complete_after_interrupt` (`production.rs:3043`) already has the right shape
for this — acknowledgement is separable from, and unconditional relative to,
the completion decision — but the spike did not exercise it, and obligation 1
should be read as requiring both the fence *and* the acknowledgement.

It also means Phase A's "no completion from the IRQ path" boundary cannot be
held in the electrically correct configuration. The edge mapping is a
measurement artifact of the spike, not a design proposal; Phase B should return
to level/active-low once it owns an acknowledging actor.

### 7.4 Why the lane is not in the repository

The spike ran from a working tree, and that tree was reverted. The lane cannot
currently be committed to `experiments/ostd-virtio-cser-spike` without breaking
the Stage 5B lane, for a reason that is worth recording precisely because it
will recur for Phase B.

OSDK 0.18 offers exactly one mechanism for selecting a build variant: Cargo
features, via `cargo osdk build --features` or a scheme's `build.features`.
There is no rustflags option, and OSDK discards `RUSTFLAGS` from the
environment — verified directly: a kernel built with `RUSTFLAGS='--cfg
irq_spike'` contained zero occurrences of the spike's strings.

Declaring a feature in the experiment manifest, however, makes OSDK propagate it
into the generated run-base crate:

```text
+++ target/osdk/ostd-virtio-cser-spike-run-base/Cargo.toml
 [features]
+irq-spike = ["ostd-virtio-cser-spike/irq-spike"]
```

To add that line OSDK regenerates the whole run-base directory from its embedded
templates, including the linker scripts. Those templates indent
otherwise-blank lines, while the repository's pinned `osdk-runner-base/*.ld` do
not, so the byte-exact `diff -ru` that both `x` and the image's own build step
run afterwards can never hold. This happens on a **plain** `cargo osdk build`,
because the feature is declared rather than activated — so merely adding the
feature breaks the default Stage 5B image build, not only the spike lane.

The cause was isolated rather than inferred: a comment-only change to the same
manifest rebuilds the image cleanly, and the identical change plus a `[features]`
table fails. Mirroring the kernel crate's `cargo fetch --locked` plus
`CARGO_NET_OFFLINE=true` recipe, which is how `kernel/nexus-ostd` builds four
schemes without hitting this, does not help.

Resolving it means either repairing the pinned `osdk-runner-base/*.ld` so they
match what OSDK emits, or relaxing the runner-base comparison for
feature-selecting lanes. Both change an existing hermeticity artifact of the
Stage 5B lane, which is a decision for the team rather than something a spike
should force — this is the stop condition of section 5 applied to the harness
instead of the patch. The implementation, its oracle, the lane wiring, and the
captured serial logs are retained under
`docs/research/irq-spike-phase-a/` (`irq_spike.rs`, `assert-irq-spike.sh`,
`lane-wiring.diff`, `kernel.log`, `oracle.log`, `serial-edge-pass.log`) so that
whichever repair is chosen, the lane does not have to be rediscovered. These
files are retained evidence and a reusable starting point; they are not part of
any build and carry no claim.

### 7.5 What this does and does not license

Observed in one separate boot, on one pinned QEMU configuration, at one vCPU:
one real INTx delivery into an OSTD `IrqLine` callback, through VT-d interrupt
remapping, with the facade's `MaskedIntx` → `UnmaskedIntx` → `MaskedIntx` token
sequence executing against real hardware state for the first time.

Not observed, and not claimed: interrupt-driven completion; the binding-epoch
fence on the IRQ path; exactly-once delivery against the polling lane; any
deadline or watchdog policy; level-triggered operation; SMP behaviour; anything
about the primary same-boot filesystem lane, which was not touched and still
prepares through `preflight_read_sector0` (`linux_fs.rs:4410`). The ledger
boundary `polling-with-intx-masked-no-real-irq`
(`status/current-capabilities.toml:41`) is unchanged and was deliberately not
edited. Obligations 1 through 5 all remain open; the spike narrows how
obligations 1 and 4 must be built, and it does not discharge any of them.
