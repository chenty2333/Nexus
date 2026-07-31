// SPDX-License-Identifier: MPL-2.0

//! QEMU-backed DMA recovery slice for the mutually exclusive portable core.
//!
//! This path owns the real `nexus-ostd-virtio::ProductionDevice` lifecycle and
//! never constructs the legacy Registry, portal, filesystem personality, or a
//! second semantic ledger. It exercises a modern VirtIO block function behind
//! QEMU VT-d: descriptor preparation, `avail.idx` Release publication, device
//! completion, a real VirtIO ISR-status read/acknowledgement, whole-device
//! reset, generation fencing, and OSTD's ownership-carrying VT-d IOTLB
//! invalidation completion.
//!
//! A real OSTD IRQ line is mapped to the firmware GSI before PCI INTx is
//! unmasked. Its top half performs exactly the device ISR read/ack and deposits
//! the opaque receipt; the manager remasks INTx before extracting the request
//! for task-context completion. QEMU is hardware emulation, not
//! physical-hardware evidence. Core transitions use an in-memory journal in
//! this development slice; reboot persistence is proved by the independent
//! persistent-provider suite.

use alloc::{sync::Arc, vec::Vec};
use core::{
    convert::Infallible,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

use cser_core::{
    BootGeneration, ChargeAccountId, ClaimId, Command, CommandRequest, CoreError, CoreLimits,
    DeviceGeneration, Digest, EffectId, Engine, Freshness, JournalGeneration, JournalRecord,
    PrincipalId, PrincipalIncarnation, RegistryInstance, ResourceGeneration, ResourceId, RootId,
    SnapshotId, TransitionDurability, TransitionOutput, TransitionReceipt, TxError,
    standard_catalog,
};
use nexus_ostd_virtio::{
    CompletedRequest, CompletionMode, InterruptCompletionProgress, InterruptNotReadyReason,
    InterruptReceipt, MaskedIntx, OwnerKind, ProductionClosureProgress, ProductionDevice,
    ProductionResetRetryError, PublishedRequest, Root, discover_and_own_bars, owner_address,
};
use ostd::{
    arch::irq::IRQ_CHIP,
    irq::IrqLine,
    power::{ExitCode, poweroff},
    prelude::*,
    sync::SpinLock,
    task::{Task, TaskOptions},
};

use super::core_dma_adapter::{
    ClaimRole, CoreDmaClaim, CoreDmaClaims, CoreDmaCohort, CoreReuseReservation,
    acknowledge_real_irq, apply_real_iotlb_closure, apply_real_reset_generation, bind_queue_commit,
    complete_real_irq, publish_real_queue,
};
use super::core_runtime::OstdCserRuntime;

const MAX_DEVICE_TURNS: usize = 16_384;
const MAX_IRQ_SPINS: usize = 20_000_000;

/// Development-only persistence backend for the QEMU hardware slice.
///
/// This value satisfies the portable transition protocol, so the slice takes
/// the same [`OstdCserRuntime`] path as a recovered production owner. Its bytes
/// are still volatile and have no independent trusted anchor; therefore they
/// are not reboot-persistence evidence.
struct VolatileDmaDurability {
    journal: Vec<u8>,
}

impl VolatileDmaDurability {
    const fn new() -> Self {
        Self {
            journal: Vec::new(),
        }
    }

    fn encoded_len(&self) -> usize {
        self.journal.len()
    }
}

impl TransitionDurability for VolatileDmaDurability {
    type Error = Infallible;

    fn persist_transition(
        &mut self,
        record: &JournalRecord,
        resulting_freshness: Freshness,
    ) -> Result<(), Self::Error> {
        assert!(!record.bytes().is_empty());
        assert_ne!(resulting_freshness.boot().get(), 0);
        self.journal.extend_from_slice(record.bytes());
        Ok(())
    }
}

type DmaRuntime = OstdCserRuntime<VolatileDmaDurability>;

fn new_dma_runtime() -> DmaRuntime {
    OstdCserRuntime::from_engine(
        Engine::new_legacy_compatibility(
            standard_catalog(),
            CoreLimits::bounded_default(),
            Freshness::new(
                nz::<BootGeneration>(1),
                nz::<RegistryInstance>(1),
                1,
                nz::<DeviceGeneration>(1),
                nz::<JournalGeneration>(1),
            )
            .expect("DMA runtime freshness is complete"),
        ),
        VolatileDmaDurability::new(),
    )
}

struct ServiceControl {
    entered: AtomicBool,
    stop: AtomicBool,
}

impl ServiceControl {
    const fn new() -> Self {
        Self {
            entered: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        }
    }
}

struct DmaServiceTask {
    incarnation: PrincipalIncarnation,
}

/// Single-request handoff between the real OSTD top half and manager task.
///
/// Task context only installs or extracts owners while PCI INTx is masked.
/// Consequently the top half's request lock cannot interrupt a task-context
/// holder on this CPU. The callback performs one ISR read/ack and publishes
/// only the opaque receipt.
struct IrqActorSlot {
    request: SpinLock<Option<PublishedRequest>>,
    receipt: SpinLock<Option<InterruptReceipt>>,
    ready: AtomicBool,
    deliveries: AtomicU32,
    duplicate_callbacks: AtomicU32,
}

impl IrqActorSlot {
    const fn new() -> Self {
        Self {
            request: SpinLock::new(None),
            receipt: SpinLock::new(None),
            ready: AtomicBool::new(false),
            deliveries: AtomicU32::new(0),
            duplicate_callbacks: AtomicU32::new(0),
        }
    }

    fn install_masked(&self, request: PublishedRequest) {
        assert!(!self.ready.load(Ordering::Acquire));
        assert!(self.receipt.lock().is_none());
        let mut slot = self.request.lock();
        assert!(slot.is_none());
        *slot = Some(request);
    }

    /// Hard-IRQ callback: exactly one device ISR read/ack, no allocation,
    /// logging, descriptor pop, core transition, or blocking task operation.
    fn acknowledge_top_half(&self) {
        if self.ready.load(Ordering::Acquire) {
            self.duplicate_callbacks.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let irq = {
            let mut slot = self.request.lock();
            let request = slot.as_mut().expect("armed IRQ retains a request");
            acknowledge_real_irq(request)
        };
        let mut receipt = self.receipt.lock();
        if receipt.is_some() {
            self.duplicate_callbacks.fetch_add(1, Ordering::Relaxed);
            return;
        }
        *receipt = Some(irq);
        self.deliveries.fetch_add(1, Ordering::Relaxed);
        self.ready.store(true, Ordering::Release);
    }

    fn take_remasked(&self) -> (PublishedRequest, InterruptReceipt) {
        assert!(self.ready.load(Ordering::Acquire));
        let request = self
            .request
            .lock()
            .take()
            .expect("remasked IRQ slot retains request");
        let receipt = self
            .receipt
            .lock()
            .take()
            .expect("remasked IRQ slot retains receipt");
        self.ready.store(false, Ordering::Release);
        (request, receipt)
    }
}

/// Runs the DMA slice inside a schedulable OSTD manager task.
pub(crate) fn launch() -> ! {
    let manager = Arc::new(
        TaskOptions::new(run_dma_recovery_slice)
            .build()
            .expect("CSER core DMA manager task builds"),
    );
    manager.run();
    Task::yield_now();
    unreachable!("the CSER core DMA manager powers the machine off")
}

// Queue-commit failures intentionally retain the complete non-clone hardware
// request and commit intent. Boxing after device publication would add a new
// allocation failure at exactly the wrong authority boundary.
#[allow(clippy::result_large_err)]
fn run_dma_recovery_slice() {
    let core = new_dma_runtime();
    let root_id = nz::<RootId>(0xd001);
    let effect1 = EffectId::new(root_id, 1).expect("first DMA effect is valid");
    let origin = principal(0xd001, 1);
    let successor1 = principal(0xd001, 2);
    let successor2 = principal(0xd001, 3);

    let (origin_task, origin_control) = spawn_service(origin, "origin");
    let mut root =
        discover_and_own_bars().expect("QEMU VirtIO block function must be discoverable");
    let bdf = root.device_bdf();
    let masked_intx = root
        .claim_masked_intx()
        .expect("fixed QEMU fixture exposes a claimable INTx route");
    let intx_route = masked_intx.route();
    let irq_slot = Arc::new(IrqActorSlot::new());
    let callback_slot = Arc::clone(&irq_slot);
    let mut irq_line = IrqLine::alloc().expect("OSTD allocates a dedicated VirtIO IRQ line");
    let irq_vector = irq_line.num();
    let irq_remapping_index = irq_line.remapping_index();
    irq_line.on_active(move |_| callback_slot.acknowledge_top_half());
    let mapped_irq = IRQ_CHIP
        .get()
        .expect("OSTD IRQ chip is initialized")
        .map_gsi_pin_to(irq_line, u32::from(intx_route.line()))
        .expect("firmware-programmed VirtIO GSI maps to the OSTD IRQ actor");
    let mut device =
        ProductionDevice::for_owned_device(&mut root).expect("owned root yields one device");

    let prepared = device
        .prepare_read_sector0_irq(&mut root)
        .expect("first real IRQ-mode request prepares");
    let receipted = device
        .issue_preparation_receipt(prepared)
        .unwrap_or_else(|_| panic!("first real preparation receipts"));
    assert_eq!(receipted.completion_mode(), CompletionMode::Interrupt);
    let first_identity = receipted.identity();
    let first_addresses = dma_addresses(first_identity.device_generation());
    let claims1 = dma_claims(0x100, 1);
    let cohort1 = CoreDmaCohort::bind(
        effect1,
        origin,
        1,
        nz::<ChargeAccountId>(0xd001),
        first_identity,
        claims1,
    )
    .expect("first real request binds to the portable core");

    enroll_new_effect(&core, cohort1);
    let intent1 = commit_intent(&core, cohort1, digest(0x11));
    let authority1 = core
        .observe(move |engine| bind_queue_commit(engine, intent1, cohort1))
        .unwrap_or_else(|_| panic!("first core commit challenge must bind before publication"));
    let published1 = publish_real_queue(&device, receipted, authority1)
        .unwrap_or_else(|_| panic!("first real queue publication must succeed"));
    let committed1 = core
        .observe(move |engine| published1.verify_commit(engine))
        .unwrap_or_else(|_| panic!("first real queue commit receipt must verify"));
    let (request1, acknowledgement1) = committed1.into_parts();
    tx(&core, acknowledgement1);
    assert_eq!(device.device_generation(), 1);

    println!(
        "CSER_CORE_DMA Commit generation=1 bdf={:02x}:{:02x}.{} queue={} descriptor={} \
         avail_idx_release=true notification_resolved=true real_virtio=true qemu=true",
        bdf.bus(),
        bdf.device(),
        bdf.function(),
        first_identity.queue(),
        first_identity.descriptor_token(),
    );

    stop_and_reap(&origin_task, &origin_control);
    tx(
        &core,
        CommandRequest::FenceIncarnation {
            root: root_id,
            crashed: origin,
            binding_generation: 1,
        },
    );
    assert_retained(&core, cohort1);

    let snapshot1 = core
        .observe(|engine| engine.snapshot_root(root_id, nz::<SnapshotId>(1)))
        .expect("first DMA post-mortem snapshot is available");
    assert_eq!(snapshot1.items().len(), 1);
    tx(&core, snapshot1.record());
    tx(
        &core,
        CommandRequest::Ready {
            root: root_id,
            snapshot: nz::<SnapshotId>(1),
            successor: successor1,
        },
    );
    tx(
        &core,
        CommandRequest::Rebind {
            root: root_id,
            snapshot: nz::<SnapshotId>(1),
            successor: successor1,
            binding_generation: 2,
        },
    );

    // A fresh successor dies before it can settle the physical tombstone.
    // The manager retains the real queue/DMA owners and fences the exact
    // rebound incarnation a second time.
    let (successor1_task, successor1_control) = spawn_service(successor1, "successor-v2");
    stop_and_reap(&successor1_task, &successor1_control);
    tx(
        &core,
        CommandRequest::FenceIncarnation {
            root: root_id,
            crashed: successor1,
            binding_generation: 2,
        },
    );
    assert_retained(&core, cohort1);
    let snapshot2 = core
        .observe(|engine| engine.snapshot_root(root_id, nz::<SnapshotId>(2)))
        .expect("second-crash DMA snapshot is available");
    assert_eq!(snapshot2.items().len(), 1);
    tx(&core, snapshot2.record());
    tx(
        &core,
        CommandRequest::Ready {
            root: root_id,
            snapshot: nz::<SnapshotId>(2),
            successor: successor2,
        },
    );
    tx(
        &core,
        CommandRequest::Rebind {
            root: root_id,
            snapshot: nz::<SnapshotId>(2),
            successor: successor2,
            binding_generation: 3,
        },
    );

    let (completed1, irq1, irq_turns1, masked_intx) =
        wait_for_real_irq_completion(&mut root, &irq_slot, masked_intx, request1);
    let first_close = close_real_generation(
        &core,
        &mut root,
        &mut device,
        cohort1,
        completed1,
        irq1,
        true,
    );
    assert!(first_close.reset_pending_observed);
    assert!(first_close.iotlb_pending_observed);
    assert_reusable(&core, cohort1);

    let effect2 = EffectId::new(root_id, 2).expect("second DMA effect is valid");
    tx(
        &core,
        CommandRequest::CreateEstate {
            effect: effect2,
            origin: successor2,
            binding_generation: 3,
            domain: cser_core::DEVICE_DOMAIN,
            obligation: cser_core::DEVICE_OBLIGATION_DMA,
            charge_account: nz::<ChargeAccountId>(0xd001),
        },
    );
    let claims2 = dma_claims(0x200, 2);
    for (role, claim) in [
        (ClaimRole::Queue, claims2_for(claims2, ClaimRole::Queue)),
        (
            ClaimRole::PinnedPages,
            claims2_for(claims2, ClaimRole::PinnedPages),
        ),
        (ClaimRole::Iova, claims2_for(claims2, ClaimRole::Iova)),
    ] {
        let permit = match output(
            &core,
            cohort1.reserve_reuse(CoreReuseReservation::new(
                role,
                effect2,
                successor2,
                3,
                claim.claim(),
                claim.units(),
                digest(0xda),
            )),
        ) {
            TransitionOutput::ReusePermit(permit) => permit,
            other => panic!("expected resource reuse permit, got {other:?}"),
        };
        assert_eq!(permit.generation(), nz::<ResourceGeneration>(2));
        tx(&core, permit.activate());
    }

    let (successor2_task, successor2_control) = spawn_service(successor2, "successor-v3");
    let prepared2 = device
        .prepare_read_sector0_irq(&mut root)
        .expect("second real IRQ-mode request prepares after IOTLB closure");
    let receipted2 = device
        .issue_preparation_receipt(prepared2)
        .unwrap_or_else(|_| panic!("second real preparation receipts"));
    let second_identity = receipted2.identity();
    assert_eq!(second_identity.device_generation(), 2);
    let second_addresses = dma_addresses(second_identity.device_generation());
    let cohort2 = CoreDmaCohort::bind(
        effect2,
        successor2,
        3,
        nz::<ChargeAccountId>(0xd001),
        second_identity,
        claims2,
    )
    .expect("second real request binds to reserved generations");
    tx(&core, cohort2.prepare());
    let intent2 = commit_intent(&core, cohort2, digest(0x22));
    let authority2 = core
        .observe(move |engine| bind_queue_commit(engine, intent2, cohort2))
        .unwrap_or_else(|_| panic!("second core commit challenge must bind before publication"));
    let published2 = publish_real_queue(&device, receipted2, authority2)
        .unwrap_or_else(|_| panic!("second real queue publication must succeed"));
    let committed2 = core
        .observe(move |engine| published2.verify_commit(engine))
        .unwrap_or_else(|_| panic!("second real queue commit receipt must verify"));
    let (request2, acknowledgement2) = committed2.into_parts();
    tx(&core, acknowledgement2);

    // The first generation's genuine ISR receipt is copyable evidence, not
    // authority. The facade rejects it against the fresh request before any
    // used-ring mutation and returns the exact second request owner.
    let stale_ack_projection = core.observe(Engine::projection_digest);
    let request2 = match complete_real_irq(request2, irq1) {
        InterruptCompletionProgress::NotReady {
            request,
            reason: InterruptNotReadyReason::WrongAttempt,
        } => request,
        InterruptCompletionProgress::NotReady { reason, .. } => {
            panic!("old ISR receipt rejected for unexpected reason: {reason:?}")
        }
        InterruptCompletionProgress::Complete(_) => {
            panic!("old-generation ISR receipt completed the new request")
        }
        InterruptCompletionProgress::Failed(_) => {
            panic!("old-generation ISR receipt mutated the new request")
        }
    };
    assert_eq!(
        core.observe(Engine::projection_digest),
        stale_ack_projection
    );

    let (completed2, irq2, irq_turns2, masked_intx) =
        wait_for_real_irq_completion(&mut root, &irq_slot, masked_intx, request2);
    stop_and_reap(&successor2_task, &successor2_control);
    tx(
        &core,
        CommandRequest::FenceIncarnation {
            root: root_id,
            crashed: successor2,
            binding_generation: 3,
        },
    );
    assert_retained(&core, cohort2);
    let second_close = close_real_generation(
        &core,
        &mut root,
        &mut device,
        cohort2,
        completed2,
        irq2,
        false,
    );
    assert!(!second_close.reset_pending_observed);
    assert!(!second_close.iotlb_pending_observed);
    assert_reusable(&core, cohort2);

    let address_reuse = first_addresses == second_addresses;
    let final_pressure = core.observe(Engine::pressure);
    assert_eq!(final_pressure.retained_claims, 0);
    assert!(!final_pressure.persistence_recovery_required);
    assert_eq!(device.device_generation(), 3);
    assert!(core.observe_persistence(VolatileDmaDurability::encoded_len) > 1_000);
    assert_eq!(intx_route.device_bdf(), bdf);
    assert_eq!(masked_intx.route(), intx_route);
    assert_eq!(irq_slot.deliveries.load(Ordering::Acquire), 2);
    assert_eq!(irq_slot.duplicate_callbacks.load(Ordering::Acquire), 0);
    drop(mapped_irq);

    println!(
        "CSER_CORE_DMA HardwareClosure PASS qemu=true physical_hardware=false real_pci=true \
         real_virtio=true avail_idx_release=true completion=true isr_status_read_ack=true \
         irq_controller_delivery=true hard_irq_actor=true intx_remap=true intx_remasked=true \
         irq_vector={} irq_remapping_index={:?} reset_status_zero=true \
         bus_master_disabled=true reset_generation=3 vt_d_iotlb_submit_poll_complete=true \
         iommu_software_typestate=false retained_dma_pages=3 core_resource_reuse=true \
         physical_address_reuse={} stale_old_irq_ack=rejected_without_mutation \
         first_irq_turns={} second_irq_turns={} reset_timeout_retry=true iotlb_pending_retry=true",
        irq_vector, irq_remapping_index, address_reuse, irq_turns1, irq_turns2,
    );
    println!(
        "CSER_CORE_DMA_OSTD_QEMU PASS death=real-task-reap fence=immediate-manager \
         second_crash=true post_mortem_owner=kernel-manager reply_registry=false \
         legacy_registry=false portal_glue=false live_dual_write=false \
         historical_profile=1 production_profile=false \
         journal=volatile-dev-only durable_provider=separate-suite qemu=true physical_hardware=false"
    );
    poweroff(ExitCode::Success);
}

fn tx<C: Into<Command>>(core: &DmaRuntime, command: C) -> TransitionReceipt {
    core.transact(command)
        .map_err(|error| match error {
            TxError::Core(error) => error,
            TxError::Journal(error) => CoreError::Journal(error),
            TxError::Persist(never) => match never {},
        })
        .expect("portable core transition must succeed")
}

fn output<C: Into<Command>>(core: &DmaRuntime, command: C) -> TransitionOutput {
    tx(core, command).into_output()
}

fn enroll_new_effect(core: &DmaRuntime, cohort: CoreDmaCohort) {
    tx(core, cohort.create_estate());
    for claim in cohort.enroll_claims() {
        tx(core, claim);
    }
    tx(core, cohort.prepare());
}

fn commit_intent(
    core: &DmaRuntime,
    cohort: CoreDmaCohort,
    operation: Digest,
) -> cser_core::CommitIntent {
    match output(core, cohort.record_commit_intent(operation)) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    }
}

fn spawn_service(
    incarnation: PrincipalIncarnation,
    label: &'static str,
) -> (Arc<Task>, Arc<ServiceControl>) {
    let control = Arc::new(ServiceControl::new());
    let task_control = Arc::clone(&control);
    let task = Arc::new(
        TaskOptions::new(move || {
            task_control.entered.store(true, Ordering::Release);
            while !task_control.stop.load(Ordering::Acquire) {
                Task::yield_now();
            }
            println!(
                "CSER_CORE_DMA ServiceExit label={} principal={} incarnation={} reason=task-return",
                label,
                incarnation.principal().get(),
                incarnation.generation(),
            );
        })
        .data(DmaServiceTask { incarnation })
        .build()
        .expect("DMA service task builds"),
    );
    task.run();
    while !control.entered.load(Ordering::Acquire) {
        Task::yield_now();
    }
    (task, control)
}

fn stop_and_reap(task: &Arc<Task>, control: &Arc<ServiceControl>) {
    let expected = task
        .data()
        .downcast_ref::<DmaServiceTask>()
        .expect("DMA service carries exact incarnation")
        .incarnation;
    control.stop.store(true, Ordering::Release);
    for _ in 0..MAX_DEVICE_TURNS {
        if task.is_reaped() {
            println!(
                "CSER_CORE_DMA ExactReap principal={} incarnation={} reaped=true",
                expected.principal().get(),
                expected.generation(),
            );
            return;
        }
        Task::yield_now();
    }
    panic!("DMA service did not reach exact reap");
}

fn wait_for_real_irq_completion(
    root: &mut Root,
    irq_slot: &IrqActorSlot,
    mut masked: MaskedIntx,
    mut request: PublishedRequest,
) -> (CompletedRequest, InterruptReceipt, usize, MaskedIntx) {
    for turn in 1..=MAX_DEVICE_TURNS {
        irq_slot.install_masked(request);
        let unmasked = root
            .unmask_intx(masked)
            .unwrap_or_else(|_| panic!("PCI INTx unmasks only after IRQ actor installation"));
        let mut spins = 0;
        while !irq_slot.ready.load(Ordering::Acquire) && spins < MAX_IRQ_SPINS {
            spins += 1;
            core::hint::spin_loop();
        }
        masked = root
            .mask_intx(unmasked)
            .unwrap_or_else(|_| panic!("PCI INTx remasks before task-context owner extraction"));
        assert!(
            irq_slot.ready.load(Ordering::Acquire),
            "real OSTD IRQ actor did not receive the bounded QEMU delivery"
        );
        let (returned, irq) = irq_slot.take_remasked();
        request = returned;
        match complete_real_irq(request, irq) {
            InterruptCompletionProgress::Complete(completed) => {
                return (completed, irq, turn, masked);
            }
            InterruptCompletionProgress::NotReady {
                request: retained, ..
            } => {
                request = retained;
                Task::yield_now();
            }
            InterruptCompletionProgress::Failed(_) => {
                panic!("real VirtIO completion validation failed")
            }
        }
    }
    panic!("real VirtIO IRQ-status completion exceeded bounded task turns");
}

struct CloseObservation {
    reset_pending_observed: bool,
    iotlb_pending_observed: bool,
}

// Reset/IOTLB failures intentionally return the complete linear hardware
// tombstone. Keep it inline rather than adding a fallible allocation after
// reset has begun.
#[allow(clippy::result_large_err)]
fn close_real_generation(
    core: &DmaRuntime,
    root: &mut Root,
    device: &mut ProductionDevice,
    cohort: CoreDmaCohort,
    completed: CompletedRequest,
    irq: InterruptReceipt,
    inject_pending: bool,
) -> CloseObservation {
    let reset_intent = completed
        .preflight_reset(cohort.hardware())
        .unwrap_or_else(|_| panic!("completed owner preflights exact reset"));
    let mut reset_tombstone = reset_intent.apply_reset(inject_pending);
    assert_eq!(reset_tombstone.retained_dma_pages(), 3);
    let mut reset_pending_observed = false;
    let mut reset_turns = 0;
    let reset = loop {
        reset_turns += 1;
        match reset_tombstone.probe_ack_once(root) {
            Ok(reset) => break reset,
            Err(failure) => {
                assert_eq!(failure.error(), ProductionResetRetryError::Pending);
                reset_pending_observed = true;
                reset_tombstone = failure.into_tombstone();
                assert!(
                    reset_turns < MAX_DEVICE_TURNS,
                    "real device reset exceeded the bounded retry budget"
                );
                Task::yield_now();
            }
        }
    };
    let reset = apply_real_reset_generation(device, reset, cohort)
        .unwrap_or_else(|_| panic!("real reset generation binds to core cohort"));
    for role in [ClaimRole::Queue, ClaimRole::PinnedPages, ClaimRole::Iova] {
        let command = core
            .observe(|engine| reset.reset_command(engine, cohort, role))
            .expect("real reset receipt verifies sequentially");
        tx(core, command);
    }
    let irq_command = core
        .observe(|engine| reset.irq_drained_command(engine, cohort, irq))
        .expect("exact real ISR receipt verifies queue drain");
    tx(core, irq_command);

    let progress = core
        .observe(|engine| reset.begin_iotlb(engine, device, cohort, inject_pending))
        .unwrap_or_else(|_| panic!("real IOTLB closure begins after durable reset/IRQ facts"));
    let (closure, iotlb_pending_observed) = match progress {
        ProductionClosureProgress::Complete(closure) => (closure, false),
        ProductionClosureProgress::Pending(tombstone) => {
            assert_eq!(tombstone.retained_pages(), 3);
            let closure = match tombstone
                .retry(MAX_DEVICE_TURNS)
                .unwrap_or_else(|_| panic!("non-zero IOTLB retry budget"))
            {
                ProductionClosureProgress::Complete(closure) => closure,
                ProductionClosureProgress::Pending(retained) => {
                    assert!(retained.failure_retained());
                    panic!("VT-d IOTLB invalidation retained a terminal failure")
                }
            };
            (closure, true)
        }
    };
    let closure = apply_real_iotlb_closure(device, closure, cohort)
        .unwrap_or_else(|_| panic!("real IOTLB closure binds to core cohort"));
    let retirement_commands = core
        .observe(|engine| closure.retirement_commands(engine, cohort))
        .expect("real IOTLB receipt verifies page and IOVA retirement");
    for command in retirement_commands {
        tx(core, command);
    }
    drop(closure.into_receipt());
    CloseObservation {
        reset_pending_observed,
        iotlb_pending_observed,
    }
}

fn assert_retained(core: &DmaRuntime, cohort: CoreDmaCohort) {
    core.observe(|engine| {
        let estate = engine
            .estate(cohort.effect())
            .expect("DMA estate remains present");
        assert_eq!(estate.retained_claims, 3);
        for role in [ClaimRole::Queue, ClaimRole::PinnedPages, ClaimRole::Iova] {
            let claim = cohort.claim(role);
            assert_eq!(
                engine.check_reusable(claim.resource(), claim.generation()),
                Err(CoreError::ResourceRetained)
            );
        }
    });
}

fn assert_reusable(core: &DmaRuntime, cohort: CoreDmaCohort) {
    core.observe(|engine| {
        let estate = engine
            .estate(cohort.effect())
            .expect("retired DMA estate remains inspectable");
        assert_eq!(estate.retained_claims, 0);
        for role in [ClaimRole::Queue, ClaimRole::PinnedPages, ClaimRole::Iova] {
            let claim = cohort.claim(role);
            assert_eq!(
                engine.check_reusable(claim.resource(), claim.generation()),
                Ok(())
            );
        }
    });
}

fn dma_claims(claim_base: u64, resource_generation: u64) -> CoreDmaClaims {
    CoreDmaClaims::new(
        CoreDmaClaim::new(
            nz::<ClaimId>(claim_base + 1),
            nz::<ResourceId>(0xd100_0001),
            nz::<ResourceGeneration>(resource_generation),
            1,
        ),
        CoreDmaClaim::new(
            nz::<ClaimId>(claim_base + 2),
            nz::<ResourceId>(0xd100_0002),
            nz::<ResourceGeneration>(resource_generation),
            3,
        ),
        CoreDmaClaim::new(
            nz::<ClaimId>(claim_base + 3),
            nz::<ResourceId>(0xd100_0003),
            nz::<ResourceGeneration>(resource_generation),
            3,
        ),
    )
}

fn claims2_for(claims: CoreDmaClaims, role: ClaimRole) -> CoreDmaClaim {
    claims.claim(role)
}

fn dma_addresses(generation: u64) -> [(usize, usize); 3] {
    [
        owner_address(generation, OwnerKind::QueueDriver),
        owner_address(generation, OwnerKind::QueueDevice),
        owner_address(generation, OwnerKind::Request),
    ]
}

fn principal(id: u64, incarnation: u64) -> PrincipalIncarnation {
    PrincipalIncarnation::new(nz::<PrincipalId>(id), incarnation)
        .expect("principal incarnation is valid")
}

fn digest(tag: u8) -> Digest {
    let mut bytes = [0; 32];
    bytes[0] = tag;
    Digest::new(bytes)
}

trait NonZeroId: Sized {
    fn from_nonzero(value: u64) -> Self;
}

macro_rules! impl_nonzero_id {
    ($($type:ty),+ $(,)?) => {
        $(
            impl NonZeroId for $type {
                fn from_nonzero(value: u64) -> Self {
                    <$type>::new(value).expect("identifier must be non-zero")
                }
            }
        )+
    };
}

impl_nonzero_id!(
    BootGeneration,
    ChargeAccountId,
    ClaimId,
    DeviceGeneration,
    JournalGeneration,
    PrincipalId,
    RegistryInstance,
    ResourceGeneration,
    ResourceId,
    RootId,
    SnapshotId,
);

fn nz<T: NonZeroId>(value: u64) -> T {
    T::from_nonzero(value)
}
