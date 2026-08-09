// SPDX-License-Identifier: MPL-2.0

//! Real QEMU execution path for the reconstructed-finalizer baseline.
//!
//! This module is intentionally independent of the CSER `Engine`, catalog,
//! claims, and permits.  It does share the physical envelope: persistent DMA
//! arena installation, pre-replay VirtIO quarantine, ATA PIO, swtpm/TIS, the
//! COM2 endpoint bridge, COM3 crash barriers, and the actual VirtIO IRQ/reset/
//! IOTLB closure.  A successful line from this profile is therefore evidence
//! for this fixed baseline workload only, not a generic finalizer protocol.

use alloc::sync::Arc;
use core::fmt;

use cser_core::{DeviceGeneration, tool_dma_catalog};
use nexus_ostd_virtio::{
    CompletedRequest, InterruptCompletionProgress, InterruptReceipt, MaskedIntx,
    ProductionClosureProgress, ProductionDevice, ProductionResetRetryError, PublishedRequest, Root,
    install_persistent_dma_arena, qemu_hypervisor_detected,
};
use ostd::{
    arch::irq::IRQ_CHIP,
    irq::IrqLine,
    power::{ExitCode, poweroff},
    prelude::println,
    sync::SpinLock,
    task::Task,
};
use sha2::{Digest as _, Sha256};

use super::{
    core_baseline_experiment::{
        AtaTpmBaselineStore, BaselineCrashHook, BaselineCutpoint, BaselineDmaProvider,
        BaselineExperimentArm, QuarantinedBaselineDma, UartBaselineEndpoint,
    },
    core_baseline_runtime::{
        BaselineDmaReceipt, BaselineDmaReceiptVerifier, BaselineEffectId, BaselineError,
        BaselineFinalizer, BaselineOperationKey, BaselineRecord, BaselineResourceId,
        BaselineToolBinding, DmaFinalizer,
    },
    core_crash_probe::{
        CrashCutpoint, CrashProbe, CrashProbeError, CrashRunId, ExperimentIdentity,
    },
    core_device_quarantine::OstdVirtioBootQuarantine,
    core_dma_arena_allocator::{persistent_dma_arena_base, persistent_dma_arena_ready},
    core_experiment_dma_flow::{
        BaselineRawDmaEvidence, LiveBaselineCloseError, apply_baseline_iotlb, prepare_live_irq,
        probe_reset_once,
    },
    core_pio_journal::AtaJournalFixture,
    core_reboot::BootDeviceQuarantine,
    core_tool_uart::{OperationKey, ToolRunId, ToolUart, ToolV2Identity},
};

const EFFECT: u64 = 0x4241_5345_4c49_4e45;
const RESOURCE: u64 = 0xd100_0002;
const EXECUTOR: u64 = 0x4241_5345;
const GENERATION: u64 = 1;
const OPERATION: &[u8] = b"tool-dma-baseline";
const PAYLOAD: &[u8] = b"tool-dma-e2e";
const MAX_DEVICE_TURNS: usize = 16_384;
const MAX_IRQ_SPINS: usize = 20_000_000;

/// Runs once per QEMU boot.  The host either acknowledges each durable COM3
/// barrier or kills this VM; the next boot reconstructs only the independent
/// ATA/TPM baseline record and repeats no already durable external action.
pub(crate) fn run() {
    let experiment_identity = acquire_experiment_identity();
    let run_id = experiment_identity.run_id().bytes();
    let transport_identity = ToolV2Identity::new(
        experiment_identity.namespace(),
        ToolRunId::new(experiment_identity.authority_id().bytes()),
        ToolRunId::new(experiment_identity.effect_id().bytes()),
        experiment_identity.catalog_digest(),
    )
    .expect("baseline COM3 identity is valid CSER2 identity");
    let mut store = AtaTpmBaselineStore::acquire_qemu_fixture(AtaJournalFixture::PrimaryMaster)
        .expect("baseline ATA/TPM store opens before selecting a physical fence generation");
    let guard = acquire_common_quarantine(
        store
            .next_device_generation()
            .expect("baseline experiment tip selects nonzero next device generation"),
    );
    let expected_record = fixed_record(transport_identity, run_id);
    let has_record = store
        .has_record()
        .expect("baseline ATA record inspection succeeds");
    let mut arm = if has_record {
        BaselineExperimentArm::recover(store).expect("baseline record reconstructs")
    } else {
        BaselineExperimentArm::initialize_durable(store, expected_record)
            .expect("baseline topology is persisted before endpoint dispatch")
    };

    let record = arm
        .record()
        .expect("baseline runtime snapshots durable record");
    assert_eq!(
        record.tool_binding().request_identity_digest(),
        expected_record.tool_binding().request_identity_digest(),
        "TOOL_DMA_FAIL stage=recovery-experiment-identity-mismatch"
    );
    let mut uart = ToolUart::acquire().expect("baseline profile owns COM2");
    let operation = OperationKey::new(OPERATION).expect("fixed operation is valid");
    let mut endpoint = UartBaselineEndpoint::new_v2(
        &mut uart,
        transport_identity,
        ToolRunId::new(run_id),
        operation,
        PAYLOAD,
        record,
    );
    let mut dma = if record.dma_published() && !record.dma_finalized() {
        BaselineDmaExecution::Recovered(
            QuarantinedBaselineDma::from_quarantine(record, &guard)
                .expect("recovered DMA coordinate binds to common boot quarantine"),
        )
    } else {
        let activated = guard
            .try_activate()
            .unwrap_or_else(|_| panic!("baseline activates only completed quarantine"));
        let (root, masked, device) = activated.into_parts();
        BaselineDmaExecution::Live(LiveBaselineDma::new(root, masked, device, record))
    };
    let mut crash = QemuBaselineCrashHook {
        probe: CrashProbe::acquire().expect("baseline profile owns COM3"),
        enabled: !has_record,
        run_id,
    };

    let gate = arm
        .execute_resume(&mut endpoint, &mut dma, &mut crash)
        .unwrap_or_else(|_| panic!("baseline experiment retained a failed boundary"));
    let metrics = *arm.metrics();
    assert!(metrics.invariants_hold());
    // The host matrix accepts only this recovered-guest receipt. The run id
    // and full CSER2 request identity were checked against the durable record
    // before COM2 was acquired.
    println!(
        "TOOL_DMA_RECOVERY_METRICS {{\"variant\":\"baseline\",\"run_id\":\"{}\",\"terminal\":true,\"invariants_ok\":true,\"retired_by_evidence\":{},\"retained_claims\":{},\"gate_rejections\":null,\"reconciliation_delay_ms\":null,\"reconciliation_steps\":{},\"reconciliation_delay_unit\":\"unmeasured\",\"topology_registered\":{},\"tool_finalized\":{},\"dma_finalized\":{},\"reuse_authorized\":true,\"successor_generation\":{}}}",
        HexRun(run_id),
        metrics.retired_by_evidence,
        metrics.retained_claims,
        metrics.reconciliation_steps,
        metrics.topology_registered,
        metrics.tool_finalized,
        metrics.dma_finalized,
        gate.successor_generation(),
    );
    poweroff(ExitCode::Success)
}

fn acquire_common_quarantine(next_generation: u64) -> nexus_ostd_virtio::BootQuarantineGuard {
    assert!(
        persistent_dma_arena_ready(),
        "baseline DMA arena is withheld before replay"
    );
    let arena = install_persistent_dma_arena(persistent_dma_arena_base())
        .expect("baseline installs fixed DMA arena before device quarantine");
    assert!(
        arena.page_count() == 3
            && arena.paddr_base() == persistent_dma_arena_base()
            && qemu_hypervisor_detected(),
        "baseline runs only in the bounded QEMU DMA envelope"
    );
    let generation = DeviceGeneration::new(next_generation)
        .expect("baseline experiment TPM revision cannot select generation zero");
    match OstdVirtioBootQuarantine::new(generation).quarantine_all() {
        Ok(guard) => guard,
        Err(_) => panic!("baseline completes real pre-replay device quarantine"),
    }
}

fn fixed_record(transport_identity: ToolV2Identity, run_id: [u8; 16]) -> BaselineRecord {
    let effect = BaselineEffectId::new(EFFECT).expect("fixed effect is nonzero");
    let resource = BaselineResourceId::new(RESOURCE).expect("fixed resource is nonzero");
    let operation = BaselineOperationKey::from_operation_bytes(OPERATION)
        .expect("fixed operation has an independent baseline projection");
    let payload_digest: [u8; 32] = Sha256::digest(PAYLOAD).into();
    let request_identity_digest = transport_identity.request_binding_digest(
        ToolRunId::new(run_id),
        OPERATION,
        payload_digest,
    );
    BaselineRecord::register_with_tool_binding(
        effect,
        resource,
        EXECUTOR,
        GENERATION,
        BaselineToolBinding::unbound_endpoint(
            operation,
            super::core_baseline_runtime::BaselineDigest::new(payload_digest),
            super::core_baseline_runtime::BaselineDigest::new(request_identity_digest),
        ),
    )
    .expect("fixed baseline topology is valid")
}

struct QemuBaselineCrashHook {
    probe: CrashProbe,
    enabled: bool,
    run_id: [u8; 16],
}

impl BaselineCrashHook for QemuBaselineCrashHook {
    type Error = CrashProbeError;

    fn reached(&mut self, cutpoint: BaselineCutpoint) -> Result<(), Self::Error> {
        if !self.enabled {
            return Ok(());
        }
        self.probe.barrier(
            CrashRunId::new(self.run_id),
            CrashCutpoint::new(cutpoint.id()),
        )
    }
}

struct HexRun([u8; 16]);

impl fmt::Display for HexRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn acquire_experiment_identity() -> ExperimentIdentity {
    let mut control = CrashProbe::acquire().expect("baseline owns COM3 configuration channel");
    let identity = control
        .experiment_identity()
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=experiment-identity"));
    assert!(
        identity.catalog_digest() == tool_dma_catalog().digest().bytes(),
        "TOOL_DMA_FAIL stage=experiment-catalog-binding"
    );
    identity
}
/// One real IRQ handoff.  The IRQ callback only reads/acks VirtIO ISR state;
/// the manager remasks before extracting the owner and completing its used
/// ring in task context.
struct IrqActor {
    state: SpinLock<IrqActorState>,
}

struct IrqActorState {
    request: Option<PublishedRequest>,
    receipt: Option<InterruptReceipt>,
}

impl IrqActor {
    const fn new() -> Self {
        Self {
            state: SpinLock::new(IrqActorState {
                request: None,
                receipt: None,
            }),
        }
    }

    fn install_masked(&self, request: PublishedRequest) {
        let mut state = self.state.lock();
        assert!(state.request.is_none());
        assert!(state.receipt.is_none());
        state.request = Some(request);
    }

    fn acknowledge_top_half(&self) {
        let mut state = self.state.lock();
        if state.receipt.is_some() {
            return;
        }
        let receipt = state
            .request
            .as_mut()
            .expect("armed baseline IRQ owns the published request")
            .ack_interrupt();
        state.receipt = Some(receipt);
    }

    fn ready(&self) -> bool {
        self.state.lock().receipt.is_some()
    }

    fn take_remasked(&self) -> (PublishedRequest, InterruptReceipt) {
        let mut state = self.state.lock();
        let request = state
            .request
            .take()
            .expect("baseline IRQ actor retains request");
        let receipt = state
            .receipt
            .take()
            .expect("baseline IRQ actor retains receipt");
        (request, receipt)
    }
}

/// Baseline-local owner for an actual published VirtIO request.  It contains
/// no portable-core command/verifier authority.
struct LiveBaselineDma {
    root: Root,
    masked: Option<MaskedIntx>,
    device: ProductionDevice,
    irq: Arc<IrqActor>,
    published: Option<PublishedRequest>,
    completed: Option<(CompletedRequest, InterruptReceipt)>,
    record: BaselineRecord,
}

/// Fresh boots own a real published request; recovery boots retain the boot
/// quarantine and use it only to attest that an already-published predecessor
/// can no longer touch the coordinate.
enum BaselineDmaExecution {
    Live(LiveBaselineDma),
    Recovered(QuarantinedBaselineDma),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveBaselineDmaError {
    Prepare,
    Publish,
    Irq,
    Reset,
    Iotlb,
    Receipt,
}

impl LiveBaselineDma {
    fn new(
        root: Root,
        masked: MaskedIntx,
        device: ProductionDevice,
        record: BaselineRecord,
    ) -> Self {
        let route = masked.route();
        let irq = Arc::new(IrqActor::new());
        let callback = Arc::clone(&irq);
        let mut line = IrqLine::alloc().expect("baseline allocates one VirtIO IRQ line");
        line.on_active(move |_| callback.acknowledge_top_half());
        let mapped = IRQ_CHIP
            .get()
            .expect("OSTD IRQ chip is initialized")
            .map_gsi_pin_to(line, u32::from(route.line()))
            .expect("baseline maps its fixed VirtIO INTx route");
        // The experiment owns this map until QEMU powers off.  Keeping it
        // installed is required for the linear request's later completion;
        // there is no meaningful teardown after a host crash kill.
        core::mem::forget(mapped);
        Self {
            root,
            masked: Some(masked),
            device,
            irq,
            published: None,
            completed: None,
            record,
        }
    }

    fn complete_via_real_irq(&mut self) -> Result<(), LiveBaselineDmaError> {
        let mut request = self.published.take().ok_or(LiveBaselineDmaError::Receipt)?;
        for _ in 0..MAX_DEVICE_TURNS {
            self.irq.install_masked(request);
            let masked = self.masked.take().ok_or(LiveBaselineDmaError::Irq)?;
            let unmasked = self
                .root
                .unmask_intx(masked)
                .map_err(|_| LiveBaselineDmaError::Irq)?;
            let mut spins = 0;
            while !self.irq.ready() && spins < MAX_IRQ_SPINS {
                spins += 1;
                core::hint::spin_loop();
            }
            let masked = self
                .root
                .mask_intx(unmasked)
                .map_err(|_| LiveBaselineDmaError::Irq)?;
            self.masked = Some(masked);
            if !self.irq.ready() {
                return Err(LiveBaselineDmaError::Irq);
            }
            let (returned, receipt) = self.irq.take_remasked();
            match returned.complete_after_interrupt(receipt) {
                InterruptCompletionProgress::Complete(completed) => {
                    self.completed = Some((completed, receipt));
                    return Ok(());
                }
                InterruptCompletionProgress::NotReady {
                    request: retained, ..
                } => {
                    request = retained;
                    Task::yield_now();
                }
                InterruptCompletionProgress::Failed(_) => return Err(LiveBaselineDmaError::Irq),
            }
        }
        Err(LiveBaselineDmaError::Irq)
    }

    fn close_real_generation(
        &mut self,
        epoch: u64,
    ) -> Result<BaselineFinalizer, LiveBaselineDmaError> {
        let (completed, irq) = self.completed.take().ok_or(LiveBaselineDmaError::Receipt)?;
        let identity = completed.identity();
        let intent = completed
            .preflight_reset(identity)
            .map_err(|_| LiveBaselineDmaError::Reset)?;
        let mut tombstone = intent.apply_reset(false);
        let reset = loop {
            match probe_reset_once(tombstone, &mut self.root, irq) {
                Ok(reset) => break reset,
                Err(failure) => {
                    if failure.error() != ProductionResetRetryError::Pending {
                        return Err(LiveBaselineDmaError::Reset);
                    }
                    tombstone = failure.into_tombstone();
                    Task::yield_now();
                }
            }
        };
        let progress = reset
            .begin_baseline_iotlb(&mut self.device, false)
            .map_err(|error| match error {
                LiveBaselineCloseError::Generation(_) => LiveBaselineDmaError::Reset,
                LiveBaselineCloseError::Iotlb(_) => LiveBaselineDmaError::Iotlb,
            })?;
        let (closure, irq, successor) = progress.into_parts();
        let closure = match closure {
            ProductionClosureProgress::Complete(closure) => closure,
            ProductionClosureProgress::Pending(tombstone) => {
                match tombstone.retry(MAX_DEVICE_TURNS) {
                    Ok(ProductionClosureProgress::Complete(closure)) => closure,
                    _ => return Err(LiveBaselineDmaError::Iotlb),
                }
            }
        };
        let raw = apply_baseline_iotlb(
            &mut self.device,
            closure,
            irq,
            super::core_dma_adapter::ExperimentDmaResource::new(
                self.record.resource().get(),
                self.record.generation(),
            )
            .ok_or(LiveBaselineDmaError::Receipt)?,
            successor,
        )
        .map_err(|_| LiveBaselineDmaError::Iotlb)?;
        self.finalizer_from_raw(epoch, raw)
    }

    fn finalizer_from_raw(
        &self,
        epoch: u64,
        raw: BaselineRawDmaEvidence,
    ) -> Result<BaselineFinalizer, LiveBaselineDmaError> {
        let receipt = BaselineDmaReceipt::from_live_evidence(
            self.record.effect(),
            epoch,
            self.record.resource(),
            self.record.generation(),
            raw,
        )
        .map_err(|_| LiveBaselineDmaError::Receipt)?;
        let verifier = LiveReceiptVerifier {
            record: self.record,
            raw,
        };
        DmaFinalizer::from_receipt(&verifier, receipt)
            .map(BaselineFinalizer::Dma)
            .map_err(|_| LiveBaselineDmaError::Receipt)
    }
}

struct LiveReceiptVerifier {
    record: BaselineRecord,
    raw: BaselineRawDmaEvidence,
}

impl BaselineDmaReceiptVerifier for LiveReceiptVerifier {
    fn verify_dma_receipt(&self, receipt: &BaselineDmaReceipt) -> Result<(), BaselineError> {
        if receipt.resource() != self.record.resource()
            || receipt.generation() != self.record.generation()
            || receipt.epoch() == 0
            || self.raw.resource().resource() != self.record.resource().get()
            || self.raw.resource().generation() != self.record.generation()
            || self.raw.successor_generation() <= self.record.generation()
            || self.raw.completed_pages() != 3
            || !self.raw.irq().cause().includes_queue()
        {
            return Err(BaselineError::ReceiptRejected);
        }
        Ok(())
    }
}

impl BaselineDmaProvider for LiveBaselineDma {
    type Error = LiveBaselineDmaError;

    fn publish_dma_visible(&mut self) -> Result<(), Self::Error> {
        let prepared = prepare_live_irq(&mut self.device, &mut self.root)
            .map_err(|_| LiveBaselineDmaError::Prepare)?;
        let live = prepared
            .publish_baseline(&self.device)
            .map_err(|_| LiveBaselineDmaError::Publish)?;
        if self.published.is_some() || self.completed.is_some() {
            return Err(LiveBaselineDmaError::Publish);
        }
        self.published = Some(live.into_published_request());
        Ok(())
    }

    fn verified_dma_finalizer(&mut self, epoch: u64) -> Result<BaselineFinalizer, Self::Error> {
        self.complete_via_real_irq()?;
        self.close_real_generation(epoch)
    }
}

impl BaselineDmaProvider for BaselineDmaExecution {
    type Error = LiveBaselineDmaError;

    fn publish_dma_visible(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Live(live) => live.publish_dma_visible(),
            // Recovery construction requires the durable publication bit, so
            // this branch can only be reached for a malformed record.
            Self::Recovered(_) => Err(LiveBaselineDmaError::Receipt),
        }
    }

    fn verified_dma_finalizer(&mut self, epoch: u64) -> Result<BaselineFinalizer, Self::Error> {
        match self {
            Self::Live(live) => live.verified_dma_finalizer(epoch),
            Self::Recovered(recovered) => recovered
                .verified_finalizer(epoch)
                .map_err(|_| LiveBaselineDmaError::Receipt),
        }
    }
}
