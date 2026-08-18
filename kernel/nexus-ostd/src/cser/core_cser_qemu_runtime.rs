// SPDX-License-Identifier: MPL-2.0

//! Concrete first-boot composition for the CSER tool-plus-DMA experiment.
//!
//! This module is intentionally narrow: it is the only place where the
//! catalog-parametric QEMU recovery envelope, the real VirtIO publication
//! facade, and the COM2/COM3 experiment transports meet.  It never treats a
//! UART reply as completion and it never re-arms a composite recovered from
//! ATA/TPM state.  A non-empty recovered projection is retained for the
//! recovery closer; until that closer accepts endpoint and quarantine
//! evidence, this module emits no terminal result.

use alloc::sync::Arc;
use core::fmt;
use cser_core::{
    CatalogSet, ChargeAccountId, ClaimId, CommandRequest, CoordinatedPersistence, CoreLimits,
    DEVICE_DOMAIN, DEVICE_EVIDENCE_IOTLB, DEVICE_EVIDENCE_IRQ_DRAINED, DEVICE_EVIDENCE_RESET,
    DeviceScopeId, Digest, EffectId, ExecutorCoordinate, ExecutorGeneration, ExecutorId,
    OperationId, RecoveryBinding, RecoveryProfile, RegistryInstance, ResourceGeneration,
    ResourceId, TOOL_DMA_COMPONENT_DMA, TOOL_DMA_COMPONENT_TOOL, TransitionDurability,
    TransitionOutput, WorldId, tool_dma_catalog,
};
use nexus_ostd_virtio::{
    CompletedRequest, InterruptCompletionProgress, InterruptReceipt, MaskedIntx,
    ProductionClosureProgress, ProductionDevice, ProductionResetRetryError, PublishedRequest, Root,
};
use ostd::{
    arch::irq::IRQ_CHIP,
    irq::IrqLine,
    power::{ExitCode, poweroff},
    prelude::println,
    sync::SpinLock,
    task::Task,
};

use super::{
    core_crash_probe::{
        CrashCutpoint, CrashProbe, CrashProbeError, CrashRunId, ExperimentIdentity,
    },
    core_cser_tool_experiment::{
        ToolDmaBarrier, ToolDmaBarrierHook, ToolDmaCoordinates, ToolDmaCoreOwner,
        ToolDmaResumeState, arm_tool_dma, dma_reuse_gate_observation, ensure_tool_dma_provider,
        resume_tool_dma, tool_dma_metrics, tool_dma_terminal,
    },
    core_device_quarantine::{
        OstdBootClaimVerifier, OstdBootIrqVerifier, QemuArenaIotlbVerifier,
        project_replayed_component_claim,
    },
    core_experiment_dma_flow::{CserResetLiveDma, prepare_live_irq, probe_reset_once},
    core_pio_journal::JournalIoPhase,
    core_qemu_persistent_boot::{
        PreparedQemuPersistentBoot, PreparedQemuPersistentBootVNext, QemuPersistentAnchor,
        QemuPersistentBoot, QemuPersistentBootVNext, persistent_dma_arena_digest,
    },
    core_runtime::OstdCserRuntime,
    core_tool_adapter::{
        DurableToolObservation, ToolEndpointObservation, ToolOperationPlan, ToolTransportError,
        UartToolEndpoint,
    },
    core_tool_dma_runtime::ToolDmaRuntime,
    core_tool_uart::{ToolRunId, ToolUart, ToolV2Identity},
};

#[cfg(not(feature = "cser-tool-dma-experiment-vnext"))]
use super::core_pio_journal::AtaPioJournal;
#[cfg(feature = "cser-tool-dma-experiment-vnext")]
use super::core_pio_journal::AtaPioJournalVNext;

const EFFECT_ROOT: u64 = 0x544f_4f4c;
const EFFECT_SEQUENCE: u64 = 1;
const CLAIM_TOOL: u64 = 0x5101;
const CLAIM_QUEUE: u64 = 0x5102;
const CLAIM_PAGES: u64 = 0x5103;
const CLAIM_IOVA: u64 = 0x5104;
const RESOURCE_TOOL: u64 = 0x6101;
const RESOURCE_QUEUE: u64 = 0x6102;
const RESOURCE_PAGES: u64 = 0x6103;
const RESOURCE_IOVA: u64 = 0x6104;
const MAX_DEVICE_TURNS: usize = 16_384;
const MAX_IRQ_SPINS: usize = 20_000_000;
/// Development-tunable number of same-identity GET observations attempted in
/// one boot after an accepted/pending endpoint response.  Exhaustion retains
/// the durable tool intent and physical claims; it is not a synthetic error
/// or authority to POST again.
const MAX_ENDPOINT_GET_POLLS: usize = 4;

// The vNext scheme deliberately selects its journal at compile time.  There is
// no runtime probe and no path from a legacy image into this type.
#[cfg(feature = "cser-tool-dma-experiment-vnext")]
type ExperimentPreparedBoot = PreparedQemuPersistentBootVNext;
#[cfg(not(feature = "cser-tool-dma-experiment-vnext"))]
type ExperimentPreparedBoot = PreparedQemuPersistentBoot;
#[cfg(feature = "cser-tool-dma-experiment-vnext")]
type ExperimentBoot = QemuPersistentBootVNext;
#[cfg(not(feature = "cser-tool-dma-experiment-vnext"))]
type ExperimentBoot = QemuPersistentBoot;

#[cfg(feature = "cser-tool-dma-experiment-vnext")]
type ExperimentJournal = AtaPioJournalVNext;
#[cfg(not(feature = "cser-tool-dma-experiment-vnext"))]
type ExperimentJournal = AtaPioJournal;
type ExperimentRuntime =
    OstdCserRuntime<CoordinatedPersistence<ExperimentJournal, QemuPersistentAnchor>>;

#[cfg(feature = "cser-tool-dma-experiment-vnext")]
type VNextRuntime = ExperimentRuntime;

#[cfg(feature = "cser-tool-dma-experiment-vnext")]
const EXPERIMENT_JOURNAL_FORMAT: &str = "vnext";
#[cfg(not(feature = "cser-tool-dma-experiment-vnext"))]
const EXPERIMENT_JOURNAL_FORMAT: &str = "legacy";

/// Emits bounded, non-authoritative provider and runtime diagnostics. This is
/// deliberately independent of terminal evidence and reuse receipts.
fn emit_perf(runtime: &ExperimentRuntime, phase: &'static str, run_id: [u8; 16]) {
    let serialization = runtime.serialization_metrics();
    let (journal, tpm) = runtime.observe_persistence(|persistence| {
        (
            persistence.journal().telemetry().unwrap_or_default(),
            persistence.anchor().telemetry(),
        )
    });
    println!(
        "TOOL_DMA_PERF_V2 {{\"version\":2,\"run_id\":\"{}\",\"phase\":\"{}\",\"clock\":\"guest_tsc\",\"calibrated\":false,\"journal_format\":\"{}\",\"journal_phase_scope\":\"last-complete-publication\",\"runtime_transactions\":{},\"mutex_wait_cycles\":{},\"mutex_max_wait_cycles\":{},\"mutex_hold_cycles\":{},\"mutex_max_hold_cycles\":{},\"checkpoints\":{},\"commit_gate_wait_cycles\":{},\"max_commit_gate_wait_cycles\":{},\"checkpoint_lock_wait_cycles\":{},\"max_checkpoint_lock_wait_cycles\":{},\"checkpoint_lock_hold_cycles\":{},\"max_checkpoint_lock_hold_cycles\":{},\"journal_sectors_read\":{},\"journal_sectors_written\":{},\"journal_flushes\":{},\"journal_hash_bytes\":{},\"journal_image_bytes\":{},\"journal_capacity_bytes\":{},\"journal_payload_written_tsc\":{},\"journal_payload_flushed_tsc\":{},\"journal_header_written_tsc\":{},\"journal_header_flushed_tsc\":{},\"journal_readback_validated_tsc\":{},\"journal_cache_updated_tsc\":{},\"tpm_lease_advances\":{},\"tpm_tip_advances\":{},\"tpm_lease_cycles\":{},\"tpm_tip_cycles\":{}}}",
        HexRun(run_id),
        phase,
        EXPERIMENT_JOURNAL_FORMAT,
        serialization.transactions,
        serialization.lock_wait_cycles,
        serialization.max_lock_wait_cycles,
        serialization.lock_hold_cycles,
        serialization.max_lock_hold_cycles,
        serialization.checkpoints,
        serialization.commit_gate_wait_cycles,
        serialization.max_commit_gate_wait_cycles,
        serialization.checkpoint_lock_wait_cycles,
        serialization.max_checkpoint_lock_wait_cycles,
        serialization.checkpoint_lock_hold_cycles,
        serialization.max_checkpoint_lock_hold_cycles,
        journal.counters.sectors_read,
        journal.counters.sectors_written,
        journal.counters.flushes,
        journal.counters.hash_bytes,
        journal.image_bytes,
        journal.capacity_bytes,
        journal.counters.phase_tsc[JournalIoPhase::PayloadWritten as usize],
        journal.counters.phase_tsc[JournalIoPhase::PayloadFlushed as usize],
        journal.counters.phase_tsc[JournalIoPhase::HeaderWritten as usize],
        journal.counters.phase_tsc[JournalIoPhase::HeaderFlushed as usize],
        journal.counters.phase_tsc[JournalIoPhase::ReadbackValidated as usize],
        journal.counters.phase_tsc[JournalIoPhase::CacheUpdated as usize],
        tpm.recovery_lease_advances,
        tpm.tip_compare_and_advances,
        tpm.recovery_lease_cycles,
        tpm.tip_compare_and_advance_cycles,
    );
}

/// Diagnostic receipt emitted only after a vNext checkpoint has been anchored
/// and its physical replay image has been replaced.  It is separate from the
/// experiment's terminal evidence receipt so it cannot upgrade a gate or
/// effect outcome by formatting accident.
#[cfg(feature = "cser-tool-dma-experiment-vnext")]
fn compact_vnext_terminal(runtime: &VNextRuntime, phase: &'static str, run_id: [u8; 16]) {
    let (revision_before, head_before) =
        runtime.observe(|engine| (engine.revision(), engine.head()));
    let (checkpoint, (logical_before, io_before), (logical_after, io_after)) = runtime
        .compact_checkpoint_observed(|journal| {
            let telemetry = journal
                .telemetry()
                .expect("TOOL_DMA_FAIL stage=vnext-compaction-telemetry");
            (telemetry.image_bytes as usize, telemetry)
        })
        .unwrap_or_else(|error| panic!("TOOL_DMA_FAIL stage=vnext-compaction error={:?}", error));
    let (revision_after, head_after) = runtime.observe(|engine| (engine.revision(), engine.head()));
    assert_eq!(
        checkpoint.revision(),
        revision_after,
        "TOOL_DMA_FAIL stage=vnext-compaction-revision"
    );
    assert_eq!(
        checkpoint.head(),
        head_after,
        "TOOL_DMA_FAIL stage=vnext-compaction-head"
    );
    assert_eq!(
        revision_after,
        revision_before + 1,
        "TOOL_DMA_FAIL stage=vnext-compaction-revision-advance"
    );
    assert_ne!(
        head_after, head_before,
        "TOOL_DMA_FAIL stage=vnext-compaction-head-advance"
    );
    assert!(
        logical_after < logical_before,
        "TOOL_DMA_FAIL stage=vnext-compaction-size"
    );
    let sectors_read_delta = io_after
        .counters
        .sectors_read
        .checked_sub(io_before.counters.sectors_read)
        .expect("TOOL_DMA_FAIL stage=vnext-compaction-sector-read-counter");
    let sectors_written_delta = io_after
        .counters
        .sectors_written
        .checked_sub(io_before.counters.sectors_written)
        .expect("TOOL_DMA_FAIL stage=vnext-compaction-sector-write-counter");
    let flushes_delta = io_after
        .counters
        .flushes
        .checked_sub(io_before.counters.flushes)
        .expect("TOOL_DMA_FAIL stage=vnext-compaction-flush-counter");
    assert!(
        sectors_written_delta > 0,
        "TOOL_DMA_FAIL stage=vnext-compaction-sector-write-io"
    );
    assert!(
        flushes_delta > 0,
        "TOOL_DMA_FAIL stage=vnext-compaction-flush-io"
    );
    println!(
        "CSER_VNEXT_COMPACTION {{\"version\":1,\"run_id\":\"{}\",\"journal_format\":\"vnext\",\"phase\":\"{}\",\"revision_before\":{},\"head_before\":\"{}\",\"revision_after\":{},\"head_after\":\"{}\",\"logical_bytes_before\":{},\"logical_bytes_after\":{},\"sectors_read_delta\":{},\"sectors_written_delta\":{},\"flushes_delta\":{}}}",
        HexRun(run_id),
        phase,
        revision_before,
        HexDigest(head_before),
        revision_after,
        HexDigest(head_after),
        logical_before,
        logical_after,
        sectors_read_delta,
        sectors_written_delta,
        flushes_delta,
    );
}

/// Formats the fixed-width core digest without allocating a diagnostic
/// buffer.  The compaction receipt is deliberately separate from both the
/// gate and terminal-effect receipts.
#[cfg(feature = "cser-tool-dma-experiment-vnext")]
struct HexDigest(Digest);

#[cfg(feature = "cser-tool-dma-experiment-vnext")]
impl fmt::Display for HexDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.bytes() {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Runs exactly one fixed first-boot prefix.  Every marker follows a durable
/// transition or a real endpoint/device action.  The matrix may kill QEMU at
/// any marker; lack of a terminal marker is deliberately not success.
pub(crate) fn run() {
    let catalog = tool_dma_catalog();
    let experiment_identity = acquire_experiment_identity(catalog.digest());
    let catalogs = CatalogSet::new(core::slice::from_ref(&catalog))
        .expect("tool DMA catalog set is non-empty and canonical");
    let catalog_set_digest = catalogs.digest();
    let run_id = experiment_identity.run_id().bytes();
    let binding = RecoveryBinding::new(
        RecoveryProfile::current(),
        WorldId::new(1).expect("experiment world is non-zero"),
        catalog_set_digest,
        RegistryInstance::new(1).expect("non-zero experiment registry"),
    )
    .expect("valid experiment binding");
    let mut prepared = ExperimentPreparedBoot::acquire()
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=qemu-persistent-boot"));
    prepared.set_diagnostic_telemetry(true);
    let arena = prepared.arena();
    let boot = prepared
        .recover(catalogs, CoreLimits::bounded_default(), binding)
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=anchored-tool-catalog-recovery"));
    let effect = fixed_effect();

    let resume = resume_tool_dma(&boot, effect)
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=resume-projection"));
    match resume.state() {
        ToolDmaResumeState::Absent => run_initial(boot, effect, arena, run_id, experiment_identity),
        state => {
            if state == ToolDmaResumeState::Prepared {
                panic!("TOOL_DMA_FAIL stage=unsupported-prepublication-recovery");
            }
            let plan = fixed_tool_plan(effect, run_id, experiment_identity);
            assert!(
                resume.binds_tool_operation(plan.operation_digest()),
                "TOOL_DMA_FAIL stage=recovery-experiment-identity-mismatch"
            );
            let retry_after_checkpoint =
                resume.allows_tool_idempotent_retry(plan.operation_digest());
            run_recovery(boot, effect, arena, state, retry_after_checkpoint, plan)
        }
    }
}

/// Closes a replayed prefix while the original device remains under the boot
/// guard.  This path deliberately has no COM3 hook: the host has already
/// killed the first boot at its selected cut and only accepts the unique
/// terminal receipt from this successor.
fn run_recovery(
    mut boot: ExperimentBoot,
    effect: EffectId,
    arena: nexus_ostd_virtio::PersistentDmaArenaLayout,
    state: ToolDmaResumeState,
    retry_after_checkpoint: bool,
    plan: ToolOperationPlan,
) {
    // A successor always queries the independently durable endpoint record
    // before it claims any settlement authority. A retry POST is permitted
    // only when that GET says absent *and* the exact durable intent still
    // exists; it is the same idempotency key, never a fresh operation.
    let tool = ToolDmaRuntime::new(plan, 1).expect("fixed tool verifier epoch");
    let mut observation = match poll_same_tool_plan(tool) {
        Ok(EndpointPoll::Terminal(observation)) => Some(observation),
        Ok(EndpointPoll::Absent) => None,
        Ok(EndpointPoll::Deferred(progress)) => finish_deferred(plan.run_id(), state, progress),
        Err(error) => {
            panic!("TOOL_DMA_FAIL stage=recovery-endpoint-get state={state:?} error={error:?}")
        }
    };

    // Cut seven has already retired both component sets. GET remains a
    // consistency check on the endpoint record, but no fence or transition is
    // legal (nor necessary) once the replay projection is terminal.
    if state == ToolDmaResumeState::Terminal {
        assert!(
            observation.is_some(),
            "TOOL_DMA_FAIL stage=terminal-endpoint-record"
        );
        let metrics = tool_dma_metrics(&boot, effect);
        assert!(
            tool_dma_terminal(metrics),
            "TOOL_DMA_FAIL stage=terminal-projection"
        );
        let reusable = dma_reuse_gate_observation(&boot, effect, false);
        finish_recovery(boot, metrics, plan.run_id(), None, reusable);
    }

    // Consume an existing tool intent before fencing: fencing intentionally
    // converts it to an indeterminate committed fact. If GET was absent this
    // is the one narrow point at which its stable operation key may POST.
    if matches!(
        state,
        ToolDmaResumeState::OutstandingCommits { tool: true, dma: _ }
    ) {
        let resumed = resume_tool_dma(&boot, effect).expect("outstanding projection");
        let (intent, _) = resumed.into_outstanding_intents();
        let intent = intent.expect("tool intent retained in projection");
        let endpoint_observation = match observation {
            Some(value) => value,
            None => match post_same_tool_plan(tool) {
                Ok(EndpointPoll::Terminal(value)) => value,
                Ok(EndpointPoll::Deferred(progress)) => {
                    finish_deferred(plan.run_id(), state, progress)
                }
                Ok(EndpointPoll::Absent) => panic!("TOOL_DMA_FAIL stage=recovery-post-absent"),
                Err(error) => {
                    panic!("TOOL_DMA_FAIL stage=recovery-idempotent-post error={error:?}")
                }
            },
        };
        let command = boot
            .observe(|engine| tool.acknowledge_commit(engine, intent, &endpoint_observation))
            .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=recovery-tool-commit-verify"));
        expect_none(boot.recovery_transact(command), "recovery-tool-commit-ack");
        observation = Some(endpoint_observation);
    }
    if observation.is_none() && retry_after_checkpoint {
        observation = Some(match post_same_tool_plan(tool) {
            Ok(EndpointPoll::Terminal(value)) => value,
            Ok(EndpointPoll::Deferred(progress)) => finish_deferred(plan.run_id(), state, progress),
            Ok(EndpointPoll::Absent) => panic!("TOOL_DMA_FAIL stage=recovery-post-absent"),
            Err(error) => panic!("TOOL_DMA_FAIL stage=recovery-idempotent-post error={error:?}"),
        });
    }
    let successor = snapshot_ready_rebind(&mut boot, effect, state);
    let observation = observation
        .unwrap_or_else(|| panic!("TOOL_DMA_FAIL stage=recovery-endpoint-get state={state:?}"));
    // A fence turns the interrupted claim into a new reconciliation generation;
    // do not consume post-fence intents here, because none remain authoritative.
    if matches!(
        state,
        ToolDmaResumeState::OutstandingCommits { tool: false, .. }
    ) {
        panic!("TOOL_DMA_FAIL stage=missing-tool-intent");
    }
    // This is a real replayed live DMA coordinate, not a synthetic allocator
    // state.  The read-only gate must reject it before any reset/IRQ/IOTLB
    // evidence is consumed, preserving the exact journal revision and head.
    let retained_gate = dma_reuse_gate_observation(&boot, effect, true);
    reconcile_tool(&mut boot, effect, successor, tool, observation, || {});
    reconcile_boot_dma(&mut boot, effect, arena);

    let metrics = tool_dma_metrics(&boot, effect);
    assert!(
        tool_dma_terminal(metrics),
        "recovery left CSER claims retained"
    );
    let reusable = dma_reuse_gate_observation(&boot, effect, false);
    finish_recovery(boot, metrics, plan.run_id(), Some(retained_gate), reusable);
}

fn finish_recovery(
    boot: ExperimentBoot,
    metrics: super::core_cser_tool_experiment::ToolDmaMetrics,
    run_id: [u8; 16],
    retained_gate: Option<super::core_cser_tool_experiment::DmaReuseGateObservation>,
    reusable_gate: super::core_cser_tool_experiment::DmaReuseGateObservation,
) -> ! {
    let activated = boot
        .try_activate()
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=recovery-activation"));
    // Activation is the final gate observation: printing before it would turn
    // a merely replayed terminal projection into a false reuse claim.  The
    // fresh vNext path additionally compacts this terminal state before its
    // standalone diagnostic receipt; legacy media remains append-only.
    let (engine, persistence, _devices) = activated.into_parts();
    let runtime = OstdCserRuntime::from_engine(engine, persistence);
    runtime.set_serialization_timing(true);
    #[cfg(feature = "cser-tool-dma-experiment-vnext")]
    compact_vnext_terminal(&runtime, "recovery", run_id);
    emit_perf(&runtime, "terminal-recovery", run_id);
    println!(
        "TOOL_DMA_RECOVERY_METRICS {{\"variant\":\"cser\",\"run_id\":\"{}\",\"terminal\":true,\"invariants_ok\":true,\"retired_by_evidence\":{},\"retained_claims\":{},\"gate_rejections\":null,\"reconciliation_delay_ms\":null,\"reconciliation_steps\":{},\"reconciliation_delay_unit\":\"unmeasured\",\"topology_registered\":true,\"tool_finalized\":true,\"dma_finalized\":true,\"reuse_authorized\":false,\"dma_retained_gate\":{},\"dma_reusable_gate\":{{\"resource_id_raw\":{},\"generation\":{},\"retained\":{},\"gate_result\":\"{}\",\"revision_unchanged\":{},\"head_unchanged\":{}}}}}",
        HexRun(run_id),
        metrics.retired_components,
        metrics.retained_claims,
        metrics.reconciliation_steps,
        retained_gate.map_or_else(
            || "null".into(),
            |gate| alloc::format!("{{\"resource_id_raw\":{},\"generation\":{},\"retained\":{},\"gate_result\":\"{}\",\"revision_unchanged\":{},\"head_unchanged\":{}}}", gate.resource_id_raw, gate.generation, gate.retained, gate.gate_result, gate.revision_unchanged, gate.head_unchanged),
        ),
        reusable_gate.resource_id_raw,
        reusable_gate.generation,
        reusable_gate.retained,
        reusable_gate.gate_result,
        reusable_gate.revision_unchanged,
        reusable_gate.head_unchanged,
    );
    poweroff(ExitCode::Success)
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

fn acquire_experiment_identity(expected_catalog: cser_core::Digest) -> ExperimentIdentity {
    let mut control = CrashProbe::acquire().expect("experiment owns COM3 configuration channel");
    let identity = control
        .experiment_identity()
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=experiment-identity"));
    assert!(
        identity.catalog_digest() == expected_catalog.bytes(),
        "TOOL_DMA_FAIL stage=experiment-catalog-binding"
    );
    identity
}

fn fixed_tool_plan(
    effect: EffectId,
    run_id: [u8; 16],
    identity: ExperimentIdentity,
) -> ToolOperationPlan {
    ToolOperationPlan::new(
        run_id,
        effect,
        TOOL_DMA_COMPONENT_TOOL,
        nz(CLAIM_TOOL),
        nz(RESOURCE_TOOL),
        nz(1),
        tool_dma_catalog().digest(),
        b"tool-dma-e2e",
    )
    .expect("fixed tool plan")
    .bind_cser2(
        ToolV2Identity::new(
            identity.namespace(),
            ToolRunId::new(identity.authority_id().bytes()),
            ToolRunId::new(identity.effect_id().bytes()),
            identity.catalog_digest(),
        )
        .expect("COM3 identity is valid CSER2 identity"),
    )
}

fn fixed_tool_runtime(
    effect: EffectId,
    run_id: [u8; 16],
    identity: ExperimentIdentity,
) -> ToolDmaRuntime {
    ToolDmaRuntime::new(fixed_tool_plan(effect, run_id, identity), 1)
        .expect("fixed tool verifier epoch")
}

enum EndpointPoll {
    Terminal(DurableToolObservation),
    Absent,
    Deferred(ToolEndpointObservation),
}

fn poll_same_tool_plan(tool: ToolDmaRuntime) -> Result<EndpointPoll, ToolTransportError> {
    let mut uart = ToolUart::acquire().expect("experiment owns COM2 for idempotent retry");
    let mut endpoint = UartToolEndpoint::new(&mut uart);
    for attempt in 0..MAX_ENDPOINT_GET_POLLS {
        match tool.recover(&mut endpoint)? {
            ToolEndpointObservation::Terminal(value) => return Ok(EndpointPoll::Terminal(value)),
            ToolEndpointObservation::Absent => return Ok(EndpointPoll::Absent),
            ToolEndpointObservation::Expired => {
                return Ok(EndpointPoll::Deferred(ToolEndpointObservation::Expired));
            }
            progress @ ToolEndpointObservation::Nonterminal(_)
                if attempt + 1 == MAX_ENDPOINT_GET_POLLS =>
            {
                return Ok(EndpointPoll::Deferred(progress));
            }
            ToolEndpointObservation::Nonterminal(_) => Task::yield_now(),
        }
    }
    unreachable!("bounded endpoint poll always returns")
}

/// POST is reachable only from a checksum-bound GET/404 absence.  A valid
/// Accepted/Pending POST response is followed by bounded GET polling; it is
/// never treated as a failed POST or authority for a second POST.
fn post_same_tool_plan(tool: ToolDmaRuntime) -> Result<EndpointPoll, ToolTransportError> {
    let mut uart = ToolUart::acquire().expect("experiment owns COM2 for idempotent retry");
    let mut endpoint = UartToolEndpoint::new(&mut uart);
    match tool.submit(&mut endpoint)? {
        ToolEndpointObservation::Terminal(value) => Ok(EndpointPoll::Terminal(value)),
        ToolEndpointObservation::Nonterminal(progress) => {
            drop(endpoint);
            match poll_same_tool_plan(tool)? {
                EndpointPoll::Terminal(value) => Ok(EndpointPoll::Terminal(value)),
                EndpointPoll::Absent => Ok(EndpointPoll::Absent),
                EndpointPoll::Deferred(_) => Ok(EndpointPoll::Deferred(
                    ToolEndpointObservation::Nonterminal(progress),
                )),
            }
        }
        ToolEndpointObservation::Absent => Ok(EndpointPoll::Absent),
        ToolEndpointObservation::Expired => {
            Ok(EndpointPoll::Deferred(ToolEndpointObservation::Expired))
        }
    }
}

fn finish_deferred(
    run_id: [u8; 16],
    state: ToolDmaResumeState,
    progress: ToolEndpointObservation,
) -> ! {
    println!(
        "TOOL_DMA_DEFERRED {{\"variant\":\"cser\",\"run_id\":\"{}\",\"state\":\"{:?}\",\"endpoint\":\"{:?}\",\"terminal\":false,\"claims_retained\":true,\"post_authorized\":false}}",
        HexRun(run_id),
        state,
        progress,
    );
    poweroff(ExitCode::Success)
}

fn reconcile_tool<O: ToolDmaCoreOwner>(
    runtime: &mut O,
    effect: EffectId,
    claimant: ExecutorCoordinate,
    tool: ToolDmaRuntime,
    observation: super::core_tool_adapter::DurableToolObservation,
    after_apply_intent: impl FnOnce(),
) {
    let receipt = runtime
        .transact(
            CommandRequest::ClaimComponentSettlement {
                effect,
                component: TOOL_DMA_COMPONENT_TOOL,
                claimant,
            }
            .into(),
        )
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=tool-settlement-claim"));
    let claim = match receipt.into_output() {
        TransitionOutput::SettlementClaim(claim) => claim,
        _ => panic!("TOOL_DMA_FAIL stage=tool-settlement-claim-output"),
    };
    let claim = match tool.record_reconciliation(claim) {
        Ok(command) => {
            let receipt = runtime
                .transact(command)
                .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=tool-apply-intent-durable"));
            match receipt.into_output() {
                TransitionOutput::SettlementClaim(claim) => claim,
                _ => panic!("TOOL_DMA_FAIL stage=tool-apply-intent-output"),
            }
        }
        Err(failure) if failure.error() == &cser_core::CoreError::WrongSettlementStage => {
            // Recovery checkpointing converts an interrupted durable apply
            // intent into ReconciliationRequired. The newly claimed linear
            // authority already names that stage; recording a second intent
            // is forbidden, but the claim can verify the same endpoint fact.
            failure.into_claim()
        }
        Err(_) => panic!("TOOL_DMA_FAIL stage=tool-apply-intent"),
    };
    // This is the exact recovery cut: a crash here leaves a durable apply
    // intent but no fabricated outcome/retirement state.
    after_apply_intent();
    let command = runtime
        .observe(|engine| tool.record_reconciled(engine, claim, &observation))
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=tool-apply-verify"));
    let receipt = runtime
        .transact(command)
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=tool-applied-durable"));
    let claim = match receipt.into_output() {
        TransitionOutput::SettlementClaim(claim) => claim,
        _ => panic!("TOOL_DMA_FAIL stage=tool-applied-output"),
    };
    let command = runtime
        .observe(|engine| tool.settle(engine, claim, &observation))
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=tool-settle-verify"));
    expect_none(runtime.transact(command), "tool-settle-durable");
    let command = runtime
        .observe(|engine| tool.retire_outcome(engine, &observation))
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=tool-retirement-verify"));
    expect_none(runtime.transact(command), "tool-retirement-durable");
}

fn reconcile_boot_dma(
    boot: &mut ExperimentBoot,
    effect: EffectId,
    arena: nexus_ostd_virtio::PersistentDmaArenaLayout,
) {
    let layout_digest = persistent_dma_arena_digest(arena);
    let component = boot
        .observe(|engine| engine.component(effect, TOOL_DMA_COMPONENT_DMA))
        .expect("recovered DMA component");
    assert_eq!(component.commit_operation, Some(layout_digest));
    let claims = boot.observe(|engine| {
        engine
            .retained_component_claims()
            .into_iter()
            .filter(|claim| {
                claim.effect == effect
                    && claim.component == TOOL_DMA_COMPONENT_DMA
                    && claim.domain == DEVICE_DOMAIN
            })
            .collect::<alloc::vec::Vec<_>>()
    });
    for claim in claims {
        let receipts = boot
            .inspect_with_guard(|_, guard| project_replayed_component_claim(guard, claim))
            .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=boot-claim-projection"));
        let (reset, irq, iotlb) = receipts.into_parts();
        let reset_command = boot
            .observe(|engine| {
                engine.verify_component_retirement_evidence(
                    claim.effect,
                    claim.component,
                    claim.claim,
                    DEVICE_EVIDENCE_RESET,
                    &OstdBootClaimVerifier::new_component(claim),
                    &reset,
                )
            })
            .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=boot-reset-verify"))
            .submit();
        expect_none(boot.recovery_transact(reset_command), "boot-reset-durable");
        if claim.kind == cser_core::DEVICE_CLAIM_QUEUE_SLOT {
            let command = boot
                .observe(|engine| {
                    engine.verify_component_retirement_evidence(
                        claim.effect,
                        claim.component,
                        claim.claim,
                        DEVICE_EVIDENCE_IRQ_DRAINED,
                        &OstdBootIrqVerifier::new_component(claim),
                        &irq,
                    )
                })
                .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=boot-irq-verify"))
                .submit();
            expect_none(boot.recovery_transact(command), "boot-irq-durable");
        } else {
            let verifier = QemuArenaIotlbVerifier::new_component(
                claim,
                arena,
                layout_digest,
                component.commit_operation,
                true,
                true,
            );
            let command = boot
                .observe(|engine| {
                    engine.verify_component_retirement_evidence(
                        claim.effect,
                        claim.component,
                        claim.claim,
                        DEVICE_EVIDENCE_IOTLB,
                        &verifier,
                        &iotlb,
                    )
                })
                .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=boot-iotlb-verify"))
                .submit();
            expect_none(boot.recovery_transact(command), "boot-iotlb-durable");
        }
    }
}

fn expect_none<E>(
    result: Result<cser_core::TransitionReceipt, cser_core::TxError<E>>,
    stage: &str,
) {
    let receipt = result.unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage={stage}"));
    assert!(
        matches!(receipt.into_output(), TransitionOutput::None),
        "TOOL_DMA_FAIL stage={stage}-output"
    );
}

fn run_initial(
    mut boot: ExperimentBoot,
    effect: EffectId,
    arena: nexus_ostd_virtio::PersistentDmaArenaLayout,
    run_id: [u8; 16],
    experiment_identity: ExperimentIdentity,
) {
    ensure_tool_dma_provider(&mut boot)
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=provider-generation-registration"));
    let activated = boot
        .try_activate()
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=empty-boot-activation"));
    let (engine, persistence, devices) = activated.into_parts();
    let mut runtime = OstdCserRuntime::from_engine(engine, persistence);
    runtime.set_serialization_timing(true);
    let (root, masked_intx, device) = devices.into_parts();
    let mut live = LiveCserDma::new(root, masked_intx, device);
    let prepared = prepare_live_irq(&mut live.device, &mut live.root)
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=real-virtio-prepare"));
    let identity = prepared.identity();
    let coordinates = coordinates(effect, identity.device_bdf());
    let mut barriers = QemuBarriers::acquire(run_id);
    let mut deferred = DeferredBarriers;
    let tool_plan = fixed_tool_plan(effect, run_id, experiment_identity);
    let mut armed = arm_tool_dma(
        &mut runtime,
        coordinates,
        tool_plan,
        persistent_dma_arena_digest(arena),
        &mut deferred,
    )
    .unwrap_or_else(|error| panic!("TOOL_DMA_FAIL stage=durable-composite-arm error={error:?}"));

    let dma_intent = armed
        .take_dma_intent()
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=dma-intent"));
    let cohort = super::core_dma_adapter::CoreDmaCohort::bind_component(
        effect,
        TOOL_DMA_COMPONENT_DMA,
        fixed_actor(),
        nz::<ChargeAccountId>(0x7101),
        identity,
        super::core_dma_adapter::CoreDmaClaims::new(
            super::core_dma_adapter::CoreDmaClaim::new(
                nz(CLAIM_QUEUE),
                nz(RESOURCE_QUEUE),
                nz(1),
                1,
            ),
            super::core_dma_adapter::CoreDmaClaim::new(
                nz(CLAIM_PAGES),
                nz(RESOURCE_PAGES),
                nz(1),
                3,
            ),
            super::core_dma_adapter::CoreDmaClaim::new(nz(CLAIM_IOVA), nz(RESOURCE_IOVA), nz(1), 3),
        ),
    )
    .expect("real identity binds fixed tool-DMA cohort");
    let published = runtime
        .observe(|engine| prepared.publish_cser(engine, dma_intent, cohort, &live.device))
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=real-virtio-publish"));
    let committed = runtime
        .observe(|engine| published.verify_commit(engine))
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=real-dma-commit-verify"));
    let (request, dma_acknowledgement) = committed.into_parts();
    runtime
        .transact(dma_acknowledgement)
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=durable-dma-commit-ack"));
    let retained_gate = dma_reuse_gate_observation(&runtime, effect, true);
    // Both early cut numbers intentionally observe the same first prefix:
    // it already contains a real DMA publication plus its durable local ack,
    // so recovery never has to invent a lost queue owner.
    barriers
        .reached(ToolDmaBarrier::TopologyPrepared)
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=barrier-1"));
    barriers
        .reached(ToolDmaBarrier::CommitIntentsDurable)
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=barrier-2"));
    let initial = {
        let mut uart = ToolUart::acquire().expect("experiment owns COM2");
        let mut endpoint = UartToolEndpoint::new(&mut uart);
        armed
            .post_tool(&mut endpoint)
            .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=durable-tool-post"))
    };
    let observation = match initial {
        ToolEndpointObservation::Terminal(value) => value,
        ToolEndpointObservation::Nonterminal(progress) => {
            match poll_same_tool_plan(fixed_tool_runtime(effect, run_id, experiment_identity)) {
                Ok(EndpointPoll::Terminal(value)) => value,
                Ok(EndpointPoll::Deferred(_)) | Ok(EndpointPoll::Absent) => finish_deferred(
                    run_id,
                    ToolDmaResumeState::Absent,
                    ToolEndpointObservation::Nonterminal(progress),
                ),
                Err(error) => panic!("TOOL_DMA_FAIL stage=initial-endpoint-poll error={error:?}"),
            }
        }
        ToolEndpointObservation::Absent | ToolEndpointObservation::Expired => {
            panic!("TOOL_DMA_FAIL stage=initial-endpoint-invalid-state")
        }
    };
    // The performance lane kills this boot at barrier three. Emit its one
    // diagnostic receipt after the endpoint outcome is durable but before the
    // crash probe can terminate QEMU. This is deliberately not a terminal
    // effect receipt and precedes any vNext compaction.
    emit_perf(&runtime, "post-endpoint-precrash", run_id);
    barriers
        .reached(ToolDmaBarrier::ToolEndpointApplied)
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=barrier-3"));
    // Cutpoint four deliberately includes the local durable commit
    // acknowledgement.  A bare device-visible `avail.idx` has no replayable
    // publication receipt after QEMU is killed; advertising that earlier
    // window as a recoverable matrix cut would force recovery to invent one.
    barriers
        .reached(ToolDmaBarrier::DmaQueuePublished)
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=barrier-4"));
    armed
        .acknowledge_tool_commit(&mut runtime, &observation)
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=durable-tool-commit-ack"));
    barriers
        .reached(ToolDmaBarrier::ToolCommitAcknowledged)
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=barrier-5"));

    reconcile_tool(
        &mut runtime,
        effect,
        fixed_actor(),
        fixed_tool_runtime(effect, run_id, experiment_identity),
        observation,
        || {
            barriers
                .reached(ToolDmaBarrier::ToolApplyIntentDurable)
                .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=barrier-6"));
        },
    );
    live.close_real(&mut runtime, request, cohort);
    let metrics = tool_dma_metrics(&runtime, effect);
    assert!(
        tool_dma_terminal(metrics),
        "live closure left CSER claims retained"
    );
    barriers
        .reached(ToolDmaBarrier::ComponentsRetired)
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=barrier-7"));
    let reusable_gate = dma_reuse_gate_observation(&runtime, effect, false);
    #[cfg(feature = "cser-tool-dma-experiment-vnext")]
    compact_vnext_terminal(&runtime, "initial", run_id);
    emit_perf(&runtime, "terminal-initial", run_id);
    println!(
        "TOOL_DMA_RECOVERY_METRICS {{\"variant\":\"cser\",\"run_id\":\"{}\",\"terminal\":true,\"invariants_ok\":true,\"retired_by_evidence\":{},\"retained_claims\":{},\"gate_rejections\":null,\"reconciliation_delay_ms\":null,\"reconciliation_steps\":{},\"reconciliation_delay_unit\":\"unmeasured\",\"topology_registered\":true,\"tool_finalized\":true,\"dma_finalized\":true,\"reuse_authorized\":false,\"dma_retained_gate\":{{\"resource_id_raw\":{},\"generation\":{},\"retained\":{},\"gate_result\":\"{}\",\"revision_unchanged\":{},\"head_unchanged\":{}}},\"dma_reusable_gate\":{{\"resource_id_raw\":{},\"generation\":{},\"retained\":{},\"gate_result\":\"{}\",\"revision_unchanged\":{},\"head_unchanged\":{}}}}}",
        HexRun(run_id),
        metrics.retired_components,
        metrics.retained_claims,
        metrics.reconciliation_steps,
        retained_gate.resource_id_raw,
        retained_gate.generation,
        retained_gate.retained,
        retained_gate.gate_result,
        retained_gate.revision_unchanged,
        retained_gate.head_unchanged,
        reusable_gate.resource_id_raw,
        reusable_gate.generation,
        reusable_gate.retained,
        reusable_gate.gate_result,
        reusable_gate.revision_unchanged,
        reusable_gate.head_unchanged,
    );
    poweroff(ExitCode::Success)
}

/// The live half deliberately owns the IRQ receipt, the completed request and
/// the reset/IOTLB tombstones linearly.  The CSER commands below are therefore
/// derived from the same real VirtIO closure as the baseline, rather than from
/// a synthetic `quiescent=true` flag.
struct LiveCserDma {
    root: Root,
    masked: Option<MaskedIntx>,
    device: ProductionDevice,
    irq: Arc<LiveIrqActor>,
}

struct LiveIrqActor {
    state: SpinLock<LiveIrqState>,
}

struct LiveIrqState {
    request: Option<PublishedRequest>,
    receipt: Option<InterruptReceipt>,
}

impl LiveIrqActor {
    const fn new() -> Self {
        Self {
            state: SpinLock::new(LiveIrqState {
                request: None,
                receipt: None,
            }),
        }
    }

    fn install(&self, request: PublishedRequest) {
        let mut state = self.state.lock();
        assert!(state.request.is_none());
        assert!(state.receipt.is_none());
        state.request = Some(request);
    }

    fn acknowledge(&self) {
        let mut state = self.state.lock();
        if state.receipt.is_some() {
            return;
        }
        let receipt = state
            .request
            .as_mut()
            .expect("CSER IRQ actor owns published request")
            .ack_interrupt();
        state.receipt = Some(receipt);
    }

    fn ready(&self) -> bool {
        self.state.lock().receipt.is_some()
    }

    fn take(&self) -> (PublishedRequest, InterruptReceipt) {
        let mut state = self.state.lock();
        let request = state.request.take().expect("CSER IRQ request");
        let receipt = state.receipt.take().expect("CSER IRQ receipt");
        (request, receipt)
    }
}

impl LiveCserDma {
    fn new(root: Root, masked: MaskedIntx, device: ProductionDevice) -> Self {
        let route = masked.route();
        let irq = Arc::new(LiveIrqActor::new());
        let callback = Arc::clone(&irq);
        let mut line = IrqLine::alloc().expect("CSER allocates VirtIO IRQ line");
        line.on_active(move |_| callback.acknowledge());
        let mapped = IRQ_CHIP
            .get()
            .expect("OSTD IRQ chip initialized")
            .map_gsi_pin_to(line, u32::from(route.line()))
            .expect("CSER maps fixed VirtIO INTx route");
        core::mem::forget(mapped);
        Self {
            root,
            masked: Some(masked),
            device,
            irq,
        }
    }

    fn complete(&mut self, mut request: PublishedRequest) -> (CompletedRequest, InterruptReceipt) {
        for _ in 0..MAX_DEVICE_TURNS {
            self.irq.install(request);
            let masked = self.masked.take().expect("CSER INTx mask owner");
            let unmasked = self
                .root
                .unmask_intx(masked)
                .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=live-intx-unmask"));
            let mut spins = 0;
            while !self.irq.ready() && spins < MAX_IRQ_SPINS {
                spins += 1;
                core::hint::spin_loop();
            }
            let masked = self
                .root
                .mask_intx(unmasked)
                .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=live-intx-remask"));
            self.masked = Some(masked);
            assert!(self.irq.ready(), "CSER IRQ timeout");
            let (returned, receipt) = self.irq.take();
            match returned.complete_after_interrupt(receipt) {
                InterruptCompletionProgress::Complete(completed) => return (completed, receipt),
                InterruptCompletionProgress::NotReady {
                    request: retained, ..
                } => {
                    request = retained;
                    Task::yield_now();
                }
                InterruptCompletionProgress::Failed(_) => panic!("TOOL_DMA_FAIL stage=live-irq"),
            }
        }
        panic!("TOOL_DMA_FAIL stage=live-irq-turn-limit")
    }

    fn close_real<P: TransitionDurability>(
        &mut self,
        runtime: &mut OstdCserRuntime<P>,
        request: super::core_experiment_dma_flow::BaselineLiveDma,
        cohort: super::core_dma_adapter::CoreDmaCohort,
    ) {
        let (completed, irq) = self.complete(request.into_published_request());
        let identity = completed.identity();
        let intent = completed
            .preflight_reset(identity)
            .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=live-reset-preflight"));
        let mut tombstone = intent.apply_reset(false);
        let reset = loop {
            match probe_reset_once(tombstone, &mut self.root, irq) {
                Ok(reset) => break reset,
                Err(failure) if failure.error() == ProductionResetRetryError::Pending => {
                    tombstone = failure.into_tombstone();
                    Task::yield_now();
                }
                Err(_) => panic!("TOOL_DMA_FAIL stage=live-reset"),
            }
        };
        let reset = reset
            .bind_cser(&mut self.device, cohort)
            .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=live-reset-bind"));
        self.retire_real(runtime, reset, cohort);
    }

    fn retire_real<P: TransitionDurability>(
        &mut self,
        runtime: &mut OstdCserRuntime<P>,
        reset: CserResetLiveDma,
        cohort: super::core_dma_adapter::CoreDmaCohort,
    ) {
        for command in runtime
            .observe(|engine| reset.reset_commands(engine))
            .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=live-reset-verify"))
        {
            expect_none(runtime.transact(command), "live-reset-durable");
        }
        let command = runtime
            .observe(|engine| reset.irq_drain_command(engine))
            .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=live-irq-drain-verify"));
        expect_none(runtime.transact(command), "live-irq-drain-durable");
        let progress = runtime
            .observe(|engine| reset.begin_iotlb(engine, &self.device, false))
            .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=live-iotlb-begin"));
        let closure = match progress {
            ProductionClosureProgress::Complete(closure) => closure,
            ProductionClosureProgress::Pending(tombstone) => {
                match tombstone.retry(MAX_DEVICE_TURNS) {
                    Ok(ProductionClosureProgress::Complete(closure)) => closure,
                    _ => panic!("TOOL_DMA_FAIL stage=live-iotlb-retry"),
                }
            }
        };
        let iotlb = CserResetLiveDma::bind_iotlb(&mut self.device, closure, cohort)
            .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=live-iotlb-bind"));
        for command in runtime
            .observe(|engine| iotlb.retirement_commands(engine, cohort))
            .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=live-iotlb-verify"))
        {
            expect_none(runtime.transact(command), "live-iotlb-durable");
        }
    }
}

struct QemuBarriers {
    probe: CrashProbe,
    run_id: [u8; 16],
}

struct DeferredBarriers;

impl ToolDmaBarrierHook for DeferredBarriers {
    type Error = core::convert::Infallible;

    fn reached(&mut self, _barrier: ToolDmaBarrier) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl QemuBarriers {
    fn acquire(run_id: [u8; 16]) -> Self {
        Self {
            probe: CrashProbe::acquire().expect("experiment owns COM3"),
            run_id,
        }
    }
}

impl ToolDmaBarrierHook for QemuBarriers {
    type Error = CrashProbeError;

    fn reached(&mut self, barrier: ToolDmaBarrier) -> Result<(), Self::Error> {
        self.probe.barrier(
            CrashRunId::new(self.run_id),
            CrashCutpoint::new(barrier.wire_id()),
        )
    }
}

fn fixed_effect() -> EffectId {
    EffectId::new(
        OperationId::new(EFFECT_ROOT).expect("fixed operation"),
        EFFECT_SEQUENCE,
    )
    .expect("fixed effect")
}

fn fixed_actor() -> ExecutorCoordinate {
    ExecutorCoordinate::new(
        ExecutorId::new(EFFECT_ROOT).expect("fixed executor"),
        ExecutorGeneration::new(1).expect("fixed executor generation"),
    )
}

/// Re-establishes successor custody before a replayed settlement is claimed.
/// `CheckpointRecovery` already fenced every root before the boot owner was
/// returned, including conversion of interrupted commit/apply authority into
/// conservative indeterminate/reconciliation state. Repeating that fence here
/// would be a stale-executor transition.
fn snapshot_ready_rebind(
    boot: &mut ExperimentBoot,
    effect: EffectId,
    state: ToolDmaResumeState,
) -> ExecutorCoordinate {
    let operation = effect.operation();
    let successor = ExecutorCoordinate::new(
        ExecutorId::new(EFFECT_ROOT).expect("fixed recovery executor"),
        ExecutorGeneration::new(2).expect("fixed recovery successor"),
    );
    let snapshot = cser_core::SnapshotId::new(1).expect("fixed recovery snapshot");
    let command = boot
        .observe(|engine| engine.snapshot_operation(operation, snapshot))
        .unwrap_or_else(|_| panic!("TOOL_DMA_FAIL stage=recovery-snapshot-build"))
        .record();
    expect_none(boot.recovery_transact(command), "recovery-snapshot");
    expect_none(
        boot.recovery_transact(CommandRequest::Ready {
            operation,
            snapshot,
            successor,
        }),
        "recovery-ready",
    );
    expect_none(
        boot.recovery_transact(CommandRequest::Rebind {
            operation,
            snapshot,
            successor,
        }),
        "recovery-rebind",
    );
    if state == ToolDmaResumeState::Prepared {
        expect_none(
            boot.recovery_transact(CommandRequest::AdoptEffect { effect, successor }),
            "recovery-adopt-precommit",
        );
        expect_none(
            boot.recovery_transact(CommandRequest::RebaseCompositePrecommitClaims {
                effect,
                actor: successor,
            }),
            "recovery-rebase-precommit",
        );
    }
    successor
}

fn coordinates(effect: EffectId, bdf: nexus_ostd_virtio::DeviceBdf) -> ToolDmaCoordinates {
    let packed =
        (u64::from(bdf.bus()) << 16) | (u64::from(bdf.device()) << 8) | u64::from(bdf.function());
    ToolDmaCoordinates::new(
        effect,
        fixed_actor(),
        nz::<ChargeAccountId>(0x7101),
        nz(CLAIM_TOOL),
        nz(RESOURCE_TOOL),
        nz(1),
        nz(CLAIM_QUEUE),
        nz(RESOURCE_QUEUE),
        nz(CLAIM_PAGES),
        nz(RESOURCE_PAGES),
        nz(CLAIM_IOVA),
        nz(RESOURCE_IOVA),
        DeviceScopeId::new(packed + 1).expect("PCI scope"),
        // This is the CSER allocation generation of three newly enrolled
        // resource coordinates, not the independently advancing hardware
        // session generation carried by `DeviceSessionIdentity` and evidence
        // freshness. Every first enrollment is generation one even when boot
        // quarantine has already advanced the emulated device to session two.
        ResourceGeneration::new(1).expect("initial resource generation"),
    )
    .expect("fixed coordinates")
}

trait NonZeroId: Sized {
    fn from_nonzero(value: u64) -> Self;
}

macro_rules! impl_nonzero_id {
    ($($type:ty),+ $(,)?) => {$(
        impl NonZeroId for $type {
            fn from_nonzero(value: u64) -> Self {
                <$type>::new(value).expect("fixed non-zero experiment id")
            }
        }
    )+};
}

impl_nonzero_id!(ChargeAccountId, ClaimId, ResourceGeneration, ResourceId,);

fn nz<T: NonZeroId>(value: u64) -> T {
    T::from_nonzero(value)
}
