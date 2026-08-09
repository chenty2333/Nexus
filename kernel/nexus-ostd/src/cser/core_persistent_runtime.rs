// SPDX-License-Identifier: MPL-2.0

//! Combined persistent CSER restart profile.
//!
//! Boot one creates one composite agent operation under one real service task,
//! commits its reply component through the dedicated ATA outbox, and publishes
//! its DMA component through one real VirtIO request. Boot two replays the exact
//! journal, TPM state, and fixed DMA arena under an unreleased quarantine
//! guard, retires all three generation-one DMA claims through reset/ISR/IOTLB
//! evidence, and crashes after durably recording the reply component's
//! external-apply intent. Boot three reconciles that intent without recording a
//! second one, settles the reply, and publishes a DMA-only generation-two reuse
//! witness at the exact same guest PFNs and emulated IOVAs. Boot four retires
//! that witness and proves the terminal projection is stable. The reuse proof is
//! deliberately QEMU-only: it identifies a guest PFN, emulated IOVA, and
//! memory-backend-file offset, never a host physical PFN or physical DMA drain.

use alloc::{
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::{
    fmt,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, AuthorityState,
    CSER_CORE_API_PROFILE_VERSION, ChargeAccountId, ClaimId, ClaimScope, Command, CommandRequest,
    CommitIntent, CommitState, ComponentClaimProjection, ComponentCommitOperation, ComponentId,
    ComponentProjection, CompositeEffectProjection, CoordinatedPersistence, CoreError, CoreLimits,
    CustodyState, DEVICE_CLAIM_IOVA, DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT,
    DEVICE_DOMAIN, DEVICE_EVIDENCE_IOTLB, DEVICE_EVIDENCE_IRQ_DRAINED, DEVICE_EVIDENCE_RESET,
    DEVICE_OBLIGATION_DMA, DMA_ARENA_REUSE_COMPOSITE, Digest, EffectEscapeState, EffectId, Engine,
    JOURNAL_SCHEMA_VERSION, OutcomeState, PROJECTION_VERSION, PrincipalId, PrincipalIncarnation,
    RECOVERY_SNAPSHOT_VERSION, REPLY_CLAIM_PUBLICATION_SLOT, REPLY_DOMAIN,
    REPLY_EVIDENCE_PUBLICATION_ACK, REPLY_OBLIGATION_PUBLICATION, RecoveryBinding,
    RegistryInstance, ResourceGeneration, ResourceId, RetirementState, ReusePermit, RootId,
    RootRecoveryState, STANDARD_CATALOG_VERSION, SettlementClaim, SettlementState, SnapshotId,
    TransitionDurability, TransitionOutput, TransitionReceipt, TxError, standard_catalog,
};
use nexus_ostd_virtio::{
    BootQuarantineGuard, MaskedIntx, OwnerKind, PersistentDmaArenaLayout, ProductionDevice,
    PublishedRequest, Root, persistent_dma_arena_layout, persistent_dma_arena_observation,
    qemu_hypervisor_detected,
};
use ostd::{
    mm::PAGE_SIZE,
    power::{ExitCode, poweroff},
    prelude::*,
    sync::{Mutex, SpinLock},
    task::{Task, TaskOptions, inject_post_task_exit_handler},
};

use super::{
    core_device_quarantine::{
        OstdBootClaimVerifier, OstdBootIrqVerifier, QemuArenaIotlbVerifier,
        project_replayed_component_claim,
    },
    core_dma_adapter::{
        ClaimRole, CoreDmaClaim, CoreDmaClaims, CoreDmaCohort, bind_queue_commit,
        publish_real_queue,
    },
    core_dma_arena_allocator::persistent_dma_arena_ready,
    core_pio_journal::AtaPioJournal,
    core_portal_vnext::{
        CorePortalVNext, CoreRegistry, CoreTransitionView, PortalDispatchError, PortalRequest,
        PortalResponseBody,
    },
    core_production_registry::{
        InstalledCore, ProductionCoreOwner, ProductionIngressError, ProductionIngressExitObserver,
        ProductionIngressIdentity, ProductionIngressTaskData, ProductionRegistryError,
    },
    core_qemu_persistent_boot::{
        PreparedQemuPersistentBoot, QemuPersistentAnchor, QemuPersistentBootError,
        is_legacy_schema5, persistent_dma_arena_digest,
    },
    core_reboot::{BootActivationBlock, BootActivationFailure, QuarantinedRecoveredBoot},
    core_reply_adapter::{
        ReplyAckError, ReplyCoordinate, ReplyCustody, ReplyPlan, reply_pair, reply_plan,
    },
    core_reply_outbox::{
        AtaPioReplyOutbox, ReplyAckRecord, ReplyApplyRecord, ReplyApplySource,
        ReplyCommitInspection, ReplyCommitReceipt, ReplyDeliveryInspection,
        ReplyDurableAckVerifier, ReplyDurableApplyVerifier, ReplyDurableRetirementVerifier,
        ReplyOutboxCommitVerifier, ReplyOutboxIdentity,
    },
    core_runtime::OstdCserRuntime,
    core_supervisor_vnext::{CORE_SUPERVISOR_PROTOCOL, CoreSupervisorVNext},
};

type PersistentAnchor = QemuPersistentAnchor;
type PersistentDurability = CoordinatedPersistence<AtaPioJournal, PersistentAnchor>;
type PersistentRuntime = OstdCserRuntime<PersistentDurability>;
type PersistentBoot =
    QuarantinedRecoveredBoot<AtaPioJournal, PersistentAnchor, BootQuarantineGuard>;
type ActiveProductionOwner = ProductionCoreOwner<PersistentRuntime>;
type QuarantinedProductionOwner = ProductionCoreOwner<QuarantinedPersistentCore>;
type ReplyClient = (
    Arc<Task>,
    ReplyCustody,
    Arc<OneShot<Result<u64, ReplyAckError>>>,
);

const REPLY_SEQUENCE: u64 = 1;
const REUSE_EFFECT_SEQUENCE: u64 = 2;
const REPLY_VALUE: u64 = 0xc5e2;
const MAX_TASK_TURNS: usize = 100_000;
const SERVICE_CREATED: u8 = 0;
const SERVICE_ENTERED: u8 = 1;
const SERVICE_READY: u8 = 2;
const SERVICE_REBOUND: u8 = 3;
const SERVICE_DOMAIN_COMPLETE: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeMetrics {
    revision: u64,
    boot_generation: u64,
    journal_generation: u64,
    device_generation: u64,
    retained: usize,
    catalog_digest: Digest,
    projection_digest: Digest,
}

struct HexDigest(Digest);

impl fmt::Display for HexDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.bytes() {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistentPhase {
    ArmSecondCrash,
    ReconcileSecondCrash,
    RecoverApplied,
    RetireDurableReply,
    StableRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionServiceStage {
    InitialCompositePublication,
    RebasePrecommit,
    ArmSecondCrash,
    ReconcileSecondCrash,
    StableRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProductionServiceIdentity {
    ingress: ProductionIngressIdentity,
    snapshot: Option<SnapshotId>,
    stage: ProductionServiceStage,
}

struct ProductionServiceControl {
    phase: AtomicU8,
    ingress_open: AtomicBool,
}

impl ProductionServiceControl {
    const fn new() -> Self {
        Self {
            phase: AtomicU8::new(SERVICE_CREATED),
            ingress_open: AtomicBool::new(false),
        }
    }

    fn advance(&self, from: u8, to: u8) -> Result<(), &'static str> {
        self.phase
            .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| "service-phase-order")
    }

    fn wait_for(&self, phase: u8) -> bool {
        for _ in 0..MAX_TASK_TURNS {
            if self.phase.load(Ordering::Acquire) >= phase {
                return true;
            }
            Task::yield_now();
        }
        false
    }

    fn close_ingress(&self) -> bool {
        self.ingress_open.swap(false, Ordering::AcqRel)
    }

    fn mark_ingress_open(&self) -> Result<(), &'static str> {
        self.ingress_open
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| "service-ingress-already-open")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProductionServiceExit {
    identity: ProductionServiceIdentity,
}

struct ProductionServiceExitInbox {
    slot: SpinLock<Option<ProductionServiceExit>>,
    rejected: AtomicBool,
}

impl ProductionServiceExitInbox {
    const fn new() -> Self {
        Self {
            slot: SpinLock::new(None),
            rejected: AtomicBool::new(false),
        }
    }

    fn publish(&self, observation: ProductionServiceExit) {
        let mut slot = self.slot.lock();
        if slot.is_some() {
            self.rejected.store(true, Ordering::Release);
            return;
        }
        *slot = Some(observation);
    }

    fn wait_take_bounded(&self) -> Option<ProductionServiceExit> {
        for _ in 0..MAX_TASK_TURNS {
            if let Some(observation) = self.slot.lock().take() {
                return Some(observation);
            }
            Task::yield_now();
        }
        None
    }
}

struct PersistentServiceExitObserver {
    identity: ProductionServiceIdentity,
    control: Weak<ProductionServiceControl>,
    inbox: Weak<ProductionServiceExitInbox>,
}

impl ProductionIngressExitObserver for PersistentServiceExitObserver {
    fn observe_exit(&self, identity: ProductionIngressIdentity, gate_closed: bool) {
        let Some(control) = self.control.upgrade() else {
            return;
        };
        let Some(inbox) = self.inbox.upgrade() else {
            return;
        };
        if identity != self.identity.ingress || !gate_closed || !control.close_ingress() {
            inbox.rejected.store(true, Ordering::Release);
            return;
        }
        inbox.publish(ProductionServiceExit {
            identity: self.identity,
        });
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionServiceDisposition {
    ExitAfterCompletion,
    RemainLive,
}

struct ProductionServiceRun {
    task: Arc<Task>,
    control: Arc<ProductionServiceControl>,
    exits: Arc<ProductionServiceExitInbox>,
    result: Arc<OneShot<Result<(), &'static str>>>,
    identity: ProductionServiceIdentity,
}

struct InitialCompositeOutput {
    outbox: AtaPioReplyOutbox,
    checksum: Digest,
    resumed_prefix: bool,
    root: Root,
    masked_intx: MaskedIntx,
    device: ProductionDevice,
    request: PublishedRequest,
}

struct InitialCompositeResources {
    outbox: AtaPioReplyOutbox,
    root: Root,
    masked_intx: MaskedIntx,
    device: ProductionDevice,
}

struct ReusePublicationOutput {
    root: Root,
    masked_intx: MaskedIntx,
    device: ProductionDevice,
    request: PublishedRequest,
}

struct ReuseActivationOutput {
    outbox: AtaPioReplyOutbox,
    publication: ReusePublicationOutput,
}

struct ArmSecondCrashOutput {
    outbox: AtaPioReplyOutbox,
    checksum: Digest,
    resumed_prefix: bool,
}

struct ArmedSecondCrash {
    service: ProductionServiceRun,
    outbox: AtaPioReplyOutbox,
    checksum: Digest,
    resumed_prefix: bool,
    successor: PrincipalIncarnation,
    binding_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
enum DurableReplyDelivery {
    Absent,
    Applied(ReplyApplyRecord),
    Acknowledged {
        apply: ReplyApplyRecord,
        acknowledgement: ReplyAckRecord,
    },
}

struct ProductionServiceIngress<S> {
    owner: Arc<ProductionCoreOwner<S>>,
    control: Arc<ProductionServiceControl>,
    identity: ProductionServiceIdentity,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DmaRecoveryReport {
    reset_submitted: usize,
    irq_submitted: usize,
    iotlb_submitted: usize,
    resource_reuse_authorized: bool,
}

struct OneShot<T> {
    slot: SpinLock<Option<T>>,
    published: AtomicBool,
}

impl<T> OneShot<T> {
    const fn new() -> Self {
        Self {
            slot: SpinLock::new(None),
            published: AtomicBool::new(false),
        }
    }

    fn publish(&self, value: T) {
        assert!(
            self.published
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "one-shot publication is unique"
        );
        *self.slot.lock() = Some(value);
    }

    fn wait_take_bounded(&self) -> Option<T> {
        for _ in 0..MAX_TASK_TURNS {
            if let Some(value) = self.slot.lock().take() {
                return Some(value);
            }
            Task::yield_now();
        }
        None
    }
}

/// Interior-mutable installation of one recovered core which still owns the
/// boot quarantine guard. No operation can extract or release that guard while
/// portal, supervisor, reply, or DMA ingress retains the production owner.
struct QuarantinedPersistentCore {
    boot: Mutex<Option<PersistentBoot>>,
}

impl QuarantinedPersistentCore {
    fn new(boot: PersistentBoot) -> Self {
        Self {
            boot: Mutex::new(Some(boot)),
        }
    }

    fn inspect_with_guard<R>(
        &self,
        operation: impl FnOnce(&Engine, &mut BootQuarantineGuard) -> R,
    ) -> R {
        self.boot
            .lock()
            .as_mut()
            .expect("quarantined production core is installed")
            .inspect_with_guard(operation)
    }

    fn activation_block(&self) -> Option<BootActivationBlock> {
        self.boot
            .lock()
            .as_ref()
            .expect("quarantined production core is installed")
            .activation_block()
    }

    fn into_boot(self) -> PersistentBoot {
        self.boot
            .lock()
            .take()
            .expect("quarantined production core is installed")
    }
}

impl InstalledCore for QuarantinedPersistentCore {
    type PersistenceError = <PersistentDurability as TransitionDurability>::Error;

    fn transact(
        &self,
        command: Command,
    ) -> Result<TransitionReceipt, TxError<Self::PersistenceError>> {
        self.boot
            .lock()
            .as_mut()
            .expect("quarantined production core is installed")
            .recovery_transact(command)
    }

    fn observe<R>(&self, operation: impl FnOnce(&Engine) -> R) -> R {
        self.boot
            .lock()
            .as_ref()
            .expect("quarantined production core is installed")
            .observe(operation)
    }
}

impl<S: InstalledCore + 'static> ProductionServiceIngress<S> {
    fn authorize_task(&self) -> Result<(), &'static str> {
        self.owner
            .authorize_current_task(self.identity.ingress)
            .map_err(|_| "service-task-binding")
    }

    fn authorize_ingress(&self) -> Result<(), &'static str> {
        if !self.control.ingress_open.load(Ordering::Acquire) {
            return Err("service-ingress-latch-closed");
        }
        let identity = self
            .owner
            .authorize_current_ingress()
            .map_err(|_| "service-production-ingress")?;
        if identity != self.identity.ingress {
            return Err("service-production-ingress-identity");
        }
        Ok(())
    }

    fn ready_and_wait_for_rebind(&self) -> Result<(), &'static str> {
        self.authorize_task()?;
        let snapshot = self.identity.snapshot.ok_or("service-snapshot-absent")?;
        let supervisor = CoreSupervisorVNext::new(Arc::clone(&self.owner));
        expect_no_output_checked(
            supervisor
                .ready(
                    self.identity.ingress.root(),
                    snapshot,
                    self.identity.ingress.incarnation(),
                )
                .map_err(|_| "service-ready")?,
        )?;
        self.control.advance(SERVICE_ENTERED, SERVICE_READY)?;
        if !self.control.wait_for(SERVICE_REBOUND) {
            return Err("service-rebind-timeout");
        }
        self.authorize_ingress()?;
        let rebound = self.owner.observe_engine(|engine| {
            engine.root(self.identity.ingress.root())
                == Some(RootRecoveryState::Rebound {
                    successor: self.identity.ingress.incarnation(),
                    binding_generation: self.identity.ingress.binding_generation(),
                })
        });
        if !rebound {
            return Err("service-rebind-observation");
        }
        Ok(())
    }

    fn observe<R>(&self, operation: impl FnOnce(&Engine) -> R) -> Result<R, &'static str> {
        self.authorize_ingress()?;
        Ok(self.owner.observe_engine(operation))
    }

    fn transact<C>(&self, command: C) -> Result<TransitionReceipt, &'static str>
    where
        C: Into<Command>,
    {
        self.authorize_ingress()?;
        owner_tx_checked(&self.owner, command)
    }

    fn claim_component_settlement(
        &self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<SettlementClaim, &'static str> {
        self.authorize_ingress()?;
        let supervisor = CoreSupervisorVNext::new(Arc::clone(&self.owner));
        settlement_claim_checked(
            supervisor
                .claim_component_settlement(effect, component, self.identity.ingress.incarnation())
                .map_err(|_| "service-settlement-claim")?,
        )
    }

    fn verify_component_observation(
        &self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), &'static str> {
        self.authorize_ingress()?;
        let observed = self.owner.observe_engine(|engine| {
            engine.component(effect, component).is_some()
                && engine.component_claims(effect, component).is_ok()
        });
        if observed {
            Ok(())
        } else {
            Err("service-component-observation")
        }
    }

    fn complete_initial_domain(&self) -> Result<(), &'static str> {
        self.authorize_ingress()?;
        self.control
            .advance(SERVICE_ENTERED, SERVICE_DOMAIN_COMPLETE)
    }

    fn complete_rebound_domain(&self) -> Result<(), &'static str> {
        self.authorize_ingress()?;
        self.control
            .advance(SERVICE_REBOUND, SERVICE_DOMAIN_COMPLETE)
    }
}

fn observe_persistent_task_exit(task: &Task) {
    if let Some(data) = task
        .data()
        .downcast_ref::<ProductionIngressTaskData<PersistentRuntime>>()
    {
        data.observe_exact_exit(task);
        return;
    }
    if let Some(data) = task
        .data()
        .downcast_ref::<ProductionIngressTaskData<QuarantinedPersistentCore>>()
    {
        data.observe_exact_exit(task);
    }
}

fn build_production_service<S, F>(
    owner: &Arc<ProductionCoreOwner<S>>,
    identity: ProductionServiceIdentity,
    entry: F,
) -> Result<ProductionServiceRun, &'static str>
where
    S: InstalledCore + 'static,
    F: FnOnce(ProductionServiceIngress<S>) -> Result<ProductionServiceDisposition, &'static str>
        + Send
        + 'static,
{
    let control = Arc::new(ProductionServiceControl::new());
    let exits = Arc::new(ProductionServiceExitInbox::new());
    let result = Arc::new(OneShot::new());
    let task_control = Arc::clone(&control);
    let task_result = Arc::clone(&result);
    let ingress = ProductionServiceIngress {
        owner: Arc::clone(owner),
        control: Arc::clone(&control),
        identity,
    };
    let exit_observer: Arc<dyn ProductionIngressExitObserver> =
        Arc::new(PersistentServiceExitObserver {
            identity,
            control: Arc::downgrade(&control),
            inbox: Arc::downgrade(&exits),
        });
    let task_data = ProductionIngressTaskData::new(owner, identity.ingress, exit_observer);
    let task = Arc::new(
        TaskOptions::new(move || {
            let entered = task_control.advance(SERVICE_CREATED, SERVICE_ENTERED);
            let outcome = entered.and_then(|()| entry(ingress));
            match outcome {
                Ok(ProductionServiceDisposition::ExitAfterCompletion) => {
                    task_result.publish(Ok(()));
                }
                Ok(ProductionServiceDisposition::RemainLive) => {
                    task_result.publish(Ok(()));
                    loop {
                        Task::yield_now();
                    }
                }
                Err(reason) => task_result.publish(Err(reason)),
            }
        })
        .data(task_data)
        .build()
        .map_err(|_| "production-service-task-build")?,
    );
    Ok(ProductionServiceRun {
        task,
        control,
        exits,
        result,
        identity,
    })
}

fn open_initial_service<S>(
    owner: &Arc<ProductionCoreOwner<S>>,
    run: &ProductionServiceRun,
) -> Result<(), &'static str> {
    owner
        .open_ingress(run.identity.ingress)
        .map_err(|_| "initial-service-ingress-open")?;
    run.control.mark_ingress_open()?;
    run.task.run();
    Ok(())
}

fn rebind_production_service<S>(
    owner: &Arc<ProductionCoreOwner<S>>,
    supervisor: &CoreSupervisorVNext<ProductionCoreOwner<S>>,
    run: &ProductionServiceRun,
) -> Result<(), &'static str>
where
    S: InstalledCore + 'static,
{
    let snapshot = run.identity.snapshot.ok_or("service-snapshot-absent")?;
    run.task.run();
    if !run.control.wait_for(SERVICE_READY) {
        return Err("service-ready-timeout");
    }
    let ready = owner.observe_engine(|engine| {
        engine.root(run.identity.ingress.root())
            == Some(RootRecoveryState::Ready {
                snapshot,
                successor: run.identity.ingress.incarnation(),
            })
    });
    if !ready {
        return Err("service-ready-observation");
    }
    expect_no_output_checked(
        supervisor
            .rebind(
                run.identity.ingress.root(),
                snapshot,
                run.identity.ingress.incarnation(),
                run.identity.ingress.binding_generation(),
            )
            .map_err(|_| "service-rebind")?,
    )?;
    owner
        .open_ingress(run.identity.ingress)
        .map_err(|_| "service-ingress-open-after-rebind")?;
    run.control.mark_ingress_open()?;
    run.control.advance(SERVICE_READY, SERVICE_REBOUND)
}

fn start_prepared_service<S>(
    owner: &Arc<ProductionCoreOwner<S>>,
    supervisor: &CoreSupervisorVNext<ProductionCoreOwner<S>>,
    run: &ProductionServiceRun,
) -> Result<(), &'static str>
where
    S: InstalledCore + 'static,
{
    if run.identity.snapshot.is_some() {
        rebind_production_service(owner, supervisor, run)
    } else {
        open_initial_service(owner, run)
    }
}

fn prepare_production_service<S>(
    owner: &ProductionCoreOwner<S>,
    supervisor: &CoreSupervisorVNext<ProductionCoreOwner<S>>,
    root: RootId,
    initial: PrincipalIncarnation,
    stage: ProductionServiceStage,
) -> Result<ProductionServiceIdentity, &'static str>
where
    S: InstalledCore + 'static,
{
    let state = owner.observe_engine(|engine| engine.root(root));
    let (incarnation, binding_generation, snapshot) = match state {
        None => (initial, 1, None),
        Some(RootRecoveryState::Active {
            incarnation,
            binding_generation,
        }) => (incarnation, binding_generation, None),
        Some(RootRecoveryState::Rebound {
            successor,
            binding_generation,
        }) => (successor, binding_generation, None),
        Some(RootRecoveryState::Fenced {
            crashed,
            binding_generation,
            ..
        }) => {
            let successor_generation = crashed
                .generation()
                .checked_add(1)
                .ok_or("successor-generation-exhausted")?;
            let successor = PrincipalIncarnation::new(crashed.principal(), successor_generation)
                .map_err(|_| "successor-generation")?;
            let next_binding = binding_generation
                .checked_add(1)
                .ok_or("binding-generation-exhausted")?;
            let snapshot_generation =
                owner.observe_engine(|engine| engine.freshness().boot().get());
            let snapshot =
                SnapshotId::new(snapshot_generation).map_err(|_| "snapshot-generation")?;
            expect_no_output_checked(
                supervisor
                    .snapshot_fenced(root, snapshot)
                    .map_err(|_| "root-snapshot")?,
            )?;
            (successor, next_binding, Some(snapshot))
        }
        Some(RootRecoveryState::Snapshotted { .. } | RootRecoveryState::Ready { .. }) => {
            return Err("partial-root-recovery-stage");
        }
        Some(RootRecoveryState::RecoveryExhausted { .. }) => {
            return Err("root-recovery-exhausted");
        }
    };
    let ingress = ProductionIngressIdentity::new(root, incarnation, binding_generation)
        .map_err(|_| "production-service-identity")?;
    Ok(ProductionServiceIdentity {
        ingress,
        snapshot,
        stage,
    })
}

fn wait_service_completion(run: &ProductionServiceRun) -> Result<(), &'static str> {
    run.result
        .wait_take_bounded()
        .ok_or("production-service-result-timeout")?
}

fn wait_exact_service_exit<S>(
    owner: &Arc<ProductionCoreOwner<S>>,
    run: &ProductionServiceRun,
) -> Result<(), &'static str>
where
    S: InstalledCore,
{
    let observation = run
        .exits
        .wait_take_bounded()
        .ok_or("production-service-exit-timeout")?;
    if observation.identity != run.identity
        || run.exits.rejected.load(Ordering::Acquire)
        || !run.task.is_reaped()
        || run.control.ingress_open.load(Ordering::Acquire)
        || owner.ingress_identity().is_some()
    {
        return Err("production-service-exit-mismatch");
    }
    ensure_exact_reap_fenced(owner, run.identity.ingress)?;
    Ok(())
}

fn wait_exact_service_exit_without_fence<S>(
    owner: &Arc<ProductionCoreOwner<S>>,
    run: &ProductionServiceRun,
) -> Result<(), &'static str>
where
    S: InstalledCore,
{
    let observation = run
        .exits
        .wait_take_bounded()
        .ok_or("production-service-exit-timeout")?;
    if observation.identity != run.identity
        || run.exits.rejected.load(Ordering::Acquire)
        || !run.task.is_reaped()
        || run.control.ingress_open.load(Ordering::Acquire)
        || owner.ingress_identity().is_some()
    {
        return Err("production-service-exit-mismatch");
    }
    Ok(())
}

fn ensure_exact_reap_fenced<S>(
    owner: &ProductionCoreOwner<S>,
    identity: ProductionIngressIdentity,
) -> Result<(), &'static str>
where
    S: InstalledCore,
{
    let root = identity.root();
    let crashed = identity.incarnation();
    let binding_generation = identity.binding_generation();
    match owner.observe_engine(|engine| engine.root(root)) {
        Some(
            RootRecoveryState::Active {
                incarnation,
                binding_generation: observed_binding,
            }
            | RootRecoveryState::Rebound {
                successor: incarnation,
                binding_generation: observed_binding,
            },
        ) if incarnation == crashed && observed_binding == binding_generation => {
            expect_no_output_checked(owner_tx_checked(
                owner,
                CommandRequest::FenceIncarnation {
                    root,
                    crashed,
                    binding_generation,
                },
            )?)?;
        }
        Some(RootRecoveryState::Fenced {
            crashed: observed,
            binding_generation: observed_binding,
            ..
        }) if observed == crashed && observed_binding == binding_generation => {}
        _ => return Err("exact-reap-root-state"),
    }
    if !matches!(
        owner.observe_engine(|engine| engine.root(root)),
        Some(RootRecoveryState::Fenced {
            crashed: observed,
            binding_generation: observed_binding,
            ..
        }) if observed == crashed && observed_binding == binding_generation
    ) {
        return Err("exact-reap-fence-postcondition");
    }
    Ok(())
}

fn verify_closed_portal_rejection<S>(
    owner: &Arc<ProductionCoreOwner<S>>,
    portal: &CorePortalVNext<ProductionCoreOwner<S>>,
    request_id: u64,
    command: CommandRequest,
) -> Result<(), &'static str>
where
    S: InstalledCore + 'static,
{
    let before = owner
        .observe_engine(|engine| (engine.revision(), engine.head(), engine.projection_digest()));
    let request =
        PortalRequest::transact(request_id, command).map_err(|_| "closed-portal-request")?;
    let rejected = portal.dispatch(request);
    if !matches!(
        rejected,
        Err(PortalDispatchError::Registry(
            ProductionRegistryError::Ingress(ProductionIngressError::Closed)
        ))
    ) {
        return Err("closed-portal-admitted-request");
    }
    let after = owner
        .observe_engine(|engine| (engine.revision(), engine.head(), engine.projection_digest()));
    if before != after || owner.ingress_identity().is_some() {
        return Err("closed-portal-mutated-core");
    }
    Ok(())
}

/// Enters the persistent profile from a normal schedulable manager context.
pub(crate) fn launch() -> ! {
    inject_post_task_exit_handler(observe_persistent_task_exit);
    let manager = Arc::new(
        TaskOptions::new(run_persistent_recovery)
            .build()
            .expect("persistent CSER manager task builds"),
    );
    manager.run();
    Task::yield_now();
    unreachable!("the persistent CSER manager powers the machine off")
}

fn run_persistent_recovery() {
    let catalog = standard_catalog();
    let binding = RecoveryBinding::new(
        catalog.digest(),
        RegistryInstance::new(1).expect("persistent Registry identity is non-zero"),
        1,
    )
    .expect("persistent recovery binding is valid");
    let mut prepared = match PreparedQemuPersistentBoot::acquire() {
        Ok(prepared) => prepared,
        Err(error) => fail_closed(qemu_boot_failure_reason(error), ()),
    };
    let selected_tip = prepared.candidate().committed();
    let selected_bytes = match prepared.journal_bytes() {
        Ok(bytes) => bytes,
        Err(error) => fail_closed(qemu_boot_failure_reason(error), prepared),
    };
    if is_legacy_schema5(&selected_bytes) {
        if selected_tip.revision() == 0 || selected_tip.head().is_zero() {
            fail_closed("unanchored-schema5-journal", prepared);
        }
        let quarantine = prepared.quarantine_observation();
        println!(
            "CSER_CORE_SCHEMA5_MIGRATION_REQUIRED PASS trusted_tpm_candidate_selected=true \
             profile2_binding_authorized=false \
             selected_revision={} selected_head={} selected_catalog={} expected_catalog={} \
             anchor_binding_match={} journal_schema=5 typed_error=migration-required \
             semantic_replay=false inferred_pairing=false pre_replay_quarantine=true \
             bus_master_disabled={} intx_masked={} reset_status_zero={} \
             observed_isr_bits={} isr_reads={} consecutive_empty_isr_reads={} \
             iotlb_used_remapped_iova={} iotlb_completed_trigger_pages={} \
             device_guard_retained=true production_registry=false device_activation=false \
             arena_withheld=true queue_republish=false page_iova_reuse=false \
             qemu=true physical_hardware=false",
            selected_tip.revision(),
            HexDigest(selected_tip.head()),
            HexDigest(selected_tip.binding().catalog_digest()),
            HexDigest(binding.catalog_digest()),
            selected_tip.binding() == binding,
            quarantine.bus_master_disabled(),
            quarantine.intx_masked(),
            quarantine.reset_status_zero(),
            quarantine.observed_isr_bits(),
            quarantine.isr_reads(),
            quarantine.consecutive_empty_isr_reads(),
            quarantine.iotlb_used_remapped_iova(),
            quarantine.iotlb_completed_trigger_pages(),
        );
        fail_closed("schema5-migration-required", prepared)
    }
    let boot = match prepared.recover(catalog, CoreLimits::bounded_default(), binding) {
        Ok(boot) => boot,
        Err(error) => fail_closed(qemu_boot_failure_reason(error), ()),
    };

    if boot.observe(|engine| engine.profile_one_estate_count() != 0) {
        fail_closed("profile1-state-selected-for-profile2-boot", boot);
    }

    let can_activate = boot.observe(|engine| {
        engine
            .retained_component_claims()
            .iter()
            .all(|claim| claim.domain != DEVICE_DOMAIN)
    });
    if can_activate {
        run_activation_boot(boot)
    } else {
        run_quarantined_boot(boot)
    }
}

/// Preserves the production profile's fail-closed categories while the shared
/// QEMU envelope keeps the device and durability acquisition reusable by the
/// experiment profiles.
const fn qemu_boot_failure_reason(error: QemuPersistentBootError) -> &'static str {
    match error {
        QemuPersistentBootError::ArenaNotWithheld => "dma-arena-not-withheld",
        QemuPersistentBootError::ArenaInstall => "dma-arena-install",
        QemuPersistentBootError::UnsupportedQemuProfile => "qemu-dma-arena-profile",
        QemuPersistentBootError::TpmTransport => "tpm2-transport-unavailable",
        QemuPersistentBootError::TpmAuth => "tpm2-index-auth-invalid",
        QemuPersistentBootError::TpmInspect => "tpm2-anchor-inspect",
        QemuPersistentBootError::DeviceGenerationOverflow => "device-generation-overflow",
        QemuPersistentBootError::DeviceGenerationInvalid => "device-generation-invalid",
        QemuPersistentBootError::DeviceQuarantine => "device-quarantine",
        QemuPersistentBootError::AtaJournalUnavailable => "ata-journal-unavailable",
        QemuPersistentBootError::AtaJournalRead => "ata-journal-read",
        QemuPersistentBootError::CatalogBindingMismatch => "recovery-catalog-binding",
        QemuPersistentBootError::AnchorBinding => "tpm2-anchor-binding",
        QemuPersistentBootError::Recovery => "anchored-replay",
    }
}

fn run_activation_boot(boot: PersistentBoot) -> ! {
    let activated = match boot.try_activate() {
        Ok(activated) => activated,
        Err(BootActivationFailure::Blocked { boot, .. }) => {
            fail_closed("activation-projection-changed", boot)
        }
        Err(BootActivationFailure::Provider { boot, .. }) => {
            fail_closed("device-activation-provider", boot)
        }
    };
    let (engine, persistence, devices) = activated.into_parts();
    let installed = PersistentRuntime::from_engine(engine, persistence);
    let owner = match ProductionCoreOwner::new(installed) {
        Ok(owner) => Arc::new(owner),
        Err(error) => fail_closed("profile2-production-install", (error, devices)),
    };
    let supervisor_owner = Arc::clone(&owner);
    let supervisor = CoreSupervisorVNext::new(supervisor_owner);
    if supervisor.protocol() != CORE_SUPERVISOR_PROTOCOL {
        fail_closed("supervisor-protocol", (owner, supervisor, devices));
    }

    let outbox = match AtaPioReplyOutbox::acquire_secondary_master() {
        Ok(outbox) => outbox,
        Err(_) => fail_closed("reply-outbox-open", (owner, supervisor, devices)),
    };
    let (root, masked_intx, device) = devices.into_parts();
    let initial_operation =
        owner.observe_engine(|engine| engine.composite_effect(operation_effect()).is_none());
    if !initial_operation {
        run_reuse_activation_boot(owner, supervisor, outbox, root, masked_intx, device)
    }
    let service_identity = match prepare_production_service(
        &owner,
        &supervisor,
        operation_root(),
        operation_origin(),
        ProductionServiceStage::InitialCompositePublication,
    ) {
        Ok(identity) => identity,
        Err(reason) => fail_closed(
            reason,
            (owner, supervisor, outbox, root, masked_intx, device),
        ),
    };
    let output = Arc::new(OneShot::new());
    let task_output = Arc::clone(&output);
    let service = match build_production_service(&owner, service_identity, move |ingress| {
        if ingress.identity.snapshot.is_some() {
            ingress.ready_and_wait_for_rebind()?;
        }
        let portal = CorePortalVNext::new(Arc::clone(&ingress.owner));
        let task_supervisor = CoreSupervisorVNext::new(Arc::clone(&ingress.owner));
        let output = publish_first_boot_operation(
            &portal,
            &task_supervisor,
            &ingress.owner,
            InitialCompositeResources {
                outbox,
                root,
                masked_intx,
                device,
            },
            ingress.identity.ingress,
        )?;
        if ingress.identity.snapshot.is_some() {
            ingress.complete_rebound_domain()?;
        } else {
            ingress.complete_initial_domain()?;
        }
        task_output.publish(output);
        Ok(ProductionServiceDisposition::ExitAfterCompletion)
    }) {
        Ok(run) => run,
        Err(reason) => fail_closed(reason, (owner, supervisor)),
    };
    if let Err(reason) = start_prepared_service(&owner, &supervisor, &service) {
        fail_closed(reason, (owner, supervisor, service));
    }
    if let Err(reason) = wait_service_completion(&service) {
        fail_closed(reason, (owner, supervisor, service));
    }
    let InitialCompositeOutput {
        outbox,
        checksum: reply_checksum,
        resumed_prefix,
        root,
        masked_intx,
        device,
        request,
    } = match output.wait_take_bounded() {
        Some(output) => output,
        None => fail_closed(
            "composite-service-output-timeout",
            (owner, supervisor, service),
        ),
    };
    if let Err(reason) = wait_exact_service_exit(&owner, &service) {
        fail_closed(
            reason,
            (
                owner,
                supervisor,
                outbox,
                root,
                masked_intx,
                device,
                request,
                service,
            ),
        );
    }
    let closed_portal = CorePortalVNext::new(Arc::clone(&owner));
    if let Err(reason) = verify_closed_portal_rejection(
        &owner,
        &closed_portal,
        0xc501_00ff,
        CommandRequest::PrepareCompositeEffect {
            effect: operation_effect(),
            actor: service_identity.ingress.incarnation(),
            binding_generation: service_identity.ingress.binding_generation(),
        },
    ) {
        fail_closed(
            reason,
            (
                owner,
                supervisor,
                outbox,
                root,
                masked_intx,
                device,
                request,
                service,
                closed_portal,
            ),
        );
    }
    if owner.pending_linear_outputs() != 0 {
        fail_closed(
            "linear-custody-not-empty",
            (
                owner,
                supervisor,
                outbox,
                root,
                masked_intx,
                device,
                request,
            ),
        );
    }
    let arena = match persistent_dma_arena_observation(device.device_generation()) {
        Some(observation) => observation.layout(),
        None => fail_closed(
            "boot1-dma-arena-observation",
            (
                owner,
                supervisor,
                outbox,
                root,
                masked_intx,
                device,
                request,
            ),
        ),
    };
    let RuntimeMetrics {
        revision,
        boot_generation,
        journal_generation,
        device_generation,
        retained,
        catalog_digest,
        projection_digest,
    } = runtime_metrics(&owner);
    let resource_generation = owner
        .observe_engine(|engine| exact_dma_resource_generation(engine, operation_effect(), false));
    let state_is_exact = owner.observe_engine(|engine| {
        validate_committed_reply_component(engine, reply_checksum)
            && validate_dma_component(engine)
            && validate_composite_identity(engine)
            && engine
                .retained_component_claims()
                .iter()
                .filter(|claim| claim.domain == DEVICE_DOMAIN)
                .count()
                == 3
    });
    if retained != 4
        || device.device_generation() != device_generation
        || resource_generation != Some(1)
        || !state_is_exact
    {
        fail_closed(
            "boot1-postcondition",
            (
                owner,
                supervisor,
                outbox,
                root,
                masked_intx,
                device,
                request,
            ),
        );
    }

    println!(
        "CSER_CORE_PERSISTENT_BOOT1 PASS shared_runtime=true production_registry=single \
         profile=2 composite_effect=true effect_identity=shared component_ids=reply+dma \
         api_profile={} catalog_version={} projection_version={} snapshot_version={} \
         journal_schema={} catalog_digest={} projection_digest={} \
         operation_effect_root={} operation_effect_sequence={} \
         reply_component_id={} dma_component_id={} arena_contract_digest={} \
         portal=nxp3 supervisor=core-v1 reply=committed-unsettled \
         dma=queue-published-retained retained={} dma_retained=3 resumed_prefix={} \
         resource_generation={} guest_pfn_base={} emulated_iova_base={} host_backing_offset={} \
         service_principal_generation={} binding_generation={} \
         production_service_tasks=1 service_death=task-return exact_reap=true \
         same_boot_fence=true ingress_latch=closed closed_ingress_rejected=true \
         production_rebind=initial \
         revision={} boot={} journal={} device={} \
         journal_provider=ata-pio outbox_provider=ata-pio-secondary anchor_provider=tpm2-nv \
         quarantine=pre-replay-virtio+global-iotlb qemu=true physical_antirollback=false \
         physical_powerloss=false physical_dma_custody=false",
        CSER_CORE_API_PROFILE_VERSION,
        STANDARD_CATALOG_VERSION,
        PROJECTION_VERSION,
        RECOVERY_SNAPSHOT_VERSION,
        JOURNAL_SCHEMA_VERSION,
        HexDigest(catalog_digest),
        HexDigest(projection_digest),
        operation_effect().root().get(),
        operation_effect().sequence(),
        AGENT_COMPONENT_REPLY.get(),
        AGENT_COMPONENT_DMA.get(),
        HexDigest(persistent_dma_arena_digest(arena)),
        retained,
        resumed_prefix,
        resource_generation.expect("boot1 generation was checked"),
        arena.paddr_base() / PAGE_SIZE,
        arena.daddr_base(),
        arena.qemu_backing_offset(OwnerKind::QueueDriver),
        service.identity.ingress.incarnation().generation(),
        service.identity.ingress.binding_generation(),
        revision,
        boot_generation,
        journal_generation,
        device_generation,
    );
    poweroff_retaining((
        owner,
        supervisor,
        outbox,
        root,
        masked_intx,
        device,
        request,
    ))
}

fn run_reuse_activation_boot(
    owner: Arc<ActiveProductionOwner>,
    supervisor: CoreSupervisorVNext<ActiveProductionOwner>,
    mut outbox: AtaPioReplyOutbox,
    root: Root,
    masked_intx: MaskedIntx,
    device: ProductionDevice,
) -> ! {
    let plan = match reply_plan(reply_coordinate(), REPLY_SEQUENCE, REPLY_VALUE) {
        Ok(plan) => plan,
        Err(_) => fail_closed(
            "reply-plan",
            (owner, supervisor, outbox, root, masked_intx, device),
        ),
    };
    let source = match inspect_reply_apply_source(&owner, &mut outbox, plan) {
        Ok(source) => source,
        Err(reason) => fail_closed(
            reason,
            (owner, supervisor, outbox, root, masked_intx, device),
        ),
    };
    let phase = match owner
        .observe_engine(|engine| classify_persistent_phase(engine, source.predecessor_digest()))
    {
        Ok(phase) => phase,
        Err(reason) => fail_closed(
            reason,
            (owner, supervisor, outbox, root, masked_intx, device),
        ),
    };
    let activation_prefix = owner.observe_engine(|engine| {
        matches!(
            phase,
            PersistentPhase::ReconcileSecondCrash
                | PersistentPhase::RecoverApplied
                | PersistentPhase::RetireDurableReply
                | PersistentPhase::StableRecovery
        ) && engine.composite_effect(reuse_effect()).is_none()
            && [
                dma_claims().claim(ClaimRole::Queue),
                dma_claims().claim(ClaimRole::PinnedPages),
                dma_claims().claim(ClaimRole::Iova),
            ]
            .into_iter()
            .all(|claim| engine.check_reusable(claim.resource(), claim.generation()) == Ok(()))
    });
    if !activation_prefix {
        fail_closed(
            "boot3-activation-prefix",
            (owner, supervisor, outbox, root, masked_intx, device),
        );
    }
    let delivery = match inspect_reply_delivery(&mut outbox, plan, source) {
        Ok(delivery) => delivery,
        Err(reason) => fail_closed(
            reason,
            (owner, supervisor, outbox, root, masked_intx, device),
        ),
    };
    let needs_receiver = match (phase, delivery) {
        (
            PersistentPhase::ReconcileSecondCrash,
            DurableReplyDelivery::Absent | DurableReplyDelivery::Applied(_),
        )
        | (PersistentPhase::RecoverApplied, DurableReplyDelivery::Applied(_)) => true,
        (
            PersistentPhase::RecoverApplied
            | PersistentPhase::RetireDurableReply
            | PersistentPhase::StableRecovery,
            DurableReplyDelivery::Acknowledged { .. },
        ) => false,
        (PersistentPhase::ArmSecondCrash, _)
        | (PersistentPhase::ReconcileSecondCrash, DurableReplyDelivery::Acknowledged { .. })
        | (PersistentPhase::RecoverApplied, DurableReplyDelivery::Absent)
        | (
            PersistentPhase::RetireDurableReply | PersistentPhase::StableRecovery,
            DurableReplyDelivery::Absent | DurableReplyDelivery::Applied(_),
        ) => fail_closed(
            "reply-delivery-prefix-mismatch",
            (owner, supervisor, outbox, root, masked_intx, device),
        ),
    };

    let identity = match prepare_production_service(
        &owner,
        &supervisor,
        operation_root(),
        operation_origin(),
        ProductionServiceStage::ReconcileSecondCrash,
    ) {
        Ok(identity) if identity.snapshot.is_some() => identity,
        Ok(_) => fail_closed(
            "reconciliation-service-not-fresh",
            (owner, supervisor, outbox, root, masked_intx, device),
        ),
        Err(reason) => fail_closed(
            reason,
            (owner, supervisor, outbox, root, masked_intx, device),
        ),
    };
    let successor = identity.ingress.incarnation();
    let binding_generation = identity.ingress.binding_generation();
    let (client, endpoint) = if needs_receiver {
        let (client, custody, result) = match spawn_reply_client(reply_coordinate()) {
            Ok(client) => client,
            Err(reason) => fail_closed(
                reason,
                (owner, supervisor, outbox, root, masked_intx, device),
            ),
        };
        if custody
            .plan(REPLY_SEQUENCE, REPLY_VALUE)
            .map_err(|_| "reply-custody-plan")
            != Ok(plan)
        {
            fail_closed(
                "reply-custody-plan-mismatch",
                (owner, supervisor, outbox, root, masked_intx, device, client),
            );
        }
        (Some(client), Some((custody, result)))
    } else {
        (None, None)
    };

    let output = Arc::new(OneShot::new());
    let task_output = Arc::clone(&output);
    let run = match build_production_service(&owner, identity, move |ingress| {
        ingress.ready_and_wait_for_rebind()?;
        let mut outbox = outbox;
        let endpoint = endpoint
            .as_ref()
            .map(|(custody, result)| (custody, result.as_ref()));
        reconcile_reply_in_service(&ingress, &mut outbox, endpoint, plan, source)?;
        let reused = publish_reused_dma(&ingress, root, masked_intx, device)?;
        ingress.complete_rebound_domain()?;
        task_output.publish(ReuseActivationOutput {
            outbox,
            publication: reused,
        });
        Ok(ProductionServiceDisposition::RemainLive)
    }) {
        Ok(run) => run,
        Err(reason) => fail_closed(reason, (owner, supervisor, client)),
    };
    if let Err(reason) = start_prepared_service(&owner, &supervisor, &run) {
        fail_closed(reason, (owner, supervisor, client, run));
    }
    if let Err(reason) = wait_service_completion(&run) {
        fail_closed(reason, (owner, supervisor, client, run));
    }
    let ReuseActivationOutput {
        outbox,
        publication:
            ReusePublicationOutput {
                root,
                masked_intx,
                device,
                request,
            },
    } = match output.wait_take_bounded() {
        Some(output) => output,
        None => fail_closed(
            "reuse-service-output-timeout",
            (owner, supervisor, client, run),
        ),
    };
    if let Some(client) = client.as_ref() {
        for _ in 0..MAX_TASK_TURNS {
            if client.is_reaped() {
                break;
            }
            Task::yield_now();
        }
    }
    if client.as_ref().is_some_and(|client| !client.is_reaped())
        || run.task.is_reaped()
        || !run.control.ingress_open.load(Ordering::Acquire)
        || owner.ingress_identity() != Some(identity.ingress)
        || run.exits.rejected.load(Ordering::Acquire)
        || owner.pending_linear_outputs() != 0
    {
        fail_closed(
            "reuse-service-not-live",
            (
                owner,
                supervisor,
                outbox,
                client,
                run,
                root,
                masked_intx,
                device,
                request,
            ),
        );
    }
    let arena = match persistent_dma_arena_observation(device.device_generation()) {
        Some(observation) => observation.layout(),
        None => fail_closed(
            "boot3-dma-arena-observation",
            (
                owner,
                supervisor,
                outbox,
                client,
                run,
                root,
                masked_intx,
                device,
                request,
            ),
        ),
    };
    let RuntimeMetrics {
        revision,
        boot_generation,
        journal_generation,
        device_generation,
        retained,
        catalog_digest,
        projection_digest,
    } = runtime_metrics(&owner);
    let (old_resource_generation, resource_generation, stale_old_generation_evidence) = owner
        .observe_engine(|engine| {
            let before = (engine.revision(), engine.projection_digest());
            let rejected = matches!(
                engine.component_evidence_challenge(
                    operation_effect(),
                    AGENT_COMPONENT_DMA,
                    dma_claims().claim(ClaimRole::Queue).claim(),
                    DEVICE_EVIDENCE_IRQ_DRAINED,
                ),
                Err(CoreError::DuplicateEvidence)
            );
            let after = (engine.revision(), engine.projection_digest());
            (
                exact_dma_resource_generation(engine, operation_effect(), true),
                exact_dma_resource_generation(engine, reuse_effect(), false),
                rejected && before == after,
            )
        });
    let exact = owner.observe_engine(|engine| {
        engine
            .component(operation_effect(), AGENT_COMPONENT_REPLY)
            .is_some_and(|component| {
                component.settlement == SettlementState::Settled
                    && component.retirement == RetirementState::Retired
                    && component.retained_claims == 0
            })
            && validate_dma_component(engine)
            && validate_dma_component_for(
                engine,
                reuse_effect(),
                reused_dma_claims(),
                DMA_ARENA_REUSE_COMPOSITE,
                1,
            )
            && engine
                .component(reuse_effect(), AGENT_COMPONENT_DMA)
                .is_some_and(|component| {
                    component.retirement == RetirementState::RetirementPending
                        && component.retained_claims == 3
                })
    });
    if retained != 3
        || old_resource_generation != Some(1)
        || resource_generation != Some(2)
        || !stale_old_generation_evidence
        || !exact
    {
        fail_closed(
            "boot3-postcondition",
            (
                owner,
                supervisor,
                outbox,
                client,
                run,
                root,
                masked_intx,
                device,
                request,
            ),
        );
    }

    println!(
        "CSER_CORE_PERSISTENT_BOOT3 PASS shared_runtime=true production_registry=single \
         api_profile={} catalog_version={} projection_version={} snapshot_version={} \
         journal_schema={} catalog_digest={} projection_digest={} \
         operation_effect_root={} operation_effect_sequence={} \
         reply_component_id={} dma_component_id={} reuse_effect_root={} \
         reuse_effect_sequence={} arena_contract_digest={} \
         portal=nxp3 supervisor=core-v1 reply=settled-after-second-crash \
         reconciliation=true second_apply_intent=false dma=reused-published \
         retained={} dma_retained=3 resource_generation={} prior_resource_generation={} \
         guest_pfn_base={} emulated_iova_base={} host_backing_offset={} \
         stale_old_generation_evidence=rejected_without_mutation \
         activation=active resource_reuse_authorized=true exact_guest_pfn_reuse=true \
         exact_emulated_iova_reuse=true exact_backing_offset_reuse=true \
         service_principal_generation={} successor_generation={} binding_generation={} \
         fresh_service_task=true ready_in_fresh_task=true production_rebind=true \
         service_state=live ingress_latch=open prior_service_fence=same-boot-exact-reap \
         revision={} boot={} journal={} device={} journal_provider=ata-pio \
         outbox_provider=ata-pio-secondary anchor_provider=tpm2-nv \
         quarantine=pre-replay-virtio+global-iotlb qemu=true physical_hardware=false \
         host_physical_pfn_identity=false physical_dma_drain=false \
         physical_antirollback=false physical_powerloss=false physical_dma_custody=false",
        CSER_CORE_API_PROFILE_VERSION,
        STANDARD_CATALOG_VERSION,
        PROJECTION_VERSION,
        RECOVERY_SNAPSHOT_VERSION,
        JOURNAL_SCHEMA_VERSION,
        HexDigest(catalog_digest),
        HexDigest(projection_digest),
        operation_effect().root().get(),
        operation_effect().sequence(),
        AGENT_COMPONENT_REPLY.get(),
        AGENT_COMPONENT_DMA.get(),
        reuse_effect().root().get(),
        reuse_effect().sequence(),
        HexDigest(persistent_dma_arena_digest(arena)),
        retained,
        resource_generation.expect("boot3 generation was checked"),
        old_resource_generation.expect("boot3 prior generation was checked"),
        arena.paddr_base() / PAGE_SIZE,
        arena.daddr_base(),
        arena.qemu_backing_offset(OwnerKind::QueueDriver),
        successor.generation(),
        successor.generation(),
        binding_generation,
        revision,
        boot_generation,
        journal_generation,
        device_generation,
    );
    poweroff_retaining((
        owner,
        supervisor,
        outbox,
        client,
        run,
        root,
        masked_intx,
        device,
        request,
    ))
}

#[allow(clippy::result_large_err)]
fn publish_reused_dma(
    ingress: &ProductionServiceIngress<PersistentRuntime>,
    mut root: Root,
    masked_intx: MaskedIntx,
    mut device: ProductionDevice,
) -> Result<ReusePublicationOutput, &'static str> {
    let actor = ingress.identity.ingress.incarnation();
    let binding_generation = ingress.identity.ingress.binding_generation();
    let old_claims = ingress
        .observe(|engine| engine.component_claims(operation_effect(), AGENT_COMPONENT_DMA))?
        .map_err(|_| "old-dma-claims-query")?;
    if !validate_dma_claims_for(&old_claims, operation_effect(), dma_claims())
        || old_claims.iter().any(|claim| !claim.retired)
    {
        return Err("old-dma-claims-not-retired");
    }
    let scope = old_claims
        .first()
        .map(|claim| claim.scope)
        .ok_or("old-dma-scope-absent")?;
    if old_claims.iter().any(|claim| claim.scope != scope) {
        return Err("old-dma-scope-mismatch");
    }
    let arena = persistent_dma_arena_layout().ok_or("dma-arena-layout-absent")?;
    let mut composite = ingress.observe(|engine| engine.composite_effect(reuse_effect()))?;
    if composite.is_none() {
        expect_no_output_checked(ingress.transact(CommandRequest::CreateCompositeEffect {
            effect: reuse_effect(),
            origin: actor,
            binding_generation,
            kind: DMA_ARENA_REUSE_COMPOSITE,
            charge_account: operation_charge_account(),
        })?)?;
        composite = ingress.observe(|engine| engine.composite_effect(reuse_effect()))?;
    }
    let composite = composite.ok_or("dma-reuse-effect-disappeared")?;
    if composite.effect != reuse_effect()
        || composite.kind != DMA_ARENA_REUSE_COMPOSITE
        || composite.causal_owner.principal() != actor.principal()
        || composite.charge_owner != operation_charge_account()
        || composite.component_count != 1
        || composite.authority == AuthorityState::Revoked
        || composite.custodian == CustodyState::Released
    {
        return Err("dma-reuse-effect-identity");
    }
    let supervisor = CoreSupervisorVNext::new(Arc::clone(&ingress.owner));
    ensure_uncommitted_composite_actor(
        &ingress.owner,
        &supervisor,
        reuse_effect(),
        composite,
        actor,
        binding_generation,
    )?;
    let mut projections = ingress
        .observe(|engine| engine.component_claims(reuse_effect(), AGENT_COMPONENT_DMA))?
        .map_err(|_| "dma-reuse-claims-query")?;
    for (role, kind) in [
        (ClaimRole::Queue, DEVICE_CLAIM_QUEUE_SLOT),
        (ClaimRole::PinnedPages, DEVICE_CLAIM_PINNED_PAGE),
        (ClaimRole::Iova, DEVICE_CLAIM_IOVA),
    ] {
        let old = dma_claims().claim(role);
        let new = reused_dma_claims().claim(role);
        if let Some(projection) = projections
            .iter()
            .find(|projection| projection.claim == new.claim())
        {
            if !validate_dma_claim_projection(*projection, reuse_effect(), new, kind, scope, false)
            {
                return Err("dma-reuse-prefix-claim-coordinate");
            }
            let reclaim = ingress.observe(|engine| {
                engine.reclaim_component_resource_reuse(
                    reuse_effect(),
                    AGENT_COMPONENT_DMA,
                    actor,
                    binding_generation,
                    new.resource(),
                    new.generation(),
                )
            })?;
            match reclaim {
                Ok(command) => {
                    let permit = reuse_permit_checked(ingress.transact(command)?)?;
                    let permit = validate_reuse_permit(permit, old, new, arena)?;
                    expect_no_output_checked(ingress.transact(permit.activate())?)?;
                }
                Err(CoreError::StaleReusePermit) => {}
                Err(_) => return Err("dma-reuse-prefix-reclaim"),
            }
        } else {
            let permit =
                reuse_permit_checked(ingress.transact(CommandRequest::ReserveComponentReuse {
                    effect: reuse_effect(),
                    component: AGENT_COMPONENT_DMA,
                    actor,
                    binding_generation,
                    claim: new.claim(),
                    kind,
                    scope,
                    resource: old.resource(),
                    expected_generation: old.generation(),
                    units: new.units(),
                    reuse_contract: persistent_dma_arena_digest(arena),
                })?)?;
            let permit = validate_reuse_permit(permit, old, new, arena)?;
            expect_no_output_checked(ingress.transact(permit.activate())?)?;
        }
        projections = ingress
            .observe(|engine| engine.component_claims(reuse_effect(), AGENT_COMPONENT_DMA))?
            .map_err(|_| "dma-reuse-claims-query")?;
    }
    let component = ingress
        .observe(|engine| engine.component(reuse_effect(), AGENT_COMPONENT_DMA))?
        .ok_or("dma-reuse-component-absent")?;
    match component.commit {
        CommitState::Registered => {
            expect_no_output_checked(ingress.transact(
                CommandRequest::PrepareCompositeEffect {
                    effect: reuse_effect(),
                    actor,
                    binding_generation,
                },
            )?)?;
        }
        CommitState::Prepared => {}
        CommitState::CommitIntentDurable | CommitState::Committed => {
            return Err("dma-reuse-prefix-commit-state");
        }
    }
    let precommit = ingress.observe(validate_reuse_precommit)?;
    if !precommit {
        return Err("dma-reuse-precommit");
    }

    let prepared = device
        .prepare_read_sector0(&mut root)
        .map_err(|_| "dma-reuse-prepare")?;
    let receipted = device
        .issue_preparation_receipt(prepared)
        .map_err(|_| "dma-reuse-preparation-receipt")?;
    let cohort = CoreDmaCohort::bind_component(
        reuse_effect(),
        AGENT_COMPONENT_DMA,
        actor,
        binding_generation,
        operation_charge_account(),
        receipted.identity(),
        reused_dma_claims(),
    )
    .map_err(|_| "dma-reuse-cohort-binding")?;
    if ClaimScope::Device(cohort.scope()) != scope {
        return Err("dma-reuse-device-scope");
    }
    let intent = commit_intent_checked(
        ingress.transact(cohort.record_commit_intent(persistent_dma_arena_digest(arena)))?,
    )?;
    let authority = ingress
        .observe(move |engine| bind_queue_commit(engine, intent, cohort))?
        .map_err(|_| "dma-reuse-commit-binding")?;
    let published = publish_real_queue(&device, receipted, authority)
        .map_err(|_| "dma-reuse-queue-publication")?;
    let committed = ingress
        .observe(move |engine| published.verify_commit(engine))?
        .map_err(|_| "dma-reuse-queue-commit-verify")?;
    let (request, acknowledgement) = committed.into_parts();
    expect_no_output_checked(ingress.transact(acknowledgement)?)?;
    if !ingress.observe(|engine| {
        validate_dma_component_for(
            engine,
            reuse_effect(),
            reused_dma_claims(),
            DMA_ARENA_REUSE_COMPOSITE,
            1,
        )
    })? {
        return Err("dma-reuse-component-postcondition");
    }
    Ok(ReusePublicationOutput {
        root,
        masked_intx,
        device,
        request,
    })
}

fn ensure_composite_prepared<S>(
    portal: &CorePortalVNext<ProductionCoreOwner<S>>,
    supervisor: &CoreSupervisorVNext<ProductionCoreOwner<S>>,
    owner: &ProductionCoreOwner<S>,
    actor: PrincipalIncarnation,
    binding_generation: u64,
    dma: CoreDmaCohort,
) -> Result<bool, &'static str>
where
    S: InstalledCore + 'static,
{
    let effect = operation_effect();
    let mut resumed_prefix = true;
    let mut composite = owner.observe_engine(|engine| engine.composite_effect(effect));
    if composite.is_none() {
        if actor != operation_origin() || binding_generation != 1 {
            return Err("composite-create-after-root-recovery");
        }
        resumed_prefix = false;
        portal_tx_checked(
            portal,
            0xc501_0001,
            CommandRequest::CreateCompositeEffect {
                effect,
                origin: operation_origin(),
                binding_generation,
                kind: AGENT_OPERATION_COMPOSITE,
                charge_account: operation_charge_account(),
            },
        )?;
        composite = owner.observe_engine(|engine| engine.composite_effect(effect));
    }

    let projection = composite.ok_or("composite-effect-disappeared")?;
    if !validate_composite_projection(&projection) {
        return Err("composite-effect-identity");
    }
    ensure_uncommitted_composite_actor(
        owner,
        supervisor,
        effect,
        projection,
        actor,
        binding_generation,
    )?;

    let reply = owner
        .observe_engine(|engine| engine.component(effect, AGENT_COMPONENT_REPLY))
        .ok_or("reply-component-absent")?;
    let dma_projection = owner
        .observe_engine(|engine| engine.component(effect, AGENT_COMPONENT_DMA))
        .ok_or("dma-component-absent")?;
    if reply.commit != dma_projection.commit
        || !matches!(
            reply.commit,
            CommitState::Registered | CommitState::Prepared
        )
    {
        return Err("composite-prefix-not-resumable");
    }

    if reply.commit == CommitState::Registered {
        let reply_claims = owner
            .observe_engine(|engine| engine.component_claims(effect, AGENT_COMPONENT_REPLY))
            .map_err(|_| "reply-component-claims-query")?;
        match reply_claims.as_slice() {
            [] => portal_tx_checked(
                portal,
                0xc501_0002,
                CommandRequest::AddComponentClaim {
                    effect,
                    component: AGENT_COMPONENT_REPLY,
                    actor,
                    binding_generation,
                    claim: reply_claim(),
                    kind: REPLY_CLAIM_PUBLICATION_SLOT,
                    scope: ClaimScope::Logical,
                    resource: reply_resource(),
                    resource_generation: resource_generation(1),
                    units: 1,
                },
            )
            .map(|_| ())?,
            [claim] if validate_reply_claim(*claim, false) => {}
            _ => return Err("reply-component-prefix-claims"),
        }

        let mut enrolled_dma_claims = owner
            .observe_engine(|engine| engine.component_claims(effect, AGENT_COMPONENT_DMA))
            .map_err(|_| "dma-component-claims-query")?;
        for (index, (role, kind, command)) in
            [ClaimRole::Queue, ClaimRole::PinnedPages, ClaimRole::Iova]
                .into_iter()
                .zip([
                    DEVICE_CLAIM_QUEUE_SLOT,
                    DEVICE_CLAIM_PINNED_PAGE,
                    DEVICE_CLAIM_IOVA,
                ])
                .zip(dma.enroll_claims())
                .map(|((role, kind), command)| (role, kind, command))
                .enumerate()
        {
            let expected = dma_claims().claim(role);
            match enrolled_dma_claims
                .iter()
                .find(|projection| projection.claim == expected.claim())
            {
                Some(projection)
                    if validate_dma_claim_projection(
                        *projection,
                        effect,
                        expected,
                        kind,
                        ClaimScope::Device(dma.scope()),
                        false,
                    ) => {}
                Some(_) => return Err("dma-component-prefix-claim-coordinate"),
                None => {
                    portal_tx_checked(portal, 0xc501_0010 + index as u64, command)?;
                    enrolled_dma_claims = owner
                        .observe_engine(|engine| {
                            engine.component_claims(effect, AGENT_COMPONENT_DMA)
                        })
                        .map_err(|_| "dma-component-claims-query")?;
                }
            }
        }
        if !validate_dma_claims(&enrolled_dma_claims) {
            return Err("dma-component-prefix-claims");
        }

        portal_tx_checked(
            portal,
            0xc501_0020,
            CommandRequest::PrepareCompositeEffect {
                effect,
                actor,
                binding_generation,
            },
        )?;
    }
    if !owner.observe_engine(validate_precommit_components) {
        return Err("composite-prefix-prepare");
    }
    Ok(resumed_prefix)
}

fn ensure_reply_component_committed<S>(
    owner: &ProductionCoreOwner<S>,
    outbox: &mut AtaPioReplyOutbox,
    intent: Option<CommitIntent>,
) -> Result<Digest, &'static str>
where
    S: InstalledCore + 'static,
{
    let plan =
        reply_plan(reply_coordinate(), REPLY_SEQUENCE, REPLY_VALUE).map_err(|_| "reply-plan")?;
    let inspected = inspect_reply_outbox(outbox, plan)?;
    let projection = owner
        .observe_engine(|engine| engine.component(operation_effect(), AGENT_COMPONENT_REPLY))
        .ok_or("reply-component-disappeared")?;
    if projection.commit == CommitState::Committed {
        let receipt = inspected.ok_or("committed-reply-outbox-absent")?;
        if !owner.observe_engine(|engine| validate_reply_commit_lineage(engine, receipt)) {
            return Err("committed-reply-outbox-lineage");
        }
        let checksum = receipt.record_checksum();
        if !validate_committed_reply_with_projection(owner, projection, checksum) {
            return Err("committed-reply-component-projection");
        }
        return Ok(checksum);
    }
    if projection.commit != CommitState::CommitIntentDurable
        || projection.settlement != SettlementState::Unavailable
        || projection.outcome != OutcomeState::Pending
        || projection.retirement != RetirementState::Held
    {
        return Err("reply-component-prefix-not-resumable");
    }
    let intent = intent.ok_or("reply-atomic-commit-intent-custody")?;
    if intent.effect() != operation_effect() || intent.component() != Some(AGENT_COMPONENT_REPLY) {
        return Err("reply-atomic-commit-intent-coordinate");
    }
    let challenge = owner
        .observe_engine(|engine| engine.commit_outcome_challenge(&intent))
        .map_err(|_| "reply-commit-challenge")?;
    let receipt = outbox
        .commit(&challenge, REPLY_SEQUENCE, plan.payload_digest())
        .map_err(|_| "reply-outbox-commit")?;
    let checksum = receipt.record_checksum();
    let verifier = ReplyOutboxCommitVerifier::new(1).ok_or("reply-verifier")?;
    let outcome = owner
        .observe_engine(|engine| engine.verify_commit_outcome(&intent, &verifier, &receipt))
        .map_err(|_| "reply-outbox-verify")?;
    let acknowledgement = intent
        .acknowledge(outcome)
        .map_err(|_| "reply-commit-acknowledgement")?;
    expect_no_output_checked(owner_tx_checked(owner, acknowledgement)?)?;
    if !owner.observe_engine(|engine| validate_committed_reply_component(engine, checksum)) {
        return Err("reply-component-commit-postcondition");
    }
    Ok(checksum)
}

fn arm_initial_component_commits<S>(
    portal: &CorePortalVNext<ProductionCoreOwner<S>>,
    owner: &ProductionCoreOwner<S>,
    actor: PrincipalIncarnation,
    binding_generation: u64,
    dma_operation: Digest,
) -> Result<(CommitIntent, CommitIntent), &'static str>
where
    S: InstalledCore + 'static,
{
    portal_tx_checked(
        portal,
        0xc501_0021,
        CommandRequest::RecordCompositeCommitIntents {
            effect: operation_effect(),
            actor,
            binding_generation,
            operations: vec![
                ComponentCommitOperation::new(AGENT_COMPONENT_REPLY, digest(0xc1)),
                ComponentCommitOperation::new(AGENT_COMPONENT_DMA, dma_operation),
            ],
        },
    )?;
    let mut intents = owner
        .take_composite_commit_intents(operation_effect())
        .ok_or("composite-commit-intent-custody")?;
    if intents.len() != 2 {
        return Err("composite-commit-intent-count");
    }
    let reply_index = intents
        .iter()
        .position(|intent| intent.component() == Some(AGENT_COMPONENT_REPLY))
        .ok_or("reply-atomic-commit-intent-absent")?;
    let reply = intents.swap_remove(reply_index);
    let dma = intents.pop().ok_or("dma-atomic-commit-intent-absent")?;
    if reply.effect() != operation_effect()
        || dma.effect() != operation_effect()
        || dma.component() != Some(AGENT_COMPONENT_DMA)
    {
        return Err("composite-commit-intent-coordinate");
    }
    Ok((reply, dma))
}

// The post-publication error owns the real queue request and both component
// commit coordinates. Boxing it could fail after the device-visible commit and
// discard authority.
#[allow(clippy::result_large_err)]
fn publish_first_boot_operation(
    portal: &CorePortalVNext<ActiveProductionOwner>,
    supervisor: &CoreSupervisorVNext<ActiveProductionOwner>,
    owner: &ActiveProductionOwner,
    resources: InitialCompositeResources,
    ingress: ProductionIngressIdentity,
) -> Result<InitialCompositeOutput, &'static str> {
    let InitialCompositeResources {
        mut outbox,
        mut root,
        masked_intx,
        mut device,
    } = resources;
    let actor = ingress.incarnation();
    let binding_generation = ingress.binding_generation();
    let prepared = device
        .prepare_read_sector0(&mut root)
        .map_err(|_| "dma-prepare")?;
    let receipted = device
        .issue_preparation_receipt(prepared)
        .map_err(|_| "dma-preparation-receipt")?;
    let cohort = CoreDmaCohort::bind_component(
        operation_effect(),
        AGENT_COMPONENT_DMA,
        actor,
        binding_generation,
        operation_charge_account(),
        receipted.identity(),
        dma_claims(),
    )
    .map_err(|_| "dma-cohort-binding")?;

    let resumed_prefix =
        ensure_composite_prepared(portal, supervisor, owner, actor, binding_generation, cohort)?;
    let arena = persistent_dma_arena_layout().ok_or("dma-arena-layout-absent")?;
    let arena_digest = persistent_dma_arena_digest(arena);
    let (reply_intent, dma_intent) =
        arm_initial_component_commits(portal, owner, actor, binding_generation, arena_digest)?;
    let reply_checksum = ensure_reply_component_committed(owner, &mut outbox, Some(reply_intent))?;
    if owner
        .observe_engine(|engine| engine.component(operation_effect(), AGENT_COMPONENT_DMA))
        .is_none_or(|component| component.commit != CommitState::CommitIntentDurable)
    {
        return Err("dma-component-not-atomically-armed");
    }
    let authority = owner
        .observe_engine(move |engine| bind_queue_commit(engine, dma_intent, cohort))
        .map_err(|_| "dma-commit-binding")?;
    let published =
        publish_real_queue(&device, receipted, authority).map_err(|_| "dma-queue-publication")?;
    let committed = owner
        .observe_engine(move |engine| published.verify_commit(engine))
        .map_err(|_| "dma-queue-commit-verify")?;
    let (request, acknowledgement) = committed.into_parts();
    expect_no_output_checked(owner_tx_checked(owner, acknowledgement)?)?;
    if !owner.observe_engine(validate_dma_component) {
        return Err("dma-component-commit-postcondition");
    }
    Ok(InitialCompositeOutput {
        outbox,
        checksum: reply_checksum,
        resumed_prefix,
        root,
        masked_intx,
        device,
        request,
    })
}

fn rebase_prearm_and_activate(boot: PersistentBoot) -> ! {
    let installed = QuarantinedPersistentCore::new(boot);
    let owner = match ProductionCoreOwner::new(installed) {
        Ok(owner) => Arc::new(owner),
        Err(error) => fail_closed("prearm-profile2-install", error),
    };
    let supervisor = CoreSupervisorVNext::new(Arc::clone(&owner));
    let identity = match prepare_production_service(
        &owner,
        &supervisor,
        operation_root(),
        operation_origin(),
        ProductionServiceStage::RebasePrecommit,
    ) {
        Ok(identity) if identity.snapshot.is_some() => identity,
        Ok(_) => fail_closed("prearm-service-not-fresh", (owner, supervisor)),
        Err(reason) => fail_closed(reason, (owner, supervisor)),
    };
    let successor = identity.ingress.incarnation();
    let binding_generation = identity.ingress.binding_generation();
    let run = match build_production_service(&owner, identity, move |ingress| {
        ingress.ready_and_wait_for_rebind()?;
        let quarantine_is_exact = ingress
            .owner
            .installed()
            .inspect_with_guard(|engine, guard| {
                let observation = guard.observation();
                validate_prearm_recovery_candidate(engine)
                    && observation.bus_master_disabled()
                    && observation.intx_masked()
                    && observation.reset_status_zero()
                    && observation.isr_reads() != 0
                    && observation.consecutive_empty_isr_reads() != 0
                    && observation.iotlb_used_remapped_iova()
                    && observation.iotlb_completed_trigger_pages() != 0
            });
        if !quarantine_is_exact
            || ingress.owner.installed().activation_block()
                != Some(BootActivationBlock::DeviceClaimsRetained)
        {
            return Err("prearm-device-quarantine-not-retained");
        }
        let projection = ingress
            .observe(|engine| engine.composite_effect(operation_effect()))?
            .ok_or("prearm-composite-disappeared")?;
        let recovery_supervisor = CoreSupervisorVNext::new(Arc::clone(&ingress.owner));
        ensure_uncommitted_composite_actor(
            &ingress.owner,
            &recovery_supervisor,
            operation_effect(),
            projection,
            successor,
            binding_generation,
        )?;
        expect_no_output_checked(ingress.transact(
            CommandRequest::RebaseCompositePrecommitClaims {
                effect: operation_effect(),
                actor: successor,
                binding_generation,
            },
        )?)?;
        let exact_rebase = ingress.observe(|engine| {
            validate_prearm_recovery_candidate(engine)
                && engine
                    .component_claims(operation_effect(), AGENT_COMPONENT_REPLY)
                    .is_ok_and(|claims| {
                        claims
                            .iter()
                            .all(|claim| claim.enrolled_freshness == engine.freshness())
                    })
                && engine
                    .component_claims(operation_effect(), AGENT_COMPONENT_DMA)
                    .is_ok_and(|claims| {
                        claims
                            .iter()
                            .all(|claim| claim.enrolled_freshness == engine.freshness())
                    })
        })?;
        if !exact_rebase || ingress.owner.installed().activation_block().is_some() {
            return Err("prearm-rebase-postcondition");
        }
        ingress.complete_rebound_domain()?;
        Ok(ProductionServiceDisposition::ExitAfterCompletion)
    }) {
        Ok(run) => run,
        Err(reason) => fail_closed(reason, (owner, supervisor)),
    };
    if let Err(reason) = start_prepared_service(&owner, &supervisor, &run) {
        fail_closed(reason, (owner, supervisor, run));
    }
    if let Err(reason) = wait_service_completion(&run) {
        fail_closed(reason, (owner, supervisor, run));
    }
    if let Err(reason) = wait_exact_service_exit_without_fence(&owner, &run) {
        fail_closed(reason, (owner, supervisor, run));
    }
    if owner.pending_linear_outputs() != 0
        || owner.installed().activation_block().is_some()
        || !owner.observe_engine(validate_prearm_recovery_candidate)
    {
        fail_closed("prearm-owner-postcondition", (owner, supervisor, run));
    }
    drop(run);
    drop(supervisor);
    let owner = match Arc::try_unwrap(owner) {
        Ok(owner) => owner,
        Err(owner) => fail_closed("prearm-owner-still-aliased", owner),
    };
    let boot = owner.into_installed().into_boot();
    println!(
        "CSER_CORE_PREARM_REBASE PASS effect_root={} effect_sequence={} \
         successor_generation={} binding_generation={} task_bound_ingress=true \
         ready=true rebind=true adopt=true device_quarantine_guard=retained \
         claims_freshness=rebased activation_block=clear manager_portal_bypass=false",
        operation_effect().root().get(),
        operation_effect().sequence(),
        successor.generation(),
        binding_generation,
    );
    run_activation_boot(boot)
}

fn run_quarantined_boot(boot: PersistentBoot) -> ! {
    if boot.activation_block() != Some(BootActivationBlock::DeviceClaimsRetained) {
        fail_closed("quarantine-without-device-tombstone", boot);
    }
    if boot.observe(validate_prearm_recovery_candidate) {
        rebase_prearm_and_activate(boot);
    }
    let installed = QuarantinedPersistentCore::new(boot);
    let owner = match ProductionCoreOwner::new(installed) {
        Ok(owner) => Arc::new(owner),
        Err(error) => fail_closed("profile2-quarantined-install", error),
    };
    let supervisor_owner = Arc::clone(&owner);
    let reply_owner = Arc::clone(&owner);
    let dma_owner = Arc::clone(&owner);
    let supervisor = CoreSupervisorVNext::new(supervisor_owner);
    if supervisor.protocol() != CORE_SUPERVISOR_PROTOCOL {
        fail_closed(
            "supervisor-protocol",
            (owner, supervisor, reply_owner, dma_owner),
        );
    }

    let mut outbox = match AtaPioReplyOutbox::acquire_secondary_master() {
        Ok(outbox) => outbox,
        Err(_) => fail_closed(
            "reply-outbox-open",
            (owner, supervisor, reply_owner, dma_owner),
        ),
    };
    let plan = match reply_plan(reply_coordinate(), REPLY_SEQUENCE, REPLY_VALUE) {
        Ok(plan) => plan,
        Err(_) => fail_closed(
            "reply-plan",
            (owner, supervisor, reply_owner, dma_owner, outbox),
        ),
    };
    let dma_effect = match owner.observe_engine(|engine| {
        let retained = engine.retained_component_claims();
        let effect = retained
            .iter()
            .find(|claim| claim.domain == DEVICE_DOMAIN)
            .map(|claim| claim.effect)?;
        retained
            .iter()
            .filter(|claim| claim.domain == DEVICE_DOMAIN)
            .all(|claim| claim.effect == effect)
            .then_some(effect)
    }) {
        Some(effect) => effect,
        None => fail_closed(
            "mixed-device-tombstone-effects",
            (owner, supervisor, reply_owner, dma_owner, outbox),
        ),
    };
    let expected_dma_claims = if dma_effect == operation_effect() {
        dma_claims()
    } else if dma_effect == reuse_effect() {
        reused_dma_claims()
    } else {
        fail_closed(
            "unknown-device-tombstone-effect",
            (owner, supervisor, reply_owner, dma_owner, outbox),
        )
    };
    let dma_report = match reconcile_dma_tombstones(&dma_owner, dma_effect, expected_dma_claims) {
        Ok(report) => report,
        Err(reason) => fail_closed(reason, (owner, supervisor, reply_owner, dma_owner, outbox)),
    };
    let source = match inspect_reply_apply_source(&owner, &mut outbox, plan) {
        Ok(source) => source,
        Err(reason) => fail_closed(reason, (owner, supervisor, reply_owner, dma_owner, outbox)),
    };
    let phase = match owner
        .observe_engine(|engine| classify_persistent_phase(engine, source.predecessor_digest()))
    {
        Ok(phase) => phase,
        Err(reason) => fail_closed(reason, (owner, supervisor, reply_owner, dma_owner, outbox)),
    };
    if !dma_report.resource_reuse_authorized
        || !validate_dma_reuse_boundary(&owner, dma_effect, expected_dma_claims)
        || owner.installed().activation_block().is_some()
        || owner.pending_linear_outputs() != 0
    {
        fail_closed(
            "quarantine-postcondition",
            (owner, supervisor, reply_owner, dma_owner, outbox),
        );
    }

    match phase {
        PersistentPhase::ArmSecondCrash => {
            let ArmedSecondCrash {
                service,
                outbox,
                checksum: reply_checksum,
                resumed_prefix,
                successor,
                binding_generation,
            } = match arm_reply_second_crash(&reply_owner, &supervisor, plan, source, outbox) {
                Ok(armed) => armed,
                Err(reason) => fail_closed(reason, (owner, supervisor, reply_owner, dma_owner)),
            };
            let RuntimeMetrics {
                revision,
                boot_generation,
                journal_generation,
                device_generation,
                retained,
                catalog_digest,
                projection_digest,
            } = runtime_metrics(&owner);
            let exact = owner.observe_engine(|engine| {
                engine
                    .component(operation_effect(), AGENT_COMPONENT_REPLY)
                    .is_some_and(|component| {
                        validate_committed_reply_component(engine, reply_checksum)
                            && matches!(
                                component.settlement,
                                SettlementState::ReconciliationRequired { applied: false, .. }
                            )
                            && component.retirement == RetirementState::RetirementPending
                            && component.retained_claims == 1
                    })
            });
            if dma_effect != operation_effect()
                || retained != 1
                || dma_report.reset_submitted != 3
                || dma_report.irq_submitted != 1
                || dma_report.iotlb_submitted != 2
                || !exact
            {
                fail_closed(
                    "boot2-postcondition",
                    (owner, supervisor, reply_owner, dma_owner, outbox, service),
                );
            }
            println!(
                "CSER_CORE_PERSISTENT_BOOT2 PASS shared_runtime=true production_registry=single \
                 api_profile={} catalog_version={} projection_version={} snapshot_version={} \
                 journal_schema={} catalog_digest={} projection_digest={} \
                 operation_effect_root={} operation_effect_sequence={} \
                 reply_component_id={} dma_component_id={} \
                 portal=nxp3 supervisor=core-v1 reply=reconciliation-required \
                 pre_fence_reply=apply-intent-durable core_apply_intent_durable=true \
                 second_crash=service-exact-reap external_apply_durable=false \
                 no_external_apply=true dma_queue=retired \
                 dma_pages_iova=retired dma_component=retired retained={} dma_retained=0 \
                 activation=deferred resource_reuse_authorized=true \
                 reset_submitted={} irq_submitted={} iotlb_submitted={} \
                 service_principal_generation={} successor_generation={} binding_generation={} \
                 fresh_service_task=true ready_in_fresh_task=true production_rebind=true \
                 service_death=task-return exact_reap=true same_boot_fence=true ingress_latch=closed \
                 closed_ingress_rejected=true resumed_prefix={} \
                 revision={} boot={} journal={} device={} journal_provider=ata-pio \
                 outbox_provider=ata-pio-secondary anchor_provider=tpm2-nv \
                 quarantine=pre-replay-virtio+global-iotlb qemu=true \
                 physical_antirollback=false physical_powerloss=false \
                 physical_dma_custody=false",
                CSER_CORE_API_PROFILE_VERSION,
                STANDARD_CATALOG_VERSION,
                PROJECTION_VERSION,
                RECOVERY_SNAPSHOT_VERSION,
                JOURNAL_SCHEMA_VERSION,
                HexDigest(catalog_digest),
                HexDigest(projection_digest),
                operation_effect().root().get(),
                operation_effect().sequence(),
                AGENT_COMPONENT_REPLY.get(),
                AGENT_COMPONENT_DMA.get(),
                retained,
                dma_report.reset_submitted,
                dma_report.irq_submitted,
                dma_report.iotlb_submitted,
                successor.generation(),
                successor.generation(),
                binding_generation,
                resumed_prefix,
                revision,
                boot_generation,
                journal_generation,
                device_generation,
            );
            poweroff_retaining((owner, supervisor, reply_owner, dma_owner, outbox, service))
        }
        PersistentPhase::ReconcileSecondCrash
        | PersistentPhase::RecoverApplied
        | PersistentPhase::RetireDurableReply => fail_closed(
            "reply-reconciliation-requires-activated-device",
            (
                plan,
                owner,
                supervisor,
                reply_owner,
                dma_owner,
                outbox,
                dma_report,
            ),
        ),
        PersistentPhase::StableRecovery => {
            let (service, successor, binding_generation) =
                match bind_stable_recovery_service(&reply_owner, &supervisor) {
                    Ok(recovered) => recovered,
                    Err(reason) => {
                        fail_closed(reason, (owner, supervisor, reply_owner, dma_owner, outbox))
                    }
                };
            let RuntimeMetrics {
                revision,
                boot_generation,
                journal_generation,
                device_generation,
                retained,
                catalog_digest,
                projection_digest,
            } = runtime_metrics(&owner);
            let exact = owner.observe_engine(|engine| {
                validate_dma_component_for(
                    engine,
                    reuse_effect(),
                    reused_dma_claims(),
                    DMA_ARENA_REUSE_COMPOSITE,
                    1,
                ) && engine
                    .component(reuse_effect(), AGENT_COMPONENT_DMA)
                    .is_some_and(|component| {
                        component.retirement == RetirementState::Retired
                            && component.retained_claims == 0
                    })
            });
            if dma_effect != reuse_effect()
                || retained != 0
                || dma_report.reset_submitted != 3
                || dma_report.irq_submitted != 1
                || dma_report.iotlb_submitted != 2
                || !exact
            {
                fail_closed(
                    "boot4-postcondition",
                    (owner, supervisor, reply_owner, dma_owner, outbox, service),
                );
            }
            println!(
                "CSER_CORE_PERSISTENT_BOOT4 PASS shared_runtime=true production_registry=single \
                 api_profile={} catalog_version={} projection_version={} snapshot_version={} \
                 journal_schema={} catalog_digest={} projection_digest={} \
                 operation_effect_root={} operation_effect_sequence={} \
                 reply_component_id={} dma_component_id={} reuse_effect_root={} \
                 reuse_effect_sequence={} \
                 portal=nxp3 supervisor=core-v1 reply=settled repeated_recovery=stable \
                 duplicate_apply_intent=false duplicate_dma_evidence=false dma_queue=retired \
                 dma_pages_iova=retired reuse_generation=2 retained={} dma_retained=0 \
                 activation=deferred resource_reuse_authorized=true \
                 reset_submitted={} irq_submitted={} iotlb_submitted={} \
                 service_principal_generation={} successor_generation={} binding_generation={} \
                 fresh_service_task=true ready_in_fresh_task=true production_rebind=true \
                 service_state=live ingress_latch=open prior_service_fence=boot-checkpoint \
                 revision={} boot={} journal={} device={} journal_provider=ata-pio \
                 outbox_provider=ata-pio-secondary anchor_provider=tpm2-nv \
                 quarantine=pre-replay-virtio+global-iotlb qemu=true \
                 physical_antirollback=false physical_powerloss=false \
                 physical_dma_custody=false",
                CSER_CORE_API_PROFILE_VERSION,
                STANDARD_CATALOG_VERSION,
                PROJECTION_VERSION,
                RECOVERY_SNAPSHOT_VERSION,
                JOURNAL_SCHEMA_VERSION,
                HexDigest(catalog_digest),
                HexDigest(projection_digest),
                operation_effect().root().get(),
                operation_effect().sequence(),
                AGENT_COMPONENT_REPLY.get(),
                AGENT_COMPONENT_DMA.get(),
                reuse_effect().root().get(),
                reuse_effect().sequence(),
                retained,
                dma_report.reset_submitted,
                dma_report.irq_submitted,
                dma_report.iotlb_submitted,
                successor.generation(),
                successor.generation(),
                binding_generation,
                revision,
                boot_generation,
                journal_generation,
                device_generation,
            );
            poweroff_retaining((owner, supervisor, reply_owner, dma_owner, outbox, service))
        }
    }
}

fn arm_reply_second_crash(
    owner: &Arc<QuarantinedProductionOwner>,
    supervisor: &CoreSupervisorVNext<QuarantinedProductionOwner>,
    plan: ReplyPlan,
    source: ReplyApplySource,
    outbox: AtaPioReplyOutbox,
) -> Result<ArmedSecondCrash, &'static str> {
    let identity = prepare_production_service(
        owner,
        supervisor,
        operation_root(),
        operation_origin(),
        ProductionServiceStage::ArmSecondCrash,
    )?;
    if identity.snapshot.is_none() {
        return Err("second-crash-service-not-fresh");
    }
    let successor = identity.ingress.incarnation();
    let binding_generation = identity.ingress.binding_generation();
    let output = Arc::new(OneShot::new());
    let task_output = Arc::clone(&output);
    let run = build_production_service(owner, identity, move |ingress| {
        ingress.ready_and_wait_for_rebind()?;
        let outbox = outbox;
        let checksum = source.predecessor_digest();
        if !ingress.observe(|engine| validate_committed_reply_component(engine, checksum))? {
            return Err("reply-atomic-arm-recovery-projection");
        }
        let resumed_prefix = true;
        ingress.verify_component_observation(operation_effect(), AGENT_COMPONENT_REPLY)?;
        let settlement =
            ingress.claim_component_settlement(operation_effect(), AGENT_COMPONENT_REPLY)?;
        let command = settlement
            .record_apply_intent(plan.intent_digest())
            .map_err(|_| "reply-apply-intent-command")?;
        let _settlement = settlement_claim_checked(ingress.transact(command)?)?;
        if !ingress.observe(|engine| {
            engine
                .component(operation_effect(), AGENT_COMPONENT_REPLY)
                .is_some_and(|component| {
                    matches!(
                        component.settlement,
                        SettlementState::ApplyIntentDurable { .. }
                    ) && component.retirement == RetirementState::RetirementPending
                        && component.retained_claims == 1
                })
        })? {
            return Err("reply-apply-intent-not-durable-before-second-crash");
        }
        ingress.complete_rebound_domain()?;
        task_output.publish(ArmSecondCrashOutput {
            outbox,
            checksum,
            resumed_prefix,
        });
        Ok(ProductionServiceDisposition::ExitAfterCompletion)
    })?;
    start_prepared_service(owner, supervisor, &run)?;
    wait_service_completion(&run)?;
    let ArmSecondCrashOutput {
        outbox,
        checksum,
        resumed_prefix,
    } = output
        .wait_take_bounded()
        .ok_or("second-crash-service-output-timeout")?;
    wait_exact_service_exit(owner, &run)?;
    let closed_portal = CorePortalVNext::new(Arc::clone(owner));
    verify_closed_portal_rejection(
        owner,
        &closed_portal,
        0xc501_01ff,
        CommandRequest::PrepareCompositeEffect {
            effect: operation_effect(),
            actor: successor,
            binding_generation,
        },
    )?;
    Ok(ArmedSecondCrash {
        service: run,
        outbox,
        checksum,
        resumed_prefix,
        successor,
        binding_generation,
    })
}

fn reconcile_reply_in_service<S>(
    ingress: &ProductionServiceIngress<S>,
    outbox: &mut AtaPioReplyOutbox,
    endpoint: Option<(&ReplyCustody, &OneShot<Result<u64, ReplyAckError>>)>,
    plan: ReplyPlan,
    source: ReplyApplySource,
) -> Result<(), &'static str>
where
    S: InstalledCore + 'static,
{
    ingress.verify_component_observation(operation_effect(), AGENT_COMPONENT_REPLY)?;
    let component = ingress
        .observe(|engine| engine.component(operation_effect(), AGENT_COMPONENT_REPLY))?
        .ok_or("reply-component-disappeared")?;
    if component.settlement == SettlementState::Settled {
        let DurableReplyDelivery::Acknowledged {
            apply,
            acknowledgement,
        } = inspect_reply_delivery(outbox, plan, source)?
        else {
            return Err("settled-reply-durable-ack-absent");
        };
        if component.retirement == RetirementState::Retired && component.retained_claims == 0 {
            return Ok(());
        }
        if component.retirement != RetirementState::RetirementPending
            || component.retained_claims != 1
        {
            return Err("settled-reply-retirement-prefix");
        }
        return retire_reply_from_durable_ack(ingress, plan, apply, acknowledgement);
    }
    let already_applied = matches!(
        component.settlement,
        SettlementState::ReconciliationRequired { applied: true, .. }
    );
    if !matches!(
        component.settlement,
        SettlementState::Open { .. } | SettlementState::ReconciliationRequired { .. }
    ) {
        return Err("reply-reconciliation-prefix");
    }
    let settlement =
        ingress.claim_component_settlement(operation_effect(), AGENT_COMPONENT_REPLY)?;
    let settlement = match settlement.record_apply_intent(plan.intent_digest()) {
        Ok(command) if !already_applied => settlement_claim_checked(ingress.transact(command)?)?,
        Ok(_) => return Err("reply-applied-prefix-accepted-second-intent"),
        Err(failure) if failure.error() == &CoreError::WrongSettlementStage => failure.into_claim(),
        Err(_) => return Err("reply-reconciliation-stage"),
    };
    let delivery = inspect_reply_delivery(outbox, plan, source)?;
    let (apply, durable_ack) = match delivery {
        DurableReplyDelivery::Absent if !already_applied => {
            let apply = outbox
                .record_apply(plan, source)
                .map_err(|_| "reply-durable-apply")?;
            (apply, None)
        }
        DurableReplyDelivery::Applied(apply) => (apply, None),
        DurableReplyDelivery::Acknowledged {
            apply,
            acknowledgement,
        } if already_applied => (apply, Some(acknowledgement)),
        DurableReplyDelivery::Absent => return Err("reply-applied-prefix-missing-durable-apply"),
        DurableReplyDelivery::Acknowledged { .. } => {
            return Err("reply-ack-before-core-applied");
        }
    };

    if durable_ack.is_none() {
        let (custody, _) = endpoint.ok_or("reply-receiver-required")?;
        custody
            .redeliver_durable(plan, apply.semantic_digest())
            .map_err(|_| "reply-durable-redelivery")?;
    } else if endpoint.is_some() {
        return Err("reply-acknowledged-prefix-created-receiver");
    }

    let settlement = if already_applied {
        settlement
    } else {
        let verifier = ReplyDurableApplyVerifier::new(plan);
        let applied = ingress
            .observe(|engine| engine.verify_apply_completion(&settlement, &verifier, &apply))?
            .map_err(|_| "reply-durable-apply-verify")?;
        let command = settlement
            .record_applied(applied)
            .map_err(|_| "reply-record-applied-command")?;
        settlement_claim_checked(ingress.transact(command)?)?
    };

    let acknowledgement = match durable_ack {
        Some(acknowledgement) => acknowledgement,
        None => {
            let (_, result) = endpoint.ok_or("reply-receiver-required")?;
            if result.wait_take_bounded() != Some(Ok(REPLY_VALUE)) {
                return Err("reply-client-result");
            }
            outbox
                .record_acknowledgement(plan, apply)
                .map_err(|_| "reply-durable-ack")?
        }
    };
    let verifier = ReplyDurableAckVerifier::new(plan, apply);
    let verified_ack = ingress
        .observe(|engine| engine.verify_settlement_ack(&settlement, &verifier, &acknowledgement))?
        .map_err(|_| "reply-durable-ack-verify")?;
    let settle = settlement
        .settle(verified_ack)
        .map_err(|_| "reply-settle-command")?;
    expect_no_output_checked(ingress.transact(settle)?)?;
    retire_reply_from_durable_ack(ingress, plan, apply, acknowledgement)
}

fn retire_reply_from_durable_ack<S>(
    ingress: &ProductionServiceIngress<S>,
    plan: ReplyPlan,
    apply: ReplyApplyRecord,
    acknowledgement: ReplyAckRecord,
) -> Result<(), &'static str>
where
    S: InstalledCore + 'static,
{
    let verifier = ReplyDurableRetirementVerifier::new(plan, apply);
    let retirement = ingress
        .observe(|engine| {
            engine.verify_component_retirement_evidence(
                operation_effect(),
                AGENT_COMPONENT_REPLY,
                reply_claim(),
                REPLY_EVIDENCE_PUBLICATION_ACK,
                &verifier,
                &acknowledgement,
            )
        })?
        .map_err(|_| "reply-durable-retirement-verify")?;
    expect_no_output_checked(ingress.transact(retirement.submit())?)
}

fn bind_stable_recovery_service(
    owner: &Arc<QuarantinedProductionOwner>,
    supervisor: &CoreSupervisorVNext<QuarantinedProductionOwner>,
) -> Result<(ProductionServiceRun, PrincipalIncarnation, u64), &'static str> {
    let identity = prepare_production_service(
        owner,
        supervisor,
        operation_root(),
        operation_origin(),
        ProductionServiceStage::StableRecovery,
    )?;
    if identity.snapshot.is_none() {
        return Err("stable-service-not-fresh");
    }
    let successor = identity.ingress.incarnation();
    let binding_generation = identity.ingress.binding_generation();
    let run = build_production_service(owner, identity, move |ingress| {
        ingress.ready_and_wait_for_rebind()?;
        ingress.verify_component_observation(operation_effect(), AGENT_COMPONENT_REPLY)?;
        ingress.verify_component_observation(operation_effect(), AGENT_COMPONENT_DMA)?;
        ingress.verify_component_observation(reuse_effect(), AGENT_COMPONENT_DMA)?;
        let stable = ingress.observe(|engine| {
            engine
                .component(operation_effect(), AGENT_COMPONENT_REPLY)
                .is_some_and(|component| {
                    component.settlement == SettlementState::Settled
                        && component.retirement == RetirementState::Retired
                        && component.retained_claims == 0
                })
                && validate_dma_component(engine)
                && validate_dma_component_for(
                    engine,
                    reuse_effect(),
                    reused_dma_claims(),
                    DMA_ARENA_REUSE_COMPOSITE,
                    1,
                )
        })?;
        if !stable {
            return Err("stable-service-projection");
        }
        ingress.complete_rebound_domain()?;
        Ok(ProductionServiceDisposition::RemainLive)
    })?;
    start_prepared_service(owner, supervisor, &run)?;
    wait_service_completion(&run)?;
    if run.task.is_reaped()
        || !run.control.ingress_open.load(Ordering::Acquire)
        || owner.ingress_identity() != Some(identity.ingress)
        || run.exits.rejected.load(Ordering::Acquire)
    {
        return Err("stable-service-not-live");
    }
    Ok((run, successor, binding_generation))
}

fn bound_root_identity<S>(
    owner: &ProductionCoreOwner<S>,
    root: RootId,
) -> Result<(PrincipalIncarnation, u64), &'static str>
where
    S: InstalledCore,
{
    let state = owner
        .observe_engine(|engine| engine.root(root))
        .ok_or("recovery-root-absent")?;
    match state {
        RootRecoveryState::Active {
            incarnation,
            binding_generation,
        } => Ok((incarnation, binding_generation)),
        RootRecoveryState::Rebound {
            successor,
            binding_generation,
        } => Ok((successor, binding_generation)),
        RootRecoveryState::Fenced { .. } => Err("service-root-not-rebound"),
        RootRecoveryState::Snapshotted { .. } | RootRecoveryState::Ready { .. } => {
            Err("partial-root-recovery-stage")
        }
        RootRecoveryState::RecoveryExhausted { .. } => Err("root-recovery-exhausted"),
    }
}

fn spawn_reply_client(coordinate: ReplyCoordinate) -> Result<ReplyClient, &'static str> {
    let custody = Arc::new(OneShot::new());
    let result = Arc::new(OneShot::new());
    let task_custody = Arc::clone(&custody);
    let task_result = Arc::clone(&result);
    let task = Arc::new(
        TaskOptions::new(move || {
            let (receiver, reply_custody) = reply_pair(coordinate);
            task_custody.publish(reply_custody);
            task_result.publish(receiver.wait_and_ack());
        })
        .build()
        .map_err(|_| "reply-client-task-build")?,
    );
    task.run();
    let custody = custody
        .wait_take_bounded()
        .ok_or("reply-client-custody-timeout")?;
    Ok((task, custody, result))
}

fn reconcile_dma_tombstones(
    owner: &QuarantinedProductionOwner,
    effect: EffectId,
    expected: CoreDmaClaims,
) -> Result<DmaRecoveryReport, &'static str> {
    let layout = persistent_dma_arena_layout().ok_or("dma-arena-layout-absent")?;
    let layout_digest = persistent_dma_arena_digest(layout);
    let component = owner
        .observe_engine(|engine| engine.component(effect, AGENT_COMPONENT_DMA))
        .ok_or("dma-component-absent")?;
    if component.commit_operation != Some(layout_digest) {
        return Err("dma-arena-journal-binding");
    }
    let claims = owner.observe_engine(|engine| {
        engine
            .retained_component_claims()
            .into_iter()
            .filter(|claim| {
                claim.effect == effect
                    && claim.component == AGENT_COMPONENT_DMA
                    && claim.domain == DEVICE_DOMAIN
            })
            .collect::<Vec<_>>()
    });
    if claims.is_empty() {
        return Err("dma-tombstones-absent");
    }
    let mut report = DmaRecoveryReport::default();

    for claim in claims {
        if !matches!(
            claim.kind,
            DEVICE_CLAIM_QUEUE_SLOT | DEVICE_CLAIM_PINNED_PAGE | DEVICE_CLAIM_IOVA
        ) {
            return Err("dma-tombstone-kind");
        }
        let reset_missing = !owner
            .observe_engine(|engine| {
                engine.component_retirement_evidence_accepted(
                    claim.effect,
                    claim.component,
                    claim.claim,
                    DEVICE_EVIDENCE_RESET,
                )
            })
            .map_err(|_| "dma-reset-state")?;
        let irq_missing = if claim.kind == DEVICE_CLAIM_QUEUE_SLOT {
            !owner
                .observe_engine(|engine| {
                    engine.component_retirement_evidence_accepted(
                        claim.effect,
                        claim.component,
                        claim.claim,
                        DEVICE_EVIDENCE_IRQ_DRAINED,
                    )
                })
                .map_err(|_| "dma-irq-state")?
        } else {
            false
        };
        let iotlb_missing = if matches!(claim.kind, DEVICE_CLAIM_PINNED_PAGE | DEVICE_CLAIM_IOVA) {
            !owner
                .observe_engine(|engine| {
                    engine.component_retirement_evidence_accepted(
                        claim.effect,
                        claim.component,
                        claim.claim,
                        DEVICE_EVIDENCE_IOTLB,
                    )
                })
                .map_err(|_| "dma-iotlb-state")?
        } else {
            false
        };
        if !reset_missing && !irq_missing && !iotlb_missing {
            continue;
        }
        let receipts = owner
            .installed()
            .inspect_with_guard(|_, guard| project_replayed_component_claim(guard, claim))
            .map_err(|_| "dma-quarantine-projection")?;
        let (reset, irq, iotlb) = receipts.into_parts();
        if iotlb.resource_reuse_authorized() {
            return Err("dma-global-iotlb-overclaimed-reuse");
        }
        if reset_missing {
            let command = owner
                .observe_engine(|engine| {
                    engine.verify_component_retirement_evidence(
                        claim.effect,
                        claim.component,
                        claim.claim,
                        DEVICE_EVIDENCE_RESET,
                        &OstdBootClaimVerifier::new_component(claim),
                        &reset,
                    )
                })
                .map_err(|_| "dma-reset-verify")?
                .submit();
            expect_no_output_checked(owner_tx_checked(owner, command)?)?;
            report.reset_submitted += 1;
        }
        if irq_missing {
            let irq_command = owner
                .observe_engine(|engine| {
                    engine.verify_component_retirement_evidence(
                        claim.effect,
                        claim.component,
                        claim.claim,
                        DEVICE_EVIDENCE_IRQ_DRAINED,
                        &OstdBootIrqVerifier::new_component(claim),
                        &irq,
                    )
                })
                .map_err(|_| "dma-irq-verify")?
                .submit();
            expect_no_output_checked(owner_tx_checked(owner, irq_command)?)?;
            report.irq_submitted += 1;
        }
        if iotlb_missing {
            let verifier = QemuArenaIotlbVerifier::new_component(
                claim,
                layout,
                layout_digest,
                component.commit_operation,
                persistent_dma_arena_ready(),
                qemu_hypervisor_detected(),
            );
            let iotlb_command = owner
                .observe_engine(|engine| {
                    engine.verify_component_retirement_evidence(
                        claim.effect,
                        claim.component,
                        claim.claim,
                        DEVICE_EVIDENCE_IOTLB,
                        &verifier,
                        &iotlb,
                    )
                })
                .map_err(|_| "dma-iotlb-verify")?
                .submit();
            expect_no_output_checked(owner_tx_checked(owner, iotlb_command)?)?;
            report.iotlb_submitted += 1;
        }
    }
    report.resource_reuse_authorized = validate_dma_reuse_boundary(owner, effect, expected);
    if !report.resource_reuse_authorized {
        return Err("dma-resource-reuse-boundary");
    }
    Ok(report)
}

fn validate_dma_reuse_boundary(
    owner: &QuarantinedProductionOwner,
    effect: EffectId,
    claims: CoreDmaClaims,
) -> bool {
    owner.observe_engine(|engine| {
        if [
            claims.claim(ClaimRole::Queue),
            claims.claim(ClaimRole::PinnedPages),
            claims.claim(ClaimRole::Iova),
        ]
        .into_iter()
        .any(|claim| engine.check_reusable(claim.resource(), claim.generation()) != Ok(()))
        {
            return false;
        }
        !engine.retained_component_claims().into_iter().any(|claim| {
            claim.effect == effect
                && claim.component == AGENT_COMPONENT_DMA
                && claim.domain == DEVICE_DOMAIN
        })
    })
}

fn inspect_reply_outbox(
    outbox: &mut AtaPioReplyOutbox,
    plan: ReplyPlan,
) -> Result<Option<ReplyCommitReceipt>, &'static str> {
    let identity = ReplyOutboxIdentity::new(operation_effect(), REPLY_SEQUENCE)
        .ok_or("reply-outbox-identity")?;
    match outbox.inspect(identity) {
        ReplyCommitInspection::Absent => Ok(None),
        ReplyCommitInspection::Committed(receipt)
            if receipt.reply() == identity
                && receipt.component() == AGENT_COMPONENT_REPLY
                && receipt.authority_generation() != 0
                && receipt.intent_nonce() != 0
                && receipt.operation() == digest(0xc1)
                && receipt.payload_digest() == plan.payload_digest()
                && receipt.commit_generation() != 0
                && !receipt.record_checksum().is_zero() =>
        {
            Ok(Some(receipt))
        }
        ReplyCommitInspection::Committed(_) => Err("reply-outbox-coordinate-mismatch"),
        ReplyCommitInspection::Corrupt(_) => Err("reply-outbox-corrupt"),
        ReplyCommitInspection::Indeterminate(_) => Err("reply-outbox-indeterminate"),
    }
}

fn inspect_reply_apply_source<S>(
    owner: &ProductionCoreOwner<S>,
    outbox: &mut AtaPioReplyOutbox,
    plan: ReplyPlan,
) -> Result<ReplyApplySource, &'static str>
where
    S: InstalledCore,
{
    let committed = inspect_reply_outbox(outbox, plan)?;
    let component = owner
        .observe_engine(|engine| engine.component(operation_effect(), AGENT_COMPONENT_REPLY))
        .ok_or("reply-component-disappeared")?;
    if component.commit != CommitState::Committed
        || component.commit_operation != Some(digest(0xc1))
    {
        return Err("reply-component-not-committed");
    }
    if let Some(receipt) = committed
        && !owner.observe_engine(|engine| validate_reply_commit_lineage(engine, receipt))
    {
        return Err("reply-commit-lineage-mismatch");
    }
    match (component.outcome, committed) {
        (OutcomeState::KnownSuccess(expected), Some(observed))
            if expected == observed.record_checksum() =>
        {
            Ok(ReplyApplySource::Committed(observed.record_checksum()))
        }
        (OutcomeState::Indeterminate(operation), Some(observed)) if operation == digest(0xc1) => {
            Ok(ReplyApplySource::Committed(observed.record_checksum()))
        }
        (OutcomeState::Indeterminate(operation), None) if operation == digest(0xc1) => {
            Ok(ReplyApplySource::AtomicArmIndeterminate(operation))
        }
        (OutcomeState::Pending | OutcomeState::KnownFailure(_), _)
        | (OutcomeState::KnownSuccess(_), _)
        | (OutcomeState::Indeterminate(_), _) => Err("reply-commit-source-mismatch"),
    }
}

fn validate_reply_commit_lineage(engine: &Engine, receipt: ReplyCommitReceipt) -> bool {
    let Some(composite) = engine.composite_effect(operation_effect()) else {
        return false;
    };
    if receipt.component() != AGENT_COMPONENT_REPLY
        || receipt.actor() != composite.causal_owner
        || composite.effect != operation_effect()
    {
        return false;
    }
    let current = match engine.root(operation_root()) {
        Some(RootRecoveryState::Active { incarnation, .. }) => incarnation,
        Some(RootRecoveryState::Fenced { crashed, .. })
        | Some(RootRecoveryState::RecoveryExhausted { crashed, .. }) => crashed,
        Some(RootRecoveryState::Ready { successor, .. })
        | Some(RootRecoveryState::Rebound { successor, .. }) => successor,
        Some(RootRecoveryState::Snapshotted { .. }) | None => return false,
    };
    current.principal() == receipt.actor().principal()
        && current.generation() >= receipt.actor().generation()
}

fn inspect_reply_delivery(
    outbox: &mut AtaPioReplyOutbox,
    plan: ReplyPlan,
    source: ReplyApplySource,
) -> Result<DurableReplyDelivery, &'static str> {
    let identity = ReplyOutboxIdentity::new(operation_effect(), REPLY_SEQUENCE)
        .ok_or("reply-delivery-identity")?;
    match outbox.inspect_delivery(identity) {
        ReplyDeliveryInspection::Absent => Ok(DurableReplyDelivery::Absent),
        ReplyDeliveryInspection::Applied(apply)
            if apply.reply() == identity
                && apply.matches_plan(plan)
                && apply.source() == source =>
        {
            Ok(DurableReplyDelivery::Applied(apply))
        }
        ReplyDeliveryInspection::Acknowledged {
            apply,
            acknowledgement,
        } if apply.reply() == identity
            && acknowledgement.reply() == identity
            && apply.matches_plan(plan)
            && apply.source() == source
            && acknowledgement.matches_plan(plan, apply) =>
        {
            Ok(DurableReplyDelivery::Acknowledged {
                apply,
                acknowledgement,
            })
        }
        ReplyDeliveryInspection::Applied(_) | ReplyDeliveryInspection::Acknowledged { .. } => {
            Err("reply-delivery-coordinate-mismatch")
        }
        ReplyDeliveryInspection::Corrupt(_) => Err("reply-delivery-corrupt"),
        ReplyDeliveryInspection::Indeterminate(_) => Err("reply-delivery-indeterminate"),
    }
}

fn validate_composite_projection(composite: &CompositeEffectProjection) -> bool {
    composite.effect == operation_effect()
        && composite.kind == AGENT_OPERATION_COMPOSITE
        && composite.causal_owner == operation_origin()
        && composite.charge_owner == operation_charge_account()
        && composite.component_count == 2
        && composite.authority != AuthorityState::Revoked
        && composite.custodian != CustodyState::Released
}

fn validate_composite_identity(engine: &Engine) -> bool {
    let Some(composite) = engine.composite_effect(operation_effect()) else {
        return false;
    };
    let Some(reply) = engine.component(operation_effect(), AGENT_COMPONENT_REPLY) else {
        return false;
    };
    let Some(dma) = engine.component(operation_effect(), AGENT_COMPONENT_DMA) else {
        return false;
    };
    validate_composite_projection(&composite)
        && reply.effect == operation_effect()
        && reply.component == AGENT_COMPONENT_REPLY
        && reply.obligation == (REPLY_DOMAIN, REPLY_OBLIGATION_PUBLICATION)
        && dma.effect == operation_effect()
        && dma.component == AGENT_COMPONENT_DMA
        && dma.obligation == (DEVICE_DOMAIN, DEVICE_OBLIGATION_DMA)
}

fn validate_reply_claim(claim: ComponentClaimProjection, retired: bool) -> bool {
    claim.effect == operation_effect()
        && claim.component == AGENT_COMPONENT_REPLY
        && claim.claim == reply_claim()
        && claim.domain == REPLY_DOMAIN
        && claim.kind == REPLY_CLAIM_PUBLICATION_SLOT
        && claim.scope == ClaimScope::Logical
        && claim.resource == reply_resource()
        && claim.resource_generation == resource_generation(1)
        && claim.units == 1
        && claim.retired == retired
}

fn validate_dma_claims(claims: &[ComponentClaimProjection]) -> bool {
    validate_dma_claims_for(claims, operation_effect(), dma_claims())
}

fn validate_dma_claims_for(
    claims: &[ComponentClaimProjection],
    effect: EffectId,
    expected: CoreDmaClaims,
) -> bool {
    if claims.len() != 3 {
        return false;
    }
    let Some(queue) = claims
        .iter()
        .find(|claim| claim.claim == expected.claim(ClaimRole::Queue).claim())
    else {
        return false;
    };
    let ClaimScope::Device(scope) = queue.scope else {
        return false;
    };
    [
        (ClaimRole::Queue, DEVICE_CLAIM_QUEUE_SLOT),
        (ClaimRole::PinnedPages, DEVICE_CLAIM_PINNED_PAGE),
        (ClaimRole::Iova, DEVICE_CLAIM_IOVA),
    ]
    .into_iter()
    .all(|(role, kind)| {
        let expected = expected.claim(role);
        claims.iter().any(|claim| {
            validate_dma_claim_projection(
                *claim,
                effect,
                expected,
                kind,
                ClaimScope::Device(scope),
                claim.retired,
            )
        })
    })
}

fn validate_dma_claim_projection(
    claim: ComponentClaimProjection,
    effect: EffectId,
    expected: CoreDmaClaim,
    kind: cser_core::ClaimKindId,
    scope: ClaimScope,
    retired: bool,
) -> bool {
    claim.effect == effect
        && claim.component == AGENT_COMPONENT_DMA
        && claim.claim == expected.claim()
        && claim.domain == DEVICE_DOMAIN
        && claim.kind == kind
        && claim.scope == scope
        && claim.resource == expected.resource()
        && claim.resource_generation == expected.generation()
        && claim.units == expected.units()
        && claim.retired == retired
}

fn validate_reuse_precommit(engine: &Engine) -> bool {
    let Some(composite) = engine.composite_effect(reuse_effect()) else {
        return false;
    };
    let Some(component) = engine.component(reuse_effect(), AGENT_COMPONENT_DMA) else {
        return false;
    };
    composite.effect == reuse_effect()
        && composite.kind == DMA_ARENA_REUSE_COMPOSITE
        && composite.charge_owner == operation_charge_account()
        && composite.component_count == 1
        && composite.authority == AuthorityState::Active
        && matches!(composite.custodian, CustodyState::Principal(_))
        && component.commit == CommitState::Prepared
        && component.claim_count == 3
        && component.retained_claims == 3
        && matches!(
            engine.component_claims(reuse_effect(), AGENT_COMPONENT_DMA),
            Ok(claims)
                if validate_dma_claims_for(&claims, reuse_effect(), reused_dma_claims())
                    && claims.iter().all(|claim| !claim.retired)
        )
}

fn validate_precommit_components(engine: &Engine) -> bool {
    if !validate_composite_identity(engine) {
        return false;
    }
    let Some(reply) = engine.component(operation_effect(), AGENT_COMPONENT_REPLY) else {
        return false;
    };
    let Some(dma) = engine.component(operation_effect(), AGENT_COMPONENT_DMA) else {
        return false;
    };
    if reply.commit != CommitState::Prepared
        || reply.claim_count != 1
        || dma.commit != CommitState::Prepared
        || dma.claim_count != 3
    {
        return false;
    }
    matches!(
        engine.component_claims(operation_effect(), AGENT_COMPONENT_REPLY),
        Ok(claims) if matches!(
        claims.as_slice(),
        [claim] if validate_reply_claim(*claim, false)
    )) && matches!(
        engine.component_claims(operation_effect(), AGENT_COMPONENT_DMA),
        Ok(claims) if validate_dma_claims(&claims) && claims.iter().all(|claim| !claim.retired)
    )
}

fn validate_prearm_recovery_candidate(engine: &Engine) -> bool {
    let Some(composite) = engine.composite_effect(operation_effect()) else {
        return false;
    };
    let Some(reply) = engine.component(operation_effect(), AGENT_COMPONENT_REPLY) else {
        return false;
    };
    let Some(dma) = engine.component(operation_effect(), AGENT_COMPONENT_DMA) else {
        return false;
    };
    if !validate_composite_projection(&composite)
        || composite.escape != EffectEscapeState::Unescaped
        || !matches!(
            (composite.authority, composite.custodian),
            (AuthorityState::Fenced, CustodyState::KernelEstate)
                | (AuthorityState::Active, CustodyState::Principal(_))
        )
        || !matches!(
            reply.commit,
            CommitState::Registered | CommitState::Prepared
        )
        || reply.commit_operation.is_some()
        || reply.outcome != OutcomeState::Pending
        || reply.settlement != SettlementState::Unavailable
        || reply.retirement != RetirementState::Held
        || reply.claim_count != 1
        || reply.retained_claims != 1
        || !matches!(dma.commit, CommitState::Registered | CommitState::Prepared)
        || dma.commit_operation.is_some()
        || dma.outcome != OutcomeState::Pending
        || dma.settlement != SettlementState::Unavailable
        || dma.retirement != RetirementState::Held
        || !(1..=3).contains(&dma.claim_count)
        || dma.retained_claims != dma.claim_count
    {
        return false;
    }
    let Ok(reply_claims) = engine.component_claims(operation_effect(), AGENT_COMPONENT_REPLY)
    else {
        return false;
    };
    if !matches!(
        reply_claims.as_slice(),
        [claim] if validate_reply_claim(*claim, false)
    ) {
        return false;
    }
    let Ok(dma_projections) = engine.component_claims(operation_effect(), AGENT_COMPONENT_DMA)
    else {
        return false;
    };
    if dma_projections.is_empty()
        || dma_projections.len() > 3
        || dma_projections.iter().any(|claim| claim.retired)
    {
        return false;
    }
    let expected = dma_claims();
    let ClaimScope::Device(scope) = dma_projections[0].scope else {
        return false;
    };
    dma_projections.iter().all(|claim| {
        [
            (ClaimRole::Queue, DEVICE_CLAIM_QUEUE_SLOT),
            (ClaimRole::PinnedPages, DEVICE_CLAIM_PINNED_PAGE),
            (ClaimRole::Iova, DEVICE_CLAIM_IOVA),
        ]
        .into_iter()
        .any(|(role, kind)| {
            validate_dma_claim_projection(
                *claim,
                operation_effect(),
                expected.claim(role),
                kind,
                ClaimScope::Device(scope),
                false,
            )
        })
    })
}

fn validate_committed_reply_component(engine: &Engine, checksum: Digest) -> bool {
    let Some(component) = engine.component(operation_effect(), AGENT_COMPONENT_REPLY) else {
        return false;
    };
    let outcome_matches = component.outcome == OutcomeState::KnownSuccess(checksum)
        || component.outcome == OutcomeState::Indeterminate(digest(0xc1));
    validate_composite_identity(engine)
        && component.commit == CommitState::Committed
        && outcome_matches
        && component.claim_count == 1
        && matches!(
            engine.component_claims(operation_effect(), AGENT_COMPONENT_REPLY),
            Ok(claims) if matches!(
            claims.as_slice(),
            [claim] if validate_reply_claim(
                *claim,
                component.retirement == RetirementState::Retired
            )
        ))
}

fn validate_committed_reply_with_projection<S>(
    owner: &ProductionCoreOwner<S>,
    projection: ComponentProjection,
    checksum: Digest,
) -> bool
where
    S: InstalledCore,
{
    owner.observe_engine(|engine| {
        engine.component(operation_effect(), AGENT_COMPONENT_REPLY) == Some(projection)
            && validate_committed_reply_component(engine, checksum)
            && matches!(
                projection.settlement,
                SettlementState::Open { .. }
                    | SettlementState::ReconciliationRequired { .. }
                    | SettlementState::Settled
            )
    })
}

fn ensure_uncommitted_composite_actor<S>(
    owner: &ProductionCoreOwner<S>,
    supervisor: &CoreSupervisorVNext<ProductionCoreOwner<S>>,
    effect: EffectId,
    projection: CompositeEffectProjection,
    actor: PrincipalIncarnation,
    binding_generation: u64,
) -> Result<(), &'static str>
where
    S: InstalledCore,
{
    if bound_root_identity(owner, effect.root())? != (actor, binding_generation) {
        return Err("composite-actor-binding");
    }
    match projection.authority {
        AuthorityState::Fenced if projection.custodian == CustodyState::KernelEstate => {
            expect_no_output_checked(
                supervisor
                    .adopt_effect(effect, actor, binding_generation)
                    .map_err(|_| "composite-adoption")?,
            )?;
        }
        AuthorityState::Active if projection.custodian == CustodyState::Principal(actor) => {}
        AuthorityState::Active | AuthorityState::Fenced | AuthorityState::Revoked => {
            return Err("composite-adoption-state");
        }
    }
    let live = owner.observe_engine(|engine| engine.composite_effect(effect));
    if !live.is_some_and(|composite| {
        composite.authority == AuthorityState::Active
            && composite.custodian == CustodyState::Principal(actor)
    }) {
        return Err("composite-adoption-postcondition");
    }
    Ok(())
}

fn validate_dma_component(engine: &Engine) -> bool {
    validate_dma_component_for(
        engine,
        operation_effect(),
        dma_claims(),
        AGENT_OPERATION_COMPOSITE,
        2,
    )
}

fn exact_dma_resource_generation(
    engine: &Engine,
    effect: EffectId,
    require_retired: bool,
) -> Option<u64> {
    let claims = engine.component_claims(effect, AGENT_COMPONENT_DMA).ok()?;
    let first = claims.first()?.resource_generation;
    (claims.len() == 3
        && claims
            .iter()
            .all(|claim| claim.resource_generation == first && claim.retired == require_retired))
    .then_some(first.get())
}

fn validate_dma_component_for(
    engine: &Engine,
    effect: EffectId,
    claims: CoreDmaClaims,
    composite_kind: cser_core::CompositeKindId,
    component_count: usize,
) -> bool {
    let Some(composite) = engine.composite_effect(effect) else {
        return false;
    };
    let Some(component) = engine.component(effect, AGENT_COMPONENT_DMA) else {
        return false;
    };
    let Some(arena) = persistent_dma_arena_layout() else {
        return false;
    };
    let operation = persistent_dma_arena_digest(arena);
    if composite.effect != effect
        || composite.kind != composite_kind
        || composite.charge_owner != operation_charge_account()
        || composite.component_count != component_count
        || composite.authority == AuthorityState::Revoked
        || composite.custodian == CustodyState::Released
        || component.obligation != (DEVICE_DOMAIN, DEVICE_OBLIGATION_DMA)
        || component.commit != CommitState::Committed
        || component.commit_operation != Some(operation)
        || !matches!(component.outcome, OutcomeState::KnownSuccess(digest) if !digest.is_zero())
            && component.outcome != OutcomeState::Indeterminate(operation)
        || component.settlement != SettlementState::NotRequired
        || component.claim_count != 3
        || !matches!(
            (component.retirement, component.retained_claims),
            (RetirementState::RetirementPending, 1..=3) | (RetirementState::Retired, 0)
        )
    {
        return false;
    }
    let Ok(projections) = engine.component_claims(effect, AGENT_COMPONENT_DMA) else {
        return false;
    };
    validate_dma_claims_for(&projections, effect, claims)
        && projections.iter().filter(|claim| !claim.retired).count() == component.retained_claims
}

fn classify_persistent_phase(
    engine: &Engine,
    reply_checksum: Digest,
) -> Result<PersistentPhase, &'static str> {
    if !validate_committed_reply_component(engine, reply_checksum) {
        return Err("reply-replay-projection");
    }
    if !validate_dma_component(engine) {
        return Err("dma-replay-projection");
    }
    let composite = engine
        .composite_effect(operation_effect())
        .ok_or("composite-effect-absent")?;
    if !matches!(
        composite.escape,
        EffectEscapeState::PartiallyDischarged | EffectEscapeState::Retired
    ) {
        return Err("composite-escape-projection");
    }
    if engine
        .retained_component_claims()
        .iter()
        .filter(|claim| {
            claim.effect == operation_effect()
                && claim.component == AGENT_COMPONENT_DMA
                && claim.domain == DEVICE_DOMAIN
        })
        .count()
        != 0
    {
        return Err("dma-component-not-retired");
    }
    if engine
        .component(operation_effect(), AGENT_COMPONENT_DMA)
        .is_none_or(|component| {
            component.retirement != RetirementState::Retired || component.retained_claims != 0
        })
    {
        return Err("dma-component-retirement");
    }
    let component = engine
        .component(operation_effect(), AGENT_COMPONENT_REPLY)
        .ok_or("reply-component-absent")?;
    match component.settlement {
        SettlementState::Open { .. }
            if component.retirement == RetirementState::RetirementPending
                && component.retained_claims == 1 =>
        {
            Ok(PersistentPhase::ArmSecondCrash)
        }
        SettlementState::ReconciliationRequired { applied: false, .. }
            if component.retirement == RetirementState::RetirementPending
                && component.retained_claims == 1 =>
        {
            Ok(PersistentPhase::ReconcileSecondCrash)
        }
        SettlementState::ReconciliationRequired { applied: true, .. }
            if component.retirement == RetirementState::RetirementPending
                && component.retained_claims == 1 =>
        {
            Ok(PersistentPhase::RecoverApplied)
        }
        SettlementState::Settled
            if component.retirement == RetirementState::RetirementPending
                && component.retained_claims == 1 =>
        {
            Ok(PersistentPhase::RetireDurableReply)
        }
        SettlementState::Settled
            if component.retirement == RetirementState::Retired
                && component.retained_claims == 0 =>
        {
            Ok(PersistentPhase::StableRecovery)
        }
        SettlementState::Unavailable
        | SettlementState::NotRequired
        | SettlementState::Claimed { .. }
        | SettlementState::ApplyIntentDurable { .. }
        | SettlementState::AppliedUnacknowledged { .. }
        | SettlementState::Open { .. }
        | SettlementState::ReconciliationRequired { .. }
        | SettlementState::Settled
        | SettlementState::Revoked => Err("reply-settlement-prefix-fail-closed"),
    }
}

fn runtime_metrics<S>(owner: &ProductionCoreOwner<S>) -> RuntimeMetrics
where
    S: InstalledCore,
{
    owner.observe_engine(|engine| {
        let freshness = engine.freshness();
        RuntimeMetrics {
            revision: engine.revision(),
            boot_generation: freshness.boot().get(),
            journal_generation: freshness.journal().get(),
            device_generation: freshness.device().get(),
            retained: engine.retained_component_claims().len(),
            catalog_digest: engine.catalog_digest(),
            projection_digest: engine.projection_digest(),
        }
    })
}

fn portal_tx_checked<R: CoreRegistry>(
    portal: &CorePortalVNext<R>,
    request_id: u64,
    command: CommandRequest,
) -> Result<CoreTransitionView, &'static str> {
    let request =
        PortalRequest::transact(request_id, command).map_err(|_| "portal-request-identity")?;
    let response = portal.dispatch(request).map_err(|_| "portal-transition")?;
    if response.request_id() != request_id {
        return Err("portal-response-identity");
    }
    match response.body() {
        PortalResponseBody::Transition(view) => Ok(*view),
        PortalResponseBody::Observation(_) => Err("portal-response-kind"),
    }
}

fn owner_tx_checked<S, C>(
    owner: &ProductionCoreOwner<S>,
    command: C,
) -> Result<TransitionReceipt, &'static str>
where
    S: InstalledCore,
    C: Into<Command>,
{
    owner
        .transact_trusted(command)
        .map_err(|_| "trusted-transition")
}

fn expect_no_output_checked(receipt: TransitionReceipt) -> Result<(), &'static str> {
    match receipt.into_output() {
        TransitionOutput::None => Ok(()),
        _ => Err("unexpected-linear-output"),
    }
}

fn settlement_claim_checked(receipt: TransitionReceipt) -> Result<SettlementClaim, &'static str> {
    match receipt.into_output() {
        TransitionOutput::SettlementClaim(claim) => Ok(claim),
        _ => Err("settlement-output-kind"),
    }
}

fn commit_intent_checked(receipt: TransitionReceipt) -> Result<CommitIntent, &'static str> {
    match receipt.into_output() {
        TransitionOutput::CommitIntent(intent) => Ok(intent),
        _ => Err("commit-intent-output-kind"),
    }
}

fn reuse_permit_checked(receipt: TransitionReceipt) -> Result<ReusePermit, &'static str> {
    match receipt.into_output() {
        TransitionOutput::ReusePermit(permit) => Ok(permit),
        _ => Err("reuse-permit-output-kind"),
    }
}

fn validate_reuse_permit(
    permit: ReusePermit,
    old: CoreDmaClaim,
    new: CoreDmaClaim,
    arena: PersistentDmaArenaLayout,
) -> Result<ReusePermit, &'static str> {
    if permit.effect() != reuse_effect()
        || permit.component() != Some(AGENT_COMPONENT_DMA)
        || permit.resource() != new.resource()
        || permit.claim() != new.claim()
        || permit.previous_generation() != old.generation()
        || permit.generation() != new.generation()
        || permit.catalog_digest() != cser_core::standard_catalog().digest()
        || permit.retirement_digest().is_zero()
        || permit.reuse_contract() != persistent_dma_arena_digest(arena)
    {
        return Err("dma-reuse-permit-coordinate");
    }
    Ok(permit)
}

fn fail_closed<T>(reason: &'static str, owners: T) -> ! {
    println!(
        "CSER_CORE_PERSISTENT_FAIL_CLOSED reason={} activation=blocked \
         queue_republish=false page_iova_reuse=false qemu=true \
         physical_antirollback=false physical_powerloss=false physical_dma_custody=false",
        reason,
    );
    poweroff_retaining(owners)
}

fn dma_claims() -> CoreDmaClaims {
    CoreDmaClaims::new(
        CoreDmaClaim::new(
            claim_id(0xd101),
            resource(0xd100_0001),
            resource_generation(1),
            1,
        ),
        CoreDmaClaim::new(
            claim_id(0xd102),
            resource(0xd100_0002),
            resource_generation(1),
            3,
        ),
        CoreDmaClaim::new(
            claim_id(0xd103),
            resource(0xd100_0003),
            resource_generation(1),
            3,
        ),
    )
}

fn reused_dma_claims() -> CoreDmaClaims {
    CoreDmaClaims::new(
        CoreDmaClaim::new(
            claim_id(0xd201),
            resource(0xd100_0001),
            resource_generation(2),
            1,
        ),
        CoreDmaClaim::new(
            claim_id(0xd202),
            resource(0xd100_0002),
            resource_generation(2),
            3,
        ),
        CoreDmaClaim::new(
            claim_id(0xd203),
            resource(0xd100_0003),
            resource_generation(2),
            3,
        ),
    )
}

fn reply_coordinate() -> ReplyCoordinate {
    ReplyCoordinate::new_component(
        operation_effect(),
        AGENT_COMPONENT_REPLY,
        reply_claim(),
        reply_resource(),
        resource_generation(1),
    )
}

fn operation_root() -> RootId {
    root(0xc501)
}

fn operation_effect() -> EffectId {
    EffectId::new(operation_root(), 1).expect("agent operation effect is non-zero")
}

fn reuse_effect() -> EffectId {
    EffectId::new(operation_root(), REUSE_EFFECT_SEQUENCE)
        .expect("DMA reuse effect identity is non-zero")
}

fn operation_origin() -> PrincipalIncarnation {
    principal(0xc501, 1)
}

fn operation_charge_account() -> ChargeAccountId {
    charge_account(0xc501)
}

fn reply_claim() -> ClaimId {
    claim_id(0xc511)
}

fn reply_resource() -> ResourceId {
    resource(0xc521)
}

fn root(value: u64) -> RootId {
    RootId::new(value).expect("root identity is non-zero")
}

fn claim_id(value: u64) -> ClaimId {
    ClaimId::new(value).expect("claim identity is non-zero")
}

fn resource(value: u64) -> ResourceId {
    ResourceId::new(value).expect("resource identity is non-zero")
}

fn resource_generation(value: u64) -> ResourceGeneration {
    ResourceGeneration::new(value).expect("resource generation is non-zero")
}

fn charge_account(value: u64) -> ChargeAccountId {
    ChargeAccountId::new(value).expect("charge account is non-zero")
}

fn principal(value: u64, generation: u64) -> PrincipalIncarnation {
    PrincipalIncarnation::new(
        PrincipalId::new(value).expect("principal identity is non-zero"),
        generation,
    )
    .expect("principal generation is non-zero")
}

fn digest(tag: u8) -> Digest {
    let mut bytes = [0; 32];
    bytes[0] = tag;
    Digest::new(bytes)
}

fn poweroff_retaining<T>(_owners: T) -> ! {
    poweroff(ExitCode::Success)
}
