// SPDX-License-Identifier: MPL-2.0

//! Combined persistent CSER restart profile.
//!
//! Boot one commits one reply through the dedicated ATA outbox and publishes
//! one real VirtIO request while the same recovered runtime owns both domain
//! transitions. Boot two replays the exact journal and TPM state under an
//! unreleased quarantine guard, consumes only the reset/ISR evidence sufficient
//! to retire the queue claim, and crashes after durably recording the reply's
//! external-apply intent. Boot three reconciles that intent without recording a
//! second one, applies and settles the reply, and retains the page and IOVA
//! claims. Boot four proves the same settled projection is stable without
//! duplicate reply or DMA evidence. The boot-global IOTLB observation does not
//! establish crash-persistent custody or authorize page/IOVA reuse.

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use cser_core::{
    AuthorityState, ChargeAccountId, ClaimId, ClaimProjection, ClaimScope, Command, CommandRequest,
    CommitState, CoordinatedPersistence, CoreError, CoreLimits, CustodyState, DEVICE_CLAIM_IOVA,
    DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT, DEVICE_DOMAIN, DEVICE_EVIDENCE_IRQ_DRAINED,
    DEVICE_EVIDENCE_RESET, DEVICE_OBLIGATION_DMA, DeviceGeneration, Digest, EffectId, Engine,
    EstateProjection, OutcomeState, PrincipalId, PrincipalIncarnation,
    REPLY_CLAIM_PUBLICATION_SLOT, REPLY_DOMAIN, REPLY_OBLIGATION_PUBLICATION, RecoveryBinding,
    RegistryInstance, ResourceGeneration, ResourceId, RetirementState, RootId, RootRecoveryState,
    SettlementClaim, SettlementState, SnapshotId, TransitionDurability, TransitionOutput,
    TransitionReceipt, TxError, standard_catalog,
};
use nexus_ostd_virtio::{
    BootQuarantineGuard, MaskedIntx, ProductionDevice, PublishedRequest, Root,
};
use ostd::{
    power::{ExitCode, poweroff},
    prelude::*,
    sync::{Mutex, SpinLock},
    task::{Task, TaskOptions, inject_post_task_exit_handler},
};

use super::{
    core_device_quarantine::{
        OstdBootClaimVerifier, OstdBootIrqVerifier, OstdVirtioBootQuarantine,
        project_replayed_claim,
    },
    core_dma_adapter::{
        ClaimRole, CoreDmaClaim, CoreDmaClaims, CoreDmaCohort, bind_queue_commit,
        publish_real_queue,
    },
    core_pio_journal::{AtaJournalFixture, AtaPioJournal},
    core_portal_vnext::{
        CorePortalVNext, CoreQuery, CoreRegistry, CoreTransitionView, PortalDispatchError,
        PortalRequest, PortalResponseBody,
    },
    core_production_registry::{
        InstalledCore, ProductionCoreOwner, ProductionIngressError, ProductionIngressExitObserver,
        ProductionIngressIdentity, ProductionIngressTaskData, ProductionRegistryError,
    },
    core_reboot::{
        BootActivationBlock, BootActivationFailure, QuarantinedRecoveredBoot,
        recover_quarantined_boot,
    },
    core_reply_adapter::{
        ReplyAckError, ReplyCoordinate, ReplyCustody, ReplyPlan, reply_pair, reply_plan,
    },
    core_reply_outbox::{
        AtaPioReplyOutbox, ReplyCommitInspection, ReplyOutboxCommitVerifier, ReplyOutboxIdentity,
    },
    core_runtime::OstdCserRuntime,
    core_supervisor_vnext::{CORE_SUPERVISOR_PROTOCOL, CoreSupervisorVNext},
    core_tpm_anchor::{QemuTisTpm2, TpmNvIndexAuth, TpmNvLayout, TpmNvTrustedAnchor},
};

type PersistentAnchor = TpmNvTrustedAnchor<QemuTisTpm2>;
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
const REPLY_VALUE: u64 = 0xc5e2;
const MAX_TASK_TURNS: usize = 100_000;
const SERVICE_CREATED: u8 = 0;
const SERVICE_ENTERED: u8 = 1;
const SERVICE_READY: u8 = 2;
const SERVICE_REBOUND: u8 = 3;
const SERVICE_DOMAIN_COMPLETE: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistentPhase {
    ArmSecondCrash,
    ReconcileSecondCrash,
    StableRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionServiceStage {
    InitialReplyPublication,
    InitialDmaPublication,
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

struct InitialReplyOutput {
    outbox: AtaPioReplyOutbox,
    checksum: Digest,
    resumed_prefix: bool,
}

struct InitialDmaOutput {
    root: Root,
    masked_intx: MaskedIntx,
    device: ProductionDevice,
    request: PublishedRequest,
}

struct ArmSecondCrashOutput {
    outbox: AtaPioReplyOutbox,
    checksum: Digest,
    resumed_prefix: bool,
}

struct ArmedSecondCrash {
    client: Arc<Task>,
    service: ProductionServiceRun,
    outbox: AtaPioReplyOutbox,
    checksum: Digest,
    resumed_prefix: bool,
    successor: PrincipalIncarnation,
    binding_generation: u64,
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

    fn claim_settlement(&self, effect: EffectId) -> Result<SettlementClaim, &'static str> {
        self.authorize_ingress()?;
        let supervisor = CoreSupervisorVNext::new(Arc::clone(&self.owner));
        settlement_claim_checked(
            supervisor
                .claim_settlement(effect, self.identity.ingress.incarnation())
                .map_err(|_| "service-settlement-claim")?,
        )
    }

    fn verify_portal_observation(
        &self,
        request_id: u64,
        effect: EffectId,
    ) -> Result<(), &'static str> {
        self.authorize_ingress()?;
        let portal = CorePortalVNext::new(Arc::clone(&self.owner));
        let request = PortalRequest::observe(request_id, CoreQuery::Estate(effect))
            .map_err(|_| "service-portal-observation-request")?;
        let response = portal
            .dispatch(request)
            .map_err(|_| "service-portal-observation-dispatch")?;
        match response.body() {
            PortalResponseBody::Observation(_) => Ok(()),
            PortalResponseBody::Transition(_) => Err("service-portal-observation-kind"),
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
) -> Result<(), &'static str> {
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

    let transport = match QemuTisTpm2::acquire_qemu_fixture() {
        Ok(transport) => transport,
        Err(error) => fail_closed("tpm2-transport-unavailable", error),
    };
    let auth = match TpmNvIndexAuth::new(&[]) {
        Ok(auth) => auth,
        Err(error) => fail_closed("tpm2-index-auth-invalid", error),
    };
    let anchor =
        match TpmNvTrustedAnchor::open(transport, TpmNvLayout::qemu_fixture(), auth, binding) {
            Ok(anchor) => anchor,
            Err(error) => fail_closed("tpm2-anchor-open", error),
        };
    let trusted_device_high_water = anchor
        .committed()
        .committed_freshness()
        .device()
        .get()
        .max(anchor.issued().device().get());
    let Some(next_device_generation) = trusted_device_high_water.checked_add(1) else {
        fail_closed("device-generation-overflow", anchor);
    };
    let observed_generation = match DeviceGeneration::new(next_device_generation) {
        Ok(generation) => generation,
        Err(error) => fail_closed("device-generation-invalid", (anchor, error)),
    };

    let journal = match AtaPioJournal::acquire(AtaJournalFixture::PrimaryMaster) {
        Ok(journal) => journal,
        Err(error) => fail_closed("ata-journal-unavailable", (anchor, error)),
    };
    let boot = match recover_quarantined_boot(
        catalog,
        CoreLimits::bounded_default(),
        binding,
        journal,
        anchor,
        OstdVirtioBootQuarantine::new(observed_generation),
    ) {
        Ok(boot) => boot,
        Err(error) => fail_closed("anchored-replay", error),
    };

    let can_activate = boot.observe(|engine| {
        engine
            .retained_claims()
            .iter()
            .all(|claim| claim.domain != DEVICE_DOMAIN)
            && engine.estate(dma_effect()).is_none()
    });
    if can_activate {
        run_activation_boot(boot)
    } else {
        run_quarantined_boot(boot)
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
    let owner = Arc::new(ProductionCoreOwner::new(PersistentRuntime::from_engine(
        engine,
        persistence,
    )));
    let supervisor_owner = Arc::clone(&owner);
    let supervisor = CoreSupervisorVNext::new(supervisor_owner);
    if supervisor.protocol() != CORE_SUPERVISOR_PROTOCOL {
        fail_closed("supervisor-protocol", (owner, supervisor, devices));
    }

    let outbox = match AtaPioReplyOutbox::acquire_secondary_master() {
        Ok(outbox) => outbox,
        Err(_) => fail_closed("reply-outbox-open", (owner, supervisor, devices)),
    };

    let reply_identity = match prepare_production_service(
        &owner,
        &supervisor,
        reply_root(),
        reply_origin(),
        ProductionServiceStage::InitialReplyPublication,
    ) {
        Ok(identity) => identity,
        Err(reason) => fail_closed(reason, (owner, supervisor, devices, outbox)),
    };
    let reply_output = Arc::new(OneShot::new());
    let task_reply_output = Arc::clone(&reply_output);
    let reply_run = match build_production_service(&owner, reply_identity, move |ingress| {
        if ingress.identity.snapshot.is_some() {
            ingress.ready_and_wait_for_rebind()?;
        }
        let portal = CorePortalVNext::new(Arc::clone(&ingress.owner));
        let supervisor = CoreSupervisorVNext::new(Arc::clone(&ingress.owner));
        let mut outbox = outbox;
        let (checksum, resumed_prefix) =
            ensure_reply_committed(&portal, &supervisor, &ingress.owner, &mut outbox)?;
        if ingress.identity.snapshot.is_some() {
            ingress.complete_rebound_domain()?;
        } else {
            ingress.complete_initial_domain()?;
        }
        task_reply_output.publish(InitialReplyOutput {
            outbox,
            checksum,
            resumed_prefix,
        });
        Ok(ProductionServiceDisposition::ExitAfterCompletion)
    }) {
        Ok(run) => run,
        Err(reason) => fail_closed(reason, (owner, supervisor, devices)),
    };
    if let Err(reason) = start_prepared_service(&owner, &supervisor, &reply_run) {
        fail_closed(reason, (owner, supervisor, devices, reply_run));
    }
    if let Err(reason) = wait_service_completion(&reply_run) {
        fail_closed(reason, (owner, supervisor, devices, reply_run));
    }
    let InitialReplyOutput {
        outbox,
        checksum: reply_checksum,
        resumed_prefix,
    } = match reply_output.wait_take_bounded() {
        Some(output) => output,
        None => fail_closed(
            "reply-service-output-timeout",
            (owner, supervisor, devices, reply_run),
        ),
    };
    if let Err(reason) = wait_exact_service_exit(&owner, &reply_run) {
        fail_closed(reason, (owner, supervisor, devices, outbox, reply_run));
    }
    let closed_reply_portal = CorePortalVNext::new(Arc::clone(&owner));
    if let Err(reason) = verify_closed_portal_rejection(
        &owner,
        &closed_reply_portal,
        0xc501_00ff,
        CommandRequest::PrepareEffect {
            effect: reply_effect(),
            actor: reply_origin(),
            binding_generation: 1,
        },
    ) {
        fail_closed(
            reason,
            (
                owner,
                supervisor,
                devices,
                outbox,
                reply_run,
                closed_reply_portal,
            ),
        );
    }

    let (root, masked_intx, device) = devices.into_parts();
    let dma_identity = match prepare_production_service(
        &owner,
        &supervisor,
        dma_root(),
        dma_origin(),
        ProductionServiceStage::InitialDmaPublication,
    ) {
        Ok(identity) => identity,
        Err(reason) => fail_closed(
            reason,
            (owner, supervisor, outbox, root, masked_intx, device),
        ),
    };
    let dma_output = Arc::new(OneShot::new());
    let task_dma_output = Arc::clone(&dma_output);
    let dma_run = match build_production_service(&owner, dma_identity, move |ingress| {
        if ingress.identity.snapshot.is_some() {
            ingress.ready_and_wait_for_rebind()?;
        }
        let portal = CorePortalVNext::new(Arc::clone(&ingress.owner));
        let (root, masked_intx, device, request) =
            publish_first_boot_dma(&portal, &ingress.owner, root, masked_intx, device)?;
        if ingress.identity.snapshot.is_some() {
            ingress.complete_rebound_domain()?;
        } else {
            ingress.complete_initial_domain()?;
        }
        task_dma_output.publish(InitialDmaOutput {
            root,
            masked_intx,
            device,
            request,
        });
        Ok(ProductionServiceDisposition::ExitAfterCompletion)
    }) {
        Ok(run) => run,
        Err(reason) => fail_closed(reason, (owner, supervisor, outbox)),
    };
    if let Err(reason) = start_prepared_service(&owner, &supervisor, &dma_run) {
        fail_closed(reason, (owner, supervisor, outbox, dma_run));
    }
    if let Err(reason) = wait_service_completion(&dma_run) {
        fail_closed(reason, (owner, supervisor, outbox, dma_run));
    }
    let InitialDmaOutput {
        root,
        masked_intx,
        device,
        request,
    } = match dma_output.wait_take_bounded() {
        Some(output) => output,
        None => fail_closed(
            "dma-service-output-timeout",
            (owner, supervisor, outbox, dma_run),
        ),
    };
    if let Err(reason) = wait_exact_service_exit(&owner, &dma_run) {
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
                dma_run,
            ),
        );
    }
    let closed_dma_portal = CorePortalVNext::new(Arc::clone(&owner));
    if let Err(reason) = verify_closed_portal_rejection(
        &owner,
        &closed_dma_portal,
        0xd001_00ff,
        CommandRequest::PrepareEffect {
            effect: dma_effect(),
            actor: dma_origin(),
            binding_generation: 1,
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
                dma_run,
                closed_dma_portal,
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
    let (revision, boot_generation, journal_generation, device_generation, retained) = owner
        .observe_engine(|engine| {
            let freshness = engine.freshness();
            (
                engine.revision(),
                freshness.boot().get(),
                freshness.journal().get(),
                freshness.device().get(),
                engine.retained_claims().len(),
            )
        });
    let state_is_exact = owner.observe_engine(|engine| {
        validate_committed_reply(engine, reply_checksum)
            && validate_dma_estate(engine)
            && engine
                .retained_claims()
                .iter()
                .filter(|claim| claim.domain == DEVICE_DOMAIN)
                .count()
                == 3
    });
    if retained != 4 || device.device_generation() != device_generation || !state_is_exact {
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
         portal=nxp3 supervisor=core-v1 reply=committed-unsettled \
         dma=queue-published-retained retained={} dma_retained=3 resumed_prefix={} \
         service_principal_generation={} binding_generation={} \
         reply_service_task=true reply_service_death=task-return reply_exact_reap=true \
         dma_service_task=true dma_service_death=task-return dma_exact_reap=true \
         ingress_latch=closed closed_ingress_rejected=true production_rebind=initial \
         revision={} boot={} journal={} device={} \
         journal_provider=ata-pio outbox_provider=ata-pio-secondary anchor_provider=tpm2-nv \
         quarantine=pre-replay-virtio+global-iotlb qemu=true physical_antirollback=false \
         physical_powerloss=false physical_dma_custody=false",
        retained,
        resumed_prefix,
        reply_run.identity.ingress.incarnation().generation(),
        reply_run.identity.ingress.binding_generation(),
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

fn ensure_reply_committed<S>(
    portal: &CorePortalVNext<ProductionCoreOwner<S>>,
    supervisor: &CoreSupervisorVNext<ProductionCoreOwner<S>>,
    owner: &ProductionCoreOwner<S>,
    outbox: &mut AtaPioReplyOutbox,
) -> Result<(Digest, bool), &'static str>
where
    S: InstalledCore + 'static,
{
    let effect = reply_effect();
    let plan =
        reply_plan(reply_coordinate(), REPLY_SEQUENCE, REPLY_VALUE).map_err(|_| "reply-plan")?;
    let inspected = inspect_reply_outbox(outbox, plan)?;
    let mut resumed_prefix = false;
    let mut estate = owner.observe_engine(|engine| engine.estate(effect));
    if estate.is_none() {
        if inspected.is_some() {
            return Err("outbox-without-reply-estate");
        }
        portal_tx_checked(
            portal,
            0xc501_0001,
            CommandRequest::CreateEstate {
                effect,
                origin: reply_origin(),
                binding_generation: 1,
                domain: REPLY_DOMAIN,
                obligation: REPLY_OBLIGATION_PUBLICATION,
                charge_account: charge_account(0xc501),
            },
        )?;
        estate = owner.observe_engine(|engine| engine.estate(effect));
    } else {
        resumed_prefix = true;
    }

    let projection = estate.ok_or("reply-estate-disappeared")?;
    if !validate_reply_identity(projection) {
        return Err("reply-estate-identity");
    }
    if projection.commit == CommitState::Committed {
        let checksum = inspected.ok_or("committed-reply-outbox-absent")?;
        if !validate_committed_reply_with_projection(owner, projection, checksum) {
            return Err("committed-reply-projection");
        }
        return Ok((checksum, resumed_prefix));
    }
    if !matches!(
        projection.commit,
        CommitState::Registered | CommitState::Prepared
    ) || projection.settlement != SettlementState::Unavailable
        || projection.outcome != OutcomeState::Pending
        || projection.retirement != RetirementState::Held
        || inspected.is_some()
    {
        return Err("reply-prefix-not-resumable");
    }

    let (actor, binding_generation) =
        ensure_uncommitted_reply_actor(owner, supervisor, projection)?;
    let mut commit = projection.commit;
    if commit == CommitState::Registered {
        let claims = owner
            .observe_engine(|engine| engine.claims(effect))
            .map_err(|_| "reply-claims-query")?;
        match claims.as_slice() {
            [] => {
                portal_tx_checked(
                    portal,
                    0xc501_0002,
                    CommandRequest::AddClaim {
                        effect,
                        actor,
                        binding_generation,
                        claim: reply_claim(),
                        domain: REPLY_DOMAIN,
                        kind: REPLY_CLAIM_PUBLICATION_SLOT,
                        scope: ClaimScope::Logical,
                        resource: reply_resource(),
                        resource_generation: resource_generation(1),
                        units: 1,
                    },
                )?;
            }
            [claim] if validate_reply_claim(*claim, false) => {}
            _ => return Err("reply-prefix-claims"),
        }
        portal_tx_checked(
            portal,
            0xc501_0003,
            CommandRequest::PrepareEffect {
                effect,
                actor,
                binding_generation,
            },
        )?;
        commit = CommitState::Prepared;
    }
    if commit != CommitState::Prepared || !owner.observe_engine(validate_precommit_reply_claim) {
        return Err("reply-prefix-prepare");
    }
    portal_tx_checked(
        portal,
        0xc501_0004,
        CommandRequest::RecordCommitIntent {
            effect,
            actor,
            binding_generation,
            operation: digest(0xc1),
        },
    )?;
    let intent = owner
        .take_commit_intent(effect)
        .ok_or("reply-commit-intent-custody")?;
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
    if !owner.observe_engine(|engine| validate_committed_reply(engine, checksum)) {
        return Err("reply-commit-postcondition");
    }
    Ok((checksum, resumed_prefix))
}

// The post-publication error owns the real queue request and the core intent.
// Boxing it could fail after the device-visible commit and discard authority.
#[allow(clippy::result_large_err)]
fn publish_first_boot_dma(
    portal: &CorePortalVNext<ActiveProductionOwner>,
    owner: &ActiveProductionOwner,
    mut root: Root,
    masked_intx: MaskedIntx,
    mut device: ProductionDevice,
) -> Result<(Root, MaskedIntx, ProductionDevice, PublishedRequest), &'static str> {
    let prepared = device
        .prepare_read_sector0(&mut root)
        .map_err(|_| "dma-prepare")?;
    let receipted = device
        .issue_preparation_receipt(prepared)
        .map_err(|_| "dma-preparation-receipt")?;
    let cohort = CoreDmaCohort::bind(
        dma_effect(),
        dma_origin(),
        1,
        charge_account(0xd001),
        receipted.identity(),
        dma_claims(),
    )
    .map_err(|_| "dma-cohort-binding")?;

    portal_tx_checked(portal, 0xd001_0001, cohort.create_estate())?;
    for (index, claim) in cohort.enroll_claims().into_iter().enumerate() {
        portal_tx_checked(portal, 0xd001_0010 + index as u64, claim)?;
    }
    portal_tx_checked(portal, 0xd001_0020, cohort.prepare())?;
    portal_tx_checked(
        portal,
        0xd001_0021,
        cohort.record_commit_intent(digest(0xd1)),
    )?;
    let intent = owner
        .take_commit_intent(dma_effect())
        .ok_or("dma-commit-intent-custody")?;
    let authority = owner
        .observe_engine(move |engine| bind_queue_commit(engine, intent, cohort))
        .map_err(|_| "dma-commit-binding")?;
    let published =
        publish_real_queue(&device, receipted, authority).map_err(|_| "dma-queue-publication")?;
    let committed = owner
        .observe_engine(move |engine| published.verify_commit(engine))
        .map_err(|_| "dma-queue-commit-verify")?;
    let (request, acknowledgement) = committed.into_parts();
    expect_no_output_checked(owner_tx_checked(owner, acknowledgement)?)?;
    Ok((root, masked_intx, device, request))
}

fn run_quarantined_boot(boot: PersistentBoot) -> ! {
    if boot.activation_block() != Some(BootActivationBlock::DeviceClaimsRetained) {
        fail_closed("quarantine-without-device-tombstone", boot);
    }
    let owner = Arc::new(ProductionCoreOwner::new(QuarantinedPersistentCore::new(
        boot,
    )));
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
    let reply_is_uncommitted = owner.observe_engine(|engine| {
        engine.estate(reply_effect()).is_some_and(|estate| {
            matches!(
                estate.commit,
                CommitState::Registered | CommitState::Prepared
            )
        })
    });
    let plan = match reply_plan(reply_coordinate(), REPLY_SEQUENCE, REPLY_VALUE) {
        Ok(plan) => plan,
        Err(_) => fail_closed(
            "reply-plan",
            (owner, supervisor, reply_owner, dma_owner, outbox),
        ),
    };
    let reply_checksum = match inspect_reply_outbox(&mut outbox, plan) {
        Ok(checksum) => checksum,
        Err(reason) => fail_closed(reason, (owner, supervisor, reply_owner, dma_owner, outbox)),
    };

    let dma_report = match reconcile_dma_tombstones(&dma_owner) {
        Ok(report) => report,
        Err(reason) => fail_closed(reason, (owner, supervisor, reply_owner, dma_owner, outbox)),
    };
    let phase = if reply_is_uncommitted {
        PersistentPhase::ArmSecondCrash
    } else {
        let checksum = match reply_checksum {
            Some(checksum) => checksum,
            None => fail_closed(
                "committed-reply-outbox-absent",
                (owner, supervisor, reply_owner, dma_owner, outbox),
            ),
        };
        match owner.observe_engine(|engine| classify_persistent_phase(engine, checksum)) {
            Ok(phase) => phase,
            Err(reason) => fail_closed(reason, (owner, supervisor, reply_owner, dma_owner, outbox)),
        }
    };
    if dma_report.resource_reuse_authorized
        || !validate_dma_reuse_boundary(&owner)
        || owner.installed().activation_block() != Some(BootActivationBlock::DeviceClaimsRetained)
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
                client,
                service,
                outbox,
                checksum: reply_checksum,
                resumed_prefix,
                successor,
                binding_generation,
            } = match arm_reply_second_crash(&reply_owner, &supervisor, plan, outbox) {
                Ok(armed) => armed,
                Err(reason) => fail_closed(reason, (owner, supervisor, reply_owner, dma_owner)),
            };
            let (revision, boot_generation, journal_generation, device_generation, retained) =
                runtime_metrics(&owner);
            let exact = owner.observe_engine(|engine| {
                engine.estate(reply_effect()).is_some_and(|estate| {
                    validate_committed_reply(engine, reply_checksum)
                        && matches!(
                            estate.settlement,
                            SettlementState::ApplyIntentDurable { .. }
                        )
                        && estate.retirement == RetirementState::RetirementPending
                        && estate.retained_claims == 1
                })
            });
            if retained != 3 || !exact {
                fail_closed(
                    "boot2-postcondition",
                    (
                        owner,
                        supervisor,
                        reply_owner,
                        dma_owner,
                        outbox,
                        client,
                        service,
                    ),
                );
            }
            println!(
                "CSER_CORE_PERSISTENT_BOOT2 PASS shared_runtime=true production_registry=single \
                 portal=nxp3 supervisor=core-v1 reply=apply-intent-durable \
                 second_crash=service-exact-reap no_external_apply=true dma_queue=retired \
                 dma_queue_resource=scope-quarantined dma_pages_iova=retained \
                 retained={} dma_retained=2 activation=blocked \
                 resource_reuse_authorized=false reset_submitted={} irq_submitted={} \
                 service_principal_generation={} successor_generation={} binding_generation={} \
                 fresh_service_task=true ready_in_fresh_task=true production_rebind=true \
                 service_death=task-return exact_reap=true ingress_latch=closed \
                 closed_ingress_rejected=true resumed_prefix={} \
                 revision={} boot={} journal={} device={} journal_provider=ata-pio \
                 outbox_provider=ata-pio-secondary anchor_provider=tpm2-nv \
                 quarantine=pre-replay-virtio+global-iotlb qemu=true \
                 physical_antirollback=false physical_powerloss=false \
                 physical_dma_custody=false",
                retained,
                dma_report.reset_submitted,
                dma_report.irq_submitted,
                successor.generation(),
                successor.generation(),
                binding_generation,
                resumed_prefix,
                revision,
                boot_generation,
                journal_generation,
                device_generation,
            );
            poweroff_retaining((
                owner,
                supervisor,
                reply_owner,
                dma_owner,
                outbox,
                client,
                service,
            ))
        }
        PersistentPhase::ReconcileSecondCrash => {
            let (client, service, successor, binding_generation) =
                match reconcile_reply_after_second_crash(&reply_owner, &supervisor, plan) {
                    Ok(recovered) => recovered,
                    Err(reason) => {
                        fail_closed(reason, (owner, supervisor, reply_owner, dma_owner, outbox))
                    }
                };
            let (revision, boot_generation, journal_generation, device_generation, retained) =
                runtime_metrics(&owner);
            let exact = owner.observe_engine(|engine| {
                engine.estate(reply_effect()).is_some_and(|estate| {
                    estate.settlement == SettlementState::Settled
                        && estate.retirement == RetirementState::Retired
                        && estate.retained_claims == 0
                })
            });
            if retained != 2 || !exact {
                fail_closed(
                    "boot3-postcondition",
                    (
                        owner,
                        supervisor,
                        reply_owner,
                        dma_owner,
                        outbox,
                        client,
                        service,
                    ),
                );
            }
            println!(
                "CSER_CORE_PERSISTENT_BOOT3 PASS shared_runtime=true production_registry=single \
                 portal=nxp3 supervisor=core-v1 reply=settled-after-second-crash \
                 reconciliation=true second_apply_intent=false dma_queue=retired \
                 dma_queue_resource=scope-quarantined dma_pages_iova=retained \
                 retained={} dma_retained=2 activation=blocked \
                 resource_reuse_authorized=false reset_submitted={} irq_submitted={} \
                 service_principal_generation={} successor_generation={} binding_generation={} \
                 fresh_service_task=true ready_in_fresh_task=true production_rebind=true \
                 service_state=live ingress_latch=open prior_service_fence=boot-checkpoint \
                 revision={} boot={} journal={} device={} journal_provider=ata-pio \
                 outbox_provider=ata-pio-secondary anchor_provider=tpm2-nv \
                 quarantine=pre-replay-virtio+global-iotlb qemu=true \
                 physical_antirollback=false physical_powerloss=false \
                 physical_dma_custody=false",
                retained,
                dma_report.reset_submitted,
                dma_report.irq_submitted,
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
                reply_owner,
                dma_owner,
                outbox,
                client,
                service,
            ))
        }
        PersistentPhase::StableRecovery => {
            let (service, successor, binding_generation) =
                match bind_stable_recovery_service(&reply_owner, &supervisor) {
                    Ok(recovered) => recovered,
                    Err(reason) => {
                        fail_closed(reason, (owner, supervisor, reply_owner, dma_owner, outbox))
                    }
                };
            let (revision, boot_generation, journal_generation, device_generation, retained) =
                runtime_metrics(&owner);
            if retained != 2 || dma_report.reset_submitted != 0 || dma_report.irq_submitted != 0 {
                fail_closed(
                    "boot4-postcondition",
                    (owner, supervisor, reply_owner, dma_owner, outbox, service),
                );
            }
            println!(
                "CSER_CORE_PERSISTENT_BOOT4 PASS shared_runtime=true production_registry=single \
                 portal=nxp3 supervisor=core-v1 reply=settled repeated_recovery=stable \
                 duplicate_apply_intent=false duplicate_dma_evidence=false dma_queue=retired \
                 dma_queue_resource=scope-quarantined dma_pages_iova=retained \
                 retained={} dma_retained=2 activation=blocked \
                 resource_reuse_authorized=false reset_submitted=0 irq_submitted=0 \
                 service_principal_generation={} successor_generation={} binding_generation={} \
                 fresh_service_task=true ready_in_fresh_task=true production_rebind=true \
                 service_state=live ingress_latch=open prior_service_fence=boot-checkpoint \
                 revision={} boot={} journal={} device={} journal_provider=ata-pio \
                 outbox_provider=ata-pio-secondary anchor_provider=tpm2-nv \
                 quarantine=pre-replay-virtio+global-iotlb qemu=true \
                 physical_antirollback=false physical_powerloss=false \
                 physical_dma_custody=false",
                retained,
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
    outbox: AtaPioReplyOutbox,
) -> Result<ArmedSecondCrash, &'static str> {
    let identity = prepare_production_service(
        owner,
        supervisor,
        reply_root(),
        reply_origin(),
        ProductionServiceStage::ArmSecondCrash,
    )?;
    if identity.snapshot.is_none() {
        return Err("second-crash-service-not-fresh");
    }
    let successor = identity.ingress.incarnation();
    let binding_generation = identity.ingress.binding_generation();
    let (client, custody, _result) = spawn_reply_client(reply_coordinate())?;
    if custody
        .plan(REPLY_SEQUENCE, REPLY_VALUE)
        .map_err(|_| "reply-custody-plan")?
        != plan
    {
        return Err("reply-custody-plan-mismatch");
    }
    let output = Arc::new(OneShot::new());
    let task_output = Arc::clone(&output);
    let run = build_production_service(owner, identity, move |ingress| {
        ingress.ready_and_wait_for_rebind()?;
        let portal = CorePortalVNext::new(Arc::clone(&ingress.owner));
        let task_supervisor = CoreSupervisorVNext::new(Arc::clone(&ingress.owner));
        let mut outbox = outbox;
        let (checksum, resumed_prefix) =
            ensure_reply_committed(&portal, &task_supervisor, &ingress.owner, &mut outbox)?;
        ingress.verify_portal_observation(0xc501_0100, reply_effect())?;
        let settlement = ingress.claim_settlement(reply_effect())?;
        let command = settlement
            .record_apply_intent(plan.intent_digest())
            .map_err(|_| "reply-apply-intent-command")?;
        let _settlement = settlement_claim_checked(ingress.transact(command)?)?;
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
        CommandRequest::PrepareEffect {
            effect: reply_effect(),
            actor: successor,
            binding_generation,
        },
    )?;
    Ok(ArmedSecondCrash {
        client,
        service: run,
        outbox,
        checksum,
        resumed_prefix,
        successor,
        binding_generation,
    })
}

fn reconcile_reply_after_second_crash(
    owner: &Arc<QuarantinedProductionOwner>,
    supervisor: &CoreSupervisorVNext<QuarantinedProductionOwner>,
    plan: ReplyPlan,
) -> Result<(Arc<Task>, ProductionServiceRun, PrincipalIncarnation, u64), &'static str> {
    let identity = prepare_production_service(
        owner,
        supervisor,
        reply_root(),
        reply_origin(),
        ProductionServiceStage::ReconcileSecondCrash,
    )?;
    if identity.snapshot.is_none() {
        return Err("reconciliation-service-not-fresh");
    }
    let successor = identity.ingress.incarnation();
    let binding_generation = identity.ingress.binding_generation();
    let (client, custody, result) = spawn_reply_client(reply_coordinate())?;
    if custody
        .plan(REPLY_SEQUENCE, REPLY_VALUE)
        .map_err(|_| "reply-custody-plan")?
        != plan
    {
        return Err("reply-custody-plan-mismatch");
    }
    let run = build_production_service(owner, identity, move |ingress| {
        ingress.ready_and_wait_for_rebind()?;
        ingress.verify_portal_observation(0xc501_0200, reply_effect())?;
        let settlement = ingress.claim_settlement(reply_effect())?;
        let settlement = match settlement.record_apply_intent(plan.intent_digest()) {
            Err(failure) if failure.error() == &CoreError::WrongSettlementStage => {
                failure.into_claim()
            }
            Err(_) => return Err("reply-reconciliation-stage"),
            Ok(_) => return Err("reply-second-apply-intent-authorized"),
        };
        let apply_challenge = ingress
            .observe(|engine| engine.apply_completion_challenge(&settlement))?
            .map_err(|_| "reply-reconciliation-challenge")?;
        let observation = custody
            .apply(apply_challenge, plan)
            .map_err(|_| "reply-reconciliation-apply")?;
        let duplicate = custody
            .apply(apply_challenge, plan)
            .map_err(|_| "reply-reconciliation-observe")?;
        if duplicate != observation {
            return Err("reply-duplicate-publication-observation");
        }
        let applied = ingress
            .observe(|engine| custody.verify_applied(engine, &settlement, &observation))?
            .map_err(|_| "reply-reconciliation-verify")?;
        let command = settlement
            .record_applied(applied)
            .map_err(|_| "reply-record-applied-command")?;
        let settlement = settlement_claim_checked(ingress.transact(command)?)?;
        if result.wait_take_bounded() != Some(Ok(REPLY_VALUE)) {
            return Err("reply-client-result");
        }
        let acknowledgement = custody
            .observe_ack(plan)
            .map_err(|_| "reply-client-ack-observation")?;
        let verified_ack = ingress
            .observe(|engine| custody.verify_settlement_ack(engine, &settlement, &acknowledgement))?
            .map_err(|_| "reply-client-ack-verify")?;
        let settle = settlement
            .settle(verified_ack)
            .map_err(|_| "reply-settle-command")?;
        expect_no_output_checked(ingress.transact(settle)?)?;
        let retirement = ingress
            .observe(|engine| custody.verify_retirement(engine, &acknowledgement))?
            .map_err(|_| "reply-retirement-verify")?;
        expect_no_output_checked(ingress.transact(retirement.submit())?)?;
        ingress.complete_rebound_domain()?;
        Ok(ProductionServiceDisposition::RemainLive)
    })?;
    start_prepared_service(owner, supervisor, &run)?;
    wait_service_completion(&run)?;
    for _ in 0..MAX_TASK_TURNS {
        if client.is_reaped() {
            if run.task.is_reaped()
                || !run.control.ingress_open.load(Ordering::Acquire)
                || owner.ingress_identity() != Some(identity.ingress)
                || run.exits.rejected.load(Ordering::Acquire)
            {
                return Err("reconciliation-service-not-live");
            }
            return Ok((client, run, successor, binding_generation));
        }
        Task::yield_now();
    }
    Err("reply-client-not-reaped")
}

fn bind_stable_recovery_service(
    owner: &Arc<QuarantinedProductionOwner>,
    supervisor: &CoreSupervisorVNext<QuarantinedProductionOwner>,
) -> Result<(ProductionServiceRun, PrincipalIncarnation, u64), &'static str> {
    let identity = prepare_production_service(
        owner,
        supervisor,
        reply_root(),
        reply_origin(),
        ProductionServiceStage::StableRecovery,
    )?;
    if identity.snapshot.is_none() {
        return Err("stable-service-not-fresh");
    }
    let successor = identity.ingress.incarnation();
    let binding_generation = identity.ingress.binding_generation();
    let run = build_production_service(owner, identity, move |ingress| {
        ingress.ready_and_wait_for_rebind()?;
        ingress.verify_portal_observation(0xc501_0300, reply_effect())?;
        let stable = ingress.observe(|engine| {
            engine.estate(reply_effect()).is_some_and(|estate| {
                estate.settlement == SettlementState::Settled
                    && estate.retirement == RetirementState::Retired
                    && estate.retained_claims == 0
            })
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
) -> Result<DmaRecoveryReport, &'static str> {
    let claims = owner.observe_engine(|engine| {
        engine
            .retained_claims()
            .into_iter()
            .filter(|claim| claim.domain == DEVICE_DOMAIN)
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
                engine.retirement_evidence_accepted(
                    claim.effect,
                    claim.claim,
                    DEVICE_EVIDENCE_RESET,
                )
            })
            .map_err(|_| "dma-reset-state")?;
        let irq_missing = if claim.kind == DEVICE_CLAIM_QUEUE_SLOT {
            !owner
                .observe_engine(|engine| {
                    engine.retirement_evidence_accepted(
                        claim.effect,
                        claim.claim,
                        DEVICE_EVIDENCE_IRQ_DRAINED,
                    )
                })
                .map_err(|_| "dma-irq-state")?
        } else {
            false
        };
        if !reset_missing && !irq_missing {
            continue;
        }
        let projected = owner.installed().inspect_with_guard(|engine, guard| {
            let receipts = project_replayed_claim(guard, claim).ok()?;
            let (reset, irq, iotlb) = receipts.into_parts();
            let reset_command = if reset_missing {
                Some(
                    engine
                        .verify_retirement_evidence(
                            claim.effect,
                            claim.claim,
                            DEVICE_EVIDENCE_RESET,
                            &OstdBootClaimVerifier::new(claim),
                            &reset,
                        )
                        .ok()?
                        .submit(),
                )
            } else {
                None
            };
            Some((reset_command, irq, iotlb.resource_reuse_authorized()))
        });
        let Some((reset_command, irq, reuse_authorized)) = projected else {
            return Err("dma-quarantine-projection");
        };
        report.resource_reuse_authorized |= reuse_authorized;
        if reuse_authorized {
            return Err("dma-global-iotlb-overclaimed-reuse");
        }
        if let Some(command) = reset_command {
            expect_no_output_checked(owner_tx_checked(owner, command)?)?;
            report.reset_submitted += 1;
        }
        if irq_missing {
            let irq_command = owner
                .observe_engine(|engine| {
                    engine.verify_retirement_evidence(
                        claim.effect,
                        claim.claim,
                        DEVICE_EVIDENCE_IRQ_DRAINED,
                        &OstdBootIrqVerifier::new(claim),
                        &irq,
                    )
                })
                .map_err(|_| "dma-irq-verify")?
                .submit();
            expect_no_output_checked(owner_tx_checked(owner, irq_command)?)?;
            report.irq_submitted += 1;
        }
    }
    Ok(report)
}

fn validate_dma_reuse_boundary(owner: &QuarantinedProductionOwner) -> bool {
    let claims = dma_claims();
    owner.observe_engine(|engine| {
        if engine.check_reusable(
            claims.claim(ClaimRole::Queue).resource(),
            claims.claim(ClaimRole::Queue).generation(),
        ) != Err(CoreError::Quarantined)
        {
            return false;
        }
        if [
            claims.claim(ClaimRole::PinnedPages),
            claims.claim(ClaimRole::Iova),
        ]
        .into_iter()
        .any(|claim| {
            engine.check_reusable(claim.resource(), claim.generation())
                != Err(CoreError::ResourceRetained)
        }) {
            return false;
        }
        let retained: Vec<ClaimProjection> = engine
            .retained_claims()
            .into_iter()
            .filter(|claim| claim.domain == DEVICE_DOMAIN)
            .collect();
        retained.len() == 2
            && retained.iter().all(|claim| {
                claim.kind == DEVICE_CLAIM_PINNED_PAGE || claim.kind == DEVICE_CLAIM_IOVA
            })
    })
}

fn inspect_reply_outbox(
    outbox: &mut AtaPioReplyOutbox,
    plan: ReplyPlan,
) -> Result<Option<Digest>, &'static str> {
    let identity =
        ReplyOutboxIdentity::new(reply_effect(), REPLY_SEQUENCE).ok_or("reply-outbox-identity")?;
    match outbox.inspect(identity) {
        ReplyCommitInspection::Absent => Ok(None),
        ReplyCommitInspection::Committed(receipt)
            if receipt.reply() == identity
                && receipt.actor() == reply_origin()
                && receipt.authority_generation() != 0
                && receipt.intent_nonce() != 0
                && receipt.operation() == digest(0xc1)
                && receipt.payload_digest() == plan.payload_digest()
                && receipt.commit_generation() != 0
                && !receipt.record_checksum().is_zero() =>
        {
            Ok(Some(receipt.record_checksum()))
        }
        ReplyCommitInspection::Committed(_) => Err("reply-outbox-coordinate-mismatch"),
        ReplyCommitInspection::Corrupt(_) => Err("reply-outbox-corrupt"),
        ReplyCommitInspection::Indeterminate(_) => Err("reply-outbox-indeterminate"),
    }
}

fn validate_reply_identity(estate: EstateProjection) -> bool {
    estate.effect == reply_effect()
        && estate.causal_owner == reply_origin()
        && estate.charge_owner == charge_account(0xc501)
        && estate.obligation == (REPLY_DOMAIN, REPLY_OBLIGATION_PUBLICATION)
        && estate.authority != AuthorityState::Revoked
        && estate.custodian != CustodyState::Released
}

fn validate_reply_claim(claim: ClaimProjection, retired: bool) -> bool {
    claim.effect == reply_effect()
        && claim.claim == reply_claim()
        && claim.domain == REPLY_DOMAIN
        && claim.kind == REPLY_CLAIM_PUBLICATION_SLOT
        && claim.scope == ClaimScope::Logical
        && claim.resource == reply_resource()
        && claim.resource_generation == resource_generation(1)
        && claim.units == 1
        && claim.retired == retired
}

fn validate_precommit_reply_claim(engine: &Engine) -> bool {
    let Some(estate) = engine.estate(reply_effect()) else {
        return false;
    };
    if estate.commit != CommitState::Prepared || estate.claim_count != 1 {
        return false;
    }
    matches!(engine.claims(reply_effect()), Ok(claims) if matches!(
        claims.as_slice(),
        [claim] if validate_reply_claim(*claim, false)
    ))
}

fn validate_committed_reply(engine: &Engine, checksum: Digest) -> bool {
    let Some(estate) = engine.estate(reply_effect()) else {
        return false;
    };
    let outcome_matches = estate.outcome == OutcomeState::KnownSuccess(checksum)
        || estate.outcome == OutcomeState::Indeterminate(digest(0xc1));
    validate_reply_identity(estate)
        && estate.commit == CommitState::Committed
        && outcome_matches
        && estate.claim_count == 1
        && matches!(engine.claims(reply_effect()), Ok(claims) if matches!(
            claims.as_slice(),
            [claim] if validate_reply_claim(*claim, estate.retirement == RetirementState::Retired)
        ))
}

fn validate_committed_reply_with_projection<S>(
    owner: &ProductionCoreOwner<S>,
    projection: EstateProjection,
    checksum: Digest,
) -> bool
where
    S: InstalledCore,
{
    owner.observe_engine(|engine| {
        engine.estate(reply_effect()) == Some(projection)
            && validate_committed_reply(engine, checksum)
            && matches!(
                projection.settlement,
                SettlementState::Open { .. }
                    | SettlementState::ReconciliationRequired { .. }
                    | SettlementState::Settled
            )
    })
}

fn ensure_uncommitted_reply_actor<S>(
    owner: &ProductionCoreOwner<S>,
    supervisor: &CoreSupervisorVNext<ProductionCoreOwner<S>>,
    projection: EstateProjection,
) -> Result<(PrincipalIncarnation, u64), &'static str>
where
    S: InstalledCore,
{
    let (actor, binding_generation) = bound_root_identity(owner, reply_root())?;
    match projection.authority {
        AuthorityState::Fenced if projection.custodian == CustodyState::KernelEstate => {
            expect_no_output_checked(
                supervisor
                    .adopt_effect(reply_effect(), actor, binding_generation)
                    .map_err(|_| "reply-adoption")?,
            )?;
        }
        AuthorityState::Active if projection.custodian == CustodyState::Principal(actor) => {}
        AuthorityState::Active | AuthorityState::Fenced | AuthorityState::Revoked => {
            return Err("reply-adoption-state");
        }
    }
    let live = owner.observe_engine(|engine| engine.estate(reply_effect()));
    if !live.is_some_and(|estate| {
        estate.authority == AuthorityState::Active
            && estate.custodian == CustodyState::Principal(actor)
            && matches!(
                estate.commit,
                CommitState::Registered | CommitState::Prepared
            )
    }) {
        return Err("reply-adoption-postcondition");
    }
    Ok((actor, binding_generation))
}

fn validate_dma_estate(engine: &Engine) -> bool {
    let Some(estate) = engine.estate(dma_effect()) else {
        return false;
    };
    if estate.effect != dma_effect()
        || estate.causal_owner != dma_origin()
        || estate.charge_owner != charge_account(0xd001)
        || estate.obligation != (DEVICE_DOMAIN, DEVICE_OBLIGATION_DMA)
        || estate.commit != CommitState::Committed
        || !matches!(estate.outcome, OutcomeState::KnownSuccess(digest) if !digest.is_zero())
        || estate.settlement != SettlementState::NotRequired
        || estate.retirement != RetirementState::RetirementPending
        || estate.claim_count != 3
        || !matches!(estate.retained_claims, 2 | 3)
    {
        return false;
    }
    let Ok(claims) = engine.claims(dma_effect()) else {
        return false;
    };
    let expected = dma_claims();
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
            claim.effect == dma_effect()
                && claim.claim == expected.claim()
                && claim.domain == DEVICE_DOMAIN
                && claim.kind == kind
                && claim.scope == ClaimScope::Device(scope)
                && claim.resource == expected.resource()
                && claim.resource_generation == expected.generation()
                && claim.units == expected.units()
                && (role == ClaimRole::Queue || !claim.retired)
        })
    })
}

fn classify_persistent_phase(
    engine: &Engine,
    reply_checksum: Digest,
) -> Result<PersistentPhase, &'static str> {
    if !validate_committed_reply(engine, reply_checksum) {
        return Err("reply-replay-projection");
    }
    if !validate_dma_estate(engine) {
        return Err("dma-replay-projection");
    }
    if engine
        .retained_claims()
        .iter()
        .filter(|claim| claim.domain == DEVICE_DOMAIN)
        .count()
        != 2
    {
        return Err("dma-queue-not-retired");
    }
    let estate = engine.estate(reply_effect()).ok_or("reply-estate-absent")?;
    match estate.settlement {
        SettlementState::Open { .. }
            if estate.retirement == RetirementState::RetirementPending
                && estate.retained_claims == 1 =>
        {
            Ok(PersistentPhase::ArmSecondCrash)
        }
        SettlementState::ReconciliationRequired { applied: false, .. }
            if estate.retirement == RetirementState::RetirementPending
                && estate.retained_claims == 1 =>
        {
            Ok(PersistentPhase::ReconcileSecondCrash)
        }
        SettlementState::ReconciliationRequired { applied: true, .. } => {
            Err("reply-applied-without-persistent-custody")
        }
        SettlementState::Settled
            if estate.retirement == RetirementState::Retired && estate.retained_claims == 0 =>
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

fn runtime_metrics<S>(owner: &ProductionCoreOwner<S>) -> (u64, u64, u64, u64, usize)
where
    S: InstalledCore,
{
    owner.observe_engine(|engine| {
        let freshness = engine.freshness();
        (
            engine.revision(),
            freshness.boot().get(),
            freshness.journal().get(),
            freshness.device().get(),
            engine.retained_claims().len(),
        )
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

fn reply_coordinate() -> ReplyCoordinate {
    ReplyCoordinate::new(
        reply_effect(),
        reply_claim(),
        reply_resource(),
        resource_generation(1),
    )
}

fn reply_root() -> RootId {
    root(0xc501)
}

fn reply_effect() -> EffectId {
    EffectId::new(reply_root(), 1).expect("reply effect is non-zero")
}

fn reply_origin() -> PrincipalIncarnation {
    principal(0xc501, 1)
}

fn reply_claim() -> ClaimId {
    claim_id(0xc511)
}

fn reply_resource() -> ResourceId {
    resource(0xc521)
}

fn dma_effect() -> EffectId {
    EffectId::new(dma_root(), 1).expect("DMA effect is non-zero")
}

fn dma_root() -> RootId {
    root(0xd001)
}

fn dma_origin() -> PrincipalIncarnation {
    principal(0xd001, 1)
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
