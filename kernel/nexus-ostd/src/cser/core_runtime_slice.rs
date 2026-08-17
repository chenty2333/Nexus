// SPDX-License-Identifier: MPL-2.0

//! Real OSTD task-lifecycle probe for the mutually-exclusive portable core.
//!
//! The probe uses the same `TransitionDurability` transaction boundary as the
//! recovered production owner, backed here by a same-boot byte journal. It
//! proves task/reap/fence/recovery transition binding, but it is not
//! reboot-persistence evidence because those bytes have no durable provider or
//! trusted anchor. The commit verifier below remains a
//! challenge-reflecting probe. Reply application, wake-up, client
//! acknowledgement, settlement, and retirement use a real task-bound OSTD
//! `Waiter`/`Waker` through `core_reply_adapter`. `Rebind` is still task-bound
//! core state rather than a production ingress switch. This feature has no
//! service ingress. A production adapter must therefore add an immediate death
//! latch that rejects ingress between exact reap and the durable
//! `FenceExecutor` commit.

use alloc::{
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::{
    convert::Infallible,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, AuthorityState,
    BootGeneration, ChargeAccountId, ClaimId, ClaimScope, CommandRequest, CommitState,
    ComponentCommitOperation, ComponentProviderBinding, CoreError, CoreLimits,
    DEVICE_CLAIM_QUEUE_SLOT, DEVICE_COMMIT_RECEIPT_SCHEMA, DEVICE_EVIDENCE_IRQ_DRAINED,
    DEVICE_EVIDENCE_RESET, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, DeviceGeneration, DeviceScopeId,
    Digest, EffectFactChallenge, EffectFactKind, EffectId, EffectReceiptVerifier,
    EvidenceChallenge, ExecutorCoordinate, ExecutorGeneration, ExecutorId, ExternalOutcome,
    Freshness, JournalGeneration, JournalRecord, OperationId, OutcomeState, ProviderCoordinate,
    ProviderGeneration, ProviderId, REPLY_CLAIM_PUBLICATION_SLOT, REPLY_COMMIT_RECEIPT_SCHEMA,
    REPLY_VERIFIER, ReceiptSchemaId, ReceiptVerifier, RegistryInstance, ResourceGeneration,
    ResourceId, RetirementState, SettlementClaim, SettlementState, SnapshotId,
    TransitionDurability, TransitionOutput, TransitionReceipt, TxError, VerificationError,
    VerifiedEffectObservation, VerifiedObservation, VerifierBinding, VerifierGeneration,
    VerifierIdentity, WorldId, standard_catalog,
};
use ostd::{
    power::{ExitCode, poweroff},
    prelude::*,
    sync::SpinLock,
    task::{Task, TaskOptions, inject_post_task_exit_handler},
};

use super::core_reply_adapter::{
    ReplyAckError, ReplyCoordinate, ReplyCustody, ReplyPlan, reply_pair,
};
use super::core_runtime::OstdCserRuntime;

#[path = "core_runtime_dev.rs"]
mod core_runtime_dev;

use self::core_runtime_dev::run_boot_probe;

struct VolatileReplyDurability {
    journal: Vec<u8>,
}

impl VolatileReplyDurability {
    const fn new() -> Self {
        Self {
            journal: Vec::new(),
        }
    }
}

impl TransitionDurability for VolatileReplyDurability {
    type Error = Infallible;

    fn persist_transition(
        &mut self,
        record: &JournalRecord,
        resulting_freshness: Freshness,
        _resulting_projection: Digest,
    ) -> Result<(), Self::Error> {
        assert!(!record.bytes().is_empty());
        assert_ne!(resulting_freshness.boot().get(), 0);
        self.journal.extend_from_slice(record.bytes());
        Ok(())
    }
}

type SpikeRuntime = OstdCserRuntime<VolatileReplyDurability>;

const PHASE_INITIAL: u8 = 0;
const PHASE_READY: u8 = 1;
const PHASE_REBOUND: u8 = 2;
const PHASE_INTENT_RECORDED: u8 = 3;
const PHASE_SETTLED: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReapStage {
    Origin,
    FirstSuccessor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReapObservation {
    operation: OperationId,
    crashed: ExecutorCoordinate,
    stage: ReapStage,
}

struct ReapInbox {
    slot: SpinLock<Option<ReapObservation>>,
    rejected: AtomicBool,
}

impl ReapInbox {
    const fn new() -> Self {
        Self {
            slot: SpinLock::new(None),
            rejected: AtomicBool::new(false),
        }
    }

    fn publish(&self, observation: ReapObservation) {
        let mut slot = self.slot.lock();
        if slot.is_some() {
            self.rejected.store(true, Ordering::Release);
            return;
        }
        *slot = Some(observation);
    }

    fn take(&self) -> Option<ReapObservation> {
        self.slot.lock().take()
    }
}

struct ReapBinding {
    inbox: Weak<ReapInbox>,
    observation: ReapObservation,
}

enum CoreTaskRole {
    Manager,
    ReapObserved(ReapBinding),
    ReplyClient,
    TerminalSuccessor,
}

struct CoreTaskData {
    role: CoreTaskRole,
}

impl CoreTaskData {
    const fn manager() -> Self {
        Self {
            role: CoreTaskRole::Manager,
        }
    }

    fn reaped(inbox: &Arc<ReapInbox>, observation: ReapObservation) -> Self {
        Self {
            role: CoreTaskRole::ReapObserved(ReapBinding {
                inbox: Arc::downgrade(inbox),
                observation,
            }),
        }
    }

    const fn terminal_successor() -> Self {
        Self {
            role: CoreTaskRole::TerminalSuccessor,
        }
    }

    const fn reply_client() -> Self {
        Self {
            role: CoreTaskRole::ReplyClient,
        }
    }
}

struct RecoveryControl {
    phase: AtomicU8,
}

struct OneShotInbox<T> {
    slot: SpinLock<Option<T>>,
    published: AtomicBool,
    rejected: AtomicBool,
}

impl<T> OneShotInbox<T> {
    const fn new() -> Self {
        Self {
            slot: SpinLock::new(None),
            published: AtomicBool::new(false),
            rejected: AtomicBool::new(false),
        }
    }

    fn publish(&self, value: T) {
        if self
            .published
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.rejected.store(true, Ordering::Release);
            return;
        }
        *self.slot.lock() = Some(value);
    }

    fn wait_take(&self) -> T {
        loop {
            assert!(!self.rejected.load(Ordering::Acquire));
            if let Some(value) = self.slot.lock().take() {
                return value;
            }
            Task::yield_now();
        }
    }
}

impl RecoveryControl {
    const fn new() -> Self {
        Self {
            phase: AtomicU8::new(PHASE_INITIAL),
        }
    }

    fn publish(&self, phase: u8) {
        self.phase.store(phase, Ordering::Release);
    }

    fn wait_for(&self, phase: u8) {
        while self.phase.load(Ordering::Acquire) < phase {
            Task::yield_now();
        }
    }
}

#[derive(Clone, Copy)]
struct ProbeEffectReceipt {
    challenge: EffectFactChallenge,
    digest: Digest,
    outcome: Option<ExternalOutcome>,
}

struct ProbeEffectVerifier {
    binding: VerifierBinding,
}

#[derive(Clone, Copy)]
struct ProbeEvidenceReceipt {
    challenge: EvidenceChallenge,
    observation: Freshness,
    digest: Digest,
}

struct ProbeEvidenceVerifier {
    binding: VerifierBinding,
}

impl ReceiptVerifier for ProbeEvidenceVerifier {
    type Receipt = ProbeEvidenceReceipt;

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new_exact(self.binding)
    }

    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        if *challenge != receipt.challenge
            || challenge.expected_verifier_binding() != self.binding
            || challenge.verification_scope().verifier_binding() != self.binding
            || receipt.digest.is_zero()
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new(
            challenge.subject(),
            receipt.observation,
            receipt.digest,
        ))
    }
}

impl EffectReceiptVerifier for ProbeEffectVerifier {
    type Receipt = ProbeEffectReceipt;

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new_exact(self.binding)
    }

    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        if *challenge != receipt.challenge
            || challenge.expected_verifier() != self.binding.verifier()
            || challenge.expected_receipt_schema() != self.binding.receipt_schema()
            || challenge.expected_verifier_binding() != self.binding
            || challenge.verification_scope().verifier_binding() != self.binding
            || receipt.digest.is_zero()
        {
            return Err(VerificationError::Rejected);
        }
        match (challenge.kind(), receipt.outcome) {
            (EffectFactKind::CommitOutcome, Some(outcome)) => {
                Ok(VerifiedEffectObservation::commit(
                    challenge.current_observation(),
                    outcome,
                    receipt.digest,
                ))
            }
            _ => Err(VerificationError::Rejected),
        }
    }
}

/// OSTD's patched switch tail calls this once after exact terminal switch-out.
///
/// The hook never enters the sleepable core writer. It only deposits the exact
/// task-bound selector into a bounded same-boot inbox for the manager task.
pub(crate) fn observe_post_task_exit(task: &Task) {
    if !task.is_reaped() {
        return;
    }
    let Some(data) = task.data().downcast_ref::<CoreTaskData>() else {
        return;
    };
    let CoreTaskRole::ReapObserved(binding) = &data.role else {
        return;
    };
    let Some(inbox) = binding.inbox.upgrade() else {
        return;
    };
    inbox.publish(binding.observation);
}

/// Installs the exact-reap observer before creating any OSTD task.
pub(crate) fn launch() -> ! {
    inject_post_task_exit_handler(observe_post_task_exit);
    let manager = Arc::new(
        TaskOptions::new(run_task_recovery_slice)
            .data(CoreTaskData::manager())
            .build()
            .expect("core runtime manager task builds"),
    );
    manager.run();
    Task::yield_now();
    unreachable!("the core runtime manager powers the machine off")
}

fn run_task_recovery_slice() {
    // First preserve the production boundary's fail-closed behavior.
    run_boot_probe();

    let runtime = Arc::new(OstdCserRuntime::from_engine(
        cser_engine(),
        VolatileReplyDurability::new(),
    ));
    let inbox = Arc::new(ReapInbox::new());
    let operation = operation(1);
    let effect = effect(operation, 1);
    let origin = executor(1, 1);
    let coordinate = ReplyCoordinate::new_component(
        effect,
        AGENT_COMPONENT_REPLY,
        claim_id(operation.get()),
        resource(operation.get()),
        ResourceGeneration::new(1).expect("reply resource generation is valid"),
    );
    let custody_inbox = Arc::new(OneShotInbox::<ReplyCustody>::new());
    let client_result = Arc::new(OneShotInbox::<Result<u64, ReplyAckError>>::new());
    let client_custody_inbox = Arc::clone(&custody_inbox);
    let client_result_inbox = Arc::clone(&client_result);
    let client_task = Arc::new(
        TaskOptions::new(move || {
            println!("CSER_CORE_REPLY_TRACE client=entered");
            // `Waiter::new_pair` binds to `Task::current`, so the client must
            // create and retain the receiver in its own real OSTD task.
            let (receiver, custody) = reply_pair(coordinate);
            client_custody_inbox.publish(custody);
            println!("CSER_CORE_REPLY_TRACE client=custody-published");
            let result = receiver.wait_and_ack();
            println!("CSER_CORE_REPLY_TRACE client=acknowledged");
            client_result_inbox.publish(result);
        })
        .data(CoreTaskData::reply_client())
        .build()
        .expect("reply client task builds"),
    );
    println!("CSER_CORE_REPLY_TRACE manager=client-start");
    client_task.run();
    let custody = custody_inbox.wait_take();
    println!("CSER_CORE_REPLY_TRACE manager=custody-acquired");
    let plan = custody.plan(1, 0xc5e2).expect("exact reply plan is valid");

    let origin_runtime = Arc::clone(&runtime);
    let origin_task = Arc::new(
        TaskOptions::new(move || {
            println!("CSER_CORE_REPLY_TRACE origin=entered");
            create_committed_reply(&origin_runtime, effect, origin);
            println!("CSER_CORE_REPLY_TRACE origin=returning");
        })
        .data(CoreTaskData::reaped(
            &inbox,
            ReapObservation {
                operation,
                crashed: origin,
                stage: ReapStage::Origin,
            },
        ))
        .build()
        .expect("origin service task builds"),
    );
    println!("CSER_CORE_REPLY_TRACE manager=origin-start");
    origin_task.run();
    Task::yield_now();

    let first_reap = wait_for_reap(&inbox);
    println!("CSER_CORE_REPLY_TRACE manager=origin-reaped");
    assert_eq!(
        first_reap,
        ReapObservation {
            operation,
            crashed: origin,
            stage: ReapStage::Origin,
        }
    );
    assert!(origin_task.is_reaped());
    fence_and_snapshot(&runtime, operation, origin, snapshot(1));
    println!("CSER_CORE_REPLY_TRACE manager=origin-fenced-snapshotted");

    let first_successor = executor(1, 2);
    let first_control = Arc::new(RecoveryControl::new());
    let successor_runtime = Arc::clone(&runtime);
    let successor_control = Arc::clone(&first_control);
    let apply_intent = plan.intent_digest();
    let successor_task = Arc::new(
        TaskOptions::new(move || {
            println!("CSER_CORE_REPLY_TRACE successor-v2=entered");
            ready_and_wait_for_rebind(
                &successor_runtime,
                &successor_control,
                operation,
                snapshot(1),
                first_successor,
            );
            record_settlement_intent(&successor_runtime, effect, first_successor, apply_intent);
            successor_control.publish(PHASE_INTENT_RECORDED);
            println!("CSER_CORE_REPLY_TRACE successor-v2=returning-after-intent");
            // Returning is the second real OSTD task death. The exact-reap
            // hook, not this closure, authorizes the next fence.
        })
        .data(CoreTaskData::reaped(
            &inbox,
            ReapObservation {
                operation,
                crashed: first_successor,
                stage: ReapStage::FirstSuccessor,
            },
        ))
        .build()
        .expect("first successor task builds"),
    );
    println!("CSER_CORE_REPLY_TRACE manager=successor-v2-start");
    successor_task.run();
    first_control.wait_for(PHASE_READY);
    println!("CSER_CORE_REPLY_TRACE manager=successor-v2-ready");
    tx(
        &runtime,
        CommandRequest::Rebind {
            operation,
            snapshot: snapshot(1),
            successor: first_successor,
        },
    );
    first_control.publish(PHASE_REBOUND);
    let second_reap = wait_for_reap(&inbox);
    println!("CSER_CORE_REPLY_TRACE manager=successor-v2-reaped");
    assert_eq!(
        second_reap,
        ReapObservation {
            operation,
            crashed: first_successor,
            stage: ReapStage::FirstSuccessor,
        }
    );
    assert_eq!(
        first_control.phase.load(Ordering::Acquire),
        PHASE_INTENT_RECORDED
    );
    assert!(successor_task.is_reaped());

    fence_and_snapshot(&runtime, operation, first_successor, snapshot(2));
    println!("CSER_CORE_REPLY_TRACE manager=successor-v2-fenced-snapshotted");
    assert!(matches!(
        runtime.observe(|engine| {
            engine
                .component(effect, AGENT_COMPONENT_REPLY)
                .expect("reply component survives the second crash")
                .settlement
        }),
        SettlementState::ReconciliationRequired {
            generation: 2,
            applied: false,
        }
    ));

    let terminal_successor = executor(1, 3);
    let terminal_control = Arc::new(RecoveryControl::new());
    let settlement_inbox = Arc::new(OneShotInbox::<SettlementClaim>::new());
    let terminal_runtime = Arc::clone(&runtime);
    let task_control = Arc::clone(&terminal_control);
    let task_settlement_inbox = Arc::clone(&settlement_inbox);
    let terminal_task = Arc::new(
        TaskOptions::new(move || {
            println!("CSER_CORE_REPLY_TRACE successor-v3=entered");
            ready_and_wait_for_rebind(
                &terminal_runtime,
                &task_control,
                operation,
                snapshot(2),
                terminal_successor,
            );
            let settlement = claim_reconciliation(&terminal_runtime, effect, terminal_successor);
            task_settlement_inbox.publish(settlement);
            println!("CSER_CORE_REPLY_TRACE successor-v3=claim-exported");
            task_control.wait_for(PHASE_SETTLED);
            // This is the live v3 successor, not a third crash. Keep its exact
            // task and authority alive while the manager validates the final
            // projection and powers the probe off.
            loop {
                Task::yield_now();
            }
        })
        .data(CoreTaskData::terminal_successor())
        .build()
        .expect("terminal successor task builds"),
    );
    println!("CSER_CORE_REPLY_TRACE manager=successor-v3-start");
    terminal_task.run();
    terminal_control.wait_for(PHASE_READY);
    println!("CSER_CORE_REPLY_TRACE manager=successor-v3-ready");
    tx(
        &runtime,
        CommandRequest::Rebind {
            operation,
            snapshot: snapshot(2),
            successor: terminal_successor,
        },
    );
    terminal_control.publish(PHASE_REBOUND);
    let settlement = settlement_inbox.wait_take();
    println!("CSER_CORE_REPLY_TRACE manager=claim-acquired");
    settle_real_reply(&runtime, settlement, &custody, plan, &client_result);
    println!("CSER_CORE_REPLY_TRACE manager=reply-settled-retired");
    terminal_control.publish(PHASE_SETTLED);

    exercise_revoke_adopt_orders(&runtime);

    let composite = runtime.observe(|engine| {
        engine
            .composite_effect(effect)
            .expect("reply composite effect exists")
    });
    let reply_component = runtime.observe(|engine| {
        engine
            .component(effect, AGENT_COMPONENT_REPLY)
            .expect("reply component exists")
    });
    let dma_component = runtime.observe(|engine| {
        engine
            .component(effect, AGENT_COMPONENT_DMA)
            .expect("DMA component exists")
    });
    assert_eq!(composite.authority, AuthorityState::Fenced);
    assert_eq!(
        reply_component.outcome,
        OutcomeState::KnownSuccess(digest(11))
    );
    assert_eq!(reply_component.settlement, SettlementState::Settled);
    assert_eq!(reply_component.retirement, RetirementState::Retired);
    assert_eq!(dma_component.commit, CommitState::Committed);
    assert_eq!(dma_component.retirement, RetirementState::Retired);
    assert!(!inbox.rejected.load(Ordering::Acquire));
    assert!(!custody_inbox.rejected.load(Ordering::Acquire));
    assert!(!settlement_inbox.rejected.load(Ordering::Acquire));
    assert!(!client_result.rejected.load(Ordering::Acquire));
    assert!(client_task.is_reaped());
    println!(
        "CSER_CORE_OSTD_TASK_RECOVERY PASS death=task-return exact_reap=true \
         fence_before_snapshot=true ready_in_fresh_task=true rebind_by_manager=true \
         settlement_claim=true second_crash=true reconcile_without_second_intent=true \
         physical_reply=true real_waiter_wake=true client_ack=true duplicate_wake=false \
         postcommit_authority=fenced precommit_adopt_race=true \
         revoke_adopt_orders=2 legacy_runtime=false live_dual_write=false \
         rebind=task-bound-core production_rebind=false \
         receipt_provider=commit-probe+physical-reply real_reply=true \
         api_profile=5 production_profile=false scoped_providers=true \
         exact_verifier_binding=true \
         journal=same-boot-memory durability_boundary=transition-trait \
         reboot_persistence=false"
    );
    poweroff(ExitCode::Success);
}

fn cser_engine() -> cser_core::Engine {
    let world = WorldId::new(1).expect("probe world is non-zero");
    let freshness = Freshness::new(
        BootGeneration::new(1).expect("probe boot generation is valid"),
        RegistryInstance::new(1).expect("probe Registry instance is valid"),
        cser_core::DeviceGeneration::new(1).expect("probe device generation is valid"),
        JournalGeneration::new(1).expect("probe journal generation is valid"),
    );
    let catalog = standard_catalog();
    let catalog_set = cser_core::CatalogSet::new(core::slice::from_ref(&catalog))
        .expect("probe catalog set is valid");
    let mut engine =
        cser_core::Engine::new(world, catalog_set, CoreLimits::bounded_default(), freshness);
    let verifier_bindings = probe_verifier_bindings();
    for provider in [provider_coordinate(world, 1), provider_coordinate(world, 2)] {
        engine
            .transact(
                CommandRequest::RegisterProviderGeneration {
                    coordinate: provider,
                    catalog_digest: catalog.digest(),
                    verifier_bindings: verifier_bindings.clone(),
                },
                |_| Ok::<(), Infallible>(()),
            )
            .expect("probe provider generation is valid");
    }
    engine
}

fn provider_coordinate(world: WorldId, provider: u64) -> ProviderCoordinate {
    ProviderCoordinate::new(
        world,
        ProviderId::new(provider).expect("probe provider id is non-zero"),
        ProviderGeneration::new(1).expect("probe provider generation is non-zero"),
    )
}

fn probe_verifier_bindings() -> Vec<VerifierBinding> {
    let generation = VerifierGeneration::new(1).expect("probe verifier generation is non-zero");
    vec![
        VerifierBinding::new(
            REPLY_VERIFIER,
            generation,
            cser_core::REPLY_RECEIPT_SCHEMA,
            Digest::new([0x51; 32]),
        )
        .expect("probe reply receipt binding is valid"),
        VerifierBinding::new(
            REPLY_VERIFIER,
            generation,
            REPLY_COMMIT_RECEIPT_SCHEMA,
            Digest::new([0x52; 32]),
        )
        .expect("probe reply commit binding is valid"),
        VerifierBinding::new(
            REPLY_VERIFIER,
            generation,
            cser_core::REPLY_APPLY_RECEIPT_SCHEMA,
            Digest::new([0x53; 32]),
        )
        .expect("probe reply apply binding is valid"),
        VerifierBinding::new(
            REPLY_VERIFIER,
            generation,
            cser_core::REPLY_SETTLEMENT_RECEIPT_SCHEMA,
            Digest::new([0x54; 32]),
        )
        .expect("probe reply settlement binding is valid"),
        VerifierBinding::new(
            DEVICE_VERIFIER,
            generation,
            DEVICE_RECEIPT_SCHEMA,
            Digest::new([0x61; 32]),
        )
        .expect("probe device receipt binding is valid"),
        VerifierBinding::new(
            DEVICE_VERIFIER,
            generation,
            DEVICE_COMMIT_RECEIPT_SCHEMA,
            Digest::new([0x62; 32]),
        )
        .expect("probe device commit binding is valid"),
    ]
}

fn probe_verifier_binding(
    verifier: cser_core::VerifierId,
    schema: ReceiptSchemaId,
) -> VerifierBinding {
    let digest = match (verifier, schema) {
        (REPLY_VERIFIER, cser_core::REPLY_RECEIPT_SCHEMA) => Digest::new([0x51; 32]),
        (REPLY_VERIFIER, REPLY_COMMIT_RECEIPT_SCHEMA) => Digest::new([0x52; 32]),
        (REPLY_VERIFIER, cser_core::REPLY_APPLY_RECEIPT_SCHEMA) => Digest::new([0x53; 32]),
        (REPLY_VERIFIER, cser_core::REPLY_SETTLEMENT_RECEIPT_SCHEMA) => Digest::new([0x54; 32]),
        (DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA) => Digest::new([0x61; 32]),
        (DEVICE_VERIFIER, DEVICE_COMMIT_RECEIPT_SCHEMA) => Digest::new([0x62; 32]),
        _ => panic!("probe verifier binding is outside the standard catalog"),
    };
    VerifierBinding::new(
        verifier,
        VerifierGeneration::new(1).expect("probe verifier generation is non-zero"),
        schema,
        digest,
    )
    .expect("probe verifier binding is valid")
}

fn wait_for_reap(inbox: &ReapInbox) -> ReapObservation {
    loop {
        assert!(!inbox.rejected.load(Ordering::Acquire));
        if let Some(observation) = inbox.take() {
            return observation;
        }
        Task::yield_now();
    }
}

fn ready_and_wait_for_rebind(
    runtime: &SpikeRuntime,
    control: &RecoveryControl,
    operation: OperationId,
    snapshot: SnapshotId,
    successor: ExecutorCoordinate,
) {
    tx(
        runtime,
        CommandRequest::Ready {
            operation,
            snapshot,
            successor,
        },
    );
    control.publish(PHASE_READY);
    control.wait_for(PHASE_REBOUND);
}

fn fence_and_snapshot(
    runtime: &SpikeRuntime,
    operation: OperationId,
    crashed: ExecutorCoordinate,
    snapshot: SnapshotId,
) {
    tx(
        runtime,
        CommandRequest::FenceExecutor { operation, crashed },
    );
    let command = runtime.observe(|engine| {
        engine
            .snapshot_operation(operation, snapshot)
            .expect("fenced operation produces a snapshot")
            .record()
    });
    tx(runtime, command);
}

fn create_committed_reply(runtime: &SpikeRuntime, effect: EffectId, origin: ExecutorCoordinate) {
    tx(
        runtime,
        CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: ChargeAccountId::new(effect.operation().get())
                .expect("reply charge account is valid"),
            bindings: vec![
                ComponentProviderBinding::new(
                    AGENT_COMPONENT_REPLY,
                    provider_coordinate(WorldId::new(1).expect("probe world is valid"), 1),
                ),
                ComponentProviderBinding::new(
                    AGENT_COMPONENT_DMA,
                    provider_coordinate(WorldId::new(1).expect("probe world is valid"), 2),
                ),
            ],
        },
    );
    tx(
        runtime,
        CommandRequest::AddComponentClaim {
            effect,
            component: AGENT_COMPONENT_REPLY,
            actor: origin,
            claim: claim_id(effect.operation().get()),
            kind: REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(effect.operation().get()),
            resource_generation: ResourceGeneration::new(1)
                .expect("reply resource generation is valid"),
            units: 1,
        },
    );
    let dma_claim = claim_id(
        effect
            .operation()
            .get()
            .checked_add(1_000)
            .expect("probe DMA claim identity is bounded"),
    );
    tx(
        runtime,
        CommandRequest::AddComponentClaim {
            effect,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            claim: dma_claim,
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(
                DeviceScopeId::new(1).expect("probe DMA device scope is valid"),
            ),
            resource: resource(
                effect
                    .operation()
                    .get()
                    .checked_add(2_000)
                    .expect("probe DMA resource identity is bounded"),
            ),
            resource_generation: ResourceGeneration::new(1)
                .expect("probe DMA resource generation is valid"),
            units: 1,
        },
    );
    tx(
        runtime,
        CommandRequest::PrepareCompositeEffect {
            effect,
            actor: origin,
        },
    );
    let output = output(
        runtime,
        CommandRequest::RecordCompositeCommitIntents {
            effect,
            actor: origin,
            operations: vec![
                ComponentCommitOperation::new(AGENT_COMPONENT_REPLY, digest(10)),
                ComponentCommitOperation::new(AGENT_COMPONENT_DMA, digest(12)),
            ],
        },
    );
    let TransitionOutput::CompositeCommitIntents(intents) = output else {
        panic!("reply composite commit intents returned the wrong authority");
    };
    assert_eq!(intents.len(), 2);
    for intent in intents {
        let (binding, receipt_digest) = match intent.component() {
            component if component == AGENT_COMPONENT_REPLY => (
                probe_verifier_binding(REPLY_VERIFIER, REPLY_COMMIT_RECEIPT_SCHEMA),
                digest(11),
            ),
            component if component == AGENT_COMPONENT_DMA => (
                probe_verifier_binding(DEVICE_VERIFIER, DEVICE_COMMIT_RECEIPT_SCHEMA),
                digest(13),
            ),
            _ => panic!("reply composite commit intent has an unknown component"),
        };
        let challenge = runtime.observe(|engine| {
            engine
                .commit_outcome_challenge(&intent)
                .expect("component commit outcome challenge is available")
        });
        let verifier = ProbeEffectVerifier { binding };
        let receipt = ProbeEffectReceipt {
            challenge,
            digest: receipt_digest,
            outcome: Some(ExternalOutcome::Success),
        };
        let outcome = runtime.observe(|engine| {
            engine
                .verify_commit_outcome(&intent, &verifier, &receipt)
                .expect("scoped component commit receipt verifies")
        });
        tx(
            runtime,
            intent
                .acknowledge(outcome)
                .expect("verified component commit outcome matches the intent"),
        );
    }
    retire_probe_dma_claim(runtime, effect, dma_claim);
}

fn retire_probe_dma_claim(runtime: &SpikeRuntime, effect: EffectId, claim: ClaimId) {
    let binding = probe_verifier_binding(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA);
    let verifier = ProbeEvidenceVerifier { binding };
    let reset_challenge = runtime.observe(|engine| {
        engine
            .component_evidence_challenge(effect, AGENT_COMPONENT_DMA, claim, DEVICE_EVIDENCE_RESET)
            .expect("probe DMA reset challenge is available")
    });
    let current = reset_challenge.current_observation();
    let reset_observation = current.with_device(
        DeviceGeneration::new(
            current
                .device()
                .get()
                .checked_add(1)
                .expect("probe device generation is bounded"),
        )
        .expect("probe device generation advances"),
    );
    let reset_receipt = ProbeEvidenceReceipt {
        challenge: reset_challenge,
        observation: reset_observation,
        digest: digest(14),
    };
    let reset = runtime.observe(|engine| {
        engine
            .verify_component_retirement_evidence(
                effect,
                AGENT_COMPONENT_DMA,
                claim,
                DEVICE_EVIDENCE_RESET,
                &verifier,
                &reset_receipt,
            )
            .expect("probe DMA reset evidence verifies")
    });
    tx(runtime, reset.submit());

    let irq_challenge = runtime.observe(|engine| {
        engine
            .component_evidence_challenge(
                effect,
                AGENT_COMPONENT_DMA,
                claim,
                DEVICE_EVIDENCE_IRQ_DRAINED,
            )
            .expect("probe DMA IRQ-drain challenge is available")
    });
    let irq_receipt = ProbeEvidenceReceipt {
        challenge: irq_challenge,
        observation: irq_challenge.current_observation(),
        digest: digest(15),
    };
    let irq = runtime.observe(|engine| {
        engine
            .verify_component_retirement_evidence(
                effect,
                AGENT_COMPONENT_DMA,
                claim,
                DEVICE_EVIDENCE_IRQ_DRAINED,
                &verifier,
                &irq_receipt,
            )
            .expect("probe DMA IRQ-drain evidence verifies")
    });
    tx(runtime, irq.submit());
}

fn record_settlement_intent(
    runtime: &SpikeRuntime,
    effect: EffectId,
    successor: ExecutorCoordinate,
    apply_intent: Digest,
) {
    let settlement = settlement_claim(
        output(
            runtime,
            CommandRequest::ClaimComponentSettlement {
                effect,
                component: AGENT_COMPONENT_REPLY,
                claimant: successor,
            },
        ),
        "fresh settlement claim",
    );
    let _settlement = settlement_claim(
        output(
            runtime,
            settlement
                .record_apply_intent(apply_intent)
                .expect("fresh claim records apply intent"),
        ),
        "intent-stage settlement claim",
    );
}

fn claim_reconciliation(
    runtime: &SpikeRuntime,
    effect: EffectId,
    successor: ExecutorCoordinate,
) -> SettlementClaim {
    let settlement = settlement_claim(
        output(
            runtime,
            CommandRequest::ClaimComponentSettlement {
                effect,
                component: AGENT_COMPONENT_REPLY,
                claimant: successor,
            },
        ),
        "reconciliation settlement claim",
    );
    let rejected = settlement
        .record_apply_intent(digest(21))
        .expect_err("second claimant must not mint another apply intent");
    assert_eq!(rejected.error(), &CoreError::WrongSettlementStage);
    rejected.into_claim()
}

fn settle_real_reply(
    runtime: &SpikeRuntime,
    settlement: SettlementClaim,
    custody: &ReplyCustody,
    plan: ReplyPlan,
    client_result: &OneShotInbox<Result<u64, ReplyAckError>>,
) {
    let apply_challenge = runtime.observe(|engine| {
        engine
            .apply_completion_challenge(&settlement)
            .expect("reconciliation apply challenge is available")
    });
    let apply_observation = custody
        .apply(apply_challenge, plan)
        .expect("real OSTD reply publication succeeds");
    let duplicate_observation = custody
        .apply(apply_challenge, plan)
        .expect("reconciliation observes the same publication without another wake");
    assert_eq!(duplicate_observation, apply_observation);
    let applied = runtime.observe(|engine| {
        custody
            .verify_applied(engine, &settlement, &apply_observation)
            .expect("prior apply completion verifies")
    });
    let settlement = settlement_claim(
        output(
            runtime,
            settlement
                .record_applied(applied)
                .expect("reconciliation records prior apply"),
        ),
        "reconciled applied settlement claim",
    );

    assert_eq!(client_result.wait_take(), Ok(plan.value()));
    let ack_observation = custody
        .observe_ack(plan)
        .expect("real client acknowledgement is visible");
    let acknowledgement = runtime.observe(|engine| {
        custody
            .verify_settlement_ack(engine, &settlement, &ack_observation)
            .expect("settlement acknowledgement verifies")
    });
    tx(
        runtime,
        settlement
            .settle(acknowledgement)
            .expect("applied settlement claim settles once"),
    );

    let evidence = runtime.observe(|engine| {
        custody
            .verify_retirement(engine, &ack_observation)
            .expect("reply retirement evidence verifies")
    });
    tx(runtime, evidence.submit());
}

fn exercise_revoke_adopt_orders(runtime: &SpikeRuntime) {
    let revoke_effect = effect(operation(11), 1);
    let revoke_origin = executor(11, 1);
    let revoke_successor = executor(11, 2);
    create_registered_reply(runtime, revoke_effect, revoke_origin);
    fence_snapshot_ready_rebind(
        runtime,
        revoke_effect.operation(),
        revoke_origin,
        revoke_successor,
        snapshot(11),
    );
    let revoke_epoch = runtime.observe(|engine| {
        engine
            .composite_effect(revoke_effect)
            .expect("revoke-race composite exists")
            .authority_epoch
    });
    tx(
        runtime,
        CommandRequest::BeginRevoke {
            effect: revoke_effect,
            expected_actor: revoke_successor,
            authority_epoch: revoke_epoch,
        },
    );
    assert_eq!(
        runtime.transact(CommandRequest::AdoptEffect {
            effect: revoke_effect,
            successor: revoke_successor,
        }),
        Err(TxError::Core(CoreError::GateClosed))
    );

    let adopt_effect = effect(operation(12), 1);
    let adopt_origin = executor(12, 1);
    let adopt_successor = executor(12, 2);
    create_registered_reply(runtime, adopt_effect, adopt_origin);
    fence_snapshot_ready_rebind(
        runtime,
        adopt_effect.operation(),
        adopt_origin,
        adopt_successor,
        snapshot(12),
    );
    let stale_epoch = runtime.observe(|engine| {
        engine
            .composite_effect(adopt_effect)
            .expect("adopt-race composite exists")
            .authority_epoch
    });
    tx(
        runtime,
        CommandRequest::AdoptEffect {
            effect: adopt_effect,
            successor: adopt_successor,
        },
    );
    assert_eq!(
        runtime.transact(CommandRequest::BeginRevoke {
            effect: adopt_effect,
            expected_actor: adopt_successor,
            authority_epoch: stale_epoch,
        }),
        Err(TxError::Core(CoreError::StaleAuthorityEpoch))
    );
}

fn create_registered_reply(runtime: &SpikeRuntime, effect: EffectId, origin: ExecutorCoordinate) {
    tx(
        runtime,
        CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: ChargeAccountId::new(effect.operation().get())
                .expect("race charge account is valid"),
            bindings: vec![
                ComponentProviderBinding::new(
                    AGENT_COMPONENT_REPLY,
                    provider_coordinate(WorldId::new(1).expect("probe world is valid"), 1),
                ),
                ComponentProviderBinding::new(
                    AGENT_COMPONENT_DMA,
                    provider_coordinate(WorldId::new(1).expect("probe world is valid"), 2),
                ),
            ],
        },
    );
}

fn fence_snapshot_ready_rebind(
    runtime: &SpikeRuntime,
    operation: OperationId,
    origin: ExecutorCoordinate,
    successor: ExecutorCoordinate,
    snapshot: SnapshotId,
) {
    fence_and_snapshot(runtime, operation, origin, snapshot);
    tx(
        runtime,
        CommandRequest::Ready {
            operation,
            snapshot,
            successor,
        },
    );
    tx(
        runtime,
        CommandRequest::Rebind {
            operation,
            snapshot,
            successor,
        },
    );
}

fn settlement_claim(output: TransitionOutput, stage: &str) -> SettlementClaim {
    match output {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("{stage} returned the wrong authority: {other:?}"),
    }
}

fn tx<C>(runtime: &SpikeRuntime, command: C) -> TransitionReceipt
where
    C: Into<cser_core::Command>,
{
    runtime
        .transact(command)
        .expect("same-boot durable transition succeeds")
}

fn output<C>(runtime: &SpikeRuntime, command: C) -> TransitionOutput
where
    C: Into<cser_core::Command>,
{
    tx(runtime, command).into_output()
}

const fn operation(value: u64) -> OperationId {
    match OperationId::new(value) {
        Ok(value) => value,
        Err(_) => panic!("probe operation must be non-zero"),
    }
}

const fn effect(operation: OperationId, sequence: u64) -> EffectId {
    match EffectId::new(operation, sequence) {
        Ok(value) => value,
        Err(_) => panic!("probe effect sequence must be non-zero"),
    }
}

const fn executor(id: u64, generation: u64) -> ExecutorCoordinate {
    let id = match ExecutorId::new(id) {
        Ok(value) => value,
        Err(_) => panic!("probe executor must be non-zero"),
    };
    ExecutorCoordinate::new(
        id,
        match ExecutorGeneration::new(generation) {
            Ok(value) => value,
            Err(_) => panic!("probe executor generation must be non-zero"),
        },
    )
}

const fn snapshot(value: u64) -> SnapshotId {
    match SnapshotId::new(value) {
        Ok(value) => value,
        Err(_) => panic!("probe snapshot must be non-zero"),
    }
}

const fn claim_id(value: u64) -> ClaimId {
    match ClaimId::new(value) {
        Ok(value) => value,
        Err(_) => panic!("probe claim must be non-zero"),
    }
}

const fn resource(value: u64) -> ResourceId {
    match ResourceId::new(value) {
        Ok(value) => value,
        Err(_) => panic!("probe resource must be non-zero"),
    }
}

const fn digest(value: u8) -> Digest {
    Digest::new([value; 32])
}
