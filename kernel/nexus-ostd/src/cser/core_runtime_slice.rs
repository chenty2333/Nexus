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
//! `FenceIncarnation` commit.

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    convert::Infallible,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

use cser_core::{
    AuthorityState, BootGeneration, ChargeAccountId, ClaimId, ClaimScope, CommandRequest,
    CoreError, CoreLimits, Digest, EffectFactChallenge, EffectFactKind, EffectId,
    EffectReceiptVerifier, ExternalOutcome, Freshness, JournalGeneration, JournalRecord,
    OutcomeState, PrincipalId, PrincipalIncarnation, REPLY_CLAIM_PUBLICATION_SLOT,
    REPLY_COMMIT_RECEIPT_SCHEMA, REPLY_DOMAIN, REPLY_OBLIGATION_PUBLICATION, REPLY_VERIFIER,
    ReceiptSchemaId, RegistryInstance, ResourceGeneration, ResourceId, RetirementState, RootId,
    SettlementClaim, SettlementState, SnapshotId, TransitionDurability, TransitionOutput,
    TransitionReceipt, TxError, VerificationError, VerifiedEffectObservation, VerifierIdentity,
    standard_catalog,
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
    root: RootId,
    crashed: PrincipalIncarnation,
    binding_generation: u64,
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
    schema: ReceiptSchemaId,
}

impl EffectReceiptVerifier for ProbeEffectVerifier {
    type Receipt = ProbeEffectReceipt;

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new(REPLY_VERIFIER, 1, self.schema)
            .expect("probe verifier identity is valid")
    }

    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        if *challenge != receipt.challenge
            || challenge.expected_verifier() != REPLY_VERIFIER
            || challenge.expected_receipt_schema() != self.schema
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
    let root = root(1);
    let effect = effect(root, 1);
    let origin = principal(1, 1);
    let coordinate = ReplyCoordinate::new(
        effect,
        claim_id(root.get()),
        resource(root.get()),
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
            create_committed_reply(&origin_runtime, effect, origin, 1);
            println!("CSER_CORE_REPLY_TRACE origin=returning");
        })
        .data(CoreTaskData::reaped(
            &inbox,
            ReapObservation {
                root,
                crashed: origin,
                binding_generation: 1,
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
            root,
            crashed: origin,
            binding_generation: 1,
            stage: ReapStage::Origin,
        }
    );
    assert!(origin_task.is_reaped());
    fence_and_snapshot(&runtime, root, origin, 1, snapshot(1));
    println!("CSER_CORE_REPLY_TRACE manager=origin-fenced-snapshotted");

    let first_successor = principal(1, 2);
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
                root,
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
                root,
                crashed: first_successor,
                binding_generation: 2,
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
            root,
            snapshot: snapshot(1),
            successor: first_successor,
            binding_generation: 2,
        },
    );
    first_control.publish(PHASE_REBOUND);
    let second_reap = wait_for_reap(&inbox);
    println!("CSER_CORE_REPLY_TRACE manager=successor-v2-reaped");
    assert_eq!(
        second_reap,
        ReapObservation {
            root,
            crashed: first_successor,
            binding_generation: 2,
            stage: ReapStage::FirstSuccessor,
        }
    );
    assert_eq!(
        first_control.phase.load(Ordering::Acquire),
        PHASE_INTENT_RECORDED
    );
    assert!(successor_task.is_reaped());

    fence_and_snapshot(&runtime, root, first_successor, 2, snapshot(2));
    println!("CSER_CORE_REPLY_TRACE manager=successor-v2-fenced-snapshotted");
    assert!(matches!(
        runtime.observe(|engine| engine.estate(effect).unwrap().settlement),
        SettlementState::ReconciliationRequired {
            generation: 2,
            applied: false,
        }
    ));

    let terminal_successor = principal(1, 3);
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
                root,
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
            root,
            snapshot: snapshot(2),
            successor: terminal_successor,
            binding_generation: 3,
        },
    );
    terminal_control.publish(PHASE_REBOUND);
    let settlement = settlement_inbox.wait_take();
    println!("CSER_CORE_REPLY_TRACE manager=claim-acquired");
    settle_real_reply(&runtime, settlement, &custody, plan, &client_result);
    println!("CSER_CORE_REPLY_TRACE manager=reply-settled-retired");
    terminal_control.publish(PHASE_SETTLED);

    exercise_revoke_adopt_orders(&runtime);

    let estate = runtime.observe(|engine| engine.estate(effect).expect("reply estate exists"));
    assert_eq!(estate.authority, AuthorityState::Fenced);
    assert_eq!(estate.outcome, OutcomeState::KnownSuccess(digest(11)));
    assert_eq!(estate.settlement, SettlementState::Settled);
    assert_eq!(estate.retirement, RetirementState::Retired);
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
         journal=same-boot-memory durability_boundary=transition-trait \
         reboot_persistence=false"
    );
    poweroff(ExitCode::Success);
}

fn cser_engine() -> cser_core::Engine {
    let freshness = Freshness::new(
        BootGeneration::new(1).expect("probe boot generation is valid"),
        RegistryInstance::new(1).expect("probe Registry instance is valid"),
        1,
        cser_core::DeviceGeneration::new(1).expect("probe device generation is valid"),
        JournalGeneration::new(1).expect("probe journal generation is valid"),
    )
    .expect("probe freshness is complete");
    cser_core::Engine::new(standard_catalog(), CoreLimits::bounded_default(), freshness)
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
    root: RootId,
    snapshot: SnapshotId,
    successor: PrincipalIncarnation,
) {
    tx(
        runtime,
        CommandRequest::Ready {
            root,
            snapshot,
            successor,
        },
    );
    control.publish(PHASE_READY);
    control.wait_for(PHASE_REBOUND);
}

fn fence_and_snapshot(
    runtime: &SpikeRuntime,
    root: RootId,
    crashed: PrincipalIncarnation,
    binding_generation: u64,
    snapshot: SnapshotId,
) {
    tx(
        runtime,
        CommandRequest::FenceIncarnation {
            root,
            crashed,
            binding_generation,
        },
    );
    let command = runtime.observe(|engine| {
        engine
            .snapshot_root(root, snapshot)
            .expect("fenced root produces a snapshot")
            .record()
    });
    tx(runtime, command);
}

fn create_committed_reply(
    runtime: &SpikeRuntime,
    effect: EffectId,
    origin: PrincipalIncarnation,
    binding_generation: u64,
) {
    tx(
        runtime,
        CommandRequest::CreateEstate {
            effect,
            origin,
            binding_generation,
            domain: REPLY_DOMAIN,
            obligation: REPLY_OBLIGATION_PUBLICATION,
            charge_account: ChargeAccountId::new(effect.root().get())
                .expect("reply charge account is valid"),
        },
    );
    tx(
        runtime,
        CommandRequest::AddClaim {
            effect,
            actor: origin,
            binding_generation,
            claim: claim_id(effect.root().get()),
            domain: REPLY_DOMAIN,
            kind: REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(effect.root().get()),
            resource_generation: ResourceGeneration::new(1)
                .expect("reply resource generation is valid"),
            units: 1,
        },
    );
    tx(
        runtime,
        CommandRequest::PrepareEffect {
            effect,
            actor: origin,
            binding_generation,
        },
    );
    let intent = output(
        runtime,
        CommandRequest::RecordCommitIntent {
            effect,
            actor: origin,
            binding_generation,
            operation: digest(10),
        },
    );
    let TransitionOutput::CommitIntent(intent) = intent else {
        panic!("reply commit intent transition returned the wrong authority");
    };
    let challenge = runtime.observe(|engine| {
        engine
            .commit_outcome_challenge(&intent)
            .expect("commit outcome challenge is available")
    });
    let verifier = ProbeEffectVerifier {
        schema: REPLY_COMMIT_RECEIPT_SCHEMA,
    };
    let receipt = ProbeEffectReceipt {
        challenge,
        digest: digest(11),
        outcome: Some(ExternalOutcome::Success),
    };
    let outcome = runtime.observe(|engine| {
        engine
            .verify_commit_outcome(&intent, &verifier, &receipt)
            .expect("commit receipt verifies")
    });
    tx(
        runtime,
        intent
            .acknowledge(outcome)
            .expect("verified commit outcome matches the intent"),
    );
}

fn record_settlement_intent(
    runtime: &SpikeRuntime,
    effect: EffectId,
    successor: PrincipalIncarnation,
    apply_intent: Digest,
) {
    let settlement = settlement_claim(
        output(
            runtime,
            CommandRequest::ClaimSettlement {
                effect,
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
    successor: PrincipalIncarnation,
) -> SettlementClaim {
    let settlement = settlement_claim(
        output(
            runtime,
            CommandRequest::ClaimSettlement {
                effect,
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
    let revoke_effect = effect(root(11), 1);
    let revoke_origin = principal(11, 1);
    let revoke_successor = principal(11, 2);
    create_registered_reply(runtime, revoke_effect, revoke_origin);
    fence_snapshot_ready_rebind(
        runtime,
        revoke_effect.root(),
        revoke_origin,
        revoke_successor,
        snapshot(11),
    );
    let revoke_epoch = runtime.observe(|engine| {
        engine
            .estate(revoke_effect)
            .expect("revoke-race estate exists")
            .authority_epoch
    });
    tx(
        runtime,
        CommandRequest::BeginRevoke {
            effect: revoke_effect,
            expected_actor: revoke_successor,
            binding_generation: 2,
            authority_epoch: revoke_epoch,
        },
    );
    assert_eq!(
        runtime.transact(CommandRequest::AdoptEffect {
            effect: revoke_effect,
            successor: revoke_successor,
            binding_generation: 2,
        }),
        Err(TxError::Core(CoreError::GateClosed))
    );

    let adopt_effect = effect(root(12), 1);
    let adopt_origin = principal(12, 1);
    let adopt_successor = principal(12, 2);
    create_registered_reply(runtime, adopt_effect, adopt_origin);
    fence_snapshot_ready_rebind(
        runtime,
        adopt_effect.root(),
        adopt_origin,
        adopt_successor,
        snapshot(12),
    );
    let stale_epoch = runtime.observe(|engine| {
        engine
            .estate(adopt_effect)
            .expect("adopt-race estate exists")
            .authority_epoch
    });
    tx(
        runtime,
        CommandRequest::AdoptEffect {
            effect: adopt_effect,
            successor: adopt_successor,
            binding_generation: 2,
        },
    );
    assert_eq!(
        runtime.transact(CommandRequest::BeginRevoke {
            effect: adopt_effect,
            expected_actor: adopt_successor,
            binding_generation: 2,
            authority_epoch: stale_epoch,
        }),
        Err(TxError::Core(CoreError::StaleAuthorityEpoch))
    );
}

fn create_registered_reply(runtime: &SpikeRuntime, effect: EffectId, origin: PrincipalIncarnation) {
    tx(
        runtime,
        CommandRequest::CreateEstate {
            effect,
            origin,
            binding_generation: 1,
            domain: REPLY_DOMAIN,
            obligation: REPLY_OBLIGATION_PUBLICATION,
            charge_account: ChargeAccountId::new(effect.root().get())
                .expect("race charge account is valid"),
        },
    );
}

fn fence_snapshot_ready_rebind(
    runtime: &SpikeRuntime,
    root: RootId,
    origin: PrincipalIncarnation,
    successor: PrincipalIncarnation,
    snapshot: SnapshotId,
) {
    fence_and_snapshot(runtime, root, origin, 1, snapshot);
    tx(
        runtime,
        CommandRequest::Ready {
            root,
            snapshot,
            successor,
        },
    );
    tx(
        runtime,
        CommandRequest::Rebind {
            root,
            snapshot,
            successor,
            binding_generation: 2,
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

const fn root(value: u64) -> RootId {
    match RootId::new(value) {
        Ok(value) => value,
        Err(_) => panic!("probe root must be non-zero"),
    }
}

const fn effect(root: RootId, sequence: u64) -> EffectId {
    match EffectId::new(root, sequence) {
        Ok(value) => value,
        Err(_) => panic!("probe effect sequence must be non-zero"),
    }
}

const fn principal(id: u64, generation: u64) -> PrincipalIncarnation {
    let id = match PrincipalId::new(id) {
        Ok(value) => value,
        Err(_) => panic!("probe principal must be non-zero"),
    };
    match PrincipalIncarnation::new(id, generation) {
        Ok(value) => value,
        Err(_) => panic!("probe incarnation generation must be non-zero"),
    }
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
