#[allow(dead_code)]
mod support;

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, AuthorityState,
    CatalogSet, ClaimId, ClaimScope, Command as AuthorizedCommand, CommandRequest, CommitIntent,
    CommitState, ComponentCommitOperation, ComponentId, ComponentProviderBinding, CoreError,
    CoreLimits, CustodyState, DEVICE_CLAIM_IOVA, DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT,
    DEVICE_COMMIT_RECEIPT_SCHEMA, DEVICE_EVIDENCE_IOTLB, DEVICE_EVIDENCE_IRQ_DRAINED,
    DEVICE_EVIDENCE_RESET, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, DMA_ARENA_REUSE_COMPOSITE,
    EffectId, Engine, EvidenceKindId, ExecutorCoordinate, ExternalOutcome, Freshness, OutcomeState,
    REPLY_APPLY_RECEIPT_SCHEMA, REPLY_CLAIM_PUBLICATION_SLOT, REPLY_COMMIT_RECEIPT_SCHEMA,
    REPLY_SETTLEMENT_RECEIPT_SCHEMA, REPLY_VERIFIER, ReceiptBinding, ResourceGeneration,
    SettlementClaim, SettlementState, TransitionOutput, VerifierId, standard_catalog,
};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};
use std::sync::Arc as StdArc;
use support::{
    ExactTestVerifier, Harness, TestReceipt, charge, claim, digest, effect, executor,
    fence_and_rebind, freshness, recovery_anchor, resource, resource_generation, snapshot,
    verified_apply_completion_for_engine, verified_commit_outcome_for_engine,
    verified_settlement_ack_for_engine,
};

fn standard_catalog_set() -> CatalogSet {
    CatalogSet::new(&[standard_catalog()]).expect("standard catalog set must be valid")
}

fn admit_composite(
    harness: &mut Harness,
    effect: EffectId,
    origin: ExecutorCoordinate,
    kind: cser_core::CompositeKindId,
    charge_account: cser_core::ChargeAccountId,
    components: &[ComponentId],
) {
    harness
        .tx(CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin,
            kind,
            charge_account,
            bindings: components
                .iter()
                .copied()
                .map(|component| ComponentProviderBinding::new(component, support::provider()))
                .collect(),
        })
        .unwrap();
}

fn model_transition(body: impl Fn() + Send + Sync + 'static) {
    let body = StdArc::new(body);
    model(move || {
        let body = StdArc::clone(&body);
        thread::Builder::new()
            .stack_size(16 << 20)
            .spawn(move || body())
            .expect("Loom scenario thread must spawn")
            .join()
            .expect("Loom scenario thread must complete");
    });
}

fn spawn_transition<F, T>(body: F) -> thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(body)
        .expect("Loom transition thread must spawn")
}

fn composite_commit_fence_scenario(root_value: u64) {
    model_transition(move || {
        let mut harness = Harness::standard();
        let effect = effect(root_value, 1);
        let origin = executor(root_value, 1);
        admit_composite(
            &mut harness,
            effect,
            origin,
            AGENT_OPERATION_COMPOSITE,
            charge(root_value),
            &[AGENT_COMPONENT_REPLY, AGENT_COMPONENT_DMA],
        );
        harness
            .tx(CommandRequest::AddComponentClaim {
                effect,
                component: AGENT_COMPONENT_REPLY,
                actor: origin,
                claim: claim(root_value),
                kind: REPLY_CLAIM_PUBLICATION_SLOT,
                scope: ClaimScope::Logical,
                resource: resource(root_value),
                resource_generation: resource_generation(1),
                units: 1,
            })
            .unwrap();
        harness
            .tx(CommandRequest::AddComponentClaim {
                effect,
                component: AGENT_COMPONENT_DMA,
                actor: origin,
                claim: claim(root_value + 1),
                kind: DEVICE_CLAIM_QUEUE_SLOT,
                scope: ClaimScope::Device(cser_core::DeviceScopeId::new(root_value).unwrap()),
                resource: resource(root_value + 1),
                resource_generation: resource_generation(1),
                units: 1,
            })
            .unwrap();
        harness
            .tx(CommandRequest::PrepareCompositeEffect {
                effect,
                actor: origin,
            })
            .unwrap();
        let initial_revision = harness.engine.revision();
        let shared = Arc::new(Mutex::new(harness.engine));

        let commit_engine = Arc::clone(&shared);
        let commit = thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(move || {
                commit_engine
                    .lock()
                    .unwrap()
                    .transact_volatile(CommandRequest::RecordCompositeCommitIntents {
                        effect,
                        actor: origin,
                        operations: vec![
                            ComponentCommitOperation::new(AGENT_COMPONENT_REPLY, digest(91)),
                            ComponentCommitOperation::new(AGENT_COMPONENT_DMA, digest(92)),
                        ],
                    })
                    .map(|_| ())
            })
            .expect("component commit racer must spawn");
        let fence_engine = Arc::clone(&shared);
        let fence = thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(move || {
                fence_engine
                    .lock()
                    .unwrap()
                    .transact_volatile(CommandRequest::FenceExecutor {
                        operation: effect.operation(),
                        crashed: origin,
                    })
                    .map(|_| ())
            })
            .expect("parent fence racer must spawn");

        let commit_result = commit.join().unwrap();
        assert_eq!(fence.join().unwrap(), Ok(()));
        let engine = shared.lock().unwrap();
        assert_eq!(
            engine.composite_effect(effect).unwrap().authority,
            AuthorityState::Fenced
        );
        match commit_result {
            Ok(()) => {
                assert_eq!(engine.revision(), initial_revision + 2);
                for (component, operation) in [
                    (AGENT_COMPONENT_REPLY, digest(91)),
                    (AGENT_COMPONENT_DMA, digest(92)),
                ] {
                    assert_eq!(
                        engine.component(effect, component).unwrap().commit,
                        CommitState::Committed
                    );
                    assert_eq!(
                        engine.component(effect, component).unwrap().outcome,
                        OutcomeState::Indeterminate(operation)
                    );
                }
            }
            Err(CoreError::WrongRecoveryState) => {
                assert_eq!(engine.revision(), initial_revision + 1);
                for component in [AGENT_COMPONENT_REPLY, AGENT_COMPONENT_DMA] {
                    assert_eq!(
                        engine.component(effect, component).unwrap().commit,
                        CommitState::Prepared
                    );
                }
            }
            other => panic!("unexpected component commit/fence outcome: {other:?}"),
        }
    });
}

fn acknowledge_component(
    harness: &mut Harness,
    intent: CommitIntent,
    receipt_marker: u8,
    verifier: VerifierId,
    receipt_schema: cser_core::ReceiptSchemaId,
) {
    let outcome = verified_commit_outcome_for_engine(
        &harness.engine,
        &intent,
        verifier,
        receipt_schema,
        ExternalOutcome::Success,
        digest(receipt_marker),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
}

fn commit_agent_components(
    harness: &mut Harness,
    effect: EffectId,
    actor: ExecutorCoordinate,
    reply_operation: u8,
    reply_receipt: u8,
    dma_operation: u8,
    dma_receipt: u8,
) {
    let intents = match harness.output(CommandRequest::RecordCompositeCommitIntents {
        effect,
        actor,
        operations: vec![
            ComponentCommitOperation::new(AGENT_COMPONENT_REPLY, digest(reply_operation)),
            ComponentCommitOperation::new(AGENT_COMPONENT_DMA, digest(dma_operation)),
        ],
    }) {
        TransitionOutput::CompositeCommitIntents(intents) => intents,
        other => panic!("expected atomic composite commit intents, got {other:?}"),
    };
    let mut intents = intents.into_iter();
    acknowledge_component(
        harness,
        intents.next().expect("reply intent"),
        reply_receipt,
        REPLY_VERIFIER,
        REPLY_COMMIT_RECEIPT_SCHEMA,
    );
    acknowledge_component(
        harness,
        intents.next().expect("DMA intent"),
        dma_receipt,
        DEVICE_VERIFIER,
        DEVICE_COMMIT_RECEIPT_SCHEMA,
    );
    assert!(intents.next().is_none());
}

fn committed_rebound_composite(
    harness: &mut Harness,
    root_value: u64,
) -> (EffectId, ExecutorCoordinate) {
    let effect = effect(root_value, 1);
    let origin = executor(root_value, 1);
    admit_composite(
        harness,
        effect,
        origin,
        AGENT_OPERATION_COMPOSITE,
        charge(root_value),
        &[AGENT_COMPONENT_REPLY, AGENT_COMPONENT_DMA],
    );
    harness
        .tx(CommandRequest::AddComponentClaim {
            effect,
            component: AGENT_COMPONENT_REPLY,
            actor: origin,
            claim: claim(root_value),
            kind: REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(root_value),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    for (offset, kind) in [
        (1, DEVICE_CLAIM_QUEUE_SLOT),
        (2, DEVICE_CLAIM_PINNED_PAGE),
        (3, DEVICE_CLAIM_IOVA),
    ] {
        harness
            .tx(CommandRequest::AddComponentClaim {
                effect,
                component: AGENT_COMPONENT_DMA,
                actor: origin,
                claim: claim(root_value + offset),
                kind,
                scope: ClaimScope::Device(cser_core::DeviceScopeId::new(root_value).unwrap()),
                resource: resource(root_value + offset),
                resource_generation: resource_generation(1),
                units: 1,
            })
            .unwrap();
    }
    harness
        .tx(CommandRequest::PrepareCompositeEffect {
            effect,
            actor: origin,
        })
        .unwrap();
    commit_agent_components(harness, effect, origin, 101, 102, 103, 104);
    let successor = executor(root_value, 2);
    fence_and_rebind(harness, effect, origin, successor, root_value * 10);
    (effect, successor)
}

fn claim_component_reply(
    harness: &mut Harness,
    effect: EffectId,
    successor: ExecutorCoordinate,
) -> SettlementClaim {
    match harness.output(CommandRequest::ClaimComponentSettlement {
        effect,
        component: AGENT_COMPONENT_REPLY,
        claimant: successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected component settlement claim, got {other:?}"),
    }
}

fn component_evidence_command(
    engine: &cser_core::Engine,
    effect: EffectId,
    claim: ClaimId,
    kind: EvidenceKindId,
    observation: Freshness,
    marker: u8,
) -> AuthorizedCommand {
    let challenge = engine
        .component_evidence_challenge(effect, AGENT_COMPONENT_DMA, claim, kind)
        .unwrap();
    let binding = ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA);
    let receipt = TestReceipt {
        effect,
        claim,
        kind,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject: challenge.subject(),
        observation,
        digest: digest(marker),
    };
    engine
        .verify_component_retirement_evidence(
            effect,
            AGENT_COMPONENT_DMA,
            claim,
            kind,
            &ExactTestVerifier::new(binding.verifier(), binding.receipt_schema()),
            &receipt,
        )
        .unwrap()
        .submit()
}

fn current_component_evidence_command(
    engine: &cser_core::Engine,
    effect: EffectId,
    claim: ClaimId,
    kind: EvidenceKindId,
    marker: u8,
) -> AuthorizedCommand {
    let observation = engine
        .component_evidence_challenge(effect, AGENT_COMPONENT_DMA, claim, kind)
        .unwrap()
        .current_observation();
    component_evidence_command(engine, effect, claim, kind, observation, marker)
}

fn reset_component_command(
    engine: &cser_core::Engine,
    effect: EffectId,
    claim: ClaimId,
    marker: u8,
) -> AuthorizedCommand {
    let challenge = engine
        .component_evidence_challenge(effect, AGENT_COMPONENT_DMA, claim, DEVICE_EVIDENCE_RESET)
        .unwrap();
    let current = challenge.current_observation();
    let observation = if current.device() == challenge.subject().device() {
        freshness(
            current.boot().get(),
            current.registry().get(),
            current.device().get() + 1,
            current.journal().get(),
        )
    } else {
        current
    };
    component_evidence_command(
        engine,
        effect,
        claim,
        DEVICE_EVIDENCE_RESET,
        observation,
        marker,
    )
}

fn create_dma_reuse_effect(
    harness: &mut Harness,
    root_value: u64,
    sequence: u64,
    actor: ExecutorCoordinate,
) -> EffectId {
    let reuse = effect(root_value, sequence);
    harness
        .tx(CommandRequest::AdmitScopedCompositeEffect {
            effect: reuse,
            origin: actor,
            kind: DMA_ARENA_REUSE_COMPOSITE,
            charge_account: charge(root_value),
            bindings: vec![ComponentProviderBinding::new(
                AGENT_COMPONENT_DMA,
                support::provider(),
            )],
        })
        .unwrap();
    reuse
}

#[test]
fn loom_reply_and_dma_commit_intents_share_the_parent_fence_gate() {
    composite_commit_fence_scenario(92);
}

#[test]
fn loom_component_second_crash_before_or_after_durable_intent() {
    model_transition(|| {
        let mut harness = Harness::standard();
        let (effect, successor) = committed_rebound_composite(&mut harness, 94);
        let claim = claim_component_reply(&mut harness, effect, successor);
        let intent = claim.record_apply_intent(digest(111)).unwrap();
        let shared = Arc::new(Mutex::new(harness.engine));

        let intent_engine = Arc::clone(&shared);
        let intent_thread = spawn_transition(move || {
            intent_engine
                .lock()
                .unwrap()
                .transact_volatile(intent)
                .map(|_| ())
        });
        let crash_engine = Arc::clone(&shared);
        let crash_thread = spawn_transition(move || {
            crash_engine
                .lock()
                .unwrap()
                .transact_volatile(CommandRequest::FenceExecutor {
                    operation: effect.operation(),
                    crashed: successor,
                })
                .map(|_| ())
        });

        let intent_result = intent_thread.join().unwrap();
        assert_eq!(crash_thread.join().unwrap(), Ok(()));
        let engine = shared.lock().unwrap();
        match intent_result {
            Ok(()) => assert_eq!(
                engine
                    .component(effect, AGENT_COMPONENT_REPLY)
                    .unwrap()
                    .settlement,
                SettlementState::ReconciliationRequired {
                    generation: 2,
                    applied: false
                }
            ),
            Err(CoreError::StaleSettlementClaim) => assert_eq!(
                engine
                    .component(effect, AGENT_COMPONENT_REPLY)
                    .unwrap()
                    .settlement,
                SettlementState::Open { generation: 2 }
            ),
            other => panic!("unexpected component intent/crash outcome: {other:?}"),
        }
        assert_eq!(
            engine
                .component(effect, AGENT_COMPONENT_DMA)
                .unwrap()
                .retained_claims,
            3
        );
    });
}

#[test]
fn loom_component_second_crash_before_or_after_external_apply() {
    model_transition(|| {
        let mut harness = Harness::standard();
        let (effect, successor) = committed_rebound_composite(&mut harness, 95);
        let claim = claim_component_reply(&mut harness, effect, successor);
        let claim = match harness.output(claim.record_apply_intent(digest(112)).unwrap()) {
            TransitionOutput::SettlementClaim(claim) => claim,
            other => panic!("expected intent-stage component claim, got {other:?}"),
        };
        let applied = verified_apply_completion_for_engine(
            &harness.engine,
            &claim,
            REPLY_VERIFIER,
            REPLY_APPLY_RECEIPT_SCHEMA,
            digest(113),
        );
        let record_applied = claim.record_applied(applied).unwrap();
        let shared = Arc::new(Mutex::new(harness.engine));

        let apply_engine = Arc::clone(&shared);
        let apply_thread = spawn_transition(move || {
            apply_engine
                .lock()
                .unwrap()
                .transact_volatile(record_applied)
                .map(|_| ())
        });
        let crash_engine = Arc::clone(&shared);
        let crash_thread = spawn_transition(move || {
            crash_engine
                .lock()
                .unwrap()
                .transact_volatile(CommandRequest::FenceExecutor {
                    operation: effect.operation(),
                    crashed: successor,
                })
                .map(|_| ())
        });

        let apply_result = apply_thread.join().unwrap();
        assert_eq!(crash_thread.join().unwrap(), Ok(()));
        let engine = shared.lock().unwrap();
        match apply_result {
            Ok(()) => assert_eq!(
                engine
                    .component(effect, AGENT_COMPONENT_REPLY)
                    .unwrap()
                    .settlement,
                SettlementState::ReconciliationRequired {
                    generation: 2,
                    applied: true
                }
            ),
            Err(CoreError::StaleSettlementClaim) => assert_eq!(
                engine
                    .component(effect, AGENT_COMPONENT_REPLY)
                    .unwrap()
                    .settlement,
                SettlementState::ReconciliationRequired {
                    generation: 2,
                    applied: false
                }
            ),
            other => panic!("unexpected component apply/crash outcome: {other:?}"),
        }
        assert_eq!(
            engine
                .component(effect, AGENT_COMPONENT_DMA)
                .unwrap()
                .retained_claims,
            3
        );
    });
}

#[test]
fn loom_component_ack_and_second_crash_settle_once() {
    model_transition(|| {
        let mut harness = Harness::standard();
        let (effect, successor) = committed_rebound_composite(&mut harness, 96);
        let claim = claim_component_reply(&mut harness, effect, successor);
        let claim = match harness.output(claim.record_apply_intent(digest(114)).unwrap()) {
            TransitionOutput::SettlementClaim(claim) => claim,
            other => panic!("expected intent-stage component claim, got {other:?}"),
        };
        let applied = verified_apply_completion_for_engine(
            &harness.engine,
            &claim,
            REPLY_VERIFIER,
            REPLY_APPLY_RECEIPT_SCHEMA,
            digest(115),
        );
        let claim = match harness.output(claim.record_applied(applied).unwrap()) {
            TransitionOutput::SettlementClaim(claim) => claim,
            other => panic!("expected applied-stage component claim, got {other:?}"),
        };
        let acknowledgement = verified_settlement_ack_for_engine(
            &harness.engine,
            &claim,
            REPLY_VERIFIER,
            REPLY_SETTLEMENT_RECEIPT_SCHEMA,
            digest(116),
        );
        let settle = claim.settle(acknowledgement).unwrap();
        let shared = Arc::new(Mutex::new(harness.engine));

        let settle_engine = Arc::clone(&shared);
        let settle_thread = spawn_transition(move || {
            settle_engine
                .lock()
                .unwrap()
                .transact_volatile(settle)
                .map(|_| ())
        });
        let crash_engine = Arc::clone(&shared);
        let crash_thread = spawn_transition(move || {
            crash_engine
                .lock()
                .unwrap()
                .transact_volatile(CommandRequest::FenceExecutor {
                    operation: effect.operation(),
                    crashed: successor,
                })
                .map(|_| ())
        });

        let settle_result = settle_thread.join().unwrap();
        assert_eq!(crash_thread.join().unwrap(), Ok(()));
        let engine = shared.lock().unwrap();
        match settle_result {
            Ok(()) => assert_eq!(
                engine
                    .component(effect, AGENT_COMPONENT_REPLY)
                    .unwrap()
                    .settlement,
                SettlementState::Settled
            ),
            Err(CoreError::StaleSettlementClaim) => assert_eq!(
                engine
                    .component(effect, AGENT_COMPONENT_REPLY)
                    .unwrap()
                    .settlement,
                SettlementState::ReconciliationRequired {
                    generation: 2,
                    applied: true
                }
            ),
            other => panic!("unexpected component ack/crash outcome: {other:?}"),
        }
        assert_eq!(
            engine
                .component(effect, AGENT_COMPONENT_DMA)
                .unwrap()
                .retained_claims,
            3
        );
    });
}

#[test]
fn loom_reply_ack_and_dma_retirement_evidence_discharge_independently() {
    model_transition(|| {
        let mut harness = Harness::standard();
        let root_value = 97;
        let (effect, successor) = committed_rebound_composite(&mut harness, root_value);
        let queue_claim = claim(root_value + 1);

        let reply = claim_component_reply(&mut harness, effect, successor);
        let reply = match harness.output(reply.record_apply_intent(digest(117)).unwrap()) {
            TransitionOutput::SettlementClaim(claim) => claim,
            other => panic!("expected intent-stage component claim, got {other:?}"),
        };
        let applied = verified_apply_completion_for_engine(
            &harness.engine,
            &reply,
            REPLY_VERIFIER,
            REPLY_APPLY_RECEIPT_SCHEMA,
            digest(118),
        );
        let reply = match harness.output(reply.record_applied(applied).unwrap()) {
            TransitionOutput::SettlementClaim(claim) => claim,
            other => panic!("expected applied-stage component claim, got {other:?}"),
        };
        let acknowledgement = verified_settlement_ack_for_engine(
            &harness.engine,
            &reply,
            REPLY_VERIFIER,
            REPLY_SETTLEMENT_RECEIPT_SCHEMA,
            digest(119),
        );
        let settle = reply.settle(acknowledgement).unwrap();

        let reset = reset_component_command(&harness.engine, effect, queue_claim, 120);
        harness.tx(reset).unwrap();
        let retire_queue = current_component_evidence_command(
            &harness.engine,
            effect,
            queue_claim,
            DEVICE_EVIDENCE_IRQ_DRAINED,
            121,
        );
        let initial_revision = harness.engine.revision();
        let shared = Arc::new(Mutex::new(harness.engine));

        let reply_engine = Arc::clone(&shared);
        let reply_thread = spawn_transition(move || {
            reply_engine
                .lock()
                .unwrap()
                .transact_volatile(settle)
                .map(|_| ())
        });
        let dma_engine = Arc::clone(&shared);
        let dma_thread = spawn_transition(move || {
            dma_engine
                .lock()
                .unwrap()
                .transact_volatile(retire_queue)
                .map(|_| ())
        });

        assert_eq!(reply_thread.join().unwrap(), Ok(()));
        assert_eq!(dma_thread.join().unwrap(), Ok(()));
        let engine = shared.lock().unwrap();
        assert_eq!(engine.revision(), initial_revision + 2);
        assert_eq!(
            engine
                .component(effect, AGENT_COMPONENT_REPLY)
                .unwrap()
                .settlement,
            SettlementState::Settled
        );
        let dma = engine.component(effect, AGENT_COMPONENT_DMA).unwrap();
        assert_eq!(dma.retained_claims, 2);
        let claims = engine
            .component_claims(effect, AGENT_COMPONENT_DMA)
            .unwrap();
        assert!(
            claims
                .iter()
                .find(|projection| projection.claim == queue_claim)
                .unwrap()
                .retired
        );
        assert_eq!(
            claims
                .iter()
                .filter(|projection| !projection.retired)
                .count(),
            2
        );
    });
}

fn component_discharge_crash_scenario(
    root_value: u64,
    claim_offset: u64,
    terminal_evidence: EvidenceKindId,
) {
    model_transition(move || {
        let mut harness = Harness::standard();
        let (effect, successor) = committed_rebound_composite(&mut harness, root_value);
        let target = claim(root_value + claim_offset);
        let reset = reset_component_command(&harness.engine, effect, target, 120);
        harness.tx(reset).unwrap();
        let terminal = current_component_evidence_command(
            &harness.engine,
            effect,
            target,
            terminal_evidence,
            121,
        );
        let shared = Arc::new(Mutex::new(harness.engine));

        let evidence_engine = Arc::clone(&shared);
        let evidence_thread = spawn_transition(move || {
            evidence_engine
                .lock()
                .unwrap()
                .transact_volatile(terminal)
                .map(|_| ())
        });
        let crash_engine = Arc::clone(&shared);
        let crash_thread = spawn_transition(move || {
            crash_engine
                .lock()
                .unwrap()
                .transact_volatile(CommandRequest::FenceExecutor {
                    operation: effect.operation(),
                    crashed: successor,
                })
                .map(|_| ())
        });

        assert_eq!(evidence_thread.join().unwrap(), Ok(()));
        assert_eq!(crash_thread.join().unwrap(), Ok(()));
        let engine = shared.lock().unwrap();
        let claims = engine
            .component_claims(effect, AGENT_COMPONENT_DMA)
            .unwrap();
        assert_eq!(claims.iter().filter(|claim| claim.retired).count(), 1);
        assert!(
            claims
                .iter()
                .find(|projection| projection.claim == target)
                .unwrap()
                .retired
        );
        assert_eq!(
            engine
                .component(effect, AGENT_COMPONENT_REPLY)
                .unwrap()
                .retained_claims,
            1
        );
    });
}

#[test]
fn loom_second_crash_after_each_queue_pfn_and_iova_discharge_preserves_custody() {
    component_discharge_crash_scenario(97, 1, DEVICE_EVIDENCE_IRQ_DRAINED);
    component_discharge_crash_scenario(98, 2, DEVICE_EVIDENCE_IOTLB);
    component_discharge_crash_scenario(99, 3, DEVICE_EVIDENCE_IOTLB);
}

#[test]
fn loom_final_irq_evidence_and_component_reuse_reservation_linearize_once() {
    model_transition(|| {
        let root_value = 100;
        let mut harness = Harness::standard();
        let (original, successor) = committed_rebound_composite(&mut harness, root_value);
        let queue_claim = claim(root_value + 1);
        let queue_resource = resource(root_value + 1);
        let reset = reset_component_command(&harness.engine, original, queue_claim, 130);
        harness.tx(reset).unwrap();
        let terminal = current_component_evidence_command(
            &harness.engine,
            original,
            queue_claim,
            DEVICE_EVIDENCE_IRQ_DRAINED,
            131,
        );
        let reuse = create_dma_reuse_effect(&mut harness, root_value, 2, successor);
        let shared = Arc::new(Mutex::new(harness.engine));

        let evidence_engine = Arc::clone(&shared);
        let evidence_thread = spawn_transition(move || {
            evidence_engine
                .lock()
                .unwrap()
                .transact_volatile(terminal)
                .map(|_| ())
        });
        let reserve_engine = Arc::clone(&shared);
        let reserve_thread = spawn_transition(move || {
            reserve_engine
                .lock()
                .unwrap()
                .transact_volatile(CommandRequest::ReserveComponentReuse {
                    effect: reuse,
                    component: AGENT_COMPONENT_DMA,
                    actor: successor,
                    claim: claim(root_value + 10),
                    kind: DEVICE_CLAIM_QUEUE_SLOT,
                    scope: ClaimScope::Device(cser_core::DeviceScopeId::new(root_value).unwrap()),
                    resource: queue_resource,
                    expected_generation: resource_generation(1),
                    units: 1,
                    reuse_contract: digest(201),
                })
                .map(|_| ())
        });

        assert_eq!(evidence_thread.join().unwrap(), Ok(()));
        let reserve_result = reserve_thread.join().unwrap();
        let engine = shared.lock().unwrap();
        assert!(
            engine
                .component_claims(original, AGENT_COMPONENT_DMA)
                .unwrap()
                .iter()
                .find(|projection| projection.claim == queue_claim)
                .unwrap()
                .retired
        );
        match reserve_result {
            Ok(()) => {
                let claims = engine.component_claims(reuse, AGENT_COMPONENT_DMA).unwrap();
                assert_eq!(claims.len(), 1);
                assert_eq!(claims[0].resource, queue_resource);
                assert_eq!(claims[0].resource_generation, resource_generation(2));
            }
            Err(CoreError::ResourceRetained) => assert!(
                engine
                    .component_claims(reuse, AGENT_COMPONENT_DMA)
                    .unwrap()
                    .is_empty()
            ),
            other => panic!("unexpected evidence/reuse reservation outcome: {other:?}"),
        }
    });
}

#[test]
fn loom_conflicting_component_reuse_reservations_have_one_owner() {
    model_transition(|| {
        let root_value = 101;
        let mut harness = Harness::standard();
        let (original, successor) = committed_rebound_composite(&mut harness, root_value);
        let queue_claim = claim(root_value + 1);
        let queue_resource = resource(root_value + 1);
        let reset = reset_component_command(&harness.engine, original, queue_claim, 132);
        harness.tx(reset).unwrap();
        let terminal = current_component_evidence_command(
            &harness.engine,
            original,
            queue_claim,
            DEVICE_EVIDENCE_IRQ_DRAINED,
            133,
        );
        harness.tx(terminal).unwrap();
        let first = create_dma_reuse_effect(&mut harness, root_value, 2, successor);
        let second = create_dma_reuse_effect(&mut harness, root_value, 3, successor);
        let shared = Arc::new(Mutex::new(harness.engine));

        let first_engine = Arc::clone(&shared);
        let first_thread = spawn_transition(move || {
            first_engine
                .lock()
                .unwrap()
                .transact_volatile(CommandRequest::ReserveComponentReuse {
                    effect: first,
                    component: AGENT_COMPONENT_DMA,
                    actor: successor,
                    claim: claim(root_value + 10),
                    kind: DEVICE_CLAIM_QUEUE_SLOT,
                    scope: ClaimScope::Device(cser_core::DeviceScopeId::new(root_value).unwrap()),
                    resource: queue_resource,
                    expected_generation: resource_generation(1),
                    units: 1,
                    reuse_contract: digest(202),
                })
                .map(|_| ())
        });
        let second_engine = Arc::clone(&shared);
        let second_thread = spawn_transition(move || {
            second_engine
                .lock()
                .unwrap()
                .transact_volatile(CommandRequest::ReserveComponentReuse {
                    effect: second,
                    component: AGENT_COMPONENT_DMA,
                    actor: successor,
                    claim: claim(root_value + 11),
                    kind: DEVICE_CLAIM_QUEUE_SLOT,
                    scope: ClaimScope::Device(cser_core::DeviceScopeId::new(root_value).unwrap()),
                    resource: queue_resource,
                    expected_generation: resource_generation(1),
                    units: 1,
                    reuse_contract: digest(203),
                })
                .map(|_| ())
        });

        let first_result = first_thread.join().unwrap();
        let second_result = second_thread.join().unwrap();
        assert!(matches!(
            (first_result, second_result),
            (
                Ok(()),
                Err(CoreError::ResourceRetained | CoreError::StaleResourceGeneration)
            ) | (
                Err(CoreError::ResourceRetained | CoreError::StaleResourceGeneration),
                Ok(())
            )
        ));
        let engine = shared.lock().unwrap();
        assert_eq!(
            [first, second]
                .into_iter()
                .filter(|effect| {
                    !engine
                        .component_claims(*effect, AGENT_COMPONENT_DMA)
                        .unwrap()
                        .is_empty()
                })
                .count(),
            1
        );
        assert_eq!(
            engine.check_reusable(queue_resource, ResourceGeneration::new(1).unwrap()),
            Err(CoreError::ResourceRetained)
        );
    });
}

#[test]
fn loom_late_old_irq_cannot_mutate_generation_plus_one_activation() {
    model_transition(|| {
        let root_value = 102;
        let mut harness = Harness::standard();
        let (original, successor) = committed_rebound_composite(&mut harness, root_value);
        let queue_claim = claim(root_value + 1);
        let queue_resource = resource(root_value + 1);
        let late_irq = current_component_evidence_command(
            &harness.engine,
            original,
            queue_claim,
            DEVICE_EVIDENCE_IRQ_DRAINED,
            134,
        );
        let reset = reset_component_command(&harness.engine, original, queue_claim, 135);
        harness.tx(reset).unwrap();
        let terminal = current_component_evidence_command(
            &harness.engine,
            original,
            queue_claim,
            DEVICE_EVIDENCE_IRQ_DRAINED,
            136,
        );
        harness.tx(terminal).unwrap();
        let reuse = create_dma_reuse_effect(&mut harness, root_value, 2, successor);
        let permit = match harness.output(CommandRequest::ReserveComponentReuse {
            effect: reuse,
            component: AGENT_COMPONENT_DMA,
            actor: successor,
            claim: claim(root_value + 10),
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(cser_core::DeviceScopeId::new(root_value).unwrap()),
            resource: queue_resource,
            expected_generation: resource_generation(1),
            units: 1,
            reuse_contract: digest(204),
        }) {
            TransitionOutput::ReusePermit(permit) => permit,
            other => panic!("expected generation-plus-one reuse permit, got {other:?}"),
        };
        let activate = permit.activate();
        let shared = Arc::new(Mutex::new(harness.engine));

        let irq_engine = Arc::clone(&shared);
        let irq_thread = spawn_transition(move || {
            irq_engine
                .lock()
                .unwrap()
                .transact_volatile(late_irq)
                .map(|_| ())
        });
        let activate_engine = Arc::clone(&shared);
        let activate_thread = spawn_transition(move || {
            activate_engine
                .lock()
                .unwrap()
                .transact_volatile(activate)
                .map(|_| ())
        });

        assert!(matches!(
            irq_thread.join().unwrap(),
            Err(CoreError::StaleEvidence | CoreError::DuplicateEvidence)
        ));
        assert_eq!(activate_thread.join().unwrap(), Ok(()));
        let engine = shared.lock().unwrap();
        let new_claims = engine.component_claims(reuse, AGENT_COMPONENT_DMA).unwrap();
        assert_eq!(new_claims.len(), 1);
        assert_eq!(new_claims[0].resource_generation, resource_generation(2));
        assert!(!new_claims[0].retired);
        // A generation+1 activation is a complete target projection, not
        // merely a non-zero claim count. Check every authority and lifecycle
        // coordinate that a recovery adapter would consume so a stale old
        // generation cannot masquerade as a valid successor.
        let target = engine.composite_effect(reuse).unwrap();
        assert_eq!(target.effect, reuse);
        assert_eq!(target.kind, DMA_ARENA_REUSE_COMPOSITE);
        assert_eq!(target.operation, reuse.operation());
        assert_eq!(target.causal_owner, successor);
        assert_eq!(target.custodian, CustodyState::Executor(successor));
        assert_eq!(target.authority, AuthorityState::Active);
        assert_eq!(target.authority_epoch, 1);
        assert_eq!(target.component_count, 1);
        assert_eq!(target.retained_claims, 1);
        assert_eq!(
            target.provider_bindings,
            vec![ComponentProviderBinding::new(
                AGENT_COMPONENT_DMA,
                support::provider(),
            )]
        );
        let target_component = engine.component(reuse, AGENT_COMPONENT_DMA).unwrap();
        assert_eq!(target_component.commit, CommitState::Registered);
        assert_eq!(target_component.outcome, OutcomeState::Pending);
        assert_eq!(target_component.settlement, SettlementState::Unavailable);
        assert_eq!(
            target_component.retirement,
            cser_core::RetirementState::Held
        );
        assert_eq!(target_component.claim_count, 1);
        assert_eq!(target_component.retained_claims, 1);
        assert!(
            engine
                .component_claims(original, AGENT_COMPONENT_DMA)
                .unwrap()
                .iter()
                .find(|projection| projection.claim == queue_claim)
                .unwrap()
                .retired
        );
    });
}

#[test]
fn loom_precommit_adoption_wins_and_evidence_rejection_survives_two_recoveries() {
    model_transition(|| {
        let mut harness = Harness::standard();
        let root_value = 90;
        let effect = effect(root_value, 1);
        let origin = executor(root_value, 1);
        let successor = executor(root_value, 2);
        let queue_claim = claim(root_value + 1);
        let scope = cser_core::DeviceScopeId::new(root_value).unwrap();
        admit_composite(
            &mut harness,
            effect,
            origin,
            AGENT_OPERATION_COMPOSITE,
            charge(root_value),
            &[AGENT_COMPONENT_REPLY, AGENT_COMPONENT_DMA],
        );
        harness
            .tx(CommandRequest::AddComponentClaim {
                effect,
                component: AGENT_COMPONENT_REPLY,
                actor: origin,
                claim: claim(root_value),
                kind: REPLY_CLAIM_PUBLICATION_SLOT,
                scope: ClaimScope::Logical,
                resource: resource(root_value),
                resource_generation: resource_generation(1),
                units: 1,
            })
            .unwrap();
        harness
            .tx(CommandRequest::AddComponentClaim {
                effect,
                component: AGENT_COMPONENT_DMA,
                actor: origin,
                claim: queue_claim,
                kind: DEVICE_CLAIM_QUEUE_SLOT,
                scope: ClaimScope::Device(scope),
                resource: resource(root_value + 1),
                resource_generation: resource_generation(1),
                units: 1,
            })
            .unwrap();
        harness
            .tx(CommandRequest::PrepareCompositeEffect {
                effect,
                actor: origin,
            })
            .unwrap();
        fence_and_rebind(&mut harness, effect, origin, successor, root_value * 10);
        let reset = reset_component_command(&harness.engine, effect, queue_claim, 90);
        let initial_revision = harness.engine.revision();
        let shared = Arc::new(Mutex::new(harness));

        let adopt_harness = Arc::clone(&shared);
        let adopt = spawn_transition(move || {
            adopt_harness
                .lock()
                .unwrap()
                .tx(CommandRequest::AdoptEffect { effect, successor })
                .map(|_| ())
        });
        let evidence_harness = Arc::clone(&shared);
        let evidence =
            spawn_transition(move || evidence_harness.lock().unwrap().tx(reset).map(|_| ()));

        assert_eq!(adopt.join().unwrap(), Ok(()));
        assert_eq!(evidence.join().unwrap(), Err(CoreError::WrongCommitState));
        let harness = shared.lock().unwrap();
        assert_eq!(harness.engine.revision(), initial_revision + 1);
        assert_eq!(
            harness.engine.composite_effect(effect).unwrap().authority,
            AuthorityState::Active
        );
        assert_eq!(harness.engine.device_generation(scope).unwrap().get(), 1);
        assert!(
            !harness
                .engine
                .component_claims(effect, AGENT_COMPONENT_DMA)
                .unwrap()[0]
                .retired
        );

        let revision = harness.engine.revision();
        let head = harness.engine.head();
        let recovery_anchor = || {
            recovery_anchor(
                standard_catalog_set().digest(),
                freshness(1, 1, 1, 1),
                freshness(2, 1, 1, 2),
                revision,
                head,
                harness.engine.projection_digest(),
            )
        };
        let recovered = Engine::recover(
            standard_catalog_set(),
            CoreLimits::bounded_default(),
            recovery_anchor(),
            &harness.journal,
        )
        .unwrap()
        .into_engine();
        let mut recovered_again = Engine::recover(
            standard_catalog_set(),
            CoreLimits::bounded_default(),
            recovery_anchor(),
            &harness.journal,
        )
        .unwrap()
        .into_engine();
        for engine in [&recovered, &recovered_again] {
            assert_eq!(
                engine.composite_effect(effect).unwrap().authority,
                AuthorityState::Active
            );
            assert_eq!(engine.device_generation(scope).unwrap().get(), 1);
            assert!(
                !engine
                    .component_claims(effect, AGENT_COMPONENT_DMA)
                    .unwrap()[0]
                    .retired
            );
        }
        assert_eq!(
            recovered.projection_digest(),
            recovered_again.projection_digest()
        );
        recovered_again
            .transact_volatile(CommandRequest::CheckpointRecovery {
                boot: freshness(2, 1, 1, 2).boot(),
                journal: freshness(2, 1, 1, 2).journal(),
                device: freshness(2, 1, 1, 2).device(),
            })
            .unwrap();
        let post_recovery_successor = executor(root_value, 3);
        let post_recovery_snapshot = snapshot(root_value * 10 + 1);
        let cohort = recovered_again
            .snapshot_operation(effect.operation(), post_recovery_snapshot)
            .unwrap();
        recovered_again.transact_volatile(cohort.record()).unwrap();
        recovered_again
            .transact_volatile(CommandRequest::Ready {
                operation: effect.operation(),
                snapshot: post_recovery_snapshot,
                successor: post_recovery_successor,
            })
            .unwrap();
        recovered_again
            .transact_volatile(CommandRequest::Rebind {
                operation: effect.operation(),
                snapshot: post_recovery_snapshot,
                successor: post_recovery_successor,
            })
            .unwrap();
        recovered_again
            .transact_volatile(CommandRequest::AdoptEffect {
                effect,
                successor: post_recovery_successor,
            })
            .unwrap();
        let authority_epoch = recovered_again
            .composite_effect(effect)
            .unwrap()
            .authority_epoch;
        recovered_again
            .transact_volatile(CommandRequest::BeginRevoke {
                effect,
                expected_actor: post_recovery_successor,
                authority_epoch,
            })
            .unwrap();
        recovered_again
            .transact_volatile(CommandRequest::ReleaseCompositeEffect { effect })
            .unwrap();
        assert_eq!(
            recovered_again.composite_effect(effect).unwrap().custodian,
            CustodyState::Released
        );
    });
}

#[test]
fn loom_precommit_adopt_and_begin_revoke_drive_the_production_command_gate() {
    model_transition(|| {
        let mut harness = Harness::standard();
        let effect = effect(91, 1);
        let origin = executor(91, 1);
        admit_composite(
            &mut harness,
            effect,
            origin,
            AGENT_OPERATION_COMPOSITE,
            charge(91),
            &[AGENT_COMPONENT_REPLY, AGENT_COMPONENT_DMA],
        );
        harness
            .tx(CommandRequest::AddComponentClaim {
                effect,
                component: AGENT_COMPONENT_REPLY,
                actor: origin,
                claim: claim(91),
                kind: REPLY_CLAIM_PUBLICATION_SLOT,
                scope: ClaimScope::Logical,
                resource: resource(91),
                resource_generation: resource_generation(1),
                units: 1,
            })
            .unwrap();
        for (offset, kind) in [
            (1, DEVICE_CLAIM_QUEUE_SLOT),
            (2, DEVICE_CLAIM_PINNED_PAGE),
            (3, DEVICE_CLAIM_IOVA),
        ] {
            harness
                .tx(CommandRequest::AddComponentClaim {
                    effect,
                    component: AGENT_COMPONENT_DMA,
                    actor: origin,
                    claim: claim(91 + offset),
                    kind,
                    scope: ClaimScope::Device(cser_core::DeviceScopeId::new(91).unwrap()),
                    resource: resource(91 + offset),
                    resource_generation: resource_generation(1),
                    units: 1,
                })
                .unwrap();
        }
        harness
            .tx(CommandRequest::PrepareCompositeEffect {
                effect,
                actor: origin,
            })
            .unwrap();
        let successor = executor(91, 2);
        fence_and_rebind(&mut harness, effect, origin, successor, 910);
        let authority_epoch = harness
            .engine
            .composite_effect(effect)
            .unwrap()
            .authority_epoch;
        let initial_revision = harness.engine.revision();
        let shared = Arc::new(Mutex::new(harness.engine));

        let adopt_engine = Arc::clone(&shared);
        let adopt = thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(move || {
                adopt_engine
                    .lock()
                    .unwrap()
                    .transact_volatile(CommandRequest::AdoptEffect { effect, successor })
                    .map(|_| ())
            })
            .expect("adopt racer must spawn");
        let revoke_engine = Arc::clone(&shared);
        let revoke = thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(move || {
                revoke_engine
                    .lock()
                    .unwrap()
                    .transact_volatile(CommandRequest::BeginRevoke {
                        effect,
                        expected_actor: successor,
                        authority_epoch,
                    })
                    .map(|_| ())
            })
            .expect("revoke racer must spawn");

        let adopt_result = adopt.join().unwrap();
        let revoke_result = revoke.join().unwrap();
        let mut engine = shared.lock().unwrap();
        assert_eq!(engine.revision(), initial_revision + 1);
        match (adopt_result, revoke_result) {
            (Ok(()), Err(CoreError::StaleAuthorityEpoch)) => {
                let composite = engine.composite_effect(effect).unwrap();
                assert_eq!(composite.authority, AuthorityState::Active);
                assert_eq!(
                    engine
                        .component(effect, AGENT_COMPONENT_REPLY)
                        .unwrap()
                        .settlement,
                    SettlementState::Unavailable
                );
                assert_eq!(
                    engine
                        .component(effect, AGENT_COMPONENT_DMA)
                        .unwrap()
                        .settlement,
                    SettlementState::Unavailable
                );
                assert_eq!(engine.composite_effect(effect).unwrap().retained_claims, 4);
            }
            (Err(CoreError::GateClosed), Ok(())) => {
                let composite = engine.composite_effect(effect).unwrap();
                assert_eq!(composite.authority, AuthorityState::Revoked);
                assert_eq!(
                    engine
                        .component(effect, AGENT_COMPONENT_REPLY)
                        .unwrap()
                        .settlement,
                    SettlementState::Revoked
                );
                assert_eq!(
                    engine
                        .component(effect, AGENT_COMPONENT_DMA)
                        .unwrap()
                        .settlement,
                    SettlementState::Revoked
                );
                for component in [AGENT_COMPONENT_REPLY, AGENT_COMPONENT_DMA] {
                    let projection = engine.component(effect, component).unwrap();
                    assert_eq!(projection.retirement, cser_core::RetirementState::Retired);
                    assert_eq!(projection.retained_claims, 0);
                }
                for offset in 0..=3 {
                    assert_eq!(
                        engine.check_reusable(resource(91 + offset), resource_generation(1)),
                        Err(CoreError::UnknownResource)
                    );
                }
                engine
                    .transact_volatile(CommandRequest::ReleaseCompositeEffect { effect })
                    .unwrap();
                assert_eq!(
                    engine.composite_effect(effect).unwrap().custodian,
                    CustodyState::Released
                );
            }
            other => panic!("production adopt/revoke gate did not have one winner: {other:?}"),
        }

        let before_stale = engine.projection_digest();
        let before_revision = engine.revision();
        assert_eq!(
            engine.transact_volatile(CommandRequest::AdoptEffect {
                effect,
                successor: origin,
            }),
            Err(CoreError::StaleExecutor)
        );
        assert_eq!(engine.projection_digest(), before_stale);
        assert_eq!(engine.revision(), before_revision);
    });
}
