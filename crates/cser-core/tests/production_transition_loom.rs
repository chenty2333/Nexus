#[allow(dead_code)]
mod support;

use cser_core::{
    AuthorityState, BootGeneration, ChargeAccountId, ClaimId, ClaimScope, Command, CommandRequest,
    CoreError, CoreLimits, DEVICE_CLAIM_IOVA, DEVICE_DOMAIN, DEVICE_EVIDENCE_IOTLB,
    DEVICE_EVIDENCE_RESET, DEVICE_OBLIGATION_DMA, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER,
    DeviceGeneration, DeviceScopeId, Digest, EffectId, Engine, EvidenceChallenge, ExternalOutcome,
    Freshness, JournalGeneration, PrincipalId, PrincipalIncarnation, ReceiptVerifier,
    RegistryInstance, ResourceGeneration, ResourceId, SettlementClaim, SettlementState, SnapshotId,
    TransitionOutput, TransitionReceipt, TxError, VerificationError, VerifiedObservation,
    VerifierIdentity, standard_catalog,
};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};
use std::sync::Arc as StdArc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawDeviceReceipt {
    effect: EffectId,
    claim: ClaimId,
    kind: cser_core::EvidenceKindId,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
    subject: Freshness,
    observation: Freshness,
    digest: Digest,
}

#[derive(Clone, Copy, Debug)]
struct ExactDeviceVerifier {
    identity: VerifierIdentity,
}

impl ExactDeviceVerifier {
    fn new() -> Self {
        Self {
            identity: VerifierIdentity::new(DEVICE_VERIFIER, 1, DEVICE_RECEIPT_SCHEMA).unwrap(),
        }
    }
}

impl ReceiptVerifier for ExactDeviceVerifier {
    type Receipt = RawDeviceReceipt;

    fn identity(&self) -> VerifierIdentity {
        self.identity
    }

    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        if receipt.effect != challenge.effect()
            || receipt.claim != challenge.claim()
            || receipt.kind != challenge.kind()
            || receipt.resource != challenge.resource()
            || receipt.resource_generation != challenge.resource_generation()
            || receipt.subject != challenge.subject()
            || receipt.digest.is_zero()
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new(
            receipt.subject,
            receipt.observation,
            receipt.digest,
        ))
    }
}

struct Harness {
    engine: Engine,
    journal: Vec<u8>,
}

impl Harness {
    fn new() -> Self {
        Self {
            engine: Engine::new(
                standard_catalog(),
                CoreLimits::bounded_default(),
                freshness(1, 1, 1, 1, 1),
            ),
            journal: Vec::new(),
        }
    }

    fn tx<C: Into<Command>>(&mut self, command: C) -> Result<TransitionReceipt, CoreError> {
        let journal = &mut self.journal;
        self.engine
            .transact(command, |record| {
                journal.extend_from_slice(record.bytes());
                Ok::<(), ()>(())
            })
            .map_err(|error| match error {
                TxError::Core(error) => error,
                TxError::Journal(error) => CoreError::Journal(error),
                TxError::Persist(()) => unreachable!("memory journal cannot fail"),
            })
    }

    fn output<C: Into<Command>>(&mut self, command: C) -> TransitionOutput {
        self.tx(command).unwrap().into_output()
    }
}

#[derive(Clone, Copy)]
struct DeviceFixture {
    effect: EffectId,
    scope: DeviceScopeId,
    claim_a: ClaimId,
    resource_a: ResourceId,
    claim_b: ClaimId,
}

fn spawn_transition<F, T>(body: F) -> thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new()
        .stack_size(4 << 20)
        .spawn(body)
        .expect("Loom transition thread must spawn")
}

fn model_transition<F>(body: F)
where
    F: Fn() + Send + Sync + 'static,
{
    let body = StdArc::new(body);
    model(move || {
        let body = StdArc::clone(&body);
        thread::Builder::new()
            .stack_size(4 << 20)
            .spawn(move || body())
            .expect("Loom scenario thread must spawn")
            .join()
            .expect("Loom scenario thread must complete");
    });
}

fn effect(root_value: u64) -> EffectId {
    EffectId::new(cser_core::RootId::new(root_value).unwrap(), 1).unwrap()
}

fn principal(id: u64, generation: u64) -> PrincipalIncarnation {
    PrincipalIncarnation::new(PrincipalId::new(id).unwrap(), generation).unwrap()
}

fn claim(value: u64) -> ClaimId {
    ClaimId::new(value).unwrap()
}

fn resource(value: u64) -> ResourceId {
    ResourceId::new(value).unwrap()
}

fn snapshot(value: u64) -> SnapshotId {
    SnapshotId::new(value).unwrap()
}

fn digest(value: u8) -> Digest {
    let mut bytes = [0; 32];
    bytes[0] = value;
    Digest::new(bytes)
}

fn freshness(boot: u64, registry: u64, binding: u64, device: u64, journal: u64) -> Freshness {
    Freshness::new(
        BootGeneration::new(boot).unwrap(),
        RegistryInstance::new(registry).unwrap(),
        binding,
        DeviceGeneration::new(device).unwrap(),
        JournalGeneration::new(journal).unwrap(),
    )
    .unwrap()
}

fn committed_reply(harness: &mut Harness, root_value: u64) -> (EffectId, PrincipalIncarnation) {
    let effect = effect(root_value);
    let origin = principal(root_value, 1);
    harness
        .tx(CommandRequest::CreateEstate {
            effect,
            origin,
            binding_generation: 1,
            domain: cser_core::REPLY_DOMAIN,
            obligation: cser_core::REPLY_OBLIGATION_PUBLICATION,
            charge_account: ChargeAccountId::new(root_value).unwrap(),
        })
        .unwrap();
    harness
        .tx(CommandRequest::AddClaim {
            effect,
            actor: origin,
            binding_generation: 1,
            claim: claim(root_value),
            domain: cser_core::REPLY_DOMAIN,
            kind: cser_core::REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(root_value),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
        })
        .unwrap();
    harness
        .tx(CommandRequest::PrepareEffect {
            effect,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    let intent = match harness.output(CommandRequest::RecordCommitIntent {
        effect,
        actor: origin,
        binding_generation: 1,
        operation: digest(10),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    };
    let outcome = support::verified_commit_outcome_for_engine(
        &harness.engine,
        &intent,
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_COMMIT_RECEIPT_SCHEMA,
        ExternalOutcome::Success,
        digest(11),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    (effect, origin)
}

fn fence_and_rebind(
    harness: &mut Harness,
    effect: EffectId,
    crashed: PrincipalIncarnation,
    successor: PrincipalIncarnation,
    old_binding: u64,
    new_binding: u64,
    snapshot_value: u64,
) {
    harness
        .tx(CommandRequest::FenceIncarnation {
            root: effect.root(),
            crashed,
            binding_generation: old_binding,
        })
        .unwrap();
    let snapshot = snapshot(snapshot_value);
    let snapshot_record = harness
        .engine
        .snapshot_root(effect.root(), snapshot)
        .unwrap()
        .record();
    harness.tx(snapshot_record).unwrap();
    harness
        .tx(CommandRequest::Ready {
            root: effect.root(),
            snapshot,
            successor,
        })
        .unwrap();
    harness
        .tx(CommandRequest::Rebind {
            root: effect.root(),
            snapshot,
            successor,
            binding_generation: new_binding,
        })
        .unwrap();
}

fn reconciliation_claim(
    harness: &mut Harness,
    root_value: u64,
    applied_before_crash: bool,
) -> (EffectId, PrincipalIncarnation, SettlementClaim) {
    let (effect, origin) = committed_reply(harness, root_value);
    let successor = principal(root_value, 2);
    fence_and_rebind(harness, effect, origin, successor, 1, 2, root_value * 10);
    let claim = match harness.output(CommandRequest::ClaimSettlement {
        effect,
        claimant: successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    };
    let claim = match harness.output(claim.record_apply_intent(digest(130)).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected intent-stage claim, got {other:?}"),
    };
    if applied_before_crash {
        let applied = support::verified_apply_completion_for_engine(
            &harness.engine,
            &claim,
            cser_core::REPLY_VERIFIER,
            cser_core::REPLY_APPLY_RECEIPT_SCHEMA,
            digest(131),
        );
        let _applied = match harness.output(claim.record_applied(applied).unwrap()) {
            TransitionOutput::SettlementClaim(claim) => claim,
            other => panic!("expected applied-stage claim, got {other:?}"),
        };
    }
    harness
        .tx(CommandRequest::FenceIncarnation {
            root: effect.root(),
            crashed: successor,
            binding_generation: 2,
        })
        .unwrap();

    let third = principal(root_value, 3);
    let recovery_snapshot = snapshot(root_value * 10 + 1);
    let snapshot_record = harness
        .engine
        .snapshot_root(effect.root(), recovery_snapshot)
        .unwrap()
        .record();
    harness.tx(snapshot_record).unwrap();
    harness
        .tx(CommandRequest::Ready {
            root: effect.root(),
            snapshot: recovery_snapshot,
            successor: third,
        })
        .unwrap();
    harness
        .tx(CommandRequest::Rebind {
            root: effect.root(),
            snapshot: recovery_snapshot,
            successor: third,
            binding_generation: 3,
        })
        .unwrap();
    let claim = match harness.output(CommandRequest::ClaimSettlement {
        effect,
        claimant: third,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected reconciliation claim, got {other:?}"),
    };
    (effect, third, claim)
}

fn committed_device_fixture(harness: &mut Harness, root_value: u64) -> DeviceFixture {
    let effect = effect(root_value);
    let origin = principal(root_value, 1);
    let claim_a = claim(root_value * 10 + 1);
    let claim_b = claim(root_value * 10 + 2);
    let resource_a = resource(root_value * 10 + 1);
    let resource_b = resource(root_value * 10 + 2);
    let scope = DeviceScopeId::new(1).unwrap();
    harness
        .tx(CommandRequest::CreateEstate {
            effect,
            origin,
            binding_generation: 1,
            domain: DEVICE_DOMAIN,
            obligation: DEVICE_OBLIGATION_DMA,
            charge_account: ChargeAccountId::new(root_value).unwrap(),
        })
        .unwrap();
    for (claim, resource) in [(claim_a, resource_a), (claim_b, resource_b)] {
        harness
            .tx(CommandRequest::AddClaim {
                effect,
                actor: origin,
                binding_generation: 1,
                claim,
                domain: DEVICE_DOMAIN,
                kind: DEVICE_CLAIM_IOVA,
                scope: ClaimScope::Device(scope),
                resource,
                resource_generation: ResourceGeneration::new(1).unwrap(),
                units: 1,
            })
            .unwrap();
    }
    harness
        .tx(CommandRequest::PrepareEffect {
            effect,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    let intent = match harness.output(CommandRequest::RecordCommitIntent {
        effect,
        actor: origin,
        binding_generation: 1,
        operation: digest(100),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    };
    let outcome = support::verified_commit_outcome_for_engine(
        &harness.engine,
        &intent,
        cser_core::DEVICE_VERIFIER,
        cser_core::DEVICE_COMMIT_RECEIPT_SCHEMA,
        ExternalOutcome::Success,
        digest(101),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    DeviceFixture {
        effect,
        scope,
        claim_a,
        resource_a,
        claim_b,
    }
}

fn verified_device_command(
    engine: &Engine,
    effect: EffectId,
    claim: ClaimId,
    kind: cser_core::EvidenceKindId,
    subject: Freshness,
    observation: Freshness,
    digest: Digest,
) -> Command {
    let challenge = engine.evidence_challenge(effect, claim, kind).unwrap();
    let receipt = RawDeviceReceipt {
        effect,
        claim,
        kind,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject,
        observation,
        digest,
    };
    engine
        .verify_retirement_evidence(effect, claim, kind, &ExactDeviceVerifier::new(), &receipt)
        .unwrap()
        .submit()
}

#[test]
fn loom_claim_and_revoke_share_one_production_gate() {
    model_transition(|| {
        let mut harness = Harness::new();
        let (effect, origin) = committed_reply(&mut harness, 80);
        let successor = principal(80, 2);
        fence_and_rebind(&mut harness, effect, origin, successor, 1, 2, 800);
        let initial_revision = harness.engine.revision();
        let authority_epoch = harness.engine.estate(effect).unwrap().authority_epoch;
        let shared = Arc::new(Mutex::new(harness.engine));

        let claim_engine = Arc::clone(&shared);
        let claim_thread = spawn_transition(move || {
            claim_engine
                .lock()
                .unwrap()
                .transact_volatile(CommandRequest::ClaimSettlement {
                    effect,
                    claimant: successor,
                })
                .map(|_| ())
        });
        let revoke_engine = Arc::clone(&shared);
        let revoke_thread = spawn_transition(move || {
            revoke_engine
                .lock()
                .unwrap()
                .transact_volatile(CommandRequest::BeginRevoke {
                    effect,
                    expected_actor: successor,
                    binding_generation: 2,
                    authority_epoch,
                })
                .map(|_| ())
        });

        let claim_result = claim_thread.join().unwrap();
        let revoke_result = revoke_thread.join().unwrap();
        let engine = shared.lock().unwrap();
        assert_eq!(engine.revision(), initial_revision + 1);
        match (claim_result, revoke_result) {
            (Ok(()), Err(CoreError::GateClaimed)) => assert!(matches!(
                engine.estate(effect).unwrap().settlement,
                SettlementState::Claimed {
                    claimant,
                    generation: 1
                } if claimant == successor
            )),
            (Err(CoreError::GateClosed), Ok(())) => {
                let estate = engine.estate(effect).unwrap();
                assert_eq!(estate.authority, AuthorityState::Revoked);
                assert_eq!(estate.settlement, SettlementState::Open { generation: 1 });
            }
            other => panic!("claim/revoke did not linearize through one gate: {other:?}"),
        }
    });
}

#[test]
fn loom_second_crash_preserves_durable_intent_or_reopens_before_it() {
    model_transition(|| {
        let mut harness = Harness::new();
        let (effect, origin) = committed_reply(&mut harness, 81);
        let successor = principal(81, 2);
        fence_and_rebind(&mut harness, effect, origin, successor, 1, 2, 810);
        let claim = match harness.output(CommandRequest::ClaimSettlement {
            effect,
            claimant: successor,
        }) {
            TransitionOutput::SettlementClaim(claim) => claim,
            other => panic!("expected settlement claim, got {other:?}"),
        };
        let apply_intent = claim.record_apply_intent(digest(110)).unwrap();
        let shared = Arc::new(Mutex::new(harness.engine));

        let intent_engine = Arc::clone(&shared);
        let intent_thread = spawn_transition(move || {
            intent_engine
                .lock()
                .unwrap()
                .transact_volatile(apply_intent)
                .map(|_| ())
        });
        let crash_engine = Arc::clone(&shared);
        let crash_thread = spawn_transition(move || {
            crash_engine
                .lock()
                .unwrap()
                .transact_volatile(CommandRequest::FenceIncarnation {
                    root: effect.root(),
                    crashed: successor,
                    binding_generation: 2,
                })
                .map(|_| ())
        });

        let intent_result = intent_thread.join().unwrap();
        assert_eq!(crash_thread.join().unwrap(), Ok(()));
        let mut engine = shared.lock().unwrap();
        match &intent_result {
            Ok(()) => assert_eq!(
                engine.estate(effect).unwrap().settlement,
                SettlementState::ReconciliationRequired {
                    generation: 2,
                    applied: false
                }
            ),
            Err(CoreError::StaleSettlementClaim) => assert_eq!(
                engine.estate(effect).unwrap().settlement,
                SettlementState::Open { generation: 2 }
            ),
            other => panic!("unexpected intent/crash linearization: {other:?}"),
        }

        let third = principal(81, 3);
        let recovery_snapshot = snapshot(811);
        let snapshot_record = engine
            .snapshot_root(effect.root(), recovery_snapshot)
            .unwrap()
            .record();
        engine.transact_volatile(snapshot_record).unwrap();
        engine
            .transact_volatile(CommandRequest::Ready {
                root: effect.root(),
                snapshot: recovery_snapshot,
                successor: third,
            })
            .unwrap();
        engine
            .transact_volatile(CommandRequest::Rebind {
                root: effect.root(),
                snapshot: recovery_snapshot,
                successor: third,
                binding_generation: 3,
            })
            .unwrap();
        let third_claim = match engine
            .transact_volatile(CommandRequest::ClaimSettlement {
                effect,
                claimant: third,
            })
            .unwrap()
            .into_output()
        {
            TransitionOutput::SettlementClaim(claim) => claim,
            other => panic!("expected third-incarnation claim, got {other:?}"),
        };

        if intent_result.is_ok() {
            let rejected = third_claim
                .record_apply_intent(digest(112))
                .expect_err("durable intent cannot be blindly issued twice");
            assert_eq!(rejected.error(), &CoreError::WrongSettlementStage);
            let reconcile = rejected.into_claim();
            let applied = support::verified_apply_completion_for_engine(
                &engine,
                &reconcile,
                cser_core::REPLY_VERIFIER,
                cser_core::REPLY_APPLY_RECEIPT_SCHEMA,
                digest(113),
            );
            engine
                .transact_volatile(reconcile.record_applied(applied).unwrap())
                .unwrap();
            assert!(matches!(
                engine.estate(effect).unwrap().settlement,
                SettlementState::AppliedUnacknowledged {
                    claimant,
                    generation: 2
                } if claimant == third
            ));
        } else {
            engine
                .transact_volatile(third_claim.record_apply_intent(digest(112)).unwrap())
                .unwrap();
            assert!(matches!(
                engine.estate(effect).unwrap().settlement,
                SettlementState::ApplyIntentDurable {
                    claimant,
                    generation: 2
                } if claimant == third
            ));
        }
    });
}

#[test]
fn loom_device_generation_linearizes_before_or_after_old_evidence() {
    model_transition(|| {
        let mut harness = Harness::new();
        let fixture = committed_device_fixture(&mut harness, 82);
        let subject = freshness(1, 1, 1, 1, 1);
        let observation_two = freshness(1, 1, 1, 2, 1);
        let observation_three = freshness(1, 1, 1, 3, 1);
        let reset_a = verified_device_command(
            &harness.engine,
            fixture.effect,
            fixture.claim_a,
            DEVICE_EVIDENCE_RESET,
            subject,
            observation_two,
            digest(120),
        );
        harness.tx(reset_a).unwrap();
        let old_iotlb = verified_device_command(
            &harness.engine,
            fixture.effect,
            fixture.claim_a,
            DEVICE_EVIDENCE_IOTLB,
            subject,
            observation_two,
            digest(121),
        );
        let next_reset = verified_device_command(
            &harness.engine,
            fixture.effect,
            fixture.claim_b,
            DEVICE_EVIDENCE_RESET,
            subject,
            observation_three,
            digest(122),
        );
        let shared = Arc::new(Mutex::new(harness.engine));

        let evidence_engine = Arc::clone(&shared);
        let evidence_thread = spawn_transition(move || {
            evidence_engine
                .lock()
                .unwrap()
                .transact_volatile(old_iotlb)
                .map(|_| ())
        });
        let generation_engine = Arc::clone(&shared);
        let generation_thread = spawn_transition(move || {
            generation_engine
                .lock()
                .unwrap()
                .transact_volatile(next_reset)
                .map(|_| ())
        });

        let evidence_result = evidence_thread.join().unwrap();
        assert_eq!(generation_thread.join().unwrap(), Ok(()));
        let mut engine = shared.lock().unwrap();
        assert_eq!(engine.device_generation(fixture.scope).unwrap().get(), 3);
        match evidence_result {
            Ok(()) => assert_eq!(
                engine.check_reusable(fixture.resource_a, ResourceGeneration::new(1).unwrap()),
                Ok(())
            ),
            Err(CoreError::StaleEvidence) => {
                assert_eq!(
                    engine.check_reusable(fixture.resource_a, ResourceGeneration::new(1).unwrap()),
                    Err(CoreError::ResourceRetained)
                );
                let fresh_iotlb = verified_device_command(
                    &engine,
                    fixture.effect,
                    fixture.claim_a,
                    DEVICE_EVIDENCE_IOTLB,
                    subject,
                    observation_three,
                    digest(123),
                );
                engine.transact_volatile(fresh_iotlb).unwrap();
                assert_eq!(
                    engine.check_reusable(fixture.resource_a, ResourceGeneration::new(1).unwrap()),
                    Ok(())
                );
            }
            other => panic!("unexpected evidence/generation linearization: {other:?}"),
        }
    });
}

#[test]
fn loom_reconciliation_claimant_crash_preserves_prior_intent_knowledge() {
    model_transition(|| {
        let mut harness = Harness::new();
        let (effect, third, reconciliation) = reconciliation_claim(&mut harness, 83, false);
        let applied = support::verified_apply_completion_for_engine(
            &harness.engine,
            &reconciliation,
            cser_core::REPLY_VERIFIER,
            cser_core::REPLY_APPLY_RECEIPT_SCHEMA,
            digest(140),
        );
        let record_applied = reconciliation.record_applied(applied).unwrap();
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
                .transact_volatile(CommandRequest::FenceIncarnation {
                    root: effect.root(),
                    crashed: third,
                    binding_generation: 3,
                })
                .map(|_| ())
        });

        let apply_result = apply_thread.join().unwrap();
        assert_eq!(crash_thread.join().unwrap(), Ok(()));
        let engine = shared.lock().unwrap();
        match apply_result {
            Ok(()) => assert_eq!(
                engine.estate(effect).unwrap().settlement,
                SettlementState::ReconciliationRequired {
                    generation: 3,
                    applied: true
                }
            ),
            Err(CoreError::StaleSettlementClaim) => assert_eq!(
                engine.estate(effect).unwrap().settlement,
                SettlementState::ReconciliationRequired {
                    generation: 3,
                    applied: false
                }
            ),
            other => panic!("unexpected reconciliation/crash linearization: {other:?}"),
        }
    });
}

#[test]
fn loom_reconciliation_claimant_crash_preserves_prior_applied_knowledge() {
    model_transition(|| {
        let mut harness = Harness::new();
        let (effect, third, reconciliation) = reconciliation_claim(&mut harness, 84, true);
        let acknowledgement = support::verified_settlement_ack_for_engine(
            &harness.engine,
            &reconciliation,
            cser_core::REPLY_VERIFIER,
            cser_core::REPLY_SETTLEMENT_RECEIPT_SCHEMA,
            digest(150),
        );
        let settle = reconciliation.settle(acknowledgement).unwrap();
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
                .transact_volatile(CommandRequest::FenceIncarnation {
                    root: effect.root(),
                    crashed: third,
                    binding_generation: 3,
                })
                .map(|_| ())
        });

        let settle_result = settle_thread.join().unwrap();
        assert_eq!(crash_thread.join().unwrap(), Ok(()));
        let engine = shared.lock().unwrap();
        match settle_result {
            Ok(()) => assert_eq!(
                engine.estate(effect).unwrap().settlement,
                SettlementState::Settled
            ),
            Err(CoreError::StaleSettlementClaim) => assert_eq!(
                engine.estate(effect).unwrap().settlement,
                SettlementState::ReconciliationRequired {
                    generation: 3,
                    applied: true
                }
            ),
            other => panic!("unexpected settlement/crash linearization: {other:?}"),
        }
    });
}
