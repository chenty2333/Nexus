#[allow(dead_code)]
mod support;

use cser_core::{
    ClaimScope, CommandRequest as Command, CoreError, EffectFactChallenge, EffectFactKind,
    EffectReceiptVerifier, ExternalOutcome, ReceiptSchemaId, TransitionOutput, VerificationError,
    VerifiedEffectObservation, VerifierId, VerifierIdentity,
};
use support::{
    EFFECT_APPLY_RECEIPT_SCHEMA, EFFECT_CLAIM_KIND, EFFECT_COMMIT_RECEIPT_SCHEMA, EFFECT_COMPONENT,
    EFFECT_SETTLEMENT_RECEIPT_SCHEMA, EFFECT_VERIFIER, ExactTestVerifier, Harness, TestReceipt,
    admit_command, claim, committed_reply, digest, effect, executor, fence_and_rebind, freshness,
    resource, resource_generation, test_effect_receipt, verified_apply_completion,
    verified_commit_outcome, verified_evidence_command, verified_settlement_ack, verifier_binding,
};

#[derive(Clone, Copy)]
struct ControlledVerifier {
    identity: VerifierIdentity,
    observation: Result<VerifiedEffectObservation, VerificationError>,
}

impl EffectReceiptVerifier for ControlledVerifier {
    type Receipt = ();

    fn identity(&self) -> VerifierIdentity {
        self.identity
    }

    fn verify(
        &self,
        _challenge: &EffectFactChallenge,
        _receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        self.observation
    }
}

fn open_commit_intent(
    harness: &mut Harness,
    operation_value: u64,
) -> (cser_core::CommitIntent, cser_core::EffectId) {
    let effect = effect(operation_value, 1);
    let origin = executor(operation_value, 1);
    harness.tx(admit_command(effect, operation_value)).unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect,
            component: EFFECT_COMPONENT,
            actor: origin,
            claim: claim(operation_value),
            kind: EFFECT_CLAIM_KIND,
            scope: ClaimScope::Logical,
            resource: resource(operation_value),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect,
            actor: origin,
        })
        .unwrap();
    let intent = match harness.output(Command::RecordComponentCommitIntent {
        effect,
        component: EFFECT_COMPONENT,
        actor: origin,
        operation: digest(1),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    };
    (intent, effect)
}

#[test]
fn commit_facts_require_the_exact_verifier_schema_epoch_freshness_and_shape() {
    let mut harness = Harness::new();
    let (intent, effect) = open_commit_intent(&mut harness, 900);
    let challenge = harness.engine.commit_outcome_challenge(&intent).unwrap();
    let before = harness.engine.projection_digest();
    let revision = harness.engine.revision();

    let wrong_verifier = ControlledVerifier {
        identity: VerifierIdentity::new_exact(
            cser_core::VerifierBinding::new(
                VerifierId::new(99).unwrap(),
                cser_core::VerifierGeneration::new(1).unwrap(),
                EFFECT_COMMIT_RECEIPT_SCHEMA,
                verifier_binding(EFFECT_VERIFIER, EFFECT_COMMIT_RECEIPT_SCHEMA)
                    .implementation_digest(),
            )
            .unwrap(),
        ),
        observation: Ok(VerifiedEffectObservation::commit(
            challenge.current_observation(),
            ExternalOutcome::Success,
            digest(2),
        )),
    };
    assert_eq!(
        harness
            .engine
            .verify_commit_outcome(&intent, &wrong_verifier, &()),
        Err(CoreError::UnknownVerifier)
    );

    let wrong_schema = ControlledVerifier {
        identity: VerifierIdentity::new_exact(
            cser_core::VerifierBinding::new(
                EFFECT_VERIFIER,
                cser_core::VerifierGeneration::new(1).unwrap(),
                ReceiptSchemaId::new(99).unwrap(),
                verifier_binding(EFFECT_VERIFIER, EFFECT_COMMIT_RECEIPT_SCHEMA)
                    .implementation_digest(),
            )
            .unwrap(),
        ),
        observation: wrong_verifier.observation,
    };
    assert_eq!(
        harness
            .engine
            .verify_commit_outcome(&intent, &wrong_schema, &()),
        Err(CoreError::ReceiptSchemaMismatch)
    );

    let expected_implementation_digest =
        verifier_binding(EFFECT_VERIFIER, EFFECT_COMMIT_RECEIPT_SCHEMA).implementation_digest();
    let wrong_implementation_digest = if expected_implementation_digest == digest(0x99) {
        digest(0x98)
    } else {
        digest(0x99)
    };
    let wrong_implementation = ControlledVerifier {
        identity: VerifierIdentity::new_exact(
            cser_core::VerifierBinding::new(
                EFFECT_VERIFIER,
                cser_core::VerifierGeneration::new(1).unwrap(),
                EFFECT_COMMIT_RECEIPT_SCHEMA,
                wrong_implementation_digest,
            )
            .unwrap(),
        ),
        observation: wrong_verifier.observation,
    };
    assert_eq!(
        harness
            .engine
            .verify_commit_outcome(&intent, &wrong_implementation, &()),
        Err(CoreError::UnknownVerifier)
    );

    let stale_epoch = ControlledVerifier {
        identity: VerifierIdentity::new_exact(
            cser_core::VerifierBinding::new(
                EFFECT_VERIFIER,
                cser_core::VerifierGeneration::new(2).unwrap(),
                EFFECT_COMMIT_RECEIPT_SCHEMA,
                verifier_binding(EFFECT_VERIFIER, EFFECT_COMMIT_RECEIPT_SCHEMA)
                    .implementation_digest(),
            )
            .unwrap(),
        ),
        observation: wrong_verifier.observation,
    };
    assert_eq!(
        harness
            .engine
            .verify_commit_outcome(&intent, &stale_epoch, &()),
        Err(CoreError::StaleVerifierEpoch)
    );

    let wrong_freshness = ControlledVerifier {
        identity: VerifierIdentity::new_exact(verifier_binding(
            EFFECT_VERIFIER,
            EFFECT_COMMIT_RECEIPT_SCHEMA,
        )),
        observation: Ok(VerifiedEffectObservation::commit(
            freshness(2, 1, 1, 1),
            ExternalOutcome::Success,
            digest(3),
        )),
    };
    assert_eq!(
        harness
            .engine
            .verify_commit_outcome(&intent, &wrong_freshness, &()),
        Err(CoreError::StaleEvidence)
    );

    let wrong_shape = ControlledVerifier {
        identity: wrong_freshness.identity,
        observation: Ok(VerifiedEffectObservation::fact(
            challenge.current_observation(),
            digest(4),
        )),
    };
    assert_eq!(
        harness
            .engine
            .verify_commit_outcome(&intent, &wrong_shape, &()),
        Err(CoreError::StaleEvidence)
    );

    let zero_digest = ControlledVerifier {
        identity: wrong_freshness.identity,
        observation: Ok(VerifiedEffectObservation::commit(
            challenge.current_observation(),
            ExternalOutcome::Success,
            cser_core::Digest::ZERO,
        )),
    };
    assert_eq!(
        harness
            .engine
            .verify_commit_outcome(&intent, &zero_digest, &()),
        Err(CoreError::InvalidPayload)
    );

    let rejected = ControlledVerifier {
        identity: wrong_freshness.identity,
        observation: Err(VerificationError::Rejected),
    };
    assert_eq!(
        harness
            .engine
            .verify_commit_outcome(&intent, &rejected, &()),
        Err(CoreError::VerificationFailed)
    );
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(harness.engine.revision(), revision);

    let receipt = test_effect_receipt(challenge, digest(5), Some(ExternalOutcome::Success));
    assert_eq!(receipt.kind, EffectFactKind::CommitOutcome);
    let outcome = verified_commit_outcome(
        &harness,
        &intent,
        EFFECT_VERIFIER,
        EFFECT_COMMIT_RECEIPT_SCHEMA,
        ExternalOutcome::Success,
        digest(5),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    assert!(harness.engine.component(effect, EFFECT_COMPONENT).is_some());
}

#[test]
fn verified_apply_and_settlement_facts_cannot_cross_effects() {
    let mut harness = Harness::new();
    let (left, left_origin) = committed_reply(&mut harness, 910);
    let (right, right_origin) = committed_reply(&mut harness, 911);
    let left_successor = executor(910, 2);
    let right_successor = executor(911, 2);
    fence_and_rebind(&mut harness, left, left_origin, left_successor, 9100);
    fence_and_rebind(&mut harness, right, right_origin, right_successor, 9110);

    let left_claim = match harness.output(Command::ClaimComponentSettlement {
        effect: left,
        component: EFFECT_COMPONENT,
        claimant: left_successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected left settlement claim, got {other:?}"),
    };
    let right_claim = match harness.output(Command::ClaimComponentSettlement {
        effect: right,
        component: EFFECT_COMPONENT,
        claimant: right_successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected right settlement claim, got {other:?}"),
    };
    let left_claim = match harness.output(left_claim.record_apply_intent(digest(10)).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected left intent claim, got {other:?}"),
    };
    let right_claim = match harness.output(right_claim.record_apply_intent(digest(11)).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected right intent claim, got {other:?}"),
    };

    let left_evidence = verified_apply_completion(
        &harness,
        &left_claim,
        EFFECT_VERIFIER,
        EFFECT_APPLY_RECEIPT_SCHEMA,
        digest(12),
    );
    let before = harness.engine.projection_digest();
    let revision = harness.engine.revision();
    let rejected = right_claim
        .record_applied(left_evidence)
        .expect_err("left effect evidence must not authorize right effect apply");
    assert_eq!(rejected.error(), &CoreError::StaleSettlementClaim);
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(harness.engine.revision(), revision);
    let right_claim = rejected.into_claim();

    let right_evidence = verified_apply_completion(
        &harness,
        &right_claim,
        EFFECT_VERIFIER,
        EFFECT_APPLY_RECEIPT_SCHEMA,
        digest(13),
    );
    let right_claim = match harness.output(right_claim.record_applied(right_evidence).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected applied right claim, got {other:?}"),
    };

    let left_evidence = verified_apply_completion(
        &harness,
        &left_claim,
        EFFECT_VERIFIER,
        EFFECT_APPLY_RECEIPT_SCHEMA,
        digest(14),
    );
    let left_claim = match harness.output(left_claim.record_applied(left_evidence).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected applied left claim, got {other:?}"),
    };

    let right_ack = verified_settlement_ack(
        &harness,
        &right_claim,
        EFFECT_VERIFIER,
        EFFECT_SETTLEMENT_RECEIPT_SCHEMA,
        digest(15),
    );
    let rejected = left_claim
        .settle(right_ack)
        .expect_err("right settlement acknowledgement must not settle left");
    assert_eq!(rejected.error(), &CoreError::StaleSettlementClaim);
    let left_claim = rejected.into_claim();

    let left_ack = verified_settlement_ack(
        &harness,
        &left_claim,
        EFFECT_VERIFIER,
        EFFECT_SETTLEMENT_RECEIPT_SCHEMA,
        digest(16),
    );
    harness.tx(left_claim.settle(left_ack).unwrap()).unwrap();
    let right_ack = verified_settlement_ack(
        &harness,
        &right_claim,
        EFFECT_VERIFIER,
        EFFECT_SETTLEMENT_RECEIPT_SCHEMA,
        digest(17),
    );
    harness.tx(right_claim.settle(right_ack).unwrap()).unwrap();
}

#[test]
fn a_verified_fact_loses_the_race_to_a_real_fence_without_mutation() {
    let mut harness = Harness::new();
    let (effect, origin) = committed_reply(&mut harness, 920);
    let successor = executor(920, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 9200);
    let claim = match harness.output(Command::ClaimComponentSettlement {
        effect,
        component: EFFECT_COMPONENT,
        claimant: successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    };
    let claim = match harness.output(claim.record_apply_intent(digest(20)).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected intent claim, got {other:?}"),
    };
    let evidence = verified_apply_completion(
        &harness,
        &claim,
        EFFECT_VERIFIER,
        EFFECT_APPLY_RECEIPT_SCHEMA,
        digest(21),
    );
    let stale_command = claim.record_applied(evidence).unwrap();

    harness
        .tx(Command::FenceExecutor {
            operation: effect.operation(),
            crashed: successor,
        })
        .unwrap();
    let before = harness.engine.projection_digest();
    let revision = harness.engine.revision();
    assert!(matches!(
        harness.tx(stale_command),
        Err(CoreError::StaleEvidence | CoreError::StaleSettlementClaim)
    ));
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(harness.engine.revision(), revision);
    assert!(matches!(
        harness
            .engine
            .component(effect, EFFECT_COMPONENT)
            .unwrap()
            .settlement,
        cser_core::SettlementState::ReconciliationRequired {
            generation: 2,
            applied: false
        }
    ));
}

#[test]
fn verified_retirement_evidence_loses_the_race_to_executor_replacement() {
    let mut harness = Harness::new();
    let (effect, origin) = committed_reply(&mut harness, 921);
    let before_replacement = harness
        .engine
        .component_evidence_challenge(
            effect,
            EFFECT_COMPONENT,
            claim(921),
            support::EFFECT_EVIDENCE_KIND,
        )
        .unwrap();
    let old_receipt = TestReceipt {
        effect,
        claim: claim(921),
        kind: support::EFFECT_EVIDENCE_KIND,
        resource: before_replacement.resource(),
        resource_generation: before_replacement.resource_generation(),
        subject: before_replacement.subject(),
        subject_binding: before_replacement.subject_binding(),
        observation: before_replacement.current_observation(),
        observation_binding: before_replacement.current_binding(),
        digest: digest(22),
    };
    let stale = verified_evidence_command(
        &harness,
        effect,
        claim(921),
        support::EFFECT_EVIDENCE_KIND,
        cser_core::ReceiptBinding::new(EFFECT_VERIFIER, support::EFFECT_RECEIPT_SCHEMA),
        before_replacement.current_observation(),
        digest(22),
    );

    let successor = executor(921, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 9210);
    let after_replacement = harness
        .engine
        .component_evidence_challenge(
            effect,
            EFFECT_COMPONENT,
            claim(921),
            support::EFFECT_EVIDENCE_KIND,
        )
        .unwrap();
    assert_eq!(before_replacement.effect(), after_replacement.effect());
    assert_eq!(before_replacement.resource(), after_replacement.resource());
    assert_eq!(
        before_replacement.resource_generation(),
        after_replacement.resource_generation()
    );
    assert_eq!(
        before_replacement.verification_scope(),
        after_replacement.verification_scope()
    );
    assert_ne!(
        before_replacement.current_binding(),
        after_replacement.current_binding()
    );
    let verifier = ExactTestVerifier::new(EFFECT_VERIFIER, support::EFFECT_RECEIPT_SCHEMA);
    assert_eq!(
        harness.engine.verify_component_retirement_evidence(
            effect,
            EFFECT_COMPONENT,
            claim(921),
            support::EFFECT_EVIDENCE_KIND,
            &verifier,
            &old_receipt,
        ),
        Err(CoreError::VerificationFailed)
    );

    let before = harness.engine.projection_digest();
    let revision = harness.engine.revision();
    assert_eq!(harness.tx(stale), Err(CoreError::StaleEvidence));
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(harness.engine.revision(), revision);
    assert_eq!(
        harness.engine.component_retirement_evidence_accepted(
            effect,
            EFFECT_COMPONENT,
            claim(921),
            support::EFFECT_EVIDENCE_KIND,
        ),
        Ok(false)
    );

    let current = verified_evidence_command(
        &harness,
        effect,
        claim(921),
        support::EFFECT_EVIDENCE_KIND,
        cser_core::ReceiptBinding::new(EFFECT_VERIFIER, support::EFFECT_RECEIPT_SCHEMA),
        after_replacement.current_observation(),
        digest(23),
    );
    harness.tx(current).unwrap();
    assert_eq!(
        harness.engine.component_retirement_evidence_accepted(
            effect,
            EFFECT_COMPONENT,
            claim(921),
            support::EFFECT_EVIDENCE_KIND,
        ),
        Ok(true)
    );
}
