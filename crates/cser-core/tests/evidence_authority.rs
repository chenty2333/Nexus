#[allow(dead_code)]
mod support;

use cser_core::{
    ClaimScope, CommandRequest as Command, CoreError, EffectFactChallenge, EffectFactKind,
    EffectReceiptVerifier, ExternalOutcome, ReceiptSchemaId, TransitionOutput, VerificationError,
    VerifiedEffectObservation, VerifierId, VerifierIdentity,
};
use support::{
    Harness, charge, claim, committed_reply, digest, effect, fence_and_rebind, freshness,
    principal, resource, resource_generation, test_effect_receipt, verified_apply_completion,
    verified_commit_outcome, verified_settlement_ack,
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
    root_value: u64,
) -> (cser_core::CommitIntent, cser_core::EffectId) {
    let effect = effect(root_value, 1);
    let origin = principal(root_value, 1);
    harness
        .tx(Command::CreateEstate {
            effect,
            origin,
            binding_generation: 1,
            domain: cser_core::REPLY_DOMAIN,
            obligation: cser_core::REPLY_OBLIGATION_PUBLICATION,
            charge_account: charge(root_value),
        })
        .unwrap();
    harness
        .tx(Command::AddClaim {
            effect,
            actor: origin,
            binding_generation: 1,
            claim: claim(root_value),
            domain: cser_core::REPLY_DOMAIN,
            kind: cser_core::REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(root_value),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::PrepareEffect {
            effect,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    let intent = match harness.output(Command::RecordCommitIntent {
        effect,
        actor: origin,
        binding_generation: 1,
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
        identity: VerifierIdentity::new(
            VerifierId::new(99).unwrap(),
            1,
            cser_core::REPLY_COMMIT_RECEIPT_SCHEMA,
        )
        .unwrap(),
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
        identity: VerifierIdentity::new(
            cser_core::REPLY_VERIFIER,
            1,
            ReceiptSchemaId::new(99).unwrap(),
        )
        .unwrap(),
        observation: wrong_verifier.observation,
    };
    assert_eq!(
        harness
            .engine
            .verify_commit_outcome(&intent, &wrong_schema, &()),
        Err(CoreError::ReceiptSchemaMismatch)
    );

    let stale_epoch = ControlledVerifier {
        identity: VerifierIdentity::new(
            cser_core::REPLY_VERIFIER,
            2,
            cser_core::REPLY_COMMIT_RECEIPT_SCHEMA,
        )
        .unwrap(),
        observation: wrong_verifier.observation,
    };
    assert_eq!(
        harness
            .engine
            .verify_commit_outcome(&intent, &stale_epoch, &()),
        Err(CoreError::StaleVerifierEpoch)
    );

    let wrong_freshness = ControlledVerifier {
        identity: VerifierIdentity::new(
            cser_core::REPLY_VERIFIER,
            1,
            cser_core::REPLY_COMMIT_RECEIPT_SCHEMA,
        )
        .unwrap(),
        observation: Ok(VerifiedEffectObservation::commit(
            freshness(2, 1, 1, 1, 1),
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
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_COMMIT_RECEIPT_SCHEMA,
        ExternalOutcome::Success,
        digest(5),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    assert!(harness.engine.estate(effect).is_some());
}

#[test]
fn verified_apply_and_settlement_facts_cannot_cross_effects() {
    let mut harness = Harness::new();
    let (left, left_origin) = committed_reply(&mut harness, 910);
    let (right, right_origin) = committed_reply(&mut harness, 911);
    let left_successor = principal(910, 2);
    let right_successor = principal(911, 2);
    fence_and_rebind(&mut harness, left, left_origin, left_successor, 1, 2, 9100);
    fence_and_rebind(
        &mut harness,
        right,
        right_origin,
        right_successor,
        1,
        2,
        9110,
    );

    let left_claim = match harness.output(Command::ClaimSettlement {
        effect: left,
        claimant: left_successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected left settlement claim, got {other:?}"),
    };
    let right_claim = match harness.output(Command::ClaimSettlement {
        effect: right,
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
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_APPLY_RECEIPT_SCHEMA,
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
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_APPLY_RECEIPT_SCHEMA,
        digest(13),
    );
    let right_claim = match harness.output(right_claim.record_applied(right_evidence).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected applied right claim, got {other:?}"),
    };

    let left_evidence = verified_apply_completion(
        &harness,
        &left_claim,
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_APPLY_RECEIPT_SCHEMA,
        digest(14),
    );
    let left_claim = match harness.output(left_claim.record_applied(left_evidence).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected applied left claim, got {other:?}"),
    };

    let right_ack = verified_settlement_ack(
        &harness,
        &right_claim,
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_SETTLEMENT_RECEIPT_SCHEMA,
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
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_SETTLEMENT_RECEIPT_SCHEMA,
        digest(16),
    );
    harness.tx(left_claim.settle(left_ack).unwrap()).unwrap();
    let right_ack = verified_settlement_ack(
        &harness,
        &right_claim,
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_SETTLEMENT_RECEIPT_SCHEMA,
        digest(17),
    );
    harness.tx(right_claim.settle(right_ack).unwrap()).unwrap();
}

#[test]
fn a_verified_fact_loses_the_race_to_a_real_fence_without_mutation() {
    let mut harness = Harness::new();
    let (effect, origin) = committed_reply(&mut harness, 920);
    let successor = principal(920, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 1, 2, 9200);
    let claim = match harness.output(Command::ClaimSettlement {
        effect,
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
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_APPLY_RECEIPT_SCHEMA,
        digest(21),
    );
    let stale_command = claim.record_applied(evidence).unwrap();

    harness
        .tx(Command::FenceIncarnation {
            root: effect.root(),
            crashed: successor,
            binding_generation: 2,
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
        harness.engine.estate(effect).unwrap().settlement,
        cser_core::SettlementState::ReconciliationRequired {
            generation: 2,
            applied: false
        }
    ));
}
