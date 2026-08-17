#[allow(dead_code)]
mod support;

use cser_core::{
    AuthorityState, CommandRequest as Command, CoreError, OutcomeState, RetirementState,
    SettlementState, TransitionOutput,
};
use support::{
    EFFECT_APPLY_RECEIPT_SCHEMA, EFFECT_COMPONENT, EFFECT_CREDIT, EFFECT_EVIDENCE_KIND,
    EFFECT_RECEIPT_SCHEMA, EFFECT_SETTLEMENT_RECEIPT_SCHEMA, EFFECT_VERIFIER, Harness, claim,
    committed_reply, current_evidence_command, digest, executor, fence_and_rebind, prepared_reply,
    resource, snapshot, verified_apply_completion, verified_settlement_ack,
};

#[test]
fn postcommit_reply_uses_real_snapshot_ready_rebind_and_one_settlement() {
    let mut harness = Harness::new();
    let (effect, origin) = committed_reply(&mut harness, 1);
    let successor = executor(1, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 1);

    let settlement = match harness.output(Command::ClaimComponentSettlement {
        effect,
        component: EFFECT_COMPONENT,
        claimant: successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    };
    let apply_command = settlement.record_apply_intent(digest(30)).unwrap();
    let settlement = match harness.output(apply_command) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected intent-stage claim, got {other:?}"),
    };

    let applied = verified_apply_completion(
        &harness,
        &settlement,
        EFFECT_VERIFIER,
        EFFECT_APPLY_RECEIPT_SCHEMA,
        digest(31),
    );
    let settlement = match harness.output(settlement.record_applied(applied).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected applied-stage claim, got {other:?}"),
    };
    let acknowledgement = verified_settlement_ack(
        &harness,
        &settlement,
        EFFECT_VERIFIER,
        EFFECT_SETTLEMENT_RECEIPT_SCHEMA,
        digest(32),
    );
    harness
        .tx(settlement.settle(acknowledgement).unwrap())
        .unwrap();

    let evidence = current_evidence_command(
        &harness,
        effect,
        claim(1),
        EFFECT_EVIDENCE_KIND,
        cser_core::ReceiptBinding::new(EFFECT_VERIFIER, EFFECT_RECEIPT_SCHEMA),
        digest(33),
    );
    harness.tx(evidence).unwrap();
    let component = harness.engine.component(effect, EFFECT_COMPONENT).unwrap();
    assert_eq!(component.outcome, OutcomeState::KnownSuccess(digest(11)));
    assert_eq!(component.settlement, SettlementState::Settled);
    assert_eq!(component.retirement, RetirementState::Retired);
    assert_eq!(
        harness
            .engine
            .charge(support::charge(1), EFFECT_CREDIT)
            .retained_units,
        0
    );
    assert_eq!(
        harness
            .engine
            .check_reusable(resource(1), cser_core::ResourceGeneration::new(1).unwrap()),
        Ok(())
    );
    harness
        .tx(Command::ReleaseCompositeEffect { effect })
        .unwrap();
    assert_eq!(
        harness
            .engine
            .component(effect, EFFECT_COMPONENT)
            .unwrap()
            .retirement,
        RetirementState::Released
    );
}

#[test]
fn precommit_revoke_closes_the_commit_gate_and_claim_wins_after_commit() {
    let mut revoke_wins = Harness::new();
    let (effect, origin) = prepared_reply(&mut revoke_wins, 2);
    let successor = executor(2, 2);
    fence_and_rebind(&mut revoke_wins, effect, origin, successor, 2);
    let authority_epoch = revoke_wins
        .engine
        .composite_effect(effect)
        .unwrap()
        .authority_epoch;
    revoke_wins
        .tx(Command::BeginRevoke {
            effect,
            expected_actor: successor,
            authority_epoch,
        })
        .unwrap();
    let before = revoke_wins.engine.projection_digest();
    assert_eq!(
        revoke_wins.tx(Command::RecordComponentCommitIntent {
            effect,
            component: EFFECT_COMPONENT,
            actor: successor,
            operation: digest(20),
        }),
        Err(CoreError::StaleExecutor)
    );
    assert_eq!(revoke_wins.engine.projection_digest(), before);
    assert_eq!(
        revoke_wins
            .engine
            .component(effect, EFFECT_COMPONENT)
            .unwrap()
            .settlement,
        SettlementState::Revoked
    );
    assert_eq!(
        revoke_wins
            .engine
            .composite_effect(effect)
            .unwrap()
            .authority,
        AuthorityState::Revoked
    );

    let mut claim_wins = Harness::new();
    let (effect, origin) = committed_reply(&mut claim_wins, 3);
    let successor = executor(3, 2);
    fence_and_rebind(&mut claim_wins, effect, origin, successor, 3);
    let _claim = match claim_wins.output(Command::ClaimComponentSettlement {
        effect,
        component: EFFECT_COMPONENT,
        claimant: successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected claim, got {other:?}"),
    };
    let before = claim_wins.engine.projection_digest();
    let authority_epoch = claim_wins
        .engine
        .composite_effect(effect)
        .unwrap()
        .authority_epoch;
    assert_eq!(
        claim_wins.tx(Command::BeginRevoke {
            effect,
            expected_actor: successor,
            authority_epoch,
        }),
        Err(CoreError::GateClaimed)
    );
    assert_eq!(claim_wins.engine.projection_digest(), before);
}

#[test]
fn second_crash_reclaims_durable_intent_without_reapplying_blindly() {
    let mut harness = Harness::new();
    let (effect, origin) = committed_reply(&mut harness, 4);
    let successor = executor(4, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 4);
    let settlement = match harness.output(Command::ClaimComponentSettlement {
        effect,
        component: EFFECT_COMPONENT,
        claimant: successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    };
    let _intent = match harness.output(settlement.record_apply_intent(digest(40)).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected intent claim, got {other:?}"),
    };

    let third = executor(4, 3);
    fence_and_rebind(&mut harness, effect, successor, third, 5);
    assert!(matches!(
        harness
            .engine
            .component(effect, EFFECT_COMPONENT)
            .unwrap()
            .settlement,
        SettlementState::ReconciliationRequired {
            generation: 2,
            applied: false
        }
    ));
    let reconciliation = match harness.output(Command::ClaimComponentSettlement {
        effect,
        component: EFFECT_COMPONENT,
        claimant: third,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected reconciliation claim, got {other:?}"),
    };
    let rejected = reconciliation
        .record_apply_intent(digest(41))
        .expect_err("reconciliation must not mint a second apply intent");
    assert_eq!(rejected.error(), &CoreError::WrongSettlementStage);
    let reconciliation = rejected.into_claim();
    let applied = verified_apply_completion(
        &harness,
        &reconciliation,
        EFFECT_VERIFIER,
        EFFECT_APPLY_RECEIPT_SCHEMA,
        digest(42),
    );
    let reconciliation = match harness.output(
        reconciliation
            .record_applied(applied)
            .expect("reconciliation proves prior apply"),
    ) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected reconciled applied claim, got {other:?}"),
    };
    let acknowledgement = verified_settlement_ack(
        &harness,
        &reconciliation,
        EFFECT_VERIFIER,
        EFFECT_SETTLEMENT_RECEIPT_SCHEMA,
        digest(43),
    );
    harness
        .tx(reconciliation.settle(acknowledgement).unwrap())
        .unwrap();
    assert_eq!(
        harness
            .engine
            .component(effect, EFFECT_COMPONENT)
            .unwrap()
            .settlement,
        SettlementState::Settled
    );
}

#[test]
fn indeterminate_outcome_and_physical_retirement_are_orthogonal() {
    let mut harness = Harness::new();
    let (effect, origin) = committed_reply(&mut harness, 5);
    let successor = executor(5, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 6);
    let settlement = match harness.output(Command::ClaimComponentSettlement {
        effect,
        component: EFFECT_COMPONENT,
        claimant: successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    };
    harness
        .tx(settlement.mark_indeterminate(digest(50)))
        .unwrap();
    let component = harness.engine.component(effect, EFFECT_COMPONENT).unwrap();
    assert_eq!(component.outcome, OutcomeState::Indeterminate(digest(50)));
    assert_eq!(component.retirement, RetirementState::RetirementPending);

    let evidence = current_evidence_command(
        &harness,
        effect,
        claim(5),
        EFFECT_EVIDENCE_KIND,
        cser_core::ReceiptBinding::new(EFFECT_VERIFIER, EFFECT_RECEIPT_SCHEMA),
        digest(51),
    );
    harness.tx(evidence).unwrap();
    assert_eq!(
        harness
            .engine
            .component(effect, EFFECT_COMPONENT)
            .unwrap()
            .retirement,
        RetirementState::Retired
    );
}

#[test]
fn wrong_snapshot_and_stale_successor_reject_without_mutation() {
    let mut harness = Harness::new();
    let (effect, origin) = committed_reply(&mut harness, 6);
    harness
        .tx(Command::FenceExecutor {
            operation: effect.operation(),
            crashed: origin,
        })
        .unwrap();
    let snapshot_record = harness
        .engine
        .snapshot_operation(effect.operation(), snapshot(7))
        .unwrap()
        .record();
    harness.tx(snapshot_record).unwrap();
    let before = harness.engine.projection_digest();
    assert_eq!(
        harness.tx(Command::Ready {
            operation: effect.operation(),
            snapshot: snapshot(8),
            successor: executor(6, 2),
        }),
        Err(CoreError::StaleSnapshot)
    );
    assert_eq!(harness.engine.projection_digest(), before);
}
