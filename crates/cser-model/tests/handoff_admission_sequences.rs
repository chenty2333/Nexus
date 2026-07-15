#[path = "handoff_admission_support/mod.rs"]
mod support;

use cser_model::handoff_admission::{
    ClosureProgress, DestinationAuthority, EffectDisposition, FreezeReadiness,
    HandoffAdmissionError, HandoffProgress, LocalScopePhase, SourcePrincipal, ThawProgress,
};
use support::{abort_receipt, commit_receipt, intent, model};

#[test]
fn intent_crash_before_freeze_leaves_source_active() {
    let mut model = model();
    model.record_intent(intent()).unwrap();

    assert_eq!(model.query_handoff().unwrap(), HandoffProgress::Open);
    assert_eq!(model.source_principal(), SourcePrincipal::Active);
    assert_eq!(model.scope_phase(), LocalScopePhase::Active);
    model.check_invariants().unwrap();
}

#[test]
fn freeze_before_first_commit_rejects_commit_atomically() {
    let mut model = model();
    let effect = model.register_effect().unwrap();
    model.prepare_effect(effect).unwrap();
    model.record_intent(intent()).unwrap();
    let frozen = model.freeze_admission().unwrap();
    let before = model.clone();

    assert_eq!(
        model.commit_effect(effect),
        Err(HandoffAdmissionError::InvalidGate)
    );
    assert_eq!(model, before);
    assert_eq!(frozen.readiness, FreezeReadiness::NeedsAbort);
    assert_eq!(
        model.effect_disposition(effect).unwrap(),
        EffectDisposition::Prepared
    );
}

#[test]
fn first_commit_before_freeze_is_classified_for_drain() {
    let mut model = model();
    let effect = model.register_effect().unwrap();
    model.prepare_effect(effect).unwrap();
    model.commit_effect(effect).unwrap();
    model.record_intent(intent()).unwrap();

    let frozen = model.freeze_admission().unwrap();
    assert_eq!(frozen.readiness, FreezeReadiness::ReadyToCommit);
    assert_eq!(
        model.effect_disposition(effect).unwrap(),
        EffectDisposition::Committed
    );
    model.complete_committed(effect).unwrap();
    model.acknowledge_closure_publication(effect).unwrap();
    model.check_invariants().unwrap();
}

#[test]
fn predecision_tombstone_blocks_ownership_commit() {
    let mut model = model();
    let effect = model.register_effect().unwrap();
    model.prepare_effect(effect).unwrap();
    model.commit_effect(effect).unwrap();
    model.retain_effect(effect).unwrap();
    model.record_intent(intent()).unwrap();
    let frozen = model.freeze_admission().unwrap();
    let before = model.clone();

    assert_eq!(frozen.readiness, FreezeReadiness::BlockedRetained);
    assert_eq!(
        model.commit_close(commit_receipt(&frozen.receipt)),
        Err(HandoffAdmissionError::RetainedTombstone)
    );
    assert_eq!(model, before);
}

#[test]
fn typed_abort_receipt_is_required_to_thaw() {
    let mut model = model();
    model.register_effect().unwrap();
    model.record_intent(intent()).unwrap();
    let frozen = model.freeze_admission().unwrap();

    assert_eq!(
        model.unfreeze_without_receipt(),
        Err(HandoffAdmissionError::DecisionReceiptRequired)
    );
    let abort = abort_receipt(&frozen.receipt);
    assert_eq!(model.unfreeze(abort).unwrap(), ThawProgress::Thawed);
    assert_eq!(model.unfreeze(abort).unwrap(), ThawProgress::Thawed);
    assert_eq!(model.source_principal(), SourcePrincipal::Active);
    assert_eq!(
        model.query_handoff().unwrap(),
        HandoffProgress::Aborted(ThawProgress::Thawed)
    );
}

#[test]
fn lost_commit_ack_replays_the_same_decision() {
    let mut model = model();
    model.register_effect().unwrap();
    model.record_intent(intent()).unwrap();
    let frozen = model.freeze_admission().unwrap();
    assert_eq!(model.abort_uncommitted(&frozen.receipt).unwrap(), 1);
    let receipt = commit_receipt(&frozen.receipt);

    let first = model.commit_close(receipt).unwrap();
    let epoch = model.authority_epoch();
    let replay = model.commit_close(receipt).unwrap();

    assert_eq!(first, replay);
    assert!(matches!(first, ClosureProgress::Closed(_)));
    assert_eq!(model.authority_epoch(), epoch);
}

#[test]
fn source_crash_rejects_old_binding_while_frozen() {
    let mut model = model();
    model.register_effect().unwrap();
    model.record_intent(intent()).unwrap();
    model.freeze_admission().unwrap();
    let old_binding = model.crash_source().unwrap();
    let before = model.clone();

    assert_eq!(
        model.publish_from_binding(old_binding),
        Err(HandoffAdmissionError::StaleBinding)
    );
    assert_eq!(model, before);
    assert!(matches!(
        model.query_handoff().unwrap(),
        HandoffProgress::Frozen(_)
    ));
    assert_eq!(model.source_principal(), SourcePrincipal::Frozen);
}

#[test]
fn duplicate_commit_close_returns_the_same_closure() {
    let mut model = model();
    let effect = model.register_effect().unwrap();
    model.prepare_effect(effect).unwrap();
    model.commit_effect(effect).unwrap();
    model.record_intent(intent()).unwrap();
    let frozen = model.freeze_admission().unwrap();
    let commit = commit_receipt(&frozen.receipt);

    assert_eq!(
        model.commit_close(commit).unwrap(),
        ClosureProgress::Pending
    );
    model.complete_committed(effect).unwrap();
    model.acknowledge_closure_publication(effect).unwrap();
    let first = model.commit_close(commit).unwrap();
    let replay = model.commit_close(commit).unwrap();

    assert_eq!(first, replay);
    let ClosureProgress::Closed(receipt) = first else {
        panic!("closure must complete");
    };
    assert_eq!(receipt.closure_sequence(), 1);
    assert_eq!(model.scope_phase(), LocalScopePhase::Revoked);
}

#[test]
fn conflicting_abort_after_commit_is_rejected_atomically() {
    let mut model = model();
    model.register_effect().unwrap();
    model.record_intent(intent()).unwrap();
    let frozen = model.freeze_admission().unwrap();
    model.abort_uncommitted(&frozen.receipt).unwrap();
    model.commit_close(commit_receipt(&frozen.receipt)).unwrap();
    let before = model.clone();

    assert_eq!(
        model.unfreeze(abort_receipt(&frozen.receipt)),
        Err(HandoffAdmissionError::ConflictingDecision)
    );
    assert_eq!(model, before);
    assert_eq!(model.source_principal(), SourcePrincipal::Fenced);
}

#[test]
fn postcommit_retained_effect_blocks_activation_without_rollback() {
    let mut model = model();
    let effect = model.register_effect().unwrap();
    model.prepare_effect(effect).unwrap();
    model.commit_effect(effect).unwrap();
    model.record_intent(intent()).unwrap();
    let frozen = model.freeze_admission().unwrap();
    let commit = commit_receipt(&frozen.receipt);
    assert_eq!(
        model.commit_close(commit).unwrap(),
        ClosureProgress::Pending
    );
    let committed_epoch = model.authority_epoch();

    model.retain_effect(effect).unwrap();

    assert_eq!(
        model.commit_close(commit).unwrap(),
        ClosureProgress::Retained
    );
    assert_eq!(model.authority_epoch(), committed_epoch);
    assert_eq!(
        model.destination_authority(),
        DestinationAuthority::RecoveryRequired
    );
    assert_eq!(
        model.authorize_destination_without_closure(),
        Err(HandoffAdmissionError::ClosureRequired)
    );
    assert_eq!(model.source_principal(), SourcePrincipal::Fenced);
}
