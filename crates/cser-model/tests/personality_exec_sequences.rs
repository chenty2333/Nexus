use cser_model::ScopeState;
use cser_model::personality::exec::{
    ExecError, ExecLayout, ExecModel, ExecRevocationStep, ImageId,
};
use cser_model::personality::registry::{RegistryBudget, RegistryCreditClass, RegistryError};
use cser_model::personality::{PersonalityId, TaskId};

fn model(
    segments: u64,
) -> (
    ExecModel,
    cser_model::ScopeId,
    cser_model::personality::PersonalityBindingToken,
) {
    let mut model = ExecModel::new();
    let (scope, binding) = model
        .create_scope(
            PersonalityId::new(1),
            RegistryBudget::new(1, segments, 0, 0, 0, 0, 1),
            Some(ImageId::new(1)),
        )
        .unwrap();
    (model, scope, binding)
}

fn layout() -> ExecLayout {
    ExecLayout {
        tls_base: 0x7000_0000,
        stack_pointer: 0x7fff_ffff_f000,
    }
}

fn close(model: &mut ExecModel, scope: cser_model::ScopeId) {
    model.revoke_begin(scope).unwrap();
    while model.revoke_next(scope).unwrap().is_some() {
        model.check_invariants().unwrap();
    }
    model.revoke_complete(scope).unwrap();
    model.check_invariants().unwrap();
}

#[test]
fn staging_is_invisible_and_one_exec_commit_publishes_the_complete_image() {
    let (mut model, scope, binding) = model(3);
    let token = model
        .stage(binding, TaskId::new(1), ImageId::new(2), 3, layout())
        .unwrap();
    let staged = model.scope(scope).unwrap();
    assert_eq!(staged.current_image, Some(ImageId::new(1)));
    assert!(staged.staging);
    assert_eq!(staged.registry.free_budget.continuation(), 0);
    assert_eq!(staged.registry.free_budget.exec_segment(), 0);

    let receipt = model.commit(binding, token).unwrap();
    assert_eq!(receipt.previous_image(), Some(ImageId::new(1)));
    assert_eq!(receipt.image(), ImageId::new(2));
    assert_eq!(receipt.segment_effects().len(), 3);
    assert_eq!(receipt.layout(), layout());
    let committed = model.scope(scope).unwrap();
    assert_eq!(committed.current_image, Some(ImageId::new(2)));
    assert!(!committed.staging);

    let before_duplicate = model.clone();
    assert_eq!(model.commit(binding, token), Err(ExecError::InvalidState));
    assert_eq!(model, before_duplicate);
    model.complete(&receipt).unwrap();
    let before_completion_replay = model.clone();
    assert_eq!(model.complete(&receipt), Err(ExecError::ReceiptMismatch));
    assert_eq!(model, before_completion_replay);
    assert_eq!(
        model.scope(scope).unwrap().registry.free_budget,
        model.scope(scope).unwrap().registry.initial_budget
    );

    close(&mut model, scope);
    let closed = model.scope(scope).unwrap();
    assert_eq!(closed.current_image, Some(ImageId::new(2)));
    assert_eq!(closed.registry.gate.state, ScopeState::Revoked);
}

#[test]
fn precommit_crash_requires_every_effect_to_be_explicitly_adopted() {
    let (mut model, scope, old_binding) = model(2);
    let token = model
        .stage(old_binding, TaskId::new(1), ImageId::new(2), 2, layout())
        .unwrap();
    let old_segments = model.segments(token.effect()).unwrap();
    model.crash(old_binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();

    let before_old = model.clone();
    assert!(matches!(
        model.commit(old_binding, token),
        Err(ExecError::Registry(
            RegistryError::Personality(_) | RegistryError::EffectIdentityMismatch
        ))
    ));
    assert_eq!(model, before_old);
    assert_eq!(
        model.scope(scope).unwrap().current_image,
        Some(ImageId::new(1))
    );

    model.adopt(replacement, token.transaction()).unwrap();
    let partially_adopted = model.transaction(token.effect()).unwrap();
    let before_partial = model.clone();
    assert_eq!(
        model.commit(replacement, partially_adopted),
        Err(ExecError::Registry(RegistryError::EffectIdentityMismatch))
    );
    assert_eq!(model, before_partial);
    for segment in old_segments {
        model.adopt(replacement, segment).unwrap();
    }
    let adopted = model.transaction(token.effect()).unwrap();
    let receipt = model.commit(replacement, adopted).unwrap();
    assert_eq!(
        model.scope(scope).unwrap().current_image,
        Some(ImageId::new(2))
    );

    model.crash(replacement).unwrap();
    model.complete(&receipt).unwrap();
    assert_eq!(model.scope(scope).unwrap().registry.free_budget.timer(), 1);
    model.revoke_begin(scope).unwrap();
    while model.revoke_next(scope).unwrap().is_some() {}
    model.revoke_complete(scope).unwrap();
    model.check_invariants().unwrap();
}

#[test]
fn kernel_completion_invalidates_a_ready_proof_before_rebind() {
    let (mut model, scope, binding) = model(2);
    let token = model
        .stage(binding, TaskId::new(1), ImageId::new(2), 2, layout())
        .unwrap();
    let receipt = model.commit(binding, token).unwrap();
    model.crash(binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    let ready = model.ready(&snapshot).unwrap();

    model.complete(&receipt).unwrap();
    let before_stale_rebind = model.clone();
    assert!(matches!(
        model.rebind(ready),
        Err(ExecError::Registry(RegistryError::Personality(_)))
    ));
    assert_eq!(model, before_stale_rebind);

    let snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    let ready = model.ready(&snapshot).unwrap();
    model.rebind(ready).unwrap();
    close(&mut model, scope);
}

#[test]
fn revoke_before_commit_aborts_staging_and_preserves_the_old_image() {
    let (mut model, scope, binding) = model(2);
    let token = model
        .stage(binding, TaskId::new(1), ImageId::new(2), 2, layout())
        .unwrap();
    model.revoke_begin(scope).unwrap();
    let before_commit = model.clone();
    assert!(matches!(
        model.commit(binding, token),
        Err(ExecError::Registry(_))
    ));
    assert_eq!(model, before_commit);
    while model.revoke_next(scope).unwrap().is_some() {
        model.check_invariants().unwrap();
    }
    model.revoke_complete(scope).unwrap();
    let closed = model.scope(scope).unwrap();
    assert_eq!(closed.current_image, Some(ImageId::new(1)));
    assert_eq!(closed.registry.free_budget, closed.registry.initial_budget);
}

#[test]
fn revoke_after_commit_drains_once_without_restoring_the_old_image() {
    let (mut model, scope, binding) = model(2);
    let token = model
        .stage(binding, TaskId::new(1), ImageId::new(2), 2, layout())
        .unwrap();
    model.commit(binding, token).unwrap();
    model.revoke_begin(scope).unwrap();
    assert_eq!(
        model.revoke_next(scope).unwrap(),
        Some(ExecRevocationStep::DrainedCommit {
            transaction: token.effect()
        })
    );
    assert_eq!(model.revoke_next(scope).unwrap(), None);
    model.revoke_complete(scope).unwrap();
    let closed = model.scope(scope).unwrap();
    assert_eq!(closed.current_image, Some(ImageId::new(2)));
    assert_eq!(closed.registry.free_budget, closed.registry.initial_budget);
    model.check_invariants().unwrap();
}

#[test]
fn insufficient_segment_credit_rolls_back_the_entire_staging_transaction() {
    let (mut model, scope, binding) = model(1);
    let before = model.clone();
    assert_eq!(
        model.stage(binding, TaskId::new(1), ImageId::new(2), 2, layout()),
        Err(ExecError::Registry(RegistryError::CreditExhausted(
            RegistryCreditClass::ExecSegment
        )))
    );
    assert_eq!(model, before);
    assert!(!model.scope(scope).unwrap().staging);
    assert!(model.scope(scope).unwrap().registry.live_effects.is_empty());
    model.check_invariants().unwrap();

    let before_invalid = model.clone();
    assert_eq!(
        model.stage(
            binding,
            TaskId::new(1),
            ImageId::new(1_u64 << 60),
            1,
            layout(),
        ),
        Err(ExecError::InvalidImage)
    );
    assert_eq!(model, before_invalid);
}
