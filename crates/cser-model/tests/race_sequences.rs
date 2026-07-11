use cser_model::{
    Budget, BudgetDisposition, EffectState, Model, ModelError, ScopeState, SupervisorId,
    TraceAction,
};

fn supervisor(id: u64) -> SupervisorId {
    SupervisorId::new(id)
}

#[test]
fn revoke_linearizes_before_commit_and_fences_the_stale_reply() {
    let mut model = Model::new();
    let (scope, binding) = model.create_scope(supervisor(1), Budget::new(5)).unwrap();
    let effect = model.register(binding, Budget::new(5)).unwrap();
    model.prepare(binding, effect).unwrap();

    model.revoke_begin(scope).unwrap();
    let closing = model.scope(scope).unwrap();
    assert_eq!(closing.epoch, 2);
    assert_eq!(closing.binding_epoch, binding.binding_epoch());
    assert_eq!(closing.supervisor, Some(binding.supervisor()));
    assert!(matches!(
        model.commit(binding, effect),
        Err(ModelError::InvalidScopeState {
            state: ScopeState::Closing
        })
    ));
    assert_eq!(model.effect(effect).unwrap().state, EffectState::Prepared);
    assert!(
        !model
            .trace()
            .iter()
            .any(|event| event.action == TraceAction::Commit)
    );

    assert_eq!(
        model.revoke_step(scope).unwrap().unwrap().to,
        EffectState::Cancelling
    );
    assert_eq!(
        model.revoke_step(scope).unwrap().unwrap().to,
        EffectState::Aborted
    );
    assert!(model.revoke_step(scope).unwrap().is_none());
    model.revoke_complete(scope).unwrap();

    let effect = model.effect(effect).unwrap();
    assert_eq!(effect.state, EffectState::Aborted);
    assert_eq!(effect.terminalizations, 1);
    assert_eq!(effect.budget_disposition, BudgetDisposition::Returned);
    let scope = model.scope(scope).unwrap();
    assert_eq!(scope.state, ScopeState::Revoked);
    assert_eq!(scope.free_budget, Budget::new(5));
    assert_eq!(scope.spent_budget, Budget::ZERO);
    model.check_invariants().unwrap();
}

#[test]
fn commit_linearizes_before_revoke_and_is_drained_not_rolled_back() {
    let mut model = Model::new();
    let (scope, binding) = model.create_scope(supervisor(1), Budget::new(5)).unwrap();
    let effect = model.register(binding, Budget::new(5)).unwrap();
    model.prepare(binding, effect).unwrap();
    model.commit(binding, effect).unwrap();

    model.revoke_begin(scope).unwrap();
    assert!(matches!(
        model.commit(binding, effect),
        Err(ModelError::InvalidScopeState {
            state: ScopeState::Closing
        })
    ));
    assert_eq!(
        model.revoke_step(scope).unwrap().unwrap().to,
        EffectState::Draining
    );

    // A trusted completion can win the race with the second revoke step.
    model.complete(effect).unwrap();
    assert!(model.revoke_step(scope).unwrap().is_none());
    model.revoke_complete(scope).unwrap();

    let effect = model.effect(effect).unwrap();
    assert_eq!(effect.state, EffectState::Completed);
    assert_eq!(effect.terminalizations, 1);
    assert_eq!(effect.budget_disposition, BudgetDisposition::Spent);
    let scope = model.scope(scope).unwrap();
    assert_eq!(scope.free_budget, Budget::ZERO);
    assert_eq!(scope.spent_budget, Budget::new(5));
    model.check_invariants().unwrap();
}

#[test]
fn an_effect_can_terminalize_only_once() {
    let mut model = Model::new();
    let (_scope, binding) = model.create_scope(supervisor(1), Budget::new(1)).unwrap();
    let effect = model.register(binding, Budget::new(1)).unwrap();
    model.prepare(binding, effect).unwrap();
    model.commit(binding, effect).unwrap();
    model.complete(effect).unwrap();

    assert_eq!(model.complete(effect), Err(ModelError::AlreadyTerminal));
    assert_eq!(model.effect(effect).unwrap().terminalizations, 1);
    assert_eq!(
        model
            .trace()
            .iter()
            .filter(|event| {
                event.effect == Some(effect) && event.to == Some(EffectState::Completed)
            })
            .count(),
        1
    );
    model.check_invariants().unwrap();
}

#[test]
fn crash_requires_fallback_then_ready_rebind_and_explicit_adoption() {
    let mut model = Model::new();
    let (scope, old_binding) = model.create_scope(supervisor(1), Budget::new(4)).unwrap();
    let orphan = model.register(old_binding, Budget::new(2)).unwrap();
    model.prepare(old_binding, orphan).unwrap();

    model.crash(old_binding).unwrap();
    assert!(matches!(
        model.commit(old_binding, orphan),
        Err(ModelError::StaleBinding { .. })
    ));
    assert_eq!(
        model.rebind(scope, supervisor(2)),
        Err(ModelError::FallbackUnavailable)
    );

    model.fallback_pick(scope).unwrap();
    assert!(model.scope(scope).unwrap().fallback_selected);
    let replacement = model.rebind(scope, supervisor(2)).unwrap();
    assert!(!model.scope(scope).unwrap().fallback_selected);
    assert!(matches!(
        model.commit(replacement, orphan),
        Err(ModelError::EffectBindingFenced { .. })
    ));

    model.adopt(replacement, orphan).unwrap();
    assert!(matches!(
        model.commit(old_binding, orphan),
        Err(ModelError::StaleBinding { .. })
    ));
    model.commit(replacement, orphan).unwrap();
    assert_eq!(
        model.adopt(replacement, orphan),
        Err(ModelError::NotAdoptable)
    );
    model.complete(orphan).unwrap();

    let actions: Vec<_> = model.trace().iter().map(|event| event.action).collect();
    let crash = actions
        .iter()
        .position(|action| *action == TraceAction::Crash)
        .unwrap();
    let fallback = actions
        .iter()
        .position(|action| *action == TraceAction::FallbackPick)
        .unwrap();
    let rebind = actions
        .iter()
        .position(|action| *action == TraceAction::Rebind)
        .unwrap();
    let adopt = actions
        .iter()
        .position(|action| *action == TraceAction::Adopt)
        .unwrap();
    let commit = actions
        .iter()
        .position(|action| *action == TraceAction::Commit)
        .unwrap();
    assert!(crash < fallback && fallback < rebind && rebind < adopt && adopt < commit);
    model.check_invariants().unwrap();
}

#[test]
fn fallback_progress_survives_revocation_without_rebinding_the_closed_scope() {
    let mut model = Model::new();
    let (scope, binding) = model.create_scope(supervisor(1), Budget::new(1)).unwrap();
    let effect = model.register(binding, Budget::new(1)).unwrap();

    model.crash(binding).unwrap();
    assert!(model.scope(scope).unwrap().fallback_pending);
    model.revoke_begin(scope).unwrap();

    let closing = model.scope(scope).unwrap();
    assert_eq!(closing.state, ScopeState::Closing);
    assert!(closing.fallback_pending);
    assert!(!closing.fallback_selected);
    model.fallback_pick(scope).unwrap();
    assert!(model.scope(scope).unwrap().fallback_selected);
    assert_eq!(
        model.rebind(scope, supervisor(2)),
        Err(ModelError::InvalidScopeState {
            state: ScopeState::Closing
        })
    );

    assert_eq!(
        model.revoke_step(scope).unwrap().unwrap().to,
        EffectState::Cancelling
    );
    assert_eq!(
        model.revoke_step(scope).unwrap().unwrap().to,
        EffectState::Aborted
    );
    model.revoke_complete(scope).unwrap();

    let revoked = model.scope(scope).unwrap();
    assert_eq!(revoked.state, ScopeState::Revoked);
    assert!(revoked.fallback_selected);
    assert_eq!(model.effect(effect).unwrap().state, EffectState::Aborted);
    assert_eq!(
        model.rebind(scope, supervisor(2)),
        Err(ModelError::InvalidScopeState {
            state: ScopeState::Revoked
        })
    );

    let actions: Vec<_> = model.trace().iter().map(|event| event.action).collect();
    let crash = actions
        .iter()
        .position(|action| *action == TraceAction::Crash)
        .unwrap();
    let revoke_begin = actions
        .iter()
        .position(|action| *action == TraceAction::RevokeBegin)
        .unwrap();
    let fallback = actions
        .iter()
        .position(|action| *action == TraceAction::FallbackPick)
        .unwrap();
    let revoke_complete = actions
        .iter()
        .position(|action| *action == TraceAction::RevokeComplete)
        .unwrap();
    assert!(crash < revoke_begin && revoke_begin < fallback && fallback < revoke_complete);
    model.check_invariants().unwrap();
}

#[test]
fn pending_fallback_can_be_selected_after_revocation_completes() {
    let mut model = Model::new();
    let (scope, binding) = model.create_scope(supervisor(1), Budget::ZERO).unwrap();

    model.crash(binding).unwrap();
    model.revoke_begin(scope).unwrap();
    model.revoke_complete(scope).unwrap();
    assert!(model.scope(scope).unwrap().fallback_pending);

    model.fallback_pick(scope).unwrap();
    let revoked = model.scope(scope).unwrap();
    assert_eq!(revoked.state, ScopeState::Revoked);
    assert!(revoked.fallback_selected);
    assert!(!revoked.fallback_pending);
    model.check_invariants().unwrap();
}

#[test]
fn revocation_work_touches_only_the_affected_reverse_index() {
    const TARGET_EFFECTS: usize = 7;
    const UNRELATED_EFFECTS: usize = 31;

    let mut model = Model::new();
    let (target_scope, target_binding) = model
        .create_scope(supervisor(1), Budget::new(TARGET_EFFECTS as u64))
        .unwrap();
    let (other_scope, other_binding) = model
        .create_scope(supervisor(2), Budget::new(UNRELATED_EFFECTS as u64))
        .unwrap();
    for _ in 0..TARGET_EFFECTS {
        model.register(target_binding, Budget::new(1)).unwrap();
    }
    for _ in 0..UNRELATED_EFFECTS {
        model.register(other_binding, Budget::new(1)).unwrap();
    }

    model.revoke_begin(target_scope).unwrap();
    assert_eq!(
        model.revoke_complete(target_scope),
        Err(ModelError::RevocationNotQuiescent {
            remaining: TARGET_EFFECTS
        })
    );
    let mut steps = 0;
    while model.revoke_step(target_scope).unwrap().is_some() {
        steps += 1;
    }
    assert_eq!(steps, TARGET_EFFECTS * 2);
    model.revoke_complete(target_scope).unwrap();

    assert_eq!(
        model.live_effects(other_scope).unwrap().len(),
        UNRELATED_EFFECTS
    );
    assert_eq!(model.scope(other_scope).unwrap().state, ScopeState::Active);
    let progress = model.scope(target_scope).unwrap().revocation.unwrap();
    assert_eq!(progress.target_count, TARGET_EFFECTS);
    assert_eq!(progress.steps, TARGET_EFFECTS * 2);
    assert_eq!(progress.remaining, 0);
    model.check_invariants().unwrap();
}

#[test]
fn trace_has_a_dense_total_order_and_shared_fields() {
    let mut model = Model::new();
    let (scope, binding) = model.create_scope(supervisor(1), Budget::new(1)).unwrap();
    let effect = model.register(binding, Budget::new(1)).unwrap();
    model.prepare(binding, effect).unwrap();
    model.commit(binding, effect).unwrap();
    model.complete(effect).unwrap();

    for (expected, event) in model.trace().iter().enumerate() {
        assert_eq!(event.seq, expected);
        assert_eq!(event.scope, scope);
        assert!(event.authority_epoch > 0);
        assert!(event.binding_epoch > 0);
    }
}
