use cser_model::ScopeState;
use cser_model::personality::readiness::{
    READY_READABLE, READY_WRITABLE, ReadinessError, ReadinessModel, ReadinessOutcome,
    ReadinessRevocationStep, SubscriptionSpec, TriggerMode,
};
use cser_model::personality::registry::{RegistryBudget, RegistryCreditClass, RegistryError};
use cser_model::personality::{PersonalityId, TaskId};

fn model(
    initial_mask: u32,
) -> (
    ReadinessModel,
    cser_model::ScopeId,
    cser_model::personality::PersonalityBindingToken,
    cser_model::personality::readiness::ReadySourceId,
    cser_model::personality::readiness::ReadySetId,
) {
    let mut model = ReadinessModel::new();
    let (scope, binding, source, set) = model
        .create_scope(
            PersonalityId::new(1),
            RegistryBudget::new(0, 0, 0, 4, 2, 0, 3),
            7,
            initial_mask,
        )
        .unwrap();
    (model, scope, binding, source, set)
}

fn close(model: &mut ReadinessModel, scope: cser_model::ScopeId) {
    model.revoke_begin(scope).unwrap();
    while model.revoke_next(scope).unwrap().is_some() {
        model.check_invariants().unwrap();
    }
    model.revoke_complete(scope).unwrap();
    model.check_invariants().unwrap();
}

#[test]
fn atomic_sample_arm_level_and_oneshot_freeze_immutable_batches() {
    let (mut model, scope, binding, source, set) = model(READY_READABLE);
    let level = model
        .attach(
            binding,
            TaskId::new(1),
            set,
            source,
            SubscriptionSpec {
                interest: READY_READABLE,
                mode: TriggerMode::Level,
                cookie: 0x11,
            },
        )
        .unwrap();
    assert_eq!(model.scope(scope).unwrap().queued, vec![level.id()]);

    let wait = model
        .wait_register(binding, TaskId::new(2), set, 50)
        .unwrap();
    let receipt = model.ready_commit(binding, wait, 4).unwrap();
    assert_eq!(receipt.outcome(), ReadinessOutcome::Ready);
    assert_eq!(receipt.events().len(), 1);
    assert_eq!(receipt.events()[0].cookie, 0x11);
    assert_eq!(receipt.events()[0].source_generation, 7);
    assert_eq!(model.scope(scope).unwrap().queued, vec![level.id()]);

    let frozen = receipt.clone();
    model.source_update(scope, source, 7, 0).unwrap();
    assert_eq!(receipt, frozen);
    model.publish(&receipt).unwrap();
    let before_replay = model.clone();
    assert_eq!(
        model.publish(&receipt),
        Err(ReadinessError::ReceiptMismatch)
    );
    assert_eq!(model, before_replay);

    let oneshot = model
        .modify(binding, level, READY_READABLE, TriggerMode::OneShot, 0x22)
        .unwrap();
    let before_stale_subscription = model.clone();
    assert_eq!(
        model.modify(binding, level, READY_READABLE, TriggerMode::Edge, 0x99,),
        Err(ReadinessError::StaleSubscription)
    );
    assert_eq!(model, before_stale_subscription);
    model
        .source_update(scope, source, 7, READY_READABLE)
        .unwrap();
    assert_eq!(model.scope(scope).unwrap().queued, vec![oneshot.id()]);
    let wait = model
        .wait_register(binding, TaskId::new(2), set, 50)
        .unwrap();
    let receipt = model.ready_commit(binding, wait, 1).unwrap();
    assert_eq!(receipt.events()[0].subscription_generation, 2);
    assert_eq!(receipt.events()[0].cookie, 0x22);
    model.publish(&receipt).unwrap();
    assert!(model.scope(scope).unwrap().queued.is_empty());
    model.source_update(scope, source, 7, 0).unwrap();
    model
        .source_update(scope, source, 7, READY_READABLE)
        .unwrap();
    assert!(model.scope(scope).unwrap().queued.is_empty());

    close(&mut model, scope);
    let closed = model.scope(scope).unwrap();
    assert_eq!(closed.registry.gate.state, ScopeState::Revoked);
    assert_eq!(closed.registry.free_budget, closed.registry.initial_budget);
}

#[test]
fn edge_trigger_requires_a_new_not_ready_to_ready_transition() {
    let (mut model, scope, binding, source, set) = model(0);
    let edge = model
        .attach(
            binding,
            TaskId::new(1),
            set,
            source,
            SubscriptionSpec {
                interest: READY_READABLE,
                mode: TriggerMode::Edge,
                cookie: 0x44,
            },
        )
        .unwrap();
    model
        .source_update(scope, source, 7, READY_READABLE)
        .unwrap();
    assert_eq!(model.scope(scope).unwrap().queued, vec![edge.id()]);
    let wait = model
        .wait_register(binding, TaskId::new(2), set, 10)
        .unwrap();
    let receipt = model.ready_commit(binding, wait, 1).unwrap();
    model.publish(&receipt).unwrap();
    assert!(model.scope(scope).unwrap().queued.is_empty());

    model
        .source_update(scope, source, 7, READY_READABLE | READY_WRITABLE)
        .unwrap();
    assert!(model.scope(scope).unwrap().queued.is_empty());
    model.source_update(scope, source, 7, 0).unwrap();
    model
        .source_update(scope, source, 7, READY_READABLE)
        .unwrap();
    assert_eq!(model.scope(scope).unwrap().queued, vec![edge.id()]);
    close(&mut model, scope);
}

#[test]
fn crash_requires_exact_snapshot_and_explicit_adoption_before_timeout_commit() {
    let (mut model, scope, old_binding, source, set) = model(0);
    let subscription = model
        .attach(
            old_binding,
            TaskId::new(1),
            set,
            source,
            SubscriptionSpec {
                interest: READY_READABLE,
                mode: TriggerMode::Edge,
                cookie: 0x33,
            },
        )
        .unwrap();
    let wait = model
        .wait_register(old_binding, TaskId::new(2), set, 10)
        .unwrap();

    model.crash(old_binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let stale_snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    model
        .source_update(scope, source, 7, READY_WRITABLE)
        .unwrap();
    assert_eq!(
        model.ready(&stale_snapshot),
        Err(ReadinessError::StaleRecoverySnapshot)
    );
    let snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    let ready = model.ready(&snapshot).unwrap();
    model
        .source_update(scope, source, 7, READY_READABLE)
        .unwrap();
    assert!(matches!(
        model.rebind(ready),
        Err(ReadinessError::Registry(RegistryError::Personality(_)))
    ));
    let snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();

    let before_old = model.clone();
    assert!(matches!(
        model.timeout_commit(old_binding, wait),
        Err(ReadinessError::Registry(
            RegistryError::Personality(_) | RegistryError::EffectIdentityMismatch
        ))
    ));
    assert_eq!(model, before_old);

    model.adopt(replacement, subscription.registry()).unwrap();
    model.adopt(replacement, wait.wait()).unwrap();
    model.adopt(replacement, wait.timer()).unwrap();
    let adopted = model.wait(wait.wait().effect()).unwrap();
    let receipt = model.timeout_commit(replacement, adopted).unwrap();
    assert_eq!(receipt.outcome(), ReadinessOutcome::TimedOut);
    assert!(receipt.events().is_empty());
    model.publish(&receipt).unwrap();

    let generation = model.source_restart(scope, source, 7).unwrap();
    assert_eq!(generation, 8);
    let before_stale_source = model.clone();
    assert_eq!(
        model.source_update(scope, source, 7, READY_READABLE),
        Err(ReadinessError::StaleSourceGeneration)
    );
    assert_eq!(model, before_stale_source);
    close(&mut model, scope);
}

#[test]
fn ready_commit_cannot_select_an_unadopted_old_binding_subscription() {
    let (mut model, scope, old_binding, source, set) = model(READY_READABLE);
    let subscription = model
        .attach(
            old_binding,
            TaskId::new(1),
            set,
            source,
            SubscriptionSpec {
                interest: READY_READABLE,
                mode: TriggerMode::Edge,
                cookie: 0x55,
            },
        )
        .unwrap();
    let wait = model
        .wait_register(old_binding, TaskId::new(2), set, 10)
        .unwrap();

    model.crash(old_binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();
    model.adopt(replacement, wait.wait()).unwrap();
    model.adopt(replacement, wait.timer()).unwrap();
    let adopted_wait = model.wait(wait.wait().effect()).unwrap();

    let before_fenced_selection = model.clone();
    assert_eq!(
        model.ready_commit(replacement, adopted_wait, 1),
        Err(ReadinessError::Registry(
            RegistryError::EffectIdentityMismatch
        ))
    );
    assert_eq!(model, before_fenced_selection);

    model.adopt(replacement, subscription.registry()).unwrap();
    let receipt = model.ready_commit(replacement, adopted_wait, 1).unwrap();
    assert_eq!(receipt.outcome(), ReadinessOutcome::Ready);
    model.publish(&receipt).unwrap();
    close(&mut model, scope);
}

#[test]
fn ready_timeout_and_revoke_have_exactly_one_winner() {
    let (mut ready_model, ready_scope, binding, source, set) = model(READY_READABLE);
    ready_model
        .attach(
            binding,
            TaskId::new(1),
            set,
            source,
            SubscriptionSpec {
                interest: READY_READABLE,
                mode: TriggerMode::Edge,
                cookie: 1,
            },
        )
        .unwrap();
    let wait = ready_model
        .wait_register(binding, TaskId::new(2), set, 1)
        .unwrap();
    let receipt = ready_model.ready_commit(binding, wait, 1).unwrap();
    let before_timeout = ready_model.clone();
    assert_eq!(
        ready_model.timeout_commit(binding, wait),
        Err(ReadinessError::WinnerAlreadyChosen)
    );
    assert_eq!(ready_model, before_timeout);
    ready_model.revoke_begin(ready_scope).unwrap();
    assert_eq!(
        ready_model.revoke_next(ready_scope).unwrap(),
        Some(ReadinessRevocationStep::DrainedResolution {
            wait: wait.wait().effect()
        })
    );
    while ready_model.revoke_next(ready_scope).unwrap().is_some() {}
    ready_model.revoke_complete(ready_scope).unwrap();
    assert_eq!(receipt.outcome(), ReadinessOutcome::Ready);

    let (mut timeout_model, timeout_scope, binding, source, set) = model(READY_READABLE);
    timeout_model
        .attach(
            binding,
            TaskId::new(1),
            set,
            source,
            SubscriptionSpec {
                interest: READY_READABLE,
                mode: TriggerMode::Edge,
                cookie: 1,
            },
        )
        .unwrap();
    let wait = timeout_model
        .wait_register(binding, TaskId::new(2), set, 1)
        .unwrap();
    let receipt = timeout_model.timeout_commit(binding, wait).unwrap();
    let before_ready = timeout_model.clone();
    assert_eq!(
        timeout_model.ready_commit(binding, wait, 1),
        Err(ReadinessError::WinnerAlreadyChosen)
    );
    assert_eq!(timeout_model, before_ready);
    timeout_model.publish(&receipt).unwrap();
    close(&mut timeout_model, timeout_scope);

    let (mut revoke_model, revoke_scope, binding, source, set) = model(READY_READABLE);
    revoke_model
        .attach(
            binding,
            TaskId::new(1),
            set,
            source,
            SubscriptionSpec {
                interest: READY_READABLE,
                mode: TriggerMode::Edge,
                cookie: 1,
            },
        )
        .unwrap();
    let wait = revoke_model
        .wait_register(binding, TaskId::new(2), set, 1)
        .unwrap();
    revoke_model.revoke_begin(revoke_scope).unwrap();
    let before_ready = revoke_model.clone();
    assert!(matches!(
        revoke_model.ready_commit(binding, wait, 1),
        Err(ReadinessError::Registry(_))
    ));
    assert_eq!(revoke_model, before_ready);
    let before_timeout = revoke_model.clone();
    assert!(matches!(
        revoke_model.timeout_commit(binding, wait),
        Err(ReadinessError::Registry(_))
    ));
    assert_eq!(revoke_model, before_timeout);
    while revoke_model.revoke_next(revoke_scope).unwrap().is_some() {
        revoke_model.check_invariants().unwrap();
    }
    revoke_model.revoke_complete(revoke_scope).unwrap();
}

#[test]
fn failed_timer_registration_rolls_back_wait_identity_and_credit() {
    let mut model = ReadinessModel::new();
    let (scope, binding, _source, set) = model
        .create_scope(
            PersonalityId::new(1),
            RegistryBudget::new(0, 0, 0, 0, 1, 0, 1),
            1,
            0,
        )
        .unwrap();
    let before = model.clone();
    assert_eq!(
        model.wait_register(binding, TaskId::new(1), set, 1),
        Err(ReadinessError::Registry(RegistryError::CreditExhausted(
            RegistryCreditClass::Timer
        )))
    );
    assert_eq!(model, before);
    assert!(model.scope(scope).unwrap().registry.live_effects.is_empty());
    model.check_invariants().unwrap();
}
