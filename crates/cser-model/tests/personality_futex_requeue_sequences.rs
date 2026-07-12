use cser_model::ScopeState;
use cser_model::personality::futex::{AddressSpaceGeneration, AddressSpaceId, FutexKey};
use cser_model::personality::futex_requeue::{
    FutexControlReceipt, FutexRequeueError, FutexRequeueModel, FutexRequeueOperation,
    FutexRequeueRevocationStep, FutexRequeueState, FutexRequeueToken,
};
use cser_model::personality::registry::{RegistryBudget, RegistryError};
use cser_model::personality::{PersonalityError, PersonalityId, TaskId};

fn key(address: u64) -> FutexKey {
    FutexKey::new(
        AddressSpaceId::new(7),
        AddressSpaceGeneration::new(3),
        address,
    )
    .unwrap()
}

fn model(
    waits: u64,
) -> (
    FutexRequeueModel,
    cser_model::ScopeId,
    cser_model::personality::PersonalityBindingToken,
    FutexKey,
    FutexKey,
) {
    let mut model = FutexRequeueModel::new();
    let source = key(0x4000);
    let target = key(0x4004);
    let (scope, binding) = model
        .create_scope(
            PersonalityId::new(1),
            RegistryBudget::new(8, 0, waits, 0, 0, 0, 1),
            source,
            0,
            target,
            0,
        )
        .unwrap();
    (model, scope, binding, source, target)
}

fn queue(
    model: &FutexRequeueModel,
    scope: cser_model::ScopeId,
    key: FutexKey,
) -> Vec<cser_model::EffectId> {
    model
        .scope(scope)
        .unwrap()
        .queues
        .into_iter()
        .find(|queue| queue.key == key)
        .unwrap()
        .waits
}

#[test]
fn wake_one_move_one_returns_two_and_preserves_moved_identity_and_credit() {
    let (mut model, scope, binding, source, target) = model(2);
    let first = model
        .wait_register(binding, TaskId::new(1), source, 0)
        .unwrap();
    let second = model
        .wait_register(binding, TaskId::new(2), source, 0)
        .unwrap();
    let control = model
        .capture_requeue(binding, TaskId::new(3), source, target, 1, 1)
        .unwrap();
    let receipt = model.requeue_commit(binding, control).unwrap();
    assert_eq!(receipt.woken_wait, Some(first.effect()));
    assert_eq!(receipt.moved_wait, Some(second.effect()));
    assert_eq!(receipt.woken_count, 1);
    assert_eq!(receipt.requeued_count, 1);
    assert_eq!(receipt.affected_count, 2);
    assert!(queue(&model, scope, source).is_empty());
    assert_eq!(queue(&model, scope, target), vec![second.effect()]);

    let moved = model.effect(second.effect()).unwrap();
    assert_eq!(moved.token, second);
    assert_eq!(moved.state, FutexRequeueState::WaitQueued);
    assert_eq!(moved.queued_on, Some(target));
    assert_eq!(moved.migration_count, 1);
    assert_eq!(
        model
            .scope(scope)
            .unwrap()
            .registry
            .free_budget
            .futex_wait(),
        0
    );
    model.check_invariants().unwrap();

    model
        .kernel_publish(FutexControlReceipt::Requeue(receipt))
        .unwrap();
    assert_eq!(
        model.effect(first.effect()).unwrap().state,
        FutexRequeueState::Completed
    );
    assert_eq!(
        model.effect(second.effect()).unwrap().state,
        FutexRequeueState::WaitQueued
    );
    assert_eq!(
        model
            .scope(scope)
            .unwrap()
            .registry
            .free_budget
            .futex_wait(),
        1
    );

    let wake = model
        .capture_wake(binding, TaskId::new(3), target, 1)
        .unwrap();
    let wake = model.wake_commit(binding, wake).unwrap();
    assert_eq!(wake.selected_wait, Some(second.effect()));
    model
        .kernel_publish(FutexControlReceipt::Wake(wake))
        .unwrap();
    assert_eq!(
        model.scope(scope).unwrap().registry.free_budget,
        RegistryBudget::new(8, 0, 2, 0, 0, 0, 1)
    );
    model.check_invariants().unwrap();
}

#[test]
fn round4_late_waiter_recovery_loop_observes_one_zero_one_one() {
    let (mut model, scope, binding, source, target) = model(2);
    let first = model
        .wait_register(binding, TaskId::new(1), source, 0)
        .unwrap();
    let first_requeue = model
        .capture_requeue(binding, TaskId::new(10), source, target, 1, 1)
        .unwrap();
    let first_requeue = model.requeue_commit(binding, first_requeue).unwrap();
    assert_eq!(first_requeue.affected_count, 1);
    assert_eq!(first_requeue.woken_wait, Some(first.effect()));
    assert_eq!(first_requeue.moved_wait, None);
    model
        .kernel_publish(FutexControlReceipt::Requeue(first_requeue))
        .unwrap();

    let late = model
        .wait_register(binding, TaskId::new(2), source, 0)
        .unwrap();
    let empty_target_wake = model
        .capture_wake(binding, TaskId::new(10), target, 1)
        .unwrap();
    let empty_target_wake = model.wake_commit(binding, empty_target_wake).unwrap();
    assert_eq!(empty_target_wake.frozen_count, 0);
    model
        .kernel_publish(FutexControlReceipt::Wake(empty_target_wake))
        .unwrap();

    let recovery = model
        .capture_requeue(binding, TaskId::new(10), source, target, 0, 1)
        .unwrap();
    let recovery = model.requeue_commit(binding, recovery).unwrap();
    assert_eq!(recovery.woken_count, 0);
    assert_eq!(recovery.requeued_count, 1);
    assert_eq!(recovery.affected_count, 1);
    assert_eq!(recovery.moved_wait, Some(late.effect()));
    model
        .kernel_publish(FutexControlReceipt::Requeue(recovery))
        .unwrap();

    let target_wake = model
        .capture_wake(binding, TaskId::new(10), target, 1)
        .unwrap();
    let target_wake = model.wake_commit(binding, target_wake).unwrap();
    assert_eq!(target_wake.frozen_count, 1);
    assert_eq!(target_wake.selected_wait, Some(late.effect()));
    model
        .kernel_publish(FutexControlReceipt::Wake(target_wake))
        .unwrap();
    assert!(queue(&model, scope, source).is_empty());
    assert!(queue(&model, scope, target).is_empty());
    model.check_invariants().unwrap();
}

#[test]
fn target_backlog_stays_ahead_of_migrated_wait_and_source_cannot_wake_it() {
    let (mut model, scope, binding, source, target) = model(3);
    let existing = model
        .wait_register(binding, TaskId::new(1), target, 0)
        .unwrap();
    let source_first = model
        .wait_register(binding, TaskId::new(2), source, 0)
        .unwrap();
    let source_second = model
        .wait_register(binding, TaskId::new(3), source, 0)
        .unwrap();
    let requeue = model
        .capture_requeue(binding, TaskId::new(10), source, target, 1, 1)
        .unwrap();
    let requeue = model.requeue_commit(binding, requeue).unwrap();
    assert_eq!(requeue.woken_wait, Some(source_first.effect()));
    assert_eq!(requeue.moved_wait, Some(source_second.effect()));
    assert_eq!(
        queue(&model, scope, target),
        vec![existing.effect(), source_second.effect()]
    );
    model
        .kernel_publish(FutexControlReceipt::Requeue(requeue))
        .unwrap();

    let source_wake = model
        .capture_wake(binding, TaskId::new(10), source, 1)
        .unwrap();
    let source_wake = model.wake_commit(binding, source_wake).unwrap();
    assert_eq!(source_wake.frozen_count, 0);
    model
        .kernel_publish(FutexControlReceipt::Wake(source_wake))
        .unwrap();
    let target_wake = model
        .capture_wake(binding, TaskId::new(10), target, 1)
        .unwrap();
    let target_wake = model.wake_commit(binding, target_wake).unwrap();
    assert_eq!(target_wake.selected_wait, Some(existing.effect()));
    model.check_invariants().unwrap();
}

#[test]
fn fresh_binding_cannot_requeue_unadopted_old_wait() {
    let (mut model, scope, old_binding, source, target) = model(1);
    let wait = model
        .wait_register(old_binding, TaskId::new(1), source, 0)
        .unwrap();
    model.crash(old_binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();

    let requeue = model
        .capture_requeue(replacement, TaskId::new(2), source, target, 0, 1)
        .unwrap();
    let requeue = model.requeue_commit(replacement, requeue).unwrap();
    assert_eq!(requeue.affected_count, 0);
    assert_eq!(queue(&model, scope, source), vec![wait.effect()]);
    model
        .kernel_publish(FutexControlReceipt::Requeue(requeue))
        .unwrap();

    let adopted = model.adopt(replacement, wait).unwrap();
    let requeue = model
        .capture_requeue(replacement, TaskId::new(2), source, target, 0, 1)
        .unwrap();
    let requeue = model.requeue_commit(replacement, requeue).unwrap();
    assert_eq!(requeue.moved_wait, Some(adopted.effect()));
    assert_eq!(requeue.affected_count, 1);
    model.check_invariants().unwrap();
}

#[test]
fn unadopted_old_queue_head_cannot_be_skipped_for_a_fresh_waiter() {
    let (mut model, scope, old_binding, source, _target) = model(2);
    let old = model
        .wait_register(old_binding, TaskId::new(1), source, 0)
        .unwrap();
    model.crash(old_binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();
    let fresh = model
        .wait_register(replacement, TaskId::new(2), source, 0)
        .unwrap();

    let wake = model
        .capture_wake(replacement, TaskId::new(3), source, 1)
        .unwrap();
    let receipt = model.wake_commit(replacement, wake).unwrap();
    assert_eq!(receipt.selected_wait, None);
    assert_eq!(receipt.frozen_count, 0);
    assert_eq!(
        queue(&model, scope, source),
        vec![old.effect(), fresh.effect()]
    );
    model
        .kernel_publish(FutexControlReceipt::Wake(receipt))
        .unwrap();
    model.check_invariants().unwrap();
}

#[test]
fn crash_after_commit_preserves_receipt_across_snapshot_rebind_and_adoption() {
    let (mut model, scope, old_binding, source, target) = model(2);
    let first = model
        .wait_register(old_binding, TaskId::new(1), source, 0)
        .unwrap();
    let second = model
        .wait_register(old_binding, TaskId::new(2), source, 0)
        .unwrap();
    let control = model
        .capture_requeue(old_binding, TaskId::new(3), source, target, 1, 1)
        .unwrap();
    let receipt = model.requeue_commit(old_binding, control).unwrap();
    model.crash(old_binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();
    for token in [first, second, control] {
        model.adopt(replacement, token).unwrap();
    }
    model
        .kernel_publish(FutexControlReceipt::Requeue(receipt))
        .unwrap();
    assert_eq!(
        model.effect(first.effect()).unwrap().state,
        FutexRequeueState::Completed
    );
    assert_eq!(
        model.effect(second.effect()).unwrap().state,
        FutexRequeueState::WaitQueued
    );
    assert_eq!(
        model.effect(second.effect()).unwrap().queued_on,
        Some(target)
    );
    model.check_invariants().unwrap();
}

#[test]
fn requeue_before_revoke_drains_woken_and_aborts_moved_but_reverse_order_never_moves() {
    let (mut commit_first, scope, binding, source, target) = model(2);
    let first = commit_first
        .wait_register(binding, TaskId::new(1), source, 0)
        .unwrap();
    let second = commit_first
        .wait_register(binding, TaskId::new(2), source, 0)
        .unwrap();
    let control = commit_first
        .capture_requeue(binding, TaskId::new(3), source, target, 1, 1)
        .unwrap();
    let receipt = commit_first.requeue_commit(binding, control).unwrap();
    commit_first.revoke_begin(scope).unwrap();
    assert_eq!(
        commit_first.revoke_next(scope).unwrap(),
        Some(FutexRequeueRevocationStep::DrainedControl {
            control: control.effect(),
            wait: Some(first.effect())
        })
    );
    assert_eq!(
        commit_first.revoke_next(scope).unwrap(),
        Some(FutexRequeueRevocationStep::Aborted {
            effect: second.effect()
        })
    );
    commit_first.revoke_complete(scope).unwrap();
    assert_eq!(
        commit_first.scope(scope).unwrap().registry.gate.state,
        ScopeState::Revoked
    );
    assert_eq!(receipt.affected_count, 2);
    commit_first.check_invariants().unwrap();

    let (mut revoke_first, scope, binding, source, target) = model(2);
    let first = revoke_first
        .wait_register(binding, TaskId::new(1), source, 0)
        .unwrap();
    let second = revoke_first
        .wait_register(binding, TaskId::new(2), source, 0)
        .unwrap();
    let control = revoke_first
        .capture_requeue(binding, TaskId::new(3), source, target, 1, 1)
        .unwrap();
    revoke_first.revoke_begin(scope).unwrap();
    let before = revoke_first.clone();
    assert!(matches!(
        revoke_first.requeue_commit(binding, control),
        Err(FutexRequeueError::EffectIdentityMismatch)
    ));
    assert_eq!(revoke_first, before);
    assert_eq!(
        queue(&revoke_first, scope, source),
        vec![first.effect(), second.effect()]
    );
    while revoke_first.revoke_next(scope).unwrap().is_some() {}
    revoke_first.revoke_complete(scope).unwrap();
    revoke_first.check_invariants().unwrap();
}

#[test]
fn mismatch_and_forged_two_key_identity_are_failure_atomic() {
    let (mut model, _scope, binding, source, target) = model(1);
    let before_mismatch = model.clone();
    assert_eq!(
        model.wait_register(binding, TaskId::new(1), source, 1),
        Err(FutexRequeueError::Again { observed: 0 })
    );
    assert_eq!(model, before_mismatch);

    let control = model
        .capture_requeue(binding, TaskId::new(2), source, target, 1, 1)
        .unwrap();
    let forged = FutexRequeueToken::from_parts(
        control.registry(),
        FutexRequeueOperation::Requeue {
            source,
            target,
            max_wake: 0,
            max_requeue: 1,
        },
    );
    let before_forged = model.clone();
    assert_eq!(
        model.requeue_commit(binding, forged),
        Err(FutexRequeueError::EffectIdentityMismatch)
    );
    assert_eq!(model, before_forged);

    model.crash(binding).unwrap();
    let before_stale = model.clone();
    assert!(matches!(
        model.capture_wake(binding, TaskId::new(3), target, 1),
        Err(FutexRequeueError::Registry(RegistryError::Personality(
            PersonalityError::StaleBinding { .. }
        )))
    ));
    assert_eq!(model, before_stale);
}
