use cser_model::ScopeState;
use cser_model::personality::futex::{
    AddressSpaceGeneration, AddressSpaceId, FutexBudget, FutexContinuationState, FutexDelivery,
    FutexEffectId, FutexEffectState, FutexError, FutexKey, FutexModel, FutexOperation,
    FutexRevocationStep, FutexToken, FutexTokenParts,
};
use cser_model::personality::{PersonalityError, PersonalityFallbackState, PersonalityId, TaskId};

fn key(space: u64, generation: u64, address: u64) -> FutexKey {
    FutexKey::new(
        AddressSpaceId::new(space),
        AddressSpaceGeneration::new(generation),
        address,
    )
    .unwrap()
}

fn model(
    waits: u64,
    word: u32,
) -> (
    FutexModel,
    cser_model::ScopeId,
    cser_model::personality::PersonalityBindingToken,
    FutexKey,
) {
    let mut model = FutexModel::new();
    let key = key(7, 3, 0x4000);
    let (scope, binding) = model
        .create_scope(
            PersonalityId::new(1),
            FutexBudget::new(waits, 1, 1),
            key,
            word,
        )
        .unwrap();
    (model, scope, binding, key)
}

#[test]
fn wait_mismatch_is_failure_atomic_eagain_without_identity_queue_or_credit() {
    let (mut model, scope, binding, key) = model(1, 9);
    let before = model.clone();
    assert_eq!(
        model.wait_register(binding, TaskId::new(1), key, 8),
        Err(FutexError::Again { observed: 9 })
    );
    assert_eq!(model, before);
    let unchanged = model.scope(scope).unwrap();
    assert_eq!(unchanged.free_budget, FutexBudget::new(1, 1, 1));
    assert!(unchanged.queue.is_empty());
    assert_eq!(unchanged.live_effects, 0);

    let wait = model
        .wait_register(binding, TaskId::new(1), key, 9)
        .unwrap();
    assert_eq!(wait.effect(), FutexEffectId::new(1));
    let registered = model.scope(scope).unwrap();
    assert_eq!(registered.free_budget, FutexBudget::new(0, 1, 1));
    assert_eq!(registered.queue, vec![wait.effect()]);

    let before_duplicate = model.clone();
    assert_eq!(
        model.wait_register(binding, TaskId::new(1), key, 9),
        Err(FutexError::TaskAlreadyBlocked {
            effect: wait.effect()
        })
    );
    assert_eq!(model, before_duplicate);
    model.check_invariants().unwrap();
}

#[test]
fn wake_selection_survives_crash_snapshot_rebind_and_adoption_without_requeue() {
    let (mut model, scope, old_binding, key) = model(2, 5);
    let first = model
        .wait_register(old_binding, TaskId::new(10), key, 5)
        .unwrap();
    let second = model
        .wait_register(old_binding, TaskId::new(11), key, 5)
        .unwrap();
    let wake = model
        .wake_commit(old_binding, TaskId::new(12), key, 8)
        .unwrap();
    assert_eq!(wake.selected_wait, Some(first.effect()));
    assert_eq!(wake.frozen_count, 1);
    assert_eq!(model.scope(scope).unwrap().queue, vec![second.effect()]);

    model.crash(old_binding).unwrap();
    let crashed = model.scope(scope).unwrap();
    assert_eq!(crashed.gate.fallback, PersonalityFallbackState::Required);
    assert_eq!(crashed.free_budget, FutexBudget::new(0, 0, 0));
    assert_eq!(
        crashed.watchdog.unwrap().cohort,
        vec![first.effect(), second.effect(), wake.token.effect()]
    );
    model.fallback_pick(scope).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    assert_eq!(snapshot.queue(), &[second.effect()]);
    assert_eq!(snapshot.effects().len(), 3);
    let wake_snapshot = snapshot
        .effects()
        .iter()
        .find(|effect| effect.token.effect() == wake.token.effect())
        .unwrap();
    assert_eq!(wake_snapshot.selected_wait, Some(first.effect()));
    assert_eq!(wake_snapshot.frozen_count, Some(1));

    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();
    let adopted_second = model.adopt(replacement, second).unwrap();
    assert_eq!(model.scope(scope).unwrap().queue, vec![second.effect()]);
    let adopted_wake = model.adopt(replacement, wake.token).unwrap();
    assert_eq!(
        model.effect(adopted_wake.effect()).unwrap().selected_wait,
        Some(first.effect())
    );
    let adopted_first = model.adopt(replacement, first).unwrap();
    let recovered = model.scope(scope).unwrap();
    assert!(recovered.watchdog.is_none());
    assert_eq!(recovered.free_budget, FutexBudget::new(0, 0, 1));
    assert_eq!(recovered.queue, vec![adopted_second.effect()]);

    let publication = model.kernel_wake_publish(adopted_wake).unwrap();
    assert_eq!(publication.wait, Some(adopted_first.effect()));
    assert_eq!(publication.frozen_count, 1);
    let first_view = model.effect(first.effect()).unwrap();
    assert_eq!(first_view.state, FutexEffectState::Completed);
    assert_eq!(first_view.delivery, Some(FutexDelivery::WaitWoken));
    let wake_view = model.effect(wake.token.effect()).unwrap();
    assert_eq!(wake_view.state, FutexEffectState::Completed);
    assert_eq!(
        wake_view.delivery,
        Some(FutexDelivery::WakeReturned { count: 1 })
    );
    let second_view = model.effect(second.effect()).unwrap();
    assert_eq!(second_view.state, FutexEffectState::WaitQueued);
    assert_eq!(second_view.continuation, FutexContinuationState::Pending);
    assert_eq!(model.scope(scope).unwrap().free_budget.wait_credits(), 1);

    let before_spurious_deadline = model.clone();
    assert_eq!(
        model.watchdog_expire(scope),
        Err(FutexError::WatchdogNotArmed)
    );
    assert_eq!(model, before_spurious_deadline);

    model.revoke_begin(scope).unwrap();
    assert_eq!(
        model.revoke_next(scope).unwrap(),
        Some(FutexRevocationStep::AbortedWait {
            wait: second.effect()
        })
    );
    model.revoke_complete(scope).unwrap();
    assert_eq!(model.scope(scope).unwrap().gate.state, ScopeState::Revoked);
    assert_eq!(
        model.effect(second.effect()).unwrap().delivery,
        Some(FutexDelivery::Aborted)
    );
    assert_eq!(
        model.scope(scope).unwrap().free_budget,
        FutexBudget::new(2, 1, 1)
    );
    model.check_invariants().unwrap();
}

#[test]
fn zero_wake_count_is_frozen_and_published_without_waiter_selection() {
    let (mut model, scope, binding, key) = model(1, 1);
    let wait = model
        .wait_register(binding, TaskId::new(1), key, 1)
        .unwrap();
    let wake = model.wake_commit(binding, TaskId::new(2), key, 0).unwrap();
    assert_eq!(wake.selected_wait, None);
    assert_eq!(wake.frozen_count, 0);
    assert_eq!(model.scope(scope).unwrap().queue, vec![wait.effect()]);
    assert_eq!(model.scope(scope).unwrap().free_budget.wake_credits(), 0);

    let publication = model.kernel_wake_publish(wake.token).unwrap();
    assert_eq!(publication.wait, None);
    assert_eq!(publication.frozen_count, 0);
    assert_eq!(
        model.effect(wake.token.effect()).unwrap().delivery,
        Some(FutexDelivery::WakeReturned { count: 0 })
    );
    assert_eq!(
        model.effect(wait.effect()).unwrap().state,
        FutexEffectState::WaitQueued
    );
    assert_eq!(model.scope(scope).unwrap().queue, vec![wait.effect()]);
    assert_eq!(model.scope(scope).unwrap().free_budget.wake_credits(), 1);
    model.check_invariants().unwrap();
}

#[test]
fn empty_queue_wakes_are_bounded_by_one_wake_credit_and_return_it_once() {
    let mut model = FutexModel::new();
    let key = key(9, 1, 0x6000);
    let (scope, binding) = model
        .create_scope(PersonalityId::new(1), FutexBudget::new(0, 1, 1), key, 12)
        .unwrap();

    let before_wait = model.clone();
    assert_eq!(
        model.wait_register(binding, TaskId::new(1), key, 12),
        Err(FutexError::WaitBudgetExhausted)
    );
    assert_eq!(model, before_wait);

    let first = model.wake_commit(binding, TaskId::new(2), key, 1).unwrap();
    assert_eq!(first.frozen_count, 0);
    assert_eq!(model.scope(scope).unwrap().free_budget.wake_credits(), 0);
    let before_exhausted = model.clone();
    assert_eq!(
        model.wake_commit(binding, TaskId::new(3), key, 1),
        Err(FutexError::WakeBudgetExhausted)
    );
    assert_eq!(model, before_exhausted);

    model.kernel_wake_publish(first.token).unwrap();
    assert_eq!(model.scope(scope).unwrap().free_budget.wake_credits(), 1);
    let second = model.wake_commit(binding, TaskId::new(3), key, 1).unwrap();
    assert_eq!(second.frozen_count, 0);
    model.revoke_begin(scope).unwrap();
    assert_eq!(
        model.revoke_next(scope).unwrap(),
        Some(FutexRevocationStep::DrainedWake {
            wake: second.token.effect(),
            wait: None,
            frozen_count: 0,
        })
    );
    model.revoke_complete(scope).unwrap();
    assert_eq!(
        model.scope(scope).unwrap().free_budget,
        FutexBudget::new(0, 1, 1)
    );
    model.check_invariants().unwrap();
}

#[test]
fn wake_before_revoke_drains_but_revoke_before_wake_aborts() {
    let (mut wake_first, scope, binding, key) = model(1, 4);
    let wait = wake_first
        .wait_register(binding, TaskId::new(1), key, 4)
        .unwrap();
    let wake = wake_first
        .wake_commit(binding, TaskId::new(2), key, 1)
        .unwrap();
    wake_first.revoke_begin(scope).unwrap();
    assert_eq!(
        wake_first.revoke_next(scope).unwrap(),
        Some(FutexRevocationStep::DrainedWake {
            wake: wake.token.effect(),
            wait: Some(wait.effect()),
            frozen_count: 1,
        })
    );
    assert_eq!(wake_first.revoke_next(scope).unwrap(), None);
    wake_first.revoke_complete(scope).unwrap();
    assert_eq!(
        wake_first.effect(wait.effect()).unwrap().delivery,
        Some(FutexDelivery::WaitWoken)
    );
    assert_eq!(
        wake_first.effect(wake.token.effect()).unwrap().delivery,
        Some(FutexDelivery::WakeReturned { count: 1 })
    );
    wake_first.check_invariants().unwrap();

    let (mut revoke_first, scope, binding, key) = model(1, 4);
    let wait = revoke_first
        .wait_register(binding, TaskId::new(1), key, 4)
        .unwrap();
    revoke_first.revoke_begin(scope).unwrap();
    let before_fenced_wake = revoke_first.clone();
    assert!(matches!(
        revoke_first.wake_commit(binding, TaskId::new(2), key, 1),
        Err(FutexError::Personality(
            PersonalityError::InvalidScopeState {
                state: ScopeState::Closing
            }
        ))
    ));
    assert_eq!(revoke_first, before_fenced_wake);
    assert_eq!(
        revoke_first.revoke_next(scope).unwrap(),
        Some(FutexRevocationStep::AbortedWait {
            wait: wait.effect()
        })
    );
    revoke_first.revoke_complete(scope).unwrap();
    let aborted = revoke_first.effect(wait.effect()).unwrap();
    assert_eq!(aborted.state, FutexEffectState::Aborted);
    assert_eq!(aborted.delivery, Some(FutexDelivery::Aborted));
    assert_eq!(aborted.terminalizations, 1);
    revoke_first.check_invariants().unwrap();
}

#[test]
fn incomplete_recovery_watchdog_revokes_and_aborts_without_linux_timeout() {
    let (mut model, scope, old_binding, key) = model(2, 6);
    let first = model
        .wait_register(old_binding, TaskId::new(1), key, 6)
        .unwrap();
    let second = model
        .wait_register(old_binding, TaskId::new(2), key, 6)
        .unwrap();
    model.crash(old_binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();
    model.adopt(replacement, first).unwrap();
    assert_eq!(
        model.scope(scope).unwrap().watchdog.unwrap().cohort,
        vec![second.effect()]
    );

    model.watchdog_expire(scope).unwrap();
    assert_eq!(model.scope(scope).unwrap().gate.state, ScopeState::Closing);
    while model.revoke_next(scope).unwrap().is_some() {}
    model.revoke_complete(scope).unwrap();
    for wait in [first, second] {
        let view = model.effect(wait.effect()).unwrap();
        assert_eq!(view.state, FutexEffectState::Aborted);
        assert_eq!(view.delivery, Some(FutexDelivery::Aborted));
        assert_eq!(view.terminalizations, 1);
    }
    assert_eq!(
        model.scope(scope).unwrap().free_budget,
        FutexBudget::new(2, 1, 1)
    );
    model.check_invariants().unwrap();
}

#[test]
fn forged_stale_and_replayed_adoption_reject_without_mutation_after_rebind() {
    let (mut model, scope, old_binding, key) = model(1, 14);
    let old_wait = model
        .wait_register(old_binding, TaskId::new(1), key, 14)
        .unwrap();
    model.crash(old_binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();

    let before_stale_binding = model.clone();
    assert!(matches!(
        model.adopt(old_binding, old_wait),
        Err(FutexError::Personality(
            PersonalityError::StaleBinding { .. }
        ))
    ));
    assert_eq!(model, before_stale_binding);

    let mut forged_parts = old_wait.parts();
    forged_parts.task = TaskId::new(99);
    let forged = FutexToken::from_parts(forged_parts).unwrap();
    let before_forged = model.clone();
    assert_eq!(
        model.adopt(replacement, forged),
        Err(FutexError::EffectIdentityMismatch)
    );
    assert_eq!(model, before_forged);

    let adopted = model.adopt(replacement, old_wait).unwrap();
    let after_adoption = model.clone();
    assert_eq!(
        model.adopt(replacement, old_wait),
        Err(FutexError::EffectIdentityMismatch)
    );
    assert_eq!(model, after_adoption);
    assert_eq!(
        model.adopt(replacement, adopted),
        Err(FutexError::NotAdoptable)
    );
    assert_eq!(model, after_adoption);
    model.check_invariants().unwrap();
}

#[test]
fn premature_revoke_complete_with_wait_and_committed_wake_is_failure_atomic() {
    let (mut model, scope, binding, key) = model(1, 15);
    let wait = model
        .wait_register(binding, TaskId::new(1), key, 15)
        .unwrap();
    let wake = model.wake_commit(binding, TaskId::new(2), key, 1).unwrap();
    model.revoke_begin(scope).unwrap();

    let before = model.clone();
    assert_eq!(
        model.revoke_complete(scope),
        Err(FutexError::RevocationNotQuiescent { remaining: 2 })
    );
    assert_eq!(model, before);
    assert_eq!(
        model.revoke_next(scope).unwrap(),
        Some(FutexRevocationStep::DrainedWake {
            wake: wake.token.effect(),
            wait: Some(wait.effect()),
            frozen_count: 1,
        })
    );
    model.revoke_complete(scope).unwrap();
    model.check_invariants().unwrap();
}

#[test]
fn adopted_queued_wait_rearms_and_cancels_one_timer_credit_across_second_crash() {
    let (mut model, scope, first_binding, key) = model(1, 16);
    let original = model
        .wait_register(first_binding, TaskId::new(1), key, 16)
        .unwrap();

    model.crash(first_binding).unwrap();
    assert_eq!(model.scope(scope).unwrap().free_budget.timer_credits(), 0);
    model.fallback_pick(scope).unwrap();
    let first_snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    let first_ready = model.ready(&first_snapshot).unwrap();
    let second_binding = model.rebind(first_ready).unwrap();
    let first_adopted = model.adopt(second_binding, original).unwrap();
    assert!(model.scope(scope).unwrap().watchdog.is_none());
    assert_eq!(model.scope(scope).unwrap().free_budget.timer_credits(), 1);
    assert_eq!(
        model.effect(first_adopted.effect()).unwrap().state,
        FutexEffectState::WaitQueued
    );

    model.crash(second_binding).unwrap();
    let second_crash = model.scope(scope).unwrap();
    assert_eq!(second_crash.free_budget.timer_credits(), 0);
    assert_eq!(
        second_crash.watchdog.unwrap().cohort,
        vec![first_adopted.effect()]
    );
    model.fallback_pick(scope).unwrap();
    let second_snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(3))
        .unwrap();
    let second_ready = model.ready(&second_snapshot).unwrap();
    let third_binding = model.rebind(second_ready).unwrap();
    let second_adopted = model.adopt(third_binding, first_adopted).unwrap();
    let recovered = model.scope(scope).unwrap();
    assert!(recovered.watchdog.is_none());
    assert_eq!(recovered.free_budget.timer_credits(), 1);
    assert_eq!(recovered.free_budget.wait_credits(), 0);
    assert_eq!(
        second_adopted.binding_epoch(),
        third_binding.binding_epoch()
    );

    model.revoke_begin(scope).unwrap();
    assert!(matches!(
        model.revoke_next(scope).unwrap(),
        Some(FutexRevocationStep::AbortedWait { .. })
    ));
    model.revoke_complete(scope).unwrap();
    assert_eq!(
        model.scope(scope).unwrap().free_budget,
        FutexBudget::new(1, 1, 1)
    );
    model.check_invariants().unwrap();
}

#[test]
fn direct_kernel_publication_while_closing_drains_indexes_and_allows_completion() {
    let (mut model, scope, binding, key) = model(1, 18);
    let wait = model
        .wait_register(binding, TaskId::new(1), key, 18)
        .unwrap();
    let wake = model.wake_commit(binding, TaskId::new(2), key, 1).unwrap();
    model.revoke_begin(scope).unwrap();

    let publication = model.kernel_wake_publish(wake.token).unwrap();
    assert_eq!(publication.wait, Some(wait.effect()));
    let progress = model.scope(scope).unwrap().revocation.unwrap();
    assert_eq!(progress.target_count, 2);
    assert_eq!(progress.terminalized, 2);
    assert_eq!(progress.index_selections, 0);
    assert_eq!(model.revoke_next(scope).unwrap(), None);
    model.revoke_complete(scope).unwrap();
    assert_eq!(
        model.scope(scope).unwrap().free_budget,
        FutexBudget::new(1, 1, 1)
    );
    model.check_invariants().unwrap();
}

#[test]
fn every_full_identity_fence_and_duplicate_publication_reject_atomically() {
    let (mut model, _scope, binding, key) = model(1, 3);
    let wait = model
        .wait_register(binding, TaskId::new(1), key, 3)
        .unwrap();
    let wake = model.wake_commit(binding, TaskId::new(2), key, 1).unwrap();
    let original = wake.token.parts();
    let forged = vec![
        FutexTokenParts {
            scope: cser_model::ScopeId::new(original.scope.get() + 20),
            ..original
        },
        FutexTokenParts {
            effect: FutexEffectId::new(original.effect.get() + 20),
            ..original
        },
        FutexTokenParts {
            task: TaskId::new(original.task.get() + 20),
            ..original
        },
        FutexTokenParts {
            operation: FutexOperation::Wake { max_wake: 2 },
            ..original
        },
        FutexTokenParts {
            address_space: AddressSpaceId::new(original.address_space.get() + 1),
            ..original
        },
        FutexTokenParts {
            address_space_generation: AddressSpaceGeneration::new(
                original.address_space_generation.get() + 1,
            ),
            ..original
        },
        FutexTokenParts {
            aligned_address: original.aligned_address + 4,
            ..original
        },
        FutexTokenParts {
            authority_epoch: cser_model::personality::AuthorityEpoch::new(
                original.authority_epoch.get() + 1,
            ),
            ..original
        },
        FutexTokenParts {
            binding_epoch: cser_model::personality::BindingEpoch::new(
                original.binding_epoch.get() + 1,
            ),
            ..original
        },
    ];

    for parts in forged {
        let token = FutexToken::from_parts(parts).unwrap();
        let before = model.clone();
        assert!(matches!(
            model.kernel_wake_publish(token),
            Err(FutexError::EffectIdentityMismatch | FutexError::UnknownEffect(_))
        ));
        assert_eq!(model, before);
    }
    assert_eq!(
        model.effect(wait.effect()).unwrap().state,
        FutexEffectState::WaitClaimed
    );
    model.kernel_wake_publish(wake.token).unwrap();
    let completed = model.clone();
    assert!(matches!(
        model.kernel_wake_publish(wake.token),
        Err(FutexError::InvalidEffectState {
            state: FutexEffectState::Completed
        })
    ));
    assert_eq!(model, completed);
    model.check_invariants().unwrap();
}

#[test]
fn closure_selects_only_target_scope_index_heads_despite_large_unrelated_n() {
    let mut model = FutexModel::new();
    let target_key = key(21, 1, 0x9000);
    let unrelated_key = key(22, 1, 0xa000);
    let (target, target_binding) = model
        .create_scope(
            PersonalityId::new(1),
            FutexBudget::new(4, 2, 1),
            target_key,
            41,
        )
        .unwrap();
    let (unrelated, unrelated_binding) = model
        .create_scope(
            PersonalityId::new(2),
            FutexBudget::new(96, 1, 1),
            unrelated_key,
            42,
        )
        .unwrap();

    let mut target_waits = Vec::new();
    for task in 1..=4 {
        target_waits.push(
            model
                .wait_register(target_binding, TaskId::new(task), target_key, 41)
                .unwrap(),
        );
    }
    let first_wake = model
        .wake_commit(target_binding, TaskId::new(100), target_key, 1)
        .unwrap();
    let second_wake = model
        .wake_commit(target_binding, TaskId::new(101), target_key, 1)
        .unwrap();
    assert_eq!(first_wake.selected_wait, Some(target_waits[0].effect()));
    assert_eq!(second_wake.selected_wait, Some(target_waits[1].effect()));

    for task in 1..=96 {
        model
            .wait_register(unrelated_binding, TaskId::new(task), unrelated_key, 42)
            .unwrap();
    }
    let unrelated_before = model.scope(unrelated).unwrap();

    model.revoke_begin(target).unwrap();
    let initial = model.scope(target).unwrap().revocation.unwrap();
    assert_eq!(initial.target_count, 6);
    assert_eq!(initial.index_selections, 0);
    let mut successful_steps = 0usize;
    while model.revoke_next(target).unwrap().is_some() {
        successful_steps += 1;
        let progress = model.scope(target).unwrap().revocation.unwrap();
        assert_eq!(progress.index_selections, successful_steps);
        model.check_invariants().unwrap();
    }
    assert_eq!(successful_steps, 4);
    let finished = model.scope(target).unwrap().revocation.unwrap();
    assert_eq!(finished.terminalized, 6);
    assert_eq!(finished.index_selections, 4);
    model.revoke_complete(target).unwrap();

    assert_eq!(model.scope(unrelated).unwrap(), unrelated_before);
    assert_eq!(model.scope(unrelated).unwrap().live_effects, 96);
    model.check_invariants().unwrap();
}

#[test]
fn kernel_change_invalidates_snapshot_and_ready_without_reselection() {
    let (mut model, scope, binding, key) = self::model(1, 2);
    let wait = model
        .wait_register(binding, TaskId::new(1), key, 2)
        .unwrap();
    let wake = model.wake_commit(binding, TaskId::new(2), key, 1).unwrap();
    model.crash(binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let stale_snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    model.kernel_wake_publish(wake.token).unwrap();
    let after_publication = model.clone();
    assert_eq!(
        model.ready(&stale_snapshot),
        Err(FutexError::Personality(
            PersonalityError::StaleRecoverySnapshot
        ))
    );
    assert_eq!(model, after_publication);
    assert_eq!(
        model.effect(wait.effect()).unwrap().state,
        FutexEffectState::Completed
    );

    let fresh = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    assert!(fresh.effects().is_empty());
    let ready = model.ready(&fresh).unwrap();
    model.rebind(ready).unwrap();
    model.check_invariants().unwrap();

    let (mut model, scope, binding, key) = self::model(1, 2);
    let wait = model
        .wait_register(binding, TaskId::new(1), key, 2)
        .unwrap();
    let wake = model.wake_commit(binding, TaskId::new(2), key, 1).unwrap();
    model.crash(binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    let stale_ready = model.ready(&snapshot).unwrap();
    assert_eq!(
        model.scope(scope).unwrap().gate.fallback,
        PersonalityFallbackState::ReplacementReady
    );
    model.kernel_wake_publish(wake.token).unwrap();
    assert_eq!(
        model.scope(scope).unwrap().gate.fallback,
        PersonalityFallbackState::Running
    );
    let after_publication = model.clone();
    assert_eq!(
        model.rebind(stale_ready),
        Err(FutexError::Personality(
            PersonalityError::FallbackUnavailable
        ))
    );
    assert_eq!(model, after_publication);
    assert_eq!(
        model.effect(wait.effect()).unwrap().state,
        FutexEffectState::Completed
    );
    model.check_invariants().unwrap();
}
