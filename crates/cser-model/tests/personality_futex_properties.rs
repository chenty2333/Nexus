use cser_model::ScopeState;
use cser_model::personality::futex::{
    AddressSpaceGeneration, AddressSpaceId, FutexBudget, FutexDelivery, FutexEffectState,
    FutexError, FutexKey, FutexModel, FutexOperation, FutexToken,
};
use cser_model::personality::{PersonalityError, PersonalityId, TaskId};
use proptest::prelude::*;

fn key() -> FutexKey {
    FutexKey::new(
        AddressSpaceId::new(11),
        AddressSpaceGeneration::new(4),
        0x8000,
    )
    .unwrap()
}

proptest! {
    #[test]
    fn arbitrary_value_mismatch_is_exact_eagain_and_failure_atomic(
        observed in any::<u32>(),
        nonzero_delta in 1u32..=u32::MAX,
        waits in 1u64..16,
    ) {
        let expected = observed.wrapping_add(nonzero_delta);
        prop_assume!(expected != observed);
        let mut model = FutexModel::new();
        let key = key();
        let (scope, binding) = model
            .create_scope(
                PersonalityId::new(1),
                FutexBudget::new(waits, 1, 1),
                key,
                observed,
            )
            .unwrap();
        let before = model.clone();
        prop_assert_eq!(
            model.wait_register(binding, TaskId::new(1), key, expected),
            Err(FutexError::Again { observed })
        );
        prop_assert_eq!(&model, &before);
        let scope = model.scope(scope).unwrap();
        prop_assert_eq!(scope.free_budget, FutexBudget::new(waits, 1, 1));
        prop_assert!(scope.queue.is_empty());
        prop_assert_eq!(scope.live_effects, 0);
        model.check_invariants().unwrap();
    }

    #[test]
    fn arbitrary_fifo_cohort_has_one_frozen_winner_and_conserves_credits(
        wait_count in 1usize..16,
        max_wake in 0u32..5,
        publish_before_revoke in any::<bool>(),
    ) {
        let mut model = FutexModel::new();
        let key = key();
        let (scope, binding) = model
            .create_scope(
                PersonalityId::new(1),
                FutexBudget::new(wait_count as u64, 1, 2),
                key,
                17,
            )
            .unwrap();
        let mut waits = Vec::new();
        for index in 0..wait_count {
            waits.push(
                model
                    .wait_register(binding, TaskId::new(index as u64 + 1), key, 17)
                    .unwrap(),
            );
            model.check_invariants().unwrap();
        }
        let wake = model
            .wake_commit(binding, TaskId::new(100), key, max_wake)
            .unwrap();
        let expected_winner = (max_wake > 0).then_some(waits[0].effect());
        prop_assert_eq!(wake.selected_wait, expected_winner);
        prop_assert_eq!(wake.frozen_count, u32::from(expected_winner.is_some()));
        let expected_queue: Vec<_> = waits
            .iter()
            .skip(usize::from(expected_winner.is_some()))
            .map(|token| token.effect())
            .collect();
        prop_assert_eq!(&model.scope(scope).unwrap().queue, &expected_queue);

        if publish_before_revoke {
            let publication = model.kernel_wake_publish(wake.token).unwrap();
            prop_assert_eq!(publication.wait, expected_winner);
            prop_assert_eq!(publication.frozen_count, wake.frozen_count);
        }
        model.revoke_begin(scope).unwrap();
        while model.revoke_next(scope).unwrap().is_some() {
            model.check_invariants().unwrap();
        }
        model.revoke_complete(scope).unwrap();

        for (index, wait) in waits.iter().enumerate() {
            let view = model.effect(wait.effect()).unwrap();
            prop_assert_eq!(view.terminalizations, 1);
            if expected_winner == Some(wait.effect()) {
                prop_assert_eq!(index, 0);
                prop_assert_eq!(view.state, FutexEffectState::Completed);
                prop_assert_eq!(view.delivery, Some(FutexDelivery::WaitWoken));
            } else {
                prop_assert_eq!(view.state, FutexEffectState::Aborted);
                prop_assert_eq!(view.delivery, Some(FutexDelivery::Aborted));
            }
        }
        let wake_view = model.effect(wake.token.effect()).unwrap();
        prop_assert_eq!(wake_view.state, FutexEffectState::Completed);
        prop_assert_eq!(
            wake_view.delivery,
            Some(FutexDelivery::WakeReturned {
                count: wake.frozen_count,
            })
        );
        prop_assert_eq!(wake_view.terminalizations, 1);
        let closed = model.scope(scope).unwrap();
        prop_assert_eq!(closed.gate.state, ScopeState::Revoked);
        prop_assert_eq!(
            closed.free_budget,
            FutexBudget::new(wait_count as u64, 1, 2)
        );
        prop_assert!(closed.queue.is_empty());
        model.check_invariants().unwrap();
    }

    #[test]
    fn arbitrary_partial_adoption_controls_only_recovery_watchdog_lifetime(
        wait_count in 1usize..10,
        adopt_mask in any::<u16>(),
        include_wake in any::<bool>(),
    ) {
        let mut model = FutexModel::new();
        let key = key();
        let (scope, old_binding) = model
            .create_scope(
                PersonalityId::new(1),
                FutexBudget::new(wait_count as u64, 1, 1),
                key,
                23,
            )
            .unwrap();
        let mut effects = Vec::new();
        for index in 0..wait_count {
            effects.push(
                model
                    .wait_register(old_binding, TaskId::new(index as u64 + 1), key, 23)
                    .unwrap(),
            );
        }
        if include_wake {
            effects.push(
                model
                    .wake_commit(old_binding, TaskId::new(100), key, 1)
                    .unwrap()
                    .token,
            );
        }
        model.crash(old_binding).unwrap();
        model.fallback_pick(scope).unwrap();
        let snapshot = model
            .recovery_snapshot(scope, PersonalityId::new(2))
            .unwrap();
        let ready = model.ready(&snapshot).unwrap();
        let replacement = model.rebind(ready).unwrap();

        let mut adopted_count = 0usize;
        for (index, token) in effects.iter().copied().enumerate() {
            if adopt_mask & (1u16 << index) != 0 {
                model.adopt(replacement, token).unwrap();
                adopted_count += 1;
                model.check_invariants().unwrap();
            }
        }
        let all_adopted = adopted_count == effects.len();
        let before_deadline = model.clone();
        if all_adopted {
            prop_assert_eq!(
                model.watchdog_expire(scope),
                Err(FutexError::WatchdogNotArmed)
            );
            prop_assert_eq!(&model, &before_deadline);
            prop_assert!(model.scope(scope).unwrap().watchdog.is_none());
            model.revoke_begin(scope).unwrap();
        } else {
            prop_assert!(model.scope(scope).unwrap().watchdog.is_some());
            model.watchdog_expire(scope).unwrap();
        }
        while model.revoke_next(scope).unwrap().is_some() {
            model.check_invariants().unwrap();
        }
        model.revoke_complete(scope).unwrap();
        let closed = model.scope(scope).unwrap();
        prop_assert!(closed.watchdog.is_none());
        prop_assert_eq!(
            closed.free_budget,
            FutexBudget::new(wait_count as u64, 1, 1)
        );
        for token in effects {
            let view = model.effect(token.effect()).unwrap();
            prop_assert!(view.state.is_terminal());
            prop_assert_eq!(view.terminalizations, 1);
            let delivery_is_bounded_terminal = matches!(
                view.delivery,
                Some(
                    FutexDelivery::WaitWoken
                        | FutexDelivery::WakeReturned { .. }
                        | FutexDelivery::Aborted
                )
            );
            prop_assert!(delivery_is_bounded_terminal);
        }
        model.check_invariants().unwrap();
    }

    #[test]
    fn arbitrary_single_field_forgery_cannot_change_frozen_selection(
        field in 0u8..8,
        delta in 1u64..1000,
    ) {
        let mut model = FutexModel::new();
        let key = key();
        let (_scope, binding) = model
            .create_scope(
                PersonalityId::new(1),
                FutexBudget::new(1, 1, 1),
                key,
                31,
            )
            .unwrap();
        let wait = model
            .wait_register(binding, TaskId::new(1), key, 31)
            .unwrap();
        let wake = model
            .wake_commit(binding, TaskId::new(2), key, 1)
            .unwrap();
        let mut parts = wake.token.parts();
        match field {
            0 => parts.scope = cser_model::ScopeId::new(parts.scope.get() + delta),
            1 => parts.task = TaskId::new(parts.task.get() + delta),
            2 => parts.operation = FutexOperation::Wake {
                max_wake: match parts.operation {
                    FutexOperation::Wake { max_wake } => max_wake.wrapping_add(delta as u32),
                    FutexOperation::Wait { .. } => unreachable!(),
                },
            },
            3 => parts.address_space = AddressSpaceId::new(parts.address_space.get() + delta),
            4 => {
                parts.address_space_generation =
                    AddressSpaceGeneration::new(parts.address_space_generation.get() + delta);
            }
            5 => parts.aligned_address += delta * 4,
            6 => {
                parts.authority_epoch = cser_model::personality::AuthorityEpoch::new(
                    parts.authority_epoch.get() + delta,
                );
            }
            7 => {
                parts.binding_epoch = cser_model::personality::BindingEpoch::new(
                    parts.binding_epoch.get() + delta,
                );
            }
            _ => unreachable!(),
        }
        let forged = FutexToken::from_parts(parts).unwrap();
        let before = model.clone();
        prop_assert_eq!(
            model.kernel_wake_publish(forged),
            Err(FutexError::EffectIdentityMismatch)
        );
        prop_assert_eq!(&model, &before);
        prop_assert_eq!(
            model.effect(wake.token.effect()).unwrap().selected_wait,
            Some(wait.effect())
        );
        prop_assert_eq!(
            model.effect(wait.effect()).unwrap().state,
            FutexEffectState::WaitClaimed
        );
        model.check_invariants().unwrap();
    }

    #[test]
    fn stale_binding_after_crash_rejects_wait_and_wake_without_mutation(
        expected in any::<u32>(),
    ) {
        let mut model = FutexModel::new();
        let key = key();
        let (scope, binding) = model
            .create_scope(
                PersonalityId::new(1),
                FutexBudget::new(1, 1, 1),
                key,
                expected,
            )
            .unwrap();
        model.crash(binding).unwrap();
        let before = model.clone();
        let stale_wait_rejected = matches!(
            model.wait_register(binding, TaskId::new(1), key, expected),
            Err(FutexError::Personality(PersonalityError::StaleBinding { .. }))
        );
        prop_assert!(stale_wait_rejected);
        let stale_wake_rejected = matches!(
            model.wake_commit(binding, TaskId::new(2), key, 1),
            Err(FutexError::Personality(PersonalityError::StaleBinding { .. }))
        );
        prop_assert!(stale_wake_rejected);
        prop_assert_eq!(&model, &before);
        prop_assert_eq!(model.scope(scope).unwrap().live_effects, 0);
        model.check_invariants().unwrap();
    }
}
