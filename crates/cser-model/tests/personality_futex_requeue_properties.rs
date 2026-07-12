use cser_model::personality::futex::{AddressSpaceGeneration, AddressSpaceId, FutexKey};
use cser_model::personality::futex_requeue::{
    FutexControlReceipt, FutexRequeueModel, FutexRequeueState,
};
use cser_model::personality::registry::{RegistryBudget, RegistryCreditClass};
use cser_model::personality::{PersonalityId, TaskId};
use proptest::prelude::*;

fn key(address: u64) -> FutexKey {
    FutexKey::new(
        AddressSpaceId::new(19),
        AddressSpaceGeneration::new(2),
        address,
    )
    .unwrap()
}

proptest! {
    #[test]
    fn arbitrary_two_key_partition_is_exact_and_quiesces_once(
        source_count in 0usize..10,
        target_count in 0usize..6,
        max_wake in 0u32..=1,
        max_requeue in 0u32..=1,
        publish_before_revoke in any::<bool>(),
    ) {
        let source = key(0x8000);
        let target = key(0x8004);
        let total = source_count + target_count;
        let mut model = FutexRequeueModel::new();
        let (scope, binding) = model
            .create_scope(
                PersonalityId::new(1),
                RegistryBudget::new(4, 0, total as u64, 0, 0, 0, 1),
                source,
                0,
                target,
                0,
            )
            .unwrap();
        let mut source_waits = Vec::new();
        let mut all_waits = Vec::new();
        for index in 0..source_count {
            let wait = model
                .wait_register(binding, TaskId::new(index as u64 + 1), source, 0)
                .unwrap();
            source_waits.push(wait);
            all_waits.push(wait);
        }
        let mut target_waits = Vec::new();
        for index in 0..target_count {
            let wait = model
                .wait_register(
                    binding,
                    TaskId::new(source_count as u64 + index as u64 + 1),
                    target,
                    0,
                )
                .unwrap();
            target_waits.push(wait);
            all_waits.push(wait);
        }
        let control = model
            .capture_requeue(
                binding,
                TaskId::new(100),
                source,
                target,
                max_wake,
                max_requeue,
            )
            .unwrap();
        let receipt = model.requeue_commit(binding, control).unwrap();
        let expected_woken = (max_wake > 0 && source_count > 0)
            .then(|| source_waits[0].effect());
        let expected_moved_index = usize::from(expected_woken.is_some());
        let expected_moved = (max_requeue > 0 && source_count > expected_moved_index)
            .then(|| source_waits[expected_moved_index].effect());
        prop_assert_eq!(receipt.woken_wait, expected_woken);
        prop_assert_eq!(receipt.moved_wait, expected_moved);
        prop_assert_eq!(
            receipt.affected_count,
            u32::from(expected_woken.is_some()) + u32::from(expected_moved.is_some())
        );
        if let Some(moved) = expected_moved {
            let view = model.effect(moved).unwrap();
            prop_assert_eq!(view.state, FutexRequeueState::WaitQueued);
            prop_assert_eq!(view.queued_on, Some(target));
            prop_assert_eq!(view.migration_count, 1);
        }
        model.check_invariants().unwrap();

        if publish_before_revoke {
            model
                .kernel_publish(FutexControlReceipt::Requeue(receipt))
                .unwrap();
        }
        model.revoke_begin(scope).unwrap();
        while model.revoke_next(scope).unwrap().is_some() {
            model.check_invariants().unwrap();
        }
        model.revoke_complete(scope).unwrap();
        for wait in all_waits {
            let view = model.effect(wait.effect()).unwrap();
            prop_assert!(view.state.is_terminal());
        }
        let closed = model.scope(scope).unwrap();
        prop_assert_eq!(closed.registry.free_budget.futex_wait(), total as u64);
        prop_assert_eq!(closed.registry.free_budget.continuation(), 4);
        prop_assert_eq!(closed.registry.free_budget.timer(), 1);
        prop_assert!(closed.queues.iter().all(|queue| queue.waits.is_empty()));
        model.check_invariants().unwrap();
    }

    #[test]
    fn arbitrary_moved_wait_never_changes_its_credit_class(
        target_backlog in 0usize..8,
    ) {
        let source = key(0x9000);
        let target = key(0x9004);
        let mut model = FutexRequeueModel::new();
        let (scope, binding) = model
            .create_scope(
                PersonalityId::new(1),
                RegistryBudget::new(2, 0, target_backlog as u64 + 1, 0, 0, 0, 1),
                source,
                0,
                target,
                0,
            )
            .unwrap();
        for index in 0..target_backlog {
            model
                .wait_register(binding, TaskId::new(index as u64 + 1), target, 0)
                .unwrap();
        }
        let moved = model
            .wait_register(binding, TaskId::new(50), source, 0)
            .unwrap();
        prop_assert_eq!(
            moved.registry().credit(),
            RegistryCreditClass::FutexWait
        );
        let control = model
            .capture_requeue(binding, TaskId::new(100), source, target, 0, 1)
            .unwrap();
        let receipt = model.requeue_commit(binding, control).unwrap();
        prop_assert_eq!(receipt.moved_wait, Some(moved.effect()));
        let moved_after = model.effect(moved.effect()).unwrap();
        prop_assert_eq!(moved_after.token, moved);
        prop_assert_eq!(
            moved_after.token.registry().credit(),
            RegistryCreditClass::FutexWait
        );
        prop_assert_eq!(moved_after.queued_on, Some(target));
        prop_assert_eq!(
            model.scope(scope).unwrap().registry.free_budget.futex_wait(),
            0
        );
        model.check_invariants().unwrap();
    }
}
