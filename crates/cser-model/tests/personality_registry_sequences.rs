use cser_model::ScopeState;
use cser_model::personality::registry::{
    EffectRegistry, RegistryBudget, RegistryContinuationState, RegistryCreditClass,
    RegistryEffectKind, RegistryEffectState, RegistryError, RegistryResourceKey, RegistryResources,
    RegistryRevocationStep, RegistryTokenParts,
};
use cser_model::personality::{PersonalityId, TaskId};

fn model() -> (
    EffectRegistry,
    cser_model::ScopeId,
    cser_model::personality::PersonalityBindingToken,
) {
    let mut registry = EffectRegistry::new();
    let (scope, binding) = registry
        .create_scope(
            PersonalityId::new(1),
            RegistryBudget::new(2, 0, 2, 2, 1, 1, 1),
        )
        .unwrap();
    (registry, scope, binding)
}

#[test]
fn batch_commit_and_completion_are_atomic_and_return_typed_credits_once() {
    let (mut registry, scope, binding) = model();
    let wait = registry
        .register(
            binding,
            TaskId::new(1),
            RegistryEffectKind::FutexWait,
            RegistryResources::one(RegistryResourceKey::new(10)),
            RegistryCreditClass::FutexWait,
        )
        .unwrap();
    let control = registry
        .register(
            binding,
            TaskId::new(2),
            RegistryEffectKind::FutexRequeue,
            RegistryResources::pair(RegistryResourceKey::new(10), RegistryResourceKey::new(11)),
            RegistryCreditClass::Continuation,
        )
        .unwrap();
    let registered = registry.scope(scope).unwrap();
    assert_eq!(
        registered.free_budget,
        RegistryBudget::new(1, 0, 1, 2, 1, 1, 1)
    );
    assert_eq!(registered.resources.len(), 2);
    assert_eq!(registered.resources[0].effects.len(), 2);
    assert_eq!(registered.resources[1].effects, vec![control.effect()]);

    let before_duplicate = registry.clone();
    assert_eq!(
        registry.commit_many(binding, &[(wait, 72), (wait, 73)]),
        Err(RegistryError::InvalidBatch)
    );
    assert_eq!(registry, before_duplicate);

    let receipts = registry
        .commit_many(binding, &[(control, 70), (wait, 71)])
        .unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].domain_receipt(), 70);
    assert_eq!(receipts[1].domain_receipt(), 71);
    assert_eq!(registry.scope(scope).unwrap().committed_effects.len(), 2);

    registry.complete_many(&receipts).unwrap();
    let completed = registry.scope(scope).unwrap();
    assert_eq!(
        completed.free_budget,
        RegistryBudget::new(2, 0, 2, 2, 1, 1, 1)
    );
    assert!(completed.resources.is_empty());
    assert!(completed.live_effects.is_empty());
    for token in [wait, control] {
        let effect = registry.effect(token.effect()).unwrap();
        assert_eq!(effect.state, RegistryEffectState::Completed);
        assert_eq!(effect.continuation, RegistryContinuationState::Delivered);
        assert_eq!(effect.publications, 1);
        assert_eq!(effect.terminalizations, 1);
    }
    let before_replay = registry.clone();
    assert!(matches!(
        registry.complete_many(&receipts),
        Err(RegistryError::InvalidEffectState {
            state: RegistryEffectState::Completed
        })
    ));
    assert_eq!(registry, before_replay);
    registry.check_invariants().unwrap();
}

#[test]
fn crash_snapshot_rebind_and_adopt_preserve_an_immutable_old_commit_receipt() {
    let (mut registry, scope, old_binding) = model();
    let wait = registry
        .register(
            old_binding,
            TaskId::new(1),
            RegistryEffectKind::FutexWait,
            RegistryResources::one(RegistryResourceKey::new(10)),
            RegistryCreditClass::FutexWait,
        )
        .unwrap();
    let control = registry
        .register(
            old_binding,
            TaskId::new(2),
            RegistryEffectKind::FutexWake,
            RegistryResources::one(RegistryResourceKey::new(10)),
            RegistryCreditClass::Continuation,
        )
        .unwrap();
    let receipt = registry.commit(old_binding, control, 99).unwrap();

    registry.crash(old_binding).unwrap();
    assert_eq!(registry.scope(scope).unwrap().free_budget.timer(), 0);
    registry.fallback_pick(scope).unwrap();
    let snapshot = registry
        .recovery_snapshot(scope, PersonalityId::new(2))
        .unwrap();
    assert_eq!(snapshot.effects().len(), 2);
    let ready = registry.ready(&snapshot).unwrap();
    let replacement = registry.rebind(ready).unwrap();

    let adopted_wait = registry.adopt(replacement, wait).unwrap();
    let adopted_control = registry.adopt(replacement, control).unwrap();
    assert_ne!(adopted_control, receipt.token());
    assert_eq!(
        registry.effect(control.effect()).unwrap().receipt,
        Some(receipt)
    );
    assert!(registry.scope(scope).unwrap().watchdog_cohort.is_none());
    assert_eq!(registry.scope(scope).unwrap().free_budget.timer(), 1);

    registry.complete(receipt).unwrap();
    assert_eq!(
        registry.effect(adopted_control.effect()).unwrap().state,
        RegistryEffectState::Completed
    );
    assert_eq!(
        registry.effect(adopted_wait.effect()).unwrap().state,
        RegistryEffectState::Registered
    );
    registry.revoke_begin(scope).unwrap();
    assert_eq!(
        registry.revoke_next(scope).unwrap(),
        Some(RegistryRevocationStep::Aborted {
            effect: adopted_wait.effect()
        })
    );
    registry.revoke_complete(scope).unwrap();
    assert_eq!(
        registry.scope(scope).unwrap().gate.state,
        ScopeState::Revoked
    );
    registry.check_invariants().unwrap();
}

#[test]
fn revocation_drains_committed_and_aborts_registered_without_global_scan() {
    let (mut registry, scope, binding) = model();
    let committed = registry
        .register(
            binding,
            TaskId::new(1),
            RegistryEffectKind::FutexWake,
            RegistryResources::one(RegistryResourceKey::new(10)),
            RegistryCreditClass::Continuation,
        )
        .unwrap();
    registry.commit(binding, committed, 1).unwrap();
    let registered = registry
        .register(
            binding,
            TaskId::new(2),
            RegistryEffectKind::FutexWait,
            RegistryResources::one(RegistryResourceKey::new(10)),
            RegistryCreditClass::FutexWait,
        )
        .unwrap();

    registry.revoke_begin(scope).unwrap();
    assert_eq!(
        registry.revoke_next(scope).unwrap(),
        Some(RegistryRevocationStep::Drained {
            effect: committed.effect()
        })
    );
    assert_eq!(
        registry.revoke_next(scope).unwrap(),
        Some(RegistryRevocationStep::Aborted {
            effect: registered.effect()
        })
    );
    assert_eq!(registry.revoke_next(scope).unwrap(), None);
    let progress = registry.scope(scope).unwrap().revocation.unwrap();
    assert_eq!(progress.target_count, 2);
    assert_eq!(progress.terminalized, 2);
    assert_eq!(progress.index_selections, 2);
    registry.revoke_complete(scope).unwrap();
    assert_eq!(
        registry.scope(scope).unwrap().free_budget,
        RegistryBudget::new(2, 0, 2, 2, 1, 1, 1)
    );
    registry.check_invariants().unwrap();
}

#[test]
fn full_identity_forgery_and_stale_binding_reject_without_mutation() {
    let (mut registry, _scope, binding) = model();
    let token = registry
        .register(
            binding,
            TaskId::new(1),
            RegistryEffectKind::FutexWait,
            RegistryResources::one(RegistryResourceKey::new(10)),
            RegistryCreditClass::FutexWait,
        )
        .unwrap();
    let original = token.parts();
    let forged = [
        RegistryTokenParts {
            task: TaskId::new(99),
            ..original
        },
        RegistryTokenParts {
            kind: RegistryEffectKind::ReadinessWait,
            ..original
        },
        RegistryTokenParts {
            resources: RegistryResources::one(RegistryResourceKey::new(99)),
            ..original
        },
        RegistryTokenParts {
            credit: RegistryCreditClass::ReadinessWait,
            ..original
        },
        RegistryTokenParts {
            binding_epoch: cser_model::personality::BindingEpoch::new(
                original.binding_epoch.get() + 1,
            ),
            ..original
        },
    ];
    for parts in forged {
        let before = registry.clone();
        assert_eq!(
            registry.commit(
                binding,
                cser_model::personality::registry::RegistryEffectToken::from_parts(parts),
                1
            ),
            Err(RegistryError::EffectIdentityMismatch)
        );
        assert_eq!(registry, before);
    }
    registry.check_invariants().unwrap();
}

#[test]
fn wrong_credit_class_rejects_registration_without_mutation() {
    let (mut registry, _scope, binding) = model();
    let before = registry.clone();
    assert_eq!(
        registry.register(
            binding,
            TaskId::new(44),
            RegistryEffectKind::ReadinessSubscription,
            RegistryResources::one(RegistryResourceKey::new(100)),
            RegistryCreditClass::FutexWait,
        ),
        Err(RegistryError::WrongCreditClass {
            kind: RegistryEffectKind::ReadinessSubscription,
            credit: RegistryCreditClass::FutexWait,
        })
    );
    assert_eq!(registry, before);
    registry.check_invariants().unwrap();
}

#[test]
fn timer_registration_cannot_consume_the_crash_watchdog_reserve() {
    let (mut registry, scope, binding) = model();
    let before = registry.clone();
    assert_eq!(
        registry.register(
            binding,
            TaskId::new(44),
            RegistryEffectKind::TimerDeadline,
            RegistryResources::one(RegistryResourceKey::new(100)),
            RegistryCreditClass::Timer,
        ),
        Err(RegistryError::CreditExhausted(RegistryCreditClass::Timer))
    );
    assert_eq!(registry, before);

    let syscall = registry
        .register(
            binding,
            TaskId::new(45),
            RegistryEffectKind::SyscallContinuation,
            RegistryResources::one(RegistryResourceKey::new(200)),
            RegistryCreditClass::Continuation,
        )
        .unwrap();
    registry.crash(binding).unwrap();
    let crashed = registry.scope(scope).unwrap();
    assert_eq!(crashed.free_budget.timer(), 0);
    assert_eq!(crashed.watchdog_cohort, Some(vec![syscall.effect()]));
    registry.check_invariants().unwrap();
}

#[test]
fn a_timer_deadline_can_coexist_with_a_reserved_crash_watchdog_credit() {
    let mut registry = EffectRegistry::new();
    let (scope, binding) = registry
        .create_scope(
            PersonalityId::new(1),
            RegistryBudget::new(1, 0, 0, 0, 0, 0, 2),
        )
        .unwrap();
    let timer = registry
        .register(
            binding,
            TaskId::new(44),
            RegistryEffectKind::TimerDeadline,
            RegistryResources::one(RegistryResourceKey::new(100)),
            RegistryCreditClass::Timer,
        )
        .unwrap();
    assert_eq!(registry.scope(scope).unwrap().free_budget.timer(), 1);

    registry.crash(binding).unwrap();
    let crashed = registry.scope(scope).unwrap();
    assert_eq!(crashed.free_budget.timer(), 0);
    assert_eq!(crashed.watchdog_cohort, Some(vec![timer.effect()]));
    registry.check_invariants().unwrap();
}

#[test]
fn exec_controller_and_detached_segments_commit_and_terminalize_as_one_batch() {
    let mut registry = EffectRegistry::new();
    let (scope, binding) = registry
        .create_scope(
            PersonalityId::new(1),
            RegistryBudget::new(1, 2, 0, 0, 0, 0, 1),
        )
        .unwrap();
    let owner = TaskId::new(44);
    let transaction = registry
        .register(
            binding,
            owner,
            RegistryEffectKind::ExecTransaction,
            RegistryResources::one(RegistryResourceKey::new(100)),
            RegistryCreditClass::Continuation,
        )
        .unwrap();
    let first_segment = registry
        .register(
            binding,
            owner,
            RegistryEffectKind::ExecSegment,
            RegistryResources::one(RegistryResourceKey::new(101)),
            RegistryCreditClass::ExecSegment,
        )
        .unwrap();
    let second_segment = registry
        .register(
            binding,
            owner,
            RegistryEffectKind::ExecSegment,
            RegistryResources::one(RegistryResourceKey::new(102)),
            RegistryCreditClass::ExecSegment,
        )
        .unwrap();
    assert_eq!(
        registry.scope(scope).unwrap().free_budget,
        RegistryBudget::new(0, 0, 0, 0, 0, 0, 1)
    );

    let receipts = registry
        .commit_many(
            binding,
            &[(transaction, 1), (first_segment, 2), (second_segment, 3)],
        )
        .unwrap();
    registry.complete_many(&receipts).unwrap();
    assert_eq!(
        registry.scope(scope).unwrap().free_budget,
        RegistryBudget::new(1, 2, 0, 0, 0, 0, 1)
    );
    assert!(registry.scope(scope).unwrap().live_effects.is_empty());
    registry.check_invariants().unwrap();
}

#[test]
fn persistent_subscriptions_share_an_owner_without_occupying_blocked_task_slot() {
    let (mut registry, scope, binding) = model();
    let owner = TaskId::new(44);
    let first = registry
        .register(
            binding,
            owner,
            RegistryEffectKind::ReadinessSubscription,
            RegistryResources::one(RegistryResourceKey::new(100)),
            RegistryCreditClass::ReadinessSubscription,
        )
        .unwrap();
    let second = registry
        .register(
            binding,
            owner,
            RegistryEffectKind::ReadinessSubscription,
            RegistryResources::one(RegistryResourceKey::new(101)),
            RegistryCreditClass::ReadinessSubscription,
        )
        .unwrap();
    assert_ne!(first.effect(), second.effect());

    let wait = registry
        .register(
            binding,
            owner,
            RegistryEffectKind::ReadinessWait,
            RegistryResources::pair(RegistryResourceKey::new(200), RegistryResourceKey::new(100)),
            RegistryCreditClass::ReadinessWait,
        )
        .unwrap();
    let before_second_wait = registry.clone();
    assert_eq!(
        registry.register(
            binding,
            owner,
            RegistryEffectKind::ReadinessDelivery,
            RegistryResources::one(RegistryResourceKey::new(200)),
            RegistryCreditClass::ReadinessDelivery,
        ),
        Err(RegistryError::TaskAlreadyBlocked {
            effect: wait.effect()
        })
    );
    assert_eq!(registry, before_second_wait);

    registry.revoke_begin(scope).unwrap();
    while registry.revoke_next(scope).unwrap().is_some() {}
    registry.revoke_complete(scope).unwrap();
    registry.check_invariants().unwrap();
}

#[test]
fn completing_a_nonblocking_effect_preserves_its_owners_blocked_continuation() {
    let (mut registry, _scope, binding) = model();
    let owner = TaskId::new(44);
    let subscription = registry
        .register(
            binding,
            owner,
            RegistryEffectKind::ReadinessSubscription,
            RegistryResources::one(RegistryResourceKey::new(100)),
            RegistryCreditClass::ReadinessSubscription,
        )
        .unwrap();
    let wait = registry
        .register(
            binding,
            owner,
            RegistryEffectKind::ReadinessWait,
            RegistryResources::one(RegistryResourceKey::new(100)),
            RegistryCreditClass::ReadinessWait,
        )
        .unwrap();
    let receipt = registry.commit(binding, subscription, 1).unwrap();
    registry.complete(receipt).unwrap();

    let before = registry.clone();
    assert_eq!(
        registry.register(
            binding,
            owner,
            RegistryEffectKind::SyscallContinuation,
            RegistryResources::one(RegistryResourceKey::new(200)),
            RegistryCreditClass::Continuation,
        ),
        Err(RegistryError::TaskAlreadyBlocked {
            effect: wait.effect()
        })
    );
    assert_eq!(registry, before);
    registry.check_invariants().unwrap();
}

#[test]
fn aborting_a_nonblocking_effect_preserves_its_owners_blocked_continuation() {
    let (mut registry, scope, binding) = model();
    let owner = TaskId::new(44);
    let subscription = registry
        .register(
            binding,
            owner,
            RegistryEffectKind::ReadinessSubscription,
            RegistryResources::one(RegistryResourceKey::new(100)),
            RegistryCreditClass::ReadinessSubscription,
        )
        .unwrap();
    let wait = registry
        .register(
            binding,
            owner,
            RegistryEffectKind::ReadinessWait,
            RegistryResources::one(RegistryResourceKey::new(100)),
            RegistryCreditClass::ReadinessWait,
        )
        .unwrap();

    registry.revoke_begin(scope).unwrap();
    assert_eq!(
        registry.revoke_next(scope).unwrap(),
        Some(RegistryRevocationStep::Aborted {
            effect: subscription.effect()
        })
    );
    registry.check_invariants().unwrap();
    assert_eq!(
        registry.revoke_next(scope).unwrap(),
        Some(RegistryRevocationStep::Aborted {
            effect: wait.effect()
        })
    );
    registry.revoke_complete(scope).unwrap();
    registry.check_invariants().unwrap();
}
