use cser_model::personality::registry::{
    EffectRegistry, RegistryBudget, RegistryCreditClass, RegistryEffectKind, RegistryEffectState,
    RegistryResourceKey, RegistryResources,
};
use cser_model::personality::{PersonalityId, TaskId};
use proptest::prelude::*;

proptest! {
    #[test]
    fn arbitrary_commit_partition_reaches_single_terminal_quiescence(
        effect_count in 1usize..12,
        commit_mask in any::<u16>(),
        crash_before_close in any::<bool>(),
    ) {
        let mut registry = EffectRegistry::new();
        let (scope, binding) = registry
            .create_scope(
                PersonalityId::new(1),
                RegistryBudget::new(
                    effect_count as u64,
                    0,
                    effect_count as u64,
                    0,
                    0,
                    0,
                    1,
                ),
            )
            .unwrap();
        let mut tokens = Vec::new();
        for index in 0..effect_count {
            let (kind, credit) = if index % 2 == 0 {
                (
                    RegistryEffectKind::FutexWait,
                    RegistryCreditClass::FutexWait,
                )
            } else {
                (
                    RegistryEffectKind::FutexWake,
                    RegistryCreditClass::Continuation,
                )
            };
            let token = registry
                .register(
                    binding,
                    TaskId::new(index as u64 + 1),
                    kind,
                    RegistryResources::one(RegistryResourceKey::new(
                        (index % 3) as u64 + 1,
                    )),
                    credit,
                )
                .unwrap();
            if commit_mask & (1 << index) != 0 {
                registry.commit(binding, token, index as u64 + 100).unwrap();
            }
            tokens.push(token);
            registry.check_invariants().unwrap();
        }

        if crash_before_close {
            registry.crash(binding).unwrap();
            registry.fallback_pick(scope).unwrap();
            let snapshot = registry
                .recovery_snapshot(scope, PersonalityId::new(2))
                .unwrap();
            let ready = registry.ready(&snapshot).unwrap();
            let replacement = registry.rebind(ready).unwrap();
            for token in &mut tokens {
                *token = registry.adopt(replacement, *token).unwrap();
            }
        }

        registry.revoke_begin(scope).unwrap();
        while registry.revoke_next(scope).unwrap().is_some() {
            registry.check_invariants().unwrap();
        }
        registry.revoke_complete(scope).unwrap();
        for token in tokens {
            let effect = registry.effect(token.effect()).unwrap();
            prop_assert!(effect.state.is_terminal());
            prop_assert_eq!(effect.terminalizations, 1);
            let expected = if effect.receipt.is_some() {
                RegistryEffectState::Completed
            } else {
                RegistryEffectState::Aborted
            };
            prop_assert_eq!(effect.state, expected);
        }
        let closed = registry.scope(scope).unwrap();
        prop_assert!(closed.live_effects.is_empty());
        prop_assert_eq!(closed.free_budget.futex_wait(), effect_count as u64);
        prop_assert_eq!(closed.free_budget.continuation(), effect_count as u64);
        prop_assert_eq!(closed.free_budget.timer(), 1);
        registry.check_invariants().unwrap();
    }
}
