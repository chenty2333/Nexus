use cser_model::{Budget, EffectState, Model, ModelError, ScopeState, SupervisorId, TraceAction};
use proptest::prelude::*;

proptest! {
    #[test]
    fn revocation_closes_every_live_effect_with_at_most_two_steps_each(
        initial_states in prop::collection::vec(0u8..3, 0..48)
    ) {
        let mut model = Model::new();
        let total = initial_states.len() as u64;
        let (scope, binding) = model
            .create_scope(SupervisorId::new(1), Budget::new(total))
            .unwrap();
        let mut effects = Vec::new();

        for state in &initial_states {
            let effect = model.register(binding, Budget::new(1)).unwrap();
            if *state >= 1 {
                model.prepare(binding, effect).unwrap();
            }
            if *state >= 2 {
                model.commit(binding, effect).unwrap();
            }
            effects.push((effect, *state));
        }

        model.revoke_begin(scope).unwrap();
        let mut steps = 0usize;
        while model.revoke_step(scope).unwrap().is_some() {
            steps += 1;
            prop_assert!(steps <= initial_states.len() * 2);
            model.check_invariants().unwrap();
        }
        model.revoke_complete(scope).unwrap();

        prop_assert_eq!(steps, initial_states.len() * 2);
        prop_assert_eq!(model.scope(scope).unwrap().state, ScopeState::Revoked);
        for (effect, initial) in effects {
            let effect = model.effect(effect).unwrap();
            let expected = if initial == 2 {
                EffectState::Completed
            } else {
                EffectState::Aborted
            };
            prop_assert_eq!(effect.state, expected);
            prop_assert_eq!(effect.terminalizations, 1);
        }
        model.check_invariants().unwrap();
    }

    #[test]
    fn old_binding_can_never_commit_after_crash_or_adoption(
        prepared in prop::collection::vec(any::<bool>(), 1..40)
    ) {
        let mut model = Model::new();
        let (scope, old_binding) = model
            .create_scope(SupervisorId::new(1), Budget::new(prepared.len() as u64))
            .unwrap();
        let mut effects = Vec::new();
        for should_prepare in &prepared {
            let effect = model.register(old_binding, Budget::new(1)).unwrap();
            if *should_prepare {
                model.prepare(old_binding, effect).unwrap();
            }
            effects.push(effect);
        }

        model.crash(old_binding).unwrap();
        for effect in &effects {
            let stale_was_rejected = matches!(
                model.commit(old_binding, *effect),
                Err(ModelError::StaleBinding { .. })
            );
            prop_assert!(stale_was_rejected);
        }
        model.fallback_pick(scope).unwrap();
        let replacement = model.rebind(scope, SupervisorId::new(2)).unwrap();

        for (effect, should_prepare) in effects.into_iter().zip(prepared.iter().copied()) {
            model.adopt(replacement, effect).unwrap();
            let stale_was_rejected = matches!(
                model.commit(old_binding, effect),
                Err(ModelError::StaleBinding { .. })
            );
            prop_assert!(stale_was_rejected);
            if should_prepare {
                model.commit(replacement, effect).unwrap();
                model.complete(effect).unwrap();
            }
            model.check_invariants().unwrap();
        }
        let successful_commits = model
            .trace()
            .iter()
            .filter(|event| event.action == TraceAction::Commit)
            .count();
        prop_assert_eq!(successful_commits, prepared.iter().filter(|value| **value).count());
    }

    #[test]
    fn complete_racing_with_revoke_never_double_terminalizes(
        complete_before_revoke in prop::collection::vec(any::<bool>(), 1..40)
    ) {
        let mut model = Model::new();
        let (scope, binding) = model
            .create_scope(
                SupervisorId::new(1),
                Budget::new(complete_before_revoke.len() as u64),
            )
            .unwrap();
        let mut effects = Vec::new();
        for complete_early in &complete_before_revoke {
            let effect = model.register(binding, Budget::new(1)).unwrap();
            model.prepare(binding, effect).unwrap();
            model.commit(binding, effect).unwrap();
            if *complete_early {
                model.complete(effect).unwrap();
            }
            effects.push(effect);
        }

        model.revoke_begin(scope).unwrap();
        while model.revoke_step(scope).unwrap().is_some() {}
        model.revoke_complete(scope).unwrap();

        for effect in effects {
            let effect = model.effect(effect).unwrap();
            prop_assert_eq!(effect.state, EffectState::Completed);
            prop_assert_eq!(effect.terminalizations, 1);
        }
        model.check_invariants().unwrap();
    }
}
