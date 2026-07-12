use cser_model::personality::readiness::{
    READY_READABLE, ReadinessModel, ReadinessOutcome, SubscriptionSpec, TriggerMode,
};
use cser_model::personality::registry::RegistryBudget;
use cser_model::personality::{PersonalityId, TaskId};
use proptest::prelude::*;

proptest! {
    #[test]
    fn arbitrary_mode_and_source_edges_end_in_single_terminal_quiescence(
        mode in 0u8..3,
        transitions in prop::collection::vec(any::<bool>(), 0..12),
        timeout_wins in any::<bool>(),
    ) {
        let mode = match mode {
            0 => TriggerMode::Level,
            1 => TriggerMode::Edge,
            _ => TriggerMode::OneShot,
        };
        let mut model = ReadinessModel::new();
        let (scope, binding, source, set) = model
            .create_scope(
                PersonalityId::new(1),
                RegistryBudget::new(0, 0, 0, 2, 1, 0, 2),
                1,
                0,
            )
            .unwrap();
        model
            .attach(
                binding,
                TaskId::new(1),
                set,
                source,
                SubscriptionSpec {
                    interest: READY_READABLE,
                    mode,
                    cookie: 7,
                },
            )
            .unwrap();
        for ready in transitions {
            model
                .source_update(
                    scope,
                    source,
                    1,
                    if ready { READY_READABLE } else { 0 },
                )
                .unwrap();
            model.check_invariants().unwrap();
        }
        let wait = model
            .wait_register(binding, TaskId::new(2), set, 10)
            .unwrap();
        let queued = !model.scope(scope).unwrap().queued.is_empty();
        let receipt = if timeout_wins || !queued {
            model.timeout_commit(binding, wait).unwrap()
        } else {
            model.ready_commit(binding, wait, 1).unwrap()
        };
        prop_assert_eq!(
            receipt.outcome(),
            if timeout_wins || !queued {
                ReadinessOutcome::TimedOut
            } else {
                ReadinessOutcome::Ready
            }
        );
        model.publish(&receipt).unwrap();
        model.revoke_begin(scope).unwrap();
        while model.revoke_next(scope).unwrap().is_some() {
            model.check_invariants().unwrap();
        }
        model.revoke_complete(scope).unwrap();
        let closed = model.scope(scope).unwrap();
        prop_assert!(closed.registry.live_effects.is_empty());
        prop_assert_eq!(closed.registry.free_budget, closed.registry.initial_budget);
        model.check_invariants().unwrap();
    }
}
