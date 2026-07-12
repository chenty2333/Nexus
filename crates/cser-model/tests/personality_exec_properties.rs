use cser_model::personality::exec::{ExecLayout, ExecModel, ImageId};
use cser_model::personality::registry::RegistryBudget;
use cser_model::personality::{PersonalityId, TaskId};
use proptest::prelude::*;

proptest! {
    #[test]
    fn arbitrary_segment_batch_has_one_all_or_nothing_image_outcome(
        segment_count in 1usize..8,
        commit_before_revoke in any::<bool>(),
        publish_before_revoke in any::<bool>(),
    ) {
        let mut model = ExecModel::new();
        let old = ImageId::new(1);
        let new = ImageId::new(2);
        let (scope, binding) = model
            .create_scope(
                PersonalityId::new(1),
                RegistryBudget::new(1, segment_count as u64, 0, 0, 0, 0, 1),
                Some(old),
            )
            .unwrap();
        let token = model
            .stage(
                binding,
                TaskId::new(1),
                new,
                segment_count,
                ExecLayout {
                    tls_base: 0x7000_0000,
                    stack_pointer: 0x7fff_ffff_f000,
                },
            )
            .unwrap();
        prop_assert_eq!(model.scope(scope).unwrap().current_image, Some(old));
        let receipt = commit_before_revoke
            .then(|| model.commit(binding, token).unwrap());
        if publish_before_revoke
            && let Some(receipt) = &receipt
        {
            model.complete(receipt).unwrap();
        }
        model.revoke_begin(scope).unwrap();
        while model.revoke_next(scope).unwrap().is_some() {
            model.check_invariants().unwrap();
        }
        model.revoke_complete(scope).unwrap();
        let closed = model.scope(scope).unwrap();
        prop_assert_eq!(
            closed.current_image,
            Some(if commit_before_revoke { new } else { old })
        );
        prop_assert_eq!(closed.registry.free_budget, closed.registry.initial_budget);
        prop_assert!(closed.registry.live_effects.is_empty());
        model.check_invariants().unwrap();
    }
}
