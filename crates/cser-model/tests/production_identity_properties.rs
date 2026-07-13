#[path = "production_identity_support/mod.rs"]
mod support;

use cser_model::production_identity::{
    DomainId, OperationClass, ParentIdentity, ProductionIdentityError, RegistryInstance, RootId,
    ServiceInstanceId,
};
use proptest::prelude::*;
use support::{prepared_model, registered_model};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn substituted_registry_root_generations_and_parent_reject_atomically(
        operation_index in 0usize..6,
        delta in 1u64..32,
    ) {
        let (mut model, identities) = registered_model();
        let operation = OperationClass::ALL[operation_index];
        let identity = identities.by_operation(operation);
        let binding = model.binding(identity.domain()).unwrap();

        let substitutions = [
            (
                identity.with_registry(RegistryInstance::new(identity.key().lineage().registry().get() + delta)),
                ProductionIdentityError::WrongRegistry,
            ),
            (
                identity.with_root(RootId::new(identity.key().lineage().root().get() + delta)),
                ProductionIdentityError::WrongRoot,
            ),
            (
                identity.with_root_generation(identity.key().lineage().generation() + delta),
                ProductionIdentityError::WrongRootGeneration,
            ),
            (
                identity.with_effect_generation(identity.key().effect_generation() + delta),
                ProductionIdentityError::WrongEffectGeneration,
            ),
            (
                identity.with_parent(if operation == OperationClass::FilesystemSyscall {
                    ParentIdentity::Effect(identities.filesystem.key())
                } else {
                    ParentIdentity::Root(model.root_identity().lineage())
                }),
                ProductionIdentityError::WrongParent,
            ),
        ];
        for (forged, expected) in substitutions {
            let before = model.projection();
            prop_assert_eq!(model.prepare_effect(binding, forged), Err(expected));
            prop_assert_eq!(model.projection(), before);
        }
        prop_assert_eq!(model.check_invariants(), Ok(()));
    }

    #[test]
    fn arbitrary_domain_recovery_preserves_every_immutable_effect_identity(
        domain_index in 0usize..3,
        replacement_raw in 100u64..1000,
    ) {
        let (mut model, identities) = prepared_model();
        let domain = DomainId::ALL[domain_index];
        let immutable = identities.all();
        let old_binding = model.binding(domain).unwrap();
        model.crash_domain(old_binding).unwrap();
        let snapshot = model.snapshot_domain(model.root_identity(), domain).unwrap();
        let ready = model.ready_domain(snapshot.clone()).unwrap();
        let replacement = model
            .rebind_domain(ready, ServiceInstanceId::new(replacement_raw))
            .unwrap();
        for identity in snapshot.cohort() {
            let adopted = model.adopt_effect(replacement, *identity).unwrap();
            prop_assert_eq!(adopted, *identity);
            prop_assert_eq!(adopted.origin_binding(), old_binding);
        }
        let projection = model.projection();
        prop_assert!(projection
            .effects
            .iter()
            .zip(immutable)
            .all(|(effect, original)| effect.identity == original));
        for peer in DomainId::ALL {
            let expected = 1 + u64::from(peer == domain);
            prop_assert_eq!(projection.bindings[peer as usize].binding_epoch, expected);
        }
        prop_assert_eq!(model.check_invariants(), Ok(()));
    }

    #[test]
    fn foreign_root_tokens_never_mutate_registration_or_revoke(
        delta in 1u64..64,
        choose_registry in any::<bool>(),
    ) {
        let (mut model, _) = registered_model();
        let root = model.root_identity();
        let forged = if choose_registry {
            root.with_registry(RegistryInstance::new(root.lineage().registry().get() + delta))
        } else {
            root.with_root(RootId::new(root.lineage().root().get() + delta))
        };
        let expected = if choose_registry {
            ProductionIdentityError::WrongRegistry
        } else {
            ProductionIdentityError::WrongRoot
        };
        let before = model.projection();
        prop_assert_eq!(model.revoke_begin(forged), Err(expected));
        prop_assert_eq!(model.projection(), before);
        prop_assert_eq!(model.check_invariants(), Ok(()));
    }
}
