use cser_model::composition::{
    ClosureStatus, CompositionEffectKind, CompositionModel, CreditBundle, DomainBindingToken,
    DomainCloseStep, DomainId, RevokeOutcome, ServiceId,
};
use proptest::prelude::*;

fn kind(domain: DomainId) -> CompositionEffectKind {
    match domain {
        DomainId::Scheduler => CompositionEffectKind::SchedulerAction,
        DomainId::Pager => CompositionEffectKind::PagerFault,
        DomainId::Personality => CompositionEffectKind::PersonalitySyscall,
        DomainId::Readiness => CompositionEffectKind::ReadinessWait,
        DomainId::VirtIo => CompositionEffectKind::VirtIoRequest,
    }
}

fn binding(bindings: &[DomainBindingToken; 5], domain: DomainId) -> DomainBindingToken {
    bindings[match domain {
        DomainId::Scheduler => 0,
        DomainId::Pager => 1,
        DomainId::Personality => 2,
        DomainId::Readiness => 3,
        DomainId::VirtIo => 4,
    }]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn bounded_cross_domain_batches_conserve_credits_and_terminalize_once(
        decisions in prop::collection::vec((0usize..5, any::<bool>(), any::<bool>()), 1..18),
    ) {
        let count = decisions.len() as u64;
        let initial = CreditBundle::new(0, 0, count + 1, 0, 0, 0);
        let mut model = CompositionModel::new();
        let scope = model.create_scope(initial).unwrap();
        let bindings = [
            model.register_domain(scope, DomainId::Scheduler, ServiceId::new(1)).unwrap(),
            model.register_domain(scope, DomainId::Pager, ServiceId::new(2)).unwrap(),
            model.register_domain(scope, DomainId::Personality, ServiceId::new(3)).unwrap(),
            model.register_domain(scope, DomainId::Readiness, ServiceId::new(4)).unwrap(),
            model.register_domain(scope, DomainId::VirtIo, ServiceId::new(5)).unwrap(),
        ];
        let root = model.register_root(
            bindings[2],
            CompositionEffectKind::PersonalitySyscall,
            initial,
        ).unwrap();
        let mut effects = Vec::with_capacity(decisions.len());
        for (domain_index, prepare, commit) in decisions {
            let domain = DomainId::ALL[domain_index];
            let token = model.derive_child(
                root,
                binding(&bindings, domain),
                kind(domain),
                CreditBundle::new(0, 0, 1, 0, 0, 0),
            ).unwrap();
            if prepare {
                model.prepare(binding(&bindings, domain), token).unwrap();
                // Keep VirtIO effects cancellable in this property. The
                // dedicated sequence test covers retained external effects.
                if commit && domain != DomainId::VirtIo {
                    model.commit(binding(&bindings, domain), token).unwrap();
                }
            }
            effects.push(token.effect());
        }
        model.check_invariants().unwrap();

        let ticket = model.revoke_begin(scope).unwrap();
        let frozen = model.scope(scope).unwrap().frozen_domains;
        for domain in [
            DomainId::Scheduler,
            DomainId::Pager,
            DomainId::Readiness,
            DomainId::VirtIo,
        ] {
            if !frozen.contains(&domain) {
                continue;
            }
            loop {
                match model.close_next(ticket, domain).unwrap() {
                    Some(DomainCloseStep::Aborted(_) | DomainCloseStep::Completed(_)) => {}
                    Some(DomainCloseStep::NeedsQuiescence(_)) => unreachable!(),
                    Some(DomainCloseStep::BlockedByDescendants { .. }) => unreachable!(),
                    None => break,
                }
            }
        }
        loop {
            match model.close_next(ticket, DomainId::Personality).unwrap() {
                Some(DomainCloseStep::Aborted(_) | DomainCloseStep::Completed(_)) => {}
                Some(DomainCloseStep::NeedsQuiescence(_)) => unreachable!(),
                Some(DomainCloseStep::BlockedByDescendants { .. }) => unreachable!(),
                None => break,
            }
        }

        for domain in frozen {
            let receipt = model.issue_domain_receipt(ticket, domain).unwrap();
            prop_assert_eq!(receipt.status(), &ClosureStatus::Closed);
            model.accept_domain_receipt(ticket, &receipt).unwrap();
            let progress = model.closure_progress(scope, domain).unwrap();
            prop_assert_eq!(progress.target_count, progress.terminalized);
            prop_assert_eq!(progress.remaining, 0);
            prop_assert!(progress.index_selections <= progress.terminalized);
        }
        prop_assert_eq!(model.revoke_complete(ticket).unwrap(), RevokeOutcome::Revoked);
        prop_assert_eq!(model.scope(scope).unwrap().free_credits, initial);
        for effect in effects.into_iter().chain(core::iter::once(root.effect())) {
            prop_assert_eq!(model.effect(effect).unwrap().terminalizations, 1);
        }
        model.check_invariants().unwrap();
    }
}
