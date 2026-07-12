use cser_model::linux_io_composition::{
    CloseStep, CompositionError, DomainId, EffectKind, LinuxIoCompositionModel, ReceiptStatus,
};
use proptest::prelude::*;

fn prepare_commit(model: &mut LinuxIoCompositionModel, kind: EffectKind) {
    let token = model.token(kind);
    model.prepare(token).unwrap();
    model.commit(token).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn arbitrary_bounded_mixed_publications_conserve_all_eight_credit_classes(
        commit_fs in any::<bool>(),
        commit_block in any::<bool>(),
        commit_net in any::<bool>(),
        commit_ready in any::<bool>(),
    ) {
        let mut model = LinuxIoCompositionModel::new();
        if commit_fs {
            prepare_commit(&mut model, EffectKind::FsOp);
        }
        if commit_block {
            prepare_commit(&mut model, EffectKind::BlockReq);
        }
        let mut net_receipt = None;
        if commit_net {
            let net = model.token(EffectKind::NetOp);
            let buffer = model.token(EffectKind::BufferLease);
            model.prepare(net).unwrap();
            model.prepare(buffer).unwrap();
            net_receipt = Some(model.commit_network(net, buffer).unwrap().0);
        }
        if commit_ready && let Some(network) = net_receipt {
            let ready = model.token(EffectKind::ReadinessWait);
            model.prepare(ready).unwrap();
            model.commit_ready(ready, network).unwrap();
        }
        prop_assert_eq!(model.check_invariants(), Ok(()));

        let ticket = model.revoke_begin().unwrap();
        for domain in [DomainId::Scheduler, DomainId::Pager] {
            while let Some(step) = model.close_next(&ticket, domain).unwrap() {
                prop_assert!(matches!(step, CloseStep::Aborted(_) | CloseStep::Drained(_)));
            }
            let receipt = model.issue_domain_receipt(&ticket, domain).unwrap();
            model.accept_domain_receipt(&ticket, receipt).unwrap();
        }
        if commit_block {
            prop_assert_eq!(
                model.close_next(&ticket, DomainId::VirtIo),
                Ok(Some(CloseStep::NeedsQuiescence))
            );
            let tombstone = model.timeout_virtio(&ticket).unwrap();
            let timeout = model.issue_domain_receipt(&ticket, DomainId::VirtIo).unwrap();
            prop_assert_eq!(timeout.status(), ReceiptStatus::TimedOut);
            model.accept_domain_receipt(&ticket, timeout).unwrap();
            model.retry_virtio(&ticket, tombstone).unwrap();
        }
        for domain in [
            DomainId::VirtIo,
            DomainId::Filesystem,
            DomainId::Readiness,
            DomainId::Network,
            DomainId::Personality,
        ] {
            loop {
                match model.close_next(&ticket, domain).unwrap() {
                    Some(CloseStep::Aborted(_) | CloseStep::Drained(_)) => {}
                    Some(CloseStep::NeedsQuiescence | CloseStep::BlockedByDescendants) => {
                        prop_assert!(false, "unexpected closure blocker in {domain:?}");
                    }
                    None => break,
                }
            }
            let receipt = model.issue_domain_receipt(&ticket, domain).unwrap();
            model.accept_domain_receipt(&ticket, receipt).unwrap();
        }
        model.revoke_complete(&ticket).unwrap();
        prop_assert_eq!(model.projection().free_credits, [2, 1, 1, 1, 1, 1, 1, 1]);
        prop_assert_eq!(model.check_invariants(), Ok(()));
    }

    #[test]
    fn arbitrary_full_identity_forgery_rejects_without_semantic_mutation(
        kind_index in 0usize..9,
        authority_delta in 1u64..8,
        binding_delta in 1u64..8,
        generation_delta in 1u64..8,
    ) {
        let mut model = LinuxIoCompositionModel::new();
        let kind = EffectKind::ALL[kind_index];
        let token = model.token(kind);

        let before = model.clone();
        prop_assert_eq!(
            model.prepare(token.with_authority_epoch(token.authority_epoch() + authority_delta)),
            Err(CompositionError::StaleAuthority)
        );
        prop_assert_eq!(&model, &before);

        prop_assert_eq!(
            model.prepare(token.with_binding_epoch(token.binding_epoch() + binding_delta)),
            Err(CompositionError::StaleBinding)
        );
        prop_assert_eq!(&model, &before);

        prop_assert_eq!(
            model.prepare(token.with_generation(token.generation() + generation_delta)),
            Err(CompositionError::StaleGeneration)
        );
        prop_assert_eq!(&model, &before);
        prop_assert_eq!(model.check_invariants(), Ok(()));
    }
}
