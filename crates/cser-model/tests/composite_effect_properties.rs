use cser_model::composite_effect_oracle::{
    ClaimKind, ClaimState, ComponentId, CompositeAuthority, CompositeEffectOracle, CompositeError,
    CompositeResources, EscapeState, ReplyState, ResourceId, ReusePermit,
};
use cser_model::{EffectId, ExecutorCoordinate, ExecutorGeneration, ExecutorId, OperationId};
use proptest::prelude::*;

fn executor(id: u64, generation: u64) -> ExecutorCoordinate {
    ExecutorCoordinate::new(
        ExecutorId::new(id).unwrap(),
        ExecutorGeneration::new(generation).unwrap(),
    )
}

fn resources(seed: u64) -> CompositeResources {
    CompositeResources {
        reply_output: ResourceId::new(seed),
        queue_slot: ResourceId::new(seed + 1),
        pinned_page: ResourceId::new(seed + 2),
        iova_mapping: ResourceId::new(seed + 3),
    }
}

fn recovered(effect: EffectId, resource_generation: u64) -> CompositeEffectOracle {
    let mut model = CompositeEffectOracle::new(
        effect,
        executor(1, 1),
        resource_generation,
        1,
        resources(100),
    );
    let authority = model.observe_authority().unwrap();
    model.commit_dma(authority).unwrap();
    model.commit_reply(authority).unwrap();
    model.fence_executor(executor(1, 1)).unwrap();
    model.rebind(executor(1, 2)).unwrap();
    model
}

fn settle_reply(model: &mut CompositeEffectOracle) {
    let authority = model.observe_authority().unwrap();
    let claim = model.claim_reply(authority).unwrap();
    model.record_reply_apply_intent(claim).unwrap();
    model.record_reply_applied(claim).unwrap();
    model.accept_reply_ack(claim).unwrap();
    model.retire_reply_output().unwrap();
}

fn retire_dma_through(model: &mut CompositeEffectOracle, boundary: u8) {
    if boundary == 0 {
        return;
    }
    model.advance_device_generation(2).unwrap();
    let evidence = model.dma_retirement_evidence();
    model.accept_reset(evidence).unwrap();
    if boundary == 1 {
        return;
    }
    model.accept_irq_drain(evidence).unwrap();
    if boundary == 2 {
        return;
    }
    model.accept_iotlb_invalidation(evidence).unwrap();
    if boundary == 3 {
        return;
    }
    model.accept_allocator_release(evidence).unwrap();
}

fn issue_reuse(
    model: &mut CompositeEffectOracle,
    kind: ClaimKind,
    next_generation: u64,
) -> Result<ReusePermit, CompositeError> {
    let authority = model.observe_authority()?;
    model.issue_reuse_permit(authority, kind, next_generation)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn rebind_requires_the_origin_executor_and_a_strictly_newer_generation(
        origin_id in 1_u64..10_000,
        initial_generation in 1_u64..10_000,
        generation_delta in 1_u64..10_000,
    ) {
        let successor_generation = initial_generation + generation_delta;
        let origin = executor(origin_id, initial_generation);
        let wrong_id = if origin_id == 1 { 2 } else { 1 };
        let mut model = CompositeEffectOracle::new(
            EffectId::new(OperationId::new(0xce03).unwrap(), 1).unwrap(),
            origin,
            1,
            1,
            resources(300),
        );
        model.fence_executor(origin).unwrap();

        let before = model.projection();
        prop_assert_eq!(
            model.rebind(executor(wrong_id, successor_generation)),
            Err(CompositeError::StaleAuthority)
        );
        prop_assert_eq!(model.projection(), before);
        prop_assert_eq!(
            model.rebind(executor(origin_id, initial_generation)),
            Err(CompositeError::StaleAuthority)
        );
        prop_assert_eq!(model.projection(), before);

        prop_assert_eq!(
            model.rebind(executor(origin_id, successor_generation)),
            Ok(())
        );
        prop_assert_eq!(
            model.projection().live_executor,
            Some(executor(origin_id, successor_generation))
        );
        prop_assert!(model.check_invariants());
    }

    #[test]
    fn arbitrary_retirement_and_reuse_orders_are_failure_atomic_and_resource_local(
        actions in prop::collection::vec(0_u8..=7, 1..40),
    ) {
        let mut model = recovered(EffectId::new(OperationId::new(0xce01).unwrap(), 1).unwrap(), 1);
        model.advance_device_generation(2).unwrap();
        let evidence = model.dma_retirement_evidence();

        for action in actions {
            let before = model.projection();
            let result = match action {
                0 => model.accept_reset(evidence),
                1 => model.accept_irq_drain(evidence),
                2 => model.accept_iotlb_invalidation(evidence),
                3 => model.accept_allocator_release(evidence),
                4 => issue_reuse(&mut model, ClaimKind::QueueSlot, 2).map(|_| ()),
                5 => issue_reuse(&mut model, ClaimKind::IovaMapping, 2).map(|_| ()),
                6 => issue_reuse(&mut model, ClaimKind::PinnedPage, 2).map(|_| ()),
                7 => issue_reuse(&mut model, ClaimKind::QueueSlot, 3).map(|_| ()),
                _ => unreachable!(),
            };
            if result.is_err() {
                prop_assert_eq!(model.projection(), before);
            }
            prop_assert_eq!(model.claim(ClaimKind::ReplyOutput).state, ClaimState::Live);
            prop_assert!(model.check_invariants());
        }

        let projection = model.projection();
        if !projection.reset_accepted {
            model.accept_reset(evidence).unwrap();
        }
        if !model.projection().irq_drained {
            model.accept_irq_drain(evidence).unwrap();
        }
        if model.claim(ClaimKind::QueueSlot).state == ClaimState::Discharged {
            issue_reuse(&mut model, ClaimKind::QueueSlot, 2).unwrap();
        }
        if !model.projection().iotlb_invalidated {
            model.accept_iotlb_invalidation(evidence).unwrap();
        }
        if model.claim(ClaimKind::IovaMapping).state == ClaimState::Discharged {
            issue_reuse(&mut model, ClaimKind::IovaMapping, 2).unwrap();
        }
        if !model.projection().allocator_released {
            model.accept_allocator_release(evidence).unwrap();
        }
        if model.claim(ClaimKind::PinnedPage).state == ClaimState::Discharged {
            issue_reuse(&mut model, ClaimKind::PinnedPage, 2).unwrap();
        }

        for kind in [
            ClaimKind::QueueSlot,
            ClaimKind::PinnedPage,
            ClaimKind::IovaMapping,
        ] {
            prop_assert_eq!(
                model.claim(kind).state,
                ClaimState::ReusePermitted { next_generation: 2 }
            );
        }
        prop_assert_eq!(model.claim(ClaimKind::ReplyOutput).state, ClaimState::Live);
        prop_assert_eq!(model.projection().escape, EscapeState::PartiallyDischarged);
        prop_assert!(model.check_invariants());
    }

    #[test]
    fn every_retirement_coordinate_is_exact_and_rejection_preserves_projection(
        field in 0_u8..4,
        wrong in 3_u64..10_000,
    ) {
        let mut model = recovered(EffectId::new(OperationId::new(0xce01).unwrap(), 1).unwrap(), 1);
        model.advance_device_generation(2).unwrap();
        let exact = model.dma_retirement_evidence();
        let stale = match field {
            0 => exact.with_operation(OperationId::new(wrong).unwrap()),
            1 => exact.with_resource_generation(wrong),
            2 => exact.with_subject_device_generation(wrong),
            3 => exact.with_observation_device_generation(wrong),
            _ => unreachable!(),
        };
        let before = model.projection();

        prop_assert_eq!(
            model.accept_reset(stale),
            Err(CompositeError::StaleDeviceEvidence)
        );
        prop_assert_eq!(model.projection(), before);
        prop_assert!(model.check_invariants());
    }

    #[test]
    fn exact_successor_generation_is_the_only_reuse_generation(
        resource_generation in 1_u64..(u64::MAX - 1),
    ) {
        let mut model = recovered(EffectId::new(OperationId::new(0xce01).unwrap(), 1).unwrap(), resource_generation);
        model.advance_device_generation(2).unwrap();
        let evidence = model.dma_retirement_evidence();
        model.accept_reset(evidence).unwrap();
        model.accept_irq_drain(evidence).unwrap();
        model.accept_iotlb_invalidation(evidence).unwrap();
        model.accept_allocator_release(evidence).unwrap();
        let successor = resource_generation + 1;

        for kind in [
            ClaimKind::QueueSlot,
            ClaimKind::PinnedPage,
            ClaimKind::IovaMapping,
        ] {
            let before = model.projection();
            prop_assert!(!model.reuse_is_admissible(kind, resource_generation));
            prop_assert_eq!(
                issue_reuse(&mut model, kind, resource_generation),
                Err(CompositeError::ReuseGenerationMismatch)
            );
            prop_assert_eq!(model.projection(), before);
            prop_assert!(model.reuse_is_admissible(kind, successor));
            let permit = issue_reuse(&mut model, kind, successor).unwrap();
            prop_assert_eq!(permit.operation(), OperationId::new(0xce01).unwrap());
            prop_assert_eq!(permit.kind(), kind);
            prop_assert_eq!(permit.retired_generation(), resource_generation);
            prop_assert_eq!(permit.next_generation(), successor);
        }

        prop_assert_eq!(model.claim(ClaimKind::ReplyOutput).state, ClaimState::Live);
        prop_assert_eq!(model.projection().escape, EscapeState::PartiallyDischarged);
        prop_assert!(model.check_invariants());
    }

    #[test]
    fn authority_bound_reuse_bearer_substitution_is_failure_atomic(
        field in 0_u8..4,
        wrong in 10_u64..10_000,
    ) {
        let mut model = recovered(EffectId::new(OperationId::new(0xce01).unwrap(), 1).unwrap(), 1);
        model.advance_device_generation(2).unwrap();
        let evidence = model.dma_retirement_evidence();
        model.accept_reset(evidence).unwrap();
        model.accept_irq_drain(evidence).unwrap();
        let permit = issue_reuse(&mut model, ClaimKind::QueueSlot, 2).unwrap();
        let forged = match field {
            0 => permit.with_actor(executor(wrong, wrong)),
            1 => permit.with_authority_epoch(wrong),
            2 => permit.with_next_generation(wrong),
            3 => permit.with_nonce(wrong),
            _ => unreachable!(),
        };
        let before = model.projection();

        prop_assert_eq!(
            model.activate_reuse(forged),
            Err(CompositeError::StaleReusePermit)
        );
        prop_assert_eq!(model.projection(), before);
        prop_assert_eq!(
            model.claim(ClaimKind::QueueSlot).pending_reuse.unwrap().actor,
            permit.actor()
        );
        prop_assert!(model.check_invariants());
    }

    #[test]
    fn parent_release_is_iff_all_components_terminal_and_claims_discharged(
        reply_settled in any::<bool>(),
        dma_boundary in 0_u8..5,
    ) {
        let mut model = recovered(EffectId::new(OperationId::new(0xce01).unwrap(), 1).unwrap(), 1);
        let physical_before = [
            model.claim(ClaimKind::QueueSlot),
            model.claim(ClaimKind::PinnedPage),
            model.claim(ClaimKind::IovaMapping),
        ];
        if reply_settled {
            settle_reply(&mut model);
            prop_assert_eq!(model.projection().reply, ReplyState::Settled);
            prop_assert_eq!(
                [
                    model.claim(ClaimKind::QueueSlot),
                    model.claim(ClaimKind::PinnedPage),
                    model.claim(ClaimKind::IovaMapping),
                ],
                physical_before
            );
        }
        retire_dma_through(&mut model, dma_boundary);

        let components_terminal = model.component(ComponentId::Reply).terminal
            && model.component(ComponentId::Dma).terminal;
        let claims_discharged = ClaimKind::ALL.iter().all(|kind| {
            matches!(
                model.claim(*kind).state,
                ClaimState::Discharged
                    | ClaimState::ReusePermitted { .. }
                    | ClaimState::Reused { .. }
            )
        });
        let releasable = components_terminal && claims_discharged;
        prop_assert_eq!(releasable, reply_settled && dma_boundary == 4);
        let before_release = model.projection();

        if releasable {
            prop_assert_eq!(model.release_effect(), Ok(()));
            prop_assert_eq!(model.projection().escape, EscapeState::Released);
            let released = model.projection();
            prop_assert_eq!(model.release_effect(), Err(CompositeError::GateClosed));
            prop_assert_eq!(model.projection(), released);
        } else {
            prop_assert_eq!(
                model.release_effect(),
                Err(CompositeError::EffectNotRetired)
            );
            prop_assert_eq!(model.projection(), before_release);
        }
        prop_assert!(model.check_invariants());
    }

    #[test]
    fn quarantined_composite_does_not_block_unrelated_effect_progress(
        reply_first in any::<bool>(),
        settle_unrelated_reply in any::<bool>(),
    ) {
        let mut quarantined = recovered(EffectId::new(OperationId::new(0xce01).unwrap(), 1).unwrap(), 1);
        quarantined.fence_executor(executor(1, 2)).unwrap();
        let quarantined_projection = quarantined.projection();

        let mut unrelated = CompositeEffectOracle::new(
            EffectId::new(OperationId::new(0xce02).unwrap(), 1).unwrap(),
            executor(11, 13),
            1,
            1,
            resources(1_000),
        );
        let authority = unrelated.observe_authority().unwrap();
        if reply_first {
            unrelated.commit_reply(authority).unwrap();
            unrelated.commit_dma(authority).unwrap();
        } else {
            unrelated.commit_dma(authority).unwrap();
            unrelated.commit_reply(authority).unwrap();
        }
        if settle_unrelated_reply {
            settle_reply(&mut unrelated);
        }

        prop_assert_eq!(quarantined.projection(), quarantined_projection);
        prop_assert_eq!(
            quarantined.projection().authority,
            CompositeAuthority::Fenced
        );
        prop_assert_eq!(unrelated.projection().effect, EffectId::new(OperationId::new(0xce02).unwrap(), 1).unwrap());
        prop_assert!(unrelated.component(ComponentId::Reply).committed);
        prop_assert!(unrelated.component(ComponentId::Dma).committed);
        prop_assert_eq!(
            unrelated.projection().reply == ReplyState::Settled,
            settle_unrelated_reply
        );
        prop_assert!(quarantined.check_invariants());
        prop_assert!(unrelated.check_invariants());
    }
}
