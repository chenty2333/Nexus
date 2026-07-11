use cser_model::ScopeState;
use cser_model::io::{
    CommitCharges, CommitDisposition, DeviceId, DmaIdentity, DmaLeaseId, DmaLeaseState,
    InvalidateTarget, IoBudget, IoEffectState, IoError, IoModel, IoServiceId, Iova, LeaseCredits,
    MappingId, QueueId, RequestGrant,
};
use proptest::prelude::*;

fn dma(id: u64) -> DmaIdentity {
    DmaIdentity::new(
        DmaLeaseId::new(id),
        MappingId::new(id),
        Iova::new(0x1_0000 * id),
    )
}

fn grant() -> RequestGrant {
    RequestGrant::new(LeaseCredits::new(1, 1, 4096), CommitCharges::new(1))
}

fn create(capacity: u64) -> (IoModel, cser_model::ScopeId, cser_model::io::IoBindingToken) {
    let mut model = IoModel::new();
    let queue = LeaseCredits::new(0, 2, 8192);
    let total = LeaseCredits::new(
        capacity,
        capacity + queue.pinned_pages,
        capacity * 4096 + queue.dma_bytes,
    );
    let (scope, binding) = model
        .create_scope(
            IoServiceId::new(1),
            DeviceId::new(1),
            QueueId::new(1),
            IoBudget::new(total, CommitCharges::new(capacity)),
            dma(1),
            queue,
        )
        .unwrap();
    (model, scope, binding)
}

fn clean_request(
    model: &mut IoModel,
    scope: cser_model::ScopeId,
    request: cser_model::io::RequestId,
) {
    if model.request(request).unwrap().dma_state == DmaLeaseState::Released {
        return;
    }
    let attempt = model
        .begin_invalidate(scope, InvalidateTarget::Request(request))
        .unwrap();
    model.invalidate_ack(attempt).unwrap();
}

fn close_queue(model: &mut IoModel, scope: cser_model::ScopeId) {
    let attempt = model
        .begin_invalidate(scope, InvalidateTarget::Queue)
        .unwrap();
    model.invalidate_ack(attempt).unwrap();
    model.revoke_complete(scope).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn bounded_mixed_request_batches_preserve_terminalization_dma_and_typed_budgets(
        decisions in prop::collection::vec((any::<bool>(), any::<bool>(), any::<bool>()), 1..12),
        reset_first in any::<bool>(),
    ) {
        let count = decisions.len() as u64;
        let (mut model, scope, binding) = create(count);
        let mut requests = Vec::new();
        let mut completions = Vec::new();
        let mut published = 0u64;

        for (index, (prepare, publish, complete_before_reset)) in decisions.iter().copied().enumerate() {
            let token = model.register(binding, grant(), dma(index as u64 + 2)).unwrap();
            if prepare {
                model.prepare(binding, token).unwrap();
            }
            if prepare && publish {
                model.publish_avail(binding, token).unwrap();
                completions.push((
                    model.completion_for(token.request()).unwrap(),
                    complete_before_reset,
                ));
                published += 1;
            }
            requests.push(token.request());
            model.check_invariants().unwrap();
        }

        model.revoke_begin(scope).unwrap();
        let reset = model.begin_reset(scope).unwrap();
        for (completion, complete) in completions.iter().copied() {
            if complete {
                model.device_complete(completion).unwrap();
            }
        }
        if reset_first {
            model.reset_ack(reset).unwrap();
        }

        while model.cancel_unpublished(scope).unwrap().is_some() {
            model.check_invariants().unwrap();
        }
        if !reset_first {
            // Requests proven invisible or complete may release their own DMA
            // while reset is still in flight.
            for request in requests.iter().copied() {
                if matches!(
                    model.request(request).unwrap().state,
                    IoEffectState::Cancelling | IoEffectState::Completed
                ) {
                    clean_request(&mut model, scope, request);
                }
            }
            model.reset_ack(reset).unwrap();
        }

        for request in requests.iter().copied() {
            clean_request(&mut model, scope, request);
            let view = model.request(request).unwrap();
            prop_assert!(view.state.is_terminal());
            prop_assert_eq!(view.terminalizations, 1);
            prop_assert_eq!(view.dma_state, DmaLeaseState::Released);
            prop_assert_eq!(
                view.commit_disposition,
                if view.avail_publications == 1 {
                    CommitDisposition::Spent
                } else {
                    CommitDisposition::Returned
                }
            );
        }
        close_queue(&mut model, scope);
        let closed = model.scope(scope).unwrap();
        prop_assert_eq!(closed.state, ScopeState::Revoked);
        prop_assert_eq!(closed.live_obligations, 0);
        prop_assert_eq!(closed.unpublished_obligations, 0);
        prop_assert_eq!(closed.nonterminal_requests, 0);
        prop_assert_eq!(closed.queue_slot_obligations, 0);
        prop_assert_eq!(closed.free_lease_credits, closed.initial_budget.leases);
        prop_assert_eq!(closed.held_commit_charges, CommitCharges::ZERO);
        prop_assert_eq!(closed.spent_commit_charges, CommitCharges::new(published));
        prop_assert_eq!(
            closed.free_commit_charges.get() + closed.spent_commit_charges.get(),
            count
        );
        model.check_invariants().unwrap();
    }

    #[test]
    fn publish_and_revoke_have_only_precommit_cancel_or_postcommit_indeterminate(
        publish_first in any::<bool>(),
    ) {
        let (mut model, scope, binding) = create(1);
        let token = model.register(binding, grant(), dma(2)).unwrap();
        model.prepare(binding, token).unwrap();

        if publish_first {
            model.publish_avail(binding, token).unwrap();
            model.revoke_begin(scope).unwrap();
            prop_assert_eq!(model.cancel_unpublished(scope).unwrap(), None);
        } else {
            model.revoke_begin(scope).unwrap();
            let snapshot = model.clone();
            let fenced = matches!(
                model.publish_avail(binding, token),
                Err(IoError::StaleAuthority { .. })
            );
            prop_assert!(fenced);
            prop_assert_eq!(&model, &snapshot);
            model.cancel_unpublished(scope).unwrap();
        }
        let reset = model.begin_reset(scope).unwrap();
        model.reset_ack(reset).unwrap();
        clean_request(&mut model, scope, token.request());
        close_queue(&mut model, scope);
        let request = model.request(token.request()).unwrap();
        prop_assert_eq!(request.avail_publications, u8::from(publish_first));
        prop_assert_eq!(
            request.state,
            if publish_first {
                IoEffectState::IndeterminateAfterReset
            } else {
                IoEffectState::Cancelled
            }
        );
        prop_assert_eq!(request.terminalizations, 1);
        model.check_invariants().unwrap();
    }

    #[test]
    fn completion_and_reset_ack_never_both_terminalize(
        completion_first in any::<bool>(),
    ) {
        let (mut model, scope, binding) = create(1);
        let token = model.register(binding, grant(), dma(2)).unwrap();
        model.prepare(binding, token).unwrap();
        model.publish_avail(binding, token).unwrap();
        let completion = model.completion_for(token.request()).unwrap();
        model.revoke_begin(scope).unwrap();
        let reset = model.begin_reset(scope).unwrap();

        if completion_first {
            model.device_complete(completion).unwrap();
            prop_assert_eq!(model.reset_ack(reset).unwrap(), 0);
        } else {
            prop_assert_eq!(model.reset_ack(reset).unwrap(), 1);
            let stale = matches!(
                model.device_complete(completion),
                Err(IoError::StaleDeviceGeneration { .. })
            );
            prop_assert!(stale);
        }
        let request = model.request(token.request()).unwrap();
        prop_assert_eq!(request.terminalizations, 1);
        prop_assert_eq!(
            request.state,
            if completion_first {
                IoEffectState::Completed
            } else {
                IoEffectState::IndeterminateAfterReset
            }
        );
        model.check_invariants().unwrap();
    }

    #[test]
    fn any_bounded_timeout_retry_count_retains_until_matching_ack(
        reset_timeouts in 0usize..4,
        request_timeouts in 0usize..4,
        queue_timeouts in 0usize..4,
    ) {
        let (mut model, scope, binding) = create(1);
        let token = model.register(binding, grant(), dma(2)).unwrap();
        model.prepare(binding, token).unwrap();
        model.publish_avail(binding, token).unwrap();
        model.revoke_begin(scope).unwrap();

        let mut reset = model.begin_reset(scope).unwrap();
        for _ in 0..reset_timeouts {
            let retained = model.reset_timeout(reset).unwrap();
            prop_assert!(retained.retained().queue_lease);
            prop_assert_eq!(retained.retained().request_leases, 1);
            prop_assert_eq!(model.scope(scope).unwrap().state, ScopeState::Closing);
            reset = model.retry_reset(retained).unwrap();
        }
        model.reset_ack(reset).unwrap();

        let mut request = model
            .begin_invalidate(scope, InvalidateTarget::Request(token.request()))
            .unwrap();
        for _ in 0..request_timeouts {
            let retained = model.invalidate_timeout(request).unwrap();
            prop_assert_eq!(retained.retained().request_leases, 1);
            prop_assert_eq!(model.scope(scope).unwrap().free_lease_credits.queue_slots, 0);
            request = model.retry_invalidate(retained).unwrap();
        }
        model.invalidate_ack(request).unwrap();

        let mut queue = model
            .begin_invalidate(scope, InvalidateTarget::Queue)
            .unwrap();
        for _ in 0..queue_timeouts {
            let retained = model.invalidate_timeout(queue).unwrap();
            prop_assert!(retained.retained().queue_lease);
            queue = model.retry_invalidate(retained).unwrap();
        }
        model.invalidate_ack(queue).unwrap();
        model.revoke_complete(scope).unwrap();
        prop_assert_eq!(model.scope(scope).unwrap().state, ScopeState::Revoked);
        model.check_invariants().unwrap();
    }
}
