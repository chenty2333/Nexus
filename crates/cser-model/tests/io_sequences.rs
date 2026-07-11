use cser_model::ScopeState;
use cser_model::io::{
    CommitCharges, CommitDisposition, DeviceId, DmaIdentity, DmaLeaseId, DmaLeaseState,
    InvalidateTarget, InvalidationState, IoBudget, IoEffectState, IoError, IoFallbackState,
    IoModel, IoServiceId, Iova, LeaseCredits, MappingId, QueueId, RequestGrant, ResetState,
};

fn service(id: u64) -> IoServiceId {
    IoServiceId::new(id)
}

fn dma(id: u64) -> DmaIdentity {
    DmaIdentity::new(
        DmaLeaseId::new(id),
        MappingId::new(id),
        Iova::new(id * 0x1_0000),
    )
}

fn dma_at(id: u64, iova: u64) -> DmaIdentity {
    DmaIdentity::new(DmaLeaseId::new(id), MappingId::new(id), Iova::new(iova))
}

fn queue_credits() -> LeaseCredits {
    LeaseCredits::new(0, 2, 8192)
}

fn grant() -> RequestGrant {
    RequestGrant::new(LeaseCredits::new(1, 1, 4096), CommitCharges::new(1))
}

fn model_with_capacity(
    request_slots: u64,
    commit_charges: u64,
) -> (IoModel, cser_model::ScopeId, cser_model::io::IoBindingToken) {
    let mut model = IoModel::new();
    let total = LeaseCredits::new(
        request_slots,
        request_slots + queue_credits().pinned_pages,
        request_slots * 4096 + queue_credits().dma_bytes,
    );
    let (scope, binding) = model
        .create_scope(
            service(1),
            DeviceId::new(1),
            QueueId::new(1),
            IoBudget::new(total, CommitCharges::new(commit_charges)),
            dma(1),
            queue_credits(),
        )
        .unwrap();
    (model, scope, binding)
}

fn ack_request_invalidation(
    model: &mut IoModel,
    scope: cser_model::ScopeId,
    request: cser_model::io::RequestId,
) {
    let attempt = model
        .begin_invalidate(scope, InvalidateTarget::Request(request))
        .unwrap();
    model.invalidate_ack(attempt).unwrap();
}

fn reset_and_release_queue(model: &mut IoModel, scope: cser_model::ScopeId) {
    let reset = model.begin_reset(scope).unwrap();
    model.reset_ack(reset).unwrap();
    let queue = model
        .begin_invalidate(scope, InvalidateTarget::Queue)
        .unwrap();
    model.invalidate_ack(queue).unwrap();
}

#[test]
fn avail_publication_and_revoke_choose_one_linearization_order() {
    let (mut prepared, scope, binding) = model_with_capacity(1, 1);
    let token = prepared.register(binding, grant(), dma(2)).unwrap();
    assert_eq!(
        prepared.notify(binding, token),
        Err(IoError::NotifyBeforePublish)
    );
    prepared.prepare(binding, token).unwrap();

    let mut publish_first = prepared.clone();
    assert_eq!(publish_first.publish_avail(binding, token).unwrap(), 1);
    let published = publish_first.request(token.request()).unwrap();
    assert_eq!(published.state, IoEffectState::Committed);
    assert_eq!(published.avail_publications, 1);
    assert!(!published.notified);
    publish_first.revoke_begin(scope).unwrap();
    assert_eq!(publish_first.cancel_unpublished(scope).unwrap(), None);
    let reset = publish_first.begin_reset(scope).unwrap();
    assert_eq!(publish_first.reset_ack(reset).unwrap(), 1);
    let reset_request = publish_first.request(token.request()).unwrap();
    assert_eq!(reset_request.state, IoEffectState::IndeterminateAfterReset);
    assert_eq!(reset_request.commit_disposition, CommitDisposition::Spent);
    ack_request_invalidation(&mut publish_first, scope, token.request());
    let queue = publish_first
        .begin_invalidate(scope, InvalidateTarget::Queue)
        .unwrap();
    publish_first.invalidate_ack(queue).unwrap();
    let after_queue_ack = publish_first.clone();
    assert_eq!(
        publish_first.begin_invalidate(scope, InvalidateTarget::Queue),
        Err(IoError::InvalidInvalidationState {
            state: InvalidationState::Acknowledged,
        })
    );
    assert_eq!(publish_first, after_queue_ack);
    publish_first.revoke_complete(scope).unwrap();
    assert_eq!(
        publish_first.scope(scope).unwrap().state,
        ScopeState::Revoked
    );
    publish_first.check_invariants().unwrap();

    let mut revoke_first = prepared;
    revoke_first.revoke_begin(scope).unwrap();
    let before_stale_publish = revoke_first.clone();
    assert!(matches!(
        revoke_first.publish_avail(binding, token),
        Err(IoError::StaleAuthority { .. })
    ));
    assert_eq!(revoke_first, before_stale_publish);
    assert_eq!(
        revoke_first.cancel_unpublished(scope).unwrap(),
        Some(token.request())
    );
    let cancelling = revoke_first.request(token.request()).unwrap();
    assert_eq!(cancelling.state, IoEffectState::Cancelling);
    assert_eq!(cancelling.dma_state, DmaLeaseState::Mapped);
    assert_eq!(cancelling.terminalizations, 0);
    ack_request_invalidation(&mut revoke_first, scope, token.request());
    let cancelled = revoke_first.request(token.request()).unwrap();
    assert_eq!(cancelled.state, IoEffectState::Cancelled);
    assert_eq!(cancelled.dma_state, DmaLeaseState::Released);
    assert_eq!(cancelled.commit_disposition, CommitDisposition::Returned);
    reset_and_release_queue(&mut revoke_first, scope);
    revoke_first.revoke_complete(scope).unwrap();
    assert_eq!(
        revoke_first.scope(scope).unwrap().spent_commit_charges,
        CommitCharges::ZERO
    );
    revoke_first.check_invariants().unwrap();
}

#[test]
fn notification_is_only_a_post_commit_hint() {
    let (mut model, _scope, binding) = model_with_capacity(1, 1);
    let token = model.register(binding, grant(), dma(2)).unwrap();
    model.prepare(binding, token).unwrap();
    model.publish_avail(binding, token).unwrap();
    let completion = model.completion_for(token.request()).unwrap();

    let mut notified = model.clone();
    notified.notify(binding, token).unwrap();
    let after_first_hint = notified.clone();
    assert_eq!(
        notified.notify(binding, token),
        Err(IoError::AlreadyNotified)
    );
    assert_eq!(notified, after_first_hint);
    notified.check_invariants().unwrap();

    // A polling device may finish before the driver sends a notification.
    model.device_complete(completion).unwrap();
    let request = model.request(token.request()).unwrap();
    assert_eq!(request.state, IoEffectState::Completed);
    assert!(!request.notified);
    assert_eq!(request.avail_publications, 1);
    assert_eq!(model.notify(binding, token), Err(IoError::AlreadyTerminal));
    model.check_invariants().unwrap();
}

#[test]
fn completion_and_reset_ack_have_one_terminalization_order() {
    let (mut base, scope, binding) = model_with_capacity(1, 1);
    let token = base.register(binding, grant(), dma(2)).unwrap();
    base.prepare(binding, token).unwrap();
    base.publish_avail(binding, token).unwrap();
    let completion = base.completion_for(token.request()).unwrap();
    base.revoke_begin(scope).unwrap();
    let reset = base.begin_reset(scope).unwrap();

    let mut completion_first = base.clone();
    completion_first.device_complete(completion).unwrap();
    assert_eq!(
        completion_first.device_complete(completion),
        Err(IoError::AlreadyTerminal)
    );
    assert_eq!(completion_first.reset_ack(reset).unwrap(), 0);
    assert_eq!(
        completion_first
            .scope(scope)
            .unwrap()
            .revocation
            .unwrap()
            .reset_index_visits,
        1
    );
    assert_eq!(
        completion_first.request(token.request()).unwrap().state,
        IoEffectState::Completed
    );
    assert!(matches!(
        completion_first.device_complete(completion),
        Err(IoError::StaleDeviceGeneration { .. })
    ));
    assert_eq!(
        completion_first
            .request(token.request())
            .unwrap()
            .terminalizations,
        1
    );
    completion_first.check_invariants().unwrap();

    let mut reset_first = base;
    assert_eq!(reset_first.reset_ack(reset).unwrap(), 1);
    assert_eq!(
        reset_first
            .scope(scope)
            .unwrap()
            .revocation
            .unwrap()
            .reset_index_visits,
        1
    );
    assert_eq!(
        reset_first.request(token.request()).unwrap().state,
        IoEffectState::IndeterminateAfterReset
    );
    assert!(matches!(
        reset_first.device_complete(completion),
        Err(IoError::StaleDeviceGeneration { .. })
    ));
    assert_eq!(
        reset_first
            .request(token.request())
            .unwrap()
            .terminalizations,
        1
    );
    reset_first.check_invariants().unwrap();
}

#[test]
fn crash_rebind_requires_explicit_adopt_but_committed_work_is_kernel_owned() {
    let (mut model, scope, old_binding) = model_with_capacity(2, 2);
    let orphan = model.register(old_binding, grant(), dma(2)).unwrap();
    model.prepare(old_binding, orphan).unwrap();
    let committed = model.register(old_binding, grant(), dma(3)).unwrap();
    model.prepare(old_binding, committed).unwrap();
    model.publish_avail(old_binding, committed).unwrap();
    let completion = model.completion_for(committed.request()).unwrap();
    let before = model.scope(scope).unwrap();

    model.crash(old_binding).unwrap();
    let after = model.scope(scope).unwrap();
    assert_eq!(after.authority_epoch, before.authority_epoch);
    assert_eq!(after.device_generation, before.device_generation);
    assert_eq!(after.binding_epoch.get(), before.binding_epoch.get() + 1);
    assert_eq!(after.fallback, IoFallbackState::Required);
    assert!(matches!(
        model.publish_avail(old_binding, orphan),
        Err(IoError::StaleBinding { .. })
    ));

    // Post-commit notification and completion remain kernel/device-owned even
    // though the original service binding is now crash-fenced.
    model.notify(old_binding, committed).unwrap();
    assert_eq!(
        model.notify(old_binding, committed),
        Err(IoError::AlreadyNotified)
    );
    model.device_complete(completion).unwrap();
    assert_eq!(
        model.request(committed.request()).unwrap().state,
        IoEffectState::Completed
    );
    model.fallback_pick(scope).unwrap();
    let snapshot = model.recovery_snapshot(scope, service(2)).unwrap();
    assert_eq!(snapshot.requests().len(), 1);
    assert_eq!(snapshot.requests()[0].token, orphan);
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();
    assert_eq!(replacement.binding_epoch(), after.binding_epoch);
    assert!(matches!(
        model.publish_avail(replacement, orphan),
        Err(IoError::RequestBindingFenced { .. })
    ));
    let adopted = model.adopt(replacement, orphan).unwrap();
    model.publish_avail(replacement, adopted).unwrap();
    model.check_invariants().unwrap();
}

#[test]
fn reset_timeout_retains_only_queue_and_device_visible_requests_until_retry() {
    let (mut model, scope, binding) = model_with_capacity(2, 2);
    let visible = model.register(binding, grant(), dma(2)).unwrap();
    model.prepare(binding, visible).unwrap();
    model.publish_avail(binding, visible).unwrap();
    let unpublished = model.register(binding, grant(), dma(3)).unwrap();
    model.prepare(binding, unpublished).unwrap();
    model.revoke_begin(scope).unwrap();
    model.cancel_unpublished(scope).unwrap();
    assert_eq!(
        model.request(unpublished.request()).unwrap().state,
        IoEffectState::Cancelling
    );

    let reset = model.begin_reset(scope).unwrap();
    let tombstone = model.reset_timeout(reset).unwrap();
    assert_eq!(model.scope(scope).unwrap().state, ScopeState::Closing);
    assert_eq!(model.scope(scope).unwrap().reset, ResetState::TimedOut);
    assert!(tombstone.retained().queue_lease);
    assert_eq!(tombstone.retained().request_leases, 1);
    assert_eq!(
        model.begin_invalidate(scope, InvalidateTarget::Queue),
        Err(IoError::DeviceNotQuiescent)
    );
    assert_eq!(
        model.revoke_complete(scope),
        Err(IoError::RevocationNotQuiescent)
    );

    // Never-published work is independently safe to unmap during reset retry.
    ack_request_invalidation(&mut model, scope, unpublished.request());
    let retry = model.retry_reset(tombstone).unwrap();
    assert_eq!(model.reset_ack(retry).unwrap(), 1);
    assert_eq!(
        model.request(visible.request()).unwrap().state,
        IoEffectState::IndeterminateAfterReset
    );
    ack_request_invalidation(&mut model, scope, visible.request());
    let queue = model
        .begin_invalidate(scope, InvalidateTarget::Queue)
        .unwrap();
    model.invalidate_ack(queue).unwrap();
    model.revoke_complete(scope).unwrap();
    model.check_invariants().unwrap();
}

#[test]
fn invalidation_timeout_prevents_early_free_then_allows_iova_reuse_with_fresh_ids() {
    let (mut model, scope, binding) = model_with_capacity(2, 2);
    let first_dma = dma_at(2, 0x20_0000);
    let token = model.register(binding, grant(), first_dma).unwrap();
    model.prepare(binding, token).unwrap();
    model.publish_avail(binding, token).unwrap();
    let completion = model.completion_for(token.request()).unwrap();
    model.device_complete(completion).unwrap();
    assert_eq!(model.scope(scope).unwrap().live_obligations, 1);
    assert_eq!(
        model.scope(scope).unwrap().free_lease_credits.queue_slots,
        1
    );

    let attempt = model
        .begin_invalidate(scope, InvalidateTarget::Request(token.request()))
        .unwrap();
    let tombstone = model.invalidate_timeout(attempt).unwrap();
    assert_eq!(
        tombstone.target(),
        InvalidateTarget::Request(token.request())
    );
    assert_eq!(tombstone.retained().request_leases, 1);
    assert_eq!(
        model.request(token.request()).unwrap().dma_state,
        DmaLeaseState::UnmappedAwaitingInvalidation
    );
    assert_eq!(
        model.request(token.request()).unwrap().invalidation,
        InvalidationState::TimedOut
    );
    assert!(model.dma_identity_retained(first_dma));
    assert!(matches!(
        model.register(binding, grant(), dma_at(3, first_dma.iova().get())),
        Err(IoError::DmaIdentityInUse(_))
    ));

    let retry = model.retry_invalidate(tombstone).unwrap();
    model.invalidate_ack(retry).unwrap();
    assert_eq!(model.scope(scope).unwrap().live_obligations, 0);
    assert!(!model.dma_identity_retained(first_dma));
    assert_eq!(
        model.scope(scope).unwrap().free_lease_credits.queue_slots,
        2
    );

    // IOVA may be recycled only with fresh monotonic lease/mapping identities.
    let reused = model
        .register(binding, grant(), dma_at(3, first_dma.iova().get()))
        .unwrap();
    assert_eq!(reused.request().get(), 2);
    assert!(matches!(
        model.register(binding, grant(), dma_at(2, 0x30_0000)),
        Err(IoError::DmaIdentityInUse(_))
    ));
    assert!(matches!(
        model.register(
            binding,
            grant(),
            DmaIdentity::new(DmaLeaseId::new(4), MappingId::new(2), Iova::new(0x40_0000))
        ),
        Err(IoError::DmaIdentityInUse(_))
    ));
    model.check_invariants().unwrap();
}

#[test]
fn registered_cancel_is_immediate_but_prepared_cancel_waits_for_iotlb_ack() {
    let (mut model, scope, binding) = model_with_capacity(2, 2);
    let registered = model.register(binding, grant(), dma(2)).unwrap();
    let prepared = model.register(binding, grant(), dma(3)).unwrap();
    model.prepare(binding, prepared).unwrap();
    model.revoke_begin(scope).unwrap();

    let first = model.cancel_unpublished(scope).unwrap().unwrap();
    let second = model.cancel_unpublished(scope).unwrap().unwrap();
    assert_ne!(first, second);
    assert_eq!(model.cancel_unpublished(scope).unwrap(), None);
    let registered = model.request(registered.request()).unwrap();
    assert_eq!(registered.state, IoEffectState::Cancelled);
    assert_eq!(registered.dma_state, DmaLeaseState::Released);
    let prepared = model.request(prepared.request()).unwrap();
    assert_eq!(prepared.state, IoEffectState::Cancelling);
    assert_eq!(prepared.terminalizations, 0);
    assert_eq!(model.scope(scope).unwrap().live_obligations, 1);
    assert_eq!(
        model.revoke_complete(scope),
        Err(IoError::RevocationNotQuiescent)
    );
    model.check_invariants().unwrap();
}

#[test]
fn reset_ack_may_precede_unpublished_cancellation_without_touching_it() {
    let (mut model, scope, binding) = model_with_capacity(1, 1);
    let prepared = model.register(binding, grant(), dma(2)).unwrap();
    model.prepare(binding, prepared).unwrap();
    model.revoke_begin(scope).unwrap();

    // Stop the device and queue as early as possible. ResetAck is not a
    // blanket abort: the unpublished request remains Prepared.
    let reset = model.begin_reset(scope).unwrap();
    assert_eq!(model.reset_ack(reset).unwrap(), 0);
    assert_eq!(
        model.request(prepared.request()).unwrap().state,
        IoEffectState::Prepared
    );
    assert_eq!(model.scope(scope).unwrap().queue_slot_obligations, 1);
    let before_early_queue_teardown = model.clone();
    assert_eq!(
        model.begin_invalidate(scope, InvalidateTarget::Queue),
        Err(IoError::QueueSlotsOutstanding { remaining: 1 })
    );
    assert_eq!(model, before_early_queue_teardown);
    assert_eq!(
        model.cancel_unpublished(scope).unwrap(),
        Some(prepared.request())
    );
    assert_eq!(
        model.request(prepared.request()).unwrap().state,
        IoEffectState::Cancelling
    );
    ack_request_invalidation(&mut model, scope, prepared.request());
    let queue = model
        .begin_invalidate(scope, InvalidateTarget::Queue)
        .unwrap();
    model.invalidate_ack(queue).unwrap();
    model.revoke_complete(scope).unwrap();
    model.check_invariants().unwrap();
}

#[test]
fn revocation_target_excludes_large_cleaned_history_and_never_scans_other_scopes() {
    const HISTORY: u64 = 24;
    const TARGET: u64 = 4;
    const UNRELATED: u64 = 13;
    let (mut model, scope, binding) = model_with_capacity(TARGET, HISTORY + TARGET);

    // Build history whose effect outcomes and DMA cleanup are already final.
    for index in 0..HISTORY {
        let token = model
            .register(
                binding,
                grant(),
                dma_at(10 + index, 0x1000_0000 + index * 0x1_0000),
            )
            .unwrap();
        model.prepare(binding, token).unwrap();
        model.publish_avail(binding, token).unwrap();
        let completion = model.completion_for(token.request()).unwrap();
        model.device_complete(completion).unwrap();
        ack_request_invalidation(&mut model, scope, token.request());
    }
    assert_eq!(model.scope(scope).unwrap().live_obligations, 0);
    assert_eq!(
        model.scope(scope).unwrap().historical_requests,
        HISTORY as usize
    );

    let mut targets = Vec::new();
    for index in 0..TARGET {
        let token = model
            .register(
                binding,
                grant(),
                dma_at(100 + index, 0x2000_0000 + index * 0x1_0000),
            )
            .unwrap();
        model.prepare(binding, token).unwrap();
        targets.push(token.request());
    }

    let unrelated_total = LeaseCredits::new(
        UNRELATED,
        UNRELATED + queue_credits().pinned_pages,
        UNRELATED * 4096 + queue_credits().dma_bytes,
    );
    let (other_scope, other_binding) = model
        .create_scope(
            service(9),
            DeviceId::new(9),
            QueueId::new(9),
            IoBudget::new(unrelated_total, CommitCharges::new(UNRELATED)),
            dma_at(500, 0x5000_0000),
            queue_credits(),
        )
        .unwrap();
    for index in 0..UNRELATED {
        model
            .register(
                other_binding,
                grant(),
                dma_at(501 + index, 0x5100_0000 + index * 0x1_0000),
            )
            .unwrap();
    }

    model.revoke_begin(scope).unwrap();
    let closing = model.scope(scope).unwrap();
    assert_eq!(closing.historical_requests, (HISTORY + TARGET) as usize);
    assert_eq!(closing.unpublished_obligations, TARGET as usize);
    assert_eq!(closing.queue_slot_obligations, TARGET as usize);
    assert_eq!(closing.revocation.unwrap().target_count, TARGET as usize);
    for _ in 0..TARGET {
        model.cancel_unpublished(scope).unwrap().unwrap();
    }
    assert_eq!(model.cancel_unpublished(scope).unwrap(), None);
    for request in targets {
        ack_request_invalidation(&mut model, scope, request);
    }
    reset_and_release_queue(&mut model, scope);
    model.revoke_complete(scope).unwrap();

    let progress = model.scope(scope).unwrap().revocation.unwrap();
    assert_eq!(progress.target_count, TARGET as usize);
    assert_eq!(progress.cancel_steps, TARGET as usize);
    assert_eq!(progress.cancel_index_visits, TARGET as usize);
    assert_eq!(progress.reset_index_visits, 0);
    assert_eq!(progress.invalidated_request_leases, TARGET as usize);
    assert_eq!(
        model.scope(other_scope).unwrap().live_obligations,
        UNRELATED as usize
    );
    assert_eq!(
        model.global_request_count(),
        (HISTORY + TARGET + UNRELATED) as usize
    );
    model.check_invariants().unwrap();
}

#[test]
fn revoked_device_and_queue_identity_can_be_rebound_to_a_fresh_scope() {
    let (mut model, old_scope, _) = model_with_capacity(1, 1);
    model.revoke_begin(old_scope).unwrap();
    reset_and_release_queue(&mut model, old_scope);
    model.revoke_complete(old_scope).unwrap();

    let total = LeaseCredits::new(
        1,
        1 + queue_credits().pinned_pages,
        4096 + queue_credits().dma_bytes,
    );
    let (new_scope, _) = model
        .create_scope(
            service(2),
            DeviceId::new(1),
            QueueId::new(1),
            IoBudget::new(total, CommitCharges::new(1)),
            dma(99),
            queue_credits(),
        )
        .unwrap();

    assert_ne!(new_scope, old_scope);
    assert_eq!(model.scope(old_scope).unwrap().state, ScopeState::Revoked);
    assert_eq!(model.scope(new_scope).unwrap().state, ScopeState::Active);
    model.check_invariants().unwrap();

    let before_conflicts = model.clone();
    assert_eq!(
        model.create_scope(
            service(3),
            DeviceId::new(1),
            QueueId::new(2),
            IoBudget::new(total, CommitCharges::new(1)),
            dma(100),
            queue_credits(),
        ),
        Err(IoError::DeviceInUse(DeviceId::new(1)))
    );
    assert_eq!(model, before_conflicts);
    assert_eq!(
        model.create_scope(
            service(3),
            DeviceId::new(2),
            QueueId::new(1),
            IoBudget::new(total, CommitCharges::new(1)),
            dma(101),
            queue_credits(),
        ),
        Err(IoError::QueueInUse(QueueId::new(1)))
    );
    assert_eq!(model, before_conflicts);
}

#[test]
fn zero_or_partial_dma_budgets_are_rejected_without_reserving_identity() {
    let invalid_queue_leases = [
        LeaseCredits::ZERO,
        LeaseCredits::new(0, 0, 8192),
        LeaseCredits::new(0, 2, 0),
        LeaseCredits::new(1, 2, 8192),
    ];
    for (index, queue_lease) in invalid_queue_leases.into_iter().enumerate() {
        let mut model = IoModel::new();
        let before = model.clone();
        assert_eq!(
            model.create_scope(
                service(1),
                DeviceId::new(index as u64 + 20),
                QueueId::new(index as u64 + 20),
                IoBudget::new(LeaseCredits::new(2, 4, 16_384), CommitCharges::new(1)),
                dma(index as u64 + 20),
                queue_lease,
            ),
            Err(IoError::InvalidQueueLease)
        );
        assert_eq!(model, before);
    }

    let (mut model, _scope, binding) = model_with_capacity(1, 1);
    let invalid_grants = [
        RequestGrant::new(LeaseCredits::ZERO, CommitCharges::new(1)),
        RequestGrant::new(LeaseCredits::new(0, 1, 4096), CommitCharges::new(1)),
        RequestGrant::new(LeaseCredits::new(1, 0, 4096), CommitCharges::new(1)),
        RequestGrant::new(LeaseCredits::new(1, 1, 0), CommitCharges::new(1)),
        RequestGrant::new(LeaseCredits::new(2, 1, 4096), CommitCharges::new(1)),
        RequestGrant::new(LeaseCredits::new(1, 1, 4096), CommitCharges::ZERO),
    ];
    for invalid in invalid_grants {
        let before = model.clone();
        assert_eq!(
            model.register(binding, invalid, dma(2)),
            Err(IoError::InvalidGrant)
        );
        assert_eq!(model, before);
    }

    // Rejected grants consumed neither the request ID nor any DMA identity.
    let token = model.register(binding, grant(), dma(2)).unwrap();
    assert_eq!(token.request().get(), 1);
    let before_exhaustion = model.clone();
    assert!(matches!(
        model.register(binding, grant(), dma(3)),
        Err(IoError::LeaseBudgetExhausted { .. })
    ));
    assert_eq!(model, before_exhaustion);
    model.check_invariants().unwrap();
}

#[test]
fn reset_timeout_witness_fences_late_ack_and_is_returned_on_retry_error() {
    let (mut base, scope, binding) = model_with_capacity(1, 1);
    let token = base.register(binding, grant(), dma(2)).unwrap();
    base.prepare(binding, token).unwrap();
    base.publish_avail(binding, token).unwrap();
    base.revoke_begin(scope).unwrap();
    let reset = base.begin_reset(scope).unwrap();

    let mut timeout_branch = base.clone();
    let tombstone = timeout_branch.reset_timeout(reset).unwrap();
    let after_timeout = timeout_branch.clone();
    assert_eq!(
        timeout_branch.reset_ack(reset),
        Err(IoError::InvalidResetState {
            state: ResetState::TimedOut,
        })
    );
    assert_eq!(timeout_branch, after_timeout);
    let retry = timeout_branch.retry_reset(tombstone).unwrap();
    let before_stale_ack = timeout_branch.clone();
    assert_eq!(
        timeout_branch.reset_ack(reset),
        Err(IoError::StaleResetAttempt)
    );
    assert_eq!(timeout_branch, before_stale_ack);
    timeout_branch.reset_ack(retry).unwrap();
    timeout_branch.check_invariants().unwrap();

    let mut timeout_for_error = base.clone();
    let tombstone = timeout_for_error.reset_timeout(reset).unwrap();
    let mut acknowledged_branch = base;
    acknowledged_branch.reset_ack(reset).unwrap();
    let retry_error = acknowledged_branch.retry_reset(tombstone).unwrap_err();
    assert_eq!(
        retry_error.error(),
        IoError::InvalidResetState {
            state: ResetState::Acknowledged,
        }
    );
    let recovered = retry_error.into_tombstone();
    assert_eq!(recovered.scope(), scope);
    assert_eq!(recovered.failed_attempt(), reset.sequence());
    assert!(recovered.retained().queue_lease);
    acknowledged_branch.check_invariants().unwrap();
}

#[test]
fn invalidation_timeout_witness_fences_late_ack_and_is_returned_on_retry_error() {
    let (mut base, scope, binding) = model_with_capacity(1, 1);
    let token = base.register(binding, grant(), dma(2)).unwrap();
    base.prepare(binding, token).unwrap();
    base.publish_avail(binding, token).unwrap();
    base.revoke_begin(scope).unwrap();
    let reset = base.begin_reset(scope).unwrap();
    base.reset_ack(reset).unwrap();
    let invalidate = base
        .begin_invalidate(scope, InvalidateTarget::Request(token.request()))
        .unwrap();

    let mut timeout_branch = base.clone();
    let tombstone = timeout_branch.invalidate_timeout(invalidate).unwrap();
    let after_timeout = timeout_branch.clone();
    assert_eq!(
        timeout_branch.invalidate_ack(invalidate),
        Err(IoError::InvalidInvalidationState {
            state: InvalidationState::TimedOut,
        })
    );
    assert_eq!(timeout_branch, after_timeout);
    let retry = timeout_branch.retry_invalidate(tombstone).unwrap();
    let before_stale_ack = timeout_branch.clone();
    assert_eq!(
        timeout_branch.invalidate_ack(invalidate),
        Err(IoError::StaleInvalidateAttempt)
    );
    assert_eq!(timeout_branch, before_stale_ack);
    timeout_branch.invalidate_ack(retry).unwrap();
    timeout_branch.check_invariants().unwrap();

    let mut timeout_for_error = base.clone();
    let tombstone = timeout_for_error.invalidate_timeout(invalidate).unwrap();
    let mut acknowledged_branch = base;
    acknowledged_branch.invalidate_ack(invalidate).unwrap();
    let after_request_ack = acknowledged_branch.clone();
    assert_eq!(
        acknowledged_branch.begin_invalidate(scope, InvalidateTarget::Request(token.request()),),
        Err(IoError::InvalidInvalidationState {
            state: InvalidationState::Acknowledged,
        })
    );
    assert_eq!(acknowledged_branch, after_request_ack);
    let retry_error = acknowledged_branch.retry_invalidate(tombstone).unwrap_err();
    assert_eq!(
        retry_error.error(),
        IoError::InvalidInvalidationState {
            state: InvalidationState::Acknowledged,
        }
    );
    let recovered = retry_error.into_tombstone();
    assert_eq!(
        recovered.target(),
        InvalidateTarget::Request(token.request())
    );
    assert_eq!(recovered.failed_attempt(), invalidate.sequence());
    assert_eq!(recovered.retained().request_leases, 1);
    acknowledged_branch.check_invariants().unwrap();
}
