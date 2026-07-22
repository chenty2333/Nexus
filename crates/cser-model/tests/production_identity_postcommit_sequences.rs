use cser_model::production_identity_postcommit::{
    BackendOutcome, BackendPhase, CREDIT_CLASS_COUNT, CausalIdentityPhase, ClosureTrigger,
    CommitReceipt, CreditClass, EFFECT_COUNT, EffectPhase, ObligationOwner, PostcommitError,
    ProductionIdentityPostcommitModel, PublicationTicket, RootId, RootPhase, ServiceAuthority,
    ServiceId,
};

fn pending_publication_credits() -> [u64; CREDIT_CLASS_COUNT] {
    let mut credits = [0; CREDIT_CLASS_COUNT];
    credits[CreditClass::Control as usize] = 1;
    credits[CreditClass::GuestReply as usize] = 1;
    credits
}

fn returned_before_ack() -> [u64; CREDIT_CLASS_COUNT] {
    let pending = pending_publication_credits();
    core::array::from_fn(|index| CreditClass::ALL[index].capacity() - pending[index])
}

fn post_backend_crashed() -> (
    ProductionIdentityPostcommitModel,
    ServiceAuthority,
    CommitReceipt,
    PublicationTicket,
) {
    let mut model = ProductionIdentityPostcommitModel::new(RootId::new(91), ServiceId::new(951));
    let old_service = model.service_authority().unwrap();
    let commit = model.commit(old_service).unwrap();
    let ticket = model.terminalize_backend(commit).unwrap();
    model.observe_service_crash(old_service).unwrap();
    (model, old_service, commit, ticket)
}

fn closure_trigger(model: &mut ProductionIdentityPostcommitModel) -> ClosureTrigger {
    model.issue_closure_trigger(ServiceId::new(953)).unwrap()
}

#[test]
fn compound_commit_precedes_backend_terminalization_and_keeps_root_active() {
    let mut model = ProductionIdentityPostcommitModel::new(RootId::new(91), ServiceId::new(951));
    let old_service = model.service_authority().unwrap();
    let commit = model.commit(old_service).unwrap();
    let committed = model.projection();

    assert_eq!(committed.root_phase, RootPhase::Active);
    assert_eq!(committed.backend_phase, BackendPhase::Committed);
    assert_eq!(committed.causal_identity_phase, CausalIdentityPhase::Active);
    assert_eq!(committed.authority_epoch, old_service.authority_epoch());
    assert_eq!(committed.bound_service, Some(old_service.service()));
    assert_eq!(committed.obligation_owner, ObligationOwner::Kernel);
    assert_eq!(commit.effects(), EFFECT_COUNT);
    assert!(
        committed
            .effects
            .iter()
            .all(|effect| effect.phase == EffectPhase::Committed && effect.terminalizations == 0)
    );
    assert_eq!(committed.pending_publications, 0);
    assert_eq!(committed.counters.terminalizations, 0);

    let before_early_crash = model.projection();
    assert_eq!(
        model.observe_service_crash(old_service),
        Err(PostcommitError::BackendNotTerminalized)
    );
    assert_eq!(model.projection(), before_early_crash);

    let before_duplicate_commit = model.projection();
    assert_eq!(
        model.commit(old_service),
        Err(PostcommitError::AlreadyCommitted)
    );
    assert_eq!(model.projection(), before_duplicate_commit);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn backend_terminalizes_once_and_enters_awaiting_publication_before_crash() {
    let mut model = ProductionIdentityPostcommitModel::new(RootId::new(91), ServiceId::new(951));
    let old_service = model.service_authority().unwrap();
    let commit = model.commit(old_service).unwrap();
    let ticket = model.terminalize_backend(commit).unwrap();
    let awaiting = model.projection();

    assert_eq!(awaiting.root_phase, RootPhase::Closing);
    assert_eq!(awaiting.backend_phase, BackendPhase::AwaitingPublication);
    assert_eq!(awaiting.causal_identity_phase, CausalIdentityPhase::Active);
    assert!(!awaiting.service_crashed);
    assert_eq!(awaiting.pending_publication, Some(ticket));
    assert_eq!(awaiting.pending_publications, 1);
    assert_eq!(ticket.outcome(), BackendOutcome::Data);
    assert_eq!(ticket.terminalizations(), EFFECT_COUNT as u64);
    assert_eq!(awaiting.counters.backend_closures, 1);
    assert_eq!(awaiting.counters.terminalizations, EFFECT_COUNT as u64);
    assert!(
        awaiting.effects.iter().all(|effect| {
            effect.phase == EffectPhase::Completed && effect.terminalizations == 1
        })
    );
    assert_eq!(awaiting.credits.committed, pending_publication_credits());
    assert_eq!(awaiting.credits.returned, returned_before_ack());

    let before_duplicate = model.projection();
    assert_eq!(
        model.terminalize_backend(commit),
        Err(PostcommitError::AlreadyTerminalized)
    );
    assert_eq!(model.projection(), before_duplicate);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn post_backend_crash_preserves_active_identity_and_fresh_v3_is_closure_only() {
    let mut model = ProductionIdentityPostcommitModel::new(RootId::new(91), ServiceId::new(951));
    let old_service = model.service_authority().unwrap();
    let commit = model.commit(old_service).unwrap();
    let ticket = model.terminalize_backend(commit).unwrap();
    let before_crash = model.projection();

    model.observe_service_crash(old_service).unwrap();
    let crashed = model.projection();
    assert_eq!(
        before_crash.causal_identity_phase,
        CausalIdentityPhase::Active
    );
    assert_eq!(crashed.causal_identity_phase, CausalIdentityPhase::Active);
    assert_eq!(crashed.root_phase, before_crash.root_phase);
    assert_eq!(crashed.backend_phase, before_crash.backend_phase);
    assert_eq!(crashed.authority_epoch, before_crash.authority_epoch);
    assert_eq!(crashed.binding_epoch, before_crash.binding_epoch);
    assert_eq!(crashed.bound_service, before_crash.bound_service);
    assert_eq!(crashed.pending_publication, Some(ticket));
    assert_eq!(crashed.effects, before_crash.effects);
    assert_eq!(crashed.credits, before_crash.credits);
    assert_eq!(crashed.recovery_records, 0);
    assert_eq!(crashed.adoptions, 0);
    assert_eq!(crashed.rebinds, 0);

    let trigger = model.issue_closure_trigger(ServiceId::new(953)).unwrap();
    assert_eq!(trigger.service(), ServiceId::new(953));
    assert!(!trigger.has_registry_authority());
    let triggered = model.projection();
    assert_eq!(triggered.bound_service, Some(ServiceId::new(951)));
    assert_eq!(triggered.causal_identity_phase, CausalIdentityPhase::Active);
    assert_eq!(triggered.closure_trigger, Some(trigger));
    assert_eq!(triggered.recovery_records, 0);
    assert_eq!(triggered.adoptions, 0);
    assert_eq!(triggered.rebinds, 0);

    let before_old_service = model.projection();
    assert_eq!(
        model.publish_from_service(old_service),
        Err(PostcommitError::StaleAuthority)
    );
    assert_eq!(model.projection(), before_old_service);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn outer_ack_failure_keeps_closed_identity_and_exact_pending_retry() {
    let (mut model, _, commit, ticket) = post_backend_crashed();
    let trigger = closure_trigger(&mut model);
    let attempt = model.begin_publication(trigger).unwrap();
    let started = model.projection();

    assert_eq!(started.causal_identity_phase, CausalIdentityPhase::Closed);
    assert_eq!(started.active_attempt, Some(attempt));
    assert_eq!(started.pending_retry, None);
    assert_eq!(attempt.ticket(), ticket);
    assert_eq!(attempt.retry_generation(), 0);

    let retry = model.fail_outer_ack(attempt).unwrap();
    let failed = model.projection();
    assert_eq!(failed.causal_identity_phase, CausalIdentityPhase::Closed);
    assert_eq!(failed.pending_publication, Some(ticket));
    assert_eq!(failed.active_attempt, None);
    assert_eq!(failed.pending_retry, Some(retry));
    assert_eq!(retry.ticket(), ticket);
    assert_eq!(retry.trigger(), trigger);
    assert_eq!(retry.failed_attempt_sequence(), attempt.attempt_sequence());
    assert_eq!(retry.retry_generation(), 1);
    assert_eq!(failed.counters.terminalizations, EFFECT_COUNT as u64);

    let before_wrong_retry = model.projection();
    assert_eq!(
        model.retry_publication(retry.with_retry_generation(2)),
        Err(PostcommitError::InvalidPublicationRetry)
    );
    assert_eq!(model.projection(), before_wrong_retry);

    let retried = model.retry_publication(retry).unwrap();
    let retrying = model.projection();
    assert_eq!(retrying.causal_identity_phase, CausalIdentityPhase::Closed);
    assert_eq!(retrying.pending_retry, None);
    assert_eq!(retrying.active_attempt, Some(retried));
    assert_eq!(retried.ticket(), ticket);
    assert_eq!(retried.retry_generation(), retry.retry_generation());
    assert_ne!(retried.attempt_sequence(), attempt.attempt_sequence());
    assert_eq!(retrying.effects, failed.effects);
    assert_eq!(
        retrying.counters.terminalizations,
        failed.counters.terminalizations
    );

    let before_reterminalize = model.projection();
    assert_eq!(
        model.terminalize_backend(commit),
        Err(PostcommitError::AlreadyTerminalized)
    );
    assert_eq!(model.projection(), before_reterminalize);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn successful_outer_ack_consumes_closed_identity_to_vacant_without_reterminalizing() {
    let (mut model, _, commit, ticket) = post_backend_crashed();
    let trigger = closure_trigger(&mut model);
    let first = model.begin_publication(trigger).unwrap();
    let retry = model.fail_outer_ack(first).unwrap();
    let second = model.retry_publication(retry).unwrap();
    let before_ack = model.projection();
    let publication = model.acknowledge_outer_publication(second).unwrap();
    let closed = model.projection();

    assert_eq!(publication.ticket(), ticket);
    assert_eq!(publication.attempt_sequence(), second.attempt_sequence());
    assert_eq!(closed.root_phase, RootPhase::Revoked);
    assert_eq!(closed.backend_phase, BackendPhase::Complete);
    assert_eq!(closed.causal_identity_phase, CausalIdentityPhase::Vacant);
    assert_eq!(closed.obligation_owner, ObligationOwner::None);
    assert_eq!(closed.bound_service, None);
    assert_eq!(closed.pending_publication, None);
    assert_eq!(closed.pending_publications, 0);
    assert_eq!(closed.active_attempt, None);
    assert_eq!(closed.pending_retry, None);
    assert_eq!(closed.credits.committed, [0; CREDIT_CLASS_COUNT]);
    assert_eq!(closed.credits.returned, closed.credits.capacity);
    assert_eq!(closed.credits.registry_free(), closed.credits.capacity);
    assert_eq!(closed.effects, before_ack.effects);
    assert_eq!(closed.counters.terminalizations, EFFECT_COUNT as u64);
    assert_eq!(closed.counters.publication_acks, 1);
    assert_eq!(closed.counters.guest_replies, 1);
    assert_eq!(closed.counters.closures, 1);
    assert_eq!(
        closed.closure.unwrap().terminalizations(),
        EFFECT_COUNT as u64
    );

    let before_replay = model.projection();
    assert_eq!(
        model.acknowledge_outer_publication(second),
        Err(PostcommitError::AlreadyAcknowledged)
    );
    assert_eq!(model.projection(), before_replay);
    assert_eq!(
        model.terminalize_backend(commit),
        Err(PostcommitError::AlreadyTerminalized)
    );
    assert_eq!(model.projection(), before_replay);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn closure_trigger_and_attempt_substitution_are_failure_atomic() {
    let mut model = ProductionIdentityPostcommitModel::new(RootId::new(91), ServiceId::new(951));
    let old_service = model.service_authority().unwrap();
    let commit = model.commit(old_service).unwrap();
    let ticket = model.terminalize_backend(commit).unwrap();

    let before_trigger = model.projection();
    assert_eq!(
        model.issue_closure_trigger(ServiceId::new(953)),
        Err(PostcommitError::TriggerBeforeCrash)
    );
    assert_eq!(model.projection(), before_trigger);

    model.observe_service_crash(old_service).unwrap();
    let trigger = closure_trigger(&mut model);
    let before_wrong_trigger = model.projection();
    assert_eq!(
        model.begin_publication(trigger.with_service(ServiceId::new(954))),
        Err(PostcommitError::InvalidClosureTrigger)
    );
    assert_eq!(model.projection(), before_wrong_trigger);

    let attempt = model.begin_publication(trigger).unwrap();
    let before_wrong_attempt = model.projection();
    assert_eq!(
        model.fail_outer_ack(attempt.with_attempt_sequence(77)),
        Err(PostcommitError::InvalidPublicationAttempt)
    );
    assert_eq!(model.projection(), before_wrong_attempt);
    assert_eq!(model.projection().pending_publication, Some(ticket));
    assert_eq!(model.check_invariants(), Ok(()));
}
