use cser_model::production_identity_postcommit::{
    BackendPhase, CREDIT_CLASS_COUNT, CausalIdentityPhase, CreditClass, EFFECT_COUNT, EffectPhase,
    PostcommitError, ProductionIdentityPostcommitModel, RootId, RootPhase, ServiceId,
};
use proptest::prelude::*;

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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn arbitrary_outer_ack_failures_preserve_one_terminalization_and_exact_ticket(
        root_raw in any::<u64>(),
        service_raw in any::<u64>(),
        fresh_delta in 1u64..u64::MAX,
        failures in 0u8..8,
    ) {
        let root = RootId::new(root_raw);
        let service = ServiceId::new(service_raw);
        let fresh = ServiceId::new(service_raw.wrapping_add(fresh_delta));
        prop_assume!(fresh != service);

        let mut model = ProductionIdentityPostcommitModel::new(root, service);
        let old_service = model.service_authority().unwrap();
        let commit = model.commit(old_service).unwrap();
        let ticket = model.terminalize_backend(commit).unwrap();
        model.observe_service_crash(old_service).unwrap();
        let trigger = model.issue_closure_trigger(fresh).unwrap();
        prop_assert!(!trigger.has_registry_authority());

        let mut attempt = model.begin_publication(trigger).unwrap();
        for generation in 1..=u64::from(failures) {
            let retry = model.fail_outer_ack(attempt).unwrap();
            let retained = model.projection();
            prop_assert_eq!(retained.causal_identity_phase, CausalIdentityPhase::Closed);
            prop_assert_eq!(retained.pending_publication, Some(ticket));
            prop_assert_eq!(retained.pending_retry, Some(retry));
            prop_assert_eq!(retry.ticket(), ticket);
            prop_assert_eq!(retry.retry_generation(), generation);
            prop_assert_eq!(retained.counters.terminalizations, EFFECT_COUNT as u64);
            prop_assert_eq!(retained.credits.committed, pending_publication_credits());
            prop_assert_eq!(retained.credits.returned, returned_before_ack());
            prop_assert!(retained.effects.iter().all(|effect|
                effect.phase == EffectPhase::Completed && effect.terminalizations == 1));
            attempt = model.retry_publication(retry).unwrap();
            prop_assert_eq!(attempt.ticket(), ticket);
            prop_assert_eq!(attempt.retry_generation(), generation);
        }

        let before_ack = model.projection();
        model.acknowledge_outer_publication(attempt).unwrap();
        let closed = model.projection();
        prop_assert_eq!(closed.root_phase, RootPhase::Revoked);
        prop_assert_eq!(closed.backend_phase, BackendPhase::Complete);
        prop_assert_eq!(closed.causal_identity_phase, CausalIdentityPhase::Vacant);
        prop_assert_eq!(closed.pending_publications, 0);
        prop_assert_eq!(closed.credits.held, [0; CREDIT_CLASS_COUNT]);
        prop_assert_eq!(closed.credits.committed, [0; CREDIT_CLASS_COUNT]);
        prop_assert_eq!(closed.credits.returned, closed.credits.capacity);
        prop_assert_eq!(closed.credits.registry_free(), closed.credits.capacity);
        prop_assert_eq!(closed.effects, before_ack.effects);
        prop_assert_eq!(closed.counters.terminalizations, EFFECT_COUNT as u64);
        prop_assert_eq!(closed.counters.outer_ack_failures, u64::from(failures));
        prop_assert_eq!(closed.counters.publication_attempts, u64::from(failures) + 1);
        prop_assert_eq!(closed.counters.publication_acks, 1);
        prop_assert_eq!(closed.counters.guest_replies, 1);
        prop_assert_eq!(model.check_invariants(), Ok(()));
    }

    #[test]
    fn post_backend_crash_preserves_active_causal_identity_and_registry_topology(
        root_raw in any::<u64>(),
        service_raw in any::<u64>(),
    ) {
        let mut model = ProductionIdentityPostcommitModel::new(
            RootId::new(root_raw),
            ServiceId::new(service_raw),
        );
        let old_service = model.service_authority().unwrap();
        let commit = model.commit(old_service).unwrap();
        let ticket = model.terminalize_backend(commit).unwrap();
        let before = model.projection();
        model.observe_service_crash(old_service).unwrap();
        let after = model.projection();

        prop_assert_eq!(before.causal_identity_phase, CausalIdentityPhase::Active);
        prop_assert_eq!(after.causal_identity_phase, CausalIdentityPhase::Active);
        prop_assert_eq!(after.root_phase, before.root_phase);
        prop_assert_eq!(after.backend_phase, before.backend_phase);
        prop_assert_eq!(after.authority_epoch, before.authority_epoch);
        prop_assert_eq!(after.binding_epoch, before.binding_epoch);
        prop_assert_eq!(after.bound_service, before.bound_service);
        prop_assert_eq!(after.obligation_owner, before.obligation_owner);
        prop_assert_eq!(after.pending_publication, Some(ticket));
        prop_assert_eq!(after.effects, before.effects);
        prop_assert_eq!(after.credits, before.credits);
        prop_assert_eq!(after.recovery_records, 0);
        prop_assert_eq!(after.adoptions, 0);
        prop_assert_eq!(after.rebinds, 0);
        prop_assert_eq!(after.counters.terminalizations, before.counters.terminalizations);
        prop_assert_eq!(after.counters.backend_closures, before.counters.backend_closures);
        prop_assert_eq!(after.counters.crashes, before.counters.crashes + 1);
        prop_assert_eq!(model.check_invariants(), Ok(()));
    }

    #[test]
    fn substituted_attempts_and_retries_are_failure_atomic(
        root_raw in any::<u64>(),
        service_raw in any::<u64>(),
        fresh_delta in 1u64..u64::MAX,
        substitution in 1u64..u64::MAX,
    ) {
        let service = ServiceId::new(service_raw);
        let fresh = ServiceId::new(service_raw.wrapping_add(fresh_delta));
        prop_assume!(fresh != service);
        let mut model = ProductionIdentityPostcommitModel::new(RootId::new(root_raw), service);
        let old_service = model.service_authority().unwrap();
        let commit = model.commit(old_service).unwrap();
        model.terminalize_backend(commit).unwrap();
        model.observe_service_crash(old_service).unwrap();
        let trigger = model.issue_closure_trigger(fresh).unwrap();
        let attempt = model.begin_publication(trigger).unwrap();

        let wrong_attempt = attempt.with_attempt_sequence(
            attempt.attempt_sequence().wrapping_add(substitution),
        );
        prop_assume!(wrong_attempt != attempt);
        let before_attempt = model.projection();
        prop_assert_eq!(
            model.fail_outer_ack(wrong_attempt),
            Err(PostcommitError::InvalidPublicationAttempt),
        );
        prop_assert_eq!(model.projection(), before_attempt);

        let retry = model.fail_outer_ack(attempt).unwrap();
        let wrong_retry = retry.with_retry_generation(
            retry.retry_generation().wrapping_add(substitution),
        );
        prop_assume!(wrong_retry != retry);
        let before_retry = model.projection();
        prop_assert_eq!(
            model.retry_publication(wrong_retry),
            Err(PostcommitError::InvalidPublicationRetry),
        );
        prop_assert_eq!(model.projection(), before_retry.clone());

        let retried = model.retry_publication(retry).unwrap();
        let before_wrong_ack = model.projection();
        prop_assert_eq!(
            model.acknowledge_outer_publication(
                retried.with_attempt_sequence(retried.attempt_sequence().wrapping_add(substitution)),
            ),
            Err(PostcommitError::InvalidPublicationAttempt),
        );
        prop_assert_eq!(model.projection(), before_wrong_ack);
        prop_assert_eq!(model.projection().counters.terminalizations, EFFECT_COUNT as u64);
        prop_assert_eq!(model.check_invariants(), Ok(()));
    }
}
