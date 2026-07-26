use cser_model::production_identity_adoption::{
    AdoptionError, AdoptionPresentation, BackendOutcome, CREDIT_CLASS_COUNT, ClientObservation,
    CreditClass, EFFECT_COUNT, EffectPhase, FlightPhase, ObligationOwner,
    ProductionIdentityAdoptionModel, PublicationGate, RetainedFlight, RootId, RootPhase, ServiceId,
    SuccessorAuthority, TerminalDisposition,
};

const ROOT: RootId = RootId::new(91);
const CRASHED: ServiceId = ServiceId::new(951);
const SUCCESSOR: ServiceId = ServiceId::new(952);
const CLOSER: ServiceId = ServiceId::new(953);
const COOKIE: u64 = 0x00c0_ffee_0000_0001;

fn pending_publication_credits() -> [u64; CREDIT_CLASS_COUNT] {
    let mut credits = [0; CREDIT_CLASS_COUNT];
    credits[CreditClass::Control as usize] = 1;
    credits[CreditClass::GuestReply as usize] = 1;
    credits
}

fn returned_before_gate() -> [u64; CREDIT_CLASS_COUNT] {
    let pending = pending_publication_credits();
    core::array::from_fn(|index| CreditClass::ALL[index].capacity() - pending[index])
}

struct Retained {
    model: ProductionIdentityAdoptionModel,
    flight: RetainedFlight,
    presentation: AdoptionPresentation,
    successor: SuccessorAuthority,
}

fn retained() -> Retained {
    let mut model = ProductionIdentityAdoptionModel::new(ROOT, CRASHED, COOKIE);
    let crashed = model.service_authority().unwrap();
    let commit = model.commit(crashed).unwrap();
    model.terminalize_backend(commit).unwrap();
    let flight = model.observe_service_crash(crashed).unwrap();
    let presentation = flight.identity().presentation();
    let successor = model.successor_authority(SUCCESSOR).unwrap();
    Retained {
        model,
        flight,
        presentation,
        successor,
    }
}

fn foreign_flight() -> RetainedFlight {
    let mut model = ProductionIdentityAdoptionModel::new(RootId::new(1), ServiceId::new(2), 3);
    let service = model.service_authority().unwrap();
    let commit = model.commit(service).unwrap();
    model.terminalize_backend(commit).unwrap();
    model.observe_service_crash(service).unwrap()
}

#[test]
fn post_commit_crash_retains_causal_identity_digest_and_held_credits() {
    let mut model = ProductionIdentityAdoptionModel::new(ROOT, CRASHED, COOKIE);
    let service = model.service_authority().unwrap();
    let commit = model.commit(service).unwrap();
    let ticket = model.terminalize_backend(commit).unwrap();
    let awaiting = model.projection();

    assert_eq!(awaiting.flight_phase, FlightPhase::AwaitingPublication);
    assert_eq!(awaiting.gate, PublicationGate::Unarmed);
    assert_eq!(awaiting.retained, None);
    assert_eq!(awaiting.fenced_binding_epoch, None);
    assert_eq!(awaiting.binding_epoch, 1);
    assert_eq!(ticket.outcome(), BackendOutcome::Data);
    assert_eq!(model.successor_authority(SUCCESSOR), None);

    let before_early_gate = model.projection();
    assert_eq!(
        model.close_with_tombstone(foreign_flight(), CLOSER),
        Err(AdoptionError::FlightNotRetained)
    );
    assert_eq!(model.projection(), before_early_gate);

    let flight = model.observe_service_crash(service).unwrap();
    let retained = model.projection();

    assert_eq!(retained.flight_phase, FlightPhase::Retained);
    assert_eq!(retained.gate, PublicationGate::Open);
    assert_eq!(retained.obligation_owner, ObligationOwner::Root);
    assert_eq!(retained.root_phase, RootPhase::Closing);
    assert_eq!(retained.bound_service, Some(CRASHED));
    assert_eq!(retained.retained, Some(flight));
    assert_eq!(retained.pending_publication, Some(ticket));
    assert_eq!(retained.pending_publications, 1);
    assert_eq!(retained.counters.retentions, 1);
    assert_eq!(retained.counters.gate_closures, 0);
    assert_eq!(retained.counters.guest_replies, 0);

    assert_eq!(retained.fenced_binding_epoch, Some(1));
    assert_eq!(retained.binding_epoch, 2);
    assert_eq!(model.fenced_binding_epoch(), Some(1));

    let identity = flight.identity();
    assert_eq!(identity.root(), ROOT);
    assert_eq!(identity.cookie(), COOKIE);
    assert_eq!(identity.ticket(), ticket);
    assert_eq!(identity.ancestry().commit_sequence(), commit.sequence());
    assert_eq!(identity.ancestry().effects(), EFFECT_COUNT);
    assert_eq!(identity.ancestry().commit_authority_epoch(), 1);
    assert_ne!(identity.result_digest(), 0);

    assert_eq!(flight.crashed_service(), CRASHED);
    assert_eq!(flight.crashed_binding_epoch(), 1);
    assert_eq!(flight.held_credits(), pending_publication_credits());
    assert_eq!(retained.credits.committed, pending_publication_credits());
    assert_eq!(retained.credits.returned, returned_before_gate());
    assert!(
        retained
            .effects
            .iter()
            .all(|effect| effect.phase == EffectPhase::Completed && effect.terminalizations == 1)
    );

    let before_second_crash = model.projection();
    assert_eq!(
        model.observe_service_crash(service),
        Err(AdoptionError::CrashAlreadyObserved)
    );
    assert_eq!(model.projection(), before_second_crash);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn successor_adoption_wins_the_gate_and_publishes_exactly_one_reply() {
    let Retained {
        mut model,
        flight,
        presentation,
        successor,
    } = retained();
    let adoption = model.adopt_and_publish(presentation, successor).unwrap();
    let closed = model.projection();

    assert_eq!(closed.flight_phase, FlightPhase::Published);
    assert_eq!(closed.gate, PublicationGate::ClosedByAdoption);
    assert_eq!(model.disposition(), Some(TerminalDisposition::Adopted));
    assert_eq!(closed.root_phase, RootPhase::Revoked);
    assert_eq!(closed.obligation_owner, ObligationOwner::None);
    assert_eq!(closed.bound_service, None);
    assert_eq!(closed.retained, None);
    assert_eq!(closed.pending_publication, None);
    assert_eq!(closed.adoption, Some(adoption));
    assert_eq!(closed.tombstone, None);

    assert_eq!(adoption.identity(), flight.identity());
    assert_eq!(adoption.presented(), presentation);
    assert_eq!(adoption.successor(), SUCCESSOR);
    assert_eq!(adoption.successor_binding_epoch(), 2);
    assert_eq!(adoption.fenced_binding_epoch(), 1);
    assert_eq!(adoption.guest_replies(), 1);
    assert_eq!(adoption.terminalizations(), EFFECT_COUNT as u64);

    let closure = closed.closure.unwrap();
    assert_eq!(closure.disposition(), TerminalDisposition::Adopted);
    assert_eq!(closure.observation(), ClientObservation::Published);
    assert_eq!(closure.guest_replies(), 1);
    assert_eq!(closure.gate_sequence(), adoption.gate_sequence());
    assert_eq!(closure.terminalizations(), EFFECT_COUNT as u64);

    assert_eq!(closed.counters.adoptions, 1);
    assert_eq!(closed.counters.tombstones, 0);
    assert_eq!(closed.counters.gate_closures, 1);
    assert_eq!(closed.counters.guest_replies, 1);
    assert_eq!(closed.counters.closures, 1);
    assert_eq!(closed.credits.committed, [0; CREDIT_CLASS_COUNT]);
    assert_eq!(closed.credits.returned, closed.credits.capacity);
    assert_eq!(closed.credits.registry_free(), closed.credits.capacity);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn tombstone_closure_wins_the_gate_and_publishes_no_reply() {
    let Retained {
        mut model, flight, ..
    } = retained();
    let tombstone = model.close_with_tombstone(flight, CLOSER).unwrap();
    let closed = model.projection();

    assert_eq!(closed.flight_phase, FlightPhase::Tombstoned);
    assert_eq!(closed.gate, PublicationGate::ClosedByTombstone);
    assert_eq!(model.disposition(), Some(TerminalDisposition::Tombstoned));
    assert_eq!(closed.root_phase, RootPhase::Revoked);
    assert_eq!(closed.obligation_owner, ObligationOwner::None);
    assert_eq!(closed.retained, None);
    assert_eq!(closed.adoption, None);
    assert_eq!(closed.tombstone, Some(tombstone));

    assert_eq!(tombstone.identity(), flight.identity());
    assert_eq!(tombstone.closer(), CLOSER);
    assert_eq!(tombstone.observation(), ClientObservation::Indeterminate);
    assert_eq!(tombstone.terminalizations(), EFFECT_COUNT as u64);

    let closure = closed.closure.unwrap();
    assert_eq!(closure.disposition(), TerminalDisposition::Tombstoned);
    assert_eq!(closure.observation(), ClientObservation::Indeterminate);
    assert_eq!(closure.guest_replies(), 0);
    assert_eq!(closure.gate_sequence(), tombstone.gate_sequence());

    assert_eq!(closed.counters.adoptions, 0);
    assert_eq!(closed.counters.tombstones, 1);
    assert_eq!(closed.counters.gate_closures, 1);
    assert_eq!(closed.counters.guest_replies, 0);
    assert_eq!(closed.counters.closures, 1);
    assert_eq!(closed.credits.returned, closed.credits.capacity);
    assert_eq!(closed.credits.registry_free(), closed.credits.capacity);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn tombstone_loses_after_adoption_and_leaves_state_unchanged() {
    let Retained {
        mut model,
        flight,
        presentation,
        successor,
    } = retained();
    model.adopt_and_publish(presentation, successor).unwrap();
    let after_adoption = model.projection();

    assert_eq!(
        model.close_with_tombstone(flight, CLOSER),
        Err(AdoptionError::GateAlreadyClosed)
    );
    assert_eq!(model.projection(), after_adoption);

    assert_eq!(
        model.adopt_and_publish(presentation, successor),
        Err(AdoptionError::GateAlreadyClosed)
    );
    assert_eq!(model.projection(), after_adoption);

    assert_eq!(model.retained_flight(), None);
    assert_eq!(model.projection().counters.gate_closures, 1);
    assert_eq!(model.projection().counters.guest_replies, 1);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn adoption_loses_after_tombstone_and_leaves_state_unchanged() {
    let Retained {
        mut model,
        flight,
        presentation,
        successor,
    } = retained();
    model.close_with_tombstone(flight, CLOSER).unwrap();
    let after_tombstone = model.projection();

    assert_eq!(
        model.adopt_and_publish(presentation, successor),
        Err(AdoptionError::GateAlreadyClosed)
    );
    assert_eq!(model.projection(), after_tombstone);

    assert_eq!(
        model.close_with_tombstone(flight, CLOSER),
        Err(AdoptionError::GateAlreadyClosed)
    );
    assert_eq!(model.projection(), after_tombstone);

    assert_eq!(model.projection().counters.gate_closures, 1);
    assert_eq!(model.projection().counters.guest_replies, 0);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn substituted_bearers_and_the_crashed_incarnation_are_failure_atomic() {
    let Retained {
        mut model,
        flight,
        presentation,
        successor,
    } = retained();
    let before = model.projection();

    assert_eq!(
        model.close_with_tombstone(flight.with_retention_sequence(77), CLOSER),
        Err(AdoptionError::InvalidRetainedFlight)
    );
    assert_eq!(model.projection(), before);

    assert_eq!(
        model.adopt_and_publish(presentation, successor.with_service(CRASHED)),
        Err(AdoptionError::FreshIncarnationRequired)
    );
    assert_eq!(model.projection(), before);

    assert_eq!(
        model.close_with_tombstone(flight, CRASHED),
        Err(AdoptionError::FreshIncarnationRequired)
    );
    assert_eq!(model.projection(), before);

    assert_eq!(model.gate(), PublicationGate::Open);
    assert_eq!(model.retained_flight(), Some(flight));
    assert_eq!(model.check_invariants(), Ok(()));

    let adoption = model.adopt_and_publish(presentation, successor).unwrap();
    assert_eq!(adoption.gate_sequence(), 1);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn the_gate_stays_unarmed_until_the_flight_is_retained() {
    let foreign = foreign_flight();
    let mut model = ProductionIdentityAdoptionModel::new(ROOT, CRASHED, COOKIE);
    let before_commit = model.projection();
    assert_eq!(model.gate(), PublicationGate::Unarmed);
    assert_eq!(model.successor_authority(SUCCESSOR), None);
    assert_eq!(
        model.close_with_tombstone(foreign, CLOSER),
        Err(AdoptionError::FlightNotRetained)
    );
    assert_eq!(model.projection(), before_commit);

    let service = model.service_authority().unwrap();
    assert_eq!(
        model.commit(service.with_binding_epoch(7)),
        Err(AdoptionError::StaleBinding)
    );
    assert_eq!(model.projection(), before_commit);

    let commit = model.commit(service).unwrap();
    let committed = model.projection();
    assert_eq!(committed.flight_phase, FlightPhase::Committed);
    assert_eq!(committed.gate, PublicationGate::Unarmed);
    assert_eq!(
        model.close_with_tombstone(foreign, CLOSER),
        Err(AdoptionError::FlightNotRetained)
    );
    assert_eq!(model.projection(), committed);

    assert_eq!(
        model.observe_service_crash(service),
        Err(AdoptionError::BackendNotTerminalized)
    );
    assert_eq!(model.projection(), committed);

    model.terminalize_backend(commit).unwrap();
    let awaiting = model.projection();
    assert_eq!(
        model.terminalize_backend(commit),
        Err(AdoptionError::AlreadyTerminalized)
    );
    assert_eq!(model.projection(), awaiting);

    // No successor authority can be minted before the fence installs one, so
    // adoption has no epoch to present and the flight cannot be inherited.
    assert_eq!(model.successor_authority(SUCCESSOR), None);
    assert_eq!(model.fenced_binding_epoch(), None);

    model.observe_service_crash(service).unwrap();
    assert_eq!(model.gate(), PublicationGate::Open);
    assert!(model.successor_authority(SUCCESSOR).is_some());
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn the_fence_rejects_the_crashed_incarnation_before_and_after_the_gate_closes() {
    let mut model = ProductionIdentityAdoptionModel::new(ROOT, CRASHED, COOKIE);
    let crashed = model.service_authority().unwrap();
    let commit = model.commit(crashed).unwrap();
    model.terminalize_backend(commit).unwrap();

    // Before the fence the epoch is current, so the rejection is about who owns
    // publication, not about staleness.
    let before_fence = model.projection();
    assert_eq!(
        model.publish_from_crashed_incarnation(crashed),
        Err(AdoptionError::KernelObligationRequired)
    );
    assert_eq!(model.projection(), before_fence);

    let flight = model.observe_service_crash(crashed).unwrap();
    let presentation = flight.identity().presentation();
    let successor = model.successor_authority(SUCCESSOR).unwrap();
    assert_eq!(crashed.binding_epoch(), 1);
    assert_eq!(successor.binding_epoch(), 2);

    // The same credential is now fenced while the gate is still open: the case
    // a well-formedness check alone cannot express.
    let open_gate = model.projection();
    assert_eq!(open_gate.gate, PublicationGate::Open);
    assert_eq!(
        model.publish_from_crashed_incarnation(crashed),
        Err(AdoptionError::FencedIncarnation)
    );
    assert_eq!(model.projection(), open_gate);

    // A successor presenting the retired epoch is fenced before reaching the
    // gate, even with an otherwise exact presentation.
    assert_eq!(
        model.adopt_and_publish(presentation, successor.with_binding_epoch(1)),
        Err(AdoptionError::FencedIncarnation)
    );
    assert_eq!(model.projection(), open_gate);

    // Foreign coordinates stay distinguishable from the fence.
    assert_eq!(
        model.publish_from_crashed_incarnation(crashed.with_root(RootId::new(4242))),
        Err(AdoptionError::WrongRoot)
    );
    assert_eq!(model.projection(), open_gate);
    assert_eq!(
        model.publish_from_crashed_incarnation(crashed.with_service(ServiceId::new(4242))),
        Err(AdoptionError::WrongService)
    );
    assert_eq!(model.projection(), open_gate);

    model.adopt_and_publish(presentation, successor).unwrap();
    let closed = model.projection();

    // After a winner closed the gate the fence still answers first.
    assert_eq!(
        model.publish_from_crashed_incarnation(crashed),
        Err(AdoptionError::FencedIncarnation)
    );
    assert_eq!(model.projection(), closed);
    assert_eq!(
        model.adopt_and_publish(presentation, successor.with_binding_epoch(1)),
        Err(AdoptionError::FencedIncarnation)
    );
    assert_eq!(model.projection(), closed);
    assert_eq!(closed.counters.guest_replies, 1);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn each_mispresented_identity_field_is_its_own_rejection() {
    let Retained {
        mut model,
        presentation,
        successor,
        ..
    } = retained();
    let before = model.projection();
    let ancestry = presentation.ancestry();

    for (mutated, expected) in [
        (
            presentation.with_cookie(COOKIE ^ 1),
            AdoptionError::WrongCookie,
        ),
        (
            presentation.with_ticket(presentation.ticket().with_ticket_sequence(77)),
            AdoptionError::WrongPublicationTicket,
        ),
        (
            presentation.with_ancestry(ancestry.with_commit_sequence(77)),
            AdoptionError::WrongRootAncestry,
        ),
        (
            presentation.with_ancestry(ancestry.with_effects(EFFECT_COUNT - 1)),
            AdoptionError::WrongRootAncestry,
        ),
        (
            presentation.with_result_digest(presentation.result_digest() ^ 1),
            AdoptionError::WrongResultDigest,
        ),
    ] {
        assert_ne!(mutated, presentation);
        assert_eq!(model.adopt_and_publish(mutated, successor), Err(expected));
        assert_eq!(model.projection(), before);
        assert_eq!(model.gate(), PublicationGate::Open);
    }

    assert_eq!(model.check_invariants(), Ok(()));

    // The exact presentation still adopts after every rejection.
    let adoption = model.adopt_and_publish(presentation, successor).unwrap();
    assert_eq!(adoption.presented(), presentation);
    assert_eq!(model.projection().counters.guest_replies, 1);
    assert_eq!(model.check_invariants(), Ok(()));
}
