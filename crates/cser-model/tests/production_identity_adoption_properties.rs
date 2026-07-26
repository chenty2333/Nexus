use cser_model::production_identity_adoption::{
    AdoptionError, AdoptionPresentation, CREDIT_CLASS_COUNT, ClientObservation, CreditClass,
    EFFECT_COUNT, EffectPhase, FlightPhase, ObligationOwner, ProductionIdentityAdoptionModel,
    PublicationGate, RetainedFlight, RootId, RootPhase, ServiceAuthority, ServiceId,
    SuccessorAuthority, TerminalDisposition,
};
use proptest::prelude::*;

/// Adopt, tombstone, a late reply from the crashed incarnation, and a successor
/// presenting the retired epoch.  The last two can never win.
const ADOPT: u8 = 0;
const TOMBSTONE: u8 = 1;
const STALE_REPLY: u8 = 2;
const STALE_EPOCH_ADOPT: u8 = 3;

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
    crashed: ServiceAuthority,
    flight: RetainedFlight,
    presentation: AdoptionPresentation,
    successor: SuccessorAuthority,
}

fn retained(root_raw: u64, service_raw: u64, cookie: u64, successor_raw: u64) -> Retained {
    let mut model = ProductionIdentityAdoptionModel::new(
        RootId::new(root_raw),
        ServiceId::new(service_raw),
        cookie,
    );
    let crashed = model.service_authority().unwrap();
    let commit = model.commit(crashed).unwrap();
    model.terminalize_backend(commit).unwrap();
    let flight = model.observe_service_crash(crashed).unwrap();
    let presentation = flight.identity().presentation();
    let successor = model
        .successor_authority(ServiceId::new(successor_raw))
        .unwrap();
    Retained {
        model,
        crashed,
        flight,
        presentation,
        successor,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Obligations 2 and 3 together: for any sequential interleaving of gate
    /// claims and fenced attempts, exactly one claim wins, every fenced attempt
    /// is rejected without perturbing anything, and the surviving state is
    /// identical to the run with the fenced attempts removed.
    #[test]
    fn arbitrary_interleavings_admit_one_winner_and_ignore_fenced_attempts(
        root_raw in any::<u64>(),
        service_raw in any::<u64>(),
        cookie in any::<u64>(),
        successor_delta in 1u64..u64::MAX,
        closer_delta in 1u64..u64::MAX,
        actions in prop::collection::vec(ADOPT..=STALE_EPOCH_ADOPT, 1..14),
    ) {
        let service = ServiceId::new(service_raw);
        let successor_raw = service_raw.wrapping_add(successor_delta);
        let closer = ServiceId::new(service_raw.wrapping_add(closer_delta));
        prop_assume!(ServiceId::new(successor_raw) != service && closer != service);

        let Retained { mut model, crashed, flight, presentation, successor } =
            retained(root_raw, service_raw, cookie, successor_raw);
        prop_assert_eq!(model.gate(), PublicationGate::Open);
        let stale_successor = successor.with_binding_epoch(crashed.binding_epoch());

        let mut winner: Option<TerminalDisposition> = None;
        let mut settled = model.projection();
        for action in &actions {
            let before = model.projection();
            match *action {
                STALE_REPLY => {
                    prop_assert_eq!(
                        model.publish_from_crashed_incarnation(crashed),
                        Err(AdoptionError::FencedIncarnation),
                    );
                    prop_assert_eq!(model.projection(), before);
                    continue;
                }
                STALE_EPOCH_ADOPT => {
                    prop_assert_eq!(
                        model.adopt_and_publish(presentation, stale_successor),
                        Err(AdoptionError::FencedIncarnation),
                    );
                    prop_assert_eq!(model.projection(), before);
                    continue;
                }
                _ => {}
            }
            let outcome = if *action == ADOPT {
                model.adopt_and_publish(presentation, successor)
                    .map(|_| TerminalDisposition::Adopted)
            } else {
                model.close_with_tombstone(flight, closer)
                    .map(|_| TerminalDisposition::Tombstoned)
            };
            match (winner, outcome) {
                (None, Ok(disposition)) => {
                    winner = Some(disposition);
                    settled = model.projection();
                    prop_assert_ne!(model.projection(), before);
                }
                (Some(_), Err(error)) => {
                    prop_assert_eq!(error, AdoptionError::GateAlreadyClosed);
                    prop_assert_eq!(model.projection(), settled.clone());
                }
                (winner, outcome) => prop_assert!(
                    false,
                    "gate exclusivity broken: winner {:?} then {:?}",
                    winner,
                    outcome.map(|_| ()),
                ),
            }
            prop_assert_eq!(model.check_invariants(), Ok(()));
        }

        // Obligation 3: dropping every fenced attempt leaves the same state.
        let claims: Vec<u8> = actions
            .iter()
            .copied()
            .filter(|action| *action == ADOPT || *action == TOMBSTONE)
            .collect();
        let Retained {
            model: mut clean,
            flight: clean_flight,
            presentation: clean_presentation,
            successor: clean_successor,
            ..
        } = retained(root_raw, service_raw, cookie, successor_raw);
        for action in &claims {
            let _ = if *action == ADOPT {
                clean.adopt_and_publish(clean_presentation, clean_successor).map(|_| ())
            } else {
                clean.close_with_tombstone(clean_flight, closer).map(|_| ())
            };
        }
        prop_assert_eq!(model.projection(), clean.projection());

        let Some(disposition) = winner else {
            // Every action was a fenced attempt: the gate is untouched.
            prop_assert!(claims.is_empty());
            let open = model.projection();
            prop_assert_eq!(open.gate, PublicationGate::Open);
            prop_assert_eq!(open.flight_phase, FlightPhase::Retained);
            prop_assert_eq!(open.retained, Some(flight));
            prop_assert_eq!(open.counters.gate_closures, 0);
            prop_assert_eq!(open.counters.guest_replies, 0);
            prop_assert_eq!(open.credits.committed, pending_publication_credits());
            prop_assert_eq!(model.check_invariants(), Ok(()));
            return Ok(());
        };

        prop_assert_eq!(model.disposition(), Some(disposition));
        let closed = model.projection();
        prop_assert_eq!(closed.counters.gate_closures, 1);
        prop_assert_eq!(closed.counters.closures, 1);
        prop_assert_eq!(closed.counters.adoptions + closed.counters.tombstones, 1);
        prop_assert_eq!(closed.retained, None);
        prop_assert_eq!(closed.pending_publications, 0);
        prop_assert_eq!(closed.root_phase, RootPhase::Revoked);
        prop_assert_eq!(closed.obligation_owner, ObligationOwner::None);
        prop_assert_eq!(closed.credits.held, [0; CREDIT_CLASS_COUNT]);
        prop_assert_eq!(closed.credits.committed, [0; CREDIT_CLASS_COUNT]);
        prop_assert_eq!(closed.credits.returned, closed.credits.capacity);
        prop_assert_eq!(closed.credits.registry_free(), closed.credits.capacity);
        prop_assert_eq!(closed.counters.terminalizations, EFFECT_COUNT as u64);
        prop_assert_eq!(closed.fenced_binding_epoch, Some(1));
        prop_assert_eq!(closed.binding_epoch, 2);

        let closure = closed.closure.expect("a winning disposition always closes the root");
        match disposition {
            TerminalDisposition::Adopted => {
                prop_assert_eq!(closed.flight_phase, FlightPhase::Published);
                prop_assert_eq!(closed.gate, PublicationGate::ClosedByAdoption);
                prop_assert_eq!(closed.counters.guest_replies, 1);
                prop_assert_eq!(closure.observation(), ClientObservation::Published);
                let adoption = closed.adoption.expect("adoption won");
                prop_assert_eq!(adoption.identity(), flight.identity());
                prop_assert_eq!(adoption.presented(), presentation);
                prop_assert_eq!(adoption.successor_binding_epoch(), 2);
                prop_assert_eq!(adoption.fenced_binding_epoch(), 1);
                prop_assert_eq!(closed.tombstone, None);
            }
            TerminalDisposition::Tombstoned => {
                prop_assert_eq!(closed.flight_phase, FlightPhase::Tombstoned);
                prop_assert_eq!(closed.gate, PublicationGate::ClosedByTombstone);
                prop_assert_eq!(closed.counters.guest_replies, 0);
                prop_assert_eq!(closure.observation(), ClientObservation::Indeterminate);
                prop_assert_eq!(
                    closed.tombstone.map(|receipt| receipt.identity()),
                    Some(flight.identity()),
                );
                prop_assert_eq!(closed.adoption, None);
            }
        }
        prop_assert_eq!(closure.gate_sequence(), 1);
        prop_assert_eq!(closure.guest_replies(), closed.counters.guest_replies);
        prop_assert_eq!(model.check_invariants(), Ok(()));
    }

    /// Obligation 1: the crash retains the exact causal identity, result
    /// digest, and typed credits, and obligation 3: it is also the fence.
    #[test]
    fn post_commit_crash_retains_identity_and_installs_the_fence(
        root_raw in any::<u64>(),
        service_raw in any::<u64>(),
        cookie in any::<u64>(),
    ) {
        let mut model = ProductionIdentityAdoptionModel::new(
            RootId::new(root_raw),
            ServiceId::new(service_raw),
            cookie,
        );
        let service = model.service_authority().unwrap();
        let commit = model.commit(service).unwrap();
        let ticket = model.terminalize_backend(commit).unwrap();
        let before = model.projection();
        let flight = model.observe_service_crash(service).unwrap();
        let after = model.projection();

        prop_assert_eq!(before.gate, PublicationGate::Unarmed);
        prop_assert_eq!(before.fenced_binding_epoch, None);
        prop_assert_eq!(after.gate, PublicationGate::Open);
        prop_assert_eq!(after.flight_phase, FlightPhase::Retained);
        prop_assert_eq!(after.obligation_owner, ObligationOwner::Root);
        prop_assert_eq!(after.root_phase, before.root_phase);
        prop_assert_eq!(after.authority_epoch, before.authority_epoch);
        prop_assert_eq!(after.bound_service, before.bound_service);
        prop_assert_eq!(after.effects, before.effects);
        prop_assert_eq!(after.credits, before.credits);
        prop_assert_eq!(after.pending_publication, Some(ticket));
        prop_assert_eq!(after.counters.terminalizations, before.counters.terminalizations);
        prop_assert_eq!(after.counters.crashes, before.counters.crashes + 1);
        prop_assert_eq!(after.counters.retentions, 1);
        prop_assert_eq!(after.counters.gate_closures, 0);

        // The fence retires exactly the epoch the crashed incarnation held.
        prop_assert_eq!(after.fenced_binding_epoch, Some(before.binding_epoch));
        prop_assert!(after.binding_epoch > before.binding_epoch);
        prop_assert_eq!(flight.crashed_binding_epoch(), before.binding_epoch);
        prop_assert_eq!(
            model.successor_authority(ServiceId::new(service_raw)).map(|a| a.binding_epoch()),
            Some(after.binding_epoch),
        );

        let identity = flight.identity();
        prop_assert_eq!(identity.root(), RootId::new(root_raw));
        prop_assert_eq!(identity.cookie(), cookie);
        prop_assert_eq!(identity.ticket(), ticket);
        prop_assert_eq!(identity.ancestry().commit_sequence(), commit.sequence());
        prop_assert_eq!(identity.ancestry().effects(), EFFECT_COUNT);
        prop_assert_eq!(flight.crashed_service(), ServiceId::new(service_raw));
        prop_assert_eq!(flight.held_credits(), pending_publication_credits());
        prop_assert_eq!(after.credits.committed, pending_publication_credits());
        prop_assert_eq!(after.credits.returned, returned_before_gate());
        prop_assert!(after.effects.iter().all(|effect|
            effect.phase == EffectPhase::Completed && effect.terminalizations == 1));
        prop_assert_eq!(model.check_invariants(), Ok(()));
    }

    /// Obligation 4: every single-field substitution in the presented identity
    /// is its own rejection and leaves the retained flight unchanged.
    #[test]
    fn each_mispresented_field_is_rejected_without_side_effect(
        root_raw in any::<u64>(),
        service_raw in any::<u64>(),
        cookie in any::<u64>(),
        successor_delta in 1u64..u64::MAX,
        substitution in 1u64..u64::MAX,
    ) {
        let service = ServiceId::new(service_raw);
        let successor_raw = service_raw.wrapping_add(successor_delta);
        prop_assume!(ServiceId::new(successor_raw) != service);

        let Retained { mut model, presentation, successor, flight, .. } =
            retained(root_raw, service_raw, cookie, successor_raw);
        let ancestry = presentation.ancestry();
        let before = model.projection();

        for (mutated, expected) in [
            (
                presentation.with_cookie(cookie.wrapping_add(substitution)),
                AdoptionError::WrongCookie,
            ),
            (
                presentation.with_ticket(
                    presentation.ticket().with_ticket_sequence(
                        presentation.ticket().ticket_sequence().wrapping_add(substitution),
                    ),
                ),
                AdoptionError::WrongPublicationTicket,
            ),
            (
                presentation.with_ancestry(
                    ancestry.with_commit_sequence(
                        ancestry.commit_sequence().wrapping_add(substitution),
                    ),
                ),
                AdoptionError::WrongRootAncestry,
            ),
            (
                presentation.with_result_digest(
                    presentation.result_digest().wrapping_add(substitution),
                ),
                AdoptionError::WrongResultDigest,
            ),
        ] {
            prop_assume!(mutated != presentation);
            prop_assert_eq!(model.adopt_and_publish(mutated, successor), Err(expected));
            prop_assert_eq!(model.projection(), before.clone());
            prop_assert_eq!(model.gate(), PublicationGate::Open);
            prop_assert_eq!(model.retained_flight(), Some(flight));
        }

        // The exact presentation still wins after every rejection.
        prop_assert!(model.adopt_and_publish(presentation, successor).is_ok());
        prop_assert_eq!(model.projection().counters.guest_replies, 1);
        prop_assert_eq!(model.check_invariants(), Ok(()));
    }

    /// A substituted bearer or the crashed incarnation never closes the gate,
    /// and the rejection leaves the retained flight observably unchanged.
    #[test]
    fn rejected_gate_claims_leave_the_retained_flight_unchanged(
        root_raw in any::<u64>(),
        service_raw in any::<u64>(),
        cookie in any::<u64>(),
        successor_delta in 1u64..u64::MAX,
        substitution in 1u64..u64::MAX,
    ) {
        let service = ServiceId::new(service_raw);
        let successor_raw = service_raw.wrapping_add(successor_delta);
        prop_assume!(ServiceId::new(successor_raw) != service);

        let Retained { mut model, crashed, flight, presentation, successor } =
            retained(root_raw, service_raw, cookie, successor_raw);
        let substituted = flight.with_retention_sequence(
            flight.retention_sequence().wrapping_add(substitution),
        );
        prop_assume!(substituted != flight);

        let before = model.projection();
        prop_assert_eq!(
            model.close_with_tombstone(substituted, ServiceId::new(successor_raw)),
            Err(AdoptionError::InvalidRetainedFlight),
        );
        prop_assert_eq!(model.projection(), before.clone());
        prop_assert_eq!(
            model.adopt_and_publish(presentation, successor.with_service(service)),
            Err(AdoptionError::FreshIncarnationRequired),
        );
        prop_assert_eq!(model.projection(), before.clone());
        prop_assert_eq!(
            model.close_with_tombstone(flight, service),
            Err(AdoptionError::FreshIncarnationRequired),
        );
        prop_assert_eq!(model.projection(), before.clone());
        prop_assert_eq!(
            model.publish_from_crashed_incarnation(crashed),
            Err(AdoptionError::FencedIncarnation),
        );
        prop_assert_eq!(model.projection(), before);

        prop_assert_eq!(model.gate(), PublicationGate::Open);
        prop_assert_eq!(model.retained_flight(), Some(flight));
        prop_assert_eq!(model.disposition(), None);
        prop_assert_eq!(model.check_invariants(), Ok(()));
    }
}
