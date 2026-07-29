#[allow(dead_code)]
mod support;

use cser_core::{AuthorityState, CommandRequest, CoreError, SettlementState};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};
use std::sync::Arc as StdArc;
use support::{Harness, charge, effect, fence_and_rebind, principal};

fn model_transition(body: impl Fn() + Send + Sync + 'static) {
    let body = StdArc::new(body);
    model(move || {
        let body = StdArc::clone(&body);
        thread::Builder::new()
            .stack_size(4 << 20)
            .spawn(move || body())
            .expect("Loom scenario thread must spawn")
            .join()
            .expect("Loom scenario thread must complete");
    });
}

#[test]
fn loom_precommit_adopt_and_begin_revoke_drive_the_production_command_gate() {
    model_transition(|| {
        let mut harness = Harness::new();
        let effect = effect(91, 1);
        let origin = principal(91, 1);
        harness
            .tx(CommandRequest::CreateEstate {
                effect,
                origin,
                binding_generation: 1,
                domain: cser_core::REPLY_DOMAIN,
                obligation: cser_core::REPLY_OBLIGATION_PUBLICATION,
                charge_account: charge(91),
            })
            .unwrap();
        let successor = principal(91, 2);
        fence_and_rebind(&mut harness, effect, origin, successor, 1, 2, 910);
        let authority_epoch = harness.engine.estate(effect).unwrap().authority_epoch;
        let initial_revision = harness.engine.revision();
        let shared = Arc::new(Mutex::new(harness.engine));

        let adopt_engine = Arc::clone(&shared);
        let adopt = thread::spawn(move || {
            adopt_engine
                .lock()
                .unwrap()
                .transact_volatile(CommandRequest::AdoptEffect {
                    effect,
                    successor,
                    binding_generation: 2,
                })
                .map(|_| ())
        });
        let revoke_engine = Arc::clone(&shared);
        let revoke = thread::spawn(move || {
            revoke_engine
                .lock()
                .unwrap()
                .transact_volatile(CommandRequest::BeginRevoke {
                    effect,
                    expected_actor: successor,
                    binding_generation: 2,
                    authority_epoch,
                })
                .map(|_| ())
        });

        let adopt_result = adopt.join().unwrap();
        let revoke_result = revoke.join().unwrap();
        let mut engine = shared.lock().unwrap();
        assert_eq!(engine.revision(), initial_revision + 1);
        match (adopt_result, revoke_result) {
            (Ok(()), Err(CoreError::StaleAuthorityEpoch)) => {
                let estate = engine.estate(effect).unwrap();
                assert_eq!(estate.authority, AuthorityState::Active);
                assert_eq!(estate.settlement, SettlementState::Unavailable);
            }
            (Err(CoreError::GateClosed), Ok(())) => {
                let estate = engine.estate(effect).unwrap();
                assert_eq!(estate.authority, AuthorityState::Revoked);
                assert_eq!(estate.settlement, SettlementState::Revoked);
            }
            other => panic!("production adopt/revoke gate did not have one winner: {other:?}"),
        }

        let before_stale = engine.projection_digest();
        let before_revision = engine.revision();
        assert_eq!(
            engine.transact_volatile(CommandRequest::AdoptEffect {
                effect,
                successor: origin,
                binding_generation: 1,
            }),
            Err(CoreError::StaleIncarnation)
        );
        assert_eq!(engine.projection_digest(), before_stale);
        assert_eq!(engine.revision(), before_revision);
    });
}
