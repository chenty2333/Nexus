//! Bounded Loom schedules for the independent CSER core-rebaseline oracle.
//!
//! These tests execute the real oracle transitions behind a modeled outer
//! writer mutex. They are not hand-enumerated sequential orders. The matching
//! `cser-core/tests/production_precommit_adoption_loom.rs` and
//! `cser-core/tests/production_transition_loom.rs` drive the production
//! `CommandRequest` path; this file independently checks the same normalized
//! winner sets and post-crash invariants.

use cser_model::core_rebaseline_oracle::{
    EstateOracle, OracleAuthorityState, OracleCommitState, OracleError, OracleSettlement,
};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};

#[test]
fn loom_precommit_adopt_and_begin_revoke_share_one_gate() {
    model(|| {
        let mut initial = EstateOracle::precommit(1, 1);
        initial.fence_incarnation(1, 1).unwrap();
        initial.rebind(2, 2).unwrap();
        let observation = initial.observe_authority().unwrap();
        let initial_revision = initial.projection().revision;
        let shared = Arc::new(Mutex::new(initial));

        let adopt_oracle = Arc::clone(&shared);
        let adopt = thread::spawn(move || adopt_oracle.lock().unwrap().adopt_effect(2, 2));
        let revoke_oracle = Arc::clone(&shared);
        let revoke = thread::spawn(move || revoke_oracle.lock().unwrap().begin_revoke(observation));

        let adopt_result = adopt.join().unwrap();
        let revoke_result = revoke.join().unwrap();
        let mut oracle = shared.lock().unwrap();
        let projection = oracle.projection();

        assert_eq!(projection.commit, OracleCommitState::Precommit);
        assert_eq!(projection.revision, initial_revision + 1);
        assert_eq!(projection.settlement, None);
        match (adopt_result, revoke_result) {
            (Ok(()), Err(OracleError::StaleAuthorityEpoch)) => {
                assert_eq!(projection.authority, OracleAuthorityState::Active);
            }
            (Err(OracleError::GateClosed), Ok(())) => {
                assert_eq!(projection.authority, OracleAuthorityState::Revoked);
            }
            other => panic!("adopt/revoke did not have one winner: {other:?}"),
        }

        let before_stale = oracle.projection();
        assert_eq!(
            oracle.begin_revoke(observation.with_incarnation(1).with_binding_generation(1)),
            Err(OracleError::StaleIncarnation)
        );
        assert_eq!(oracle.projection(), before_stale);
        assert!(oracle.check_invariants());
    });
}

#[test]
fn loom_postcommit_claim_and_begin_revoke_preserve_the_obligation() {
    model(|| {
        let mut initial = EstateOracle::postcommit(1, 1);
        initial.fence_incarnation(1, 1).unwrap();
        initial.rebind(2, 2).unwrap();
        let observation = initial.observe_authority().unwrap();
        let initial_revision = initial.projection().revision;
        let shared = Arc::new(Mutex::new(initial));

        let claim_oracle = Arc::clone(&shared);
        let claim = thread::spawn(move || claim_oracle.lock().unwrap().claim_settlement(2));
        let revoke_oracle = Arc::clone(&shared);
        let revoke = thread::spawn(move || revoke_oracle.lock().unwrap().begin_revoke(observation));

        let claim_result = claim.join().unwrap();
        let revoke_result = revoke.join().unwrap();
        let mut oracle = shared.lock().unwrap();
        let projection = oracle.projection();

        assert_eq!(projection.commit, OracleCommitState::Postcommit);
        assert_ne!(projection.authority, OracleAuthorityState::Active);
        assert_eq!(projection.revision, initial_revision + 1);
        match (claim_result, revoke_result) {
            (Ok(claim), Err(OracleError::GateClaimed)) => {
                assert_eq!(claim.claimant(), 2);
                assert_eq!(claim.generation(), 1);
                assert_eq!(projection.authority, OracleAuthorityState::Fenced);
                assert_eq!(
                    projection.settlement,
                    Some(OracleSettlement::Claimed {
                        claimant: 2,
                        generation: 1,
                    })
                );
            }
            (Err(OracleError::GateClosed), Ok(())) => {
                assert_eq!(projection.authority, OracleAuthorityState::Revoked);
                assert_eq!(
                    projection.settlement,
                    Some(OracleSettlement::Open { generation: 1 })
                );
            }
            other => panic!("claim/revoke did not have one winner: {other:?}"),
        }

        let before_adopt = oracle.projection();
        assert!(matches!(
            oracle.adopt_effect(2, 2),
            Err(OracleError::WrongCommitState | OracleError::GateClosed)
        ));
        assert_eq!(oracle.projection(), before_adopt);
        assert!(oracle.check_invariants());
    });
}

#[test]
fn loom_second_crash_fences_stale_claim_and_prevents_duplicate_apply() {
    model(|| {
        let mut initial = EstateOracle::postcommit(1, 1);
        initial.fence_incarnation(1, 1).unwrap();
        initial.rebind(2, 2).unwrap();
        let stale_after_crash = initial.claim_settlement(2).unwrap();
        let initial_revision = initial.projection().revision;
        let shared = Arc::new(Mutex::new(initial));

        let intent_oracle = Arc::clone(&shared);
        let intent = thread::spawn(move || {
            intent_oracle
                .lock()
                .unwrap()
                .record_apply_intent(stale_after_crash)
        });
        let crash_oracle = Arc::clone(&shared);
        let crash = thread::spawn(move || crash_oracle.lock().unwrap().fence_incarnation(2, 2));

        let intent_result = intent.join().unwrap();
        assert_eq!(crash.join().unwrap(), Ok(()));
        let mut oracle = shared.lock().unwrap();
        let after_crash = oracle.projection();

        assert_eq!(after_crash.crash_generation, 2);
        assert_eq!(after_crash.authority, OracleAuthorityState::Fenced);
        assert_eq!(after_crash.live_incarnation, None);
        match intent_result {
            Ok(()) => {
                assert_eq!(after_crash.revision, initial_revision + 2);
                assert_eq!(
                    after_crash.settlement,
                    Some(OracleSettlement::ReconciliationRequired {
                        generation: 2,
                        applied: false,
                    })
                );
                assert_eq!(after_crash.apply_intents, 1);
            }
            Err(OracleError::StaleClaim) => {
                assert_eq!(after_crash.revision, initial_revision + 1);
                assert_eq!(
                    after_crash.settlement,
                    Some(OracleSettlement::Open { generation: 2 })
                );
                assert_eq!(after_crash.apply_intents, 0);
            }
            other => panic!("unexpected intent/second-crash result: {other:?}"),
        }

        let before_stale = oracle.projection();
        assert_eq!(
            oracle.record_apply_intent(stale_after_crash),
            Err(OracleError::StaleClaim)
        );
        assert_eq!(oracle.projection(), before_stale);

        oracle.rebind(3, 3).unwrap();
        let reconciliation = oracle.claim_settlement(3).unwrap();
        if after_crash.apply_intents == 1 {
            let before_duplicate = oracle.projection();
            assert_eq!(
                oracle.record_apply_intent(reconciliation),
                Err(OracleError::WrongSettlementStage)
            );
            assert_eq!(oracle.projection(), before_duplicate);
        } else {
            oracle.record_apply_intent(reconciliation).unwrap();
            let before_duplicate = oracle.projection();
            assert_eq!(
                oracle.record_apply_intent(reconciliation),
                Err(OracleError::WrongSettlementStage)
            );
            assert_eq!(oracle.projection(), before_duplicate);
        }

        oracle.record_applied(reconciliation).unwrap();
        oracle.settle(reconciliation).unwrap();
        let settled = oracle.projection();
        assert_eq!(settled.apply_intents, 1);
        assert_eq!(settled.external_applies, 1);
        assert_eq!(settled.settlements, 1);
        assert_eq!(settled.settlement, Some(OracleSettlement::Settled));
        assert_ne!(settled.authority, OracleAuthorityState::Active);

        assert_eq!(
            oracle.settle(stale_after_crash),
            Err(OracleError::StaleClaim)
        );
        assert_eq!(oracle.projection(), settled);
        assert!(oracle.check_invariants());
    });
}
