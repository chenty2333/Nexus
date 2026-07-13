// SPDX-License-Identifier: MPL-2.0

extern crate alloc;

#[path = "../../../kernel/nexus-ostd/src/cser/effect_registry.rs"]
mod effect_registry;

use alloc::boxed::Box;
use cser_transition_gates::{
    oneshot::{OneShotError, OneShotGate},
    pager::{
        CommitMappingError, ContinuationOutcome, FaultKey, FaultTicket, PagerError, PagerGate,
        PagerLifecycle,
    },
};
use effect_registry::{ScopePhase, Stage7bActiveFixture, Stage7bFixtureConfig};
use loom::{
    model,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateOutcome {
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Decision {
    Adopted,
    Aborted,
}

struct OldReplyComposite {
    pager: PagerGate<2>,
    continuation: OneShotGate<ContinuationOutcome>,
}

fn key() -> FaultKey {
    FaultKey {
        address_space_id: 1,
        address_space_generation: 1,
        page_address: 0x4000,
    }
}

fn report(case: &str, assertions: &[&str]) {
    println!("STAGE7B_CONCURRENCY case={case} status=PASS");
    for assertion in assertions {
        println!("STAGE7B_CONCURRENCY_ASSERT case={case} assertion={assertion} status=PASS");
    }
}

struct SamePageState {
    pager: PagerGate<2>,
    continuations: [OneShotGate<ContinuationOutcome>; 2],
    candidate_releases: [OneShotGate<CandidateOutcome>; 2],
}

#[test]
fn same_page_single_publication() {
    model(|| {
        let publications = Arc::new(AtomicUsize::new(0));
        let mut pager = PagerGate::<2>::new(5, 1, 10).unwrap();
        let leader = pager.register(key(), 100).unwrap().ticket();
        let follower = pager.register(key(), 101).unwrap().ticket();
        pager.prepare_leader(leader).unwrap();

        let before_early_resume = pager;
        assert_eq!(
            pager.terminalize(leader, None, ContinuationOutcome::Resolved),
            Err(PagerError::MappingMismatch)
        );
        assert_eq!(pager, before_early_resume);

        let gate = Arc::new(Mutex::new(SamePageState {
            pager,
            continuations: [
                OneShotGate::new(0x5001, 100, 1).unwrap(),
                OneShotGate::new(0x5002, 101, 1).unwrap(),
            ],
            candidate_releases: [
                OneShotGate::new(0x5101, 1, 1).unwrap(),
                OneShotGate::new(0x5102, 2, 1).unwrap(),
            ],
        }));
        let mut joins = Vec::new();
        for candidate in 0..2 {
            let contender_gate = gate.clone();
            let contender_publications = publications.clone();
            joins.push(thread::spawn(move || {
                let mut state = contender_gate.lock().unwrap();
                match state.pager.commit_mapping_with(leader, || {
                    contender_publications.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(candidate)
                }) {
                    Ok((mapping, published_candidate)) => {
                        assert_eq!(published_candidate, candidate);
                        Some(mapping)
                    }
                    Err(CommitMappingError::Gate(PagerError::InvalidPhase)) => {
                        let release = &mut state.candidate_releases[candidate];
                        let receipt = release
                            .try_terminalize(release.token(), CandidateOutcome::Released)
                            .unwrap();
                        release.consume_terminal(&receipt).unwrap();
                        None
                    }
                    Err(error) => panic!("unexpected same-page commit result: {error:?}"),
                }
            }));
        }
        let results: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();
        assert_eq!(results.iter().flatten().count(), 1);
        assert_eq!(publications.load(Ordering::SeqCst), 1);
        let mapping = results.iter().flatten().next().copied().unwrap();

        let mut state = gate.lock().unwrap();
        for (index, ticket) in [leader, follower].into_iter().enumerate() {
            state
                .pager
                .terminalize(ticket, Some(mapping), ContinuationOutcome::Resolved)
                .unwrap();
            let continuation = &mut state.continuations[index];
            let receipt = continuation
                .try_terminalize(continuation.token(), ContinuationOutcome::Resolved)
                .unwrap();
            continuation.consume_terminal(&receipt).unwrap();
        }
        let losing_candidate = usize::from(results[0].is_some());
        assert_eq!(
            state.candidate_releases[losing_candidate].terminal(),
            Some(CandidateOutcome::Released)
        );
        assert_eq!(
            state.candidate_releases[1 - losing_candidate].terminal(),
            None
        );
        let release = &mut state.candidate_releases[losing_candidate];
        let before_duplicate_release = release.projection();
        assert_eq!(
            release.try_terminalize(release.token(), CandidateOutcome::Released),
            Err(OneShotError::AlreadyTerminal)
        );
        assert_eq!(release.projection(), before_duplicate_release);

        let before_duplicate_resume = state.pager;
        assert_eq!(
            state
                .pager
                .terminalize(follower, Some(mapping), ContinuationOutcome::Resolved),
            Err(PagerError::AlreadyTerminal)
        );
        assert_eq!(state.pager, before_duplicate_resume);
        let projection = state.pager.projection();
        assert_eq!(projection.mapping_publications, 1);
        assert_eq!(projection.terminalizations, 2);
        state.pager.begin_revoke().unwrap();
        state.pager.complete_revoke(true).unwrap();
        assert_eq!(state.pager.projection().lifecycle, PagerLifecycle::Revoked);
    });
    report(
        "same_page_single_publication",
        &[
            "resume-before-commit-rejected",
            "publication-closure-once",
            "losing-candidate-released-once",
            "continuations-terminal-once",
            "duplicate-resume-rejected",
            "scope-revoked",
        ],
    );
}

fn run_handler_crash(prepared: bool) {
    model(move || {
        let mut pager = PagerGate::<2>::new(5, 1, 10).unwrap();
        let leader = pager.register(key(), 100).unwrap().ticket();
        if prepared {
            pager.prepare_leader(leader).unwrap();
        }
        let gate = Arc::new(Mutex::new(pager));
        let commit_gate = gate.clone();
        let crash_gate = gate.clone();
        let commit = thread::spawn(move || {
            commit_gate
                .lock()
                .unwrap()
                .commit_mapping_with(leader, || Ok::<_, ()>(()))
                .map(|(mapping, ())| mapping)
        });
        let crash = thread::spawn(move || crash_gate.lock().unwrap().crash(1).unwrap());
        let mapping = commit.join().unwrap().ok();
        assert_eq!(crash.join().unwrap().binding_epoch, 2);

        let mut pager = gate.lock().unwrap();
        let before_old_resume = *pager;
        assert_eq!(pager.tickets()[0], Some(leader));
        assert_eq!(
            pager.terminalize(leader, mapping, ContinuationOutcome::Resolved),
            Err(PagerError::StaleBinding)
        );
        assert_eq!(*pager, before_old_resume);

        let mut continuation = OneShotGate::new(0x5003, 100, 1).unwrap();
        if let Some(mapping) = mapping {
            pager.terminalize_published_kernel(leader, mapping).unwrap();
            let receipt = continuation
                .try_terminalize(continuation.token(), ContinuationOutcome::Resolved)
                .unwrap();
            continuation.consume_terminal(&receipt).unwrap();
            let before_duplicate = *pager;
            assert_eq!(
                pager.terminalize_published_kernel(leader, mapping),
                Err(PagerError::AlreadyTerminal)
            );
            assert_eq!(*pager, before_duplicate);
        } else {
            pager.abort_orphan(leader).unwrap();
            let receipt = continuation
                .try_terminalize(continuation.token(), ContinuationOutcome::Aborted)
                .unwrap();
            continuation.consume_terminal(&receipt).unwrap();
            let before_duplicate = *pager;
            assert_eq!(pager.abort_orphan(leader), Err(PagerError::AlreadyTerminal));
            assert_eq!(*pager, before_duplicate);
        }
        assert!(matches!(
            continuation.terminal(),
            Some(ContinuationOutcome::Resolved | ContinuationOutcome::Aborted)
        ));
        assert_eq!(pager.projection().binding_epoch, 2);
        assert_eq!(pager.projection().terminalizations, 1);
        pager.begin_revoke().unwrap();
        pager.complete_revoke(true).unwrap();
        assert_eq!(pager.projection().lifecycle, PagerLifecycle::Revoked);
    });
}

#[test]
fn handler_crash_before_resolution() {
    run_handler_crash(false);
    run_handler_crash(true);
    report(
        "handler_crash_before_resolution",
        &[
            "crash-fences-old-binding",
            "committed-crash-kernel-terminal",
            "uncommitted-crash-aborts",
            "continuation-single-terminal",
            "no-implicit-adoption",
            "scope-revoked",
        ],
    );
}

#[test]
fn old_binding_reply_after_rebind() {
    model(|| {
        thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let mut pager = PagerGate::<2>::new(5, 1, 10).unwrap();
                let old = pager.register(key(), 100).unwrap().ticket();
                pager.prepare_leader(old).unwrap();
                let (mapping, ()) = pager.commit_mapping_with(old, || Ok::<_, ()>(())).unwrap();
                pager.crash(1).unwrap();
                let snapshot = pager.snapshot(11, 1).unwrap();
                pager.ready(snapshot).unwrap();

                let mut credits =
                    Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 1, k: 1, h: 0 }).unwrap();
                let credit_handle = credits.prepare_single_target().unwrap();
                let credits = Box::new(credits);
                let composite = Arc::new(Mutex::new(OldReplyComposite {
                    pager,
                    continuation: OneShotGate::new(0x5004, 100, 1).unwrap(),
                }));
                let reply_composite = composite.clone();
                let rebind_composite = composite.clone();
                let reply = thread::Builder::new()
                    .stack_size(4 * 1024 * 1024)
                    .spawn(move || {
                        let mut credits = credits;
                        let mut composite = reply_composite.lock().unwrap();
                        let before_pager = composite.pager;
                        let before_continuation = composite.continuation.projection();
                        let before_credit = credits.target_projection().unwrap();
                        let old_commit = composite.pager.commit_mapping_with(old, || {
                            credits.commit_single_target(credit_handle).map(|_| ())
                        });
                        assert_eq!(
                            old_commit,
                            Err(CommitMappingError::Gate(PagerError::StaleBinding))
                        );
                        assert_eq!(composite.pager, before_pager);
                        assert_eq!(composite.continuation.projection(), before_continuation);
                        assert_eq!(credits.target_projection().unwrap(), before_credit);
                        assert_eq!(
                            composite.pager.terminalize(
                                old,
                                Some(mapping),
                                ContinuationOutcome::Resolved
                            ),
                            Err(PagerError::StaleBinding)
                        );
                        assert_eq!(composite.pager, before_pager);
                        assert_eq!(composite.continuation.projection(), before_continuation);
                        assert_eq!(credits.target_projection().unwrap(), before_credit);
                        credits.check_invariants().unwrap();
                        credits
                    })
                    .unwrap();
                let rebind = thread::Builder::new()
                    .stack_size(4 * 1024 * 1024)
                    .spawn(move || rebind_composite.lock().unwrap().pager.rebind(11).unwrap())
                    .unwrap();
                let mut credits = reply.join().unwrap();
                assert_eq!(rebind.join().unwrap().binding_epoch, 2);

                let mut composite = composite.lock().unwrap();
                composite
                    .pager
                    .terminalize_published_kernel(old, mapping)
                    .unwrap();
                let continuation_token = composite.continuation.token();
                let receipt = composite
                    .continuation
                    .try_terminalize(continuation_token, ContinuationOutcome::Resolved)
                    .unwrap();
                composite.continuation.consume_terminal(&receipt).unwrap();
                let after_terminal = composite.pager;
                assert_eq!(
                    composite.pager.terminalize_published_kernel(old, mapping),
                    Err(PagerError::AlreadyTerminal)
                );
                assert_eq!(composite.pager, after_terminal);
                composite.pager.begin_revoke().unwrap();
                composite.pager.complete_revoke(true).unwrap();
                let selection = credits.close_all().unwrap();
                let credit_projection = credits.observation(&selection).unwrap().target;
                assert_eq!(credit_projection.phase, ScopePhase::Revoked);
                assert_eq!(credit_projection.live_effects, 0);
                assert_eq!(credit_projection.credits.free, 1);
                assert_eq!(credit_projection.credits.held, 0);
                assert_eq!(credit_projection.credits.committed, 0);
                credits.check_invariants().unwrap();
                assert_eq!(composite.pager.projection().mapping_publications, 1);
                assert_eq!(composite.pager.projection().terminalizations, 1);
                assert_eq!(
                    composite.pager.projection().lifecycle,
                    PagerLifecycle::Revoked
                );
            })
            .unwrap()
            .join()
            .unwrap();
    });
    report(
        "old_binding_reply_after_rebind",
        &[
            "mapping-committed-before-crash",
            "old-reply-failure-atomic",
            "old-reply-no-resume",
            "old-reply-credit-failure-atomic",
            "kernel-terminal-once",
            "scope-revoked",
        ],
    );
}

struct AdoptAbortState {
    pager: PagerGate<2>,
    decision: OneShotGate<Decision>,
}

#[test]
fn adopt_vs_abort_single_winner() {
    model(|| {
        let mut pager = PagerGate::<2>::new(5, 1, 10).unwrap();
        let old = pager.register(key(), 100).unwrap().ticket();
        pager.prepare_leader(old).unwrap();
        pager.crash(1).unwrap();
        let snapshot = pager.snapshot(11, 1).unwrap();
        pager.ready(snapshot).unwrap();
        pager.rebind(11).unwrap();
        let gate = Arc::new(Mutex::new(AdoptAbortState {
            pager,
            decision: OneShotGate::new(0x5005, 100, 1).unwrap(),
        }));
        let adopt_gate = gate.clone();
        let abort_gate = gate.clone();
        let adopt = thread::spawn(move || {
            let mut state = adopt_gate.lock().unwrap();
            let adopted = state.pager.adopt(old).ok();
            if adopted.is_some() {
                let token = state.decision.token();
                let receipt = state
                    .decision
                    .try_terminalize(token, Decision::Adopted)
                    .unwrap();
                state.decision.consume_terminal(&receipt).unwrap();
            }
            adopted
        });
        let abort = thread::spawn(move || {
            let mut state = abort_gate.lock().unwrap();
            let aborted = state.pager.abort_orphan(old).is_ok();
            if aborted {
                let token = state.decision.token();
                let receipt = state
                    .decision
                    .try_terminalize(token, Decision::Aborted)
                    .unwrap();
                state.decision.consume_terminal(&receipt).unwrap();
            }
            aborted
        });
        let adopted: Option<FaultTicket> = adopt.join().unwrap();
        let aborted = abort.join().unwrap();
        assert_ne!(adopted.is_some(), aborted);

        let mut state = gate.lock().unwrap();
        assert_eq!(
            state.decision.terminal(),
            Some(if adopted.is_some() {
                Decision::Adopted
            } else {
                Decision::Aborted
            })
        );
        state.pager.begin_revoke().unwrap();
        if let Some(adopted) = adopted {
            assert_eq!(adopted.binding_epoch(), 2);
            state
                .pager
                .terminalize(adopted, None, ContinuationOutcome::Aborted)
                .unwrap();
        }
        state.pager.complete_revoke(true).unwrap();
        assert_eq!(state.pager.projection().terminalizations, 1);
        assert_eq!(state.pager.projection().lifecycle, PagerLifecycle::Revoked);
        let before_late_action = state.pager;
        assert!(state.pager.adopt(old).is_err());
        assert_eq!(state.pager, before_late_action);
        assert!(state.pager.abort_orphan(old).is_err());
        assert_eq!(state.pager, before_late_action);
    });
    report(
        "adopt_vs_abort_single_winner",
        &[
            "decision-single-winner",
            "adoption-explicit-only",
            "ownership-authority-consumed-once",
            "continuation-terminal-once",
            "late-action-failure-atomic",
            "scope-revoked",
        ],
    );
}
