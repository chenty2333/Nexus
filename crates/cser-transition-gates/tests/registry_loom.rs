// SPDX-License-Identifier: MPL-2.0

extern crate alloc;

#[path = "../../../kernel/nexus-ostd/src/cser/effect_registry.rs"]
mod effect_registry;

use alloc::boxed::Box;
use cser_transition_gates::{
    deadline::{DeadlineError, DeadlineGate, DeadlineToken},
    oneshot::{
        OneShotError, OneShotGate, OneShotProjection, TerminalReceipt as OneShotTerminalReceipt,
    },
};
use effect_registry::{
    CommitOutcome, PortalHandle, RegistryError, RevokeSelection, ScopePhase, Stage7bActiveFixture,
    Stage7bFixtureConfig, TerminalOutcome,
};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};

fn report(case: &str, assertions: &[&str]) {
    println!("STAGE7B_CONCURRENCY case={case} status=PASS");
    for assertion in assertions {
        println!("STAGE7B_CONCURRENCY_ASSERT case={case} assertion={assertion} status=PASS");
    }
}

fn run_commit_revoke_race(n: usize, h: usize) {
    model(move || {
        thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let mut fixture =
                    Stage7bActiveFixture::new(Stage7bFixtureConfig { n, k: 1, h }).unwrap();
                let handle = fixture.prepare_single_target().unwrap();
                let fixture = Arc::new(Mutex::new(fixture));
                let commit_fixture = fixture.clone();
                let revoke_fixture = fixture.clone();
                let commit = thread::spawn(move || {
                    commit_fixture.lock().unwrap().commit_single_target(handle)
                });
                let revoke = thread::spawn(move || {
                    let mut fixture = revoke_fixture.lock().unwrap();
                    let selection = fixture.begin().unwrap();
                    fixture.finish_revoke(&selection).unwrap();
                    selection
                });
                let commit = commit.join().unwrap();
                let selection = revoke.join().unwrap();
                let mut fixture = fixture.lock().unwrap();
                let terminal = fixture.single_target_terminal(handle).unwrap();
                match commit {
                    Ok(CommitOutcome::Applied(_) | CommitOutcome::AlreadyCommitted(_)) => {
                        assert_eq!(terminal, TerminalOutcome::Completed);
                    }
                    Err(error) => {
                        assert!(matches!(
                            error,
                            RegistryError::StaleAuthority | RegistryError::ScopeNotActive
                        ));
                        assert_eq!(terminal, TerminalOutcome::Aborted);
                    }
                }
                let observation = fixture.observation(&selection).unwrap();
                assert_eq!(observation.target.phase, ScopePhase::Revoked);
                assert_eq!(observation.target.live_effects, 0);
                assert_eq!(observation.target.pending_publications, 0);
                assert_eq!(observation.work.target_count, 1);
                assert_eq!(observation.work.next_calls, 2);
                assert_eq!(observation.work.head_selections, 1);
                assert_eq!(observation.work.terminalized, 1);
                assert_eq!(observation.work.completion_members_checked, 1);
                assert_eq!(observation.work.target_index_removals, 1);
                assert_eq!(observation.work.pending_targets, 0);
                assert_eq!(observation.work.unrelated_effect_visits, 0);
                assert_eq!(observation.work.history_effect_visits, 0);
                assert_eq!(observation.target.credits.capacity, 1);
                assert_eq!(observation.target.credits.free, 1);
                assert_eq!(observation.target.credits.held, 0);
                assert_eq!(observation.target.credits.committed, 0);
                fixture.check_invariants().unwrap();

                let before_late_commit = fixture.clone();
                assert!(matches!(
                    fixture.commit_single_target(handle),
                    Err(RegistryError::StaleAuthority | RegistryError::ScopeNotActive)
                ));
                assert_eq!(*fixture, before_late_commit);
                let before_duplicate_completion = fixture.clone();
                assert!(fixture.finish_revoke(&selection).is_err());
                assert_eq!(*fixture, before_duplicate_completion);
            })
            .unwrap()
            .join()
            .unwrap();
    });
}

#[test]
fn commit_vs_revoke_linearization() {
    run_commit_revoke_race(1, 0);
    report(
        "commit_vs_revoke_linearization",
        &[
            "commit-revoke-single-order",
            "closed-epoch-commit-rejected",
            "committed-effect-drained",
            "uncommitted-effect-aborted",
            "reverse-index-empty",
            "scope-revoked",
        ],
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaitTerminal {
    Wake,
    Timeout,
    Revoked,
}

impl WaitTerminal {
    const fn registry_terminal(self) -> TerminalOutcome {
        match self {
            Self::Wake => TerminalOutcome::Completed,
            Self::Timeout | Self::Revoked => TerminalOutcome::Aborted,
        }
    }

    const fn commits(self) -> bool {
        matches!(self, Self::Wake)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LateActivity {
    Wake,
    Timer,
}

struct DeferredState {
    fixture: Stage7bActiveFixture,
    terminal: OneShotGate<WaitTerminal>,
    deadline: DeadlineGate,
    deadline_token: DeadlineToken,
    handle: PortalHandle,
    selection: Option<RevokeSelection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeferredProjection {
    fixture: Stage7bActiveFixture,
    terminal: OneShotProjection<WaitTerminal>,
    deadline: DeadlineGate,
    deadline_token: DeadlineToken,
    handle: PortalHandle,
    selection: Option<RevokeSelection>,
}

impl DeferredState {
    fn new() -> Self {
        let mut fixture =
            Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 8, k: 1, h: 4 }).unwrap();
        let handle = fixture.prepare_single_target().unwrap();
        let mut deadline = DeadlineGate::new(0x7201).unwrap();
        let deadline_token = deadline.arm(10).unwrap();
        let terminal = OneShotGate::new(
            handle.scope().id(),
            handle.effect().id(),
            handle.effect().generation(),
        )
        .unwrap();
        let token = terminal.token();
        assert_eq!(token.instance_id(), handle.scope().id());
        assert_eq!(token.id(), handle.effect().id());
        assert_eq!(token.generation(), handle.effect().generation());
        Self {
            fixture,
            terminal,
            deadline,
            deadline_token,
            handle,
            selection: None,
        }
    }

    fn projection(&self) -> DeferredProjection {
        DeferredProjection {
            fixture: self.fixture.clone(),
            terminal: self.terminal.projection(),
            deadline: self.deadline,
            deadline_token: self.deadline_token,
            handle: self.handle,
            selection: self.selection.clone(),
        }
    }

    fn close_from_winner(&mut self, winner: &OneShotTerminalReceipt<WaitTerminal>) {
        assert_eq!(winner.token(), self.terminal.token());
        assert_eq!(winner.token().instance_id(), self.handle.scope().id());
        assert_eq!(winner.token().id(), self.handle.effect().id());
        assert_eq!(
            winner.token().generation(),
            self.handle.effect().generation()
        );
        assert!(self.terminal.projection().receipt_consumed());
        let outcome = winner.outcome();
        if outcome.commits() {
            match self.fixture.commit_single_target(self.handle).unwrap() {
                CommitOutcome::Applied(receipt) => assert_eq!(receipt.result(), 1),
                CommitOutcome::AlreadyCommitted(_) => {
                    panic!("wake winner must own the first registry commit")
                }
            }
        }
        let selection = self.fixture.begin().unwrap();
        self.fixture.finish_revoke(&selection).unwrap();
        assert_eq!(
            self.fixture.single_target_terminal(self.handle).unwrap(),
            outcome.registry_terminal()
        );
        self.selection = Some(selection);
    }

    fn revoke(&mut self) -> bool {
        let before = Box::new(self.projection());
        let token = self.terminal.token();
        match self.terminal.try_terminalize(token, WaitTerminal::Revoked) {
            Ok(receipt) => {
                assert_eq!(receipt.outcome(), WaitTerminal::Revoked);
                self.terminal.consume_terminal(&receipt).unwrap();
                self.deadline.cancel(self.deadline_token).unwrap();
                self.close_from_winner(&receipt);
                true
            }
            Err(OneShotError::AlreadyTerminal) => {
                assert_eq!(self.deadline.current(), None);
                assert_eq!(self.projection(), *before);
                false
            }
            Err(error) => panic!("unexpected revoke terminal result: {error:?}"),
        }
    }

    fn activity(&mut self, activity: LateActivity) -> bool {
        let before = Box::new(self.projection());
        let token = self.terminal.token();
        match activity {
            LateActivity::Wake => match self.terminal.try_terminalize(token, WaitTerminal::Wake) {
                Ok(receipt) => {
                    assert_eq!(receipt.outcome(), WaitTerminal::Wake);
                    self.terminal.consume_terminal(&receipt).unwrap();
                    self.deadline.cancel(self.deadline_token).unwrap();
                    self.close_from_winner(&receipt);
                    true
                }
                Err(OneShotError::AlreadyTerminal) => {
                    assert_eq!(self.projection(), *before);
                    false
                }
                Err(error) => panic!("unexpected wake result: {error:?}"),
            },
            LateActivity::Timer => match self.deadline.expire(self.deadline_token, 10) {
                Ok(expiry) => {
                    assert_eq!(expiry.token(), self.deadline_token);
                    let receipt = self
                        .terminal
                        .try_terminalize(token, WaitTerminal::Timeout)
                        .unwrap();
                    assert_eq!(receipt.outcome(), WaitTerminal::Timeout);
                    self.terminal.consume_terminal(&receipt).unwrap();
                    self.close_from_winner(&receipt);
                    true
                }
                Err(DeadlineError::NotArmed) => {
                    assert_eq!(
                        self.terminal.try_terminalize(token, WaitTerminal::Timeout),
                        Err(OneShotError::AlreadyTerminal)
                    );
                    assert_eq!(self.projection(), *before);
                    false
                }
                Err(error) => panic!("unexpected timer result: {error:?}"),
            },
        }
    }

    fn assert_final(&self) {
        let selection = self.selection.as_ref().unwrap();
        let observation = self.fixture.observation(selection).unwrap();
        assert_eq!(observation.target.phase, ScopePhase::Revoked);
        assert_eq!(observation.target.live_effects, 0);
        assert_eq!(observation.target.pending_publications, 0);
        assert_eq!(observation.target.credits.capacity, 1);
        assert_eq!(observation.target.credits.free, 1);
        assert_eq!(observation.target.credits.held, 0);
        assert_eq!(observation.target.credits.committed, 0);
        assert_eq!(observation.work.target_count, 1);
        assert_eq!(observation.work.terminalized, 1);
        assert_eq!(observation.work.target_index_removals, 1);
        assert_eq!(observation.work.pending_targets, 0);
        assert_eq!(observation.work.unrelated_effect_visits, 0);
        assert_eq!(observation.work.history_effect_visits, 0);
        assert_eq!(self.deadline.current(), None);
        let terminal = self.terminal.terminal().unwrap();
        assert!(self.terminal.projection().receipt_consumed());
        assert_eq!(
            self.fixture.single_target_terminal(self.handle).unwrap(),
            terminal.registry_terminal()
        );
        self.fixture.check_invariants().unwrap();
    }
}

fn assert_foreign_wait_receipts_failure_atomic() {
    let mut first = OneShotGate::new(0x7b01, 0x7bff, 1).unwrap();
    let mut second = OneShotGate::new(0x7b02, 0x7bff, 1).unwrap();
    let first_token = first.token();
    let second_token = second.token();
    let first_before = first.projection();
    let second_before = second.projection();
    assert_eq!(
        first.try_terminalize(second_token, WaitTerminal::Wake),
        Err(OneShotError::ForeignInstance)
    );
    assert_eq!(first.projection(), first_before);
    assert_eq!(
        second.try_terminalize(first_token, WaitTerminal::Revoked),
        Err(OneShotError::ForeignInstance)
    );
    assert_eq!(second.projection(), second_before);

    let first_receipt = first
        .try_terminalize(first_token, WaitTerminal::Wake)
        .unwrap();
    let second_receipt = second
        .try_terminalize(second_token, WaitTerminal::Revoked)
        .unwrap();
    let first_before = first.projection();
    let second_before = second.projection();
    assert_eq!(
        first.consume_terminal(&second_receipt),
        Err(OneShotError::ForeignInstance)
    );
    assert_eq!(first.projection(), first_before);
    assert_eq!(
        second.consume_terminal(&first_receipt),
        Err(OneShotError::ForeignInstance)
    );
    assert_eq!(second.projection(), second_before);

    let mut reconstructed = OneShotGate::new(0x7b01, 0x7bff, 1).unwrap();
    let reconstructed_receipt = reconstructed
        .try_terminalize(reconstructed.token(), WaitTerminal::Wake)
        .unwrap();
    let first_before = first.projection();
    let reconstructed_before = reconstructed.projection();
    assert_eq!(
        first.consume_terminal(&reconstructed_receipt),
        Err(OneShotError::ForeignInstance)
    );
    assert_eq!(first.projection(), first_before);
    assert_eq!(
        reconstructed.consume_terminal(&first_receipt),
        Err(OneShotError::ForeignInstance)
    );
    assert_eq!(reconstructed.projection(), reconstructed_before);

    first.consume_terminal(&first_receipt).unwrap();
    second.consume_terminal(&second_receipt).unwrap();
    reconstructed
        .consume_terminal(&reconstructed_receipt)
        .unwrap();
    let before_replay = second.projection();
    assert_eq!(
        second.consume_terminal(&second_receipt),
        Err(OneShotError::ReceiptAlreadyConsumed)
    );
    assert_eq!(second.projection(), before_replay);
}

fn run_revoke_vs_activity(activity: LateActivity) {
    model(move || {
        assert_foreign_wait_receipts_failure_atomic();
        let state = thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| Arc::new(Mutex::new(DeferredState::new())))
            .unwrap()
            .join()
            .unwrap();
        let revoke_state = state.clone();
        let activity_state = state.clone();
        let revoke = thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || revoke_state.lock().unwrap().revoke())
            .unwrap();
        let late = thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || activity_state.lock().unwrap().activity(activity))
            .unwrap();
        let revoke_won = revoke.join().unwrap();
        let activity_won = late.join().unwrap();
        assert_ne!(revoke_won, activity_won);

        let mut state = state.lock().unwrap();
        state.assert_final();
        let before_late_wake = state.projection();
        assert!(!state.activity(LateActivity::Wake));
        assert_eq!(state.projection(), before_late_wake);
        let before_late_timer = state.projection();
        assert!(!state.activity(LateActivity::Timer));
        assert_eq!(state.projection(), before_late_timer);
        let before_late_revoke = state.projection();
        assert!(!state.revoke());
        assert_eq!(state.projection(), before_late_revoke);
    });
}

#[test]
fn revoke_deferred_wait_timer() {
    run_revoke_vs_activity(LateActivity::Wake);
    run_revoke_vs_activity(LateActivity::Timer);
    report(
        "revoke_deferred_wait_timer",
        &[
            "target-cohort-only",
            "oneshot-receipt-provenance",
            "typed-receipt-registry-disposition",
            "late-wake-failure-atomic",
            "late-timer-failure-atomic",
            "credits-fully-returned",
            "reverse-index-empty",
            "unrelated-history-unvisited",
            "scope-revoked",
        ],
    );
}

#[test]
fn budget_commit_vs_abort_conservation() {
    run_commit_revoke_race(2, 1);
    report(
        "budget_commit_vs_abort_conservation",
        &[
            "single-credit-disposition",
            "free-held-committed-conserved",
            "credit-returned-once",
            "duplicate-completion-rejected",
            "abort-after-commit-not-reported",
            "scope-revoked",
        ],
    );
}
