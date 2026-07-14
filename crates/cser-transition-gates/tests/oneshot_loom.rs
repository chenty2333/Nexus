// SPDX-License-Identifier: MPL-2.0

extern crate alloc;

#[path = "../../../kernel/nexus-ostd/src/cser/effect_registry.rs"]
mod effect_registry;

use alloc::vec;
use cser_transition_gates::{
    deadline::{DeadlineError, DeadlineGate, DeadlineToken},
    oneshot::{OneShotError, OneShotGate, TerminalReceipt as OneShotTerminalReceipt},
};
use effect_registry::{
    CommitMetadata, CommitOutcome, CreditCharge, CreditClass, CreditLimit, EffectKey,
    EffectRegistry, OperationClass, PortalHandle, PublicationMode, RegisterRequest, RegistryError,
    ResourceKey, RevokeDisposition, RevokeSelection, ScopeConfig, ScopeKey, ScopePhase,
    SyscallDescriptor, TaskKey, TerminalOutcome, TerminalRequest,
};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Wake,
    Timeout,
    Cancel,
    Resolve,
    Abort,
}

impl Outcome {
    const fn registry_terminal(self) -> TerminalOutcome {
        match self {
            Self::Wake | Self::Resolve => TerminalOutcome::Completed,
            Self::Timeout | Self::Cancel | Self::Abort => TerminalOutcome::Aborted,
        }
    }

    const fn registry_result(self) -> i64 {
        match self.registry_terminal() {
            TerminalOutcome::Completed => 1,
            TerminalOutcome::IndeterminateAfterReset => -5,
            TerminalOutcome::Aborted => -125,
        }
    }

    const fn commits(self) -> bool {
        matches!(self, Self::Wake | Self::Resolve)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RegistryContinuation {
    registry: EffectRegistry,
    scope: ScopeKey,
    task: TaskKey,
    resource: ResourceKey,
    effect: EffectKey,
    handle: PortalHandle,
    selection: Option<RevokeSelection>,
}

impl RegistryContinuation {
    fn new() -> Self {
        let scope = ScopeKey::new(0x7101, 1);
        let task = TaskKey::new(0x7102, 1);
        let resource = ResourceKey::new(0x71, 1, 1);
        let credit = CreditClass::new(0x71);
        let mut registry = EffectRegistry::new();
        registry
            .create_scope(ScopeConfig {
                key: scope,
                authority_epoch: 1,
                binding_epoch: 1,
                supervisor: task,
                credits: vec![CreditLimit::new(credit, 1)],
            })
            .unwrap();
        let registered = registry
            .register(RegisterRequest {
                scope,
                task,
                operation: OperationClass::new(0x71),
                descriptor: SyscallDescriptor::new(202, [0; 6]),
                resources: vec![resource],
                credits: vec![CreditCharge::new(credit, 1)],
                publication: PublicationMode::Required,
            })
            .unwrap();
        let effect = registered.identity.effect();
        registry.prepare(task, registered.handle).unwrap();
        Self {
            registry,
            scope,
            task,
            resource,
            effect,
            handle: registered.handle,
            selection: None,
        }
    }

    fn failure_atomic_projection(&self) -> (String, Option<RevokeSelection>) {
        (
            self.registry.failure_atomic_projection(),
            self.selection.clone(),
        )
    }

    fn terminalize_and_close(&mut self, winner: &OneShotTerminalReceipt<Outcome>) {
        assert_eq!(winner.token().instance_id(), self.scope.id());
        assert_eq!(winner.token().id(), self.effect.id());
        assert_eq!(winner.token().generation(), self.effect.generation());
        let outcome = winner.outcome();
        let expected_terminal = outcome.registry_terminal();
        let commit = if outcome.commits() {
            match self
                .registry
                .commit(
                    self.task,
                    self.handle,
                    CommitMetadata::new(outcome.registry_result(), 1),
                )
                .unwrap()
            {
                CommitOutcome::Applied(receipt) => {
                    assert_eq!(receipt.effect(), self.effect);
                    assert_eq!(receipt.result(), outcome.registry_result());
                    Some(receipt)
                }
                CommitOutcome::AlreadyCommitted(_) => {
                    panic!("one-shot winner must own the first registry commit")
                }
            }
        } else {
            None
        };
        let selection = self.registry.revoke_begin(self.scope).unwrap();
        let selected = self.registry.revoke_next(&selection).unwrap().unwrap();
        assert_eq!(selected.effect, self.effect);
        assert!(selected.publication_required);
        match (&selected.disposition, &commit) {
            (RevokeDisposition::Drain(selected), Some(committed)) => {
                assert_eq!(selected, committed)
            }
            (RevokeDisposition::Abort, None) => {}
            _ => panic!("typed winner and registry revoke disposition diverged"),
        }
        let request = match commit {
            Some(commit) => {
                TerminalRequest::completed_by(outcome.registry_result(), commit.clone())
            }
            None => TerminalRequest::aborted(outcome.registry_result()),
        };
        let terminal = self
            .registry
            .stage_revoke_terminal(&selection, self.effect, request.clone())
            .unwrap();
        assert_eq!(terminal.receipt.outcome(), expected_terminal);
        assert_eq!(terminal.receipt.result(), outcome.registry_result());
        let ticket = terminal.publication.expect("wait publication is explicit");
        assert_eq!(ticket.outcome(), expected_terminal);
        assert_eq!(ticket.result(), outcome.registry_result());

        let before_ack = self.registry.scope_projection(self.scope).unwrap();
        assert_eq!(before_ack.phase, ScopePhase::Closing);
        assert_eq!(before_ack.live_effects, 0);
        assert_eq!(before_ack.pending_publications, 1);
        assert_eq!(before_ack.credits.free, 0);
        assert_eq!(before_ack.credits.held, u64::from(!outcome.commits()));
        assert_eq!(before_ack.credits.committed, u64::from(outcome.commits()));

        self.registry.acknowledge_publication(&ticket).unwrap();
        let after_ack = self.registry.failure_atomic_projection();
        assert_eq!(
            self.registry.acknowledge_publication(&ticket),
            Err(RegistryError::InvalidPublication)
        );
        assert_eq!(self.registry.failure_atomic_projection(), after_ack);
        let before_duplicate_terminal = self.registry.failure_atomic_projection();
        assert_eq!(
            self.registry
                .stage_revoke_terminal(&selection, self.effect, request),
            Err(RegistryError::AlreadyTerminal)
        );
        assert_eq!(
            self.registry.failure_atomic_projection(),
            before_duplicate_terminal
        );
        assert!(self.registry.revoke_next(&selection).unwrap().is_none());
        self.registry.revoke_complete(&selection).unwrap();
        self.selection = Some(selection);
    }

    fn registry_terminal(&self) -> TerminalOutcome {
        self.registry
            .effect_view(self.effect)
            .unwrap()
            .terminal
            .as_ref()
            .expect("winner terminal receipt is retained")
            .outcome()
    }

    fn registry_result(&self) -> i64 {
        self.registry
            .effect_view(self.effect)
            .unwrap()
            .terminal
            .as_ref()
            .expect("winner terminal receipt is retained")
            .result()
    }

    fn assert_closed(&self, winner: Outcome) {
        let projection = self.registry.scope_projection(self.scope).unwrap();
        assert_eq!(projection.phase, ScopePhase::Revoked);
        assert_eq!(projection.live_effects, 0);
        assert_eq!(projection.pending_publications, 0);
        assert_eq!(projection.credits.capacity, 1);
        assert_eq!(projection.credits.free, 1);
        assert_eq!(projection.credits.held, 0);
        assert_eq!(projection.credits.committed, 0);
        assert!(self.registry.effects_for_scope(self.scope).is_empty());
        assert!(self.registry.effects_for_task(self.task).is_empty());
        assert!(self.registry.effects_for_resource(self.resource).is_empty());
        assert_eq!(self.registry_terminal(), winner.registry_terminal());
        assert_eq!(self.registry_result(), winner.registry_result());
        assert!(self.selection.is_some());
        self.registry.check_invariants().unwrap();
    }
}

struct CompositeWait {
    terminal: OneShotGate<Outcome>,
    deadline: Option<(DeadlineGate, DeadlineToken)>,
    continuation: RegistryContinuation,
}

impl CompositeWait {
    fn new(with_deadline: bool) -> Self {
        let deadline = with_deadline.then(|| {
            let mut gate = DeadlineGate::new(1).unwrap();
            let token = gate.arm(10).unwrap();
            (gate, token)
        });
        let continuation = RegistryContinuation::new();
        let terminal = OneShotGate::new(
            continuation.scope.id(),
            continuation.effect.id(),
            continuation.effect.generation(),
        )
        .unwrap();
        let token = terminal.token();
        assert_eq!(token.instance_id(), continuation.scope.id());
        assert_eq!(token.id(), continuation.effect.id());
        assert_eq!(token.generation(), continuation.effect.generation());
        Self {
            terminal,
            deadline,
            continuation,
        }
    }

    fn apply(&mut self, outcome: Outcome) -> bool {
        let before_continuation = self.continuation.failure_atomic_projection();
        let token = self.terminal.token();
        if outcome == Outcome::Timeout {
            let (deadline, deadline_token) = self.deadline.as_mut().unwrap();
            match deadline.expire(*deadline_token, 10) {
                Ok(_) => {}
                Err(DeadlineError::NotArmed) => {
                    assert_eq!(
                        self.terminal.try_terminalize(token, outcome),
                        Err(OneShotError::AlreadyTerminal)
                    );
                    assert_eq!(
                        self.continuation.failure_atomic_projection(),
                        before_continuation
                    );
                    return false;
                }
                Err(error) => panic!("unexpected timeout result: {error:?}"),
            }
        }

        match self.terminal.try_terminalize(token, outcome) {
            Ok(receipt) => {
                assert_eq!(receipt.token(), token);
                assert_eq!(receipt.outcome(), outcome);
                self.terminal.consume_terminal(&receipt).unwrap();
                assert!(self.terminal.projection().receipt_consumed());
                if outcome != Outcome::Timeout
                    && let Some((deadline, deadline_token)) = self.deadline.as_mut()
                {
                    deadline.cancel(*deadline_token).unwrap();
                }
                self.continuation.terminalize_and_close(&receipt);
                true
            }
            Err(OneShotError::AlreadyTerminal) => {
                assert_eq!(
                    self.continuation.failure_atomic_projection(),
                    before_continuation
                );
                false
            }
            Err(error) => panic!("unexpected one-shot result: {error:?}"),
        }
    }
}

fn assert_same_counter_foreign_faults_failure_atomic() {
    let mut first = OneShotGate::new(0x7101, 0x71ff, 1).unwrap();
    let mut second = OneShotGate::new(0x7201, 0x71ff, 1).unwrap();
    let first_token = first.token();
    let second_token = second.token();
    assert_eq!(first_token.id(), second_token.id());
    assert_eq!(first_token.generation(), second_token.generation());
    assert_ne!(first_token.instance_id(), second_token.instance_id());

    let before_first = first.projection();
    let before_second = second.projection();
    assert_eq!(
        first.try_terminalize(second_token, Outcome::Wake),
        Err(OneShotError::ForeignInstance)
    );
    assert_eq!(first.projection(), before_first);
    assert_eq!(
        second.try_terminalize(first_token, Outcome::Abort),
        Err(OneShotError::ForeignInstance)
    );
    assert_eq!(second.projection(), before_second);

    let first_receipt = first.try_terminalize(first_token, Outcome::Wake).unwrap();
    let second_receipt = second
        .try_terminalize(second_token, Outcome::Abort)
        .unwrap();
    let before_first = first.projection();
    let before_second = second.projection();
    assert_eq!(
        first.consume_terminal(&second_receipt),
        Err(OneShotError::ForeignInstance)
    );
    assert_eq!(first.projection(), before_first);
    assert_eq!(
        second.consume_terminal(&first_receipt),
        Err(OneShotError::ForeignInstance)
    );
    assert_eq!(second.projection(), before_second);

    let mut reconstructed = OneShotGate::new(0x7101, 0x71ff, 1).unwrap();
    let reconstructed_receipt = reconstructed
        .try_terminalize(reconstructed.token(), Outcome::Wake)
        .unwrap();
    let before_first = first.projection();
    let before_reconstructed = reconstructed.projection();
    assert_eq!(
        first.consume_terminal(&reconstructed_receipt),
        Err(OneShotError::ForeignInstance)
    );
    assert_eq!(first.projection(), before_first);
    assert_eq!(
        reconstructed.consume_terminal(&first_receipt),
        Err(OneShotError::ForeignInstance)
    );
    assert_eq!(reconstructed.projection(), before_reconstructed);

    first.consume_terminal(&first_receipt).unwrap();
    second.consume_terminal(&second_receipt).unwrap();
    reconstructed
        .consume_terminal(&reconstructed_receipt)
        .unwrap();
    let before_replay = first.projection();
    assert_eq!(
        first.consume_terminal(&first_receipt),
        Err(OneShotError::ReceiptAlreadyConsumed)
    );
    assert_eq!(first.projection(), before_replay);
}

fn run_single_winner(left: Outcome, right: Outcome, with_deadline: bool) {
    model(move || {
        assert_same_counter_foreign_faults_failure_atomic();
        let gate = Arc::new(Mutex::new(CompositeWait::new(with_deadline)));
        let left_gate = gate.clone();
        let right_gate = gate.clone();
        let left_result = thread::spawn(move || left_gate.lock().unwrap().apply(left));
        let right_result = thread::spawn(move || right_gate.lock().unwrap().apply(right));
        assert_ne!(left_result.join().unwrap(), right_result.join().unwrap());

        let mut gate = gate.lock().unwrap();
        let winner = gate.terminal.terminal().unwrap();
        assert!(winner == left || winner == right);
        assert_eq!(
            gate.continuation.registry_terminal(),
            winner.registry_terminal()
        );
        assert_eq!(
            gate.continuation.registry_result(),
            winner.registry_result()
        );
        let before_duplicate_continuation = gate.continuation.failure_atomic_projection();
        let before_duplicate = gate.terminal.projection();
        let token = gate.terminal.token();
        assert_eq!(
            gate.terminal.try_terminalize(token, left),
            Err(OneShotError::AlreadyTerminal)
        );
        assert_eq!(gate.terminal.projection(), before_duplicate);
        assert_eq!(
            gate.continuation.failure_atomic_projection(),
            before_duplicate_continuation
        );
        assert_eq!(
            gate.terminal.try_terminalize(token, right),
            Err(OneShotError::AlreadyTerminal)
        );
        assert_eq!(gate.terminal.projection(), before_duplicate);
        assert_eq!(
            gate.continuation.failure_atomic_projection(),
            before_duplicate_continuation
        );
        if let Some((deadline, _)) = gate.deadline {
            assert_eq!(deadline.current(), None);
        }
        gate.continuation.assert_closed(winner);
    });
}

fn report(case: &str, assertions: &[&str]) {
    println!("STAGE7B_CONCURRENCY case={case} status=PASS");
    for assertion in assertions {
        println!("STAGE7B_CONCURRENCY_ASSERT case={case} assertion={assertion} status=PASS");
    }
}

#[test]
fn wake_vs_timeout_single_winner() {
    run_single_winner(Outcome::Wake, Outcome::Timeout, true);
    report(
        "wake_vs_timeout_single_winner",
        &[
            "oneshot-single-terminal",
            "oneshot-receipt-provenance",
            "deadline-single-consume",
            "registry-terminal-once",
            "typed-receipt-registry-disposition",
            "publication-ack-once",
            "credits-fully-returned",
            "reverse-indexes-empty",
            "scope-revoked",
        ],
    );
}

#[test]
fn cancel_vs_wake_single_winner() {
    run_single_winner(Outcome::Cancel, Outcome::Wake, true);
    report(
        "cancel_vs_wake_single_winner",
        &[
            "oneshot-single-terminal",
            "oneshot-receipt-provenance",
            "late-wake-rejected",
            "typed-receipt-registry-disposition",
            "publication-ack-once",
            "credits-fully-returned",
            "reverse-indexes-empty",
            "scope-revoked",
        ],
    );
}

#[test]
fn resolve_vs_abort_one_shot() {
    run_single_winner(Outcome::Resolve, Outcome::Abort, false);
    report(
        "resolve_vs_abort_one_shot",
        &[
            "oneshot-single-terminal",
            "oneshot-receipt-provenance",
            "second-terminal-rejected",
            "token-reuse-rejected",
            "typed-receipt-registry-disposition",
            "publication-ack-once",
            "credits-fully-returned",
            "reverse-indexes-empty",
            "scope-revoked",
        ],
    );
}
