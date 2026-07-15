// SPDX-License-Identifier: MPL-2.0

use cser_transition_gates::handoff::{
    FreezeContext, HandoffAdmissionGate, HandoffGateError, HandoffId, LogPosition,
    OwnershipDecision, OwnershipDecisionReceipt, PrepareIntent,
};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};

const INITIAL_SCOPE_REVISION: u64 = 13;
const INITIAL_COHORT_SIZE: u64 = 1;

struct SourceState {
    gate: HandoffAdmissionGate,
    scope_revision: u64,
    cohort_size: u64,
}

impl SourceState {
    fn freeze_context(&self) -> FreezeContext {
        FreezeContext {
            registry_instance: 7,
            boot_incarnation: 8,
            scope_id: 9,
            scope_generation: 10,
            authority_epoch: 11,
            binding_epoch: 12,
            scope_revision: self.scope_revision,
            cohort_digest: 100 + self.cohort_size,
            classification_digest: 200 + self.cohort_size,
        }
    }
}

fn inputs() -> (PrepareIntent, FreezeContext) {
    let intent = PrepareIntent::new(
        HandoffId::new(1).unwrap(),
        2,
        LogPosition::new(3).unwrap(),
        4,
        5,
        6,
    )
    .unwrap();
    let context = SourceState {
        gate: HandoffAdmissionGate::new(),
        scope_revision: INITIAL_SCOPE_REVISION,
        cohort_size: INITIAL_COHORT_SIZE,
    }
    .freeze_context();
    (intent, context)
}

#[test]
fn freeze_and_source_mutation_have_one_outer_lock_winner() {
    model(|| {
        let (intent, _) = inputs();
        let state = Arc::new(Mutex::new(SourceState {
            gate: HandoffAdmissionGate::new(),
            scope_revision: INITIAL_SCOPE_REVISION,
            cohort_size: INITIAL_COHORT_SIZE,
        }));
        let freezer = Arc::clone(&state);
        let source = Arc::clone(&state);
        let freeze = thread::spawn(move || {
            let mut state = freezer.lock().unwrap();
            let context = state.freeze_context();
            state.gate.freeze(intent, context)
        });
        let mutate = thread::spawn(move || {
            let mut state = source.lock().unwrap();
            state.gate.require_open()?;
            state.scope_revision += 1;
            state.cohort_size += 1;
            Ok::<(), HandoffGateError>(())
        });
        let freeze = freeze.join().unwrap().unwrap();
        let mutate = mutate.join().unwrap();
        let state = state.lock().unwrap();

        match mutate {
            Ok(()) => {
                assert_eq!(state.scope_revision, INITIAL_SCOPE_REVISION + 1);
                assert_eq!(state.cohort_size, INITIAL_COHORT_SIZE + 1);
            }
            Err(HandoffGateError::AdmissionFrozen) => {
                assert_eq!(state.scope_revision, INITIAL_SCOPE_REVISION);
                assert_eq!(state.cohort_size, INITIAL_COHORT_SIZE);
            }
            Err(error) => panic!("unexpected source mutation error: {error:?}"),
        }
        assert_eq!(freeze.context(), state.freeze_context());
        assert_eq!(
            state.gate.require_open(),
            Err(HandoffGateError::AdmissionFrozen)
        );
    });
}

#[test]
fn abort_and_commit_cannot_both_win() {
    model(|| {
        let (intent, context) = inputs();
        let mut gate = HandoffAdmissionGate::new();
        let freeze = gate.freeze(intent, context).unwrap();
        let abort = OwnershipDecisionReceipt::new(
            freeze,
            LogPosition::new(16).unwrap(),
            intent.request_digest(),
            OwnershipDecision::Abort,
        )
        .unwrap();
        let commit = OwnershipDecisionReceipt::new(
            freeze,
            LogPosition::new(17).unwrap(),
            intent.request_digest(),
            OwnershipDecision::Commit,
        )
        .unwrap();
        let gate = Arc::new(Mutex::new(gate));
        let first = Arc::clone(&gate);
        let second = Arc::clone(&gate);
        let abort_result = thread::spawn(move || first.lock().unwrap().accept_decision(abort));
        let commit_result = thread::spawn(move || second.lock().unwrap().accept_decision(commit));
        let abort_result = abort_result.join().unwrap();
        let commit_result = commit_result.join().unwrap();
        assert!(matches!(
            (abort_result, commit_result),
            (
                Ok(OwnershipDecision::Abort),
                Err(HandoffGateError::ConflictingDecision)
            ) | (
                Err(HandoffGateError::ConflictingDecision),
                Ok(OwnershipDecision::Commit)
            )
        ));
    });
}
