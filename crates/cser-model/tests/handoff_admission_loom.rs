#[path = "handoff_admission_support/mod.rs"]
mod support;

use cser_model::handoff_admission::{EffectDisposition, HandoffAdmissionError, HandoffProgress};
use loom::sync::{Arc, Mutex};
use loom::thread;
use support::{abort_receipt, commit_receipt, intent, model};

#[test]
fn freeze_and_first_commit_have_one_serialized_winner() {
    loom::model(|| {
        let mut initial = model();
        let effect = initial.register_effect().unwrap();
        initial.prepare_effect(effect).unwrap();
        initial.record_intent(intent()).unwrap();
        let shared = Arc::new(Mutex::new(initial));

        let freeze_model = Arc::clone(&shared);
        let freeze = thread::spawn(move || freeze_model.lock().unwrap().freeze_admission());
        let commit_model = Arc::clone(&shared);
        let commit = thread::spawn(move || commit_model.lock().unwrap().commit_effect(effect));

        let freeze_result = freeze.join().unwrap();
        let commit_result = commit.join().unwrap();
        assert!(freeze_result.is_ok());
        assert!(commit_result.is_ok() || commit_result == Err(HandoffAdmissionError::InvalidGate));
        let model = shared.lock().unwrap();
        model.check_invariants().unwrap();
        if commit_result.is_ok() {
            assert_eq!(
                model.effect_disposition(effect).unwrap(),
                EffectDisposition::Committed
            );
        } else {
            assert_eq!(
                model.effect_disposition(effect).unwrap(),
                EffectDisposition::Prepared
            );
        }
    });
}

#[test]
fn abort_and_commit_decisions_cannot_both_win() {
    loom::model(|| {
        let mut initial = model();
        initial.register_effect().unwrap();
        initial.record_intent(intent()).unwrap();
        let frozen = initial.freeze_admission().unwrap();
        initial.abort_uncommitted(&frozen.receipt).unwrap();
        let abort = abort_receipt(&frozen.receipt);
        let commit = commit_receipt(&frozen.receipt);
        let shared = Arc::new(Mutex::new(initial));

        let abort_model = Arc::clone(&shared);
        let abort_thread = thread::spawn(move || abort_model.lock().unwrap().unfreeze(abort));
        let commit_model = Arc::clone(&shared);
        let commit_thread =
            thread::spawn(move || commit_model.lock().unwrap().commit_close(commit));

        let abort_result = abort_thread.join().unwrap();
        let commit_result = commit_thread.join().unwrap();
        assert_ne!(abort_result.is_ok(), commit_result.is_ok());
        let model = shared.lock().unwrap();
        model.check_invariants().unwrap();
        assert!(matches!(
            model.query_handoff().unwrap(),
            HandoffProgress::Aborted(_) | HandoffProgress::Committed(_)
        ));
    });
}

#[test]
fn duplicate_close_replays_one_receipt() {
    loom::model(|| {
        let mut initial = model();
        initial.register_effect().unwrap();
        initial.record_intent(intent()).unwrap();
        let frozen = initial.freeze_admission().unwrap();
        initial.abort_uncommitted(&frozen.receipt).unwrap();
        let commit = commit_receipt(&frozen.receipt);
        let shared = Arc::new(Mutex::new(initial));

        let left_model = Arc::clone(&shared);
        let left = thread::spawn(move || left_model.lock().unwrap().commit_close(commit));
        let right_model = Arc::clone(&shared);
        let right = thread::spawn(move || right_model.lock().unwrap().commit_close(commit));

        assert_eq!(
            left.join().unwrap().unwrap(),
            right.join().unwrap().unwrap()
        );
        shared.lock().unwrap().check_invariants().unwrap();
    });
}
