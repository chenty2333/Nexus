// SPDX-License-Identifier: MPL-2.0

use cser_transition_gates::oneshot::OneShotGate;
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

fn run_single_winner(left: Outcome, right: Outcome) {
    model(move || {
        let gate = Arc::new(Mutex::new(OneShotGate::new(1, 1).unwrap()));
        let token = gate.lock().unwrap().token();
        let left_gate = gate.clone();
        let right_gate = gate.clone();
        let left_result = thread::spawn(move || {
            left_gate
                .lock()
                .unwrap()
                .try_terminalize(token, left)
                .is_ok()
        });
        let right_result = thread::spawn(move || {
            right_gate
                .lock()
                .unwrap()
                .try_terminalize(token, right)
                .is_ok()
        });
        assert_ne!(left_result.join().unwrap(), right_result.join().unwrap());
        assert!(matches!(
            gate.lock().unwrap().terminal(),
            Some(outcome) if outcome == left || outcome == right
        ));
    });
}

#[test]
fn wake_vs_timeout_single_winner() {
    run_single_winner(Outcome::Wake, Outcome::Timeout);
    println!("STAGE7B_CONCURRENCY case=wake_vs_timeout_single_winner status=PASS");
}

#[test]
fn cancel_vs_wake_single_winner() {
    run_single_winner(Outcome::Cancel, Outcome::Wake);
    println!("STAGE7B_CONCURRENCY case=cancel_vs_wake_single_winner status=PASS");
}

#[test]
fn resolve_vs_abort_one_shot() {
    run_single_winner(Outcome::Resolve, Outcome::Abort);
    println!("STAGE7B_CONCURRENCY case=resolve_vs_abort_one_shot status=PASS");
}
