// SPDX-License-Identifier: MPL-2.0

use cser_transition_gates::io::{IoGate, IoTerminal};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};

#[test]
fn publish_vs_revoke_commit_gate() {
    model(|| {
        let mut initial = IoGate::<2>::new().unwrap();
        let identity = initial.register(initial.binding_token().unwrap()).unwrap();
        let gate = Arc::new(Mutex::new(initial));
        let commit_gate = gate.clone();
        let revoke_gate = gate.clone();
        let commit = thread::spawn(move || {
            commit_gate
                .lock()
                .unwrap()
                .commit_with(identity, || Ok::<_, ()>(()))
                .is_ok()
        });
        let revoke = thread::spawn(move || revoke_gate.lock().unwrap().begin_closing().unwrap());
        let committed = commit.join().unwrap();
        revoke.join().unwrap();
        let gate = gate.lock().unwrap();
        assert_eq!(
            gate.terminal(identity),
            if committed {
                None
            } else {
                Some(IoTerminal::AbortedBeforeCommit)
            }
        );
    });
    println!("STAGE7B_CONCURRENCY case=publish_vs_revoke_commit_gate status=PASS");
}

#[test]
fn timeout_vs_late_completion_tombstone() {
    model(|| {
        let mut initial = IoGate::<2>::new().unwrap();
        let identity = initial.register(initial.binding_token().unwrap()).unwrap();
        initial.commit_with(identity, || Ok::<_, ()>(())).unwrap();
        let close = initial.begin_closing().unwrap();
        let reset = initial
            .begin_reset(close)
            .unwrap()
            .retain()
            .retry()
            .acknowledge();
        let gate = Arc::new(Mutex::new(initial));
        let completion_gate = gate.clone();
        let reset_gate = gate.clone();
        let completion = thread::spawn(move || {
            completion_gate
                .lock()
                .unwrap()
                .complete_device(identity)
                .is_ok()
        });
        let reset = thread::spawn(move || reset_gate.lock().unwrap().apply_reset(reset).unwrap());
        let completion_won = completion.join().unwrap();
        let reset = reset.join().unwrap();
        assert_eq!(reset.terminalized(), usize::from(!completion_won));
        assert_eq!(
            gate.lock().unwrap().terminal(identity),
            Some(if completion_won {
                IoTerminal::Completed
            } else {
                IoTerminal::IndeterminateAfterReset
            })
        );
    });
    println!("STAGE7B_CONCURRENCY case=timeout_vs_late_completion_tombstone status=PASS");
}
