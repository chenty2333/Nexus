// SPDX-License-Identifier: MPL-2.0

use cser_transition_gates::pager::{
    CommitMappingError, ContinuationOutcome, FaultKey, PagerError, PagerGate,
};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};

fn key() -> FaultKey {
    FaultKey {
        address_space_id: 1,
        address_space_generation: 1,
        page_address: 0x4000,
    }
}

#[test]
fn same_page_single_publication() {
    model(|| {
        let mut initial = PagerGate::<2>::new(5, 1, 10).unwrap();
        let leader = initial.register(key(), 100).unwrap().ticket();
        let follower = initial.register(key(), 101).unwrap().ticket();
        initial.prepare_leader(leader).unwrap();
        let gate = Arc::new(Mutex::new(initial));
        let first_gate = gate.clone();
        let second_gate = gate.clone();
        let first = thread::spawn(move || {
            first_gate
                .lock()
                .unwrap()
                .commit_mapping_with(leader, || Ok::<_, ()>(()))
        });
        let second = thread::spawn(move || {
            second_gate
                .lock()
                .unwrap()
                .commit_mapping_with(leader, || Ok::<_, ()>(()))
        });
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert_ne!(first.is_ok(), second.is_ok());
        let mapping = first.or(second).unwrap().0;
        let mut gate = gate.lock().unwrap();
        gate.terminalize(leader, Some(mapping), ContinuationOutcome::Resolved)
            .unwrap();
        gate.terminalize(follower, Some(mapping), ContinuationOutcome::Resolved)
            .unwrap();
        assert_eq!(gate.projection().mapping_publications, 1);
        assert_eq!(gate.projection().terminalizations, 2);
    });
    println!("STAGE7B_CONCURRENCY case=same_page_single_publication status=PASS");
}

#[test]
fn handler_crash_before_resolution() {
    model(|| {
        let mut initial = PagerGate::<2>::new(5, 1, 10).unwrap();
        let leader = initial.register(key(), 100).unwrap().ticket();
        initial.prepare_leader(leader).unwrap();
        let gate = Arc::new(Mutex::new(initial));
        let commit_gate = gate.clone();
        let crash_gate = gate.clone();
        let commit = thread::spawn(move || {
            commit_gate
                .lock()
                .unwrap()
                .commit_mapping_with(leader, || Ok::<_, ()>(()))
                .is_ok()
        });
        let crash = thread::spawn(move || crash_gate.lock().unwrap().crash(1).unwrap());
        let committed = commit.join().unwrap();
        assert_eq!(crash.join().unwrap().binding_epoch, 2);
        let mut gate = gate.lock().unwrap();
        if !committed {
            gate.abort_orphan(leader).unwrap();
        }
        assert_eq!(gate.projection().binding_epoch, 2);
        assert!(committed || gate.projection().terminalizations == 1);
    });
    println!("STAGE7B_CONCURRENCY case=handler_crash_before_resolution status=PASS");
}

#[test]
fn old_binding_reply_after_rebind() {
    model(|| {
        let mut gate = PagerGate::<2>::new(5, 1, 10).unwrap();
        let old = gate.register(key(), 100).unwrap().ticket();
        gate.prepare_leader(old).unwrap();
        gate.crash(1).unwrap();
        let snapshot = gate.snapshot(11, 1).unwrap();
        gate.ready(snapshot).unwrap();
        gate.rebind(11).unwrap();
        let before = gate;
        assert_eq!(
            gate.commit_mapping_with(old, || Ok::<_, ()>(())),
            Err(CommitMappingError::Gate(PagerError::StaleBinding))
        );
        assert_eq!(gate, before);
    });
    println!("STAGE7B_CONCURRENCY case=old_binding_reply_after_rebind status=PASS");
}

#[test]
fn adopt_vs_abort_single_winner() {
    model(|| {
        let mut initial = PagerGate::<2>::new(5, 1, 10).unwrap();
        let old = initial.register(key(), 100).unwrap().ticket();
        initial.prepare_leader(old).unwrap();
        initial.crash(1).unwrap();
        let snapshot = initial.snapshot(11, 1).unwrap();
        initial.ready(snapshot).unwrap();
        initial.rebind(11).unwrap();
        let gate = Arc::new(Mutex::new(initial));
        let adopt_gate = gate.clone();
        let abort_gate = gate.clone();
        let adopt = thread::spawn(move || adopt_gate.lock().unwrap().adopt(old).is_ok());
        let abort = thread::spawn(move || abort_gate.lock().unwrap().abort_orphan(old).is_ok());
        assert_ne!(adopt.join().unwrap(), abort.join().unwrap());
    });
    println!("STAGE7B_CONCURRENCY case=adopt_vs_abort_single_winner status=PASS");
}
