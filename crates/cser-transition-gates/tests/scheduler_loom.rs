// SPDX-License-Identifier: MPL-2.0

use cser_transition_gates::scheduler::{SchedulerError, SchedulerGate, SchedulerMode};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};

#[test]
fn fallback_before_rebind() {
    model(|| {
        let gate = Arc::new(Mutex::new(SchedulerGate::<u64>::new(7, 4).unwrap()));
        let binding = gate.lock().unwrap().binding();
        let proposal_gate = gate.clone();
        let crash_gate = gate.clone();
        let proposal =
            thread::spawn(move || proposal_gate.lock().unwrap().prepare(binding, true, 19));
        let crash =
            thread::spawn(move || crash_gate.lock().unwrap().enter_fallback(binding).unwrap());
        let proposal = proposal.join().unwrap();
        let crash = crash.join().unwrap();
        assert_eq!(crash.binding_epoch, 2);
        let mut gate = gate.lock().unwrap();
        assert_eq!(gate.mode(), SchedulerMode::Fallback);
        assert_eq!(gate.pending(), None);
        if proposal.is_err() {
            assert_eq!(proposal, Err(SchedulerError::StaleBinding));
        }
        assert_eq!(gate.rebind(7), Err(SchedulerError::FallbackPickRequired));
        gate.note_fallback_pick(23).unwrap();
        assert_eq!(gate.rebind(7).unwrap().binding_epoch, 2);
        assert_eq!(
            gate.prepare(binding, true, 29),
            Err(SchedulerError::StaleBinding)
        );
    });
    println!("STAGE7B_CONCURRENCY case=fallback_before_rebind status=PASS");
}
