// SPDX-License-Identifier: MPL-2.0

use cser_transition_gates::scheduler::{SchedulerError, SchedulerGate, SchedulerMode};
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
        assert_eq!(crash.previous_binding_epoch, 1);
        assert_eq!(crash.binding_epoch, 2);
        assert_eq!(crash.pending_cleared, proposal.is_ok());

        let mut gate = gate.lock().unwrap();
        assert_eq!(gate.mode(), SchedulerMode::Fallback);
        assert_eq!(gate.pending(), None);
        if proposal.is_err() {
            assert_eq!(proposal, Err(SchedulerError::StaleBinding));
        }

        let before_repeated_crash = *gate;
        let current_binding = gate.binding();
        assert_eq!(
            gate.enter_fallback(current_binding),
            Err(SchedulerError::AlreadyFallback)
        );
        assert_eq!(*gate, before_repeated_crash);
        let before_early_rebind = *gate;
        assert_eq!(gate.rebind(7), Err(SchedulerError::FallbackPickRequired));
        assert_eq!(*gate, before_early_rebind);

        let pick = gate.note_fallback_pick(23).unwrap();
        assert_eq!(pick.selection_attempt, 1);
        let evidence = gate.fallback_evidence().unwrap();
        assert_eq!(evidence.crash_tick, crash.crash_tick);
        assert_eq!(evidence.pick_tick, pick.tick);
        assert_eq!(evidence.pick_task_id, 23);
        assert!(evidence.pick_tick >= evidence.crash_tick);
        let rebound = gate.rebind(7).unwrap();
        assert_eq!(rebound.binding_epoch, crash.binding_epoch);
        assert_eq!(gate.mode(), SchedulerMode::Bound);

        let before_stale_proposal = *gate;
        assert_eq!(
            gate.prepare(binding, true, 29),
            Err(SchedulerError::StaleBinding)
        );
        assert_eq!(*gate, before_stale_proposal);
        let before_old_crash = *gate;
        assert_eq!(
            gate.enter_fallback(binding),
            Err(SchedulerError::StaleBinding)
        );
        assert_eq!(*gate, before_old_crash);
    });
    report(
        "fallback_before_rebind",
        &[
            "crash-advances-binding-once",
            "repeated-crash-unchanged",
            "pending-proposal-cleared",
            "fallback-pick-before-rebind",
            "rebind-keeps-binding-epoch",
            "stale-proposals-failure-atomic",
        ],
    );
}
