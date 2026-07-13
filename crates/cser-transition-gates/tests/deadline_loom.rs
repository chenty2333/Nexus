// SPDX-License-Identifier: MPL-2.0

use cser_transition_gates::deadline::{DeadlineError, DeadlineGate};
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
fn stale_deadline_after_rearm() {
    model(|| {
        let mut initial = DeadlineGate::new(1).unwrap();
        let old = initial.arm(10).unwrap();
        let gate = Arc::new(Mutex::new(initial));
        let rearm_gate = gate.clone();
        let expire_gate = gate.clone();
        let rearm = thread::spawn(move || rearm_gate.lock().unwrap().rearm(old, 20));
        let expire = thread::spawn(move || expire_gate.lock().unwrap().expire(old, 10));
        let rearmed = rearm.join().unwrap();
        let expired = expire.join().unwrap();
        assert_ne!(rearmed.is_ok(), expired.is_ok());

        let mut gate = gate.lock().unwrap();
        let current = match rearmed {
            Ok(current) => {
                assert_eq!(expired, Err(DeadlineError::StaleToken));
                assert_eq!(gate.current(), Some(current));
                current
            }
            Err(DeadlineError::NotArmed) => {
                assert!(expired.is_ok());
                let replacement = gate.arm(20).unwrap();
                assert!(replacement.generation() > old.generation());
                replacement
            }
            Err(error) => panic!("unexpected rearm result: {error:?}"),
        };

        let before_old_expiry = gate.projection();
        assert_eq!(gate.expire(old, u64::MAX), Err(DeadlineError::StaleToken));
        assert_eq!(gate.projection(), before_old_expiry);
        assert_eq!(gate.current(), Some(current));
        assert!(current.generation() > old.generation());
        assert_eq!(current.deadline(), 20);
    });
    report(
        "stale_deadline_after_rearm",
        &[
            "old-token-rejected",
            "rejection-failure-atomic",
            "replacement-generation-advanced",
            "replacement-remains-live",
        ],
    );
}
