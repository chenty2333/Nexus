// SPDX-License-Identifier: MPL-2.0

use cser_transition_gates::deadline::{DeadlineError, DeadlineGate};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};

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
        if let Ok(current) = rearmed {
            assert_eq!(expired, Err(DeadlineError::StaleToken));
            assert_eq!(gate.lock().unwrap().current(), Some(current));
        } else {
            assert_eq!(rearmed, Err(DeadlineError::NotArmed));
            assert_eq!(gate.lock().unwrap().current(), None);
        }
    });
    println!("STAGE7B_CONCURRENCY case=stale_deadline_after_rearm status=PASS");
}
