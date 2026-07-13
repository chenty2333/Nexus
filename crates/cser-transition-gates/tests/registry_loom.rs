// SPDX-License-Identifier: MPL-2.0

extern crate alloc;

#[path = "../../../kernel/nexus-ostd/src/cser/effect_registry.rs"]
mod effect_registry;

use effect_registry::{
    CommitOutcome, RegistryError, ScopePhase, Stage7bActiveFixture, Stage7bFixtureConfig,
    TerminalOutcome,
};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};

fn run_commit_revoke_race(n: usize, h: usize) {
    model(move || {
        let mut fixture = Stage7bActiveFixture::new(Stage7bFixtureConfig { n, k: 1, h }).unwrap();
        let handle = fixture.prepare_single_target().unwrap();
        let fixture = Arc::new(Mutex::new(fixture));
        let commit_fixture = fixture.clone();
        let revoke_fixture = fixture.clone();
        let commit =
            thread::spawn(move || commit_fixture.lock().unwrap().commit_single_target(handle));
        let revoke = thread::spawn(move || {
            let mut fixture = revoke_fixture.lock().unwrap();
            let selection = fixture.begin().unwrap();
            fixture.finish_revoke(&selection).unwrap();
            selection
        });
        let commit = commit.join().unwrap();
        let selection = revoke.join().unwrap();
        let fixture = fixture.lock().unwrap();
        let terminal = fixture.single_target_terminal(handle).unwrap();
        match commit {
            Ok(CommitOutcome::Applied(_) | CommitOutcome::AlreadyCommitted(_)) => {
                assert_eq!(terminal, TerminalOutcome::Completed);
            }
            Err(error) => {
                assert!(matches!(
                    error,
                    RegistryError::StaleAuthority | RegistryError::ScopeNotActive
                ));
                assert_eq!(terminal, TerminalOutcome::Aborted);
            }
        }
        let observation = fixture.observation(&selection).unwrap();
        assert_eq!(observation.target.phase, ScopePhase::Revoked);
        assert_eq!(observation.work.target_count, 1);
        assert_eq!(observation.work.terminalized, 1);
        assert_eq!(observation.work.completion_members_checked, 1);
        assert_eq!(observation.work.unrelated_effect_visits, 0);
        assert_eq!(observation.work.history_effect_visits, 0);
        assert_eq!(observation.target.credits.capacity, 1);
        assert_eq!(observation.target.credits.free, 1);
        assert_eq!(observation.target.credits.held, 0);
        assert_eq!(observation.target.credits.committed, 0);
        fixture.check_invariants().unwrap();
    });
}

#[test]
fn commit_vs_revoke_linearization() {
    run_commit_revoke_race(1, 0);
    println!("STAGE7B_CONCURRENCY case=commit_vs_revoke_linearization status=PASS");
}

#[test]
fn revoke_deferred_wait_timer() {
    run_commit_revoke_race(8, 4);
    println!("STAGE7B_CONCURRENCY case=revoke_deferred_wait_timer status=PASS");
}

#[test]
fn budget_commit_vs_abort_conservation() {
    run_commit_revoke_race(2, 1);
    println!("STAGE7B_CONCURRENCY case=budget_commit_vs_abort_conservation status=PASS");
}
