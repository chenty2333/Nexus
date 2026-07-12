//! Small Loom refinements of the composition model's shared linearization gates.

use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootState {
    Active,
    Closing,
}

#[derive(Debug)]
struct DeriveState {
    root: RootState,
    parent_credits: usize,
    child_installed: bool,
    frozen_children: usize,
}

#[test]
fn loom_failure_atomic_derive_and_root_revoke_share_one_gate() {
    model(|| {
        let state = Arc::new(Mutex::new(DeriveState {
            root: RootState::Active,
            parent_credits: 1,
            child_installed: false,
            frozen_children: 0,
        }));
        let derive_state = state.clone();
        let revoke_state = state.clone();
        let derive = thread::spawn(move || {
            let mut state = derive_state.lock().unwrap();
            if state.root != RootState::Active || state.parent_credits == 0 {
                return false;
            }
            // Parent edge, target-domain envelope, and credit move refine one
            // failure-atomic CompositionModel::derive_child operation.
            state.parent_credits -= 1;
            state.child_installed = true;
            true
        });
        let revoke = thread::spawn(move || {
            let mut state = revoke_state.lock().unwrap();
            assert_eq!(state.root, RootState::Active);
            state.root = RootState::Closing;
            state.frozen_children = usize::from(state.child_installed);
        });
        let derived = derive.join().unwrap();
        revoke.join().unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.root, RootState::Closing);
        assert_eq!(state.child_installed, derived);
        assert_eq!(state.parent_credits + usize::from(state.child_installed), 1);
        assert_eq!(state.frozen_children, usize::from(state.child_installed));
    });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitState {
    Prepared,
    Committed,
    Aborted,
}

#[derive(Debug)]
struct CommitGate {
    root: RootState,
    effect: CommitState,
    publications: usize,
}

#[test]
fn loom_cross_domain_commit_cannot_cross_a_closed_root_gate() {
    model(|| {
        let gate = Arc::new(Mutex::new(CommitGate {
            root: RootState::Active,
            effect: CommitState::Prepared,
            publications: 0,
        }));
        let commit_gate = gate.clone();
        let revoke_gate = gate.clone();
        let commit = thread::spawn(move || {
            let mut gate = commit_gate.lock().unwrap();
            if gate.root != RootState::Active || gate.effect != CommitState::Prepared {
                return false;
            }
            gate.effect = CommitState::Committed;
            gate.publications += 1;
            true
        });
        let revoke = thread::spawn(move || {
            let mut gate = revoke_gate.lock().unwrap();
            gate.root = RootState::Closing;
            if gate.effect == CommitState::Prepared {
                gate.effect = CommitState::Aborted;
            }
        });
        let committed = commit.join().unwrap();
        revoke.join().unwrap();
        let gate = gate.lock().unwrap();
        assert_eq!(gate.root, RootState::Closing);
        assert_eq!(gate.publications, usize::from(committed));
        assert_eq!(
            gate.effect,
            if committed {
                CommitState::Committed
            } else {
                CommitState::Aborted
            }
        );
    });
}

#[derive(Debug)]
struct ReceiptGate {
    revision: usize,
    issued_revision: Option<usize>,
    accepted_revision: Option<usize>,
    tombstone_retained: bool,
}

impl ReceiptGate {
    fn accept(&mut self, revision: usize) -> bool {
        if self.issued_revision != Some(revision) || self.accepted_revision.is_some() {
            return false;
        }
        self.accepted_revision = Some(revision);
        true
    }

    fn begin_retry(&mut self) {
        assert!(self.tombstone_retained);
        self.revision += 1;
        self.issued_revision = None;
        self.accepted_revision = None;
    }
}

#[test]
fn loom_tombstone_retry_invalidates_an_accepted_or_inflight_timeout_receipt() {
    model(|| {
        let gate = Arc::new(Mutex::new(ReceiptGate {
            revision: 1,
            issued_revision: Some(1),
            accepted_revision: None,
            tombstone_retained: true,
        }));
        let accept_gate = gate.clone();
        let retry_gate = gate.clone();
        let accept = thread::spawn(move || accept_gate.lock().unwrap().accept(1));
        let retry = thread::spawn(move || retry_gate.lock().unwrap().begin_retry());
        let _accepted_before_retry = accept.join().unwrap();
        retry.join().unwrap();

        let mut gate = gate.lock().unwrap();
        assert_eq!(gate.revision, 2);
        assert_eq!(gate.issued_revision, None);
        assert_eq!(gate.accepted_revision, None);
        assert!(!gate.accept(1), "old timeout receipt must be stale");
        gate.tombstone_retained = false;
        gate.issued_revision = Some(2);
        assert!(gate.accept(2), "fresh Closed receipt must be accepted");
        assert_eq!(gate.accepted_revision, Some(2));
    });
}
