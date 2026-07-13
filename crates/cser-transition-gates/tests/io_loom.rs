// SPDX-License-Identifier: MPL-2.0

use cser_transition_gates::io::{
    IoCommitError, IoError, IoGate, IoPhase, IoTerminal, IotlbProgress, QuiescenceReceipt,
    ResetReceipt,
};
use loom::{
    model,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

const PRIMARY_IO_INSTANCE_ID: u64 = 1;
const FOREIGN_RESET_INSTANCE_ID: u64 = 2;
const FOREIGN_IOTLB_INSTANCE_ID: u64 = 3;
const AUXILIARY_IO_INSTANCE_ID: u64 = 4;

fn report(case: &str, assertions: &[&str]) {
    println!("STAGE7B_CONCURRENCY case={case} status=PASS");
    for assertion in assertions {
        println!("STAGE7B_CONCURRENCY_ASSERT case={case} assertion={assertion} status=PASS");
    }
}

#[test]
fn publish_vs_revoke_commit_gate() {
    model(|| {
        let publications = Arc::new(AtomicUsize::new(0));
        let mut initial = IoGate::<2>::new(PRIMARY_IO_INSTANCE_ID).unwrap();
        let identity = initial.register(initial.binding_token().unwrap()).unwrap();
        let gate = Arc::new(Mutex::new(initial));
        let commit_gate = gate.clone();
        let revoke_gate = gate.clone();
        let commit_publications = publications.clone();
        let commit = thread::spawn(move || {
            commit_gate.lock().unwrap().commit_with(identity, || {
                commit_publications.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ()>(())
            })
        });
        let revoke = thread::spawn(move || revoke_gate.lock().unwrap().begin_closing().unwrap());
        let committed = commit.join().unwrap().is_ok();
        let close = revoke.join().unwrap();
        assert_eq!(publications.load(Ordering::SeqCst), usize::from(committed));
        assert_eq!(close.aborted(), usize::from(!committed));

        let mut gate = gate.lock().unwrap();
        assert_eq!(
            gate.terminal(identity),
            if committed {
                None
            } else {
                Some(IoTerminal::AbortedBeforeCommit)
            }
        );
        let reset_attempt = gate.begin_reset(close).unwrap();
        let reset_generation = reset_attempt.generation();
        let reset_tombstone = reset_attempt.retain();
        assert_eq!(reset_tombstone.generation(), reset_generation);
        assert!(gate.projection().reset_pending);
        let reset = gate
            .apply_reset(reset_tombstone.retry().acknowledge())
            .unwrap();
        assert_eq!(reset.terminalized(), usize::from(committed));
        assert_eq!(
            gate.terminal(identity),
            Some(if committed {
                IoTerminal::IndeterminateAfterReset
            } else {
                IoTerminal::AbortedBeforeCommit
            })
        );

        let owners = gate.begin_iotlb::<2>(reset).unwrap();
        let owners = match owners.owner_complete(0).unwrap() {
            IotlbProgress::Pending(owners) => owners.retain().retry(),
            IotlbProgress::Complete(_) => panic!("two owners are required"),
        };
        let quiescence = match owners.owner_complete(1).unwrap() {
            IotlbProgress::Complete(receipt) => receipt,
            IotlbProgress::Pending(_) => panic!("both owners completed"),
        };
        assert_eq!(quiescence.completed(), 2);
        let before_early_reuse = gate.state_projection();
        assert_eq!(gate.binding_token(), Err(IoError::Closing));
        assert_eq!(gate.rebind_after_quiescence(), Err(IoError::InvalidPhase));
        assert_eq!(gate.state_projection(), before_early_reuse);
        gate.mark_quiesced(quiescence).unwrap();
        assert_eq!(gate.projection().phase, IoPhase::Quiesced);
        let rebound = gate.rebind_after_quiescence().unwrap();
        assert_eq!(gate.projection().phase, IoPhase::Active);
        assert!(!gate.accepts_service_action(identity));
        let replacement = gate.register(rebound).unwrap();
        assert!(replacement.request_id() > identity.request_id());
        assert!(replacement.device_generation() > identity.device_generation());
        assert!(gate.accepts_service_action(replacement));

        let before_late_commit = gate.state_projection();
        assert!(matches!(
            gate.commit_with(identity, || Ok::<_, ()>(())),
            Err(IoCommitError::Gate(
                IoError::StaleAuthority | IoError::StaleBinding | IoError::StaleDeviceGeneration
            ))
        ));
        assert_eq!(gate.state_projection(), before_late_commit);
    });
    report(
        "publish_vs_revoke_commit_gate",
        &[
            "commit-revoke-single-order",
            "publication-closure-at-most-once",
            "uncommitted-loser-aborted",
            "committed-effect-retained-until-reset",
            "committed-result-not-rolled-back",
            "modeled-iotlb-owner-progress-complete",
            "pre-quiescence-reuse-rejected",
            "post-quiescence-new-binding",
            "final-quiescence-before-rebind",
        ],
    );
}

fn foreign_reset_receipt() -> ResetReceipt {
    let mut gate = IoGate::<1>::new(FOREIGN_RESET_INSTANCE_ID).unwrap();
    let identity = gate.register(gate.binding_token().unwrap()).unwrap();
    gate.commit_with(identity, || Ok::<_, ()>(())).unwrap();
    let close = gate.begin_closing().unwrap();
    gate.begin_reset(close).unwrap().acknowledge()
}

fn foreign_quiescence_receipt() -> QuiescenceReceipt {
    let mut gate = IoGate::<1>::new(FOREIGN_IOTLB_INSTANCE_ID).unwrap();
    let identity = gate.register(gate.binding_token().unwrap()).unwrap();
    gate.commit_with(identity, || Ok::<_, ()>(())).unwrap();
    let close = gate.begin_closing().unwrap();
    let reset_receipt = gate.begin_reset(close).unwrap().acknowledge();
    let reset = gate.apply_reset(reset_receipt).unwrap();
    match gate
        .begin_iotlb::<1>(reset)
        .unwrap()
        .owner_complete(0)
        .unwrap()
    {
        IotlbProgress::Complete(receipt) => receipt,
        IotlbProgress::Pending(_) => unreachable!(),
    }
}

fn assert_duplicate_owner_rejected() {
    let mut gate = IoGate::<1>::new(AUXILIARY_IO_INSTANCE_ID).unwrap();
    let identity = gate.register(gate.binding_token().unwrap()).unwrap();
    gate.commit_with(identity, || Ok::<_, ()>(())).unwrap();
    let close = gate.begin_closing().unwrap();
    let reset_receipt = gate.begin_reset(close).unwrap().acknowledge();
    let reset = gate.apply_reset(reset_receipt).unwrap();
    let pending = match gate
        .begin_iotlb::<2>(reset)
        .unwrap()
        .owner_complete(0)
        .unwrap()
    {
        IotlbProgress::Pending(pending) => pending.retain().retry(),
        IotlbProgress::Complete(_) => unreachable!(),
    };
    assert_eq!(pending.owner_complete(0), Err(IoError::DuplicateOwner));
    assert!(gate.projection().iotlb_pending);
}

#[test]
fn timeout_vs_late_completion_tombstone() {
    model(|| {
        let mut initial = IoGate::<2>::new(PRIMARY_IO_INSTANCE_ID).unwrap();
        let identity = initial.register(initial.binding_token().unwrap()).unwrap();
        initial.commit_with(identity, || Ok::<_, ()>(())).unwrap();
        let close = initial.begin_closing().unwrap();
        let reset_attempt = initial.begin_reset(close).unwrap();
        let reset_generation = reset_attempt.generation();
        let reset_tombstone = reset_attempt.retain();
        assert_eq!(reset_tombstone.generation(), reset_generation);
        assert!(initial.projection().reset_pending);

        let foreign_reset = foreign_reset_receipt();
        assert_eq!(foreign_reset.generation(), reset_tombstone.generation());
        assert_eq!(foreign_reset.nonce(), reset_tombstone.nonce());
        assert_ne!(foreign_reset.instance_id(), reset_tombstone.instance_id());
        let before_foreign_reset = initial.state_projection();
        assert_eq!(
            initial.apply_reset(foreign_reset),
            Err(IoError::InvalidReceipt)
        );
        assert_eq!(initial.state_projection(), before_foreign_reset);
        let reset_receipt = reset_tombstone.retry().acknowledge();

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
        let reset = thread::spawn(move || {
            reset_gate
                .lock()
                .unwrap()
                .apply_reset(reset_receipt)
                .unwrap()
        });
        let completion_won = completion.join().unwrap();
        let reset = reset.join().unwrap();
        assert_eq!(reset.terminalized(), usize::from(!completion_won));

        let mut gate = gate.lock().unwrap();
        assert_eq!(
            gate.terminal(identity),
            Some(if completion_won {
                IoTerminal::Completed
            } else {
                IoTerminal::IndeterminateAfterReset
            })
        );
        assert_eq!(gate.projection().terminalized, 1);
        let before_duplicate_completion = gate.state_projection();
        assert_eq!(
            gate.complete_device(identity),
            Err(IoError::StaleDeviceGeneration)
        );
        assert_eq!(gate.state_projection(), before_duplicate_completion);

        let owners = gate.begin_iotlb::<3>(reset).unwrap();
        let owners = match owners.owner_complete(0).unwrap() {
            IotlbProgress::Pending(owners) => owners.retain().retry(),
            IotlbProgress::Complete(_) => unreachable!(),
        };
        let owners = match owners.owner_complete(1).unwrap() {
            IotlbProgress::Pending(owners) => owners,
            IotlbProgress::Complete(_) => unreachable!(),
        };
        let quiescence = match owners.owner_complete(2).unwrap() {
            IotlbProgress::Complete(receipt) => receipt,
            IotlbProgress::Pending(_) => unreachable!(),
        };
        assert_eq!(quiescence.completed(), 3);

        let fabricated = foreign_quiescence_receipt();
        assert_eq!(fabricated.generation(), quiescence.generation());
        assert_eq!(fabricated.nonce(), quiescence.nonce());
        assert_ne!(fabricated.instance_id(), quiescence.instance_id());
        let before_fabricated_ack = gate.state_projection();
        assert_eq!(gate.mark_quiesced(fabricated), Err(IoError::InvalidReceipt));
        assert_eq!(gate.state_projection(), before_fabricated_ack);
        let before_early_reuse = gate.state_projection();
        assert_eq!(gate.binding_token(), Err(IoError::Closing));
        assert_eq!(gate.rebind_after_quiescence(), Err(IoError::InvalidPhase));
        assert_eq!(gate.state_projection(), before_early_reuse);
        gate.mark_quiesced(quiescence).unwrap();
        assert_eq!(gate.projection().phase, IoPhase::Quiesced);
        let before_duplicate_ack = gate.state_projection();
        assert_eq!(gate.mark_quiesced(quiescence), Err(IoError::InvalidReceipt));
        assert_eq!(gate.state_projection(), before_duplicate_ack);
        let rebound = gate.rebind_after_quiescence().unwrap();
        assert_eq!(gate.projection().phase, IoPhase::Active);
        assert!(!gate.projection().reset_pending);
        assert!(!gate.projection().iotlb_pending);
        let replacement = gate.register(rebound).unwrap();
        assert!(replacement.request_id() > identity.request_id());
        assert!(replacement.device_generation() > identity.device_generation());
        assert!(gate.accepts_service_action(replacement));
        let (retry_commit, ()) = gate.commit_with(replacement, || Ok::<_, ()>(())).unwrap();
        gate.accept_notify(replacement, retry_commit).unwrap();
        gate.complete_device(replacement).unwrap();
        assert_eq!(gate.terminal(replacement), Some(IoTerminal::Completed));
        let before_second_retry_completion = gate.state_projection();
        assert_eq!(
            gate.complete_device(replacement),
            Err(IoError::AlreadyTerminal)
        );
        assert_eq!(gate.state_projection(), before_second_retry_completion);

        assert_duplicate_owner_rejected();
    });
    report(
        "timeout_vs_late_completion_tombstone",
        &[
            "reset-tombstone-preserves-identity",
            "completion-reset-single-terminal",
            "second-user-result-rejected",
            "modeled-iotlb-owner-tombstone-preserves-progress",
            "duplicate-owner-rejected",
            "fabricated-ack-failure-atomic",
            "duplicate-ack-failure-atomic",
            "pre-quiescence-reuse-rejected",
            "post-quiescence-new-binding",
            "retry-completes-exactly-once",
            "final-quiescence-before-rebind",
        ],
    );
}
