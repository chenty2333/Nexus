#[path = "production_identity_support/mod.rs"]
mod support;

use cser_model::production_identity::{DomainId, ProductionIdentityError, RootPhase};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};
use support::prepared_model;

fn run_in_large_stack_driver(body: impl FnOnce() + Send + 'static) {
    thread::Builder::new()
        .stack_size(4 * 1024 * 1024)
        .spawn(body)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn loom_block_commit_and_root_revoke_have_one_gate_winner() {
    model(|| {
        run_in_large_stack_driver(|| {
            let (initial, identities) = prepared_model();
            let root = initial.root_identity();
            let binding = initial.binding(DomainId::VirtIo).unwrap();
            let shared = Arc::new(Mutex::new(initial));

            let commit_model = Arc::clone(&shared);
            let commit = thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(move || {
                    commit_model.lock().unwrap().commit_block(
                        binding,
                        identities.block,
                        identities.dma_owners(),
                    )
                })
                .unwrap();
            let revoke_model = Arc::clone(&shared);
            let revoke = thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(move || revoke_model.lock().unwrap().revoke_begin(root))
                .unwrap();

            let commit_result = commit.join().unwrap();
            let ticket = revoke.join().unwrap().unwrap();
            let guard = shared.lock().unwrap();
            assert_eq!(guard.projection().root_phase, RootPhase::Closing);
            assert_eq!(ticket.frozen_effects().len(), 6);
            match commit_result {
                Ok(receipt) => assert_eq!(guard.projection().commit, Some(receipt)),
                Err(ProductionIdentityError::RootNotActive) => {
                    assert_eq!(guard.projection().commit, None);
                }
                other => panic!("unexpected commit/revoke result: {other:?}"),
            }
            assert_eq!(guard.check_invariants(), Ok(()));
        });
    });
}

#[test]
fn loom_domain_crash_fences_or_follows_device_commit_without_identity_replacement() {
    model(|| {
        run_in_large_stack_driver(|| {
            let (initial, identities) = prepared_model();
            let binding = initial.binding(DomainId::VirtIo).unwrap();
            let shared = Arc::new(Mutex::new(initial));

            let commit_model = Arc::clone(&shared);
            let commit = thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(move || {
                    commit_model.lock().unwrap().commit_block(
                        binding,
                        identities.block,
                        identities.dma_owners(),
                    )
                })
                .unwrap();
            let crash_model = Arc::clone(&shared);
            let crash = thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(move || crash_model.lock().unwrap().crash_domain(binding))
                .unwrap();

            let commit_result = commit.join().unwrap();
            crash.join().unwrap().unwrap();
            let guard = shared.lock().unwrap();
            assert_eq!(guard.binding(DomainId::VirtIo), None);
            match commit_result {
                Ok(receipt) => assert_eq!(guard.projection().commit, Some(receipt)),
                Err(
                    ProductionIdentityError::DomainUnavailable
                    | ProductionIdentityError::StaleBinding,
                ) => {
                    assert_eq!(guard.projection().commit, None);
                }
                other => panic!("unexpected crash/commit result: {other:?}"),
            }
            assert!(
                guard
                    .projection()
                    .effects
                    .iter()
                    .zip(identities.all())
                    .all(|(effect, original)| effect.identity == original)
            );
            assert_eq!(guard.check_invariants(), Ok(()));
        });
    });
}

#[test]
fn loom_retry_iotlb_ack_and_old_completion_cannot_double_publish() {
    model(|| {
        run_in_large_stack_driver(|| {
            let (mut initial, identities) = prepared_model();
            let commit = initial
                .commit_block(
                    initial.binding(DomainId::VirtIo).unwrap(),
                    identities.block,
                    identities.dma_owners(),
                )
                .unwrap();
            let ticket = initial.revoke_begin(initial.root_identity()).unwrap();
            let tombstone = initial
                .retain_reset_timeout(ticket.clone(), commit)
                .unwrap();
            let reset_retry = initial
                .retry_after_reset(ticket.clone(), tombstone)
                .unwrap();
            let iotlb_tombstone = initial
                .retain_iotlb_timeout(ticket.clone(), reset_retry)
                .unwrap();
            let retry = initial.retry_iotlb(ticket, iotlb_tombstone).unwrap();
            let shared = Arc::new(Mutex::new(initial));

            let ack_model = Arc::clone(&shared);
            let ack = thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(move || ack_model.lock().unwrap().acknowledge_retry_iotlb(retry))
                .unwrap();
            let stale_model = Arc::clone(&shared);
            let stale = thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(move || stale_model.lock().unwrap().complete_backend(commit))
                .unwrap();

            ack.join().unwrap().unwrap();
            assert_eq!(
                stale.join().unwrap(),
                Err(ProductionIdentityError::StaleDeviceGeneration)
            );
            let guard = shared.lock().unwrap();
            assert_eq!(guard.projection().counters.iotlb_acks, 1);
            assert_eq!(guard.projection().counters.device_completions, 0);
            assert_eq!(guard.check_invariants(), Ok(()));
        });
    });
}
