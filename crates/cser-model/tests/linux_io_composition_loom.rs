use cser_model::linux_io_composition::{
    CloseStep, DomainId, EffectKind, GenerationKind, LinuxIoCompositionModel,
};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};

#[test]
fn loom_filesystem_commit_and_root_revoke_share_the_actual_model_gate() {
    model(|| {
        let mut initial = LinuxIoCompositionModel::new();
        let token = initial.token(EffectKind::FsOp);
        initial.prepare(token).unwrap();
        let shared = Arc::new(Mutex::new(initial));

        let commit_model = Arc::clone(&shared);
        let commit = thread::spawn(move || {
            let _ = commit_model.lock().unwrap().commit(token);
        });
        let revoke_model = Arc::clone(&shared);
        let revoke = thread::spawn(move || {
            revoke_model.lock().unwrap().revoke_begin().unwrap();
        });
        commit.join().unwrap();
        revoke.join().unwrap();

        assert_eq!(shared.lock().unwrap().check_invariants(), Ok(()));
    });
}

#[test]
fn loom_atomic_network_buffer_commit_and_root_revoke_have_one_winner() {
    model(|| {
        let mut initial = LinuxIoCompositionModel::new();
        let network = initial.token(EffectKind::NetOp);
        let buffer = initial.token(EffectKind::BufferLease);
        initial.prepare(network).unwrap();
        initial.prepare(buffer).unwrap();
        let shared = Arc::new(Mutex::new(initial));

        let commit_model = Arc::clone(&shared);
        let commit = thread::spawn(move || {
            let _ = commit_model.lock().unwrap().commit_network(network, buffer);
        });
        let revoke_model = Arc::clone(&shared);
        let revoke = thread::spawn(move || {
            revoke_model.lock().unwrap().revoke_begin().unwrap();
        });
        commit.join().unwrap();
        revoke.join().unwrap();

        assert_eq!(shared.lock().unwrap().check_invariants(), Ok(()));
    });
}

#[test]
fn loom_domain_crash_fences_or_follows_one_filesystem_commit() {
    model(|| {
        let mut initial = LinuxIoCompositionModel::new();
        let token = initial.token(EffectKind::FsOp);
        initial.prepare(token).unwrap();
        let peer_bindings = initial.projection().bindings;
        let shared = Arc::new(Mutex::new(initial));

        let crash_model = Arc::clone(&shared);
        let crash = thread::spawn(move || {
            crash_model
                .lock()
                .unwrap()
                .crash(DomainId::Filesystem)
                .unwrap();
        });
        let commit_model = Arc::clone(&shared);
        let commit = thread::spawn(move || {
            let _ = commit_model.lock().unwrap().commit(token);
        });
        crash.join().unwrap();
        commit.join().unwrap();

        let guard = shared.lock().unwrap();
        for domain in DomainId::ALL {
            let expected =
                peer_bindings[domain as usize] + u64::from(domain == DomainId::Filesystem);
            assert_eq!(guard.binding_epoch(domain), expected);
        }
        assert_eq!(guard.check_invariants(), Ok(()));
    });
}

#[test]
fn loom_timeout_receipt_acceptance_fences_tombstone_retry() {
    model(|| {
        let mut initial = LinuxIoCompositionModel::new();
        let block = initial.token(EffectKind::BlockReq);
        initial.prepare(block).unwrap();
        initial.commit(block).unwrap();
        let ticket = initial.revoke_begin().unwrap();
        for domain in [DomainId::Scheduler, DomainId::Pager] {
            while matches!(
                initial.close_next(&ticket, domain).unwrap(),
                Some(CloseStep::Aborted(_) | CloseStep::Drained(_))
            ) {}
            let receipt = initial.issue_domain_receipt(&ticket, domain).unwrap();
            initial.accept_domain_receipt(&ticket, receipt).unwrap();
        }
        assert_eq!(
            initial.close_next(&ticket, DomainId::VirtIo),
            Ok(Some(CloseStep::NeedsQuiescence))
        );
        let tombstone = initial.timeout_virtio(&ticket).unwrap();
        let timeout = initial
            .issue_domain_receipt(&ticket, DomainId::VirtIo)
            .unwrap();
        let shared = Arc::new(Mutex::new(initial));

        let accept_model = Arc::clone(&shared);
        let accept_ticket = ticket.clone();
        let accept = thread::spawn(move || {
            accept_model
                .lock()
                .unwrap()
                .accept_domain_receipt(&accept_ticket, timeout)
                .unwrap();
        });
        let retry_model = Arc::clone(&shared);
        let retry_ticket = ticket.clone();
        let retry = thread::spawn(move || {
            let _ = retry_model
                .lock()
                .unwrap()
                .retry_virtio(&retry_ticket, tombstone);
        });
        accept.join().unwrap();
        retry.join().unwrap();

        let mut guard = shared.lock().unwrap();
        if guard.generation(GenerationKind::Device) == 1 {
            guard.retry_virtio(&ticket, tombstone).unwrap();
        }
        assert_eq!(guard.check_invariants(), Ok(()));
    });
}
