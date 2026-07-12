use cser_model::linux_io_composition::{
    CloseStep, CompositionError, DomainClosureReceipt, DomainId, EffectKind, GenerationKind,
    LinuxIoCompositionModel, PublicationPoint, ReceiptStatus, RootPhase, RootRevokeTicket,
};

fn commit_one(
    model: &mut LinuxIoCompositionModel,
    kind: EffectKind,
) -> cser_model::linux_io_composition::CommitReceipt {
    let token = model.token(kind);
    model.prepare(token).unwrap();
    model.commit(token).unwrap()
}

fn commit_network(
    model: &mut LinuxIoCompositionModel,
) -> (
    cser_model::linux_io_composition::CommitReceipt,
    cser_model::linux_io_composition::CommitReceipt,
) {
    let network = model.token(EffectKind::NetOp);
    let buffer = model.token(EffectKind::BufferLease);
    model.prepare(network).unwrap();
    model.prepare(buffer).unwrap();
    model.commit_network(network, buffer).unwrap()
}

fn issue_accept(
    model: &mut LinuxIoCompositionModel,
    ticket: &RootRevokeTicket,
    domain: DomainId,
) -> DomainClosureReceipt {
    let receipt = model.issue_domain_receipt(ticket, domain).unwrap();
    model.accept_domain_receipt(ticket, receipt).unwrap();
    receipt
}

fn drain_domain(model: &mut LinuxIoCompositionModel, ticket: &RootRevokeTicket, domain: DomainId) {
    loop {
        match model.close_next(ticket, domain).unwrap() {
            Some(CloseStep::Aborted(_) | CloseStep::Drained(_)) => {}
            Some(CloseStep::BlockedByDescendants) => {
                panic!("closure order left a live descendant in {domain:?}")
            }
            Some(CloseStep::NeedsQuiescence) => {
                panic!("unexpected external-quiescence obligation in {domain:?}")
            }
            None => break,
        }
    }
}

fn close_without_timeout(model: &mut LinuxIoCompositionModel, ticket: &RootRevokeTicket) {
    for domain in [
        DomainId::Scheduler,
        DomainId::Pager,
        DomainId::VirtIo,
        DomainId::Filesystem,
        DomainId::Readiness,
        DomainId::Network,
        DomainId::Personality,
    ] {
        drain_domain(model, ticket, domain);
        let receipt = issue_accept(model, ticket, domain);
        assert_eq!(receipt.status(), ReceiptStatus::Closed);
    }
    model.revoke_complete(ticket).unwrap();
}

#[test]
fn full_seven_domain_mixed_closure_retains_timeout_then_accepts_eight_receipts() {
    let mut model = LinuxIoCompositionModel::new();
    let _fs = commit_one(&mut model, EffectKind::FsOp);
    let _block = commit_one(&mut model, EffectKind::BlockReq);
    let (network, _buffer) = commit_network(&mut model);
    let ready_token = model.token(EffectKind::ReadinessWait);
    model.prepare(ready_token).unwrap();
    let _ready = model.commit_ready(ready_token, network).unwrap();

    let ticket = model.revoke_begin().unwrap();
    assert_eq!(ticket.frozen_domains(), 7);
    assert_eq!(ticket.frozen_effects(), 9);

    drain_domain(&mut model, &ticket, DomainId::Scheduler);
    assert_eq!(
        issue_accept(&mut model, &ticket, DomainId::Scheduler).sequence(),
        1
    );
    drain_domain(&mut model, &ticket, DomainId::Pager);
    assert_eq!(
        issue_accept(&mut model, &ticket, DomainId::Pager).sequence(),
        2
    );

    assert_eq!(
        model.close_next(&ticket, DomainId::VirtIo),
        Ok(Some(CloseStep::NeedsQuiescence))
    );
    let tombstone = model.timeout_virtio(&ticket).unwrap();
    let timeout = issue_accept(&mut model, &ticket, DomainId::VirtIo);
    assert_eq!(timeout.sequence(), 3);
    assert_eq!(timeout.status(), ReceiptStatus::TimedOut);
    assert_eq!(
        model.revoke_complete(&ticket),
        Err(CompositionError::RevokeTimedOut)
    );
    assert_eq!(model.retry_virtio(&ticket, tombstone), Ok(2));
    assert_eq!(
        model.close_next(&ticket, DomainId::VirtIo),
        Ok(Some(CloseStep::Drained(EffectKind::BlockReq)))
    );
    assert_eq!(
        issue_accept(&mut model, &ticket, DomainId::VirtIo).sequence(),
        4
    );

    for (domain, sequence) in [
        (DomainId::Filesystem, 5),
        (DomainId::Readiness, 6),
        (DomainId::Network, 7),
        (DomainId::Personality, 8),
    ] {
        drain_domain(&mut model, &ticket, domain);
        let receipt = issue_accept(&mut model, &ticket, domain);
        assert_eq!(receipt.sequence(), sequence);
        assert_eq!(receipt.effect_count(), domain.effect_count());
        assert_eq!(receipt.credit_units(), domain.effect_count());
    }
    model.revoke_complete(&ticket).unwrap();

    let projection = model.projection();
    assert_eq!(projection.phase, RootPhase::Revoked);
    assert_eq!(projection.accepted_receipts, 8);
    assert_eq!(projection.invalidated_receipts, 1);
    assert_eq!(projection.receipt_revision, 8);
    assert_eq!(projection.free_credits, [2, 1, 1, 1, 1, 1, 1, 1]);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn revoke_before_both_io_commits_aborts_nine_effects_without_publication() {
    let mut model = LinuxIoCompositionModel::new();
    for kind in [EffectKind::FsOp, EffectKind::NetOp, EffectKind::BufferLease] {
        model.prepare(model.token(kind)).unwrap();
    }
    let ticket = model.revoke_begin().unwrap();
    close_without_timeout(&mut model, &ticket);
    assert_eq!(model.projection().publications, [0; 9]);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn filesystem_visible_network_suppressed_split_preserves_only_inode_history() {
    let mut model = LinuxIoCompositionModel::new();
    commit_one(&mut model, EffectKind::FsOp);
    let ticket = model.revoke_begin().unwrap();
    close_without_timeout(&mut model, &ticket);
    assert_eq!(model.publication_count(PublicationPoint::Inode), 1);
    assert_eq!(model.publication_count(PublicationPoint::NetCommit), 0);
    assert_eq!(model.publication_count(PublicationPoint::NetReply), 0);
    assert_eq!(model.publication_count(PublicationPoint::FsReply), 0);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn network_visible_filesystem_suppressed_split_closure_drains_buffer() {
    let mut model = LinuxIoCompositionModel::new();
    commit_network(&mut model);
    let ticket = model.revoke_begin().unwrap();
    close_without_timeout(&mut model, &ticket);
    assert_eq!(model.publication_count(PublicationPoint::NetCommit), 1);
    assert_eq!(model.publication_count(PublicationPoint::BufferVisible), 1);
    assert_eq!(model.publication_count(PublicationPoint::Inode), 0);
    assert_eq!(model.publication_count(PublicationPoint::NetReply), 0);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn filesystem_crash_rebind_adopt_advances_only_filesystem_binding() {
    let mut model = LinuxIoCompositionModel::new();
    let old = model.token(EffectKind::FsOp);
    model.prepare(old).unwrap();
    let before_bindings = model.projection().bindings;
    model.crash(DomainId::Filesystem).unwrap();
    let crashed = model.clone();
    assert_eq!(model.commit(old), Err(CompositionError::StaleBinding));
    assert_eq!(model, crashed);
    let snapshot = model.recovery_snapshot(DomainId::Filesystem).unwrap();
    assert_eq!(snapshot.cohort(), &[old]);
    let ready = model.ready(snapshot).unwrap();
    model.rebind(&ready).unwrap();
    let adopted = model.adopt(&ready, old).unwrap();
    model.commit(adopted).unwrap();
    for domain in DomainId::ALL {
        let expected = before_bindings[domain as usize] + u64::from(domain == DomainId::Filesystem);
        assert_eq!(model.binding_epoch(domain), expected);
    }
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn network_crash_rebind_adopts_net_and_buffer_without_advancing_peers() {
    let mut model = LinuxIoCompositionModel::new();
    let old_net = model.token(EffectKind::NetOp);
    let old_buffer = model.token(EffectKind::BufferLease);
    model.prepare(old_net).unwrap();
    model.prepare(old_buffer).unwrap();
    let before_bindings = model.projection().bindings;
    model.crash(DomainId::Network).unwrap();
    let snapshot = model.recovery_snapshot(DomainId::Network).unwrap();
    assert_eq!(snapshot.cohort(), &[old_net, old_buffer]);
    let ready = model.ready(snapshot).unwrap();
    model.rebind(&ready).unwrap();
    let net = model.adopt(&ready, old_net).unwrap();
    let buffer = model.adopt(&ready, old_buffer).unwrap();
    model.commit_network(net, buffer).unwrap();
    for domain in DomainId::ALL {
        let expected = before_bindings[domain as usize] + u64::from(domain == DomainId::Network);
        assert_eq!(model.binding_epoch(domain), expected);
    }
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn readiness_and_revoke_have_both_orders_without_fabricated_guest_reply() {
    let mut ready_first = LinuxIoCompositionModel::new();
    let (network, _) = commit_network(&mut ready_first);
    let wait = ready_first.token(EffectKind::ReadinessWait);
    ready_first.prepare(wait).unwrap();
    ready_first.commit_ready(wait, network).unwrap();
    let ticket = ready_first.revoke_begin().unwrap();
    close_without_timeout(&mut ready_first, &ticket);
    assert_eq!(
        ready_first.publication_count(PublicationPoint::ReadyCommit),
        1
    );
    assert_eq!(ready_first.publication_count(PublicationPoint::NetReply), 0);

    let mut revoke_first = LinuxIoCompositionModel::new();
    commit_network(&mut revoke_first);
    let wait = revoke_first.token(EffectKind::ReadinessWait);
    revoke_first.prepare(wait).unwrap();
    let ticket = revoke_first.revoke_begin().unwrap();
    let closed = revoke_first.clone();
    assert_eq!(
        revoke_first.commit(wait),
        Err(CompositionError::StaleAuthority)
    );
    assert_eq!(revoke_first, closed);
    close_without_timeout(&mut revoke_first, &ticket);
    assert_eq!(
        revoke_first.publication_count(PublicationPoint::ReadyCommit),
        0
    );
    assert_eq!(
        revoke_first.publication_count(PublicationPoint::NetReply),
        0
    );
}

#[test]
fn stale_envelopes_and_closure_receipts_reject_with_full_model_equality() {
    for (kind, generation) in [
        (EffectKind::PagerMap, GenerationKind::AddressSpace),
        (EffectKind::FsOp, GenerationKind::Inode),
        (EffectKind::BlockReq, GenerationKind::Device),
        (EffectKind::NetOp, GenerationKind::Socket),
        (EffectKind::ReadinessWait, GenerationKind::Source),
    ] {
        let mut model = LinuxIoCompositionModel::new();
        let old = model.token(kind);
        model.advance_generation(generation).unwrap();
        let before = model.clone();
        assert_eq!(model.prepare(old), Err(CompositionError::StaleGeneration));
        assert_eq!(model, before);
    }

    let mut model = LinuxIoCompositionModel::new();
    let token = model.token(EffectKind::FsSyscall);
    let before = model.clone();
    assert_eq!(
        model.prepare(token.with_authority_epoch(2)),
        Err(CompositionError::StaleAuthority)
    );
    assert_eq!(model, before);
    let before = model.clone();
    assert_eq!(
        model.prepare(token.with_binding_epoch(2)),
        Err(CompositionError::StaleBinding)
    );
    assert_eq!(model, before);

    let ticket = model.revoke_begin().unwrap();
    drain_domain(&mut model, &ticket, DomainId::Scheduler);
    let receipt = model
        .issue_domain_receipt(&ticket, DomainId::Scheduler)
        .unwrap();
    let issued = model.clone();
    assert_eq!(
        model.accept_domain_receipt(&ticket, receipt.with_authority_epoch(1)),
        Err(CompositionError::StaleReceipt)
    );
    assert_eq!(model, issued);
    assert_eq!(
        model.accept_domain_receipt(&ticket, receipt.with_sequence(2)),
        Err(CompositionError::OutOfOrderReceipt)
    );
    assert_eq!(model, issued);
    model.accept_domain_receipt(&ticket, receipt).unwrap();
    let accepted = model.clone();
    assert_eq!(
        model.accept_domain_receipt(&ticket, receipt),
        Err(CompositionError::DuplicateReceipt)
    );
    assert_eq!(model, accepted);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn closing_generation_advance_rejects_without_expiring_current_receipt() {
    let mut model = LinuxIoCompositionModel::new();
    let ticket = model.revoke_begin().unwrap();
    drain_domain(&mut model, &ticket, DomainId::Scheduler);
    issue_accept(&mut model, &ticket, DomainId::Scheduler);
    drain_domain(&mut model, &ticket, DomainId::Pager);
    issue_accept(&mut model, &ticket, DomainId::Pager);

    let closing = model.clone();
    assert_eq!(
        model.advance_generation(GenerationKind::AddressSpace),
        Err(CompositionError::RootNotActive)
    );
    assert_eq!(model, closing);
    assert_eq!(model.check_invariants(), Ok(()));
}
