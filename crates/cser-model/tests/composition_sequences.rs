use cser_model::ScopeState;
use cser_model::composition::{
    ClosureStatus, CompositionEffectKind, CompositionEffectState, CompositionError,
    CompositionModel, CreditBundle, DomainBindingToken, DomainCloseStep, DomainFallbackState,
    DomainId, RevokeOutcome, ServiceId, TombstoneState,
};

#[derive(Clone, Copy)]
struct Bindings {
    scheduler: DomainBindingToken,
    pager: DomainBindingToken,
    personality: DomainBindingToken,
    readiness: DomainBindingToken,
    virtio: DomainBindingToken,
}

fn five_domain_model(credits: CreditBundle) -> (CompositionModel, cser_model::ScopeId, Bindings) {
    let mut model = CompositionModel::new();
    let scope = model.create_scope(credits).unwrap();
    let bindings = Bindings {
        scheduler: model
            .register_domain(scope, DomainId::Scheduler, ServiceId::new(1))
            .unwrap(),
        pager: model
            .register_domain(scope, DomainId::Pager, ServiceId::new(2))
            .unwrap(),
        personality: model
            .register_domain(scope, DomainId::Personality, ServiceId::new(3))
            .unwrap(),
        readiness: model
            .register_domain(scope, DomainId::Readiness, ServiceId::new(4))
            .unwrap(),
        virtio: model
            .register_domain(scope, DomainId::VirtIo, ServiceId::new(5))
            .unwrap(),
    };
    (model, scope, bindings)
}

#[test]
fn five_domains_close_one_causal_graph_with_an_honest_timeout_and_retry() {
    let initial = CreditBundle::new(4, 4, 8, 2, 4, 8192);
    let (mut model, scope, bindings) = five_domain_model(initial);
    let root = model
        .register_root(
            bindings.personality,
            CompositionEffectKind::PersonalitySyscall,
            initial,
        )
        .unwrap();
    let pager = model
        .derive_child(
            root,
            bindings.pager,
            CompositionEffectKind::PagerFault,
            CreditBundle::new(1, 1, 1, 0, 0, 0),
        )
        .unwrap();
    let scheduler = model
        .derive_child(
            pager,
            bindings.scheduler,
            CompositionEffectKind::SchedulerAction,
            CreditBundle::new(1, 0, 0, 0, 0, 0),
        )
        .unwrap();
    let readiness = model
        .derive_child(
            root,
            bindings.readiness,
            CompositionEffectKind::ReadinessWait,
            CreditBundle::new(0, 0, 1, 1, 1, 4096),
        )
        .unwrap();
    let virtio = model
        .derive_child(
            readiness,
            bindings.virtio,
            CompositionEffectKind::VirtIoRequest,
            CreditBundle::new(0, 0, 0, 1, 1, 4096),
        )
        .unwrap();

    model.prepare(bindings.personality, root).unwrap();
    model.commit(bindings.personality, root).unwrap();
    model.prepare(bindings.pager, pager).unwrap();
    model.prepare(bindings.readiness, readiness).unwrap();
    model.commit(bindings.readiness, readiness).unwrap();
    model.prepare(bindings.virtio, virtio).unwrap();
    model.commit(bindings.virtio, virtio).unwrap();

    let ticket = model.revoke_begin(scope).unwrap();
    let closing = model.scope(scope).unwrap();
    assert_eq!(closing.state, ScopeState::Closing);
    assert_eq!(closing.authority_epoch.get(), 2);
    assert_eq!(closing.frozen_domains, DomainId::ALL);

    let before_stale_child = model.clone();
    assert!(matches!(
        model.derive_child(
            root,
            bindings.scheduler,
            CompositionEffectKind::SchedulerAction,
            CreditBundle::new(1, 0, 0, 0, 0, 0),
        ),
        Err(CompositionError::ScopeNotActive(ScopeState::Closing))
    ));
    assert_eq!(model, before_stale_child);
    let before_stale_commit = model.clone();
    assert!(matches!(
        model.commit(bindings.pager, pager),
        Err(CompositionError::ScopeNotActive(ScopeState::Closing))
    ));
    assert_eq!(model, before_stale_commit);

    assert_eq!(
        model.close_next(ticket, DomainId::Scheduler).unwrap(),
        Some(DomainCloseStep::Aborted(scheduler.effect()))
    );
    assert_eq!(
        model.close_next(ticket, DomainId::Pager).unwrap(),
        Some(DomainCloseStep::Aborted(pager.effect()))
    );
    assert_eq!(
        model.close_next(ticket, DomainId::Readiness).unwrap(),
        Some(DomainCloseStep::BlockedByDescendants { remaining: 1 })
    );
    assert_eq!(
        model.close_next(ticket, DomainId::VirtIo).unwrap(),
        Some(DomainCloseStep::NeedsQuiescence(virtio.effect()))
    );
    let tombstone = model.timeout_committed(ticket, virtio).unwrap();
    let before_duplicate_timeout = model.clone();
    assert_eq!(
        model.timeout_committed(ticket, virtio),
        Err(CompositionError::NotTombstoneEligible)
    );
    assert_eq!(model, before_duplicate_timeout);
    let retained = model.effect(virtio.effect()).unwrap();
    assert_eq!(retained.state, CompositionEffectState::Tombstoned);
    assert_eq!(retained.terminalizations, 0);
    assert_eq!(
        retained.held_credits,
        CreditBundle::new(0, 0, 0, 1, 1, 4096)
    );
    assert_eq!(model.scope(scope).unwrap().state, ScopeState::Closing);
    assert_ne!(model.scope(scope).unwrap().free_credits, initial);
    let io_progress = model.closure_progress(scope, DomainId::VirtIo).unwrap();
    assert_eq!(io_progress.terminalized, 0);
    assert_eq!(io_progress.remaining, 1);
    model.check_invariants().unwrap();
    assert_eq!(
        model.close_next(ticket, DomainId::Readiness).unwrap(),
        Some(DomainCloseStep::BlockedByDescendants { remaining: 1 })
    );

    let mut closed_sequences = Vec::new();
    for domain in [DomainId::Scheduler, DomainId::Pager] {
        let receipt = model.issue_domain_receipt(ticket, domain).unwrap();
        assert_eq!(receipt.status(), &ClosureStatus::Closed);
        closed_sequences.push(receipt.sequence());
        model.accept_domain_receipt(ticket, &receipt).unwrap();
    }
    let timeout_receipt = model
        .issue_domain_receipt(ticket, DomainId::VirtIo)
        .unwrap();
    assert!(matches!(
        timeout_receipt.status(),
        ClosureStatus::TimedOut { tombstones, .. } if tombstones == &[tombstone]
    ));
    let before_duplicate_issue = model.clone();
    assert_eq!(
        model.issue_domain_receipt(ticket, DomainId::VirtIo),
        Err(CompositionError::DuplicateClosureReceipt)
    );
    assert_eq!(model, before_duplicate_issue);
    model
        .accept_domain_receipt(ticket, &timeout_receipt)
        .unwrap();
    assert_eq!(
        model.accept_domain_receipt(ticket, &timeout_receipt),
        Err(CompositionError::DuplicateClosureReceipt)
    );

    assert_eq!(
        model.revoke_complete(ticket).unwrap(),
        RevokeOutcome::TimedOut {
            pending_domains: vec![DomainId::VirtIo],
            tombstones: vec![tombstone],
            retained_credits: CreditBundle::new(0, 0, 0, 1, 1, 4096),
        }
    );
    let old_device = model
        .domain(scope, DomainId::VirtIo)
        .unwrap()
        .device_generation;
    assert_eq!(timeout_receipt.device_generation(), old_device);
    assert_eq!(
        timeout_receipt.binding_epoch(),
        bindings.virtio.binding_epoch()
    );
    let retry = model.begin_tombstone_retry(ticket, tombstone).unwrap();
    let before_stale_receipt = model.clone();
    assert_eq!(
        model.accept_domain_receipt(ticket, &timeout_receipt),
        Err(CompositionError::StaleClosureReceipt)
    );
    assert_eq!(model, before_stale_receipt);
    assert_eq!(
        model.revoke_complete(ticket),
        Err(CompositionError::MissingClosureReceipts(vec![
            DomainId::Personality,
            DomainId::Readiness,
            DomainId::VirtIo
        ]))
    );
    model.tombstone_retry_ack(retry).unwrap();
    assert_eq!(
        model.tombstone(tombstone).unwrap().state,
        TombstoneState::Released
    );
    assert_eq!(
        model
            .domain(scope, DomainId::VirtIo)
            .unwrap()
            .device_generation
            .get(),
        old_device.get() + 1
    );
    let retried = model.effect(virtio.effect()).unwrap();
    assert_eq!(retried.state, CompositionEffectState::Committed);
    assert!(retried.external_quiesced);
    assert_eq!(retried.terminalizations, 0);
    assert_eq!(
        model.close_next(ticket, DomainId::VirtIo).unwrap(),
        Some(DomainCloseStep::Completed(virtio.effect()))
    );
    assert_eq!(
        model.close_next(ticket, DomainId::Readiness).unwrap(),
        Some(DomainCloseStep::Completed(readiness.effect()))
    );
    assert_eq!(
        model.close_next(ticket, DomainId::Personality).unwrap(),
        Some(DomainCloseStep::Completed(root.effect()))
    );
    for domain in [DomainId::Personality, DomainId::Readiness, DomainId::VirtIo] {
        let receipt = model.issue_domain_receipt(ticket, domain).unwrap();
        assert_eq!(receipt.status(), &ClosureStatus::Closed);
        assert!(receipt.sequence() > timeout_receipt.sequence());
        if domain == DomainId::VirtIo {
            assert_eq!(receipt.device_generation().get(), old_device.get() + 1);
            assert_eq!(receipt.binding_epoch(), bindings.virtio.binding_epoch());
        }
        closed_sequences.push(receipt.sequence());
        model.accept_domain_receipt(ticket, &receipt).unwrap();
    }
    closed_sequences.sort_unstable();
    closed_sequences.dedup();
    assert_eq!(closed_sequences.len(), DomainId::ALL.len());
    assert_eq!(
        model.revoke_complete(ticket).unwrap(),
        RevokeOutcome::Revoked
    );
    let scope_view = model.scope(scope).unwrap();
    assert_eq!(scope_view.state, ScopeState::Revoked);
    assert_eq!(scope_view.free_credits, initial);
    for effect in [root, scheduler, pager, readiness, virtio] {
        assert_eq!(model.effect(effect.effect()).unwrap().terminalizations, 1);
    }
    assert_eq!(
        model.effect(scheduler.effect()).unwrap().parent,
        Some(pager.effect())
    );
    assert_eq!(
        model.effect(virtio.effect()).unwrap().parent,
        Some(readiness.effect())
    );
    model.check_invariants().unwrap();
}

#[test]
fn domain_crash_rebind_is_exact_and_does_not_advance_root_or_device_generation() {
    let initial = CreditBundle::new(0, 2, 4, 0, 0, 0);
    let (mut model, scope, bindings) = five_domain_model(initial);
    let root = model
        .register_root(
            bindings.personality,
            CompositionEffectKind::PersonalitySyscall,
            initial,
        )
        .unwrap();
    let orphan = model
        .derive_child(
            root,
            bindings.pager,
            CompositionEffectKind::PagerFault,
            CreditBundle::new(0, 1, 1, 0, 0, 0),
        )
        .unwrap();
    let kernel_owned = model
        .derive_child(
            root,
            bindings.pager,
            CompositionEffectKind::PagerFault,
            CreditBundle::new(0, 1, 1, 0, 0, 0),
        )
        .unwrap();
    model.prepare(bindings.pager, orphan).unwrap();
    model.prepare(bindings.pager, kernel_owned).unwrap();
    let receipt = model.commit(bindings.pager, kernel_owned).unwrap();
    let before = model.domain(scope, DomainId::Pager).unwrap();
    let peer_bindings = [
        DomainId::Scheduler,
        DomainId::Personality,
        DomainId::Readiness,
        DomainId::VirtIo,
    ]
    .map(|domain| model.domain(scope, domain).unwrap().binding_epoch);
    let virtio_device = model
        .domain(scope, DomainId::VirtIo)
        .unwrap()
        .device_generation;

    model.crash(bindings.pager).unwrap();
    let crashed = model.domain(scope, DomainId::Pager).unwrap();
    assert_eq!(crashed.binding_epoch.get(), before.binding_epoch.get() + 1);
    assert_eq!(crashed.device_generation, before.device_generation);
    assert_eq!(model.scope(scope).unwrap().authority_epoch.get(), 1);
    assert_eq!(crashed.fallback, DomainFallbackState::Required);
    assert_eq!(
        [
            DomainId::Scheduler,
            DomainId::Personality,
            DomainId::Readiness,
            DomainId::VirtIo,
        ]
        .map(|domain| model.domain(scope, domain).unwrap().binding_epoch),
        peer_bindings
    );
    assert_eq!(
        model
            .domain(scope, DomainId::VirtIo)
            .unwrap()
            .device_generation,
        virtio_device
    );
    let before_stale = model.clone();
    assert_eq!(
        model.commit(bindings.pager, orphan),
        Err(CompositionError::StaleBinding)
    );
    assert_eq!(model, before_stale);

    model.fallback_pick(scope, DomainId::Pager).unwrap();
    let stale_snapshot = model
        .recovery_snapshot(scope, DomainId::Pager, ServiceId::new(22))
        .unwrap();
    assert_eq!(stale_snapshot.adoption_cohort(), &[orphan.effect()]);
    model.complete(receipt).unwrap();
    assert_eq!(
        model.ready(&stale_snapshot),
        Err(CompositionError::StaleRecoveryProof)
    );

    let snapshot = model
        .recovery_snapshot(scope, DomainId::Pager, ServiceId::new(22))
        .unwrap();
    assert_eq!(snapshot.effects().len(), 1);
    assert_eq!(snapshot.adoption_cohort(), &[orphan.effect()]);
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();
    assert_eq!(replacement.binding_epoch(), crashed.binding_epoch);
    assert_eq!(replacement.device_generation(), crashed.device_generation);
    assert_eq!(
        model.commit(replacement, orphan),
        Err(CompositionError::EffectIdentityMismatch)
    );
    let adopted = model.adopt(replacement, orphan).unwrap();
    assert_eq!(adopted.parent(), Some(root.effect()));
    assert_eq!(
        model.effect(adopted.effect()).unwrap().parent,
        Some(root.effect())
    );
    model.commit(replacement, adopted).unwrap();
    assert_eq!(
        model.adopt(replacement, orphan),
        Err(CompositionError::EffectIdentityMismatch)
    );
    assert_eq!(
        model
            .domain(scope, DomainId::Pager)
            .unwrap()
            .adoption_cohort,
        Vec::new()
    );
    model.check_invariants().unwrap();
}

#[test]
fn peer_child_completion_invalidates_a_crashed_parent_domain_snapshot() {
    let initial = CreditBundle::new(0, 0, 2, 0, 0, 0);
    let (mut model, scope, bindings) = five_domain_model(initial);
    let parent = model
        .register_root(bindings.pager, CompositionEffectKind::PagerFault, initial)
        .unwrap();
    let parent_before_derive = model
        .domain(scope, DomainId::Pager)
        .unwrap()
        .mutation_generation;
    let child_before_derive = model
        .domain(scope, DomainId::Scheduler)
        .unwrap()
        .mutation_generation;
    let child = model
        .derive_child(
            parent,
            bindings.scheduler,
            CompositionEffectKind::SchedulerAction,
            CreditBundle::new(0, 0, 1, 0, 0, 0),
        )
        .unwrap();
    assert_eq!(
        model
            .domain(scope, DomainId::Pager)
            .unwrap()
            .mutation_generation,
        parent_before_derive + 1
    );
    assert_eq!(
        model
            .domain(scope, DomainId::Scheduler)
            .unwrap()
            .mutation_generation,
        child_before_derive + 1
    );
    model.prepare(bindings.scheduler, child).unwrap();
    let child_receipt = model.commit(bindings.scheduler, child).unwrap();

    model.crash(bindings.pager).unwrap();
    model.fallback_pick(scope, DomainId::Pager).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, DomainId::Pager, ServiceId::new(32))
        .unwrap();
    assert_eq!(snapshot.adoption_cohort(), &[parent.effect()]);
    let parent_at_snapshot = model
        .domain(scope, DomainId::Pager)
        .unwrap()
        .mutation_generation;

    let mut issued_ready_branch = model.clone();
    let issued_ready = issued_ready_branch.ready(&snapshot).unwrap();
    issued_ready_branch.complete(child_receipt).unwrap();
    let before_stale_rebind = issued_ready_branch.clone();
    assert_eq!(
        issued_ready_branch.rebind(issued_ready),
        Err(CompositionError::StaleRecoveryProof)
    );
    assert_eq!(issued_ready_branch, before_stale_rebind);

    // Completion is kernel-owned by the Scheduler domain, but it returns a
    // typed credit, removes one child edge, and republishes the Pager leaf
    // index. Those parent-domain mutations must invalidate the old snapshot.
    model.complete(child_receipt).unwrap();
    let parent_after_completion = model.domain(scope, DomainId::Pager).unwrap();
    assert_eq!(
        parent_after_completion.mutation_generation,
        parent_at_snapshot + 1
    );
    assert_eq!(parent_after_completion.leaf_effects, vec![parent.effect()]);
    assert_eq!(model.effect(parent.effect()).unwrap().held_credits, initial);
    let before_stale_ready = model.clone();
    assert_eq!(
        model.ready(&snapshot),
        Err(CompositionError::StaleRecoveryProof)
    );
    assert_eq!(model, before_stale_ready);
    let fresh = model
        .recovery_snapshot(scope, DomainId::Pager, ServiceId::new(32))
        .unwrap();
    assert_eq!(fresh.effects().len(), 1);
    assert_eq!(fresh.adoption_cohort(), &[parent.effect()]);
    model.check_invariants().unwrap();
}

#[test]
fn failed_cross_domain_derivation_is_failure_atomic() {
    let initial = CreditBundle::new(0, 0, 2, 0, 0, 0);
    let (mut model, _scope, bindings) = five_domain_model(initial);
    let parent = model
        .register_root(
            bindings.personality,
            CompositionEffectKind::PersonalitySyscall,
            initial,
        )
        .unwrap();

    let before_wrong_domain = model.clone();
    assert_eq!(
        model.derive_child(
            parent,
            bindings.pager,
            CompositionEffectKind::SchedulerAction,
            CreditBundle::new(0, 0, 1, 0, 0, 0),
        ),
        Err(CompositionError::WrongDomain)
    );
    assert_eq!(model, before_wrong_domain);

    let before_exhaustion = model.clone();
    assert_eq!(
        model.derive_child(
            parent,
            bindings.pager,
            CompositionEffectKind::PagerFault,
            CreditBundle::new(0, 1, 1, 0, 0, 0),
        ),
        Err(CompositionError::CreditExhausted)
    );
    assert_eq!(model, before_exhaustion);

    model.crash(bindings.personality).unwrap();
    let before_stale_parent = model.clone();
    assert_eq!(
        model.derive_child(
            parent,
            bindings.pager,
            CompositionEffectKind::PagerFault,
            CreditBundle::new(0, 0, 1, 0, 0, 0),
        ),
        Err(CompositionError::EffectIdentityMismatch)
    );
    assert_eq!(model, before_stale_parent);

    model.crash(bindings.pager).unwrap();
    let before_stale_target = model.clone();
    assert_eq!(
        model.derive_child(
            parent,
            bindings.pager,
            CompositionEffectKind::PagerFault,
            CreditBundle::new(0, 0, 1, 0, 0, 0),
        ),
        Err(CompositionError::StaleBinding)
    );
    assert_eq!(model, before_stale_target);
    assert_eq!(model.global_effect_count(), 1);
    assert_eq!(model.effect(parent.effect()).unwrap().held_credits, initial);
    model.check_invariants().unwrap();
}

#[test]
fn root_revocation_uses_only_the_target_scope_domain_index() {
    let mut model = CompositionModel::new();
    let target = model
        .create_scope(CreditBundle::new(0, 0, 1, 0, 0, 0))
        .unwrap();
    let target_binding = model
        .register_domain(target, DomainId::Personality, ServiceId::new(1))
        .unwrap();
    model
        .register_domain(target, DomainId::Readiness, ServiceId::new(9))
        .unwrap();
    let target_effect = model
        .register_root(
            target_binding,
            CompositionEffectKind::PersonalitySyscall,
            CreditBundle::new(0, 0, 1, 0, 0, 0),
        )
        .unwrap();

    let noisy = model
        .create_scope(CreditBundle::new(0, 0, 64, 0, 0, 0))
        .unwrap();
    let noisy_binding = model
        .register_domain(noisy, DomainId::Personality, ServiceId::new(2))
        .unwrap();
    for _ in 0..64 {
        model
            .register_root(
                noisy_binding,
                CompositionEffectKind::PersonalitySyscall,
                CreditBundle::new(0, 0, 1, 0, 0, 0),
            )
            .unwrap();
    }
    assert_eq!(model.global_effect_count(), 65);

    let ticket = model.revoke_begin(target).unwrap();
    assert_eq!(
        model.scope(target).unwrap().frozen_domains,
        vec![DomainId::Personality]
    );
    assert_eq!(
        model.close_next(ticket, DomainId::Personality).unwrap(),
        Some(DomainCloseStep::Aborted(target_effect.effect()))
    );
    let progress = model
        .closure_progress(target, DomainId::Personality)
        .unwrap();
    assert_eq!(progress.target_count, 1);
    assert_eq!(progress.terminalized, 1);
    assert_eq!(progress.index_selections, 1);
    assert_eq!(progress.remaining, 0);
    assert_eq!(
        model
            .domain(noisy, DomainId::Personality)
            .unwrap()
            .live_effects
            .len(),
        64
    );
    let receipt = model
        .issue_domain_receipt(ticket, DomainId::Personality)
        .unwrap();
    model.accept_domain_receipt(ticket, &receipt).unwrap();
    assert_eq!(
        model.revoke_complete(ticket).unwrap(),
        RevokeOutcome::Revoked
    );
    assert_eq!(model.scope(noisy).unwrap().state, ScopeState::Active);
    model.check_invariants().unwrap();
}

#[test]
fn a_cross_scope_timeout_ticket_rejects_without_polluting_either_scope() {
    let credits = CreditBundle::new(0, 0, 0, 1, 1, 4096);
    let mut model = CompositionModel::new();
    let closing_scope = model.create_scope(credits).unwrap();
    let closing_binding = model
        .register_domain(closing_scope, DomainId::VirtIo, ServiceId::new(41))
        .unwrap();
    model
        .register_root(
            closing_binding,
            CompositionEffectKind::VirtIoRequest,
            credits,
        )
        .unwrap();

    let active_scope = model.create_scope(credits).unwrap();
    let active_binding = model
        .register_domain(active_scope, DomainId::VirtIo, ServiceId::new(42))
        .unwrap();
    let foreign = model
        .register_root(
            active_binding,
            CompositionEffectKind::VirtIoRequest,
            credits,
        )
        .unwrap();
    model.prepare(active_binding, foreign).unwrap();
    model.commit(active_binding, foreign).unwrap();

    let ticket = model.revoke_begin(closing_scope).unwrap();
    let before = model.clone();
    assert_eq!(
        model.timeout_committed(ticket, foreign),
        Err(CompositionError::CrossScopeEffect {
            ticket_scope: closing_scope,
            effect_scope: active_scope,
        })
    );
    assert_eq!(model, before);
    assert!(
        model
            .domain(closing_scope, DomainId::VirtIo)
            .unwrap()
            .tombstones
            .is_empty()
    );
    assert!(
        model
            .domain(active_scope, DomainId::VirtIo)
            .unwrap()
            .tombstones
            .is_empty()
    );
    assert_eq!(
        model.effect(foreign.effect()).unwrap().state,
        CompositionEffectState::Committed
    );
    assert_eq!(
        model.scope(closing_scope).unwrap().state,
        ScopeState::Closing
    );
    assert_eq!(model.scope(active_scope).unwrap().state, ScopeState::Active);
    model.check_invariants().unwrap();
}

#[test]
fn retry_timeout_keeps_the_tombstone_and_requires_a_fresh_receipt() {
    let initial = CreditBundle::new(0, 0, 0, 1, 1, 4096);
    let (mut model, scope, bindings) = five_domain_model(initial);
    let io = model
        .register_root(
            bindings.virtio,
            CompositionEffectKind::VirtIoRequest,
            initial,
        )
        .unwrap();
    model.prepare(bindings.virtio, io).unwrap();
    model.commit(bindings.virtio, io).unwrap();
    let ticket = model.revoke_begin(scope).unwrap();
    let tombstone = model.timeout_committed(ticket, io).unwrap();
    assert_eq!(
        model.effect(io.effect()).unwrap().state,
        CompositionEffectState::Tombstoned
    );
    assert_eq!(model.effect(io.effect()).unwrap().terminalizations, 0);
    let old = model
        .issue_domain_receipt(ticket, DomainId::VirtIo)
        .unwrap();
    model.accept_domain_receipt(ticket, &old).unwrap();
    let retry = model.begin_tombstone_retry(ticket, tombstone).unwrap();
    model.tombstone_retry_timeout(retry).unwrap();
    assert_eq!(
        model.tombstone(tombstone).unwrap().state,
        TombstoneState::Retained
    );
    assert_eq!(
        model.accept_domain_receipt(ticket, &old),
        Err(CompositionError::StaleClosureReceipt)
    );
    let fresh = model
        .issue_domain_receipt(ticket, DomainId::VirtIo)
        .unwrap();
    assert!(fresh.sequence() > old.sequence());
    assert!(fresh.revision() > old.revision());
    model.check_invariants().unwrap();
}

#[test]
fn public_effect_states_keep_timeout_nonterminal() {
    assert!(CompositionEffectState::Completed.is_terminal());
    assert!(CompositionEffectState::Aborted.is_terminal());
    assert!(!CompositionEffectState::Tombstoned.is_terminal());
    assert!(!CompositionEffectState::Committed.is_terminal());
}
