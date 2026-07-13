#[path = "production_identity_support/mod.rs"]
mod support;

use cser_model::production_identity::{
    CREDIT_CLASS_COUNT, ClosureResult, CreditClass, DomainId, EffectPhase, OperationClass,
    ParentIdentity, ProductionIdentityError, ProductionIdentityModel, RegistryInstance, RootId,
    RootPhase, ServiceInstanceId, TombstoneKind,
};
use support::prepared_model;

#[test]
fn normal_read_preserves_one_tree_through_device_and_one_shot_guest_reply() {
    let (mut model, identities) = prepared_model();
    let commit = model
        .commit_block(
            model.binding(DomainId::VirtIo).unwrap(),
            identities.block,
            identities.dma_owners(),
        )
        .unwrap();
    model.complete_backend(commit).unwrap();
    model.acknowledge_iotlb(commit).unwrap();
    let reply = model
        .publish_guest_reply(identities.syscall, identities.filesystem, commit)
        .unwrap();

    assert_eq!(reply.syscall(), identities.syscall);
    let projection = model.projection();
    assert_eq!(projection.effects.len(), 6);
    assert!(projection.root_live.is_empty());
    assert_eq!(projection.counters.commits, 1);
    assert_eq!(projection.counters.guest_replies, 1);
    assert_eq!(projection.counters.terminalizations, 6);
    assert_eq!(projection.ledger.free, [0; CREDIT_CLASS_COUNT]);
    assert_eq!(
        projection.ledger.returned,
        core::array::from_fn(|index| CreditClass::ALL[index].capacity())
    );
    assert!(
        projection
            .effects
            .iter()
            .all(|effect| effect.phase == EffectPhase::Completed)
    );

    let ticket = model.revoke_begin(model.root_identity()).unwrap();
    assert!(ticket.frozen_effects().is_empty());
    assert!(matches!(
        model.revoke_complete(ticket),
        Ok(ClosureResult::Revoked { .. })
    ));
    assert_eq!(model.projection().root_phase, RootPhase::Revoked);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn crash_snapshot_ready_rebind_adopt_changes_only_current_binding() {
    let (mut model, identities) = prepared_model();
    let old_binding = model.binding(DomainId::Filesystem).unwrap();
    let immutable_identity = identities.filesystem;
    model.crash_domain(old_binding).unwrap();

    let rejected = model.projection();
    assert_eq!(
        model.prepare_effect(old_binding, identities.filesystem),
        Err(ProductionIdentityError::StaleBinding)
    );
    assert_eq!(model.projection(), rejected);

    let snapshot = model
        .snapshot_domain(model.root_identity(), DomainId::Filesystem)
        .unwrap();
    assert_eq!(snapshot.cohort(), &[immutable_identity]);
    let ready = model.ready_domain(snapshot).unwrap();
    let replacement = model
        .rebind_domain(ready, ServiceInstanceId::new(41))
        .unwrap();
    let adopted = model.adopt_effect(replacement, immutable_identity).unwrap();
    assert_eq!(adopted, immutable_identity);
    assert_eq!(adopted.origin_binding(), old_binding);

    let projection = model.projection();
    let filesystem = projection
        .effects
        .iter()
        .find(|effect| effect.identity.operation() == OperationClass::FilesystemRead)
        .unwrap();
    assert_eq!(filesystem.identity, immutable_identity);
    assert_eq!(filesystem.current_binding, replacement);
    assert_eq!(filesystem.adoptions, 1);
    for domain in [DomainId::Personality, DomainId::VirtIo] {
        assert_eq!(model.binding(domain).unwrap().binding_epoch(), 1);
    }
    assert_eq!(replacement.binding_epoch(), 2);

    model
        .commit_block(
            model.binding(DomainId::VirtIo).unwrap(),
            identities.block,
            identities.dma_owners(),
        )
        .unwrap();
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn reset_timeout_is_indeterminate_until_same_identity_retry_and_iotlb_ack() {
    let (mut model, identities) = prepared_model();
    let commit = model
        .commit_block(
            model.binding(DomainId::VirtIo).unwrap(),
            identities.block,
            identities.dma_owners(),
        )
        .unwrap();
    let ticket = model.revoke_begin(model.root_identity()).unwrap();
    let tombstone = model.retain_reset_timeout(ticket.clone(), commit).unwrap();

    assert_eq!(tombstone.block(), identities.block.key());
    assert_eq!(
        tombstone.dma_owners(),
        identities.dma_owners().map(|identity| identity.key())
    );
    assert!(matches!(
        model.revoke_complete(ticket.clone()),
        Ok(ClosureResult::IndeterminateAfterReset { .. })
    ));
    let retained = model.projection();
    assert_eq!(retained.root_phase, RootPhase::Closing);
    assert_eq!(retained.ledger.retained[CreditClass::QueueSlot as usize], 1);
    assert_eq!(
        retained.ledger.retained[CreditClass::PinnedPage as usize],
        3
    );
    assert_eq!(
        retained.ledger.retained[CreditClass::DmaMapping as usize],
        3
    );

    let retry = model.retry_after_reset(ticket.clone(), tombstone).unwrap();
    assert_eq!(retry.tombstone(), tombstone);
    assert_eq!(retry.new_device().device_generation(), 2);
    let before_stale_completion = model.projection();
    assert_eq!(
        model.complete_backend(commit),
        Err(ProductionIdentityError::StaleDeviceGeneration)
    );
    assert_eq!(model.projection(), before_stale_completion);

    let iotlb_tombstone = model.retain_iotlb_timeout(ticket.clone(), retry).unwrap();
    assert_eq!(iotlb_tombstone.kind(), TombstoneKind::Iotlb);
    assert_ne!(iotlb_tombstone.id(), tombstone.id());
    assert_eq!(iotlb_tombstone.block(), identities.block.key());
    assert_eq!(iotlb_tombstone.dma_owners(), tombstone.dma_owners());
    assert_eq!(iotlb_tombstone.old_device(), retry.new_device());
    assert!(matches!(
        model.revoke_complete(ticket.clone()),
        Ok(ClosureResult::IndeterminateAfterReset { .. })
    ));
    let iotlb_retry = model.retry_iotlb(ticket.clone(), iotlb_tombstone).unwrap();
    assert_eq!(iotlb_retry.device(), retry.new_device());
    model.acknowledge_retry_iotlb(iotlb_retry).unwrap();
    let reply = model
        .publish_guest_reply(identities.syscall, identities.filesystem, commit)
        .unwrap();
    assert_eq!(
        reply.outcome(),
        cser_model::production_identity::BackendOutcome::IndeterminateAfterReset
    );
    assert!(matches!(
        model.revoke_complete(ticket),
        Ok(ClosureResult::Revoked { .. })
    ));

    let projection = model.projection();
    assert_eq!(projection.root_phase, RootPhase::Revoked);
    assert_eq!(projection.device.identity.device_generation(), 2);
    assert_eq!(projection.counters.reset_timeouts, 1);
    assert_eq!(projection.counters.reset_retries, 1);
    assert_eq!(projection.counters.iotlb_timeouts, 1);
    assert_eq!(projection.counters.iotlb_retries, 1);
    assert_eq!(projection.counters.iotlb_acks, 1);
    assert_eq!(projection.effects.len(), 6);
    assert!(
        projection
            .effects
            .iter()
            .zip(identities.all())
            .all(|(projected, original)| projected.identity == original)
    );
    assert_eq!(
        projection.closure_order,
        vec![
            identities.dma_a.key(),
            identities.dma_b.key(),
            identities.dma_request.key(),
            identities.block.key(),
            identities.filesystem.key(),
            identities.syscall.key(),
        ]
    );
    assert_eq!(projection.counters.unrelated_index_visits, 0);
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn revoke_winner_aborts_the_complete_tree_in_leaf_first_order() {
    let (mut model, identities) = prepared_model();
    let old_root = model.root_identity();
    let ticket = model.revoke_begin(old_root).unwrap();
    let revoked_projection = model.projection();
    assert_eq!(
        model.commit_block(
            model.binding(DomainId::VirtIo).unwrap(),
            identities.block,
            identities.dma_owners(),
        ),
        Err(ProductionIdentityError::RootNotActive)
    );
    assert_eq!(model.projection(), revoked_projection);

    while !model.projection().root_live.is_empty() {
        model.revoke_next(ticket.clone()).unwrap();
    }
    assert_eq!(
        model.projection().closure_order,
        vec![
            identities.dma_a.key(),
            identities.dma_b.key(),
            identities.dma_request.key(),
            identities.block.key(),
            identities.filesystem.key(),
            identities.syscall.key(),
        ]
    );
    assert!(matches!(
        model.revoke_complete(ticket),
        Ok(ClosureResult::Revoked { .. })
    ));
    assert_eq!(model.check_invariants(), Ok(()));
}

#[test]
fn wrong_parent_registration_rejects_the_complete_projection() {
    let mut model = ProductionIdentityModel::new(RegistryInstance::new(7), RootId::new(11), 3);
    let root = model.root_identity();
    let syscall = model
        .register_effect(
            root,
            model.binding(DomainId::Personality).unwrap(),
            OperationClass::FilesystemSyscall,
            ParentIdentity::Root(root.lineage()),
        )
        .unwrap();
    let before = model.projection();
    assert_eq!(
        model.register_effect(
            root,
            model.binding(DomainId::Filesystem).unwrap(),
            OperationClass::FilesystemRead,
            ParentIdentity::Root(root.lineage()),
        ),
        Err(ProductionIdentityError::WrongParent)
    );
    assert_eq!(model.projection(), before);
    assert_eq!(
        model.effect(OperationClass::FilesystemSyscall),
        Some(syscall)
    );
}
