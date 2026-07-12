use cser_model::{
    ScopeState,
    runtime_fs::{
        FsCreditClass, FsCredits, FsDmaRecoveryKind, FsDmaState, FsDomain, FsEffectPhase,
        FsFallbackState, RuntimeFsBindings, RuntimeFsClosureStep, RuntimeFsError, RuntimeFsModel,
        RuntimeFsRevokeTicket, RuntimeFsServices, RuntimeFsToken, ServiceId,
    },
};

fn services(base: u64) -> RuntimeFsServices {
    RuntimeFsServices::new(
        ServiceId::new(base + 1),
        ServiceId::new(base + 2),
        ServiceId::new(base + 3),
        ServiceId::new(base + 4),
    )
}

fn one_request() -> (RuntimeFsModel, cser_model::ScopeId, RuntimeFsBindings) {
    let mut model = RuntimeFsModel::new();
    let (scope, bindings) = model
        .create_scope(services(0), FsCredits::ONE_REQUEST)
        .unwrap();
    (model, scope, bindings)
}

fn prepare_write_path(
    model: &mut RuntimeFsModel,
    bindings: RuntimeFsBindings,
    token: RuntimeFsToken,
) {
    model
        .prepare_syscall(bindings.get(FsDomain::Personality), token.syscall())
        .unwrap();
    model
        .prepare_filesystem(bindings.get(FsDomain::Filesystem), token.filesystem())
        .unwrap();
    model
        .prepare_block(bindings.get(FsDomain::Block), token.block())
        .unwrap();
}

fn drain_without_dma(model: &mut RuntimeFsModel, ticket: RuntimeFsRevokeTicket) {
    loop {
        match model.revoke_next(ticket).unwrap() {
            Some(RuntimeFsClosureStep::Aborted(_) | RuntimeFsClosureStep::Completed(_)) => {}
            Some(step) => panic!("unexpected retained closure step: {step:?}"),
            None => break,
        }
    }
}

#[test]
fn normal_pwrite_publishes_each_boundary_once_then_closes_an_empty_root() {
    let (mut model, scope, bindings) = one_request();
    let token = model.register_pwrite(bindings).unwrap();

    prepare_write_path(&mut model, bindings, token);
    model
        .prepare_pager_map(bindings.get(FsDomain::Pager), token.pager())
        .unwrap();
    let pager = model
        .commit_pager_map(bindings.get(FsDomain::Pager), token.pager())
        .unwrap();
    let pwrite = model
        .commit_pwrite(bindings.get(FsDomain::Filesystem), token.filesystem())
        .unwrap();
    let block = model
        .commit_block(bindings.get(FsDomain::Block), token.block())
        .unwrap();
    let iotlb = model.observe_block_completion(block).unwrap();
    assert_eq!(iotlb.kind(), FsDmaRecoveryKind::Iotlb);
    assert_eq!(
        model.acknowledge_iotlb(iotlb).unwrap(),
        FsEffectPhase::Completed
    );
    model
        .complete_filesystem(bindings.get(FsDomain::Filesystem), token.filesystem())
        .unwrap();
    model
        .complete_pager_map(bindings.get(FsDomain::Pager), token.pager())
        .unwrap();
    let publication = model
        .commit_syscall_reply(bindings.get(FsDomain::Personality), token.syscall(), 2)
        .unwrap();
    model.publish_reply(publication).unwrap();

    assert_eq!(pager.generation().get(), 2);
    assert_eq!(pwrite.generation().get(), 2);
    assert_eq!(pwrite.version(), 1);
    assert_eq!(pwrite.word(), 0x0000_7879);
    assert_eq!(block.avail_index(), 1);
    let active = model.scope(scope).unwrap();
    assert_eq!(active.state, ScopeState::Active);
    assert_eq!(active.free_credits, FsCredits::ONE_REQUEST);
    assert_eq!(active.mapping_publications, 1);
    assert_eq!(active.pwrite_publications, 1);
    assert_eq!(active.avail_index, 1);
    assert_eq!(active.reply_publications, 1);
    assert_eq!(active.live_effects, 0);

    let ticket = model.revoke_begin(scope).unwrap();
    assert_eq!(model.revoke_next(ticket).unwrap(), None);
    model.revoke_complete(ticket).unwrap();
    let revoked = model.scope(scope).unwrap();
    assert_eq!(revoked.state, ScopeState::Revoked);
    assert_eq!(revoked.closure_target_count, 0);
    assert_eq!(revoked.closure_steps, 0);
    model.check_invariants().unwrap();
}

#[test]
fn revoke_before_pwrite_aborts_the_fixed_graph_without_publication() {
    let (mut model, scope, bindings) = one_request();
    let token = model.register_pwrite(bindings).unwrap();
    let ticket = model.revoke_begin(scope).unwrap();
    drain_without_dma(&mut model, ticket);
    model.revoke_complete(ticket).unwrap();

    let view = model.scope(scope).unwrap();
    assert_eq!(view.state, ScopeState::Revoked);
    assert_eq!(view.inode_word, 0);
    assert_eq!(view.inode_version, 0);
    assert_eq!(view.pwrite_publications, 0);
    assert_eq!(view.reply_publications, 0);
    assert_eq!(view.free_credits, FsCredits::ONE_REQUEST);
    for effect in [
        token.syscall(),
        token.pager(),
        token.filesystem(),
        token.block(),
    ] {
        let effect = model.effect(effect.effect()).unwrap();
        assert_eq!(effect.phase, FsEffectPhase::Aborted);
        assert_eq!(effect.terminalizations, 1);
    }
    model.check_invariants().unwrap();
}

#[test]
fn pwrite_visible_reply_absent() {
    let (mut model, scope, bindings) = one_request();
    let token = model.register_pwrite(bindings).unwrap();
    model
        .prepare_syscall(bindings.get(FsDomain::Personality), token.syscall())
        .unwrap();
    model
        .prepare_filesystem(bindings.get(FsDomain::Filesystem), token.filesystem())
        .unwrap();
    model
        .commit_pwrite(bindings.get(FsDomain::Filesystem), token.filesystem())
        .unwrap();

    let ticket = model.revoke_begin(scope).unwrap();
    drain_without_dma(&mut model, ticket);
    model.revoke_complete(ticket).unwrap();

    let view = model.scope(scope).unwrap();
    assert_eq!(view.inode_word, 0x0000_7879);
    assert_eq!(view.inode_version, 1);
    assert_eq!(view.pwrite_publications, 1);
    assert_eq!(view.reply_publications, 0);
    assert_eq!(
        model.effect(token.filesystem().effect()).unwrap().phase,
        FsEffectPhase::Completed
    );
    assert_eq!(
        model.effect(token.syscall().effect()).unwrap().phase,
        FsEffectPhase::Aborted
    );
    model.check_invariants().unwrap();
}

#[test]
fn committed_syscall_reply_remains_a_one_shot_closure_obligation() {
    let (mut model, scope, bindings) = one_request();
    let token = model.register_pwrite(bindings).unwrap();
    prepare_write_path(&mut model, bindings, token);
    model
        .prepare_pager_map(bindings.get(FsDomain::Pager), token.pager())
        .unwrap();
    model
        .commit_pager_map(bindings.get(FsDomain::Pager), token.pager())
        .unwrap();
    model
        .commit_pwrite(bindings.get(FsDomain::Filesystem), token.filesystem())
        .unwrap();
    let block = model
        .commit_block(bindings.get(FsDomain::Block), token.block())
        .unwrap();
    let iotlb = model.observe_block_completion(block).unwrap();
    model.acknowledge_iotlb(iotlb).unwrap();
    model
        .complete_filesystem(bindings.get(FsDomain::Filesystem), token.filesystem())
        .unwrap();
    model
        .complete_pager_map(bindings.get(FsDomain::Pager), token.pager())
        .unwrap();
    let publication = model
        .commit_syscall_reply(bindings.get(FsDomain::Personality), token.syscall(), 2)
        .unwrap();

    let ticket = model.revoke_begin(scope).unwrap();
    assert_eq!(
        model.revoke_next(ticket).unwrap(),
        Some(RuntimeFsClosureStep::AwaitingReply(publication))
    );
    model.publish_reply(publication).unwrap();
    let before_duplicate = model.clone();
    assert_eq!(
        model.publish_reply(publication),
        Err(RuntimeFsError::AlreadyPublished)
    );
    assert_eq!(model, before_duplicate);
    assert_eq!(model.revoke_next(ticket).unwrap(), None);
    model.revoke_complete(ticket).unwrap();

    let view = model.scope(scope).unwrap();
    assert_eq!(view.reply_publications, 1);
    assert_eq!(view.closure_target_count, 1);
    assert_eq!(view.closure_steps, 1);
    model.check_invariants().unwrap();
}

#[test]
fn pager_crash_requires_rebind_and_adoption_before_mapping_publication() {
    let (mut model, scope, bindings) = one_request();
    let token = model.register_pwrite(bindings).unwrap();
    model
        .prepare_pager_map(bindings.get(FsDomain::Pager), token.pager())
        .unwrap();
    model.crash(bindings.get(FsDomain::Pager)).unwrap();
    assert_eq!(
        model.domain(scope, FsDomain::Pager).unwrap().fallback,
        FsFallbackState::Required
    );
    let before_stale = model.clone();
    assert!(matches!(
        model.commit_pager_map(bindings.get(FsDomain::Pager), token.pager()),
        Err(RuntimeFsError::StaleBinding { .. })
    ));
    assert_eq!(model, before_stale);

    model.fallback_pick(scope, FsDomain::Pager).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, FsDomain::Pager, ServiceId::new(20))
        .unwrap();
    assert_eq!(snapshot.cohort(), &[token.pager()]);
    let ready = model.ready(&snapshot).unwrap();
    let binding = model.rebind(ready).unwrap();
    let orphan = model.recover_next(binding).unwrap().unwrap();
    assert_eq!(orphan, token.pager());
    let adopted = model.adopt(binding, orphan).unwrap();
    assert_eq!(adopted.effect(), token.pager().effect());
    assert_ne!(adopted.binding_epoch(), token.pager().binding_epoch());
    assert_eq!(model.recover_next(binding).unwrap(), None);
    model.commit_pager_map(binding, adopted).unwrap();
    model.complete_pager_map(binding, adopted).unwrap();

    let ticket = model.revoke_begin(scope).unwrap();
    drain_without_dma(&mut model, ticket);
    model.revoke_complete(ticket).unwrap();
    assert_eq!(model.scope(scope).unwrap().mapping_publications, 1);
    model.check_invariants().unwrap();
}

#[test]
fn filesystem_crash_requires_rebind_and_adoption_before_visible_write() {
    let (mut model, scope, bindings) = one_request();
    let token = model.register_pwrite(bindings).unwrap();
    model
        .prepare_syscall(bindings.get(FsDomain::Personality), token.syscall())
        .unwrap();
    model
        .prepare_filesystem(bindings.get(FsDomain::Filesystem), token.filesystem())
        .unwrap();
    model.crash(bindings.get(FsDomain::Filesystem)).unwrap();
    model.fallback_pick(scope, FsDomain::Filesystem).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, FsDomain::Filesystem, ServiceId::new(30))
        .unwrap();
    let ready = model.ready(&snapshot).unwrap();
    let binding = model.rebind(ready).unwrap();
    let adopted = model
        .adopt(binding, model.recover_next(binding).unwrap().unwrap())
        .unwrap();
    model.commit_pwrite(binding, adopted).unwrap();

    let ticket = model.revoke_begin(scope).unwrap();
    drain_without_dma(&mut model, ticket);
    model.revoke_complete(ticket).unwrap();
    let view = model.scope(scope).unwrap();
    assert_eq!(view.inode_word, 0x0000_7879);
    assert_eq!(view.pwrite_publications, 1);
    assert_eq!(view.reply_publications, 0);
    model.check_invariants().unwrap();
}

#[test]
fn committed_block_request_drains_through_kernel_and_device_after_block_crash() {
    let (mut model, scope, bindings) = one_request();
    let token = model.register_pwrite(bindings).unwrap();
    prepare_write_path(&mut model, bindings, token);
    model
        .commit_pwrite(bindings.get(FsDomain::Filesystem), token.filesystem())
        .unwrap();
    let receipt = model
        .commit_block(bindings.get(FsDomain::Block), token.block())
        .unwrap();
    model.crash(bindings.get(FsDomain::Block)).unwrap();
    assert!(
        model
            .domain(scope, FsDomain::Block)
            .unwrap()
            .recovery_cohort
            .is_empty()
    );

    let iotlb = model.observe_block_completion(receipt).unwrap();
    model.acknowledge_iotlb(iotlb).unwrap();
    assert_eq!(
        model.effect(token.block().effect()).unwrap().phase,
        FsEffectPhase::Completed
    );
    let ticket = model.revoke_begin(scope).unwrap();
    drain_without_dma(&mut model, ticket);
    model.revoke_complete(ticket).unwrap();
    assert_eq!(
        model.scope(scope).unwrap().free_credits,
        FsCredits::ONE_REQUEST
    );
    model.check_invariants().unwrap();
}

#[test]
fn reset_timeout_retry_retains_identity_until_reset_and_iotlb_ack() {
    let (mut model, scope, bindings) = one_request();
    let token = model.register_pwrite(bindings).unwrap();
    prepare_write_path(&mut model, bindings, token);
    model
        .commit_pwrite(bindings.get(FsDomain::Filesystem), token.filesystem())
        .unwrap();
    let receipt = model
        .commit_block(bindings.get(FsDomain::Block), token.block())
        .unwrap();
    let ticket = model.revoke_begin(scope).unwrap();
    assert!(matches!(
        model.revoke_next(ticket).unwrap(),
        Some(RuntimeFsClosureStep::Aborted(_))
    ));
    let reset = match model.revoke_next(ticket).unwrap() {
        Some(RuntimeFsClosureStep::NeedsDma(recovery)) => recovery,
        step => panic!("expected reset recovery, got {step:?}"),
    };
    assert_eq!(reset.kind(), FsDmaRecoveryKind::Reset);
    let tombstone = model.dma_timeout(reset).unwrap();
    assert_eq!(tombstone.effect(), token.block().effect());
    assert_eq!(
        model.scope(scope).unwrap().device_generation.get(),
        1,
        "reset timeout must not advance the device generation"
    );
    assert_eq!(
        model.scope(scope).unwrap().free_credits.dma(),
        0,
        "timeout must retain the DMA credit"
    );
    assert_eq!(
        model.revoke_next(ticket).unwrap(),
        Some(RuntimeFsClosureStep::RetainedTombstone(tombstone))
    );
    let retry = model.retry_tombstone(tombstone).unwrap();
    assert_eq!(retry.effect(), reset.effect());
    assert!(retry.attempt() > reset.attempt());
    assert_eq!(model.scope(scope).unwrap().device_generation.get(), 1);
    let before_stale_tombstone = model.clone();
    assert_eq!(
        model.retry_tombstone(tombstone),
        Err(RuntimeFsError::StaleTombstone)
    );
    assert_eq!(model, before_stale_tombstone);

    let iotlb = model.acknowledge_reset(retry).unwrap();
    assert_eq!(iotlb.kind(), FsDmaRecoveryKind::Iotlb);
    assert_eq!(iotlb.device_generation().get(), 2);
    let before_stale_receipt = model.clone();
    assert!(matches!(
        model.observe_block_completion(receipt),
        Err(RuntimeFsError::StaleDeviceGeneration { .. })
    ));
    assert_eq!(model, before_stale_receipt);
    assert_eq!(model.scope(scope).unwrap().free_credits.dma(), 0);
    model.acknowledge_iotlb(iotlb).unwrap();
    assert_eq!(model.scope(scope).unwrap().free_credits.dma(), 1);
    drain_without_dma(&mut model, ticket);
    model.revoke_complete(ticket).unwrap();
    assert_eq!(model.scope(scope).unwrap().tombstones, 0);
    assert_eq!(
        model.scope(scope).unwrap().free_credits,
        FsCredits::ONE_REQUEST
    );
    model.check_invariants().unwrap();
}

#[test]
fn iotlb_timeout_retry_retains_dma_credit_until_fresh_ack() {
    let (mut model, scope, bindings) = one_request();
    let token = model.register_pwrite(bindings).unwrap();
    model
        .prepare_block(bindings.get(FsDomain::Block), token.block())
        .unwrap();
    let ticket = model.revoke_begin(scope).unwrap();
    assert!(matches!(
        model.revoke_next(ticket).unwrap(),
        Some(RuntimeFsClosureStep::Aborted(_))
    ));
    let iotlb = match model.revoke_next(ticket).unwrap() {
        Some(RuntimeFsClosureStep::NeedsDma(recovery)) => recovery,
        step => panic!("expected IOTLB recovery, got {step:?}"),
    };
    assert_eq!(iotlb.kind(), FsDmaRecoveryKind::Iotlb);
    let tombstone = model.dma_timeout(iotlb).unwrap();
    assert_eq!(tombstone.kind(), FsDmaRecoveryKind::Iotlb);
    assert_eq!(model.scope(scope).unwrap().device_generation.get(), 1);
    assert_eq!(
        model.effect(token.block().effect()).unwrap().dma_state,
        FsDmaState::IotlbTimedOut
    );
    assert_eq!(model.scope(scope).unwrap().free_credits.dma(), 0);
    let retry = model.retry_tombstone(tombstone).unwrap();
    assert_eq!(retry.effect(), token.block().effect());
    assert_eq!(
        model.acknowledge_iotlb(retry).unwrap(),
        FsEffectPhase::Aborted
    );
    assert_eq!(model.scope(scope).unwrap().free_credits.dma(), 1);
    drain_without_dma(&mut model, ticket);
    model.revoke_complete(ticket).unwrap();
    model.check_invariants().unwrap();
}

#[test]
fn stale_authority_binding_and_all_generations_reject_failure_atomically() {
    let mut model = RuntimeFsModel::new();
    let credits = FsCredits::new(2, 2, 2, 2);
    let (scope, bindings) = model.create_scope(services(100), credits).unwrap();
    let first = model.register_pwrite(bindings).unwrap();
    let second = model.register_pwrite(bindings).unwrap();

    model
        .prepare_pager_map(bindings.get(FsDomain::Pager), first.pager())
        .unwrap();
    model
        .prepare_pager_map(bindings.get(FsDomain::Pager), second.pager())
        .unwrap();
    model
        .commit_pager_map(bindings.get(FsDomain::Pager), first.pager())
        .unwrap();
    let before_stale_as = model.clone();
    assert!(matches!(
        model.commit_pager_map(bindings.get(FsDomain::Pager), second.pager()),
        Err(RuntimeFsError::StaleAddressSpaceGeneration { .. })
    ));
    assert_eq!(model, before_stale_as);

    for token in [first, second] {
        model
            .prepare_syscall(bindings.get(FsDomain::Personality), token.syscall())
            .unwrap();
        model
            .prepare_filesystem(bindings.get(FsDomain::Filesystem), token.filesystem())
            .unwrap();
    }
    model
        .commit_pwrite(bindings.get(FsDomain::Filesystem), first.filesystem())
        .unwrap();
    let before_stale_inode = model.clone();
    assert!(matches!(
        model.commit_pwrite(bindings.get(FsDomain::Filesystem), second.filesystem()),
        Err(RuntimeFsError::StaleInodeGeneration { .. })
    ));
    assert_eq!(model, before_stale_inode);

    model.crash(bindings.get(FsDomain::Pager)).unwrap();
    let before_stale_binding = model.clone();
    assert!(matches!(
        model.complete_pager_map(bindings.get(FsDomain::Pager), first.pager()),
        Err(RuntimeFsError::StaleBinding { .. })
    ));
    assert_eq!(model, before_stale_binding);

    let ticket = model.revoke_begin(scope).unwrap();
    let before_stale_authority = model.clone();
    assert!(matches!(
        model.register_pwrite(bindings),
        Err(RuntimeFsError::StaleAuthority { .. })
    ));
    assert_eq!(model, before_stale_authority);
    assert_eq!(model.scope(scope).unwrap().state, ScopeState::Closing);
    assert_eq!(model.scope(scope).unwrap().free_credits.control(), 0);
    assert_eq!(
        model.scope(scope).unwrap().closure_target_count,
        2 * 4,
        "committed and uncommitted effects are both frozen while still live"
    );
    let _ = ticket;
    model.check_invariants().unwrap();

    let (mut reset_model, reset_scope, reset_bindings) = one_request();
    let reset_token = reset_model.register_pwrite(reset_bindings).unwrap();
    prepare_write_path(&mut reset_model, reset_bindings, reset_token);
    reset_model
        .commit_pwrite(
            reset_bindings.get(FsDomain::Filesystem),
            reset_token.filesystem(),
        )
        .unwrap();
    let receipt = reset_model
        .commit_block(reset_bindings.get(FsDomain::Block), reset_token.block())
        .unwrap();
    let reset_ticket = reset_model.revoke_begin(reset_scope).unwrap();
    assert!(matches!(
        reset_model.revoke_next(reset_ticket).unwrap(),
        Some(RuntimeFsClosureStep::Aborted(_))
    ));
    let reset = match reset_model.revoke_next(reset_ticket).unwrap() {
        Some(RuntimeFsClosureStep::NeedsDma(recovery)) => recovery,
        step => panic!("expected reset recovery, got {step:?}"),
    };
    let iotlb = reset_model.acknowledge_reset(reset).unwrap();
    let before_stale_device = reset_model.clone();
    assert!(matches!(
        reset_model.observe_block_completion(receipt),
        Err(RuntimeFsError::StaleDeviceGeneration { .. })
    ));
    assert_eq!(reset_model, before_stale_device);
    let before_stale_reset = reset_model.clone();
    assert!(matches!(
        reset_model.acknowledge_reset(reset),
        Err(RuntimeFsError::StaleDeviceGeneration { .. })
    ));
    assert_eq!(reset_model, before_stale_reset);
    reset_model.acknowledge_iotlb(iotlb).unwrap();
    reset_model.check_invariants().unwrap();

    assert_eq!(
        FsCreditClass::Dma,
        reset_model
            .effect(reset_token.block().effect())
            .unwrap()
            .credit
    );
}
