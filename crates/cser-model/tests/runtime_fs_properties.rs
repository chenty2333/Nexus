use cser_model::{
    ScopeId, ScopeState,
    runtime_fs::{
        BlockCommitReceipt, FsCredits, FsDmaRecoveryKind, FsDmaRecoveryToken, FsDomain,
        FsEffectPhase, FsPublicationTicket, RuntimeFsBindings, RuntimeFsClosureStep,
        RuntimeFsError, RuntimeFsModel, RuntimeFsServices, RuntimeFsToken, ServiceId,
    },
};
use proptest::prelude::*;

fn services() -> RuntimeFsServices {
    RuntimeFsServices::new(
        ServiceId::new(1),
        ServiceId::new(2),
        ServiceId::new(3),
        ServiceId::new(4),
    )
}

fn finish_dma(model: &mut RuntimeFsModel, recovery: FsDmaRecoveryToken) {
    match recovery.kind() {
        FsDmaRecoveryKind::Reset => {
            let iotlb = model.acknowledge_reset(recovery).unwrap();
            assert_eq!(iotlb.kind(), FsDmaRecoveryKind::Iotlb);
            model.acknowledge_iotlb(iotlb).unwrap();
        }
        FsDmaRecoveryKind::Iotlb => {
            model.acknowledge_iotlb(recovery).unwrap();
        }
    }
}

fn close_scope(model: &mut RuntimeFsModel, scope: ScopeId) {
    let ticket = model.revoke_begin(scope).unwrap();
    let mut iterations = 0usize;
    loop {
        iterations += 1;
        assert!(iterations <= 64, "bounded graph must make closure progress");
        match model.revoke_next(ticket).unwrap() {
            Some(RuntimeFsClosureStep::Aborted(_) | RuntimeFsClosureStep::Completed(_)) => {}
            Some(
                RuntimeFsClosureStep::NeedsDma(recovery)
                | RuntimeFsClosureStep::AwaitingDma(recovery),
            ) => finish_dma(model, recovery),
            Some(RuntimeFsClosureStep::RetainedTombstone(tombstone)) => {
                let recovery = model.retry_tombstone(tombstone).unwrap();
                finish_dma(model, recovery);
            }
            Some(RuntimeFsClosureStep::AwaitingReply(publication)) => {
                model.publish_reply(publication).unwrap();
            }
            None => break,
        }
        model.check_invariants().unwrap();
    }
    model.revoke_complete(ticket).unwrap();
    model.check_invariants().unwrap();
}

struct ActiveReceipts {
    block: Option<BlockCommitReceipt>,
    iotlb: Option<FsDmaRecoveryToken>,
    publication: Option<FsPublicationTicket>,
}

fn attempt_action(
    model: &mut RuntimeFsModel,
    scope: ScopeId,
    bindings: RuntimeFsBindings,
    token: RuntimeFsToken,
    receipts: &mut ActiveReceipts,
    action: u8,
) -> Result<(), RuntimeFsError> {
    match action % 20 {
        0 => model.prepare_syscall(bindings.get(FsDomain::Personality), token.syscall()),
        1 => model.prepare_pager_map(bindings.get(FsDomain::Pager), token.pager()),
        2 => model.prepare_filesystem(bindings.get(FsDomain::Filesystem), token.filesystem()),
        3 => model.prepare_block(bindings.get(FsDomain::Block), token.block()),
        4 => model
            .commit_pager_map(bindings.get(FsDomain::Pager), token.pager())
            .map(|_| ()),
        5 => model
            .commit_pwrite(bindings.get(FsDomain::Filesystem), token.filesystem())
            .map(|_| ()),
        6 => model
            .commit_block(bindings.get(FsDomain::Block), token.block())
            .map(|receipt| receipts.block = Some(receipt)),
        7 => {
            let Some(receipt) = receipts.block else {
                return model
                    .commit_block(bindings.get(FsDomain::Block), token.block())
                    .map(|receipt| receipts.block = Some(receipt));
            };
            model
                .observe_block_completion(receipt)
                .map(|recovery| receipts.iotlb = Some(recovery))
        }
        8 => {
            let Some(recovery) = receipts.iotlb else {
                return model
                    .complete_filesystem(bindings.get(FsDomain::Filesystem), token.filesystem());
            };
            model
                .acknowledge_iotlb(recovery)
                .map(|_| receipts.iotlb = None)
        }
        9 => model.complete_pager_map(bindings.get(FsDomain::Pager), token.pager()),
        10 => model.complete_filesystem(bindings.get(FsDomain::Filesystem), token.filesystem()),
        11 => model
            .commit_syscall_reply(bindings.get(FsDomain::Personality), token.syscall(), 2)
            .map(|publication| receipts.publication = Some(publication)),
        12 => {
            let Some(publication) = receipts.publication else {
                return model
                    .commit_syscall_reply(bindings.get(FsDomain::Personality), token.syscall(), 2)
                    .map(|publication| receipts.publication = Some(publication));
            };
            model
                .publish_reply(publication)
                .map(|()| receipts.publication = None)
        }
        13..=16 => {
            let domain = FsDomain::ALL[usize::from(action % 4)];
            model.crash(bindings.get(domain))
        }
        _ => {
            let domain = FsDomain::ALL[usize::from(action % 4)];
            model.fallback_pick(scope, domain)
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn bounded_action_sequences_preserve_invariants_reject_atomically_and_close(
        actions in prop::collection::vec(any::<u8>(), 1..40),
    ) {
        let mut model = RuntimeFsModel::new();
        let (scope, bindings) = model
            .create_scope(services(), FsCredits::ONE_REQUEST)
            .unwrap();
        let token = model.register_pwrite(bindings).unwrap();
        let mut receipts = ActiveReceipts {
            block: None,
            iotlb: None,
            publication: None,
        };

        for action in actions {
            let before = model.clone();
            let result = attempt_action(
                &mut model,
                scope,
                bindings,
                token,
                &mut receipts,
                action,
            );
            if result.is_err() {
                prop_assert_eq!(&model, &before);
            }
            model.check_invariants().unwrap();
        }

        close_scope(&mut model, scope);
        let view = model.scope(scope).unwrap();
        prop_assert_eq!(view.state, ScopeState::Revoked);
        prop_assert_eq!(view.free_credits, FsCredits::ONE_REQUEST);
        prop_assert_eq!(view.live_effects, 0);
        prop_assert_eq!(view.pending_publications, 0);
        prop_assert_eq!(view.tombstones, 0);
        for effect in [
            token.syscall(),
            token.pager(),
            token.filesystem(),
            token.block(),
        ] {
            prop_assert_eq!(model.effect(effect.effect()).unwrap().terminalizations, 1);
        }
    }

    #[test]
    fn bounded_request_batches_conserve_each_typed_credit(
        count in 1usize..6,
        prepare_bits in prop::collection::vec(any::<u8>(), 1..24),
    ) {
        let capacity = count as u64;
        let initial = FsCredits::new(capacity, capacity, capacity, capacity);
        let mut model = RuntimeFsModel::new();
        let (scope, bindings) = model.create_scope(services(), initial).unwrap();
        let tokens: Vec<_> = (0..count)
            .map(|_| model.register_pwrite(bindings).unwrap())
            .collect();

        for (index, bits) in prepare_bits.into_iter().enumerate() {
            let token = tokens[index % tokens.len()];
            let operation = bits % 7;
            let before = model.clone();
            let result = match operation {
                0 => model.prepare_syscall(
                    bindings.get(FsDomain::Personality),
                    token.syscall(),
                ),
                1 => model.prepare_pager_map(bindings.get(FsDomain::Pager), token.pager()),
                2 => model.prepare_filesystem(
                    bindings.get(FsDomain::Filesystem),
                    token.filesystem(),
                ),
                3 => model.prepare_block(bindings.get(FsDomain::Block), token.block()),
                4 => model
                    .commit_pager_map(bindings.get(FsDomain::Pager), token.pager())
                    .map(|_| ()),
                5 => model
                    .commit_pwrite(
                        bindings.get(FsDomain::Filesystem),
                        token.filesystem(),
                    )
                    .map(|_| ()),
                _ => model
                    .commit_block(bindings.get(FsDomain::Block), token.block())
                    .map(|_| ()),
            };
            if result.is_err() {
                prop_assert_eq!(&model, &before);
            }
            model.check_invariants().unwrap();
        }

        close_scope(&mut model, scope);
        let view = model.scope(scope).unwrap();
        prop_assert_eq!(view.free_credits, initial);
        prop_assert_eq!(view.closure_steps, view.closure_target_count);
        for token in tokens {
            for effect in [
                token.syscall(),
                token.pager(),
                token.filesystem(),
                token.block(),
            ] {
                let effect = model.effect(effect.effect()).unwrap();
                prop_assert!(matches!(
                    effect.phase,
                    FsEffectPhase::Completed | FsEffectPhase::Aborted
                ));
                prop_assert_eq!(effect.terminalizations, 1);
            }
        }
    }
}
