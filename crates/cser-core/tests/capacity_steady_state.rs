#[allow(dead_code)]
mod support;

use cser_core::{
    AuthorityState, CatalogSet, CommandRequest as Command, ComponentProviderBinding, CoreError,
    CoreLimits, CustodyState, Engine, OperationRecoveryState, SettlementState, TransitionOutput,
    tool_dma_catalog,
};
use support::{
    EFFECT_APPLY_RECEIPT_SCHEMA, EFFECT_CATALOG_KIND, EFFECT_COMPONENT, EFFECT_EVIDENCE_KIND,
    EFFECT_RECEIPT_SCHEMA, EFFECT_SETTLEMENT_RECEIPT_SCHEMA, EFFECT_VERIFIER, Harness, charge,
    claim, committed_reply, current_evidence_command, digest, effect, executor, fence_and_rebind,
    freshness, prepared_reply, recovery_anchor, snapshot, snapshot_command,
    verified_apply_completion, verified_settlement_ack,
};

fn small_limits() -> CoreLimits {
    CoreLimits::new(1, 1, 1, 8, 1, 8, 8)
        .unwrap()
        .with_custody_limits(2, 2, 2)
        .unwrap()
}

fn admit(
    harness: &mut Harness,
    effect: cser_core::EffectId,
    origin: cser_core::ExecutorCoordinate,
) {
    harness
        .tx(Command::AdmitScopedCompositeEffect {
            effect,
            origin,
            kind: EFFECT_CATALOG_KIND,
            charge_account: charge(effect.operation().get()),
            bindings: vec![ComponentProviderBinding::new(
                EFFECT_COMPONENT,
                support::provider(),
            )],
        })
        .unwrap();
}

fn indeterminate_core_custody(harness: &mut Harness, operation: u64) -> cser_core::EffectId {
    let (effect, origin) = committed_reply(harness, operation);
    let successor = executor(operation, 2);
    fence_and_rebind(harness, effect, origin, successor, operation);
    let settlement = match harness.output(Command::ClaimComponentSettlement {
        effect,
        component: EFFECT_COMPONENT,
        claimant: successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    };
    harness
        .tx(settlement.mark_indeterminate(digest(operation as u8)))
        .unwrap();
    harness
        .tx(Command::FenceExecutor {
            operation: effect.operation(),
            crashed: successor,
        })
        .unwrap();
    effect
}

fn release_terminal_operation(harness: &mut Harness, operation: u64) -> cser_core::EffectId {
    let (effect, origin) = committed_reply(harness, operation);
    let settlement = match harness.output(Command::ClaimComponentSettlement {
        effect,
        component: EFFECT_COMPONENT,
        claimant: origin,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    };
    let settlement = match harness.output(
        settlement
            .record_apply_intent(digest(operation as u8))
            .unwrap(),
    ) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected apply-intent claim, got {other:?}"),
    };
    let applied = verified_apply_completion(
        harness,
        &settlement,
        EFFECT_VERIFIER,
        EFFECT_APPLY_RECEIPT_SCHEMA,
        digest((operation as u8).wrapping_add(1)),
    );
    let settlement = match harness.output(settlement.record_applied(applied).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected applied claim, got {other:?}"),
    };
    let acknowledgement = verified_settlement_ack(
        harness,
        &settlement,
        EFFECT_VERIFIER,
        EFFECT_SETTLEMENT_RECEIPT_SCHEMA,
        digest((operation as u8).wrapping_add(2)),
    );
    harness
        .tx(settlement.settle(acknowledgement).unwrap())
        .unwrap();
    harness
        .tx(current_evidence_command(
            harness,
            effect,
            claim(operation),
            EFFECT_EVIDENCE_KIND,
            cser_core::ReceiptBinding::new(EFFECT_VERIFIER, EFFECT_RECEIPT_SCHEMA),
            digest((operation as u8).wrapping_add(3)),
        ))
        .unwrap();
    harness
        .tx(Command::ReleaseCompositeEffect { effect })
        .unwrap();
    effect
}

#[test]
fn custody_reserve_admits_a_second_operation_but_rebind_respects_active_pressure() {
    let mut harness = Harness::with_limits(small_limits());
    let (custody_effect, crashed) = prepared_reply(&mut harness, 10);

    assert_eq!(
        harness.engine.pressure(),
        cser_core::PressureProjection {
            active_operations: 1,
            custody_operations: 0,
            active_composites: 1,
            custody_composites: 0,
            active_claim_records: 1,
            custody_claim_records: 0,
            retained_claims: 1,
            terminal_archive_entries: 0,
            quarantined: false,
            persistence_recovery_required: false,
        }
    );
    harness
        .tx(Command::FenceExecutor {
            operation: custody_effect.operation(),
            crashed,
        })
        .unwrap();
    assert_eq!(
        harness.engine.pressure(),
        cser_core::PressureProjection {
            active_operations: 0,
            custody_operations: 1,
            active_composites: 0,
            custody_composites: 1,
            active_claim_records: 0,
            custody_claim_records: 1,
            retained_claims: 1,
            terminal_archive_entries: 0,
            quarantined: false,
            persistence_recovery_required: false,
        }
    );

    let active_effect = effect(11, 1);
    admit(&mut harness, active_effect, executor(11, 1));
    assert_eq!(harness.engine.pressure().active_operations, 1);
    assert_eq!(harness.engine.pressure().custody_operations, 1);

    let recovery_snapshot = snapshot(10);
    harness
        .tx(snapshot_command(
            &harness,
            custody_effect.operation(),
            recovery_snapshot,
        ))
        .unwrap();
    harness
        .tx(Command::Ready {
            operation: custody_effect.operation(),
            snapshot: recovery_snapshot,
            successor: executor(10, 2),
        })
        .unwrap();
    let before_revision = harness.engine.revision();
    let before_head = harness.engine.head();
    let before_pressure = harness.engine.pressure();

    assert_eq!(
        harness.tx(Command::Rebind {
            operation: custody_effect.operation(),
            snapshot: recovery_snapshot,
            successor: executor(10, 2),
        }),
        Err(CoreError::CapacityExceeded)
    );
    assert_eq!(harness.engine.revision(), before_revision);
    assert_eq!(harness.engine.head(), before_head);
    assert_eq!(harness.engine.pressure(), before_pressure);
}

#[test]
fn adopt_refuses_to_bypass_active_effect_pressure_without_mutating_custody() {
    let mut harness = Harness::with_limits(small_limits());
    let (custody_effect, crashed) = prepared_reply(&mut harness, 20);
    let recovery_snapshot = snapshot(20);
    let successor = executor(20, 2);
    harness
        .tx(Command::FenceExecutor {
            operation: custody_effect.operation(),
            crashed,
        })
        .unwrap();
    harness
        .tx(snapshot_command(
            &harness,
            custody_effect.operation(),
            recovery_snapshot,
        ))
        .unwrap();
    harness
        .tx(Command::Ready {
            operation: custody_effect.operation(),
            snapshot: recovery_snapshot,
            successor,
        })
        .unwrap();
    harness
        .tx(Command::Rebind {
            operation: custody_effect.operation(),
            snapshot: recovery_snapshot,
            successor,
        })
        .unwrap();

    let active_effect = effect(20, 2);
    admit(&mut harness, active_effect, successor);
    let before_revision = harness.engine.revision();
    let before_head = harness.engine.head();
    let before_pressure = harness.engine.pressure();

    assert_eq!(
        harness.tx(Command::AdoptEffect {
            effect: custody_effect,
            successor,
        }),
        Err(CoreError::CapacityExceeded)
    );
    assert_eq!(harness.engine.revision(), before_revision);
    assert_eq!(harness.engine.head(), before_head);
    assert_eq!(harness.engine.pressure(), before_pressure);
    let custody = harness.engine.composite_effect(custody_effect).unwrap();
    assert_eq!(custody.authority, AuthorityState::Fenced);
    assert_eq!(custody.custodian, CustodyState::CoreOwned);
}

#[test]
fn cold_recovery_retains_indeterminate_core_custody_pressure() {
    let limits = small_limits();
    let mut harness = Harness::with_limits(limits);
    let custody_effect = indeterminate_core_custody(&mut harness, 30);
    assert!(matches!(
        harness
            .engine
            .component(custody_effect, EFFECT_COMPONENT)
            .unwrap()
            .settlement,
        SettlementState::ReconciliationRequired { applied: false, .. }
    ));
    assert_eq!(harness.engine.pressure().custody_operations, 1);
    assert_eq!(harness.engine.pressure().custody_composites, 1);
    assert_eq!(harness.engine.pressure().custody_claim_records, 1);

    let checkpoint = harness.checkpoint();
    let catalog = tool_dma_catalog();
    let catalogs = CatalogSet::new(core::slice::from_ref(&catalog)).unwrap();
    let recovered = Engine::recover(
        catalogs,
        limits,
        recovery_anchor(
            CatalogSet::new(core::slice::from_ref(&catalog))
                .unwrap()
                .digest(),
            freshness(1, 1, 1, 1),
            freshness(2, 1, 1, 2),
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        checkpoint.image(),
    )
    .unwrap()
    .into_engine();

    assert_eq!(recovered.pressure().custody_operations, 1);
    assert_eq!(recovered.pressure().custody_composites, 1);
    assert_eq!(recovered.pressure().custody_claim_records, 1);
    assert_eq!(
        recovered.operation(custody_effect.operation()),
        Some(OperationRecoveryState::Fenced {
            crashed: executor(30, 2),
            crash_generation: 2,
        })
    );
    assert!(matches!(
        recovered
            .component(custody_effect, EFFECT_COMPONENT)
            .unwrap()
            .settlement,
        SettlementState::ReconciliationRequired { applied: false, .. }
    ));
}

#[test]
fn cold_recovery_preserves_terminal_archive_and_rejects_replayed_operation() {
    let limits = small_limits();
    let mut harness = Harness::with_limits(limits);
    let released = release_terminal_operation(&mut harness, 35);
    harness
        .tx(cser_core::Command::compact_terminal_operation(
            released.operation(),
        ))
        .unwrap();
    let archive_root = harness.engine.terminal_archive_root();
    let archive_entries = harness.engine.terminal_archive_entries();
    let operation_high_water = harness.engine.terminal_operation_high_water();
    let artifact_high_water = harness.engine.terminal_artifact_high_water();
    let checkpoint = harness.checkpoint();
    let catalog = tool_dma_catalog();
    let catalogs = CatalogSet::new(core::slice::from_ref(&catalog)).unwrap();
    let mut recovered = Engine::recover(
        catalogs,
        limits,
        recovery_anchor(
            CatalogSet::new(core::slice::from_ref(&catalog))
                .unwrap()
                .digest(),
            freshness(1, 1, 1, 1),
            freshness(2, 1, 1, 2),
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        checkpoint.image(),
    )
    .unwrap()
    .into_engine();
    assert_eq!(recovered.terminal_archive_root(), archive_root);
    assert_eq!(recovered.terminal_archive_entries(), archive_entries);
    assert_eq!(
        recovered.terminal_operation_high_water(),
        operation_high_water
    );
    assert_eq!(
        recovered.terminal_artifact_high_water(),
        artifact_high_water
    );
    assert_eq!(recovered.operation(released.operation()), None);
    recovered
        .transact(
            Command::CheckpointRecovery {
                boot: cser_core::BootGeneration::new(2).unwrap(),
                journal: cser_core::JournalGeneration::new(2).unwrap(),
                device: cser_core::DeviceGeneration::new(1).unwrap(),
            },
            |_| Ok::<(), ()>(()),
        )
        .unwrap();
    let before_revision = recovered.revision();
    let before_head = recovered.head();
    let before_projection = recovered.projection_digest();
    let before_pressure = recovered.pressure();
    assert!(
        recovered
            .transact(replay_request(released), |_| Ok::<(), ()>(()))
            .is_err()
    );
    assert_eq!(recovered.revision(), before_revision);
    assert_eq!(recovered.head(), before_head);
    assert_eq!(recovered.projection_digest(), before_projection);
    assert_eq!(recovered.pressure(), before_pressure);
}

#[test]
fn released_operations_reclaim_resident_capacity_only_after_explicit_compaction() {
    let mut harness = Harness::with_limits(small_limits());

    for operation in 40..44 {
        let released = release_terminal_operation(&mut harness, operation);
        assert_eq!(harness.engine.pressure().active_operations, 1);
        assert_eq!(harness.engine.pressure().active_composites, 1);
        assert_eq!(harness.engine.pressure().active_claim_records, 1);
        harness
            .tx(cser_core::Command::compact_terminal_operation(
                released.operation(),
            ))
            .unwrap();
        assert_eq!(harness.engine.pressure().active_operations, 0);
        assert_eq!(harness.engine.pressure().active_composites, 0);
        assert_eq!(harness.engine.pressure().active_claim_records, 0);
        assert_eq!(
            harness.engine.pressure().terminal_archive_entries,
            operation - 39
        );

        let before_revision = harness.engine.revision();
        let before_head = harness.engine.head();
        let before_pressure = harness.engine.pressure();
        assert!(admit_replay(&mut harness, released).is_err());
        assert_eq!(harness.engine.revision(), before_revision);
        assert_eq!(harness.engine.head(), before_head);
        assert_eq!(harness.engine.pressure(), before_pressure);
    }
}

#[test]
fn permanent_indeterminate_custody_does_not_block_other_terminal_operations() {
    let mut harness = Harness::with_limits(small_limits());
    let retained = indeterminate_core_custody(&mut harness, 60);

    for operation in 61..64 {
        let released = release_terminal_operation(&mut harness, operation);
        assert_eq!(harness.engine.pressure().custody_operations, 1);
        assert_eq!(harness.engine.pressure().custody_composites, 1);
        harness
            .tx(cser_core::Command::compact_terminal_operation(
                released.operation(),
            ))
            .unwrap();
        assert_eq!(harness.engine.pressure().custody_operations, 1);
        assert_eq!(harness.engine.pressure().custody_composites, 1);
        assert_eq!(harness.engine.pressure().active_operations, 0);
        assert_eq!(harness.engine.pressure().active_composites, 0);
    }

    let retained_projection = harness.engine.composite_effect(retained).unwrap();
    assert_eq!(retained_projection.authority, AuthorityState::Fenced);
    assert_eq!(retained_projection.custodian, CustodyState::CoreOwned);
    assert!(matches!(
        harness
            .engine
            .component(retained, EFFECT_COMPONENT)
            .unwrap()
            .settlement,
        SettlementState::ReconciliationRequired { .. }
    ));
}

#[test]
fn blocked_terminal_compaction_is_failure_atomic() {
    let mut harness = Harness::with_limits(small_limits());
    let (live_effect, _) = prepared_reply(&mut harness, 50);
    let before_revision = harness.engine.revision();
    let before_head = harness.engine.head();
    let before_pressure = harness.engine.pressure();

    assert_eq!(
        harness.tx(cser_core::Command::compact_terminal_operation(
            live_effect.operation(),
        )),
        Err(CoreError::EffectNotReleasable)
    );
    assert_eq!(harness.engine.revision(), before_revision);
    assert_eq!(harness.engine.head(), before_head);
    assert_eq!(harness.engine.pressure(), before_pressure);
    assert!(harness.engine.composite_effect(live_effect).is_some());
}

fn admit_replay(harness: &mut Harness, effect: cser_core::EffectId) -> Result<(), CoreError> {
    harness.tx(replay_request(effect)).map(|_| ())
}

fn replay_request(effect: cser_core::EffectId) -> Command {
    Command::AdmitScopedCompositeEffect {
        effect,
        origin: executor(effect.operation().get(), 1),
        kind: EFFECT_CATALOG_KIND,
        charge_account: charge(effect.operation().get()),
        bindings: vec![ComponentProviderBinding::new(
            EFFECT_COMPONENT,
            support::provider(),
        )],
    }
}
