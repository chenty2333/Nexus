#[allow(dead_code)]
mod support;

use cser_core::{
    AuthorityState, CatalogSet, CommandRequest as Command, CommitState, CoreError, CoreLimits,
    CustodyState, Engine, ExecutorCoordinate, OperationRecoveryState, SettlementState,
    TransitionOutput, tool_dma_catalog,
};
use support::{
    EFFECT_CLAIM_KIND, EFFECT_COMMIT_RECEIPT_SCHEMA, EFFECT_COMPONENT, EFFECT_VERIFIER,
    ExactEffectVerifier, Harness, admit_command, claim, committed_reply, digest, effect, executor,
    fence_and_rebind, freshness, recovery_anchor, resource, resource_generation, snapshot,
    test_effect_receipt,
};

fn one_crash_limits() -> CoreLimits {
    CoreLimits::new(8, 32, 64, 64, 8, 1024, 1).unwrap()
}

fn tool_dma_catalog_set() -> CatalogSet {
    CatalogSet::new(&[tool_dma_catalog()]).unwrap()
}

fn registered_reply(
    harness: &mut Harness,
    operation_value: u64,
) -> (cser_core::EffectId, ExecutorCoordinate) {
    let effect = effect(operation_value, 1);
    let origin = executor(operation_value, 1);
    harness.tx(admit_command(effect, operation_value)).unwrap();
    (effect, origin)
}

fn exact_revoke(
    harness: &Harness,
    effect: cser_core::EffectId,
    actor: ExecutorCoordinate,
) -> Command {
    Command::BeginRevoke {
        effect,
        expected_actor: actor,
        authority_epoch: harness
            .engine
            .composite_effect(effect)
            .unwrap()
            .authority_epoch,
    }
}

#[test]
fn crash_quota_exhaustion_fences_first_and_blocks_automatic_recovery() {
    let limits = one_crash_limits();
    let mut harness = Harness::with_limits(limits);
    let (effect, origin) = registered_reply(&mut harness, 101);
    let successor = executor(101, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 101);
    harness
        .tx(Command::AdoptEffect { effect, successor })
        .unwrap();

    harness
        .tx(Command::FenceExecutor {
            operation: effect.operation(),
            crashed: successor,
        })
        .expect("quota exhaustion must persist the fence instead of rolling it back");

    assert_eq!(
        harness.engine.operation(effect.operation()),
        Some(OperationRecoveryState::RecoveryExhausted {
            crashed: successor,
            crash_generation: 2,
        })
    );
    let composite = harness.engine.composite_effect(effect).unwrap();
    assert_eq!(composite.authority, AuthorityState::Fenced);
    assert_eq!(composite.custodian, CustodyState::CoreOwned);

    assert_eq!(
        harness
            .engine
            .snapshot_operation(effect.operation(), snapshot(102)),
        Err(CoreError::RecoveryExhausted)
    );
    assert_eq!(
        harness.tx(Command::Ready {
            operation: effect.operation(),
            snapshot: snapshot(102),
            successor: executor(101, 3),
        }),
        Err(CoreError::RecoveryExhausted)
    );
    assert_eq!(
        harness.tx(Command::Rebind {
            operation: effect.operation(),
            snapshot: snapshot(102),
            successor: executor(101, 3),
        }),
        Err(CoreError::RecoveryExhausted)
    );
    assert_eq!(
        harness.tx(Command::AdoptEffect {
            effect,
            successor: executor(101, 3),
        }),
        Err(CoreError::RecoveryExhausted)
    );

    let replayed = Engine::recover(
        tool_dma_catalog_set(),
        limits,
        recovery_anchor(
            tool_dma_catalog_set().digest(),
            freshness(1, 1, 1, 1),
            freshness(2, 1, 1, 2),
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        &harness.journal,
    )
    .unwrap()
    .into_engine();
    assert_eq!(
        replayed.operation(effect.operation()),
        Some(OperationRecoveryState::RecoveryExhausted {
            crashed: successor,
            crash_generation: 2,
        })
    );
}

#[test]
fn boot_checkpoint_also_persists_exhausted_fencing() {
    let limits = one_crash_limits();
    let mut harness = Harness::with_limits(limits);
    let (effect, origin) = registered_reply(&mut harness, 102);
    let successor = executor(102, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 103);
    harness
        .tx(Command::AdoptEffect { effect, successor })
        .unwrap();

    let expected_head = harness.engine.head();
    let minimum_revision = harness.engine.revision();
    let report = Engine::recover(
        tool_dma_catalog_set(),
        limits,
        recovery_anchor(
            tool_dma_catalog_set().digest(),
            freshness(1, 1, 1, 1),
            freshness(2, 1, 1, 2),
            minimum_revision,
            expected_head,
            harness.engine.projection_digest(),
        ),
        &harness.journal,
    )
    .unwrap();
    let mut recovered = report.into_engine();
    recovered
        .transact_volatile(Command::CheckpointRecovery {
            boot: cser_core::BootGeneration::new(2).unwrap(),
            journal: cser_core::JournalGeneration::new(2).unwrap(),
            device: cser_core::DeviceGeneration::new(1).unwrap(),
        })
        .expect("boot recovery must fence even when it exceeds the crash quota");

    assert_eq!(
        recovered.operation(effect.operation()),
        Some(OperationRecoveryState::RecoveryExhausted {
            crashed: successor,
            crash_generation: 2,
        })
    );
    let composite = recovered.composite_effect(effect).unwrap();
    assert_eq!(composite.authority, AuthorityState::Fenced);
    assert_eq!(composite.custodian, CustodyState::CoreOwned);
}

#[test]
fn revoke_and_adopt_are_one_winner_at_an_exact_authority_epoch() {
    let mut revoke_wins = Harness::new();
    let (effect, origin) = registered_reply(&mut revoke_wins, 103);
    let successor = executor(103, 2);
    fence_and_rebind(&mut revoke_wins, effect, origin, successor, 104);
    let revoke = exact_revoke(&revoke_wins, effect, successor);
    revoke_wins.tx(revoke).unwrap();
    assert_eq!(
        revoke_wins.tx(Command::AdoptEffect { effect, successor }),
        Err(CoreError::GateClosed)
    );

    let mut adopt_wins = Harness::new();
    let (effect, origin) = registered_reply(&mut adopt_wins, 104);
    let successor = executor(104, 2);
    fence_and_rebind(&mut adopt_wins, effect, origin, successor, 105);
    let stale_revoke = exact_revoke(&adopt_wins, effect, successor);
    adopt_wins
        .tx(Command::AdoptEffect { effect, successor })
        .unwrap();
    assert_eq!(
        adopt_wins.tx(stale_revoke),
        Err(CoreError::StaleAuthorityEpoch)
    );

    let explicit_new_epoch_revoke = exact_revoke(&adopt_wins, effect, successor);
    adopt_wins.tx(explicit_new_epoch_revoke).unwrap();
    let composite = adopt_wins.engine.composite_effect(effect).unwrap();
    assert_eq!(composite.authority, AuthorityState::Revoked);
    assert_eq!(
        adopt_wins
            .engine
            .component(effect, EFFECT_COMPONENT)
            .unwrap()
            .settlement,
        SettlementState::Revoked
    );
}

#[test]
fn committed_revoke_cannot_discharge_a_live_obligation() {
    let mut harness = Harness::new();
    let (effect, origin) = committed_reply(&mut harness, 105);
    let successor = executor(105, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 106);

    let revoke = exact_revoke(&harness, effect, successor);
    assert_eq!(harness.tx(revoke), Err(CoreError::WrongCommitState));

    let composite = harness.engine.composite_effect(effect).unwrap();
    let component = harness.engine.component(effect, EFFECT_COMPONENT).unwrap();
    assert_eq!(component.commit, CommitState::Committed);
    assert_eq!(composite.authority, AuthorityState::Fenced);
    assert_eq!(composite.custodian, CustodyState::CoreOwned);
    assert_eq!(
        component.settlement,
        SettlementState::Open { generation: 1 }
    );
    assert!(
        harness
            .tx(Command::ClaimComponentSettlement {
                effect,
                component: EFFECT_COMPONENT,
                claimant: successor,
            })
            .is_ok()
    );
}

#[test]
fn pending_cannot_acknowledge_a_commit_intent() {
    let mut harness = Harness::new();
    let (effect, origin) = registered_reply(&mut harness, 106);
    harness
        .tx(Command::AddComponentClaim {
            effect,
            component: EFFECT_COMPONENT,
            actor: origin,
            claim: claim(106),
            kind: EFFECT_CLAIM_KIND,
            scope: cser_core::ClaimScope::Logical,
            resource: resource(106),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect,
            actor: origin,
        })
        .unwrap();
    let intent = match harness.output(Command::RecordComponentCommitIntent {
        effect,
        component: EFFECT_COMPONENT,
        actor: origin,
        operation: digest(107),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    };
    let before = harness.engine.projection_digest();
    let challenge = harness.engine.commit_outcome_challenge(&intent).unwrap();
    let invalid = test_effect_receipt(challenge, digest(108), None);
    assert_eq!(
        harness.engine.verify_commit_outcome(
            &intent,
            &ExactEffectVerifier::new(EFFECT_VERIFIER, EFFECT_COMMIT_RECEIPT_SCHEMA,),
            &invalid,
        ),
        Err(CoreError::VerificationFailed)
    );
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(
        harness
            .engine
            .component(effect, EFFECT_COMPONENT)
            .unwrap()
            .commit,
        CommitState::CommitIntentDurable
    );
}
