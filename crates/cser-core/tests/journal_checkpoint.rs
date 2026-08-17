#[allow(dead_code)]
mod support;

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_OPERATION_COMPOSITE, ClaimScope, CommandRequest as Command,
    CoreError, CoreLimits, DEVICE_CLAIM_QUEUE_SLOT, DeviceScopeId, Engine, JournalCheckpoint,
    RootRecoveryState, standard_catalog,
};
use support::{
    Harness, charge, claim, effect, freshness, principal, recovery_anchor, resource,
    resource_generation,
};

#[test]
fn exact_replay_checkpoint_requires_advancing_anchor_and_fences_the_root() {
    let mut harness = Harness::new();
    let operation = effect(0xce01, 1);
    let origin = principal(0xce01, 1);
    harness
        .tx(Command::CreateCompositeEffect {
            effect: operation,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(0xce01),
        })
        .unwrap();

    let checkpoint = harness.checkpoint();
    let checkpoint_anchor = checkpoint.anchor();
    assert_eq!(checkpoint_anchor.revision(), harness.engine.revision());
    assert_eq!(checkpoint_anchor.head(), harness.engine.head());
    assert_eq!(
        checkpoint_anchor.projection(),
        harness.engine.projection_digest()
    );
    assert_eq!(checkpoint.image(), harness.journal);

    let encoded = checkpoint.encode();
    let decoded = JournalCheckpoint::decode(&encoded).unwrap();
    let mut recovered = Engine::recover_legacy_compatibility(
        standard_catalog(),
        CoreLimits::bounded_default(),
        recovery_anchor(
            standard_catalog().digest(),
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 1, 2),
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        decoded.image(),
    )
    .unwrap()
    .into_engine();
    assert_eq!(recovered.revision(), harness.engine.revision());
    assert_eq!(recovered.head(), harness.engine.head());
    assert!(matches!(
        recovered.journal_checkpoint(&harness.journal),
        Err(CoreError::RecoveryPending)
    ));
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
    assert_eq!(recovered.freshness(), freshness(2, 1, 1, 1, 2));
    assert_eq!(
        recovered.root(operation.root()),
        Some(RootRecoveryState::Fenced {
            crashed: origin,
            binding_generation: 1,
            crash_generation: 1,
        })
    );

    let mut corrupted = encoded;
    corrupted[164] ^= 0x80;
    assert!(matches!(
        JournalCheckpoint::decode(&corrupted),
        Err(cser_core::JournalCheckpointDecodeError::ChecksumMismatch)
    ));
}

#[test]
fn checkpoint_recovery_quarantines_retained_device_claims() {
    let mut harness = Harness::new();
    let operation = effect(0xce03, 1);
    let origin = principal(0xce03, 1);
    harness
        .tx(Command::CreateCompositeEffect {
            effect: operation,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(0xce03),
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: operation,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: claim(0xce03),
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(DeviceScopeId::new(0xce03).unwrap()),
            resource: resource(0xce03_0001),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    let checkpoint = harness.checkpoint();
    let mut recovered = Engine::recover_legacy_compatibility(
        standard_catalog(),
        CoreLimits::bounded_default(),
        recovery_anchor(
            standard_catalog().digest(),
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 1, 2),
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        checkpoint.image(),
    )
    .unwrap()
    .into_engine();
    assert!(recovered.pressure().quarantined);
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
    assert!(matches!(
        recovered.root(operation.root()),
        Some(RootRecoveryState::Fenced { .. })
    ));
}

#[test]
fn checkpoint_refuses_the_uncheckpointed_recovery_epoch() {
    let mut harness = Harness::new();
    let operation = effect(0xce02, 1);
    harness
        .tx(Command::CreateCompositeEffect {
            effect: operation,
            origin: principal(0xce02, 1),
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(0xce02),
        })
        .unwrap();

    let recovered = Engine::recover_legacy_compatibility(
        standard_catalog(),
        CoreLimits::bounded_default(),
        recovery_anchor(
            standard_catalog().digest(),
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 1, 2),
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        &harness.journal,
    )
    .unwrap()
    .into_engine();
    assert_eq!(
        recovered.journal_checkpoint(&harness.journal),
        Err(CoreError::RecoveryPending)
    );
}
