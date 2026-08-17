#[allow(dead_code)]
mod support;

use cser_core::{
    AuthorityState, CommandRequest as Command, CommitState, CoreError, CoreLimits, CustodyState,
    Engine, RootRecoveryState, SettlementState, TransitionOutput, standard_catalog,
};
use support::{
    ExactEffectVerifier, Harness, charge, claim, committed_reply, digest, effect, fence_and_rebind,
    freshness, principal, recovery_anchor, resource, resource_generation, snapshot,
    test_effect_receipt,
};

fn one_crash_limits() -> CoreLimits {
    CoreLimits::new(8, 32, 64, 64, 8, 1024, 1).unwrap()
}

fn registered_reply(
    harness: &mut Harness,
    root_value: u64,
) -> (cser_core::EffectId, cser_core::PrincipalIncarnation) {
    let effect = effect(root_value, 1);
    let origin = principal(root_value, 1);
    harness
        .tx(Command::CreateEstate {
            effect,
            origin,
            binding_generation: 1,
            domain: cser_core::REPLY_DOMAIN,
            obligation: cser_core::REPLY_OBLIGATION_PUBLICATION,
            charge_account: charge(root_value),
        })
        .unwrap();
    (effect, origin)
}

fn exact_revoke(
    harness: &Harness,
    effect: cser_core::EffectId,
    actor: cser_core::PrincipalIncarnation,
    binding_generation: u64,
) -> Command {
    Command::BeginRevoke {
        effect,
        expected_actor: actor,
        binding_generation,
        authority_epoch: harness.engine.estate(effect).unwrap().authority_epoch,
    }
}

#[test]
fn crash_quota_exhaustion_fences_first_and_blocks_automatic_recovery() {
    let limits = one_crash_limits();
    let mut harness = Harness::with_limits(limits);
    let (effect, origin) = registered_reply(&mut harness, 101);
    let successor = principal(101, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 1, 2, 101);
    harness
        .tx(Command::AdoptEffect {
            effect,
            successor,
            binding_generation: 2,
        })
        .unwrap();

    harness
        .tx(Command::FenceIncarnation {
            root: effect.root(),
            crashed: successor,
            binding_generation: 2,
        })
        .expect("quota exhaustion must persist the fence instead of rolling it back");

    assert_eq!(
        harness.engine.root(effect.root()),
        Some(RootRecoveryState::RecoveryExhausted {
            crashed: successor,
            binding_generation: 2,
            crash_generation: 2,
        })
    );
    let estate = harness.engine.estate(effect).unwrap();
    assert_eq!(estate.authority, AuthorityState::Fenced);
    assert_eq!(estate.custodian, CustodyState::KernelEstate);

    assert_eq!(
        harness.engine.snapshot_root(effect.root(), snapshot(102)),
        Err(CoreError::RecoveryExhausted)
    );
    assert_eq!(
        harness.tx(Command::Ready {
            root: effect.root(),
            snapshot: snapshot(102),
            successor: principal(101, 3),
        }),
        Err(CoreError::RecoveryExhausted)
    );
    assert_eq!(
        harness.tx(Command::Rebind {
            root: effect.root(),
            snapshot: snapshot(102),
            successor: principal(101, 3),
            binding_generation: 3,
        }),
        Err(CoreError::RecoveryExhausted)
    );
    assert_eq!(
        harness.tx(Command::AdoptEffect {
            effect,
            successor: principal(101, 3),
            binding_generation: 3,
        }),
        Err(CoreError::RecoveryExhausted)
    );

    let replayed = Engine::recover_legacy_compatibility(
        standard_catalog(),
        limits,
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
        replayed.root(effect.root()),
        Some(RootRecoveryState::RecoveryExhausted {
            crashed: successor,
            binding_generation: 2,
            crash_generation: 2,
        })
    );
}

#[test]
fn boot_checkpoint_also_persists_exhausted_fencing() {
    let limits = one_crash_limits();
    let mut harness = Harness::with_limits(limits);
    let (effect, origin) = registered_reply(&mut harness, 102);
    let successor = principal(102, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 1, 2, 103);
    harness
        .tx(Command::AdoptEffect {
            effect,
            successor,
            binding_generation: 2,
        })
        .unwrap();

    let expected_head = harness.engine.head();
    let minimum_revision = harness.engine.revision();
    let report = Engine::recover_legacy_compatibility(
        standard_catalog(),
        limits,
        recovery_anchor(
            standard_catalog().digest(),
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 1, 2),
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
        recovered.root(effect.root()),
        Some(RootRecoveryState::RecoveryExhausted {
            crashed: successor,
            binding_generation: 2,
            crash_generation: 2,
        })
    );
    let estate = recovered.estate(effect).unwrap();
    assert_eq!(estate.authority, AuthorityState::Fenced);
    assert_eq!(estate.custodian, CustodyState::KernelEstate);
}

#[test]
fn revoke_and_adopt_are_one_winner_at_an_exact_authority_epoch() {
    let mut revoke_wins = Harness::new();
    let (effect, origin) = registered_reply(&mut revoke_wins, 103);
    let successor = principal(103, 2);
    fence_and_rebind(&mut revoke_wins, effect, origin, successor, 1, 2, 104);
    let revoke = exact_revoke(&revoke_wins, effect, successor, 2);
    revoke_wins.tx(revoke).unwrap();
    assert_eq!(
        revoke_wins.tx(Command::AdoptEffect {
            effect,
            successor,
            binding_generation: 2,
        }),
        Err(CoreError::GateClosed)
    );

    let mut adopt_wins = Harness::new();
    let (effect, origin) = registered_reply(&mut adopt_wins, 104);
    let successor = principal(104, 2);
    fence_and_rebind(&mut adopt_wins, effect, origin, successor, 1, 2, 105);
    let stale_revoke = exact_revoke(&adopt_wins, effect, successor, 2);
    adopt_wins
        .tx(Command::AdoptEffect {
            effect,
            successor,
            binding_generation: 2,
        })
        .unwrap();
    assert_eq!(
        adopt_wins.tx(stale_revoke),
        Err(CoreError::StaleAuthorityEpoch)
    );

    let explicit_new_epoch_revoke = exact_revoke(&adopt_wins, effect, successor, 2);
    adopt_wins.tx(explicit_new_epoch_revoke).unwrap();
    let estate = adopt_wins.engine.estate(effect).unwrap();
    assert_eq!(estate.authority, AuthorityState::Revoked);
    assert_eq!(estate.settlement, SettlementState::Revoked);
}

#[test]
fn committed_revoke_closes_successor_authority_but_keeps_obligation_live() {
    let mut harness = Harness::new();
    let (effect, origin) = committed_reply(&mut harness, 105);
    let successor = principal(105, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 1, 2, 106);

    let revoke = exact_revoke(&harness, effect, successor, 2);
    harness.tx(revoke).unwrap();

    let estate = harness.engine.estate(effect).unwrap();
    assert_eq!(estate.commit, CommitState::Committed);
    assert_eq!(estate.authority, AuthorityState::Revoked);
    assert_eq!(estate.custodian, CustodyState::KernelEstate);
    assert_eq!(estate.settlement, SettlementState::Open { generation: 1 });
    assert_eq!(
        harness.tx(Command::ClaimSettlement {
            effect,
            claimant: successor,
        }),
        Err(CoreError::GateClosed)
    );
    assert_eq!(
        harness.tx(Command::ReleaseEstate { effect }),
        Err(CoreError::EstateNotReleasable)
    );
}

#[test]
fn pending_cannot_acknowledge_a_commit_intent() {
    let mut harness = Harness::new();
    let (effect, origin) = registered_reply(&mut harness, 106);
    harness
        .tx(Command::AddClaim {
            effect,
            actor: origin,
            binding_generation: 1,
            claim: claim(106),
            domain: cser_core::REPLY_DOMAIN,
            kind: cser_core::REPLY_CLAIM_PUBLICATION_SLOT,
            scope: cser_core::ClaimScope::Logical,
            resource: resource(106),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::PrepareEffect {
            effect,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    let intent = match harness.output(Command::RecordCommitIntent {
        effect,
        actor: origin,
        binding_generation: 1,
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
            &ExactEffectVerifier::new(
                cser_core::REPLY_VERIFIER,
                cser_core::REPLY_COMMIT_RECEIPT_SCHEMA,
            ),
            &invalid,
        ),
        Err(CoreError::VerificationFailed)
    );
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(
        harness.engine.estate(effect).unwrap().commit,
        CommitState::CommitIntentDurable
    );
}
