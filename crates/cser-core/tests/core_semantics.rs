#[allow(dead_code)]
mod support;

use cser_core::{
    AuthorityState, CommandRequest as Command, CoreError, CustodyState, DEVICE_CLAIM_IOVA,
    DEVICE_EVIDENCE_IOTLB, DEVICE_OBLIGATION_DMA, Engine, ExternalOutcome, RecoveryAnchor,
    RetirementState, SettlementState, TransitionOutput, standard_catalog,
};
use support::{
    Harness, charge, claim, committed_reply, current_evidence_command, digest, effect,
    fence_and_rebind, freshness, principal, resource, snapshot, verified_commit_outcome,
    verified_evidence_command,
};

#[test]
fn successor_generation_and_principal_never_roll_back() {
    let mut harness = Harness::new();
    let effect = effect(100, 1);
    let origin = principal(100, 10);
    harness
        .tx(Command::CreateEstate {
            effect,
            origin,
            binding_generation: 10,
            domain: cser_core::REPLY_DOMAIN,
            obligation: cser_core::REPLY_OBLIGATION_PUBLICATION,
            charge_account: charge(100),
        })
        .unwrap();
    let successor = principal(100, 11);
    fence_and_rebind(&mut harness, effect, origin, successor, 10, 11, 100);
    harness
        .tx(Command::FenceIncarnation {
            root: effect.root(),
            crashed: successor,
            binding_generation: 11,
        })
        .unwrap();
    let recovery = snapshot(101);
    let snapshot_record = harness
        .engine
        .snapshot_root(effect.root(), recovery)
        .unwrap()
        .record();
    harness.tx(snapshot_record).unwrap();

    for stale in [principal(100, 11), principal(100, 2), principal(999, 12)] {
        let before = harness.engine.projection_digest();
        assert_eq!(
            harness.tx(Command::Ready {
                root: effect.root(),
                snapshot: recovery,
                successor: stale,
            }),
            Err(CoreError::StaleIncarnation)
        );
        assert_eq!(harness.engine.projection_digest(), before);
    }
}

#[test]
fn generated_snapshot_is_stale_after_any_later_journal_transition() {
    let mut harness = Harness::new();
    let (target_effect, origin) = committed_reply(&mut harness, 109);
    harness
        .tx(Command::FenceIncarnation {
            root: target_effect.root(),
            crashed: origin,
            binding_generation: 1,
        })
        .unwrap();

    let recovery = snapshot(109);
    let descriptor = harness
        .engine
        .snapshot_root(target_effect.root(), recovery)
        .unwrap();
    let covered_revision = descriptor.covered_revision();
    let covered_head = descriptor.covered_head();
    let stale_record = descriptor.record();

    harness
        .tx(Command::CreateEstate {
            effect: effect(110, 1),
            origin: principal(110, 1),
            binding_generation: 1,
            domain: cser_core::REPLY_DOMAIN,
            obligation: cser_core::REPLY_OBLIGATION_PUBLICATION,
            charge_account: charge(110),
        })
        .unwrap();
    assert!(harness.engine.revision() > covered_revision);
    assert_ne!(harness.engine.head(), covered_head);

    let before = harness.engine.projection_digest();
    let revision_before = harness.engine.revision();
    let root_before = harness.engine.root(target_effect.root());
    assert_eq!(harness.tx(stale_record), Err(CoreError::StaleSnapshot));
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(harness.engine.revision(), revision_before);
    assert_eq!(harness.engine.root(target_effect.root()), root_before);
}

#[test]
fn rebind_grants_fresh_authority_but_old_effects_require_explicit_adoption() {
    let mut harness = Harness::new();
    let orphan = effect(101, 1);
    let origin = principal(101, 1);
    harness
        .tx(Command::CreateEstate {
            effect: orphan,
            origin,
            binding_generation: 1,
            domain: cser_core::REPLY_DOMAIN,
            obligation: cser_core::REPLY_OBLIGATION_PUBLICATION,
            charge_account: charge(101),
        })
        .unwrap();
    harness
        .tx(Command::AddClaim {
            effect: orphan,
            actor: origin,
            binding_generation: 1,
            claim: claim(101),
            domain: cser_core::REPLY_DOMAIN,
            kind: cser_core::REPLY_CLAIM_PUBLICATION_SLOT,
            scope: cser_core::ClaimScope::Logical,
            resource: resource(101),
            resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
            units: 1,
        })
        .unwrap();

    let successor = principal(101, 2);
    fence_and_rebind(&mut harness, orphan, origin, successor, 1, 2, 102);
    assert_eq!(
        harness.engine.estate(orphan).unwrap().custodian,
        CustodyState::KernelEstate
    );
    assert_eq!(
        harness.tx(Command::PrepareEffect {
            effect: orphan,
            actor: successor,
            binding_generation: 2,
        }),
        Err(CoreError::StaleIncarnation)
    );

    harness
        .tx(Command::AdoptEffect {
            effect: orphan,
            successor,
            binding_generation: 2,
        })
        .unwrap();
    let adopted = harness.engine.estate(orphan).unwrap();
    assert_eq!(adopted.causal_owner, origin);
    assert_eq!(adopted.custodian, CustodyState::Principal(successor));
    assert_eq!(adopted.authority, AuthorityState::Active);

    let before = harness.engine.projection_digest();
    assert_eq!(
        harness.tx(Command::PrepareEffect {
            effect: orphan,
            actor: origin,
            binding_generation: 1,
        }),
        Err(CoreError::StaleIncarnation)
    );
    assert_eq!(harness.engine.projection_digest(), before);
    harness
        .tx(Command::PrepareEffect {
            effect: orphan,
            actor: successor,
            binding_generation: 2,
        })
        .unwrap();

    let fresh = effect(101, 2);
    harness
        .tx(Command::CreateEstate {
            effect: fresh,
            origin: successor,
            binding_generation: 2,
            domain: cser_core::REPLY_DOMAIN,
            obligation: cser_core::REPLY_OBLIGATION_PUBLICATION,
            charge_account: charge(101),
        })
        .unwrap();
    assert_eq!(
        harness.engine.estate(fresh).unwrap().causal_owner,
        successor
    );
}

#[test]
fn evidence_cannot_retire_a_resource_before_the_effect_lifecycle_allows_it() {
    let mut harness = Harness::new();
    let effect = effect(102, 1);
    let origin = principal(102, 1);
    harness
        .tx(Command::CreateEstate {
            effect,
            origin,
            binding_generation: 1,
            domain: cser_core::DEVICE_DOMAIN,
            obligation: DEVICE_OBLIGATION_DMA,
            charge_account: charge(102),
        })
        .unwrap();
    harness
        .tx(Command::AddClaim {
            effect,
            actor: origin,
            binding_generation: 1,
            claim: claim(102),
            domain: cser_core::DEVICE_DOMAIN,
            kind: DEVICE_CLAIM_IOVA,
            scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
            resource: resource(102),
            resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
            units: 1,
        })
        .unwrap();
    let before = harness.engine.projection_digest();
    let evidence = current_evidence_command(
        &harness,
        effect,
        claim(102),
        DEVICE_EVIDENCE_IOTLB,
        cser_core::ReceiptBinding::new(
            cser_core::DEVICE_VERIFIER,
            cser_core::DEVICE_RECEIPT_SCHEMA,
        ),
        digest(102),
    );
    assert_eq!(harness.tx(evidence), Err(CoreError::WrongCommitState));
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(
        harness.engine.check_reusable(
            resource(102),
            cser_core::ResourceGeneration::new(1).unwrap()
        ),
        Err(CoreError::ResourceRetained)
    );
}

#[test]
fn retirement_only_obligations_release_without_a_reply_settlement_escape_hatch() {
    let mut harness = Harness::new();
    let effect = effect(103, 1);
    let origin = principal(103, 1);
    harness
        .tx(Command::CreateEstate {
            effect,
            origin,
            binding_generation: 1,
            domain: cser_core::DEVICE_DOMAIN,
            obligation: DEVICE_OBLIGATION_DMA,
            charge_account: charge(103),
        })
        .unwrap();
    harness
        .tx(Command::AddClaim {
            effect,
            actor: origin,
            binding_generation: 1,
            claim: claim(103),
            domain: cser_core::DEVICE_DOMAIN,
            kind: DEVICE_CLAIM_IOVA,
            scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
            resource: resource(103),
            resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
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
        operation: digest(103),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    };
    let outcome = verified_commit_outcome(
        &harness,
        &intent,
        cser_core::DEVICE_VERIFIER,
        cser_core::DEVICE_COMMIT_RECEIPT_SCHEMA,
        ExternalOutcome::Success,
        digest(104),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    assert_eq!(
        harness.engine.estate(effect).unwrap().settlement,
        SettlementState::NotRequired
    );
    assert_eq!(
        harness.tx(Command::ClaimSettlement {
            effect,
            claimant: origin,
        }),
        Err(CoreError::WrongSettlementStage)
    );
    let reset_observation = harness
        .engine
        .evidence_challenge(effect, claim(103), cser_core::DEVICE_EVIDENCE_RESET)
        .unwrap()
        .current_observation()
        .with_device(cser_core::DeviceGeneration::new(2).unwrap());
    let reset = verified_evidence_command(
        &harness,
        effect,
        claim(103),
        cser_core::DEVICE_EVIDENCE_RESET,
        cser_core::ReceiptBinding::new(
            cser_core::DEVICE_VERIFIER,
            cser_core::DEVICE_RECEIPT_SCHEMA,
        ),
        reset_observation,
        digest(106),
    );
    harness.tx(reset).unwrap();
    let iotlb = current_evidence_command(
        &harness,
        effect,
        claim(103),
        DEVICE_EVIDENCE_IOTLB,
        cser_core::ReceiptBinding::new(
            cser_core::DEVICE_VERIFIER,
            cser_core::DEVICE_RECEIPT_SCHEMA,
        ),
        digest(107),
    );
    harness.tx(iotlb).unwrap();
    assert_eq!(
        harness.engine.estate(effect).unwrap().retirement,
        RetirementState::Retired
    );
    harness.tx(Command::ReleaseEstate { effect }).unwrap();
    assert_eq!(
        harness.engine.estate(effect).unwrap().custodian,
        CustodyState::Released
    );
}

#[test]
fn indeterminate_is_a_live_reconciliation_object_even_after_physical_retirement() {
    let mut harness = Harness::new();
    let (effect, origin) = support::committed_reply(&mut harness, 104);
    let successor = principal(104, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 1, 2, 104);
    let settlement = match harness.output(Command::ClaimSettlement {
        effect,
        claimant: successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    };
    harness
        .tx(settlement.mark_indeterminate(digest(107)))
        .unwrap();
    assert!(matches!(
        harness.engine.estate(effect).unwrap().settlement,
        SettlementState::ReconciliationRequired {
            generation: 2,
            applied: false
        }
    ));
    let publication = current_evidence_command(
        &harness,
        effect,
        claim(104),
        cser_core::REPLY_EVIDENCE_PUBLICATION_ACK,
        cser_core::ReceiptBinding::new(cser_core::REPLY_VERIFIER, cser_core::REPLY_RECEIPT_SCHEMA),
        digest(108),
    );
    harness.tx(publication).unwrap();
    assert_eq!(
        harness.engine.estate(effect).unwrap().retirement,
        RetirementState::Retired
    );
    assert_eq!(
        harness.tx(Command::ReleaseEstate { effect }),
        Err(CoreError::EstateNotReleasable)
    );
}

#[test]
fn resource_reverse_index_rejects_a_second_live_owner_in_either_order() {
    for roots in [[106, 105], [105, 106]] {
        let mut harness = Harness::new();
        for (index, root_value) in roots.into_iter().enumerate() {
            let effect = effect(root_value, 1);
            let origin = principal(root_value, 1);
            harness
                .tx(Command::CreateEstate {
                    effect,
                    origin,
                    binding_generation: 1,
                    domain: cser_core::DEVICE_DOMAIN,
                    obligation: DEVICE_OBLIGATION_DMA,
                    charge_account: charge(root_value),
                })
                .unwrap();
            let command = Command::AddClaim {
                effect,
                actor: origin,
                binding_generation: 1,
                claim: claim(root_value),
                domain: cser_core::DEVICE_DOMAIN,
                kind: DEVICE_CLAIM_IOVA,
                scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
                resource: resource(500),
                resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
                units: 1,
            };
            if index == 0 {
                harness.tx(command).unwrap();
            } else {
                let before = (
                    harness.engine.revision(),
                    harness.engine.head(),
                    harness.engine.projection_digest(),
                );
                assert_eq!(harness.tx(command), Err(CoreError::ResourceRetained));
                assert_eq!(
                    (
                        harness.engine.revision(),
                        harness.engine.head(),
                        harness.engine.projection_digest(),
                    ),
                    before
                );
            }
        }
        assert_eq!(harness.engine.pressure().retained_claims, 1);
    }
}

#[test]
fn journal_records_and_recovery_preserve_nondefault_binding_freshness() {
    let mut engine = Engine::new_legacy_compatibility(
        standard_catalog(),
        cser_core::CoreLimits::bounded_default(),
        freshness(1, 1, 7, 1, 1),
    );
    let mut journal = Vec::new();
    engine
        .transact(
            Command::CreateEstate {
                effect: effect(107, 1),
                origin: principal(107, 7),
                binding_generation: 7,
                domain: cser_core::REPLY_DOMAIN,
                obligation: cser_core::REPLY_OBLIGATION_PUBLICATION,
                charge_account: charge(107),
            },
            |record| {
                journal.extend_from_slice(record.bytes());
                Ok::<(), ()>(())
            },
        )
        .unwrap();
    let scan = cser_core::scan_journal(&journal).unwrap();
    assert_eq!(scan.records()[0].binding(), 7);
    let recovered = Engine::recover_legacy_compatibility(
        standard_catalog(),
        cser_core::CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            freshness(1, 1, 7, 1, 1),
            freshness(2, 1, 7, 1, 2),
            1,
            engine.head(),
        )
        .unwrap(),
        &journal,
    )
    .unwrap();
    assert_eq!(recovered.into_engine().freshness().binding(), 7);
}
