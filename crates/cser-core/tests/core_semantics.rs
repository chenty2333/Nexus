#[allow(dead_code)]
mod support;

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, AuthorityState,
    CatalogSet, CommandRequest as Command, ComponentProviderBinding, CoreError, CoreLimits,
    CustodyState, DEVICE_CLAIM_IOVA, DEVICE_EVIDENCE_IOTLB, DEVICE_EVIDENCE_RESET,
    DMA_ARENA_REUSE_COMPOSITE, Engine, OperationId, OperationRecoveryState, RetirementState,
    SettlementState, TransitionOutput, standard_catalog,
};
use support::{
    EFFECT_CATALOG_KIND, EFFECT_CLAIM_KIND, EFFECT_COMPONENT, EFFECT_EVIDENCE_KIND,
    EFFECT_RECEIPT_SCHEMA, EFFECT_VERIFIER, ExactTestVerifier, Harness, TestReceipt, admit_command,
    charge, claim, committed_reply, current_evidence_command, digest, effect, executor,
    fence_and_rebind, freshness, provider, recovery_anchor, register_provider_command, resource,
    resource_generation, snapshot, test_world, verified_commit_outcome,
};

fn admit_dma(
    harness: &mut Harness,
    effect: cser_core::EffectId,
    origin: cser_core::ExecutorCoordinate,
    account: u64,
) {
    harness
        .tx(cser_core::CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin,
            kind: DMA_ARENA_REUSE_COMPOSITE,
            charge_account: charge(account),
            bindings: vec![ComponentProviderBinding::new(
                AGENT_COMPONENT_DMA,
                support::provider(),
            )],
        })
        .unwrap();
}

fn add_dma_claim(
    harness: &mut Harness,
    effect: cser_core::EffectId,
    actor: cser_core::ExecutorCoordinate,
    claim_value: u64,
    kind: cser_core::ClaimKindId,
    resource_value: u64,
) -> Result<(), CoreError> {
    harness
        .tx(cser_core::CommandRequest::AddComponentClaim {
            effect,
            component: AGENT_COMPONENT_DMA,
            actor,
            claim: claim(claim_value),
            kind,
            scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
            resource: resource(resource_value),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .map(|_| ())
}

fn admit_reply_at(
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
            bindings: vec![ComponentProviderBinding::new(EFFECT_COMPONENT, provider())],
        })
        .unwrap();
}

fn dma_evidence_command(
    harness: &Harness,
    effect: cser_core::EffectId,
    claim_value: u64,
    subject: cser_core::Freshness,
    kind: cser_core::EvidenceKindId,
    observation: cser_core::Freshness,
    digest_value: u8,
) -> Result<cser_core::Command, CoreError> {
    let claim_id = claim(claim_value);
    let challenge =
        harness
            .engine
            .component_evidence_challenge(effect, AGENT_COMPONENT_DMA, claim_id, kind)?;
    let receipt = TestReceipt {
        effect,
        claim: claim_id,
        kind,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject,
        subject_binding: challenge.subject_binding(),
        observation,
        observation_binding: challenge.current_binding(),
        digest: digest(digest_value),
    };
    let verifier =
        ExactTestVerifier::new(cser_core::DEVICE_VERIFIER, cser_core::DEVICE_RECEIPT_SCHEMA);
    harness
        .engine
        .verify_component_retirement_evidence(
            effect,
            AGENT_COMPONENT_DMA,
            claim_id,
            kind,
            &verifier,
            &receipt,
        )
        .map(|verified| verified.submit())
}

#[test]
fn successor_generation_and_executor_coordinate_never_roll_back() {
    let mut harness = Harness::new();
    let effect = effect(100, 1);
    let origin = executor(100, 1);
    harness.tx(admit_command(effect, 100)).unwrap();
    harness
        .tx(cser_core::CommandRequest::AddComponentClaim {
            effect,
            component: EFFECT_COMPONENT,
            actor: origin,
            claim: claim(100),
            kind: EFFECT_CLAIM_KIND,
            scope: cser_core::ClaimScope::Logical,
            resource: resource(100),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    fence_and_rebind(&mut harness, effect, origin, executor(100, 2), 100);
    harness
        .tx(cser_core::CommandRequest::FenceExecutor {
            operation: effect.operation(),
            crashed: executor(100, 2),
        })
        .unwrap();
    let recovery = snapshot(101);
    let snapshot_record = harness
        .engine
        .snapshot_operation(effect.operation(), recovery)
        .unwrap()
        .record();
    harness.tx(snapshot_record).unwrap();

    for stale in [executor(100, 2), executor(100, 1), executor(999, 3)] {
        let before = harness.engine.projection_digest();
        assert_eq!(
            harness.tx(cser_core::CommandRequest::Ready {
                operation: effect.operation(),
                snapshot: recovery,
                successor: stale,
            }),
            Err(CoreError::StaleExecutor)
        );
        assert_eq!(harness.engine.projection_digest(), before);
    }
}

#[test]
fn generated_snapshot_is_stale_after_any_later_journal_transition() {
    let mut harness = Harness::new();
    let (target_effect, origin) = committed_reply(&mut harness, 109);
    harness
        .tx(cser_core::CommandRequest::FenceExecutor {
            operation: target_effect.operation(),
            crashed: origin,
        })
        .unwrap();

    let recovery = snapshot(109);
    let descriptor = harness
        .engine
        .snapshot_operation(target_effect.operation(), recovery)
        .unwrap();
    let covered_revision = descriptor.covered_revision();
    let covered_head = descriptor.covered_head();
    let stale_record = descriptor.record();

    harness.tx(admit_command(effect(110, 1), 110)).unwrap();
    assert!(harness.engine.revision() > covered_revision);
    assert_ne!(harness.engine.head(), covered_head);

    let before = harness.engine.projection_digest();
    let revision_before = harness.engine.revision();
    let operation_before = harness.engine.operation(target_effect.operation());
    assert_eq!(harness.tx(stale_record), Err(CoreError::StaleSnapshot));
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(harness.engine.revision(), revision_before);
    assert_eq!(
        harness.engine.operation(target_effect.operation()),
        operation_before
    );
}

#[test]
fn rebind_grants_fresh_authority_but_old_effects_require_explicit_adoption() {
    let mut harness = Harness::new();
    let orphan = effect(101, 1);
    let origin = executor(101, 1);
    harness.tx(admit_command(orphan, 101)).unwrap();
    harness
        .tx(cser_core::CommandRequest::AddComponentClaim {
            effect: orphan,
            component: EFFECT_COMPONENT,
            actor: origin,
            claim: claim(101),
            kind: EFFECT_CLAIM_KIND,
            scope: cser_core::ClaimScope::Logical,
            resource: resource(101),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();

    let successor = executor(101, 2);
    fence_and_rebind(&mut harness, orphan, origin, successor, 102);
    assert_eq!(
        harness.engine.composite_effect(orphan).unwrap().custodian,
        CustodyState::CoreOwned
    );
    assert_eq!(
        harness.tx(cser_core::CommandRequest::PrepareCompositeEffect {
            effect: orphan,
            actor: successor,
        }),
        Err(CoreError::StaleExecutor)
    );

    harness
        .tx(cser_core::CommandRequest::AdoptEffect {
            effect: orphan,
            successor,
        })
        .unwrap();
    let adopted = harness.engine.composite_effect(orphan).unwrap();
    assert_eq!(adopted.causal_owner, origin);
    assert_eq!(adopted.custodian, CustodyState::Executor(successor));
    assert_eq!(adopted.authority, AuthorityState::Active);

    let before = harness.engine.projection_digest();
    assert_eq!(
        harness.tx(cser_core::CommandRequest::PrepareCompositeEffect {
            effect: orphan,
            actor: origin,
        }),
        Err(CoreError::StaleExecutor)
    );
    assert_eq!(harness.engine.projection_digest(), before);
    harness
        .tx(cser_core::CommandRequest::PrepareCompositeEffect {
            effect: orphan,
            actor: successor,
        })
        .unwrap();

    let fresh = effect(101, 2);
    admit_reply_at(&mut harness, fresh, successor);
    assert_eq!(
        harness.engine.composite_effect(fresh).unwrap().causal_owner,
        successor
    );
}

#[test]
fn evidence_cannot_retire_a_resource_before_the_effect_lifecycle_allows_it() {
    let mut harness = Harness::new();
    let effect = effect(102, 1);
    let origin = executor(102, 1);
    harness.tx(admit_command(effect, 102)).unwrap();
    harness
        .tx(cser_core::CommandRequest::AddComponentClaim {
            effect,
            component: EFFECT_COMPONENT,
            actor: origin,
            claim: claim(102),
            kind: EFFECT_CLAIM_KIND,
            scope: cser_core::ClaimScope::Logical,
            resource: resource(102),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    let before = harness.engine.projection_digest();
    let evidence = current_evidence_command(
        &harness,
        effect,
        claim(102),
        EFFECT_EVIDENCE_KIND,
        cser_core::ReceiptBinding::new(EFFECT_VERIFIER, EFFECT_RECEIPT_SCHEMA),
        digest(102),
    );
    assert_eq!(harness.tx(evidence), Err(CoreError::WrongCommitState));
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(
        harness
            .engine
            .check_reusable(resource(102), resource_generation(1)),
        Err(CoreError::ResourceRetained)
    );
}

#[test]
fn retirement_only_obligations_release_without_a_reply_settlement_escape_hatch() {
    let mut harness = Harness::standard();
    let effect = effect(103, 1);
    let origin = executor(103, 1);
    admit_dma(&mut harness, effect, origin, 103);
    add_dma_claim(&mut harness, effect, origin, 103, DEVICE_CLAIM_IOVA, 103).unwrap();
    harness
        .tx(cser_core::CommandRequest::PrepareCompositeEffect {
            effect,
            actor: origin,
        })
        .unwrap();
    let intent = match harness.output(cser_core::CommandRequest::RecordComponentCommitIntent {
        effect,
        component: AGENT_COMPONENT_DMA,
        actor: origin,
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
        cser_core::ExternalOutcome::Success,
        digest(104),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .settlement,
        SettlementState::NotRequired
    );
    assert_eq!(
        harness.tx(cser_core::CommandRequest::ClaimComponentSettlement {
            effect,
            component: AGENT_COMPONENT_DMA,
            claimant: origin,
        }),
        Err(CoreError::WrongSettlementStage)
    );
    let reset_challenge = harness
        .engine
        .component_evidence_challenge(
            effect,
            AGENT_COMPONENT_DMA,
            claim(103),
            DEVICE_EVIDENCE_RESET,
        )
        .unwrap();
    let subject = reset_challenge.subject();
    let reset_observation = reset_challenge
        .current_observation()
        .with_device(cser_core::DeviceGeneration::new(2).unwrap());
    let reset = dma_evidence_command(
        &harness,
        effect,
        103,
        subject,
        DEVICE_EVIDENCE_RESET,
        reset_observation,
        106,
    )
    .unwrap();
    harness.tx(reset).unwrap();
    let iotlb_observation = harness
        .engine
        .component_evidence_challenge(
            effect,
            AGENT_COMPONENT_DMA,
            claim(103),
            DEVICE_EVIDENCE_IOTLB,
        )
        .unwrap()
        .current_observation();
    let iotlb = dma_evidence_command(
        &harness,
        effect,
        103,
        subject,
        DEVICE_EVIDENCE_IOTLB,
        iotlb_observation,
        107,
    )
    .unwrap();
    harness.tx(iotlb).unwrap();
    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .retirement,
        RetirementState::Retired
    );
    harness
        .tx(cser_core::CommandRequest::ReleaseCompositeEffect { effect })
        .unwrap();
    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .retirement,
        RetirementState::Released
    );
}

#[test]
fn indeterminate_is_a_live_reconciliation_object_even_after_physical_retirement() {
    let mut harness = Harness::new();
    let (effect, origin) = committed_reply(&mut harness, 104);
    let successor = executor(104, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 104);
    let settlement = match harness.output(cser_core::CommandRequest::ClaimComponentSettlement {
        effect,
        component: EFFECT_COMPONENT,
        claimant: successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    };
    harness
        .tx(settlement.mark_indeterminate(digest(107)))
        .unwrap();
    assert!(matches!(
        harness
            .engine
            .component(effect, EFFECT_COMPONENT)
            .unwrap()
            .settlement,
        SettlementState::ReconciliationRequired {
            generation: 2,
            applied: false
        }
    ));
    let publication = current_evidence_command(
        &harness,
        effect,
        claim(104),
        EFFECT_EVIDENCE_KIND,
        cser_core::ReceiptBinding::new(EFFECT_VERIFIER, EFFECT_RECEIPT_SCHEMA),
        digest(108),
    );
    harness.tx(publication).unwrap();
    assert_eq!(
        harness
            .engine
            .component(effect, EFFECT_COMPONENT)
            .unwrap()
            .retirement,
        RetirementState::Retired
    );
    assert_eq!(
        harness.tx(cser_core::CommandRequest::ReleaseCompositeEffect { effect }),
        Err(CoreError::EffectNotReleasable)
    );
}

#[test]
fn resource_reverse_index_rejects_a_second_live_owner_in_either_order() {
    for operations in [[106, 105], [105, 106]] {
        let mut harness = Harness::standard();
        for (index, operation_value) in operations.into_iter().enumerate() {
            let effect = effect(operation_value, 1);
            let origin = executor(operation_value, 1);
            admit_dma(&mut harness, effect, origin, operation_value);
            let result = add_dma_claim(
                &mut harness,
                effect,
                origin,
                operation_value,
                DEVICE_CLAIM_IOVA,
                500,
            );
            if index == 0 {
                result.unwrap();
            } else {
                assert_eq!(result, Err(CoreError::ResourceRetained));
            }
        }
        assert_eq!(harness.engine.pressure().retained_claims, 1);
    }
}

#[test]
fn journal_records_and_recovery_preserve_executor_generation_identity() {
    let catalog = standard_catalog();
    let catalog_set = CatalogSet::new(std::slice::from_ref(&catalog)).unwrap();
    let limits = CoreLimits::bounded_default();
    let mut engine = Engine::new(
        test_world(),
        catalog_set.clone(),
        limits,
        freshness(1, 1, 1, 1),
    );
    let mut journal = Vec::new();
    engine
        .transact(register_provider_command(&catalog), |record| {
            journal.extend_from_slice(record.bytes());
            Ok::<(), ()>(())
        })
        .unwrap();
    engine
        .transact(
            Command::AdmitScopedCompositeEffect {
                effect: effect(107, 1),
                origin: executor(107, 7),
                kind: AGENT_OPERATION_COMPOSITE,
                charge_account: charge(107),
                bindings: vec![
                    ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, support::provider()),
                    ComponentProviderBinding::new(AGENT_COMPONENT_DMA, support::provider()),
                ],
            },
            |record| {
                journal.extend_from_slice(record.bytes());
                Ok::<(), ()>(())
            },
        )
        .unwrap();

    let recovered = Engine::recover(
        catalog_set,
        limits,
        recovery_anchor(
            CatalogSet::new(std::slice::from_ref(&catalog))
                .unwrap()
                .digest(),
            freshness(1, 1, 1, 1),
            freshness(2, 1, 1, 2),
            engine.revision(),
            engine.head(),
            engine.projection_digest(),
        ),
        &journal,
    )
    .unwrap();
    let recovered = recovered.into_engine();
    assert_eq!(recovered.freshness(), freshness(1, 1, 1, 1));
    assert_eq!(
        recovered.operation(OperationId::new(107).unwrap()),
        Some(OperationRecoveryState::Active {
            executor: executor(107, 7),
        })
    );
}
