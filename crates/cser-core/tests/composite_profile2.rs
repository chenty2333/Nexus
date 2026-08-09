#[allow(dead_code)]
mod support;

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, AdoptionPolicy,
    AuthorityState, CREDIT_QUEUE_SLOT, CREDIT_REPLY_SLOT, ClaimCardinality, ClaimCustodian,
    ClaimId, ClaimScope, ClaimScopePolicy, Command as AuthorizedCommand, CommandRequest as Command,
    CommitIntent, CommitState, ComponentCommitOperation, ComponentId, CompositeComponentSpec,
    CompositeKindId, CoreError, CoreLimits, CustodyState, DEVICE_CLAIM_IOVA,
    DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT, DEVICE_COMMIT_RECEIPT_SCHEMA, DEVICE_DOMAIN,
    DEVICE_EVIDENCE_IOTLB, DEVICE_EVIDENCE_IRQ_DRAINED, DEVICE_EVIDENCE_RESET,
    DEVICE_OBLIGATION_DMA, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, DMA_ARENA_REUSE_COMPOSITE,
    DeviceScopeId, DomainCatalogBuilder, EffectEscapeState, EffectId, Engine, EvidenceKindId,
    EvidenceRule, ExternalOutcome, Freshness, FreshnessAxes, JOURNAL_CORE_API_PROFILE,
    JOURNAL_SCHEMA_VERSION, JournalDecodeError, NORMALIZED_TRACE_VERSION, ObligationKindId,
    ObligationPolicy, ObligationReceipts, ObligationSpec, PROJECTION_VERSION,
    RECOVERY_SNAPSHOT_VERSION, REPLY_APPLY_RECEIPT_SCHEMA, REPLY_CLAIM_PUBLICATION_SLOT,
    REPLY_COMMIT_RECEIPT_SCHEMA, REPLY_DOMAIN, REPLY_EVIDENCE_PUBLICATION_ACK,
    REPLY_RECEIPT_SCHEMA, REPLY_SETTLEMENT_RECEIPT_SCHEMA, REPLY_VERIFIER, ReceiptBinding,
    ReceiptSchemaId, RecoveryAnchor, ResourceId, RetirementState, RootRecoveryState,
    SettlementState, TransitionDurability, TransitionEvent, TransitionOutput, TransitionResult,
    TxError, VerifierId, scan_journal, standard_catalog,
};
use proptest::prelude::*;
use support::{
    ExactTestVerifier, Harness, TestReceipt, charge, claim, digest, effect, freshness, principal,
    resource, resource_generation, snapshot, verified_apply_completion, verified_commit_outcome,
    verified_settlement_ack,
};

const MAIN_ROOT: u64 = 0xc501;
const SEED_ROOT: u64 = 0xd001;

#[test]
fn profile2_receipt_journal_and_snapshot_are_self_describing() {
    let mut harness = Harness::new_profile_two();
    let operation = effect(MAIN_ROOT, 1);
    let origin = principal(MAIN_ROOT, 1);
    let create = Command::CreateCompositeEffect {
        effect: operation,
        origin,
        binding_generation: 1,
        kind: AGENT_OPERATION_COMPOSITE,
        charge_account: charge(MAIN_ROOT),
    };
    assert!(create.is_profile_two_compatible());
    let authorized: AuthorizedCommand = create.clone().into();
    assert!(authorized.is_profile_two_compatible());

    let receipt = harness.tx(create).unwrap();
    assert_eq!(receipt.core_api_profile(), 2);
    assert_eq!(receipt.journal_schema(), JOURNAL_SCHEMA_VERSION);
    assert_eq!(receipt.catalog_digest(), standard_catalog().digest());
    assert_eq!(receipt.projection_version(), PROJECTION_VERSION);
    assert_eq!(receipt.trace_version(), NORMALIZED_TRACE_VERSION);
    assert_eq!(receipt.result(), TransitionResult::Applied);
    assert_eq!(receipt.coordinates().root(), Some(operation.root()));
    assert_eq!(receipt.coordinates().effect(), Some(operation));
    assert_eq!(receipt.coordinates().component(), None);
    assert_eq!(receipt.coordinates().claim(), None);
    assert_eq!(
        u16::from_le_bytes(harness.journal[8..10].try_into().unwrap()),
        6
    );
    assert_eq!(
        u16::from_le_bytes(harness.journal[10..12].try_into().unwrap()),
        JOURNAL_CORE_API_PROFILE
    );
    let mut mismatched_profile = harness.journal.clone();
    mismatched_profile[10..12].copy_from_slice(&1u16.to_le_bytes());
    assert!(matches!(
        scan_journal(&mismatched_profile),
        Err(JournalDecodeError::UnsupportedApiProfile { profile: 1 })
    ));

    let legacy = Command::CreateEstate {
        effect: effect(MAIN_ROOT + 1, 1),
        origin: principal(MAIN_ROOT + 1, 1),
        binding_generation: 1,
        domain: DEVICE_DOMAIN,
        obligation: DEVICE_OBLIGATION_DMA,
        charge_account: charge(MAIN_ROOT + 1),
    };
    assert!(!legacy.is_profile_two_compatible());
    let legacy_authorized: AuthorizedCommand = legacy.into();
    assert!(!legacy_authorized.is_profile_two_compatible());

    harness
        .tx(Command::FenceIncarnation {
            root: operation.root(),
            crashed: origin,
            binding_generation: 1,
        })
        .unwrap();
    let cohort = harness
        .engine
        .snapshot_root(operation.root(), snapshot(1))
        .unwrap();
    assert_eq!(cohort.core_api_profile(), 2);
    assert_eq!(cohort.snapshot_version(), RECOVERY_SNAPSHOT_VERSION);
    assert_eq!(cohort.journal_schema(), JOURNAL_SCHEMA_VERSION);
    assert_eq!(cohort.catalog_digest(), standard_catalog().digest());
    assert!(cohort.items().is_empty());
    assert_eq!(cohort.composites().len(), 1);
    assert_eq!(cohort.composites()[0].effect, operation);
    assert_eq!(cohort.composites()[0].components.len(), 2);
    assert_eq!(cohort.component_items().len(), 2);
}

#[test]
fn profile2_recovery_snapshot_exposes_exact_partial_dma_claim_evidence() {
    let mut harness = Harness::new_profile_two();
    let operation = effect(0xc502, 1);
    let origin = principal(0xc502, 1);
    let reply_claim = claim(1);
    let queue_claim = claim(2);
    let queue_resource = resource(0xc502_0001);
    let scope = device_scope();

    harness
        .tx(Command::CreateCompositeEffect {
            effect: operation,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(0xc502),
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: operation,
            component: AGENT_COMPONENT_REPLY,
            actor: origin,
            binding_generation: 1,
            claim: reply_claim,
            kind: REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(0xc502_0002),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: operation,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: queue_claim,
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(scope),
            resource: queue_resource,
            resource_generation: resource_generation(1),
            units: 3,
        })
        .unwrap();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect: operation,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    commit_agent_components(&mut harness, operation, origin, 1, 10, 11, 12, 13);

    let reset_challenge = harness
        .engine
        .component_evidence_challenge(
            operation,
            AGENT_COMPONENT_DMA,
            queue_claim,
            DEVICE_EVIDENCE_RESET,
        )
        .unwrap();
    let reset_subject = reset_challenge.subject();
    let reset_observation = next_device_freshness(reset_challenge.current_observation());
    let reset_receipt = digest(14);
    let reset = component_evidence_command(
        &harness,
        operation,
        AGENT_COMPONENT_DMA,
        queue_claim,
        DEVICE_EVIDENCE_RESET,
        ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
        reset_observation,
        reset_receipt,
    );
    harness.tx(reset).unwrap();
    harness
        .tx(Command::FenceIncarnation {
            root: operation.root(),
            crashed: origin,
            binding_generation: 1,
        })
        .unwrap();

    let snapshot = harness
        .engine
        .snapshot_root(operation.root(), snapshot(0xc502))
        .unwrap();
    let composite = snapshot
        .composites()
        .iter()
        .find(|item| item.effect == operation)
        .expect("composite operation must be present");
    let queue = composite
        .retained_claims
        .iter()
        .find(|item| item.claim.component == AGENT_COMPONENT_DMA && item.claim.claim == queue_claim)
        .expect("retained DMA queue claim must be present");
    let projected_queue = harness
        .engine
        .component_claims(operation, AGENT_COMPONENT_DMA)
        .unwrap()
        .into_iter()
        .find(|claim| claim.claim == queue_claim)
        .unwrap();

    assert_eq!(queue.claim, projected_queue);
    assert_eq!(queue.claim.effect, operation);
    assert_eq!(queue.claim.component, AGENT_COMPONENT_DMA);
    assert_eq!(queue.claim.claim, queue_claim);
    assert_eq!(queue.claim.domain, DEVICE_DOMAIN);
    assert_eq!(queue.claim.kind, DEVICE_CLAIM_QUEUE_SLOT);
    assert_eq!(queue.claim.scope, ClaimScope::Device(scope));
    assert_eq!(queue.claim.custodian, ClaimCustodian::DeviceProvider(scope));
    assert_eq!(queue.claim.resource, queue_resource);
    assert_eq!(queue.claim.resource_generation, resource_generation(1));
    assert_eq!(queue.claim.units, 3);
    assert_eq!(queue.claim.enrolled_freshness, freshness(1, 1, 1, 1, 1));
    assert!(!queue.claim.retired);

    assert_eq!(queue.accepted_evidence.len(), 1);
    let accepted_reset = queue.accepted_evidence[0];
    assert_eq!(accepted_reset.kind, DEVICE_EVIDENCE_RESET);
    assert_eq!(accepted_reset.subject, reset_subject);
    assert_eq!(accepted_reset.observation, reset_observation);
    assert_eq!(accepted_reset.stamp.identity().verifier(), DEVICE_VERIFIER);
    assert_eq!(accepted_reset.stamp.identity().epoch(), 1);
    assert_eq!(
        accepted_reset.stamp.identity().receipt_schema(),
        DEVICE_RECEIPT_SCHEMA
    );
    assert_eq!(accepted_reset.stamp.receipt_digest(), reset_receipt);
    assert_eq!(queue.pending_evidence, vec![DEVICE_EVIDENCE_IRQ_DRAINED]);
}

#[test]
fn recovery_checkpoint_preserves_an_already_durable_same_boot_fence() {
    let mut harness = Harness::new_profile_two();
    let operation = effect(0xc503, 1);
    let origin = principal(0xc503, 1);
    harness
        .tx(Command::CreateCompositeEffect {
            effect: operation,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(0xc503),
        })
        .unwrap();
    harness
        .tx(Command::FenceIncarnation {
            root: operation.root(),
            crashed: origin,
            binding_generation: 1,
        })
        .unwrap();

    let committed_freshness = harness.engine.freshness();
    let next_freshness = freshness(2, 1, 1, 1, 2);
    let anchor = RecoveryAnchor::from_trusted_provider(
        standard_catalog().digest(),
        committed_freshness,
        next_freshness,
        harness.engine.revision(),
        harness.engine.head(),
    )
    .unwrap();
    let mut recovered = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        anchor,
        &harness.journal,
    )
    .unwrap()
    .into_engine();
    let fenced_root = recovered.root(operation.root()).unwrap();
    let authority_epoch = recovered
        .composite_effect(operation)
        .unwrap()
        .authority_epoch;
    assert_eq!(
        fenced_root,
        RootRecoveryState::Fenced {
            crashed: origin,
            binding_generation: 1,
            crash_generation: 1,
        }
    );
    assert_eq!(recovered.freshness(), committed_freshness);

    recovered
        .transact_volatile(Command::CheckpointRecovery {
            boot: next_freshness.boot(),
            journal: next_freshness.journal(),
            device: next_freshness.device(),
        })
        .unwrap();

    assert_eq!(recovered.root(operation.root()), Some(fenced_root));
    assert_eq!(
        recovered
            .composite_effect(operation)
            .unwrap()
            .authority_epoch,
        authority_epoch
    );
    assert_eq!(recovered.freshness(), next_freshness);
    assert_eq!(
        recovered.composite_effect(operation).unwrap().authority,
        AuthorityState::Fenced
    );
}

#[test]
fn outstanding_component_commit_intents_track_acknowledgements_across_cold_recovery() {
    let mut harness = Harness::new_profile_two();
    let (operation, origin, _, _) = create_precommit_agent(&mut harness, 0xc504);
    let unknown = effect(0xc505, 1);

    assert_eq!(
        harness.engine.outstanding_component_commit_intents(unknown),
        Err(CoreError::UnknownEstate)
    );

    arm_agent_components(&mut harness, operation, origin, 1, 10, 11);
    let outstanding = harness
        .engine
        .outstanding_component_commit_intents(operation)
        .unwrap();
    assert_eq!(outstanding.len(), 2);
    assert_eq!(outstanding[0].effect(), operation);
    assert_eq!(outstanding[0].component(), Some(AGENT_COMPONENT_REPLY));
    assert_eq!(outstanding[1].effect(), operation);
    assert_eq!(outstanding[1].component(), Some(AGENT_COMPONENT_DMA));

    let reply_intent = outstanding
        .into_iter()
        .find(|intent| intent.component() == Some(AGENT_COMPONENT_REPLY))
        .expect("reply intent must be outstanding");
    acknowledge_component(
        &mut harness,
        reply_intent,
        12,
        REPLY_VERIFIER,
        REPLY_COMMIT_RECEIPT_SCHEMA,
    );

    let outstanding = harness
        .engine
        .outstanding_component_commit_intents(operation)
        .unwrap();
    assert_eq!(outstanding.len(), 1);
    assert_eq!(outstanding[0].effect(), operation);
    assert_eq!(outstanding[0].component(), Some(AGENT_COMPONENT_DMA));

    let recovered = replay_profile_two_prefix(&harness, "outstanding component commit intents");
    let outstanding = recovered
        .outstanding_component_commit_intents(operation)
        .unwrap();
    assert_eq!(outstanding.len(), 1);
    assert_eq!(outstanding[0].effect(), operation);
    assert_eq!(outstanding[0].component(), Some(AGENT_COMPONENT_DMA));

    let dma_intent = harness
        .engine
        .outstanding_component_commit_intents(operation)
        .unwrap()
        .into_iter()
        .next()
        .expect("DMA intent must remain outstanding");
    acknowledge_component(
        &mut harness,
        dma_intent,
        13,
        DEVICE_VERIFIER,
        DEVICE_COMMIT_RECEIPT_SCHEMA,
    );
    assert!(
        harness
            .engine
            .outstanding_component_commit_intents(operation)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn profile2_rejects_legacy_commands_before_transition_and_replay() {
    let legacy_command = Command::CreateEstate {
        effect: effect(MAIN_ROOT + 10, 1),
        origin: principal(MAIN_ROOT + 10, 1),
        binding_generation: 1,
        domain: DEVICE_DOMAIN,
        obligation: DEVICE_OBLIGATION_DMA,
        charge_account: charge(MAIN_ROOT + 10),
    };

    let mut profile_two = Harness::new_profile_two();
    let before = (
        profile_two.engine.revision(),
        profile_two.engine.head(),
        profile_two.engine.projection_digest(),
    );
    assert_eq!(
        profile_two.engine.transact_volatile(legacy_command.clone()),
        Err(CoreError::IncompatibleApiProfile)
    );
    assert_eq!(
        (
            profile_two.engine.revision(),
            profile_two.engine.head(),
            profile_two.engine.projection_digest(),
        ),
        before
    );

    let mut legacy = Harness::new();
    legacy.tx(legacy_command).unwrap();
    let anchor = RecoveryAnchor::from_trusted_provider(
        standard_catalog().digest(),
        freshness(1, 1, 1, 1, 1),
        freshness(2, 1, 1, 1, 2),
        legacy.engine.revision(),
        legacy.engine.head(),
    )
    .unwrap();
    assert!(matches!(
        Engine::recover(
            standard_catalog(),
            CoreLimits::bounded_default(),
            anchor,
            &legacy.journal,
        ),
        Err(CoreError::IncompatibleApiProfile)
    ));
}

#[test]
fn composite_adoption_requires_every_component_catalog_policy() {
    let component = ComponentId::new(0xf001).unwrap();
    let obligation = ObligationKindId::new(0xf001).unwrap();
    let composite_kind = CompositeKindId::new(0xf001).unwrap();
    let logical_freshness = FreshnessAxes::BOOT
        .union(FreshnessAxes::REGISTRY)
        .union(FreshnessAxes::BINDING)
        .union(FreshnessAxes::JOURNAL);
    let catalog = DomainCatalogBuilder::new()
        .credit_class(CREDIT_REPLY_SLOT, 8)
        .unwrap()
        .obligation(
            ObligationSpec::new(
                REPLY_DOMAIN,
                obligation,
                ObligationPolicy::SuccessorSettlement,
                AdoptionPolicy::Forbidden,
                ObligationReceipts::successor_settlement(
                    ReceiptBinding::new(REPLY_VERIFIER, REPLY_COMMIT_RECEIPT_SCHEMA),
                    ReceiptBinding::new(REPLY_VERIFIER, REPLY_APPLY_RECEIPT_SCHEMA),
                    ReceiptBinding::new(REPLY_VERIFIER, REPLY_SETTLEMENT_RECEIPT_SCHEMA),
                ),
                1,
            ),
            &[ClaimCardinality::new(REPLY_CLAIM_PUBLICATION_SLOT, 1, 1).unwrap()],
        )
        .unwrap()
        .claim(
            REPLY_DOMAIN,
            REPLY_CLAIM_PUBLICATION_SLOT,
            CREDIT_REPLY_SLOT,
            ClaimScopePolicy::Logical,
            &[EvidenceRule::logical(
                REPLY_EVIDENCE_PUBLICATION_ACK,
                ReceiptBinding::new(REPLY_VERIFIER, REPLY_RECEIPT_SCHEMA),
                logical_freshness,
            )],
        )
        .unwrap()
        .composite(
            composite_kind,
            &[CompositeComponentSpec::new(
                component,
                REPLY_DOMAIN,
                obligation,
            )],
        )
        .unwrap()
        .build()
        .unwrap();
    let mut harness = Harness {
        engine: Engine::new(
            catalog.clone(),
            CoreLimits::bounded_default(),
            freshness(1, 1, 1, 1, 1),
        ),
        journal: Vec::new(),
    };
    let operation = effect(0xcf01, 1);
    let origin = principal(0xcf01, 1);
    let successor = principal(0xcf01, 2);
    harness
        .tx(Command::CreateCompositeEffect {
            effect: operation,
            origin,
            binding_generation: 1,
            kind: composite_kind,
            charge_account: charge(0xcf01),
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: operation,
            component,
            actor: origin,
            binding_generation: 1,
            claim: claim(0xcf01),
            kind: REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(0xcf01),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect: operation,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    harness
        .tx(Command::FenceIncarnation {
            root: operation.root(),
            crashed: origin,
            binding_generation: 1,
        })
        .unwrap();
    let snapshot_id = snapshot(0xcf01);
    let recovery = harness
        .engine
        .snapshot_root(operation.root(), snapshot_id)
        .unwrap();
    harness.tx(recovery.record()).unwrap();
    harness
        .tx(Command::Ready {
            root: operation.root(),
            snapshot: snapshot_id,
            successor,
        })
        .unwrap();
    harness
        .tx(Command::Rebind {
            root: operation.root(),
            snapshot: snapshot_id,
            successor,
            binding_generation: 2,
        })
        .unwrap();

    let before = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
    );
    assert_eq!(
        harness.tx(Command::AdoptEffect {
            effect: operation,
            successor,
            binding_generation: 2,
        }),
        Err(CoreError::AdoptionForbidden)
    );
    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        before
    );
    let projection = harness.engine.composite_effect(operation).unwrap();
    assert_eq!(projection.authority, AuthorityState::Fenced);
    assert_eq!(projection.custodian, CustodyState::KernelEstate);

    let mut original_owner = Harness {
        engine: Engine::new(
            catalog,
            CoreLimits::bounded_default(),
            freshness(1, 1, 1, 1, 1),
        ),
        journal: Vec::new(),
    };
    let commit_effect = effect(0xcf02, 1);
    let commit_owner = principal(0xcf02, 1);
    original_owner
        .tx(Command::CreateCompositeEffect {
            effect: commit_effect,
            origin: commit_owner,
            binding_generation: 1,
            kind: composite_kind,
            charge_account: charge(0xcf02),
        })
        .unwrap();
    original_owner
        .tx(Command::AddComponentClaim {
            effect: commit_effect,
            component,
            actor: commit_owner,
            binding_generation: 1,
            claim: claim(0xcf02),
            kind: REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(0xcf02),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    original_owner
        .tx(Command::PrepareCompositeEffect {
            effect: commit_effect,
            actor: commit_owner,
            binding_generation: 1,
        })
        .unwrap();
    assert!(matches!(
        original_owner.output(Command::RecordComponentCommitIntent {
            effect: commit_effect,
            component,
            actor: commit_owner,
            binding_generation: 1,
            operation: digest(0xf0),
        }),
        TransitionOutput::CommitIntent(_)
    ));
}

#[test]
fn profile_two_rejects_a_second_live_claim_for_one_resource_id() {
    let mut harness = Harness::new_profile_two();
    let operation = effect(0xcf03, 1);
    let owner = principal(0xcf03, 1);
    let shared_resource = resource(0xcf03);
    harness
        .tx(Command::CreateCompositeEffect {
            effect: operation,
            origin: owner,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(0xcf03),
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: operation,
            component: AGENT_COMPONENT_DMA,
            actor: owner,
            binding_generation: 1,
            claim: claim(0xcf03),
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(DeviceScopeId::new(0xcf03).unwrap()),
            resource: shared_resource,
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    let before = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
    );
    assert_eq!(
        harness.tx(Command::AddComponentClaim {
            effect: operation,
            component: AGENT_COMPONENT_DMA,
            actor: owner,
            binding_generation: 1,
            claim: claim(0xcf04),
            kind: DEVICE_CLAIM_PINNED_PAGE,
            scope: ClaimScope::Device(DeviceScopeId::new(0xcf03).unwrap()),
            resource: shared_resource,
            resource_generation: resource_generation(1),
            units: 1,
        }),
        Err(CoreError::ResourceRetained)
    );
    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        before
    );
}

fn device_scope() -> DeviceScopeId {
    DeviceScopeId::new(7).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn component_evidence_command(
    harness: &Harness,
    effect: EffectId,
    component: ComponentId,
    claim: ClaimId,
    kind: EvidenceKindId,
    receipt_binding: ReceiptBinding,
    observation: Freshness,
    receipt_digest: cser_core::Digest,
) -> AuthorizedCommand {
    let challenge = harness
        .engine
        .component_evidence_challenge(effect, component, claim, kind)
        .unwrap();
    let verifier =
        ExactTestVerifier::new(receipt_binding.verifier(), receipt_binding.receipt_schema());
    let receipt = TestReceipt {
        effect,
        claim,
        kind,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject: challenge.subject(),
        observation,
        digest: receipt_digest,
    };
    harness
        .engine
        .verify_component_retirement_evidence(effect, component, claim, kind, &verifier, &receipt)
        .unwrap()
        .submit()
}

fn current_component_evidence_command(
    harness: &Harness,
    effect: EffectId,
    component: ComponentId,
    claim: ClaimId,
    kind: EvidenceKindId,
    receipt_binding: ReceiptBinding,
    receipt_digest: cser_core::Digest,
) -> AuthorizedCommand {
    let observation = harness
        .engine
        .component_evidence_challenge(effect, component, claim, kind)
        .unwrap()
        .current_observation();
    component_evidence_command(
        harness,
        effect,
        component,
        claim,
        kind,
        receipt_binding,
        observation,
        receipt_digest,
    )
}

fn next_device_freshness(current: Freshness) -> Freshness {
    freshness(
        current.boot().get(),
        current.registry().get(),
        current.binding(),
        current.device().get() + 1,
        current.journal().get(),
    )
}

fn reset_component_claim(
    harness: &mut Harness,
    effect: EffectId,
    claim: ClaimId,
    receipt_marker: u8,
) {
    let challenge = harness
        .engine
        .component_evidence_challenge(effect, AGENT_COMPONENT_DMA, claim, DEVICE_EVIDENCE_RESET)
        .unwrap();
    let current = challenge.current_observation();
    let observation = if current.device() == challenge.subject().device() {
        next_device_freshness(current)
    } else {
        current
    };
    let evidence = component_evidence_command(
        harness,
        effect,
        AGENT_COMPONENT_DMA,
        claim,
        DEVICE_EVIDENCE_RESET,
        ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
        observation,
        digest(receipt_marker),
    );
    harness.tx(evidence).unwrap();
}

fn retire_dma_claim(
    harness: &mut Harness,
    effect: EffectId,
    claim: ClaimId,
    terminal_evidence: EvidenceKindId,
    marker: u8,
) -> cser_core::TransitionReceipt {
    reset_component_claim(harness, effect, claim, marker);
    let evidence = current_component_evidence_command(
        harness,
        effect,
        AGENT_COMPONENT_DMA,
        claim,
        terminal_evidence,
        ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
        digest(marker + 1),
    );
    harness.tx(evidence).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn commit_component(
    harness: &mut Harness,
    effect: EffectId,
    component: ComponentId,
    actor: cser_core::PrincipalIncarnation,
    binding_generation: u64,
    operation_marker: u8,
    receipt_marker: u8,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
) {
    let intent = match harness.output(Command::RecordComponentCommitIntent {
        effect,
        component,
        actor,
        binding_generation,
        operation: digest(operation_marker),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected component commit intent, got {other:?}"),
    };
    assert_eq!(intent.effect(), effect);
    assert_eq!(intent.component(), Some(component));
    let outcome = verified_commit_outcome(
        harness,
        &intent,
        verifier,
        receipt_schema,
        ExternalOutcome::Success,
        digest(receipt_marker),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
}

fn arm_agent_components(
    harness: &mut Harness,
    effect: EffectId,
    actor: cser_core::PrincipalIncarnation,
    binding_generation: u64,
    reply_operation: u8,
    dma_operation: u8,
) -> Vec<CommitIntent> {
    match harness.output(Command::RecordCompositeCommitIntents {
        effect,
        actor,
        binding_generation,
        operations: vec![
            ComponentCommitOperation::new(AGENT_COMPONENT_REPLY, digest(reply_operation)),
            ComponentCommitOperation::new(AGENT_COMPONENT_DMA, digest(dma_operation)),
        ],
    }) {
        TransitionOutput::CompositeCommitIntents(intents) => intents,
        other => panic!("expected atomic composite commit intents, got {other:?}"),
    }
}

fn acknowledge_component(
    harness: &mut Harness,
    intent: CommitIntent,
    receipt_marker: u8,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
) {
    let outcome = verified_commit_outcome(
        harness,
        &intent,
        verifier,
        receipt_schema,
        ExternalOutcome::Success,
        digest(receipt_marker),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
}

#[allow(clippy::too_many_arguments)]
fn commit_agent_components(
    harness: &mut Harness,
    effect: EffectId,
    actor: cser_core::PrincipalIncarnation,
    binding_generation: u64,
    reply_operation: u8,
    reply_receipt: u8,
    dma_operation: u8,
    dma_receipt: u8,
) {
    let mut intents = arm_agent_components(
        harness,
        effect,
        actor,
        binding_generation,
        reply_operation,
        dma_operation,
    )
    .into_iter();
    acknowledge_component(
        harness,
        intents.next().expect("reply intent"),
        reply_receipt,
        REPLY_VERIFIER,
        REPLY_COMMIT_RECEIPT_SCHEMA,
    );
    acknowledge_component(
        harness,
        intents.next().expect("DMA intent"),
        dma_receipt,
        DEVICE_VERIFIER,
        DEVICE_COMMIT_RECEIPT_SCHEMA,
    );
    assert!(intents.next().is_none());
}

fn fence_snapshot_ready_rebind(
    harness: &mut Harness,
    effect: EffectId,
    crashed: cser_core::PrincipalIncarnation,
    successor: cser_core::PrincipalIncarnation,
    old_binding: u64,
    new_binding: u64,
    snapshot_value: u64,
) {
    harness
        .tx(Command::FenceIncarnation {
            root: effect.root(),
            crashed,
            binding_generation: old_binding,
        })
        .unwrap();
    let snapshot_id = snapshot(snapshot_value);
    let cohort = harness
        .engine
        .snapshot_root(effect.root(), snapshot_id)
        .unwrap();
    assert!(cohort.items().is_empty());
    assert_eq!(cohort.component_items().len(), 2);
    assert_eq!(cohort.component_items()[0].effect, effect);
    assert_eq!(cohort.component_items()[0].component, AGENT_COMPONENT_REPLY);
    assert_eq!(cohort.component_items()[1].effect, effect);
    assert_eq!(cohort.component_items()[1].component, AGENT_COMPONENT_DMA);
    let expected_retained = cohort
        .component_items()
        .iter()
        .map(|component| component.retained_claims)
        .sum::<usize>();
    assert_eq!(
        cohort.composites()[0].retained_claims.len(),
        expected_retained
    );
    assert!(
        cohort.composites()[0]
            .retained_claims
            .iter()
            .all(|item| item.claim.effect == effect && !item.claim.retired)
    );
    harness.tx(cohort.record()).unwrap();
    harness
        .tx(Command::Ready {
            root: effect.root(),
            snapshot: snapshot_id,
            successor,
        })
        .unwrap();
    harness
        .tx(Command::Rebind {
            root: effect.root(),
            snapshot: snapshot_id,
            successor,
            binding_generation: new_binding,
        })
        .unwrap();
}

fn seed_retired_queue(harness: &mut Harness) -> ResourceId {
    let seed_effect = effect(SEED_ROOT, 1);
    let seed_origin = principal(SEED_ROOT, 1);
    let seed_claim = claim(1);
    let queue = resource(0x7001);
    harness
        .tx(Command::CreateCompositeEffect {
            effect: seed_effect,
            origin: seed_origin,
            binding_generation: 1,
            kind: DMA_ARENA_REUSE_COMPOSITE,
            charge_account: charge(SEED_ROOT),
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: seed_effect,
            component: AGENT_COMPONENT_DMA,
            actor: seed_origin,
            binding_generation: 1,
            claim: seed_claim,
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(device_scope()),
            resource: queue,
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect: seed_effect,
            actor: seed_origin,
            binding_generation: 1,
        })
        .unwrap();
    let intent = match harness.output(Command::RecordComponentCommitIntent {
        effect: seed_effect,
        component: AGENT_COMPONENT_DMA,
        actor: seed_origin,
        binding_generation: 1,
        operation: digest(1),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected seed commit intent, got {other:?}"),
    };
    let outcome = verified_commit_outcome(
        harness,
        &intent,
        DEVICE_VERIFIER,
        DEVICE_COMMIT_RECEIPT_SCHEMA,
        ExternalOutcome::Success,
        digest(2),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();

    let reset_challenge = harness
        .engine
        .component_evidence_challenge(
            seed_effect,
            AGENT_COMPONENT_DMA,
            seed_claim,
            DEVICE_EVIDENCE_RESET,
        )
        .unwrap();
    let reset = component_evidence_command(
        harness,
        seed_effect,
        AGENT_COMPONENT_DMA,
        seed_claim,
        DEVICE_EVIDENCE_RESET,
        ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
        next_device_freshness(reset_challenge.current_observation()),
        digest(3),
    );
    harness.tx(reset).unwrap();
    let irq = current_component_evidence_command(
        harness,
        seed_effect,
        AGENT_COMPONENT_DMA,
        seed_claim,
        DEVICE_EVIDENCE_IRQ_DRAINED,
        ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
        digest(4),
    );
    harness.tx(irq).unwrap();
    assert_eq!(
        harness.engine.check_reusable(queue, resource_generation(1)),
        Ok(())
    );
    harness
        .tx(Command::ReleaseCompositeEffect {
            effect: seed_effect,
        })
        .unwrap();
    queue
}

/// Builds a committed DMA component with reset accepted but its final IRQ-drain
/// quiescence evidence still pending.  The returned command is the transition
/// which releases the resource coordinate when it becomes durable.
fn pending_dma_quiescence_release(
    harness: &mut Harness,
) -> (
    EffectId,
    cser_core::PrincipalIncarnation,
    ClaimId,
    ResourceId,
    AuthorizedCommand,
) {
    let effect = effect(MAIN_ROOT, 1);
    let origin = principal(MAIN_ROOT, 1);
    let claim_id = claim(1);
    let queue = resource(0x7011);
    harness
        .tx(Command::CreateCompositeEffect {
            effect,
            origin,
            binding_generation: 1,
            kind: DMA_ARENA_REUSE_COMPOSITE,
            charge_account: charge(MAIN_ROOT),
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: claim_id,
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(device_scope()),
            resource: queue,
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    commit_component(
        harness,
        effect,
        AGENT_COMPONENT_DMA,
        origin,
        1,
        0x51,
        0x52,
        DEVICE_VERIFIER,
        DEVICE_COMMIT_RECEIPT_SCHEMA,
    );
    reset_component_claim(harness, effect, claim_id, 0x53);
    let final_evidence = current_component_evidence_command(
        harness,
        effect,
        AGENT_COMPONENT_DMA,
        claim_id,
        DEVICE_EVIDENCE_IRQ_DRAINED,
        ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
        digest(0x54),
    );
    (effect, origin, claim_id, queue, final_evidence)
}

#[test]
fn composite_prepare_is_atomic_across_heterogeneous_components() {
    let mut harness = Harness::new_profile_two();
    let effect = effect(0xca01, 1);
    let origin = principal(0xca01, 1);
    harness
        .tx(Command::CreateCompositeEffect {
            effect,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(0xca01),
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: claim(1),
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(DeviceScopeId::new(11).unwrap()),
            resource: resource(0xca11),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();

    let before_revision = harness.engine.revision();
    let before_head = harness.engine.head();
    let before_projection = harness.engine.projection_digest();
    let before_reply = harness
        .engine
        .component(effect, AGENT_COMPONENT_REPLY)
        .unwrap();
    let before_dma = harness
        .engine
        .component(effect, AGENT_COMPONENT_DMA)
        .unwrap();
    assert_eq!(
        harness.tx(Command::PrepareCompositeEffect {
            effect,
            actor: origin,
            binding_generation: 1,
        }),
        Err(CoreError::ClaimCardinalityViolation)
    );
    assert_eq!(harness.engine.revision(), before_revision);
    assert_eq!(harness.engine.head(), before_head);
    assert_eq!(harness.engine.projection_digest(), before_projection);
    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_REPLY)
            .unwrap(),
        before_reply
    );
    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_DMA)
            .unwrap(),
        before_dma
    );
    assert_eq!(before_reply.commit, CommitState::Registered);
    assert_eq!(before_dma.commit, CommitState::Registered);

    harness
        .tx(Command::AddComponentClaim {
            effect,
            component: AGENT_COMPONENT_REPLY,
            actor: origin,
            binding_generation: 1,
            claim: claim(2),
            kind: REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(0xca12),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    let prepare_revision = harness.engine.revision();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    assert_eq!(harness.engine.revision(), prepare_revision + 1);
    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_REPLY)
            .unwrap()
            .commit,
        CommitState::Prepared
    );
    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .commit,
        CommitState::Prepared
    );
}

#[test]
fn composite_profile2_reuses_one_resource_and_replays_the_complete_projection() {
    let mut harness = Harness::new_profile_two();
    let queue_resource = seed_retired_queue(&mut harness);
    let effect = effect(MAIN_ROOT, 1);
    let origin = principal(MAIN_ROOT, 1);
    let first_successor = principal(MAIN_ROOT, 2);
    let second_successor = principal(MAIN_ROOT, 3);
    let settlement_successor = principal(MAIN_ROOT, 4);
    let reconciliation_successor = principal(MAIN_ROOT, 5);
    let reply_claim = claim(10);
    let page_claim = claim(11);
    let iova_claim = claim(12);
    let reused_queue_claim = claim(13);

    harness
        .tx(Command::CreateCompositeEffect {
            effect,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(MAIN_ROOT),
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect,
            component: AGENT_COMPONENT_REPLY,
            actor: origin,
            binding_generation: 1,
            claim: reply_claim,
            kind: REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(0xc511),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: page_claim,
            kind: DEVICE_CLAIM_PINNED_PAGE,
            scope: ClaimScope::Device(device_scope()),
            resource: resource(0xc512),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: iova_claim,
            kind: DEVICE_CLAIM_IOVA,
            scope: ClaimScope::Device(device_scope()),
            resource: resource(0xc513),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();

    fence_snapshot_ready_rebind(&mut harness, effect, origin, first_successor, 1, 2, 1);
    harness
        .tx(Command::AdoptEffect {
            effect,
            successor: first_successor,
            binding_generation: 2,
        })
        .unwrap();
    assert_eq!(
        harness.engine.composite_effect(effect).unwrap().custodian,
        CustodyState::Principal(first_successor)
    );
    assert_eq!(
        harness
            .engine
            .check_reusable(queue_resource, resource_generation(1)),
        Ok(())
    );

    {
        let dead_permit = match harness.output(Command::ReserveComponentReuse {
            effect,
            component: AGENT_COMPONENT_DMA,
            actor: first_successor,
            binding_generation: 2,
            claim: reused_queue_claim,
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(device_scope()),
            resource: queue_resource,
            expected_generation: resource_generation(1),
            units: 1,
            reuse_contract: digest(201),
        }) {
            TransitionOutput::ReusePermit(permit) => permit,
            other => panic!("expected component reuse permit, got {other:?}"),
        };
        assert_eq!(dead_permit.effect(), effect);
        assert_eq!(dead_permit.component(), Some(AGENT_COMPONENT_DMA));
        assert_eq!(dead_permit.claim(), reused_queue_claim);
        assert_eq!(dead_permit.resource(), queue_resource);
        assert_eq!(dead_permit.previous_generation(), resource_generation(1));
        assert_eq!(dead_permit.generation(), resource_generation(2));
        assert_eq!(dead_permit.catalog_digest(), standard_catalog().digest());
        assert!(!dead_permit.retirement_digest().is_zero());
        assert_eq!(dead_permit.reuse_contract(), digest(201));
    }

    fence_snapshot_ready_rebind(
        &mut harness,
        effect,
        first_successor,
        second_successor,
        2,
        3,
        2,
    );
    harness
        .tx(Command::AdoptEffect {
            effect,
            successor: second_successor,
            binding_generation: 3,
        })
        .unwrap();
    let reclaim = harness
        .engine
        .reclaim_component_resource_reuse(
            effect,
            AGENT_COMPONENT_DMA,
            second_successor,
            3,
            queue_resource,
            resource_generation(2),
        )
        .unwrap();
    let reclaimed_permit = match harness.output(reclaim) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected reclaimed component reuse permit, got {other:?}"),
    };
    assert_eq!(reclaimed_permit.effect(), effect);
    assert_eq!(reclaimed_permit.component(), Some(AGENT_COMPONENT_DMA));
    assert_eq!(reclaimed_permit.generation(), resource_generation(2));
    harness.tx(reclaimed_permit.activate()).unwrap();

    let queue_projection = harness
        .engine
        .component_claims(effect, AGENT_COMPONENT_DMA)
        .unwrap()
        .into_iter()
        .find(|projection| projection.claim == reused_queue_claim)
        .unwrap();
    assert_eq!(queue_projection.resource, queue_resource);
    assert_eq!(queue_projection.resource_generation, resource_generation(2));
    assert!(!queue_projection.retired);
    assert!(
        !harness
            .engine
            .component_claims(effect, AGENT_COMPONENT_REPLY)
            .unwrap()[0]
            .retired
    );

    let before_prepare = harness.engine.revision();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect,
            actor: second_successor,
            binding_generation: 3,
        })
        .unwrap();
    assert_eq!(harness.engine.revision(), before_prepare + 1);
    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_REPLY)
            .unwrap()
            .commit,
        CommitState::Prepared
    );
    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .commit,
        CommitState::Prepared
    );

    let before_split_intent = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
    );
    assert_eq!(
        harness.tx(Command::RecordComponentCommitIntent {
            effect,
            component: AGENT_COMPONENT_REPLY,
            actor: second_successor,
            binding_generation: 3,
            operation: digest(19),
        }),
        Err(CoreError::WrongCommitState)
    );
    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        before_split_intent
    );

    let mut intents =
        arm_agent_components(&mut harness, effect, second_successor, 3, 20, 22).into_iter();
    acknowledge_component(
        &mut harness,
        intents.next().expect("reply intent"),
        21,
        REPLY_VERIFIER,
        REPLY_COMMIT_RECEIPT_SCHEMA,
    );
    assert_eq!(
        harness.engine.composite_effect(effect).unwrap().escape,
        EffectEscapeState::Escaped
    );
    acknowledge_component(
        &mut harness,
        intents.next().expect("DMA intent"),
        23,
        DEVICE_VERIFIER,
        DEVICE_COMMIT_RECEIPT_SCHEMA,
    );
    assert!(intents.next().is_none());
    let before_committed_revoke = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
    );
    let committed_authority_epoch = harness
        .engine
        .composite_effect(effect)
        .unwrap()
        .authority_epoch;
    assert_eq!(
        harness.tx(Command::BeginRevoke {
            effect,
            expected_actor: second_successor,
            binding_generation: 3,
            authority_epoch: committed_authority_epoch,
        }),
        Err(CoreError::WrongCommitState)
    );
    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        before_committed_revoke
    );
    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_REPLY)
            .unwrap()
            .effect,
        effect
    );
    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .effect,
        effect
    );

    fence_snapshot_ready_rebind(
        &mut harness,
        effect,
        second_successor,
        settlement_successor,
        3,
        4,
        3,
    );
    // This is a deterministic occupancy measurement, not elapsed time.  The
    // durable journal revision at which the final DMA claim retires gives a
    // stable lower endpoint for the interval during which a flat parent gate
    // would have retained the DMA credits along with the still-live reply.
    let dma_live_claims = harness
        .engine
        .component_claims(effect, AGENT_COMPONENT_DMA)
        .unwrap()
        .into_iter()
        .filter(|claim| !claim.retired)
        .collect::<Vec<_>>();
    let dma_withheld_credit_units = dma_live_claims.iter().map(|claim| claim.units).sum::<u64>();
    assert_eq!(dma_withheld_credit_units, 3);
    let claim_units = |claim_id| {
        dma_live_claims
            .iter()
            .find(|claim| claim.claim == claim_id)
            .expect("measured DMA claim must be live before discharge")
            .units
    };

    let late_irq = current_component_evidence_command(
        &harness,
        effect,
        AGENT_COMPONENT_DMA,
        reused_queue_claim,
        DEVICE_EVIDENCE_IRQ_DRAINED,
        ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
        digest(30),
    );
    reset_component_claim(&mut harness, effect, reused_queue_claim, 31);
    assert_eq!(harness.tx(late_irq), Err(CoreError::StaleEvidence));
    let current_irq = current_component_evidence_command(
        &harness,
        effect,
        AGENT_COMPONENT_DMA,
        reused_queue_claim,
        DEVICE_EVIDENCE_IRQ_DRAINED,
        ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
        digest(32),
    );
    let queue_retirement_revision = harness.tx(current_irq).unwrap().revision();
    let page_retirement_revision =
        retire_dma_claim(&mut harness, effect, page_claim, DEVICE_EVIDENCE_IOTLB, 33).revision();
    let iova_retirement_revision =
        retire_dma_claim(&mut harness, effect, iova_claim, DEVICE_EVIDENCE_IOTLB, 35).revision();

    let dma = harness
        .engine
        .component(effect, AGENT_COMPONENT_DMA)
        .unwrap();
    let reply = harness
        .engine
        .component(effect, AGENT_COMPONENT_REPLY)
        .unwrap();
    assert_eq!(dma.retirement, RetirementState::Retired);
    assert_eq!(dma.settlement, SettlementState::NotRequired);
    assert_eq!(reply.retirement, RetirementState::RetirementPending);
    assert_eq!(reply.retained_claims, 1);
    assert_eq!(
        harness.engine.composite_effect(effect).unwrap().escape,
        EffectEscapeState::PartiallyDischarged
    );
    assert_eq!(
        harness
            .engine
            .check_reusable(queue_resource, resource_generation(2)),
        Ok(())
    );

    let settlement = match harness.output(Command::ClaimComponentSettlement {
        effect,
        component: AGENT_COMPONENT_REPLY,
        claimant: settlement_successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected reply component settlement claim, got {other:?}"),
    };
    assert_eq!(settlement.effect(), effect);
    assert_eq!(settlement.component(), Some(AGENT_COMPONENT_REPLY));
    let settlement = match harness.output(settlement.record_apply_intent(digest(40)).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected intent-stage component claim, got {other:?}"),
    };
    let applied = verified_apply_completion(
        &harness,
        &settlement,
        REPLY_VERIFIER,
        REPLY_APPLY_RECEIPT_SCHEMA,
        digest(41),
    );
    let settlement = match harness.output(settlement.record_applied(applied).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected applied-stage component claim, got {other:?}"),
    };
    let acknowledgement = verified_settlement_ack(
        &harness,
        &settlement,
        REPLY_VERIFIER,
        REPLY_SETTLEMENT_RECEIPT_SCHEMA,
        digest(42),
    );
    let late_ack = settlement.settle(acknowledgement).unwrap();

    fence_snapshot_ready_rebind(
        &mut harness,
        effect,
        settlement_successor,
        reconciliation_successor,
        4,
        5,
        4,
    );
    assert!(matches!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_REPLY)
            .unwrap()
            .settlement,
        SettlementState::ReconciliationRequired {
            generation: 2,
            applied: true
        }
    ));
    assert_eq!(harness.tx(late_ack), Err(CoreError::StaleEvidence));

    let reconciliation = match harness.output(Command::ClaimComponentSettlement {
        effect,
        component: AGENT_COMPONENT_REPLY,
        claimant: reconciliation_successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected reconciliation component claim, got {other:?}"),
    };
    assert_eq!(reconciliation.generation(), 2);
    let acknowledgement = verified_settlement_ack(
        &harness,
        &reconciliation,
        REPLY_VERIFIER,
        REPLY_SETTLEMENT_RECEIPT_SCHEMA,
        digest(43),
    );
    harness
        .tx(reconciliation.settle(acknowledgement).unwrap())
        .unwrap();
    let reply_retirement = current_component_evidence_command(
        &harness,
        effect,
        AGENT_COMPONENT_REPLY,
        reply_claim,
        REPLY_EVIDENCE_PUBLICATION_ACK,
        ReceiptBinding::new(REPLY_VERIFIER, REPLY_RECEIPT_SCHEMA),
        digest(44),
    );
    let reply_retirement_revision = harness.tx(reply_retirement).unwrap().revision();

    // `revision` is a durable semantic-transition coordinate, not a clock.
    // The sum is therefore a counterfactual flat-parent occupancy measure in
    // credit-unit revisions: each DMA credit is counted from its own local
    // discharge until reply discharge. It is deliberately not wall-clock time.
    let partial_discharge_revision_window = reply_retirement_revision
        .checked_sub(iova_retirement_revision)
        .expect("reply retirement must follow DMA retirement");
    let counterfactual_flat_parent_saved_claim_revision_units = [
        (queue_retirement_revision, claim_units(reused_queue_claim)),
        (page_retirement_revision, claim_units(page_claim)),
        (iova_retirement_revision, claim_units(iova_claim)),
    ]
    .into_iter()
    .map(|(retirement_revision, units)| {
        reply_retirement_revision
            .checked_sub(retirement_revision)
            .expect("every DMA claim must retire before the reply")
            .checked_mul(units)
            .expect("bounded claim occupancy must not overflow")
    })
    .try_fold(0u64, |total, window| total.checked_add(window))
    .expect("bounded test measurement must not overflow");
    assert_eq!(partial_discharge_revision_window, 10);
    assert_eq!(counterfactual_flat_parent_saved_claim_revision_units, 36);

    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_REPLY)
            .unwrap()
            .settlement,
        SettlementState::Settled
    );
    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_REPLY)
            .unwrap()
            .retirement,
        RetirementState::Retired
    );
    assert_eq!(
        harness.engine.composite_effect(effect).unwrap().escape,
        EffectEscapeState::Retired
    );
    harness
        .tx(Command::ReleaseCompositeEffect { effect })
        .unwrap();
    assert_eq!(
        harness.engine.composite_effect(effect).unwrap().escape,
        EffectEscapeState::Released
    );
    assert_eq!(
        harness.engine.composite_effect(effect).unwrap().authority,
        AuthorityState::Revoked
    );
    assert_eq!(
        harness.engine.composite_effect(effect).unwrap().custodian,
        CustodyState::Released
    );

    let expected_composite = harness.engine.composite_effect(effect).unwrap();
    let expected_reply = harness
        .engine
        .component(effect, AGENT_COMPONENT_REPLY)
        .unwrap();
    let expected_dma = harness
        .engine
        .component(effect, AGENT_COMPONENT_DMA)
        .unwrap();
    let expected_reply_claims = harness
        .engine
        .component_claims(effect, AGENT_COMPONENT_REPLY)
        .unwrap();
    let expected_dma_claims = harness
        .engine
        .component_claims(effect, AGENT_COMPONENT_DMA)
        .unwrap();
    let pre_recovery_projection_digest = harness.engine.projection_digest();
    let revision = harness.engine.revision();
    let head = harness.engine.head();
    let recovery_anchor = || {
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 3, 2),
            revision,
            head,
        )
        .unwrap()
    };
    let report = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        recovery_anchor(),
        &harness.journal,
    )
    .unwrap();
    assert_eq!(report.acknowledged_revision(), revision);
    assert_eq!(report.acknowledged_head(), head);
    let recovered = report.into_engine();
    let recovered_projection_digest = recovered.projection_digest();
    assert_ne!(
        recovered_projection_digest, pre_recovery_projection_digest,
        "the pending fresh recovery target is part of projection v6"
    );
    let replayed_again = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        recovery_anchor(),
        &harness.journal,
    )
    .unwrap()
    .into_engine();
    assert_eq!(
        replayed_again.projection_digest(),
        recovered_projection_digest,
        "the same journal prefix and trusted anchor must replay deterministically"
    );
    assert_eq!(
        recovered.composite_effect(effect).unwrap(),
        expected_composite
    );
    assert_eq!(
        recovered.component(effect, AGENT_COMPONENT_REPLY).unwrap(),
        expected_reply
    );
    assert_eq!(
        recovered.component(effect, AGENT_COMPONENT_DMA).unwrap(),
        expected_dma
    );
    assert_eq!(
        recovered
            .component_claims(effect, AGENT_COMPONENT_REPLY)
            .unwrap(),
        expected_reply_claims
    );
    assert_eq!(
        recovered
            .component_claims(effect, AGENT_COMPONENT_DMA)
            .unwrap(),
        expected_dma_claims
    );
}

#[test]
fn dma_only_profile2_operation_reuses_a_retired_composite_resource() {
    let mut harness = Harness::new_profile_two();
    let origin = principal(MAIN_ROOT, 1);
    let original = effect(MAIN_ROOT, 1);
    let reuse = effect(MAIN_ROOT, 2);
    let reply_claim = claim(50);
    let queue_claim = claim(51);
    let reused_queue_claim = claim(52);
    let queue_resource = resource(0xc552);

    harness
        .tx(Command::CreateCompositeEffect {
            effect: original,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(MAIN_ROOT),
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: original,
            component: AGENT_COMPONENT_REPLY,
            actor: origin,
            binding_generation: 1,
            claim: reply_claim,
            kind: REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(0xc551),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: original,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: queue_claim,
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(device_scope()),
            resource: queue_resource,
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect: original,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    commit_agent_components(&mut harness, original, origin, 1, 50, 51, 52, 53);

    // A real reservation command, rather than a read-only projection, proves
    // that the retained claim closes the admission gate.  The failed command
    // is deliberately retried unchanged after exact retirement below.
    harness
        .tx(Command::CreateCompositeEffect {
            effect: reuse,
            origin,
            binding_generation: 1,
            kind: DMA_ARENA_REUSE_COMPOSITE,
            charge_account: charge(MAIN_ROOT),
        })
        .unwrap();
    let before_retained_reuse_probe = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
    );
    assert_eq!(
        harness.tx(Command::ReserveComponentReuse {
            effect: reuse,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: reused_queue_claim,
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(device_scope()),
            resource: queue_resource,
            expected_generation: resource_generation(1),
            units: 1,
            reuse_contract: digest(202),
        }),
        Err(CoreError::ResourceRetained)
    );
    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        before_retained_reuse_probe
    );

    retire_dma_claim(
        &mut harness,
        original,
        queue_claim,
        DEVICE_EVIDENCE_IRQ_DRAINED,
        54,
    );
    assert_eq!(
        harness
            .engine
            .check_reusable(queue_resource, resource_generation(1)),
        Ok(())
    );
    assert_eq!(
        harness
            .engine
            .component(original, AGENT_COMPONENT_REPLY)
            .unwrap()
            .retained_claims,
        1
    );

    let before_invalid_contract = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
    );
    assert_eq!(
        harness.tx(Command::ReserveComponentReuse {
            effect: reuse,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: reused_queue_claim,
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(device_scope()),
            resource: queue_resource,
            expected_generation: resource_generation(1),
            units: 1,
            reuse_contract: cser_core::Digest::ZERO,
        }),
        Err(CoreError::InvalidPayload)
    );
    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        before_invalid_contract
    );
    let permit = match harness.output(Command::ReserveComponentReuse {
        effect: reuse,
        component: AGENT_COMPONENT_DMA,
        actor: origin,
        binding_generation: 1,
        claim: reused_queue_claim,
        kind: DEVICE_CLAIM_QUEUE_SLOT,
        scope: ClaimScope::Device(device_scope()),
        resource: queue_resource,
        expected_generation: resource_generation(1),
        units: 1,
        reuse_contract: digest(202),
    }) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected cross-effect component reuse permit, got {other:?}"),
    };
    assert_eq!(permit.effect(), reuse);
    assert_eq!(permit.component(), Some(AGENT_COMPONENT_DMA));
    assert_eq!(permit.claim(), reused_queue_claim);
    assert_eq!(permit.previous_generation(), resource_generation(1));
    assert_eq!(permit.generation(), resource_generation(2));
    assert_eq!(permit.catalog_digest(), standard_catalog().digest());
    assert!(!permit.retirement_digest().is_zero());
    assert_eq!(permit.reuse_contract(), digest(202));
    harness.tx(permit.activate()).unwrap();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect: reuse,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    commit_component(
        &mut harness,
        reuse,
        AGENT_COMPONENT_DMA,
        origin,
        1,
        55,
        56,
        DEVICE_VERIFIER,
        DEVICE_COMMIT_RECEIPT_SCHEMA,
    );

    let reused = harness
        .engine
        .component_claims(reuse, AGENT_COMPONENT_DMA)
        .unwrap();
    assert_eq!(reused.len(), 1);
    assert_eq!(reused[0].resource, queue_resource);
    assert_eq!(reused[0].resource_generation, resource_generation(2));
    assert!(!reused[0].retired);
    assert_eq!(
        harness
            .engine
            .component(original, AGENT_COMPONENT_REPLY)
            .unwrap()
            .retained_claims,
        1
    );
}

struct AdoptedProfileTwoFixture {
    harness: Harness,
    effect: EffectId,
    successor: cser_core::PrincipalIncarnation,
    reply_claim: ClaimId,
    page_claim: ClaimId,
    iova_claim: ClaimId,
    reusable_queue: ResourceId,
}

fn replay_profile_two_prefix(harness: &Harness, label: &str) -> Engine {
    let revision = harness.engine.revision();
    let head = harness.engine.head();
    let anchor = || {
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 99, 2),
            revision,
            head,
        )
        .unwrap()
    };
    let recovered = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        anchor(),
        &harness.journal,
    )
    .unwrap_or_else(|error| panic!("{label}: profile-2 recovery failed: {error:?}"));
    assert_eq!(recovered.acknowledged_revision(), revision, "{label}");
    assert_eq!(recovered.acknowledged_head(), head, "{label}");
    let recovered = recovered.into_engine();
    let recovered_projection_digest = recovered.projection_digest();
    let replayed_again = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        anchor(),
        &harness.journal,
    )
    .unwrap_or_else(|error| panic!("{label}: second profile-2 recovery failed: {error:?}"));
    assert_eq!(
        replayed_again.into_engine().projection_digest(),
        recovered_projection_digest,
        "{label}: replay is deterministic"
    );
    recovered
}

fn adopted_profile_two_fixture(root: u64) -> AdoptedProfileTwoFixture {
    let mut harness = Harness::new_profile_two();
    let reusable_queue = seed_retired_queue(&mut harness);
    let effect = effect(root, 1);
    let origin = principal(root, 1);
    let successor = principal(root, 2);
    let reply_claim = claim(root + 1);
    let page_claim = claim(root + 2);
    let iova_claim = claim(root + 3);

    harness
        .tx(Command::CreateCompositeEffect {
            effect,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(root),
        })
        .unwrap();
    for (component, claim, kind, scope, resource) in [
        (
            AGENT_COMPONENT_REPLY,
            reply_claim,
            REPLY_CLAIM_PUBLICATION_SLOT,
            ClaimScope::Logical,
            resource(root + 10),
        ),
        (
            AGENT_COMPONENT_DMA,
            page_claim,
            DEVICE_CLAIM_PINNED_PAGE,
            ClaimScope::Device(device_scope()),
            resource(root + 11),
        ),
        (
            AGENT_COMPONENT_DMA,
            iova_claim,
            DEVICE_CLAIM_IOVA,
            ClaimScope::Device(device_scope()),
            resource(root + 12),
        ),
    ] {
        harness
            .tx(Command::AddComponentClaim {
                effect,
                component,
                actor: origin,
                binding_generation: 1,
                claim,
                kind,
                scope,
                resource,
                resource_generation: resource_generation(1),
                units: 1,
            })
            .unwrap();
    }
    fence_snapshot_ready_rebind(&mut harness, effect, origin, successor, 1, 2, root);
    harness
        .tx(Command::AdoptEffect {
            effect,
            successor,
            binding_generation: 2,
        })
        .unwrap();

    AdoptedProfileTwoFixture {
        harness,
        effect,
        successor,
        reply_claim,
        page_claim,
        iova_claim,
        reusable_queue,
    }
}

#[test]
fn profile2_durable_replay_covers_composite_partial_prefixes() {
    let mut fixture = adopted_profile_two_fixture(0xcb01);
    let reuse_claim = claim(0xcb10);
    let issued = match fixture.harness.output(Command::ReserveComponentReuse {
        effect: fixture.effect,
        component: AGENT_COMPONENT_DMA,
        actor: fixture.successor,
        binding_generation: 2,
        claim: reuse_claim,
        kind: DEVICE_CLAIM_QUEUE_SLOT,
        scope: ClaimScope::Device(device_scope()),
        resource: fixture.reusable_queue,
        expected_generation: resource_generation(1),
        units: 1,
        reuse_contract: digest(211),
    }) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected issued reuse permit, got {other:?}"),
    };
    let recovered = replay_profile_two_prefix(&fixture.harness, "issued-before-consume");
    assert!(
        recovered
            .component_claims(fixture.effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .iter()
            .any(|claim| {
                claim.claim == reuse_claim
                    && claim.resource == fixture.reusable_queue
                    && claim.resource_generation == resource_generation(2)
            })
    );

    let second_successor = principal(0xcb01, 3);
    fence_snapshot_ready_rebind(
        &mut fixture.harness,
        fixture.effect,
        fixture.successor,
        second_successor,
        2,
        3,
        0xcb02,
    );
    fixture
        .harness
        .tx(Command::AdoptEffect {
            effect: fixture.effect,
            successor: second_successor,
            binding_generation: 3,
        })
        .unwrap();
    let reclaimed = fixture
        .harness
        .engine
        .reclaim_component_resource_reuse(
            fixture.effect,
            AGENT_COMPONENT_DMA,
            second_successor,
            3,
            fixture.reusable_queue,
            resource_generation(2),
        )
        .unwrap();
    let reclaimed = match fixture.harness.output(reclaimed) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected reclaimed reuse permit, got {other:?}"),
    };
    assert_eq!(reclaimed.generation(), issued.generation());
    let recovered = replay_profile_two_prefix(&fixture.harness, "reclaimed-before-consume");
    assert_eq!(
        recovered
            .component_claims(fixture.effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .iter()
            .find(|claim| claim.claim == reuse_claim)
            .unwrap()
            .resource_generation,
        resource_generation(2)
    );
    fixture.harness.tx(reclaimed.activate()).unwrap();
    let recovered = replay_profile_two_prefix(&fixture.harness, "partial-generation-plus-one");
    assert!(
        recovered
            .component_claims(fixture.effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .iter()
            .any(|claim| {
                claim.claim == reuse_claim
                    && claim.resource_generation == resource_generation(2)
                    && !claim.retired
            })
    );

    fixture
        .harness
        .tx(Command::PrepareCompositeEffect {
            effect: fixture.effect,
            actor: second_successor,
            binding_generation: 3,
        })
        .unwrap();
    commit_agent_components(
        &mut fixture.harness,
        fixture.effect,
        second_successor,
        3,
        212,
        213,
        214,
        215,
    );

    for (claim, terminal, label) in [
        (reuse_claim, DEVICE_EVIDENCE_IRQ_DRAINED, "queue-discharge"),
        (fixture.iova_claim, DEVICE_EVIDENCE_IOTLB, "iova-discharge"),
        (fixture.page_claim, DEVICE_EVIDENCE_IOTLB, "page-discharge"),
    ] {
        retire_dma_claim(&mut fixture.harness, fixture.effect, claim, terminal, 220);
        let recovered = replay_profile_two_prefix(&fixture.harness, label);
        assert!(
            recovered
                .component_claims(fixture.effect, AGENT_COMPONENT_DMA)
                .unwrap()
                .iter()
                .find(|projection| projection.claim == claim)
                .unwrap()
                .retired
        );
    }

    let settlement = match fixture.harness.output(Command::ClaimComponentSettlement {
        effect: fixture.effect,
        component: AGENT_COMPONENT_REPLY,
        claimant: second_successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected reply settlement claim, got {other:?}"),
    };
    let settlement = match fixture
        .harness
        .output(settlement.record_apply_intent(digest(230)).unwrap())
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected reply apply intent, got {other:?}"),
    };
    let applied = verified_apply_completion(
        &fixture.harness,
        &settlement,
        REPLY_VERIFIER,
        REPLY_APPLY_RECEIPT_SCHEMA,
        digest(231),
    );
    fixture
        .harness
        .tx(settlement.record_applied(applied).unwrap())
        .unwrap();
    fixture
        .harness
        .tx(Command::FenceIncarnation {
            root: fixture.effect.root(),
            crashed: second_successor,
            binding_generation: 3,
        })
        .unwrap();
    let recovered = replay_profile_two_prefix(&fixture.harness, "applied-unacknowledged");
    assert_eq!(
        recovered
            .component(fixture.effect, AGENT_COMPONENT_REPLY)
            .unwrap()
            .settlement,
        SettlementState::ReconciliationRequired {
            generation: 2,
            applied: true,
        }
    );
    assert_eq!(
        recovered
            .component_claims(fixture.effect, AGENT_COMPONENT_REPLY)
            .unwrap()[0]
            .claim,
        fixture.reply_claim
    );
}

#[test]
fn profile2_activation_persist_failure_replays_the_ambiguous_generation_plus_one_record() {
    #[derive(Debug)]
    struct PersistFault;

    let mut fixture = adopted_profile_two_fixture(0xcb21);
    let reuse_claim = claim(0xcb30);
    let permit = match fixture.harness.output(Command::ReserveComponentReuse {
        effect: fixture.effect,
        component: AGENT_COMPONENT_DMA,
        actor: fixture.successor,
        binding_generation: 2,
        claim: reuse_claim,
        kind: DEVICE_CLAIM_QUEUE_SLOT,
        scope: ClaimScope::Device(device_scope()),
        resource: fixture.reusable_queue,
        expected_generation: resource_generation(1),
        units: 1,
        reuse_contract: digest(240),
    }) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected reusable queue permit, got {other:?}"),
    };
    let prefix_revision =
        replay_profile_two_prefix(&fixture.harness, "activation-persist-prefix").revision();
    let activation = permit.activate();
    let mut ambiguous_record = Vec::new();
    assert!(matches!(
        fixture.harness.engine.transact(activation, |record| {
            ambiguous_record.extend_from_slice(record.bytes());
            Err(PersistFault)
        }),
        Err(TxError::Persist(PersistFault))
    ));
    assert!(fixture.harness.engine.persistence_recovery_required());
    fixture.harness.journal.extend_from_slice(&ambiguous_record);
    let activated_scan = scan_journal(&fixture.harness.journal).unwrap();
    let activated_record = activated_scan.records().last().unwrap();
    let recovery_anchor = RecoveryAnchor::from_trusted_provider(
        standard_catalog().digest(),
        freshness(1, 1, 1, 1, 1),
        freshness(2, 1, 1, 99, 2),
        activated_record.revision(),
        activated_record.digest(),
    )
    .unwrap();
    let recovered = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        recovery_anchor,
        &fixture.harness.journal,
    )
    .unwrap()
    .into_engine();
    assert_eq!(recovered.revision(), prefix_revision + 1);
    assert!(
        recovered
            .component_claims(fixture.effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .iter()
            .any(|claim| {
                claim.claim == reuse_claim
                    && claim.resource_generation == resource_generation(2)
                    && !claim.retired
            })
    );
}

fn create_precommit_agent(
    harness: &mut Harness,
    root_value: u64,
) -> (EffectId, cser_core::PrincipalIncarnation, ClaimId, ClaimId) {
    let operation = effect(root_value, 1);
    let origin = principal(root_value, 1);
    let reply_claim = claim(root_value + 1);
    let queue_claim = claim(root_value + 2);
    harness
        .tx(Command::CreateCompositeEffect {
            effect: operation,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(root_value),
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: operation,
            component: AGENT_COMPONENT_REPLY,
            actor: origin,
            binding_generation: 1,
            claim: reply_claim,
            kind: REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(root_value + 10),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: operation,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: queue_claim,
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(device_scope()),
            resource: resource(root_value + 11),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect: operation,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    (operation, origin, reply_claim, queue_claim)
}

fn recover_checkpoint_and_adopt_precommit(
    harness: &mut Harness,
    operation: EffectId,
    origin: cser_core::PrincipalIncarnation,
    successor: cser_core::PrincipalIncarnation,
    snapshot_value: u64,
) {
    let anchor = RecoveryAnchor::from_trusted_provider(
        standard_catalog().digest(),
        freshness(1, 1, 1, 1, 1),
        freshness(2, 1, 1, 2, 2),
        harness.engine.revision(),
        harness.engine.head(),
    )
    .unwrap();
    harness.engine = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        anchor,
        &harness.journal,
    )
    .unwrap()
    .into_engine();
    assert!(harness.engine.pressure().quarantined);

    let before_pending = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
    );
    assert_eq!(
        harness.tx(Command::RebaseCompositePrecommitClaims {
            effect: operation,
            actor: origin,
            binding_generation: 1,
        }),
        Err(CoreError::RecoveryPending)
    );
    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        before_pending
    );

    harness
        .tx(Command::CheckpointRecovery {
            boot: freshness(2, 1, 1, 2, 2).boot(),
            journal: freshness(2, 1, 1, 2, 2).journal(),
            device: freshness(2, 1, 1, 2, 2).device(),
        })
        .unwrap();
    let snapshot_id = snapshot(snapshot_value);
    let cohort = harness
        .engine
        .snapshot_root(operation.root(), snapshot_id)
        .unwrap();
    harness.tx(cohort.record()).unwrap();
    harness
        .tx(Command::Ready {
            root: operation.root(),
            snapshot: snapshot_id,
            successor,
        })
        .unwrap();
    harness
        .tx(Command::Rebind {
            root: operation.root(),
            snapshot: snapshot_id,
            successor,
            binding_generation: 2,
        })
        .unwrap();
    harness
        .tx(Command::AdoptEffect {
            effect: operation,
            successor,
            binding_generation: 2,
        })
        .unwrap();
}

#[test]
fn adopted_precommit_claim_rebase_clears_quarantine_and_replays_schema_six() {
    let mut harness = Harness::new_profile_two();
    let (operation, origin, reply_claim, queue_claim) =
        create_precommit_agent(&mut harness, 0xcd01);
    let successor = principal(0xcd01, 2);
    let before_adoption = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
    );
    assert_eq!(
        harness.tx(Command::RebaseCompositePrecommitClaims {
            effect: operation,
            actor: origin,
            binding_generation: 1,
        }),
        Err(CoreError::WrongCommitState)
    );
    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        before_adoption
    );
    recover_checkpoint_and_adopt_precommit(&mut harness, operation, origin, successor, 0xcd01);

    let old_freshness = freshness(1, 1, 1, 1, 1);
    assert_eq!(
        harness
            .engine
            .component_claims(operation, AGENT_COMPONENT_REPLY)
            .unwrap()[0]
            .enrolled_freshness,
        old_freshness
    );
    assert_eq!(
        harness
            .engine
            .component_claims(operation, AGENT_COMPONENT_DMA)
            .unwrap()[0]
            .enrolled_freshness,
        old_freshness
    );
    let parent_before = harness.engine.composite_effect(operation).unwrap();
    let reply_before = harness
        .engine
        .component(operation, AGENT_COMPONENT_REPLY)
        .unwrap();
    let dma_before = harness
        .engine
        .component(operation, AGENT_COMPONENT_DMA)
        .unwrap();

    let request = Command::RebaseCompositePrecommitClaims {
        effect: operation,
        actor: successor,
        binding_generation: 2,
    };
    assert!(request.is_profile_two_compatible());
    let receipt = harness.tx(request).unwrap();
    assert_eq!(
        receipt.event(),
        TransitionEvent::CompositePrecommitClaimsRebased
    );
    assert_eq!(receipt.coordinates().effect(), Some(operation));
    assert_eq!(receipt.coordinates().component(), None);
    assert_eq!(receipt.into_output(), TransitionOutput::None);

    let current = freshness(2, 1, 2, 2, 2);
    let reply = harness
        .engine
        .component_claims(operation, AGENT_COMPONENT_REPLY)
        .unwrap();
    let dma = harness
        .engine
        .component_claims(operation, AGENT_COMPONENT_DMA)
        .unwrap();
    assert_eq!(reply[0].claim, reply_claim);
    assert_eq!(reply[0].enrolled_freshness, current);
    assert_eq!(dma[0].claim, queue_claim);
    assert_eq!(dma[0].enrolled_freshness, current);
    assert!(!harness.engine.pressure().quarantined);
    assert_eq!(
        harness.engine.composite_effect(operation).unwrap(),
        parent_before
    );
    assert_eq!(
        harness
            .engine
            .component(operation, AGENT_COMPONENT_REPLY)
            .unwrap(),
        reply_before
    );
    assert_eq!(
        harness
            .engine
            .component(operation, AGENT_COMPONENT_DMA)
            .unwrap(),
        dma_before
    );

    let before_duplicate = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
    );
    assert_eq!(
        harness.tx(Command::RebaseCompositePrecommitClaims {
            effect: operation,
            actor: successor,
            binding_generation: 2,
        }),
        Err(CoreError::StaleEvidence)
    );
    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        before_duplicate
    );

    let replay = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            freshness(2, 1, 1, 2, 2),
            freshness(3, 1, 1, 2, 3),
            harness.engine.revision(),
            harness.engine.head(),
        )
        .unwrap(),
        &harness.journal,
    )
    .unwrap()
    .into_engine();
    assert_eq!(
        replay
            .component_claims(operation, AGENT_COMPONENT_REPLY)
            .unwrap()[0]
            .enrolled_freshness,
        current
    );
    assert_eq!(
        replay
            .component_claims(operation, AGENT_COMPONENT_DMA)
            .unwrap()[0]
            .enrolled_freshness,
        current
    );
    assert!(
        replay.pressure().quarantined,
        "the next boot must establish its own quarantine before another rebase"
    );
}

#[test]
fn pending_generation_plus_one_survives_rebase_for_explicit_reclaim_only() {
    let mut harness = Harness::new_profile_two();
    let queue = seed_retired_queue(&mut harness);
    let operation = effect(0xcd11, 1);
    let origin = principal(0xcd11, 1);
    let successor = principal(0xcd11, 2);
    let reuse_claim = claim(0xcd11);
    harness
        .tx(Command::CreateCompositeEffect {
            effect: operation,
            origin,
            binding_generation: 1,
            kind: DMA_ARENA_REUSE_COMPOSITE,
            charge_account: charge(0xcd11),
        })
        .unwrap();
    let old_permit = match harness.output(Command::ReserveComponentReuse {
        effect: operation,
        component: AGENT_COMPONENT_DMA,
        actor: origin,
        binding_generation: 1,
        claim: reuse_claim,
        kind: DEVICE_CLAIM_QUEUE_SLOT,
        scope: ClaimScope::Device(device_scope()),
        resource: queue,
        expected_generation: resource_generation(1),
        units: 1,
        reuse_contract: digest(0xd1),
    }) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected pending generation+1 permit, got {other:?}"),
    };
    let retained_contract = (
        old_permit.previous_generation(),
        old_permit.generation(),
        old_permit.catalog_digest(),
        old_permit.retirement_digest(),
        old_permit.reuse_contract(),
    );
    harness
        .tx(Command::PrepareCompositeEffect {
            effect: operation,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    recover_checkpoint_and_adopt_precommit(&mut harness, operation, origin, successor, 0xcd11);
    assert_eq!(
        harness.engine.reclaim_component_resource_reuse(
            operation,
            AGENT_COMPONENT_DMA,
            successor,
            2,
            queue,
            resource_generation(2),
        ),
        Err(CoreError::Quarantined)
    );

    let receipt = harness
        .tx(Command::RebaseCompositePrecommitClaims {
            effect: operation,
            actor: successor,
            binding_generation: 2,
        })
        .unwrap();
    assert_eq!(receipt.into_output(), TransitionOutput::None);
    assert!(!harness.engine.pressure().quarantined);
    let before_stale_bearer = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
    );
    assert_eq!(
        harness.tx(old_permit.activate()),
        Err(CoreError::StaleIncarnation)
    );
    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        before_stale_bearer
    );

    let reclaim = harness
        .engine
        .reclaim_component_resource_reuse(
            operation,
            AGENT_COMPONENT_DMA,
            successor,
            2,
            queue,
            resource_generation(2),
        )
        .unwrap();
    let permit = match harness.output(reclaim) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("explicit reclaim must be the only new bearer, got {other:?}"),
    };
    assert_eq!(
        (
            permit.previous_generation(),
            permit.generation(),
            permit.catalog_digest(),
            permit.retirement_digest(),
            permit.reuse_contract(),
        ),
        retained_contract
    );
    assert_eq!(permit.freshness(), freshness(2, 1, 2, 2, 2));
    harness.tx(permit.activate()).unwrap();
}

#[test]
fn activated_generation_plus_one_remains_retained_across_precommit_rebase() {
    let mut harness = Harness::new_profile_two();
    let queue = seed_retired_queue(&mut harness);
    let operation = effect(0xcd21, 1);
    let origin = principal(0xcd21, 1);
    let successor = principal(0xcd21, 2);
    let reuse_claim = claim(0xcd21);
    harness
        .tx(Command::CreateCompositeEffect {
            effect: operation,
            origin,
            binding_generation: 1,
            kind: DMA_ARENA_REUSE_COMPOSITE,
            charge_account: charge(0xcd21),
        })
        .unwrap();
    let permit = match harness.output(Command::ReserveComponentReuse {
        effect: operation,
        component: AGENT_COMPONENT_DMA,
        actor: origin,
        binding_generation: 1,
        claim: reuse_claim,
        kind: DEVICE_CLAIM_QUEUE_SLOT,
        scope: ClaimScope::Device(device_scope()),
        resource: queue,
        expected_generation: resource_generation(1),
        units: 1,
        reuse_contract: digest(0xd2),
    }) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected generation+1 permit, got {other:?}"),
    };
    harness.tx(permit.activate()).unwrap();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect: operation,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    recover_checkpoint_and_adopt_precommit(&mut harness, operation, origin, successor, 0xcd21);
    assert_eq!(
        harness
            .tx(Command::RebaseCompositePrecommitClaims {
                effect: operation,
                actor: successor,
                binding_generation: 2,
            })
            .unwrap()
            .into_output(),
        TransitionOutput::None
    );
    assert_eq!(
        harness.engine.reclaim_component_resource_reuse(
            operation,
            AGENT_COMPONENT_DMA,
            successor,
            2,
            queue,
            resource_generation(2),
        ),
        Err(CoreError::StaleReusePermit)
    );
    assert_eq!(
        harness
            .engine
            .component_claims(operation, AGENT_COMPONENT_DMA)
            .unwrap()[0]
            .resource_generation,
        resource_generation(2)
    );
    assert!(matches!(
        harness.output(Command::RecordComponentCommitIntent {
            effect: operation,
            component: AGENT_COMPONENT_DMA,
            actor: successor,
            binding_generation: 2,
            operation: digest(0xd3),
        }),
        TransitionOutput::CommitIntent(_)
    ));
}

#[test]
fn escaped_claim_in_shared_device_scope_keeps_rebase_fail_closed() {
    let mut harness = Harness::new_profile_two();
    let root_value = 0xcd31;
    let origin = principal(root_value, 1);
    let blocker = effect(root_value, 1);
    let target = effect(root_value, 2);
    harness
        .tx(Command::CreateCompositeEffect {
            effect: blocker,
            origin,
            binding_generation: 1,
            kind: DMA_ARENA_REUSE_COMPOSITE,
            charge_account: charge(root_value),
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: blocker,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: claim(0xcd31),
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(device_scope()),
            resource: resource(0xcd31),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect: blocker,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    commit_component(
        &mut harness,
        blocker,
        AGENT_COMPONENT_DMA,
        origin,
        1,
        0xd4,
        0xd5,
        DEVICE_VERIFIER,
        DEVICE_COMMIT_RECEIPT_SCHEMA,
    );
    let escaped_before = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
    );
    assert_eq!(
        harness.tx(Command::RebaseCompositePrecommitClaims {
            effect: blocker,
            actor: origin,
            binding_generation: 1,
        }),
        Err(CoreError::WrongCommitState)
    );
    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        escaped_before
    );

    harness
        .tx(Command::CreateCompositeEffect {
            effect: target,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(root_value),
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: target,
            component: AGENT_COMPONENT_REPLY,
            actor: origin,
            binding_generation: 1,
            claim: claim(0xcd32),
            kind: REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(0xcd32),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: target,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: claim(0xcd33),
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(device_scope()),
            resource: resource(0xcd33),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect: target,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();

    let successor = principal(root_value, 2);
    recover_checkpoint_and_adopt_precommit(&mut harness, target, origin, successor, 0xcd31);
    let before = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
    );
    assert_eq!(
        harness.tx(Command::RebaseCompositePrecommitClaims {
            effect: target,
            actor: successor,
            binding_generation: 2,
        }),
        Err(CoreError::ResourceRetained)
    );
    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
        ),
        before
    );
    assert!(harness.engine.pressure().quarantined);
    assert_eq!(
        harness
            .engine
            .component_claims(target, AGENT_COMPONENT_DMA)
            .unwrap()[0]
            .enrolled_freshness,
        freshness(1, 1, 1, 1, 1)
    );
    assert_eq!(
        harness
            .engine
            .component(blocker, AGENT_COMPONENT_DMA)
            .unwrap()
            .commit,
        CommitState::Committed
    );
}

#[test]
fn nonempty_profile1_journal_fails_closed_without_pairing_heuristics() {
    assert!(matches!(
        scan_journal(b"CSERJR5\0"),
        Err(JournalDecodeError::UnsupportedVersion { version: 5 })
    ));

    let mut profile_one = Vec::from(*b"CSERJR5\0");
    profile_one.extend_from_slice(&5u16.to_le_bytes());
    profile_one.extend_from_slice(&0u16.to_le_bytes());
    profile_one.extend_from_slice(&16u32.to_le_bytes());
    profile_one.extend_from_slice(&MAIN_ROOT.to_le_bytes());
    profile_one.extend_from_slice(&SEED_ROOT.to_le_bytes());
    profile_one.extend_from_slice(&1_786_000_000u64.to_le_bytes());

    assert!(matches!(
        scan_journal(&profile_one),
        Err(JournalDecodeError::UnsupportedVersion { version: 5 })
    ));
    let genesis_anchor = RecoveryAnchor::from_trusted_provider(
        standard_catalog().digest(),
        freshness(1, 1, 1, 1, 1),
        freshness(2, 1, 1, 1, 2),
        0,
        cser_core::Digest::ZERO,
    )
    .unwrap();
    assert!(matches!(
        Engine::recover(
            standard_catalog(),
            CoreLimits::bounded_default(),
            genesis_anchor,
            &profile_one,
        ),
        Err(CoreError::Journal(JournalDecodeError::UnsupportedVersion {
            version: 5
        }))
    ));
    let anchor = RecoveryAnchor::from_trusted_provider(
        standard_catalog().digest(),
        freshness(1, 1, 1, 1, 1),
        freshness(2, 1, 1, 1, 2),
        1,
        digest(99),
    )
    .unwrap();
    assert!(matches!(
        Engine::recover(
            standard_catalog(),
            CoreLimits::bounded_default(),
            anchor,
            &profile_one,
        ),
        Err(CoreError::Journal(JournalDecodeError::UnsupportedVersion {
            version: 5
        }))
    ));
}

#[test]
fn profile1_pairing_collision_corpus_is_rejected_before_payload_decode() {
    let collision_payloads = [
        // Historical root constants.
        [MAIN_ROOT.to_le_bytes(), SEED_ROOT.to_le_bytes()].concat(),
        // Adjacent effect sequences.
        [41u64.to_le_bytes(), 42u64.to_le_bytes()].concat(),
        // Equal wall-clock-like coordinates.
        [1_786_000_000u64.to_le_bytes(); 2].concat(),
        // Shared boot/Registry/device epochs.
        [7u64.to_le_bytes(); 3].concat(),
        // Shared resource and charge-account identifiers.
        [0x7001u64.to_le_bytes(); 2].concat(),
    ];
    for payload in collision_payloads {
        let mut bytes = Vec::from(*b"CSERJR5\0");
        bytes.extend_from_slice(&payload);
        assert!(matches!(
            scan_journal(&bytes),
            Err(JournalDecodeError::UnsupportedVersion { version: 5 })
        ));
    }
}

proptest! {
    #[test]
    fn every_profile1_suffix_is_rejected_without_pairing(payload in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut bytes = Vec::from(*b"CSERJR5\0");
        bytes.extend_from_slice(&payload);
        let rejected = matches!(
            scan_journal(&bytes),
            Err(JournalDecodeError::UnsupportedVersion { version: 5 })
        );
        prop_assert!(rejected);
    }
}

#[derive(Debug, Eq, PartialEq)]
struct DiskFull;

/// Minimal durability provider used to exercise the production-shaped
/// `transact_durable` boundary.  Its successful return represents completion
/// of the provider's durability barrier.
struct TestDurability {
    fail: bool,
    calls: usize,
}

impl TransitionDurability for TestDurability {
    type Error = DiskFull;

    fn persist_transition(
        &mut self,
        _: &cser_core::JournalRecord,
        _: Freshness,
    ) -> Result<(), Self::Error> {
        self.calls += 1;
        if self.fail { Err(DiskFull) } else { Ok(()) }
    }
}

/// Custody must not be released before the terminal quiescence evidence which
/// releases it reaches the durability boundary.
#[test]
fn custody_release_is_not_observable_before_its_evidence_is_durable() {
    let mut harness = Harness::new_profile_two();
    let (effect, origin, claim_id, queue, final_evidence) =
        pending_dma_quiescence_release(&mut harness);
    assert_eq!(
        harness.engine.check_reusable(queue, resource_generation(1)),
        Err(CoreError::ResourceRetained)
    );
    let before_claim = harness
        .engine
        .component_claims(effect, AGENT_COMPONENT_DMA)
        .unwrap();
    let before_reset = harness
        .engine
        .component_retirement_evidence_accepted(
            effect,
            AGENT_COMPONENT_DMA,
            claim_id,
            DEVICE_EVIDENCE_RESET,
        )
        .unwrap();
    let before_irq = harness
        .engine
        .component_retirement_evidence_accepted(
            effect,
            AGENT_COMPONENT_DMA,
            claim_id,
            DEVICE_EVIDENCE_IRQ_DRAINED,
        )
        .unwrap();
    let before_charge = harness.engine.charge(charge(MAIN_ROOT), CREDIT_QUEUE_SLOT);
    let before_projection = harness.engine.projection_digest();
    let before_revision = harness.engine.revision();
    let before_head = harness.engine.head();

    // This is the final IRQ-drain evidence: accepting it would retire the
    // claim, release its charge, and make generation 1 reusable.  A failed
    // durability barrier must leave all of those facts unobservable.
    let mut persistence = TestDurability {
        fail: true,
        calls: 0,
    };
    let error = harness
        .engine
        .transact_durable(final_evidence, &mut persistence)
        .unwrap_err();
    assert_eq!(error, TxError::Persist(DiskFull));
    assert_eq!(persistence.calls, 1);

    // The pending evidence, live claim, retention charge, and resource gate
    // all remain unchanged; no transition receipt (and therefore no permit)
    // escaped the failed durability boundary.
    assert_eq!(
        harness
            .engine
            .component_claims(effect, AGENT_COMPONENT_DMA)
            .unwrap(),
        before_claim
    );
    assert_eq!(
        harness
            .engine
            .component_retirement_evidence_accepted(
                effect,
                AGENT_COMPONENT_DMA,
                claim_id,
                DEVICE_EVIDENCE_RESET,
            )
            .unwrap(),
        before_reset
    );
    assert_eq!(
        harness
            .engine
            .component_retirement_evidence_accepted(
                effect,
                AGENT_COMPONENT_DMA,
                claim_id,
                DEVICE_EVIDENCE_IRQ_DRAINED,
            )
            .unwrap(),
        before_irq
    );
    assert_eq!(
        harness.engine.charge(charge(MAIN_ROOT), CREDIT_QUEUE_SLOT),
        before_charge
    );
    assert_eq!(
        harness.engine.check_reusable(queue, resource_generation(1)),
        Err(CoreError::ResourceRetained)
    );
    assert_eq!(harness.engine.projection_digest(), before_projection);
    assert_eq!(harness.engine.revision(), before_revision);
    assert_eq!(harness.engine.head(), before_head);
    assert!(harness.engine.persistence_recovery_required());
    assert_eq!(
        harness.engine.transact(
            Command::ReserveComponentReuse {
                effect,
                component: AGENT_COMPONENT_DMA,
                actor: origin,
                binding_generation: 1,
                claim: claim(2),
                kind: DEVICE_CLAIM_QUEUE_SLOT,
                scope: ClaimScope::Device(device_scope()),
                resource: queue,
                expected_generation: resource_generation(1),
                units: 1,
                reuse_contract: digest(0x55),
            },
            |_| Ok::<(), DiskFull>(()),
        ),
        Err(TxError::Core(CoreError::PersistenceRecoveryRequired))
    );
}

/// The closure API has the same publication rule as the typed provider API:
/// final quiescence evidence cannot release custody when its persistence
/// callback fails.
#[test]
fn closure_persistence_failure_keeps_final_quiescence_release_unobservable() {
    let mut harness = Harness::new_profile_two();
    let (effect, _, _, queue, final_evidence) = pending_dma_quiescence_release(&mut harness);
    let before_claims = harness.engine.retained_component_claims();
    let before_charge = harness.engine.charge(charge(MAIN_ROOT), CREDIT_QUEUE_SLOT);
    let before_projection = harness.engine.projection_digest();
    let before_revision = harness.engine.revision();
    let before_head = harness.engine.head();

    assert_eq!(
        harness.engine.transact(final_evidence, |_| Err(DiskFull)),
        Err(TxError::Persist(DiskFull))
    );
    assert_eq!(harness.engine.retained_component_claims(), before_claims);
    assert_eq!(
        harness.engine.charge(charge(MAIN_ROOT), CREDIT_QUEUE_SLOT),
        before_charge
    );
    assert_eq!(harness.engine.projection_digest(), before_projection);
    assert_eq!(harness.engine.revision(), before_revision);
    assert_eq!(harness.engine.head(), before_head);
    assert_eq!(
        harness.engine.check_reusable(queue, resource_generation(1)),
        Err(CoreError::ResourceRetained)
    );
    assert!(harness.engine.persistence_recovery_required());
    assert!(
        !harness
            .engine
            .component_claims(effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .into_iter()
            .find(|claim| claim.resource == queue)
            .unwrap()
            .retired
    );
}

/// Guards the negative test above against passing because the final evidence
/// was invalid: the same final evidence releases the claim after durable
/// success.
#[test]
fn final_quiescence_evidence_releases_custody_after_durable_success() {
    let mut harness = Harness::new_profile_two();
    let (effect, _, claim_id, queue, final_evidence) = pending_dma_quiescence_release(&mut harness);
    let mut persistence = TestDurability {
        fail: false,
        calls: 0,
    };
    let receipt = harness
        .engine
        .transact_durable(final_evidence, &mut persistence)
        .unwrap();
    assert_eq!(persistence.calls, 1);
    assert_eq!(receipt.into_output(), TransitionOutput::None);
    assert!(
        harness
            .engine
            .component_claims(effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .into_iter()
            .find(|claim| claim.claim == claim_id)
            .unwrap()
            .retired
    );
    assert!(
        harness
            .engine
            .component_retirement_evidence_accepted(
                effect,
                AGENT_COMPONENT_DMA,
                claim_id,
                DEVICE_EVIDENCE_IRQ_DRAINED,
            )
            .unwrap()
    );
    assert_eq!(
        harness
            .engine
            .charge(charge(MAIN_ROOT), CREDIT_QUEUE_SLOT)
            .retained_units,
        0
    );
    assert_eq!(
        harness.engine.check_reusable(queue, resource_generation(1)),
        Ok(())
    );
}

/// Credit pressure inside a sealed composite is per component obligation's
/// credit class, not per composite.
///
/// The composite admission gate is a second, independent enforcement site from
/// the simple-estate one, and the paper's custody claims all live on composite
/// effects. This drives the DMA component's queue-slot class to its ceiling and
/// requires that the reply component -- inside the same sealed topology, on the
/// same charge account -- still admits its publication slot.
#[test]
fn a_saturated_component_does_not_backpressure_its_sibling() {
    let limits = CoreLimits::new(8, 8, 16, 16, 8, 3, 8).unwrap();
    let mut harness = Harness::profile_two_with_limits(limits);
    let operation = effect(0xc5b0, 1);
    let origin = principal(0xc5b0, 1);
    let scope = device_scope();

    harness
        .tx(Command::CreateCompositeEffect {
            effect: operation,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(0xc5b0),
        })
        .unwrap();

    // Saturate the DMA component's queue-slot credit class exactly.
    harness
        .tx(Command::AddComponentClaim {
            effect: operation,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: claim(1),
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(scope),
            resource: resource(0xc5b0_0001),
            resource_generation: resource_generation(1),
            units: 3,
        })
        .unwrap();
    assert_eq!(
        harness
            .engine
            .charge(charge(0xc5b0), CREDIT_QUEUE_SLOT)
            .retained_units,
        3
    );

    // Same account, same composite, same actor: a further queue slot is refused.
    let before = harness.engine.projection_digest();
    assert_eq!(
        harness.tx(Command::AddComponentClaim {
            effect: operation,
            component: AGENT_COMPONENT_DMA,
            actor: origin,
            binding_generation: 1,
            claim: claim(2),
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(scope),
            resource: resource(0xc5b0_0002),
            resource_generation: resource_generation(1),
            units: 1,
        }),
        Err(CoreError::Backpressure)
    );
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(
        harness
            .engine
            .charge(charge(0xc5b0), CREDIT_QUEUE_SLOT)
            .retained_units,
        3,
        "a refused component admission must leave its live claim charged",
    );

    // A second composite reaches the same component admission path with the
    // same class and units, but a distinct account. Thus a class-global quota
    // key cannot pass this test merely because the sibling uses another class.
    let unrelated = effect(0xc5b1, 1);
    let unrelated_origin = principal(0xc5b1, 1);
    harness
        .tx(Command::CreateCompositeEffect {
            effect: unrelated,
            origin: unrelated_origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(0xc5b1),
        })
        .unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect: unrelated,
            component: AGENT_COMPONENT_DMA,
            actor: unrelated_origin,
            binding_generation: 1,
            claim: claim(4),
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: ClaimScope::Device(scope),
            resource: resource(0xc5b1_0001),
            resource_generation: resource_generation(1),
            units: 3,
        })
        .expect("a second account must not inherit a component's queue ceiling");
    assert_eq!(
        harness
            .engine
            .charge(charge(0xc5b1), CREDIT_QUEUE_SLOT)
            .retained_units,
        3
    );

    // The sibling component's own credit class is untouched.
    harness
        .tx(Command::AddComponentClaim {
            effect: operation,
            component: AGENT_COMPONENT_REPLY,
            actor: origin,
            binding_generation: 1,
            claim: claim(3),
            kind: REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(0xc5b0_0003),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .expect("a saturated sibling must not freeze the reply component");
    assert_eq!(
        harness
            .engine
            .charge(charge(0xc5b0), CREDIT_REPLY_SLOT)
            .retained_units,
        1
    );

    // Paired headroom control for the rejected second queue claim. This keeps
    // the effect, account, component, class, and claim shape fixed while only
    // increasing the unit ceiling.
    let mut headroom =
        Harness::profile_two_with_limits(CoreLimits::new(8, 8, 16, 16, 8, 4, 8).unwrap());
    let operation = effect(0xc5b2, 1);
    let origin = principal(0xc5b2, 1);
    headroom
        .tx(Command::CreateCompositeEffect {
            effect: operation,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(0xc5b2),
        })
        .unwrap();
    for (claim_value, resource_value, units) in [(1, 0xc5b2_0001, 3), (2, 0xc5b2_0002, 1)] {
        headroom
            .tx(Command::AddComponentClaim {
                effect: operation,
                component: AGENT_COMPONENT_DMA,
                actor: origin,
                binding_generation: 1,
                claim: claim(claim_value),
                kind: DEVICE_CLAIM_QUEUE_SLOT,
                scope: ClaimScope::Device(scope),
                resource: resource(resource_value),
                resource_generation: resource_generation(1),
                units,
            })
            .expect("raising only the unit ceiling must admit the same queue shape");
    }
    assert_eq!(
        headroom
            .engine
            .charge(charge(0xc5b2), CREDIT_QUEUE_SLOT)
            .retained_units,
        4
    );
}
