//! Admission algebra over claim conflict modes.
//!
//! The paper claims a claim names its conflict mode and that admission is a
//! decision of that algebra rather than an unconditional exclusion. These
//! tests pin both halves: that a `Shared` class admits a second custodian at
//! the same coordinate and generation, that an `Exclusive` class refuses one,
//! and that the retirement reference count releases the coordinate only when
//! the last custodian discharges.

mod support;

use cser_core::{
    AdoptionPolicy, ClaimCardinality, ClaimKindId, ClaimScope, ClaimScopePolicy,
    CommandRequest as Command, ComponentId, CompositeComponentSpec, CompositeKindId, ConflictMode,
    CoreError, CoreLimits, CreditClassId, DeviceGeneration, DeviceGenerationEffect, DeviceScopeId,
    DomainCatalog, DomainCatalogBuilder, DomainId, Engine, EvidenceKindId, EvidenceRule,
    ExternalOutcome, Freshness, FreshnessAxes, ObligationKindId, ObligationPolicy,
    ObligationReceipts, ReceiptBinding, ReceiptSchemaId, TransitionOutput, VerifierId,
};
use support::{
    ExactTestVerifier, Harness, TestReceipt, charge, claim, current_evidence_command, digest,
    effect, freshness, principal, resource, resource_generation, verified_commit_outcome,
    verified_evidence_command,
};

const DOMAIN: DomainId = match DomainId::new(9) {
    Ok(id) => id,
    Err(_) => unreachable!(),
};
const OBLIGATION: ObligationKindId = match ObligationKindId::new(1) {
    Ok(id) => id,
    Err(_) => unreachable!(),
};
const SHARED_KIND: ClaimKindId = match ClaimKindId::new(1) {
    Ok(id) => id,
    Err(_) => unreachable!(),
};
const EXCLUSIVE_KIND: ClaimKindId = match ClaimKindId::new(2) {
    Ok(id) => id,
    Err(_) => unreachable!(),
};
const ADVANCE_KIND: ClaimKindId = match ClaimKindId::new(3) {
    Ok(id) => id,
    Err(_) => unreachable!(),
};
const CREDIT: CreditClassId = match CreditClassId::new(1) {
    Ok(id) => id,
    Err(_) => unreachable!(),
};
const EVIDENCE: EvidenceKindId = match EvidenceKindId::new(1) {
    Ok(id) => id,
    Err(_) => unreachable!(),
};
const VERIFIER: VerifierId = match VerifierId::new(1) {
    Ok(id) => id,
    Err(_) => unreachable!(),
};
const SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(1) {
    Ok(id) => id,
    Err(_) => unreachable!(),
};
const COMPONENT: ComponentId = match ComponentId::new(1) {
    Ok(id) => id,
    Err(_) => unreachable!(),
};
const COMPOSITE: CompositeKindId = match CompositeKindId::new(1) {
    Ok(id) => id,
    Err(_) => unreachable!(),
};
const DEVICE_SCOPE: DeviceScopeId = match DeviceScopeId::new(1) {
    Ok(id) => id,
    Err(_) => unreachable!(),
};

fn logical_freshness() -> FreshnessAxes {
    FreshnessAxes::BOOT
        .union(FreshnessAxes::REGISTRY)
        .union(FreshnessAxes::JOURNAL)
}

fn device_retirement_evidence(effect: DeviceGenerationEffect) -> EvidenceRule {
    EvidenceRule::retirement(
        EVIDENCE,
        ReceiptBinding::new(VERIFIER, SCHEMA),
        FreshnessAxes::DEVICE,
        logical_freshness().union(FreshnessAxes::DEVICE),
        FreshnessAxes::DEVICE,
        effect,
        None,
    )
}

/// Builds a catalog carrying one shared and one exclusive claim class over the
/// same domain, so admission differences are attributable to conflict mode
/// alone.
fn two_mode_catalog() -> DomainCatalog {
    DomainCatalogBuilder::new()
        .credit_class(CREDIT, 64)
        .unwrap()
        .obligation(
            cser_core::ObligationSpec::new(
                DOMAIN,
                OBLIGATION,
                ObligationPolicy::RetirementEvidence,
                AdoptionPolicy::Forbidden,
                ObligationReceipts::retirement_only(ReceiptBinding::new(VERIFIER, SCHEMA)),
                1,
            ),
            &[
                ClaimCardinality::new(SHARED_KIND, 0, 8).unwrap(),
                ClaimCardinality::new(EXCLUSIVE_KIND, 0, 8).unwrap(),
                ClaimCardinality::new(ADVANCE_KIND, 0, 8).unwrap(),
            ],
        )
        .unwrap()
        .claim_with_conflict(
            DOMAIN,
            ADVANCE_KIND,
            CREDIT,
            ClaimScopePolicy::Device,
            ConflictMode::Exclusive,
            &[device_retirement_evidence(
                DeviceGenerationEffect::AdvanceOne,
            )],
        )
        .unwrap()
        .claim_with_conflict(
            DOMAIN,
            SHARED_KIND,
            CREDIT,
            ClaimScopePolicy::Device,
            ConflictMode::Shared,
            &[device_retirement_evidence(DeviceGenerationEffect::None)],
        )
        .unwrap()
        .claim_with_conflict(
            DOMAIN,
            EXCLUSIVE_KIND,
            CREDIT,
            ClaimScopePolicy::Device,
            ConflictMode::Exclusive,
            &[device_retirement_evidence(DeviceGenerationEffect::None)],
        )
        .unwrap()
        .composite(
            COMPOSITE,
            &[CompositeComponentSpec::new(COMPONENT, DOMAIN, OBLIGATION)],
        )
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn catalog_records_declared_conflict_mode() {
    let catalog = two_mode_catalog();
    assert_eq!(
        catalog.claim_rule(DOMAIN, SHARED_KIND).unwrap().conflict(),
        ConflictMode::Shared,
    );
    assert_eq!(
        catalog
            .claim_rule(DOMAIN, EXCLUSIVE_KIND)
            .unwrap()
            .conflict(),
        ConflictMode::Exclusive,
    );
}

#[test]
fn exclusive_is_the_default_for_the_compatibility_constructor() {
    let catalog = DomainCatalogBuilder::new()
        .credit_class(CREDIT, 64)
        .unwrap()
        .obligation(
            cser_core::ObligationSpec::new(
                DOMAIN,
                OBLIGATION,
                ObligationPolicy::RetirementEvidence,
                AdoptionPolicy::Forbidden,
                ObligationReceipts::retirement_only(ReceiptBinding::new(VERIFIER, SCHEMA)),
                1,
            ),
            &[ClaimCardinality::new(SHARED_KIND, 0, 8).unwrap()],
        )
        .unwrap()
        .claim(
            DOMAIN,
            SHARED_KIND,
            CREDIT,
            ClaimScopePolicy::Device,
            &[device_retirement_evidence(DeviceGenerationEffect::None)],
        )
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        catalog.claim_rule(DOMAIN, SHARED_KIND).unwrap().conflict(),
        ConflictMode::Exclusive,
        "silence must mean exclusion, so pre-existing profiles keep their gate",
    );
}

#[test]
fn conflict_mode_participates_in_the_catalog_digest() {
    let shared = two_mode_catalog();
    let exclusive = DomainCatalogBuilder::new()
        .credit_class(CREDIT, 64)
        .unwrap()
        .obligation(
            cser_core::ObligationSpec::new(
                DOMAIN,
                OBLIGATION,
                ObligationPolicy::RetirementEvidence,
                AdoptionPolicy::Forbidden,
                ObligationReceipts::retirement_only(ReceiptBinding::new(VERIFIER, SCHEMA)),
                1,
            ),
            &[
                ClaimCardinality::new(SHARED_KIND, 0, 8).unwrap(),
                ClaimCardinality::new(EXCLUSIVE_KIND, 0, 8).unwrap(),
                ClaimCardinality::new(ADVANCE_KIND, 0, 8).unwrap(),
            ],
        )
        .unwrap()
        .claim_with_conflict(
            DOMAIN,
            ADVANCE_KIND,
            CREDIT,
            ClaimScopePolicy::Device,
            ConflictMode::Exclusive,
            &[device_retirement_evidence(
                DeviceGenerationEffect::AdvanceOne,
            )],
        )
        .unwrap()
        .claim_with_conflict(
            DOMAIN,
            SHARED_KIND,
            CREDIT,
            ClaimScopePolicy::Device,
            ConflictMode::Exclusive,
            &[device_retirement_evidence(DeviceGenerationEffect::None)],
        )
        .unwrap()
        .claim_with_conflict(
            DOMAIN,
            EXCLUSIVE_KIND,
            CREDIT,
            ClaimScopePolicy::Device,
            ConflictMode::Exclusive,
            &[device_retirement_evidence(DeviceGenerationEffect::None)],
        )
        .unwrap()
        .composite(
            COMPOSITE,
            &[CompositeComponentSpec::new(COMPONENT, DOMAIN, OBLIGATION)],
        )
        .unwrap()
        .build()
        .unwrap();
    assert_ne!(
        shared.digest(),
        exclusive.digest(),
        "a change of admission algebra must change the frozen catalog identity",
    );
}

/// Builds a harness over the two-mode catalog with one estate already open, so
/// each admission test differs only in the claim class it enrolls.
fn two_mode_harness() -> Harness {
    let mut harness = Harness {
        engine: Engine::new_legacy_compatibility(
            two_mode_catalog(),
            CoreLimits::bounded_default(),
            freshness(1, 1, 1, 1, 1),
        ),
        journal: Vec::new(),
    };
    harness
        .tx(Command::CreateEstate {
            effect: effect(7, 1),
            origin: principal(7, 1),
            binding_generation: 1,
            domain: DOMAIN,
            obligation: OBLIGATION,
            charge_account: charge(7),
        })
        .unwrap();
    harness
}

/// One enrollment at the shared resource coordinate, varying only the class and
/// the claim identity.
fn add_claim(kind: ClaimKindId, id: u64) -> Command {
    add_claim_at(kind, id, 500)
}

fn add_claim_at(kind: ClaimKindId, id: u64, resource_id: u64) -> Command {
    Command::AddClaim {
        effect: effect(7, 1),
        actor: principal(7, 1),
        binding_generation: 1,
        claim: claim(id),
        domain: DOMAIN,
        kind,
        scope: ClaimScope::Device(DEVICE_SCOPE),
        resource: resource(resource_id),
        resource_generation: resource_generation(1),
        units: 1,
    }
}

fn add_component_claim(effect_id: u64, kind: ClaimKindId, id: u64) -> Command {
    Command::AddComponentClaim {
        effect: effect(7, effect_id),
        component: COMPONENT,
        actor: principal(7, 1),
        binding_generation: 1,
        claim: claim(id),
        kind,
        scope: ClaimScope::Device(DEVICE_SCOPE),
        resource: resource(500),
        resource_generation: resource_generation(1),
        units: 1,
    }
}

fn create_composite(harness: &mut Harness, effect_id: u64, account: u64) {
    harness
        .tx(Command::CreateCompositeEffect {
            effect: effect(7, effect_id),
            origin: principal(7, 1),
            binding_generation: 1,
            kind: COMPOSITE,
            charge_account: charge(account),
        })
        .unwrap();
}

fn commit_estate(harness: &mut Harness, effect_id: u64, marker: u8) {
    let actor = principal(7, 1);
    let effect = effect(7, effect_id);
    harness
        .tx(Command::PrepareEffect {
            effect,
            actor,
            binding_generation: 1,
        })
        .unwrap();
    let intent = match harness.output(Command::RecordCommitIntent {
        effect,
        actor,
        binding_generation: 1,
        operation: digest(marker),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected estate commit intent, got {other:?}"),
    };
    let outcome = verified_commit_outcome(
        harness,
        &intent,
        VERIFIER,
        SCHEMA,
        ExternalOutcome::Success,
        digest(marker + 1),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
}

fn commit_component(harness: &mut Harness, effect_id: u64, marker: u8) {
    let actor = principal(7, 1);
    let effect = effect(7, effect_id);
    harness
        .tx(Command::PrepareCompositeEffect {
            effect,
            actor,
            binding_generation: 1,
        })
        .unwrap();
    let intent = match harness.output(Command::RecordComponentCommitIntent {
        effect,
        component: COMPONENT,
        actor,
        binding_generation: 1,
        operation: digest(marker),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected component commit intent, got {other:?}"),
    };
    let outcome = verified_commit_outcome(
        harness,
        &intent,
        VERIFIER,
        SCHEMA,
        ExternalOutcome::Success,
        digest(marker + 1),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
}

fn current_component_evidence_command(
    harness: &Harness,
    effect_id: u64,
    claim_id: u64,
    receipt_marker: u8,
) -> cser_core::Command {
    let effect = effect(7, effect_id);
    let claim = claim(claim_id);
    let challenge = harness
        .engine
        .component_evidence_challenge(effect, COMPONENT, claim, EVIDENCE)
        .unwrap();
    let receipt = TestReceipt {
        effect,
        claim,
        kind: EVIDENCE,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject: challenge.subject(),
        observation: challenge.current_observation(),
        digest: digest(receipt_marker),
    };
    harness
        .engine
        .verify_component_retirement_evidence(
            effect,
            COMPONENT,
            claim,
            EVIDENCE,
            &ExactTestVerifier::new(VERIFIER, SCHEMA),
            &receipt,
        )
        .unwrap()
        .submit()
}

#[test]
fn a_shared_class_admits_a_second_custodian_at_one_coordinate() {
    let mut harness = two_mode_harness();
    harness.tx(add_claim(SHARED_KIND, 1)).unwrap();
    harness
        .tx(add_claim(SHARED_KIND, 2))
        .expect("a shared class must admit a co-custodian at the same generation");
}

#[test]
fn an_exclusive_class_still_refuses_a_second_custodian() {
    let mut harness = two_mode_harness();
    harness.tx(add_claim(EXCLUSIVE_KIND, 1)).unwrap();
    assert_eq!(
        harness.tx(add_claim(EXCLUSIVE_KIND, 2)),
        Err(CoreError::ResourceRetained),
        "exclusion must remain the decision for a class that declares it",
    );
}

#[test]
fn conflict_mode_is_read_per_class_not_per_resource() {
    let mut harness = two_mode_harness();
    harness.tx(add_claim(SHARED_KIND, 1)).unwrap();
    assert_eq!(
        harness.tx(add_claim(EXCLUSIVE_KIND, 2)),
        Err(CoreError::ResourceRetained),
        "an exclusive newcomer must be refused even where the incumbent shares",
    );
}

#[test]
fn a_shared_newcomer_cannot_join_an_exclusive_incumbent() {
    let mut harness = two_mode_harness();
    harness.tx(add_claim(EXCLUSIVE_KIND, 1)).unwrap();
    assert_eq!(
        harness.tx(add_claim(SHARED_KIND, 2)),
        Err(CoreError::ResourceRetained),
        "compatibility must be symmetric rather than depend on enrollment order",
    );
}

#[test]
fn compatibility_checks_estate_and_composite_custodians_together() {
    let mut harness = two_mode_harness();
    harness.tx(add_claim(EXCLUSIVE_KIND, 1)).unwrap();
    create_composite(&mut harness, 2, 8);
    assert_eq!(
        harness.tx(add_component_claim(2, SHARED_KIND, 2)),
        Err(CoreError::ResourceRetained),
        "a composite newcomer must not bypass an estate incumbent through a separate index",
    );
}

#[test]
fn composite_exclusive_incumbent_rejects_estate_shared_newcomer_and_precheck() {
    let mut harness = two_mode_harness();
    create_composite(&mut harness, 2, 8);
    harness
        .tx(add_component_claim(2, EXCLUSIVE_KIND, 2))
        .unwrap();
    assert_eq!(
        harness.engine.check_co_claimable(
            DOMAIN,
            SHARED_KIND,
            ClaimScope::Device(DEVICE_SCOPE),
            resource(500),
            resource_generation(1),
        ),
        Err(CoreError::ResourceRetained),
        "the precheck must consult composite incumbents as well as estate incumbents",
    );
    assert_eq!(
        harness.tx(add_claim(SHARED_KIND, 1)),
        Err(CoreError::ResourceRetained),
        "an estate newcomer must not bypass a composite exclusive incumbent",
    );
}

#[test]
fn shared_custody_spans_estate_and_composite_indexes_across_accounts() {
    let mut harness = two_mode_harness();
    harness.tx(add_claim(SHARED_KIND, 1)).unwrap();
    create_composite(&mut harness, 2, 8);
    harness
        .tx(add_component_claim(2, SHARED_KIND, 2))
        .expect("two shared custodians may co-hold one coordinate across both indexes");
}

#[test]
fn shared_coordinate_retires_only_after_its_last_custodian_then_reuses_at_next_generation() {
    let mut harness = two_mode_harness();
    harness.tx(add_claim(SHARED_KIND, 1)).unwrap();
    harness.tx(add_claim_at(ADVANCE_KIND, 3, 600)).unwrap();
    create_composite(&mut harness, 2, 8);
    harness.tx(add_component_claim(2, SHARED_KIND, 2)).unwrap();
    // Account 7 carries its shared custody plus the independent generation
    // advancer; account 8 separately carries its shared custody. Credits
    // measure live custody obligations, not physical-coordinate occupancy.
    assert_eq!(harness.engine.charge(charge(7), CREDIT).retained_units, 2);
    assert_eq!(harness.engine.charge(charge(8), CREDIT).retained_units, 1);
    commit_estate(&mut harness, 1, 10);
    commit_component(&mut harness, 2, 20);

    let advance_challenge = harness
        .engine
        .evidence_challenge(effect(7, 1), claim(3), EVIDENCE)
        .unwrap();
    let current = advance_challenge.current_observation();
    let advanced_observation = Freshness::new(
        current.boot(),
        current.registry(),
        current.binding(),
        DeviceGeneration::new(current.device().get() + 1).unwrap(),
        current.journal(),
    )
    .unwrap();
    harness
        .tx(verified_evidence_command(
            &harness,
            effect(7, 1),
            claim(3),
            EVIDENCE,
            ReceiptBinding::new(VERIFIER, SCHEMA),
            advanced_observation,
            digest(29),
        ))
        .unwrap();

    harness
        .tx(current_evidence_command(
            &harness,
            effect(7, 1),
            claim(1),
            EVIDENCE,
            ReceiptBinding::new(VERIFIER, SCHEMA),
            digest(30),
        ))
        .unwrap();
    assert_eq!(
        harness
            .engine
            .check_reusable(resource(500), resource_generation(1)),
        Err(CoreError::ResourceRetained),
        "the component custodian must retain the coordinate after the estate retires",
    );

    harness
        .tx(current_component_evidence_command(&harness, 2, 2, 31))
        .unwrap();
    assert_eq!(
        harness
            .engine
            .check_reusable(resource(500), resource_generation(1)),
        Ok(()),
        "the coordinate becomes reusable only after the final shared custodian retires",
    );

    let reuse_effect = effect(7, 3);
    let reuse_actor = principal(7, 1);
    harness
        .tx(Command::CreateEstate {
            effect: reuse_effect,
            origin: reuse_actor,
            binding_generation: 1,
            domain: DOMAIN,
            obligation: OBLIGATION,
            charge_account: charge(9),
        })
        .unwrap();
    let permit = match harness.output(Command::ReserveReuse {
        effect: reuse_effect,
        actor: reuse_actor,
        binding_generation: 1,
        claim: claim(4),
        domain: DOMAIN,
        kind: SHARED_KIND,
        scope: ClaimScope::Device(DEVICE_SCOPE),
        resource: resource(500),
        expected_generation: resource_generation(1),
        units: 1,
        reuse_contract: digest(32),
    }) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected reuse permit, got {other:?}"),
    };
    assert_eq!(permit.previous_generation(), resource_generation(1));
    assert_eq!(permit.generation(), resource_generation(2));
    harness.tx(permit.activate()).unwrap();

    let reused = harness.engine.claims(reuse_effect).unwrap();
    assert_eq!(reused.len(), 1);
    assert_eq!(reused[0].resource, resource(500));
    assert_eq!(reused[0].resource_generation, resource_generation(2));
    assert!(!reused[0].retired);
    assert_eq!(harness.engine.charge(charge(9), CREDIT).retained_units, 1);
    assert_eq!(
        harness
            .engine
            .check_reusable(resource(500), resource_generation(2)),
        Err(CoreError::ResourceRetained),
        "activation enrolls the next generation before external reuse",
    );
}

#[test]
fn co_claim_precheck_refuses_an_absent_noninitial_generation() {
    let harness = two_mode_harness();
    assert_eq!(
        harness.engine.check_co_claimable(
            DOMAIN,
            SHARED_KIND,
            ClaimScope::Device(DEVICE_SCOPE),
            resource(501),
            resource_generation(2),
        ),
        Err(CoreError::StaleResourceGeneration),
    );
}

#[test]
fn shared_newcomer_cannot_bypass_an_exclusive_generation_advancer() {
    let catalog = DomainCatalogBuilder::new()
        .credit_class(CREDIT, 64)
        .unwrap()
        .obligation(
            cser_core::ObligationSpec::new(
                DOMAIN,
                OBLIGATION,
                ObligationPolicy::RetirementEvidence,
                AdoptionPolicy::Forbidden,
                ObligationReceipts::retirement_only(ReceiptBinding::new(VERIFIER, SCHEMA)),
                1,
            ),
            &[
                ClaimCardinality::new(SHARED_KIND, 0, 8).unwrap(),
                ClaimCardinality::new(EXCLUSIVE_KIND, 0, 8).unwrap(),
            ],
        )
        .unwrap()
        .claim_with_conflict(
            DOMAIN,
            SHARED_KIND,
            CREDIT,
            ClaimScopePolicy::Device,
            ConflictMode::Shared,
            &[EvidenceRule::retirement(
                EVIDENCE,
                ReceiptBinding::new(VERIFIER, SCHEMA),
                FreshnessAxes::DEVICE,
                logical_freshness().union(FreshnessAxes::DEVICE),
                FreshnessAxes::DEVICE,
                DeviceGenerationEffect::None,
                None,
            )],
        )
        .unwrap()
        .claim_with_conflict(
            DOMAIN,
            EXCLUSIVE_KIND,
            CREDIT,
            ClaimScopePolicy::Device,
            ConflictMode::Exclusive,
            &[EvidenceRule::retirement(
                EVIDENCE,
                ReceiptBinding::new(VERIFIER, SCHEMA),
                FreshnessAxes::DEVICE,
                logical_freshness().union(FreshnessAxes::DEVICE),
                FreshnessAxes::DEVICE,
                DeviceGenerationEffect::AdvanceOne,
                None,
            )],
        )
        .unwrap()
        .build()
        .unwrap();
    let mut harness = Harness {
        engine: Engine::new_legacy_compatibility(
            catalog,
            CoreLimits::bounded_default(),
            freshness(1, 1, 1, 1, 1),
        ),
        journal: Vec::new(),
    };
    harness
        .tx(Command::CreateEstate {
            effect: effect(9, 1),
            origin: principal(9, 1),
            binding_generation: 1,
            domain: DOMAIN,
            obligation: OBLIGATION,
            charge_account: charge(9),
        })
        .unwrap();
    let device_claim = |kind, id| Command::AddClaim {
        effect: effect(9, 1),
        actor: principal(9, 1),
        binding_generation: 1,
        claim: claim(id),
        domain: DOMAIN,
        kind,
        scope: ClaimScope::Device(DEVICE_SCOPE),
        resource: resource(700),
        resource_generation: resource_generation(1),
        units: 1,
    };
    harness.tx(device_claim(EXCLUSIVE_KIND, 1)).unwrap();
    assert_eq!(
        harness.tx(device_claim(SHARED_KIND, 2)),
        Err(CoreError::ResourceRetained),
        "a shared claimant must not join an incumbent that may advance the generation",
    );
}

#[test]
fn shared_custody_and_scope_wide_generation_advance_are_mutually_exclusive() {
    let result = DomainCatalogBuilder::new()
        .credit_class(CREDIT, 64)
        .unwrap()
        .obligation(
            cser_core::ObligationSpec::new(
                DOMAIN,
                OBLIGATION,
                ObligationPolicy::RetirementEvidence,
                AdoptionPolicy::Forbidden,
                ObligationReceipts::retirement_only(ReceiptBinding::new(VERIFIER, SCHEMA)),
                1,
            ),
            &[ClaimCardinality::new(SHARED_KIND, 0, 8).unwrap()],
        )
        .unwrap()
        .claim_with_conflict(
            DOMAIN,
            SHARED_KIND,
            CREDIT,
            ClaimScopePolicy::Device,
            ConflictMode::Shared,
            &[EvidenceRule::retirement(
                EVIDENCE,
                ReceiptBinding::new(VERIFIER, SCHEMA),
                FreshnessAxes::DEVICE,
                logical_freshness().union(FreshnessAxes::DEVICE),
                FreshnessAxes::DEVICE,
                cser_core::DeviceGenerationEffect::AdvanceOne,
                None,
            )],
        );
    assert_eq!(
        result.err(),
        Some(cser_core::DomainCatalogError::SharedClaimAdvancesGeneration),
        "one sharer's retirement must not strand every other sharer's snapshot",
    );
}
