//! Admission algebra for catalog-declared component claims.
//!
//! All transitions in this file use the provider-scoped composite grammar.
//! A one-component composite is the smallest valid effect; the old singleton
//! legacy single-effect claim command family is deliberately not exercised here.

use cser_core::{
    AdoptionPolicy, CatalogSet, ClaimCardinality, ClaimKindId, ClaimScope, ClaimScopePolicy,
    CommandRequest, ComponentId, ComponentProviderBinding, CompositeComponentSpec, CompositeKindId,
    ConflictMode, CoreError, CoreLimits, CreditClassId, DeviceGenerationEffect, DeviceScopeId,
    Digest, DomainCatalog, DomainCatalogBuilder, DomainId, EffectId, Engine, EvidenceKindId,
    EvidenceRule, ExecutorCoordinate, ExecutorGeneration, ExecutorId, Freshness, FreshnessAxes,
    JournalGeneration, ObligationKindId, ObligationPolicy, ObligationReceipts, OperationId,
    ProviderCoordinate, ProviderGeneration, ProviderId, ReceiptBinding, ReceiptSchemaId,
    RegistryInstance, ResourceGeneration, ResourceId, VerifierBinding, VerifierGeneration,
    VerifierId, WorldId,
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
const WORLD: WorldId = match WorldId::new(1) {
    Ok(id) => id,
    Err(_) => unreachable!(),
};
const PROVIDER: ProviderId = match ProviderId::new(1) {
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

/// Builds a catalog carrying shared and exclusive classes over one component.
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
        .composite(
            COMPOSITE,
            &[CompositeComponentSpec::new(COMPONENT, DOMAIN, OBLIGATION)],
        )
        .unwrap()
        .build()
        .unwrap()
}

fn freshness() -> Freshness {
    Freshness::new(
        cser_core::BootGeneration::new(1).unwrap(),
        RegistryInstance::new(1).unwrap(),
        cser_core::DeviceGeneration::new(1).unwrap(),
        JournalGeneration::new(1).unwrap(),
    )
}

fn verifier_bindings(catalog: &DomainCatalog) -> Vec<VerifierBinding> {
    catalog
        .verifier_class_bindings()
        .into_iter()
        .enumerate()
        .map(|(index, class)| {
            VerifierBinding::new(
                class.verifier(),
                VerifierGeneration::new(1).unwrap(),
                class.receipt_schema(),
                Digest::new([index as u8 + 1; 32]),
            )
            .unwrap()
        })
        .collect()
}

struct ScopedHarness {
    engine: Engine,
}

fn tx(engine: &mut Engine, request: CommandRequest) -> Result<(), CoreError> {
    engine.transact_volatile(request).map(|_| ())
}

fn effect(value: u64) -> EffectId {
    EffectId::new(OperationId::new(value).unwrap(), 1).unwrap()
}

fn actor(value: u64) -> ExecutorCoordinate {
    ExecutorCoordinate::new(
        ExecutorId::new(value).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    )
}

fn provider() -> ProviderCoordinate {
    ProviderCoordinate::new(WORLD, PROVIDER, ProviderGeneration::new(1).unwrap())
}

fn two_mode_harness() -> ScopedHarness {
    let catalog = two_mode_catalog();
    let catalog_set = CatalogSet::new(std::slice::from_ref(&catalog)).unwrap();
    let mut engine = Engine::new(
        WORLD,
        catalog_set,
        CoreLimits::bounded_default(),
        freshness(),
    );
    tx(
        &mut engine,
        CommandRequest::RegisterProviderGeneration {
            coordinate: provider(),
            catalog_digest: catalog.digest(),
            verifier_bindings: verifier_bindings(&catalog),
        },
    )
    .unwrap();
    ScopedHarness { engine }
}

fn admit(harness: &mut ScopedHarness, value: u64) -> EffectId {
    let effect = effect(value);
    let origin = actor(value);
    tx(
        &mut harness.engine,
        CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin,
            kind: COMPOSITE,
            charge_account: cser_core::ChargeAccountId::new(value).unwrap(),
            bindings: vec![ComponentProviderBinding::new(COMPONENT, provider())],
        },
    )
    .unwrap();
    effect
}

fn add_claim(
    harness: &mut ScopedHarness,
    effect: EffectId,
    kind: ClaimKindId,
    id: u64,
    resource_id: u64,
) -> Result<(), CoreError> {
    tx(
        &mut harness.engine,
        CommandRequest::AddComponentClaim {
            effect,
            component: COMPONENT,
            actor: actor(effect.operation().get()),
            claim: cser_core::ClaimId::new(id).unwrap(),
            kind,
            scope: ClaimScope::Device(DEVICE_SCOPE),
            resource: ResourceId::new(resource_id).unwrap(),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
        },
    )
}

#[test]
fn catalog_records_declared_conflict_mode() {
    let catalog = two_mode_catalog();
    assert_eq!(
        catalog.claim_rule(DOMAIN, SHARED_KIND).unwrap().conflict(),
        ConflictMode::Shared
    );
    assert_eq!(
        catalog
            .claim_rule(DOMAIN, EXCLUSIVE_KIND)
            .unwrap()
            .conflict(),
        ConflictMode::Exclusive
    );
}

#[test]
fn omitted_conflict_mode_is_exclusive() {
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
        ConflictMode::Exclusive
    );
}

#[test]
fn conflict_mode_participates_in_catalog_digest() {
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
        .composite(
            COMPOSITE,
            &[CompositeComponentSpec::new(COMPONENT, DOMAIN, OBLIGATION)],
        )
        .unwrap()
        .build()
        .unwrap();
    assert_ne!(shared.digest(), exclusive.digest());
}

#[test]
fn a_shared_class_admits_a_second_component_custodian() {
    let mut harness = two_mode_harness();
    let first = admit(&mut harness, 1);
    let second = admit(&mut harness, 2);
    add_claim(&mut harness, first, SHARED_KIND, 1, 500).unwrap();
    add_claim(&mut harness, second, SHARED_KIND, 2, 500).unwrap();
}

#[test]
fn an_exclusive_class_refuses_a_second_component_custodian() {
    let mut harness = two_mode_harness();
    let first = admit(&mut harness, 1);
    let second = admit(&mut harness, 2);
    add_claim(&mut harness, first, EXCLUSIVE_KIND, 1, 500).unwrap();
    assert_eq!(
        add_claim(&mut harness, second, EXCLUSIVE_KIND, 2, 500),
        Err(CoreError::ResourceRetained)
    );
}

#[test]
fn conflict_mode_is_symmetric_across_component_effects() {
    let mut harness = two_mode_harness();
    let first = admit(&mut harness, 1);
    let second = admit(&mut harness, 2);
    add_claim(&mut harness, first, EXCLUSIVE_KIND, 1, 500).unwrap();
    assert_eq!(
        add_claim(&mut harness, second, SHARED_KIND, 2, 500),
        Err(CoreError::ResourceRetained)
    );
}

#[test]
fn co_claim_precheck_refuses_an_absent_noninitial_generation() {
    let mut harness = two_mode_harness();
    let effect = admit(&mut harness, 1);
    assert_eq!(
        harness.engine.check_co_claimable(
            effect,
            DOMAIN,
            SHARED_KIND,
            ClaimScope::Device(DEVICE_SCOPE),
            ResourceId::new(501).unwrap(),
            ResourceGeneration::new(2).unwrap(),
        ),
        Err(CoreError::StaleResourceGeneration)
    );
}

#[test]
fn shared_generation_advancement_is_rejected_by_catalog_validation() {
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
            &[device_retirement_evidence(
                DeviceGenerationEffect::AdvanceOne,
            )],
        );
    assert_eq!(
        result.err(),
        Some(cser_core::DomainCatalogError::SharedClaimAdvancesGeneration)
    );
}
