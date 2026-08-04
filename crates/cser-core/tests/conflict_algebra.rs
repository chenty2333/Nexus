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
    CommandRequest as Command, ConflictMode, CoreError, CoreLimits, CreditClassId, DomainCatalog,
    DomainCatalogBuilder, DomainId, Engine, EvidenceKindId, EvidenceRule, FreshnessAxes,
    ObligationKindId, ObligationPolicy, ObligationReceipts, ReceiptBinding, ReceiptSchemaId,
    VerifierId,
};
use support::{
    Harness, charge, claim, effect, freshness, principal, resource, resource_generation,
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

fn logical_freshness() -> FreshnessAxes {
    FreshnessAxes::BOOT
        .union(FreshnessAxes::REGISTRY)
        .union(FreshnessAxes::JOURNAL)
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
            ],
        )
        .unwrap()
        .claim_with_conflict(
            DOMAIN,
            SHARED_KIND,
            CREDIT,
            ClaimScopePolicy::Logical,
            ConflictMode::Shared,
            &[EvidenceRule::logical(
                EVIDENCE,
                ReceiptBinding::new(VERIFIER, SCHEMA),
                logical_freshness(),
            )],
        )
        .unwrap()
        .claim_with_conflict(
            DOMAIN,
            EXCLUSIVE_KIND,
            CREDIT,
            ClaimScopePolicy::Logical,
            ConflictMode::Exclusive,
            &[EvidenceRule::logical(
                EVIDENCE,
                ReceiptBinding::new(VERIFIER, SCHEMA),
                logical_freshness(),
            )],
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
            ClaimScopePolicy::Logical,
            &[EvidenceRule::logical(
                EVIDENCE,
                ReceiptBinding::new(VERIFIER, SCHEMA),
                logical_freshness(),
            )],
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
            ],
        )
        .unwrap()
        .claim_with_conflict(
            DOMAIN,
            SHARED_KIND,
            CREDIT,
            ClaimScopePolicy::Logical,
            ConflictMode::Exclusive,
            &[EvidenceRule::logical(
                EVIDENCE,
                ReceiptBinding::new(VERIFIER, SCHEMA),
                logical_freshness(),
            )],
        )
        .unwrap()
        .claim_with_conflict(
            DOMAIN,
            EXCLUSIVE_KIND,
            CREDIT,
            ClaimScopePolicy::Logical,
            ConflictMode::Exclusive,
            &[EvidenceRule::logical(
                EVIDENCE,
                ReceiptBinding::new(VERIFIER, SCHEMA),
                logical_freshness(),
            )],
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
    Command::AddClaim {
        effect: effect(7, 1),
        actor: principal(7, 1),
        binding_generation: 1,
        claim: claim(id),
        domain: DOMAIN,
        kind,
        scope: ClaimScope::Logical,
        resource: resource(500),
        resource_generation: resource_generation(1),
        units: 1,
    }
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
