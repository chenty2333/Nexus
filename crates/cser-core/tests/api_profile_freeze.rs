// SPDX-License-Identifier: MPL-2.0

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, AdoptionPolicy,
    CREDIT_REPLY_SLOT, CSER_CORE_API_PROFILE_VERSION, ClaimCardinality, ClaimScopePolicy,
    ConflictMode, DEVICE_CLAIM_IOVA, DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT,
    DEVICE_DOMAIN, DEVICE_EVIDENCE_IOTLB, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER,
    DMA_ARENA_REUSE_COMPOSITE, DeviceGenerationEffect, DomainCatalogBuilder, DomainCatalogError,
    EvidenceCapability, EvidenceRecovery, EvidenceRule, FreshnessAxes, JOURNAL_CHECKPOINT_MAGIC,
    JOURNAL_CHECKPOINT_VERSION, JOURNAL_CORE_API_PROFILE, JOURNAL_MAGIC, JOURNAL_SCHEMA_VERSION,
    NORMALIZED_TRACE_VERSION, ObligationPolicy, ObligationReceipts, ObligationSpec,
    PROJECTION_VERSION, RECOVERY_SNAPSHOT_VERSION, REPLY_APPLY_RECEIPT_SCHEMA,
    REPLY_CLAIM_PUBLICATION_SLOT, REPLY_COMMIT_RECEIPT_SCHEMA, REPLY_DOMAIN,
    REPLY_EVIDENCE_PUBLICATION_ACK, REPLY_OBLIGATION_PUBLICATION, REPLY_RECEIPT_SCHEMA,
    REPLY_SETTLEMENT_RECEIPT_SCHEMA, REPLY_VERIFIER, ReceiptBinding, STANDARD_CATALOG_VERSION,
    standard_catalog,
};

#[test]
fn semantic_api_current_profile_freezes_journal_and_domain_catalog() {
    assert_eq!(CSER_CORE_API_PROFILE_VERSION, 8);
    assert_eq!(JOURNAL_MAGIC, *b"CSERJ12\0");
    assert_eq!(JOURNAL_SCHEMA_VERSION, 12);
    assert_eq!(JOURNAL_CORE_API_PROFILE, 8);
    assert_eq!(STANDARD_CATALOG_VERSION, 8);
    assert_eq!(PROJECTION_VERSION, 12);
    assert_eq!(RECOVERY_SNAPSHOT_VERSION, 8);
    assert_eq!(NORMALIZED_TRACE_VERSION, 5);
    assert_eq!(JOURNAL_CHECKPOINT_MAGIC, *b"CSERCP5\0");
    assert_eq!(JOURNAL_CHECKPOINT_VERSION, 5);
    let catalog = standard_catalog();
    let agent_operation = catalog
        .composite_rule(AGENT_OPERATION_COMPOSITE)
        .expect("the standard agent operation must remain catalog-bound");
    assert_eq!(agent_operation.components().len(), 2);
    assert_eq!(
        agent_operation.components()[0].component(),
        AGENT_COMPONENT_REPLY
    );
    assert_eq!(
        agent_operation.components()[1].component(),
        AGENT_COMPONENT_DMA
    );
    let arena_reuse = catalog
        .composite_rule(DMA_ARENA_REUSE_COMPOSITE)
        .expect("the DMA arena reuse operation must remain catalog-bound");
    assert_eq!(arena_reuse.components().len(), 1);
    assert_eq!(arena_reuse.components()[0].component(), AGENT_COMPONENT_DMA);
    assert_eq!(
        catalog.digest().bytes(),
        [
            0x07, 0x82, 0xc4, 0x85, 0x8f, 0x2a, 0x99, 0x78, 0x76, 0xa4, 0xbe, 0xe9, 0xba, 0x30,
            0xeb, 0xf0, 0xca, 0xdf, 0x65, 0xd9, 0x9d, 0x93, 0xdc, 0xc0, 0xdc, 0x77, 0xc6, 0xa1,
            0x58, 0x1c, 0xa8, 0xee,
        ]
    );
}

/// Every standard claim class must declare exclusive conflict, because each one
/// names a coordinate a single custodian may hold: a reply publication slot, one
/// queue slot, one pinned page, one IOVA mapping. Shared custody exists in the
/// admission algebra for domains that need it, but silence in the standard
/// profile must continue to mean exclusion.
#[test]
fn semantic_api_current_profile_freezes_exclusive_conflict_for_every_standard_class() {
    let catalog = standard_catalog();
    for (domain, kind) in [
        (REPLY_DOMAIN, REPLY_CLAIM_PUBLICATION_SLOT),
        (DEVICE_DOMAIN, DEVICE_CLAIM_QUEUE_SLOT),
        (DEVICE_DOMAIN, DEVICE_CLAIM_PINNED_PAGE),
        (DEVICE_DOMAIN, DEVICE_CLAIM_IOVA),
    ] {
        assert_eq!(
            catalog
                .claim_rule(domain, kind)
                .expect("every standard claim class must remain catalog-bound")
                .conflict(),
            ConflictMode::Exclusive,
        );
    }
}

/// The evidence capability classification is part of the frozen catalog contract,
/// not an internal detail. The current API profile must keep its logical
/// outcome and every device claim's quiescence path separate, because an
/// escaped effect can reach physical quiescence while its externally visible
/// outcome is unresolved.
#[test]
fn semantic_api_current_profile_freezes_evidence_capability_classification() {
    let catalog = standard_catalog();

    let reply = catalog
        .claim_rule(REPLY_DOMAIN, REPLY_CLAIM_PUBLICATION_SLOT)
        .expect("the reply publication slot must remain catalog-bound");
    assert!(!reply.evidence().is_empty());
    for rule in reply.evidence() {
        assert_eq!(
            rule.capability(),
            EvidenceCapability::Outcome,
            "reply publication evidence resolves the visible outcome"
        );
        assert_eq!(
            rule.recovery(),
            EvidenceRecovery::Recoverable,
            "a publication acknowledgement is queryable by durable effect identity"
        );
    }

    for kind in [
        DEVICE_CLAIM_QUEUE_SLOT,
        DEVICE_CLAIM_PINNED_PAGE,
        DEVICE_CLAIM_IOVA,
    ] {
        let claim = catalog
            .claim_rule(DEVICE_DOMAIN, kind)
            .expect("every device claim must remain catalog-bound");
        assert!(
            !claim.evidence().is_empty(),
            "a physical claim must declare retirement evidence"
        );
        for rule in claim.evidence() {
            assert_eq!(
                rule.capability(),
                EvidenceCapability::Quiescence,
                "device retirement evidence proves the device stopped touching the resource"
            );
            assert_eq!(
                rule.recovery(),
                EvidenceRecovery::Recoverable,
                "a successor executor must be able to re-observe device quiescence"
            );
        }
    }
}

fn logical_freshness() -> FreshnessAxes {
    FreshnessAxes::BOOT
        .union(FreshnessAxes::REGISTRY)
        .union(FreshnessAxes::JOURNAL)
}

fn device_freshness() -> FreshnessAxes {
    logical_freshness().union(FreshnessAxes::DEVICE)
}

fn recoverable_quiescence() -> EvidenceRule {
    EvidenceRule::retirement(
        DEVICE_EVIDENCE_IOTLB,
        ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
        device_freshness(),
        device_freshness(),
        FreshnessAxes::DEVICE,
        DeviceGenerationEffect::AdvanceOne,
        None,
    )
}

#[test]
fn device_claim_rejects_outcome_only_evidence() {
    let result = DomainCatalogBuilder::new()
        .credit_class(CREDIT_REPLY_SLOT, 1)
        .unwrap()
        .claim(
            REPLY_DOMAIN,
            REPLY_CLAIM_PUBLICATION_SLOT,
            CREDIT_REPLY_SLOT,
            ClaimScopePolicy::Device,
            &[EvidenceRule::logical(
                REPLY_EVIDENCE_PUBLICATION_ACK,
                ReceiptBinding::new(REPLY_VERIFIER, REPLY_RECEIPT_SCHEMA),
                logical_freshness(),
            )],
        );

    assert!(matches!(
        result,
        Err(DomainCatalogError::MissingQuiescenceEvidence)
    ));
}

#[test]
fn claim_rejects_ephemeral_quiescence_evidence() {
    let result = DomainCatalogBuilder::new()
        .credit_class(CREDIT_REPLY_SLOT, 1)
        .unwrap()
        .claim(
            DEVICE_DOMAIN,
            DEVICE_CLAIM_PINNED_PAGE,
            CREDIT_REPLY_SLOT,
            ClaimScopePolicy::Device,
            &[recoverable_quiescence().ephemeral()],
        );

    assert!(matches!(
        result,
        Err(DomainCatalogError::UnrecoverableRetirementEvidence)
    ));
}

#[test]
fn logical_claim_rejects_ephemeral_outcome_evidence() {
    let result = DomainCatalogBuilder::new()
        .credit_class(CREDIT_REPLY_SLOT, 1)
        .unwrap()
        .claim(
            REPLY_DOMAIN,
            REPLY_CLAIM_PUBLICATION_SLOT,
            CREDIT_REPLY_SLOT,
            ClaimScopePolicy::Logical,
            &[EvidenceRule::logical(
                REPLY_EVIDENCE_PUBLICATION_ACK,
                ReceiptBinding::new(REPLY_VERIFIER, REPLY_RECEIPT_SCHEMA),
                logical_freshness(),
            )
            .ephemeral()],
        );

    assert!(matches!(
        result,
        Err(DomainCatalogError::UnrecoverableRetirementEvidence)
    ));
}

#[test]
fn retirement_only_obligation_rejects_outcome_only_logical_claim() {
    let result = DomainCatalogBuilder::new()
        .credit_class(CREDIT_REPLY_SLOT, 1)
        .unwrap()
        .obligation(
            ObligationSpec::new(
                REPLY_DOMAIN,
                REPLY_OBLIGATION_PUBLICATION,
                ObligationPolicy::RetirementEvidence,
                AdoptionPolicy::UncommittedOnly,
                ObligationReceipts::retirement_only(ReceiptBinding::new(
                    REPLY_VERIFIER,
                    REPLY_COMMIT_RECEIPT_SCHEMA,
                )),
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
                logical_freshness(),
            )],
        )
        .unwrap()
        .build();

    assert!(matches!(
        result,
        Err(DomainCatalogError::InvalidRetirementEvidenceClaim)
    ));
}

#[test]
fn retirement_only_obligation_checks_optional_claim_classes() {
    let result = DomainCatalogBuilder::new()
        .credit_class(CREDIT_REPLY_SLOT, 1)
        .unwrap()
        .obligation(
            ObligationSpec::new(
                REPLY_DOMAIN,
                REPLY_OBLIGATION_PUBLICATION,
                ObligationPolicy::RetirementEvidence,
                AdoptionPolicy::UncommittedOnly,
                ObligationReceipts::retirement_only(ReceiptBinding::new(
                    REPLY_VERIFIER,
                    REPLY_COMMIT_RECEIPT_SCHEMA,
                )),
                1,
            ),
            &[
                ClaimCardinality::new(DEVICE_CLAIM_PINNED_PAGE, 1, 1).unwrap(),
                ClaimCardinality::new(REPLY_CLAIM_PUBLICATION_SLOT, 0, 1).unwrap(),
            ],
        )
        .unwrap()
        .claim(
            REPLY_DOMAIN,
            DEVICE_CLAIM_PINNED_PAGE,
            CREDIT_REPLY_SLOT,
            ClaimScopePolicy::Device,
            &[recoverable_quiescence()],
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
                logical_freshness(),
            )],
        )
        .unwrap()
        .build();

    assert!(matches!(
        result,
        Err(DomainCatalogError::InvalidRetirementEvidenceClaim)
    ));
}

#[test]
fn successor_settlement_rejects_ephemeral_evidence_in_a_device_conjunction() {
    let result = DomainCatalogBuilder::new()
        .credit_class(CREDIT_REPLY_SLOT, 1)
        .unwrap()
        .obligation(
            ObligationSpec::new(
                REPLY_DOMAIN,
                REPLY_OBLIGATION_PUBLICATION,
                ObligationPolicy::SuccessorSettlement,
                AdoptionPolicy::UncommittedOnly,
                ObligationReceipts::successor_settlement(
                    ReceiptBinding::new(REPLY_VERIFIER, REPLY_COMMIT_RECEIPT_SCHEMA),
                    ReceiptBinding::new(REPLY_VERIFIER, REPLY_APPLY_RECEIPT_SCHEMA),
                    ReceiptBinding::new(REPLY_VERIFIER, REPLY_SETTLEMENT_RECEIPT_SCHEMA),
                ),
                1,
            ),
            &[ClaimCardinality::new(DEVICE_CLAIM_PINNED_PAGE, 1, 1).unwrap()],
        )
        .unwrap()
        .claim(
            REPLY_DOMAIN,
            DEVICE_CLAIM_PINNED_PAGE,
            CREDIT_REPLY_SLOT,
            ClaimScopePolicy::Device,
            &[
                recoverable_quiescence(),
                EvidenceRule::logical(
                    REPLY_EVIDENCE_PUBLICATION_ACK,
                    ReceiptBinding::new(REPLY_VERIFIER, REPLY_RECEIPT_SCHEMA),
                    logical_freshness(),
                )
                .ephemeral(),
            ],
        );

    assert!(matches!(
        result,
        Err(DomainCatalogError::UnrecoverableRetirementEvidence)
    ));
}
