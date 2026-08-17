use cser_core::{
    CREDIT_REPLY_SLOT, ClaimScopePolicy, DomainCatalogBuilder, DomainCatalogError, DomainId,
    EvidenceRule, FreshnessAxes, HARNESS_CLAIM_ARTIFACT_CLOSURE, HARNESS_CLAIM_PROVIDER_OPERATION,
    HARNESS_CLAIM_QUEUED_JOB, HARNESS_CLAIM_RECOVERY_WORKER, HARNESS_CLAIM_REMOTE_IDEMPOTENCY_SLOT,
    HARNESS_CLAIM_REPLY_DELIVERY, HARNESS_CLAIM_RETAINED_PROVIDER_GENERATION, HARNESS_DOMAIN,
    HARNESS_OPERATION_COMPOSITE, HARNESS_RECEIPT_SCHEMA, HARNESS_VERIFIER, LogicalClaimRole,
    REPLY_CLAIM_PUBLICATION_SLOT, REPLY_DOMAIN, REPLY_EVIDENCE_PUBLICATION_ACK, ReceiptBinding,
};

fn freshness() -> FreshnessAxes {
    FreshnessAxes::BOOT
        .union(FreshnessAxes::REGISTRY)
        .union(FreshnessAxes::JOURNAL)
}

#[test]
fn harness_catalog_is_complete_and_roles_are_digest_bound() {
    let catalog = cser_core::harness_catalog();
    let expected = [
        (
            HARNESS_CLAIM_REMOTE_IDEMPOTENCY_SLOT,
            LogicalClaimRole::RemoteIdempotencySlot,
        ),
        (
            HARNESS_CLAIM_PROVIDER_OPERATION,
            LogicalClaimRole::ProviderOperation,
        ),
        (
            HARNESS_CLAIM_REPLY_DELIVERY,
            LogicalClaimRole::ReplyDelivery,
        ),
        (HARNESS_CLAIM_QUEUED_JOB, LogicalClaimRole::QueuedJob),
        (
            HARNESS_CLAIM_RECOVERY_WORKER,
            LogicalClaimRole::RecoveryWorker,
        ),
        (
            HARNESS_CLAIM_RETAINED_PROVIDER_GENERATION,
            LogicalClaimRole::RetainedProviderGeneration,
        ),
        (
            HARNESS_CLAIM_ARTIFACT_CLOSURE,
            LogicalClaimRole::ArtifactClosure,
        ),
    ];
    for (kind, role) in expected {
        let claim = catalog
            .claim_rule(HARNESS_DOMAIN, kind)
            .expect("every Harness logical claim must be catalog-bound");
        assert_eq!(claim.scope(), ClaimScopePolicy::Logical);
        assert_eq!(claim.role(), role);
        assert!(
            claim
                .evidence()
                .iter()
                .all(|rule| rule.recovery().survives_crash())
        );
    }
    assert_eq!(catalog.claim_rules().count(), expected.len());
    assert_eq!(
        catalog
            .composite_rule(HARNESS_OPERATION_COMPOSITE)
            .expect("Harness topology must be sealed")
            .components()
            .len(),
        expected.len()
    );

    let generic = DomainCatalogBuilder::new()
        .credit_class(CREDIT_REPLY_SLOT, 1)
        .unwrap()
        .claim(
            REPLY_DOMAIN,
            REPLY_CLAIM_PUBLICATION_SLOT,
            CREDIT_REPLY_SLOT,
            ClaimScopePolicy::Logical,
            &[EvidenceRule::logical(
                REPLY_EVIDENCE_PUBLICATION_ACK,
                ReceiptBinding::new(HARNESS_VERIFIER, HARNESS_RECEIPT_SCHEMA),
                freshness(),
            )],
        )
        .unwrap()
        .build()
        .unwrap();
    let classified = DomainCatalogBuilder::new()
        .credit_class(CREDIT_REPLY_SLOT, 1)
        .unwrap()
        .claim_with_role(
            REPLY_DOMAIN,
            REPLY_CLAIM_PUBLICATION_SLOT,
            CREDIT_REPLY_SLOT,
            ClaimScopePolicy::Logical,
            LogicalClaimRole::ProviderOperation,
            &[EvidenceRule::logical(
                REPLY_EVIDENCE_PUBLICATION_ACK,
                ReceiptBinding::new(HARNESS_VERIFIER, HARNESS_RECEIPT_SCHEMA),
                freshness(),
            )],
        )
        .unwrap()
        .build()
        .unwrap();
    assert_ne!(generic.digest(), classified.digest());
    assert_eq!(
        generic
            .claim_rule(REPLY_DOMAIN, REPLY_CLAIM_PUBLICATION_SLOT)
            .unwrap()
            .role(),
        LogicalClaimRole::Generic
    );
}

#[test]
fn explicit_logical_role_is_rejected_for_device_scope() {
    let result = DomainCatalogBuilder::new()
        .credit_class(CREDIT_REPLY_SLOT, 1)
        .unwrap()
        .claim_with_role(
            DomainId::new(99).unwrap(),
            cser_core::ClaimKindId::new(99).unwrap(),
            CREDIT_REPLY_SLOT,
            ClaimScopePolicy::Device,
            LogicalClaimRole::QueuedJob,
            &[],
        );
    assert!(matches!(
        result,
        Err(DomainCatalogError::NonGenericClaimRoleOnDeviceScope)
    ));
}
