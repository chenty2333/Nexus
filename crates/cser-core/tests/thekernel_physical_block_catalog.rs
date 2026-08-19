use cser_core::{
    BLOCK_CLAIM_COMPLETION, BLOCK_CLAIM_DESCRIPTOR, BLOCK_CLAIM_IOVA, BLOCK_CLAIM_PINNED_PAGE,
    BLOCK_CLAIM_QUEUE_SLOT, BLOCK_CLAIM_RECOVERY_DESCRIPTOR, BLOCK_CLAIM_RECOVERY_IOVA,
    BLOCK_CLAIM_RECOVERY_PINNED_PAGE, BLOCK_CLAIM_RECOVERY_QUEUE_SLOT, BLOCK_EVIDENCE_COMPLETION,
    BLOCK_EVIDENCE_DMA_UNMAPPED, BLOCK_EVIDENCE_IOTLB, BLOCK_EVIDENCE_IRQ_DRAINED,
    BLOCK_EVIDENCE_RESET, BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED, BLOCK_OBLIGATION_COMPLETION,
    BLOCK_OBLIGATION_PHYSICAL_IO, BLOCK_OBLIGATION_PHYSICAL_IO_RECOVERY,
    BLOCK_USED_COMPLETION_RECEIPT_SCHEMA, ClaimScopePolicy, DeviceGenerationEffect,
    EvidenceCapability, EvidenceSubjectBinding, FreshnessAxes, ObligationPolicy,
    THEKERNEL_BLOCK_COMPONENT_COMPLETION, THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
    THEKERNEL_BLOCK_COMPONENT_RECOVERY, THEKERNEL_BLOCK_DOMAIN,
    THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE, THEKERNEL_PHYSICAL_BLOCK_IO_RECOVERY_COMPOSITE,
    thekernel_physical_block_io_catalog,
};

#[test]
fn block_catalog_is_separate_and_has_explicit_normal_and_recovery_products() {
    let catalog = thekernel_physical_block_io_catalog();
    assert_ne!(catalog.digest(), cser_core::standard_catalog().digest());

    let normal = catalog
        .composite_rule(THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE)
        .expect("normal block product must be sealed");
    assert_eq!(normal.components().len(), 2);
    assert_eq!(
        normal.components()[0].component(),
        THEKERNEL_BLOCK_COMPONENT_COMPLETION
    );
    assert_eq!(
        normal.components()[1].component(),
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO
    );
    assert_eq!(normal.components()[0].domain(), THEKERNEL_BLOCK_DOMAIN);
    assert_eq!(normal.components()[1].domain(), THEKERNEL_BLOCK_DOMAIN);
    assert_eq!(
        normal.components()[0].obligation(),
        BLOCK_OBLIGATION_COMPLETION
    );
    assert_eq!(
        normal.components()[1].obligation(),
        BLOCK_OBLIGATION_PHYSICAL_IO
    );

    let recovery = catalog
        .composite_rule(THEKERNEL_PHYSICAL_BLOCK_IO_RECOVERY_COMPOSITE)
        .expect("recovery block product must be sealed");
    assert_eq!(recovery.components().len(), 2);
    assert_eq!(
        recovery.components()[0].component(),
        THEKERNEL_BLOCK_COMPONENT_COMPLETION
    );
    assert_eq!(
        recovery.components()[1].component(),
        THEKERNEL_BLOCK_COMPONENT_RECOVERY
    );
    assert_eq!(
        recovery.components()[1].obligation(),
        BLOCK_OBLIGATION_PHYSICAL_IO_RECOVERY
    );

    assert!(
        catalog
            .composite_rule(cser_core::DMA_ARENA_REUSE_COMPOSITE)
            .is_none()
    );
}

#[test]
fn normal_used_completion_is_quiescence_only_and_dma_is_independent() {
    let catalog = thekernel_physical_block_io_catalog();
    let completion = catalog
        .claim_rule(THEKERNEL_BLOCK_DOMAIN, BLOCK_CLAIM_COMPLETION)
        .unwrap();
    assert_eq!(completion.scope(), ClaimScopePolicy::Logical);
    assert_eq!(completion.evidence().len(), 1);
    assert_eq!(completion.evidence()[0].kind(), BLOCK_EVIDENCE_COMPLETION);
    assert_eq!(
        completion.evidence()[0].capability(),
        EvidenceCapability::Outcome
    );
    assert_eq!(
        completion.evidence()[0].subject(),
        EvidenceSubjectBinding::LogicalEffect
    );

    let queue = catalog
        .claim_rule(THEKERNEL_BLOCK_DOMAIN, BLOCK_CLAIM_QUEUE_SLOT)
        .unwrap();
    assert_eq!(queue.evidence().len(), 1);
    assert_eq!(
        queue.evidence()[0].kind(),
        BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED
    );
    assert_eq!(
        queue.evidence()[0].receipt_schema(),
        BLOCK_USED_COMPLETION_RECEIPT_SCHEMA
    );
    assert_eq!(
        queue.evidence()[0].capability(),
        EvidenceCapability::Quiescence
    );
    assert_eq!(
        queue.evidence()[0].subject_freshness(),
        FreshnessAxes::BOOT
            .union(FreshnessAxes::REGISTRY)
            .union(FreshnessAxes::BINDING)
            .union(FreshnessAxes::DEVICE)
            .union(FreshnessAxes::JOURNAL)
    );
    assert_eq!(queue.evidence()[0].strictly_advanced(), FreshnessAxes::NONE);
    assert_eq!(
        queue.evidence()[0].observation_freshness(),
        FreshnessAxes::BOOT
            .union(FreshnessAxes::REGISTRY)
            .union(FreshnessAxes::BINDING)
            .union(FreshnessAxes::DEVICE)
            .union(FreshnessAxes::JOURNAL)
    );
    assert_eq!(
        queue.evidence()[0].device_generation(),
        DeviceGenerationEffect::None
    );

    for kind in [BLOCK_CLAIM_PINNED_PAGE, BLOCK_CLAIM_IOVA] {
        let claim = catalog.claim_rule(THEKERNEL_BLOCK_DOMAIN, kind).unwrap();
        assert_eq!(claim.evidence().len(), 1);
        assert_eq!(claim.evidence()[0].kind(), BLOCK_EVIDENCE_DMA_UNMAPPED);
        assert_ne!(
            claim.evidence()[0].kind(),
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED
        );
    }
}

#[test]
fn recovery_requires_the_exact_reset_conjunct_for_each_resource_class() {
    let catalog = thekernel_physical_block_io_catalog();
    for kind in [
        BLOCK_CLAIM_RECOVERY_QUEUE_SLOT,
        BLOCK_CLAIM_RECOVERY_DESCRIPTOR,
    ] {
        let claim = catalog.claim_rule(THEKERNEL_BLOCK_DOMAIN, kind).unwrap();
        assert_eq!(claim.evidence().len(), 2);
        assert_eq!(claim.evidence()[0].kind(), BLOCK_EVIDENCE_RESET);
        assert_eq!(claim.evidence()[1].kind(), BLOCK_EVIDENCE_IRQ_DRAINED);
        assert_eq!(
            claim.evidence()[1].prerequisite(),
            Some(BLOCK_EVIDENCE_RESET)
        );
    }
    for kind in [BLOCK_CLAIM_RECOVERY_PINNED_PAGE, BLOCK_CLAIM_RECOVERY_IOVA] {
        let claim = catalog.claim_rule(THEKERNEL_BLOCK_DOMAIN, kind).unwrap();
        assert_eq!(claim.evidence().len(), 2);
        assert_eq!(claim.evidence()[0].kind(), BLOCK_EVIDENCE_RESET);
        assert_eq!(claim.evidence()[1].kind(), BLOCK_EVIDENCE_IOTLB);
        assert_eq!(
            claim.evidence()[1].prerequisite(),
            Some(BLOCK_EVIDENCE_RESET)
        );
    }
    assert_eq!(
        catalog
            .obligation_rule(
                THEKERNEL_BLOCK_DOMAIN,
                BLOCK_OBLIGATION_PHYSICAL_IO_RECOVERY
            )
            .unwrap()
            .policy(),
        ObligationPolicy::RetirementEvidence
    );
}

#[test]
fn descriptor_and_queue_are_distinct_generation_bound_claims() {
    let catalog = thekernel_physical_block_io_catalog();
    let physical = catalog
        .composite_rule(THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE)
        .unwrap();
    assert_eq!(
        physical.components()[1].obligation(),
        BLOCK_OBLIGATION_PHYSICAL_IO
    );
    for kind in [BLOCK_CLAIM_QUEUE_SLOT, BLOCK_CLAIM_DESCRIPTOR] {
        let claim = catalog.claim_rule(THEKERNEL_BLOCK_DOMAIN, kind).unwrap();
        assert_eq!(claim.scope(), ClaimScopePolicy::Device);
        assert!(
            claim.evidence()[0]
                .subject_freshness()
                .contains(FreshnessAxes::DEVICE)
        );
    }
    assert_ne!(
        THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE,
        THEKERNEL_PHYSICAL_BLOCK_IO_RECOVERY_COMPOSITE
    );
}
