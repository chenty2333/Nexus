// SPDX-License-Identifier: MPL-2.0

use cser_core::{
    CREDIT_IOVA, CREDIT_PINNED_PAGE, CREDIT_QUEUE_SLOT, CREDIT_TOOL_OUTCOME_SLOT, ClaimScopePolicy,
    DEVICE_CLAIM_IOVA, DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT, DEVICE_DOMAIN,
    DEVICE_OBLIGATION_DMA, EvidenceCapability, EvidenceRecovery, TOOL_CLAIM_OUTCOME_SLOT,
    TOOL_DMA_COMPONENT_DMA, TOOL_DMA_COMPONENT_TOOL, TOOL_DMA_OPERATION_COMPOSITE, TOOL_DOMAIN,
    TOOL_HANDOFF_CHILD_COMPOSITE, TOOL_HANDOFF_COMPONENT, TOOL_HANDOFF_SOURCE_COMPONENT,
    TOOL_HANDOFF_SOURCE_COMPOSITE, TOOL_OBLIGATION_INVOCATION, standard_catalog, tool_dma_catalog,
};

/// The tool/DMA experiment is an independent catalog, so adding it cannot
/// silently alter the frozen standard-profile identity used by v6 journals.
#[test]
fn tool_dma_catalog_is_separate_from_the_frozen_standard_catalog() {
    let standard = standard_catalog();
    let experiment = tool_dma_catalog();

    assert_ne!(experiment.digest(), standard.digest());
    assert!(
        standard
            .composite_rule(TOOL_DMA_OPERATION_COMPOSITE)
            .is_none()
    );
    assert!(
        standard
            .claim_rule(TOOL_DOMAIN, TOOL_CLAIM_OUTCOME_SLOT)
            .is_none()
    );
}

/// The experimental topology puts one queryable tool outcome and one DMA
/// obligation under the same effect while keeping their evidence paths
/// independently typed.
#[test]
fn tool_dma_catalog_binds_one_logical_outcome_and_one_dma_component() {
    let catalog = tool_dma_catalog();
    let composite = catalog
        .composite_rule(TOOL_DMA_OPERATION_COMPOSITE)
        .expect("the experimental composite must be catalog-bound");

    assert_eq!(composite.components().len(), 2);
    assert_eq!(
        composite.components()[0].component(),
        TOOL_DMA_COMPONENT_TOOL
    );
    assert_eq!(composite.components()[0].domain(), TOOL_DOMAIN);
    assert_eq!(
        composite.components()[0].obligation(),
        TOOL_OBLIGATION_INVOCATION
    );
    assert_eq!(
        composite.components()[1].component(),
        TOOL_DMA_COMPONENT_DMA
    );
    assert_eq!(composite.components()[1].domain(), DEVICE_DOMAIN);
    assert_eq!(
        composite.components()[1].obligation(),
        DEVICE_OBLIGATION_DMA
    );
}

#[test]
fn tool_dma_catalog_binds_explicit_one_component_handoff_topology() {
    let catalog = tool_dma_catalog();
    let source = catalog
        .composite_rule(TOOL_HANDOFF_SOURCE_COMPOSITE)
        .expect("the handoff source must be catalog-bound");
    assert_eq!(source.components().len(), 1);
    assert_eq!(
        source.components()[0].component(),
        TOOL_HANDOFF_SOURCE_COMPONENT
    );
    assert_eq!(source.components()[0].domain(), TOOL_DOMAIN);
    assert_eq!(
        source.components()[0].obligation(),
        TOOL_OBLIGATION_INVOCATION
    );

    let child = catalog
        .composite_rule(TOOL_HANDOFF_CHILD_COMPOSITE)
        .expect("the handoff child must be catalog-bound");
    assert_eq!(child.components().len(), 1);
    assert_eq!(child.components()[0].component(), TOOL_HANDOFF_COMPONENT);
    assert_eq!(child.components()[0].domain(), TOOL_DOMAIN);
    assert_eq!(
        child.components()[0].obligation(),
        TOOL_OBLIGATION_INVOCATION
    );
    assert_eq!(
        catalog
            .single_hop_handoff_rule(TOOL_HANDOFF_SOURCE_COMPOSITE)
            .expect("the handoff edge must be catalog-bound")
            .target(),
        TOOL_HANDOFF_CHILD_COMPOSITE
    );
}

/// A tool outcome is queryable outcome evidence, whereas reuse of DMA
/// resources remains conditioned on the standard recoverable quiescence
/// conjunction. Neither component's type can stand in for the other.
#[test]
fn tool_dma_catalog_preserves_outcome_and_quiescence_separation() {
    let catalog = tool_dma_catalog();
    let tool = catalog
        .claim_rule(TOOL_DOMAIN, TOOL_CLAIM_OUTCOME_SLOT)
        .expect("the tool outcome slot must remain catalog-bound");
    assert_eq!(tool.scope(), ClaimScopePolicy::Logical);
    assert_eq!(tool.credit_class(), CREDIT_TOOL_OUTCOME_SLOT);
    assert_eq!(tool.evidence().len(), 1);
    assert_eq!(tool.evidence()[0].capability(), EvidenceCapability::Outcome);
    assert_eq!(tool.evidence()[0].recovery(), EvidenceRecovery::Recoverable);

    for (kind, credit) in [
        (DEVICE_CLAIM_QUEUE_SLOT, CREDIT_QUEUE_SLOT),
        (DEVICE_CLAIM_PINNED_PAGE, CREDIT_PINNED_PAGE),
        (DEVICE_CLAIM_IOVA, CREDIT_IOVA),
    ] {
        let dma = catalog
            .claim_rule(DEVICE_DOMAIN, kind)
            .expect("every standard DMA claim must be present in the experiment");
        assert_eq!(dma.scope(), ClaimScopePolicy::Device);
        assert_eq!(dma.credit_class(), credit);
        assert!(
            dma.evidence()
                .iter()
                .all(|rule| rule.capability() == EvidenceCapability::Quiescence)
        );
        assert!(
            dma.evidence()
                .iter()
                .all(|rule| rule.recovery() == EvidenceRecovery::Recoverable)
        );
    }
}
