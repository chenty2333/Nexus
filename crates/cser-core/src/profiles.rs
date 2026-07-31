// SPDX-License-Identifier: MPL-2.0

use crate::{
    AdoptionPolicy, ClaimCardinality, ClaimKindId, ClaimScopePolicy, ComponentId,
    CompositeComponentSpec, CompositeKindId, CreditClassId, DeviceGenerationEffect, DomainCatalog,
    DomainCatalogBuilder, DomainId, EvidenceKindId, EvidenceRule, FreshnessAxes, ObligationKindId,
    ObligationPolicy, ObligationReceipts, ObligationSpec, ReceiptBinding, ReceiptSchemaId,
    VerifierId,
};

/// Verifier for exact reply-publication acknowledgements.
pub const REPLY_VERIFIER: VerifierId = match VerifierId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical reply-publication acknowledgement receipt schema.
pub const REPLY_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical reply backend commit-outcome receipt schema.
pub const REPLY_COMMIT_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical reply publication/reconciliation apply receipt schema.
pub const REPLY_APPLY_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical reply settlement acknowledgement receipt schema.
pub const REPLY_SETTLEMENT_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(4) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Verifier for reset, IRQ-drain, and IOTLB receipts.
pub const DEVICE_VERIFIER: VerifierId = match VerifierId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical device-retirement receipt schema.
pub const DEVICE_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical device queue-publication commit-outcome receipt schema.
pub const DEVICE_COMMIT_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Conserved reply publication-slot credits.
pub const CREDIT_REPLY_SLOT: CreditClassId = match CreditClassId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Conserved VirtIO queue-slot credits.
pub const CREDIT_QUEUE_SLOT: CreditClassId = match CreditClassId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Conserved pinned-page credits.
pub const CREDIT_PINNED_PAGE: CreditClassId = match CreditClassId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Conserved IOVA credits.
pub const CREDIT_IOVA: CreditClassId = match CreditClassId::new(4) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Standard reply/publication domain.
pub const REPLY_DOMAIN: DomainId = match DomainId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Post-commit reply publication obligation.
pub const REPLY_OBLIGATION_PUBLICATION: ObligationKindId = match ObligationKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// One-shot reply queue or publication slot.
pub const REPLY_CLAIM_PUBLICATION_SLOT: ClaimKindId = match ClaimKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Exact acknowledgement of one published result.
pub const REPLY_EVIDENCE_PUBLICATION_ACK: EvidenceKindId = match EvidenceKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Standard DMA/IOMMU domain.
pub const DEVICE_DOMAIN: DomainId = match DomainId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Device-visible DMA obligation.
pub const DEVICE_OBLIGATION_DMA: ObligationKindId = match ObligationKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Virtqueue slot or descriptor ownership.
pub const DEVICE_CLAIM_QUEUE_SLOT: ClaimKindId = match ClaimKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Physical page retained against possible DMA.
pub const DEVICE_CLAIM_PINNED_PAGE: ClaimKindId = match ClaimKindId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// IOVA or IOMMU mapping ownership.
pub const DEVICE_CLAIM_IOVA: ClaimKindId = match ClaimKindId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Typed reset-completion evidence.
pub const DEVICE_EVIDENCE_RESET: EvidenceKindId = match EvidenceKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Typed IRQ-drain evidence.
pub const DEVICE_EVIDENCE_IRQ_DRAINED: EvidenceKindId = match EvidenceKindId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Typed IOTLB invalidation-completion evidence.
pub const DEVICE_EVIDENCE_IOTLB: EvidenceKindId = match EvidenceKindId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Standard agent operation whose logical reply and DMA custody share one effect.
pub const AGENT_OPERATION_COMPOSITE: CompositeKindId = match CompositeKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Logical reply/output component of the standard agent operation.
pub const AGENT_COMPONENT_REPLY: ComponentId = match ComponentId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Queue/PFN/IOVA component of the standard agent operation.
pub const AGENT_COMPONENT_DMA: ComponentId = match ComponentId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// DMA-only composite used to prove resource-local generation reuse after the
/// original heterogeneous agent operation has discharged its DMA component.
pub const DMA_ARENA_REUSE_COMPOSITE: CompositeKindId = match CompositeKindId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Returns the built-in reply and DMA catalog.
///
/// Additional domains construct a catalog with [`DomainCatalogBuilder`] and use
/// their own stable identifiers. The built-in catalog is a profile, not a
/// closed enum in the engine.
pub fn standard_catalog() -> DomainCatalog {
    let reply_freshness = FreshnessAxes::BOOT
        .union(FreshnessAxes::REGISTRY)
        .union(FreshnessAxes::BINDING)
        .union(FreshnessAxes::JOURNAL);
    let device_freshness = FreshnessAxes::BOOT
        .union(FreshnessAxes::REGISTRY)
        .union(FreshnessAxes::DEVICE)
        .union(FreshnessAxes::JOURNAL);
    let device_subject = device_freshness.union(FreshnessAxes::BINDING);
    let device_reset = EvidenceRule::retirement(
        DEVICE_EVIDENCE_RESET,
        ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
        device_subject,
        device_freshness,
        FreshnessAxes::DEVICE,
        DeviceGenerationEffect::AdvanceOne,
        None,
    );
    let irq_after_reset = EvidenceRule::retirement(
        DEVICE_EVIDENCE_IRQ_DRAINED,
        ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
        device_subject,
        device_freshness,
        FreshnessAxes::DEVICE,
        DeviceGenerationEffect::None,
        Some(DEVICE_EVIDENCE_RESET),
    );
    let iotlb_after_reset = EvidenceRule::retirement(
        DEVICE_EVIDENCE_IOTLB,
        ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
        device_subject,
        device_freshness,
        FreshnessAxes::DEVICE,
        DeviceGenerationEffect::None,
        Some(DEVICE_EVIDENCE_RESET),
    );

    DomainCatalogBuilder::new()
        .credit_class(CREDIT_REPLY_SLOT, 1024)
        .expect("standard reply credits are unique")
        .credit_class(CREDIT_QUEUE_SLOT, 4096)
        .expect("standard queue credits are unique")
        .credit_class(CREDIT_PINNED_PAGE, 1 << 20)
        .expect("standard page credits are unique")
        .credit_class(CREDIT_IOVA, 1 << 20)
        .expect("standard IOVA credits are unique")
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
            &[ClaimCardinality::new(REPLY_CLAIM_PUBLICATION_SLOT, 1, 1)
                .expect("reply cardinality is valid")],
        )
        .expect("standard reply obligation is unique")
        .claim(
            REPLY_DOMAIN,
            REPLY_CLAIM_PUBLICATION_SLOT,
            CREDIT_REPLY_SLOT,
            ClaimScopePolicy::Logical,
            &[EvidenceRule::logical(
                REPLY_EVIDENCE_PUBLICATION_ACK,
                ReceiptBinding::new(REPLY_VERIFIER, REPLY_RECEIPT_SCHEMA),
                reply_freshness,
            )],
        )
        .expect("standard reply claim is valid")
        .obligation(
            ObligationSpec::new(
                DEVICE_DOMAIN,
                DEVICE_OBLIGATION_DMA,
                ObligationPolicy::RetirementEvidence,
                AdoptionPolicy::UncommittedOnly,
                ObligationReceipts::retirement_only(ReceiptBinding::new(
                    DEVICE_VERIFIER,
                    DEVICE_COMMIT_RECEIPT_SCHEMA,
                )),
                1,
            ),
            &[
                ClaimCardinality::new(DEVICE_CLAIM_QUEUE_SLOT, 0, 64)
                    .expect("queue cardinality is valid"),
                ClaimCardinality::new(DEVICE_CLAIM_PINNED_PAGE, 0, 4096)
                    .expect("page cardinality is valid"),
                ClaimCardinality::new(DEVICE_CLAIM_IOVA, 0, 4096)
                    .expect("IOVA cardinality is valid"),
            ],
        )
        .expect("standard device obligation is unique")
        .claim(
            DEVICE_DOMAIN,
            DEVICE_CLAIM_QUEUE_SLOT,
            CREDIT_QUEUE_SLOT,
            ClaimScopePolicy::Device,
            &[device_reset, irq_after_reset],
        )
        .expect("standard queue claim is valid")
        .claim(
            DEVICE_DOMAIN,
            DEVICE_CLAIM_PINNED_PAGE,
            CREDIT_PINNED_PAGE,
            ClaimScopePolicy::Device,
            &[device_reset, iotlb_after_reset],
        )
        .expect("standard pinned-page claim is valid")
        .claim(
            DEVICE_DOMAIN,
            DEVICE_CLAIM_IOVA,
            CREDIT_IOVA,
            ClaimScopePolicy::Device,
            &[device_reset, iotlb_after_reset],
        )
        .expect("standard IOVA claim is valid")
        .composite(
            AGENT_OPERATION_COMPOSITE,
            &[
                CompositeComponentSpec::new(
                    AGENT_COMPONENT_REPLY,
                    REPLY_DOMAIN,
                    REPLY_OBLIGATION_PUBLICATION,
                ),
                CompositeComponentSpec::new(
                    AGENT_COMPONENT_DMA,
                    DEVICE_DOMAIN,
                    DEVICE_OBLIGATION_DMA,
                ),
            ],
        )
        .expect("standard agent operation composite is valid")
        .composite(
            DMA_ARENA_REUSE_COMPOSITE,
            &[CompositeComponentSpec::new(
                AGENT_COMPONENT_DMA,
                DEVICE_DOMAIN,
                DEVICE_OBLIGATION_DMA,
            )],
        )
        .expect("standard DMA arena reuse composite is valid")
        .build()
        .expect("standard domain catalog is internally complete")
}
