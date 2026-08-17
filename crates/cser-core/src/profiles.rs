// SPDX-License-Identifier: MPL-2.0

use crate::domain::LogicalClaimRole;
use crate::{
    AdoptionPolicy, ClaimCardinality, ClaimKindId, ClaimScopePolicy, ComponentId,
    CompositeComponentSpec, CompositeKindId, CreditClassId, DeviceGenerationEffect, DomainCatalog,
    DomainCatalogBuilder, DomainId, EvidenceKindId, EvidenceRule, FreshnessAxes, ObligationKindId,
    ObligationPolicy, ObligationReceipts, ObligationSpec, ReceiptBinding, ReceiptSchemaId,
    RecoveryArtifactPolicy, VerifierId,
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

/// Verifier for a queryable tool-operation outcome.
///
/// This is intentionally distinct from the reply verifier: the experimental
/// profile models a tool endpoint whose durable operation identity can be
/// reconciled after the executor that issued it has gone away.
pub const TOOL_VERIFIER: VerifierId = match VerifierId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical queryable tool-outcome receipt schema.
pub const TOOL_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical tool commit-outcome receipt schema.
pub const TOOL_COMMIT_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical tool reconciliation apply receipt schema.
pub const TOOL_APPLY_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical tool settlement acknowledgement receipt schema.
pub const TOOL_SETTLEMENT_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(4) {
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
/// Conserved slots for a queryable tool outcome.
pub const CREDIT_TOOL_OUTCOME_SLOT: CreditClassId = match CreditClassId::new(5) {
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

/// Experimental queryable-tool domain.
pub const TOOL_DOMAIN: DomainId = match DomainId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// One tool invocation whose outcome is reconciled by a durable operation ID.
pub const TOOL_OBLIGATION_INVOCATION: ObligationKindId = match ObligationKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Logical slot retained until the tool outcome has been reconciled.
pub const TOOL_CLAIM_OUTCOME_SLOT: ClaimKindId = match ClaimKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Exact, queryable acknowledgement of one tool invocation's outcome.
pub const TOOL_EVIDENCE_OUTCOME_ACK: EvidenceKindId = match EvidenceKindId::new(1) {
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
/// Experimental composite binding one queryable tool outcome to one DMA
/// custody component. It is deliberately outside the standard catalog.
pub const TOOL_DMA_OPERATION_COMPOSITE: CompositeKindId = match CompositeKindId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Logical tool-outcome component of [`TOOL_DMA_OPERATION_COMPOSITE`].
pub const TOOL_DMA_COMPONENT_TOOL: ComponentId = match ComponentId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// DMA custody component of [`TOOL_DMA_OPERATION_COMPOSITE`].
pub const TOOL_DMA_COMPONENT_DMA: ComponentId = match ComponentId::new(4) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Sole logical child component of the explicit profile-two handoff pilot.
pub const TOOL_HANDOFF_COMPONENT: ComponentId = match ComponentId::new(5) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Independent logical source component of the bounded handoff pilot.
pub const TOOL_HANDOFF_SOURCE_COMPONENT: ComponentId = match ComponentId::new(6) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// One-component queryable-tool source used only by the experimental handoff profile.
pub const TOOL_HANDOFF_SOURCE_COMPOSITE: CompositeKindId = match CompositeKindId::new(4) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Catalog-defined one-component child admitted by the handoff guard.
pub const TOOL_HANDOFF_CHILD_COMPOSITE: CompositeKindId = match CompositeKindId::new(5) {
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
                )
                .with_artifact_policy(RecoveryArtifactPolicy::NotRequired),
                CompositeComponentSpec::new(
                    AGENT_COMPONENT_DMA,
                    DEVICE_DOMAIN,
                    DEVICE_OBLIGATION_DMA,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::NotRequired),
            ],
        )
        .expect("standard agent operation composite is valid")
        .composite(
            DMA_ARENA_REUSE_COMPOSITE,
            &[CompositeComponentSpec::new(
                AGENT_COMPONENT_DMA,
                DEVICE_DOMAIN,
                DEVICE_OBLIGATION_DMA,
            )
            .with_artifact_policy(RecoveryArtifactPolicy::NotRequired)],
        )
        .expect("standard DMA arena reuse composite is valid")
        .build()
        .expect("standard domain catalog is internally complete")
}

/// Returns the experimental catalog for one queryable tool operation coupled
/// to a DMA effect.
///
/// The tool component carries an outcome-only, crash-recoverable logical
/// claim. The DMA component deliberately reuses the standard queue, pinned
/// page, and IOVA classes, whose reset, IRQ-drain, and IOTLB evidence prove
/// quiescence independently. This is a separate catalog so the experiment
/// cannot change the standard profile's v6 digest.
pub fn tool_dma_catalog() -> DomainCatalog {
    let tool_freshness = FreshnessAxes::BOOT
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
        .credit_class(CREDIT_TOOL_OUTCOME_SLOT, 1024)
        .expect("tool outcome credits are unique")
        .credit_class(CREDIT_QUEUE_SLOT, 4096)
        .expect("tool DMA queue credits are unique")
        .credit_class(CREDIT_PINNED_PAGE, 1 << 20)
        .expect("tool DMA page credits are unique")
        .credit_class(CREDIT_IOVA, 1 << 20)
        .expect("tool DMA IOVA credits are unique")
        .obligation(
            ObligationSpec::new(
                TOOL_DOMAIN,
                TOOL_OBLIGATION_INVOCATION,
                ObligationPolicy::SuccessorSettlement,
                AdoptionPolicy::UncommittedOnly,
                ObligationReceipts::successor_settlement(
                    ReceiptBinding::new(TOOL_VERIFIER, TOOL_COMMIT_RECEIPT_SCHEMA),
                    ReceiptBinding::new(TOOL_VERIFIER, TOOL_APPLY_RECEIPT_SCHEMA),
                    ReceiptBinding::new(TOOL_VERIFIER, TOOL_SETTLEMENT_RECEIPT_SCHEMA),
                ),
                1,
            ),
            &[ClaimCardinality::new(TOOL_CLAIM_OUTCOME_SLOT, 1, 1)
                .expect("tool outcome cardinality is valid")],
        )
        .expect("tool obligation is unique")
        .claim(
            TOOL_DOMAIN,
            TOOL_CLAIM_OUTCOME_SLOT,
            CREDIT_TOOL_OUTCOME_SLOT,
            ClaimScopePolicy::Logical,
            &[EvidenceRule::logical(
                TOOL_EVIDENCE_OUTCOME_ACK,
                ReceiptBinding::new(TOOL_VERIFIER, TOOL_RECEIPT_SCHEMA),
                tool_freshness,
            )],
        )
        .expect("tool outcome claim is valid")
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
        .expect("tool DMA obligation is unique")
        .claim(
            DEVICE_DOMAIN,
            DEVICE_CLAIM_QUEUE_SLOT,
            CREDIT_QUEUE_SLOT,
            ClaimScopePolicy::Device,
            &[device_reset, irq_after_reset],
        )
        .expect("tool DMA queue claim is valid")
        .claim(
            DEVICE_DOMAIN,
            DEVICE_CLAIM_PINNED_PAGE,
            CREDIT_PINNED_PAGE,
            ClaimScopePolicy::Device,
            &[device_reset, iotlb_after_reset],
        )
        .expect("tool DMA pinned-page claim is valid")
        .claim(
            DEVICE_DOMAIN,
            DEVICE_CLAIM_IOVA,
            CREDIT_IOVA,
            ClaimScopePolicy::Device,
            &[device_reset, iotlb_after_reset],
        )
        .expect("tool DMA IOVA claim is valid")
        .composite(
            TOOL_DMA_OPERATION_COMPOSITE,
            &[
                CompositeComponentSpec::new(
                    TOOL_DMA_COMPONENT_TOOL,
                    TOOL_DOMAIN,
                    TOOL_OBLIGATION_INVOCATION,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::NotRequired),
                CompositeComponentSpec::new(
                    TOOL_DMA_COMPONENT_DMA,
                    DEVICE_DOMAIN,
                    DEVICE_OBLIGATION_DMA,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::NotRequired),
            ],
        )
        .expect("tool DMA composite is valid")
        .composite(
            TOOL_HANDOFF_SOURCE_COMPOSITE,
            &[CompositeComponentSpec::new(
                TOOL_HANDOFF_SOURCE_COMPONENT,
                TOOL_DOMAIN,
                TOOL_OBLIGATION_INVOCATION,
            )
            .with_artifact_policy(RecoveryArtifactPolicy::NotRequired)],
        )
        .expect("tool handoff source composite is valid")
        .composite(
            TOOL_HANDOFF_CHILD_COMPOSITE,
            &[CompositeComponentSpec::new(
                TOOL_HANDOFF_COMPONENT,
                TOOL_DOMAIN,
                TOOL_OBLIGATION_INVOCATION,
            )
            .with_artifact_policy(RecoveryArtifactPolicy::NotRequired)],
        )
        .expect("tool handoff child composite is valid")
        .single_hop_handoff(TOOL_HANDOFF_SOURCE_COMPOSITE, TOOL_HANDOFF_CHILD_COMPOSITE)
        .expect("tool handoff relation is valid")
        .build()
        .expect("tool DMA domain catalog is internally complete")
}

/// Verifier for the crash-recoverable Harness logical-operation receipts.
pub const HARNESS_VERIFIER: VerifierId = match VerifierId::new(4) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical Harness logical-operation observation receipt schema.
pub const HARNESS_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical Harness logical-operation commit receipt schema.
pub const HARNESS_COMMIT_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical Harness logical-operation apply receipt schema.
pub const HARNESS_APPLY_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Canonical Harness logical-operation settlement receipt schema.
pub const HARNESS_SETTLEMENT_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(4) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Logical Harness/World profile domain.
pub const HARNESS_DOMAIN: DomainId = match DomainId::new(4) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Conserved remote idempotency-slot credits.
pub const HARNESS_CREDIT_REMOTE_IDEMPOTENCY_SLOT: CreditClassId = match CreditClassId::new(6) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Conserved provider-operation credits.
pub const HARNESS_CREDIT_PROVIDER_OPERATION: CreditClassId = match CreditClassId::new(7) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Conserved reply-delivery credits.
pub const HARNESS_CREDIT_REPLY_DELIVERY: CreditClassId = match CreditClassId::new(8) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Conserved queued-job credits.
pub const HARNESS_CREDIT_QUEUED_JOB: CreditClassId = match CreditClassId::new(9) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Conserved recovery-worker credits.
pub const HARNESS_CREDIT_RECOVERY_WORKER: CreditClassId = match CreditClassId::new(10) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Conserved retained-provider-generation credits.
pub const HARNESS_CREDIT_RETAINED_PROVIDER_GENERATION: CreditClassId = match CreditClassId::new(11)
{
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Conserved artifact-closure credits.
pub const HARNESS_CREDIT_ARTIFACT_CLOSURE: CreditClassId = match CreditClassId::new(12) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Harness remote idempotency-slot obligation.
pub const HARNESS_OBLIGATION_REMOTE_IDEMPOTENCY_SLOT: ObligationKindId =
    match ObligationKindId::new(1) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    };
/// Harness provider-operation obligation.
pub const HARNESS_OBLIGATION_PROVIDER_OPERATION: ObligationKindId = match ObligationKindId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Harness reply-delivery obligation.
pub const HARNESS_OBLIGATION_REPLY_DELIVERY: ObligationKindId = match ObligationKindId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Harness queued-job obligation.
pub const HARNESS_OBLIGATION_QUEUED_JOB: ObligationKindId = match ObligationKindId::new(4) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Harness recovery-worker obligation.
pub const HARNESS_OBLIGATION_RECOVERY_WORKER: ObligationKindId = match ObligationKindId::new(5) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Harness retained-provider-generation obligation.
pub const HARNESS_OBLIGATION_RETAINED_PROVIDER_GENERATION: ObligationKindId =
    match ObligationKindId::new(6) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    };
/// Harness artifact-closure obligation.
pub const HARNESS_OBLIGATION_ARTIFACT_CLOSURE: ObligationKindId = match ObligationKindId::new(7) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Harness remote idempotency-slot claim.
pub const HARNESS_CLAIM_REMOTE_IDEMPOTENCY_SLOT: ClaimKindId = match ClaimKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Harness provider-operation claim.
pub const HARNESS_CLAIM_PROVIDER_OPERATION: ClaimKindId = match ClaimKindId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Harness reply-delivery claim.
pub const HARNESS_CLAIM_REPLY_DELIVERY: ClaimKindId = match ClaimKindId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Harness queued-job claim.
pub const HARNESS_CLAIM_QUEUED_JOB: ClaimKindId = match ClaimKindId::new(4) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Harness recovery-worker claim.
pub const HARNESS_CLAIM_RECOVERY_WORKER: ClaimKindId = match ClaimKindId::new(5) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Harness retained-provider-generation claim.
pub const HARNESS_CLAIM_RETAINED_PROVIDER_GENERATION: ClaimKindId = match ClaimKindId::new(6) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Harness artifact-closure claim.
pub const HARNESS_CLAIM_ARTIFACT_CLOSURE: ClaimKindId = match ClaimKindId::new(7) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Bounded composite containing the seven logical Harness custody components.
pub const HARNESS_OPERATION_COMPOSITE: CompositeKindId = match CompositeKindId::new(6) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Remote idempotency component of [`HARNESS_OPERATION_COMPOSITE`].
pub const HARNESS_COMPONENT_REMOTE_IDEMPOTENCY_SLOT: ComponentId = match ComponentId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Provider-operation component of [`HARNESS_OPERATION_COMPOSITE`].
pub const HARNESS_COMPONENT_PROVIDER_OPERATION: ComponentId = match ComponentId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Reply-delivery component of [`HARNESS_OPERATION_COMPOSITE`].
pub const HARNESS_COMPONENT_REPLY_DELIVERY: ComponentId = match ComponentId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Queued-job component of [`HARNESS_OPERATION_COMPOSITE`].
pub const HARNESS_COMPONENT_QUEUED_JOB: ComponentId = match ComponentId::new(4) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Recovery-worker component of [`HARNESS_OPERATION_COMPOSITE`].
pub const HARNESS_COMPONENT_RECOVERY_WORKER: ComponentId = match ComponentId::new(5) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Retained-provider-generation component of [`HARNESS_OPERATION_COMPOSITE`].
pub const HARNESS_COMPONENT_RETAINED_PROVIDER_GENERATION: ComponentId = match ComponentId::new(6) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
/// Artifact-closure component of [`HARNESS_OPERATION_COMPOSITE`].
pub const HARNESS_COMPONENT_ARTIFACT_CLOSURE: ComponentId = match ComponentId::new(7) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

const HARNESS_EVIDENCE_REMOTE_IDEMPOTENCY_SLOT: EvidenceKindId = match EvidenceKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
const HARNESS_EVIDENCE_PROVIDER_OPERATION: EvidenceKindId = match EvidenceKindId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
const HARNESS_EVIDENCE_REPLY_DELIVERY: EvidenceKindId = match EvidenceKindId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
const HARNESS_EVIDENCE_QUEUED_JOB: EvidenceKindId = match EvidenceKindId::new(4) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
const HARNESS_EVIDENCE_RECOVERY_WORKER: EvidenceKindId = match EvidenceKindId::new(5) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
const HARNESS_EVIDENCE_RETAINED_PROVIDER_GENERATION: EvidenceKindId = match EvidenceKindId::new(6) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};
const HARNESS_EVIDENCE_ARTIFACT_CLOSURE: EvidenceKindId = match EvidenceKindId::new(7) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// One bounded, sealed logical profile for a World/Harness integration.
///
/// The catalog names the seven logical custody classes needed to reconcile
/// escaped provider work and its recovery closure.  It contains one fixed
/// seven-component composite and no loader, resolver, dependency-injection,
/// or general workflow surface.
pub fn harness_catalog() -> DomainCatalog {
    let freshness = FreshnessAxes::BOOT
        .union(FreshnessAxes::REGISTRY)
        .union(FreshnessAxes::BINDING)
        .union(FreshnessAxes::JOURNAL);
    let receipt = ReceiptBinding::new(HARNESS_VERIFIER, HARNESS_RECEIPT_SCHEMA);
    let commit = ReceiptBinding::new(HARNESS_VERIFIER, HARNESS_COMMIT_RECEIPT_SCHEMA);
    let apply = ReceiptBinding::new(HARNESS_VERIFIER, HARNESS_APPLY_RECEIPT_SCHEMA);
    let settlement = ReceiptBinding::new(HARNESS_VERIFIER, HARNESS_SETTLEMENT_RECEIPT_SCHEMA);
    let logical_obligation = |kind| {
        ObligationSpec::new(
            HARNESS_DOMAIN,
            kind,
            ObligationPolicy::SuccessorSettlement,
            AdoptionPolicy::UncommittedOnly,
            ObligationReceipts::successor_settlement(commit, apply, settlement),
            1,
        )
    };

    DomainCatalogBuilder::new()
        .credit_class(HARNESS_CREDIT_REMOTE_IDEMPOTENCY_SLOT, 1024)
        .expect("harness idempotency credits are unique")
        .credit_class(HARNESS_CREDIT_PROVIDER_OPERATION, 1024)
        .expect("harness provider-operation credits are unique")
        .credit_class(HARNESS_CREDIT_REPLY_DELIVERY, 1024)
        .expect("harness reply-delivery credits are unique")
        .credit_class(HARNESS_CREDIT_QUEUED_JOB, 1024)
        .expect("harness queued-job credits are unique")
        .credit_class(HARNESS_CREDIT_RECOVERY_WORKER, 1024)
        .expect("harness recovery-worker credits are unique")
        .credit_class(HARNESS_CREDIT_RETAINED_PROVIDER_GENERATION, 1024)
        .expect("harness retained-generation credits are unique")
        .credit_class(HARNESS_CREDIT_ARTIFACT_CLOSURE, 1024)
        .expect("harness artifact-closure credits are unique")
        .obligation(
            logical_obligation(HARNESS_OBLIGATION_REMOTE_IDEMPOTENCY_SLOT),
            &[
                ClaimCardinality::new(HARNESS_CLAIM_REMOTE_IDEMPOTENCY_SLOT, 1, 1)
                    .expect("harness idempotency cardinality is valid"),
            ],
        )
        .expect("harness idempotency obligation is unique")
        .obligation(
            logical_obligation(HARNESS_OBLIGATION_PROVIDER_OPERATION),
            &[
                ClaimCardinality::new(HARNESS_CLAIM_PROVIDER_OPERATION, 1, 1)
                    .expect("harness provider-operation cardinality is valid"),
            ],
        )
        .expect("harness provider-operation obligation is unique")
        .obligation(
            logical_obligation(HARNESS_OBLIGATION_REPLY_DELIVERY),
            &[ClaimCardinality::new(HARNESS_CLAIM_REPLY_DELIVERY, 1, 1)
                .expect("harness reply-delivery cardinality is valid")],
        )
        .expect("harness reply-delivery obligation is unique")
        .obligation(
            logical_obligation(HARNESS_OBLIGATION_QUEUED_JOB),
            &[ClaimCardinality::new(HARNESS_CLAIM_QUEUED_JOB, 1, 1)
                .expect("harness queued-job cardinality is valid")],
        )
        .expect("harness queued-job obligation is unique")
        .obligation(
            logical_obligation(HARNESS_OBLIGATION_RECOVERY_WORKER),
            &[ClaimCardinality::new(HARNESS_CLAIM_RECOVERY_WORKER, 1, 1)
                .expect("harness recovery-worker cardinality is valid")],
        )
        .expect("harness recovery-worker obligation is unique")
        .obligation(
            logical_obligation(HARNESS_OBLIGATION_RETAINED_PROVIDER_GENERATION),
            &[
                ClaimCardinality::new(HARNESS_CLAIM_RETAINED_PROVIDER_GENERATION, 1, 1)
                    .expect("harness retained-generation cardinality is valid"),
            ],
        )
        .expect("harness retained-generation obligation is unique")
        .obligation(
            logical_obligation(HARNESS_OBLIGATION_ARTIFACT_CLOSURE),
            &[ClaimCardinality::new(HARNESS_CLAIM_ARTIFACT_CLOSURE, 1, 1)
                .expect("harness artifact-closure cardinality is valid")],
        )
        .expect("harness artifact-closure obligation is unique")
        .claim_with_role(
            HARNESS_DOMAIN,
            HARNESS_CLAIM_REMOTE_IDEMPOTENCY_SLOT,
            HARNESS_CREDIT_REMOTE_IDEMPOTENCY_SLOT,
            ClaimScopePolicy::Logical,
            LogicalClaimRole::RemoteIdempotencySlot,
            &[EvidenceRule::logical(
                HARNESS_EVIDENCE_REMOTE_IDEMPOTENCY_SLOT,
                receipt,
                freshness,
            )],
        )
        .expect("harness idempotency claim is valid")
        .claim_with_role(
            HARNESS_DOMAIN,
            HARNESS_CLAIM_PROVIDER_OPERATION,
            HARNESS_CREDIT_PROVIDER_OPERATION,
            ClaimScopePolicy::Logical,
            LogicalClaimRole::ProviderOperation,
            &[EvidenceRule::logical(
                HARNESS_EVIDENCE_PROVIDER_OPERATION,
                receipt,
                freshness,
            )],
        )
        .expect("harness provider-operation claim is valid")
        .claim_with_role(
            HARNESS_DOMAIN,
            HARNESS_CLAIM_REPLY_DELIVERY,
            HARNESS_CREDIT_REPLY_DELIVERY,
            ClaimScopePolicy::Logical,
            LogicalClaimRole::ReplyDelivery,
            &[EvidenceRule::logical(
                HARNESS_EVIDENCE_REPLY_DELIVERY,
                receipt,
                freshness,
            )],
        )
        .expect("harness reply-delivery claim is valid")
        .claim_with_role(
            HARNESS_DOMAIN,
            HARNESS_CLAIM_QUEUED_JOB,
            HARNESS_CREDIT_QUEUED_JOB,
            ClaimScopePolicy::Logical,
            LogicalClaimRole::QueuedJob,
            &[EvidenceRule::logical(
                HARNESS_EVIDENCE_QUEUED_JOB,
                receipt,
                freshness,
            )],
        )
        .expect("harness queued-job claim is valid")
        .claim_with_role(
            HARNESS_DOMAIN,
            HARNESS_CLAIM_RECOVERY_WORKER,
            HARNESS_CREDIT_RECOVERY_WORKER,
            ClaimScopePolicy::Logical,
            LogicalClaimRole::RecoveryWorker,
            &[EvidenceRule::logical(
                HARNESS_EVIDENCE_RECOVERY_WORKER,
                receipt,
                freshness,
            )],
        )
        .expect("harness recovery-worker claim is valid")
        .claim_with_role(
            HARNESS_DOMAIN,
            HARNESS_CLAIM_RETAINED_PROVIDER_GENERATION,
            HARNESS_CREDIT_RETAINED_PROVIDER_GENERATION,
            ClaimScopePolicy::Logical,
            LogicalClaimRole::RetainedProviderGeneration,
            &[EvidenceRule::logical(
                HARNESS_EVIDENCE_RETAINED_PROVIDER_GENERATION,
                receipt,
                freshness,
            )],
        )
        .expect("harness retained-generation claim is valid")
        .claim_with_role(
            HARNESS_DOMAIN,
            HARNESS_CLAIM_ARTIFACT_CLOSURE,
            HARNESS_CREDIT_ARTIFACT_CLOSURE,
            ClaimScopePolicy::Logical,
            LogicalClaimRole::ArtifactClosure,
            &[EvidenceRule::logical(
                HARNESS_EVIDENCE_ARTIFACT_CLOSURE,
                receipt,
                freshness,
            )],
        )
        .expect("harness artifact-closure claim is valid")
        .composite(
            HARNESS_OPERATION_COMPOSITE,
            &[
                CompositeComponentSpec::new(
                    HARNESS_COMPONENT_REMOTE_IDEMPOTENCY_SLOT,
                    HARNESS_DOMAIN,
                    HARNESS_OBLIGATION_REMOTE_IDEMPOTENCY_SLOT,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::NotRequired),
                CompositeComponentSpec::new(
                    HARNESS_COMPONENT_PROVIDER_OPERATION,
                    HARNESS_DOMAIN,
                    HARNESS_OBLIGATION_PROVIDER_OPERATION,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::NotRequired),
                CompositeComponentSpec::new(
                    HARNESS_COMPONENT_REPLY_DELIVERY,
                    HARNESS_DOMAIN,
                    HARNESS_OBLIGATION_REPLY_DELIVERY,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::NotRequired),
                CompositeComponentSpec::new(
                    HARNESS_COMPONENT_QUEUED_JOB,
                    HARNESS_DOMAIN,
                    HARNESS_OBLIGATION_QUEUED_JOB,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::NotRequired),
                CompositeComponentSpec::new(
                    HARNESS_COMPONENT_RECOVERY_WORKER,
                    HARNESS_DOMAIN,
                    HARNESS_OBLIGATION_RECOVERY_WORKER,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::NotRequired),
                CompositeComponentSpec::new(
                    HARNESS_COMPONENT_RETAINED_PROVIDER_GENERATION,
                    HARNESS_DOMAIN,
                    HARNESS_OBLIGATION_RETAINED_PROVIDER_GENERATION,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::Required),
                CompositeComponentSpec::new(
                    HARNESS_COMPONENT_ARTIFACT_CLOSURE,
                    HARNESS_DOMAIN,
                    HARNESS_OBLIGATION_ARTIFACT_CLOSURE,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::Required),
            ],
        )
        .expect("harness bounded composite is valid")
        .build()
        .expect("harness domain catalog is internally complete")
}
