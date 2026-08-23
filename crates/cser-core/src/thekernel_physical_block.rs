// SPDX-License-Identifier: MPL-2.0

//! TheKernel's bounded physical block-I/O catalog.
//!
//! This profile is deliberately separate from [`crate::DMA_ARENA_REUSE_COMPOSITE`].
//! The arena profile predates a request-level completion contract and is a
//! reset-only resource-reuse product.  A TheKernel block request instead has
//! an exact logical completion, a queue/descriptor custody tuple, and
//! separately typed DMA resource custody.
//!
//! The current catalog grammar makes the evidence listed for one claim a
//! conjunction.  Consequently this catalog seals two products: the normal
//! completion product and a recovery product.  The normal product uses the
//! exact used-completion fact for queue and descriptor claims and an
//! independent DMA-unmap fact for SG/IOVA claims.  The recovery product uses
//! RESET+IRQ_DRAINED for queue/descriptor claims and RESET+IOTLB for SG/IOVA
//! claims.  An embedding selects the product before admission; normal
//! used-completion receipts use [`BlockUsedCompletionVerifier`], while reset
//! recovery remains a separate verifier path.  Neither product changes the
//! meaning of the existing DMA arena profile.

use crate::{
    AdoptionPolicy, ClaimCardinality, ClaimId, ClaimKindId, ClaimScope, ClaimScopePolicy,
    ComponentId, CompositeComponentSpec, CompositeKindId, CreditClassId, DeviceGenerationEffect,
    Digest, DomainCatalog, DomainCatalogBuilder, DomainId, EffectId, EvidenceChallenge,
    EvidenceKindId, EvidenceRule, Freshness, FreshnessAxes, ObligationKindId, ObligationPolicy,
    ObligationReceipts, ObligationSpec, ReceiptBinding, ReceiptSchemaId, ReceiptVerifier,
    RecoveryArtifactPolicy, ResourceGeneration, ResourceId, VerificationError, VerifiedObservation,
    VerifierId, VerifierIdentity,
};

/// Domain of TheKernel's physical block-I/O profile.
pub const THEKERNEL_BLOCK_DOMAIN: DomainId = match DomainId::new(5) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Alias naming the profile's complete physical block-I/O domain.
pub const THEKERNEL_PHYSICAL_BLOCK_IO_DOMAIN: DomainId = THEKERNEL_BLOCK_DOMAIN;

/// Verifier class for TheKernel block-I/O receipts.
pub const THEKERNEL_BLOCK_VERIFIER: VerifierId = match VerifierId::new(5) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Short alias for the block-I/O verifier class.
pub const BLOCK_VERIFIER: VerifierId = THEKERNEL_BLOCK_VERIFIER;

/// Explicit TheKernel block-I/O verifier alias.
pub const THEKERNEL_BLOCK_IO_VERIFIER: VerifierId = THEKERNEL_BLOCK_VERIFIER;

/// Receipt schema for exact used-completion/quiescence facts.
pub const BLOCK_USED_COMPLETION_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(5) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Canonical short name for the used-completion receipt schema.
pub const BLOCK_RECEIPT_SCHEMA: ReceiptSchemaId = BLOCK_USED_COMPLETION_RECEIPT_SCHEMA;

/// Receipt schema for the independent logical completion fact.
pub const BLOCK_COMPLETION_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(6) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Receipt schema for an explicit DMA-unmap/SG termination fact.
pub const BLOCK_DMA_UNMAP_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(7) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Receipt schema for reset, IRQ-drain, and IOTLB recovery facts.
pub const BLOCK_RECOVERY_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(8) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Receipt schema for the block provider's durable commit outcome.
pub const BLOCK_COMMIT_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(9) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Receipt schema for the logical completion apply fact.
pub const BLOCK_APPLY_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(10) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Receipt schema for the logical completion settlement acknowledgement.
pub const BLOCK_SETTLEMENT_RECEIPT_SCHEMA: ReceiptSchemaId = match ReceiptSchemaId::new(11) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Conserved logical completion-slot credits.
pub const CREDIT_BLOCK_COMPLETION_SLOT: CreditClassId = match CreditClassId::new(13) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Conserved queue-slot credits for one physical block request.
pub const CREDIT_BLOCK_QUEUE_SLOT: CreditClassId = match CreditClassId::new(14) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Conserved descriptor/request-resource credits.
pub const CREDIT_BLOCK_DESCRIPTOR: CreditClassId = match CreditClassId::new(15) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Conserved pinned-page/SG-buffer credits.
pub const CREDIT_BLOCK_PINNED_PAGE: CreditClassId = match CreditClassId::new(16) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Conserved IOVA credits.
pub const CREDIT_BLOCK_IOVA: CreditClassId = match CreditClassId::new(17) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Alias for the completion credit class used by the physical block profile.
pub const THEKERNEL_BLOCK_COMPLETION_CREDIT: CreditClassId = CREDIT_BLOCK_COMPLETION_SLOT;

/// Alias for the queue credit class used by the physical block profile.
pub const THEKERNEL_BLOCK_QUEUE_CREDIT: CreditClassId = CREDIT_BLOCK_QUEUE_SLOT;

/// Alias for the descriptor/request credit class used by the physical block profile.
pub const THEKERNEL_BLOCK_DESCRIPTOR_CREDIT: CreditClassId = CREDIT_BLOCK_DESCRIPTOR;

/// Alias for the pinned-page credit class used by the physical block profile.
pub const THEKERNEL_BLOCK_PINNED_PAGE_CREDIT: CreditClassId = CREDIT_BLOCK_PINNED_PAGE;

/// Alias for the IOVA credit class used by the physical block profile.
pub const THEKERNEL_BLOCK_IOVA_CREDIT: CreditClassId = CREDIT_BLOCK_IOVA;

/// Logical obligation which records the request's independently settled outcome.
pub const BLOCK_OBLIGATION_COMPLETION: ObligationKindId = match ObligationKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Physical obligation for the normal used-completion product.
pub const BLOCK_OBLIGATION_PHYSICAL_IO: ObligationKindId = match ObligationKindId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Physical obligation for the RESET/IRQ/IOTLB recovery product.
pub const BLOCK_OBLIGATION_PHYSICAL_IO_RECOVERY: ObligationKindId = match ObligationKindId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Logical completion claim retained until the request outcome is settled.
pub const BLOCK_CLAIM_COMPLETION: ClaimKindId = match ClaimKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Queue identity claim. Its resource identity is the exact queue id and its
/// resource generation is the queue generation enrolled for this request.
pub const BLOCK_CLAIM_QUEUE_SLOT: ClaimKindId = match ClaimKindId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Descriptor/request identity claim. Its resource generation is the exact
/// descriptor/request generation bound into the device receipt.
pub const BLOCK_CLAIM_DESCRIPTOR: ClaimKindId = match ClaimKindId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Alias spelling out that the descriptor claim carries request identity.
pub const BLOCK_CLAIM_DESCRIPTOR_REQUEST: ClaimKindId = BLOCK_CLAIM_DESCRIPTOR;

/// Short alias for the request-resource claim.
pub const BLOCK_CLAIM_REQUEST: ClaimKindId = BLOCK_CLAIM_DESCRIPTOR;

/// Pinned SG/page claim retained while the device may still DMA.
pub const BLOCK_CLAIM_PINNED_PAGE: ClaimKindId = match ClaimKindId::new(4) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// IOVA mapping claim retained while the device may still DMA.
pub const BLOCK_CLAIM_IOVA: ClaimKindId = match ClaimKindId::new(5) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Recovery-product queue identity claim.
pub const BLOCK_CLAIM_RECOVERY_QUEUE_SLOT: ClaimKindId = match ClaimKindId::new(6) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Recovery-product descriptor/request identity claim.
pub const BLOCK_CLAIM_RECOVERY_DESCRIPTOR: ClaimKindId = match ClaimKindId::new(7) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Recovery alias spelling out the descriptor/request resource.
pub const BLOCK_CLAIM_RECOVERY_DESCRIPTOR_REQUEST: ClaimKindId = BLOCK_CLAIM_RECOVERY_DESCRIPTOR;

/// Recovery-product pinned SG/page claim.
pub const BLOCK_CLAIM_RECOVERY_PINNED_PAGE: ClaimKindId = match ClaimKindId::new(8) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Recovery-product IOVA mapping claim.
pub const BLOCK_CLAIM_RECOVERY_IOVA: ClaimKindId = match ClaimKindId::new(9) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Component carrying the logical request completion.
pub const THEKERNEL_BLOCK_COMPONENT_COMPLETION: ComponentId = match ComponentId::new(7) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Component carrying normal physical block-I/O custody.
pub const THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO: ComponentId = match ComponentId::new(8) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Component carrying RESET/IRQ/IOTLB recovery custody.
pub const THEKERNEL_BLOCK_COMPONENT_RECOVERY: ComponentId = match ComponentId::new(9) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Alias for the normal physical component.
pub const THEKERNEL_PHYSICAL_BLOCK_IO_COMPONENT: ComponentId =
    THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO;

/// Exact logical completion evidence. This is outcome evidence, not physical
/// quiescence and never authorizes queue, SG, or IOVA reuse.
pub const BLOCK_EVIDENCE_COMPLETION: EvidenceKindId = match EvidenceKindId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Exact request/queue/cookie used-completion evidence which may retire queue
/// and descriptor claims after the queue owner consumed `used` and detached
/// device ownership.
pub const BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED: EvidenceKindId = match EvidenceKindId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Short alias for the exact used-completion quiescence evidence.
pub const BLOCK_EVIDENCE_USED_COMPLETION: EvidenceKindId = BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED;

/// Independent typed evidence that DMA access to SG/page and IOVA resources
/// has ended. Used-completion alone never satisfies this requirement.
pub const BLOCK_EVIDENCE_DMA_UNMAPPED: EvidenceKindId = match EvidenceKindId::new(3) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Alias using the operation name used by DMA adapters.
pub const BLOCK_EVIDENCE_DMA_UNMAP: EvidenceKindId = BLOCK_EVIDENCE_DMA_UNMAPPED;

/// Recovery reset evidence for one exact enrolled device generation.
pub const BLOCK_EVIDENCE_RESET: EvidenceKindId = match EvidenceKindId::new(4) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Recovery IRQ-drained evidence, ordered after [`BLOCK_EVIDENCE_RESET`].
pub const BLOCK_EVIDENCE_IRQ_DRAINED: EvidenceKindId = match EvidenceKindId::new(5) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Recovery IOTLB invalidation evidence, ordered after [`BLOCK_EVIDENCE_RESET`].
pub const BLOCK_EVIDENCE_IOTLB: EvidenceKindId = match EvidenceKindId::new(6) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Normal product: logical completion plus exact request/queue and DMA claims.
pub const THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE: CompositeKindId = match CompositeKindId::new(7) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Recovery product: logical completion plus reset-drained physical claims.
pub const THEKERNEL_PHYSICAL_BLOCK_IO_RECOVERY_COMPOSITE: CompositeKindId =
    match CompositeKindId::new(8) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    };

/// Profile alias for the normal TheKernel physical block-I/O composite.
pub const THEKERNEL_PHYSICAL_BLOCK_IO_PROFILE: CompositeKindId =
    THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE;

/// Short TheKernel block-I/O composite alias.
pub const THEKERNEL_BLOCK_IO_COMPOSITE: CompositeKindId = THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE;

/// Short TheKernel block-I/O recovery composite alias.
pub const THEKERNEL_BLOCK_IO_RECOVERY_COMPOSITE: CompositeKindId =
    THEKERNEL_PHYSICAL_BLOCK_IO_RECOVERY_COMPOSITE;

/// Typed receipt grammar for the normal used-completion fact.
///
/// A normal completion is not a reset observation.  Its device generation is
/// carried explicitly and must be the same generation named by both the
/// enrolled subject and the active observation.  Queue and request/descriptor
/// coordinates, together with the completion cookie, are part of the receipt
/// rather than descriptive fields which a verifier may ignore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockUsedCompletionReceipt {
    /// Effect whose physical claim is being retired.
    pub effect: EffectId,
    /// Exact component-local claim receiving the fact.
    pub claim: ClaimId,
    /// Receipt evidence kind; must be [`BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED`].
    pub kind: EvidenceKindId,
    /// Resource identity carried by the core challenge.
    pub resource: ResourceId,
    /// Allocation generation carried by the core challenge.
    pub resource_generation: ResourceGeneration,
    /// Enrolled freshness subject named by the device receipt.
    pub subject: Freshness,
    /// Exact executor authority under which the claim was enrolled.
    pub subject_binding: crate::ExecutorBinding,
    /// Active freshness observation named by the device receipt.
    pub observation: Freshness,
    /// Exact current executor authority named by the completion receipt.
    pub observation_binding: crate::ExecutorBinding,
    /// Exact device generation carried by the completion tuple.
    pub device_generation: crate::DeviceGeneration,
    /// Queue identity which consumed the used entry.
    pub queue: ResourceId,
    /// Queue allocation generation which consumed the used entry.
    pub queue_generation: ResourceGeneration,
    /// Descriptor/request identity completed by the device.
    pub request: ResourceId,
    /// Descriptor/request allocation generation completed by the device.
    pub request_generation: ResourceGeneration,
    /// Device completion cookie bound to this request.
    pub completion_cookie: u64,
    /// Canonical authenticated receipt digest.
    pub digest: Digest,
}

/// Typed verifier contract for a normal used-completion receipt.
///
/// The contract is deliberately separate from the RESET/IRQ/IOTLB recovery
/// verifier path.  It rejects a generation-1 completion paired with a
/// generation-2 active observation, even when the generic freshness grammar
/// would accept each coordinate independently.  It also authenticates the
/// exact queue/request coordinates and completion cookie for the request.  The
/// challenged catalog claim kind selects which tuple member is authoritative;
/// the verifier never infers that role from a raw resource identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockUsedCompletionVerifier {
    identity: VerifierIdentity,
    queue: ResourceId,
    queue_generation: ResourceGeneration,
    request: ResourceId,
    request_generation: ResourceGeneration,
    completion_cookie: u64,
}

impl BlockUsedCompletionVerifier {
    /// Creates a verifier for one exact queue/request completion tuple.
    pub const fn new(
        identity: VerifierIdentity,
        queue: ResourceId,
        queue_generation: ResourceGeneration,
        request: ResourceId,
        request_generation: ResourceGeneration,
        completion_cookie: u64,
    ) -> Self {
        Self {
            identity,
            queue,
            queue_generation,
            request,
            request_generation,
            completion_cookie,
        }
    }

    /// Returns the exact queue identity expected by this verifier.
    pub const fn queue(&self) -> ResourceId {
        self.queue
    }

    /// Returns the exact queue generation expected by this verifier.
    pub const fn queue_generation(&self) -> ResourceGeneration {
        self.queue_generation
    }

    /// Returns the exact descriptor/request identity expected by this verifier.
    pub const fn request(&self) -> ResourceId {
        self.request
    }

    /// Returns the exact descriptor/request generation expected by this verifier.
    pub const fn request_generation(&self) -> ResourceGeneration {
        self.request_generation
    }

    /// Returns the exact completion cookie expected by this verifier.
    pub const fn completion_cookie(&self) -> u64 {
        self.completion_cookie
    }

    fn verify_completion(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &BlockUsedCompletionReceipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        // The queue and descriptor claims carry different members of the
        // completion tuple.  Checking each generation independently is not
        // enough: a generation-2 claim could otherwise be paired with a
        // generation-1 tuple while both the generic claim coordinates and
        // the verifier's tuple coordinates pass their individual checks.
        // The challenged claim class selects the typed tuple member, and the
        // selected member must carry the exact claim coordinate.  Do not
        // infer this role from an untyped ResourceId: a queue claim may be
        // admitted against the descriptor identity (or vice versa), and an
        // ID-based branch would accept that cross-role swap.
        let claim_tuple_matches = match challenge.claim_kind() {
            BLOCK_CLAIM_QUEUE_SLOT => {
                receipt.queue == challenge.resource()
                    && receipt.queue_generation == challenge.resource_generation()
            }
            BLOCK_CLAIM_DESCRIPTOR => {
                receipt.request == challenge.resource()
                    && receipt.request_generation == challenge.resource_generation()
            }
            _ => false,
        };
        if !matches!(challenge.scope(), ClaimScope::Device(_))
            || challenge.kind() != BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED
            || receipt.effect != challenge.effect()
            || receipt.claim != challenge.claim()
            || receipt.kind != challenge.kind()
            || receipt.resource != challenge.resource()
            || receipt.resource_generation != challenge.resource_generation()
            || receipt.subject != challenge.subject()
            || receipt.subject_binding != challenge.subject_binding()
            || receipt.observation != challenge.current_observation()
            || receipt.observation_binding != challenge.current_binding()
            || receipt.device_generation != challenge.subject().device()
            || receipt.device_generation != challenge.current_observation().device()
            || receipt.queue != self.queue
            || receipt.queue_generation != self.queue_generation
            || receipt.request != self.request
            || receipt.request_generation != self.request_generation
            || receipt.completion_cookie != self.completion_cookie
            || !claim_tuple_matches
            || receipt.digest.is_zero()
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new_bound(
            receipt.subject,
            receipt.subject_binding,
            receipt.observation,
            receipt.observation_binding,
            receipt.digest,
        ))
    }
}

impl ReceiptVerifier for BlockUsedCompletionVerifier {
    type Receipt = BlockUsedCompletionReceipt;

    fn identity(&self) -> VerifierIdentity {
        self.identity
    }

    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        self.verify_completion(challenge, receipt)
    }
}

fn block_freshness() -> FreshnessAxes {
    FreshnessAxes::BOOT
        .union(FreshnessAxes::REGISTRY)
        .union(FreshnessAxes::BINDING)
        .union(FreshnessAxes::DEVICE)
        .union(FreshnessAxes::JOURNAL)
}

fn logical_freshness() -> FreshnessAxes {
    FreshnessAxes::BOOT
        .union(FreshnessAxes::REGISTRY)
        .union(FreshnessAxes::BINDING)
        .union(FreshnessAxes::JOURNAL)
}

fn physical_obligation(
    kind: ObligationKindId,
    claims: &[ClaimCardinality],
) -> (ObligationSpec, &[ClaimCardinality]) {
    (
        ObligationSpec::new(
            THEKERNEL_BLOCK_DOMAIN,
            kind,
            ObligationPolicy::RetirementEvidence,
            AdoptionPolicy::UncommittedOnly,
            ObligationReceipts::retirement_only(ReceiptBinding::new(
                THEKERNEL_BLOCK_VERIFIER,
                BLOCK_COMMIT_RECEIPT_SCHEMA,
            )),
            1,
        ),
        claims,
    )
}

/// Returns the sealed TheKernel physical block-I/O catalog.
///
/// The catalog has two explicit products because the existing typed grammar
/// treats each claim's evidence list as one bounded conjunction.  The normal
/// product is selected for a request whose device contract supplies an exact
/// used-completion receipt.  The recovery product is selected for a request
/// settled through reset and drain evidence.  Both products bind every claim
/// to the exact component/provider generation at admission.  Normal
/// used-completion receipts are typed by [`BlockUsedCompletionReceipt`] and
/// verified through [`BlockUsedCompletionVerifier`], which authenticates the
/// request id, queue id and generation, descriptor/resource generation,
/// completion cookie, and same-generation subject/observation relation.
pub fn thekernel_physical_block_io_catalog() -> DomainCatalog {
    let block_subject = block_freshness();
    let block_observation = block_freshness();
    let logical = logical_freshness();
    let completion_receipt =
        ReceiptBinding::new(THEKERNEL_BLOCK_VERIFIER, BLOCK_COMPLETION_RECEIPT_SCHEMA);
    let used_completion = EvidenceRule::retirement(
        BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
        ReceiptBinding::new(
            THEKERNEL_BLOCK_VERIFIER,
            BLOCK_USED_COMPLETION_RECEIPT_SCHEMA,
        ),
        block_subject,
        block_observation,
        // This fact observes the enrolled generation; it does not advance a
        // device generation.  The typed `BlockUsedCompletionVerifier` enforces
        // the additional equality relation between the receipt's device
        // generation, enrolled subject, and active observation.  RESET remains
        // the only evidence which advances a device generation.
        FreshnessAxes::NONE,
        DeviceGenerationEffect::None,
        None,
    );
    let dma_unmapped = EvidenceRule::retirement(
        BLOCK_EVIDENCE_DMA_UNMAPPED,
        ReceiptBinding::new(THEKERNEL_BLOCK_VERIFIER, BLOCK_DMA_UNMAP_RECEIPT_SCHEMA),
        block_subject,
        block_observation,
        FreshnessAxes::NONE,
        DeviceGenerationEffect::None,
        None,
    );
    let reset = EvidenceRule::retirement(
        BLOCK_EVIDENCE_RESET,
        ReceiptBinding::new(THEKERNEL_BLOCK_VERIFIER, BLOCK_RECOVERY_RECEIPT_SCHEMA),
        block_subject,
        block_observation,
        FreshnessAxes::DEVICE,
        DeviceGenerationEffect::AdvanceOne,
        None,
    );
    let irq_drained = EvidenceRule::retirement(
        BLOCK_EVIDENCE_IRQ_DRAINED,
        ReceiptBinding::new(THEKERNEL_BLOCK_VERIFIER, BLOCK_RECOVERY_RECEIPT_SCHEMA),
        block_subject,
        block_observation,
        FreshnessAxes::NONE,
        DeviceGenerationEffect::None,
        Some(BLOCK_EVIDENCE_RESET),
    );
    let iotlb = EvidenceRule::retirement(
        BLOCK_EVIDENCE_IOTLB,
        ReceiptBinding::new(THEKERNEL_BLOCK_VERIFIER, BLOCK_RECOVERY_RECEIPT_SCHEMA),
        block_subject,
        block_observation,
        FreshnessAxes::NONE,
        DeviceGenerationEffect::None,
        Some(BLOCK_EVIDENCE_RESET),
    );
    let normal_queue_claims = [
        ClaimCardinality::new(BLOCK_CLAIM_QUEUE_SLOT, 1, 1)
            .expect("block queue cardinality is valid"),
        ClaimCardinality::new(BLOCK_CLAIM_DESCRIPTOR, 1, 1)
            .expect("block descriptor cardinality is valid"),
        ClaimCardinality::new(BLOCK_CLAIM_PINNED_PAGE, 1, 4)
            .expect("block pinned-page cardinality is valid"),
        ClaimCardinality::new(BLOCK_CLAIM_IOVA, 1, 4).expect("block IOVA cardinality is valid"),
    ];
    let recovery_queue_claims = [
        ClaimCardinality::new(BLOCK_CLAIM_RECOVERY_QUEUE_SLOT, 1, 1)
            .expect("block recovery queue cardinality is valid"),
        ClaimCardinality::new(BLOCK_CLAIM_RECOVERY_DESCRIPTOR, 1, 1)
            .expect("block recovery descriptor cardinality is valid"),
        ClaimCardinality::new(BLOCK_CLAIM_RECOVERY_PINNED_PAGE, 1, 4)
            .expect("block recovery pinned-page cardinality is valid"),
        ClaimCardinality::new(BLOCK_CLAIM_RECOVERY_IOVA, 1, 4)
            .expect("block recovery IOVA cardinality is valid"),
    ];
    let (normal_obligation, normal_claims) =
        physical_obligation(BLOCK_OBLIGATION_PHYSICAL_IO, &normal_queue_claims);
    let (recovery_obligation, recovery_claims) = physical_obligation(
        BLOCK_OBLIGATION_PHYSICAL_IO_RECOVERY,
        &recovery_queue_claims,
    );

    DomainCatalogBuilder::new()
        .credit_class(CREDIT_BLOCK_COMPLETION_SLOT, 1024)
        .expect("block completion credits are unique")
        .credit_class(CREDIT_BLOCK_QUEUE_SLOT, 4096)
        .expect("block queue credits are unique")
        .credit_class(CREDIT_BLOCK_DESCRIPTOR, 4096)
        .expect("block descriptor credits are unique")
        .credit_class(CREDIT_BLOCK_PINNED_PAGE, 1 << 20)
        .expect("block pinned-page credits are unique")
        .credit_class(CREDIT_BLOCK_IOVA, 1 << 20)
        .expect("block IOVA credits are unique")
        .obligation(
            ObligationSpec::new(
                THEKERNEL_BLOCK_DOMAIN,
                BLOCK_OBLIGATION_COMPLETION,
                ObligationPolicy::SuccessorSettlement,
                AdoptionPolicy::UncommittedOnly,
                ObligationReceipts::successor_settlement(
                    ReceiptBinding::new(THEKERNEL_BLOCK_VERIFIER, BLOCK_COMMIT_RECEIPT_SCHEMA),
                    ReceiptBinding::new(THEKERNEL_BLOCK_VERIFIER, BLOCK_APPLY_RECEIPT_SCHEMA),
                    ReceiptBinding::new(THEKERNEL_BLOCK_VERIFIER, BLOCK_SETTLEMENT_RECEIPT_SCHEMA),
                ),
                1,
            ),
            &[ClaimCardinality::new(BLOCK_CLAIM_COMPLETION, 1, 1)
                .expect("block completion cardinality is valid")],
        )
        .expect("block completion obligation is unique")
        .obligation(normal_obligation, normal_claims)
        .expect("normal block physical obligation is unique")
        .obligation(recovery_obligation, recovery_claims)
        .expect("recovery block physical obligation is unique")
        .claim(
            THEKERNEL_BLOCK_DOMAIN,
            BLOCK_CLAIM_COMPLETION,
            CREDIT_BLOCK_COMPLETION_SLOT,
            ClaimScopePolicy::Logical,
            &[EvidenceRule::logical(
                BLOCK_EVIDENCE_COMPLETION,
                completion_receipt,
                logical,
            )],
        )
        .expect("block completion claim is valid")
        .claim(
            THEKERNEL_BLOCK_DOMAIN,
            BLOCK_CLAIM_QUEUE_SLOT,
            CREDIT_BLOCK_QUEUE_SLOT,
            ClaimScopePolicy::Device,
            &[used_completion],
        )
        .expect("normal block queue claim is valid")
        .claim(
            THEKERNEL_BLOCK_DOMAIN,
            BLOCK_CLAIM_DESCRIPTOR,
            CREDIT_BLOCK_DESCRIPTOR,
            ClaimScopePolicy::Device,
            &[used_completion],
        )
        .expect("normal block descriptor claim is valid")
        .claim(
            THEKERNEL_BLOCK_DOMAIN,
            BLOCK_CLAIM_PINNED_PAGE,
            CREDIT_BLOCK_PINNED_PAGE,
            ClaimScopePolicy::Device,
            &[dma_unmapped],
        )
        .expect("normal block pinned-page claim is valid")
        .claim(
            THEKERNEL_BLOCK_DOMAIN,
            BLOCK_CLAIM_IOVA,
            CREDIT_BLOCK_IOVA,
            ClaimScopePolicy::Device,
            &[dma_unmapped],
        )
        .expect("normal block IOVA claim is valid")
        .claim(
            THEKERNEL_BLOCK_DOMAIN,
            BLOCK_CLAIM_RECOVERY_QUEUE_SLOT,
            CREDIT_BLOCK_QUEUE_SLOT,
            ClaimScopePolicy::Device,
            &[reset, irq_drained],
        )
        .expect("recovery block queue claim is valid")
        .claim(
            THEKERNEL_BLOCK_DOMAIN,
            BLOCK_CLAIM_RECOVERY_DESCRIPTOR,
            CREDIT_BLOCK_DESCRIPTOR,
            ClaimScopePolicy::Device,
            &[reset, irq_drained],
        )
        .expect("recovery block descriptor claim is valid")
        .claim(
            THEKERNEL_BLOCK_DOMAIN,
            BLOCK_CLAIM_RECOVERY_PINNED_PAGE,
            CREDIT_BLOCK_PINNED_PAGE,
            ClaimScopePolicy::Device,
            &[reset, iotlb],
        )
        .expect("recovery block pinned-page claim is valid")
        .claim(
            THEKERNEL_BLOCK_DOMAIN,
            BLOCK_CLAIM_RECOVERY_IOVA,
            CREDIT_BLOCK_IOVA,
            ClaimScopePolicy::Device,
            &[reset, iotlb],
        )
        .expect("recovery block IOVA claim is valid")
        .composite(
            THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE,
            &[
                CompositeComponentSpec::new(
                    THEKERNEL_BLOCK_COMPONENT_COMPLETION,
                    THEKERNEL_BLOCK_DOMAIN,
                    BLOCK_OBLIGATION_COMPLETION,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::NotRequired),
                CompositeComponentSpec::new(
                    THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
                    THEKERNEL_BLOCK_DOMAIN,
                    BLOCK_OBLIGATION_PHYSICAL_IO,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::NotRequired),
            ],
        )
        .expect("normal block composite is valid")
        .composite(
            THEKERNEL_PHYSICAL_BLOCK_IO_RECOVERY_COMPOSITE,
            &[
                CompositeComponentSpec::new(
                    THEKERNEL_BLOCK_COMPONENT_COMPLETION,
                    THEKERNEL_BLOCK_DOMAIN,
                    BLOCK_OBLIGATION_COMPLETION,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::NotRequired),
                CompositeComponentSpec::new(
                    THEKERNEL_BLOCK_COMPONENT_RECOVERY,
                    THEKERNEL_BLOCK_DOMAIN,
                    BLOCK_OBLIGATION_PHYSICAL_IO_RECOVERY,
                )
                .with_artifact_policy(RecoveryArtifactPolicy::NotRequired),
            ],
        )
        .expect("recovery block composite is valid")
        .build()
        .expect("TheKernel physical block-I/O catalog is internally complete")
}

/// Alias for [`thekernel_physical_block_io_catalog`].
pub fn thekernel_block_io_catalog() -> DomainCatalog {
    thekernel_physical_block_io_catalog()
}

/// Alias for [`thekernel_physical_block_io_catalog`].
pub fn thekernel_physical_block_io_profile() -> DomainCatalog {
    thekernel_physical_block_io_catalog()
}
