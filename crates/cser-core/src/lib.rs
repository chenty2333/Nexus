// SPDX-License-Identifier: MPL-2.0

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Portable authoritative implementation of the CSER semantic core.
//!
//! The core owns causal estates, authority fencing, settlement gates, typed
//! resource claims, bounded charging, journal records, and deterministic
//! recovery. It deliberately owns no task, device, wire, clock, or storage
//! implementation. Callers persist a prepared record before the core swaps its
//! candidate state.

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

/// Frozen semantic API profile established by the CSER Core vNext rebaseline.
/// slices both passed without an adapter-owned semantic escape hatch.
///
/// This is the transition/journal semantic compatibility coordinate, not a
/// Rust ABI promise. An incompatible transition or journal contract change
/// must advance this value and use a new journal schema or an explicit, tested
/// migration. Standard catalog grammar and validation evolve under the
/// separate [`STANDARD_CATALOG_VERSION`] coordinate and exact catalog digest;
/// recovery never reinterprets a journal bound to an older catalog digest.
pub const CSER_CORE_API_PROFILE_VERSION: u16 = 5;

/// Frozen standard catalog format used by semantic API profile 5.
pub const STANDARD_CATALOG_VERSION: u16 = 8;

/// Frozen deterministic projection format used by semantic API profile 5.
pub const PROJECTION_VERSION: u16 = 9;

/// Frozen recovery snapshot format used by semantic API profile 5.
pub const RECOVERY_SNAPSHOT_VERSION: u16 = 5;

/// Frozen normalized transition trace format used by semantic API profile 5.
pub const NORMALIZED_TRACE_VERSION: u16 = 3;

mod artifact;
mod authenticated_map;
mod domain;
mod engine;
mod identity;
mod journal;
mod persistence;
mod persistent_map;
mod profiles;

#[cfg(feature = "std")]
pub mod std_support;

pub use artifact::{
    ArtifactBinding, ArtifactLeaseState, ArtifactPinChallenge, ArtifactPinVerifier,
    ArtifactProtocolError, ArtifactReceiptBindings, ArtifactReleaseChallenge,
    ArtifactReleasePermit, ArtifactReleaseVerifier,
};
pub use domain::{
    AdoptionPolicy, ClaimCardinality, ClaimRule, ClaimScopePolicy, CompositeComponentSpec,
    CompositeRule, ConflictMode, CreditRule, DeviceGenerationEffect, DomainCatalog,
    DomainCatalogBuilder, DomainCatalogError, EvidenceCapability, EvidenceRecovery, EvidenceRule,
    EvidenceSubjectBinding, FreshnessAxes, LogicalClaimRole, ObligationPolicy, ObligationReceipts,
    ObligationRule, ObligationSpec, ReceiptBinding, RecoveryArtifactPolicy, SingleHopHandoffRule,
    VerifierBinding, VerifierClassBinding, VerifierSetError, canonical_verifier_set_digest,
    validate_verifier_set,
};
pub use engine::CHILD_DESCRIPTOR_V1_WIRE_LEN;
pub use engine::{
    ArtifactAdmission, ArtifactRecoveryItem, AuthorityState, ChargeProjection,
    ChildDescriptorDecodeError, ChildDescriptorV1, ChildDescriptorVerifier, ClaimCustodian,
    ClaimProjection, ClaimScope, ClaimUseError, Command, CommandDecodeError, CommandRequest,
    CommitIntent, CommitState, CommitUseError, ComponentClaimProjection,
    ComponentClaimRecoveryItem, ComponentCommitOperation, ComponentProjection,
    ComponentProviderBinding, ComponentRecoveryItem, CompositeEffectProjection,
    CompositeRecoveryItem, CoreError, CoreLimits, CustodyState, EffectEscapeState,
    EffectFactChallenge, EffectFactKind, EffectReceiptVerifier, Engine, EstateProjection,
    EvidenceChallenge, ExternalOutcome, HandoffChildResolutionVerifier, HandoffResolutionChallenge,
    HandoffResolutionVerifier, JournalFailure, OutcomeState, PressureProjection,
    ProviderEffectState, ProviderGenerationProjection, ProviderObligation,
    ProviderVerificationScope, ReceiptVerifier, RecoveryAnchor, RecoveryAnchorError,
    RecoveryEvidenceItem, RecoveryItem, RecoveryReport, RecoverySnapshot, RetirementState,
    ReusePermit, RootRecoveryState, SettlementClaim, SettlementState, SingleHopHandoffProjection,
    TransitionCoordinates, TransitionEvent, TransitionOutput, TransitionReceipt, TransitionResult,
    TxError, VerificationError, VerifiedApplyReceipt, VerifiedArtifactPin, VerifiedArtifactRelease,
    VerifiedChildDescriptor, VerifiedCommitOutcome, VerifiedEffectObservation,
    VerifiedHandoffChildResolution, VerifiedHandoffResolution, VerifiedObservation,
    VerifiedRetirementEvidence, VerifiedSettlementAck, VerifierIdentity, VerifierStamp,
};
pub use identity::{
    AuthorityBindingGeneration, BootGeneration, ChargeAccountId, ClaimId, ClaimKindId, ComponentId,
    CompositeKindId, CreditClassId, DeviceGeneration, DeviceScopeId, Digest, DomainId, EffectId,
    EvidenceKindId, Freshness, IdentityError, JournalGeneration, ObligationKindId, OperationId,
    PrincipalId, PrincipalIncarnation, ProviderCoordinate, ProviderGeneration, ProviderId,
    ReceiptSchemaId, RecoveryArtifactId, RegistryInstance, ResourceGeneration, ResourceId, RootId,
    SnapshotId, VerifierGeneration, VerifierId, WorldId,
};
pub use journal::{
    JOURNAL_CHECKPOINT_MAGIC, JOURNAL_CHECKPOINT_VERSION, JOURNAL_CORE_API_PROFILE, JOURNAL_MAGIC,
    JOURNAL_SCHEMA_VERSION, JournalCheckpoint, JournalCheckpointAnchor,
    JournalCheckpointDecodeError, JournalDecodeError, JournalRecord, JournalRepair, JournalScan,
    MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES, scan_journal, scan_journal_to_head,
};
pub use persistence::{
    CompactingJournalBackend, CoordinatedPersistence, CoordinatedPersistenceError,
    DurableJournalBackend, PersistenceProtocolError, RecoveryBinding, RecoveryLease,
    RecoveryProfile, TransitionDurability, TrustedAnchorBackend, TrustedAnchorSnapshot,
};
pub use profiles::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, CREDIT_IOVA,
    CREDIT_PINNED_PAGE, CREDIT_QUEUE_SLOT, CREDIT_REPLY_SLOT, CREDIT_TOOL_OUTCOME_SLOT,
    DEVICE_CLAIM_IOVA, DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT,
    DEVICE_COMMIT_RECEIPT_SCHEMA, DEVICE_DOMAIN, DEVICE_EVIDENCE_IOTLB,
    DEVICE_EVIDENCE_IRQ_DRAINED, DEVICE_EVIDENCE_RESET, DEVICE_OBLIGATION_DMA,
    DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, DMA_ARENA_REUSE_COMPOSITE,
    HARNESS_APPLY_RECEIPT_SCHEMA, HARNESS_CLAIM_ARTIFACT_CLOSURE, HARNESS_CLAIM_PROVIDER_OPERATION,
    HARNESS_CLAIM_QUEUED_JOB, HARNESS_CLAIM_RECOVERY_WORKER, HARNESS_CLAIM_REMOTE_IDEMPOTENCY_SLOT,
    HARNESS_CLAIM_REPLY_DELIVERY, HARNESS_CLAIM_RETAINED_PROVIDER_GENERATION,
    HARNESS_COMMIT_RECEIPT_SCHEMA, HARNESS_COMPONENT_ARTIFACT_CLOSURE,
    HARNESS_COMPONENT_PROVIDER_OPERATION, HARNESS_COMPONENT_QUEUED_JOB,
    HARNESS_COMPONENT_RECOVERY_WORKER, HARNESS_COMPONENT_REMOTE_IDEMPOTENCY_SLOT,
    HARNESS_COMPONENT_REPLY_DELIVERY, HARNESS_COMPONENT_RETAINED_PROVIDER_GENERATION,
    HARNESS_CREDIT_ARTIFACT_CLOSURE, HARNESS_CREDIT_PROVIDER_OPERATION, HARNESS_CREDIT_QUEUED_JOB,
    HARNESS_CREDIT_RECOVERY_WORKER, HARNESS_CREDIT_REMOTE_IDEMPOTENCY_SLOT,
    HARNESS_CREDIT_REPLY_DELIVERY, HARNESS_CREDIT_RETAINED_PROVIDER_GENERATION, HARNESS_DOMAIN,
    HARNESS_OBLIGATION_ARTIFACT_CLOSURE, HARNESS_OBLIGATION_PROVIDER_OPERATION,
    HARNESS_OBLIGATION_QUEUED_JOB, HARNESS_OBLIGATION_RECOVERY_WORKER,
    HARNESS_OBLIGATION_REMOTE_IDEMPOTENCY_SLOT, HARNESS_OBLIGATION_REPLY_DELIVERY,
    HARNESS_OBLIGATION_RETAINED_PROVIDER_GENERATION, HARNESS_OPERATION_COMPOSITE,
    HARNESS_RECEIPT_SCHEMA, HARNESS_SETTLEMENT_RECEIPT_SCHEMA, HARNESS_VERIFIER,
    REPLY_APPLY_RECEIPT_SCHEMA, REPLY_CLAIM_PUBLICATION_SLOT, REPLY_COMMIT_RECEIPT_SCHEMA,
    REPLY_DOMAIN, REPLY_EVIDENCE_PUBLICATION_ACK, REPLY_OBLIGATION_PUBLICATION,
    REPLY_RECEIPT_SCHEMA, REPLY_SETTLEMENT_RECEIPT_SCHEMA, REPLY_VERIFIER,
    TOOL_APPLY_RECEIPT_SCHEMA, TOOL_CLAIM_OUTCOME_SLOT, TOOL_COMMIT_RECEIPT_SCHEMA,
    TOOL_DMA_COMPONENT_DMA, TOOL_DMA_COMPONENT_TOOL, TOOL_DMA_OPERATION_COMPOSITE, TOOL_DOMAIN,
    TOOL_EVIDENCE_OUTCOME_ACK, TOOL_HANDOFF_CHILD_COMPOSITE, TOOL_HANDOFF_COMPONENT,
    TOOL_HANDOFF_SOURCE_COMPONENT, TOOL_HANDOFF_SOURCE_COMPOSITE, TOOL_OBLIGATION_INVOCATION,
    TOOL_RECEIPT_SCHEMA, TOOL_SETTLEMENT_RECEIPT_SCHEMA, TOOL_VERIFIER, harness_catalog,
    standard_catalog, tool_dma_catalog,
};
