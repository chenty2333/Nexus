// SPDX-License-Identifier: MPL-2.0

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Portable authoritative implementation of the CSER semantic core.
//!
//! The core owns causal effects, authority fencing, settlement gates, typed
//! resource claims, bounded charging, journal records, and deterministic
//! recovery. It deliberately owns no task, device, wire, clock, or storage
//! implementation. Callers persist a prepared record before the core publishes
//! the resulting authoritative state.

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

/// Frozen semantic API profile for the current CSER Core grammar.
///
/// This is the transition/journal semantic compatibility coordinate, not a
/// Rust ABI promise. An incompatible transition or journal contract change
/// must advance this value and use a new journal schema or an explicit, tested
/// migration. Standard catalog grammar and validation evolve under the
/// separate [`STANDARD_CATALOG_VERSION`] coordinate and exact catalog digest;
/// recovery never reinterprets a journal bound to an older catalog digest.
pub const CSER_CORE_API_PROFILE_VERSION: u16 = 6;

/// Frozen standard catalog format used by the current semantic API profile.
pub const STANDARD_CATALOG_VERSION: u16 = 8;

/// Frozen deterministic projection format used by the current semantic API profile.
pub const PROJECTION_VERSION: u16 = 10;

/// Frozen recovery snapshot format used by the current semantic API profile.
pub const RECOVERY_SNAPSHOT_VERSION: u16 = 6;

/// Frozen normalized transition trace format used by the current semantic API profile.
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
#[path = "recovery_source.rs"]
pub mod recovery_source;
mod thekernel_physical_block;

#[cfg(feature = "std")]
pub mod std_support;

pub use artifact::{
    ArtifactBinding, ArtifactLeaseState, ArtifactPinChallenge, ArtifactPinVerifier,
    ArtifactProtocolError, ArtifactReceiptBindings, ArtifactReleaseChallenge,
    ArtifactReleasePermit, ArtifactReleaseVerifier,
};
pub use domain::{
    AdoptionPolicy, CatalogSet, CatalogSetError, ClaimCardinality, ClaimRule, ClaimScopePolicy,
    CompositeComponentSpec, CompositeRule, ConflictMode, CreditRule, DeviceGenerationEffect,
    DomainCatalog, DomainCatalogBuilder, DomainCatalogError, EvidenceCapability, EvidenceRecovery,
    EvidenceRule, EvidenceSubjectBinding, FreshnessAxes, LogicalClaimRole,
    MAX_CATALOG_SET_CATALOGS, ObligationPolicy, ObligationReceipts, ObligationRule, ObligationSpec,
    ReceiptBinding, RecoveryArtifactPolicy, SingleHopHandoffRule, VerifierBinding,
    VerifierClassBinding, VerifierSetError, canonical_verifier_set_digest, validate_verifier_set,
};
pub use engine::{
    ArtifactAdmission, ArtifactRecoveryItem, AuthorityState, ChargeProjection, CheckpointAnchor,
    CheckpointRecordPlan, CheckpointSnapshot, CheckpointWrite, ChildDescriptorDecodeError,
    ChildDescriptorV1, ChildDescriptorVerifier, ClaimCustodian, ClaimProjection, ClaimScope,
    ClaimUseError, Command, CommandDecodeError, CommandRequest, CommitIntent, CommitState,
    CommitUseError, ComponentClaimProjection, ComponentClaimRecoveryItem, ComponentCommitOperation,
    ComponentProjection, ComponentProviderBinding, ComponentRecoveryItem,
    CompositeEffectProjection, CompositeRecoveryItem, CoreError, CoreLimits, CustodyState,
    DurablePreparedCheckpoint, EffectEscapeState, EffectFactChallenge, EffectFactKind,
    EffectReceiptVerifier, Engine, EvidenceChallenge, ExternalOutcome,
    HandoffChildResolutionVerifier, HandoffResolutionChallenge, HandoffResolutionVerifier,
    HistoryLimits, JournalFailure, OperationRecoveryState, OutcomeState, PreparedCheckpoint,
    PressureProjection, ProviderEffectState, ProviderGenerationProjection, ProviderObligation,
    ProviderVerificationScope, ReceiptVerifier, RecoveryAnchor, RecoveryAnchorError,
    RecoveryEvidenceItem, RecoveryFromSourceError, RecoveryReport, RecoverySnapshot,
    RetirementState, ReusePermit, SettlementClaim, SettlementState, SingleHopHandoffProjection,
    TransitionCoordinates, TransitionEvent, TransitionOutput, TransitionReceipt, TransitionResult,
    TxError, VerificationError, VerifiedApplyReceipt, VerifiedArtifactPin, VerifiedArtifactRelease,
    VerifiedChildDescriptor, VerifiedCommitOutcome, VerifiedEffectObservation,
    VerifiedHandoffChildResolution, VerifiedHandoffResolution, VerifiedObservation,
    VerifiedRetirementEvidence, VerifiedSettlementAck, VerifierIdentity, VerifierStamp,
};
pub use engine::{
    CHILD_DESCRIPTOR_V1_WIRE_LEN, MAX_COMMAND_PAYLOAD_BYTES, MAX_COMMAND_VECTOR_ITEMS,
};
pub use identity::{
    BootGeneration, ChargeAccountId, ClaimId, ClaimKindId, ComponentId, CompositeKindId,
    CreditClassId, DeviceGeneration, DeviceScopeId, Digest, DomainId, EffectId, EvidenceKindId,
    ExecutorCoordinate, ExecutorGeneration, ExecutorId, Freshness, IdentityError,
    JournalGeneration, ObligationKindId, OperationId, ProviderCoordinate, ProviderGeneration,
    ProviderId, ReceiptSchemaId, RecoveryArtifactId, RegistryInstance, ResourceGeneration,
    ResourceId, SnapshotId, VerifierGeneration, VerifierId, WorldId,
};
pub use journal::{
    JOURNAL_CHECKPOINT_MAGIC, JOURNAL_CHECKPOINT_VERSION, JOURNAL_CORE_API_PROFILE, JOURNAL_MAGIC,
    JOURNAL_SCHEMA_VERSION, JournalCheckpoint, JournalCheckpointAnchor,
    JournalCheckpointDecodeError, JournalDecodeError, JournalRecord, JournalRepair, JournalScan,
    MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES, scan_journal, scan_journal_to_head,
};
pub use persistence::{
    CheckpointDurability, CompactingJournalBackend, CoordinatedPersistence,
    CoordinatedPersistenceError, DurableJournalBackend, PersistenceProtocolError, RecoveryBinding,
    RecoveryLease, RecoveryProfile, StreamingJournalBackend, TransitionDurability,
    TrustedAnchorBackend, TrustedAnchorSnapshot,
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
pub use recovery_source::{JournalRecoverySource, RecoverySourceSnapshot};
pub use thekernel_physical_block::{
    BLOCK_APPLY_RECEIPT_SCHEMA, BLOCK_CLAIM_COMPLETION, BLOCK_CLAIM_DESCRIPTOR,
    BLOCK_CLAIM_DESCRIPTOR_REQUEST, BLOCK_CLAIM_IOVA, BLOCK_CLAIM_PINNED_PAGE,
    BLOCK_CLAIM_QUEUE_SLOT, BLOCK_CLAIM_RECOVERY_DESCRIPTOR,
    BLOCK_CLAIM_RECOVERY_DESCRIPTOR_REQUEST, BLOCK_CLAIM_RECOVERY_IOVA,
    BLOCK_CLAIM_RECOVERY_PINNED_PAGE, BLOCK_CLAIM_RECOVERY_QUEUE_SLOT, BLOCK_CLAIM_REQUEST,
    BLOCK_COMMIT_RECEIPT_SCHEMA, BLOCK_COMPLETION_RECEIPT_SCHEMA, BLOCK_DMA_UNMAP_RECEIPT_SCHEMA,
    BLOCK_EVIDENCE_COMPLETION, BLOCK_EVIDENCE_DMA_UNMAP, BLOCK_EVIDENCE_DMA_UNMAPPED,
    BLOCK_EVIDENCE_IOTLB, BLOCK_EVIDENCE_IRQ_DRAINED, BLOCK_EVIDENCE_RESET,
    BLOCK_EVIDENCE_USED_COMPLETION, BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
    BLOCK_OBLIGATION_COMPLETION, BLOCK_OBLIGATION_PHYSICAL_IO,
    BLOCK_OBLIGATION_PHYSICAL_IO_RECOVERY, BLOCK_RECEIPT_SCHEMA, BLOCK_RECOVERY_RECEIPT_SCHEMA,
    BLOCK_SETTLEMENT_RECEIPT_SCHEMA, BLOCK_USED_COMPLETION_RECEIPT_SCHEMA, BLOCK_VERIFIER,
    BlockUsedCompletionReceipt, BlockUsedCompletionVerifier, CREDIT_BLOCK_COMPLETION_SLOT,
    CREDIT_BLOCK_PINNED_PAGE, CREDIT_BLOCK_QUEUE_SLOT, THEKERNEL_BLOCK_COMPLETION_CREDIT,
    THEKERNEL_BLOCK_COMPONENT_COMPLETION, THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
    THEKERNEL_BLOCK_COMPONENT_RECOVERY, THEKERNEL_BLOCK_DESCRIPTOR_CREDIT, THEKERNEL_BLOCK_DOMAIN,
    THEKERNEL_BLOCK_IO_COMPOSITE, THEKERNEL_BLOCK_IO_RECOVERY_COMPOSITE,
    THEKERNEL_BLOCK_IO_VERIFIER, THEKERNEL_BLOCK_IOVA_CREDIT, THEKERNEL_BLOCK_PINNED_PAGE_CREDIT,
    THEKERNEL_BLOCK_QUEUE_CREDIT, THEKERNEL_BLOCK_VERIFIER, THEKERNEL_PHYSICAL_BLOCK_IO_COMPONENT,
    THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE, THEKERNEL_PHYSICAL_BLOCK_IO_DOMAIN,
    THEKERNEL_PHYSICAL_BLOCK_IO_PROFILE, THEKERNEL_PHYSICAL_BLOCK_IO_RECOVERY_COMPOSITE,
    thekernel_block_io_catalog, thekernel_physical_block_io_catalog,
    thekernel_physical_block_io_profile,
};
