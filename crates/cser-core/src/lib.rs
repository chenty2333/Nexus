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

/// Frozen semantic API profile established after the reply and DMA domain
/// slices both passed without an adapter-owned semantic escape hatch.
///
/// This is a source and durable-semantics compatibility coordinate, not a Rust
/// ABI promise. An incompatible public contract change must advance this value
/// and use a new journal schema or an explicit, tested migration.
pub const CSER_CORE_API_PROFILE_VERSION: u16 = 2;

/// Frozen standard catalog format used by semantic API profile 2.
pub const STANDARD_CATALOG_VERSION: u16 = 6;

/// Frozen deterministic projection format used by semantic API profile 2.
pub const PROJECTION_VERSION: u16 = 6;

/// Frozen recovery snapshot format used by semantic API profile 2.
pub const RECOVERY_SNAPSHOT_VERSION: u16 = 2;

/// Frozen normalized transition trace format used by semantic API profile 2.
pub const NORMALIZED_TRACE_VERSION: u16 = 2;

mod domain;
mod engine;
mod identity;
mod journal;
mod persistence;
mod profiles;

#[cfg(feature = "std")]
pub mod std_support;

pub use domain::{
    AdoptionPolicy, ClaimCardinality, ClaimRule, ClaimScopePolicy, CompositeComponentSpec,
    CompositeRule, CreditRule, DeviceGenerationEffect, DomainCatalog, DomainCatalogBuilder,
    DomainCatalogError, EvidenceCapability, EvidenceRecovery, EvidenceRule, EvidenceSubjectBinding,
    FreshnessAxes, ObligationPolicy, ObligationReceipts, ObligationRule, ObligationSpec,
    ReceiptBinding,
};
pub use engine::{
    AuthorityState, ChargeProjection, ClaimCustodian, ClaimProjection, ClaimScope, ClaimUseError,
    Command, CommandDecodeError, CommandRequest, CommitIntent, CommitState, CommitUseError,
    ComponentClaimProjection, ComponentClaimRecoveryItem, ComponentCommitOperation,
    ComponentProjection, ComponentRecoveryItem, CompositeEffectProjection, CompositeRecoveryItem,
    CoreError, CoreLimits, CustodyState, EffectEscapeState, EffectFactChallenge, EffectFactKind,
    EffectReceiptVerifier, Engine, EstateProjection, EvidenceChallenge, ExternalOutcome,
    JournalFailure, OutcomeState, PressureProjection, ReceiptVerifier, RecoveryAnchor,
    RecoveryAnchorError, RecoveryEvidenceItem, RecoveryItem, RecoveryReport, RecoverySnapshot,
    RetirementState, ReusePermit, RootRecoveryState, SettlementClaim, SettlementState,
    TransitionCoordinates, TransitionEvent, TransitionOutput, TransitionReceipt, TransitionResult,
    TxError, VerificationError, VerifiedApplyReceipt, VerifiedCommitOutcome,
    VerifiedEffectObservation, VerifiedObservation, VerifiedRetirementEvidence,
    VerifiedSettlementAck, VerifierIdentity, VerifierStamp,
};
pub use identity::{
    BootGeneration, ChargeAccountId, ClaimId, ClaimKindId, ComponentId, CompositeKindId,
    CreditClassId, DeviceGeneration, DeviceScopeId, Digest, DomainId, EffectId, EvidenceKindId,
    Freshness, IdentityError, JournalGeneration, ObligationKindId, PrincipalId,
    PrincipalIncarnation, ReceiptSchemaId, RegistryInstance, ResourceGeneration, ResourceId,
    RootId, SnapshotId, VerifierId,
};
pub use journal::{
    JOURNAL_CORE_API_PROFILE, JOURNAL_MAGIC, JOURNAL_SCHEMA_VERSION, JournalDecodeError,
    JournalRecord, JournalRepair, JournalScan, scan_journal, scan_journal_to_head,
};
pub use persistence::{
    CoordinatedPersistence, CoordinatedPersistenceError, DurableJournalBackend,
    PersistenceProtocolError, RecoveryBinding, RecoveryLease, TransitionDurability,
    TrustedAnchorBackend, TrustedAnchorSnapshot,
};
pub use profiles::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, CREDIT_IOVA,
    CREDIT_PINNED_PAGE, CREDIT_QUEUE_SLOT, CREDIT_REPLY_SLOT, DEVICE_CLAIM_IOVA,
    DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT, DEVICE_COMMIT_RECEIPT_SCHEMA, DEVICE_DOMAIN,
    DEVICE_EVIDENCE_IOTLB, DEVICE_EVIDENCE_IRQ_DRAINED, DEVICE_EVIDENCE_RESET,
    DEVICE_OBLIGATION_DMA, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, DMA_ARENA_REUSE_COMPOSITE,
    REPLY_APPLY_RECEIPT_SCHEMA, REPLY_CLAIM_PUBLICATION_SLOT, REPLY_COMMIT_RECEIPT_SCHEMA,
    REPLY_DOMAIN, REPLY_EVIDENCE_PUBLICATION_ACK, REPLY_OBLIGATION_PUBLICATION,
    REPLY_RECEIPT_SCHEMA, REPLY_SETTLEMENT_RECEIPT_SCHEMA, REPLY_VERIFIER, standard_catalog,
};
