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

mod domain;
mod engine;
mod identity;
mod journal;
mod persistence;
mod profiles;

#[cfg(feature = "std")]
pub mod std_support;

pub use domain::{
    AdoptionPolicy, ClaimCardinality, ClaimRule, ClaimScopePolicy, CreditRule,
    DeviceGenerationEffect, DomainCatalog, DomainCatalogBuilder, DomainCatalogError, EvidenceRule,
    EvidenceSubjectBinding, FreshnessAxes, ObligationPolicy, ObligationReceipts, ObligationRule,
    ObligationSpec, ReceiptBinding,
};
pub use engine::{
    AuthorityState, ChargeProjection, ClaimScope, ClaimUseError, Command, CommandDecodeError,
    CommandRequest, CommitIntent, CommitState, CommitUseError, CoreError, CoreLimits, CustodyState,
    EffectFactChallenge, EffectFactKind, EffectReceiptVerifier, Engine, EstateProjection,
    EvidenceChallenge, ExternalOutcome, JournalFailure, OutcomeState, PressureProjection,
    ReceiptVerifier, RecoveryAnchor, RecoveryAnchorError, RecoveryItem, RecoveryReport,
    RecoverySnapshot, RetirementState, ReusePermit, RootRecoveryState, SettlementClaim,
    SettlementState, TransitionEvent, TransitionOutput, TransitionReceipt, TxError,
    VerificationError, VerifiedApplyReceipt, VerifiedCommitOutcome, VerifiedEffectObservation,
    VerifiedObservation, VerifiedRetirementEvidence, VerifiedSettlementAck, VerifierIdentity,
    VerifierStamp,
};
pub use identity::{
    BootGeneration, ChargeAccountId, ClaimId, ClaimKindId, CreditClassId, DeviceGeneration,
    DeviceScopeId, Digest, DomainId, EffectId, EvidenceKindId, Freshness, IdentityError,
    JournalGeneration, ObligationKindId, PrincipalId, PrincipalIncarnation, ReceiptSchemaId,
    RegistryInstance, ResourceGeneration, ResourceId, RootId, SnapshotId, VerifierId,
};
pub use journal::{
    JOURNAL_MAGIC, JOURNAL_SCHEMA_VERSION, JournalDecodeError, JournalRecord, JournalRepair,
    JournalScan, scan_journal, scan_journal_to_head,
};
pub use persistence::{
    CoordinatedPersistence, CoordinatedPersistenceError, DurableJournalBackend,
    PersistenceProtocolError, RecoveryBinding, RecoveryLease, TransitionDurability,
    TrustedAnchorBackend, TrustedAnchorSnapshot,
};
pub use profiles::{
    CREDIT_IOVA, CREDIT_PINNED_PAGE, CREDIT_QUEUE_SLOT, CREDIT_REPLY_SLOT, DEVICE_CLAIM_IOVA,
    DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT, DEVICE_COMMIT_RECEIPT_SCHEMA, DEVICE_DOMAIN,
    DEVICE_EVIDENCE_IOTLB, DEVICE_EVIDENCE_IRQ_DRAINED, DEVICE_EVIDENCE_RESET,
    DEVICE_OBLIGATION_DMA, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, REPLY_APPLY_RECEIPT_SCHEMA,
    REPLY_CLAIM_PUBLICATION_SLOT, REPLY_COMMIT_RECEIPT_SCHEMA, REPLY_DOMAIN,
    REPLY_EVIDENCE_PUBLICATION_ACK, REPLY_OBLIGATION_PUBLICATION, REPLY_RECEIPT_SCHEMA,
    REPLY_SETTLEMENT_RECEIPT_SCHEMA, REPLY_VERIFIER, standard_catalog,
};
