//! Bounded system-wide CSER composition reference model.
//!
//! The model composes five independently restartable domains beneath one
//! root authority scope.  It deliberately keeps domain-owned policy out of
//! the coordinator: global state contains only causal identities, typed
//! credit transfers, authority fencing, per-domain binding generations,
//! device-generation fencing for mediated VirtIO, and exact closure receipts.
//! Runtime filesystems and networking are not modeled here.
//!
//! This executable model strengthens the bounded TLA+ root-ledger abstraction
//! with parent-owned credit partitions: deriving a child subtracts the exact
//! bundle from its parent, and child terminalization returns that same bundle
//! up the causal edge.  The property tests below exercise this refinement; it
//! must not be presented as a property already proved by the TLA+ bound.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{EffectId, ScopeId, ScopeState};

mod helpers;
mod operations;
mod queries;

macro_rules! scalar_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            /// Constructs a value from its numeric representation.
            #[must_use]
            pub const fn new(raw: u64) -> Self {
                Self(raw)
            }

            /// Returns the numeric representation.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }
        }
    };
}

scalar_type!(
    /// Root authority generation advanced only by root revocation.
    AuthorityEpoch
);
scalar_type!(
    /// Restart generation advanced independently for one service domain.
    BindingEpoch
);
scalar_type!(
    /// VirtIO device generation advanced only after acknowledged quiescence.
    DeviceGeneration
);
scalar_type!(
    /// Stable identity of one user-space service instance.
    ServiceId
);
scalar_type!(
    /// Stable identity of one retained timeout obligation.
    TombstoneId
);

/// The five bounded domains composed by this prototype.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DomainId {
    /// User-space scheduling policy and its kernel fallback.
    Scheduler,
    /// User-space pager and one-shot fault continuations.
    Pager,
    /// Linux personality syscall and exec effects.
    Personality,
    /// Readiness subscriptions, waits, deliveries, and timers.
    Readiness,
    /// Mediated VirtIO queue, DMA, reset, and invalidation effects.
    VirtIo,
}

impl DomainId {
    /// Deterministic complete domain set used by bounded integration tests.
    pub const ALL: [Self; 5] = [
        Self::Scheduler,
        Self::Pager,
        Self::Personality,
        Self::Readiness,
        Self::VirtIo,
    ];

    /// Returns whether this domain is fenced by a device generation.
    #[must_use]
    pub const fn has_device_generation(self) -> bool {
        matches!(self, Self::VirtIo)
    }
}

/// Semantic label for a composed effect.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CompositionEffectKind {
    /// One scheduler-policy decision or fallback obligation.
    SchedulerAction,
    /// One pager fault continuation or mapping obligation.
    PagerFault,
    /// One personality syscall or exec obligation.
    PersonalitySyscall,
    /// One readiness wait, delivery, subscription, or timer obligation.
    ReadinessWait,
    /// One mediated VirtIO request and its DMA ownership.
    VirtIoRequest,
}

impl CompositionEffectKind {
    /// Returns the only domain allowed to own this effect kind.
    #[must_use]
    pub const fn domain(self) -> DomainId {
        match self {
            Self::SchedulerAction => DomainId::Scheduler,
            Self::PagerFault => DomainId::Pager,
            Self::PersonalitySyscall => DomainId::Personality,
            Self::ReadinessWait => DomainId::Readiness,
            Self::VirtIoRequest => DomainId::VirtIo,
        }
    }
}

/// Independently conserved resource credits transferred along causal edges.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CreditBundle {
    cpu_quanta: u64,
    frames: u64,
    continuations: u64,
    queue_slots: u64,
    pinned_pages: u64,
    dma_bytes: u64,
}

impl CreditBundle {
    /// A bundle containing no credits.
    pub const ZERO: Self = Self::new(0, 0, 0, 0, 0, 0);

    /// Constructs one typed credit bundle.
    #[must_use]
    pub const fn new(
        cpu_quanta: u64,
        frames: u64,
        continuations: u64,
        queue_slots: u64,
        pinned_pages: u64,
        dma_bytes: u64,
    ) -> Self {
        Self {
            cpu_quanta,
            frames,
            continuations,
            queue_slots,
            pinned_pages,
            dma_bytes,
        }
    }

    /// Returns CPU-time credits.
    #[must_use]
    pub const fn cpu_quanta(self) -> u64 {
        self.cpu_quanta
    }

    /// Returns prepared-frame credits.
    #[must_use]
    pub const fn frames(self) -> u64 {
        self.frames
    }

    /// Returns one-shot continuation credits.
    #[must_use]
    pub const fn continuations(self) -> u64 {
        self.continuations
    }

    /// Returns mediated queue-slot credits.
    #[must_use]
    pub const fn queue_slots(self) -> u64 {
        self.queue_slots
    }

    /// Returns pinned-page credits.
    #[must_use]
    pub const fn pinned_pages(self) -> u64 {
        self.pinned_pages
    }

    /// Returns DMA-byte credits.
    #[must_use]
    pub const fn dma_bytes(self) -> u64 {
        self.dma_bytes
    }

    /// Returns whether every component is zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.cpu_quanta == 0
            && self.frames == 0
            && self.continuations == 0
            && self.queue_slots == 0
            && self.pinned_pages == 0
            && self.dma_bytes == 0
    }

    const fn contains(self, requested: Self) -> bool {
        self.cpu_quanta >= requested.cpu_quanta
            && self.frames >= requested.frames
            && self.continuations >= requested.continuations
            && self.queue_slots >= requested.queue_slots
            && self.pinned_pages >= requested.pinned_pages
            && self.dma_bytes >= requested.dma_bytes
    }

    fn checked_sub(self, other: Self) -> Result<Self, CompositionError> {
        if !self.contains(other) {
            return Err(CompositionError::CreditExhausted);
        }
        Ok(Self::new(
            self.cpu_quanta - other.cpu_quanta,
            self.frames - other.frames,
            self.continuations - other.continuations,
            self.queue_slots - other.queue_slots,
            self.pinned_pages - other.pinned_pages,
            self.dma_bytes - other.dma_bytes,
        ))
    }

    fn checked_add(self, other: Self) -> Result<Self, CompositionError> {
        Ok(Self::new(
            self.cpu_quanta
                .checked_add(other.cpu_quanta)
                .ok_or(CompositionError::CounterOverflow)?,
            self.frames
                .checked_add(other.frames)
                .ok_or(CompositionError::CounterOverflow)?,
            self.continuations
                .checked_add(other.continuations)
                .ok_or(CompositionError::CounterOverflow)?,
            self.queue_slots
                .checked_add(other.queue_slots)
                .ok_or(CompositionError::CounterOverflow)?,
            self.pinned_pages
                .checked_add(other.pinned_pages)
                .ok_or(CompositionError::CounterOverflow)?,
            self.dma_bytes
                .checked_add(other.dma_bytes)
                .ok_or(CompositionError::CounterOverflow)?,
        ))
    }
}

/// Lifecycle of one composed effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositionEffectState {
    /// Authority and typed credits are held, but no commit is prepared.
    Registered,
    /// The effect is ready to cross its domain commit point.
    Prepared,
    /// The domain commit point was crossed and has an immutable receipt.
    Committed,
    /// The committed obligation completed exactly once.
    Completed,
    /// Root closure aborted an uncommitted obligation exactly once.
    Aborted,
    /// A committed external effect and its credits remain live behind a tombstone.
    Tombstoned,
}

impl CompositionEffectState {
    /// Returns whether the effect has one immutable terminal outcome.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

/// Kernel fallback and replacement-handshake state for one domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainFallbackState {
    /// A live service is bound.
    Standby,
    /// A crash was fenced and kernel fallback selection is required.
    Required,
    /// Kernel fallback is active and may capture an exact snapshot.
    Running,
    /// An exact snapshot was accepted for one replacement.
    ReplacementReady,
}

/// Authenticated proof of one current domain binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainBindingToken {
    scope: ScopeId,
    domain: DomainId,
    service: ServiceId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    device_generation: DeviceGeneration,
}

impl DomainBindingToken {
    /// Returns the root scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the independently restartable domain.
    #[must_use]
    pub const fn domain(self) -> DomainId {
        self.domain
    }

    /// Returns the bound service identity.
    #[must_use]
    pub const fn service(self) -> ServiceId {
        self.service
    }

    /// Returns the captured root authority generation.
    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the captured per-domain service generation.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.binding_epoch
    }

    /// Returns the captured device generation.
    #[must_use]
    pub const fn device_generation(self) -> DeviceGeneration {
        self.device_generation
    }
}

/// Complete identity of one effect in the global causal graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositionEffectToken {
    scope: ScopeId,
    effect: EffectId,
    parent: Option<EffectId>,
    domain: DomainId,
    kind: CompositionEffectKind,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    device_generation: DeviceGeneration,
}

impl CompositionEffectToken {
    /// Returns the root scope inherited by this effect.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the globally stable effect identity.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the immutable causal parent, or `None` for a root effect.
    #[must_use]
    pub const fn parent(self) -> Option<EffectId> {
        self.parent
    }

    /// Returns the domain owning the local refinement.
    #[must_use]
    pub const fn domain(self) -> DomainId {
        self.domain
    }

    /// Returns the semantic effect label.
    #[must_use]
    pub const fn kind(self) -> CompositionEffectKind {
        self.kind
    }

    /// Returns the captured root authority generation.
    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the captured owning-domain binding generation.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.binding_epoch
    }

    /// Returns the captured VirtIO device generation.
    #[must_use]
    pub const fn device_generation(self) -> DeviceGeneration {
        self.device_generation
    }
}

/// Immutable receipt for one successful domain commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositionCommitReceipt {
    token: CompositionEffectToken,
    sequence: u64,
}

impl CompositionCommitReceipt {
    /// Returns the committed effect.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.token.effect
    }

    /// Returns the exact identity at the commit point.
    #[must_use]
    pub const fn token(self) -> CompositionEffectToken {
        self.token
    }

    /// Returns the global commit sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// One effect captured by an exact domain recovery snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryEffectSnapshot {
    /// Exact pre-adoption effect identity.
    pub token: CompositionEffectToken,
    /// Lifecycle state observed by the fallback.
    pub state: CompositionEffectState,
}

/// Exact domain-local recovery view for one prospective replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainRecoverySnapshot {
    scope: ScopeId,
    domain: DomainId,
    replacement: ServiceId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    device_generation: DeviceGeneration,
    mutation_generation: u64,
    effects: Vec<RecoveryEffectSnapshot>,
    adoption_cohort: Vec<EffectId>,
}

impl DomainRecoverySnapshot {
    /// Returns the root scope represented by the snapshot.
    #[must_use]
    pub const fn scope(&self) -> ScopeId {
        self.scope
    }

    /// Returns the captured domain.
    #[must_use]
    pub const fn domain(&self) -> DomainId {
        self.domain
    }

    /// Returns the prospective replacement service.
    #[must_use]
    pub const fn replacement(&self) -> ServiceId {
        self.replacement
    }

    /// Returns deterministic domain-local live effects.
    #[must_use]
    pub fn effects(&self) -> &[RecoveryEffectSnapshot] {
        &self.effects
    }

    /// Returns effects requiring explicit adoption.
    #[must_use]
    pub fn adoption_cohort(&self) -> &[EffectId] {
        &self.adoption_cohort
    }
}

/// Opaque proof that an exact recovery snapshot was accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainReadyToken {
    scope: ScopeId,
    domain: DomainId,
    replacement: ServiceId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    device_generation: DeviceGeneration,
    mutation_generation: u64,
}

/// Exact root-revocation generation and frozen authority epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootRevokeTicket {
    scope: ScopeId,
    closed_epoch: AuthorityEpoch,
    generation: u64,
}

impl RootRevokeTicket {
    /// Returns the closing root scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the authority generation closed at the linearization point.
    #[must_use]
    pub const fn closed_epoch(self) -> AuthorityEpoch {
        self.closed_epoch
    }

    /// Returns the scope-local revoke generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Result of one domain-local reverse-index closure selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainCloseStep {
    /// One uncommitted leaf effect was aborted.
    Aborted(EffectId),
    /// One committed in-memory leaf effect was drained and completed.
    Completed(EffectId),
    /// One committed external effect requires completion or a tombstone.
    NeedsQuiescence(EffectId),
    /// Every local effect still has a live child in another domain.
    BlockedByDescendants {
        /// Domain-local effects waiting for child terminal receipts.
        remaining: usize,
    },
}

/// Exact closure outcome reported by one frozen domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClosureStatus {
    /// The domain has no live effects or retained obligations.
    Closed,
    /// External ownership remains retained behind timeout tombstones.
    TimedOut {
        /// Exact retained tombstones.
        tombstones: Vec<TombstoneId>,
        /// Typed credits retained by those tombstones.
        retained_credits: CreditBundle,
    },
}

/// Opaque, exact, replay-protected domain closure receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainClosureReceipt {
    ticket: RootRevokeTicket,
    domain: DomainId,
    revision: u64,
    sequence: u64,
    binding_epoch: BindingEpoch,
    device_generation: DeviceGeneration,
    status: ClosureStatus,
}

impl DomainClosureReceipt {
    /// Returns the reporting domain.
    #[must_use]
    pub const fn domain(&self) -> DomainId {
        self.domain
    }

    /// Returns the root revoke ticket bound to this receipt.
    #[must_use]
    pub const fn ticket(&self) -> RootRevokeTicket {
        self.ticket
    }

    /// Returns the exact domain closure revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the globally unique closure-receipt sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the exact service-binding generation at receipt issue.
    #[must_use]
    pub const fn binding_epoch(&self) -> BindingEpoch {
        self.binding_epoch
    }

    /// Returns the exact device generation at receipt issue.
    #[must_use]
    pub const fn device_generation(&self) -> DeviceGeneration {
        self.device_generation
    }

    /// Returns the domain closure outcome.
    #[must_use]
    pub const fn status(&self) -> &ClosureStatus {
        &self.status
    }
}

/// Root closure publication after all frozen-domain receipts are accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevokeOutcome {
    /// Every frozen domain is closed and all credits are free.
    Revoked,
    /// At least one domain honestly retains an external obligation.
    TimedOut {
        /// Domains whose accepted receipts still contain tombstones.
        pending_domains: Vec<DomainId>,
        /// Exact retained tombstones.
        tombstones: Vec<TombstoneId>,
        /// Aggregate typed credits that cannot yet be reused.
        retained_credits: CreditBundle,
    },
}

/// State of one retained timeout obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TombstoneState {
    /// Ownership is retained and a later retry is permitted.
    Retained,
    /// A retry is in progress and must acknowledge or time out.
    Retrying,
    /// Quiescence was acknowledged and retained credits were released.
    Released,
}

/// Opaque identity of one active tombstone retry attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TombstoneRetryToken {
    ticket: RootRevokeTicket,
    tombstone: TombstoneId,
    attempt: u64,
    device_generation: DeviceGeneration,
}

/// Read-only view of one composed effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionEffectView {
    /// Current identity, changed only by explicit domain adoption.
    pub token: CompositionEffectToken,
    /// Immutable causal parent.
    pub parent: Option<EffectId>,
    /// Current live children in deterministic identity order.
    pub live_children: Vec<EffectId>,
    /// Lifecycle state.
    pub state: CompositionEffectState,
    /// Credits currently held by the effect.
    pub held_credits: CreditBundle,
    /// Immutable commit receipt, if the effect committed.
    pub commit_receipt: Option<CompositionCommitReceipt>,
    /// Tombstone retaining this still-live external obligation.
    pub tombstone: Option<TombstoneId>,
    /// Whether acknowledged external quiescence permits closure to drain it.
    pub external_quiesced: bool,
    /// Number of transitions into a terminal effect outcome.
    pub terminalizations: u8,
}

/// Read-only view of one independently restartable domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainView {
    /// Current or last service identity.
    pub service: Option<ServiceId>,
    /// Independent service-binding generation.
    pub binding_epoch: BindingEpoch,
    /// Independent mediated-device generation.
    pub device_generation: DeviceGeneration,
    /// Fallback/replacement lifecycle.
    pub fallback: DomainFallbackState,
    /// Exact domain-local live-effect reverse index.
    pub live_effects: Vec<EffectId>,
    /// Exact domain-local leaf index used by closure.
    pub leaf_effects: Vec<EffectId>,
    /// Crash cohort not yet explicitly adopted.
    pub adoption_cohort: Vec<EffectId>,
    /// Active retained tombstones.
    pub tombstones: Vec<TombstoneId>,
    /// Domain-local mutation generation used by exact Ready proofs.
    pub mutation_generation: u64,
    /// Revision used by exact closure receipts.
    pub closure_revision: u64,
}

/// Bounded closure progress for one frozen domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainClosureProgress {
    /// Effects present at root-revoke linearization.
    pub target_count: usize,
    /// Effects terminalized since that point.
    pub terminalized: usize,
    /// Successful domain-local reverse-index selections.
    pub index_selections: usize,
    /// Effects still live in this domain.
    pub remaining: usize,
    /// Whether an exact receipt has been accepted by the root coordinator.
    pub receipt_accepted: bool,
}

/// Read-only view of one root authority scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionScopeView {
    /// Root lifecycle state.
    pub state: ScopeState,
    /// Current root authority generation.
    pub authority_epoch: AuthorityEpoch,
    /// Immutable initial typed-credit budget.
    pub initial_credits: CreditBundle,
    /// Credits currently free at the root.
    pub free_credits: CreditBundle,
    /// Registered domain membership.
    pub domains: Vec<DomainId>,
    /// Frozen domain cohort after root revocation.
    pub frozen_domains: Vec<DomainId>,
}

/// Read-only view of one timeout tombstone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TombstoneView {
    /// Root scope retaining the obligation.
    pub scope: ScopeId,
    /// Domain retaining the obligation.
    pub domain: DomainId,
    /// Still-live committed effect retained by this obligation.
    pub effect: EffectId,
    /// Device generation that may still own DMA.
    pub device_generation: DeviceGeneration,
    /// Typed credits not yet reusable.
    pub retained_credits: CreditBundle,
    /// Retry lifecycle.
    pub state: TombstoneState,
    /// Number of retry attempts begun.
    pub attempts: u64,
}

/// Rejected composition transition.
///
/// Identity and lifecycle guard rejections are mutation-free.  The critical
/// cross-domain derivation and timeout paths additionally use clone/apply/swap
/// transactions; sequence tests compare the complete model around their
/// rejected paths.  Counter exhaustion in other multi-object helpers is
/// outside the bounded executable state space and is reported explicitly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompositionError {
    /// Unknown root scope.
    UnknownScope(ScopeId),
    /// Unknown composed effect.
    UnknownEffect(EffectId),
    /// Unknown timeout tombstone.
    UnknownTombstone(TombstoneId),
    /// A domain is not registered under this root scope.
    UnknownDomain(DomainId),
    /// A domain was registered more than once.
    DomainAlreadyRegistered(DomainId),
    /// The root authority gate is not active.
    ScopeNotActive(ScopeState),
    /// The root scope is not closing.
    ScopeNotClosing(ScopeState),
    /// Presented domain binding is stale or forged.
    StaleBinding,
    /// Presented effect identity is stale or forged.
    EffectIdentityMismatch,
    /// A revoke ticket was paired with an effect from another root scope.
    CrossScopeEffect {
        /// Root scope named by the revoke ticket.
        ticket_scope: ScopeId,
        /// Root scope captured by the effect identity.
        effect_scope: ScopeId,
    },
    /// Effect kind is owned by a different domain.
    WrongDomain,
    /// A root or parent does not hold enough typed credits.
    CreditExhausted,
    /// Zero-credit effects are outside this bounded model.
    EmptyCreditTransfer,
    /// The effect lifecycle does not permit the requested transition.
    InvalidEffectState(CompositionEffectState),
    /// A parent cannot terminalize while a live descendant remains.
    LiveDescendants,
    /// Presented commit receipt is not the immutable recorded receipt.
    CommitReceiptMismatch,
    /// The fallback/replacement lifecycle is in the wrong state.
    InvalidFallbackState(DomainFallbackState),
    /// Recovery snapshot or Ready proof is stale or inexact.
    StaleRecoveryProof,
    /// The effect is not in this domain's current adoption cohort.
    NotAdoptable,
    /// Presented root revoke ticket is stale or forged.
    StaleRevokeTicket,
    /// Domain was not part of the frozen root-revoke cohort.
    DomainNotFrozen(DomainId),
    /// A closure receipt was requested while effects remain live.
    DomainNotQuiescent {
        /// Domain-local live-effect count.
        remaining: usize,
    },
    /// Presented closure receipt is stale or forged.
    StaleClosureReceipt,
    /// An exact closure receipt was replayed.
    DuplicateClosureReceipt,
    /// Root completion lacks one or more frozen-domain receipts.
    MissingClosureReceipts(Vec<DomainId>),
    /// Only committed VirtIO effects may create timeout tombstones.
    NotTombstoneEligible,
    /// Tombstone or retry token is stale or in the wrong state.
    StaleTombstoneRetry,
    /// Counter or generation arithmetic overflowed.
    CounterOverflow,
    /// Internal relationship required by the abstract protocol was absent.
    InvariantViolation(&'static str),
}

/// Failure reported by a complete composition invariant audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositionInvariantViolation {
    /// One root scope does not conserve every typed credit component.
    CreditConservation(ScopeId),
    /// An effect has an invalid identity, parent edge, or lifecycle.
    EffectGraph(EffectId),
    /// A domain-local live or leaf reverse index is not exact.
    DomainIndex(ScopeId, DomainId),
    /// A crash adoption cohort contains an ineligible effect.
    AdoptionCohort(ScopeId, DomainId),
    /// A tombstone and its retained live effect disagree.
    Tombstone(TombstoneId),
    /// Frozen-domain progress or an accepted receipt is inconsistent.
    Revocation(ScopeId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EffectRecord {
    token: CompositionEffectToken,
    parent: Option<EffectId>,
    live_children: BTreeSet<EffectId>,
    state: CompositionEffectState,
    held_credits: CreditBundle,
    commit_receipt: Option<CompositionCommitReceipt>,
    tombstone: Option<TombstoneId>,
    external_quiesced: bool,
    terminalizations: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DomainRecord {
    service: Option<ServiceId>,
    binding_epoch: BindingEpoch,
    device_generation: DeviceGeneration,
    fallback: DomainFallbackState,
    mutation_generation: u64,
    recovery_cohort: BTreeSet<EffectId>,
    live_effects: BTreeSet<EffectId>,
    leaf_effects: BTreeSet<EffectId>,
    tombstones: BTreeSet<TombstoneId>,
    closure_revision: u64,
    issued_receipt: Option<DomainClosureReceipt>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProgressRecord {
    target_count: usize,
    terminalized: usize,
    index_selections: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RevocationRecord {
    ticket: RootRevokeTicket,
    frozen_domains: BTreeSet<DomainId>,
    progress: BTreeMap<DomainId, ProgressRecord>,
    accepted: BTreeMap<DomainId, DomainClosureReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScopeRecord {
    state: ScopeState,
    authority_epoch: AuthorityEpoch,
    initial_credits: CreditBundle,
    free_credits: CreditBundle,
    domains: BTreeMap<DomainId, DomainRecord>,
    revocation: Option<RevocationRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TombstoneRecord {
    scope: ScopeId,
    domain: DomainId,
    effect: EffectId,
    device_generation: DeviceGeneration,
    retained_credits: CreditBundle,
    state: TombstoneState,
    attempts: u64,
}

/// Deterministic `no_std + alloc` system-wide composition model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionModel {
    next_scope: u64,
    next_effect: u64,
    next_commit: u64,
    next_tombstone: u64,
    next_revoke: u64,
    next_closure_receipt: u64,
    scopes: BTreeMap<ScopeId, ScopeRecord>,
    effects: BTreeMap<EffectId, EffectRecord>,
    tombstones: BTreeMap<TombstoneId, TombstoneRecord>,
}
