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

impl Default for CompositionModel {
    fn default() -> Self {
        Self::new()
    }
}

impl CompositionModel {
    /// Creates an empty composition model.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_scope: 1,
            next_effect: 1,
            next_commit: 1,
            next_tombstone: 1,
            next_revoke: 1,
            next_closure_receipt: 1,
            scopes: BTreeMap::new(),
            effects: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        }
    }

    /// Creates one active root scope with a typed-credit ledger.
    pub fn create_scope(&mut self, credits: CreditBundle) -> Result<ScopeId, CompositionError> {
        let scope = ScopeId::new(self.next_scope);
        let next = self
            .next_scope
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        self.scopes.insert(
            scope,
            ScopeRecord {
                state: ScopeState::Active,
                authority_epoch: AuthorityEpoch::new(1),
                initial_credits: credits,
                free_credits: credits,
                domains: BTreeMap::new(),
                revocation: None,
            },
        );
        self.next_scope = next;
        Ok(scope)
    }

    /// Registers one independently restartable domain under an active root.
    pub fn register_domain(
        &mut self,
        scope: ScopeId,
        domain: DomainId,
        service: ServiceId,
    ) -> Result<DomainBindingToken, CompositionError> {
        let record = self.scope_record(scope)?;
        if record.state != ScopeState::Active {
            return Err(CompositionError::ScopeNotActive(record.state));
        }
        if record.domains.contains_key(&domain) {
            return Err(CompositionError::DomainAlreadyRegistered(domain));
        }
        let authority_epoch = record.authority_epoch;
        let binding_epoch = BindingEpoch::new(1);
        let device_generation = DeviceGeneration::new(1);
        self.scope_record_mut(scope)?.domains.insert(
            domain,
            DomainRecord {
                service: Some(service),
                binding_epoch,
                device_generation,
                fallback: DomainFallbackState::Standby,
                mutation_generation: 1,
                recovery_cohort: BTreeSet::new(),
                live_effects: BTreeSet::new(),
                leaf_effects: BTreeSet::new(),
                tombstones: BTreeSet::new(),
                closure_revision: 0,
                issued_receipt: None,
            },
        );
        Ok(DomainBindingToken {
            scope,
            domain,
            service,
            authority_epoch,
            binding_epoch,
            device_generation,
        })
    }

    /// Registers a parentless effect and transfers credits from the root pool.
    pub fn register_root(
        &mut self,
        binding: DomainBindingToken,
        kind: CompositionEffectKind,
        credits: CreditBundle,
    ) -> Result<CompositionEffectToken, CompositionError> {
        self.validate_binding(binding)?;
        if kind.domain() != binding.domain {
            return Err(CompositionError::WrongDomain);
        }
        if credits.is_zero() {
            return Err(CompositionError::EmptyCreditTransfer);
        }
        let free_after = self
            .scope_record(binding.scope)?
            .free_credits
            .checked_sub(credits)?;
        let effect = EffectId::new(self.next_effect);
        let next = self
            .next_effect
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let token = CompositionEffectToken {
            scope: binding.scope,
            effect,
            parent: None,
            domain: binding.domain,
            kind,
            authority_epoch: binding.authority_epoch,
            binding_epoch: binding.binding_epoch,
            device_generation: binding.device_generation,
        };
        self.scope_record_mut(binding.scope)?.free_credits = free_after;
        self.insert_effect(token, credits)?;
        self.next_effect = next;
        Ok(token)
    }

    /// Failure-atomically derives one causal child and transfers typed credits.
    pub fn derive_child(
        &mut self,
        parent: CompositionEffectToken,
        target: DomainBindingToken,
        kind: CompositionEffectKind,
        credits: CreditBundle,
    ) -> Result<CompositionEffectToken, CompositionError> {
        let mut candidate = self.clone();
        let token = candidate.derive_child_inner(parent, target, kind, credits)?;
        *self = candidate;
        Ok(token)
    }

    fn derive_child_inner(
        &mut self,
        parent: CompositionEffectToken,
        target: DomainBindingToken,
        kind: CompositionEffectKind,
        credits: CreditBundle,
    ) -> Result<CompositionEffectToken, CompositionError> {
        self.validate_binding(target)?;
        if kind.domain() != target.domain || parent.scope != target.scope {
            return Err(CompositionError::WrongDomain);
        }
        if credits.is_zero() {
            return Err(CompositionError::EmptyCreditTransfer);
        }
        self.validate_effect_current(parent)?;
        let parent_record = self.effect_record(parent.effect)?;
        if parent_record.state.is_terminal() {
            return Err(CompositionError::InvalidEffectState(parent_record.state));
        }
        let parent_after = parent_record.held_credits.checked_sub(credits)?;
        let effect = EffectId::new(self.next_effect);
        let next = self
            .next_effect
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let token = CompositionEffectToken {
            scope: parent.scope,
            effect,
            parent: Some(parent.effect),
            domain: target.domain,
            kind,
            authority_epoch: target.authority_epoch,
            binding_epoch: target.binding_epoch,
            device_generation: target.device_generation,
        };

        self.effect_record_mut(parent.effect)?.held_credits = parent_after;
        self.effect_record_mut(parent.effect)?
            .live_children
            .insert(effect);
        self.domain_record_mut(parent.scope, parent.domain)?
            .leaf_effects
            .remove(&parent.effect);
        self.insert_effect(token, credits)?;
        if parent.domain != target.domain {
            self.bump_domain_mutation(parent.scope, parent.domain)?;
        }
        self.next_effect = next;
        Ok(token)
    }

    /// Marks a current uncommitted effect ready for its domain commit point.
    pub fn prepare(
        &mut self,
        binding: DomainBindingToken,
        token: CompositionEffectToken,
    ) -> Result<(), CompositionError> {
        self.validate_binding(binding)?;
        self.validate_binding_for_effect(binding, token)?;
        let state = self.effect_record(token.effect)?.state;
        if state != CompositionEffectState::Registered {
            return Err(CompositionError::InvalidEffectState(state));
        }
        self.effect_record_mut(token.effect)?.state = CompositionEffectState::Prepared;
        self.bump_domain_mutation(token.scope, token.domain)?;
        Ok(())
    }

    /// Crosses one commit point under the root and domain generation gates.
    pub fn commit(
        &mut self,
        binding: DomainBindingToken,
        token: CompositionEffectToken,
    ) -> Result<CompositionCommitReceipt, CompositionError> {
        self.validate_binding(binding)?;
        self.validate_binding_for_effect(binding, token)?;
        let record = self.effect_record(token.effect)?;
        if record.state != CompositionEffectState::Prepared {
            return Err(CompositionError::InvalidEffectState(record.state));
        }
        let receipt = CompositionCommitReceipt {
            token,
            sequence: self.next_commit,
        };
        let next = self
            .next_commit
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let record = self.effect_record_mut(token.effect)?;
        record.state = CompositionEffectState::Committed;
        record.commit_receipt = Some(receipt);
        self.next_commit = next;
        self.bump_domain_mutation(token.scope, token.domain)?;
        Ok(receipt)
    }

    /// Completes one committed effect through its immutable kernel receipt.
    pub fn complete(&mut self, receipt: CompositionCommitReceipt) -> Result<(), CompositionError> {
        let record = self.effect_record(receipt.effect())?;
        if record.commit_receipt != Some(receipt) {
            return Err(CompositionError::CommitReceiptMismatch);
        }
        if record.state != CompositionEffectState::Committed {
            return Err(CompositionError::InvalidEffectState(record.state));
        }
        if !record.live_children.is_empty() {
            return Err(CompositionError::LiveDescendants);
        }
        self.terminalize(
            receipt.effect(),
            CompositionEffectState::Completed,
            true,
            false,
        )
    }

    /// Fences a crashed service by advancing only its binding generation.
    pub fn crash(&mut self, binding: DomainBindingToken) -> Result<(), CompositionError> {
        self.validate_binding(binding)?;
        let next = BindingEpoch::new(
            binding
                .binding_epoch
                .get()
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?,
        );
        let live = self
            .domain_record(binding.scope, binding.domain)?
            .live_effects
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let mut cohort = BTreeSet::new();
        for effect in live {
            let state = self.effect_record(effect)?.state;
            if matches!(
                state,
                CompositionEffectState::Registered | CompositionEffectState::Prepared
            ) {
                cohort.insert(effect);
            }
        }
        let domain = self.domain_record_mut(binding.scope, binding.domain)?;
        domain.service = None;
        domain.binding_epoch = next;
        domain.fallback = DomainFallbackState::Required;
        domain.recovery_cohort = cohort;
        domain.mutation_generation = domain
            .mutation_generation
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        Ok(())
    }

    /// Selects the kernel fallback for one crashed domain.
    pub fn fallback_pick(
        &mut self,
        scope: ScopeId,
        domain: DomainId,
    ) -> Result<(), CompositionError> {
        self.require_active(scope)?;
        let state = self.domain_record(scope, domain)?.fallback;
        if state != DomainFallbackState::Required {
            return Err(CompositionError::InvalidFallbackState(state));
        }
        self.domain_record_mut(scope, domain)?.fallback = DomainFallbackState::Running;
        Ok(())
    }

    /// Captures an exact domain-local recovery snapshot.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        domain: DomainId,
        replacement: ServiceId,
    ) -> Result<DomainRecoverySnapshot, CompositionError> {
        self.require_active(scope)?;
        let record = self.domain_record(scope, domain)?;
        if record.fallback != DomainFallbackState::Running {
            return Err(CompositionError::InvalidFallbackState(record.fallback));
        }
        let mut effects = Vec::with_capacity(record.live_effects.len());
        for effect in &record.live_effects {
            let effect_record = self.effect_record(*effect)?;
            effects.push(RecoveryEffectSnapshot {
                token: effect_record.token,
                state: effect_record.state,
            });
        }
        Ok(DomainRecoverySnapshot {
            scope,
            domain,
            replacement,
            authority_epoch: self.scope_record(scope)?.authority_epoch,
            binding_epoch: record.binding_epoch,
            device_generation: record.device_generation,
            mutation_generation: record.mutation_generation,
            effects,
            adoption_cohort: record.recovery_cohort.iter().copied().collect(),
        })
    }

    /// Accepts an exact recovery snapshot and issues one Ready proof.
    pub fn ready(
        &mut self,
        snapshot: &DomainRecoverySnapshot,
    ) -> Result<DomainReadyToken, CompositionError> {
        let current =
            self.recovery_snapshot(snapshot.scope, snapshot.domain, snapshot.replacement)?;
        if current != *snapshot {
            return Err(CompositionError::StaleRecoveryProof);
        }
        self.domain_record_mut(snapshot.scope, snapshot.domain)?
            .fallback = DomainFallbackState::ReplacementReady;
        Ok(DomainReadyToken {
            scope: snapshot.scope,
            domain: snapshot.domain,
            replacement: snapshot.replacement,
            authority_epoch: snapshot.authority_epoch,
            binding_epoch: snapshot.binding_epoch,
            device_generation: snapshot.device_generation,
            mutation_generation: snapshot.mutation_generation,
        })
    }

    /// Installs the replacement represented by one current Ready proof.
    pub fn rebind(
        &mut self,
        ready: DomainReadyToken,
    ) -> Result<DomainBindingToken, CompositionError> {
        self.require_active(ready.scope)?;
        let scope_epoch = self.scope_record(ready.scope)?.authority_epoch;
        let domain = self.domain_record(ready.scope, ready.domain)?;
        if domain.fallback != DomainFallbackState::ReplacementReady
            || ready.authority_epoch != scope_epoch
            || ready.binding_epoch != domain.binding_epoch
            || ready.device_generation != domain.device_generation
            || ready.mutation_generation != domain.mutation_generation
        {
            return Err(CompositionError::StaleRecoveryProof);
        }
        let record = self.domain_record_mut(ready.scope, ready.domain)?;
        record.service = Some(ready.replacement);
        record.fallback = DomainFallbackState::Standby;
        Ok(DomainBindingToken {
            scope: ready.scope,
            domain: ready.domain,
            service: ready.replacement,
            authority_epoch: ready.authority_epoch,
            binding_epoch: ready.binding_epoch,
            device_generation: ready.device_generation,
        })
    }

    /// Explicitly transfers one uncommitted crash orphan to a replacement.
    pub fn adopt(
        &mut self,
        binding: DomainBindingToken,
        old: CompositionEffectToken,
    ) -> Result<CompositionEffectToken, CompositionError> {
        self.validate_binding(binding)?;
        let record = self.effect_record(old.effect)?;
        if record.token != old {
            return Err(CompositionError::EffectIdentityMismatch);
        }
        if old.scope != binding.scope || old.domain != binding.domain {
            return Err(CompositionError::NotAdoptable);
        }
        if !matches!(
            record.state,
            CompositionEffectState::Registered | CompositionEffectState::Prepared
        ) || !self
            .domain_record(binding.scope, binding.domain)?
            .recovery_cohort
            .contains(&old.effect)
        {
            return Err(CompositionError::NotAdoptable);
        }
        let mut adopted = old;
        adopted.authority_epoch = binding.authority_epoch;
        adopted.binding_epoch = binding.binding_epoch;
        adopted.device_generation = binding.device_generation;
        self.effect_record_mut(old.effect)?.token = adopted;
        self.domain_record_mut(binding.scope, binding.domain)?
            .recovery_cohort
            .remove(&old.effect);
        self.bump_domain_mutation(binding.scope, binding.domain)?;
        Ok(adopted)
    }

    /// Linearizes root revocation, closes child registration and commit, and
    /// freezes the exact registered-domain cohort without scanning effects.
    pub fn revoke_begin(&mut self, scope: ScopeId) -> Result<RootRevokeTicket, CompositionError> {
        let record = self.scope_record(scope)?;
        if record.state != ScopeState::Active {
            return Err(CompositionError::ScopeNotActive(record.state));
        }
        let closed_epoch = record.authority_epoch;
        let new_epoch = AuthorityEpoch::new(
            closed_epoch
                .get()
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?,
        );
        let generation = self.next_revoke;
        let next_revoke = generation
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let ticket = RootRevokeTicket {
            scope,
            closed_epoch,
            generation,
        };
        let frozen_domains = record
            .domains
            .iter()
            .filter_map(|(domain, local)| (!local.live_effects.is_empty()).then_some(*domain))
            .collect::<BTreeSet<_>>();
        let mut progress = BTreeMap::new();
        for domain in &frozen_domains {
            let local = record
                .domains
                .get(domain)
                .ok_or(CompositionError::InvariantViolation(
                    "missing frozen domain",
                ))?;
            progress.insert(
                *domain,
                ProgressRecord {
                    target_count: local.live_effects.len(),
                    terminalized: 0,
                    index_selections: 0,
                },
            );
        }
        let record = self.scope_record_mut(scope)?;
        record.state = ScopeState::Closing;
        record.authority_epoch = new_epoch;
        for domain in record.domains.values_mut() {
            domain.closure_revision = domain
                .closure_revision
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?;
            domain.issued_receipt = None;
        }
        record.revocation = Some(RevocationRecord {
            ticket,
            frozen_domains,
            progress,
            accepted: BTreeMap::new(),
        });
        self.next_revoke = next_revoke;
        Ok(ticket)
    }

    /// Advances one leaf effect through a domain-local closure index.
    pub fn close_next(
        &mut self,
        ticket: RootRevokeTicket,
        domain: DomainId,
    ) -> Result<Option<DomainCloseStep>, CompositionError> {
        self.validate_ticket(ticket)?;
        self.require_frozen(ticket.scope, domain)?;
        let local = self.domain_record(ticket.scope, domain)?;
        let Some(effect) = local.leaf_effects.iter().next().copied() else {
            if local.live_effects.is_empty() {
                return Ok(None);
            }
            return Ok(Some(DomainCloseStep::BlockedByDescendants {
                remaining: local.live_effects.len(),
            }));
        };
        let state = self.effect_record(effect)?.state;
        match state {
            CompositionEffectState::Registered | CompositionEffectState::Prepared => {
                self.terminalize(effect, CompositionEffectState::Aborted, true, true)?;
                Ok(Some(DomainCloseStep::Aborted(effect)))
            }
            CompositionEffectState::Committed if domain == DomainId::VirtIo => {
                if self.effect_record(effect)?.external_quiesced {
                    self.terminalize(effect, CompositionEffectState::Completed, true, true)?;
                    Ok(Some(DomainCloseStep::Completed(effect)))
                } else {
                    Ok(Some(DomainCloseStep::NeedsQuiescence(effect)))
                }
            }
            CompositionEffectState::Committed => {
                self.terminalize(effect, CompositionEffectState::Completed, true, true)?;
                Ok(Some(DomainCloseStep::Completed(effect)))
            }
            CompositionEffectState::Tombstoned if domain == DomainId::VirtIo => {
                Ok(Some(DomainCloseStep::NeedsQuiescence(effect)))
            }
            _ => Err(CompositionError::InvalidEffectState(state)),
        }
    }

    /// Retains one committed VirtIO leaf and its credits behind a tombstone.
    pub fn timeout_committed(
        &mut self,
        ticket: RootRevokeTicket,
        token: CompositionEffectToken,
    ) -> Result<TombstoneId, CompositionError> {
        let mut candidate = self.clone();
        let tombstone = candidate.timeout_committed_inner(ticket, token)?;
        *self = candidate;
        Ok(tombstone)
    }

    fn timeout_committed_inner(
        &mut self,
        ticket: RootRevokeTicket,
        token: CompositionEffectToken,
    ) -> Result<TombstoneId, CompositionError> {
        self.validate_ticket(ticket)?;
        self.require_frozen(ticket.scope, DomainId::VirtIo)?;
        if token.scope != ticket.scope {
            return Err(CompositionError::CrossScopeEffect {
                ticket_scope: ticket.scope,
                effect_scope: token.scope,
            });
        }
        let record = self.effect_record(token.effect)?;
        if record.token != token {
            return Err(CompositionError::EffectIdentityMismatch);
        }
        if token.domain != DomainId::VirtIo
            || record.state != CompositionEffectState::Committed
            || !record.live_children.is_empty()
            || !self
                .domain_record(ticket.scope, DomainId::VirtIo)?
                .tombstones
                .is_empty()
        {
            return Err(CompositionError::NotTombstoneEligible);
        }
        let id = TombstoneId::new(self.next_tombstone);
        let next = self
            .next_tombstone
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let credits = record.held_credits;
        let device_generation = record.token.device_generation;
        let effect = self
            .effects
            .get_mut(&token.effect)
            .expect("validated effect");
        effect.state = CompositionEffectState::Tombstoned;
        effect.tombstone = Some(id);
        effect.external_quiesced = false;
        self.tombstones.insert(
            id,
            TombstoneRecord {
                scope: ticket.scope,
                domain: DomainId::VirtIo,
                effect: token.effect,
                device_generation,
                retained_credits: credits,
                state: TombstoneState::Retained,
                attempts: 0,
            },
        );
        self.domain_record_mut(ticket.scope, DomainId::VirtIo)?
            .tombstones
            .insert(id);
        self.bump_domain_mutation(ticket.scope, DomainId::VirtIo)?;
        self.invalidate_closure(ticket.scope, DomainId::VirtIo)?;
        self.next_tombstone = next;
        Ok(id)
    }

    /// Issues an exact Closed receipt or an honest retained-timeout receipt.
    pub fn issue_domain_receipt(
        &mut self,
        ticket: RootRevokeTicket,
        domain: DomainId,
    ) -> Result<DomainClosureReceipt, CompositionError> {
        self.validate_ticket(ticket)?;
        self.require_frozen(ticket.scope, domain)?;
        let local = self.domain_record(ticket.scope, domain)?;
        if local.issued_receipt.is_some() {
            return Err(CompositionError::DuplicateClosureReceipt);
        }
        let mut retained = CreditBundle::ZERO;
        let mut tombstones = Vec::with_capacity(local.tombstones.len());
        for id in &local.tombstones {
            let record = self.tombstone_record(*id)?;
            if record.state == TombstoneState::Retrying {
                return Err(CompositionError::DomainNotQuiescent { remaining: 1 });
            }
            if record.state == TombstoneState::Retained {
                retained = retained.checked_add(record.retained_credits)?;
                tombstones.push(*id);
            }
        }
        let status = if !tombstones.is_empty() {
            let all_live_are_retained = local.live_effects.iter().all(|effect| {
                self.effects.get(effect).is_some_and(|record| {
                    record.state == CompositionEffectState::Tombstoned
                        && record
                            .tombstone
                            .is_some_and(|id| local.tombstones.contains(&id))
                })
            });
            if domain != DomainId::VirtIo || !all_live_are_retained {
                return Err(CompositionError::DomainNotQuiescent {
                    remaining: local.live_effects.len(),
                });
            }
            ClosureStatus::TimedOut {
                tombstones,
                retained_credits: retained,
            }
        } else if local.live_effects.is_empty() {
            ClosureStatus::Closed
        } else {
            return Err(CompositionError::DomainNotQuiescent {
                remaining: local.live_effects.len(),
            });
        };
        let sequence = self.next_closure_receipt;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let receipt = DomainClosureReceipt {
            ticket,
            domain,
            revision: local.closure_revision,
            sequence,
            binding_epoch: local.binding_epoch,
            device_generation: local.device_generation,
            status,
        };
        self.domain_record_mut(ticket.scope, domain)?.issued_receipt = Some(receipt.clone());
        self.next_closure_receipt = next_sequence;
        Ok(receipt)
    }

    /// Accepts one exact domain receipt; duplicates and stale revisions reject.
    pub fn accept_domain_receipt(
        &mut self,
        ticket: RootRevokeTicket,
        receipt: &DomainClosureReceipt,
    ) -> Result<(), CompositionError> {
        self.validate_ticket(ticket)?;
        if receipt.ticket != ticket {
            return Err(CompositionError::StaleClosureReceipt);
        }
        self.require_frozen(ticket.scope, receipt.domain)?;
        let local = self.domain_record(ticket.scope, receipt.domain)?;
        if local.issued_receipt.as_ref() != Some(receipt)
            || receipt.revision != local.closure_revision
            || receipt.binding_epoch != local.binding_epoch
            || receipt.device_generation != local.device_generation
        {
            return Err(CompositionError::StaleClosureReceipt);
        }
        let revocation = self.revocation(ticket.scope)?;
        if let Some(accepted) = revocation.accepted.get(&receipt.domain) {
            return if accepted == receipt {
                Err(CompositionError::DuplicateClosureReceipt)
            } else {
                Err(CompositionError::StaleClosureReceipt)
            };
        }
        self.revocation_mut(ticket.scope)?
            .accepted
            .insert(receipt.domain, receipt.clone());
        Ok(())
    }

    /// Publishes root closure or an honest aggregate timeout result.
    pub fn revoke_complete(
        &mut self,
        ticket: RootRevokeTicket,
    ) -> Result<RevokeOutcome, CompositionError> {
        self.validate_ticket(ticket)?;
        let revocation = self.revocation(ticket.scope)?;
        let mut pending_domains = Vec::new();
        let mut tombstones = Vec::new();
        let mut retained_credits = CreditBundle::ZERO;
        for (domain, receipt) in &revocation.accepted {
            match &receipt.status {
                ClosureStatus::Closed => {}
                ClosureStatus::TimedOut {
                    tombstones: local,
                    retained_credits: retained,
                } => {
                    pending_domains.push(*domain);
                    tombstones.extend(local.iter().copied());
                    retained_credits = retained_credits.checked_add(*retained)?;
                }
            }
        }
        if !pending_domains.is_empty() {
            return Ok(RevokeOutcome::TimedOut {
                pending_domains,
                tombstones,
                retained_credits,
            });
        }
        let missing = revocation
            .frozen_domains
            .iter()
            .filter(|domain| !revocation.accepted.contains_key(domain))
            .copied()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(CompositionError::MissingClosureReceipts(missing));
        }
        let scope = self.scope_record(ticket.scope)?;
        if scope.free_credits != scope.initial_credits {
            return Err(CompositionError::InvariantViolation(
                "closed receipts did not return every credit",
            ));
        }
        self.scope_record_mut(ticket.scope)?.state = ScopeState::Revoked;
        Ok(RevokeOutcome::Revoked)
    }

    /// Begins a retry while retaining ownership and invalidating old receipts.
    pub fn begin_tombstone_retry(
        &mut self,
        ticket: RootRevokeTicket,
        tombstone: TombstoneId,
    ) -> Result<TombstoneRetryToken, CompositionError> {
        self.validate_ticket(ticket)?;
        let record = *self.tombstone_record(tombstone)?;
        if record.scope != ticket.scope || record.state != TombstoneState::Retained {
            return Err(CompositionError::StaleTombstoneRetry);
        }
        let attempt = record
            .attempts
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let current_device = self
            .domain_record(ticket.scope, record.domain)?
            .device_generation;
        if current_device != record.device_generation {
            return Err(CompositionError::StaleTombstoneRetry);
        }
        let mutable = self
            .tombstones
            .get_mut(&tombstone)
            .expect("validated tombstone");
        mutable.state = TombstoneState::Retrying;
        mutable.attempts = attempt;
        self.invalidate_closure(ticket.scope, record.domain)?;
        Ok(TombstoneRetryToken {
            ticket,
            tombstone,
            attempt,
            device_generation: record.device_generation,
        })
    }

    /// Records a retry timeout without releasing retained ownership.
    pub fn tombstone_retry_timeout(
        &mut self,
        retry: TombstoneRetryToken,
    ) -> Result<(), CompositionError> {
        self.validate_retry(retry)?;
        let domain = self.tombstone_record(retry.tombstone)?.domain;
        self.tombstones
            .get_mut(&retry.tombstone)
            .expect("validated tombstone")
            .state = TombstoneState::Retained;
        self.invalidate_closure(retry.ticket.scope, domain)
    }

    /// Acknowledges quiescence, advances only the device generation, and
    /// reopens the same committed effect for child-first closure.
    pub fn tombstone_retry_ack(
        &mut self,
        retry: TombstoneRetryToken,
    ) -> Result<(), CompositionError> {
        self.validate_retry(retry)?;
        let record = *self.tombstone_record(retry.tombstone)?;
        let new_device = DeviceGeneration::new(
            record
                .device_generation
                .get()
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?,
        );
        let effect = self.effect_record(record.effect)?;
        if effect.state != CompositionEffectState::Tombstoned
            || effect.tombstone != Some(retry.tombstone)
            || effect.held_credits != record.retained_credits
        {
            return Err(CompositionError::StaleTombstoneRetry);
        }
        let mutable = self
            .tombstones
            .get_mut(&retry.tombstone)
            .expect("validated tombstone");
        mutable.state = TombstoneState::Released;
        mutable.retained_credits = CreditBundle::ZERO;
        self.domain_record_mut(record.scope, record.domain)?
            .tombstones
            .remove(&retry.tombstone);
        self.domain_record_mut(record.scope, record.domain)?
            .device_generation = new_device;
        let effect = self.effect_record_mut(record.effect)?;
        effect.state = CompositionEffectState::Committed;
        effect.external_quiesced = true;
        self.invalidate_closure(record.scope, record.domain)
    }

    /// Returns a read-only root scope projection.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<CompositionScopeView> {
        let record = self.scopes.get(&scope)?;
        Some(CompositionScopeView {
            state: record.state,
            authority_epoch: record.authority_epoch,
            initial_credits: record.initial_credits,
            free_credits: record.free_credits,
            domains: record.domains.keys().copied().collect(),
            frozen_domains: record.revocation.as_ref().map_or_else(Vec::new, |revoke| {
                revoke.frozen_domains.iter().copied().collect()
            }),
        })
    }

    /// Returns a read-only domain projection.
    #[must_use]
    pub fn domain(&self, scope: ScopeId, domain: DomainId) -> Option<DomainView> {
        let record = self.scopes.get(&scope)?.domains.get(&domain)?;
        Some(DomainView {
            service: record.service,
            binding_epoch: record.binding_epoch,
            device_generation: record.device_generation,
            fallback: record.fallback,
            live_effects: record.live_effects.iter().copied().collect(),
            leaf_effects: record.leaf_effects.iter().copied().collect(),
            adoption_cohort: record.recovery_cohort.iter().copied().collect(),
            tombstones: record.tombstones.iter().copied().collect(),
            mutation_generation: record.mutation_generation,
            closure_revision: record.closure_revision,
        })
    }

    /// Returns a read-only effect projection.
    #[must_use]
    pub fn effect(&self, effect: EffectId) -> Option<CompositionEffectView> {
        let record = self.effects.get(&effect)?;
        Some(CompositionEffectView {
            token: record.token,
            parent: record.parent,
            live_children: record.live_children.iter().copied().collect(),
            state: record.state,
            held_credits: record.held_credits,
            commit_receipt: record.commit_receipt,
            tombstone: record.tombstone,
            external_quiesced: record.external_quiesced,
            terminalizations: record.terminalizations,
        })
    }

    /// Returns a read-only tombstone projection.
    #[must_use]
    pub fn tombstone(&self, tombstone: TombstoneId) -> Option<TombstoneView> {
        let record = self.tombstones.get(&tombstone)?;
        Some(TombstoneView {
            scope: record.scope,
            domain: record.domain,
            effect: record.effect,
            device_generation: record.device_generation,
            retained_credits: record.retained_credits,
            state: record.state,
            attempts: record.attempts,
        })
    }

    /// Returns bounded closure progress for one frozen domain.
    #[must_use]
    pub fn closure_progress(
        &self,
        scope: ScopeId,
        domain: DomainId,
    ) -> Option<DomainClosureProgress> {
        let scope_record = self.scopes.get(&scope)?;
        let revocation = scope_record.revocation.as_ref()?;
        let progress = revocation.progress.get(&domain)?;
        let remaining = scope_record.domains.get(&domain)?.live_effects.len();
        Some(DomainClosureProgress {
            target_count: progress.target_count,
            terminalized: progress.terminalized,
            index_selections: progress.index_selections,
            remaining,
            receipt_accepted: revocation.accepted.contains_key(&domain),
        })
    }

    /// Returns the number of global effect records, for negative scan tests.
    #[must_use]
    pub fn global_effect_count(&self) -> usize {
        self.effects.len()
    }

    /// Audits graph identity, local indexes, credits, recovery, and closure.
    pub fn check_invariants(&self) -> Result<(), CompositionInvariantViolation> {
        for (scope_id, scope) in &self.scopes {
            let mut accounted = scope.free_credits;
            for (effect_id, effect) in &self.effects {
                if effect.token.scope != *scope_id {
                    continue;
                }
                if effect.token.effect != *effect_id
                    || effect.parent != effect.token.parent
                    || effect.kind_domain() != effect.token.domain
                    || effect.token.authority_epoch.get() > scope.authority_epoch.get()
                    || (effect.token.domain != DomainId::VirtIo
                        && effect.token.device_generation != DeviceGeneration::new(1))
                {
                    return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                }
                let Some(owner) = scope.domains.get(&effect.token.domain) else {
                    return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                };
                if effect.token.binding_epoch.get() > owner.binding_epoch.get()
                    || effect.token.device_generation.get() > owner.device_generation.get()
                {
                    return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                }
                if effect.state.is_terminal() {
                    if effect.terminalizations != 1 || !effect.held_credits.is_zero() {
                        return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                    }
                } else {
                    if effect.terminalizations != 0 {
                        return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                    }
                    accounted = accounted.checked_add(effect.held_credits).map_err(|_| {
                        CompositionInvariantViolation::CreditConservation(*scope_id)
                    })?;
                }
                if effect.state == CompositionEffectState::Tombstoned
                    && (effect.tombstone.is_none()
                        || effect.external_quiesced
                        || effect.commit_receipt.is_none())
                {
                    return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                }
                if effect.external_quiesced
                    && !matches!(
                        effect.state,
                        CompositionEffectState::Committed | CompositionEffectState::Completed
                    )
                {
                    return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                }
                if let Some(parent) = effect.parent {
                    let parent_record = self
                        .effects
                        .get(&parent)
                        .ok_or(CompositionInvariantViolation::EffectGraph(*effect_id))?;
                    if parent >= *effect_id
                        || parent_record.token.scope != *scope_id
                        || (!effect.state.is_terminal()
                            && !parent_record.live_children.contains(effect_id))
                    {
                        return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                    }
                }
                for child in &effect.live_children {
                    let child_record = self
                        .effects
                        .get(child)
                        .ok_or(CompositionInvariantViolation::EffectGraph(*effect_id))?;
                    if child_record.parent != Some(*effect_id) || child_record.state.is_terminal() {
                        return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                    }
                }
            }
            for (tombstone_id, tombstone) in &self.tombstones {
                if tombstone.scope != *scope_id {
                    continue;
                }
                let effect = self
                    .effects
                    .get(&tombstone.effect)
                    .ok_or(CompositionInvariantViolation::Tombstone(*tombstone_id))?;
                let local = scope
                    .domains
                    .get(&tombstone.domain)
                    .ok_or(CompositionInvariantViolation::Tombstone(*tombstone_id))?;
                if effect.token.scope != tombstone.scope
                    || effect.token.domain != tombstone.domain
                    || tombstone.domain != DomainId::VirtIo
                    || effect.token.device_generation != tombstone.device_generation
                    || effect.tombstone != Some(*tombstone_id)
                {
                    return Err(CompositionInvariantViolation::Tombstone(*tombstone_id));
                }
                if tombstone.state == TombstoneState::Released {
                    if !tombstone.retained_credits.is_zero()
                        || local.tombstones.contains(tombstone_id)
                        || !matches!(
                            effect.state,
                            CompositionEffectState::Committed | CompositionEffectState::Completed
                        )
                    {
                        return Err(CompositionInvariantViolation::Tombstone(*tombstone_id));
                    }
                    continue;
                }
                if effect.state != CompositionEffectState::Tombstoned
                    || !local.tombstones.contains(tombstone_id)
                    || effect.held_credits != tombstone.retained_credits
                {
                    return Err(CompositionInvariantViolation::Tombstone(*tombstone_id));
                }
            }
            if accounted != scope.initial_credits {
                return Err(CompositionInvariantViolation::CreditConservation(*scope_id));
            }

            for (domain_id, domain) in &scope.domains {
                let expected_live = self
                    .effects
                    .iter()
                    .filter_map(|(id, effect)| {
                        (effect.token.scope == *scope_id
                            && effect.token.domain == *domain_id
                            && !effect.state.is_terminal())
                        .then_some(*id)
                    })
                    .collect::<BTreeSet<_>>();
                let expected_leaves = expected_live
                    .iter()
                    .filter(|id| {
                        self.effects
                            .get(id)
                            .is_some_and(|effect| effect.live_children.is_empty())
                    })
                    .copied()
                    .collect::<BTreeSet<_>>();
                if expected_live != domain.live_effects || expected_leaves != domain.leaf_effects {
                    return Err(CompositionInvariantViolation::DomainIndex(
                        *scope_id, *domain_id,
                    ));
                }
                for effect in &domain.recovery_cohort {
                    let Some(record) = self.effects.get(effect) else {
                        return Err(CompositionInvariantViolation::AdoptionCohort(
                            *scope_id, *domain_id,
                        ));
                    };
                    if record.token.scope != *scope_id
                        || record.token.domain != *domain_id
                        || !matches!(
                            record.state,
                            CompositionEffectState::Registered | CompositionEffectState::Prepared
                        )
                        || !domain.live_effects.contains(effect)
                    {
                        return Err(CompositionInvariantViolation::AdoptionCohort(
                            *scope_id, *domain_id,
                        ));
                    }
                }
                for tombstone in &domain.tombstones {
                    let Some(record) = self.tombstones.get(tombstone) else {
                        return Err(CompositionInvariantViolation::Tombstone(*tombstone));
                    };
                    if record.scope != *scope_id
                        || record.domain != *domain_id
                        || record.state == TombstoneState::Released
                    {
                        return Err(CompositionInvariantViolation::Tombstone(*tombstone));
                    }
                }
            }

            match (scope.state, &scope.revocation) {
                (ScopeState::Active, None) => {}
                (ScopeState::Closing | ScopeState::Revoked, Some(revocation)) => {
                    if !revocation
                        .frozen_domains
                        .iter()
                        .all(|domain| scope.domains.contains_key(domain))
                        || revocation.progress.keys().copied().collect::<BTreeSet<_>>()
                            != revocation.frozen_domains
                        || revocation
                            .progress
                            .values()
                            .any(|progress| progress.target_count == 0)
                    {
                        return Err(CompositionInvariantViolation::Revocation(*scope_id));
                    }
                    for domain in &revocation.frozen_domains {
                        let progress = revocation
                            .progress
                            .get(domain)
                            .ok_or(CompositionInvariantViolation::Revocation(*scope_id))?;
                        let remaining = scope
                            .domains
                            .get(domain)
                            .ok_or(CompositionInvariantViolation::Revocation(*scope_id))?
                            .live_effects
                            .len();
                        if progress.target_count != progress.terminalized + remaining
                            || progress.index_selections > progress.terminalized
                        {
                            return Err(CompositionInvariantViolation::Revocation(*scope_id));
                        }
                    }
                    for (domain, receipt) in &revocation.accepted {
                        let local = scope
                            .domains
                            .get(domain)
                            .ok_or(CompositionInvariantViolation::Revocation(*scope_id))?;
                        let status_exact = match &receipt.status {
                            ClosureStatus::Closed => {
                                local.live_effects.is_empty() && local.tombstones.is_empty()
                            }
                            ClosureStatus::TimedOut {
                                tombstones,
                                retained_credits,
                            } => {
                                let exact_retained = tombstones.iter().try_fold(
                                    CreditBundle::ZERO,
                                    |sum, tombstone| {
                                        self.tombstones.get(tombstone).and_then(|record| {
                                            sum.checked_add(record.retained_credits).ok()
                                        })
                                    },
                                );
                                !tombstones.is_empty()
                                    && tombstones.iter().copied().collect::<BTreeSet<_>>()
                                        == local.tombstones
                                    && exact_retained == Some(*retained_credits)
                                    && local.live_effects.iter().all(|effect| {
                                        self.effects.get(effect).is_some_and(|effect| {
                                            effect.state == CompositionEffectState::Tombstoned
                                        })
                                    })
                            }
                        };
                        if local.issued_receipt.as_ref() != Some(receipt)
                            || receipt.revision != local.closure_revision
                            || receipt.binding_epoch != local.binding_epoch
                            || receipt.device_generation != local.device_generation
                            || !status_exact
                        {
                            return Err(CompositionInvariantViolation::Revocation(*scope_id));
                        }
                    }
                    if scope.state == ScopeState::Revoked
                        && (scope.free_credits != scope.initial_credits
                            || revocation.accepted.len() != revocation.frozen_domains.len()
                            || revocation
                                .accepted
                                .values()
                                .any(|receipt| receipt.status != ClosureStatus::Closed))
                    {
                        return Err(CompositionInvariantViolation::Revocation(*scope_id));
                    }
                }
                _ => return Err(CompositionInvariantViolation::Revocation(*scope_id)),
            }
        }
        Ok(())
    }

    fn insert_effect(
        &mut self,
        token: CompositionEffectToken,
        credits: CreditBundle,
    ) -> Result<(), CompositionError> {
        self.effects.insert(
            token.effect,
            EffectRecord {
                token,
                parent: token.parent,
                live_children: BTreeSet::new(),
                state: CompositionEffectState::Registered,
                held_credits: credits,
                commit_receipt: None,
                tombstone: None,
                external_quiesced: false,
                terminalizations: 0,
            },
        );
        let domain = self.domain_record_mut(token.scope, token.domain)?;
        domain.live_effects.insert(token.effect);
        domain.leaf_effects.insert(token.effect);
        domain.mutation_generation = domain
            .mutation_generation
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        Ok(())
    }

    fn terminalize(
        &mut self,
        effect: EffectId,
        terminal: CompositionEffectState,
        return_credits: bool,
        index_selection: bool,
    ) -> Result<(), CompositionError> {
        debug_assert!(terminal.is_terminal());
        let record = self.effect_record(effect)?;
        if record.state.is_terminal() {
            return Err(CompositionError::InvalidEffectState(record.state));
        }
        if !record.live_children.is_empty() {
            return Err(CompositionError::LiveDescendants);
        }
        let scope = record.token.scope;
        let domain = record.token.domain;
        let parent = record.parent;
        let credits = record.held_credits;
        let mut cross_domain_parent = None;
        {
            let record = self.effect_record_mut(effect)?;
            record.state = terminal;
            record.terminalizations = record
                .terminalizations
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?;
            if return_credits {
                record.held_credits = CreditBundle::ZERO;
            }
        }
        {
            let local = self.domain_record_mut(scope, domain)?;
            local.live_effects.remove(&effect);
            local.leaf_effects.remove(&effect);
            local.recovery_cohort.remove(&effect);
        }
        if let Some(parent_id) = parent {
            let parent_domain = self.effect_record(parent_id)?.token.domain;
            let parent_record = self.effect_record_mut(parent_id)?;
            parent_record.live_children.remove(&effect);
            if return_credits {
                parent_record.held_credits = parent_record.held_credits.checked_add(credits)?;
            }
            if parent_record.live_children.is_empty() && !parent_record.state.is_terminal() {
                self.domain_record_mut(scope, parent_domain)?
                    .leaf_effects
                    .insert(parent_id);
            }
            if parent_domain != domain {
                cross_domain_parent = Some(parent_domain);
            }
        } else if return_credits {
            let free = self
                .scope_record(scope)?
                .free_credits
                .checked_add(credits)?;
            self.scope_record_mut(scope)?.free_credits = free;
        }
        self.bump_domain_mutation(scope, domain)?;
        if let Some(parent_domain) = cross_domain_parent {
            self.bump_domain_mutation(scope, parent_domain)?;
        }
        if self.scope_record(scope)?.state == ScopeState::Closing {
            let progress = self
                .revocation_mut(scope)?
                .progress
                .get_mut(&domain)
                .ok_or(CompositionError::InvariantViolation(
                    "missing domain progress",
                ))?;
            progress.terminalized = progress
                .terminalized
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?;
            if index_selection {
                progress.index_selections = progress
                    .index_selections
                    .checked_add(1)
                    .ok_or(CompositionError::CounterOverflow)?;
            }
            self.invalidate_closure(scope, domain)?;
            if let Some(parent_domain) = cross_domain_parent {
                self.invalidate_closure(scope, parent_domain)?;
            }
        }
        Ok(())
    }

    fn validate_binding(&self, binding: DomainBindingToken) -> Result<(), CompositionError> {
        let scope = self.scope_record(binding.scope)?;
        if scope.state != ScopeState::Active {
            return Err(CompositionError::ScopeNotActive(scope.state));
        }
        let domain = scope
            .domains
            .get(&binding.domain)
            .ok_or(CompositionError::UnknownDomain(binding.domain))?;
        if domain.service != Some(binding.service)
            || domain.binding_epoch != binding.binding_epoch
            || domain.device_generation != binding.device_generation
            || scope.authority_epoch != binding.authority_epoch
        {
            return Err(CompositionError::StaleBinding);
        }
        Ok(())
    }

    fn validate_effect_current(
        &self,
        token: CompositionEffectToken,
    ) -> Result<(), CompositionError> {
        let record = self.effect_record(token.effect)?;
        if record.token != token {
            return Err(CompositionError::EffectIdentityMismatch);
        }
        let scope = self.scope_record(token.scope)?;
        if scope.state != ScopeState::Active {
            return Err(CompositionError::ScopeNotActive(scope.state));
        }
        let domain = self.domain_record(token.scope, token.domain)?;
        if token.authority_epoch != scope.authority_epoch
            || token.binding_epoch != domain.binding_epoch
            || token.device_generation != domain.device_generation
            || domain.service.is_none()
        {
            return Err(CompositionError::EffectIdentityMismatch);
        }
        Ok(())
    }

    fn validate_binding_for_effect(
        &self,
        binding: DomainBindingToken,
        token: CompositionEffectToken,
    ) -> Result<(), CompositionError> {
        self.validate_effect_current(token)?;
        if binding.scope != token.scope
            || binding.domain != token.domain
            || binding.authority_epoch != token.authority_epoch
            || binding.binding_epoch != token.binding_epoch
            || binding.device_generation != token.device_generation
        {
            return Err(CompositionError::EffectIdentityMismatch);
        }
        Ok(())
    }

    fn validate_ticket(&self, ticket: RootRevokeTicket) -> Result<(), CompositionError> {
        let scope = self.scope_record(ticket.scope)?;
        if scope.state != ScopeState::Closing {
            return Err(CompositionError::ScopeNotClosing(scope.state));
        }
        if scope.revocation.as_ref().map(|record| record.ticket) != Some(ticket) {
            return Err(CompositionError::StaleRevokeTicket);
        }
        Ok(())
    }

    fn validate_retry(&self, retry: TombstoneRetryToken) -> Result<(), CompositionError> {
        self.validate_ticket(retry.ticket)?;
        let record = self.tombstone_record(retry.tombstone)?;
        if record.scope != retry.ticket.scope
            || record.state != TombstoneState::Retrying
            || record.attempts != retry.attempt
            || record.device_generation != retry.device_generation
            || self
                .domain_record(record.scope, record.domain)?
                .device_generation
                != retry.device_generation
        {
            return Err(CompositionError::StaleTombstoneRetry);
        }
        Ok(())
    }

    fn require_active(&self, scope: ScopeId) -> Result<(), CompositionError> {
        let state = self.scope_record(scope)?.state;
        if state != ScopeState::Active {
            return Err(CompositionError::ScopeNotActive(state));
        }
        Ok(())
    }

    fn require_frozen(&self, scope: ScopeId, domain: DomainId) -> Result<(), CompositionError> {
        if !self.revocation(scope)?.frozen_domains.contains(&domain) {
            return Err(CompositionError::DomainNotFrozen(domain));
        }
        Ok(())
    }

    fn invalidate_closure(
        &mut self,
        scope: ScopeId,
        domain: DomainId,
    ) -> Result<(), CompositionError> {
        let local = self.domain_record_mut(scope, domain)?;
        local.closure_revision = local
            .closure_revision
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        local.issued_receipt = None;
        if let Some(revocation) = self.scope_record_mut(scope)?.revocation.as_mut() {
            revocation.accepted.remove(&domain);
        }
        Ok(())
    }

    fn bump_domain_mutation(
        &mut self,
        scope: ScopeId,
        domain: DomainId,
    ) -> Result<(), CompositionError> {
        let local = self.domain_record_mut(scope, domain)?;
        local.mutation_generation = local
            .mutation_generation
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        Ok(())
    }

    fn scope_record(&self, scope: ScopeId) -> Result<&ScopeRecord, CompositionError> {
        self.scopes
            .get(&scope)
            .ok_or(CompositionError::UnknownScope(scope))
    }

    fn scope_record_mut(&mut self, scope: ScopeId) -> Result<&mut ScopeRecord, CompositionError> {
        self.scopes
            .get_mut(&scope)
            .ok_or(CompositionError::UnknownScope(scope))
    }

    fn domain_record(
        &self,
        scope: ScopeId,
        domain: DomainId,
    ) -> Result<&DomainRecord, CompositionError> {
        self.scope_record(scope)?
            .domains
            .get(&domain)
            .ok_or(CompositionError::UnknownDomain(domain))
    }

    fn domain_record_mut(
        &mut self,
        scope: ScopeId,
        domain: DomainId,
    ) -> Result<&mut DomainRecord, CompositionError> {
        self.scope_record_mut(scope)?
            .domains
            .get_mut(&domain)
            .ok_or(CompositionError::UnknownDomain(domain))
    }

    fn effect_record(&self, effect: EffectId) -> Result<&EffectRecord, CompositionError> {
        self.effects
            .get(&effect)
            .ok_or(CompositionError::UnknownEffect(effect))
    }

    fn effect_record_mut(
        &mut self,
        effect: EffectId,
    ) -> Result<&mut EffectRecord, CompositionError> {
        self.effects
            .get_mut(&effect)
            .ok_or(CompositionError::UnknownEffect(effect))
    }

    fn tombstone_record(
        &self,
        tombstone: TombstoneId,
    ) -> Result<&TombstoneRecord, CompositionError> {
        self.tombstones
            .get(&tombstone)
            .ok_or(CompositionError::UnknownTombstone(tombstone))
    }

    fn revocation(&self, scope: ScopeId) -> Result<&RevocationRecord, CompositionError> {
        self.scope_record(scope)?
            .revocation
            .as_ref()
            .ok_or(CompositionError::StaleRevokeTicket)
    }

    fn revocation_mut(
        &mut self,
        scope: ScopeId,
    ) -> Result<&mut RevocationRecord, CompositionError> {
        self.scope_record_mut(scope)?
            .revocation
            .as_mut()
            .ok_or(CompositionError::StaleRevokeTicket)
    }
}

impl EffectRecord {
    const fn kind_domain(&self) -> DomainId {
        self.token.kind.domain()
    }
}
