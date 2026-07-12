//! Common scoped-effect registry for restartable personality services.
//!
//! The registry owns authority and binding fences, one-shot task
//! continuations, scope-local live/committed reverse indexes, typed renewable
//! credits, crash snapshots, explicit adoption, and bounded revocation.  A
//! domain refinement such as futex requeue or readiness owns its matching
//! indexes and immutable semantic receipt; the opaque `domain_receipt` value
//! binds that receipt to the generic commit point.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{EffectId, ScopeId, ScopeState};

use super::{
    AuthorityEpoch, BindingEpoch, PersonalityBindingToken, PersonalityError, PersonalityId,
    PersonalityModel, PersonalityReadyToken, PersonalityRecoverySnapshot, PersonalityScopeView,
    TaskId,
};

/// Domain label authenticated by a generic effect token.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegistryEffectKind {
    /// One ordinary trapped-syscall continuation.
    SyscallContinuation,
    /// One multi-step executable-image transaction.
    ExecTransaction,
    /// One executable segment owned by an exec transaction.
    ExecSegment,
    /// One queued private-futex wait continuation.
    FutexWait,
    /// One private-futex wake controller continuation.
    FutexWake,
    /// One private-futex requeue controller continuation.
    FutexRequeue,
    /// One persistent readiness subscription.
    ReadinessSubscription,
    /// One blocked readiness wait continuation.
    ReadinessWait,
    /// One committed readiness-delivery continuation.
    ReadinessDelivery,
    /// One timer deadline effect.
    TimerDeadline,
}

impl RegistryEffectKind {
    /// Returns whether this effect exclusively occupies its owner's blocked
    /// continuation slot.
    ///
    /// Persistent subscriptions, exec segments, and timer deadlines retain an
    /// owner for accounting but do not block that task.  This permits one task
    /// to own multiple persistent readiness subscriptions without fabricated
    /// task identities.
    #[must_use]
    pub const fn blocks_task(self) -> bool {
        matches!(
            self,
            Self::SyscallContinuation
                | Self::ExecTransaction
                | Self::FutexWait
                | Self::FutexWake
                | Self::FutexRequeue
                | Self::ReadinessWait
                | Self::ReadinessDelivery
        )
    }

    /// Returns the only renewable-credit class valid for this effect kind.
    #[must_use]
    pub const fn credit_class(self) -> RegistryCreditClass {
        match self {
            Self::SyscallContinuation
            | Self::ExecTransaction
            | Self::FutexWake
            | Self::FutexRequeue => RegistryCreditClass::Continuation,
            Self::ExecSegment => RegistryCreditClass::ExecSegment,
            Self::FutexWait => RegistryCreditClass::FutexWait,
            Self::ReadinessSubscription => RegistryCreditClass::ReadinessSubscription,
            Self::ReadinessWait => RegistryCreditClass::ReadinessWait,
            Self::ReadinessDelivery => RegistryCreditClass::ReadinessDelivery,
            Self::TimerDeadline => RegistryCreditClass::Timer,
        }
    }
}

/// Renewable resource class held by one live effect.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegistryCreditClass {
    /// An ordinary syscall, wake, requeue, or exec controller continuation.
    Continuation,
    /// One executable segment mapping/resource slot.
    ExecSegment,
    /// A queued private-futex wait position and continuation.
    FutexWait,
    /// A persistent readiness subscription slot.
    ReadinessSubscription,
    /// A blocked readiness-wait continuation.
    ReadinessWait,
    /// A committed readiness-delivery slot.
    ReadinessDelivery,
    /// A timer deadline slot, including recovery-watchdog ownership.
    Timer,
}

/// Opaque domain resource identity used only for reverse indexing.
///
/// Futex keys, file descriptions, readiness masks, executable mappings, and
/// timer identities remain domain-owned.  The common registry authenticates
/// this stable opaque key and maintains `scope + resource -> live effects`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RegistryResourceKey(u64);

impl RegistryResourceKey {
    /// Constructs an opaque resource key from a domain-stable identifier.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the opaque numeric identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One or two opaque resources atomically associated with an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryResources {
    primary: RegistryResourceKey,
    secondary: Option<RegistryResourceKey>,
}

impl RegistryResources {
    /// Constructs a single-resource association.
    #[must_use]
    pub const fn one(primary: RegistryResourceKey) -> Self {
        Self {
            primary,
            secondary: None,
        }
    }

    /// Constructs a two-resource association.
    #[must_use]
    pub const fn pair(primary: RegistryResourceKey, secondary: RegistryResourceKey) -> Self {
        Self {
            primary,
            secondary: Some(secondary),
        }
    }

    /// Returns the primary resource.
    #[must_use]
    pub const fn primary(self) -> RegistryResourceKey {
        self.primary
    }

    /// Returns the optional secondary resource.
    #[must_use]
    pub const fn secondary(self) -> Option<RegistryResourceKey> {
        self.secondary
    }

    fn iter(self) -> impl Iterator<Item = RegistryResourceKey> {
        core::iter::once(self.primary).chain(self.secondary)
    }
}

/// Independent renewable credits owned by one authority scope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RegistryBudget {
    continuation: u64,
    exec_segment: u64,
    futex_wait: u64,
    readiness_subscription: u64,
    readiness_wait: u64,
    readiness_delivery: u64,
    timer: u64,
}

impl RegistryBudget {
    /// Constructs a typed scope budget.
    #[must_use]
    pub const fn new(
        continuation: u64,
        exec_segment: u64,
        futex_wait: u64,
        readiness_subscription: u64,
        readiness_wait: u64,
        readiness_delivery: u64,
        timer: u64,
    ) -> Self {
        Self {
            continuation,
            exec_segment,
            futex_wait,
            readiness_subscription,
            readiness_wait,
            readiness_delivery,
            timer,
        }
    }

    /// Returns free or initial ordinary continuation credits.
    #[must_use]
    pub const fn continuation(self) -> u64 {
        self.continuation
    }

    /// Returns free or initial executable-segment credits.
    #[must_use]
    pub const fn exec_segment(self) -> u64 {
        self.exec_segment
    }

    /// Returns free or initial private-futex wait credits.
    #[must_use]
    pub const fn futex_wait(self) -> u64 {
        self.futex_wait
    }

    /// Returns free or initial readiness-subscription credits.
    #[must_use]
    pub const fn readiness_subscription(self) -> u64 {
        self.readiness_subscription
    }

    /// Returns free or initial readiness-wait credits.
    #[must_use]
    pub const fn readiness_wait(self) -> u64 {
        self.readiness_wait
    }

    /// Returns free or initial readiness-delivery credits.
    #[must_use]
    pub const fn readiness_delivery(self) -> u64 {
        self.readiness_delivery
    }

    /// Returns free or initial timer credits.
    ///
    /// An active scope always keeps one free timer credit reserved for its
    /// crash-recovery watchdog.  `TimerDeadline` registration may consume only
    /// credits above that reserve.
    #[must_use]
    pub const fn timer(self) -> u64 {
        self.timer
    }

    const fn get(self, class: RegistryCreditClass) -> u64 {
        match class {
            RegistryCreditClass::Continuation => self.continuation,
            RegistryCreditClass::ExecSegment => self.exec_segment,
            RegistryCreditClass::FutexWait => self.futex_wait,
            RegistryCreditClass::ReadinessSubscription => self.readiness_subscription,
            RegistryCreditClass::ReadinessWait => self.readiness_wait,
            RegistryCreditClass::ReadinessDelivery => self.readiness_delivery,
            RegistryCreditClass::Timer => self.timer,
        }
    }

    fn checked_take(self, class: RegistryCreditClass) -> Result<Self, RegistryError> {
        let mut after = self;
        match class {
            RegistryCreditClass::Continuation => {
                after.continuation = after
                    .continuation
                    .checked_sub(1)
                    .ok_or(RegistryError::CreditExhausted(class))?;
            }
            RegistryCreditClass::ExecSegment => {
                after.exec_segment = after
                    .exec_segment
                    .checked_sub(1)
                    .ok_or(RegistryError::CreditExhausted(class))?;
            }
            RegistryCreditClass::FutexWait => {
                after.futex_wait = after
                    .futex_wait
                    .checked_sub(1)
                    .ok_or(RegistryError::CreditExhausted(class))?;
            }
            RegistryCreditClass::ReadinessSubscription => {
                after.readiness_subscription = after
                    .readiness_subscription
                    .checked_sub(1)
                    .ok_or(RegistryError::CreditExhausted(class))?;
            }
            RegistryCreditClass::ReadinessWait => {
                after.readiness_wait = after
                    .readiness_wait
                    .checked_sub(1)
                    .ok_or(RegistryError::CreditExhausted(class))?;
            }
            RegistryCreditClass::ReadinessDelivery => {
                after.readiness_delivery = after
                    .readiness_delivery
                    .checked_sub(1)
                    .ok_or(RegistryError::CreditExhausted(class))?;
            }
            RegistryCreditClass::Timer => {
                after.timer = after
                    .timer
                    .checked_sub(1)
                    .ok_or(RegistryError::CreditExhausted(class))?;
            }
        }
        Ok(after)
    }

    fn checked_return(self, class: RegistryCreditClass) -> Result<Self, RegistryError> {
        let mut after = self;
        match class {
            RegistryCreditClass::Continuation => {
                after.continuation = after
                    .continuation
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
            RegistryCreditClass::ExecSegment => {
                after.exec_segment = after
                    .exec_segment
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
            RegistryCreditClass::FutexWait => {
                after.futex_wait = after
                    .futex_wait
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
            RegistryCreditClass::ReadinessSubscription => {
                after.readiness_subscription = after
                    .readiness_subscription
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
            RegistryCreditClass::ReadinessWait => {
                after.readiness_wait = after
                    .readiness_wait
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
            RegistryCreditClass::ReadinessDelivery => {
                after.readiness_delivery = after
                    .readiness_delivery
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
            RegistryCreditClass::Timer => {
                after.timer = after
                    .timer
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
        }
        Ok(after)
    }
}

/// Inspectable fields of a complete generic effect identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryTokenParts {
    /// Inherited authority scope.
    pub scope: ScopeId,
    /// Stable effect identity.
    pub effect: EffectId,
    /// Task owning the one-shot continuation.
    pub task: TaskId,
    /// Domain operation label.
    pub kind: RegistryEffectKind,
    /// One or two opaque domain resource identities.
    pub resources: RegistryResources,
    /// Renewable credit held by this effect.
    pub credit: RegistryCreditClass,
    /// Authority generation captured at registration.
    pub authority_epoch: AuthorityEpoch,
    /// Personality binding generation owning the effect.
    pub binding_epoch: BindingEpoch,
}

/// Full authenticated identity of one generic effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryEffectToken(RegistryTokenParts);

impl RegistryEffectToken {
    /// Constructs an inspectable token for negative tests.
    #[must_use]
    pub const fn from_parts(parts: RegistryTokenParts) -> Self {
        Self(parts)
    }

    /// Returns every independent identity fence.
    #[must_use]
    pub const fn parts(self) -> RegistryTokenParts {
        self.0
    }

    /// Returns the inherited authority scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.0.scope
    }

    /// Returns the stable effect identity.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.0.effect
    }

    /// Returns the blocked task identity.
    #[must_use]
    pub const fn task(self) -> TaskId {
        self.0.task
    }

    /// Returns the domain operation label.
    #[must_use]
    pub const fn kind(self) -> RegistryEffectKind {
        self.0.kind
    }

    /// Returns the opaque domain resource identity.
    #[must_use]
    pub const fn resources(self) -> RegistryResources {
        self.0.resources
    }

    /// Returns the held renewable-credit class.
    #[must_use]
    pub const fn credit(self) -> RegistryCreditClass {
        self.0.credit
    }

    /// Returns the captured authority generation.
    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        self.0.authority_epoch
    }

    /// Returns the owning personality binding generation.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.0.binding_epoch
    }
}

/// Generic effect lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryEffectState {
    /// Registered and cancellable; no immutable receipt exists.
    Registered,
    /// Commit crossed the Active gate and installed an immutable receipt.
    Committed,
    /// Kernel publication consumed the committed continuation successfully.
    Completed,
    /// Revocation consumed an uncommitted continuation with failure.
    Aborted,
}

impl RegistryEffectState {
    /// Returns whether no later transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

/// One-shot continuation consumption state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryContinuationState {
    /// No success or abort delivery consumed the continuation.
    Pending,
    /// Kernel publication consumed the unique success delivery.
    Delivered,
    /// Revocation consumed the unique terminal failure.
    Aborted,
}

/// Immutable proof that one effect crossed its commit point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryCommitReceipt {
    token: RegistryEffectToken,
    domain_receipt: u64,
    commit_sequence: u64,
}

/// One failure-atomic update of an effect's current resource membership.
///
/// The authenticated token retains its immutable origin resources.  Requeue
/// and similar domain transitions move only `current_resources` and the
/// registry reverse index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryResourceMove {
    /// Exact current effect identity.
    pub token: RegistryEffectToken,
    /// New current resource association.
    pub current_resources: RegistryResources,
}

impl RegistryCommitReceipt {
    /// Returns the effect committed by this receipt.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.token.effect()
    }

    /// Returns the exact identity at the commit point.
    #[must_use]
    pub const fn token(self) -> RegistryEffectToken {
        self.token
    }

    /// Returns the domain-owned immutable receipt identity.
    #[must_use]
    pub const fn domain_receipt(self) -> u64 {
        self.domain_receipt
    }

    /// Returns the registry commit sequence.
    #[must_use]
    pub const fn commit_sequence(self) -> u64 {
        self.commit_sequence
    }
}

/// Read-only view of one generic effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryEffectView {
    /// Current identity, updated only by explicit adoption.
    pub token: RegistryEffectToken,
    /// Current resource membership, which may differ after migration.
    pub current_resources: RegistryResources,
    /// Generic lifecycle state.
    pub state: RegistryEffectState,
    /// One-shot continuation state.
    pub continuation: RegistryContinuationState,
    /// Immutable commit receipt, if committed.
    pub receipt: Option<RegistryCommitReceipt>,
    /// Whether the typed credit remains held.
    pub credit_held: bool,
    /// Successful kernel publications.
    pub publications: u8,
    /// Terminal transitions.
    pub terminalizations: u8,
}

/// One live generic effect in a recovery snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryEffectSnapshot {
    /// Current identity at snapshot capture.
    pub token: RegistryEffectToken,
    /// Current resource membership at snapshot capture.
    pub current_resources: RegistryResources,
    /// Registered or committed state.
    pub state: RegistryEffectState,
    /// Immutable receipt, if already committed.
    pub receipt: Option<RegistryCommitReceipt>,
}

/// Exact crash-recovery view for one prospective replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryRecoverySnapshot {
    gate: PersonalityRecoverySnapshot,
    effects: Vec<RegistryEffectSnapshot>,
    watchdog_cohort: Vec<EffectId>,
}

impl RegistryRecoverySnapshot {
    /// Returns the represented scope.
    #[must_use]
    pub const fn scope(&self) -> ScopeId {
        self.gate.scope()
    }

    /// Returns the prospective replacement identity.
    #[must_use]
    pub const fn personality(&self) -> PersonalityId {
        self.gate.personality()
    }

    /// Returns deterministic live effects.
    #[must_use]
    pub fn effects(&self) -> &[RegistryEffectSnapshot] {
        &self.effects
    }

    /// Returns effects still protected by the recovery watchdog.
    #[must_use]
    pub fn watchdog_cohort(&self) -> &[EffectId] {
        &self.watchdog_cohort
    }
}

/// Ready proof wrapping the shared personality gate proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryReadyToken {
    gate: PersonalityReadyToken,
}

impl RegistryReadyToken {
    /// Returns the prospective replacement identity.
    #[must_use]
    pub const fn personality(self) -> PersonalityId {
        self.gate.personality()
    }

    /// Returns the post-crash binding generation.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.gate.binding_epoch()
    }
}

/// Bounded scope-local revocation progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryRevocationProgress {
    /// Closed authority generation.
    pub closed_epoch: AuthorityEpoch,
    /// Live effects captured at `revoke_begin`.
    pub target_count: usize,
    /// Effects terminalized so far.
    pub terminalized: usize,
    /// Successful scope-local index selections.
    pub index_selections: usize,
    /// Effects still live.
    pub remaining: usize,
}

/// Read-only scope projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryScopeView {
    /// Shared authority/binding/fallback gate.
    pub gate: PersonalityScopeView,
    /// Initial typed resource budget.
    pub initial_budget: RegistryBudget,
    /// Currently free typed resource budget.
    pub free_budget: RegistryBudget,
    /// Scope-local live effects in deterministic identity order.
    pub live_effects: Vec<EffectId>,
    /// Scope-local committed effects in deterministic identity order.
    pub committed_effects: Vec<EffectId>,
    /// Exact scope-local reverse index grouped by opaque resource.
    pub resources: Vec<RegistryResourceView>,
    /// Crash cohort still requiring adoption or terminalization.
    pub watchdog_cohort: Option<Vec<EffectId>>,
    /// Closure progress after revocation begins.
    pub revocation: Option<RegistryRevocationProgress>,
}

/// One opaque resource and its exact live-effect reverse index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryResourceView {
    /// Opaque domain resource identity.
    pub resource: RegistryResourceKey,
    /// Live effects currently associated with this resource.
    pub effects: Vec<EffectId>,
}

/// Result of one generic scope-local closure step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryRevocationStep {
    /// One committed effect was drained through its immutable receipt.
    Drained {
        /// Terminalized effect.
        effect: EffectId,
    },
    /// One uncommitted effect was aborted.
    Aborted {
        /// Terminalized effect.
        effect: EffectId,
    },
}

/// Successful registry actions in total linearization order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryAction {
    /// Create one active scope.
    CreateScope,
    /// Register one effect and reserve one typed credit.
    Register,
    /// Publish a successor-domain change into snapshot freshness.
    DomainChanged,
    /// Atomically commit one or more effects.
    Commit,
    /// Atomically publish one or more committed effects.
    Complete,
    /// Fence a crashed personality.
    Crash,
    /// Select kernel fallback.
    FallbackPick,
    /// Accept an exact recovery snapshot.
    Ready,
    /// Install the ready replacement.
    Rebind,
    /// Transfer one orphan explicitly.
    Adopt,
    /// Close authority explicitly.
    RevokeBegin,
    /// Close authority through watchdog expiry.
    WatchdogExpire,
    /// Drain or abort one scope-local effect.
    RevokeStep,
    /// Publish quiescent closure.
    RevokeComplete,
}

/// One successful registry trace event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryTraceEvent {
    /// Zero-based total-order position.
    pub seq: usize,
    /// Linearized action.
    pub action: RegistryAction,
    /// Affected scope.
    pub scope: ScopeId,
    /// Primary effect, if any.
    pub effect: Option<EffectId>,
    /// Authority generation after the action.
    pub authority_epoch: AuthorityEpoch,
    /// Binding generation after the action.
    pub binding_epoch: BindingEpoch,
}

/// Rejected registry transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// Shared authority/binding gate rejection.
    Personality(PersonalityError),
    /// Unknown effect identity.
    UnknownEffect(EffectId),
    /// Presented token differs from the complete recorded identity.
    EffectIdentityMismatch,
    /// One task already owns a live continuation in this scope.
    TaskAlreadyBlocked {
        /// Existing live effect.
        effect: EffectId,
    },
    /// No credit of the requested class is free.
    CreditExhausted(RegistryCreditClass),
    /// Effect kind and supplied renewable credit class disagree.
    WrongCreditClass {
        /// Authenticated effect kind.
        kind: RegistryEffectKind,
        /// Rejected credit class.
        credit: RegistryCreditClass,
    },
    /// Crash recovery requires at least one timer credit.
    MissingWatchdogBudget,
    /// Effect state does not permit the requested transition.
    InvalidEffectState {
        /// Actual effect state.
        state: RegistryEffectState,
    },
    /// One batch contains duplicate effects or spans scopes.
    InvalidBatch,
    /// Presented immutable receipt differs from the committed receipt.
    CommitReceiptMismatch,
    /// Effect is not an old-binding orphan eligible for adoption.
    NotAdoptable,
    /// No incomplete crash cohort owns the watchdog.
    WatchdogNotArmed,
    /// Closure completion was requested while effects remain live.
    RevocationNotQuiescent {
        /// Remaining live effects.
        remaining: usize,
    },
    /// Counter or typed credit arithmetic overflowed.
    CounterOverflow,
    /// Internal model relationships were inconsistent.
    InvariantViolation(&'static str),
}

impl From<PersonalityError> for RegistryError {
    fn from(error: PersonalityError) -> Self {
        Self::Personality(error)
    }
}

/// Failure reported by a complete registry invariant audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryInvariantViolation {
    /// Shared personality gate is inconsistent.
    Personality(super::PersonalityInvariantViolation),
    /// Local scope has no matching gate scope.
    MissingGateScope(ScopeId),
    /// Scope-local live index is not exact.
    LiveIndex(ScopeId),
    /// Scope-local committed index is not exact.
    CommittedIndex(ScopeId),
    /// Scope-local by-resource reverse index is not exact.
    ResourceIndex(ScopeId),
    /// Task ownership index is not exact.
    TaskIndex(EffectId),
    /// Effect token names missing or future state.
    OrphanOrFutureEffect(EffectId),
    /// Effect lifecycle, continuation, receipt, or terminal count disagree.
    SingleTerminalization(EffectId),
    /// One typed credit ledger is not conserved.
    BudgetConservation(ScopeId),
    /// Watchdog ownership or cohort is inconsistent.
    WatchdogCohort(ScopeId),
    /// Scope state and closure accounting disagree.
    RevocationProgress(ScopeId),
    /// Trace positions are not contiguous.
    TraceOrder,
}

impl From<super::PersonalityInvariantViolation> for RegistryInvariantViolation {
    fn from(error: super::PersonalityInvariantViolation) -> Self {
        Self::Personality(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegistryEffectRecord {
    token: RegistryEffectToken,
    current_resources: RegistryResources,
    state: RegistryEffectState,
    continuation: RegistryContinuationState,
    receipt: Option<RegistryCommitReceipt>,
    credit_held: bool,
    publications: u8,
    terminalizations: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegistryRevocationRecord {
    closed_epoch: AuthorityEpoch,
    target_count: usize,
    terminalized: usize,
    index_selections: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegistryScopeRecord {
    initial_budget: RegistryBudget,
    free_budget: RegistryBudget,
    live_effects: BTreeSet<EffectId>,
    committed_effects: BTreeSet<EffectId>,
    by_resource: BTreeMap<RegistryResourceKey, BTreeSet<EffectId>>,
    watchdog: Option<BTreeSet<EffectId>>,
    revocation: Option<RegistryRevocationRecord>,
}

/// Deterministic `no_std + alloc` common personality effect registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRegistry {
    gate: PersonalityModel,
    next_effect: u64,
    next_commit: u64,
    scopes: BTreeMap<ScopeId, RegistryScopeRecord>,
    effects: BTreeMap<EffectId, RegistryEffectRecord>,
    blocked_tasks: BTreeMap<(ScopeId, TaskId), EffectId>,
    trace: Vec<RegistryTraceEvent>,
}

impl Default for EffectRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl EffectRegistry {
    /// Creates an empty common registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            gate: PersonalityModel::new(),
            next_effect: 1,
            next_commit: 1,
            scopes: BTreeMap::new(),
            effects: BTreeMap::new(),
            blocked_tasks: BTreeMap::new(),
            trace: Vec::new(),
        }
    }

    /// Creates one active personality scope with typed renewable credits.
    pub fn create_scope(
        &mut self,
        personality: PersonalityId,
        budget: RegistryBudget,
    ) -> Result<(ScopeId, PersonalityBindingToken), RegistryError> {
        if budget.timer == 0 {
            return Err(RegistryError::MissingWatchdogBudget);
        }
        let (scope, binding) = self.gate.create_scope(personality)?;
        self.scopes.insert(
            scope,
            RegistryScopeRecord {
                initial_budget: budget,
                free_budget: budget,
                live_effects: BTreeSet::new(),
                committed_effects: BTreeSet::new(),
                by_resource: BTreeMap::new(),
                watchdog: None,
                revocation: None,
            },
        );
        self.push_trace(RegistryAction::CreateScope, scope, None);
        Ok((scope, binding))
    }

    /// Registers one effect, blocks its task, and reserves one typed credit.
    pub fn register(
        &mut self,
        binding: PersonalityBindingToken,
        task: TaskId,
        kind: RegistryEffectKind,
        resources: RegistryResources,
        credit: RegistryCreditClass,
    ) -> Result<RegistryEffectToken, RegistryError> {
        self.gate.validate_refinement_binding(binding)?;
        if kind.credit_class() != credit {
            return Err(RegistryError::WrongCreditClass { kind, credit });
        }
        if kind.blocks_task()
            && let Some(effect) = self.blocked_tasks.get(&(binding.scope(), task))
        {
            return Err(RegistryError::TaskAlreadyBlocked { effect: *effect });
        }
        let scope = self.local_scope(binding.scope())?;
        if credit == RegistryCreditClass::Timer && scope.free_budget.timer <= 1 {
            return Err(RegistryError::CreditExhausted(credit));
        }
        let free_after = scope.free_budget.checked_take(credit)?;
        let effect = EffectId::new(self.next_effect);
        let next_effect = self
            .next_effect
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let token = RegistryEffectToken(RegistryTokenParts {
            scope: binding.scope(),
            effect,
            task,
            kind,
            resources,
            credit,
            authority_epoch: binding.authority_epoch(),
            binding_epoch: binding.binding_epoch(),
        });

        self.gate.refinement_changed(binding.scope())?;
        self.next_effect = next_effect;
        let scope = self.local_scope_mut(binding.scope())?;
        scope.free_budget = free_after;
        scope.live_effects.insert(effect);
        for resource in resources.iter() {
            scope
                .by_resource
                .entry(resource)
                .or_default()
                .insert(effect);
        }
        self.effects.insert(
            effect,
            RegistryEffectRecord {
                token,
                current_resources: resources,
                state: RegistryEffectState::Registered,
                continuation: RegistryContinuationState::Pending,
                receipt: None,
                credit_held: true,
                publications: 0,
                terminalizations: 0,
            },
        );
        if kind.blocks_task() {
            self.blocked_tasks.insert((binding.scope(), task), effect);
        }
        self.push_trace(RegistryAction::Register, binding.scope(), Some(effect));
        Ok(token)
    }

    /// Commits one registered effect and binds an immutable domain receipt.
    pub fn commit(
        &mut self,
        binding: PersonalityBindingToken,
        token: RegistryEffectToken,
        domain_receipt: u64,
    ) -> Result<RegistryCommitReceipt, RegistryError> {
        let receipts = self.commit_many(binding, &[(token, domain_receipt)])?;
        Ok(receipts[0])
    }

    /// Atomically commits a nonempty batch from one active scope.
    ///
    /// Every identity and counter is validated before the shared recovery
    /// revision or any effect state changes, so a rejected batch is failure
    /// atomic.  This is the generic transaction used by futex wake/requeue.
    pub fn commit_many(
        &mut self,
        binding: PersonalityBindingToken,
        requests: &[(RegistryEffectToken, u64)],
    ) -> Result<Vec<RegistryCommitReceipt>, RegistryError> {
        self.commit_with_moves(binding, requests, &[])
    }

    /// Atomically commits effects and moves other registered effects between
    /// opaque resource indexes.
    ///
    /// Commit and move sets must be disjoint.  This is the common transaction
    /// required by two-key futex requeue: the woken waiter commits while the
    /// migrated waiter remains registered under a new current resource.
    pub fn commit_with_moves(
        &mut self,
        binding: PersonalityBindingToken,
        requests: &[(RegistryEffectToken, u64)],
        moves: &[RegistryResourceMove],
    ) -> Result<Vec<RegistryCommitReceipt>, RegistryError> {
        self.gate.validate_refinement_binding(binding)?;
        if requests.is_empty() {
            return Err(RegistryError::InvalidBatch);
        }
        let mut seen = BTreeSet::new();
        for (token, _) in requests {
            if token.scope() != binding.scope() || !seen.insert(token.effect()) {
                return Err(RegistryError::InvalidBatch);
            }
            let record = self.validate_token(*token)?;
            if record.state != RegistryEffectState::Registered {
                return Err(RegistryError::InvalidEffectState {
                    state: record.state,
                });
            }
            if token.authority_epoch() != binding.authority_epoch()
                || token.binding_epoch() != binding.binding_epoch()
            {
                return Err(RegistryError::EffectIdentityMismatch);
            }
        }
        for movement in moves {
            let token = movement.token;
            if token.scope() != binding.scope() || !seen.insert(token.effect()) {
                return Err(RegistryError::InvalidBatch);
            }
            let record = self.validate_token(token)?;
            if record.state != RegistryEffectState::Registered {
                return Err(RegistryError::InvalidEffectState {
                    state: record.state,
                });
            }
            if token.authority_epoch() != binding.authority_epoch()
                || token.binding_epoch() != binding.binding_epoch()
            {
                return Err(RegistryError::EffectIdentityMismatch);
            }
        }
        let count = u64::try_from(requests.len()).map_err(|_| RegistryError::CounterOverflow)?;
        let next_commit = self
            .next_commit
            .checked_add(count)
            .ok_or(RegistryError::CounterOverflow)?;
        let receipts: Vec<_> = requests
            .iter()
            .enumerate()
            .map(|(offset, (token, domain_receipt))| {
                let offset = u64::try_from(offset).expect("request length converted above");
                RegistryCommitReceipt {
                    token: *token,
                    domain_receipt: *domain_receipt,
                    commit_sequence: self.next_commit + offset,
                }
            })
            .collect();

        self.gate.refinement_changed(binding.scope())?;
        self.next_commit = next_commit;
        for movement in moves {
            let effect = movement.token.effect();
            let before = self
                .effects
                .get(&effect)
                .ok_or(RegistryError::UnknownEffect(effect))?
                .current_resources;
            {
                let scope = self.local_scope_mut(binding.scope())?;
                for resource in before.iter() {
                    if let Some(index) = scope.by_resource.get_mut(&resource) {
                        index.remove(&effect);
                        if index.is_empty() {
                            scope.by_resource.remove(&resource);
                        }
                    }
                }
                for resource in movement.current_resources.iter() {
                    scope
                        .by_resource
                        .entry(resource)
                        .or_default()
                        .insert(effect);
                }
            }
            self.effects
                .get_mut(&effect)
                .ok_or(RegistryError::UnknownEffect(effect))?
                .current_resources = movement.current_resources;
        }
        for receipt in &receipts {
            let record = self
                .effects
                .get_mut(&receipt.effect())
                .ok_or(RegistryError::UnknownEffect(receipt.effect()))?;
            record.state = RegistryEffectState::Committed;
            record.receipt = Some(*receipt);
            self.local_scope_mut(binding.scope())?
                .committed_effects
                .insert(receipt.effect());
        }
        self.push_trace(
            RegistryAction::Commit,
            binding.scope(),
            receipts.first().map(|receipt| receipt.effect()),
        );
        Ok(receipts)
    }

    /// Publishes one committed effect through its immutable receipt.
    pub fn complete(&mut self, receipt: RegistryCommitReceipt) -> Result<(), RegistryError> {
        self.complete_many(&[receipt])
    }

    /// Atomically publishes a nonempty batch of committed effects.
    pub fn complete_many(
        &mut self,
        receipts: &[RegistryCommitReceipt],
    ) -> Result<(), RegistryError> {
        if receipts.is_empty() {
            return Err(RegistryError::InvalidBatch);
        }
        let scope_id = receipts[0].token.scope();
        let mut seen = BTreeSet::new();
        for receipt in receipts {
            if receipt.token.scope() != scope_id || !seen.insert(receipt.effect()) {
                return Err(RegistryError::InvalidBatch);
            }
            let record = self
                .effects
                .get(&receipt.effect())
                .ok_or(RegistryError::UnknownEffect(receipt.effect()))?;
            if record.state != RegistryEffectState::Committed {
                return Err(RegistryError::InvalidEffectState {
                    state: record.state,
                });
            }
            if record.receipt != Some(*receipt) {
                return Err(RegistryError::CommitReceiptMismatch);
            }
        }
        let scope = self.local_scope(scope_id)?;
        let mut free_after = scope.free_budget;
        for receipt in receipts {
            free_after = free_after.checked_return(receipt.token.credit())?;
        }
        let terminalized_after = scope.revocation.map(|revocation| {
            revocation
                .terminalized
                .checked_add(receipts.len())
                .ok_or(RegistryError::CounterOverflow)
        });
        let terminalized_after = terminalized_after.transpose()?;
        let removed: BTreeSet<_> = receipts.iter().map(|receipt| receipt.effect()).collect();
        let removed_resources: Vec<_> = receipts
            .iter()
            .map(|receipt| {
                let resources = self
                    .effects
                    .get(&receipt.effect())
                    .expect("validated committed effect remains present")
                    .current_resources;
                (receipt.effect(), resources)
            })
            .collect();
        let timer_return = self.timer_return_after_removing(scope_id, &removed)?;

        self.gate.refinement_changed(scope_id)?;
        for receipt in receipts {
            let record = self
                .effects
                .get_mut(&receipt.effect())
                .ok_or(RegistryError::UnknownEffect(receipt.effect()))?;
            record.state = RegistryEffectState::Completed;
            record.continuation = RegistryContinuationState::Delivered;
            record.credit_held = false;
            record.publications = 1;
            record.terminalizations = 1;
            if record.token.kind().blocks_task() {
                self.blocked_tasks.remove(&(scope_id, record.token.task()));
            }
        }
        let scope = self.local_scope_mut(scope_id)?;
        scope.free_budget = free_after;
        for (effect, resources) in &removed_resources {
            scope.live_effects.remove(effect);
            scope.committed_effects.remove(effect);
            for resource in resources.iter() {
                if let Some(index) = scope.by_resource.get_mut(&resource) {
                    index.remove(effect);
                    if index.is_empty() {
                        scope.by_resource.remove(&resource);
                    }
                }
            }
        }
        if let Some(terminalized_after) = terminalized_after {
            scope
                .revocation
                .as_mut()
                .ok_or(RegistryError::InvariantViolation(
                    "closing scope lost revocation metadata",
                ))?
                .terminalized = terminalized_after;
        }
        self.remove_from_watchdog(scope_id, &removed, timer_return)?;
        self.push_trace(
            RegistryAction::Complete,
            scope_id,
            receipts.first().map(|receipt| receipt.effect()),
        );
        Ok(())
    }

    /// Fences a crashed personality and protects its exact live cohort.
    pub fn crash(&mut self, binding: PersonalityBindingToken) -> Result<(), RegistryError> {
        self.gate.validate_refinement_binding(binding)?;
        let scope = self.local_scope(binding.scope())?;
        let needs_timer = !scope.live_effects.is_empty() && scope.watchdog.is_none();
        if needs_timer && scope.free_budget.timer == 0 {
            return Err(RegistryError::MissingWatchdogBudget);
        }
        let free_after = if needs_timer {
            Some(RegistryBudget {
                timer: scope
                    .free_budget
                    .timer
                    .checked_sub(1)
                    .ok_or(RegistryError::MissingWatchdogBudget)?,
                ..scope.free_budget
            })
        } else {
            None
        };
        let cohort = scope.live_effects.clone();

        self.gate.crash(binding)?;
        let scope = self.local_scope_mut(binding.scope())?;
        if cohort.is_empty() {
            scope.watchdog = None;
        } else {
            if let Some(free_after) = free_after {
                scope.free_budget = free_after;
            }
            scope.watchdog = Some(cohort);
        }
        self.push_trace(RegistryAction::Crash, binding.scope(), None);
        Ok(())
    }

    /// Selects kernel fallback through the shared personality gate.
    pub fn fallback_pick(&mut self, scope: ScopeId) -> Result<(), RegistryError> {
        self.local_scope(scope)?;
        self.gate.fallback_pick(scope)?;
        self.push_trace(RegistryAction::FallbackPick, scope, None);
        Ok(())
    }

    /// Publishes a domain-only state change into recovery snapshot freshness.
    ///
    /// Successor domains invoke this only after completing every fallible
    /// check.  A change after `ready` invalidates that proof and returns the
    /// common fallback gate to its running state for a fresh snapshot.
    pub fn domain_changed(&mut self, scope: ScopeId) -> Result<(), RegistryError> {
        self.local_scope(scope)?;
        self.gate.refinement_changed(scope)?;
        self.push_trace(RegistryAction::DomainChanged, scope, None);
        Ok(())
    }

    /// Captures an exact immutable registry recovery image.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        personality: PersonalityId,
    ) -> Result<RegistryRecoverySnapshot, RegistryError> {
        let gate = self.gate.recovery_snapshot(scope, personality)?;
        let local = self.local_scope(scope)?;
        let effects = local
            .live_effects
            .iter()
            .map(|effect| {
                let record = self
                    .effects
                    .get(effect)
                    .ok_or(RegistryError::UnknownEffect(*effect))?;
                Ok(RegistryEffectSnapshot {
                    token: record.token,
                    current_resources: record.current_resources,
                    state: record.state,
                    receipt: record.receipt,
                })
            })
            .collect::<Result<Vec<_>, RegistryError>>()?;
        Ok(RegistryRecoverySnapshot {
            gate,
            effects,
            watchdog_cohort: local
                .watchdog
                .as_ref()
                .map_or_else(Vec::new, |cohort| cohort.iter().copied().collect()),
        })
    }

    /// Accepts readiness only while the gate and registry image remain exact.
    pub fn ready(
        &mut self,
        snapshot: &RegistryRecoverySnapshot,
    ) -> Result<RegistryReadyToken, RegistryError> {
        self.validate_local_snapshot(snapshot)?;
        let gate = self.gate.ready(&snapshot.gate)?;
        self.push_trace(RegistryAction::Ready, snapshot.scope(), None);
        Ok(RegistryReadyToken { gate })
    }

    /// Installs a ready replacement without adopting any effect implicitly.
    pub fn rebind(
        &mut self,
        ready: RegistryReadyToken,
    ) -> Result<PersonalityBindingToken, RegistryError> {
        let scope = ready.gate.scope;
        self.local_scope(scope)?;
        let binding = self.gate.rebind(ready.gate)?;
        self.push_trace(RegistryAction::Rebind, scope, None);
        Ok(binding)
    }

    /// Explicitly transfers one old-binding nonterminal effect.
    pub fn adopt(
        &mut self,
        binding: PersonalityBindingToken,
        token: RegistryEffectToken,
    ) -> Result<RegistryEffectToken, RegistryError> {
        self.gate.validate_refinement_binding(binding)?;
        let gate = self
            .gate
            .scope(binding.scope())
            .ok_or(PersonalityError::UnknownScope(binding.scope()))?;
        let record = *self.validate_token(token)?;
        if token.scope() != binding.scope() || token.authority_epoch() != gate.authority_epoch {
            return Err(RegistryError::EffectIdentityMismatch);
        }
        if record.state.is_terminal() || token.binding_epoch() == gate.binding_epoch {
            return Err(RegistryError::NotAdoptable);
        }
        let removed = BTreeSet::from([token.effect()]);
        let timer_return = self.timer_return_after_removing(binding.scope(), &removed)?;

        self.gate.refinement_changed(binding.scope())?;
        let mut parts = token.parts();
        parts.binding_epoch = gate.binding_epoch;
        let adopted = RegistryEffectToken(parts);
        self.effects
            .get_mut(&token.effect())
            .ok_or(RegistryError::UnknownEffect(token.effect()))?
            .token = adopted;
        self.remove_from_watchdog(binding.scope(), &removed, timer_return)?;
        self.push_trace(RegistryAction::Adopt, binding.scope(), Some(token.effect()));
        Ok(adopted)
    }

    /// Closes authority explicitly.
    pub fn revoke_begin(&mut self, scope: ScopeId) -> Result<(), RegistryError> {
        self.begin_revocation(scope, RegistryAction::RevokeBegin)
    }

    /// Expires an incomplete recovery cohort and closes authority.
    pub fn watchdog_expire(&mut self, scope: ScopeId) -> Result<(), RegistryError> {
        let local = self.local_scope(scope)?;
        if local.watchdog.as_ref().is_none_or(BTreeSet::is_empty) {
            return Err(RegistryError::WatchdogNotArmed);
        }
        self.begin_revocation(scope, RegistryAction::WatchdogExpire)
    }

    /// Performs one scope-local generic closure step.
    pub fn revoke_next(
        &mut self,
        scope: ScopeId,
    ) -> Result<Option<RegistryRevocationStep>, RegistryError> {
        let gate = self
            .gate
            .scope(scope)
            .ok_or(PersonalityError::UnknownScope(scope))?;
        if gate.state != ScopeState::Closing {
            return Err(RegistryError::Personality(
                PersonalityError::InvalidScopeState { state: gate.state },
            ));
        }
        let local = self.local_scope(scope)?;
        if local.revocation.is_none() {
            return Err(RegistryError::InvariantViolation(
                "closing scope lacks registry revocation metadata",
            ));
        }
        if let Some(effect) = local.committed_effects.iter().next().copied() {
            let receipt = self
                .effects
                .get(&effect)
                .ok_or(RegistryError::UnknownEffect(effect))?
                .receipt
                .ok_or(RegistryError::InvariantViolation(
                    "committed effect lacks immutable receipt",
                ))?;
            self.complete(receipt)?;
            self.note_index_selection(scope)?;
            return Ok(Some(RegistryRevocationStep::Drained { effect }));
        }
        let Some(effect) = local.live_effects.iter().next().copied() else {
            return Ok(None);
        };
        self.abort_registered(scope, effect)?;
        self.note_index_selection(scope)?;
        Ok(Some(RegistryRevocationStep::Aborted { effect }))
    }

    /// Publishes quiescent closure after every live effect terminalizes.
    pub fn revoke_complete(&mut self, scope: ScopeId) -> Result<(), RegistryError> {
        let local = self.local_scope(scope)?;
        if !local.live_effects.is_empty() {
            return Err(RegistryError::RevocationNotQuiescent {
                remaining: local.live_effects.len(),
            });
        }
        if !local.committed_effects.is_empty()
            || local.watchdog.is_some()
            || local.free_budget != local.initial_budget
        {
            return Err(RegistryError::InvariantViolation(
                "quiescent registry retains index, watchdog, or credit",
            ));
        }
        let revocation = local.revocation.ok_or(RegistryError::InvariantViolation(
            "closing scope lacks registry revocation metadata",
        ))?;
        if revocation.terminalized != revocation.target_count {
            return Err(RegistryError::InvariantViolation(
                "closure terminalized a different effect count",
            ));
        }
        self.gate.revoke_complete(scope)?;
        self.push_trace(RegistryAction::RevokeComplete, scope, None);
        Ok(())
    }

    /// Returns whether a token is owned by the supplied current binding.
    pub fn is_current(&self, binding: PersonalityBindingToken, token: RegistryEffectToken) -> bool {
        self.gate.validate_refinement_binding(binding).is_ok()
            && self.validate_token(token).is_ok()
            && token.scope() == binding.scope()
            && token.authority_epoch() == binding.authority_epoch()
            && token.binding_epoch() == binding.binding_epoch()
    }

    /// Returns a read-only scope projection.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<RegistryScopeView> {
        let gate = self.gate.scope(scope)?;
        let local = self.scopes.get(&scope)?;
        Some(RegistryScopeView {
            gate,
            initial_budget: local.initial_budget,
            free_budget: local.free_budget,
            live_effects: local.live_effects.iter().copied().collect(),
            committed_effects: local.committed_effects.iter().copied().collect(),
            resources: local
                .by_resource
                .iter()
                .map(|(resource, effects)| RegistryResourceView {
                    resource: *resource,
                    effects: effects.iter().copied().collect(),
                })
                .collect(),
            watchdog_cohort: local
                .watchdog
                .as_ref()
                .map(|cohort| cohort.iter().copied().collect()),
            revocation: local
                .revocation
                .map(|revocation| RegistryRevocationProgress {
                    closed_epoch: revocation.closed_epoch,
                    target_count: revocation.target_count,
                    terminalized: revocation.terminalized,
                    index_selections: revocation.index_selections,
                    remaining: local.live_effects.len(),
                }),
        })
    }

    /// Returns a read-only effect projection.
    #[must_use]
    pub fn effect(&self, effect: EffectId) -> Option<RegistryEffectView> {
        self.effects.get(&effect).map(|record| RegistryEffectView {
            token: record.token,
            current_resources: record.current_resources,
            state: record.state,
            continuation: record.continuation,
            receipt: record.receipt,
            credit_held: record.credit_held,
            publications: record.publications,
            terminalizations: record.terminalizations,
        })
    }

    /// Returns the successful total-order trace.
    #[must_use]
    pub fn trace(&self) -> &[RegistryTraceEvent] {
        &self.trace
    }

    /// Audits authority, indexes, identities, credits, watchdog, and closure.
    pub fn check_invariants(&self) -> Result<(), RegistryInvariantViolation> {
        self.gate.check_invariants()?;
        for (scope_id, local) in &self.scopes {
            let Some(gate) = self.gate.scope(*scope_id) else {
                return Err(RegistryInvariantViolation::MissingGateScope(*scope_id));
            };
            let expected_live: BTreeSet<_> = self
                .effects
                .iter()
                .filter_map(|(effect, record)| {
                    (record.token.scope() == *scope_id && !record.state.is_terminal())
                        .then_some(*effect)
                })
                .collect();
            if local.live_effects != expected_live {
                return Err(RegistryInvariantViolation::LiveIndex(*scope_id));
            }
            let expected_committed: BTreeSet<_> = self
                .effects
                .iter()
                .filter_map(|(effect, record)| {
                    (record.token.scope() == *scope_id
                        && record.state == RegistryEffectState::Committed)
                        .then_some(*effect)
                })
                .collect();
            if local.committed_effects != expected_committed {
                return Err(RegistryInvariantViolation::CommittedIndex(*scope_id));
            }
            let mut expected_resources: BTreeMap<RegistryResourceKey, BTreeSet<EffectId>> =
                BTreeMap::new();
            for effect in &expected_live {
                let record = self
                    .effects
                    .get(effect)
                    .ok_or(RegistryInvariantViolation::OrphanOrFutureEffect(*effect))?;
                for resource in record.current_resources.iter() {
                    expected_resources
                        .entry(resource)
                        .or_default()
                        .insert(*effect);
                }
            }
            if local.by_resource != expected_resources {
                return Err(RegistryInvariantViolation::ResourceIndex(*scope_id));
            }
            for class in [
                RegistryCreditClass::Continuation,
                RegistryCreditClass::ExecSegment,
                RegistryCreditClass::FutexWait,
                RegistryCreditClass::ReadinessSubscription,
                RegistryCreditClass::ReadinessWait,
                RegistryCreditClass::ReadinessDelivery,
                RegistryCreditClass::Timer,
            ] {
                let mut held = self
                    .effects
                    .values()
                    .filter(|record| {
                        record.token.scope() == *scope_id
                            && record.token.credit() == class
                            && record.credit_held
                    })
                    .count() as u64;
                if class == RegistryCreditClass::Timer && local.watchdog.is_some() {
                    held = held
                        .checked_add(1)
                        .ok_or(RegistryInvariantViolation::BudgetConservation(*scope_id))?;
                }
                if local.free_budget.get(class).checked_add(held)
                    != Some(local.initial_budget.get(class))
                {
                    return Err(RegistryInvariantViolation::BudgetConservation(*scope_id));
                }
            }
            if let Some(cohort) = &local.watchdog
                && (cohort.is_empty()
                    || cohort.iter().any(|effect| {
                        !local.live_effects.contains(effect)
                            || self.effects.get(effect).is_none_or(|record| {
                                record.token.binding_epoch() >= gate.binding_epoch
                            })
                    }))
            {
                return Err(RegistryInvariantViolation::WatchdogCohort(*scope_id));
            }
            match gate.state {
                ScopeState::Active => {
                    if local.revocation.is_some() {
                        return Err(RegistryInvariantViolation::RevocationProgress(*scope_id));
                    }
                }
                ScopeState::Closing | ScopeState::Revoked => {
                    let Some(revocation) = local.revocation else {
                        return Err(RegistryInvariantViolation::RevocationProgress(*scope_id));
                    };
                    if revocation.terminalized > revocation.target_count
                        || revocation.terminalized + local.live_effects.len()
                            != revocation.target_count
                        || revocation.index_selections > revocation.terminalized
                    {
                        return Err(RegistryInvariantViolation::RevocationProgress(*scope_id));
                    }
                }
            }
        }

        for (effect, record) in &self.effects {
            let Some(gate) = self.gate.scope(record.token.scope()) else {
                return Err(RegistryInvariantViolation::OrphanOrFutureEffect(*effect));
            };
            if record.token.effect() != *effect
                || record.token.authority_epoch() > gate.authority_epoch
                || record.token.binding_epoch() > gate.binding_epoch
            {
                return Err(RegistryInvariantViolation::OrphanOrFutureEffect(*effect));
            }
            let blocked = self
                .blocked_tasks
                .get(&(record.token.scope(), record.token.task()));
            if record.token.kind().blocks_task() {
                if record.state.is_terminal() {
                    if blocked == Some(effect) {
                        return Err(RegistryInvariantViolation::TaskIndex(*effect));
                    }
                } else if blocked != Some(effect) {
                    return Err(RegistryInvariantViolation::TaskIndex(*effect));
                }
            } else if blocked == Some(effect) {
                return Err(RegistryInvariantViolation::TaskIndex(*effect));
            }
            let valid = match record.state {
                RegistryEffectState::Registered => {
                    record.continuation == RegistryContinuationState::Pending
                        && record.receipt.is_none()
                        && record.credit_held
                        && record.publications == 0
                        && record.terminalizations == 0
                }
                RegistryEffectState::Committed => {
                    record.continuation == RegistryContinuationState::Pending
                        && record.receipt.is_some()
                        && record.credit_held
                        && record.publications == 0
                        && record.terminalizations == 0
                }
                RegistryEffectState::Completed => {
                    record.continuation == RegistryContinuationState::Delivered
                        && record.receipt.is_some()
                        && !record.credit_held
                        && record.publications == 1
                        && record.terminalizations == 1
                }
                RegistryEffectState::Aborted => {
                    record.continuation == RegistryContinuationState::Aborted
                        && record.receipt.is_none()
                        && !record.credit_held
                        && record.publications == 0
                        && record.terminalizations == 1
                }
            };
            if !valid {
                return Err(RegistryInvariantViolation::SingleTerminalization(*effect));
            }
        }

        for ((scope, task), effect) in &self.blocked_tasks {
            let Some(record) = self.effects.get(effect) else {
                return Err(RegistryInvariantViolation::TaskIndex(*effect));
            };
            if record.token.scope() != *scope
                || record.token.task() != *task
                || !record.token.kind().blocks_task()
                || record.state.is_terminal()
            {
                return Err(RegistryInvariantViolation::TaskIndex(*effect));
            }
        }
        if self
            .trace
            .iter()
            .enumerate()
            .any(|(seq, event)| event.seq != seq)
        {
            return Err(RegistryInvariantViolation::TraceOrder);
        }
        Ok(())
    }

    fn local_scope(&self, scope: ScopeId) -> Result<&RegistryScopeRecord, RegistryError> {
        self.scopes
            .get(&scope)
            .ok_or(RegistryError::InvariantViolation(
                "shared gate scope lacks registry state",
            ))
    }

    fn local_scope_mut(
        &mut self,
        scope: ScopeId,
    ) -> Result<&mut RegistryScopeRecord, RegistryError> {
        self.scopes
            .get_mut(&scope)
            .ok_or(RegistryError::InvariantViolation(
                "shared gate scope lacks registry state",
            ))
    }

    fn validate_token(
        &self,
        token: RegistryEffectToken,
    ) -> Result<&RegistryEffectRecord, RegistryError> {
        let record = self
            .effects
            .get(&token.effect())
            .ok_or(RegistryError::UnknownEffect(token.effect()))?;
        if record.token != token {
            return Err(RegistryError::EffectIdentityMismatch);
        }
        Ok(record)
    }

    fn validate_local_snapshot(
        &self,
        snapshot: &RegistryRecoverySnapshot,
    ) -> Result<(), RegistryError> {
        let current = self.recovery_snapshot(snapshot.scope(), snapshot.personality())?;
        if current != *snapshot {
            return Err(RegistryError::Personality(
                PersonalityError::StaleRecoverySnapshot,
            ));
        }
        Ok(())
    }

    fn begin_revocation(
        &mut self,
        scope: ScopeId,
        action: RegistryAction,
    ) -> Result<(), RegistryError> {
        let gate = self
            .gate
            .scope(scope)
            .ok_or(PersonalityError::UnknownScope(scope))?;
        let local = self.local_scope(scope)?;
        let record = RegistryRevocationRecord {
            closed_epoch: gate.authority_epoch,
            target_count: local.live_effects.len(),
            terminalized: 0,
            index_selections: 0,
        };
        self.gate.revoke_begin(scope)?;
        self.local_scope_mut(scope)?.revocation = Some(record);
        self.push_trace(action, scope, None);
        Ok(())
    }

    fn abort_registered(&mut self, scope: ScopeId, effect: EffectId) -> Result<(), RegistryError> {
        let record = *self
            .effects
            .get(&effect)
            .ok_or(RegistryError::UnknownEffect(effect))?;
        if record.state != RegistryEffectState::Registered {
            return Err(RegistryError::InvalidEffectState {
                state: record.state,
            });
        }
        let local = self.local_scope(scope)?;
        let free_after = local.free_budget.checked_return(record.token.credit())?;
        let terminalized_after = local
            .revocation
            .ok_or(RegistryError::InvariantViolation(
                "closing scope lacks registry revocation metadata",
            ))?
            .terminalized
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let removed = BTreeSet::from([effect]);
        let timer_return = self.timer_return_after_removing(scope, &removed)?;
        let task = record.token.task();
        let resources = record.current_resources;

        self.gate.refinement_changed(scope)?;
        let record = self
            .effects
            .get_mut(&effect)
            .ok_or(RegistryError::UnknownEffect(effect))?;
        record.state = RegistryEffectState::Aborted;
        record.continuation = RegistryContinuationState::Aborted;
        record.credit_held = false;
        record.terminalizations = 1;
        if record.token.kind().blocks_task() {
            self.blocked_tasks.remove(&(scope, task));
        }
        let local = self.local_scope_mut(scope)?;
        local.free_budget = free_after;
        local.live_effects.remove(&effect);
        for resource in resources.iter() {
            if let Some(index) = local.by_resource.get_mut(&resource) {
                index.remove(&effect);
                if index.is_empty() {
                    local.by_resource.remove(&resource);
                }
            }
        }
        local
            .revocation
            .as_mut()
            .ok_or(RegistryError::InvariantViolation(
                "closing scope lost registry revocation metadata",
            ))?
            .terminalized = terminalized_after;
        self.remove_from_watchdog(scope, &removed, timer_return)?;
        self.push_trace(RegistryAction::RevokeStep, scope, Some(effect));
        Ok(())
    }

    fn note_index_selection(&mut self, scope: ScopeId) -> Result<(), RegistryError> {
        let local = self.local_scope_mut(scope)?;
        let revocation = local
            .revocation
            .as_mut()
            .ok_or(RegistryError::InvariantViolation(
                "closing scope lacks registry revocation metadata",
            ))?;
        revocation.index_selections = revocation
            .index_selections
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        Ok(())
    }

    fn timer_return_after_removing(
        &self,
        scope: ScopeId,
        removed: &BTreeSet<EffectId>,
    ) -> Result<Option<u64>, RegistryError> {
        let local = self.local_scope(scope)?;
        let Some(cohort) = &local.watchdog else {
            return Ok(None);
        };
        if cohort.difference(removed).next().is_some() {
            return Ok(None);
        }
        Ok(Some(
            local
                .free_budget
                .timer
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?,
        ))
    }

    fn remove_from_watchdog(
        &mut self,
        scope: ScopeId,
        removed: &BTreeSet<EffectId>,
        timer_return: Option<u64>,
    ) -> Result<(), RegistryError> {
        let local = self.local_scope_mut(scope)?;
        let Some(cohort) = local.watchdog.as_mut() else {
            if timer_return.is_some() {
                return Err(RegistryError::InvariantViolation(
                    "timer return computed without watchdog",
                ));
            }
            return Ok(());
        };
        for effect in removed {
            cohort.remove(effect);
        }
        if cohort.is_empty() {
            let timer = timer_return.ok_or(RegistryError::InvariantViolation(
                "empty watchdog cohort did not return timer credit",
            ))?;
            local.watchdog = None;
            local.free_budget.timer = timer;
        } else if timer_return.is_some() {
            return Err(RegistryError::InvariantViolation(
                "nonempty watchdog attempted timer return",
            ));
        }
        Ok(())
    }

    fn push_trace(&mut self, action: RegistryAction, scope: ScopeId, effect: Option<EffectId>) {
        let gate = self
            .gate
            .scope(scope)
            .expect("successful registry transition retains gate scope");
        self.trace.push(RegistryTraceEvent {
            seq: self.trace.len(),
            action,
            scope,
            effect,
            authority_epoch: gate.authority_epoch,
            binding_epoch: gate.binding_epoch,
        });
    }
}
