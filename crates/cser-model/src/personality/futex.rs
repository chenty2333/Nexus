//! Bounded successor model for one Linux private-futex key.
//!
//! This module refines the shared [`super::PersonalityModel`] authority and
//! crash/rebind gate with a deliberately small `WAIT`/`WAKE` protocol.  It is
//! not a general futex implementation: there is one configured private key per
//! scope, no requeue, no timeout ABI, no PI state, no robust lists, and no SMP
//! claim.  In particular, the recovery watchdog is a CSER closure deadline,
//! never a Linux futex timeout.
//!
//! Closure selects work only from the target scope's committed-wake ordered
//! index or FIFO wait head.  The queue head operations are `O(1)`; live,
//! committed-wake, and watchdog indexes are `BTreeSet`s, so their maintenance
//! remains honestly bounded by `O(log k)` for target-scope live work `k`.
//! Read-only scope/snapshot projections intentionally materialize `Vec`s in
//! `O(k)`; they are diagnostic operations, not part of `revoke_next` closure.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use crate::{ScopeId, ScopeState};

use super::{
    AuthorityEpoch, BindingEpoch, PersonalityBindingToken, PersonalityError,
    PersonalityFallbackState, PersonalityId, PersonalityModel, PersonalityReadyToken,
    PersonalityRecoverySnapshot, PersonalityScopeView, TaskId,
};

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
    /// Stable identity of one futex effect and continuation.
    FutexEffectId
);
scalar_type!(
    /// Stable identity of one address space.
    AddressSpaceId
);
scalar_type!(
    /// Generation preventing reuse of an address-space identity.
    AddressSpaceGeneration
);

/// Linux futex words are four-byte aligned.
pub const FUTEX_ALIGNMENT: u64 = 4;

/// Full private-futex key: address-space identity plus aligned virtual address.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FutexKey {
    address_space: AddressSpaceId,
    address_space_generation: AddressSpaceGeneration,
    aligned_address: u64,
}

impl FutexKey {
    /// Constructs a private key, rejecting an unaligned address.
    pub const fn new(
        address_space: AddressSpaceId,
        address_space_generation: AddressSpaceGeneration,
        aligned_address: u64,
    ) -> Result<Self, FutexError> {
        if !aligned_address.is_multiple_of(FUTEX_ALIGNMENT) {
            return Err(FutexError::UnalignedAddress { aligned_address });
        }
        Ok(Self {
            address_space,
            address_space_generation,
            aligned_address,
        })
    }

    /// Returns the address-space identity.
    #[must_use]
    pub const fn address_space(self) -> AddressSpaceId {
        self.address_space
    }

    /// Returns the address-space reuse generation.
    #[must_use]
    pub const fn address_space_generation(self) -> AddressSpaceGeneration {
        self.address_space_generation
    }

    /// Returns the aligned user virtual address.
    #[must_use]
    pub const fn aligned_address(self) -> u64 {
        self.aligned_address
    }
}

/// Operation label and the value authenticated by a futex effect token.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FutexOperation {
    /// Wait only if the word equals `expected` at registration.
    Wait {
        /// Expected futex-word value.
        expected: u32,
    },
    /// Wake at most one waiter; `max_wake == 0` freezes a zero result.
    Wake {
        /// Linux caller's requested maximum, bounded to one by this model.
        max_wake: u32,
    },
}

/// Inspectable fields of a complete futex effect identity.
///
/// The production representation must be authenticated and non-forgeable.
/// This transparent form exists so negative tests can alter exactly one fence
/// and prove that rejection leaves the model byte-for-byte unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexTokenParts {
    /// Authority scope inherited by the effect.
    pub scope: ScopeId,
    /// Stable effect identity.
    pub effect: FutexEffectId,
    /// Trapped task and one-shot continuation owner.
    pub task: TaskId,
    /// `WAIT(expected)` or `WAKE(max_wake)` operation identity.
    pub operation: FutexOperation,
    /// Private address-space identity.
    pub address_space: AddressSpaceId,
    /// Address-space reuse generation.
    pub address_space_generation: AddressSpaceGeneration,
    /// Four-byte-aligned virtual address.
    pub aligned_address: u64,
    /// Authority generation captured at registration/commit.
    pub authority_epoch: AuthorityEpoch,
    /// Personality binding generation owning the continuation.
    pub binding_epoch: BindingEpoch,
}

/// Full identity of one private-futex effect and continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexToken(FutexTokenParts);

impl FutexToken {
    /// Constructs an inspectable token for deliberate negative testing.
    pub const fn from_parts(parts: FutexTokenParts) -> Result<Self, FutexError> {
        if !parts.aligned_address.is_multiple_of(FUTEX_ALIGNMENT) {
            return Err(FutexError::UnalignedAddress {
                aligned_address: parts.aligned_address,
            });
        }
        Ok(Self(parts))
    }

    /// Returns all independent identity fences.
    #[must_use]
    pub const fn parts(self) -> FutexTokenParts {
        self.0
    }

    /// Returns the inherited authority scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.0.scope
    }

    /// Returns the stable effect identity.
    #[must_use]
    pub const fn effect(self) -> FutexEffectId {
        self.0.effect
    }

    /// Returns the trapped task identity.
    #[must_use]
    pub const fn task(self) -> TaskId {
        self.0.task
    }

    /// Returns the authenticated operation and expected/max-wake value.
    #[must_use]
    pub const fn operation(self) -> FutexOperation {
        self.0.operation
    }

    /// Returns the private futex key.
    #[must_use]
    pub const fn key(self) -> FutexKey {
        FutexKey {
            address_space: self.0.address_space,
            address_space_generation: self.0.address_space_generation,
            aligned_address: self.0.aligned_address,
        }
    }

    /// Returns the captured authority generation.
    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        self.0.authority_epoch
    }

    /// Returns the continuation's current binding generation.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.0.binding_epoch
    }
}

/// Independently conserved futex resources.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FutexBudget {
    wait_credits: u64,
    wake_credits: u64,
    timer_credits: u64,
}

impl FutexBudget {
    /// Constructs a typed wait/wake/timer budget.
    #[must_use]
    pub const fn new(wait_credits: u64, wake_credits: u64, timer_credits: u64) -> Self {
        Self {
            wait_credits,
            wake_credits,
            timer_credits,
        }
    }

    /// Returns the wait-continuation credits.
    #[must_use]
    pub const fn wait_credits(self) -> u64 {
        self.wait_credits
    }

    /// Returns the committed wake-continuation credits.
    #[must_use]
    pub const fn wake_credits(self) -> u64 {
        self.wake_credits
    }

    /// Returns the crash-recovery watchdog credits.
    #[must_use]
    pub const fn timer_credits(self) -> u64 {
        self.timer_credits
    }
}

/// Lifecycle of a bounded futex effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexEffectState {
    /// A successful `WAIT` owns one queue position and one wait credit.
    WaitQueued,
    /// `WakeCommit` removed this waiter and froze its selecting wake identity.
    WaitClaimed,
    /// Selection and return count are frozen; kernel publication remains.
    WakeCommitted,
    /// The unique success delivery was published.
    Completed,
    /// Revocation consumed an unclaimed wait with terminal failure.
    Aborted,
}

impl FutexEffectState {
    /// Returns whether no later transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

/// One-shot task-continuation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexContinuationState {
    /// No kernel success or abort delivery consumed the continuation.
    Pending,
    /// Kernel publication delivered the unique success result.
    Delivered,
    /// CSER revocation delivered terminal failure.
    Aborted,
}

/// Kernel-visible terminal result.
///
/// There is intentionally no `TimedOut` variant.  A watchdog expiry revokes
/// authority and yields `Aborted`; it is not the Linux futex timeout ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexDelivery {
    /// A selected `WAIT` may resume successfully.
    WaitWoken,
    /// A `WAKE` caller receives the count frozen at commit.
    WakeReturned {
        /// Frozen number of selected waiters: exactly zero or one.
        count: u32,
    },
    /// CSER closure terminalized the continuation with failure.
    Aborted,
}

/// Result of the atomic `WakeCommit` selection point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WakeCommitResult {
    /// Full identity of the committed wake effect.
    pub token: FutexToken,
    /// Waiter selected at commit, if `frozen_count == 1`.
    pub selected_wait: Option<FutexEffectId>,
    /// Frozen return count, including the zero-selection case.
    pub frozen_count: u32,
}

/// Result of later kernel-owned wake publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WakePublication {
    /// Committed wake effect that was terminalized.
    pub wake: FutexEffectId,
    /// Wait effect terminalized by the same publication, if any.
    pub wait: Option<FutexEffectId>,
    /// Previously frozen count returned to the wake caller.
    pub frozen_count: u32,
}

/// Read-only projection of one futex effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexEffectView {
    /// Complete, current continuation identity.
    pub token: FutexToken,
    /// Effect lifecycle state.
    pub state: FutexEffectState,
    /// One-shot continuation consumption state.
    pub continuation: FutexContinuationState,
    /// Wake that claimed this wait, if any.
    pub selected_by: Option<FutexEffectId>,
    /// Wait selected by this wake, if any.
    pub selected_wait: Option<FutexEffectId>,
    /// Wake result frozen at commit, if this is a wake.
    pub frozen_count: Option<u32>,
    /// Unique terminal delivery, if consumed.
    pub delivery: Option<FutexDelivery>,
    /// Whether the effect still retains one wait credit.
    pub wait_credit_held: bool,
    /// Number of successful kernel publications.
    pub kernel_publications: u8,
    /// Number of terminal state transitions.
    pub terminalizations: u8,
}

/// One live effect captured in a crash-recovery snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexEffectSnapshot {
    /// Full identity at snapshot creation.
    pub token: FutexToken,
    /// Queue, claim, or committed-wake state.
    pub state: FutexEffectState,
    /// Frozen wake selection, if this is a committed wake.
    pub selected_wait: Option<FutexEffectId>,
    /// Frozen wake count, if this is a committed wake.
    pub frozen_count: Option<u32>,
}

/// Exact crash-recovery view accepted by one prospective replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FutexRecoverySnapshot {
    gate: PersonalityRecoverySnapshot,
    effects: Vec<FutexEffectSnapshot>,
    queue: Vec<FutexEffectId>,
    watchdog_cohort: Vec<FutexEffectId>,
}

impl FutexRecoverySnapshot {
    /// Returns the represented scope.
    #[must_use]
    pub const fn scope(&self) -> ScopeId {
        self.gate.scope()
    }

    /// Returns the replacement identity for which the snapshot was issued.
    #[must_use]
    pub const fn personality(&self) -> PersonalityId {
        self.gate.personality()
    }

    /// Returns deterministic live recovery effects.
    #[must_use]
    pub fn effects(&self) -> &[FutexEffectSnapshot] {
        &self.effects
    }

    /// Returns the exact FIFO wait queue at snapshot creation.
    #[must_use]
    pub fn queue(&self) -> &[FutexEffectId] {
        &self.queue
    }

    /// Returns effects still protected by the recovery watchdog.
    #[must_use]
    pub fn watchdog_cohort(&self) -> &[FutexEffectId] {
        &self.watchdog_cohort
    }
}

/// Ready proof wrapping the shared personality gate's proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexReadyToken {
    gate: PersonalityReadyToken,
}

impl FutexReadyToken {
    /// Returns the replacement identity.
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

/// Active recovery-watchdog projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FutexWatchdogView {
    /// Effects from the crash cohort that still require adoption or closure.
    pub cohort: Vec<FutexEffectId>,
}

/// Bounded revocation accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexRevocationProgress {
    /// Authority generation closed at `revoke_begin`.
    pub closed_epoch: AuthorityEpoch,
    /// Live effects at that linearization point.
    pub target_count: usize,
    /// Effects terminalized so far; one wake publication may add two.
    pub terminalized: usize,
    /// Successful `revoke_next` selections from one scope-local index head.
    ///
    /// This counts one for either a committed-wake head or a FIFO wait head;
    /// it never counts inspection of another scope or historical effect.
    pub index_selections: usize,
    /// Effects still live.
    pub remaining: usize,
}

/// Read-only projection of one bounded futex scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FutexScopeView {
    /// Shared authority/binding/fallback gate projection.
    pub gate: PersonalityScopeView,
    /// The only private key accepted by this bounded scope.
    pub key: FutexKey,
    /// Modeled futex-word value used by atomic wait comparison.
    pub word: u32,
    /// Initial typed resource budget.
    pub initial_budget: FutexBudget,
    /// Currently free typed resource budget.
    pub free_budget: FutexBudget,
    /// Deterministic FIFO queue of unclaimed waits.
    ///
    /// This diagnostic projection materializes the internal `VecDeque`.
    pub queue: Vec<FutexEffectId>,
    /// Number of nonterminal wait and wake effects.
    pub live_effects: usize,
    /// Recovery watchdog, absent outside an incomplete crash cohort.
    pub watchdog: Option<FutexWatchdogView>,
    /// Scope-local closure progress.
    pub revocation: Option<FutexRevocationProgress>,
}

/// Result of one scope-local closure step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexRevocationStep {
    /// An unclaimed wait lost to revocation and was aborted.
    AbortedWait {
        /// Wait effect terminalized by closure.
        wait: FutexEffectId,
    },
    /// A previously committed wake won and was drained without reselection.
    DrainedWake {
        /// Wake effect terminalized by publication.
        wake: FutexEffectId,
        /// Previously frozen selected wait, if any.
        wait: Option<FutexEffectId>,
        /// Previously frozen result count.
        frozen_count: u32,
    },
}

/// Successful futex-refinement actions in total linearization order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexAction {
    /// Create a bounded scope through the shared personality gate.
    CreateScope,
    /// Atomically compare, charge, and enqueue one wait.
    WaitRegister,
    /// Atomically select at most one waiter and freeze the wake count.
    WakeCommit,
    /// Publish a committed wake through the kernel-owned path.
    KernelWakePublish,
    /// Fence a failed personality and arm a cohort watchdog if needed.
    Crash,
    /// Select kernel fallback.
    FallbackPick,
    /// Accept a still-exact recovery snapshot.
    Ready,
    /// Install the ready replacement.
    Rebind,
    /// Transfer one orphan continuation without queue reselection.
    Adopt,
    /// Close authority explicitly.
    RevokeBegin,
    /// Close authority because the recovery watchdog expired.
    WatchdogExpire,
    /// Abort or drain one scope-local closure unit.
    RevokeStep,
    /// Publish quiescent closure.
    RevokeComplete,
}

/// One successful futex-refinement trace event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexTraceEvent {
    /// Zero-based total-order position.
    pub seq: usize,
    /// Operation that linearized.
    pub action: FutexAction,
    /// Affected authority scope.
    pub scope: ScopeId,
    /// Primary effect, when applicable.
    pub effect: Option<FutexEffectId>,
    /// Shared authority generation immediately after the operation.
    pub authority_epoch: AuthorityEpoch,
    /// Shared binding generation immediately after the operation.
    pub binding_epoch: BindingEpoch,
}

/// Rejected bounded-futex operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexError {
    /// The shared authority/binding/recovery gate rejected the operation.
    Personality(PersonalityError),
    /// The virtual address is not aligned for a Linux futex word.
    UnalignedAddress {
        /// Rejected address.
        aligned_address: u64,
    },
    /// The request names a key other than this scope's single private key.
    WrongPrivateKey,
    /// Linux `FUTEX_WAIT` comparison failed and must return `EAGAIN`.
    Again {
        /// Value observed at the atomic compare point.
        observed: u32,
    },
    /// The requested effect does not exist.
    UnknownEffect(FutexEffectId),
    /// A token differs from the complete recorded effect identity.
    EffectIdentityMismatch,
    /// The task already owns another nonterminal futex continuation.
    TaskAlreadyBlocked {
        /// Existing continuation blocking the task.
        effect: FutexEffectId,
    },
    /// No wait credit is currently available.
    WaitBudgetExhausted,
    /// No committed-wake continuation credit is currently available.
    WakeBudgetExhausted,
    /// A recoverable scope must own at least one watchdog timer credit.
    MissingWatchdogBudget,
    /// The effect is not in the state required by the operation.
    InvalidEffectState {
        /// Actual effect state.
        state: FutexEffectState,
    },
    /// A wait operation was supplied where wake was required, or vice versa.
    WrongOperation,
    /// The effect is not an orphan eligible for explicit adoption.
    NotAdoptable,
    /// No incomplete crash-recovery cohort owns a watchdog.
    WatchdogNotArmed,
    /// Closure completion was requested while effects remain live.
    RevocationNotQuiescent {
        /// Remaining live effects.
        remaining: usize,
    },
    /// An identity, generation, counter, or budget operation overflowed.
    CounterOverflow,
    /// Internal model relationships were inconsistent.
    InvariantViolation(&'static str),
}

impl From<PersonalityError> for FutexError {
    fn from(error: PersonalityError) -> Self {
        Self::Personality(error)
    }
}

/// Failure reported by a complete bounded-futex invariant audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexInvariantViolation {
    /// The shared personality authority/binding gate is inconsistent.
    Personality(super::PersonalityInvariantViolation),
    /// A local scope has no matching shared-gate scope.
    MissingGateScope(ScopeId),
    /// The live reverse index differs from nonterminal records.
    LiveReverseIndex(ScopeId),
    /// The FIFO queue differs from exactly the unclaimed wait set.
    QueueExactness(ScopeId),
    /// The committed-wake index differs from exactly the live committed wakes.
    CommittedWakeIndex(ScopeId),
    /// Blocked-task ownership differs from live continuations.
    BlockedTaskIndex(FutexEffectId),
    /// A token names a missing scope, wrong effect, or future generation.
    OrphanOrFutureEffect(FutexEffectId),
    /// A wake selection and its claimed waiter disagree.
    FrozenSelection(FutexEffectId),
    /// Effect state, continuation, delivery, or terminal count disagree.
    SingleTerminalization(FutexEffectId),
    /// Wait credits were lost, duplicated, or returned at the wrong state.
    WaitBudgetConservation(ScopeId),
    /// Wake credits were lost, duplicated, or returned at the wrong state.
    WakeBudgetConservation(ScopeId),
    /// Watchdog timer credit was lost or duplicated.
    TimerBudgetConservation(ScopeId),
    /// Watchdog cohort contains the wrong effects.
    WatchdogCohort(ScopeId),
    /// Scope state and closure progress disagree.
    RevocationProgress(ScopeId),
    /// Trace positions are not contiguous.
    TraceOrder,
}

impl From<super::PersonalityInvariantViolation> for FutexInvariantViolation {
    fn from(error: super::PersonalityInvariantViolation) -> Self {
        Self::Personality(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FutexRecordKind {
    Wait {
        selected_by: Option<FutexEffectId>,
    },
    Wake {
        selected_wait: Option<FutexEffectId>,
        frozen_count: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FutexEffectRecord {
    token: FutexToken,
    state: FutexEffectState,
    continuation: FutexContinuationState,
    kind: FutexRecordKind,
    delivery: Option<FutexDelivery>,
    wait_credit_held: bool,
    kernel_publications: u8,
    terminalizations: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WatchdogRecord {
    cohort: BTreeSet<FutexEffectId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RevocationRecord {
    closed_epoch: AuthorityEpoch,
    target_count: usize,
    terminalized: usize,
    index_selections: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FutexScopeRecord {
    key: FutexKey,
    word: u32,
    initial_budget: FutexBudget,
    free_budget: FutexBudget,
    queue: VecDeque<FutexEffectId>,
    committed_wakes: BTreeSet<FutexEffectId>,
    live_effects: BTreeSet<FutexEffectId>,
    watchdog: Option<WatchdogRecord>,
    revocation: Option<RevocationRecord>,
}

/// Deterministic `no_std + alloc` private-futex successor oracle.
///
/// The embedded [`PersonalityModel`] is the only owner of scope lifecycle,
/// authority epochs, binding epochs, and replacement readiness.  This wrapper
/// contributes only the bounded futex registry, FIFO queue, typed credits, and
/// recovery cohort.  It therefore must not be described as a unified
/// production registry or as an SMP futex implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FutexModel {
    gate: PersonalityModel,
    next_effect: u64,
    scopes: BTreeMap<ScopeId, FutexScopeRecord>,
    effects: BTreeMap<FutexEffectId, FutexEffectRecord>,
    blocked_tasks: BTreeMap<(ScopeId, TaskId), FutexEffectId>,
    trace: Vec<FutexTraceEvent>,
}

impl Default for FutexModel {
    fn default() -> Self {
        Self::new()
    }
}

impl FutexModel {
    /// Creates an empty bounded-futex model around one shared personality gate.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            gate: PersonalityModel::new(),
            next_effect: 1,
            scopes: BTreeMap::new(),
            effects: BTreeMap::new(),
            blocked_tasks: BTreeMap::new(),
            trace: Vec::new(),
        }
    }

    /// Creates one active personality scope with exactly one private futex key.
    ///
    /// At least one timer credit is required so a crash can always be fenced
    /// and protected without making crash handling depend on a later resource
    /// allocation.
    pub fn create_scope(
        &mut self,
        personality: PersonalityId,
        budget: FutexBudget,
        key: FutexKey,
        initial_word: u32,
    ) -> Result<(ScopeId, PersonalityBindingToken), FutexError> {
        if budget.timer_credits == 0 {
            return Err(FutexError::MissingWatchdogBudget);
        }
        let (scope, binding) = self.gate.create_scope(personality)?;
        self.scopes.insert(
            scope,
            FutexScopeRecord {
                key,
                word: initial_word,
                initial_budget: budget,
                free_budget: budget,
                queue: VecDeque::new(),
                committed_wakes: BTreeSet::new(),
                live_effects: BTreeSet::new(),
                watchdog: None,
                revocation: None,
            },
        );
        self.push_trace(FutexAction::CreateScope, scope, None);
        Ok((scope, binding))
    }

    /// Atomically compares the futex word, reserves one wait credit, and queues.
    ///
    /// A mismatch returns [`FutexError::Again`] and changes nothing: no effect
    /// identity is consumed, no task is blocked, no queue entry appears, and no
    /// wait credit is charged.  A successful call is the single abstract
    /// `WaitRegister` point for all three changes.
    pub fn wait_register(
        &mut self,
        binding: PersonalityBindingToken,
        task: TaskId,
        key: FutexKey,
        expected: u32,
    ) -> Result<FutexToken, FutexError> {
        self.gate.validate_refinement_binding(binding)?;
        let scope = self.local_scope(binding.scope())?;
        Self::validate_key(scope, key)?;
        if let Some(effect) = self.blocked_tasks.get(&(binding.scope(), task)) {
            return Err(FutexError::TaskAlreadyBlocked { effect: *effect });
        }
        if scope.word != expected {
            return Err(FutexError::Again {
                observed: scope.word,
            });
        }
        if scope.free_budget.wait_credits == 0 {
            return Err(FutexError::WaitBudgetExhausted);
        }
        let effect = FutexEffectId::new(self.next_effect);
        let next_effect = self
            .next_effect
            .checked_add(1)
            .ok_or(FutexError::CounterOverflow)?;
        let token = Self::token(
            binding,
            effect,
            task,
            key,
            FutexOperation::Wait { expected },
        );
        let free_after = scope
            .free_budget
            .wait_credits
            .checked_sub(1)
            .ok_or(FutexError::WaitBudgetExhausted)?;

        self.gate.refinement_changed(binding.scope())?;
        self.next_effect = next_effect;
        let scope = self.local_scope_mut(binding.scope())?;
        scope.free_budget.wait_credits = free_after;
        scope.queue.push_back(effect);
        scope.live_effects.insert(effect);
        self.effects.insert(
            effect,
            FutexEffectRecord {
                token,
                state: FutexEffectState::WaitQueued,
                continuation: FutexContinuationState::Pending,
                kind: FutexRecordKind::Wait { selected_by: None },
                delivery: None,
                wait_credit_held: true,
                kernel_publications: 0,
                terminalizations: 0,
            },
        );
        self.blocked_tasks.insert((binding.scope(), task), effect);
        self.push_trace(FutexAction::WaitRegister, binding.scope(), Some(effect));
        Ok(token)
    }

    /// Atomically selects at most one FIFO waiter and freezes the return count.
    ///
    /// This bounded Rust oracle folds syscall capture and successful wake
    /// commit into one point, so it acquires the wake-continuation credit here.
    /// An expanded protocol may refine this point into `CaptureWake` followed
    /// by `WakeCommit`; no precommit captured-wake state exists in this model.
    ///
    /// Selection occurs here, never in crash, snapshot, rebind, adoption, or
    /// publication.  `max_wake == 0` and an empty queue both create a committed
    /// wake whose frozen count is zero and which still needs kernel publication.
    pub fn wake_commit(
        &mut self,
        binding: PersonalityBindingToken,
        task: TaskId,
        key: FutexKey,
        max_wake: u32,
    ) -> Result<WakeCommitResult, FutexError> {
        self.gate.validate_refinement_binding(binding)?;
        let scope = self.local_scope(binding.scope())?;
        Self::validate_key(scope, key)?;
        if let Some(effect) = self.blocked_tasks.get(&(binding.scope(), task)) {
            return Err(FutexError::TaskAlreadyBlocked { effect: *effect });
        }
        if scope.free_budget.wake_credits == 0 {
            return Err(FutexError::WakeBudgetExhausted);
        }
        let selected_wait = (max_wake > 0)
            .then(|| scope.queue.front().copied())
            .flatten();
        if let Some(wait) = selected_wait {
            let record = self
                .effects
                .get(&wait)
                .ok_or(FutexError::UnknownEffect(wait))?;
            if record.state != FutexEffectState::WaitQueued
                || record.token.scope() != binding.scope()
                || record.token.key() != key
                || record.kind != (FutexRecordKind::Wait { selected_by: None })
            {
                return Err(FutexError::InvariantViolation(
                    "FIFO head is not one unclaimed wait",
                ));
            }
        }
        let effect = FutexEffectId::new(self.next_effect);
        let next_effect = self
            .next_effect
            .checked_add(1)
            .ok_or(FutexError::CounterOverflow)?;
        let frozen_count = u32::from(selected_wait.is_some());
        let token = Self::token(
            binding,
            effect,
            task,
            key,
            FutexOperation::Wake { max_wake },
        );
        let free_wake_after = scope
            .free_budget
            .wake_credits
            .checked_sub(1)
            .ok_or(FutexError::WakeBudgetExhausted)?;

        self.gate.refinement_changed(binding.scope())?;
        self.next_effect = next_effect;
        if let Some(wait) = selected_wait {
            let scope = self.local_scope_mut(binding.scope())?;
            let removed = scope.queue.pop_front();
            debug_assert_eq!(removed, Some(wait));
            let wait_record = self
                .effects
                .get_mut(&wait)
                .ok_or(FutexError::UnknownEffect(wait))?;
            wait_record.state = FutexEffectState::WaitClaimed;
            wait_record.kind = FutexRecordKind::Wait {
                selected_by: Some(effect),
            };
        }
        let scope = self.local_scope_mut(binding.scope())?;
        scope.free_budget.wake_credits = free_wake_after;
        scope.live_effects.insert(effect);
        scope.committed_wakes.insert(effect);
        self.effects.insert(
            effect,
            FutexEffectRecord {
                token,
                state: FutexEffectState::WakeCommitted,
                continuation: FutexContinuationState::Pending,
                kind: FutexRecordKind::Wake {
                    selected_wait,
                    frozen_count,
                },
                delivery: None,
                wait_credit_held: false,
                kernel_publications: 0,
                terminalizations: 0,
            },
        );
        self.blocked_tasks.insert((binding.scope(), task), effect);
        self.push_trace(FutexAction::WakeCommit, binding.scope(), Some(effect));
        Ok(WakeCommitResult {
            token,
            selected_wait,
            frozen_count,
        })
    }

    /// Publishes the count frozen by `WakeCommit` through the kernel-owned path.
    ///
    /// With count one, the selected wait and wake caller terminalize together.
    /// With count zero, only the wake caller terminalizes.  Publication never
    /// consults the queue and therefore cannot reselect after crash or rebind.
    pub fn kernel_wake_publish(
        &mut self,
        token: FutexToken,
    ) -> Result<WakePublication, FutexError> {
        let publication = self.validate_wake_publication(token)?;
        self.publish_wake(token, FutexAction::KernelWakePublish)?;
        Ok(publication)
    }

    /// Fences a crashed personality and protects exactly its live effect cohort.
    pub fn crash(&mut self, binding: PersonalityBindingToken) -> Result<(), FutexError> {
        self.gate.validate_refinement_binding(binding)?;
        let scope = self.local_scope(binding.scope())?;
        let needs_timer = !scope.live_effects.is_empty() && scope.watchdog.is_none();
        if needs_timer && scope.free_budget.timer_credits == 0 {
            return Err(FutexError::MissingWatchdogBudget);
        }
        let timer_after = if needs_timer {
            Some(
                scope
                    .free_budget
                    .timer_credits
                    .checked_sub(1)
                    .ok_or(FutexError::MissingWatchdogBudget)?,
            )
        } else {
            None
        };
        let cohort = scope.live_effects.clone();

        self.gate.crash(binding)?;
        let scope = self.local_scope_mut(binding.scope())?;
        if cohort.is_empty() {
            scope.watchdog = None;
        } else {
            if let Some(timer_after) = timer_after {
                scope.free_budget.timer_credits = timer_after;
            }
            scope.watchdog = Some(WatchdogRecord { cohort });
        }
        self.push_trace(FutexAction::Crash, binding.scope(), None);
        Ok(())
    }

    /// Selects kernel fallback through the shared personality gate.
    pub fn fallback_pick(&mut self, scope: ScopeId) -> Result<(), FutexError> {
        self.local_scope(scope)?;
        self.gate.fallback_pick(scope)?;
        self.push_trace(FutexAction::FallbackPick, scope, None);
        Ok(())
    }

    /// Captures an exact immutable recovery view without changing selection.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        personality: PersonalityId,
    ) -> Result<FutexRecoverySnapshot, FutexError> {
        let gate = self.gate.recovery_snapshot(scope, personality)?;
        let local = self.local_scope(scope)?;
        Ok(FutexRecoverySnapshot {
            gate,
            effects: self.snapshot_effects(local)?,
            queue: local.queue.iter().copied().collect(),
            watchdog_cohort: Self::watchdog_cohort(local),
        })
    }

    /// Accepts readiness only while both gate revision and futex snapshot match.
    pub fn ready(
        &mut self,
        snapshot: &FutexRecoverySnapshot,
    ) -> Result<FutexReadyToken, FutexError> {
        self.validate_local_snapshot(snapshot)?;
        let gate = self.gate.ready(&snapshot.gate)?;
        self.push_trace(FutexAction::Ready, snapshot.scope(), None);
        Ok(FutexReadyToken { gate })
    }

    /// Installs a ready replacement without changing queue or frozen selection.
    pub fn rebind(
        &mut self,
        ready: FutexReadyToken,
    ) -> Result<PersonalityBindingToken, FutexError> {
        let scope = ready.gate.scope;
        self.local_scope(scope)?;
        let binding = self.gate.rebind(ready.gate)?;
        self.push_trace(FutexAction::Rebind, scope, None);
        Ok(binding)
    }

    /// Explicitly transfers one orphan continuation to the current binding.
    ///
    /// Adoption changes only the binding fence and watchdog cohort.  It never
    /// re-enqueues a wait, changes FIFO order, or changes a committed wake's
    /// selected waiter/count.  Once every crash-cohort effect is adopted (or
    /// terminalized), the watchdog credit is returned and queued waits may
    /// remain pending indefinitely.
    pub fn adopt(
        &mut self,
        binding: PersonalityBindingToken,
        token: FutexToken,
    ) -> Result<FutexToken, FutexError> {
        self.gate.validate_refinement_binding(binding)?;
        let gate = self
            .gate
            .scope(binding.scope())
            .ok_or(PersonalityError::UnknownScope(binding.scope()))?;
        let record = *self.validate_token(token)?;
        if token.scope() != binding.scope() {
            return Err(FutexError::EffectIdentityMismatch);
        }
        if token.authority_epoch() != gate.authority_epoch {
            return Err(FutexError::Personality(PersonalityError::StaleAuthority {
                presented: token.authority_epoch(),
                current: gate.authority_epoch,
            }));
        }
        if record.state.is_terminal() || token.binding_epoch() == gate.binding_epoch {
            return Err(FutexError::NotAdoptable);
        }
        let timer_after = self.timer_return_after_removing(binding.scope(), token.effect())?;

        self.gate.refinement_changed(binding.scope())?;
        let mut parts = token.parts();
        parts.binding_epoch = gate.binding_epoch;
        let adopted = FutexToken(parts);
        self.effects
            .get_mut(&token.effect())
            .ok_or(FutexError::UnknownEffect(token.effect()))?
            .token = adopted;
        self.remove_from_watchdog(binding.scope(), token.effect(), timer_after)?;
        self.push_trace(FutexAction::Adopt, binding.scope(), Some(token.effect()));
        Ok(adopted)
    }

    /// Closes authority explicitly; later wake commits are fenced by the gate.
    pub fn revoke_begin(&mut self, scope: ScopeId) -> Result<(), FutexError> {
        self.begin_revocation(scope, FutexAction::RevokeBegin)
    }

    /// Expires the crash-recovery watchdog by closing authority.
    ///
    /// Expiry is the revocation linearization point.  Subsequent bounded
    /// closure steps drain already committed wakes and abort unclaimed waits;
    /// no continuation receives a Linux timeout result.
    pub fn watchdog_expire(&mut self, scope: ScopeId) -> Result<(), FutexError> {
        let local = self.local_scope(scope)?;
        if local
            .watchdog
            .as_ref()
            .is_none_or(|watchdog| watchdog.cohort.is_empty())
        {
            return Err(FutexError::WatchdogNotArmed);
        }
        self.begin_revocation(scope, FutexAction::WatchdogExpire)
    }

    /// Performs one bounded scope-local closure step.
    ///
    /// A committed wake is always drained before an unclaimed wait is aborted,
    /// preserving `wake-before-revoke`.  If no wake committed before gate
    /// closure, one queued wait is aborted, preserving `revoke-before-wake`.
    pub fn revoke_next(
        &mut self,
        scope: ScopeId,
    ) -> Result<Option<FutexRevocationStep>, FutexError> {
        let gate = self
            .gate
            .scope(scope)
            .ok_or(PersonalityError::UnknownScope(scope))?;
        if gate.state != ScopeState::Closing {
            return Err(FutexError::Personality(
                PersonalityError::InvalidScopeState { state: gate.state },
            ));
        }
        let local = self.local_scope(scope)?;
        if local.revocation.is_none() {
            return Err(FutexError::InvariantViolation(
                "closing scope lacks futex revocation metadata",
            ));
        }
        let committed_wake = local.committed_wakes.iter().next().copied();
        if let Some(wake) = committed_wake {
            let token = self
                .effects
                .get(&wake)
                .ok_or(FutexError::UnknownEffect(wake))?
                .token;
            let publication = self.validate_wake_publication(token)?;
            self.publish_wake(token, FutexAction::RevokeStep)?;
            return Ok(Some(FutexRevocationStep::DrainedWake {
                wake: publication.wake,
                wait: publication.wait,
                frozen_count: publication.frozen_count,
            }));
        }

        let Some(wait) = local.queue.front().copied() else {
            if local.live_effects.is_empty() {
                return Ok(None);
            }
            return Err(FutexError::InvariantViolation(
                "live effects exist outside committed-wake and wait indexes",
            ));
        };
        let record = *self
            .effects
            .get(&wait)
            .ok_or(FutexError::UnknownEffect(wait))?;
        if record.state != FutexEffectState::WaitQueued
            || !matches!(record.kind, FutexRecordKind::Wait { selected_by: None })
            || !record.wait_credit_held
        {
            return Err(FutexError::InvariantViolation(
                "closure found a claimed wait without its committed wake",
            ));
        }
        let free_wait_after = local
            .free_budget
            .wait_credits
            .checked_add(1)
            .ok_or(FutexError::CounterOverflow)?;
        let terminalized_after = Self::terminalized_after(local, 1)?;
        let index_selections_after = Self::index_selections_after(local)?;
        let timer_after = self.timer_return_after_removing(scope, wait)?;
        let wait_task = record.token.task();

        self.gate.refinement_changed(scope)?;
        let record = self
            .effects
            .get_mut(&wait)
            .ok_or(FutexError::UnknownEffect(wait))?;
        record.state = FutexEffectState::Aborted;
        record.continuation = FutexContinuationState::Aborted;
        record.delivery = Some(FutexDelivery::Aborted);
        record.wait_credit_held = false;
        record.terminalizations = 1;
        let local = self.local_scope_mut(scope)?;
        let removed = local.queue.pop_front();
        debug_assert_eq!(removed, Some(wait));
        local.live_effects.remove(&wait);
        local.free_budget.wait_credits = free_wait_after;
        local
            .revocation
            .as_mut()
            .ok_or(FutexError::InvariantViolation(
                "closing scope lacks futex revocation metadata",
            ))?
            .terminalized = terminalized_after;
        local
            .revocation
            .as_mut()
            .ok_or(FutexError::InvariantViolation(
                "closing scope lacks futex revocation metadata",
            ))?
            .index_selections = index_selections_after;
        self.blocked_tasks.remove(&(scope, wait_task));
        self.remove_from_watchdog(scope, wait, timer_after)?;
        self.push_trace(FutexAction::RevokeStep, scope, Some(wait));
        Ok(Some(FutexRevocationStep::AbortedWait { wait }))
    }

    /// Publishes quiescent closure after every local effect terminalizes.
    pub fn revoke_complete(&mut self, scope: ScopeId) -> Result<(), FutexError> {
        let local = self.local_scope(scope)?;
        if !local.live_effects.is_empty() {
            return Err(FutexError::RevocationNotQuiescent {
                remaining: local.live_effects.len(),
            });
        }
        if !local.queue.is_empty()
            || !local.committed_wakes.is_empty()
            || local.watchdog.is_some()
            || local.free_budget != local.initial_budget
        {
            return Err(FutexError::InvariantViolation(
                "quiescent closure still retains queue, timer, or credit",
            ));
        }
        let revocation = local.revocation.ok_or(FutexError::InvariantViolation(
            "closing scope lacks futex revocation metadata",
        ))?;
        if revocation.terminalized != revocation.target_count {
            return Err(FutexError::InvariantViolation(
                "closure terminalized a different effect count",
            ));
        }

        self.gate.revoke_complete(scope)?;
        self.push_trace(FutexAction::RevokeComplete, scope, None);
        Ok(())
    }

    /// Returns a read-only scope projection.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<FutexScopeView> {
        let gate = self.gate.scope(scope)?;
        let local = self.scopes.get(&scope)?;
        Some(FutexScopeView {
            gate,
            key: local.key,
            word: local.word,
            initial_budget: local.initial_budget,
            free_budget: local.free_budget,
            queue: local.queue.iter().copied().collect(),
            live_effects: local.live_effects.len(),
            watchdog: local.watchdog.as_ref().map(|watchdog| FutexWatchdogView {
                cohort: watchdog.cohort.iter().copied().collect(),
            }),
            revocation: local.revocation.map(|revocation| FutexRevocationProgress {
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
    pub fn effect(&self, effect: FutexEffectId) -> Option<FutexEffectView> {
        self.effects.get(&effect).map(|record| {
            let (selected_by, selected_wait, frozen_count) = match record.kind {
                FutexRecordKind::Wait { selected_by } => (selected_by, None, None),
                FutexRecordKind::Wake {
                    selected_wait,
                    frozen_count,
                } => (None, selected_wait, Some(frozen_count)),
            };
            FutexEffectView {
                token: record.token,
                state: record.state,
                continuation: record.continuation,
                selected_by,
                selected_wait,
                frozen_count,
                delivery: record.delivery,
                wait_credit_held: record.wait_credit_held,
                kernel_publications: record.kernel_publications,
                terminalizations: record.terminalizations,
            }
        })
    }

    /// Returns the successful futex-refinement trace.
    #[must_use]
    pub fn trace(&self) -> &[FutexTraceEvent] {
        &self.trace
    }

    /// Audits gate, queue, identity, budget, watchdog, and terminalization rules.
    pub fn check_invariants(&self) -> Result<(), FutexInvariantViolation> {
        self.gate.check_invariants()?;
        for (scope_id, local) in &self.scopes {
            let Some(gate) = self.gate.scope(*scope_id) else {
                return Err(FutexInvariantViolation::MissingGateScope(*scope_id));
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
                return Err(FutexInvariantViolation::LiveReverseIndex(*scope_id));
            }
            let expected_queue: VecDeque<_> = self
                .effects
                .iter()
                .filter_map(|(effect, record)| {
                    (record.token.scope() == *scope_id
                        && record.state == FutexEffectState::WaitQueued)
                        .then_some(*effect)
                })
                .collect();
            if local.queue != expected_queue {
                return Err(FutexInvariantViolation::QueueExactness(*scope_id));
            }
            let expected_committed_wakes: BTreeSet<_> = self
                .effects
                .iter()
                .filter_map(|(effect, record)| {
                    (record.token.scope() == *scope_id
                        && record.state == FutexEffectState::WakeCommitted)
                        .then_some(*effect)
                })
                .collect();
            if local.committed_wakes != expected_committed_wakes {
                return Err(FutexInvariantViolation::CommittedWakeIndex(*scope_id));
            }

            let held_waits = self
                .effects
                .values()
                .filter(|record| record.token.scope() == *scope_id && record.wait_credit_held)
                .count() as u64;
            if local.free_budget.wait_credits.checked_add(held_waits)
                != Some(local.initial_budget.wait_credits)
            {
                return Err(FutexInvariantViolation::WaitBudgetConservation(*scope_id));
            }
            let held_wakes = local.committed_wakes.len() as u64;
            if local.free_budget.wake_credits.checked_add(held_wakes)
                != Some(local.initial_budget.wake_credits)
            {
                return Err(FutexInvariantViolation::WakeBudgetConservation(*scope_id));
            }
            let held_timers = u64::from(local.watchdog.is_some());
            if local.free_budget.timer_credits.checked_add(held_timers)
                != Some(local.initial_budget.timer_credits)
            {
                return Err(FutexInvariantViolation::TimerBudgetConservation(*scope_id));
            }

            if let Some(watchdog) = &local.watchdog
                && (watchdog.cohort.is_empty()
                    || watchdog.cohort.iter().any(|effect| {
                        !local.live_effects.contains(effect)
                            || self.effects.get(effect).is_none_or(|record| {
                                record.token.binding_epoch() >= gate.binding_epoch
                            })
                    }))
            {
                return Err(FutexInvariantViolation::WatchdogCohort(*scope_id));
            }
            if matches!(
                gate.fallback,
                PersonalityFallbackState::Required
                    | PersonalityFallbackState::Running
                    | PersonalityFallbackState::ReplacementReady
            ) && local.watchdog.as_ref().map(|watchdog| &watchdog.cohort)
                != Some(&local.live_effects)
                && !local.live_effects.is_empty()
            {
                return Err(FutexInvariantViolation::WatchdogCohort(*scope_id));
            }

            match gate.state {
                ScopeState::Active => {
                    if local.revocation.is_some() {
                        return Err(FutexInvariantViolation::RevocationProgress(*scope_id));
                    }
                }
                ScopeState::Closing | ScopeState::Revoked => {
                    let Some(revocation) = local.revocation else {
                        return Err(FutexInvariantViolation::RevocationProgress(*scope_id));
                    };
                    if revocation.terminalized > revocation.target_count
                        || revocation.terminalized + local.live_effects.len()
                            != revocation.target_count
                        || revocation.index_selections > revocation.terminalized
                    {
                        return Err(FutexInvariantViolation::RevocationProgress(*scope_id));
                    }
                    if gate.state == ScopeState::Revoked && !local.live_effects.is_empty() {
                        return Err(FutexInvariantViolation::RevocationProgress(*scope_id));
                    }
                }
            }
        }

        for (effect_id, record) in &self.effects {
            let Some(local) = self.scopes.get(&record.token.scope()) else {
                return Err(FutexInvariantViolation::OrphanOrFutureEffect(*effect_id));
            };
            let Some(gate) = self.gate.scope(record.token.scope()) else {
                return Err(FutexInvariantViolation::OrphanOrFutureEffect(*effect_id));
            };
            if record.token.effect() != *effect_id
                || record.token.key() != local.key
                || record.token.authority_epoch() > gate.authority_epoch
                || record.token.binding_epoch() > gate.binding_epoch
            {
                return Err(FutexInvariantViolation::OrphanOrFutureEffect(*effect_id));
            }
            let blocked = self
                .blocked_tasks
                .get(&(record.token.scope(), record.token.task()));
            if record.state.is_terminal() {
                if blocked == Some(effect_id) {
                    return Err(FutexInvariantViolation::BlockedTaskIndex(*effect_id));
                }
            } else if blocked != Some(effect_id) {
                return Err(FutexInvariantViolation::BlockedTaskIndex(*effect_id));
            }
            self.check_effect_invariant(*effect_id, record)?;
        }

        for ((scope, task), effect) in &self.blocked_tasks {
            let Some(record) = self.effects.get(effect) else {
                return Err(FutexInvariantViolation::BlockedTaskIndex(*effect));
            };
            if record.token.scope() != *scope
                || record.token.task() != *task
                || record.state.is_terminal()
            {
                return Err(FutexInvariantViolation::BlockedTaskIndex(*effect));
            }
        }
        if self
            .trace
            .iter()
            .enumerate()
            .any(|(seq, event)| event.seq != seq)
        {
            return Err(FutexInvariantViolation::TraceOrder);
        }
        Ok(())
    }

    fn local_scope(&self, scope: ScopeId) -> Result<&FutexScopeRecord, FutexError> {
        self.scopes
            .get(&scope)
            .ok_or(FutexError::InvariantViolation(
                "shared gate scope lacks futex refinement state",
            ))
    }

    fn local_scope_mut(&mut self, scope: ScopeId) -> Result<&mut FutexScopeRecord, FutexError> {
        self.scopes
            .get_mut(&scope)
            .ok_or(FutexError::InvariantViolation(
                "shared gate scope lacks futex refinement state",
            ))
    }

    fn validate_key(scope: &FutexScopeRecord, key: FutexKey) -> Result<(), FutexError> {
        if scope.key != key {
            return Err(FutexError::WrongPrivateKey);
        }
        Ok(())
    }

    const fn token(
        binding: PersonalityBindingToken,
        effect: FutexEffectId,
        task: TaskId,
        key: FutexKey,
        operation: FutexOperation,
    ) -> FutexToken {
        FutexToken(FutexTokenParts {
            scope: binding.scope(),
            effect,
            task,
            operation,
            address_space: key.address_space(),
            address_space_generation: key.address_space_generation(),
            aligned_address: key.aligned_address(),
            authority_epoch: binding.authority_epoch(),
            binding_epoch: binding.binding_epoch(),
        })
    }

    fn validate_token(&self, token: FutexToken) -> Result<&FutexEffectRecord, FutexError> {
        let record = self
            .effects
            .get(&token.effect())
            .ok_or(FutexError::UnknownEffect(token.effect()))?;
        if record.token != token {
            return Err(FutexError::EffectIdentityMismatch);
        }
        Ok(record)
    }

    fn begin_revocation(&mut self, scope: ScopeId, action: FutexAction) -> Result<(), FutexError> {
        let gate = self
            .gate
            .scope(scope)
            .ok_or(PersonalityError::UnknownScope(scope))?;
        let local = self.local_scope(scope)?;
        let target_count = local.live_effects.len();
        let closed_epoch = gate.authority_epoch;
        self.gate.revoke_begin(scope)?;
        self.local_scope_mut(scope)?.revocation = Some(RevocationRecord {
            closed_epoch,
            target_count,
            terminalized: 0,
            index_selections: 0,
        });
        self.push_trace(action, scope, None);
        Ok(())
    }

    fn snapshot_effects(
        &self,
        scope: &FutexScopeRecord,
    ) -> Result<Vec<FutexEffectSnapshot>, FutexError> {
        scope
            .live_effects
            .iter()
            .map(|effect| {
                let record = self
                    .effects
                    .get(effect)
                    .ok_or(FutexError::UnknownEffect(*effect))?;
                let (selected_wait, frozen_count) = match record.kind {
                    FutexRecordKind::Wait { .. } => (None, None),
                    FutexRecordKind::Wake {
                        selected_wait,
                        frozen_count,
                    } => (selected_wait, Some(frozen_count)),
                };
                Ok(FutexEffectSnapshot {
                    token: record.token,
                    state: record.state,
                    selected_wait,
                    frozen_count,
                })
            })
            .collect()
    }

    fn watchdog_cohort(scope: &FutexScopeRecord) -> Vec<FutexEffectId> {
        scope.watchdog.as_ref().map_or_else(Vec::new, |watchdog| {
            watchdog.cohort.iter().copied().collect()
        })
    }

    fn validate_local_snapshot(&self, snapshot: &FutexRecoverySnapshot) -> Result<(), FutexError> {
        let local = self.local_scope(snapshot.scope())?;
        if snapshot.effects != self.snapshot_effects(local)?
            || snapshot.queue != local.queue.iter().copied().collect::<Vec<_>>()
            || snapshot.watchdog_cohort != Self::watchdog_cohort(local)
        {
            return Err(FutexError::Personality(
                PersonalityError::StaleRecoverySnapshot,
            ));
        }
        Ok(())
    }

    fn validate_wake_publication(&self, token: FutexToken) -> Result<WakePublication, FutexError> {
        let record = self.validate_token(token)?;
        if !matches!(token.operation(), FutexOperation::Wake { .. }) {
            return Err(FutexError::WrongOperation);
        }
        if record.state != FutexEffectState::WakeCommitted {
            return Err(FutexError::InvalidEffectState {
                state: record.state,
            });
        }
        if !self
            .local_scope(token.scope())?
            .committed_wakes
            .contains(&token.effect())
        {
            return Err(FutexError::InvariantViolation(
                "committed wake is missing from its scope-local index",
            ));
        }
        if record.continuation != FutexContinuationState::Pending
            || record.delivery.is_some()
            || record.kernel_publications != 0
            || record.terminalizations != 0
        {
            return Err(FutexError::InvariantViolation(
                "committed wake continuation is not pending",
            ));
        }
        let FutexRecordKind::Wake {
            selected_wait,
            frozen_count,
        } = record.kind
        else {
            return Err(FutexError::WrongOperation);
        };
        if frozen_count != u32::from(selected_wait.is_some()) || frozen_count > 1 {
            return Err(FutexError::InvariantViolation(
                "committed wake has an invalid frozen count",
            ));
        }
        if let Some(wait) = selected_wait {
            let wait_record = self
                .effects
                .get(&wait)
                .ok_or(FutexError::UnknownEffect(wait))?;
            if wait_record.state != FutexEffectState::WaitClaimed
                || wait_record.token.scope() != token.scope()
                || wait_record.token.key() != token.key()
                || wait_record.kind
                    != (FutexRecordKind::Wait {
                        selected_by: Some(token.effect()),
                    })
                || !wait_record.wait_credit_held
            {
                return Err(FutexError::InvariantViolation(
                    "frozen wake selection disagrees with claimed wait",
                ));
            }
        }
        Ok(WakePublication {
            wake: token.effect(),
            wait: selected_wait,
            frozen_count,
        })
    }

    fn publish_wake(&mut self, token: FutexToken, action: FutexAction) -> Result<(), FutexError> {
        let publication = self.validate_wake_publication(token)?;
        let local = self.local_scope(token.scope())?;
        let free_wait_after = if publication.wait.is_some() {
            local
                .free_budget
                .wait_credits
                .checked_add(1)
                .ok_or(FutexError::CounterOverflow)?
        } else {
            local.free_budget.wait_credits
        };
        let free_wake_after = local
            .free_budget
            .wake_credits
            .checked_add(1)
            .ok_or(FutexError::CounterOverflow)?;
        let terminalized_count = 1 + usize::from(publication.wait.is_some());
        let revocation_after = if let Some(revocation) = local.revocation {
            Some(
                revocation
                    .terminalized
                    .checked_add(terminalized_count)
                    .ok_or(FutexError::CounterOverflow)?,
            )
        } else {
            None
        };
        let index_selections_after = if action == FutexAction::RevokeStep {
            Some(Self::index_selections_after(local)?)
        } else {
            None
        };
        let mut removed = Vec::with_capacity(2);
        removed.push(publication.wake);
        if let Some(wait) = publication.wait {
            removed.push(wait);
        }
        let timer_after = self.timer_return_after_removing_many(token.scope(), &removed)?;
        let wake_task = token.task();
        let wait_task = publication.wait.map(|wait| {
            self.effects
                .get(&wait)
                .expect("validated selected wait remains present")
                .token
                .task()
        });

        self.gate.refinement_changed(token.scope())?;
        if let Some(wait) = publication.wait {
            let record = self
                .effects
                .get_mut(&wait)
                .ok_or(FutexError::UnknownEffect(wait))?;
            record.state = FutexEffectState::Completed;
            record.continuation = FutexContinuationState::Delivered;
            record.delivery = Some(FutexDelivery::WaitWoken);
            record.wait_credit_held = false;
            record.kernel_publications = 1;
            record.terminalizations = 1;
        }
        let wake = self
            .effects
            .get_mut(&publication.wake)
            .ok_or(FutexError::UnknownEffect(publication.wake))?;
        wake.state = FutexEffectState::Completed;
        wake.continuation = FutexContinuationState::Delivered;
        wake.delivery = Some(FutexDelivery::WakeReturned {
            count: publication.frozen_count,
        });
        wake.kernel_publications = 1;
        wake.terminalizations = 1;

        let local = self.local_scope_mut(token.scope())?;
        local.free_budget.wait_credits = free_wait_after;
        local.free_budget.wake_credits = free_wake_after;
        local.live_effects.remove(&publication.wake);
        local.committed_wakes.remove(&publication.wake);
        if let Some(wait) = publication.wait {
            local.live_effects.remove(&wait);
        }
        if let Some(revocation_after) = revocation_after {
            local
                .revocation
                .as_mut()
                .ok_or(FutexError::InvariantViolation(
                    "closure metadata disappeared during wake drain",
                ))?
                .terminalized = revocation_after;
        }
        if let Some(index_selections_after) = index_selections_after {
            local
                .revocation
                .as_mut()
                .ok_or(FutexError::InvariantViolation(
                    "closure metadata disappeared during wake selection",
                ))?
                .index_selections = index_selections_after;
        }
        self.blocked_tasks.remove(&(token.scope(), wake_task));
        if let Some(wait_task) = wait_task {
            self.blocked_tasks.remove(&(token.scope(), wait_task));
        }
        self.remove_many_from_watchdog(token.scope(), &removed, timer_after)?;
        self.push_trace(action, token.scope(), Some(publication.wake));
        Ok(())
    }

    fn terminalized_after(scope: &FutexScopeRecord, count: usize) -> Result<usize, FutexError> {
        scope
            .revocation
            .ok_or(FutexError::InvariantViolation(
                "closing scope lacks futex revocation metadata",
            ))?
            .terminalized
            .checked_add(count)
            .ok_or(FutexError::CounterOverflow)
    }

    fn index_selections_after(scope: &FutexScopeRecord) -> Result<usize, FutexError> {
        scope
            .revocation
            .ok_or(FutexError::InvariantViolation(
                "closing scope lacks futex revocation metadata",
            ))?
            .index_selections
            .checked_add(1)
            .ok_or(FutexError::CounterOverflow)
    }

    fn timer_return_after_removing(
        &self,
        scope: ScopeId,
        effect: FutexEffectId,
    ) -> Result<Option<u64>, FutexError> {
        self.timer_return_after_removing_many(scope, &[effect])
    }

    fn timer_return_after_removing_many(
        &self,
        scope: ScopeId,
        effects: &[FutexEffectId],
    ) -> Result<Option<u64>, FutexError> {
        let local = self.local_scope(scope)?;
        let Some(watchdog) = &local.watchdog else {
            return Ok(None);
        };
        let removed_members = effects
            .iter()
            .filter(|effect| watchdog.cohort.contains(effect))
            .count();
        let empties = removed_members == watchdog.cohort.len();
        if !empties {
            return Ok(None);
        }
        Ok(Some(
            local
                .free_budget
                .timer_credits
                .checked_add(1)
                .ok_or(FutexError::CounterOverflow)?,
        ))
    }

    fn remove_from_watchdog(
        &mut self,
        scope: ScopeId,
        effect: FutexEffectId,
        timer_after: Option<u64>,
    ) -> Result<(), FutexError> {
        self.remove_many_from_watchdog(scope, &[effect], timer_after)
    }

    fn remove_many_from_watchdog(
        &mut self,
        scope: ScopeId,
        effects: &[FutexEffectId],
        timer_after: Option<u64>,
    ) -> Result<(), FutexError> {
        let local = self.local_scope_mut(scope)?;
        let Some(watchdog) = local.watchdog.as_mut() else {
            if timer_after.is_some() {
                return Err(FutexError::InvariantViolation(
                    "timer return computed without a watchdog",
                ));
            }
            return Ok(());
        };
        for effect in effects {
            watchdog.cohort.remove(effect);
        }
        if watchdog.cohort.is_empty() {
            let timer_after = timer_after.ok_or(FutexError::InvariantViolation(
                "empty watchdog cohort did not return its timer credit",
            ))?;
            local.watchdog = None;
            local.free_budget.timer_credits = timer_after;
        } else if timer_after.is_some() {
            return Err(FutexError::InvariantViolation(
                "nonempty watchdog cohort attempted timer return",
            ));
        }
        Ok(())
    }

    fn check_effect_invariant(
        &self,
        effect: FutexEffectId,
        record: &FutexEffectRecord,
    ) -> Result<(), FutexInvariantViolation> {
        match (record.token.operation(), record.kind) {
            (FutexOperation::Wait { .. }, FutexRecordKind::Wait { selected_by }) => {
                match record.state {
                    FutexEffectState::WaitQueued => {
                        if selected_by.is_some()
                            || record.continuation != FutexContinuationState::Pending
                            || record.delivery.is_some()
                            || !record.wait_credit_held
                            || record.kernel_publications != 0
                            || record.terminalizations != 0
                        {
                            return Err(FutexInvariantViolation::SingleTerminalization(effect));
                        }
                    }
                    FutexEffectState::WaitClaimed => {
                        let Some(wake) = selected_by else {
                            return Err(FutexInvariantViolation::FrozenSelection(effect));
                        };
                        let Some(wake_record) = self.effects.get(&wake) else {
                            return Err(FutexInvariantViolation::FrozenSelection(effect));
                        };
                        if wake_record.state != FutexEffectState::WakeCommitted
                            || wake_record.kind
                                != (FutexRecordKind::Wake {
                                    selected_wait: Some(effect),
                                    frozen_count: 1,
                                })
                            || record.continuation != FutexContinuationState::Pending
                            || record.delivery.is_some()
                            || !record.wait_credit_held
                            || record.kernel_publications != 0
                            || record.terminalizations != 0
                        {
                            return Err(FutexInvariantViolation::FrozenSelection(effect));
                        }
                    }
                    FutexEffectState::Completed => {
                        let Some(wake) = selected_by else {
                            return Err(FutexInvariantViolation::FrozenSelection(effect));
                        };
                        let Some(wake_record) = self.effects.get(&wake) else {
                            return Err(FutexInvariantViolation::FrozenSelection(effect));
                        };
                        if wake_record.state != FutexEffectState::Completed
                            || wake_record.kind
                                != (FutexRecordKind::Wake {
                                    selected_wait: Some(effect),
                                    frozen_count: 1,
                                })
                            || record.continuation != FutexContinuationState::Delivered
                            || record.delivery != Some(FutexDelivery::WaitWoken)
                            || record.wait_credit_held
                            || record.kernel_publications != 1
                            || record.terminalizations != 1
                        {
                            return Err(FutexInvariantViolation::SingleTerminalization(effect));
                        }
                    }
                    FutexEffectState::Aborted => {
                        if selected_by.is_some()
                            || record.continuation != FutexContinuationState::Aborted
                            || record.delivery != Some(FutexDelivery::Aborted)
                            || record.wait_credit_held
                            || record.kernel_publications != 0
                            || record.terminalizations != 1
                        {
                            return Err(FutexInvariantViolation::SingleTerminalization(effect));
                        }
                    }
                    FutexEffectState::WakeCommitted => {
                        return Err(FutexInvariantViolation::SingleTerminalization(effect));
                    }
                }
            }
            (
                FutexOperation::Wake { .. },
                FutexRecordKind::Wake {
                    selected_wait,
                    frozen_count,
                },
            ) => {
                if frozen_count != u32::from(selected_wait.is_some()) || frozen_count > 1 {
                    return Err(FutexInvariantViolation::FrozenSelection(effect));
                }
                if let Some(wait) = selected_wait {
                    let Some(wait_record) = self.effects.get(&wait) else {
                        return Err(FutexInvariantViolation::FrozenSelection(effect));
                    };
                    let expected_state = match record.state {
                        FutexEffectState::WakeCommitted => FutexEffectState::WaitClaimed,
                        FutexEffectState::Completed => FutexEffectState::Completed,
                        _ => return Err(FutexInvariantViolation::FrozenSelection(effect)),
                    };
                    if wait_record.state != expected_state
                        || wait_record.kind
                            != (FutexRecordKind::Wait {
                                selected_by: Some(effect),
                            })
                    {
                        return Err(FutexInvariantViolation::FrozenSelection(effect));
                    }
                }
                let valid = match record.state {
                    FutexEffectState::WakeCommitted => {
                        record.continuation == FutexContinuationState::Pending
                            && record.delivery.is_none()
                            && record.kernel_publications == 0
                            && record.terminalizations == 0
                    }
                    FutexEffectState::Completed => {
                        record.continuation == FutexContinuationState::Delivered
                            && record.delivery
                                == Some(FutexDelivery::WakeReturned {
                                    count: frozen_count,
                                })
                            && record.kernel_publications == 1
                            && record.terminalizations == 1
                    }
                    FutexEffectState::WaitQueued
                    | FutexEffectState::WaitClaimed
                    | FutexEffectState::Aborted => false,
                };
                if !valid || record.wait_credit_held {
                    return Err(FutexInvariantViolation::SingleTerminalization(effect));
                }
            }
            _ => return Err(FutexInvariantViolation::SingleTerminalization(effect)),
        }
        Ok(())
    }

    fn push_trace(&mut self, action: FutexAction, scope: ScopeId, effect: Option<FutexEffectId>) {
        let gate = self
            .gate
            .scope(scope)
            .expect("successful futex transition retains its shared gate scope");
        self.trace.push(FutexTraceEvent {
            seq: self.trace.len(),
            action,
            scope,
            effect,
            authority_epoch: gate.authority_epoch,
            binding_epoch: gate.binding_epoch,
        });
    }
}
