//! Executable reference model for crash-recoverable user-space paging.
//!
//! The pager model refines the generic CSER protocol with a third generation
//! fence for address-space mutations, one-shot fault continuations, prepared
//! frame ownership, and an explicit mapping-publication commit point.  It is a
//! deterministic protocol oracle, not a page-table implementation.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{Budget, BudgetDisposition, ScopeId, ScopeState};

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
    /// Authority generation closed by `PagerModel::revoke_begin`.
    AuthorityEpoch
);
scalar_type!(
    /// Pager binding generation advanced only by `PagerModel::crash`.
    BindingEpoch
);
scalar_type!(
    /// Generation advanced by an address-space mapping-policy mutation.
    AddressSpaceGeneration
);
scalar_type!(
    /// Stable identity of one address space and its pager authority scope.
    AddressSpaceId
);
scalar_type!(
    /// Stable identity of one fault effect and continuation.
    FaultId
);
scalar_type!(
    /// Stable identity of a faulting thread.
    ThreadId
);
scalar_type!(
    /// Stable identity of one pager service instance.
    PagerId
);
scalar_type!(
    /// Allocation identity of one prepared physical frame.
    FrameId
);
scalar_type!(
    /// Page-aligned virtual address in the abstract model.
    PageAddress
);

/// Access bits captured at fault registration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FaultAccess(u8);

impl FaultAccess {
    /// Read access.
    pub const READ: Self = Self(1 << 0);
    /// Write access.
    pub const WRITE: Self = Self(1 << 1);
    /// Execute access.
    pub const EXECUTE: Self = Self(1 << 2);
    /// Access originated in user mode.
    pub const USER: Self = Self(1 << 3);

    /// Constructs an access mask from protocol bits.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Returns the protocol bit mask.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Combines two access masks.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Unforgeable-in-production identity of one fault reply authority.
///
/// The reference model stores the fields directly so tests can inspect the
/// three independent generation fences.  A kernel implementation must expose
/// an authenticated handle rather than trusting a user-provided struct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultToken {
    scope: ScopeId,
    fault: FaultId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    address_space: AddressSpaceId,
    address_space_generation: AddressSpaceGeneration,
    thread: ThreadId,
    page: PageAddress,
    access: FaultAccess,
}

impl FaultToken {
    /// Returns the authority scope inherited by this fault.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the one-shot fault identity.
    #[must_use]
    pub const fn fault(self) -> FaultId {
        self.fault
    }

    /// Returns the captured authority generation.
    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the pager binding generation currently owning the fault.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.binding_epoch
    }

    /// Returns the faulting address-space identity.
    #[must_use]
    pub const fn address_space(self) -> AddressSpaceId {
        self.address_space
    }

    /// Returns the mapping-policy generation captured at registration.
    #[must_use]
    pub const fn address_space_generation(self) -> AddressSpaceGeneration {
        self.address_space_generation
    }

    /// Returns the faulting thread identity.
    #[must_use]
    pub const fn thread(self) -> ThreadId {
        self.thread
    }

    /// Returns the faulting page address.
    #[must_use]
    pub const fn page(self) -> PageAddress {
        self.page
    }

    /// Returns the captured access bits.
    #[must_use]
    pub const fn access(self) -> FaultAccess {
        self.access
    }
}

/// Opaque proof of the pager currently bound to an active scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerBindingToken {
    scope: ScopeId,
    address_space: AddressSpaceId,
    pager: PagerId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
}

impl PagerBindingToken {
    /// Returns the bound authority scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the bound address space.
    #[must_use]
    pub const fn address_space(self) -> AddressSpaceId {
        self.address_space
    }

    /// Returns the bound pager identity.
    #[must_use]
    pub const fn pager(self) -> PagerId {
        self.pager
    }

    /// Returns the captured authority generation.
    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the captured binding generation.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.binding_epoch
    }
}

/// Lifecycle of the kernel pager fallback and replacement handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagerFallbackState {
    /// A live user-space pager is bound.
    Standby,
    /// A crash was fenced and the kernel fallback must take control.
    Required,
    /// The kernel fallback is running and may issue a recovery snapshot.
    Running,
    /// A replacement declared readiness from a fresh recovery snapshot.
    ReplacementReady,
}

/// Lifecycle of one pager fault effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultState {
    /// The fault and one-shot reply authority are registered.
    Registered,
    /// A unique zeroed candidate frame is retained by the effect.
    Prepared,
    /// The mapping was published and the continuation was resolved.
    Committed,
    /// A published or coalesced mapping enabled one successful resume.
    Completed,
    /// The continuation was aborted and its held resources were returned.
    Aborted,
}

impl FaultState {
    /// Returns whether no later fault-state transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

/// Consumption state of a one-shot fault continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuationState {
    /// No terminal reply has consumed the continuation.
    Pending,
    /// Mapping commit or kernel coalescing consumed a successful continuation.
    Resolved,
    /// Kernel closure consumed the continuation with a terminal failure.
    Aborted,
}

/// Identity of one mapping publication slot.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MappingKey {
    /// Address space receiving the mapping.
    pub address_space: AddressSpaceId,
    /// Address-space generation receiving the mapping.
    pub generation: AddressSpaceGeneration,
    /// Virtual page receiving the mapping.
    pub page: PageAddress,
}

/// Ownership state of a frame identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameState {
    /// The frame is retained exclusively by an uncommitted fault.
    Prepared(FaultId),
    /// The frame belongs to a published mapping.
    Mapped {
        /// Mapping slot that owns the frame.
        key: MappingKey,
        /// Fault whose commit published the mapping.
        fault: FaultId,
    },
    /// Abort, coalescing, or generation teardown released the allocation.
    Released(FaultId),
}

/// Read-only projection of one frame identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameView {
    /// Current ownership state.
    pub state: FrameState,
}

/// Read-only projection of one published mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingView {
    /// Frame installed at the mapping slot.
    pub frame: FrameId,
    /// Fault whose commit published the mapping.
    pub fault: FaultId,
}

/// Read-only projection of one fault effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultView {
    /// Immutable fault reply identity, updated only by explicit adoption.
    pub token: FaultToken,
    /// Effect lifecycle state.
    pub state: FaultState,
    /// One-shot continuation state.
    pub continuation: ContinuationState,
    /// Resource credit reserved by the fault.
    pub budget: Budget,
    /// Current credit disposition.
    pub budget_disposition: BudgetDisposition,
    /// Candidate frame retained before commit.
    pub prepared_frame: Option<FrameId>,
    /// Frame owned by the mapping after commit.
    pub mapped_frame: Option<FrameId>,
    /// Mapping publication that resolved this continuation.
    ///
    /// The fault may own the publication, share another fault's current
    /// mapping, or retain only historical evidence after generation teardown.
    pub resolved_mapping: Option<MappingKey>,
    /// Number of mapping publications performed by this fault.
    pub mapping_publications: u8,
    /// Number of continuation consumptions performed by this fault.
    pub continuation_consumptions: u8,
    /// Number of terminal effect transitions.
    pub terminalizations: u8,
    /// Number of terminal notifications delivered to the blocked client.
    pub wakes: u8,
    /// Number of successful same-instruction fault retries enabled.
    pub resumes: u8,
}

/// Bounded progress of one pager-scope revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerRevocationProgress {
    /// Authority generation closed by `revoke_begin`.
    pub closed_epoch: AuthorityEpoch,
    /// Faults present in the scope-local reverse index at the commit point.
    pub target_count: usize,
    /// Faults visited by `revoke_next`.
    pub steps: usize,
    /// Faults still live in the scope-local reverse index.
    pub remaining: usize,
}

/// Read-only projection of one address-space pager scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerScopeView {
    /// Scope lifecycle state.
    pub state: ScopeState,
    /// Current authority generation.
    pub authority_epoch: AuthorityEpoch,
    /// Current pager binding generation.
    pub binding_epoch: BindingEpoch,
    /// Address space governed by this scope.
    pub address_space: AddressSpaceId,
    /// Current address-space mapping-policy generation.
    pub address_space_generation: AddressSpaceGeneration,
    /// Currently bound pager, if one exists.
    pub pager: Option<PagerId>,
    /// Kernel fallback/replacement lifecycle.
    pub fallback: PagerFallbackState,
    /// Immutable initial resource budget.
    pub initial_budget: Budget,
    /// Credits available for new fault registrations.
    pub free_budget: Budget,
    /// Credits retained by mappings that are currently installed.
    pub spent_budget: Budget,
    /// Number of nonterminal faults in the reverse index.
    pub live_faults: usize,
    /// Whether kernel-owned recovery deadline work remains armed.
    pub recovery_deadline_armed: bool,
    /// Whether an expired batch is waiting only for kernel completion.
    pub recovery_deadline_completion_pending: bool,
    /// Closure progress after revocation begins.
    pub revocation: Option<PagerRevocationProgress>,
}

/// One fault entry captured by a replacement recovery snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultSnapshot {
    /// Reply identity current at snapshot creation.
    pub token: FaultToken,
    /// State current at snapshot creation.
    pub state: FaultState,
    /// Candidate frame retained across the pager crash, if prepared.
    pub prepared_frame: Option<FrameId>,
}

/// Immutable recovery snapshot required before replacement readiness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySnapshot {
    scope: ScopeId,
    address_space: AddressSpaceId,
    pager: PagerId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    address_space_generation: AddressSpaceGeneration,
    recovery_revision: u64,
    faults: Vec<FaultSnapshot>,
}

impl RecoverySnapshot {
    /// Returns the scope represented by the snapshot.
    #[must_use]
    pub const fn scope(&self) -> ScopeId {
        self.scope
    }

    /// Returns the replacement pager for which the snapshot was issued.
    #[must_use]
    pub const fn pager(&self) -> PagerId {
        self.pager
    }

    /// Returns the authority generation represented by the snapshot.
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the binding generation represented by the snapshot.
    #[must_use]
    pub const fn binding_epoch(&self) -> BindingEpoch {
        self.binding_epoch
    }

    /// Returns the address-space generation represented by the snapshot.
    #[must_use]
    pub const fn address_space_generation(&self) -> AddressSpaceGeneration {
        self.address_space_generation
    }

    /// Returns the deterministic live-fault entries in the snapshot.
    #[must_use]
    pub fn faults(&self) -> &[FaultSnapshot] {
        &self.faults
    }
}

/// Opaque proof that a fresh snapshot was accepted by `ready`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerReadyToken {
    scope: ScopeId,
    address_space: AddressSpaceId,
    pager: PagerId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    address_space_generation: AddressSpaceGeneration,
    recovery_revision: u64,
}

impl PagerReadyToken {
    /// Returns the replacement pager that declared readiness.
    #[must_use]
    pub const fn pager(self) -> PagerId {
        self.pager
    }

    /// Returns the binding generation in which readiness was declared.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.binding_epoch
    }
}

/// Successful state transition performed by `revoke_next`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerRevocationStep {
    /// Fault visited through the target scope's reverse index.
    pub fault: FaultId,
    /// State before the closure step.
    pub from: FaultState,
    /// Terminal state after the closure step.
    pub to: FaultState,
    /// Candidate frame released by an abort, if any.
    pub released_frame: Option<FrameId>,
    /// Held budget returned by an abort.
    pub returned_budget: Budget,
}

/// Result of a kernel recovery deadline firing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryTimeoutResult {
    /// Uncommitted fault work caused authority revocation to begin.
    RevocationStarted,
    /// Every live fault was already committed, so only kernel completion remains.
    CompletionPending {
        /// Committed faults still requiring their one-shot success completion.
        committed: usize,
    },
}

/// Stable pager action vocabulary used by deterministic traces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagerAction {
    /// Create one address-space scope and initial pager binding.
    CreateAddressSpace,
    /// Register a fault continuation and reserve its credit.
    Register,
    /// Retain one unique prepared frame.
    Prepare,
    /// Fence a failed pager by advancing the binding generation.
    Crash,
    /// Select the minimal kernel pager fallback.
    FallbackPick,
    /// Accept a fresh replacement snapshot and readiness declaration.
    Ready,
    /// Install the ready replacement without advancing binding generation.
    Rebind,
    /// Explicitly move an orphan fault to the replacement binding.
    Adopt,
    /// Publish a mapping and consume the continuation successfully.
    Commit,
    /// Resolve a same-page continuation from an existing current mapping.
    SatisfyMapped,
    /// Deliver the unique success wake/resume after commit.
    Complete,
    /// Advance the address-space mapping-policy generation.
    AdvanceAddressSpaceGeneration,
    /// Mark an expired batch whose live effects are all already committed.
    DeadlineCompletionPending,
    /// Return a fully terminal recovery batch to the idle deadline state.
    DeadlineComplete,
    /// Consume a continuation with terminal failure and return held credit.
    Abort,
    /// Close the current authority generation.
    RevokeBegin,
    /// Visit one fault through the scope-local reverse index.
    RevokeStep,
    /// Publish quiescent closure after the reverse index becomes empty.
    RevokeComplete,
}

/// One successful pager operation in the model's total linearization order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerTraceEvent {
    /// Zero-based total-order position.
    pub seq: usize,
    /// Operation that linearized.
    pub action: PagerAction,
    /// Scope affected by the operation.
    pub scope: ScopeId,
    /// Fault affected by the operation, when applicable.
    pub fault: Option<FaultId>,
    /// Authority generation immediately after the operation.
    pub authority_epoch: AuthorityEpoch,
    /// Binding generation immediately after the operation.
    pub binding_epoch: BindingEpoch,
    /// Address-space generation immediately after the operation.
    pub address_space_generation: AddressSpaceGeneration,
}

/// Rejected pager model operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagerError {
    /// The requested scope does not exist.
    UnknownScope(ScopeId),
    /// The requested address space does not exist.
    UnknownAddressSpace(AddressSpaceId),
    /// The requested fault does not exist.
    UnknownFault(FaultId),
    /// The scope is not in the state required by the operation.
    InvalidScopeState {
        /// Actual scope state.
        state: ScopeState,
    },
    /// The fault is not in the state required by the operation.
    InvalidFaultState {
        /// Actual fault state.
        state: FaultState,
    },
    /// An operation mixed objects from different scopes.
    ScopeMismatch,
    /// An operation mixed objects from different address spaces.
    AddressSpaceMismatch,
    /// The authority generation was closed by revocation.
    StaleAuthority {
        /// Generation carried by the operation.
        presented: AuthorityEpoch,
        /// Generation currently required by the scope.
        current: AuthorityEpoch,
    },
    /// A former pager binding attempted to act after crash fencing.
    StaleBinding {
        /// Generation carried by the operation.
        presented: BindingEpoch,
        /// Generation currently required by the scope.
        current: BindingEpoch,
    },
    /// A fault still belongs to an old pager binding.
    FaultBindingFenced {
        /// Generation carried by the fault.
        fault_binding: BindingEpoch,
        /// Generation required by the current pager binding.
        current_binding: BindingEpoch,
    },
    /// A fault or recovery token names an old address-space generation.
    StaleAddressSpaceGeneration {
        /// Generation carried by the operation.
        presented: AddressSpaceGeneration,
        /// Current address-space generation.
        current: AddressSpaceGeneration,
    },
    /// The binding token names a pager other than the installed pager.
    WrongPager,
    /// No user-space pager is currently installed.
    PagerUnavailable,
    /// A live pager is already installed.
    PagerAlreadyBound,
    /// The kernel fallback is not at the required stage.
    FallbackUnavailable,
    /// No live recovery cohort has an armed kernel deadline.
    RecoveryDeadlineUnavailable,
    /// An expired committed-only batch must finish before registering new work.
    RecoveryDeadlineCompletionPending,
    /// Deadline completion was requested before its expired batch became terminal.
    RecoveryDeadlineNotComplete,
    /// A recovery snapshot changed before readiness or rebind.
    StaleRecoverySnapshot,
    /// The presented token does not match the recorded fault identity.
    FaultIdentityMismatch,
    /// The fault is not an orphaned uncommitted effect eligible for adoption.
    NotAdoptable,
    /// The frame identity was already prepared, mapped, or released.
    FrameAlreadyKnown(FrameId),
    /// The prepared frame and its ownership record disagree.
    FrameOwnershipMismatch(FrameId),
    /// Another fault already published this mapping slot and generation.
    MappingAlreadyPublished(MappingKey),
    /// No current mapping can satisfy the requested slot and generation.
    MappingUnavailable(MappingKey),
    /// Active current-generation work cannot be aborted arbitrarily.
    AbortNotPermitted,
    /// Address-space mutation must wait for mapping publication completion.
    CommittedMappingOutstanding {
        /// Committed faults that have not delivered their completion yet.
        remaining: usize,
    },
    /// A zero-credit fault registration is forbidden.
    ZeroBudget,
    /// The scope lacks enough free credits for registration.
    BudgetExhausted {
        /// Credits requested by the fault.
        requested: Budget,
        /// Credits currently available.
        available: Budget,
    },
    /// The one-shot continuation was already consumed.
    ContinuationAlreadyConsumed,
    /// The fault already reached a terminal state.
    AlreadyTerminal,
    /// Closure was acknowledged while faults remained live.
    RevocationNotQuiescent {
        /// Faults remaining in the scope-local reverse index.
        remaining: usize,
    },
    /// A monotonically increasing identifier, generation, or counter overflowed.
    CounterOverflow,
    /// Internal state relationships were inconsistent.
    InvariantViolation(&'static str),
}

/// Failure reported by a full pager model invariant audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagerInvariantViolation {
    /// Scope budget components no longer sum to the initial budget.
    BudgetConservation(ScopeId),
    /// The scope's spent counter differs from committed fault grants.
    SpentAccounting(ScopeId),
    /// A fault lifecycle and its credit disposition disagree.
    FaultBudgetState(FaultId),
    /// A scope reverse index differs from its nonterminal fault set.
    LiveReverseIndex(ScopeId),
    /// A continuation was consumed zero or multiple times for its state.
    ContinuationConsumption(FaultId),
    /// A terminal notification or resume count violates one-shot semantics.
    WakeResume(FaultId),
    /// Mapping publication and fault state disagree.
    MappingPublication(FaultId),
    /// Candidate or mapped frame ownership disagrees with the fault.
    FrameOwnership(FaultId),
    /// One mapping record disagrees with its fault or frame.
    MappingOwnership(MappingKey),
    /// An effect terminalized more than once or its count disagrees with state.
    Terminalization(FaultId),
    /// A revoked scope still contains live faults.
    RevokedScopeLive(ScopeId),
    /// Scope state and revocation progress metadata disagree.
    RevocationMetadata(ScopeId),
    /// Closure visited more faults than were indexed at `revoke_begin`.
    RevocationWorkBound(ScopeId),
    /// Pager presence, fallback state, and readiness metadata disagree.
    FallbackState(ScopeId),
    /// Kernel recovery-deadline state disagrees with the live cohort.
    RecoveryDeadlineState(ScopeId),
    /// A fault refers to a missing or mismatched scope/address space.
    OrphanFault(FaultId),
    /// A fault carries a generation newer than its owning scope.
    FutureGeneration(FaultId),
    /// The address-space reverse lookup disagrees with its scope.
    AddressSpaceIndex(AddressSpaceId),
    /// A frame record has no consistent owning fault or mapping.
    OrphanFrame(FrameId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReadyRecord {
    pager: PagerId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    address_space_generation: AddressSpaceGeneration,
    recovery_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RevocationRecord {
    closed_epoch: AuthorityEpoch,
    target_count: usize,
    steps: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PagerScopeRecord {
    state: ScopeState,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    address_space: AddressSpaceId,
    address_space_generation: AddressSpaceGeneration,
    pager: Option<PagerId>,
    fallback: PagerFallbackState,
    ready: Option<ReadyRecord>,
    initial_budget: Budget,
    free_budget: Budget,
    spent_budget: Budget,
    live_faults: BTreeSet<FaultId>,
    revocation: Option<RevocationRecord>,
    recovery_revision: u64,
    recovery_deadline_armed: bool,
    recovery_deadline_completion_pending: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaultRecord {
    token: FaultToken,
    state: FaultState,
    continuation: ContinuationState,
    budget: Budget,
    budget_disposition: BudgetDisposition,
    prepared_frame: Option<FrameId>,
    mapped_frame: Option<FrameId>,
    resolved_mapping: Option<MappingKey>,
    mapping_publications: u8,
    continuation_consumptions: u8,
    terminalizations: u8,
    wakes: u8,
    resumes: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameRecord {
    state: FrameState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MappingRecord {
    frame: FrameId,
    fault: FaultId,
}

/// Deterministic `no_std + alloc` pager recovery reference model.
///
/// Concurrency is represented by invoking atomic methods in different orders.
/// Failed methods perform no state mutation, making stale-reply and commit-vs-
/// revoke witnesses directly comparable with a finite successor specification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagerModel {
    next_scope: u64,
    next_address_space: u64,
    next_fault: u64,
    scopes: BTreeMap<ScopeId, PagerScopeRecord>,
    address_spaces: BTreeMap<AddressSpaceId, ScopeId>,
    faults: BTreeMap<FaultId, FaultRecord>,
    frames: BTreeMap<FrameId, FrameRecord>,
    current_mappings: BTreeMap<MappingKey, MappingRecord>,
    publication_history: BTreeMap<MappingKey, MappingRecord>,
    trace: Vec<PagerTraceEvent>,
}
