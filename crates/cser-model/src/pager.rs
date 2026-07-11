//! Executable reference model for crash-recoverable user-space paging.
//!
//! The pager model refines the generic CSER protocol with a third generation
//! fence for address-space mutations, one-shot fault continuations, prepared
//! frame ownership, and an explicit mapping-publication commit point.  It is a
//! deterministic protocol oracle, not a page-table implementation.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{Budget, BudgetDisposition, ScopeId, ScopeState};

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

impl Default for PagerModel {
    fn default() -> Self {
        Self::new()
    }
}

impl PagerModel {
    /// Creates an empty pager protocol model.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_scope: 1,
            next_address_space: 1,
            next_fault: 1,
            scopes: BTreeMap::new(),
            address_spaces: BTreeMap::new(),
            faults: BTreeMap::new(),
            frames: BTreeMap::new(),
            current_mappings: BTreeMap::new(),
            publication_history: BTreeMap::new(),
            trace: Vec::new(),
        }
    }

    /// Creates one active scope, address space, and initial pager binding.
    pub fn create_address_space(
        &mut self,
        pager: PagerId,
        budget: Budget,
    ) -> Result<(ScopeId, AddressSpaceId, PagerBindingToken), PagerError> {
        let scope = ScopeId::new(self.next_scope);
        let address_space = AddressSpaceId::new(self.next_address_space);
        let next_scope = self
            .next_scope
            .checked_add(1)
            .ok_or(PagerError::CounterOverflow)?;
        let next_address_space = self
            .next_address_space
            .checked_add(1)
            .ok_or(PagerError::CounterOverflow)?;
        let authority_epoch = AuthorityEpoch::new(1);
        let binding_epoch = BindingEpoch::new(1);
        let address_space_generation = AddressSpaceGeneration::new(1);
        self.next_scope = next_scope;
        self.next_address_space = next_address_space;
        self.scopes.insert(
            scope,
            PagerScopeRecord {
                state: ScopeState::Active,
                authority_epoch,
                binding_epoch,
                address_space,
                address_space_generation,
                pager: Some(pager),
                fallback: PagerFallbackState::Standby,
                ready: None,
                initial_budget: budget,
                free_budget: budget,
                spent_budget: Budget::ZERO,
                live_faults: BTreeSet::new(),
                revocation: None,
                recovery_revision: 0,
                recovery_deadline_armed: false,
                recovery_deadline_completion_pending: false,
            },
        );
        self.address_spaces.insert(address_space, scope);
        self.push_trace(PagerAction::CreateAddressSpace, scope, None);
        Ok((
            scope,
            address_space,
            PagerBindingToken {
                scope,
                address_space,
                pager,
                authority_epoch,
                binding_epoch,
            },
        ))
    }

    /// Registers one fault and atomically moves its credit from free to held.
    pub fn register_fault(
        &mut self,
        binding: PagerBindingToken,
        thread: ThreadId,
        page: PageAddress,
        access: FaultAccess,
        budget: Budget,
    ) -> Result<FaultToken, PagerError> {
        if budget == Budget::ZERO {
            return Err(PagerError::ZeroBudget);
        }
        let scope = self.validate_binding(binding)?;
        if scope.recovery_deadline_completion_pending {
            return Err(PagerError::RecoveryDeadlineCompletionPending);
        }
        if scope.free_budget.units() < budget.units() {
            return Err(PagerError::BudgetExhausted {
                requested: budget,
                available: scope.free_budget,
            });
        }
        let free_after = scope
            .free_budget
            .units()
            .checked_sub(budget.units())
            .ok_or(PagerError::InvariantViolation("budget underflow"))?;
        let revision_after = Self::next_revision(scope)?;
        let fault = FaultId::new(self.next_fault);
        let next_fault = self
            .next_fault
            .checked_add(1)
            .ok_or(PagerError::CounterOverflow)?;
        let token = FaultToken {
            scope: binding.scope,
            fault,
            authority_epoch: scope.authority_epoch,
            binding_epoch: scope.binding_epoch,
            address_space: scope.address_space,
            address_space_generation: scope.address_space_generation,
            thread,
            page,
            access,
        };

        self.next_fault = next_fault;
        let scope = self
            .scopes
            .get_mut(&binding.scope)
            .ok_or(PagerError::UnknownScope(binding.scope))?;
        scope.free_budget = Budget::new(free_after);
        scope.live_faults.insert(fault);
        scope.recovery_deadline_armed = true;
        scope.recovery_deadline_completion_pending = false;
        Self::publish_recovery_revision(scope, revision_after);
        self.faults.insert(
            fault,
            FaultRecord {
                token,
                state: FaultState::Registered,
                continuation: ContinuationState::Pending,
                budget,
                budget_disposition: BudgetDisposition::Held,
                prepared_frame: None,
                mapped_frame: None,
                resolved_mapping: None,
                mapping_publications: 0,
                continuation_consumptions: 0,
                terminalizations: 0,
                wakes: 0,
                resumes: 0,
            },
        );
        self.push_trace(PagerAction::Register, binding.scope, Some(fault));
        Ok(token)
    }

    /// Retains one uniquely identified zeroed frame for a registered fault.
    pub fn prepare_zero(
        &mut self,
        binding: PagerBindingToken,
        token: FaultToken,
        frame: FrameId,
    ) -> Result<(), PagerError> {
        self.validate_current_fault_reply(binding, token)?;
        let fault = *self
            .faults
            .get(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?;
        if fault.state != FaultState::Registered {
            return Err(if fault.state.is_terminal() {
                PagerError::AlreadyTerminal
            } else {
                PagerError::InvalidFaultState { state: fault.state }
            });
        }
        if self.frames.contains_key(&frame) {
            return Err(PagerError::FrameAlreadyKnown(frame));
        }
        let revision_after = Self::next_revision(
            self.scopes
                .get(&token.scope)
                .ok_or(PagerError::UnknownScope(token.scope))?,
        )?;

        let fault = self
            .faults
            .get_mut(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?;
        fault.state = FaultState::Prepared;
        fault.prepared_frame = Some(frame);
        self.frames.insert(
            frame,
            FrameRecord {
                state: FrameState::Prepared(token.fault),
            },
        );
        self.scopes
            .get_mut(&token.scope)
            .map(|scope| Self::publish_recovery_revision(scope, revision_after))
            .ok_or(PagerError::UnknownScope(token.scope))?;
        self.push_trace(PagerAction::Prepare, token.scope, Some(token.fault));
        Ok(())
    }

    /// Fences a crashed pager and advances only the binding generation.
    pub fn crash(&mut self, binding: PagerBindingToken) -> Result<(), PagerError> {
        let scope = self.validate_binding(binding)?;
        let next_binding = BindingEpoch::new(
            scope
                .binding_epoch
                .get()
                .checked_add(1)
                .ok_or(PagerError::CounterOverflow)?,
        );
        let scope = self
            .scopes
            .get_mut(&binding.scope)
            .ok_or(PagerError::UnknownScope(binding.scope))?;
        scope.binding_epoch = next_binding;
        scope.pager = None;
        scope.fallback = PagerFallbackState::Required;
        scope.ready = None;
        self.push_trace(PagerAction::Crash, binding.scope, None);
        Ok(())
    }

    /// Selects the minimal kernel fallback after pager failure.
    pub fn fallback_pick(&mut self, scope: ScopeId) -> Result<(), PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if record.pager.is_some() || record.fallback != PagerFallbackState::Required {
            return Err(PagerError::FallbackUnavailable);
        }
        self.scopes
            .get_mut(&scope)
            .ok_or(PagerError::UnknownScope(scope))?
            .fallback = PagerFallbackState::Running;
        self.push_trace(PagerAction::FallbackPick, scope, None);
        Ok(())
    }

    /// Captures the deterministic orphan set for a fresh replacement pager.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        pager: PagerId,
    ) -> Result<RecoverySnapshot, PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if record.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState {
                state: record.state,
            });
        }
        if record.pager.is_some() || record.fallback != PagerFallbackState::Running {
            return Err(PagerError::FallbackUnavailable);
        }
        let mut faults = Vec::new();
        for fault_id in &record.live_faults {
            let fault = self
                .faults
                .get(fault_id)
                .ok_or(PagerError::UnknownFault(*fault_id))?;
            if matches!(fault.state, FaultState::Registered | FaultState::Prepared) {
                faults.push(FaultSnapshot {
                    token: fault.token,
                    state: fault.state,
                    prepared_frame: fault.prepared_frame,
                });
            }
        }
        Ok(RecoverySnapshot {
            scope,
            address_space: record.address_space,
            pager,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            address_space_generation: record.address_space_generation,
            recovery_revision: record.recovery_revision,
            faults,
        })
    }

    /// Accepts replacement readiness only from a still-fresh recovery snapshot.
    pub fn ready(&mut self, snapshot: &RecoverySnapshot) -> Result<PagerReadyToken, PagerError> {
        let scope = self
            .scopes
            .get(&snapshot.scope)
            .ok_or(PagerError::UnknownScope(snapshot.scope))?;
        if scope.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState { state: scope.state });
        }
        if scope.pager.is_some() || scope.fallback != PagerFallbackState::Running {
            return Err(PagerError::FallbackUnavailable);
        }
        self.validate_snapshot(scope, snapshot)?;
        let token = PagerReadyToken {
            scope: snapshot.scope,
            address_space: snapshot.address_space,
            pager: snapshot.pager,
            authority_epoch: snapshot.authority_epoch,
            binding_epoch: snapshot.binding_epoch,
            address_space_generation: snapshot.address_space_generation,
            recovery_revision: snapshot.recovery_revision,
        };
        let scope = self
            .scopes
            .get_mut(&snapshot.scope)
            .ok_or(PagerError::UnknownScope(snapshot.scope))?;
        scope.fallback = PagerFallbackState::ReplacementReady;
        scope.ready = Some(ReadyRecord {
            pager: token.pager,
            authority_epoch: token.authority_epoch,
            binding_epoch: token.binding_epoch,
            address_space_generation: token.address_space_generation,
            recovery_revision: token.recovery_revision,
        });
        self.push_trace(PagerAction::Ready, snapshot.scope, None);
        Ok(token)
    }

    /// Installs a ready replacement without advancing the binding generation.
    pub fn rebind(&mut self, ready: PagerReadyToken) -> Result<PagerBindingToken, PagerError> {
        let scope = self
            .scopes
            .get(&ready.scope)
            .ok_or(PagerError::UnknownScope(ready.scope))?;
        if scope.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState { state: scope.state });
        }
        if scope.pager.is_some() {
            return Err(PagerError::PagerAlreadyBound);
        }
        if scope.fallback != PagerFallbackState::ReplacementReady {
            return Err(PagerError::FallbackUnavailable);
        }
        self.validate_ready(scope, ready)?;
        let binding = PagerBindingToken {
            scope: ready.scope,
            address_space: ready.address_space,
            pager: ready.pager,
            authority_epoch: ready.authority_epoch,
            binding_epoch: ready.binding_epoch,
        };
        let scope = self
            .scopes
            .get_mut(&ready.scope)
            .ok_or(PagerError::UnknownScope(ready.scope))?;
        scope.pager = Some(ready.pager);
        scope.fallback = PagerFallbackState::Standby;
        scope.ready = None;
        self.push_trace(PagerAction::Rebind, ready.scope, None);
        Ok(binding)
    }

    /// Explicitly transfers an orphan uncommitted fault to the replacement.
    pub fn adopt(
        &mut self,
        binding: PagerBindingToken,
        token: FaultToken,
    ) -> Result<FaultToken, PagerError> {
        let scope = self.validate_binding(binding)?;
        let fault = self.validate_fault_token(token)?;
        if token.scope != binding.scope {
            return Err(PagerError::ScopeMismatch);
        }
        if token.authority_epoch != scope.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if token.address_space_generation != scope.address_space_generation {
            return Err(PagerError::StaleAddressSpaceGeneration {
                presented: token.address_space_generation,
                current: scope.address_space_generation,
            });
        }
        if !matches!(fault.state, FaultState::Registered | FaultState::Prepared)
            || fault.token.binding_epoch == scope.binding_epoch
        {
            return Err(PagerError::NotAdoptable);
        }
        let revision_after = Self::next_revision(scope)?;
        let mut adopted = token;
        adopted.binding_epoch = scope.binding_epoch;
        self.faults
            .get_mut(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?
            .token = adopted;
        self.scopes
            .get_mut(&token.scope)
            .map(|scope| Self::publish_recovery_revision(scope, revision_after))
            .ok_or(PagerError::UnknownScope(token.scope))?;
        self.push_trace(PagerAction::Adopt, token.scope, Some(token.fault));
        Ok(adopted)
    }

    /// Atomically publishes a mapping and consumes the fault continuation.
    ///
    /// This is the pager effect's commit linearization point.  Every authority,
    /// binding, address-space, identity, state, frame, and mapping-slot check is
    /// performed before either the mapping or continuation state is mutated.
    pub fn commit(
        &mut self,
        binding: PagerBindingToken,
        token: FaultToken,
    ) -> Result<MappingKey, PagerError> {
        self.validate_current_fault_reply(binding, token)?;
        let fault = *self
            .faults
            .get(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?;
        if fault.state.is_terminal() {
            return Err(PagerError::AlreadyTerminal);
        }
        if fault.continuation != ContinuationState::Pending {
            return Err(PagerError::ContinuationAlreadyConsumed);
        }
        if fault.state != FaultState::Prepared {
            return Err(PagerError::InvalidFaultState { state: fault.state });
        }
        let frame = fault.prepared_frame.ok_or(PagerError::InvariantViolation(
            "prepared fault lacks a frame",
        ))?;
        let frame_record = self
            .frames
            .get(&frame)
            .ok_or(PagerError::FrameOwnershipMismatch(frame))?;
        if frame_record.state != FrameState::Prepared(token.fault) {
            return Err(PagerError::FrameOwnershipMismatch(frame));
        }
        let key = MappingKey {
            address_space: token.address_space,
            generation: token.address_space_generation,
            page: token.page,
        };
        if self.current_mappings.contains_key(&key) || self.publication_history.contains_key(&key) {
            return Err(PagerError::MappingAlreadyPublished(key));
        }
        if fault.budget_disposition != BudgetDisposition::Held {
            return Err(PagerError::InvariantViolation(
                "prepared fault does not hold its budget",
            ));
        }
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(PagerError::UnknownScope(token.scope))?;
        let spent_after = scope
            .spent_budget
            .units()
            .checked_add(fault.budget.units())
            .ok_or(PagerError::CounterOverflow)?;
        let revision_after = Self::next_revision(scope)?;

        let fault_record = self
            .faults
            .get_mut(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?;
        fault_record.state = FaultState::Committed;
        fault_record.continuation = ContinuationState::Resolved;
        fault_record.budget_disposition = BudgetDisposition::Spent;
        fault_record.prepared_frame = None;
        fault_record.mapped_frame = Some(frame);
        fault_record.resolved_mapping = Some(key);
        fault_record.mapping_publications = 1;
        fault_record.continuation_consumptions = 1;
        self.frames
            .get_mut(&frame)
            .ok_or(PagerError::FrameOwnershipMismatch(frame))?
            .state = FrameState::Mapped {
            key,
            fault: token.fault,
        };
        let mapping = MappingRecord {
            frame,
            fault: token.fault,
        };
        self.current_mappings.insert(key, mapping);
        self.publication_history.insert(key, mapping);
        let scope = self
            .scopes
            .get_mut(&token.scope)
            .ok_or(PagerError::UnknownScope(token.scope))?;
        scope.spent_budget = Budget::new(spent_after);
        Self::publish_recovery_revision(scope, revision_after);
        self.push_trace(PagerAction::Commit, token.scope, Some(token.fault));
        Ok(key)
    }

    /// Resolves a same-page fault from an already published current mapping.
    ///
    /// This is a kernel-owned coalescing transition. It consumes the losing
    /// continuation exactly once, releases any redundant prepared frame,
    /// returns that fault's held credit, and publishes one success wake/resume
    /// without incrementing the mapping-publication count.
    pub fn satisfy_mapped(&mut self, token: FaultToken) -> Result<MappingKey, PagerError> {
        let fault = *self.validate_fault_token(token)?;
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(PagerError::UnknownScope(token.scope))?;
        if scope.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState { state: scope.state });
        }
        if token.authority_epoch != scope.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if token.address_space_generation != scope.address_space_generation {
            return Err(PagerError::StaleAddressSpaceGeneration {
                presented: token.address_space_generation,
                current: scope.address_space_generation,
            });
        }
        if fault.state.is_terminal() {
            return Err(PagerError::AlreadyTerminal);
        }
        if !matches!(fault.state, FaultState::Registered | FaultState::Prepared) {
            return Err(PagerError::InvalidFaultState { state: fault.state });
        }
        if fault.continuation != ContinuationState::Pending
            || fault.budget_disposition != BudgetDisposition::Held
        {
            return Err(PagerError::InvariantViolation(
                "coalesced fault lacks pending continuation or held budget",
            ));
        }
        if let Some(frame) = fault.prepared_frame
            && self.frames.get(&frame).map(|record| record.state)
                != Some(FrameState::Prepared(token.fault))
        {
            return Err(PagerError::FrameOwnershipMismatch(frame));
        }
        let key = MappingKey {
            address_space: token.address_space,
            generation: token.address_space_generation,
            page: token.page,
        };
        if !self.current_mappings.contains_key(&key) {
            return Err(PagerError::MappingUnavailable(key));
        }
        let free_after = scope
            .free_budget
            .units()
            .checked_add(fault.budget.units())
            .ok_or(PagerError::CounterOverflow)?;
        let revision_after = Self::next_revision(scope)?;

        let fault_record = self
            .faults
            .get_mut(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?;
        fault_record.state = FaultState::Completed;
        fault_record.continuation = ContinuationState::Resolved;
        fault_record.budget_disposition = BudgetDisposition::Returned;
        fault_record.prepared_frame = None;
        fault_record.mapped_frame = None;
        fault_record.resolved_mapping = Some(key);
        fault_record.mapping_publications = 0;
        fault_record.continuation_consumptions = 1;
        fault_record.terminalizations = 1;
        fault_record.wakes = 1;
        fault_record.resumes = 1;
        if let Some(frame) = fault.prepared_frame {
            self.frames
                .get_mut(&frame)
                .ok_or(PagerError::FrameOwnershipMismatch(frame))?
                .state = FrameState::Released(token.fault);
        }
        let scope = self
            .scopes
            .get_mut(&token.scope)
            .ok_or(PagerError::UnknownScope(token.scope))?;
        scope.free_budget = Budget::new(free_after);
        scope.live_faults.remove(&token.fault);
        if scope.live_faults.is_empty() && !scope.recovery_deadline_completion_pending {
            scope.recovery_deadline_armed = false;
        }
        Self::publish_recovery_revision(scope, revision_after);
        self.push_trace(PagerAction::SatisfyMapped, token.scope, Some(token.fault));
        Ok(key)
    }

    /// Delivers the unique successful wake/resume for a committed mapping.
    pub fn complete(&mut self, fault: FaultId) -> Result<(), PagerError> {
        self.terminalize_committed(fault, PagerAction::Complete)?;
        Ok(())
    }

    /// Aborts one stale-AS or closing-scope continuation and returns held resources.
    ///
    /// Because the full fault token is checked, an orphan-abort token loses a
    /// race against successful adoption and cannot abort the newly owned fault.
    pub fn abort(&mut self, token: FaultToken) -> Result<(), PagerError> {
        self.validate_fault_token(token)?;
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(PagerError::UnknownScope(token.scope))?;
        let permitted = scope.state == ScopeState::Closing
            || (scope.state == ScopeState::Active
                && token.address_space_generation != scope.address_space_generation);
        if !permitted {
            return Err(PagerError::AbortNotPermitted);
        }
        self.terminalize_uncommitted(token.fault, PagerAction::Abort)?;
        Ok(())
    }

    /// Tears down current mappings and advances the address-space generation.
    ///
    /// Every mapping publisher must first reach `Completed`; mutation is
    /// rejected while a committed continuation still awaits its success wake.
    /// Teardown removes the current PTE abstraction, releases each mapped frame,
    /// and returns its page/pin credit while retaining immutable publication
    /// history for differential checks.
    pub fn advance_address_space_generation(
        &mut self,
        address_space: AddressSpaceId,
    ) -> Result<AddressSpaceGeneration, PagerError> {
        let scope_id = *self
            .address_spaces
            .get(&address_space)
            .ok_or(PagerError::UnknownAddressSpace(address_space))?;
        let scope = self
            .scopes
            .get(&scope_id)
            .ok_or(PagerError::UnknownScope(scope_id))?;
        if scope.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState { state: scope.state });
        }
        let committed = scope
            .live_faults
            .iter()
            .filter(|fault_id| {
                self.faults
                    .get(fault_id)
                    .is_some_and(|fault| fault.state == FaultState::Committed)
            })
            .count();
        if committed != 0 {
            return Err(PagerError::CommittedMappingOutstanding {
                remaining: committed,
            });
        }
        let current_generation = scope.address_space_generation;
        let mappings: Vec<_> = self
            .current_mappings
            .iter()
            .filter(|(key, _)| {
                key.address_space == address_space && key.generation == current_generation
            })
            .map(|(key, mapping)| (*key, *mapping))
            .collect();
        let mut returned_credit = 0u64;
        for (key, mapping) in &mappings {
            let fault = self
                .faults
                .get(&mapping.fault)
                .ok_or(PagerError::UnknownFault(mapping.fault))?;
            if fault.state != FaultState::Completed
                || fault.budget_disposition != BudgetDisposition::Spent
                || fault.mapped_frame != Some(mapping.frame)
                || fault.resolved_mapping != Some(*key)
            {
                return Err(PagerError::InvariantViolation(
                    "current mapping lacks one completed publisher",
                ));
            }
            if self.frames.get(&mapping.frame).map(|frame| frame.state)
                != Some(FrameState::Mapped {
                    key: *key,
                    fault: mapping.fault,
                })
            {
                return Err(PagerError::FrameOwnershipMismatch(mapping.frame));
            }
            if self.publication_history.get(key) != Some(mapping) {
                return Err(PagerError::InvariantViolation(
                    "current mapping lacks publication history",
                ));
            }
            returned_credit = returned_credit
                .checked_add(fault.budget.units())
                .ok_or(PagerError::CounterOverflow)?;
        }
        let generation = AddressSpaceGeneration::new(
            scope
                .address_space_generation
                .get()
                .checked_add(1)
                .ok_or(PagerError::CounterOverflow)?,
        );
        let free_after = scope
            .free_budget
            .units()
            .checked_add(returned_credit)
            .ok_or(PagerError::CounterOverflow)?;
        let spent_after = scope
            .spent_budget
            .units()
            .checked_sub(returned_credit)
            .ok_or(PagerError::InvariantViolation("spent budget underflow"))?;
        let revision_after = Self::next_revision(scope)?;

        for (key, mapping) in mappings {
            self.current_mappings.remove(&key);
            self.frames
                .get_mut(&mapping.frame)
                .ok_or(PagerError::FrameOwnershipMismatch(mapping.frame))?
                .state = FrameState::Released(mapping.fault);
            let fault = self
                .faults
                .get_mut(&mapping.fault)
                .ok_or(PagerError::UnknownFault(mapping.fault))?;
            fault.mapped_frame = None;
            fault.budget_disposition = BudgetDisposition::Returned;
        }
        let scope = self
            .scopes
            .get_mut(&scope_id)
            .ok_or(PagerError::UnknownScope(scope_id))?;
        scope.address_space_generation = generation;
        scope.free_budget = Budget::new(free_after);
        scope.spent_budget = Budget::new(spent_after);
        Self::publish_recovery_revision(scope, revision_after);
        self.push_trace(PagerAction::AdvanceAddressSpaceGeneration, scope_id, None);
        Ok(generation)
    }

    /// Linearizes timeout closure and advances only the authority generation.
    pub fn revoke_begin(&mut self, scope: ScopeId) -> Result<(), PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if record.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState {
                state: record.state,
            });
        }
        let closed_epoch = record.authority_epoch;
        let authority_epoch = AuthorityEpoch::new(
            record
                .authority_epoch
                .get()
                .checked_add(1)
                .ok_or(PagerError::CounterOverflow)?,
        );
        let target_count = record.live_faults.len();
        let revision_after = Self::next_revision(record)?;
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        record.state = ScopeState::Closing;
        record.authority_epoch = authority_epoch;
        record.revocation = Some(RevocationRecord {
            closed_epoch,
            target_count,
            steps: 0,
        });
        record.recovery_deadline_armed = false;
        record.recovery_deadline_completion_pending = false;
        Self::publish_recovery_revision(record, revision_after);
        self.push_trace(PagerAction::RevokeBegin, scope, None);
        Ok(())
    }

    /// Kernel-owned deadline path for a stalled pager recovery cohort.
    ///
    /// It requires no pager or fault token, so adoption cannot fence the
    /// watchdog out. Any still-uncommitted fault enters the same `RevokeBegin`
    /// linearization point used by explicit revocation. If every remaining
    /// fault is already committed or terminal, the scope stays active whether
    /// the pager is present or absent; new registration is gated and trusted
    /// `complete` operations drain the committed-only batch. The pager fallback
    /// independently records service availability because this deadline protects
    /// blocked fault continuations rather than the pager lease.
    pub fn recovery_timeout_begin(
        &mut self,
        scope: ScopeId,
    ) -> Result<RecoveryTimeoutResult, PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if !record.recovery_deadline_armed {
            return Err(PagerError::RecoveryDeadlineUnavailable);
        }
        let uncommitted = record
            .live_faults
            .iter()
            .filter(|fault_id| {
                self.faults.get(fault_id).is_some_and(|fault| {
                    matches!(fault.state, FaultState::Registered | FaultState::Prepared)
                })
            })
            .count();
        if uncommitted == 0 {
            let committed = record.live_faults.len();
            if !record.recovery_deadline_completion_pending {
                self.scopes
                    .get_mut(&scope)
                    .ok_or(PagerError::UnknownScope(scope))?
                    .recovery_deadline_completion_pending = true;
                self.push_trace(PagerAction::DeadlineCompletionPending, scope, None);
            }
            return Ok(RecoveryTimeoutResult::CompletionPending { committed });
        }
        self.revoke_begin(scope)?;
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        record.pager = None;
        record.fallback = PagerFallbackState::Running;
        record.ready = None;
        Ok(RecoveryTimeoutResult::RevocationStarted)
    }

    /// Clears an expired recovery batch after trusted completion terminalized it.
    pub fn deadline_complete(&mut self, scope: ScopeId) -> Result<(), PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if record.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState {
                state: record.state,
            });
        }
        if !record.recovery_deadline_armed
            || !record.recovery_deadline_completion_pending
            || !record.live_faults.is_empty()
        {
            return Err(PagerError::RecoveryDeadlineNotComplete);
        }
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        record.recovery_deadline_armed = false;
        record.recovery_deadline_completion_pending = false;
        self.push_trace(PagerAction::DeadlineComplete, scope, None);
        Ok(())
    }

    /// Visits and terminalizes one fault from the closing scope's reverse index.
    ///
    /// This is kernel-owned work selected by fault identity from the scope's
    /// reverse index.  It deliberately does not require an old or newly adopted
    /// pager token, so adoption cannot fence the recovery watchdog out.
    pub fn revoke_next(
        &mut self,
        scope: ScopeId,
    ) -> Result<Option<PagerRevocationStep>, PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if record.state != ScopeState::Closing {
            return Err(PagerError::InvalidScopeState {
                state: record.state,
            });
        }
        let Some(fault_id) = record.live_faults.first().copied() else {
            return Ok(None);
        };
        let fault = *self
            .faults
            .get(&fault_id)
            .ok_or(PagerError::UnknownFault(fault_id))?;
        let step = match fault.state {
            FaultState::Registered | FaultState::Prepared => {
                let released_frame = fault.prepared_frame;
                let returned_budget = fault.budget;
                self.terminalize_uncommitted(fault_id, PagerAction::RevokeStep)?;
                PagerRevocationStep {
                    fault: fault_id,
                    from: fault.state,
                    to: FaultState::Aborted,
                    released_frame,
                    returned_budget,
                }
            }
            FaultState::Committed => {
                self.terminalize_committed(fault_id, PagerAction::RevokeStep)?;
                PagerRevocationStep {
                    fault: fault_id,
                    from: FaultState::Committed,
                    to: FaultState::Completed,
                    released_frame: None,
                    returned_budget: Budget::ZERO,
                }
            }
            FaultState::Completed | FaultState::Aborted => {
                return Err(PagerError::InvariantViolation(
                    "terminal fault remained in reverse index",
                ));
            }
        };
        let progress = self
            .scopes
            .get_mut(&scope)
            .ok_or(PagerError::UnknownScope(scope))?
            .revocation
            .as_mut()
            .ok_or(PagerError::InvariantViolation(
                "closing scope lacks revocation metadata",
            ))?;
        progress.steps = progress
            .steps
            .checked_add(1)
            .ok_or(PagerError::CounterOverflow)?;
        Ok(Some(step))
    }

    /// Publishes closure only after every indexed fault has terminalized.
    pub fn revoke_complete(&mut self, scope: ScopeId) -> Result<(), PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if record.state != ScopeState::Closing {
            return Err(PagerError::InvalidScopeState {
                state: record.state,
            });
        }
        if !record.live_faults.is_empty() {
            return Err(PagerError::RevocationNotQuiescent {
                remaining: record.live_faults.len(),
            });
        }
        self.scopes
            .get_mut(&scope)
            .ok_or(PagerError::UnknownScope(scope))?
            .state = ScopeState::Revoked;
        self.push_trace(PagerAction::RevokeComplete, scope, None);
        Ok(())
    }

    /// Returns a read-only projection of a pager scope.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<PagerScopeView> {
        self.scopes.get(&scope).map(|record| PagerScopeView {
            state: record.state,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            address_space: record.address_space,
            address_space_generation: record.address_space_generation,
            pager: record.pager,
            fallback: record.fallback,
            initial_budget: record.initial_budget,
            free_budget: record.free_budget,
            spent_budget: record.spent_budget,
            live_faults: record.live_faults.len(),
            recovery_deadline_armed: record.recovery_deadline_armed,
            recovery_deadline_completion_pending: record.recovery_deadline_completion_pending,
            revocation: record.revocation.map(|revocation| PagerRevocationProgress {
                closed_epoch: revocation.closed_epoch,
                target_count: revocation.target_count,
                steps: revocation.steps,
                remaining: record.live_faults.len(),
            }),
        })
    }

    /// Returns a read-only projection of one fault.
    #[must_use]
    pub fn fault(&self, fault: FaultId) -> Option<FaultView> {
        self.faults.get(&fault).map(|record| FaultView {
            token: record.token,
            state: record.state,
            continuation: record.continuation,
            budget: record.budget,
            budget_disposition: record.budget_disposition,
            prepared_frame: record.prepared_frame,
            mapped_frame: record.mapped_frame,
            resolved_mapping: record.resolved_mapping,
            mapping_publications: record.mapping_publications,
            continuation_consumptions: record.continuation_consumptions,
            terminalizations: record.terminalizations,
            wakes: record.wakes,
            resumes: record.resumes,
        })
    }

    /// Returns a read-only projection of one frame identity.
    #[must_use]
    pub fn frame(&self, frame: FrameId) -> Option<FrameView> {
        self.frames.get(&frame).map(|record| FrameView {
            state: record.state,
        })
    }

    /// Returns one mapping currently installed in the PTE abstraction.
    #[must_use]
    pub fn mapping(&self, key: MappingKey) -> Option<MappingView> {
        self.current_mappings.get(&key).map(|record| MappingView {
            frame: record.frame,
            fault: record.fault,
        })
    }

    /// Returns the number of mappings currently installed.
    #[must_use]
    pub fn mapping_count(&self) -> usize {
        self.current_mappings.len()
    }

    /// Returns immutable evidence of one historical mapping publication.
    #[must_use]
    pub fn publication(&self, key: MappingKey) -> Option<MappingView> {
        self.publication_history
            .get(&key)
            .map(|record| MappingView {
                frame: record.frame,
                fault: record.fault,
            })
    }

    /// Returns the number of unique historical mapping publications.
    #[must_use]
    pub fn publication_count(&self) -> usize {
        self.publication_history.len()
    }

    /// Returns the deterministic contents of one scope's live reverse index.
    pub fn live_faults(&self, scope: ScopeId) -> Result<Vec<FaultId>, PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        Ok(record.live_faults.iter().copied().collect())
    }

    /// Returns successful operations in total linearization order.
    #[must_use]
    pub fn trace(&self) -> &[PagerTraceEvent] {
        &self.trace
    }

    /// Audits fencing, one-shot continuation, frame, mapping, budget, and work invariants.
    pub fn check_invariants(&self) -> Result<(), PagerInvariantViolation> {
        for (scope_id, scope) in &self.scopes {
            let mut expected_live = BTreeSet::new();
            let mut held = 0u128;
            let mut spent = 0u128;

            for (fault_id, fault) in self
                .faults
                .iter()
                .filter(|(_, fault)| fault.token.scope == *scope_id)
            {
                if fault.token.address_space != scope.address_space {
                    return Err(PagerInvariantViolation::OrphanFault(*fault_id));
                }
                if fault.token.authority_epoch > scope.authority_epoch
                    || fault.token.binding_epoch > scope.binding_epoch
                    || fault.token.address_space_generation > scope.address_space_generation
                {
                    return Err(PagerInvariantViolation::FutureGeneration(*fault_id));
                }
                if !fault.state.is_terminal() {
                    expected_live.insert(*fault_id);
                }
                let expected_disposition = match fault.state {
                    FaultState::Registered | FaultState::Prepared => BudgetDisposition::Held,
                    FaultState::Committed => BudgetDisposition::Spent,
                    FaultState::Completed if fault.mapped_frame.is_some() => {
                        BudgetDisposition::Spent
                    }
                    FaultState::Completed => BudgetDisposition::Returned,
                    FaultState::Aborted => BudgetDisposition::Returned,
                };
                if fault.budget_disposition != expected_disposition {
                    return Err(PagerInvariantViolation::FaultBudgetState(*fault_id));
                }
                match fault.budget_disposition {
                    BudgetDisposition::Held => held += u128::from(fault.budget.units()),
                    BudgetDisposition::Spent => spent += u128::from(fault.budget.units()),
                    BudgetDisposition::Returned => {}
                }
                self.check_fault_invariants(*fault_id, fault)?;
            }

            if expected_live != scope.live_faults {
                return Err(PagerInvariantViolation::LiveReverseIndex(*scope_id));
            }
            if u128::from(scope.spent_budget.units()) != spent {
                return Err(PagerInvariantViolation::SpentAccounting(*scope_id));
            }
            let accounted = u128::from(scope.free_budget.units()) + held + spent;
            if accounted != u128::from(scope.initial_budget.units()) {
                return Err(PagerInvariantViolation::BudgetConservation(*scope_id));
            }
            match scope.state {
                ScopeState::Active if scope.revocation.is_some() => {
                    return Err(PagerInvariantViolation::RevocationMetadata(*scope_id));
                }
                ScopeState::Closing | ScopeState::Revoked if scope.revocation.is_none() => {
                    return Err(PagerInvariantViolation::RevocationMetadata(*scope_id));
                }
                _ => {}
            }
            if scope.state == ScopeState::Revoked && !scope.live_faults.is_empty() {
                return Err(PagerInvariantViolation::RevokedScopeLive(*scope_id));
            }
            if let Some(revocation) = scope.revocation
                && revocation.steps > revocation.target_count
            {
                return Err(PagerInvariantViolation::RevocationWorkBound(*scope_id));
            }
            let fallback_valid = match (scope.pager, scope.fallback, scope.ready) {
                (Some(_), PagerFallbackState::Standby, None) => true,
                (None, PagerFallbackState::Required | PagerFallbackState::Running, None) => true,
                (None, PagerFallbackState::ReplacementReady, Some(ready)) => {
                    ready.authority_epoch == scope.authority_epoch
                        && ready.binding_epoch == scope.binding_epoch
                        && ready.address_space_generation == scope.address_space_generation
                        && ready.recovery_revision == scope.recovery_revision
                }
                _ => false,
            };
            if !fallback_valid {
                return Err(PagerInvariantViolation::FallbackState(*scope_id));
            }
            let deadline_valid = match scope.state {
                ScopeState::Active => match (
                    scope.live_faults.is_empty(),
                    scope.recovery_deadline_armed,
                    scope.recovery_deadline_completion_pending,
                ) {
                    (true, false, false) | (true, true, true) => true,
                    (false, true, false) => true,
                    (false, true, true) => scope.live_faults.iter().all(|fault_id| {
                        self.faults
                            .get(fault_id)
                            .is_some_and(|fault| fault.state == FaultState::Committed)
                    }),
                    _ => false,
                },
                ScopeState::Closing | ScopeState::Revoked => {
                    !scope.recovery_deadline_armed && !scope.recovery_deadline_completion_pending
                }
            };
            if !deadline_valid {
                return Err(PagerInvariantViolation::RecoveryDeadlineState(*scope_id));
            }
            if self.address_spaces.get(&scope.address_space) != Some(scope_id) {
                return Err(PagerInvariantViolation::AddressSpaceIndex(
                    scope.address_space,
                ));
            }
        }

        for (address_space, scope_id) in &self.address_spaces {
            let Some(scope) = self.scopes.get(scope_id) else {
                return Err(PagerInvariantViolation::AddressSpaceIndex(*address_space));
            };
            if scope.address_space != *address_space {
                return Err(PagerInvariantViolation::AddressSpaceIndex(*address_space));
            }
        }
        for (fault_id, fault) in &self.faults {
            if !self.scopes.contains_key(&fault.token.scope) {
                return Err(PagerInvariantViolation::OrphanFault(*fault_id));
            }
        }
        for (frame_id, frame) in &self.frames {
            match frame.state {
                FrameState::Prepared(fault_id) => {
                    let Some(fault) = self.faults.get(&fault_id) else {
                        return Err(PagerInvariantViolation::OrphanFrame(*frame_id));
                    };
                    if fault.state != FaultState::Prepared
                        || fault.prepared_frame != Some(*frame_id)
                    {
                        return Err(PagerInvariantViolation::OrphanFrame(*frame_id));
                    }
                }
                FrameState::Mapped { key, fault } => {
                    let Some(mapping) = self.current_mappings.get(&key) else {
                        return Err(PagerInvariantViolation::OrphanFrame(*frame_id));
                    };
                    if mapping.frame != *frame_id || mapping.fault != fault {
                        return Err(PagerInvariantViolation::OrphanFrame(*frame_id));
                    }
                }
                FrameState::Released(fault_id) => {
                    let Some(fault) = self.faults.get(&fault_id) else {
                        return Err(PagerInvariantViolation::OrphanFrame(*frame_id));
                    };
                    if !fault.state.is_terminal()
                        || fault.prepared_frame.is_some()
                        || fault.mapped_frame.is_some()
                        || fault.budget_disposition != BudgetDisposition::Returned
                    {
                        return Err(PagerInvariantViolation::OrphanFrame(*frame_id));
                    }
                }
            }
        }
        for (key, mapping) in &self.current_mappings {
            let Some(fault) = self.faults.get(&mapping.fault) else {
                return Err(PagerInvariantViolation::MappingOwnership(*key));
            };
            let current_generation_matches = self
                .address_spaces
                .get(&key.address_space)
                .and_then(|scope| self.scopes.get(scope))
                .is_some_and(|scope| scope.address_space_generation == key.generation);
            if !matches!(fault.state, FaultState::Committed | FaultState::Completed)
                || !current_generation_matches
                || fault.mapped_frame != Some(mapping.frame)
                || fault.resolved_mapping != Some(*key)
                || fault.mapping_publications != 1
                || fault.budget_disposition != BudgetDisposition::Spent
                || fault.token.address_space != key.address_space
                || fault.token.address_space_generation != key.generation
                || fault.token.page != key.page
                || self.publication_history.get(key) != Some(mapping)
            {
                return Err(PagerInvariantViolation::MappingOwnership(*key));
            }
        }
        for (key, publication) in &self.publication_history {
            let Some(fault) = self.faults.get(&publication.fault) else {
                return Err(PagerInvariantViolation::MappingOwnership(*key));
            };
            let identity_matches = fault.mapping_publications == 1
                && fault.resolved_mapping == Some(*key)
                && fault.token.address_space == key.address_space
                && fault.token.address_space_generation == key.generation
                && fault.token.page == key.page;
            let ownership_matches = match self.current_mappings.get(key) {
                Some(current) => {
                    current == publication
                        && fault.mapped_frame == Some(publication.frame)
                        && fault.budget_disposition == BudgetDisposition::Spent
                        && self.frames.get(&publication.frame).map(|frame| frame.state)
                            == Some(FrameState::Mapped {
                                key: *key,
                                fault: publication.fault,
                            })
                }
                None => {
                    let generation_is_historical = self
                        .address_spaces
                        .get(&key.address_space)
                        .and_then(|scope| self.scopes.get(scope))
                        .is_some_and(|scope| scope.address_space_generation > key.generation);
                    fault.state == FaultState::Completed
                        && generation_is_historical
                        && fault.mapped_frame.is_none()
                        && fault.budget_disposition == BudgetDisposition::Returned
                        && self.frames.get(&publication.frame).map(|frame| frame.state)
                            == Some(FrameState::Released(publication.fault))
                }
            };
            if !identity_matches || !ownership_matches {
                return Err(PagerInvariantViolation::MappingOwnership(*key));
            }
        }
        Ok(())
    }

    fn check_fault_invariants(
        &self,
        fault_id: FaultId,
        fault: &FaultRecord,
    ) -> Result<(), PagerInvariantViolation> {
        let terminal = u8::from(fault.state.is_terminal());
        if fault.terminalizations != terminal {
            return Err(PagerInvariantViolation::Terminalization(fault_id));
        }
        let expected_continuation = match fault.state {
            FaultState::Registered | FaultState::Prepared => (ContinuationState::Pending, 0),
            FaultState::Committed | FaultState::Completed => (ContinuationState::Resolved, 1),
            FaultState::Aborted => (ContinuationState::Aborted, 1),
        };
        if (fault.continuation, fault.continuation_consumptions) != expected_continuation {
            return Err(PagerInvariantViolation::ContinuationConsumption(fault_id));
        }
        let expected_wake_resume = match fault.state {
            FaultState::Registered | FaultState::Prepared | FaultState::Committed => (0, 0),
            FaultState::Completed => (1, 1),
            FaultState::Aborted => (1, 0),
        };
        if (fault.wakes, fault.resumes) != expected_wake_resume {
            return Err(PagerInvariantViolation::WakeResume(fault_id));
        }
        let shape_valid = match fault.state {
            FaultState::Registered => {
                fault.mapping_publications == 0
                    && fault.resolved_mapping.is_none()
                    && fault.prepared_frame.is_none()
                    && fault.mapped_frame.is_none()
            }
            FaultState::Prepared => {
                fault.mapping_publications == 0
                    && fault.resolved_mapping.is_none()
                    && fault.prepared_frame.is_some()
                    && fault.mapped_frame.is_none()
            }
            FaultState::Committed => {
                fault.mapping_publications == 1
                    && fault.resolved_mapping.is_some()
                    && fault.prepared_frame.is_none()
                    && fault.mapped_frame.is_some()
            }
            FaultState::Completed => {
                fault.mapping_publications <= 1
                    && fault.resolved_mapping.is_some()
                    && fault.prepared_frame.is_none()
                    && (fault.mapping_publications == 1 || fault.mapped_frame.is_none())
            }
            FaultState::Aborted => {
                fault.mapping_publications == 0
                    && fault.resolved_mapping.is_none()
                    && fault.prepared_frame.is_none()
                    && fault.mapped_frame.is_none()
            }
        };
        if !shape_valid {
            return Err(PagerInvariantViolation::MappingPublication(fault_id));
        }
        if let Some(frame) = fault.prepared_frame
            && self.frames.get(&frame).map(|record| record.state)
                != Some(FrameState::Prepared(fault_id))
        {
            return Err(PagerInvariantViolation::FrameOwnership(fault_id));
        }
        if let Some(key) = fault.resolved_mapping
            && (key.address_space != fault.token.address_space
                || key.generation != fault.token.address_space_generation
                || key.page != fault.token.page
                || !self.publication_history.contains_key(&key))
        {
            return Err(PagerInvariantViolation::MappingPublication(fault_id));
        }
        if let Some(frame) = fault.mapped_frame {
            let Some(key) = fault.resolved_mapping else {
                return Err(PagerInvariantViolation::FrameOwnership(fault_id));
            };
            if self.current_mappings.get(&key)
                != Some(&MappingRecord {
                    frame,
                    fault: fault_id,
                })
                || self.frames.get(&frame).map(|record| record.state)
                    != Some(FrameState::Mapped {
                        key,
                        fault: fault_id,
                    })
            {
                return Err(PagerInvariantViolation::FrameOwnership(fault_id));
            }
        }
        Ok(())
    }

    fn validate_binding(
        &self,
        binding: PagerBindingToken,
    ) -> Result<&PagerScopeRecord, PagerError> {
        let scope = self
            .scopes
            .get(&binding.scope)
            .ok_or(PagerError::UnknownScope(binding.scope))?;
        if binding.address_space != scope.address_space {
            return Err(PagerError::AddressSpaceMismatch);
        }
        if binding.authority_epoch != scope.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: binding.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if binding.binding_epoch != scope.binding_epoch {
            return Err(PagerError::StaleBinding {
                presented: binding.binding_epoch,
                current: scope.binding_epoch,
            });
        }
        match scope.pager {
            Some(pager) if pager == binding.pager => {}
            Some(_) => return Err(PagerError::WrongPager),
            None => return Err(PagerError::PagerUnavailable),
        }
        if scope.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState { state: scope.state });
        }
        Ok(scope)
    }

    fn validate_fault_token(&self, token: FaultToken) -> Result<&FaultRecord, PagerError> {
        let fault = self
            .faults
            .get(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?;
        if token.scope != fault.token.scope {
            return Err(PagerError::ScopeMismatch);
        }
        if token.address_space != fault.token.address_space
            || token.thread != fault.token.thread
            || token.page != fault.token.page
            || token.access != fault.token.access
        {
            return Err(PagerError::FaultIdentityMismatch);
        }
        if token.authority_epoch != fault.token.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: token.authority_epoch,
                current: fault.token.authority_epoch,
            });
        }
        if token.binding_epoch != fault.token.binding_epoch {
            return Err(PagerError::FaultBindingFenced {
                fault_binding: token.binding_epoch,
                current_binding: fault.token.binding_epoch,
            });
        }
        if token.address_space_generation != fault.token.address_space_generation {
            return Err(PagerError::StaleAddressSpaceGeneration {
                presented: token.address_space_generation,
                current: fault.token.address_space_generation,
            });
        }
        Ok(fault)
    }

    fn validate_current_fault_reply(
        &self,
        binding: PagerBindingToken,
        token: FaultToken,
    ) -> Result<(), PagerError> {
        let scope = self.validate_binding(binding)?;
        let fault = self.validate_fault_token(token)?;
        if token.scope != binding.scope {
            return Err(PagerError::ScopeMismatch);
        }
        if token.address_space != binding.address_space {
            return Err(PagerError::AddressSpaceMismatch);
        }
        if fault.token.authority_epoch != scope.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: fault.token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if fault.token.binding_epoch != scope.binding_epoch {
            return Err(PagerError::FaultBindingFenced {
                fault_binding: fault.token.binding_epoch,
                current_binding: scope.binding_epoch,
            });
        }
        if fault.token.address_space_generation != scope.address_space_generation {
            return Err(PagerError::StaleAddressSpaceGeneration {
                presented: fault.token.address_space_generation,
                current: scope.address_space_generation,
            });
        }
        Ok(())
    }

    fn validate_snapshot(
        &self,
        scope: &PagerScopeRecord,
        snapshot: &RecoverySnapshot,
    ) -> Result<(), PagerError> {
        if snapshot.address_space != scope.address_space {
            return Err(PagerError::AddressSpaceMismatch);
        }
        if snapshot.authority_epoch != scope.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: snapshot.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if snapshot.binding_epoch != scope.binding_epoch {
            return Err(PagerError::StaleBinding {
                presented: snapshot.binding_epoch,
                current: scope.binding_epoch,
            });
        }
        if snapshot.address_space_generation != scope.address_space_generation {
            return Err(PagerError::StaleAddressSpaceGeneration {
                presented: snapshot.address_space_generation,
                current: scope.address_space_generation,
            });
        }
        if snapshot.recovery_revision != scope.recovery_revision {
            return Err(PagerError::StaleRecoverySnapshot);
        }
        Ok(())
    }

    fn validate_ready(
        &self,
        scope: &PagerScopeRecord,
        ready: PagerReadyToken,
    ) -> Result<(), PagerError> {
        if ready.address_space != scope.address_space {
            return Err(PagerError::AddressSpaceMismatch);
        }
        if ready.authority_epoch != scope.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: ready.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if ready.binding_epoch != scope.binding_epoch {
            return Err(PagerError::StaleBinding {
                presented: ready.binding_epoch,
                current: scope.binding_epoch,
            });
        }
        if ready.address_space_generation != scope.address_space_generation {
            return Err(PagerError::StaleAddressSpaceGeneration {
                presented: ready.address_space_generation,
                current: scope.address_space_generation,
            });
        }
        if ready.recovery_revision != scope.recovery_revision {
            return Err(PagerError::StaleRecoverySnapshot);
        }
        let Some(record) = scope.ready else {
            return Err(PagerError::FallbackUnavailable);
        };
        if record.pager != ready.pager
            || record.authority_epoch != ready.authority_epoch
            || record.binding_epoch != ready.binding_epoch
            || record.address_space_generation != ready.address_space_generation
            || record.recovery_revision != ready.recovery_revision
        {
            return Err(PagerError::StaleRecoverySnapshot);
        }
        Ok(())
    }

    fn terminalize_uncommitted(
        &mut self,
        fault_id: FaultId,
        action: PagerAction,
    ) -> Result<(), PagerError> {
        let fault = *self
            .faults
            .get(&fault_id)
            .ok_or(PagerError::UnknownFault(fault_id))?;
        if fault.state.is_terminal() {
            return Err(PagerError::AlreadyTerminal);
        }
        if !matches!(fault.state, FaultState::Registered | FaultState::Prepared) {
            return Err(if fault.continuation != ContinuationState::Pending {
                PagerError::ContinuationAlreadyConsumed
            } else {
                PagerError::InvalidFaultState { state: fault.state }
            });
        }
        if fault.continuation != ContinuationState::Pending
            || fault.budget_disposition != BudgetDisposition::Held
        {
            return Err(PagerError::InvariantViolation(
                "uncommitted fault lacks pending continuation or held budget",
            ));
        }
        if let Some(frame) = fault.prepared_frame
            && self.frames.get(&frame).map(|record| record.state)
                != Some(FrameState::Prepared(fault_id))
        {
            return Err(PagerError::FrameOwnershipMismatch(frame));
        }
        let scope = self
            .scopes
            .get(&fault.token.scope)
            .ok_or(PagerError::UnknownScope(fault.token.scope))?;
        let free_after = scope
            .free_budget
            .units()
            .checked_add(fault.budget.units())
            .ok_or(PagerError::CounterOverflow)?;
        let revision_after = Self::next_revision(scope)?;

        let fault_record = self
            .faults
            .get_mut(&fault_id)
            .ok_or(PagerError::UnknownFault(fault_id))?;
        fault_record.state = FaultState::Aborted;
        fault_record.continuation = ContinuationState::Aborted;
        fault_record.budget_disposition = BudgetDisposition::Returned;
        fault_record.prepared_frame = None;
        fault_record.continuation_consumptions = 1;
        fault_record.terminalizations = 1;
        fault_record.wakes = 1;
        if let Some(frame) = fault.prepared_frame {
            self.frames
                .get_mut(&frame)
                .ok_or(PagerError::FrameOwnershipMismatch(frame))?
                .state = FrameState::Released(fault_id);
        }
        let scope = self
            .scopes
            .get_mut(&fault.token.scope)
            .ok_or(PagerError::UnknownScope(fault.token.scope))?;
        scope.free_budget = Budget::new(free_after);
        scope.live_faults.remove(&fault_id);
        if scope.state == ScopeState::Active
            && scope.live_faults.is_empty()
            && !scope.recovery_deadline_completion_pending
        {
            scope.recovery_deadline_armed = false;
        }
        Self::publish_recovery_revision(scope, revision_after);
        self.push_trace(action, fault.token.scope, Some(fault_id));
        Ok(())
    }

    fn terminalize_committed(
        &mut self,
        fault_id: FaultId,
        action: PagerAction,
    ) -> Result<(), PagerError> {
        let fault = *self
            .faults
            .get(&fault_id)
            .ok_or(PagerError::UnknownFault(fault_id))?;
        if fault.state.is_terminal() {
            return Err(PagerError::AlreadyTerminal);
        }
        if fault.state != FaultState::Committed {
            return Err(PagerError::InvalidFaultState { state: fault.state });
        }
        if fault.continuation != ContinuationState::Resolved
            || fault.continuation_consumptions != 1
            || fault.mapping_publications != 1
            || fault.mapped_frame.is_none()
            || fault.resolved_mapping.is_none()
        {
            return Err(PagerError::InvariantViolation(
                "committed fault lacks resolved mapping state",
            ));
        }
        let key = fault
            .resolved_mapping
            .ok_or(PagerError::InvariantViolation(
                "committed fault lacks mapping identity",
            ))?;
        let frame = fault.mapped_frame.ok_or(PagerError::InvariantViolation(
            "committed fault lacks mapped frame",
        ))?;
        if self.current_mappings.get(&key)
            != Some(&MappingRecord {
                frame,
                fault: fault_id,
            })
        {
            return Err(PagerError::InvariantViolation(
                "committed fault mapping is not current",
            ));
        }
        let scope = self
            .scopes
            .get(&fault.token.scope)
            .ok_or(PagerError::UnknownScope(fault.token.scope))?;
        let revision_after = Self::next_revision(scope)?;
        let fault_record = self
            .faults
            .get_mut(&fault_id)
            .ok_or(PagerError::UnknownFault(fault_id))?;
        fault_record.state = FaultState::Completed;
        fault_record.terminalizations = 1;
        fault_record.wakes = 1;
        fault_record.resumes = 1;
        let scope = self
            .scopes
            .get_mut(&fault.token.scope)
            .ok_or(PagerError::UnknownScope(fault.token.scope))?;
        scope.live_faults.remove(&fault_id);
        if scope.state == ScopeState::Active
            && scope.live_faults.is_empty()
            && !scope.recovery_deadline_completion_pending
        {
            scope.recovery_deadline_armed = false;
        }
        Self::publish_recovery_revision(scope, revision_after);
        self.push_trace(action, fault.token.scope, Some(fault_id));
        Ok(())
    }

    fn next_revision(scope: &PagerScopeRecord) -> Result<u64, PagerError> {
        scope
            .recovery_revision
            .checked_add(1)
            .ok_or(PagerError::CounterOverflow)
    }

    fn publish_recovery_revision(scope: &mut PagerScopeRecord, revision: u64) {
        scope.recovery_revision = revision;
        if scope.fallback == PagerFallbackState::ReplacementReady {
            scope.fallback = PagerFallbackState::Running;
            scope.ready = None;
        }
    }

    fn push_trace(&mut self, action: PagerAction, scope: ScopeId, fault: Option<FaultId>) {
        let record = self
            .scopes
            .get(&scope)
            .expect("trace requires an existing pager scope");
        self.trace.push(PagerTraceEvent {
            seq: self.trace.len(),
            action,
            scope,
            fault,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            address_space_generation: record.address_space_generation,
        });
    }
}
