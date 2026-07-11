//! Executable reference model for crash-recoverable Linux syscall dispatch.
//!
//! This module fixes the binding and one-shot continuation contract between a
//! trapped Linux task, the kernel, and a restartable user-space personality.
//! A modeled `write` separates publication of one kernel-owned backend output
//! obligation from the later guest reply, so a personality may crash between
//! those points without duplicating output. `write` and `exit_group` remain
//! operation labels only: the model deliberately contains no Linux ABI
//! decoding, file-descriptor state, I/O implementation, or process-group
//! semantics.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{ScopeId, ScopeState};

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
    /// Authority generation closed by `PersonalityModel::revoke_begin`.
    AuthorityEpoch
);
scalar_type!(
    /// Personality binding generation advanced only by `PersonalityModel::crash`.
    BindingEpoch
);
scalar_type!(
    /// Stable identity of one Linux personality service instance.
    PersonalityId
);
scalar_type!(
    /// Stable identity of one trapped Linux task.
    TaskId
);
scalar_type!(
    /// Stable identity of one captured syscall and its continuation.
    SyscallId
);

/// Linux operations covered by the bounded Stage 6A model.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SyscallOperation {
    /// A `write` trap that may eventually return to the calling task.
    Write,
    /// An `exit_group` trap that requests task-group termination.
    ExitGroup,
}

/// Prepared personality reply, represented only by its semantic label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedReply {
    /// The modeled `write` operation has a return reply ready.
    WriteReturned,
    /// The modeled `exit_group` operation has a termination request ready.
    ExitGroupRequested,
}

impl PreparedReply {
    const fn matches(self, operation: SyscallOperation) -> bool {
        matches!(
            (self, operation),
            (Self::WriteReturned, SyscallOperation::Write)
                | (Self::ExitGroupRequested, SyscallOperation::ExitGroup)
        )
    }
}

/// Lifecycle of one captured syscall effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallState {
    /// The trap is captured and no reply has been prepared.
    Captured,
    /// A reply is retained by the kernel but has not reached task state.
    ReplyPrepared,
    /// One `write` backend output obligation committed, but no guest reply did.
    BackendCommitted,
    /// The reply was published and the continuation completed successfully.
    Completed,
    /// Kernel closure consumed the continuation with terminal failure.
    Aborted,
}

impl SyscallState {
    /// Returns whether no later syscall-state transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

/// Consumption state of a one-shot syscall continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallContinuationState {
    /// No reply or abort has consumed the continuation.
    Pending,
    /// A validated reply or kernel closure drain consumed the continuation.
    Replied,
    /// Kernel revocation consumed the continuation with failure.
    Aborted,
}

/// Kernel-visible terminal delivery for one syscall continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallDelivery {
    /// The blocked `write` caller may resume through one return delivery.
    WriteReturned,
    /// One `exit_group` termination request was delivered; no user return occurs.
    ExitGroupRequested,
    /// Recovery failed and the blocked task received one terminal abort.
    Aborted,
}

/// Full identity of one syscall reply authority.
///
/// A production kernel must expose an authenticated, non-forgeable handle.
/// Direct fields make the independent fences inspectable in this reference
/// model and allow deliberate stale-message tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallToken {
    scope: ScopeId,
    syscall: SyscallId,
    task: TaskId,
    operation: SyscallOperation,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
}

impl SyscallToken {
    /// Returns the inherited authority scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the one-shot syscall identity.
    #[must_use]
    pub const fn syscall(self) -> SyscallId {
        self.syscall
    }

    /// Returns the blocked task identity.
    #[must_use]
    pub const fn task(self) -> TaskId {
        self.task
    }

    /// Returns the captured operation label.
    #[must_use]
    pub const fn operation(self) -> SyscallOperation {
        self.operation
    }

    /// Returns the authority generation captured at trap registration.
    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the personality binding generation owning the continuation.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.binding_epoch
    }
}

/// Opaque proof of the personality currently bound to an active scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonalityBindingToken {
    scope: ScopeId,
    personality: PersonalityId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
}

impl PersonalityBindingToken {
    /// Returns the bound authority scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the bound personality identity.
    #[must_use]
    pub const fn personality(self) -> PersonalityId {
        self.personality
    }

    /// Returns the authority generation captured by this binding.
    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the personality binding generation captured by this binding.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.binding_epoch
    }
}

/// Kernel fallback and replacement-handshake lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersonalityFallbackState {
    /// A live user-space personality is bound.
    Standby,
    /// A crash was fenced and kernel fallback selection is required.
    Required,
    /// Kernel fallback is active and may issue a recovery snapshot.
    Running,
    /// A replacement accepted a fresh snapshot and declared readiness.
    ReplacementReady,
    /// Authority closure permanently disabled replacement binding.
    Closed,
}

/// One captured continuation included in a recovery snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallSnapshot {
    /// Reply identity current when the snapshot was created.
    pub token: SyscallToken,
    /// Captured, prepared, or backend-committed state in the snapshot.
    pub state: SyscallState,
    /// Prepared reply retained across crash, if one exists.
    pub prepared_reply: Option<PreparedReply>,
}

/// Immutable orphan set presented to one prospective replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalityRecoverySnapshot {
    scope: ScopeId,
    personality: PersonalityId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    recovery_revision: u64,
    syscalls: Vec<SyscallSnapshot>,
}

impl PersonalityRecoverySnapshot {
    /// Returns the represented authority scope.
    #[must_use]
    pub const fn scope(&self) -> ScopeId {
        self.scope
    }

    /// Returns the replacement identity for which this snapshot was issued.
    #[must_use]
    pub const fn personality(&self) -> PersonalityId {
        self.personality
    }

    /// Returns the authority generation represented by the snapshot.
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the post-crash binding generation represented by the snapshot.
    #[must_use]
    pub const fn binding_epoch(&self) -> BindingEpoch {
        self.binding_epoch
    }

    /// Returns the deterministic live-continuation entries.
    #[must_use]
    pub fn syscalls(&self) -> &[SyscallSnapshot] {
        &self.syscalls
    }
}

/// Opaque proof that one replacement accepted a still-fresh snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonalityReadyToken {
    scope: ScopeId,
    personality: PersonalityId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    recovery_revision: u64,
}

impl PersonalityReadyToken {
    /// Returns the replacement that declared readiness.
    #[must_use]
    pub const fn personality(self) -> PersonalityId {
        self.personality
    }

    /// Returns the binding generation in which readiness was declared.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.binding_epoch
    }
}

/// Read-only projection of one syscall continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallView {
    /// Immutable identity, updated only by explicit adoption.
    pub token: SyscallToken,
    /// Effect lifecycle state.
    pub state: SyscallState,
    /// One-shot continuation consumption state.
    pub continuation: SyscallContinuationState,
    /// Reply prepared before successful publication, if any.
    pub prepared_reply: Option<PreparedReply>,
    /// Number of kernel-owned `write` backend obligations committed.
    pub backend_commits: u8,
    /// Unique terminal delivery, if the continuation was consumed.
    pub delivery: Option<SyscallDelivery>,
    /// Number of successful reply publications.
    pub reply_publications: u8,
    /// Number of continuation consumptions.
    pub continuation_consumptions: u8,
    /// Number of terminal effect transitions.
    pub terminalizations: u8,
    /// Number of successful `write` returns delivered to user state.
    pub resumes: u8,
    /// Number of `exit_group` termination requests delivered.
    pub exits: u8,
    /// Number of terminal recovery failures delivered.
    pub aborts: u8,
}

/// Bounded closure progress for one personality scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonalityRevocationProgress {
    /// Authority generation closed by `revoke_begin`.
    pub closed_epoch: AuthorityEpoch,
    /// Continuations in the scope-local reverse index at closure.
    pub target_count: usize,
    /// Continuations terminalized by `revoke_next`.
    pub steps: usize,
    /// Continuations still live in the reverse index.
    pub remaining: usize,
}

/// Read-only projection of one Linux personality scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonalityScopeView {
    /// Scope lifecycle state.
    pub state: ScopeState,
    /// Current authority generation.
    pub authority_epoch: AuthorityEpoch,
    /// Current personality binding generation.
    pub binding_epoch: BindingEpoch,
    /// Currently bound personality, if any.
    pub personality: Option<PersonalityId>,
    /// Kernel fallback and replacement state.
    pub fallback: PersonalityFallbackState,
    /// Number of nonterminal syscall continuations.
    pub live_syscalls: usize,
    /// Closure progress after revocation begins.
    pub revocation: Option<PersonalityRevocationProgress>,
}

/// One successful syscall closure step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonalityRevocationStep {
    /// Continuation selected through the target scope's reverse index.
    pub syscall: SyscallId,
    /// State before kernel closure terminalizes the continuation.
    pub from: SyscallState,
    /// Terminal state after aborting uncommitted work or draining a commitment.
    pub to: SyscallState,
}

/// Stable action vocabulary for deterministic protocol traces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersonalityAction {
    /// Create an active scope and initial personality binding.
    CreateScope,
    /// Capture a Linux syscall and block its task behind one continuation.
    Capture,
    /// Retain a type-matching reply without mutating task state.
    PrepareReply,
    /// Publish the unique kernel-owned backend obligation for one `write`.
    BackendCommit,
    /// Fence a failed personality by advancing the binding generation.
    Crash,
    /// Select the kernel fallback.
    FallbackPick,
    /// Accept readiness from a fresh recovery snapshot.
    Ready,
    /// Bind the ready replacement without advancing the generation again.
    Rebind,
    /// Explicitly transfer one orphan continuation to the replacement.
    Adopt,
    /// Atomically publish one reply and consume its continuation.
    Reply,
    /// Close the authority generation and the reply gate.
    RevokeBegin,
    /// Terminalize one continuation through the scope-local reverse index.
    RevokeStep,
    /// Publish quiescent closure after all continuations terminalize.
    RevokeComplete,
}

/// One successful operation in the model's total linearization order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonalityTraceEvent {
    /// Zero-based total-order position.
    pub seq: usize,
    /// Operation that linearized.
    pub action: PersonalityAction,
    /// Scope affected by the operation.
    pub scope: ScopeId,
    /// Syscall affected by the operation, when applicable.
    pub syscall: Option<SyscallId>,
    /// Authority generation immediately after the operation.
    pub authority_epoch: AuthorityEpoch,
    /// Binding generation immediately after the operation.
    pub binding_epoch: BindingEpoch,
}

/// Rejected personality-model operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersonalityError {
    /// The requested scope does not exist.
    UnknownScope(ScopeId),
    /// The requested syscall does not exist.
    UnknownSyscall(SyscallId),
    /// The scope is not in the state required by the operation.
    InvalidScopeState {
        /// Actual scope state.
        state: ScopeState,
    },
    /// The syscall is not in the state required by the operation.
    InvalidSyscallState {
        /// Actual syscall state.
        state: SyscallState,
    },
    /// An operation mixed objects from different scopes.
    ScopeMismatch,
    /// The authority generation was closed by revocation.
    StaleAuthority {
        /// Generation carried by the operation.
        presented: AuthorityEpoch,
        /// Generation currently required by the scope.
        current: AuthorityEpoch,
    },
    /// A former personality binding attempted to act after crash fencing.
    StaleBinding {
        /// Generation carried by the operation.
        presented: BindingEpoch,
        /// Generation currently required by the scope.
        current: BindingEpoch,
    },
    /// The continuation still belongs to a former binding.
    SyscallBindingFenced {
        /// Generation carried by the recorded continuation.
        syscall_binding: BindingEpoch,
        /// Generation required by the current binding.
        current_binding: BindingEpoch,
    },
    /// The binding token names a service other than the installed personality.
    WrongPersonality,
    /// No user-space personality is currently installed.
    PersonalityUnavailable,
    /// A live user-space personality is already installed.
    PersonalityAlreadyBound,
    /// Kernel fallback is not at the stage required by the operation.
    FallbackUnavailable,
    /// Snapshot contents or recovery revision changed before readiness/rebind.
    StaleRecoverySnapshot,
    /// The presented token does not match the recorded continuation identity.
    SyscallIdentityMismatch,
    /// The continuation is not an orphan eligible for explicit adoption.
    NotAdoptable,
    /// A prepared reply does not match the captured syscall label.
    ReplyOperationMismatch,
    /// A backend output commit was requested for a non-`write` operation.
    BackendCommitNotApplicable,
    /// The unique backend output obligation was already committed.
    BackendAlreadyCommitted,
    /// The task already owns another nonterminal syscall continuation.
    TaskAlreadyBlocked {
        /// Existing continuation blocking the task.
        syscall: SyscallId,
    },
    /// The one-shot continuation was already consumed.
    ContinuationAlreadyConsumed,
    /// The syscall already reached a terminal state.
    AlreadyTerminal,
    /// Closure was acknowledged while continuations remained live.
    RevocationNotQuiescent {
        /// Continuations remaining in the scope-local reverse index.
        remaining: usize,
    },
    /// A monotonically increasing identifier, generation, or counter overflowed.
    CounterOverflow,
    /// Internal state relationships were inconsistent.
    InvariantViolation(&'static str),
}

/// Failure reported by a complete personality-model invariant audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersonalityInvariantViolation {
    /// A scope reverse index differs from its nonterminal continuation set.
    LiveReverseIndex(ScopeId),
    /// Blocked-task ownership differs from nonterminal continuation ownership.
    BlockedTaskIndex(SyscallId),
    /// A continuation refers to a missing scope or future generation.
    OrphanOrFutureSyscall(SyscallId),
    /// State, prepared reply, and reply publication disagree.
    ReplyState(SyscallId),
    /// Backend commitment state or its at-most-once counter disagrees.
    BackendCommit(SyscallId),
    /// Continuation consumption or unique terminalization disagrees with state.
    Terminalization(SyscallId),
    /// Successful return, exit, or abort delivery is not one-shot.
    Delivery(SyscallId),
    /// Personality presence, fallback state, and ready record disagree.
    FallbackState(ScopeId),
    /// Scope state and revocation metadata disagree.
    RevocationMetadata(ScopeId),
    /// A revoked scope still contains live continuations.
    RevokedScopeLive(ScopeId),
    /// Closure visited more continuations than were indexed at its commit point.
    RevocationWorkBound(ScopeId),
    /// Trace sequence numbers are not a contiguous total order.
    TraceOrder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReadyRecord {
    personality: PersonalityId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    recovery_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RevocationRecord {
    closed_epoch: AuthorityEpoch,
    target_count: usize,
    steps: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PersonalityScopeRecord {
    state: ScopeState,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    personality: Option<PersonalityId>,
    fallback: PersonalityFallbackState,
    ready: Option<ReadyRecord>,
    live_syscalls: BTreeSet<SyscallId>,
    revocation: Option<RevocationRecord>,
    recovery_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SyscallRecord {
    token: SyscallToken,
    state: SyscallState,
    continuation: SyscallContinuationState,
    prepared_reply: Option<PreparedReply>,
    backend_commits: u8,
    delivery: Option<SyscallDelivery>,
    reply_publications: u8,
    continuation_consumptions: u8,
    terminalizations: u8,
    resumes: u8,
    exits: u8,
    aborts: u8,
}

/// Deterministic `no_std + alloc` Linux personality recovery oracle.
///
/// Every public mutating method is one abstract linearization point. Rejected
/// operations perform no mutation, so tests can compare stale/replayed replies
/// with a pre-operation clone. This model proves neither a production token
/// representation nor actual Rust lock/atomic refinement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalityModel {
    next_scope: u64,
    next_syscall: u64,
    scopes: BTreeMap<ScopeId, PersonalityScopeRecord>,
    syscalls: BTreeMap<SyscallId, SyscallRecord>,
    blocked_tasks: BTreeMap<(ScopeId, TaskId), SyscallId>,
    trace: Vec<PersonalityTraceEvent>,
}

impl Default for PersonalityModel {
    fn default() -> Self {
        Self::new()
    }
}

impl PersonalityModel {
    /// Creates an empty personality protocol model.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_scope: 1,
            next_syscall: 1,
            scopes: BTreeMap::new(),
            syscalls: BTreeMap::new(),
            blocked_tasks: BTreeMap::new(),
            trace: Vec::new(),
        }
    }

    /// Creates one active scope and its initial personality binding.
    pub fn create_scope(
        &mut self,
        personality: PersonalityId,
    ) -> Result<(ScopeId, PersonalityBindingToken), PersonalityError> {
        let scope = ScopeId::new(self.next_scope);
        let next_scope = self
            .next_scope
            .checked_add(1)
            .ok_or(PersonalityError::CounterOverflow)?;
        let authority_epoch = AuthorityEpoch::new(1);
        let binding_epoch = BindingEpoch::new(1);

        self.next_scope = next_scope;
        self.scopes.insert(
            scope,
            PersonalityScopeRecord {
                state: ScopeState::Active,
                authority_epoch,
                binding_epoch,
                personality: Some(personality),
                fallback: PersonalityFallbackState::Standby,
                ready: None,
                live_syscalls: BTreeSet::new(),
                revocation: None,
                recovery_revision: 0,
            },
        );
        self.push_trace(PersonalityAction::CreateScope, scope, None);
        Ok((
            scope,
            PersonalityBindingToken {
                scope,
                personality,
                authority_epoch,
                binding_epoch,
            },
        ))
    }

    /// Captures a syscall and installs the task's only live continuation.
    pub fn capture(
        &mut self,
        binding: PersonalityBindingToken,
        task: TaskId,
        operation: SyscallOperation,
    ) -> Result<SyscallToken, PersonalityError> {
        let scope = self.validate_binding(binding)?;
        if let Some(syscall) = self.blocked_tasks.get(&(binding.scope, task)) {
            return Err(PersonalityError::TaskAlreadyBlocked { syscall: *syscall });
        }
        let revision_after = Self::next_revision(scope)?;
        let syscall = SyscallId::new(self.next_syscall);
        let next_syscall = self
            .next_syscall
            .checked_add(1)
            .ok_or(PersonalityError::CounterOverflow)?;
        let token = SyscallToken {
            scope: binding.scope,
            syscall,
            task,
            operation,
            authority_epoch: scope.authority_epoch,
            binding_epoch: scope.binding_epoch,
        };

        self.next_syscall = next_syscall;
        let scope = self
            .scopes
            .get_mut(&binding.scope)
            .ok_or(PersonalityError::UnknownScope(binding.scope))?;
        scope.live_syscalls.insert(syscall);
        Self::publish_revision(scope, revision_after);
        self.blocked_tasks.insert((binding.scope, task), syscall);
        self.syscalls.insert(
            syscall,
            SyscallRecord {
                token,
                state: SyscallState::Captured,
                continuation: SyscallContinuationState::Pending,
                prepared_reply: None,
                backend_commits: 0,
                delivery: None,
                reply_publications: 0,
                continuation_consumptions: 0,
                terminalizations: 0,
                resumes: 0,
                exits: 0,
                aborts: 0,
            },
        );
        self.push_trace(PersonalityAction::Capture, binding.scope, Some(syscall));
        Ok(token)
    }

    /// Retains a type-matching reply without publishing it to task state.
    pub fn prepare_reply(
        &mut self,
        binding: PersonalityBindingToken,
        token: SyscallToken,
        reply: PreparedReply,
    ) -> Result<(), PersonalityError> {
        self.validate_current_reply(binding, token)?;
        let record = *self
            .syscalls
            .get(&token.syscall)
            .ok_or(PersonalityError::UnknownSyscall(token.syscall))?;
        if record.state.is_terminal() {
            return Err(PersonalityError::AlreadyTerminal);
        }
        if record.state != SyscallState::Captured {
            return Err(PersonalityError::InvalidSyscallState {
                state: record.state,
            });
        }
        if !reply.matches(token.operation) {
            return Err(PersonalityError::ReplyOperationMismatch);
        }
        let revision_after = Self::next_revision(
            self.scopes
                .get(&token.scope)
                .ok_or(PersonalityError::UnknownScope(token.scope))?,
        )?;

        let record = self
            .syscalls
            .get_mut(&token.syscall)
            .ok_or(PersonalityError::UnknownSyscall(token.syscall))?;
        record.state = SyscallState::ReplyPrepared;
        record.prepared_reply = Some(reply);
        let scope = self
            .scopes
            .get_mut(&token.scope)
            .ok_or(PersonalityError::UnknownScope(token.scope))?;
        Self::publish_revision(scope, revision_after);
        self.push_trace(
            PersonalityAction::PrepareReply,
            token.scope,
            Some(token.syscall),
        );
        Ok(())
    }

    /// Fences a crashed personality and advances only the binding generation.
    pub fn crash(&mut self, binding: PersonalityBindingToken) -> Result<(), PersonalityError> {
        let scope = self.validate_binding(binding)?;
        let next_binding = BindingEpoch::new(
            scope
                .binding_epoch
                .get()
                .checked_add(1)
                .ok_or(PersonalityError::CounterOverflow)?,
        );
        let revision_after = Self::next_revision(scope)?;
        let scope = self
            .scopes
            .get_mut(&binding.scope)
            .ok_or(PersonalityError::UnknownScope(binding.scope))?;
        scope.binding_epoch = next_binding;
        scope.personality = None;
        scope.fallback = PersonalityFallbackState::Required;
        scope.ready = None;
        Self::publish_revision(scope, revision_after);
        self.push_trace(PersonalityAction::Crash, binding.scope, None);
        Ok(())
    }

    /// Selects kernel fallback after personality failure.
    pub fn fallback_pick(&mut self, scope: ScopeId) -> Result<(), PersonalityError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PersonalityError::UnknownScope(scope))?;
        if record.state != ScopeState::Active {
            return Err(PersonalityError::InvalidScopeState {
                state: record.state,
            });
        }
        if record.personality.is_some() || record.fallback != PersonalityFallbackState::Required {
            return Err(PersonalityError::FallbackUnavailable);
        }
        self.scopes
            .get_mut(&scope)
            .ok_or(PersonalityError::UnknownScope(scope))?
            .fallback = PersonalityFallbackState::Running;
        self.push_trace(PersonalityAction::FallbackPick, scope, None);
        Ok(())
    }

    /// Captures the deterministic orphan set for one prospective replacement.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        personality: PersonalityId,
    ) -> Result<PersonalityRecoverySnapshot, PersonalityError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PersonalityError::UnknownScope(scope))?;
        if record.state != ScopeState::Active {
            return Err(PersonalityError::InvalidScopeState {
                state: record.state,
            });
        }
        if record.personality.is_some() || record.fallback != PersonalityFallbackState::Running {
            return Err(PersonalityError::FallbackUnavailable);
        }
        let mut syscalls = Vec::new();
        for syscall in &record.live_syscalls {
            let request = self
                .syscalls
                .get(syscall)
                .ok_or(PersonalityError::UnknownSyscall(*syscall))?;
            if matches!(
                request.state,
                SyscallState::Captured
                    | SyscallState::ReplyPrepared
                    | SyscallState::BackendCommitted
            ) {
                syscalls.push(SyscallSnapshot {
                    token: request.token,
                    state: request.state,
                    prepared_reply: request.prepared_reply,
                });
            }
        }
        Ok(PersonalityRecoverySnapshot {
            scope,
            personality,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            recovery_revision: record.recovery_revision,
            syscalls,
        })
    }

    /// Accepts replacement readiness only from a still-fresh snapshot.
    pub fn ready(
        &mut self,
        snapshot: &PersonalityRecoverySnapshot,
    ) -> Result<PersonalityReadyToken, PersonalityError> {
        let scope = self
            .scopes
            .get(&snapshot.scope)
            .ok_or(PersonalityError::UnknownScope(snapshot.scope))?;
        if scope.state != ScopeState::Active {
            return Err(PersonalityError::InvalidScopeState { state: scope.state });
        }
        if scope.personality.is_some() || scope.fallback != PersonalityFallbackState::Running {
            return Err(PersonalityError::FallbackUnavailable);
        }
        self.validate_snapshot(scope, snapshot)?;
        let token = PersonalityReadyToken {
            scope: snapshot.scope,
            personality: snapshot.personality,
            authority_epoch: snapshot.authority_epoch,
            binding_epoch: snapshot.binding_epoch,
            recovery_revision: snapshot.recovery_revision,
        };
        let scope = self
            .scopes
            .get_mut(&snapshot.scope)
            .ok_or(PersonalityError::UnknownScope(snapshot.scope))?;
        scope.fallback = PersonalityFallbackState::ReplacementReady;
        scope.ready = Some(ReadyRecord {
            personality: token.personality,
            authority_epoch: token.authority_epoch,
            binding_epoch: token.binding_epoch,
            recovery_revision: token.recovery_revision,
        });
        self.push_trace(PersonalityAction::Ready, snapshot.scope, None);
        Ok(token)
    }

    /// Installs a ready replacement without advancing the binding generation.
    pub fn rebind(
        &mut self,
        ready: PersonalityReadyToken,
    ) -> Result<PersonalityBindingToken, PersonalityError> {
        let scope = self
            .scopes
            .get(&ready.scope)
            .ok_or(PersonalityError::UnknownScope(ready.scope))?;
        if scope.state != ScopeState::Active {
            return Err(PersonalityError::InvalidScopeState { state: scope.state });
        }
        if scope.personality.is_some() {
            return Err(PersonalityError::PersonalityAlreadyBound);
        }
        if scope.fallback != PersonalityFallbackState::ReplacementReady {
            return Err(PersonalityError::FallbackUnavailable);
        }
        self.validate_ready(scope, ready)?;
        let binding = PersonalityBindingToken {
            scope: ready.scope,
            personality: ready.personality,
            authority_epoch: ready.authority_epoch,
            binding_epoch: ready.binding_epoch,
        };
        let scope = self
            .scopes
            .get_mut(&ready.scope)
            .ok_or(PersonalityError::UnknownScope(ready.scope))?;
        scope.personality = Some(ready.personality);
        scope.fallback = PersonalityFallbackState::Standby;
        scope.ready = None;
        self.push_trace(PersonalityAction::Rebind, ready.scope, None);
        Ok(binding)
    }

    /// Explicitly transfers one orphan continuation to the replacement.
    ///
    /// A prepared reply remains kernel-retained candidate state. For `write`,
    /// an already committed backend obligation is also preserved: adoption
    /// transfers only reply authority and never creates a second obligation.
    pub fn adopt(
        &mut self,
        binding: PersonalityBindingToken,
        token: SyscallToken,
    ) -> Result<SyscallToken, PersonalityError> {
        let scope = self.validate_binding(binding)?;
        let request = self.validate_syscall_token(token)?;
        if token.scope != binding.scope {
            return Err(PersonalityError::ScopeMismatch);
        }
        if token.authority_epoch != scope.authority_epoch {
            return Err(PersonalityError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if !matches!(
            request.state,
            SyscallState::Captured | SyscallState::ReplyPrepared | SyscallState::BackendCommitted
        ) || request.token.binding_epoch == scope.binding_epoch
        {
            return Err(PersonalityError::NotAdoptable);
        }
        let revision_after = Self::next_revision(scope)?;
        let mut adopted = token;
        adopted.binding_epoch = scope.binding_epoch;
        self.syscalls
            .get_mut(&token.syscall)
            .ok_or(PersonalityError::UnknownSyscall(token.syscall))?
            .token = adopted;
        let scope = self
            .scopes
            .get_mut(&token.scope)
            .ok_or(PersonalityError::UnknownScope(token.scope))?;
        Self::publish_revision(scope, revision_after);
        self.push_trace(PersonalityAction::Adopt, token.scope, Some(token.syscall));
        Ok(adopted)
    }

    /// Commits the unique backend output obligation for one prepared `write`.
    ///
    /// This is the external-output commit linearization point. The obligation
    /// becomes kernel owned before any guest reply is published. A subsequent
    /// personality crash therefore leaves `BackendCommitted` work that a fresh
    /// binding may explicitly adopt and reply to, but may not commit again.
    pub fn commit_backend(
        &mut self,
        binding: PersonalityBindingToken,
        token: SyscallToken,
    ) -> Result<(), PersonalityError> {
        self.validate_current_reply(binding, token)?;
        let request = *self
            .syscalls
            .get(&token.syscall)
            .ok_or(PersonalityError::UnknownSyscall(token.syscall))?;
        if request.state.is_terminal() {
            return Err(PersonalityError::AlreadyTerminal);
        }
        if token.operation != SyscallOperation::Write {
            return Err(PersonalityError::BackendCommitNotApplicable);
        }
        if request.state == SyscallState::BackendCommitted {
            return Err(PersonalityError::BackendAlreadyCommitted);
        }
        if request.state != SyscallState::ReplyPrepared {
            return Err(PersonalityError::InvalidSyscallState {
                state: request.state,
            });
        }
        if request.continuation != SyscallContinuationState::Pending {
            return Err(PersonalityError::ContinuationAlreadyConsumed);
        }
        if request.prepared_reply != Some(PreparedReply::WriteReturned) {
            return Err(PersonalityError::ReplyOperationMismatch);
        }
        let revision_after = Self::next_revision(
            self.scopes
                .get(&token.scope)
                .ok_or(PersonalityError::UnknownScope(token.scope))?,
        )?;

        let request = self
            .syscalls
            .get_mut(&token.syscall)
            .ok_or(PersonalityError::UnknownSyscall(token.syscall))?;
        request.state = SyscallState::BackendCommitted;
        request.backend_commits = 1;
        let scope = self
            .scopes
            .get_mut(&token.scope)
            .ok_or(PersonalityError::UnknownScope(token.scope))?;
        Self::publish_revision(scope, revision_after);
        self.push_trace(
            PersonalityAction::BackendCommit,
            token.scope,
            Some(token.syscall),
        );
        Ok(())
    }

    /// Atomically publishes a guest reply and consumes the continuation.
    ///
    /// A `write` must already own its unique backend obligation; this method
    /// publishes no external output. `exit_group` instead delivers its process
    /// terminal outcome directly and never acquires a backend obligation. All
    /// authority, binding, identity, task-index, state, and operation-label
    /// checks finish before any modeled task state changes.
    pub fn reply(
        &mut self,
        binding: PersonalityBindingToken,
        token: SyscallToken,
    ) -> Result<SyscallDelivery, PersonalityError> {
        self.validate_current_reply(binding, token)?;
        let request = *self
            .syscalls
            .get(&token.syscall)
            .ok_or(PersonalityError::UnknownSyscall(token.syscall))?;
        if request.state.is_terminal() {
            return Err(PersonalityError::AlreadyTerminal);
        }
        if request.continuation != SyscallContinuationState::Pending {
            return Err(PersonalityError::ContinuationAlreadyConsumed);
        }
        let required_state = match token.operation {
            SyscallOperation::Write => SyscallState::BackendCommitted,
            SyscallOperation::ExitGroup => SyscallState::ReplyPrepared,
        };
        if request.state != required_state {
            return Err(PersonalityError::InvalidSyscallState {
                state: request.state,
            });
        }
        let prepared = request
            .prepared_reply
            .ok_or(PersonalityError::InvariantViolation(
                "prepared syscall lacks a reply",
            ))?;
        if !prepared.matches(token.operation) {
            return Err(PersonalityError::ReplyOperationMismatch);
        }
        if self.blocked_tasks.get(&(token.scope, token.task)) != Some(&token.syscall) {
            return Err(PersonalityError::InvariantViolation(
                "blocked-task index disagrees with reply",
            ));
        }
        let delivery = match prepared {
            PreparedReply::WriteReturned => SyscallDelivery::WriteReturned,
            PreparedReply::ExitGroupRequested => SyscallDelivery::ExitGroupRequested,
        };
        match delivery {
            SyscallDelivery::WriteReturned if request.backend_commits != 1 => {
                return Err(PersonalityError::InvariantViolation(
                    "write reply lacks its unique backend commitment",
                ));
            }
            SyscallDelivery::ExitGroupRequested if request.backend_commits != 0 => {
                return Err(PersonalityError::InvariantViolation(
                    "exit_group acquired a backend output obligation",
                ));
            }
            SyscallDelivery::Aborted => {
                return Err(PersonalityError::InvariantViolation(
                    "successful reply selected abort delivery",
                ));
            }
            SyscallDelivery::WriteReturned | SyscallDelivery::ExitGroupRequested => {}
        }
        let revision_after = Self::next_revision(
            self.scopes
                .get(&token.scope)
                .ok_or(PersonalityError::UnknownScope(token.scope))?,
        )?;

        let request = self
            .syscalls
            .get_mut(&token.syscall)
            .ok_or(PersonalityError::UnknownSyscall(token.syscall))?;
        request.state = SyscallState::Completed;
        request.continuation = SyscallContinuationState::Replied;
        request.delivery = Some(delivery);
        request.reply_publications = 1;
        request.continuation_consumptions = 1;
        request.terminalizations = 1;
        match delivery {
            SyscallDelivery::WriteReturned => request.resumes = 1,
            SyscallDelivery::ExitGroupRequested => request.exits = 1,
            SyscallDelivery::Aborted => unreachable!("validated successful delivery"),
        }
        let scope = self
            .scopes
            .get_mut(&token.scope)
            .ok_or(PersonalityError::UnknownScope(token.scope))?;
        scope.live_syscalls.remove(&token.syscall);
        Self::publish_revision(scope, revision_after);
        self.blocked_tasks.remove(&(token.scope, token.task));
        self.push_trace(PersonalityAction::Reply, token.scope, Some(token.syscall));
        Ok(delivery)
    }

    /// Closes the current authority generation and rejects every later reply.
    pub fn revoke_begin(&mut self, scope: ScopeId) -> Result<(), PersonalityError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PersonalityError::UnknownScope(scope))?;
        if record.state != ScopeState::Active {
            return Err(PersonalityError::InvalidScopeState {
                state: record.state,
            });
        }
        let closed_epoch = record.authority_epoch;
        let next_epoch = AuthorityEpoch::new(
            closed_epoch
                .get()
                .checked_add(1)
                .ok_or(PersonalityError::CounterOverflow)?,
        );
        let revision_after = Self::next_revision(record)?;
        let target_count = record.live_syscalls.len();

        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(PersonalityError::UnknownScope(scope))?;
        record.state = ScopeState::Closing;
        record.authority_epoch = next_epoch;
        record.personality = None;
        record.fallback = PersonalityFallbackState::Closed;
        record.ready = None;
        record.revocation = Some(RevocationRecord {
            closed_epoch,
            target_count,
            steps: 0,
        });
        Self::publish_revision(record, revision_after);
        self.push_trace(PersonalityAction::RevokeBegin, scope, None);
        Ok(())
    }

    /// Terminalizes one continuation selected from this scope's reverse index.
    ///
    /// Uncommitted work aborts. A `write` whose backend commitment won before
    /// `revoke_begin` instead drains that existing obligation and publishes its
    /// one reply; closure never creates a second backend obligation.
    pub fn revoke_next(
        &mut self,
        scope: ScopeId,
    ) -> Result<Option<PersonalityRevocationStep>, PersonalityError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PersonalityError::UnknownScope(scope))?;
        if record.state != ScopeState::Closing {
            return Err(PersonalityError::InvalidScopeState {
                state: record.state,
            });
        }
        let Some(syscall) = record.live_syscalls.iter().next().copied() else {
            return Ok(None);
        };
        let request = *self
            .syscalls
            .get(&syscall)
            .ok_or(PersonalityError::UnknownSyscall(syscall))?;
        if request.state.is_terminal() || request.continuation != SyscallContinuationState::Pending
        {
            return Err(PersonalityError::InvariantViolation(
                "live reverse index selected a terminal syscall",
            ));
        }
        if self.blocked_tasks.get(&(scope, request.token.task)) != Some(&syscall) {
            return Err(PersonalityError::InvariantViolation(
                "blocked-task index disagrees with closure",
            ));
        }
        let revision_after = Self::next_revision(record)?;
        let next_steps = record
            .revocation
            .ok_or(PersonalityError::InvariantViolation(
                "closing scope lacks revocation metadata",
            ))?
            .steps
            .checked_add(1)
            .ok_or(PersonalityError::CounterOverflow)?;
        let from = request.state;
        let (to, continuation, delivery, reply_publications, resumes, aborts) = if request.state
            == SyscallState::BackendCommitted
        {
            if request.token.operation != SyscallOperation::Write || request.backend_commits != 1 {
                return Err(PersonalityError::InvariantViolation(
                    "closure selected an invalid backend commitment",
                ));
            }
            (
                SyscallState::Completed,
                SyscallContinuationState::Replied,
                SyscallDelivery::WriteReturned,
                1,
                1,
                0,
            )
        } else {
            (
                SyscallState::Aborted,
                SyscallContinuationState::Aborted,
                SyscallDelivery::Aborted,
                0,
                0,
                1,
            )
        };

        let request = self
            .syscalls
            .get_mut(&syscall)
            .ok_or(PersonalityError::UnknownSyscall(syscall))?;
        request.state = to;
        request.continuation = continuation;
        request.delivery = Some(delivery);
        request.reply_publications = reply_publications;
        request.continuation_consumptions = 1;
        request.terminalizations = 1;
        request.resumes = resumes;
        request.aborts = aborts;
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(PersonalityError::UnknownScope(scope))?;
        record.live_syscalls.remove(&syscall);
        record
            .revocation
            .as_mut()
            .ok_or(PersonalityError::InvariantViolation(
                "closing scope lacks revocation metadata",
            ))?
            .steps = next_steps;
        Self::publish_revision(record, revision_after);
        self.blocked_tasks.remove(&(scope, request.token.task));
        self.push_trace(PersonalityAction::RevokeStep, scope, Some(syscall));
        Ok(Some(PersonalityRevocationStep { syscall, from, to }))
    }

    /// Publishes quiescent closure after the reverse index becomes empty.
    pub fn revoke_complete(&mut self, scope: ScopeId) -> Result<(), PersonalityError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PersonalityError::UnknownScope(scope))?;
        if record.state != ScopeState::Closing {
            return Err(PersonalityError::InvalidScopeState {
                state: record.state,
            });
        }
        if !record.live_syscalls.is_empty() {
            return Err(PersonalityError::RevocationNotQuiescent {
                remaining: record.live_syscalls.len(),
            });
        }
        self.scopes
            .get_mut(&scope)
            .ok_or(PersonalityError::UnknownScope(scope))?
            .state = ScopeState::Revoked;
        self.push_trace(PersonalityAction::RevokeComplete, scope, None);
        Ok(())
    }

    /// Returns a read-only scope projection.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<PersonalityScopeView> {
        self.scopes.get(&scope).map(|record| PersonalityScopeView {
            state: record.state,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            personality: record.personality,
            fallback: record.fallback,
            live_syscalls: record.live_syscalls.len(),
            revocation: record
                .revocation
                .map(|revocation| PersonalityRevocationProgress {
                    closed_epoch: revocation.closed_epoch,
                    target_count: revocation.target_count,
                    steps: revocation.steps,
                    remaining: record.live_syscalls.len(),
                }),
        })
    }

    /// Returns a read-only syscall projection.
    #[must_use]
    pub fn syscall(&self, syscall: SyscallId) -> Option<SyscallView> {
        self.syscalls.get(&syscall).map(|record| SyscallView {
            token: record.token,
            state: record.state,
            continuation: record.continuation,
            prepared_reply: record.prepared_reply,
            backend_commits: record.backend_commits,
            delivery: record.delivery,
            reply_publications: record.reply_publications,
            continuation_consumptions: record.continuation_consumptions,
            terminalizations: record.terminalizations,
            resumes: record.resumes,
            exits: record.exits,
            aborts: record.aborts,
        })
    }

    /// Returns the target scope's live syscall identities in deterministic order.
    pub fn live_syscalls(&self, scope: ScopeId) -> Result<Vec<SyscallId>, PersonalityError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PersonalityError::UnknownScope(scope))?;
        Ok(record.live_syscalls.iter().copied().collect())
    }

    /// Returns the successful operation trace.
    #[must_use]
    pub fn trace(&self) -> &[PersonalityTraceEvent] {
        &self.trace
    }

    /// Audits all global invariants independently of protocol transitions.
    pub fn check_invariants(&self) -> Result<(), PersonalityInvariantViolation> {
        for (scope_id, scope) in &self.scopes {
            let expected_live: BTreeSet<_> = self
                .syscalls
                .iter()
                .filter_map(|(syscall, request)| {
                    (request.token.scope == *scope_id && !request.state.is_terminal())
                        .then_some(*syscall)
                })
                .collect();
            if scope.live_syscalls != expected_live {
                return Err(PersonalityInvariantViolation::LiveReverseIndex(*scope_id));
            }

            match scope.state {
                ScopeState::Active => {
                    if scope.revocation.is_some() {
                        return Err(PersonalityInvariantViolation::RevocationMetadata(*scope_id));
                    }
                    let fallback_valid = match scope.fallback {
                        PersonalityFallbackState::Standby => {
                            scope.personality.is_some() && scope.ready.is_none()
                        }
                        PersonalityFallbackState::Required | PersonalityFallbackState::Running => {
                            scope.personality.is_none() && scope.ready.is_none()
                        }
                        PersonalityFallbackState::ReplacementReady => {
                            scope.personality.is_none() && scope.ready.is_some()
                        }
                        PersonalityFallbackState::Closed => false,
                    };
                    if !fallback_valid {
                        return Err(PersonalityInvariantViolation::FallbackState(*scope_id));
                    }
                }
                ScopeState::Closing | ScopeState::Revoked => {
                    if scope.revocation.is_none()
                        || scope.personality.is_some()
                        || scope.ready.is_some()
                        || scope.fallback != PersonalityFallbackState::Closed
                    {
                        return Err(PersonalityInvariantViolation::RevocationMetadata(*scope_id));
                    }
                }
            }
            if scope.state == ScopeState::Revoked && !scope.live_syscalls.is_empty() {
                return Err(PersonalityInvariantViolation::RevokedScopeLive(*scope_id));
            }
            if let Some(revocation) = scope.revocation
                && (revocation.steps > revocation.target_count
                    || revocation.steps + scope.live_syscalls.len() != revocation.target_count)
            {
                return Err(PersonalityInvariantViolation::RevocationWorkBound(
                    *scope_id,
                ));
            }
            if let Some(ready) = scope.ready
                && (ready.authority_epoch != scope.authority_epoch
                    || ready.binding_epoch != scope.binding_epoch
                    || ready.recovery_revision != scope.recovery_revision)
            {
                return Err(PersonalityInvariantViolation::FallbackState(*scope_id));
            }
        }

        for (syscall_id, request) in &self.syscalls {
            let Some(scope) = self.scopes.get(&request.token.scope) else {
                return Err(PersonalityInvariantViolation::OrphanOrFutureSyscall(
                    *syscall_id,
                ));
            };
            if request.token.syscall != *syscall_id
                || request.token.authority_epoch > scope.authority_epoch
                || request.token.binding_epoch > scope.binding_epoch
            {
                return Err(PersonalityInvariantViolation::OrphanOrFutureSyscall(
                    *syscall_id,
                ));
            }

            let blocked = self
                .blocked_tasks
                .get(&(request.token.scope, request.token.task));
            if request.state.is_terminal() {
                if blocked == Some(syscall_id) {
                    return Err(PersonalityInvariantViolation::BlockedTaskIndex(*syscall_id));
                }
            } else if blocked != Some(syscall_id) {
                return Err(PersonalityInvariantViolation::BlockedTaskIndex(*syscall_id));
            }

            let reply_state_valid = match request.state {
                SyscallState::Captured => {
                    request.prepared_reply.is_none() && request.reply_publications == 0
                }
                SyscallState::ReplyPrepared => {
                    request
                        .prepared_reply
                        .is_some_and(|reply| reply.matches(request.token.operation))
                        && request.reply_publications == 0
                }
                SyscallState::BackendCommitted => {
                    request.prepared_reply == Some(PreparedReply::WriteReturned)
                        && request.reply_publications == 0
                }
                SyscallState::Completed => {
                    request
                        .prepared_reply
                        .is_some_and(|reply| reply.matches(request.token.operation))
                        && request.reply_publications == 1
                }
                SyscallState::Aborted => request.reply_publications == 0,
            };
            if !reply_state_valid {
                return Err(PersonalityInvariantViolation::ReplyState(*syscall_id));
            }

            let backend_commit_valid = match request.token.operation {
                SyscallOperation::Write => match request.state {
                    SyscallState::Captured
                    | SyscallState::ReplyPrepared
                    | SyscallState::Aborted => request.backend_commits == 0,
                    SyscallState::BackendCommitted | SyscallState::Completed => {
                        request.backend_commits == 1
                    }
                },
                SyscallOperation::ExitGroup => {
                    request.state != SyscallState::BackendCommitted && request.backend_commits == 0
                }
            };
            if !backend_commit_valid {
                return Err(PersonalityInvariantViolation::BackendCommit(*syscall_id));
            }

            let terminalization_valid = if request.state.is_terminal() {
                request.continuation_consumptions == 1 && request.terminalizations == 1
            } else {
                request.continuation == SyscallContinuationState::Pending
                    && request.continuation_consumptions == 0
                    && request.terminalizations == 0
                    && request.delivery.is_none()
            };
            if !terminalization_valid {
                return Err(PersonalityInvariantViolation::Terminalization(*syscall_id));
            }

            let delivery_valid = match request.state {
                SyscallState::Captured
                | SyscallState::ReplyPrepared
                | SyscallState::BackendCommitted => {
                    request.delivery.is_none()
                        && (request.resumes, request.exits, request.aborts) == (0, 0, 0)
                }
                SyscallState::Completed => match request.token.operation {
                    SyscallOperation::Write => {
                        request.continuation == SyscallContinuationState::Replied
                            && request.delivery == Some(SyscallDelivery::WriteReturned)
                            && (request.resumes, request.exits, request.aborts) == (1, 0, 0)
                    }
                    SyscallOperation::ExitGroup => {
                        request.continuation == SyscallContinuationState::Replied
                            && request.delivery == Some(SyscallDelivery::ExitGroupRequested)
                            && (request.resumes, request.exits, request.aborts) == (0, 1, 0)
                    }
                },
                SyscallState::Aborted => {
                    request.continuation == SyscallContinuationState::Aborted
                        && request.delivery == Some(SyscallDelivery::Aborted)
                        && (request.resumes, request.exits, request.aborts) == (0, 0, 1)
                }
            };
            if !delivery_valid {
                return Err(PersonalityInvariantViolation::Delivery(*syscall_id));
            }
        }

        for ((scope, task), syscall) in &self.blocked_tasks {
            let Some(request) = self.syscalls.get(syscall) else {
                return Err(PersonalityInvariantViolation::BlockedTaskIndex(*syscall));
            };
            if request.token.scope != *scope
                || request.token.task != *task
                || request.state.is_terminal()
            {
                return Err(PersonalityInvariantViolation::BlockedTaskIndex(*syscall));
            }
        }

        if self
            .trace
            .iter()
            .enumerate()
            .any(|(seq, event)| event.seq != seq)
        {
            return Err(PersonalityInvariantViolation::TraceOrder);
        }
        Ok(())
    }

    fn validate_binding(
        &self,
        binding: PersonalityBindingToken,
    ) -> Result<&PersonalityScopeRecord, PersonalityError> {
        let scope = self
            .scopes
            .get(&binding.scope)
            .ok_or(PersonalityError::UnknownScope(binding.scope))?;
        if scope.state != ScopeState::Active {
            return Err(PersonalityError::InvalidScopeState { state: scope.state });
        }
        if binding.authority_epoch != scope.authority_epoch {
            return Err(PersonalityError::StaleAuthority {
                presented: binding.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if binding.binding_epoch != scope.binding_epoch {
            return Err(PersonalityError::StaleBinding {
                presented: binding.binding_epoch,
                current: scope.binding_epoch,
            });
        }
        let personality = scope
            .personality
            .ok_or(PersonalityError::PersonalityUnavailable)?;
        if binding.personality != personality {
            return Err(PersonalityError::WrongPersonality);
        }
        Ok(scope)
    }

    fn validate_syscall_token(
        &self,
        token: SyscallToken,
    ) -> Result<&SyscallRecord, PersonalityError> {
        let request = self
            .syscalls
            .get(&token.syscall)
            .ok_or(PersonalityError::UnknownSyscall(token.syscall))?;
        if request.token != token {
            return Err(PersonalityError::SyscallIdentityMismatch);
        }
        Ok(request)
    }

    fn validate_current_reply(
        &self,
        binding: PersonalityBindingToken,
        token: SyscallToken,
    ) -> Result<(), PersonalityError> {
        let scope = self.validate_binding(binding)?;
        let request = self.validate_syscall_token(token)?;
        if token.scope != binding.scope {
            return Err(PersonalityError::ScopeMismatch);
        }
        if token.authority_epoch != scope.authority_epoch {
            return Err(PersonalityError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if request.token.binding_epoch != scope.binding_epoch {
            return Err(PersonalityError::SyscallBindingFenced {
                syscall_binding: request.token.binding_epoch,
                current_binding: scope.binding_epoch,
            });
        }
        Ok(())
    }

    fn validate_snapshot(
        &self,
        scope: &PersonalityScopeRecord,
        snapshot: &PersonalityRecoverySnapshot,
    ) -> Result<(), PersonalityError> {
        if snapshot.authority_epoch != scope.authority_epoch
            || snapshot.binding_epoch != scope.binding_epoch
            || snapshot.recovery_revision != scope.recovery_revision
        {
            return Err(PersonalityError::StaleRecoverySnapshot);
        }
        let expected: Vec<_> = scope
            .live_syscalls
            .iter()
            .filter_map(|syscall| {
                let request = self.syscalls.get(syscall)?;
                matches!(
                    request.state,
                    SyscallState::Captured
                        | SyscallState::ReplyPrepared
                        | SyscallState::BackendCommitted
                )
                .then_some(SyscallSnapshot {
                    token: request.token,
                    state: request.state,
                    prepared_reply: request.prepared_reply,
                })
            })
            .collect();
        if snapshot.syscalls != expected {
            return Err(PersonalityError::StaleRecoverySnapshot);
        }
        Ok(())
    }

    fn validate_ready(
        &self,
        scope: &PersonalityScopeRecord,
        ready: PersonalityReadyToken,
    ) -> Result<(), PersonalityError> {
        if scope.ready
            != Some(ReadyRecord {
                personality: ready.personality,
                authority_epoch: ready.authority_epoch,
                binding_epoch: ready.binding_epoch,
                recovery_revision: ready.recovery_revision,
            })
            || ready.authority_epoch != scope.authority_epoch
            || ready.binding_epoch != scope.binding_epoch
            || ready.recovery_revision != scope.recovery_revision
        {
            return Err(PersonalityError::StaleRecoverySnapshot);
        }
        Ok(())
    }

    fn next_revision(scope: &PersonalityScopeRecord) -> Result<u64, PersonalityError> {
        scope
            .recovery_revision
            .checked_add(1)
            .ok_or(PersonalityError::CounterOverflow)
    }

    const fn publish_revision(scope: &mut PersonalityScopeRecord, revision: u64) {
        scope.recovery_revision = revision;
    }

    fn push_trace(
        &mut self,
        action: PersonalityAction,
        scope: ScopeId,
        syscall: Option<SyscallId>,
    ) {
        let record = self
            .scopes
            .get(&scope)
            .expect("successful transition retains its scope");
        self.trace.push(PersonalityTraceEvent {
            seq: self.trace.len(),
            action,
            scope,
            syscall,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
        });
    }
}
