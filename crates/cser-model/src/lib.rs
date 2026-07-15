#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Executable reference model for causally scoped effect revocation (CSER).
//!
//! This crate fixes the state-machine semantics before those semantics are
//! embedded in a kernel. It deliberately models only authority lineage,
//! epoch/binding fencing, effect terminalization, revocation work, and linear
//! budget accounting. It is not a production runtime.

extern crate alloc;

pub mod composition;
pub mod handoff_admission;
pub mod io;
pub mod linux_io_composition;
mod model;
pub mod pager;
pub mod personality;
pub mod production_identity;
pub mod runtime_fs;
pub mod runtime_net;

pub use model::Model;

/// Stable identifier of an authority scope.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ScopeId(u64);

impl ScopeId {
    /// Constructs an identifier for querying or negative testing.
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

/// Stable identifier of a delegated effect.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EffectId(u64);

impl EffectId {
    /// Constructs an identifier for querying or negative testing.
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

/// Stable identity of a user-space supervisor instance.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SupervisorId(u64);

impl SupervisorId {
    /// Constructs a supervisor identity.
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

/// Scalar resource credits carried by an authority scope.
///
/// A production implementation may use a vector of independently conserved
/// resources. A scalar keeps the reference model finite without weakening the
/// no-duplication argument.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Budget(u64);

impl Budget {
    /// A budget containing no credits.
    pub const ZERO: Self = Self(0);

    /// Constructs a budget from resource-credit units.
    #[must_use]
    pub const fn new(units: u64) -> Self {
        Self(units)
    }

    /// Returns the number of resource-credit units.
    #[must_use]
    pub const fn units(self) -> u64 {
        self.0
    }
}

/// Lifecycle of an authority scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeState {
    /// New effects may be registered and prepared effects may commit.
    Active,
    /// Revocation has linearized; old effects are being cancelled or drained.
    Closing,
    /// All old-epoch effects have reached a terminal state.
    Revoked,
}

/// Lifecycle of an effect causally owned by a scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectState {
    /// Authority and budget are reserved, but no commit preparation occurred.
    Registered,
    /// The effect is ready to cross its externally visible commit point.
    Prepared,
    /// The irreversible commit point has been crossed.
    Committed,
    /// A committed effect is being quiesced after revocation.
    Draining,
    /// A committed effect finished and is terminal.
    Completed,
    /// An uncommitted effect is being cancelled after revocation.
    Cancelling,
    /// An uncommitted effect was cancelled and is terminal.
    Aborted,
}

impl EffectState {
    /// Returns whether no later transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

/// Accounting state of the budget assigned to an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetDisposition {
    /// Credits are exclusively reserved by an uncommitted effect.
    Held,
    /// Credits were consumed at the effect's commit point.
    Spent,
    /// Credits were returned to the scope when the effect aborted.
    Returned,
}

/// Opaque proof that a supervisor is the current binding of a scope.
///
/// Tokens remain useful as stale messages in tests: `crash` advances the
/// binding epoch, while `revoke_begin` closes the authority epoch and rejects
/// every supervisor operation regardless of token freshness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingToken {
    scope: ScopeId,
    supervisor: SupervisorId,
    binding_epoch: u64,
}

impl BindingToken {
    pub(crate) const fn new(scope: ScopeId, supervisor: SupervisorId, binding_epoch: u64) -> Self {
        Self {
            scope,
            supervisor,
            binding_epoch,
        }
    }

    /// Returns the bound scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the supervisor identity captured by the token.
    #[must_use]
    pub const fn supervisor(self) -> SupervisorId {
        self.supervisor
    }

    /// Returns the binding epoch captured by the token.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }
}

/// Read-only projection of a scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeView {
    /// Scope lifecycle state.
    pub state: ScopeState,
    /// Epoch inherited by newly registered effects.
    pub epoch: u64,
    /// Epoch fencing replies from former supervisor bindings.
    pub binding_epoch: u64,
    /// Current or last supervisor binding; closing state rejects its actions.
    pub supervisor: Option<SupervisorId>,
    /// Immutable initial resource budget.
    pub initial_budget: Budget,
    /// Credits available for registration.
    pub free_budget: Budget,
    /// Credits consumed by committed effects.
    pub spent_budget: Budget,
    /// Number of nonterminal effects in the reverse index.
    pub live_effects: usize,
    /// Revocation progress when closure has begun.
    pub revocation: Option<RevocationProgress>,
    /// Whether a crashed supervisor still requires a fallback selection.
    pub fallback_pending: bool,
    /// Whether the fallback has been selected since the last binding.
    pub fallback_selected: bool,
}

/// Read-only projection of an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectView {
    /// Owning authority scope.
    pub scope: ScopeId,
    /// Scope epoch captured at registration.
    pub scope_epoch: u64,
    /// Supervisor binding currently allowed to advance this effect.
    pub binding_epoch: u64,
    /// Effect lifecycle state.
    pub state: EffectState,
    /// Size of the effect's budget grant.
    pub budget: Budget,
    /// Current accounting disposition of the grant.
    pub budget_disposition: BudgetDisposition,
    /// Number of successful transitions into a terminal state.
    pub terminalizations: u8,
}

/// Bounded work accounting for an in-progress or completed revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationProgress {
    /// Epoch that was closed by `revoke_begin`.
    pub closed_epoch: u64,
    /// Number of live effects at the revocation linearization point.
    pub target_count: usize,
    /// Number of individual state transitions performed by `revoke_step`.
    pub steps: usize,
    /// Number of effects that have not terminalized yet.
    pub remaining: usize,
}

/// Result of one unit of revocation work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationStep {
    /// Effect advanced by this step.
    pub effect: EffectId,
    /// State before the step.
    pub from: EffectState,
    /// State after the step.
    pub to: EffectState,
    /// Whether this step removed the effect from the live reverse index.
    pub terminalized: bool,
}

/// Stable action vocabulary shared by the model, TLA+ specification, and
/// executable vertical slices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceAction {
    /// Create a scope and its initial supervisor binding.
    CreateScope,
    /// Reserve authority and budget for an effect.
    Register,
    /// Move an effect to the prepared state.
    Prepare,
    /// Cross an effect's irreversible commit point.
    Commit,
    /// Finish a committed or draining effect.
    Complete,
    /// Fence the old authority epoch and begin closure.
    RevokeBegin,
    /// Advance one effect toward cancellation or drainage.
    RevokeStep,
    /// Publish that all effects in the closed epoch are terminal.
    RevokeComplete,
    /// Fence replies from a crashed supervisor.
    Crash,
    /// Install a replacement supervisor.
    Rebind,
    /// Move an uncommitted effect to the replacement binding.
    Adopt,
    /// Select the kernel fallback after policy-supervisor failure.
    FallbackPick,
}

/// Action-specific result attached to a successful trace event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceOutcome {
    /// A transition completed without additional accounting detail.
    Applied,
    /// A budget grant moved from the scope's free pool to an effect.
    BudgetHeld(Budget),
    /// A budget grant became irreversibly spent at commit.
    BudgetSpent(Budget),
    /// Cancellation returned a held budget grant to the scope.
    BudgetReturned(Budget),
    /// Closure began for an old epoch and a bounded target set.
    RevocationStarted {
        /// Epoch closed by the action.
        closed_epoch: u64,
        /// Live effects in the per-scope reverse index at that instant.
        target_count: usize,
    },
    /// Closure completed within the reported transition count.
    RevocationFinished {
        /// Live effects at `revoke_begin`.
        target_count: usize,
        /// State transitions performed by `revoke_step`.
        steps: usize,
    },
    /// A binding epoch was advanced, invalidating former replies.
    BindingAdvanced {
        /// Epoch invalidated by the action.
        old_binding_epoch: u64,
    },
    /// An orphan effect moved from an old binding to the ready replacement.
    EffectAdopted {
        /// Binding epoch previously carried by the effect.
        old_binding_epoch: u64,
    },
    /// A supervisor was installed in the current binding epoch.
    SupervisorBound(SupervisorId),
    /// The kernel fallback policy was selected.
    FallbackSelected,
}

/// One successful action in the model's total linearization order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceEvent {
    /// Zero-based total-order position.
    pub seq: usize,
    /// Stable operation name.
    pub action: TraceAction,
    /// Scope affected by the operation.
    pub scope: ScopeId,
    /// Effect affected by the operation, when applicable.
    pub effect: Option<EffectId>,
    /// Authority epoch visible immediately after the operation.
    pub authority_epoch: u64,
    /// Binding epoch visible immediately after the operation.
    pub binding_epoch: u64,
    /// Effect state immediately before the operation, when applicable.
    pub from: Option<EffectState>,
    /// Effect state immediately after the operation, when applicable.
    pub to: Option<EffectState>,
    /// Successful transition outcome and action-specific accounting detail.
    pub outcome: TraceOutcome,
}

/// Rejected model operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    /// The requested scope does not exist.
    UnknownScope(ScopeId),
    /// The requested effect does not exist.
    UnknownEffect(EffectId),
    /// The scope is not in the state required by the operation.
    InvalidScopeState {
        /// Actual state.
        state: ScopeState,
    },
    /// The effect is not in a state accepted by the operation.
    InvalidEffectState {
        /// Actual state.
        state: EffectState,
    },
    /// A former supervisor binding attempted to act after a fence.
    StaleBinding {
        /// Epoch carried by the operation.
        presented: u64,
        /// Epoch currently required by the scope.
        current: u64,
    },
    /// The token names a supervisor other than the current binding.
    WrongSupervisor,
    /// The active scope has no supervisor and must be rebound.
    SupervisorUnavailable,
    /// A rebind was attempted while a live supervisor was still installed.
    SupervisorAlreadyBound,
    /// The kernel fallback is not pending for this scope.
    FallbackUnavailable,
    /// An operation mixed an effect and binding from different scopes.
    EffectScopeMismatch,
    /// The effect inherited an epoch that is no longer current.
    EpochFenced {
        /// Epoch carried by the effect.
        effect_epoch: u64,
        /// Current scope epoch.
        current_epoch: u64,
    },
    /// The effect still belongs to a former supervisor binding.
    EffectBindingFenced {
        /// Binding epoch carried by the effect.
        effect_binding: u64,
        /// Binding epoch required by the operation.
        current_binding: u64,
    },
    /// Adoption was requested for an already adopted or committed effect.
    NotAdoptable,
    /// A zero-credit budget cannot be delegated to an effect.
    ZeroBudget,
    /// The scope lacks enough free credits for registration.
    BudgetExhausted {
        /// Requested credits.
        requested: Budget,
        /// Currently free credits.
        available: Budget,
    },
    /// A terminal effect received another completion/abort transition.
    AlreadyTerminal,
    /// Closure was requested while affected effects were still live.
    RevocationNotQuiescent {
        /// Effects still present in the scope reverse index.
        remaining: usize,
    },
    /// A monotonically increasing identifier or epoch overflowed.
    CounterOverflow,
    /// An internal state relationship was inconsistent.
    InvariantViolation(&'static str),
}

/// Failure reported by a full model invariant audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvariantViolation {
    /// Scope budget components no longer sum to the initial budget.
    BudgetConservation(ScopeId),
    /// The scope's spent counter differs from its committed effect grants.
    SpentAccounting(ScopeId),
    /// An effect's lifecycle and budget disposition disagree.
    EffectBudgetState(EffectId),
    /// A scope reverse index differs from the set of nonterminal effects.
    LiveReverseIndex(ScopeId),
    /// An effect terminalized more than once or its count disagrees with state.
    Terminalization(EffectId),
    /// A revoked scope still has live effects.
    RevokedScopeLive(ScopeId),
    /// Closing state and revocation progress metadata disagree.
    RevocationMetadata(ScopeId),
    /// Revocation used more than two transitions per initially live effect.
    RevocationWorkBound(ScopeId),
    /// An effect refers to a missing scope.
    OrphanEffect(EffectId),
    /// An effect is newer than its owning scope.
    FutureEffectEpoch(EffectId),
    /// Supervisor and fallback state disagree.
    FallbackState(ScopeId),
}
