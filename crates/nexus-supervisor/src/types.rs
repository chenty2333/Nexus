// SPDX-License-Identifier: MPL-2.0

/// Identity of one concrete service task incarnation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServiceIdentity {
    id: u64,
    generation: u64,
}

impl ServiceIdentity {
    /// Constructs a nonzero service identity.
    pub const fn new(id: u64, generation: u64) -> Option<Self> {
        if id == 0 || generation == 0 {
            None
        } else {
            Some(Self { id, generation })
        }
    }

    /// Returns the task-local service identifier.
    pub const fn id(self) -> u64 {
        self.id
    }

    /// Returns the service incarnation generation.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Why a managed service stopped being usable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitReason {
    /// The task returned without an explicit manager stop request.
    UnexpectedReturn,
    /// The task encountered a user-mode or kernel-isolated fault.
    Fault,
    /// A liveness watchdog declared the task unavailable.
    Watchdog,
    /// The service violated its portal or readiness protocol.
    ProtocolViolation,
}

/// Why a replacement task is being stopped before activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    /// The replacement failed before reporting ready.
    ExitedBeforeReady,
    /// The replacement did not become ready before its deadline.
    ReadyTimeout,
    /// A pre-rebind recovery attempt was rejected.
    RecoveryRejected,
}

/// Bounded restart and recovery policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisorPolicy {
    /// Maximum recovery attempts over the manager lifetime.
    ///
    /// An attempt is consumed when backoff expires and replacement selection is
    /// invoked. Selection, spawn, and snapshot failures therefore consume an
    /// attempt even when no replacement task reaches Ready.
    pub max_recovery_attempts: u32,
    /// Delay before the first replacement start.
    pub initial_backoff_ticks: u64,
    /// Saturating upper bound for exponential recovery backoff.
    pub max_backoff_ticks: u64,
    /// Maximum ticks from replacement start to a ready notification.
    pub replacement_timeout_ticks: u64,
    /// Maximum effects adopted during one recovery activation.
    pub max_adoptions_per_recovery: u32,
}

impl SupervisorPolicy {
    /// Returns whether every policy bound is nonzero and internally ordered.
    pub const fn is_valid(self) -> bool {
        self.max_recovery_attempts != 0
            && self.initial_backoff_ticks != 0
            && self.max_backoff_ticks >= self.initial_backoff_ticks
            && self.replacement_timeout_ticks != 0
            && self.max_adoptions_per_recovery != 0
    }
}

/// Exact identity of one crash-frozen recovery cohort.
///
/// The digest is opaque to the manager. A backend adapter must derive it from
/// the ordered, immutable identities of every member in the cohort. Reusing a
/// digest for a different cohort violates [`crate::SupervisorBackend`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CohortIdentity {
    len: u32,
    digest: [u8; 32],
}

impl CohortIdentity {
    /// Constructs an exact cohort identity from its cardinality and digest.
    pub const fn new(len: u32, digest: [u8; 32]) -> Self {
        Self { len, digest }
    }

    /// Returns the exact cohort cardinality.
    pub const fn len(self) -> u32 {
        self.len
    }

    /// Returns whether the exact cohort is empty.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns the backend-defined exact cohort digest.
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

/// Registry observation produced when an active supervisor is fenced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrashObservation {
    /// Binding epoch presented by the service that was fenced.
    pub previous_binding_epoch: u64,
    /// Fresh binding epoch with no active supervisor.
    pub crashed_binding_epoch: u64,
    /// Exact identity of the live effects frozen into recovery.
    pub cohort: CohortIdentity,
}

/// Opaque backend snapshot plus the exact cohort identity it captured.
pub struct RecoverySnapshot<S> {
    value: S,
    cohort: CohortIdentity,
}

impl<S> RecoverySnapshot<S> {
    /// Binds an opaque snapshot to its exact frozen cohort identity.
    pub const fn new(value: S, cohort: CohortIdentity) -> Self {
        Self { value, cohort }
    }

    /// Returns the exact captured cohort identity.
    pub const fn cohort(&self) -> CohortIdentity {
        self.cohort
    }

    /// Returns the exact captured cohort cardinality.
    pub const fn cohort_len(&self) -> u32 {
        self.cohort.len()
    }

    /// Borrows the opaque backend snapshot.
    pub const fn value(&self) -> &S {
        &self.value
    }

    /// Consumes the envelope and returns the opaque backend snapshot.
    pub fn into_value(self) -> S {
        self.value
    }
}

/// Registry observation produced after a replacement rebinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RebindObservation {
    /// Binding epoch now owned by the replacement.
    pub binding_epoch: u64,
    /// Exact replacement that became the active supervisor.
    pub supervisor: ServiceIdentity,
}

/// Backend operations whose failures are surfaced with stable context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendStage {
    /// Fence the previously active service.
    Crash,
    /// Select a fresh replacement identity.
    SelectReplacement,
    /// Construct and enqueue a replacement task.
    Spawn,
    /// Capture the exact Registry recovery cohort.
    Snapshot,
    /// Stop a not-yet-active replacement.
    StopReplacement,
    /// Abandon a snapshot/Ready attempt while retaining its frozen cohort.
    AbortRecoveryAttempt,
    /// Validate the replacement's ready proof against its snapshot.
    Ready,
    /// Bind the replacement to the crashed binding epoch.
    Rebind,
    /// Peek at the next unadopted recovery member.
    PeekRecoveryItem,
    /// Adopt one exact recovery member.
    Adopt,
    /// Fence a replacement after a partial recovery failure.
    FenceRecovery,
}

/// Stable manager phase exposed to health and operator projections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorPhase {
    /// One service incarnation is active.
    Running,
    /// Recovery is waiting for the bounded restart backoff.
    Backoff,
    /// A replacement exists and must report Ready before its deadline.
    AwaitingReady,
    /// The recovery-attempt budget or a nonrecoverable invariant was exhausted.
    Quarantined,
}

/// Read-only manager health projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisorHealth {
    /// Current lifecycle phase.
    pub phase: SupervisorPhase,
    /// Active, failed, or pending service identity.
    pub service: ServiceIdentity,
    /// Last exact Registry binding epoch, or `None` after an invalid observation.
    pub binding_epoch: Option<u64>,
    /// Recovery attempts consumed so far.
    pub recovery_attempts: u32,
    /// Deadline or backoff wake tick, when the phase has one.
    pub deadline_tick: Option<u64>,
    /// Last observed exit reason, if recovery has begun.
    pub last_exit: Option<ExitReason>,
}

/// Progress made by a manager poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PollProgress {
    /// No deadline or backoff boundary was reached.
    Idle,
    /// A replacement was started and now has a Ready deadline.
    ReplacementStarted {
        /// Exact replacement identity.
        replacement: ServiceIdentity,
        /// Inclusive Ready deadline.
        deadline_tick: u64,
    },
    /// A replacement missed its Ready deadline and another attempt was scheduled.
    ReplacementTimedOut {
        /// Replacement that was stopped.
        replacement: ServiceIdentity,
        /// Tick at which the next attempt may start.
        retry_tick: u64,
    },
    /// The bounded recovery-attempt budget is exhausted.
    Quarantined,
}

/// Successful replacement activation and adoption summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryCompletion {
    /// Replacement that became active.
    pub replacement: ServiceIdentity,
    /// Binding epoch owned by the replacement.
    pub binding_epoch: u64,
    /// Number of explicitly adopted effects.
    pub adopted: u32,
    /// Recovery attempt which completed recovery.
    pub attempt: u32,
}

/// Typed manager failure.
#[derive(Debug, Eq, PartialEq)]
pub enum SupervisorError<E> {
    /// The supplied manager policy or initial identity is invalid.
    InvalidConfiguration,
    /// An event names an incarnation other than the exact pending one.
    StaleServiceEvent,
    /// The exact replacement reported Ready after its inclusive deadline.
    ReadyDeadlineExpired,
    /// Time moved backwards relative to a prior manager call.
    TimeWentBackwards,
    /// A tick, attempt, or adoption counter would overflow.
    CounterOverflow,
    /// A backend returned an identity, epoch, or cohort inconsistent with the request.
    InvalidBackendObservation,
    /// One backend operation failed at the named stage.
    Backend {
        /// Operation which failed.
        stage: BackendStage,
        /// Backend-specific failure.
        source: E,
    },
    /// The backend exposed more recovery members than the configured bound.
    RecoveryLimitExceeded,
    /// The manager is quarantined and accepts no further lifecycle mutation.
    Quarantined,
}
