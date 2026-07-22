//! Executable oracle for a post-backend, pre-publication service crash.
//!
//! The model follows the production order exactly: the service crosses the
//! compound commit, kernel backend closure terminalizes the six-effect cohort
//! and leaves one `AwaitingPublication` ticket, and only then does the service
//! crash.  That crash does not call the Registry and therefore does not alter
//! the retained causal identity.  A fresh task contributes only a descriptive
//! closure trigger.  The stored ticket and causal identity remain the sole
//! authority for publication and exact outer-ack retry.

/// Number of effects in the bounded production read.
pub const EFFECT_COUNT: usize = 6;
/// Number of independently conserved credit classes.
pub const CREDIT_CLASS_COUNT: usize = 6;

const PENDING_PUBLICATION_CREDITS: [u64; CREDIT_CLASS_COUNT] = [1, 0, 0, 0, 0, 1];

/// Stable root identity for this bounded successor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RootId(u64);

impl RootId {
    /// Constructs a root identity.
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

/// Stable identity of a filesystem service task.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServiceId(u64);

impl ServiceId {
    /// Constructs a service identity.
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

/// Fixed effects in the compound production read.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EffectKind {
    /// Personality-owned syscall and one-shot guest reply.
    FilesystemSyscall,
    /// Filesystem-owned logical read.
    FilesystemRead,
    /// Published VirtIO block request.
    BlockRequest,
    /// First queue DMA owner.
    DmaQueueOwnerA,
    /// Second queue DMA owner.
    DmaQueueOwnerB,
    /// Request-buffer DMA owner.
    DmaRequestOwner,
}

impl EffectKind {
    /// Complete deterministic effect set.
    pub const ALL: [Self; EFFECT_COUNT] = [
        Self::FilesystemSyscall,
        Self::FilesystemRead,
        Self::BlockRequest,
        Self::DmaQueueOwnerA,
        Self::DmaQueueOwnerB,
        Self::DmaRequestOwner,
    ];
}

/// Typed credits held by the compound production read.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CreditClass {
    /// Root/control continuation credit.
    Control,
    /// Filesystem-operation credit.
    FilesystemOperation,
    /// VirtIO queue-slot credit.
    QueueSlot,
    /// Pinned-page credits for all DMA owners.
    PinnedPage,
    /// IOMMU mapping credits for all DMA owners.
    DmaMapping,
    /// One-shot guest-publication credit.
    GuestReply,
}

impl CreditClass {
    /// Complete deterministic credit-class set.
    pub const ALL: [Self; CREDIT_CLASS_COUNT] = [
        Self::Control,
        Self::FilesystemOperation,
        Self::QueueSlot,
        Self::PinnedPage,
        Self::DmaMapping,
        Self::GuestReply,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    /// Returns the fixed capacity of this bounded read.
    #[must_use]
    pub const fn capacity(self) -> u64 {
        match self {
            Self::PinnedPage | Self::DmaMapping => 3,
            Self::Control | Self::FilesystemOperation | Self::QueueSlot | Self::GuestReply => 1,
        }
    }
}

/// Root lifecycle around backend terminalization and outer acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootPhase {
    /// The compound commit has not started Registry closure.
    Active,
    /// Backend terminalization staged one publication and fenced old authority.
    Closing,
    /// The exact publication was acknowledged and closure completed.
    Revoked,
}

/// Effect lifecycle in this bounded post-commit successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectPhase {
    /// Ready to cross the compound commit gate.
    Prepared,
    /// Irreversibly committed but not yet terminalized by backend closure.
    Committed,
    /// Terminal exactly once, possibly with publication still pending.
    Completed,
}

/// Principal that owns the compound obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObligationOwner {
    /// The service owns the still-reversible prepared cohort.
    Service,
    /// The kernel owns committed backend closure and publication.
    Kernel,
    /// Exact publication closure consumed the obligation.
    None,
}

/// Production backend flight phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendPhase {
    /// No compound commit has crossed its irreversible point.
    Prepared,
    /// The commit crossed, but backend/device closure has not terminalized it.
    Committed,
    /// All effects are terminal and one exact publication remains pending.
    AwaitingPublication,
    /// Outer acknowledgement completed publication and root closure.
    Complete,
}

/// Lifecycle of the retained causal publication identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CausalIdentityPhase {
    /// The identity can begin its one publication attempt.
    Active,
    /// Publication began; only exact acknowledgement or retry may continue it.
    Closed,
    /// Successful outer acknowledgement consumed the identity.
    Vacant,
}

/// Result made durable by backend/device closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendOutcome {
    /// The bounded read completed with valid data.
    Data,
}

/// Opaque service authority captured before the compound commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceAuthority {
    root: RootId,
    service: ServiceId,
    authority_epoch: u64,
    binding_epoch: u64,
}

impl ServiceAuthority {
    /// Returns the root named by this authority.
    #[must_use]
    pub const fn root(self) -> RootId {
        self.root
    }

    /// Returns the service named by this authority.
    #[must_use]
    pub const fn service(self) -> ServiceId {
        self.service
    }

    /// Returns the captured root-authority epoch.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the captured service binding epoch.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    /// Substitutes a root for negative testing.
    #[must_use]
    pub const fn with_root(mut self, root: RootId) -> Self {
        self.root = root;
        self
    }

    /// Substitutes a service for negative testing.
    #[must_use]
    pub const fn with_service(mut self, service: ServiceId) -> Self {
        self.service = service;
        self
    }

    /// Substitutes an authority epoch for negative testing.
    #[must_use]
    pub const fn with_authority_epoch(mut self, authority_epoch: u64) -> Self {
        self.authority_epoch = authority_epoch;
        self
    }

    /// Substitutes a binding epoch for negative testing.
    #[must_use]
    pub const fn with_binding_epoch(mut self, binding_epoch: u64) -> Self {
        self.binding_epoch = binding_epoch;
        self
    }
}

/// Immutable receipt for the one compound device commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    root: RootId,
    service: ServiceId,
    authority_epoch: u64,
    binding_epoch: u64,
    sequence: u64,
    effects: usize,
}

impl CommitReceipt {
    /// Returns the committed root.
    #[must_use]
    pub const fn root(self) -> RootId {
        self.root
    }

    /// Returns the service that crossed the commit point.
    #[must_use]
    pub const fn service(self) -> ServiceId {
        self.service
    }

    /// Returns the authority epoch accepted at commit.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the binding epoch accepted at commit.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    /// Returns the registry-local commit sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the exact committed cohort size.
    #[must_use]
    pub const fn effects(self) -> usize {
        self.effects
    }
}

/// Receipt that the real service crashed after backend terminalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrashReceipt {
    root: RootId,
    service: ServiceId,
    authority_epoch: u64,
    binding_epoch: u64,
}

impl CrashReceipt {
    /// Returns the affected root.
    #[must_use]
    pub const fn root(self) -> RootId {
        self.root
    }

    /// Returns the crashed service.
    #[must_use]
    pub const fn service(self) -> ServiceId {
        self.service
    }

    /// Returns the pre-closure authority epoch held by the crashed task.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the crashed service binding epoch.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }
}

/// Exact pending publication produced by backend terminalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationTicket {
    root: RootId,
    closing_authority_epoch: u64,
    commit_sequence: u64,
    ticket_sequence: u64,
    terminalizations: u64,
    outcome: BackendOutcome,
}

impl PublicationTicket {
    /// Returns the affected root.
    #[must_use]
    pub const fn root(self) -> RootId {
        self.root
    }

    /// Returns the authority epoch created by Registry closure.
    #[must_use]
    pub const fn closing_authority_epoch(self) -> u64 {
        self.closing_authority_epoch
    }

    /// Returns the causal compound-commit sequence.
    #[must_use]
    pub const fn commit_sequence(self) -> u64 {
        self.commit_sequence
    }

    /// Returns the publication-ticket sequence.
    #[must_use]
    pub const fn ticket_sequence(self) -> u64 {
        self.ticket_sequence
    }

    /// Returns the terminalization count frozen into the ticket.
    #[must_use]
    pub const fn terminalizations(self) -> u64 {
        self.terminalizations
    }

    /// Returns the backend outcome awaiting publication.
    #[must_use]
    pub const fn outcome(self) -> BackendOutcome {
        self.outcome
    }

    /// Substitutes the ticket sequence for negative testing.
    #[must_use]
    pub const fn with_ticket_sequence(mut self, ticket_sequence: u64) -> Self {
        self.ticket_sequence = ticket_sequence;
        self
    }
}

/// Descriptive wake-up supplied by a fresh closure-only task.
///
/// The trigger intentionally contains no root, authority epoch, binding epoch,
/// handle, Registry instance, or publication ticket.  It cannot authorize a
/// Registry transition; it only lets the retained owner begin publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosureTrigger {
    service: ServiceId,
    sequence: u64,
}

impl ClosureTrigger {
    /// Returns the fresh task that supplied the trigger.
    #[must_use]
    pub const fn service(self) -> ServiceId {
        self.service
    }

    /// Returns the model-local trigger sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Reports the deliberate absence of Registry authority.
    #[must_use]
    pub const fn has_registry_authority(self) -> bool {
        false
    }

    /// Substitutes a service for negative testing.
    #[must_use]
    pub const fn with_service(mut self, service: ServiceId) -> Self {
        self.service = service;
        self
    }
}

/// One in-progress publication attempt owned by the retained identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationAttempt {
    ticket: PublicationTicket,
    trigger: ClosureTrigger,
    attempt_sequence: u64,
    retry_generation: u64,
}

impl PublicationAttempt {
    /// Returns the exact unchanged publication ticket.
    #[must_use]
    pub const fn ticket(self) -> PublicationTicket {
        self.ticket
    }

    /// Returns the closure-only trigger which started publication.
    #[must_use]
    pub const fn trigger(self) -> ClosureTrigger {
        self.trigger
    }

    /// Returns the model-local attempt sequence.
    #[must_use]
    pub const fn attempt_sequence(self) -> u64 {
        self.attempt_sequence
    }

    /// Returns the exact retry generation.
    #[must_use]
    pub const fn retry_generation(self) -> u64 {
        self.retry_generation
    }

    /// Substitutes the attempt sequence for negative testing.
    #[must_use]
    pub const fn with_attempt_sequence(mut self, attempt_sequence: u64) -> Self {
        self.attempt_sequence = attempt_sequence;
        self
    }
}

/// Exact retry bearer retained after an outer acknowledgement failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationRetry {
    ticket: PublicationTicket,
    trigger: ClosureTrigger,
    failed_attempt_sequence: u64,
    retry_generation: u64,
}

impl PublicationRetry {
    /// Returns the unchanged publication ticket.
    #[must_use]
    pub const fn ticket(self) -> PublicationTicket {
        self.ticket
    }

    /// Returns the closure-only trigger retained with the ticket.
    #[must_use]
    pub const fn trigger(self) -> ClosureTrigger {
        self.trigger
    }

    /// Returns the exact failed attempt sequence.
    #[must_use]
    pub const fn failed_attempt_sequence(self) -> u64 {
        self.failed_attempt_sequence
    }

    /// Returns the retry generation.
    #[must_use]
    pub const fn retry_generation(self) -> u64 {
        self.retry_generation
    }

    /// Substitutes the retry generation for negative testing.
    #[must_use]
    pub const fn with_retry_generation(mut self, retry_generation: u64) -> Self {
        self.retry_generation = retry_generation;
        self
    }
}

/// Proof that the exact publication attempt received its outer acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationReceipt {
    ticket: PublicationTicket,
    attempt_sequence: u64,
    acknowledgement_sequence: u64,
}

impl PublicationReceipt {
    /// Returns the exact acknowledged ticket.
    #[must_use]
    pub const fn ticket(self) -> PublicationTicket {
        self.ticket
    }

    /// Returns the successful attempt sequence.
    #[must_use]
    pub const fn attempt_sequence(self) -> u64 {
        self.attempt_sequence
    }

    /// Returns the acknowledgement sequence.
    #[must_use]
    pub const fn acknowledgement_sequence(self) -> u64 {
        self.acknowledgement_sequence
    }
}

/// Exact proof that publication acknowledgement also closed the root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosureReceipt {
    root: RootId,
    authority_epoch: u64,
    commit_sequence: u64,
    acknowledgement_sequence: u64,
    closure_sequence: u64,
    terminalizations: u64,
}

impl ClosureReceipt {
    /// Returns the closed root.
    #[must_use]
    pub const fn root(self) -> RootId {
        self.root
    }

    /// Returns the closed authority epoch.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the causal commit sequence.
    #[must_use]
    pub const fn commit_sequence(self) -> u64 {
        self.commit_sequence
    }

    /// Returns the consumed outer acknowledgement sequence.
    #[must_use]
    pub const fn acknowledgement_sequence(self) -> u64 {
        self.acknowledgement_sequence
    }

    /// Returns the closure sequence.
    #[must_use]
    pub const fn closure_sequence(self) -> u64 {
        self.closure_sequence
    }

    /// Returns the exact terminalization count at closure.
    #[must_use]
    pub const fn terminalizations(self) -> u64 {
        self.terminalizations
    }
}

/// Typed-credit projection for the bounded compound close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreditProjection {
    /// Fixed capacity by class.
    pub capacity: [u64; CREDIT_CLASS_COUNT],
    /// Capacity never reserved by this bounded cohort.
    pub free: [u64; CREDIT_CLASS_COUNT],
    /// Credits owned by prepared effects.
    pub held: [u64; CREDIT_CLASS_COUNT],
    /// Credits retained by committed work or a pending publication.
    pub committed: [u64; CREDIT_CLASS_COUNT],
    /// Credits released by terminal stages.
    pub returned: [u64; CREDIT_CLASS_COUNT],
}

impl CreditProjection {
    /// Maps the oracle's historical returned bucket to Registry free credits.
    #[must_use]
    pub fn registry_free(self) -> [u64; CREDIT_CLASS_COUNT] {
        core::array::from_fn(|index| self.free[index] + self.returned[index])
    }
}

/// Stable projection of one effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectProjection {
    /// Fixed operation identity.
    pub effect: EffectKind,
    /// Current lifecycle phase.
    pub phase: EffectPhase,
    /// Number of successful terminal transitions.
    pub terminalizations: u8,
}

/// Successful transition counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransitionCounters {
    /// Successful compound commits.
    pub commits: u64,
    /// Successful kernel backend/device terminalizations.
    pub backend_closures: u64,
    /// Total effect terminalizations.
    pub terminalizations: u64,
    /// Observed real service crashes.
    pub crashes: u64,
    /// Fresh closure-only triggers issued.
    pub closure_triggers: u64,
    /// Publication attempts, including exact retries.
    pub publication_attempts: u64,
    /// Failed outer acknowledgements retained for exact retry.
    pub outer_ack_failures: u64,
    /// Successful outer acknowledgements.
    pub publication_acks: u64,
    /// Externally visible guest replies.
    pub guest_replies: u64,
    /// Successful root closures.
    pub closures: u64,
}

/// Complete semantic projection for failure-atomic comparisons.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostcommitProjection {
    /// Stable root identity.
    pub root: RootId,
    /// Root lifecycle.
    pub root_phase: RootPhase,
    /// Current root authority epoch.
    pub authority_epoch: u64,
    /// Unchanged service binding epoch.
    pub binding_epoch: u64,
    /// Original service binding, retained until final closure.
    pub bound_service: Option<ServiceId>,
    /// Current owner of the compound obligation.
    pub obligation_owner: ObligationOwner,
    /// Backend/device flight phase.
    pub backend_phase: BackendPhase,
    /// Retained causal publication identity phase.
    pub causal_identity_phase: CausalIdentityPhase,
    /// Whether the post-backend service crash was observed.
    pub service_crashed: bool,
    /// Recovery records; fixed at zero in this profile.
    pub recovery_records: usize,
    /// Adoptions; fixed at zero in this profile.
    pub adoptions: u64,
    /// Rebinds; fixed at zero in this profile.
    pub rebinds: u64,
    /// Descriptive fresh-task trigger, if issued.
    pub closure_trigger: Option<ClosureTrigger>,
    /// Exact six-effect state.
    pub effects: [EffectProjection; EFFECT_COUNT],
    /// Typed-credit state.
    pub credits: CreditProjection,
    /// Compound commit receipt, if committed.
    pub commit: Option<CommitReceipt>,
    /// One unacknowledged publication ticket.
    pub pending_publication: Option<PublicationTicket>,
    /// Number of pending publications.
    pub pending_publications: usize,
    /// One currently executing publication attempt.
    pub active_attempt: Option<PublicationAttempt>,
    /// Exact retry retained after an outer-ack failure.
    pub pending_retry: Option<PublicationRetry>,
    /// Acknowledged publication receipt.
    pub publication: Option<PublicationReceipt>,
    /// Final closure receipt.
    pub closure: Option<ClosureReceipt>,
    /// Successful transition counters.
    pub counters: TransitionCounters,
}

/// Rejected transition in the post-commit oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostcommitError {
    /// The authority names another root.
    WrongRoot,
    /// The authority names another service.
    WrongService,
    /// The root-authority epoch was fenced.
    StaleAuthority,
    /// The service binding epoch is stale.
    StaleBinding,
    /// The root is in the wrong lifecycle phase.
    InvalidRootPhase,
    /// The immutable compound commit receipt is invalid.
    InvalidCommitReceipt,
    /// The compound commit was already accepted.
    AlreadyCommitted,
    /// Backend terminalization already happened.
    AlreadyTerminalized,
    /// Backend terminalization has not produced `AwaitingPublication`.
    BackendNotTerminalized,
    /// The service crash was already observed.
    CrashAlreadyObserved,
    /// Only retained kernel publication authority may advance post-commit work.
    KernelObligationRequired,
    /// A closure-only trigger cannot be issued before the real crash.
    TriggerBeforeCrash,
    /// The trigger task must be distinct from the crashed service.
    FreshTriggerRequired,
    /// A closure-only trigger was already issued.
    TriggerAlreadyIssued,
    /// The supplied closure trigger is stale or substituted.
    InvalidClosureTrigger,
    /// A publication attempt is already in progress.
    PublicationAttemptInFlight,
    /// The supplied publication attempt is stale or substituted.
    InvalidPublicationAttempt,
    /// The supplied retry bearer is stale or substituted.
    InvalidPublicationRetry,
    /// No failed outer acknowledgement is pending.
    RetryNotPending,
    /// The exact publication was already acknowledged.
    AlreadyAcknowledged,
    /// A monotonic counter overflowed.
    CounterOverflow,
    /// The candidate transition failed a full invariant audit.
    InvariantViolation,
}

/// Invariant failure in the post-commit oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostcommitInvariant {
    /// Root phase, backend phase, and obligation ownership disagree.
    RootLifecycle,
    /// Effect phase and terminalization counts disagree.
    EffectLifecycle,
    /// Typed credits were copied, released early, or lost.
    CreditConservation,
    /// Commit identity or sequence fields disagree.
    CommitReceipt,
    /// Crash state accidentally changed Registry authority topology.
    CrashIsolation,
    /// Causal identity, trigger, attempt, and retry state disagree.
    CausalIdentity,
    /// Pending publication, acknowledgement, and counters disagree.
    Publication,
    /// Closure was issued before exact quiescence.
    Closure,
    /// A monotonic sequence could be reused.
    Allocator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectRecord {
    effect: EffectKind,
    phase: EffectPhase,
    terminalizations: u8,
}

/// Independent bounded state machine for one post-backend service crash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionIdentityPostcommitModel {
    root: RootId,
    root_phase: RootPhase,
    authority_epoch: u64,
    binding_epoch: u64,
    original_service: ServiceId,
    bound_service: Option<ServiceId>,
    obligation_owner: ObligationOwner,
    backend_phase: BackendPhase,
    causal_identity_phase: CausalIdentityPhase,
    service_crashed: bool,
    closure_trigger: Option<ClosureTrigger>,
    effects: [EffectRecord; EFFECT_COUNT],
    credits: CreditProjection,
    commit: Option<CommitReceipt>,
    pending_publication: Option<PublicationTicket>,
    active_attempt: Option<PublicationAttempt>,
    pending_retry: Option<PublicationRetry>,
    publication: Option<PublicationReceipt>,
    closure: Option<ClosureReceipt>,
    counters: TransitionCounters,
    next_commit_sequence: u64,
    next_ticket_sequence: u64,
    next_trigger_sequence: u64,
    next_attempt_sequence: u64,
    next_acknowledgement_sequence: u64,
    next_closure_sequence: u64,
}

impl ProductionIdentityPostcommitModel {
    /// Creates one prepared six-effect cohort owned by the filesystem service.
    #[must_use]
    pub fn new(root: RootId, service: ServiceId) -> Self {
        let capacity = core::array::from_fn(|index| CreditClass::ALL[index].capacity());
        let model = Self {
            root,
            root_phase: RootPhase::Active,
            authority_epoch: 1,
            binding_epoch: 1,
            original_service: service,
            bound_service: Some(service),
            obligation_owner: ObligationOwner::Service,
            backend_phase: BackendPhase::Prepared,
            causal_identity_phase: CausalIdentityPhase::Active,
            service_crashed: false,
            closure_trigger: None,
            effects: core::array::from_fn(|index| EffectRecord {
                effect: EffectKind::ALL[index],
                phase: EffectPhase::Prepared,
                terminalizations: 0,
            }),
            credits: CreditProjection {
                capacity,
                free: [0; CREDIT_CLASS_COUNT],
                held: capacity,
                committed: [0; CREDIT_CLASS_COUNT],
                returned: [0; CREDIT_CLASS_COUNT],
            },
            commit: None,
            pending_publication: None,
            active_attempt: None,
            pending_retry: None,
            publication: None,
            closure: None,
            counters: TransitionCounters::default(),
            next_commit_sequence: 1,
            next_ticket_sequence: 1,
            next_trigger_sequence: 1,
            next_attempt_sequence: 1,
            next_acknowledgement_sequence: 1,
            next_closure_sequence: 1,
        };
        debug_assert_eq!(model.check_invariants(), Ok(()));
        model
    }

    /// Returns the initial service authority while it can still commit.
    #[must_use]
    pub fn service_authority(&self) -> Option<ServiceAuthority> {
        (self.backend_phase == BackendPhase::Prepared).then_some(ServiceAuthority {
            root: self.root,
            service: self.original_service,
            authority_epoch: self.authority_epoch,
            binding_epoch: self.binding_epoch,
        })
    }

    /// Returns the complete semantic projection.
    #[must_use]
    pub fn projection(&self) -> PostcommitProjection {
        PostcommitProjection {
            root: self.root,
            root_phase: self.root_phase,
            authority_epoch: self.authority_epoch,
            binding_epoch: self.binding_epoch,
            bound_service: self.bound_service,
            obligation_owner: self.obligation_owner,
            backend_phase: self.backend_phase,
            causal_identity_phase: self.causal_identity_phase,
            service_crashed: self.service_crashed,
            recovery_records: 0,
            adoptions: 0,
            rebinds: 0,
            closure_trigger: self.closure_trigger,
            effects: self.effects.map(|record| EffectProjection {
                effect: record.effect,
                phase: record.phase,
                terminalizations: record.terminalizations,
            }),
            credits: self.credits,
            commit: self.commit,
            pending_publication: self.pending_publication,
            pending_publications: usize::from(self.pending_publication.is_some()),
            active_attempt: self.active_attempt,
            pending_retry: self.pending_retry,
            publication: self.publication,
            closure: self.closure,
            counters: self.counters,
        }
    }

    /// Atomically commits all six effects without closing the active root.
    pub fn commit(
        &mut self,
        authority: ServiceAuthority,
    ) -> Result<CommitReceipt, PostcommitError> {
        self.transact(|next| next.commit_inner(authority))
    }

    /// Terminalizes backend/device work exactly once and stages publication.
    pub fn terminalize_backend(
        &mut self,
        commit: CommitReceipt,
    ) -> Result<PublicationTicket, PostcommitError> {
        self.transact(|next| next.terminalize_backend_inner(commit))
    }

    /// Records the later real service crash without a Registry transition.
    pub fn observe_service_crash(
        &mut self,
        authority: ServiceAuthority,
    ) -> Result<CrashReceipt, PostcommitError> {
        self.transact(|next| next.observe_service_crash_inner(authority))
    }

    /// Attempts a service-owned publication and proves old authority is fenced.
    pub fn publish_from_service(
        &mut self,
        authority: ServiceAuthority,
    ) -> Result<(), PostcommitError> {
        self.transact(|next| {
            next.validate_service_coordinates(authority)?;
            if authority.authority_epoch != next.authority_epoch {
                return Err(PostcommitError::StaleAuthority);
            }
            Err(PostcommitError::KernelObligationRequired)
        })
    }

    /// Issues one descriptive trigger to a distinct fresh closure-only task.
    pub fn issue_closure_trigger(
        &mut self,
        fresh_service: ServiceId,
    ) -> Result<ClosureTrigger, PostcommitError> {
        self.transact(|next| next.issue_closure_trigger_inner(fresh_service))
    }

    /// Begins publication, consuming `Active` into `Closed` before outer ACK.
    pub fn begin_publication(
        &mut self,
        trigger: ClosureTrigger,
    ) -> Result<PublicationAttempt, PostcommitError> {
        self.transact(|next| next.begin_publication_inner(trigger))
    }

    /// Retains the exact ticket and retry bearer after an outer-ack failure.
    pub fn fail_outer_ack(
        &mut self,
        attempt: PublicationAttempt,
    ) -> Result<PublicationRetry, PostcommitError> {
        self.transact(|next| next.fail_outer_ack_inner(attempt))
    }

    /// Starts another attempt from the exact retained retry bearer.
    pub fn retry_publication(
        &mut self,
        retry: PublicationRetry,
    ) -> Result<PublicationAttempt, PostcommitError> {
        self.transact(|next| next.retry_publication_inner(retry))
    }

    /// Applies a successful outer ACK and atomically reaches `Vacant` closure.
    pub fn acknowledge_outer_publication(
        &mut self,
        attempt: PublicationAttempt,
    ) -> Result<PublicationReceipt, PostcommitError> {
        self.transact(|next| next.acknowledge_outer_publication_inner(attempt))
    }

    fn transact<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, PostcommitError>,
    ) -> Result<T, PostcommitError> {
        let mut candidate = self.clone();
        let result = operation(&mut candidate)?;
        candidate
            .check_invariants()
            .map_err(|_| PostcommitError::InvariantViolation)?;
        *self = candidate;
        Ok(result)
    }

    fn allocate(counter: &mut u64) -> Result<u64, PostcommitError> {
        let value = *counter;
        *counter = counter
            .checked_add(1)
            .ok_or(PostcommitError::CounterOverflow)?;
        Ok(value)
    }

    fn increment(counter: &mut u64, units: u64) -> Result<(), PostcommitError> {
        *counter = counter
            .checked_add(units)
            .ok_or(PostcommitError::CounterOverflow)?;
        Ok(())
    }

    fn validate_service_coordinates(
        &self,
        authority: ServiceAuthority,
    ) -> Result<(), PostcommitError> {
        if authority.root != self.root {
            return Err(PostcommitError::WrongRoot);
        }
        if authority.binding_epoch != self.binding_epoch {
            return Err(PostcommitError::StaleBinding);
        }
        if authority.service != self.original_service {
            return Err(PostcommitError::WrongService);
        }
        Ok(())
    }

    fn validate_current_service_authority(
        &self,
        authority: ServiceAuthority,
    ) -> Result<(), PostcommitError> {
        self.validate_service_coordinates(authority)?;
        if authority.authority_epoch != self.authority_epoch {
            return Err(PostcommitError::StaleAuthority);
        }
        if self.root_phase != RootPhase::Active || self.bound_service != Some(authority.service) {
            return Err(PostcommitError::InvalidRootPhase);
        }
        Ok(())
    }

    fn validate_crashed_service_authority(
        &self,
        authority: ServiceAuthority,
    ) -> Result<(), PostcommitError> {
        self.validate_service_coordinates(authority)?;
        let commit = self.commit.ok_or(PostcommitError::InvalidCommitReceipt)?;
        if authority.authority_epoch != commit.authority_epoch {
            return Err(PostcommitError::StaleAuthority);
        }
        Ok(())
    }

    fn validate_commit(&self, commit: CommitReceipt) -> Result<(), PostcommitError> {
        if self.commit != Some(commit) {
            return Err(PostcommitError::InvalidCommitReceipt);
        }
        Ok(())
    }

    fn commit_inner(
        &mut self,
        authority: ServiceAuthority,
    ) -> Result<CommitReceipt, PostcommitError> {
        if self.commit.is_some() {
            return Err(PostcommitError::AlreadyCommitted);
        }
        self.validate_current_service_authority(authority)?;
        if self.backend_phase != BackendPhase::Prepared
            || self.obligation_owner != ObligationOwner::Service
            || self
                .effects
                .iter()
                .any(|effect| effect.phase != EffectPhase::Prepared || effect.terminalizations != 0)
        {
            return Err(PostcommitError::InvalidRootPhase);
        }
        let receipt = CommitReceipt {
            root: self.root,
            service: authority.service,
            authority_epoch: authority.authority_epoch,
            binding_epoch: authority.binding_epoch,
            sequence: Self::allocate(&mut self.next_commit_sequence)?,
            effects: EFFECT_COUNT,
        };
        for effect in &mut self.effects {
            effect.phase = EffectPhase::Committed;
        }
        self.credits.committed = self.credits.held;
        self.credits.held = [0; CREDIT_CLASS_COUNT];
        self.obligation_owner = ObligationOwner::Kernel;
        self.backend_phase = BackendPhase::Committed;
        self.commit = Some(receipt);
        Self::increment(&mut self.counters.commits, 1)?;
        Ok(receipt)
    }

    fn terminalize_backend_inner(
        &mut self,
        commit: CommitReceipt,
    ) -> Result<PublicationTicket, PostcommitError> {
        self.validate_commit(commit)?;
        if matches!(
            self.backend_phase,
            BackendPhase::AwaitingPublication | BackendPhase::Complete
        ) {
            return Err(PostcommitError::AlreadyTerminalized);
        }
        if self.backend_phase != BackendPhase::Committed
            || self.root_phase != RootPhase::Active
            || self.obligation_owner != ObligationOwner::Kernel
            || self.effects.iter().any(|effect| {
                effect.phase != EffectPhase::Committed || effect.terminalizations != 0
            })
        {
            return Err(PostcommitError::BackendNotTerminalized);
        }
        let closing_authority_epoch = self
            .authority_epoch
            .checked_add(1)
            .ok_or(PostcommitError::CounterOverflow)?;
        let terminalizations =
            u64::try_from(EFFECT_COUNT).map_err(|_| PostcommitError::CounterOverflow)?;
        let ticket = PublicationTicket {
            root: self.root,
            closing_authority_epoch,
            commit_sequence: commit.sequence,
            ticket_sequence: Self::allocate(&mut self.next_ticket_sequence)?,
            terminalizations,
            outcome: BackendOutcome::Data,
        };
        for effect in &mut self.effects {
            effect.phase = EffectPhase::Completed;
            effect.terminalizations = 1;
        }
        self.credits.returned = core::array::from_fn(|index| {
            self.credits.capacity[index] - PENDING_PUBLICATION_CREDITS[index]
        });
        self.credits.committed = PENDING_PUBLICATION_CREDITS;
        self.root_phase = RootPhase::Closing;
        self.authority_epoch = closing_authority_epoch;
        self.backend_phase = BackendPhase::AwaitingPublication;
        self.pending_publication = Some(ticket);
        Self::increment(&mut self.counters.backend_closures, 1)?;
        Self::increment(&mut self.counters.terminalizations, terminalizations)?;
        Ok(ticket)
    }

    fn observe_service_crash_inner(
        &mut self,
        authority: ServiceAuthority,
    ) -> Result<CrashReceipt, PostcommitError> {
        if self.backend_phase != BackendPhase::AwaitingPublication
            || self.root_phase != RootPhase::Closing
        {
            return Err(PostcommitError::BackendNotTerminalized);
        }
        self.validate_crashed_service_authority(authority)?;
        if self.service_crashed {
            return Err(PostcommitError::CrashAlreadyObserved);
        }
        self.service_crashed = true;
        Self::increment(&mut self.counters.crashes, 1)?;
        Ok(CrashReceipt {
            root: self.root,
            service: authority.service,
            authority_epoch: authority.authority_epoch,
            binding_epoch: authority.binding_epoch,
        })
    }

    fn issue_closure_trigger_inner(
        &mut self,
        fresh_service: ServiceId,
    ) -> Result<ClosureTrigger, PostcommitError> {
        if !self.service_crashed {
            return Err(PostcommitError::TriggerBeforeCrash);
        }
        if fresh_service == self.original_service {
            return Err(PostcommitError::FreshTriggerRequired);
        }
        if self.closure_trigger.is_some() {
            return Err(PostcommitError::TriggerAlreadyIssued);
        }
        if self.backend_phase != BackendPhase::AwaitingPublication
            || self.causal_identity_phase != CausalIdentityPhase::Active
        {
            return Err(PostcommitError::InvalidRootPhase);
        }
        let trigger = ClosureTrigger {
            service: fresh_service,
            sequence: Self::allocate(&mut self.next_trigger_sequence)?,
        };
        self.closure_trigger = Some(trigger);
        Self::increment(&mut self.counters.closure_triggers, 1)?;
        Ok(trigger)
    }

    fn begin_publication_inner(
        &mut self,
        trigger: ClosureTrigger,
    ) -> Result<PublicationAttempt, PostcommitError> {
        if self.publication.is_some() {
            return Err(PostcommitError::AlreadyAcknowledged);
        }
        if self.closure_trigger != Some(trigger) {
            return Err(PostcommitError::InvalidClosureTrigger);
        }
        if self.active_attempt.is_some() {
            return Err(PostcommitError::PublicationAttemptInFlight);
        }
        if self.pending_retry.is_some() || self.causal_identity_phase != CausalIdentityPhase::Active
        {
            return Err(PostcommitError::RetryNotPending);
        }
        let ticket = self
            .pending_publication
            .ok_or(PostcommitError::BackendNotTerminalized)?;
        let attempt = PublicationAttempt {
            ticket,
            trigger,
            attempt_sequence: Self::allocate(&mut self.next_attempt_sequence)?,
            retry_generation: 0,
        };
        self.causal_identity_phase = CausalIdentityPhase::Closed;
        self.active_attempt = Some(attempt);
        Self::increment(&mut self.counters.publication_attempts, 1)?;
        Ok(attempt)
    }

    fn fail_outer_ack_inner(
        &mut self,
        attempt: PublicationAttempt,
    ) -> Result<PublicationRetry, PostcommitError> {
        if self.active_attempt != Some(attempt)
            || self.causal_identity_phase != CausalIdentityPhase::Closed
            || self.pending_publication != Some(attempt.ticket)
        {
            return Err(PostcommitError::InvalidPublicationAttempt);
        }
        let retry_generation = attempt
            .retry_generation
            .checked_add(1)
            .ok_or(PostcommitError::CounterOverflow)?;
        let retry = PublicationRetry {
            ticket: attempt.ticket,
            trigger: attempt.trigger,
            failed_attempt_sequence: attempt.attempt_sequence,
            retry_generation,
        };
        self.active_attempt = None;
        self.pending_retry = Some(retry);
        Self::increment(&mut self.counters.outer_ack_failures, 1)?;
        Ok(retry)
    }

    fn retry_publication_inner(
        &mut self,
        retry: PublicationRetry,
    ) -> Result<PublicationAttempt, PostcommitError> {
        if self.publication.is_some() {
            return Err(PostcommitError::AlreadyAcknowledged);
        }
        if self.pending_retry != Some(retry)
            || self.causal_identity_phase != CausalIdentityPhase::Closed
            || self.pending_publication != Some(retry.ticket)
            || self.active_attempt.is_some()
        {
            return Err(PostcommitError::InvalidPublicationRetry);
        }
        let attempt = PublicationAttempt {
            ticket: retry.ticket,
            trigger: retry.trigger,
            attempt_sequence: Self::allocate(&mut self.next_attempt_sequence)?,
            retry_generation: retry.retry_generation,
        };
        self.pending_retry = None;
        self.active_attempt = Some(attempt);
        Self::increment(&mut self.counters.publication_attempts, 1)?;
        Ok(attempt)
    }

    fn acknowledge_outer_publication_inner(
        &mut self,
        attempt: PublicationAttempt,
    ) -> Result<PublicationReceipt, PostcommitError> {
        if self.publication.is_some() {
            return Err(PostcommitError::AlreadyAcknowledged);
        }
        if self.active_attempt != Some(attempt)
            || self.causal_identity_phase != CausalIdentityPhase::Closed
            || self.pending_publication != Some(attempt.ticket)
            || self.pending_retry.is_some()
        {
            return Err(PostcommitError::InvalidPublicationAttempt);
        }
        let acknowledgement_sequence = Self::allocate(&mut self.next_acknowledgement_sequence)?;
        let closure_sequence = Self::allocate(&mut self.next_closure_sequence)?;
        let receipt = PublicationReceipt {
            ticket: attempt.ticket,
            attempt_sequence: attempt.attempt_sequence,
            acknowledgement_sequence,
        };
        let commit = self.commit.ok_or(PostcommitError::InvalidCommitReceipt)?;
        let closure = ClosureReceipt {
            root: self.root,
            authority_epoch: self.authority_epoch,
            commit_sequence: commit.sequence,
            acknowledgement_sequence,
            closure_sequence,
            terminalizations: self.counters.terminalizations,
        };
        for index in 0..CREDIT_CLASS_COUNT {
            self.credits.returned[index] = self.credits.returned[index]
                .checked_add(self.credits.committed[index])
                .ok_or(PostcommitError::CounterOverflow)?;
        }
        self.credits.committed = [0; CREDIT_CLASS_COUNT];
        self.pending_publication = None;
        self.active_attempt = None;
        self.publication = Some(receipt);
        self.closure = Some(closure);
        self.root_phase = RootPhase::Revoked;
        self.bound_service = None;
        self.obligation_owner = ObligationOwner::None;
        self.backend_phase = BackendPhase::Complete;
        self.causal_identity_phase = CausalIdentityPhase::Vacant;
        Self::increment(&mut self.counters.publication_acks, 1)?;
        Self::increment(&mut self.counters.guest_replies, 1)?;
        Self::increment(&mut self.counters.closures, 1)?;
        Ok(receipt)
    }

    /// Audits root, backend, identity, effect, credit, and allocator invariants.
    pub fn check_invariants(&self) -> Result<(), PostcommitInvariant> {
        self.check_effects()?;
        self.check_credits()?;
        self.check_commit()?;
        self.check_crash()?;
        self.check_causal_identity()?;
        self.check_publication()?;
        self.check_root()?;
        self.check_closure()?;
        self.check_allocators()?;
        Ok(())
    }

    fn check_effects(&self) -> Result<(), PostcommitInvariant> {
        let expected_phase = match self.backend_phase {
            BackendPhase::Prepared => EffectPhase::Prepared,
            BackendPhase::Committed => EffectPhase::Committed,
            BackendPhase::AwaitingPublication | BackendPhase::Complete => EffectPhase::Completed,
        };
        for (record, expected) in self.effects.iter().zip(EffectKind::ALL) {
            if record.effect != expected
                || record.phase != expected_phase
                || (record.phase == EffectPhase::Completed) != (record.terminalizations == 1)
                || record.terminalizations > 1
            {
                return Err(PostcommitInvariant::EffectLifecycle);
            }
        }
        let sum = self
            .effects
            .iter()
            .map(|effect| u64::from(effect.terminalizations))
            .sum::<u64>();
        if sum != self.counters.terminalizations || (sum != 0 && sum != EFFECT_COUNT as u64) {
            return Err(PostcommitInvariant::EffectLifecycle);
        }
        Ok(())
    }

    fn check_credits(&self) -> Result<(), PostcommitInvariant> {
        for credit in CreditClass::ALL {
            let index = credit.index();
            if self.credits.capacity[index] != credit.capacity()
                || self.credits.free[index]
                    + self.credits.held[index]
                    + self.credits.committed[index]
                    + self.credits.returned[index]
                    != credit.capacity()
            {
                return Err(PostcommitInvariant::CreditConservation);
            }
        }
        let zero = [0; CREDIT_CLASS_COUNT];
        let valid = match self.backend_phase {
            BackendPhase::Prepared => {
                self.credits.free == zero
                    && self.credits.held == self.credits.capacity
                    && self.credits.committed == zero
                    && self.credits.returned == zero
            }
            BackendPhase::Committed => {
                self.credits.free == zero
                    && self.credits.held == zero
                    && self.credits.committed == self.credits.capacity
                    && self.credits.returned == zero
            }
            BackendPhase::AwaitingPublication => {
                self.credits.free == zero
                    && self.credits.held == zero
                    && self.credits.committed == PENDING_PUBLICATION_CREDITS
                    && self.credits.returned
                        == core::array::from_fn(|index| {
                            self.credits.capacity[index] - PENDING_PUBLICATION_CREDITS[index]
                        })
            }
            BackendPhase::Complete => {
                self.credits.free == zero
                    && self.credits.held == zero
                    && self.credits.committed == zero
                    && self.credits.returned == self.credits.capacity
            }
        };
        if !valid {
            return Err(PostcommitInvariant::CreditConservation);
        }
        Ok(())
    }

    fn check_commit(&self) -> Result<(), PostcommitInvariant> {
        if self.counters.commits != u64::from(self.commit.is_some()) {
            return Err(PostcommitInvariant::CommitReceipt);
        }
        if let Some(commit) = self.commit {
            if commit.root != self.root
                || commit.service != self.original_service
                || commit.authority_epoch != 1
                || commit.binding_epoch != self.binding_epoch
                || commit.effects != EFFECT_COUNT
                || commit.sequence >= self.next_commit_sequence
                || self.backend_phase == BackendPhase::Prepared
            {
                return Err(PostcommitInvariant::CommitReceipt);
            }
        } else if self.backend_phase != BackendPhase::Prepared {
            return Err(PostcommitInvariant::CommitReceipt);
        }
        Ok(())
    }

    fn check_crash(&self) -> Result<(), PostcommitInvariant> {
        if self.counters.crashes != u64::from(self.service_crashed)
            || self.counters.crashes > 1
            || (self.service_crashed
                && !matches!(
                    self.backend_phase,
                    BackendPhase::AwaitingPublication | BackendPhase::Complete
                ))
        {
            return Err(PostcommitInvariant::CrashIsolation);
        }
        Ok(())
    }

    fn check_causal_identity(&self) -> Result<(), PostcommitInvariant> {
        if self.counters.closure_triggers != u64::from(self.closure_trigger.is_some())
            || self.counters.closure_triggers > 1
        {
            return Err(PostcommitInvariant::CausalIdentity);
        }
        if let Some(trigger) = self.closure_trigger
            && (!self.service_crashed
                || trigger.service == self.original_service
                || trigger.sequence >= self.next_trigger_sequence
                || trigger.has_registry_authority())
        {
            return Err(PostcommitInvariant::CausalIdentity);
        }
        match self.causal_identity_phase {
            CausalIdentityPhase::Active => {
                if self.active_attempt.is_some()
                    || self.pending_retry.is_some()
                    || self.publication.is_some()
                    || self.closure.is_some()
                {
                    return Err(PostcommitInvariant::CausalIdentity);
                }
            }
            CausalIdentityPhase::Closed => {
                if self.closure_trigger.is_none()
                    || self.publication.is_some()
                    || self.closure.is_some()
                    || (self.active_attempt.is_some() == self.pending_retry.is_some())
                {
                    return Err(PostcommitInvariant::CausalIdentity);
                }
            }
            CausalIdentityPhase::Vacant => {
                if self.backend_phase != BackendPhase::Complete
                    || self.active_attempt.is_some()
                    || self.pending_retry.is_some()
                    || self.publication.is_none()
                    || self.closure.is_none()
                {
                    return Err(PostcommitInvariant::CausalIdentity);
                }
            }
        }
        Ok(())
    }

    fn check_publication(&self) -> Result<(), PostcommitInvariant> {
        let pending = self.pending_publication;
        if (self.backend_phase == BackendPhase::AwaitingPublication) != pending.is_some()
            || self.counters.backend_closures
                != u64::from(matches!(
                    self.backend_phase,
                    BackendPhase::AwaitingPublication | BackendPhase::Complete
                ))
            || self.counters.publication_acks != u64::from(self.publication.is_some())
            || self.counters.guest_replies != self.counters.publication_acks
            || self.counters.publication_acks > 1
            || self.counters.outer_ack_failures > self.counters.publication_attempts
        {
            return Err(PostcommitInvariant::Publication);
        }
        let ticket = pending.or_else(|| self.publication.map(|receipt| receipt.ticket));
        if let Some(ticket) = ticket {
            let commit = self.commit.ok_or(PostcommitInvariant::Publication)?;
            if ticket.root != self.root
                || ticket.closing_authority_epoch != self.authority_epoch
                || ticket.commit_sequence != commit.sequence
                || ticket.terminalizations != EFFECT_COUNT as u64
                || ticket.ticket_sequence >= self.next_ticket_sequence
            {
                return Err(PostcommitInvariant::Publication);
            }
        }
        if let Some(attempt) = self.active_attempt
            && (Some(attempt.ticket) != pending
                || self.closure_trigger != Some(attempt.trigger)
                || attempt.attempt_sequence >= self.next_attempt_sequence)
        {
            return Err(PostcommitInvariant::Publication);
        }
        if let Some(retry) = self.pending_retry
            && (Some(retry.ticket) != pending
                || self.closure_trigger != Some(retry.trigger)
                || retry.failed_attempt_sequence >= self.next_attempt_sequence
                || retry.retry_generation == 0)
        {
            return Err(PostcommitInvariant::Publication);
        }
        if let Some(publication) = self.publication
            && (publication.acknowledgement_sequence >= self.next_acknowledgement_sequence
                || publication.attempt_sequence >= self.next_attempt_sequence)
        {
            return Err(PostcommitInvariant::Publication);
        }
        Ok(())
    }

    fn check_root(&self) -> Result<(), PostcommitInvariant> {
        let valid = match self.backend_phase {
            BackendPhase::Prepared => {
                self.root_phase == RootPhase::Active
                    && self.authority_epoch == 1
                    && self.bound_service == Some(self.original_service)
                    && self.obligation_owner == ObligationOwner::Service
            }
            BackendPhase::Committed => {
                self.root_phase == RootPhase::Active
                    && self.authority_epoch == 1
                    && self.bound_service == Some(self.original_service)
                    && self.obligation_owner == ObligationOwner::Kernel
            }
            BackendPhase::AwaitingPublication => {
                self.root_phase == RootPhase::Closing
                    && self.authority_epoch == 2
                    && self.bound_service == Some(self.original_service)
                    && self.obligation_owner == ObligationOwner::Kernel
            }
            BackendPhase::Complete => {
                self.root_phase == RootPhase::Revoked
                    && self.authority_epoch == 2
                    && self.bound_service.is_none()
                    && self.obligation_owner == ObligationOwner::None
            }
        };
        if !valid {
            return Err(PostcommitInvariant::RootLifecycle);
        }
        Ok(())
    }

    fn check_closure(&self) -> Result<(), PostcommitInvariant> {
        if self.counters.closures != u64::from(self.closure.is_some())
            || self.counters.closures != self.counters.publication_acks
        {
            return Err(PostcommitInvariant::Closure);
        }
        if let Some(closure) = self.closure {
            let commit = self.commit.ok_or(PostcommitInvariant::Closure)?;
            let publication = self.publication.ok_or(PostcommitInvariant::Closure)?;
            if self.root_phase != RootPhase::Revoked
                || closure.root != self.root
                || closure.authority_epoch != self.authority_epoch
                || closure.commit_sequence != commit.sequence
                || closure.acknowledgement_sequence != publication.acknowledgement_sequence
                || closure.terminalizations != EFFECT_COUNT as u64
                || closure.closure_sequence >= self.next_closure_sequence
                || self.credits.returned != self.credits.capacity
            {
                return Err(PostcommitInvariant::Closure);
            }
        }
        Ok(())
    }

    fn check_allocators(&self) -> Result<(), PostcommitInvariant> {
        if self.next_commit_sequence != self.counters.commits.checked_add(1).unwrap_or(0)
            || self.next_ticket_sequence
                != self.counters.backend_closures.checked_add(1).unwrap_or(0)
            || self.next_trigger_sequence
                != self.counters.closure_triggers.checked_add(1).unwrap_or(0)
            || self.next_attempt_sequence
                != self
                    .counters
                    .publication_attempts
                    .checked_add(1)
                    .unwrap_or(0)
            || self.next_acknowledgement_sequence
                != self.counters.publication_acks.checked_add(1).unwrap_or(0)
            || self.next_closure_sequence != self.counters.closures.checked_add(1).unwrap_or(0)
        {
            return Err(PostcommitInvariant::Allocator);
        }
        Ok(())
    }
}
