//! Historical executable oracle for the post-commit publication gate of RFC 0005.
//!
//! This Phase A sliver remains available for the exact RFC 0005 identity and
//! credit checks. The current CSER core-rebaseline authority, settlement,
//! repeated-crash, and concurrency semantics live in
//! [`crate::core_rebaseline_oracle::EstateOracle`] and
//! `tests/core_rebaseline_loom.rs`. That successor deliberately separates
//! precommit `AdoptEffect` from postcommit `ClaimSettlement`, and its Loom tests
//! execute real concurrent revoke/adopt, revoke/claim, and apply-intent/crash
//! schedules.
//!
//! This historical model reproduces the production order up to the
//! retention point — compound device commit, kernel backend terminalization of
//! the six-effect cohort, then the post-commit service crash — and then opens
//! one publication gate.  Retention keeps the committed flight's causal
//! identity (cookie, publication ticket, root effect ancestry) and its result
//! digest under root ownership with the pending-publication credits still held.
//! Exactly one of the successor adoption reply and the tombstone closure may
//! terminalize that flight; the loser is rejected with `GateAlreadyClosed` and
//! the clone/validate/swap transaction gate leaves the projection unchanged.
//!
//! Crash observation is also the fence: it retires the crashed incarnation's
//! binding epoch and installs a successor epoch.  Any later publication carrying
//! the retired epoch is rejected with `FencedIncarnation`, whether or not a
//! winner has already closed the gate, and never reaches the gate at all.
//! Adoption is explicit and exact: the successor presents a cookie, publication
//! ticket, root ancestry, and result digest, each compared field by field
//! against the retained identity, and a wrong field is its own typed rejection
//! rather than a fallback.  There is no adoption entry point that omits the
//! presentation, so silent inheritance cannot be expressed.
//!
//! What this historical sliver deliberately does **not** model itself:
//!
//! - `BeginRevoke` racing a rebaseline authority or settlement gate.
//! - Repeated crash and a second binding generation.
//! - No successor incarnation is snapshotted, readied, or rebound.  Adoption
//!   validates the presented identity and the successor epoch, but installs no
//!   Registry binding; the successor identity appears only in its receipt.
//!
//! Its property tests enumerate arbitrary sequential adoption/tombstone
//! interleavings. They are retained evidence, not the current concurrency claim;
//! the core-rebaseline Loom harness named above closes that gap.

/// Number of effects in the bounded production read.
pub const EFFECT_COUNT: usize = 6;
/// Number of independently conserved credit classes.
pub const CREDIT_CLASS_COUNT: usize = 6;

const PENDING_PUBLICATION_CREDITS: [u64; CREDIT_CLASS_COUNT] = [1, 0, 0, 0, 0, 1];
const DIGEST_SEED: u64 = 0xcbf2_9ce4_8422_2325;
const DIGEST_PRIME: u64 = 0x0000_0100_0000_01b3;

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

/// Stable identity of a filesystem service incarnation.
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

/// Root lifecycle around backend terminalization and gate closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootPhase {
    /// The compound commit has not started Registry closure.
    Active,
    /// Backend terminalization staged one publication and fenced old authority.
    Closing,
    /// A terminal disposition closed the gate and completed root closure.
    Revoked,
}

/// Effect lifecycle in this bounded adoption successor.
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
    /// The kernel owns committed backend closure and staged publication.
    Kernel,
    /// The root retains the committed flight across the service crash.
    Root,
    /// A terminal disposition consumed the obligation.
    None,
}

/// Committed device-flight phase across retention and gate closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlightPhase {
    /// No compound commit has crossed its irreversible point.
    Prepared,
    /// The commit crossed, but backend/device closure has not terminalized it.
    Committed,
    /// All effects are terminal and one exact publication remains pending.
    AwaitingPublication,
    /// The service crashed; the flight is retained under root ownership.
    Retained,
    /// The successor adoption reply terminalized the flight.
    Published,
    /// The tombstone closure terminalized the flight.
    Tombstoned,
}

impl FlightPhase {
    /// Reports whether no later disposition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Published | Self::Tombstoned)
    }
}

/// One-shot publication gate guarding the retained flight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationGate {
    /// Retention has not happened, so no disposition may be chosen.
    Unarmed,
    /// Exactly one terminal disposition may still be chosen.
    Open,
    /// The successor adoption reply won the gate.
    ClosedByAdoption,
    /// The tombstone closure won the gate.
    ClosedByTombstone,
}

impl PublicationGate {
    /// Reports whether a terminal disposition may still be chosen.
    #[must_use]
    pub const fn is_open(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Reports whether a terminal disposition already won.
    #[must_use]
    pub const fn is_closed(self) -> bool {
        matches!(self, Self::ClosedByAdoption | Self::ClosedByTombstone)
    }
}

/// Terminal disposition that won the one-shot gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalDisposition {
    /// A successor incarnation adopted the retained flight and replied.
    Adopted,
    /// The closure lane retained the result and published no reply.
    Tombstoned,
}

/// What the guest observes once the gate is closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientObservation {
    /// The exact retained result was published once.
    Published,
    /// No reply was published and the result is reported indeterminate.
    Indeterminate,
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

/// Root effect ancestry frozen by the compound commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootAncestry {
    root: RootId,
    commit_sequence: u64,
    commit_authority_epoch: u64,
    commit_binding_epoch: u64,
    effects: usize,
}

impl RootAncestry {
    /// Returns the ancestral root.
    #[must_use]
    pub const fn root(self) -> RootId {
        self.root
    }

    /// Returns the compound-commit sequence that rooted the cohort.
    #[must_use]
    pub const fn commit_sequence(self) -> u64 {
        self.commit_sequence
    }

    /// Returns the authority epoch in force at commit.
    #[must_use]
    pub const fn commit_authority_epoch(self) -> u64 {
        self.commit_authority_epoch
    }

    /// Returns the binding epoch in force at commit.
    #[must_use]
    pub const fn commit_binding_epoch(self) -> u64 {
        self.commit_binding_epoch
    }

    /// Returns the exact ancestral cohort size.
    #[must_use]
    pub const fn effects(self) -> usize {
        self.effects
    }

    /// Substitutes the commit sequence for negative testing.
    #[must_use]
    pub const fn with_commit_sequence(mut self, commit_sequence: u64) -> Self {
        self.commit_sequence = commit_sequence;
        self
    }

    /// Substitutes the ancestral cohort size for negative testing.
    #[must_use]
    pub const fn with_effects(mut self, effects: usize) -> Self {
        self.effects = effects;
        self
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

/// Complete causal identity of the committed flight.
///
/// The four components named by obligation 1 travel together and are never
/// reconstructed: the guest cookie, the publication ticket, the root effect
/// ancestry, and the digest of the result already made durable by the device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CausalIdentity {
    root: RootId,
    cookie: u64,
    ancestry: RootAncestry,
    ticket: PublicationTicket,
    result_digest: u64,
}

impl CausalIdentity {
    /// Returns the owning root.
    #[must_use]
    pub const fn root(self) -> RootId {
        self.root
    }

    /// Returns the opaque guest cookie carried since the request.
    #[must_use]
    pub const fn cookie(self) -> u64 {
        self.cookie
    }

    /// Returns the frozen root effect ancestry.
    #[must_use]
    pub const fn ancestry(self) -> RootAncestry {
        self.ancestry
    }

    /// Returns the exact unchanged publication ticket.
    #[must_use]
    pub const fn ticket(self) -> PublicationTicket {
        self.ticket
    }

    /// Returns the digest of the committed device result.
    #[must_use]
    pub const fn result_digest(self) -> u64 {
        self.result_digest
    }

    /// Returns the exact presentation a successor must supply to adopt.
    ///
    /// The retained identity is the only source of a presentation that can pass
    /// obligation 4; every mutator on the result produces a rejection.
    #[must_use]
    pub const fn presentation(self) -> AdoptionPresentation {
        AdoptionPresentation {
            cookie: self.cookie,
            ancestry: self.ancestry,
            ticket: self.ticket,
            result_digest: self.result_digest,
        }
    }
}

/// Causal identity a successor presents when it claims the retained flight.
///
/// Adoption is explicit: there is no entry point that lets a successor inherit
/// the retained identity without naming all four components, and each component
/// is compared exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdoptionPresentation {
    cookie: u64,
    ancestry: RootAncestry,
    ticket: PublicationTicket,
    result_digest: u64,
}

impl AdoptionPresentation {
    /// Constructs a presentation from its four exact components.
    #[must_use]
    pub const fn new(
        cookie: u64,
        ancestry: RootAncestry,
        ticket: PublicationTicket,
        result_digest: u64,
    ) -> Self {
        Self {
            cookie,
            ancestry,
            ticket,
            result_digest,
        }
    }

    /// Returns the presented guest cookie.
    #[must_use]
    pub const fn cookie(self) -> u64 {
        self.cookie
    }

    /// Returns the presented root effect ancestry.
    #[must_use]
    pub const fn ancestry(self) -> RootAncestry {
        self.ancestry
    }

    /// Returns the presented publication ticket.
    #[must_use]
    pub const fn ticket(self) -> PublicationTicket {
        self.ticket
    }

    /// Returns the presented result digest.
    #[must_use]
    pub const fn result_digest(self) -> u64 {
        self.result_digest
    }

    /// Substitutes the cookie for negative testing.
    #[must_use]
    pub const fn with_cookie(mut self, cookie: u64) -> Self {
        self.cookie = cookie;
        self
    }

    /// Substitutes the root ancestry for negative testing.
    #[must_use]
    pub const fn with_ancestry(mut self, ancestry: RootAncestry) -> Self {
        self.ancestry = ancestry;
        self
    }

    /// Substitutes the publication ticket for negative testing.
    #[must_use]
    pub const fn with_ticket(mut self, ticket: PublicationTicket) -> Self {
        self.ticket = ticket;
        self
    }

    /// Substitutes the result digest for negative testing.
    #[must_use]
    pub const fn with_result_digest(mut self, result_digest: u64) -> Self {
        self.result_digest = result_digest;
        self
    }
}

/// Authority of a replacement incarnation acting after the fence.
///
/// The binding epoch is the fence coordinate: only the epoch installed by crash
/// observation may close the gate, so a retired epoch cannot adopt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuccessorAuthority {
    service: ServiceId,
    binding_epoch: u64,
}

impl SuccessorAuthority {
    /// Returns the replacement incarnation.
    #[must_use]
    pub const fn service(self) -> ServiceId {
        self.service
    }

    /// Returns the binding epoch presented by the replacement.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    /// Substitutes a service for negative testing.
    #[must_use]
    pub const fn with_service(mut self, service: ServiceId) -> Self {
        self.service = service;
        self
    }

    /// Substitutes a binding epoch for negative testing.
    #[must_use]
    pub const fn with_binding_epoch(mut self, binding_epoch: u64) -> Self {
        self.binding_epoch = binding_epoch;
        self
    }
}

/// Bearer proving the committed flight survived the post-commit crash.
///
/// This value is both the obligation-1 retention witness and the capability
/// required to close the publication gate.  It is issued exactly once and is
/// consumed by whichever terminal disposition wins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedFlight {
    identity: CausalIdentity,
    crashed_service: ServiceId,
    crashed_authority_epoch: u64,
    crashed_binding_epoch: u64,
    retention_sequence: u64,
    held_credits: [u64; CREDIT_CLASS_COUNT],
}

impl RetainedFlight {
    /// Returns the retained causal identity and result digest.
    #[must_use]
    pub const fn identity(self) -> CausalIdentity {
        self.identity
    }

    /// Returns the incarnation that crashed after the device commit.
    #[must_use]
    pub const fn crashed_service(self) -> ServiceId {
        self.crashed_service
    }

    /// Returns the pre-closure authority epoch held by the crashed task.
    #[must_use]
    pub const fn crashed_authority_epoch(self) -> u64 {
        self.crashed_authority_epoch
    }

    /// Returns the crashed service binding epoch.
    #[must_use]
    pub const fn crashed_binding_epoch(self) -> u64 {
        self.crashed_binding_epoch
    }

    /// Returns the model-local retention sequence.
    #[must_use]
    pub const fn retention_sequence(self) -> u64 {
        self.retention_sequence
    }

    /// Returns the typed credits still held for the pending publication.
    #[must_use]
    pub const fn held_credits(self) -> [u64; CREDIT_CLASS_COUNT] {
        self.held_credits
    }

    /// Substitutes the retention sequence for negative testing.
    #[must_use]
    pub const fn with_retention_sequence(mut self, retention_sequence: u64) -> Self {
        self.retention_sequence = retention_sequence;
        self
    }
}

/// Proof that a successor incarnation adopted the flight and replied once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdoptionReceipt {
    identity: CausalIdentity,
    presented: AdoptionPresentation,
    successor: ServiceId,
    successor_binding_epoch: u64,
    fenced_binding_epoch: u64,
    gate_sequence: u64,
    guest_replies: u64,
    terminalizations: u64,
}

impl AdoptionReceipt {
    /// Returns the exact adopted causal identity.
    #[must_use]
    pub const fn identity(self) -> CausalIdentity {
        self.identity
    }

    /// Returns the presentation the successor supplied and that was accepted.
    #[must_use]
    pub const fn presented(self) -> AdoptionPresentation {
        self.presented
    }

    /// Returns the successor incarnation that published the reply.
    #[must_use]
    pub const fn successor(self) -> ServiceId {
        self.successor
    }

    /// Returns the post-fence binding epoch the successor acted under.
    #[must_use]
    pub const fn successor_binding_epoch(self) -> u64 {
        self.successor_binding_epoch
    }

    /// Returns the binding epoch retired by the fence before adoption.
    #[must_use]
    pub const fn fenced_binding_epoch(self) -> u64 {
        self.fenced_binding_epoch
    }

    /// Returns the one-shot gate sequence consumed by this disposition.
    #[must_use]
    pub const fn gate_sequence(self) -> u64 {
        self.gate_sequence
    }

    /// Returns the number of guest replies published; always one.
    #[must_use]
    pub const fn guest_replies(self) -> u64 {
        self.guest_replies
    }

    /// Returns the exact terminalization count at adoption.
    #[must_use]
    pub const fn terminalizations(self) -> u64 {
        self.terminalizations
    }
}

/// Proof that the closure lane terminalized the flight without a reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TombstoneReceipt {
    identity: CausalIdentity,
    closer: ServiceId,
    gate_sequence: u64,
    observation: ClientObservation,
    terminalizations: u64,
}

impl TombstoneReceipt {
    /// Returns the exact retained causal identity.
    #[must_use]
    pub const fn identity(self) -> CausalIdentity {
        self.identity
    }

    /// Returns the closure-only task that terminalized the flight.
    #[must_use]
    pub const fn closer(self) -> ServiceId {
        self.closer
    }

    /// Returns the one-shot gate sequence consumed by this disposition.
    #[must_use]
    pub const fn gate_sequence(self) -> u64 {
        self.gate_sequence
    }

    /// Returns the guest observation; always indeterminate.
    #[must_use]
    pub const fn observation(self) -> ClientObservation {
        self.observation
    }

    /// Returns the exact terminalization count at closure.
    #[must_use]
    pub const fn terminalizations(self) -> u64 {
        self.terminalizations
    }
}

/// Exact proof that the winning disposition also closed the root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosureReceipt {
    root: RootId,
    authority_epoch: u64,
    commit_sequence: u64,
    gate_sequence: u64,
    closure_sequence: u64,
    disposition: TerminalDisposition,
    observation: ClientObservation,
    guest_replies: u64,
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

    /// Returns the consumed gate sequence.
    #[must_use]
    pub const fn gate_sequence(self) -> u64 {
        self.gate_sequence
    }

    /// Returns the closure sequence.
    #[must_use]
    pub const fn closure_sequence(self) -> u64 {
        self.closure_sequence
    }

    /// Returns the disposition that won the one-shot gate.
    #[must_use]
    pub const fn disposition(self) -> TerminalDisposition {
        self.disposition
    }

    /// Returns what the guest observes after closure.
    #[must_use]
    pub const fn observation(self) -> ClientObservation {
        self.observation
    }

    /// Returns the number of guest replies accounted by closure.
    #[must_use]
    pub const fn guest_replies(self) -> u64 {
        self.guest_replies
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
    /// Credits retained by committed work or a retained publication.
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
    /// Observed post-commit service crashes.
    pub crashes: u64,
    /// Retentions of the committed flight under root ownership.
    pub retentions: u64,
    /// Successful successor adoptions.
    pub adoptions: u64,
    /// Successful tombstone closures.
    pub tombstones: u64,
    /// One-shot gate closures; the sum of adoptions and tombstones.
    pub gate_closures: u64,
    /// Externally visible guest replies.
    pub guest_replies: u64,
    /// Successful root closures.
    pub closures: u64,
}

/// Complete semantic projection for failure-atomic comparisons.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdoptionProjection {
    /// Stable root identity.
    pub root: RootId,
    /// Root lifecycle.
    pub root_phase: RootPhase,
    /// Current root authority epoch.
    pub authority_epoch: u64,
    /// Binding epoch currently admitted; advanced once by the crash fence.
    pub binding_epoch: u64,
    /// Binding epoch retired by the crash fence, once fenced.
    pub fenced_binding_epoch: Option<u64>,
    /// Original service binding, retained until the gate closes.
    pub bound_service: Option<ServiceId>,
    /// Current owner of the compound obligation.
    pub obligation_owner: ObligationOwner,
    /// Committed device-flight phase.
    pub flight_phase: FlightPhase,
    /// One-shot publication gate state.
    pub gate: PublicationGate,
    /// Whether the post-commit service crash was observed.
    pub service_crashed: bool,
    /// Opaque guest cookie carried since the request.
    pub cookie: u64,
    /// Exact six-effect state.
    pub effects: [EffectProjection; EFFECT_COUNT],
    /// Typed-credit state.
    pub credits: CreditProjection,
    /// Compound commit receipt, if committed.
    pub commit: Option<CommitReceipt>,
    /// One unpublished publication ticket.
    pub pending_publication: Option<PublicationTicket>,
    /// Number of pending publications.
    pub pending_publications: usize,
    /// Retained flight bearer while the gate is open.
    pub retained: Option<RetainedFlight>,
    /// Successor adoption receipt, if adoption won.
    pub adoption: Option<AdoptionReceipt>,
    /// Tombstone receipt, if the closure lane won.
    pub tombstone: Option<TombstoneReceipt>,
    /// Final closure receipt.
    pub closure: Option<ClosureReceipt>,
    /// Successful transition counters.
    pub counters: TransitionCounters,
}

/// Rejected transition in the adoption oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionError {
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
    /// No committed flight is retained, so the gate is unarmed.
    FlightNotRetained,
    /// The supplied retained-flight bearer is stale or substituted.
    InvalidRetainedFlight,
    /// The crashed incarnation may not terminalize its own retained flight.
    FreshIncarnationRequired,
    /// The presented binding epoch was retired by the crash fence.
    FencedIncarnation,
    /// Only retained root publication authority may advance post-commit work.
    KernelObligationRequired,
    /// The presented cookie is not the retained cookie.
    WrongCookie,
    /// The presented publication ticket is not the retained ticket.
    WrongPublicationTicket,
    /// The presented root ancestry is not the retained ancestry.
    WrongRootAncestry,
    /// The presented result digest is not the retained digest.
    WrongResultDigest,
    /// A terminal disposition already won the one-shot publication gate.
    GateAlreadyClosed,
    /// A monotonic counter overflowed.
    CounterOverflow,
    /// The candidate transition failed a full invariant audit.
    InvariantViolation,
}

/// Invariant failure in the adoption oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionInvariant {
    /// Root phase, flight phase, and obligation ownership disagree.
    RootLifecycle,
    /// Effect phase and terminalization counts disagree.
    EffectLifecycle,
    /// Typed credits were copied, released early, or lost.
    CreditConservation,
    /// Commit identity or sequence fields disagree.
    CommitReceipt,
    /// Crash state accidentally changed Registry authority topology.
    CrashIsolation,
    /// Fence state, retired epoch, and current binding epoch disagree.
    BindingFence,
    /// Retained identity, digest, or held credits disagree with the flight.
    Retention,
    /// Gate state, disposition receipts, and counters disagree.
    PublicationGate,
    /// Closure was issued before exact quiescence or with wrong accounting.
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

const fn result_digest(cookie: u64, commit_sequence: u64, terminalizations: u64) -> u64 {
    let mut digest = DIGEST_SEED ^ cookie.wrapping_mul(DIGEST_PRIME);
    digest = digest.rotate_left(7) ^ commit_sequence.wrapping_mul(DIGEST_PRIME);
    digest.rotate_left(11) ^ terminalizations.wrapping_mul(DIGEST_PRIME)
}

/// Independent bounded state machine for the post-commit publication gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionIdentityAdoptionModel {
    root: RootId,
    root_phase: RootPhase,
    authority_epoch: u64,
    binding_epoch: u64,
    fenced_binding_epoch: Option<u64>,
    cookie: u64,
    original_service: ServiceId,
    bound_service: Option<ServiceId>,
    obligation_owner: ObligationOwner,
    flight_phase: FlightPhase,
    gate: PublicationGate,
    service_crashed: bool,
    effects: [EffectRecord; EFFECT_COUNT],
    credits: CreditProjection,
    commit: Option<CommitReceipt>,
    pending_publication: Option<PublicationTicket>,
    retained: Option<RetainedFlight>,
    adoption: Option<AdoptionReceipt>,
    tombstone: Option<TombstoneReceipt>,
    closure: Option<ClosureReceipt>,
    counters: TransitionCounters,
    next_commit_sequence: u64,
    next_ticket_sequence: u64,
    next_retention_sequence: u64,
    next_gate_sequence: u64,
    next_closure_sequence: u64,
}

impl ProductionIdentityAdoptionModel {
    /// Creates one prepared six-effect cohort owned by the filesystem service.
    ///
    /// The cookie is the opaque guest identity that must survive retention
    /// unchanged; it is never reissued by this model.
    #[must_use]
    pub fn new(root: RootId, service: ServiceId, cookie: u64) -> Self {
        let capacity = core::array::from_fn(|index| CreditClass::ALL[index].capacity());
        let model = Self {
            root,
            root_phase: RootPhase::Active,
            authority_epoch: 1,
            binding_epoch: 1,
            fenced_binding_epoch: None,
            cookie,
            original_service: service,
            bound_service: Some(service),
            obligation_owner: ObligationOwner::Service,
            flight_phase: FlightPhase::Prepared,
            gate: PublicationGate::Unarmed,
            service_crashed: false,
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
            retained: None,
            adoption: None,
            tombstone: None,
            closure: None,
            counters: TransitionCounters::default(),
            next_commit_sequence: 1,
            next_ticket_sequence: 1,
            next_retention_sequence: 1,
            next_gate_sequence: 1,
            next_closure_sequence: 1,
        };
        debug_assert_eq!(model.check_invariants(), Ok(()));
        model
    }

    /// Returns the initial service authority while it can still commit.
    #[must_use]
    pub fn service_authority(&self) -> Option<ServiceAuthority> {
        (self.flight_phase == FlightPhase::Prepared).then_some(ServiceAuthority {
            root: self.root,
            service: self.original_service,
            authority_epoch: self.authority_epoch,
            binding_epoch: self.binding_epoch,
        })
    }

    /// Returns the retained flight bearer while the gate is open.
    #[must_use]
    pub fn retained_flight(&self) -> Option<RetainedFlight> {
        self.retained
    }

    /// Returns the authority of a replacement incarnation after the fence.
    ///
    /// The epoch is the one installed by crash observation, so an authority
    /// taken before the fence can never be reproduced by this query.
    #[must_use]
    pub fn successor_authority(&self, service: ServiceId) -> Option<SuccessorAuthority> {
        self.fenced_binding_epoch.map(|_| SuccessorAuthority {
            service,
            binding_epoch: self.binding_epoch,
        })
    }

    /// Returns the binding epoch retired by the crash fence, once fenced.
    #[must_use]
    pub fn fenced_binding_epoch(&self) -> Option<u64> {
        self.fenced_binding_epoch
    }

    /// Returns the one-shot publication gate state.
    #[must_use]
    pub fn gate(&self) -> PublicationGate {
        self.gate
    }

    /// Returns the terminal disposition that won the gate, if any.
    #[must_use]
    pub fn disposition(&self) -> Option<TerminalDisposition> {
        match self.gate {
            PublicationGate::Unarmed | PublicationGate::Open => None,
            PublicationGate::ClosedByAdoption => Some(TerminalDisposition::Adopted),
            PublicationGate::ClosedByTombstone => Some(TerminalDisposition::Tombstoned),
        }
    }

    /// Returns the complete semantic projection.
    #[must_use]
    pub fn projection(&self) -> AdoptionProjection {
        AdoptionProjection {
            root: self.root,
            root_phase: self.root_phase,
            authority_epoch: self.authority_epoch,
            binding_epoch: self.binding_epoch,
            fenced_binding_epoch: self.fenced_binding_epoch,
            bound_service: self.bound_service,
            obligation_owner: self.obligation_owner,
            flight_phase: self.flight_phase,
            gate: self.gate,
            service_crashed: self.service_crashed,
            cookie: self.cookie,
            effects: self.effects.map(|record| EffectProjection {
                effect: record.effect,
                phase: record.phase,
                terminalizations: record.terminalizations,
            }),
            credits: self.credits,
            commit: self.commit,
            pending_publication: self.pending_publication,
            pending_publications: usize::from(self.pending_publication.is_some()),
            retained: self.retained,
            adoption: self.adoption,
            tombstone: self.tombstone,
            closure: self.closure,
            counters: self.counters,
        }
    }

    /// Atomically commits all six effects without closing the active root.
    pub fn commit(&mut self, authority: ServiceAuthority) -> Result<CommitReceipt, AdoptionError> {
        self.transact(|next| next.commit_inner(authority))
    }

    /// Terminalizes backend/device work exactly once and stages publication.
    pub fn terminalize_backend(
        &mut self,
        commit: CommitReceipt,
    ) -> Result<PublicationTicket, AdoptionError> {
        self.transact(|next| next.terminalize_backend_inner(commit))
    }

    /// Retains the committed flight under root ownership and arms the gate.
    pub fn observe_service_crash(
        &mut self,
        authority: ServiceAuthority,
    ) -> Result<RetainedFlight, AdoptionError> {
        self.transact(|next| next.observe_service_crash_inner(authority))
    }

    /// Attempts a publication from the crashed incarnation's own authority.
    ///
    /// This models the dead incarnation's in-flight reply arriving late.  It
    /// never succeeds: after the fence it is rejected as `FencedIncarnation`,
    /// and before the fence publication is not the service's to perform.  The
    /// attempt never reaches the gate, so it cannot perturb a pending or
    /// decided disposition.
    pub fn publish_from_crashed_incarnation(
        &mut self,
        authority: ServiceAuthority,
    ) -> Result<(), AdoptionError> {
        self.transact(|next| next.publish_from_crashed_incarnation_inner(authority))
    }

    /// Closes the gate by explicitly adopting the presented flight identity.
    ///
    /// The successor must present the exact retained cookie, ancestry, ticket,
    /// and result digest, and must act under the post-fence binding epoch.
    pub fn adopt_and_publish(
        &mut self,
        presentation: AdoptionPresentation,
        authority: SuccessorAuthority,
    ) -> Result<AdoptionReceipt, AdoptionError> {
        self.transact(|next| next.adopt_and_publish_inner(presentation, authority))
    }

    /// Closes the gate by tombstoning the retained flight without a reply.
    pub fn close_with_tombstone(
        &mut self,
        flight: RetainedFlight,
        closer: ServiceId,
    ) -> Result<TombstoneReceipt, AdoptionError> {
        self.transact(|next| next.close_with_tombstone_inner(flight, closer))
    }

    fn transact<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, AdoptionError>,
    ) -> Result<T, AdoptionError> {
        let mut candidate = self.clone();
        let result = operation(&mut candidate)?;
        candidate
            .check_invariants()
            .map_err(|_| AdoptionError::InvariantViolation)?;
        *self = candidate;
        Ok(result)
    }

    fn allocate(counter: &mut u64) -> Result<u64, AdoptionError> {
        let value = *counter;
        *counter = counter
            .checked_add(1)
            .ok_or(AdoptionError::CounterOverflow)?;
        Ok(value)
    }

    fn increment(counter: &mut u64, units: u64) -> Result<(), AdoptionError> {
        *counter = counter
            .checked_add(units)
            .ok_or(AdoptionError::CounterOverflow)?;
        Ok(())
    }

    fn validate_service_coordinates(
        &self,
        authority: ServiceAuthority,
    ) -> Result<(), AdoptionError> {
        if authority.root != self.root {
            return Err(AdoptionError::WrongRoot);
        }
        if authority.binding_epoch != self.binding_epoch {
            return Err(AdoptionError::StaleBinding);
        }
        if authority.service != self.original_service {
            return Err(AdoptionError::WrongService);
        }
        Ok(())
    }

    fn commit_inner(
        &mut self,
        authority: ServiceAuthority,
    ) -> Result<CommitReceipt, AdoptionError> {
        if self.commit.is_some() {
            return Err(AdoptionError::AlreadyCommitted);
        }
        self.validate_service_coordinates(authority)?;
        if authority.authority_epoch != self.authority_epoch {
            return Err(AdoptionError::StaleAuthority);
        }
        if self.flight_phase != FlightPhase::Prepared
            || self.root_phase != RootPhase::Active
            || self.bound_service != Some(authority.service)
            || self.obligation_owner != ObligationOwner::Service
            || self
                .effects
                .iter()
                .any(|effect| effect.phase != EffectPhase::Prepared || effect.terminalizations != 0)
        {
            return Err(AdoptionError::InvalidRootPhase);
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
        self.flight_phase = FlightPhase::Committed;
        self.commit = Some(receipt);
        Self::increment(&mut self.counters.commits, 1)?;
        Ok(receipt)
    }

    fn terminalize_backend_inner(
        &mut self,
        commit: CommitReceipt,
    ) -> Result<PublicationTicket, AdoptionError> {
        if self.commit != Some(commit) {
            return Err(AdoptionError::InvalidCommitReceipt);
        }
        if self.flight_phase != FlightPhase::Committed {
            return Err(AdoptionError::AlreadyTerminalized);
        }
        if self.root_phase != RootPhase::Active
            || self.obligation_owner != ObligationOwner::Kernel
            || self.effects.iter().any(|effect| {
                effect.phase != EffectPhase::Committed || effect.terminalizations != 0
            })
        {
            return Err(AdoptionError::BackendNotTerminalized);
        }
        let closing_authority_epoch = self
            .authority_epoch
            .checked_add(1)
            .ok_or(AdoptionError::CounterOverflow)?;
        let terminalizations =
            u64::try_from(EFFECT_COUNT).map_err(|_| AdoptionError::CounterOverflow)?;
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
        self.flight_phase = FlightPhase::AwaitingPublication;
        self.pending_publication = Some(ticket);
        Self::increment(&mut self.counters.backend_closures, 1)?;
        Self::increment(&mut self.counters.terminalizations, terminalizations)?;
        Ok(ticket)
    }

    fn observe_service_crash_inner(
        &mut self,
        authority: ServiceAuthority,
    ) -> Result<RetainedFlight, AdoptionError> {
        if self.service_crashed {
            return Err(AdoptionError::CrashAlreadyObserved);
        }
        if self.flight_phase != FlightPhase::AwaitingPublication
            || self.root_phase != RootPhase::Closing
        {
            return Err(AdoptionError::BackendNotTerminalized);
        }
        self.validate_service_coordinates(authority)?;
        let commit = self.commit.ok_or(AdoptionError::InvalidCommitReceipt)?;
        if authority.authority_epoch != commit.authority_epoch {
            return Err(AdoptionError::StaleAuthority);
        }
        let ticket = self
            .pending_publication
            .ok_or(AdoptionError::BackendNotTerminalized)?;
        let identity = CausalIdentity {
            root: self.root,
            cookie: self.cookie,
            ancestry: RootAncestry {
                root: commit.root,
                commit_sequence: commit.sequence,
                commit_authority_epoch: commit.authority_epoch,
                commit_binding_epoch: commit.binding_epoch,
                effects: commit.effects,
            },
            ticket,
            result_digest: result_digest(
                self.cookie,
                commit.sequence,
                self.counters.terminalizations,
            ),
        };
        let flight = RetainedFlight {
            identity,
            crashed_service: authority.service,
            crashed_authority_epoch: authority.authority_epoch,
            crashed_binding_epoch: authority.binding_epoch,
            retention_sequence: Self::allocate(&mut self.next_retention_sequence)?,
            held_credits: self.credits.committed,
        };
        let successor_binding_epoch = self
            .binding_epoch
            .checked_add(1)
            .ok_or(AdoptionError::CounterOverflow)?;
        self.service_crashed = true;
        self.flight_phase = FlightPhase::Retained;
        self.obligation_owner = ObligationOwner::Root;
        self.gate = PublicationGate::Open;
        self.retained = Some(flight);
        self.fenced_binding_epoch = Some(self.binding_epoch);
        self.binding_epoch = successor_binding_epoch;
        Self::increment(&mut self.counters.crashes, 1)?;
        Self::increment(&mut self.counters.retentions, 1)?;
        Ok(flight)
    }

    fn publish_from_crashed_incarnation_inner(
        &mut self,
        authority: ServiceAuthority,
    ) -> Result<(), AdoptionError> {
        if authority.root != self.root {
            return Err(AdoptionError::WrongRoot);
        }
        if authority.service != self.original_service {
            return Err(AdoptionError::WrongService);
        }
        if authority.binding_epoch != self.binding_epoch {
            return Err(AdoptionError::FencedIncarnation);
        }
        Err(AdoptionError::KernelObligationRequired)
    }

    /// Resolves the open gate to the retained identity for a fresh claimant.
    ///
    /// The gate check precedes identity validation so the loser of a decided
    /// gate always observes `GateAlreadyClosed` rather than an error about a
    /// bearer or presentation that retention has already consumed.
    fn claim_gate(&self, claimant: ServiceId) -> Result<CausalIdentity, AdoptionError> {
        if self.gate.is_closed() {
            return Err(AdoptionError::GateAlreadyClosed);
        }
        if self.gate != PublicationGate::Open || self.flight_phase != FlightPhase::Retained {
            return Err(AdoptionError::FlightNotRetained);
        }
        if claimant == self.original_service {
            return Err(AdoptionError::FreshIncarnationRequired);
        }
        self.retained
            .map(|flight| flight.identity)
            .ok_or(AdoptionError::FlightNotRetained)
    }

    /// Compares a presented identity field by field against the retained one.
    ///
    /// Each component named by obligation 4 has its own rejection, so a wrong
    /// cookie can never be reported, or handled, as a wrong digest.
    fn validate_presentation(
        retained: CausalIdentity,
        presented: AdoptionPresentation,
    ) -> Result<(), AdoptionError> {
        if presented.cookie != retained.cookie {
            return Err(AdoptionError::WrongCookie);
        }
        if presented.ticket != retained.ticket {
            return Err(AdoptionError::WrongPublicationTicket);
        }
        if presented.ancestry != retained.ancestry {
            return Err(AdoptionError::WrongRootAncestry);
        }
        if presented.result_digest != retained.result_digest {
            return Err(AdoptionError::WrongResultDigest);
        }
        Ok(())
    }

    fn close_root(
        &mut self,
        gate_sequence: u64,
        disposition: TerminalDisposition,
        observation: ClientObservation,
        guest_replies: u64,
    ) -> Result<(), AdoptionError> {
        let commit = self.commit.ok_or(AdoptionError::InvalidCommitReceipt)?;
        let closure = ClosureReceipt {
            root: self.root,
            authority_epoch: self.authority_epoch,
            commit_sequence: commit.sequence,
            gate_sequence,
            closure_sequence: Self::allocate(&mut self.next_closure_sequence)?,
            disposition,
            observation,
            guest_replies,
            terminalizations: self.counters.terminalizations,
        };
        for index in 0..CREDIT_CLASS_COUNT {
            self.credits.returned[index] = self.credits.returned[index]
                .checked_add(self.credits.committed[index])
                .ok_or(AdoptionError::CounterOverflow)?;
        }
        self.credits.committed = [0; CREDIT_CLASS_COUNT];
        self.pending_publication = None;
        self.retained = None;
        self.bound_service = None;
        self.obligation_owner = ObligationOwner::None;
        self.root_phase = RootPhase::Revoked;
        self.closure = Some(closure);
        Self::increment(&mut self.counters.gate_closures, 1)?;
        Self::increment(&mut self.counters.closures, 1)?;
        Ok(())
    }

    fn adopt_and_publish_inner(
        &mut self,
        presentation: AdoptionPresentation,
        authority: SuccessorAuthority,
    ) -> Result<AdoptionReceipt, AdoptionError> {
        let fenced_binding_epoch = self
            .fenced_binding_epoch
            .ok_or(AdoptionError::FlightNotRetained)?;
        if authority.binding_epoch != self.binding_epoch {
            return Err(AdoptionError::FencedIncarnation);
        }
        let identity = self.claim_gate(authority.service)?;
        Self::validate_presentation(identity, presentation)?;
        let gate_sequence = Self::allocate(&mut self.next_gate_sequence)?;
        let receipt = AdoptionReceipt {
            identity,
            presented: presentation,
            successor: authority.service,
            successor_binding_epoch: authority.binding_epoch,
            fenced_binding_epoch,
            gate_sequence,
            guest_replies: 1,
            terminalizations: self.counters.terminalizations,
        };
        self.gate = PublicationGate::ClosedByAdoption;
        self.flight_phase = FlightPhase::Published;
        self.adoption = Some(receipt);
        Self::increment(&mut self.counters.adoptions, 1)?;
        Self::increment(&mut self.counters.guest_replies, 1)?;
        self.close_root(
            gate_sequence,
            TerminalDisposition::Adopted,
            ClientObservation::Published,
            1,
        )?;
        Ok(receipt)
    }

    fn close_with_tombstone_inner(
        &mut self,
        flight: RetainedFlight,
        closer: ServiceId,
    ) -> Result<TombstoneReceipt, AdoptionError> {
        let identity = self.claim_gate(closer)?;
        if self.retained != Some(flight) {
            return Err(AdoptionError::InvalidRetainedFlight);
        }
        let gate_sequence = Self::allocate(&mut self.next_gate_sequence)?;
        let receipt = TombstoneReceipt {
            identity,
            closer,
            gate_sequence,
            observation: ClientObservation::Indeterminate,
            terminalizations: self.counters.terminalizations,
        };
        self.gate = PublicationGate::ClosedByTombstone;
        self.flight_phase = FlightPhase::Tombstoned;
        self.tombstone = Some(receipt);
        Self::increment(&mut self.counters.tombstones, 1)?;
        self.close_root(
            gate_sequence,
            TerminalDisposition::Tombstoned,
            ClientObservation::Indeterminate,
            0,
        )?;
        Ok(receipt)
    }

    /// Audits root, flight, retention, gate, effect, credit, and allocator
    /// invariants.
    pub fn check_invariants(&self) -> Result<(), AdoptionInvariant> {
        self.check_effects()?;
        self.check_credits()?;
        self.check_commit()?;
        self.check_crash()?;
        self.check_fence()?;
        self.check_retention()?;
        self.check_gate()?;
        self.check_root()?;
        self.check_closure()?;
        self.check_allocators()?;
        Ok(())
    }

    fn check_effects(&self) -> Result<(), AdoptionInvariant> {
        let expected_phase = match self.flight_phase {
            FlightPhase::Prepared => EffectPhase::Prepared,
            FlightPhase::Committed => EffectPhase::Committed,
            FlightPhase::AwaitingPublication
            | FlightPhase::Retained
            | FlightPhase::Published
            | FlightPhase::Tombstoned => EffectPhase::Completed,
        };
        for (record, expected) in self.effects.iter().zip(EffectKind::ALL) {
            if record.effect != expected
                || record.phase != expected_phase
                || (record.phase == EffectPhase::Completed) != (record.terminalizations == 1)
                || record.terminalizations > 1
            {
                return Err(AdoptionInvariant::EffectLifecycle);
            }
        }
        let sum = self
            .effects
            .iter()
            .map(|effect| u64::from(effect.terminalizations))
            .sum::<u64>();
        if sum != self.counters.terminalizations || (sum != 0 && sum != EFFECT_COUNT as u64) {
            return Err(AdoptionInvariant::EffectLifecycle);
        }
        Ok(())
    }

    fn check_credits(&self) -> Result<(), AdoptionInvariant> {
        for credit in CreditClass::ALL {
            let index = credit.index();
            if self.credits.capacity[index] != credit.capacity()
                || self.credits.free[index]
                    + self.credits.held[index]
                    + self.credits.committed[index]
                    + self.credits.returned[index]
                    != credit.capacity()
            {
                return Err(AdoptionInvariant::CreditConservation);
            }
        }
        let zero = [0; CREDIT_CLASS_COUNT];
        let valid = match self.flight_phase {
            FlightPhase::Prepared => {
                self.credits.free == zero
                    && self.credits.held == self.credits.capacity
                    && self.credits.committed == zero
                    && self.credits.returned == zero
            }
            FlightPhase::Committed => {
                self.credits.free == zero
                    && self.credits.held == zero
                    && self.credits.committed == self.credits.capacity
                    && self.credits.returned == zero
            }
            FlightPhase::AwaitingPublication | FlightPhase::Retained => {
                self.credits.free == zero
                    && self.credits.held == zero
                    && self.credits.committed == PENDING_PUBLICATION_CREDITS
                    && self.credits.returned
                        == core::array::from_fn(|index| {
                            self.credits.capacity[index] - PENDING_PUBLICATION_CREDITS[index]
                        })
            }
            FlightPhase::Published | FlightPhase::Tombstoned => {
                self.credits.free == zero
                    && self.credits.held == zero
                    && self.credits.committed == zero
                    && self.credits.returned == self.credits.capacity
            }
        };
        if !valid {
            return Err(AdoptionInvariant::CreditConservation);
        }
        Ok(())
    }

    fn check_commit(&self) -> Result<(), AdoptionInvariant> {
        if self.counters.commits != u64::from(self.commit.is_some()) {
            return Err(AdoptionInvariant::CommitReceipt);
        }
        if let Some(commit) = self.commit {
            if commit.root != self.root
                || commit.service != self.original_service
                || commit.authority_epoch != 1
                || commit.binding_epoch != 1
                || commit.effects != EFFECT_COUNT
                || commit.sequence >= self.next_commit_sequence
                || self.flight_phase == FlightPhase::Prepared
            {
                return Err(AdoptionInvariant::CommitReceipt);
            }
        } else if self.flight_phase != FlightPhase::Prepared {
            return Err(AdoptionInvariant::CommitReceipt);
        }
        let ticket_expected = matches!(
            self.flight_phase,
            FlightPhase::AwaitingPublication | FlightPhase::Retained
        );
        if ticket_expected != self.pending_publication.is_some() {
            return Err(AdoptionInvariant::CommitReceipt);
        }
        if let Some(ticket) = self.pending_publication {
            let commit = self.commit.ok_or(AdoptionInvariant::CommitReceipt)?;
            if ticket.root != self.root
                || ticket.closing_authority_epoch != self.authority_epoch
                || ticket.commit_sequence != commit.sequence
                || ticket.terminalizations != EFFECT_COUNT as u64
                || ticket.ticket_sequence >= self.next_ticket_sequence
            {
                return Err(AdoptionInvariant::CommitReceipt);
            }
        }
        Ok(())
    }

    fn check_crash(&self) -> Result<(), AdoptionInvariant> {
        let retained_or_later = matches!(
            self.flight_phase,
            FlightPhase::Retained | FlightPhase::Published | FlightPhase::Tombstoned
        );
        if self.counters.crashes != u64::from(self.service_crashed)
            || self.counters.crashes > 1
            || self.counters.retentions != self.counters.crashes
            || self.service_crashed != retained_or_later
        {
            return Err(AdoptionInvariant::CrashIsolation);
        }
        Ok(())
    }

    fn check_fence(&self) -> Result<(), AdoptionInvariant> {
        match self.fenced_binding_epoch {
            None => {
                if self.service_crashed || self.binding_epoch != 1 {
                    return Err(AdoptionInvariant::BindingFence);
                }
            }
            Some(fenced) => {
                if !self.service_crashed
                    || fenced != 1
                    || self.binding_epoch != 2
                    || self.binding_epoch <= fenced
                {
                    return Err(AdoptionInvariant::BindingFence);
                }
            }
        }
        Ok(())
    }

    fn check_retention(&self) -> Result<(), AdoptionInvariant> {
        if self.retained.is_some() != (self.flight_phase == FlightPhase::Retained) {
            return Err(AdoptionInvariant::Retention);
        }
        let Some(flight) = self.retained else {
            return Ok(());
        };
        let commit = self.commit.ok_or(AdoptionInvariant::Retention)?;
        let ticket = self
            .pending_publication
            .ok_or(AdoptionInvariant::Retention)?;
        let identity = flight.identity;
        if identity.root != self.root
            || identity.cookie != self.cookie
            || identity.ticket != ticket
            || identity.ancestry.root != commit.root
            || identity.ancestry.commit_sequence != commit.sequence
            || identity.ancestry.commit_authority_epoch != commit.authority_epoch
            || identity.ancestry.commit_binding_epoch != commit.binding_epoch
            || identity.ancestry.effects != commit.effects
            || identity.result_digest
                != result_digest(self.cookie, commit.sequence, self.counters.terminalizations)
        {
            return Err(AdoptionInvariant::Retention);
        }
        if flight.crashed_service != self.original_service
            || flight.crashed_authority_epoch != commit.authority_epoch
            || Some(flight.crashed_binding_epoch) != self.fenced_binding_epoch
            || flight.retention_sequence >= self.next_retention_sequence
            || flight.held_credits != self.credits.committed
            || flight.held_credits != PENDING_PUBLICATION_CREDITS
        {
            return Err(AdoptionInvariant::Retention);
        }
        Ok(())
    }

    fn check_gate(&self) -> Result<(), AdoptionInvariant> {
        let expected_gate = match self.flight_phase {
            FlightPhase::Prepared | FlightPhase::Committed | FlightPhase::AwaitingPublication => {
                PublicationGate::Unarmed
            }
            FlightPhase::Retained => PublicationGate::Open,
            FlightPhase::Published => PublicationGate::ClosedByAdoption,
            FlightPhase::Tombstoned => PublicationGate::ClosedByTombstone,
        };
        if self.gate != expected_gate
            || self.adoption.is_some() != (self.gate == PublicationGate::ClosedByAdoption)
            || self.tombstone.is_some() != (self.gate == PublicationGate::ClosedByTombstone)
            || (self.adoption.is_some() && self.tombstone.is_some())
        {
            return Err(AdoptionInvariant::PublicationGate);
        }
        if self.counters.adoptions != u64::from(self.adoption.is_some())
            || self.counters.tombstones != u64::from(self.tombstone.is_some())
            || self.counters.gate_closures != self.counters.adoptions + self.counters.tombstones
            || self.counters.gate_closures > 1
            || self.counters.guest_replies != self.counters.adoptions
            || self.counters.gate_closures != u64::from(self.gate.is_closed())
        {
            return Err(AdoptionInvariant::PublicationGate);
        }
        if let Some(adoption) = self.adoption
            && (adoption.successor == self.original_service
                || adoption.guest_replies != 1
                || adoption.terminalizations != EFFECT_COUNT as u64
                || adoption.identity.root != self.root
                || adoption.identity.cookie != self.cookie
                || adoption.presented != adoption.identity.presentation()
                || Some(adoption.fenced_binding_epoch) != self.fenced_binding_epoch
                || adoption.successor_binding_epoch != self.binding_epoch
                || adoption.successor_binding_epoch <= adoption.fenced_binding_epoch
                || adoption.gate_sequence >= self.next_gate_sequence)
        {
            return Err(AdoptionInvariant::PublicationGate);
        }
        if let Some(tombstone) = self.tombstone
            && (tombstone.closer == self.original_service
                || tombstone.observation != ClientObservation::Indeterminate
                || tombstone.terminalizations != EFFECT_COUNT as u64
                || tombstone.identity.root != self.root
                || tombstone.identity.cookie != self.cookie
                || tombstone.gate_sequence >= self.next_gate_sequence)
        {
            return Err(AdoptionInvariant::PublicationGate);
        }
        Ok(())
    }

    fn check_root(&self) -> Result<(), AdoptionInvariant> {
        let valid = match self.flight_phase {
            FlightPhase::Prepared => {
                self.root_phase == RootPhase::Active
                    && self.authority_epoch == 1
                    && self.bound_service == Some(self.original_service)
                    && self.obligation_owner == ObligationOwner::Service
            }
            FlightPhase::Committed => {
                self.root_phase == RootPhase::Active
                    && self.authority_epoch == 1
                    && self.bound_service == Some(self.original_service)
                    && self.obligation_owner == ObligationOwner::Kernel
            }
            FlightPhase::AwaitingPublication => {
                self.root_phase == RootPhase::Closing
                    && self.authority_epoch == 2
                    && self.bound_service == Some(self.original_service)
                    && self.obligation_owner == ObligationOwner::Kernel
            }
            FlightPhase::Retained => {
                self.root_phase == RootPhase::Closing
                    && self.authority_epoch == 2
                    && self.bound_service == Some(self.original_service)
                    && self.obligation_owner == ObligationOwner::Root
            }
            FlightPhase::Published | FlightPhase::Tombstoned => {
                self.root_phase == RootPhase::Revoked
                    && self.authority_epoch == 2
                    && self.bound_service.is_none()
                    && self.obligation_owner == ObligationOwner::None
            }
        };
        if !valid {
            return Err(AdoptionInvariant::RootLifecycle);
        }
        Ok(())
    }

    fn check_closure(&self) -> Result<(), AdoptionInvariant> {
        if self.counters.closures != u64::from(self.closure.is_some())
            || self.counters.closures != self.counters.gate_closures
        {
            return Err(AdoptionInvariant::Closure);
        }
        let Some(closure) = self.closure else {
            return Ok(());
        };
        let commit = self.commit.ok_or(AdoptionInvariant::Closure)?;
        let (expected_disposition, expected_observation, expected_replies, receipt_gate) =
            match (self.adoption, self.tombstone) {
                (Some(adoption), None) => (
                    TerminalDisposition::Adopted,
                    ClientObservation::Published,
                    1,
                    adoption.gate_sequence,
                ),
                (None, Some(tombstone)) => (
                    TerminalDisposition::Tombstoned,
                    ClientObservation::Indeterminate,
                    0,
                    tombstone.gate_sequence,
                ),
                _ => return Err(AdoptionInvariant::Closure),
            };
        if !self.flight_phase.is_terminal()
            || self.root_phase != RootPhase::Revoked
            || closure.root != self.root
            || closure.authority_epoch != self.authority_epoch
            || closure.commit_sequence != commit.sequence
            || closure.gate_sequence != receipt_gate
            || closure.disposition != expected_disposition
            || closure.observation != expected_observation
            || closure.guest_replies != expected_replies
            || closure.guest_replies != self.counters.guest_replies
            || closure.terminalizations != EFFECT_COUNT as u64
            || closure.closure_sequence >= self.next_closure_sequence
            || self.credits.returned != self.credits.capacity
        {
            return Err(AdoptionInvariant::Closure);
        }
        Ok(())
    }

    fn check_allocators(&self) -> Result<(), AdoptionInvariant> {
        if self.next_commit_sequence != self.counters.commits.checked_add(1).unwrap_or(0)
            || self.next_ticket_sequence
                != self.counters.backend_closures.checked_add(1).unwrap_or(0)
            || self.next_retention_sequence != self.counters.retentions.checked_add(1).unwrap_or(0)
            || self.next_gate_sequence != self.counters.gate_closures.checked_add(1).unwrap_or(0)
            || self.next_closure_sequence != self.counters.closures.checked_add(1).unwrap_or(0)
        {
            return Err(AdoptionInvariant::Allocator);
        }
        Ok(())
    }
}
