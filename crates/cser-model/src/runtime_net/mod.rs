//! Bounded runtime-network CSER reference model.
//!
//! This successor fixes one in-memory IPv4-loopback request graph:
//!
//! ```text
//! Root -> Syscall -> NetOperation -> ReadinessWait
//!                                \-> BufferLease
//! ```
//!
//! `NetCommit`, `ReadyCommit`, and `GuestReply` are distinct publication
//! points. The four-byte payload is bounded and retained by `BufferLease`
//! until explicit consumption or root closure. This is a deterministic
//! `no_std + alloc` protocol oracle, not a TCP/IP stack, VirtIO-net driver,
//! external-packet model, or Linux ABI implementation.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{EffectId, ScopeId, ScopeState};

mod helpers;
mod operations;
mod queries;

macro_rules! scalar_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            /// Constructs an identity or generation from its raw value.
            #[must_use]
            pub const fn new(raw: u64) -> Self {
                Self(raw)
            }

            /// Returns the raw value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }
        }
    };
}

scalar_type!(
    /// Root authority generation advanced only by root revocation.
    NetAuthorityEpoch
);
scalar_type!(
    /// Restart generation of one user-space network-path service.
    NetBindingEpoch
);
scalar_type!(
    /// Generation fencing one bounded loopback socket publication.
    SocketGeneration
);
scalar_type!(
    /// Generation fencing one kernel-owned readiness source.
    ReadySourceGeneration
);
scalar_type!(
    /// Stable identity of one user-space service instance.
    NetServiceId
);

/// The fixed payload published by the bounded loopback exchange.
pub const LOOPBACK_PAYLOAD: [u8; 4] = *b"ping";

/// Independently restartable domains in the bounded network path.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NetDomain {
    /// Linux personality and its trapped syscall continuation.
    Personality,
    /// User-mode bounded loopback network service.
    Network,
    /// User-mode readiness control around a kernel-owned source.
    Readiness,
}

impl NetDomain {
    /// Complete deterministic domain set.
    pub const ALL: [Self; 3] = [Self::Personality, Self::Network, Self::Readiness];
}

/// Fixed effects in one bounded loopback request.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NetEffectKind {
    /// Trapped Linux syscall continuation.
    Syscall,
    /// One bounded loopback send/receive operation.
    NetOperation,
    /// One wait on a kernel-owned readiness source.
    ReadinessWait,
    /// Ownership of the fixed four-byte payload.
    BufferLease,
}

impl NetEffectKind {
    /// Returns the only service domain allowed to operate on this effect.
    #[must_use]
    pub const fn domain(self) -> NetDomain {
        match self {
            Self::Syscall => NetDomain::Personality,
            Self::NetOperation | Self::BufferLease => NetDomain::Network,
            Self::ReadinessWait => NetDomain::Readiness,
        }
    }

    const fn credit(self) -> NetCreditClass {
        match self {
            Self::Syscall => NetCreditClass::Control,
            Self::NetOperation => NetCreditClass::Network,
            Self::ReadinessWait => NetCreditClass::Readiness,
            Self::BufferLease => NetCreditClass::Buffer,
        }
    }
}

/// Independently conserved renewable credit classes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NetCreditClass {
    /// One trapped syscall continuation.
    Control,
    /// One loopback socket operation.
    Network,
    /// One kernel-owned readiness wait.
    Readiness,
    /// One fixed four-byte payload lease.
    Buffer,
}

/// Typed renewable credits held by a root scope or its live effects.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NetCredits {
    control: u64,
    network: u64,
    readiness: u64,
    buffer: u64,
}

impl NetCredits {
    /// A bundle with no credits.
    pub const ZERO: Self = Self::new(0, 0, 0, 0);

    /// One credit in every class, sufficient for one fixed request graph.
    pub const ONE_REQUEST: Self = Self::new(1, 1, 1, 1);

    /// Constructs a typed credit bundle.
    #[must_use]
    pub const fn new(control: u64, network: u64, readiness: u64, buffer: u64) -> Self {
        Self {
            control,
            network,
            readiness,
            buffer,
        }
    }

    /// Returns the number of control credits.
    #[must_use]
    pub const fn control(self) -> u64 {
        self.control
    }

    /// Returns the number of network credits.
    #[must_use]
    pub const fn network(self) -> u64 {
        self.network
    }

    /// Returns the number of readiness credits.
    #[must_use]
    pub const fn readiness(self) -> u64 {
        self.readiness
    }

    /// Returns the number of buffer credits.
    #[must_use]
    pub const fn buffer(self) -> u64 {
        self.buffer
    }

    const fn one(class: NetCreditClass) -> Self {
        match class {
            NetCreditClass::Control => Self::new(1, 0, 0, 0),
            NetCreditClass::Network => Self::new(0, 1, 0, 0),
            NetCreditClass::Readiness => Self::new(0, 0, 1, 0),
            NetCreditClass::Buffer => Self::new(0, 0, 0, 1),
        }
    }

    const fn get(self, class: NetCreditClass) -> u64 {
        match class {
            NetCreditClass::Control => self.control,
            NetCreditClass::Network => self.network,
            NetCreditClass::Readiness => self.readiness,
            NetCreditClass::Buffer => self.buffer,
        }
    }

    fn contains(self, other: Self) -> bool {
        self.control >= other.control
            && self.network >= other.network
            && self.readiness >= other.readiness
            && self.buffer >= other.buffer
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self::new(
            self.control.checked_add(other.control)?,
            self.network.checked_add(other.network)?,
            self.readiness.checked_add(other.readiness)?,
            self.buffer.checked_add(other.buffer)?,
        ))
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        Some(Self::new(
            self.control.checked_sub(other.control)?,
            self.network.checked_sub(other.network)?,
            self.readiness.checked_sub(other.readiness)?,
            self.buffer.checked_sub(other.buffer)?,
        ))
    }
}

/// Lifecycle of one effect in the fixed network graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetEffectPhase {
    /// Authority and one typed credit are reserved.
    Registered,
    /// Domain-private work is prepared but not visible.
    Prepared,
    /// The effect's publication point has been crossed.
    Committed,
    /// A committed effect drained and returned its credit.
    Completed,
    /// Root closure aborted an uncommitted effect and returned its credit.
    Aborted,
}

impl NetEffectPhase {
    /// Returns whether the effect owns no live obligation.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }

    const fn is_uncommitted(self) -> bool {
        matches!(self, Self::Registered | Self::Prepared)
    }
}

/// Kernel fallback and replacement-handshake state for one domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetFallbackState {
    /// A live service is bound.
    Standby,
    /// A crash was fenced and kernel fallback must be selected.
    Required,
    /// Kernel fallback is active and may expose a snapshot.
    Running,
    /// A replacement supplied a still-current ready proof.
    ReplacementReady,
}

/// Immutable service identities used to create a root scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeNetServices {
    personality: NetServiceId,
    network: NetServiceId,
    readiness: NetServiceId,
}

impl RuntimeNetServices {
    /// Constructs a complete service set.
    #[must_use]
    pub const fn new(
        personality: NetServiceId,
        network: NetServiceId,
        readiness: NetServiceId,
    ) -> Self {
        Self {
            personality,
            network,
            readiness,
        }
    }

    const fn get(self, domain: NetDomain) -> NetServiceId {
        match domain {
            NetDomain::Personality => self.personality,
            NetDomain::Network => self.network,
            NetDomain::Readiness => self.readiness,
        }
    }
}

/// Authenticated proof of one current domain binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeNetBindingToken {
    scope: ScopeId,
    domain: NetDomain,
    service: NetServiceId,
    authority_epoch: NetAuthorityEpoch,
    binding_epoch: NetBindingEpoch,
}

impl RuntimeNetBindingToken {
    /// Returns the root scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the bound domain.
    #[must_use]
    pub const fn domain(self) -> NetDomain {
        self.domain
    }

    /// Returns the service instance.
    #[must_use]
    pub const fn service(self) -> NetServiceId {
        self.service
    }

    /// Returns the captured root authority generation.
    #[must_use]
    pub const fn authority_epoch(self) -> NetAuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the captured domain binding generation.
    #[must_use]
    pub const fn binding_epoch(self) -> NetBindingEpoch {
        self.binding_epoch
    }
}

/// Complete current bindings returned when a scope is created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeNetBindings {
    personality: RuntimeNetBindingToken,
    network: RuntimeNetBindingToken,
    readiness: RuntimeNetBindingToken,
}

impl RuntimeNetBindings {
    /// Returns the binding for one domain.
    #[must_use]
    pub const fn get(self, domain: NetDomain) -> RuntimeNetBindingToken {
        match domain {
            NetDomain::Personality => self.personality,
            NetDomain::Network => self.network,
            NetDomain::Readiness => self.readiness,
        }
    }
}

/// Full fenced identity of one network-path effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeNetEffectToken {
    scope: ScopeId,
    effect: EffectId,
    parent: Option<EffectId>,
    kind: NetEffectKind,
    authority_epoch: NetAuthorityEpoch,
    binding_epoch: NetBindingEpoch,
    socket_generation: SocketGeneration,
    source_generation: ReadySourceGeneration,
}

impl RuntimeNetEffectToken {
    /// Returns the owning scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the stable effect identity.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the immutable causal parent, if any.
    #[must_use]
    pub const fn parent(self) -> Option<EffectId> {
        self.parent
    }

    /// Returns the semantic effect kind.
    #[must_use]
    pub const fn kind(self) -> NetEffectKind {
        self.kind
    }

    /// Returns the captured root authority generation.
    #[must_use]
    pub const fn authority_epoch(self) -> NetAuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the captured local binding generation.
    #[must_use]
    pub const fn binding_epoch(self) -> NetBindingEpoch {
        self.binding_epoch
    }

    /// Returns the captured socket generation.
    #[must_use]
    pub const fn socket_generation(self) -> SocketGeneration {
        self.socket_generation
    }

    /// Returns the captured readiness-source generation.
    #[must_use]
    pub const fn source_generation(self) -> ReadySourceGeneration {
        self.source_generation
    }
}

/// Tokens for one complete fixed loopback request graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeNetToken {
    syscall: RuntimeNetEffectToken,
    network: RuntimeNetEffectToken,
    readiness: RuntimeNetEffectToken,
    buffer: RuntimeNetEffectToken,
}

impl RuntimeNetToken {
    /// Returns the personality syscall effect.
    #[must_use]
    pub const fn syscall(self) -> RuntimeNetEffectToken {
        self.syscall
    }

    /// Returns the network operation effect.
    #[must_use]
    pub const fn network(self) -> RuntimeNetEffectToken {
        self.network
    }

    /// Returns the readiness-wait effect.
    #[must_use]
    pub const fn readiness(self) -> RuntimeNetEffectToken {
        self.readiness
    }

    /// Returns the payload lease effect.
    #[must_use]
    pub const fn buffer(self) -> RuntimeNetEffectToken {
        self.buffer
    }
}

/// Immutable receipt for the bounded network payload publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetCommitReceipt {
    scope: ScopeId,
    effect: EffectId,
    buffer_effect: EffectId,
    sequence: u64,
    socket_generation: SocketGeneration,
    payload: [u8; 4],
}

impl NetCommitReceipt {
    /// Returns the network effect.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the buffer lease co-published by this commit.
    #[must_use]
    pub const fn buffer_effect(self) -> EffectId {
        self.buffer_effect
    }

    /// Returns the global commit sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the newly published socket generation.
    #[must_use]
    pub const fn socket_generation(self) -> SocketGeneration {
        self.socket_generation
    }

    /// Returns the immutable four-byte payload.
    #[must_use]
    pub const fn payload(self) -> [u8; 4] {
        self.payload
    }
}

/// Immutable receipt for a kernel-owned readiness publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyCommitReceipt {
    scope: ScopeId,
    effect: EffectId,
    network_effect: EffectId,
    network_sequence: u64,
    sequence: u64,
    source_generation: ReadySourceGeneration,
}

impl ReadyCommitReceipt {
    /// Returns the readiness-wait effect.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the exact network effect that made the source ready.
    #[must_use]
    pub const fn network_effect(self) -> EffectId {
        self.network_effect
    }

    /// Returns the exact `NetCommit` sequence consumed by this receipt.
    #[must_use]
    pub const fn network_sequence(self) -> u64 {
        self.network_sequence
    }

    /// Returns this readiness publication's global commit sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the newly published readiness-source generation.
    #[must_use]
    pub const fn source_generation(self) -> ReadySourceGeneration {
        self.source_generation
    }
}

/// One-shot ticket for publishing a committed guest syscall reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestReplyTicket {
    scope: ScopeId,
    effect: EffectId,
    ready_effect: EffectId,
    ready_sequence: u64,
    commit_sequence: u64,
    ticket_sequence: u64,
    result: i64,
}

impl GuestReplyTicket {
    /// Returns the syscall effect.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the exact readiness effect authorizing the reply.
    #[must_use]
    pub const fn ready_effect(self) -> EffectId {
        self.ready_effect
    }

    /// Returns the exact `ReadyCommit` sequence authorizing the reply.
    #[must_use]
    pub const fn ready_sequence(self) -> u64 {
        self.ready_sequence
    }

    /// Returns the committed Linux result.
    #[must_use]
    pub const fn result(self) -> i64 {
        self.result
    }
}

/// Exact ticket created by root revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeNetRevokeTicket {
    scope: ScopeId,
    sequence: u64,
    closed_epoch: NetAuthorityEpoch,
    authority_epoch: NetAuthorityEpoch,
}

impl RuntimeNetRevokeTicket {
    /// Returns the closing root scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the authority generation closed by this ticket.
    #[must_use]
    pub const fn closed_epoch(self) -> NetAuthorityEpoch {
        self.closed_epoch
    }
}

/// Exact recovery snapshot for one crashed network-path service domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeNetRecoverySnapshot {
    scope: ScopeId,
    domain: NetDomain,
    replacement: NetServiceId,
    authority_epoch: NetAuthorityEpoch,
    binding_epoch: NetBindingEpoch,
    socket_generation: SocketGeneration,
    source_generation: ReadySourceGeneration,
    domain_revision: u64,
    cohort: Vec<RuntimeNetEffectToken>,
}

impl RuntimeNetRecoverySnapshot {
    /// Returns the crashed domain.
    #[must_use]
    pub const fn domain(&self) -> NetDomain {
        self.domain
    }

    /// Returns the exact uncommitted orphan cohort.
    #[must_use]
    pub fn cohort(&self) -> &[RuntimeNetEffectToken] {
        &self.cohort
    }
}

/// Ready proof wrapping one exact recovery snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeNetReadyToken {
    snapshot: RuntimeNetRecoverySnapshot,
}

/// One child-first root-closure transition or retained publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeNetClosureStep {
    /// One uncommitted effect aborted and returned its typed credit.
    Aborted(EffectId),
    /// One committed effect drained and returned its typed credit.
    Drained(EffectId),
    /// A committed guest reply must still be published exactly once.
    AwaitingGuestReply(GuestReplyTicket),
}

/// Read-only projection of one service domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeNetDomainView {
    /// Current binding generation.
    pub binding_epoch: NetBindingEpoch,
    /// Bound service, if any.
    pub service: Option<NetServiceId>,
    /// Kernel fallback/replacement state.
    pub fallback: NetFallbackState,
    /// Number of domain mutations covered by recovery snapshots.
    pub revision: u64,
    /// Effects still awaiting explicit adoption.
    pub recovery_cohort: Vec<EffectId>,
}

/// Read-only projection of one runtime-network effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeNetEffectView {
    /// Current fenced effect token.
    pub token: RuntimeNetEffectToken,
    /// Lifecycle phase.
    pub phase: NetEffectPhase,
    /// Typed credit retained by this effect until terminalization.
    pub credit: NetCreditClass,
    /// Global commit sequence, if committed.
    pub commit_sequence: Option<u64>,
    /// Whether a guest reply ticket remains unpublished.
    pub publication_pending: bool,
    /// Whether the unique guest reply was published.
    pub guest_published: bool,
    /// Number of terminal transitions; always zero or one.
    pub terminalizations: u8,
}

/// Read-only projection of one root network scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeNetScopeView {
    /// Scope lifecycle.
    pub state: ScopeState,
    /// Current root authority generation.
    pub authority_epoch: NetAuthorityEpoch,
    /// Current socket generation.
    pub socket_generation: SocketGeneration,
    /// Current kernel-owned readiness-source generation.
    pub source_generation: ReadySourceGeneration,
    /// Immutable initial credit capacity.
    pub initial_credits: NetCredits,
    /// Credits not retained by live effects.
    pub free_credits: NetCredits,
    /// Historical network payload publications.
    pub network_publications: u64,
    /// Historical readiness publications.
    pub readiness_publications: u64,
    /// Historical kernel-owned readiness deliveries.
    pub ready_deliveries: u64,
    /// Historical guest reply publications.
    pub guest_replies: u64,
    /// Historical explicit buffer consumptions.
    pub buffer_consumptions: u64,
    /// Currently visible bounded payloads.
    pub visible_buffers: usize,
    /// Historical effects retained for audit.
    pub effects: usize,
    /// Nonterminal effects.
    pub live_effects: usize,
    /// Pending guest reply tickets.
    pub pending_publications: usize,
    /// Frozen closure target count, if closing or revoked.
    pub closure_target_count: usize,
    /// Effects terminalized by the current root closure.
    pub closure_steps: usize,
}

/// Rejected runtime-network transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeNetError {
    /// The scope does not exist.
    UnknownScope(ScopeId),
    /// The effect does not exist.
    UnknownEffect(EffectId),
    /// A scope is not in the required lifecycle state.
    InvalidScopeState(ScopeState),
    /// A root authority generation was closed.
    StaleAuthority {
        /// Presented generation.
        presented: NetAuthorityEpoch,
        /// Current generation.
        current: NetAuthorityEpoch,
    },
    /// A service binding generation is stale.
    StaleBinding {
        /// Presented generation.
        presented: NetBindingEpoch,
        /// Current generation.
        current: NetBindingEpoch,
    },
    /// A network operation names an old socket generation.
    StaleSocketGeneration {
        /// Presented generation.
        presented: SocketGeneration,
        /// Current generation.
        current: SocketGeneration,
    },
    /// A readiness operation names an old source generation.
    StaleSourceGeneration {
        /// Presented generation.
        presented: ReadySourceGeneration,
        /// Current generation.
        current: ReadySourceGeneration,
    },
    /// A token names the wrong service domain.
    WrongDomain,
    /// A binding names a service other than the installed service.
    WrongService,
    /// No service is currently bound.
    ServiceUnavailable,
    /// A replacement service identity is invalid or already installed.
    ServiceAlreadyBound,
    /// Kernel fallback is not at the required handshake state.
    FallbackUnavailable,
    /// A recovery snapshot or ready proof was invalidated.
    StaleRecoverySnapshot,
    /// An effect is not eligible for explicit adoption.
    NotAdoptable,
    /// An effect token differs from the current kernel record.
    EffectIdentityMismatch,
    /// An effect is not in the phase required by the operation.
    InvalidEffectState(NetEffectPhase),
    /// A parent cannot terminalize while a live child remains.
    LiveDescendants,
    /// One typed credit class is exhausted.
    CreditExhausted(NetCreditClass),
    /// A commit or immutable receipt was presented more than once.
    AlreadyCommitted,
    /// A network receipt is stale, forged, or unrelated.
    InvalidNetReceipt,
    /// A readiness receipt is stale, forged, or unrelated.
    InvalidReadyReceipt,
    /// A buffer lease or its payload is absent or already consumed.
    InvalidBufferLease,
    /// A publication ticket is stale, forged, or already consumed.
    InvalidPublication,
    /// A guest reply publication was attempted twice.
    AlreadyPublished,
    /// A revoke ticket does not describe the current closure.
    StaleRevokeTicket,
    /// Root closure is not quiescent yet.
    NotQuiescent,
    /// A monotonically increasing identity or counter overflowed.
    CounterOverflow,
    /// Internal state relationships were inconsistent.
    InvariantViolation(&'static str),
}

/// Failure reported by a full runtime-network invariant audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeNetInvariantViolation {
    /// Typed credits were lost or duplicated.
    CreditConservation(ScopeId),
    /// A causal edge or domain-kind relationship is invalid.
    EffectGraph(EffectId),
    /// Terminalization count disagrees with effect phase.
    Terminalization(EffectId),
    /// Commit receipts, payloads, or effect phases disagree.
    PublicationState(EffectId),
    /// Scope reverse indexes disagree with effect records.
    ScopeIndex(ScopeId),
    /// Generation or publication counters disagree with retained history.
    GenerationAccounting(ScopeId),
    /// Service/fallback/recovery metadata is inconsistent.
    RecoveryState(ScopeId),
    /// Root revocation metadata is inconsistent.
    RevocationState(ScopeId),
    /// A revoked scope retains live work, payloads, or credits.
    RevokedScope(ScopeId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DomainRecord {
    binding_epoch: NetBindingEpoch,
    service: Option<NetServiceId>,
    fallback: NetFallbackState,
    revision: u64,
    recovery_cohort: BTreeSet<EffectId>,
    ready: Option<ReadyRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadyRecord {
    replacement: NetServiceId,
    authority_epoch: NetAuthorityEpoch,
    binding_epoch: NetBindingEpoch,
    socket_generation: SocketGeneration,
    source_generation: ReadySourceGeneration,
    domain_revision: u64,
    cohort: BTreeSet<EffectId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectRecord {
    token: RuntimeNetEffectToken,
    phase: NetEffectPhase,
    credit: NetCreditClass,
    commit_sequence: Option<u64>,
    terminalizations: u8,
    net_receipt: Option<NetCommitReceipt>,
    ready_receipt: Option<ReadyCommitReceipt>,
    publication: Option<GuestReplyTicket>,
    guest_published: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BufferRecord {
    effect: EffectId,
    network_effect: EffectId,
    net_sequence: u64,
    payload: [u8; 4],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RevocationRecord {
    ticket: RuntimeNetRevokeTicket,
    frozen: BTreeSet<EffectId>,
    closure_steps: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScopeRecord {
    state: ScopeState,
    authority_epoch: NetAuthorityEpoch,
    socket_generation: SocketGeneration,
    source_generation: ReadySourceGeneration,
    domains: BTreeMap<NetDomain, DomainRecord>,
    initial_credits: NetCredits,
    free_credits: NetCredits,
    effects: BTreeSet<EffectId>,
    buffers: BTreeMap<EffectId, BufferRecord>,
    network_publications: u64,
    readiness_publications: u64,
    ready_deliveries: u64,
    guest_replies: u64,
    buffer_consumptions: u64,
    revocation: Option<RevocationRecord>,
}

/// Deterministic safe-Rust runtime-network protocol oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeNetModel {
    next_scope: u64,
    next_effect: u64,
    next_commit_sequence: u64,
    next_publication_sequence: u64,
    next_revoke_sequence: u64,
    scopes: BTreeMap<ScopeId, ScopeRecord>,
    effects: BTreeMap<EffectId, EffectRecord>,
}
