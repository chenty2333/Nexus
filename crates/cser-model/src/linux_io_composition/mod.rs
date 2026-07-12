//! Additive seven-domain Linux I/O composition successor.
//!
//! This model deliberately does not widen the frozen five-domain
//! [`crate::composition`] predecessor. It fixes one bounded root graph with
//! two personality syscall roots so the filesystem and network successors
//! retain distinct guest-reply obligations:
//!
//! ```text
//! Root -> {FsSyscall, NetSyscall}
//! FsSyscall -> {PagerMap -> SchedulerAction, FsOp -> BlockReq}
//! NetSyscall -> NetOp -> {ReadinessWait, BufferLease}
//! ```
//!
//! Seven service domains own nine effects and eight credit classes (Control
//! has capacity two). One clone/validate/swap gate linearizes effect commit,
//! root revoke, recovery, closure receipts, and the retained VirtIO timeout
//! tombstone. This is a bounded protocol oracle, not a general Linux, VFS,
//! TCP/IP, device, or SMP implementation.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

/// Number of independently restartable service domains in the successor.
pub const DOMAIN_COUNT: usize = 7;
/// Number of fixed effects in the two-branch causal graph.
pub const EFFECT_COUNT: usize = 9;
/// Number of independently conserved credit classes.
pub const CREDIT_CLASS_COUNT: usize = 8;

/// The seven bounded service domains below one root authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DomainId {
    /// Linux syscall and guest-reply effects.
    Personality,
    /// Mapping and TLB-synchronization effects.
    Pager,
    /// Scheduling proposal and fallback effects.
    Scheduler,
    /// In-memory inode operation effects.
    Filesystem,
    /// Queue, DMA, reset, and IOTLB effects.
    VirtIo,
    /// Socket operation and buffer ownership effects.
    Network,
    /// Readiness wait and delivery effects.
    Readiness,
}

impl DomainId {
    /// Deterministic full domain set.
    pub const ALL: [Self; DOMAIN_COUNT] = [
        Self::Personality,
        Self::Pager,
        Self::Scheduler,
        Self::Filesystem,
        Self::VirtIo,
        Self::Network,
        Self::Readiness,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    /// Causal parent domain. Personality is rooted directly in the authority.
    #[must_use]
    pub const fn parent(self) -> Option<Self> {
        match self {
            Self::Personality => None,
            Self::Pager | Self::Filesystem | Self::Network => Some(Self::Personality),
            Self::Scheduler => Some(Self::Pager),
            Self::VirtIo => Some(Self::Filesystem),
            Self::Readiness => Some(Self::Network),
        }
    }

    /// Number of effects owned by this domain in the fixed graph.
    #[must_use]
    pub const fn effect_count(self) -> u64 {
        match self {
            Self::Personality | Self::Network => 2,
            _ => 1,
        }
    }
}

/// Exact effect labels in causal registration order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EffectKind {
    /// Filesystem syscall controller.
    FsSyscall,
    /// Network syscall controller.
    NetSyscall,
    /// Pager mapping effect.
    PagerMap,
    /// Scheduler action derived from the mapping.
    SchedulerAction,
    /// Filesystem inode mutation.
    FsOp,
    /// Mediated block request.
    BlockReq,
    /// Bounded network operation.
    NetOp,
    /// Readiness wait derived from the network operation.
    ReadinessWait,
    /// Payload buffer lease derived from the network operation.
    BufferLease,
}

impl EffectKind {
    /// Deterministic full effect set.
    pub const ALL: [Self; EFFECT_COUNT] = [
        Self::FsSyscall,
        Self::NetSyscall,
        Self::PagerMap,
        Self::SchedulerAction,
        Self::FsOp,
        Self::BlockReq,
        Self::NetOp,
        Self::ReadinessWait,
        Self::BufferLease,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    /// Stable numeric effect identity.
    #[must_use]
    pub const fn effect_id(self) -> u64 {
        self.index() as u64 + 1
    }

    /// Owning service domain.
    #[must_use]
    pub const fn domain(self) -> DomainId {
        match self {
            Self::FsSyscall | Self::NetSyscall => DomainId::Personality,
            Self::PagerMap => DomainId::Pager,
            Self::SchedulerAction => DomainId::Scheduler,
            Self::FsOp => DomainId::Filesystem,
            Self::BlockReq => DomainId::VirtIo,
            Self::NetOp | Self::BufferLease => DomainId::Network,
            Self::ReadinessWait => DomainId::Readiness,
        }
    }

    /// Immutable causal parent effect, or the root authority.
    #[must_use]
    pub const fn parent(self) -> Option<Self> {
        match self {
            Self::FsSyscall | Self::NetSyscall => None,
            Self::PagerMap | Self::FsOp => Some(Self::FsSyscall),
            Self::SchedulerAction => Some(Self::PagerMap),
            Self::BlockReq => Some(Self::FsOp),
            Self::NetOp => Some(Self::NetSyscall),
            Self::ReadinessWait | Self::BufferLease => Some(Self::NetOp),
        }
    }

    /// Conserved credit class held by this effect.
    #[must_use]
    pub const fn credit(self) -> CreditClass {
        match self {
            Self::FsSyscall | Self::NetSyscall => CreditClass::Control,
            Self::PagerMap => CreditClass::Memory,
            Self::SchedulerAction => CreditClass::Cpu,
            Self::FsOp => CreditClass::Filesystem,
            Self::BlockReq => CreditClass::Dma,
            Self::NetOp => CreditClass::Network,
            Self::ReadinessWait => CreditClass::Readiness,
            Self::BufferLease => CreditClass::Buffer,
        }
    }

    /// Exact publication point crossed by commit.
    #[must_use]
    pub const fn publication(self) -> PublicationPoint {
        match self {
            Self::FsSyscall => PublicationPoint::FsReply,
            Self::NetSyscall => PublicationPoint::NetReply,
            Self::PagerMap => PublicationPoint::Map,
            Self::SchedulerAction => PublicationPoint::Dispatch,
            Self::FsOp => PublicationPoint::Inode,
            Self::BlockReq => PublicationPoint::AvailIdx,
            Self::NetOp => PublicationPoint::NetCommit,
            Self::ReadinessWait => PublicationPoint::ReadyCommit,
            Self::BufferLease => PublicationPoint::BufferVisible,
        }
    }

    const fn generation(self) -> Option<GenerationKind> {
        match self {
            Self::PagerMap => Some(GenerationKind::AddressSpace),
            Self::FsOp => Some(GenerationKind::Inode),
            Self::BlockReq => Some(GenerationKind::Device),
            Self::NetOp | Self::BufferLease => Some(GenerationKind::Socket),
            Self::ReadinessWait => Some(GenerationKind::Source),
            Self::FsSyscall | Self::NetSyscall | Self::SchedulerAction => None,
        }
    }
}

/// Independently conserved credit classes. Control has capacity two.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CreditClass {
    /// Two syscall-controller credits.
    Control,
    /// One prepared mapping credit.
    Memory,
    /// One scheduler action credit.
    Cpu,
    /// One inode mutation credit.
    Filesystem,
    /// One DMA/request credit.
    Dma,
    /// One network operation credit.
    Network,
    /// One readiness credit.
    Readiness,
    /// One payload buffer credit.
    Buffer,
}

impl CreditClass {
    /// Deterministic full credit-class set.
    pub const ALL: [Self; CREDIT_CLASS_COUNT] = [
        Self::Control,
        Self::Memory,
        Self::Cpu,
        Self::Filesystem,
        Self::Dma,
        Self::Network,
        Self::Readiness,
        Self::Buffer,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    /// Fixed capacity for this bounded graph.
    #[must_use]
    pub const fn capacity(self) -> u64 {
        match self {
            Self::Control => 2,
            _ => 1,
        }
    }
}

/// Domain-specific resource-generation dimensions.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GenerationKind {
    /// Pager address-space generation.
    AddressSpace,
    /// Filesystem inode generation.
    Inode,
    /// VirtIO device generation.
    Device,
    /// Network socket generation.
    Socket,
    /// Readiness source generation.
    Source,
}

impl GenerationKind {
    const fn index(self) -> usize {
        self as usize
    }

    const fn domain(self) -> DomainId {
        match self {
            Self::AddressSpace => DomainId::Pager,
            Self::Inode => DomainId::Filesystem,
            Self::Device => DomainId::VirtIo,
            Self::Socket => DomainId::Network,
            Self::Source => DomainId::Readiness,
        }
    }
}

/// The nine distinct publication boundaries.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PublicationPoint {
    /// Filesystem guest reply.
    FsReply,
    /// Network guest reply.
    NetReply,
    /// PTE mapping publication.
    Map,
    /// Scheduler dispatch publication.
    Dispatch,
    /// Inode mutation publication.
    Inode,
    /// VirtIO avail-index publication.
    AvailIdx,
    /// Network operation publication.
    NetCommit,
    /// Readiness commit publication.
    ReadyCommit,
    /// Buffer visibility publication.
    BufferVisible,
}

impl PublicationPoint {
    const fn index(self) -> usize {
        self as usize
    }
}

/// Root authority lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootPhase {
    /// Registration and commit gate open.
    Active,
    /// Root epoch advanced and exact cohort frozen.
    Closing,
    /// All domain receipts accepted and resources quiescent.
    Revoked,
}

/// Effect lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectPhase {
    /// Registered but not prepared.
    Registered,
    /// Prepared but not published.
    Prepared,
    /// Published and kernel-owned.
    Committed,
    /// Retained behind an honest device timeout.
    Tombstoned,
    /// Drained after publication.
    Completed,
    /// Aborted before publication.
    Aborted,
}

impl EffectPhase {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

/// One reverse-index closure step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseStep {
    /// Uncommitted effect aborted.
    Aborted(EffectKind),
    /// Committed effect drained.
    Drained(EffectKind),
    /// The selected domain still owns an effect with live children.
    BlockedByDescendants,
    /// VirtIO reset/IOTLB acknowledgement remains external.
    NeedsQuiescence,
}

/// Authoritative domain receipt status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptStatus {
    /// Domain has no remaining live effects or credits.
    Closed,
    /// VirtIO retains one effect and DMA credit.
    TimedOut,
}

/// Complete service-visible identity for one fixed effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectToken {
    effect_id: u64,
    kind: EffectKind,
    authority_epoch: u64,
    binding_epoch: u64,
    generation: u64,
}

impl EffectToken {
    /// Stable numeric effect identity.
    #[must_use]
    pub const fn effect_id(self) -> u64 {
        self.effect_id
    }
    /// Semantic effect kind.
    #[must_use]
    pub const fn kind(self) -> EffectKind {
        self.kind
    }
    /// Captured root authority epoch.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }
    /// Captured owning-domain binding epoch.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }
    /// Captured applicable resource generation, or zero when not applicable.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
    /// Produces a stale-authority token for negative testing.
    #[must_use]
    pub const fn with_authority_epoch(mut self, authority_epoch: u64) -> Self {
        self.authority_epoch = authority_epoch;
        self
    }
    /// Produces a stale-binding token for negative testing.
    #[must_use]
    pub const fn with_binding_epoch(mut self, binding_epoch: u64) -> Self {
        self.binding_epoch = binding_epoch;
        self
    }
    /// Produces a stale-generation token for negative testing.
    #[must_use]
    pub const fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }
}

/// Immutable receipt for one committed publication point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    token: EffectToken,
    sequence: u64,
    publication: PublicationPoint,
}

impl CommitReceipt {
    /// Effect identity authorized by this receipt.
    #[must_use]
    pub const fn token(self) -> EffectToken {
        self.token
    }
    /// Global commit sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    /// Exact publication boundary.
    #[must_use]
    pub const fn publication(self) -> PublicationPoint {
        self.publication
    }
}

/// Exact old-binding recovery cohort.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySnapshot {
    domain: DomainId,
    binding_epoch: u64,
    revision: u64,
    cohort: Vec<EffectToken>,
}

impl RecoverySnapshot {
    /// Immutable adoption cohort.
    #[must_use]
    pub fn cohort(&self) -> &[EffectToken] {
        &self.cohort
    }
}

/// Proof that an exact recovery snapshot is ready for rebind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyToken {
    snapshot: RecoverySnapshot,
}

/// Exact root closure cohort.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootRevokeTicket {
    closed_authority_epoch: u64,
    authority_epoch: u64,
    sequence: u64,
    frozen_effects: BTreeSet<u64>,
    frozen_domains: BTreeSet<DomainId>,
}

impl RootRevokeTicket {
    /// Authority epoch closed by the revoke.
    #[must_use]
    pub const fn closed_authority_epoch(&self) -> u64 {
        self.closed_authority_epoch
    }
    /// New closing authority epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }
    /// Number of frozen effects.
    #[must_use]
    pub fn frozen_effects(&self) -> usize {
        self.frozen_effects.len()
    }
    /// Number of frozen domains.
    #[must_use]
    pub fn frozen_domains(&self) -> usize {
        self.frozen_domains.len()
    }
}

/// One globally sequenced domain closure receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainClosureReceipt {
    domain: DomainId,
    sequence: u64,
    revision: u64,
    domain_revision: u64,
    closed_authority_epoch: u64,
    authority_epoch: u64,
    binding_epoch: u64,
    generation: u64,
    effect_count: u64,
    credit_units: u64,
    status: ReceiptStatus,
}

impl DomainClosureReceipt {
    /// Receipt domain.
    #[must_use]
    pub const fn domain(self) -> DomainId {
        self.domain
    }
    /// Global receipt sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    /// Global receipt revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }
    /// Closed or honest timeout status.
    #[must_use]
    pub const fn status(self) -> ReceiptStatus {
        self.status
    }
    /// Number of effects covered by this domain receipt.
    #[must_use]
    pub const fn effect_count(self) -> u64 {
        self.effect_count
    }
    /// Number of credit units covered by this receipt.
    #[must_use]
    pub const fn credit_units(self) -> u64 {
        self.credit_units
    }
    /// Produces a stale-authority receipt for negative testing.
    #[must_use]
    pub const fn with_authority_epoch(mut self, authority_epoch: u64) -> Self {
        self.authority_epoch = authority_epoch;
        self
    }
    /// Produces an out-of-order receipt for negative testing.
    #[must_use]
    pub const fn with_sequence(mut self, sequence: u64) -> Self {
        self.sequence = sequence;
        self.revision = sequence;
        self
    }
}

/// Retained VirtIO timeout identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TombstoneToken {
    id: u64,
    effect: EffectKind,
    device_generation: u64,
}

/// Failure classes exposed by the bounded successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompositionError {
    /// Root registration/commit gate is not active.
    RootNotActive,
    /// Presented root authority epoch is stale.
    StaleAuthority,
    /// Presented owning-domain binding epoch is stale.
    StaleBinding,
    /// Presented resource generation is stale.
    StaleGeneration,
    /// Owning service domain is not rebound.
    DomainUnavailable,
    /// Effect is in the wrong lifecycle phase.
    InvalidEffectState,
    /// Immutable commit receipt does not match.
    CommitReceiptMismatch,
    /// Recovery snapshot was invalidated.
    SnapshotInvalidated,
    /// Recovery operation is out of order.
    InvalidRecovery,
    /// Effect is not in the old-binding adoption cohort.
    EffectNotRecoverable,
    /// Root revoke ticket is stale or foreign.
    InvalidRevokeTicket,
    /// Domain was not in the frozen root cohort.
    DomainNotFrozen,
    /// A causal child remains live or unacknowledged.
    LiveDescendant,
    /// Domain cannot yet issue a Closed receipt.
    DomainNotQuiescent,
    /// Accepted timeout receipt is required before retry.
    TombstoneRequired,
    /// Effect is not eligible for a retained timeout.
    TombstoneNotEligible,
    /// Tombstone identity or retry phase is invalid.
    InvalidTombstone,
    /// Receipt was already issued or accepted.
    DuplicateReceipt,
    /// Receipt authority, binding, generation, or revision is stale.
    StaleReceipt,
    /// Receipt sequence is not the next global sequence.
    OutOfOrderReceipt,
    /// Another receipt is awaiting acceptance.
    ReceiptPending,
    /// Not all seven current Closed receipts exist.
    ClosureReceiptsIncomplete,
    /// A current accepted VirtIO timeout still retains ownership.
    RevokeTimedOut,
    /// Bounded counter overflowed.
    CounterOverflow,
    /// Internal topology, credit, index, or receipt invariant failed.
    InvariantViolation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EffectRecord {
    token: EffectToken,
    phase: EffectPhase,
    commit: Option<CommitReceipt>,
    publication_pending: bool,
    terminalizations: u8,
    adoptions: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoveryState {
    revision: u64,
    cohort: BTreeSet<u64>,
    unadopted: BTreeSet<u64>,
    snapshot: Option<RecoverySnapshot>,
    ready: bool,
    rebound: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TombstoneRecord {
    token: TombstoneToken,
    retried: bool,
}

/// Stable observable state used by negative and property tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionProjection {
    /// Root phase.
    pub phase: RootPhase,
    /// Current root authority epoch.
    pub authority_epoch: u64,
    /// Seven independent binding epochs.
    pub bindings: [u64; DOMAIN_COUNT],
    /// AS, inode, device, socket, and source generations.
    pub generations: [u64; 5],
    /// Nine effect phases in stable order.
    pub effect_phases: Vec<EffectPhase>,
    /// Free units by credit class.
    pub free_credits: [u64; CREDIT_CLASS_COUNT],
    /// Live effect counts by domain.
    pub live_by_domain: [usize; DOMAIN_COUNT],
    /// Publication counts by publication point.
    pub publications: [u64; EFFECT_COUNT],
    /// Total accepted receipt history, including invalidated timeouts.
    pub accepted_receipts: usize,
    /// Number of invalidated timeout receipts.
    pub invalidated_receipts: usize,
    /// Current global receipt revision.
    pub receipt_revision: u64,
    /// Whether one receipt is staged but unaccepted.
    pub pending_receipt: bool,
    /// Whether a VirtIO timeout tombstone exists.
    pub tombstone: bool,
    /// Number of target-domain reverse-index selections.
    pub index_selections: u64,
}

/// Fixed seven-domain successor state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxIoCompositionModel {
    phase: RootPhase,
    authority_epoch: u64,
    bindings: [u64; DOMAIN_COUNT],
    bound: [bool; DOMAIN_COUNT],
    generations: [u64; 5],
    effects: Vec<EffectRecord>,
    live_by_domain: [BTreeSet<u64>; DOMAIN_COUNT],
    live_children: [BTreeSet<u64>; EFFECT_COUNT],
    free_credits: [u64; CREDIT_CLASS_COUNT],
    publications: [u64; EFFECT_COUNT],
    domain_revisions: [u64; DOMAIN_COUNT],
    recovery: [Option<RecoveryState>; DOMAIN_COUNT],
    revoke: Option<RootRevokeTicket>,
    next_commit_sequence: u64,
    next_revoke_sequence: u64,
    next_recovery_revision: u64,
    next_receipt_sequence: u64,
    receipt_revision: u64,
    pending_receipt: Option<DomainClosureReceipt>,
    accepted_receipts: BTreeMap<u64, DomainClosureReceipt>,
    current_receipt: BTreeMap<DomainId, u64>,
    invalidated_receipts: BTreeSet<u64>,
    tombstone: Option<TombstoneRecord>,
    next_tombstone: u64,
    virtio_quiesced: bool,
    index_selections: u64,
}

impl Default for LinuxIoCompositionModel {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxIoCompositionModel {
    /// Constructs the complete fixed graph under authority epoch one.
    #[must_use]
    pub fn new() -> Self {
        let bindings = [1; DOMAIN_COUNT];
        let generations = [1; 5];
        let effects = EffectKind::ALL
            .into_iter()
            .map(|kind| EffectRecord {
                token: EffectToken {
                    effect_id: kind.effect_id(),
                    kind,
                    authority_epoch: 1,
                    binding_epoch: bindings[kind.domain().index()],
                    generation: kind
                        .generation()
                        .map_or(0, |item| generations[item.index()]),
                },
                phase: EffectPhase::Registered,
                commit: None,
                publication_pending: false,
                terminalizations: 0,
                adoptions: 0,
            })
            .collect::<Vec<_>>();
        let mut live_by_domain: [BTreeSet<u64>; DOMAIN_COUNT] =
            core::array::from_fn(|_| BTreeSet::new());
        let mut live_children: [BTreeSet<u64>; EFFECT_COUNT] =
            core::array::from_fn(|_| BTreeSet::new());
        for kind in EffectKind::ALL {
            live_by_domain[kind.domain().index()].insert(kind.effect_id());
            if let Some(parent) = kind.parent() {
                live_children[parent.index()].insert(kind.effect_id());
            }
        }
        let model = Self {
            phase: RootPhase::Active,
            authority_epoch: 1,
            bindings,
            bound: [true; DOMAIN_COUNT],
            generations,
            effects,
            live_by_domain,
            live_children,
            free_credits: [0; CREDIT_CLASS_COUNT],
            publications: [0; EFFECT_COUNT],
            domain_revisions: [1; DOMAIN_COUNT],
            recovery: core::array::from_fn(|_| None),
            revoke: None,
            next_commit_sequence: 1,
            next_revoke_sequence: 1,
            next_recovery_revision: 1,
            next_receipt_sequence: 1,
            receipt_revision: 0,
            pending_receipt: None,
            accepted_receipts: BTreeMap::new(),
            current_receipt: BTreeMap::new(),
            invalidated_receipts: BTreeSet::new(),
            tombstone: None,
            next_tombstone: 1,
            virtio_quiesced: false,
            index_selections: 0,
        };
        debug_assert_eq!(model.check_invariants(), Ok(()));
        model
    }

    fn record(&self, kind: EffectKind) -> &EffectRecord {
        &self.effects[kind.index()]
    }

    fn record_mut(&mut self, kind: EffectKind) -> &mut EffectRecord {
        &mut self.effects[kind.index()]
    }

    fn current_generation(&self, kind: EffectKind) -> u64 {
        kind.generation()
            .map_or(0, |item| self.generations[item.index()])
    }

    fn validate_token(&self, token: EffectToken) -> Result<(), CompositionError> {
        let record = self.record(token.kind);
        if token.effect_id != token.kind.effect_id() {
            return Err(CompositionError::StaleGeneration);
        }
        if token.authority_epoch != self.authority_epoch || self.phase != RootPhase::Active {
            return Err(CompositionError::StaleAuthority);
        }
        let domain = token.kind.domain();
        if token.binding_epoch != self.bindings[domain.index()] {
            return Err(CompositionError::StaleBinding);
        }
        if !self.bound[domain.index()] {
            return Err(CompositionError::DomainUnavailable);
        }
        if token.generation != self.current_generation(token.kind) {
            return Err(CompositionError::StaleGeneration);
        }
        if record.token != token {
            return Err(CompositionError::StaleGeneration);
        }
        Ok(())
    }

    fn mutate_failure_atomically<T>(
        &mut self,
        action: impl FnOnce(&mut Self) -> Result<T, CompositionError>,
    ) -> Result<T, CompositionError> {
        let mut candidate = self.clone();
        let value = action(&mut candidate)?;
        candidate.check_invariants()?;
        *self = candidate;
        Ok(value)
    }

    /// Returns the current token for one fixed effect.
    #[must_use]
    pub fn token(&self, kind: EffectKind) -> EffectToken {
        self.record(kind).token
    }

    /// Marks a registered effect ready for its publication point.
    pub fn prepare(&mut self, token: EffectToken) -> Result<(), CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            candidate.validate_token(token)?;
            let record = candidate.record_mut(token.kind);
            if record.phase != EffectPhase::Registered {
                return Err(CompositionError::InvalidEffectState);
            }
            record.phase = EffectPhase::Prepared;
            candidate.domain_revisions[token.kind.domain().index()] += 1;
            Ok(())
        })
    }

    /// Crosses the exact effect publication gate.
    pub fn commit(&mut self, token: EffectToken) -> Result<CommitReceipt, CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            candidate.validate_token(token)?;
            if candidate.record(token.kind).phase != EffectPhase::Prepared {
                return Err(CompositionError::InvalidEffectState);
            }
            let receipt = CommitReceipt {
                token,
                sequence: candidate.next_commit_sequence,
                publication: token.kind.publication(),
            };
            candidate.next_commit_sequence = candidate
                .next_commit_sequence
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?;
            let record = candidate.record_mut(token.kind);
            record.phase = EffectPhase::Committed;
            record.commit = Some(receipt);
            record.publication_pending = true;
            candidate.publications[receipt.publication.index()] += 1;
            candidate.domain_revisions[token.kind.domain().index()] += 1;
            Ok(receipt)
        })
    }

    /// Failure-atomically commits the network operation and buffer lease.
    pub fn commit_network(
        &mut self,
        network: EffectToken,
        buffer: EffectToken,
    ) -> Result<(CommitReceipt, CommitReceipt), CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            if network.kind != EffectKind::NetOp || buffer.kind != EffectKind::BufferLease {
                return Err(CompositionError::InvalidEffectState);
            }
            candidate.validate_token(network)?;
            candidate.validate_token(buffer)?;
            if candidate.record(network.kind).phase != EffectPhase::Prepared
                || candidate.record(buffer.kind).phase != EffectPhase::Prepared
            {
                return Err(CompositionError::InvalidEffectState);
            }
            let net_receipt = CommitReceipt {
                token: network,
                sequence: candidate.next_commit_sequence,
                publication: PublicationPoint::NetCommit,
            };
            let buffer_receipt = CommitReceipt {
                token: buffer,
                sequence: candidate.next_commit_sequence + 1,
                publication: PublicationPoint::BufferVisible,
            };
            candidate.next_commit_sequence = candidate
                .next_commit_sequence
                .checked_add(2)
                .ok_or(CompositionError::CounterOverflow)?;
            for receipt in [net_receipt, buffer_receipt] {
                let record = candidate.record_mut(receipt.token.kind);
                record.phase = EffectPhase::Committed;
                record.commit = Some(receipt);
                record.publication_pending = true;
                candidate.publications[receipt.publication.index()] += 1;
            }
            candidate.domain_revisions[DomainId::Network.index()] += 1;
            Ok((net_receipt, buffer_receipt))
        })
    }

    /// Commits readiness only from the exact network publication receipt.
    pub fn commit_ready(
        &mut self,
        ready: EffectToken,
        network: CommitReceipt,
    ) -> Result<CommitReceipt, CompositionError> {
        if network.token.kind != EffectKind::NetOp
            || self.record(EffectKind::NetOp).commit != Some(network)
        {
            return Err(CompositionError::CommitReceiptMismatch);
        }
        self.commit(ready)
    }

    /// Acknowledges one externally visible publication without terminalizing.
    pub fn acknowledge_publication(
        &mut self,
        receipt: CommitReceipt,
    ) -> Result<(), CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            let record = candidate.record_mut(receipt.token.kind);
            if record.commit != Some(receipt)
                || record.phase != EffectPhase::Committed
                || !record.publication_pending
            {
                return Err(CompositionError::CommitReceiptMismatch);
            }
            record.publication_pending = false;
            Ok(())
        })
    }

    /// Advances one typed generation, fencing all old service tokens.
    pub fn advance_generation(
        &mut self,
        generation: GenerationKind,
    ) -> Result<u64, CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            if candidate.phase != RootPhase::Active {
                return Err(CompositionError::RootNotActive);
            }
            let index = generation.index();
            candidate.generations[index] = candidate.generations[index]
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?;
            candidate.domain_revisions[generation.domain().index()] += 1;
            Ok(candidate.generations[index])
        })
    }

    /// Crashes exactly one domain. Committed work stays kernel-owned; only
    /// registered/prepared effects enter the service adoption cohort.
    pub fn crash(&mut self, domain: DomainId) -> Result<(), CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            if candidate.phase != RootPhase::Active || !candidate.bound[domain.index()] {
                return Err(CompositionError::DomainUnavailable);
            }
            candidate.bound[domain.index()] = false;
            candidate.bindings[domain.index()] = candidate.bindings[domain.index()]
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?;
            let cohort = candidate.live_by_domain[domain.index()]
                .iter()
                .copied()
                .filter(|effect| {
                    matches!(
                        candidate.effects[*effect as usize - 1].phase,
                        EffectPhase::Registered | EffectPhase::Prepared
                    )
                })
                .collect::<BTreeSet<_>>();
            candidate.domain_revisions[domain.index()] += 1;
            let revision = candidate.next_recovery_revision;
            candidate.next_recovery_revision += 1;
            candidate.recovery[domain.index()] = Some(RecoveryState {
                revision,
                cohort: cohort.clone(),
                unadopted: cohort,
                snapshot: None,
                ready: false,
                rebound: false,
            });
            Ok(())
        })
    }

    /// Captures the exact old-binding adoption cohort.
    pub fn recovery_snapshot(
        &mut self,
        domain: DomainId,
    ) -> Result<RecoverySnapshot, CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            let state = candidate.recovery[domain.index()]
                .as_ref()
                .ok_or(CompositionError::InvalidRecovery)?;
            if candidate.bound[domain.index()] || state.snapshot.is_some() {
                return Err(CompositionError::InvalidRecovery);
            }
            let cohort = state
                .cohort
                .iter()
                .map(|effect| candidate.effects[*effect as usize - 1].token)
                .collect();
            let snapshot = RecoverySnapshot {
                domain,
                binding_epoch: candidate.bindings[domain.index()],
                revision: state.revision,
                cohort,
            };
            candidate.recovery[domain.index()]
                .as_mut()
                .unwrap()
                .snapshot = Some(snapshot.clone());
            Ok(snapshot)
        })
    }

    /// Marks one exact recovery snapshot ready.
    pub fn ready(&mut self, snapshot: RecoverySnapshot) -> Result<ReadyToken, CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            let state = candidate.recovery[snapshot.domain.index()]
                .as_mut()
                .ok_or(CompositionError::InvalidRecovery)?;
            if state.snapshot.as_ref() != Some(&snapshot)
                || snapshot.binding_epoch != candidate.bindings[snapshot.domain.index()]
                || snapshot.revision != state.revision
            {
                return Err(CompositionError::SnapshotInvalidated);
            }
            state.ready = true;
            Ok(ReadyToken { snapshot })
        })
    }

    /// Rebinds exactly the domain named by the ready proof.
    pub fn rebind(&mut self, ready: &ReadyToken) -> Result<(), CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            let domain = ready.snapshot.domain;
            let state = candidate.recovery[domain.index()]
                .as_mut()
                .ok_or(CompositionError::InvalidRecovery)?;
            if !state.ready
                || state.snapshot.as_ref() != Some(&ready.snapshot)
                || candidate.bound[domain.index()]
            {
                return Err(CompositionError::InvalidRecovery);
            }
            state.rebound = true;
            candidate.bound[domain.index()] = true;
            Ok(())
        })
    }

    /// Explicitly adopts one old-binding uncommitted effect.
    pub fn adopt(
        &mut self,
        ready: &ReadyToken,
        old: EffectToken,
    ) -> Result<EffectToken, CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            let domain = ready.snapshot.domain;
            let state = candidate.recovery[domain.index()]
                .as_ref()
                .ok_or(CompositionError::InvalidRecovery)?;
            if !state.rebound
                || state.snapshot.as_ref() != Some(&ready.snapshot)
                || !state.unadopted.contains(&old.effect_id)
                || old.kind.domain() != domain
                || candidate.record(old.kind).token != old
                || candidate.current_generation(old.kind) != old.generation
            {
                return Err(CompositionError::EffectNotRecoverable);
            }
            let mut adopted = old;
            adopted.binding_epoch = candidate.bindings[domain.index()];
            let record = candidate.record_mut(old.kind);
            record.token = adopted;
            record.adoptions += 1;
            candidate.recovery[domain.index()]
                .as_mut()
                .unwrap()
                .unadopted
                .remove(&old.effect_id);
            candidate.domain_revisions[domain.index()] += 1;
            Ok(adopted)
        })
    }

    /// Linearizes the root authority transition and freezes the exact live
    /// effect/domain cohort through the same model gate as commit.
    pub fn revoke_begin(&mut self) -> Result<RootRevokeTicket, CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            if candidate.phase != RootPhase::Active {
                return Err(CompositionError::RootNotActive);
            }
            let closed = candidate.authority_epoch;
            candidate.authority_epoch = candidate
                .authority_epoch
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?;
            let frozen_effects = candidate
                .effects
                .iter()
                .filter(|record| !record.phase.is_terminal())
                .map(|record| record.token.effect_id)
                .collect::<BTreeSet<_>>();
            let frozen_domains = frozen_effects
                .iter()
                .map(|effect| candidate.effects[*effect as usize - 1].token.kind.domain())
                .collect::<BTreeSet<_>>();
            let ticket = RootRevokeTicket {
                closed_authority_epoch: closed,
                authority_epoch: candidate.authority_epoch,
                sequence: candidate.next_revoke_sequence,
                frozen_effects,
                frozen_domains,
            };
            candidate.next_revoke_sequence += 1;
            candidate.phase = RootPhase::Closing;
            candidate.bound = [false; DOMAIN_COUNT];
            candidate.recovery = core::array::from_fn(|_| None);
            candidate.revoke = Some(ticket.clone());
            Ok(ticket)
        })
    }

    fn validate_ticket(&self, ticket: &RootRevokeTicket) -> Result<(), CompositionError> {
        if self.phase != RootPhase::Closing || self.revoke.as_ref() != Some(ticket) {
            return Err(CompositionError::InvalidRevokeTicket);
        }
        Ok(())
    }

    fn effect_has_live_children(&self, kind: EffectKind) -> bool {
        !self.live_children[kind.index()].is_empty()
    }

    fn terminalize(&mut self, kind: EffectKind, phase: EffectPhase) {
        let effect = kind.effect_id();
        let record = self.record_mut(kind);
        record.phase = phase;
        record.publication_pending = false;
        record.terminalizations += 1;
        self.live_by_domain[kind.domain().index()].remove(&effect);
        if let Some(parent) = kind.parent() {
            self.live_children[parent.index()].remove(&effect);
        }
        self.free_credits[kind.credit().index()] += 1;
        self.domain_revisions[kind.domain().index()] += 1;
    }

    /// Selects at most one effect from the target domain reverse index.
    pub fn close_next(
        &mut self,
        ticket: &RootRevokeTicket,
        domain: DomainId,
    ) -> Result<Option<CloseStep>, CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            candidate.validate_ticket(ticket)?;
            if !ticket.frozen_domains.contains(&domain) {
                return Err(CompositionError::DomainNotFrozen);
            }
            candidate.index_selections += 1;
            let effect = candidate.live_by_domain[domain.index()]
                .iter()
                .copied()
                .find(|effect| {
                    let kind = candidate.effects[*effect as usize - 1].token.kind;
                    !candidate.effect_has_live_children(kind)
                });
            let Some(effect) = effect else {
                return if candidate.live_by_domain[domain.index()].is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(CloseStep::BlockedByDescendants))
                };
            };
            let kind = candidate.effects[effect as usize - 1].token.kind;
            match candidate.record(kind).phase {
                EffectPhase::Registered | EffectPhase::Prepared => {
                    candidate.terminalize(kind, EffectPhase::Aborted);
                    Ok(Some(CloseStep::Aborted(kind)))
                }
                EffectPhase::Committed
                    if kind == EffectKind::BlockReq && !candidate.virtio_quiesced =>
                {
                    Ok(Some(CloseStep::NeedsQuiescence))
                }
                EffectPhase::Committed => {
                    candidate.terminalize(kind, EffectPhase::Completed);
                    Ok(Some(CloseStep::Drained(kind)))
                }
                EffectPhase::Tombstoned => Ok(Some(CloseStep::NeedsQuiescence)),
                EffectPhase::Completed | EffectPhase::Aborted => {
                    Err(CompositionError::InvalidEffectState)
                }
            }
        })
    }

    /// Retains the committed VirtIO effect and DMA credit after timeout.
    pub fn timeout_virtio(
        &mut self,
        ticket: &RootRevokeTicket,
    ) -> Result<TombstoneToken, CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            candidate.validate_ticket(ticket)?;
            let record = candidate.record(EffectKind::BlockReq);
            if record.phase != EffectPhase::Committed
                || candidate.effect_has_live_children(EffectKind::BlockReq)
                || candidate.tombstone.is_some()
            {
                return Err(CompositionError::TombstoneNotEligible);
            }
            let token = TombstoneToken {
                id: candidate.next_tombstone,
                effect: EffectKind::BlockReq,
                device_generation: candidate.generations[GenerationKind::Device.index()],
            };
            candidate.next_tombstone += 1;
            candidate.record_mut(EffectKind::BlockReq).phase = EffectPhase::Tombstoned;
            candidate
                .record_mut(EffectKind::BlockReq)
                .publication_pending = false;
            candidate.tombstone = Some(TombstoneRecord {
                token,
                retried: false,
            });
            candidate.domain_revisions[DomainId::VirtIo.index()] += 1;
            Ok(token)
        })
    }

    /// Applies reset and IOTLB acknowledgement, advances device generation,
    /// invalidates the accepted timeout receipt, and permits fresh closure.
    pub fn retry_virtio(
        &mut self,
        ticket: &RootRevokeTicket,
        token: TombstoneToken,
    ) -> Result<u64, CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            candidate.validate_ticket(ticket)?;
            let tombstone = candidate
                .tombstone
                .ok_or(CompositionError::InvalidTombstone)?;
            if tombstone.token != token || tombstone.retried {
                return Err(CompositionError::InvalidTombstone);
            }
            let sequence = *candidate
                .current_receipt
                .get(&DomainId::VirtIo)
                .ok_or(CompositionError::TombstoneRequired)?;
            if candidate.accepted_receipts[&sequence].status != ReceiptStatus::TimedOut {
                return Err(CompositionError::TombstoneRequired);
            }
            candidate.invalidated_receipts.insert(sequence);
            candidate.current_receipt.remove(&DomainId::VirtIo);
            candidate.generations[GenerationKind::Device.index()] += 1;
            candidate.virtio_quiesced = true;
            candidate.tombstone.as_mut().unwrap().retried = true;
            candidate.record_mut(EffectKind::BlockReq).phase = EffectPhase::Committed;
            candidate.domain_revisions[DomainId::VirtIo.index()] += 1;
            Ok(candidate.generations[GenerationKind::Device.index()])
        })
    }

    fn has_unclosed_child_domain(&self, domain: DomainId) -> bool {
        DomainId::ALL.into_iter().any(|child| {
            child.parent() == Some(domain)
                && self
                    .revoke
                    .as_ref()
                    .is_some_and(|ticket| ticket.frozen_domains.contains(&child))
                && self.current_receipt.get(&child).is_none_or(|sequence| {
                    self.accepted_receipts[sequence].status != ReceiptStatus::Closed
                })
        })
    }

    fn domain_generation(&self, domain: DomainId) -> u64 {
        match domain {
            DomainId::Pager => self.generations[GenerationKind::AddressSpace.index()],
            DomainId::Filesystem => self.generations[GenerationKind::Inode.index()],
            DomainId::VirtIo => self.generations[GenerationKind::Device.index()],
            DomainId::Network => self.generations[GenerationKind::Socket.index()],
            DomainId::Readiness => self.generations[GenerationKind::Source.index()],
            DomainId::Personality | DomainId::Scheduler => 0,
        }
    }

    /// Issues one globally sequenced domain receipt. VirtIO may honestly
    /// report TimedOut while its effect and DMA credit remain live.
    pub fn issue_domain_receipt(
        &mut self,
        ticket: &RootRevokeTicket,
        domain: DomainId,
    ) -> Result<DomainClosureReceipt, CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            candidate.validate_ticket(ticket)?;
            if candidate.pending_receipt.is_some() {
                return Err(CompositionError::ReceiptPending);
            }
            if candidate.has_unclosed_child_domain(domain) {
                return Err(CompositionError::LiveDescendant);
            }
            let live = candidate.live_by_domain[domain.index()].len();
            let status = if live == 0 {
                ReceiptStatus::Closed
            } else if domain == DomainId::VirtIo
                && live == 1
                && candidate.record(EffectKind::BlockReq).phase == EffectPhase::Tombstoned
            {
                ReceiptStatus::TimedOut
            } else {
                return Err(CompositionError::DomainNotQuiescent);
            };
            if candidate.current_receipt.contains_key(&domain) {
                return Err(CompositionError::DuplicateReceipt);
            }
            let receipt = DomainClosureReceipt {
                domain,
                sequence: candidate.next_receipt_sequence,
                revision: candidate.receipt_revision + 1,
                domain_revision: candidate.domain_revisions[domain.index()],
                closed_authority_epoch: ticket.closed_authority_epoch,
                authority_epoch: ticket.authority_epoch,
                binding_epoch: candidate.bindings[domain.index()],
                generation: candidate.domain_generation(domain),
                effect_count: domain.effect_count(),
                credit_units: domain.effect_count(),
                status,
            };
            candidate.pending_receipt = Some(receipt);
            Ok(receipt)
        })
    }

    /// Accepts an exact receipt through the global sequence gate.
    pub fn accept_domain_receipt(
        &mut self,
        ticket: &RootRevokeTicket,
        receipt: DomainClosureReceipt,
    ) -> Result<(), CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            candidate.validate_ticket(ticket)?;
            if candidate.accepted_receipts.contains_key(&receipt.sequence) {
                return Err(CompositionError::DuplicateReceipt);
            }
            let Some(expected) = candidate.pending_receipt else {
                return Err(CompositionError::StaleReceipt);
            };
            if receipt.sequence != candidate.next_receipt_sequence
                || receipt.revision != candidate.receipt_revision + 1
            {
                return Err(CompositionError::OutOfOrderReceipt);
            }
            if receipt != expected
                || receipt.closed_authority_epoch != ticket.closed_authority_epoch
                || receipt.authority_epoch != ticket.authority_epoch
                || receipt.binding_epoch != candidate.bindings[receipt.domain.index()]
                || receipt.generation != candidate.domain_generation(receipt.domain)
                || receipt.domain_revision != candidate.domain_revisions[receipt.domain.index()]
            {
                return Err(CompositionError::StaleReceipt);
            }
            candidate.pending_receipt = None;
            candidate
                .accepted_receipts
                .insert(receipt.sequence, receipt);
            candidate
                .current_receipt
                .insert(receipt.domain, receipt.sequence);
            candidate.receipt_revision += 1;
            candidate.next_receipt_sequence += 1;
            Ok(())
        })
    }

    /// Completes the root only after seven current Closed receipts.
    pub fn revoke_complete(&mut self, ticket: &RootRevokeTicket) -> Result<(), CompositionError> {
        self.mutate_failure_atomically(|candidate| {
            candidate.validate_ticket(ticket)?;
            if candidate.current_receipt.len() != DOMAIN_COUNT
                || DomainId::ALL.into_iter().any(|domain| {
                    candidate
                        .current_receipt
                        .get(&domain)
                        .is_none_or(|sequence| {
                            candidate.accepted_receipts[sequence].status != ReceiptStatus::Closed
                        })
                })
                || candidate.pending_receipt.is_some()
                || candidate
                    .live_by_domain
                    .iter()
                    .any(|effects| !effects.is_empty())
            {
                if candidate.current_receipt.values().any(|sequence| {
                    candidate.accepted_receipts[sequence].status == ReceiptStatus::TimedOut
                }) {
                    return Err(CompositionError::RevokeTimedOut);
                }
                return Err(CompositionError::ClosureReceiptsIncomplete);
            }
            candidate.phase = RootPhase::Revoked;
            Ok(())
        })
    }

    /// Stable semantic projection.
    #[must_use]
    pub fn projection(&self) -> CompositionProjection {
        CompositionProjection {
            phase: self.phase,
            authority_epoch: self.authority_epoch,
            bindings: self.bindings,
            generations: self.generations,
            effect_phases: self.effects.iter().map(|record| record.phase).collect(),
            free_credits: self.free_credits,
            live_by_domain: core::array::from_fn(|index| self.live_by_domain[index].len()),
            publications: self.publications,
            accepted_receipts: self.accepted_receipts.len(),
            invalidated_receipts: self.invalidated_receipts.len(),
            receipt_revision: self.receipt_revision,
            pending_receipt: self.pending_receipt.is_some(),
            tombstone: self.tombstone.is_some(),
            index_selections: self.index_selections,
        }
    }

    /// Count for one publication boundary.
    #[must_use]
    pub fn publication_count(&self, point: PublicationPoint) -> u64 {
        self.publications[point.index()]
    }

    /// Current root authority epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// Current binding epoch for one domain.
    #[must_use]
    pub const fn binding_epoch(&self, domain: DomainId) -> u64 {
        self.bindings[domain.index()]
    }

    /// Current typed resource generation.
    #[must_use]
    pub const fn generation(&self, kind: GenerationKind) -> u64 {
        self.generations[kind.index()]
    }

    /// Checks fixed topology, exact reverse indexes, credit conservation,
    /// receipt sequencing, and final quiescence.
    pub fn check_invariants(&self) -> Result<(), CompositionError> {
        if self.authority_epoch == 0
            || self.bindings.contains(&0)
            || self.generations.contains(&0)
            || self.effects.len() != EFFECT_COUNT
            || self.next_receipt_sequence != self.receipt_revision + 1
            || self.receipt_revision
                != u64::try_from(self.accepted_receipts.len())
                    .map_err(|_| CompositionError::CounterOverflow)?
        {
            return Err(CompositionError::InvariantViolation);
        }
        let mut expected_live: [BTreeSet<u64>; DOMAIN_COUNT] =
            core::array::from_fn(|_| BTreeSet::new());
        let mut expected_children: [BTreeSet<u64>; EFFECT_COUNT] =
            core::array::from_fn(|_| BTreeSet::new());
        let mut held = [0_u64; CREDIT_CLASS_COUNT];
        for kind in EffectKind::ALL {
            let record = self.record(kind);
            if record.token.effect_id != kind.effect_id()
                || record.token.kind != kind
                || record.terminalizations > 1
                || record.adoptions > 1
                || record.publication_pending && record.phase != EffectPhase::Committed
                || record.commit.is_some()
                    != matches!(
                        record.phase,
                        EffectPhase::Committed | EffectPhase::Tombstoned | EffectPhase::Completed
                    )
            {
                return Err(CompositionError::InvariantViolation);
            }
            if !record.phase.is_terminal() {
                expected_live[kind.domain().index()].insert(kind.effect_id());
                held[kind.credit().index()] += 1;
            }
            if let Some(parent) = kind.parent()
                && !record.phase.is_terminal()
            {
                expected_children[parent.index()].insert(kind.effect_id());
            }
        }
        if self.live_by_domain != expected_live || self.live_children != expected_children {
            return Err(CompositionError::InvariantViolation);
        }
        for credit in CreditClass::ALL {
            if self.free_credits[credit.index()] + held[credit.index()] != credit.capacity() {
                return Err(CompositionError::InvariantViolation);
            }
        }
        for (offset, (sequence, receipt)) in self.accepted_receipts.iter().enumerate() {
            let expected =
                u64::try_from(offset + 1).map_err(|_| CompositionError::CounterOverflow)?;
            if *sequence != expected || receipt.sequence != expected || receipt.revision != expected
            {
                return Err(CompositionError::InvariantViolation);
            }
            let invalidated = self.invalidated_receipts.contains(sequence);
            if receipt.status == ReceiptStatus::TimedOut {
                if receipt.domain != DomainId::VirtIo || (!invalidated && self.tombstone.is_none())
                {
                    return Err(CompositionError::InvariantViolation);
                }
            } else if invalidated {
                return Err(CompositionError::InvariantViolation);
            }
        }
        for (domain, sequence) in &self.current_receipt {
            let receipt = self
                .accepted_receipts
                .get(sequence)
                .ok_or(CompositionError::InvariantViolation)?;
            if receipt.domain != *domain || self.invalidated_receipts.contains(sequence) {
                return Err(CompositionError::InvariantViolation);
            }
        }
        match self.phase {
            RootPhase::Active => {
                if self.revoke.is_some()
                    || self.pending_receipt.is_some()
                    || !self.accepted_receipts.is_empty()
                {
                    return Err(CompositionError::InvariantViolation);
                }
            }
            RootPhase::Closing => {
                if self.revoke.is_none() {
                    return Err(CompositionError::InvariantViolation);
                }
            }
            RootPhase::Revoked => {
                if self.current_receipt.len() != DOMAIN_COUNT
                    || self
                        .live_by_domain
                        .iter()
                        .any(|effects| !effects.is_empty())
                    || CreditClass::ALL
                        .into_iter()
                        .any(|credit| self.free_credits[credit.index()] != credit.capacity())
                {
                    return Err(CompositionError::InvariantViolation);
                }
            }
        }
        Ok(())
    }
}
