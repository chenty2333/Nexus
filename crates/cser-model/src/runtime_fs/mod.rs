//! Bounded runtime-filesystem CSER reference model.
//!
//! This successor models one fixed causal graph for a Linux `pwrite64` path:
//!
//! ```text
//! Root -> Syscall -> PagerMap
//!                 \-> FsOperation -> BlockRequest + retained DMA ownership
//! ```
//!
//! The model separates pager mapping publication, in-memory filesystem write
//! publication, mediated block `avail.idx` publication, guest-reply
//! publication, and DMA quiescence.  It is a deterministic `no_std + alloc`
//! protocol oracle, not a filesystem, block driver, IOMMU, or Linux ABI.

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
            /// Constructs a generation or identity from its raw value.
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
    /// Root authority generation advanced only by root `RevokeBegin`.
    AuthorityEpoch
);
scalar_type!(
    /// Restart generation of one user-space service domain.
    BindingEpoch
);
scalar_type!(
    /// Generation of the guest address-space mapping observed by the pager.
    AddressSpaceGeneration
);
scalar_type!(
    /// Generation of the bounded inode contents.
    InodeGeneration
);
scalar_type!(
    /// Reset-fenced generation of the mediated block device.
    DeviceGeneration
);
scalar_type!(
    /// Stable identity of one user-space service instance.
    ServiceId
);
scalar_type!(
    /// Stable identity of one retained DMA timeout tombstone.
    TombstoneId
);

/// Independently restartable service domains in the bounded filesystem path.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FsDomain {
    /// Linux personality and the trapped syscall continuation.
    Personality,
    /// User-space pager and guest-buffer mapping publication.
    Pager,
    /// User-space filesystem and inode write publication.
    Filesystem,
    /// User-space block service and mediated queue publication.
    Block,
}

impl FsDomain {
    /// Complete deterministic domain set.
    pub const ALL: [Self; 4] = [
        Self::Personality,
        Self::Pager,
        Self::Filesystem,
        Self::Block,
    ];
}

/// Fixed effect kinds in one bounded runtime-filesystem request.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FsEffectKind {
    /// Trapped `pwrite64` continuation owned by the Linux personality.
    Syscall,
    /// Pager mapping operation for the guest buffer.
    PagerMap,
    /// Filesystem operation that publishes the inode mutation.
    FsOperation,
    /// Mediated block request that owns the DMA lease.
    BlockRequest,
}

impl FsEffectKind {
    /// Returns the service domain allowed to own this effect kind.
    #[must_use]
    pub const fn domain(self) -> FsDomain {
        match self {
            Self::Syscall => FsDomain::Personality,
            Self::PagerMap => FsDomain::Pager,
            Self::FsOperation => FsDomain::Filesystem,
            Self::BlockRequest => FsDomain::Block,
        }
    }

    const fn credit(self) -> FsCreditClass {
        match self {
            Self::Syscall => FsCreditClass::Control,
            Self::PagerMap => FsCreditClass::Memory,
            Self::FsOperation => FsCreditClass::Filesystem,
            Self::BlockRequest => FsCreditClass::Dma,
        }
    }
}

/// Independently conserved renewable credit classes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FsCreditClass {
    /// One blocked syscall continuation.
    Control,
    /// One pager mapping obligation.
    Memory,
    /// One filesystem operation slot.
    Filesystem,
    /// One block queue/DMA ownership obligation.
    Dma,
}

/// Typed renewable credits held by a root scope or its live effects.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsCredits {
    control: u64,
    memory: u64,
    filesystem: u64,
    dma: u64,
}

impl FsCredits {
    /// A bundle with no credits.
    pub const ZERO: Self = Self::new(0, 0, 0, 0);

    /// Constructs a typed credit bundle.
    #[must_use]
    pub const fn new(control: u64, memory: u64, filesystem: u64, dma: u64) -> Self {
        Self {
            control,
            memory,
            filesystem,
            dma,
        }
    }

    /// One credit in every class, sufficient for one complete request graph.
    pub const ONE_REQUEST: Self = Self::new(1, 1, 1, 1);

    /// Returns the number of control credits.
    #[must_use]
    pub const fn control(self) -> u64 {
        self.control
    }

    /// Returns the number of memory credits.
    #[must_use]
    pub const fn memory(self) -> u64 {
        self.memory
    }

    /// Returns the number of filesystem credits.
    #[must_use]
    pub const fn filesystem(self) -> u64 {
        self.filesystem
    }

    /// Returns the number of DMA credits.
    #[must_use]
    pub const fn dma(self) -> u64 {
        self.dma
    }

    const fn one(class: FsCreditClass) -> Self {
        match class {
            FsCreditClass::Control => Self::new(1, 0, 0, 0),
            FsCreditClass::Memory => Self::new(0, 1, 0, 0),
            FsCreditClass::Filesystem => Self::new(0, 0, 1, 0),
            FsCreditClass::Dma => Self::new(0, 0, 0, 1),
        }
    }

    const fn get(self, class: FsCreditClass) -> u64 {
        match class {
            FsCreditClass::Control => self.control,
            FsCreditClass::Memory => self.memory,
            FsCreditClass::Filesystem => self.filesystem,
            FsCreditClass::Dma => self.dma,
        }
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self::new(
            self.control.checked_add(other.control)?,
            self.memory.checked_add(other.memory)?,
            self.filesystem.checked_add(other.filesystem)?,
            self.dma.checked_add(other.dma)?,
        ))
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        Some(Self::new(
            self.control.checked_sub(other.control)?,
            self.memory.checked_sub(other.memory)?,
            self.filesystem.checked_sub(other.filesystem)?,
            self.dma.checked_sub(other.dma)?,
        ))
    }

    fn contains(self, other: Self) -> bool {
        self.control >= other.control
            && self.memory >= other.memory
            && self.filesystem >= other.filesystem
            && self.dma >= other.dma
    }
}

/// Lifecycle of one effect in the fixed request graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsEffectPhase {
    /// Authority and one typed credit are reserved.
    Registered,
    /// Domain-private preparation is complete.
    Prepared,
    /// The domain-specific publication point was crossed.
    Committed,
    /// A DMA timeout retains the block effect and its credit.
    Tombstoned,
    /// The committed obligation completed exactly once.
    Completed,
    /// Root closure aborted an uncommitted obligation exactly once.
    Aborted,
}

impl FsEffectPhase {
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
pub enum FsFallbackState {
    /// A live service is bound.
    Standby,
    /// A crash was fenced and kernel fallback must run.
    Required,
    /// Kernel fallback is active and may expose a snapshot.
    Running,
    /// A replacement supplied a still-current ready proof.
    ReplacementReady,
}

/// Safety state of the block request's DMA ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsDmaState {
    /// No DMA mapping has been installed yet.
    Reserved,
    /// Preparation installed a mapping and retained backing resources.
    Mapped,
    /// Whole-device reset is in flight.
    ResetInFlight,
    /// Page-table removal occurred and IOTLB completion is outstanding.
    IotlbInFlight,
    /// A reset timeout retains all DMA ownership.
    ResetTimedOut,
    /// An IOTLB timeout retains all DMA ownership.
    IotlbTimedOut,
    /// IOTLB acknowledgement made the resources reusable.
    Released,
    /// This non-block effect never owns DMA state.
    NotApplicable,
}

/// Kind of retained DMA recovery obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsDmaRecoveryKind {
    /// Whole-device reset must acknowledge quiescence.
    Reset,
    /// Synchronous IOTLB invalidation must acknowledge completion.
    Iotlb,
}

/// Immutable service identities used to create one root scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFsServices {
    personality: ServiceId,
    pager: ServiceId,
    filesystem: ServiceId,
    block: ServiceId,
}

impl RuntimeFsServices {
    /// Constructs a complete service set.
    #[must_use]
    pub const fn new(
        personality: ServiceId,
        pager: ServiceId,
        filesystem: ServiceId,
        block: ServiceId,
    ) -> Self {
        Self {
            personality,
            pager,
            filesystem,
            block,
        }
    }

    const fn get(self, domain: FsDomain) -> ServiceId {
        match domain {
            FsDomain::Personality => self.personality,
            FsDomain::Pager => self.pager,
            FsDomain::Filesystem => self.filesystem,
            FsDomain::Block => self.block,
        }
    }
}

/// Authenticated proof of one current domain binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFsBindingToken {
    scope: ScopeId,
    domain: FsDomain,
    service: ServiceId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
}

impl RuntimeFsBindingToken {
    /// Returns the root scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the bound service domain.
    #[must_use]
    pub const fn domain(self) -> FsDomain {
        self.domain
    }

    /// Returns the service instance.
    #[must_use]
    pub const fn service(self) -> ServiceId {
        self.service
    }

    /// Returns the captured root authority generation.
    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the captured domain binding generation.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.binding_epoch
    }
}

/// Complete current bindings returned when a scope is created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFsBindings {
    personality: RuntimeFsBindingToken,
    pager: RuntimeFsBindingToken,
    filesystem: RuntimeFsBindingToken,
    block: RuntimeFsBindingToken,
}

impl RuntimeFsBindings {
    /// Returns the binding for one domain.
    #[must_use]
    pub const fn get(self, domain: FsDomain) -> RuntimeFsBindingToken {
        match domain {
            FsDomain::Personality => self.personality,
            FsDomain::Pager => self.pager,
            FsDomain::Filesystem => self.filesystem,
            FsDomain::Block => self.block,
        }
    }
}

/// Full fenced identity of one effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFsEffectToken {
    scope: ScopeId,
    effect: EffectId,
    parent: Option<EffectId>,
    kind: FsEffectKind,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    address_space_generation: AddressSpaceGeneration,
    inode_generation: InodeGeneration,
    device_generation: DeviceGeneration,
}

impl RuntimeFsEffectToken {
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
    pub const fn kind(self) -> FsEffectKind {
        self.kind
    }

    /// Returns the captured root authority generation.
    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the captured local binding generation.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.binding_epoch
    }

    /// Returns the captured address-space generation.
    #[must_use]
    pub const fn address_space_generation(self) -> AddressSpaceGeneration {
        self.address_space_generation
    }

    /// Returns the captured inode generation.
    #[must_use]
    pub const fn inode_generation(self) -> InodeGeneration {
        self.inode_generation
    }

    /// Returns the captured device generation.
    #[must_use]
    pub const fn device_generation(self) -> DeviceGeneration {
        self.device_generation
    }
}

/// Tokens for the complete fixed causal graph of one `pwrite64` request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFsToken {
    syscall: RuntimeFsEffectToken,
    pager: RuntimeFsEffectToken,
    filesystem: RuntimeFsEffectToken,
    block: RuntimeFsEffectToken,
}

impl RuntimeFsToken {
    /// Returns the personality syscall effect.
    #[must_use]
    pub const fn syscall(self) -> RuntimeFsEffectToken {
        self.syscall
    }

    /// Returns the pager mapping effect.
    #[must_use]
    pub const fn pager(self) -> RuntimeFsEffectToken {
        self.pager
    }

    /// Returns the filesystem operation effect.
    #[must_use]
    pub const fn filesystem(self) -> RuntimeFsEffectToken {
        self.filesystem
    }

    /// Returns the block request effect.
    #[must_use]
    pub const fn block(self) -> RuntimeFsEffectToken {
        self.block
    }
}

/// Immutable receipt for one pager PTE/TLB publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerMapReceipt {
    effect: EffectId,
    sequence: u64,
    generation: AddressSpaceGeneration,
}

impl PagerMapReceipt {
    /// Returns the pager effect.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the global commit sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the newly published address-space generation.
    #[must_use]
    pub const fn generation(self) -> AddressSpaceGeneration {
        self.generation
    }
}

/// Immutable receipt for the bounded inode write publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PwriteReceipt {
    effect: EffectId,
    sequence: u64,
    generation: InodeGeneration,
    version: u64,
    word: u32,
}

impl PwriteReceipt {
    /// Returns the filesystem effect.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the global commit sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the newly published inode generation.
    #[must_use]
    pub const fn generation(self) -> InodeGeneration {
        self.generation
    }

    /// Returns the new inode version.
    #[must_use]
    pub const fn version(self) -> u64 {
        self.version
    }

    /// Returns the bounded little-endian inode word (`b"xy"`).
    #[must_use]
    pub const fn word(self) -> u32 {
        self.word
    }
}

/// Immutable receipt for mediated block queue publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockCommitReceipt {
    effect: EffectId,
    sequence: u64,
    device_generation: DeviceGeneration,
    avail_index: u64,
}

impl BlockCommitReceipt {
    /// Returns the block effect.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the global commit sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the device generation in which `avail.idx` was published.
    #[must_use]
    pub const fn device_generation(self) -> DeviceGeneration {
        self.device_generation
    }

    /// Returns the newly published abstract `avail.idx`.
    #[must_use]
    pub const fn avail_index(self) -> u64 {
        self.avail_index
    }
}

/// One-shot ticket for publishing a committed guest syscall reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsPublicationTicket {
    scope: ScopeId,
    effect: EffectId,
    commit_sequence: u64,
    ticket_sequence: u64,
    result: i64,
}

impl FsPublicationTicket {
    /// Returns the syscall effect.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the committed Linux result.
    #[must_use]
    pub const fn result(self) -> i64 {
        self.result
    }
}

/// Exact ticket created by root revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFsRevokeTicket {
    scope: ScopeId,
    sequence: u64,
    closed_epoch: AuthorityEpoch,
    authority_epoch: AuthorityEpoch,
}

impl RuntimeFsRevokeTicket {
    /// Returns the closing root scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the authority generation closed by this ticket.
    #[must_use]
    pub const fn closed_epoch(self) -> AuthorityEpoch {
        self.closed_epoch
    }
}

/// Current kernel recovery attempt for retained DMA ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsDmaRecoveryToken {
    scope: ScopeId,
    effect: EffectId,
    revoke_sequence: u64,
    attempt: u64,
    device_generation: DeviceGeneration,
    kind: FsDmaRecoveryKind,
}

impl FsDmaRecoveryToken {
    /// Returns the block effect.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the retry attempt.
    #[must_use]
    pub const fn attempt(self) -> u64 {
        self.attempt
    }

    /// Returns the current device generation.
    #[must_use]
    pub const fn device_generation(self) -> DeviceGeneration {
        self.device_generation
    }

    /// Returns the required recovery step.
    #[must_use]
    pub const fn kind(self) -> FsDmaRecoveryKind {
        self.kind
    }
}

/// Retained timeout identity that keeps the block effect and DMA credit live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsTombstoneToken {
    id: TombstoneId,
    scope: ScopeId,
    effect: EffectId,
    revoke_sequence: u64,
    attempt: u64,
    device_generation: DeviceGeneration,
    kind: FsDmaRecoveryKind,
}

impl FsTombstoneToken {
    /// Returns the stable tombstone identity.
    #[must_use]
    pub const fn id(self) -> TombstoneId {
        self.id
    }

    /// Returns the retained block effect.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the retained recovery kind.
    #[must_use]
    pub const fn kind(self) -> FsDmaRecoveryKind {
        self.kind
    }
}

/// Exact recovery snapshot for one crashed service domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFsRecoverySnapshot {
    scope: ScopeId,
    domain: FsDomain,
    replacement: ServiceId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    address_space_generation: AddressSpaceGeneration,
    inode_generation: InodeGeneration,
    device_generation: DeviceGeneration,
    domain_revision: u64,
    cohort: Vec<RuntimeFsEffectToken>,
}

impl RuntimeFsRecoverySnapshot {
    /// Returns the crashed domain.
    #[must_use]
    pub const fn domain(&self) -> FsDomain {
        self.domain
    }

    /// Returns the exact orphan cohort.
    #[must_use]
    pub fn cohort(&self) -> &[RuntimeFsEffectToken] {
        &self.cohort
    }
}

/// Ready proof wrapping one exact recovery snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFsReadyToken {
    snapshot: RuntimeFsRecoverySnapshot,
}

/// One child-first root-closure transition or retained obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFsClosureStep {
    /// One uncommitted effect aborted and returned its typed credit.
    Aborted(EffectId),
    /// One committed effect completed and returned its typed credit.
    Completed(EffectId),
    /// DMA recovery was started and requires an acknowledgement or timeout.
    NeedsDma(FsDmaRecoveryToken),
    /// DMA recovery is already in flight.
    AwaitingDma(FsDmaRecoveryToken),
    /// A timeout tombstone still retains the block effect and DMA credit.
    RetainedTombstone(FsTombstoneToken),
    /// A committed syscall reply must be published exactly once.
    AwaitingReply(FsPublicationTicket),
}

/// Read-only projection of one service domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFsDomainView {
    /// Current binding generation.
    pub binding_epoch: BindingEpoch,
    /// Bound service, if any.
    pub service: Option<ServiceId>,
    /// Kernel fallback/replacement state.
    pub fallback: FsFallbackState,
    /// Number of domain mutations covered by recovery snapshots.
    pub revision: u64,
    /// Effects still awaiting explicit adoption.
    pub recovery_cohort: Vec<EffectId>,
}

/// Read-only projection of one runtime-filesystem effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFsEffectView {
    /// Current fenced effect token.
    pub token: RuntimeFsEffectToken,
    /// Lifecycle phase.
    pub phase: FsEffectPhase,
    /// Typed credit retained by this effect until terminalization.
    pub credit: FsCreditClass,
    /// Global commit sequence, if committed.
    pub commit_sequence: Option<u64>,
    /// DMA state for a block effect.
    pub dma_state: FsDmaState,
    /// Whether a current-generation device completion was observed.
    pub device_completed: bool,
    /// Whether a guest reply ticket remains unpublished.
    pub publication_pending: bool,
    /// Number of terminal transitions; always zero or one.
    pub terminalizations: u8,
}

/// Read-only projection of one root scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFsScopeView {
    /// Scope lifecycle.
    pub state: ScopeState,
    /// Current root authority generation.
    pub authority_epoch: AuthorityEpoch,
    /// Current address-space generation.
    pub address_space_generation: AddressSpaceGeneration,
    /// Current inode generation.
    pub inode_generation: InodeGeneration,
    /// Current block device generation.
    pub device_generation: DeviceGeneration,
    /// Immutable initial credit capacity.
    pub initial_credits: FsCredits,
    /// Credits not retained by live effects.
    pub free_credits: FsCredits,
    /// Current bounded inode version.
    pub inode_version: u64,
    /// Current bounded inode word.
    pub inode_word: u32,
    /// Number of pager mapping publications.
    pub mapping_publications: u64,
    /// Number of visible inode writes.
    pub pwrite_publications: u64,
    /// Current abstract block `avail.idx`.
    pub avail_index: u64,
    /// Number of published guest replies.
    pub reply_publications: u64,
    /// Historical effects retained for audit.
    pub effects: usize,
    /// Nonterminal effects.
    pub live_effects: usize,
    /// Pending guest reply tickets.
    pub pending_publications: usize,
    /// Current retained tombstones.
    pub tombstones: usize,
    /// Frozen closure target count, if closing or revoked.
    pub closure_target_count: usize,
    /// Effects terminalized by the current root closure.
    pub closure_steps: usize,
}

/// Rejected runtime-filesystem transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeFsError {
    /// The scope does not exist.
    UnknownScope(ScopeId),
    /// The effect does not exist.
    UnknownEffect(EffectId),
    /// A scope is not in the required lifecycle state.
    InvalidScopeState(ScopeState),
    /// A root authority generation was closed.
    StaleAuthority {
        /// Presented generation.
        presented: AuthorityEpoch,
        /// Current generation.
        current: AuthorityEpoch,
    },
    /// A service binding generation is stale.
    StaleBinding {
        /// Presented generation.
        presented: BindingEpoch,
        /// Current generation.
        current: BindingEpoch,
    },
    /// A pager operation names an old address-space generation.
    StaleAddressSpaceGeneration {
        /// Presented generation.
        presented: AddressSpaceGeneration,
        /// Current generation.
        current: AddressSpaceGeneration,
    },
    /// A filesystem operation names an old inode generation.
    StaleInodeGeneration {
        /// Presented generation.
        presented: InodeGeneration,
        /// Current generation.
        current: InodeGeneration,
    },
    /// A block response names an old device generation.
    StaleDeviceGeneration {
        /// Presented generation.
        presented: DeviceGeneration,
        /// Current generation.
        current: DeviceGeneration,
    },
    /// A token names the wrong service domain.
    WrongDomain,
    /// A binding names a service other than the installed service.
    WrongService,
    /// No service is currently bound.
    ServiceUnavailable,
    /// A live service is already bound.
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
    InvalidEffectState(FsEffectPhase),
    /// A parent cannot terminalize while a live child remains.
    LiveDescendants,
    /// One typed credit class is exhausted.
    CreditExhausted(FsCreditClass),
    /// A commit or receipt was presented more than once.
    AlreadyCommitted,
    /// A current-generation device completion was already accepted.
    AlreadyCompleted,
    /// A publication ticket is stale, forged, or already consumed.
    InvalidPublication,
    /// A reply publication was attempted twice.
    AlreadyPublished,
    /// A revoke ticket does not describe the current closure.
    StaleRevokeTicket,
    /// DMA recovery is not in the required state.
    InvalidDmaState(FsDmaState),
    /// A timeout/retry token does not match the current attempt.
    StaleDmaAttempt,
    /// A tombstone token does not match the retained obligation.
    StaleTombstone,
    /// Root closure is not quiescent yet.
    NotQuiescent,
    /// A monotonically increasing identity or counter overflowed.
    CounterOverflow,
    /// Internal state relationships were inconsistent.
    InvariantViolation(&'static str),
}

/// Failure reported by a full invariant audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFsInvariantViolation {
    /// Typed credits were lost or duplicated.
    CreditConservation(ScopeId),
    /// A causal edge or domain-kind relationship is invalid.
    EffectGraph(EffectId),
    /// Terminalization count disagrees with effect phase.
    Terminalization(EffectId),
    /// DMA state, tombstone, and block phase disagree.
    DmaSafety(EffectId),
    /// Scope reverse indexes disagree with effect records.
    ScopeIndex(ScopeId),
    /// Generation or publication counters disagree with retained history.
    GenerationAccounting(ScopeId),
    /// Service/fallback/recovery metadata is inconsistent.
    RecoveryState(ScopeId),
    /// Root revocation metadata is inconsistent.
    RevocationState(ScopeId),
    /// A revoked scope retains live work or credits.
    RevokedScope(ScopeId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DomainRecord {
    binding_epoch: BindingEpoch,
    service: Option<ServiceId>,
    fallback: FsFallbackState,
    revision: u64,
    recovery_cohort: BTreeSet<EffectId>,
    ready: Option<ReadyRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadyRecord {
    replacement: ServiceId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    address_space_generation: AddressSpaceGeneration,
    inode_generation: InodeGeneration,
    device_generation: DeviceGeneration,
    domain_revision: u64,
    cohort: BTreeSet<EffectId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TombstoneRecord {
    token: FsTombstoneToken,
    prior_phase: FsEffectPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectRecord {
    token: RuntimeFsEffectToken,
    phase: FsEffectPhase,
    credit: FsCreditClass,
    commit_sequence: Option<u64>,
    terminalizations: u8,
    dma_state: FsDmaState,
    dma_attempt: u64,
    device_completed: bool,
    block_receipt: Option<BlockCommitReceipt>,
    publication: Option<FsPublicationTicket>,
    tombstone: Option<TombstoneRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RevocationRecord {
    ticket: RuntimeFsRevokeTicket,
    frozen: BTreeSet<EffectId>,
    closure_steps: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScopeRecord {
    state: ScopeState,
    authority_epoch: AuthorityEpoch,
    address_space_generation: AddressSpaceGeneration,
    inode_generation: InodeGeneration,
    device_generation: DeviceGeneration,
    domains: BTreeMap<FsDomain, DomainRecord>,
    initial_credits: FsCredits,
    free_credits: FsCredits,
    effects: BTreeSet<EffectId>,
    inode_version: u64,
    inode_word: u32,
    mapping_publications: u64,
    pwrite_publications: u64,
    avail_index: u64,
    reply_publications: u64,
    revocation: Option<RevocationRecord>,
}

/// Deterministic safe-Rust runtime-filesystem protocol oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFsModel {
    next_scope: u64,
    next_effect: u64,
    next_commit_sequence: u64,
    next_publication_sequence: u64,
    next_revoke_sequence: u64,
    next_tombstone: u64,
    scopes: BTreeMap<ScopeId, ScopeRecord>,
    effects: BTreeMap<EffectId, EffectRecord>,
}
