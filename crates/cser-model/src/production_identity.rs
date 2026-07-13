//! Identity-preserving block-read composition successor.
//!
//! This module is an independent safe-Rust oracle for RFC 0001. It does not
//! call the OSTD registry or reuse its transition implementation. The bounded
//! graph is created by normal registration operations beneath one root:
//!
//! ```text
//! Root
//! `-- FilesystemSyscall          (Personality)
//!     `-- FilesystemRead         (Filesystem)
//!         `-- BlockRequest       (VirtIo)
//!             |-- DmaQueueOwnerA (VirtIo)
//!             |-- DmaQueueOwnerB (VirtIo)
//!             `-- DmaRequestOwner(VirtIo)
//! ```
//!
//! One clone/validate/swap transaction gate gives every rejected operation a
//! complete failure-atomic projection. This is a bounded semantic oracle, not
//! an implementation claim about OSTD locks, IRQs, SMP, or a real device.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

/// Number of restartable service domains in the bounded workload.
pub const DOMAIN_COUNT: usize = 3;
/// Number of effects in the bounded causal tree.
pub const EFFECT_COUNT: usize = 6;
/// Number of independently conserved typed-credit classes.
pub const CREDIT_CLASS_COUNT: usize = 6;
/// Number of DMA owners below the block request.
pub const DMA_OWNER_COUNT: usize = 3;

/// Stable identity of one registry allocation domain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RegistryInstance(u64);

impl RegistryInstance {
    /// Constructs a registry identity.
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

/// Stable identity of the single root scope in this successor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RootId(u64);

impl RootId {
    /// Constructs a root identifier.
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

/// Stable identity of one user-space service instance.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServiceInstanceId(u64);

impl ServiceInstanceId {
    /// Constructs a service-instance identifier.
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

/// Immutable root lineage, excluding the revocable authority epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RootLineage {
    registry: RegistryInstance,
    root: RootId,
    generation: u64,
}

impl RootLineage {
    /// Returns the owning registry instance.
    #[must_use]
    pub const fn registry(self) -> RegistryInstance {
        self.registry
    }

    /// Returns the stable root identifier.
    #[must_use]
    pub const fn root(self) -> RootId {
        self.root
    }

    /// Returns the non-reused root generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Complete root identity presented at an authority-gated operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootIdentity {
    lineage: RootLineage,
    authority_epoch: u64,
}

impl RootIdentity {
    /// Returns the immutable root lineage.
    #[must_use]
    pub const fn lineage(self) -> RootLineage {
        self.lineage
    }

    /// Returns the authority epoch captured by this identity.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Substitutes a registry instance for negative testing.
    #[must_use]
    pub const fn with_registry(mut self, registry: RegistryInstance) -> Self {
        self.lineage.registry = registry;
        self
    }

    /// Substitutes a root identifier for negative testing.
    #[must_use]
    pub const fn with_root(mut self, root: RootId) -> Self {
        self.lineage.root = root;
        self
    }

    /// Substitutes a root generation for negative testing.
    #[must_use]
    pub const fn with_generation(mut self, generation: u64) -> Self {
        self.lineage.generation = generation;
        self
    }

    /// Substitutes an authority epoch for negative testing.
    #[must_use]
    pub const fn with_authority_epoch(mut self, authority_epoch: u64) -> Self {
        self.authority_epoch = authority_epoch;
        self
    }
}

/// Restartable service domains participating in the block-read path.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DomainId {
    /// Linux personality and one-shot guest reply.
    Personality,
    /// Filesystem policy and block mapping.
    Filesystem,
    /// Block queue, DMA, reset, and IOMMU ownership.
    VirtIo,
}

impl DomainId {
    /// Deterministic complete domain set.
    pub const ALL: [Self; DOMAIN_COUNT] = [Self::Personality, Self::Filesystem, Self::VirtIo];

    const fn index(self) -> usize {
        self as usize
    }
}

/// Complete identity of one current or historical service binding.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BindingIdentity {
    lineage: RootLineage,
    domain: DomainId,
    service: ServiceInstanceId,
    binding_epoch: u64,
}

impl BindingIdentity {
    /// Returns the root lineage authorized by the binding.
    #[must_use]
    pub const fn lineage(self) -> RootLineage {
        self.lineage
    }

    /// Returns the service domain.
    #[must_use]
    pub const fn domain(self) -> DomainId {
        self.domain
    }

    /// Returns the service-instance identity.
    #[must_use]
    pub const fn service(self) -> ServiceInstanceId {
        self.service
    }

    /// Returns the captured binding epoch.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    /// Substitutes a registry instance for negative testing.
    #[must_use]
    pub const fn with_registry(mut self, registry: RegistryInstance) -> Self {
        self.lineage.registry = registry;
        self
    }

    /// Substitutes a binding epoch for negative testing.
    #[must_use]
    pub const fn with_binding_epoch(mut self, binding_epoch: u64) -> Self {
        self.binding_epoch = binding_epoch;
        self
    }
}

/// Immutable operation classes in the first workload tree.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum OperationClass {
    /// Personality-owned filesystem syscall.
    FilesystemSyscall,
    /// Filesystem-owned read operation.
    FilesystemRead,
    /// VirtIO block request whose commit is `avail.idx` publication.
    BlockRequest,
    /// First queue-owned DMA mapping.
    DmaQueueOwnerA,
    /// Second queue-owned DMA mapping.
    DmaQueueOwnerB,
    /// Request-buffer DMA mapping.
    DmaRequestOwner,
}

impl OperationClass {
    /// Deterministic registration order for the complete workload.
    pub const ALL: [Self; EFFECT_COUNT] = [
        Self::FilesystemSyscall,
        Self::FilesystemRead,
        Self::BlockRequest,
        Self::DmaQueueOwnerA,
        Self::DmaQueueOwnerB,
        Self::DmaRequestOwner,
    ];

    /// Returns the owning service domain.
    #[must_use]
    pub const fn domain(self) -> DomainId {
        match self {
            Self::FilesystemSyscall => DomainId::Personality,
            Self::FilesystemRead => DomainId::Filesystem,
            Self::BlockRequest
            | Self::DmaQueueOwnerA
            | Self::DmaQueueOwnerB
            | Self::DmaRequestOwner => DomainId::VirtIo,
        }
    }

    /// Returns the expected parent operation, or `None` for the root child.
    #[must_use]
    pub const fn parent_operation(self) -> Option<Self> {
        match self {
            Self::FilesystemSyscall => None,
            Self::FilesystemRead => Some(Self::FilesystemSyscall),
            Self::BlockRequest => Some(Self::FilesystemRead),
            Self::DmaQueueOwnerA | Self::DmaQueueOwnerB | Self::DmaRequestOwner => {
                Some(Self::BlockRequest)
            }
        }
    }

    const fn credit_grants(self) -> &'static [(CreditClass, u64)] {
        match self {
            Self::FilesystemSyscall => &[(CreditClass::Control, 1), (CreditClass::GuestReply, 1)],
            Self::FilesystemRead => &[(CreditClass::FilesystemOperation, 1)],
            Self::BlockRequest => &[(CreditClass::QueueSlot, 1)],
            Self::DmaQueueOwnerA | Self::DmaQueueOwnerB | Self::DmaRequestOwner => {
                &[(CreditClass::PinnedPage, 1), (CreditClass::DmaMapping, 1)]
            }
        }
    }
}

/// Stable non-authoritative key for one registered effect.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EffectKey {
    lineage: RootLineage,
    effect_id: u64,
    effect_generation: u64,
}

impl EffectKey {
    /// Returns the root lineage.
    #[must_use]
    pub const fn lineage(self) -> RootLineage {
        self.lineage
    }

    /// Returns the registry-local effect identifier.
    #[must_use]
    pub const fn effect_id(self) -> u64 {
        self.effect_id
    }

    /// Returns the non-reused effect generation.
    #[must_use]
    pub const fn effect_generation(self) -> u64 {
        self.effect_generation
    }
}

/// Immutable parent installed by the registry at registration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ParentIdentity {
    /// The effect is a direct child of the root authority.
    Root(RootLineage),
    /// The effect is a child of one earlier effect.
    Effect(EffectKey),
}

/// Complete immutable identity of one effect.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EffectIdentity {
    key: EffectKey,
    authority_epoch: u64,
    origin_binding: BindingIdentity,
    domain: DomainId,
    parent: ParentIdentity,
    operation: OperationClass,
}

impl EffectIdentity {
    /// Returns the stable effect key.
    #[must_use]
    pub const fn key(self) -> EffectKey {
        self.key
    }

    /// Returns the authority epoch captured at registration.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the immutable originating service binding.
    #[must_use]
    pub const fn origin_binding(self) -> BindingIdentity {
        self.origin_binding
    }

    /// Returns the owning service domain.
    #[must_use]
    pub const fn domain(self) -> DomainId {
        self.domain
    }

    /// Returns the immutable causal parent.
    #[must_use]
    pub const fn parent(self) -> ParentIdentity {
        self.parent
    }

    /// Returns the immutable operation class.
    #[must_use]
    pub const fn operation(self) -> OperationClass {
        self.operation
    }

    /// Substitutes a registry instance for negative testing.
    #[must_use]
    pub const fn with_registry(mut self, registry: RegistryInstance) -> Self {
        self.key.lineage.registry = registry;
        self
    }

    /// Substitutes a root identifier for negative testing.
    #[must_use]
    pub const fn with_root(mut self, root: RootId) -> Self {
        self.key.lineage.root = root;
        self
    }

    /// Substitutes a root generation for negative testing.
    #[must_use]
    pub const fn with_root_generation(mut self, generation: u64) -> Self {
        self.key.lineage.generation = generation;
        self
    }

    /// Substitutes an effect generation for negative testing.
    #[must_use]
    pub const fn with_effect_generation(mut self, generation: u64) -> Self {
        self.key.effect_generation = generation;
        self
    }

    /// Substitutes an immutable parent for negative testing.
    #[must_use]
    pub const fn with_parent(mut self, parent: ParentIdentity) -> Self {
        self.parent = parent;
        self
    }
}

/// Typed resource classes held in the one shared root ledger.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CreditClass {
    /// Root/control authority for the personality request.
    Control,
    /// Filesystem-operation capacity.
    FilesystemOperation,
    /// VirtIO queue-slot capacity.
    QueueSlot,
    /// Pinned backing-page capacity.
    PinnedPage,
    /// IOMMU/DMA mapping capacity.
    DmaMapping,
    /// One-shot guest-reply capacity.
    GuestReply,
}

impl CreditClass {
    /// Deterministic complete credit-class set.
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

    /// Returns the fixed capacity of the first workload.
    #[must_use]
    pub const fn capacity(self) -> u64 {
        match self {
            Self::PinnedPage | Self::DmaMapping => DMA_OWNER_COUNT as u64,
            Self::Control | Self::FilesystemOperation | Self::QueueSlot | Self::GuestReply => 1,
        }
    }
}

/// Root authority lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootPhase {
    /// Registration, preparation, commit, and reply gate is open.
    Active,
    /// The old authority epoch is frozen and closure is in progress.
    Closing,
    /// Every frozen effect is terminal and no credit remains live or retained.
    Revoked,
}

/// Effect lifecycle in the production-identity successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectPhase {
    /// Registered with credits reserved.
    Registered,
    /// Prepared for the next publication boundary.
    Prepared,
    /// Device publication has committed kernel-owned work.
    Committed,
    /// The block backend completed and its data is valid.
    BackendCompleted,
    /// Device ownership is retained after an honest timeout.
    Tombstoned,
    /// The effect completed or drained exactly once.
    Completed,
    /// The effect aborted before publication exactly once.
    Aborted,
}

impl EffectPhase {
    /// Returns whether the effect is no longer live.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

/// Per-effect location of all credits granted at registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreditDisposition {
    /// Reserved by registered or prepared work.
    Held,
    /// Owned by a committed device obligation.
    Committed,
    /// Returned after completion or abort.
    Returned,
    /// Retained behind a reset/IOMMU tombstone.
    Retained,
}

/// Kernel-owned backend result carried to the one-shot guest reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendOutcome {
    /// The block read completed with valid data.
    Data,
    /// Reset established an error result without undoing the device commit.
    IndeterminateAfterReset,
}

/// Same-root device-session identity captured by commit and retry receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceIdentity {
    lineage: RootLineage,
    transport_instance: u64,
    queue_id: u16,
    iommu_domain: u64,
    device_generation: u64,
}

impl DeviceIdentity {
    /// Returns the root lineage.
    #[must_use]
    pub const fn lineage(self) -> RootLineage {
        self.lineage
    }

    /// Returns the transport-instance identity.
    #[must_use]
    pub const fn transport_instance(self) -> u64 {
        self.transport_instance
    }

    /// Returns the queue identifier.
    #[must_use]
    pub const fn queue_id(self) -> u16 {
        self.queue_id
    }

    /// Returns the IOMMU-domain identity.
    #[must_use]
    pub const fn iommu_domain(self) -> u64 {
        self.iommu_domain
    }

    /// Returns the reset-authorized device generation.
    #[must_use]
    pub const fn device_generation(self) -> u64 {
        self.device_generation
    }

    /// Substitutes a device generation for negative testing.
    #[must_use]
    pub const fn with_device_generation(mut self, generation: u64) -> Self {
        self.device_generation = generation;
        self
    }
}

/// Immutable proof of the one `avail.idx` commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    syscall: EffectIdentity,
    filesystem: EffectIdentity,
    block: EffectIdentity,
    dma_owners: [EffectIdentity; DMA_OWNER_COUNT],
    root: RootIdentity,
    binding: BindingIdentity,
    domain_revision: u64,
    device: DeviceIdentity,
    sequence: u64,
}

impl CommitReceipt {
    /// Returns the committed personality effect.
    #[must_use]
    pub const fn syscall(self) -> EffectIdentity {
        self.syscall
    }

    /// Returns the committed filesystem effect.
    #[must_use]
    pub const fn filesystem(self) -> EffectIdentity {
        self.filesystem
    }

    /// Returns the committed block effect.
    #[must_use]
    pub const fn block(self) -> EffectIdentity {
        self.block
    }

    /// Returns the exact DMA-owner identities.
    #[must_use]
    pub const fn dma_owners(self) -> [EffectIdentity; DMA_OWNER_COUNT] {
        self.dma_owners
    }

    /// Returns the root authority identity accepted at commit.
    #[must_use]
    pub const fn root(self) -> RootIdentity {
        self.root
    }

    /// Returns the VirtIO binding accepted at commit.
    #[must_use]
    pub const fn binding(self) -> BindingIdentity {
        self.binding
    }

    /// Returns the VirtIO domain revision accepted at commit.
    #[must_use]
    pub const fn domain_revision(self) -> u64 {
        self.domain_revision
    }

    /// Returns the device identity accepted at commit.
    #[must_use]
    pub const fn device(self) -> DeviceIdentity {
        self.device
    }

    /// Returns the registry-local commit sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Substitutes a device identity for negative testing.
    #[must_use]
    pub const fn with_device(mut self, device: DeviceIdentity) -> Self {
        self.device = device;
        self
    }
}

/// Exact old-binding cohort captured after one domain crash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySnapshot {
    lineage: RootLineage,
    domain: DomainId,
    crashed_binding_epoch: u64,
    target_binding_epoch: u64,
    revision: u64,
    cohort: Vec<EffectIdentity>,
}

impl RecoverySnapshot {
    /// Returns the root lineage.
    #[must_use]
    pub const fn lineage(&self) -> RootLineage {
        self.lineage
    }

    /// Returns the recovering domain.
    #[must_use]
    pub const fn domain(&self) -> DomainId {
        self.domain
    }

    /// Returns the exact uncommitted orphan cohort.
    #[must_use]
    pub fn cohort(&self) -> &[EffectIdentity] {
        &self.cohort
    }

    /// Returns the recovery revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the service epoch fenced by the crash.
    #[must_use]
    pub const fn crashed_binding_epoch(&self) -> u64 {
        self.crashed_binding_epoch
    }

    /// Returns the replacement binding epoch.
    #[must_use]
    pub const fn target_binding_epoch(&self) -> u64 {
        self.target_binding_epoch
    }
}

/// Proof that one exact recovery snapshot passed the ready handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyToken {
    snapshot: RecoverySnapshot,
}

impl ReadyToken {
    /// Returns the exact snapshot authorized by readiness.
    #[must_use]
    pub const fn snapshot(&self) -> &RecoverySnapshot {
        &self.snapshot
    }
}

/// Exact frozen cohort and ledger obligation produced by root revoke.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeTicket {
    lineage: RootLineage,
    closed_authority_epoch: u64,
    authority_epoch: u64,
    closure_revision: u64,
    sequence: u64,
    frozen_effects: Vec<EffectKey>,
    frozen_credits: [u64; CREDIT_CLASS_COUNT],
}

impl RevokeTicket {
    /// Returns the root lineage.
    #[must_use]
    pub const fn lineage(&self) -> RootLineage {
        self.lineage
    }

    /// Returns the closed authority epoch.
    #[must_use]
    pub const fn closed_authority_epoch(&self) -> u64 {
        self.closed_authority_epoch
    }

    /// Returns the post-linearization authority epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// Returns the closure revision.
    #[must_use]
    pub const fn closure_revision(&self) -> u64 {
        self.closure_revision
    }

    /// Returns the registry-local revoke sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the frozen effect keys.
    #[must_use]
    pub fn frozen_effects(&self) -> &[EffectKey] {
        &self.frozen_effects
    }

    /// Returns the frozen live-credit obligation by class.
    #[must_use]
    pub const fn frozen_credits(&self) -> [u64; CREDIT_CLASS_COUNT] {
        self.frozen_credits
    }

    /// Substitutes a registry instance for negative testing.
    #[must_use]
    pub fn with_registry(mut self, registry: RegistryInstance) -> Self {
        self.lineage.registry = registry;
        self
    }
}

/// Identity retained after reset cannot prove quiescence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TombstoneKind {
    /// Reset acknowledgement has not yet established a new device generation.
    Reset,
    /// IOTLB acknowledgement has not yet authorized owner release.
    Iotlb,
}

/// Identity retained after reset or IOTLB timeout cannot prove quiescence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TombstoneToken {
    lineage: RootLineage,
    id: u64,
    kind: TombstoneKind,
    closure_revision: u64,
    block: EffectKey,
    dma_owners: [EffectKey; DMA_OWNER_COUNT],
    old_device: DeviceIdentity,
}

impl TombstoneToken {
    /// Returns the root lineage.
    #[must_use]
    pub const fn lineage(self) -> RootLineage {
        self.lineage
    }

    /// Returns the registry-local tombstone identity.
    #[must_use]
    pub const fn id(self) -> u64 {
        self.id
    }

    /// Returns the reset or IOTLB timeout class.
    #[must_use]
    pub const fn kind(self) -> TombstoneKind {
        self.kind
    }

    /// Returns the closure revision retaining the owners.
    #[must_use]
    pub const fn closure_revision(self) -> u64 {
        self.closure_revision
    }

    /// Returns the retained block identity.
    #[must_use]
    pub const fn block(self) -> EffectKey {
        self.block
    }

    /// Returns the retained DMA-owner identities.
    #[must_use]
    pub const fn dma_owners(self) -> [EffectKey; DMA_OWNER_COUNT] {
        self.dma_owners
    }

    /// Returns the device generation that timed out.
    #[must_use]
    pub const fn old_device(self) -> DeviceIdentity {
        self.old_device
    }

    /// Substitutes a registry instance for negative testing.
    #[must_use]
    pub const fn with_registry(mut self, registry: RegistryInstance) -> Self {
        self.lineage.registry = registry;
        self
    }
}

/// Reset-authorized retry identity for the same retained effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResetRetryToken {
    tombstone: TombstoneToken,
    new_device: DeviceIdentity,
    sequence: u64,
}

impl ResetRetryToken {
    /// Returns the original tombstone identity.
    #[must_use]
    pub const fn tombstone(self) -> TombstoneToken {
        self.tombstone
    }

    /// Returns the newly authorized device generation.
    #[must_use]
    pub const fn new_device(self) -> DeviceIdentity {
        self.new_device
    }

    /// Returns the registry-local retry sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// Retry identity for one IOTLB timeout over the same retained owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IotlbRetryToken {
    tombstone: TombstoneToken,
    device: DeviceIdentity,
    sequence: u64,
}

impl IotlbRetryToken {
    /// Returns the exact IOTLB tombstone being retried.
    #[must_use]
    pub const fn tombstone(self) -> TombstoneToken {
        self.tombstone
    }

    /// Returns the unchanged post-reset device generation.
    #[must_use]
    pub const fn device(self) -> DeviceIdentity {
        self.device
    }

    /// Returns the registry-local retry sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// One-shot guest-reply publication receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestReplyReceipt {
    syscall: EffectIdentity,
    filesystem: EffectIdentity,
    block_commit_sequence: u64,
    outcome: BackendOutcome,
    sequence: u64,
}

impl GuestReplyReceipt {
    /// Returns the personality effect whose reply was published.
    #[must_use]
    pub const fn syscall(self) -> EffectIdentity {
        self.syscall
    }

    /// Returns the filesystem effect completed before the reply.
    #[must_use]
    pub const fn filesystem(self) -> EffectIdentity {
        self.filesystem
    }

    /// Returns the block commit sequence carried into the reply.
    #[must_use]
    pub const fn block_commit_sequence(self) -> u64 {
        self.block_commit_sequence
    }

    /// Returns the data or honest post-reset result delivered to the guest.
    #[must_use]
    pub const fn outcome(self) -> BackendOutcome {
        self.outcome
    }

    /// Returns the one-shot reply sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// Result of attempting to finish root closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClosureResult {
    /// Every frozen effect terminalized and every live credit was returned.
    Revoked {
        /// Closure revision accepted by the result.
        closure_revision: u64,
        /// Total effects terminalized in this model instance.
        terminalizations: u64,
    },
    /// Reset occurred but IOMMU quiescence remains unestablished.
    IndeterminateAfterReset {
        /// Identity that still retains device ownership.
        tombstone: Box<TombstoneToken>,
        /// Credits retained by class.
        retained_credits: [u64; CREDIT_CLASS_COUNT],
    },
}

/// One deterministic leaf-first closure transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosureStep {
    /// Effect selected through the root reverse index.
    pub effect: EffectIdentity,
    /// State before terminalization.
    pub from: EffectPhase,
    /// Terminal state after the step.
    pub to: EffectPhase,
}

/// Exact shared-ledger projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerProjection {
    /// Fixed capacity by credit class.
    pub capacity: [u64; CREDIT_CLASS_COUNT],
    /// Never-reserved credits by class.
    pub free: [u64; CREDIT_CLASS_COUNT],
    /// Credits reserved by pre-commit effects.
    pub held: [u64; CREDIT_CLASS_COUNT],
    /// Credits owned by committed effects.
    pub committed: [u64; CREDIT_CLASS_COUNT],
    /// Credits returned by terminal effects.
    pub returned: [u64; CREDIT_CLASS_COUNT],
    /// Credits retained behind a tombstone.
    pub retained: [u64; CREDIT_CLASS_COUNT],
}

/// Stable service-binding projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingProjection {
    /// Service domain.
    pub domain: DomainId,
    /// Currently installed service, if any.
    pub service: Option<ServiceInstanceId>,
    /// Current binding epoch.
    pub binding_epoch: u64,
    /// Domain state revision.
    pub domain_revision: u64,
}

/// Stable effect projection for differential oracles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectProjection {
    /// Complete immutable effect identity.
    pub identity: EffectIdentity,
    /// Binding currently authorized to perform service operations.
    pub current_binding: BindingIdentity,
    /// Current lifecycle state.
    pub phase: EffectPhase,
    /// Current credit location.
    pub credit_disposition: CreditDisposition,
    /// Successful publications by this effect.
    pub publications: u8,
    /// Successful terminal transitions.
    pub terminalizations: u8,
    /// Successful explicit adoptions.
    pub adoptions: u8,
}

/// Stable recovery projection for one domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryProjection {
    /// Recovering domain.
    pub domain: DomainId,
    /// Recovery revision.
    pub revision: u64,
    /// Old binding epoch.
    pub crashed_binding_epoch: u64,
    /// New binding epoch.
    pub target_binding_epoch: u64,
    /// Exact original orphan cohort.
    pub cohort: Vec<EffectKey>,
    /// Orphans not yet explicitly adopted.
    pub unadopted: Vec<EffectKey>,
    /// Whether the snapshot was issued.
    pub snapshot_issued: bool,
    /// Whether ready completed.
    pub ready: bool,
    /// Whether replacement rebind completed.
    pub rebound: bool,
}

/// Stable device projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceProjection {
    /// Current device-session identity.
    pub identity: DeviceIdentity,
    /// Kernel-owned backend result, if completion or reset established one.
    pub backend_outcome: Option<BackendOutcome>,
    /// Whether an active tombstone retains ownership.
    pub tombstone: Option<TombstoneToken>,
    /// Reset retry/acknowledgement identity, if issued.
    pub reset_retry: Option<ResetRetryToken>,
    /// IOTLB retry identity, if issued.
    pub iotlb_retry: Option<IotlbRetryToken>,
}

/// Exact transition and index-work counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransitionCounters {
    /// Successful registrations.
    pub registrations: u64,
    /// Successful preparations.
    pub preparations: u64,
    /// Successful device commits.
    pub commits: u64,
    /// Successful root revoke linearizations.
    pub revoke_begins: u64,
    /// Successful domain crashes.
    pub crashes: u64,
    /// Recovery snapshots issued.
    pub snapshots: u64,
    /// Ready handshakes completed.
    pub ready: u64,
    /// Replacement bindings installed.
    pub rebinds: u64,
    /// Effects explicitly adopted without identity replacement.
    pub adoptions: u64,
    /// Backend device completions accepted.
    pub device_completions: u64,
    /// Guest replies published.
    pub guest_replies: u64,
    /// Honest reset timeouts retained.
    pub reset_timeouts: u64,
    /// Reset-authorized retries issued.
    pub reset_retries: u64,
    /// Honest IOTLB timeouts retained.
    pub iotlb_timeouts: u64,
    /// IOTLB retries issued.
    pub iotlb_retries: u64,
    /// IOTLB acknowledgements consumed.
    pub iotlb_acks: u64,
    /// Effects terminalized exactly once.
    pub terminalizations: u64,
    /// Effects selected through the root reverse index.
    pub root_index_selections: u64,
    /// Child-index emptiness checks performed by closure.
    pub child_index_checks: u64,
    /// Unrelated registry objects visited by `revoke_next`; invariant audits
    /// and clone/validate/swap copying are deliberately excluded.
    pub unrelated_index_visits: u64,
}

/// Complete stable semantic projection, including future allocator positions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionIdentityProjection {
    /// Immutable root lineage.
    pub lineage: RootLineage,
    /// Root lifecycle.
    pub root_phase: RootPhase,
    /// Current authority epoch.
    pub authority_epoch: u64,
    /// Current service-binding table.
    pub bindings: [BindingProjection; DOMAIN_COUNT],
    /// Effects ordered by registry-local effect ID.
    pub effects: Vec<EffectProjection>,
    /// One shared typed-credit ledger.
    pub ledger: LedgerProjection,
    /// Root live-effect reverse index.
    pub root_live: Vec<EffectKey>,
    /// Domain live-effect reverse indexes.
    pub domain_live: [Vec<EffectKey>; DOMAIN_COUNT],
    /// Parent-to-live-child reverse indexes.
    pub live_children: Vec<(EffectKey, Vec<EffectKey>)>,
    /// Active recovery records.
    pub recovery: Vec<RecoveryProjection>,
    /// Current device state.
    pub device: DeviceProjection,
    /// Active frozen revoke ticket.
    pub revoke: Option<RevokeTicket>,
    /// Immutable block commit receipt, if published.
    pub commit: Option<CommitReceipt>,
    /// One-shot guest reply receipt, if published.
    pub guest_reply: Option<GuestReplyReceipt>,
    /// Leaf-first terminalization order.
    pub closure_order: Vec<EffectKey>,
    /// Successful transition and index-work counters.
    pub counters: TransitionCounters,
    /// Next effect identifier.
    pub next_effect_id: u64,
    /// Next commit sequence.
    pub next_commit_sequence: u64,
    /// Next revoke sequence.
    pub next_revoke_sequence: u64,
    /// Next recovery revision.
    pub next_recovery_revision: u64,
    /// Next tombstone identity.
    pub next_tombstone_id: u64,
    /// Next retry sequence.
    pub next_retry_sequence: u64,
    /// Next guest-reply sequence.
    pub next_guest_reply_sequence: u64,
    /// Current closure revision.
    pub closure_revision: u64,
}

/// Rejected successor operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionIdentityError {
    /// A token came from another registry instance.
    WrongRegistry,
    /// A token named another root identifier.
    WrongRoot,
    /// A token named another root generation.
    WrongRootGeneration,
    /// A token carried a closed authority epoch.
    StaleAuthority,
    /// The root gate is not active for this operation.
    RootNotActive,
    /// A token named the wrong service domain.
    WrongDomain,
    /// A service token carried a fenced binding epoch.
    StaleBinding,
    /// A service token named another service instance.
    WrongService,
    /// No service is currently bound to the domain.
    DomainUnavailable,
    /// The domain already has an active recovery record.
    RecoveryAlreadyActive,
    /// No crash recovery is active for the domain.
    NoRecovery,
    /// Recovery snapshot, ready, rebind, or adoption was out of order.
    InvalidRecoveryOrder,
    /// A supplied recovery object is stale or foreign.
    RecoveryMismatch,
    /// The operation class was already registered.
    EffectAlreadyRegistered,
    /// The required causal parent has not been registered.
    MissingParent,
    /// The proposed or presented immutable parent is wrong.
    WrongParent,
    /// The registry-local effect identifier is unknown.
    UnknownEffect,
    /// The effect generation is stale or foreign.
    WrongEffectGeneration,
    /// Another immutable effect field was substituted.
    EffectIdentityMismatch,
    /// An effect is in the wrong lifecycle state.
    InvalidEffectState,
    /// Typed capacity was insufficient for registration.
    CreditExhausted(CreditClass),
    /// An effect is not an eligible old-binding orphan.
    NotAdoptable,
    /// The commit receipt is stale, forged, or replayed in the wrong state.
    CommitReceiptMismatch,
    /// The device generation is stale.
    StaleDeviceGeneration,
    /// Backend completion has not made the read data valid.
    BackendNotComplete,
    /// A one-shot publication was replayed.
    DuplicatePublication,
    /// The revoke ticket is stale or foreign.
    InvalidRevokeTicket,
    /// Live committed device ownership prevents ordinary closure.
    DeviceNotQuiescent,
    /// Live effects remain before successful closure.
    ClosureIncomplete,
    /// A tombstone already exists or the presented one is invalid.
    InvalidTombstone,
    /// A reset retry was already issued or is out of order.
    InvalidRetry,
    /// A monotonic identity or sequence overflowed.
    CounterOverflow,
    /// A complete invariant audit rejected the candidate transition.
    InvariantViolation,
}

/// Failure reported by a full successor invariant audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionIdentityInvariant {
    /// Immutable ancestry or operation metadata diverged from the fixed tree.
    IdentityTree,
    /// A root/domain/child reverse index diverged from live effect state.
    ReverseIndex,
    /// Typed-credit capacity was copied or lost.
    CreditConservation,
    /// Effect lifecycle and credit disposition disagree.
    EffectCreditState,
    /// A terminal state was entered other than exactly once.
    Terminalization,
    /// Recovery state and current binding disagree.
    Recovery,
    /// Commit, publication, or device state disagree.
    Publication,
    /// Tombstone, retry, device generation, or retained credits disagree.
    Tombstone,
    /// Root phase and revoke cohort disagree.
    RootClosure,
    /// An allocator or sequence could reuse an issued value.
    Allocator,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BindingRecord {
    service: Option<ServiceInstanceId>,
    binding_epoch: u64,
    domain_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EffectRecord {
    identity: EffectIdentity,
    current_binding: BindingIdentity,
    phase: EffectPhase,
    credit_disposition: CreditDisposition,
    publications: u8,
    terminalizations: u8,
    adoptions: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoveryState {
    domain: DomainId,
    revision: u64,
    crashed_binding_epoch: u64,
    target_binding_epoch: u64,
    cohort: BTreeSet<EffectKey>,
    unadopted: BTreeSet<EffectKey>,
    snapshot: Option<RecoverySnapshot>,
    ready: bool,
    rebound: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TombstoneRecord {
    token: TombstoneToken,
    reset_retry: Option<ResetRetryToken>,
    iotlb_retry: Option<IotlbRetryToken>,
}

/// Independent safe-Rust successor for one production-identity root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionIdentityModel {
    lineage: RootLineage,
    root_phase: RootPhase,
    authority_epoch: u64,
    bindings: [BindingRecord; DOMAIN_COUNT],
    effects: BTreeMap<u64, EffectRecord>,
    effect_by_operation: BTreeMap<OperationClass, EffectKey>,
    root_live: BTreeSet<EffectKey>,
    domain_live: [BTreeSet<EffectKey>; DOMAIN_COUNT],
    live_children: BTreeMap<EffectKey, BTreeSet<EffectKey>>,
    ledger: LedgerProjection,
    recovery: [Option<RecoveryState>; DOMAIN_COUNT],
    device: DeviceIdentity,
    backend_outcome: Option<BackendOutcome>,
    tombstone: Option<TombstoneRecord>,
    commit: Option<CommitReceipt>,
    revoke: Option<RevokeTicket>,
    guest_reply: Option<GuestReplyReceipt>,
    closure_order: Vec<EffectKey>,
    counters: TransitionCounters,
    next_effect_id: u64,
    next_commit_sequence: u64,
    next_revoke_sequence: u64,
    next_recovery_revision: u64,
    next_tombstone_id: u64,
    next_retry_sequence: u64,
    next_guest_reply_sequence: u64,
    closure_revision: u64,
}

impl ProductionIdentityModel {
    /// Creates one empty root with three registry-native service bindings.
    #[must_use]
    pub fn new(registry: RegistryInstance, root: RootId, root_generation: u64) -> Self {
        let lineage = RootLineage {
            registry,
            root,
            generation: root_generation,
        };
        let bindings = core::array::from_fn(|index| BindingRecord {
            service: Some(ServiceInstanceId::new(index as u64 + 1)),
            binding_epoch: 1,
            domain_revision: 1,
        });
        let capacity = core::array::from_fn(|index| CreditClass::ALL[index].capacity());
        let model = Self {
            lineage,
            root_phase: RootPhase::Active,
            authority_epoch: 1,
            bindings,
            effects: BTreeMap::new(),
            effect_by_operation: BTreeMap::new(),
            root_live: BTreeSet::new(),
            domain_live: core::array::from_fn(|_| BTreeSet::new()),
            live_children: BTreeMap::new(),
            ledger: LedgerProjection {
                capacity,
                free: capacity,
                held: [0; CREDIT_CLASS_COUNT],
                committed: [0; CREDIT_CLASS_COUNT],
                returned: [0; CREDIT_CLASS_COUNT],
                retained: [0; CREDIT_CLASS_COUNT],
            },
            recovery: core::array::from_fn(|_| None),
            device: DeviceIdentity {
                lineage,
                transport_instance: 1,
                queue_id: 0,
                iommu_domain: 1,
                device_generation: 1,
            },
            backend_outcome: None,
            tombstone: None,
            commit: None,
            revoke: None,
            guest_reply: None,
            closure_order: Vec::new(),
            counters: TransitionCounters::default(),
            next_effect_id: 1,
            next_commit_sequence: 1,
            next_revoke_sequence: 1,
            next_recovery_revision: 1,
            next_tombstone_id: 1,
            next_retry_sequence: 1,
            next_guest_reply_sequence: 1,
            closure_revision: 0,
        };
        debug_assert_eq!(model.check_invariants(), Ok(()));
        model
    }

    /// Returns the current complete root identity.
    #[must_use]
    pub const fn root_identity(&self) -> RootIdentity {
        RootIdentity {
            lineage: self.lineage,
            authority_epoch: self.authority_epoch,
        }
    }

    /// Returns the current binding identity for a domain, if one is installed.
    #[must_use]
    pub fn binding(&self, domain: DomainId) -> Option<BindingIdentity> {
        let binding = &self.bindings[domain.index()];
        binding.service.map(|service| BindingIdentity {
            lineage: self.lineage,
            domain,
            service,
            binding_epoch: binding.binding_epoch,
        })
    }

    /// Returns the immutable registered identity for an operation class.
    #[must_use]
    pub fn effect(&self, operation: OperationClass) -> Option<EffectIdentity> {
        self.effect_by_operation
            .get(&operation)
            .and_then(|key| self.effects.get(&key.effect_id))
            .map(|record| record.identity)
    }

    /// Returns the exact complete semantic projection.
    #[must_use]
    pub fn projection(&self) -> ProductionIdentityProjection {
        let effects = self
            .effects
            .values()
            .map(|record| EffectProjection {
                identity: record.identity,
                current_binding: record.current_binding,
                phase: record.phase,
                credit_disposition: record.credit_disposition,
                publications: record.publications,
                terminalizations: record.terminalizations,
                adoptions: record.adoptions,
            })
            .collect();
        let domain_live = core::array::from_fn(|index| {
            self.domain_live[index].iter().copied().collect::<Vec<_>>()
        });
        let live_children = self
            .live_children
            .iter()
            .map(|(parent, children)| (*parent, children.iter().copied().collect()))
            .collect();
        let recovery = self
            .recovery
            .iter()
            .flatten()
            .map(|state| RecoveryProjection {
                domain: state.domain,
                revision: state.revision,
                crashed_binding_epoch: state.crashed_binding_epoch,
                target_binding_epoch: state.target_binding_epoch,
                cohort: state.cohort.iter().copied().collect(),
                unadopted: state.unadopted.iter().copied().collect(),
                snapshot_issued: state.snapshot.is_some(),
                ready: state.ready,
                rebound: state.rebound,
            })
            .collect();
        ProductionIdentityProjection {
            lineage: self.lineage,
            root_phase: self.root_phase,
            authority_epoch: self.authority_epoch,
            bindings: core::array::from_fn(|index| BindingProjection {
                domain: DomainId::ALL[index],
                service: self.bindings[index].service,
                binding_epoch: self.bindings[index].binding_epoch,
                domain_revision: self.bindings[index].domain_revision,
            }),
            effects,
            ledger: self.ledger,
            root_live: self.root_live.iter().copied().collect(),
            domain_live,
            live_children,
            recovery,
            device: DeviceProjection {
                identity: self.device,
                backend_outcome: self.backend_outcome,
                tombstone: self.tombstone.map(|record| record.token),
                reset_retry: self.tombstone.and_then(|record| record.reset_retry),
                iotlb_retry: self.tombstone.and_then(|record| record.iotlb_retry),
            },
            revoke: self.revoke.clone(),
            commit: self.commit,
            guest_reply: self.guest_reply,
            closure_order: self.closure_order.clone(),
            counters: self.counters,
            next_effect_id: self.next_effect_id,
            next_commit_sequence: self.next_commit_sequence,
            next_revoke_sequence: self.next_revoke_sequence,
            next_recovery_revision: self.next_recovery_revision,
            next_tombstone_id: self.next_tombstone_id,
            next_retry_sequence: self.next_retry_sequence,
            next_guest_reply_sequence: self.next_guest_reply_sequence,
            closure_revision: self.closure_revision,
        }
    }

    /// Registers one workload effect and installs every index and credit grant
    /// in the same failure-atomic transaction.
    pub fn register_effect(
        &mut self,
        root: RootIdentity,
        binding: BindingIdentity,
        operation: OperationClass,
        parent: ParentIdentity,
    ) -> Result<EffectIdentity, ProductionIdentityError> {
        self.transact(|next| next.register_effect_inner(root, binding, operation, parent))
    }

    /// Advances one exactly identified effect from registered to prepared.
    pub fn prepare_effect(
        &mut self,
        binding: BindingIdentity,
        effect: EffectIdentity,
    ) -> Result<(), ProductionIdentityError> {
        self.transact(|next| {
            next.require_active()?;
            next.validate_binding(binding, effect.domain)?;
            let effect_id = next.validate_effect(effect)?;
            let record = next
                .effects
                .get(&effect_id)
                .ok_or(ProductionIdentityError::UnknownEffect)?;
            if record.current_binding != binding {
                return Err(ProductionIdentityError::StaleBinding);
            }
            if record.phase != EffectPhase::Registered {
                return Err(ProductionIdentityError::InvalidEffectState);
            }
            next.effects
                .get_mut(&effect_id)
                .ok_or(ProductionIdentityError::UnknownEffect)?
                .phase = EffectPhase::Prepared;
            Self::increment(&mut next.counters.preparations)?;
            Ok(())
        })
    }

    /// Crashes one current service binding and fences only that domain epoch.
    pub fn crash_domain(
        &mut self,
        binding: BindingIdentity,
    ) -> Result<u64, ProductionIdentityError> {
        self.transact(|next| next.crash_domain_inner(binding))
    }

    /// Captures the exact uncommitted old-binding cohort after a crash.
    pub fn snapshot_domain(
        &mut self,
        root: RootIdentity,
        domain: DomainId,
    ) -> Result<RecoverySnapshot, ProductionIdentityError> {
        self.transact(|next| next.snapshot_domain_inner(root, domain))
    }

    /// Completes the ready handshake for one exact recovery snapshot.
    pub fn ready_domain(
        &mut self,
        snapshot: RecoverySnapshot,
    ) -> Result<ReadyToken, ProductionIdentityError> {
        self.transact(|next| next.ready_domain_inner(snapshot))
    }

    /// Installs a replacement service without transferring any effect.
    pub fn rebind_domain(
        &mut self,
        ready: ReadyToken,
        replacement: ServiceInstanceId,
    ) -> Result<BindingIdentity, ProductionIdentityError> {
        self.transact(|next| next.rebind_domain_inner(ready, replacement))
    }

    /// Explicitly adopts one eligible orphan while preserving its full
    /// immutable effect identity.
    pub fn adopt_effect(
        &mut self,
        binding: BindingIdentity,
        effect: EffectIdentity,
    ) -> Result<EffectIdentity, ProductionIdentityError> {
        self.transact(|next| next.adopt_effect_inner(binding, effect))
    }

    /// Atomically publishes the block request and its three exact DMA owners.
    pub fn commit_block(
        &mut self,
        binding: BindingIdentity,
        block: EffectIdentity,
        dma_owners: [EffectIdentity; DMA_OWNER_COUNT],
    ) -> Result<CommitReceipt, ProductionIdentityError> {
        self.transact(|next| next.commit_block_inner(binding, block, dma_owners))
    }

    /// Closes the old authority epoch and freezes the exact live cohort and
    /// typed-credit obligation.
    pub fn revoke_begin(
        &mut self,
        root: RootIdentity,
    ) -> Result<RevokeTicket, ProductionIdentityError> {
        self.transact(|next| next.revoke_begin_inner(root))
    }

    /// Accepts one backend completion for the immutable block commit receipt.
    pub fn complete_backend(
        &mut self,
        receipt: CommitReceipt,
    ) -> Result<(), ProductionIdentityError> {
        self.transact(|next| next.complete_backend_inner(receipt))
    }

    /// Consumes normal IOTLB quiescence and releases the committed device
    /// subtree in leaf-first order.
    pub fn acknowledge_iotlb(
        &mut self,
        receipt: CommitReceipt,
    ) -> Result<(), ProductionIdentityError> {
        self.transact(|next| next.acknowledge_iotlb_inner(receipt))
    }

    /// Publishes the one-shot guest reply after backend data and the device
    /// subtree are both complete.
    pub fn publish_guest_reply(
        &mut self,
        syscall: EffectIdentity,
        filesystem: EffectIdentity,
        block_commit: CommitReceipt,
    ) -> Result<GuestReplyReceipt, ProductionIdentityError> {
        self.transact(|next| next.publish_guest_reply_inner(syscall, filesystem, block_commit))
    }

    /// Retains the committed device subtree after reset cannot establish
    /// IOMMU quiescence.
    pub fn retain_reset_timeout(
        &mut self,
        ticket: RevokeTicket,
        receipt: CommitReceipt,
    ) -> Result<TombstoneToken, ProductionIdentityError> {
        self.transact(|next| next.retain_reset_timeout_inner(ticket, receipt))
    }

    /// Consumes reset acknowledgement, advances only the device generation,
    /// and authorizes retry for the same effect identities.
    pub fn retry_after_reset(
        &mut self,
        ticket: RevokeTicket,
        tombstone: TombstoneToken,
    ) -> Result<ResetRetryToken, ProductionIdentityError> {
        self.transact(|next| next.retry_after_reset_inner(ticket, tombstone))
    }

    /// Retains the same owners again when IOTLB completion times out after
    /// reset acknowledgement.
    pub fn retain_iotlb_timeout(
        &mut self,
        ticket: RevokeTicket,
        reset_retry: ResetRetryToken,
    ) -> Result<TombstoneToken, ProductionIdentityError> {
        self.transact(|next| next.retain_iotlb_timeout_inner(ticket, reset_retry))
    }

    /// Authorizes another IOTLB attempt without changing effect or device
    /// generation identity.
    pub fn retry_iotlb(
        &mut self,
        ticket: RevokeTicket,
        tombstone: TombstoneToken,
    ) -> Result<IotlbRetryToken, ProductionIdentityError> {
        self.transact(|next| next.retry_iotlb_inner(ticket, tombstone))
    }

    /// Consumes the IOTLB retry acknowledgement and releases every retained
    /// owner in leaf-first order.
    pub fn acknowledge_retry_iotlb(
        &mut self,
        retry: IotlbRetryToken,
    ) -> Result<(), ProductionIdentityError> {
        self.transact(|next| next.acknowledge_retry_iotlb_inner(retry))
    }

    /// Terminalizes one currently leaf-most uncommitted effect through the
    /// shared root and parent/child reverse indexes.
    pub fn revoke_next(
        &mut self,
        ticket: RevokeTicket,
    ) -> Result<ClosureStep, ProductionIdentityError> {
        self.transact(|next| next.revoke_next_inner(ticket))
    }

    /// Finishes root closure, or reports an honest retained-device result
    /// without changing the root to `Revoked`.
    pub fn revoke_complete(
        &mut self,
        ticket: RevokeTicket,
    ) -> Result<ClosureResult, ProductionIdentityError> {
        self.transact(|next| next.revoke_complete_inner(ticket))
    }

    fn transact<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, ProductionIdentityError>,
    ) -> Result<T, ProductionIdentityError> {
        let mut candidate = self.clone();
        let result = operation(&mut candidate)?;
        candidate
            .check_invariants()
            .map_err(|_| ProductionIdentityError::InvariantViolation)?;
        *self = candidate;
        Ok(result)
    }

    fn increment(counter: &mut u64) -> Result<(), ProductionIdentityError> {
        *counter = counter
            .checked_add(1)
            .ok_or(ProductionIdentityError::CounterOverflow)?;
        Ok(())
    }

    fn allocate(counter: &mut u64) -> Result<u64, ProductionIdentityError> {
        let allocated = *counter;
        Self::increment(counter)?;
        Ok(allocated)
    }

    fn validate_lineage(&self, lineage: RootLineage) -> Result<(), ProductionIdentityError> {
        if lineage.registry != self.lineage.registry {
            return Err(ProductionIdentityError::WrongRegistry);
        }
        if lineage.root != self.lineage.root {
            return Err(ProductionIdentityError::WrongRoot);
        }
        if lineage.generation != self.lineage.generation {
            return Err(ProductionIdentityError::WrongRootGeneration);
        }
        Ok(())
    }

    fn validate_root(&self, root: RootIdentity) -> Result<(), ProductionIdentityError> {
        self.validate_lineage(root.lineage)?;
        if root.authority_epoch != self.authority_epoch {
            return Err(ProductionIdentityError::StaleAuthority);
        }
        Ok(())
    }

    fn require_active(&self) -> Result<(), ProductionIdentityError> {
        if self.root_phase != RootPhase::Active {
            return Err(ProductionIdentityError::RootNotActive);
        }
        Ok(())
    }

    fn validate_binding(
        &self,
        binding: BindingIdentity,
        expected_domain: DomainId,
    ) -> Result<(), ProductionIdentityError> {
        self.validate_lineage(binding.lineage)?;
        if binding.domain != expected_domain {
            return Err(ProductionIdentityError::WrongDomain);
        }
        let current = &self.bindings[expected_domain.index()];
        if binding.binding_epoch != current.binding_epoch {
            return Err(ProductionIdentityError::StaleBinding);
        }
        let service = current
            .service
            .ok_or(ProductionIdentityError::DomainUnavailable)?;
        if binding.service != service {
            return Err(ProductionIdentityError::WrongService);
        }
        Ok(())
    }

    fn validate_effect(&self, identity: EffectIdentity) -> Result<u64, ProductionIdentityError> {
        self.validate_lineage(identity.key.lineage)?;
        let record = self
            .effects
            .get(&identity.key.effect_id)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        if identity.key.effect_generation != record.identity.key.effect_generation {
            return Err(ProductionIdentityError::WrongEffectGeneration);
        }
        if identity.parent != record.identity.parent {
            return Err(ProductionIdentityError::WrongParent);
        }
        if identity != record.identity {
            return Err(ProductionIdentityError::EffectIdentityMismatch);
        }
        Ok(identity.key.effect_id)
    }

    fn validate_parent_lineage(
        &self,
        parent: ParentIdentity,
    ) -> Result<(), ProductionIdentityError> {
        match parent {
            ParentIdentity::Root(lineage) => self.validate_lineage(lineage),
            ParentIdentity::Effect(key) => {
                self.validate_lineage(key.lineage)?;
                if let Some(record) = self.effects.get(&key.effect_id)
                    && key.effect_generation != record.identity.key.effect_generation
                {
                    return Err(ProductionIdentityError::WrongEffectGeneration);
                }
                Ok(())
            }
        }
    }

    fn register_effect_inner(
        &mut self,
        root: RootIdentity,
        binding: BindingIdentity,
        operation: OperationClass,
        parent: ParentIdentity,
    ) -> Result<EffectIdentity, ProductionIdentityError> {
        self.require_active()?;
        self.validate_root(root)?;
        self.validate_binding(binding, operation.domain())?;
        self.validate_parent_lineage(parent)?;
        if self.effect_by_operation.contains_key(&operation) {
            return Err(ProductionIdentityError::EffectAlreadyRegistered);
        }
        let expected_parent = if let Some(parent_operation) = operation.parent_operation() {
            let key = *self
                .effect_by_operation
                .get(&parent_operation)
                .ok_or(ProductionIdentityError::MissingParent)?;
            let parent_record = self
                .effects
                .get(&key.effect_id)
                .ok_or(ProductionIdentityError::MissingParent)?;
            if parent_record.phase.is_terminal() {
                return Err(ProductionIdentityError::InvalidEffectState);
            }
            self.validate_binding(parent_record.current_binding, parent_operation.domain())?;
            ParentIdentity::Effect(key)
        } else {
            ParentIdentity::Root(self.lineage)
        };
        if parent != expected_parent {
            return Err(ProductionIdentityError::WrongParent);
        }
        for &(credit, units) in operation.credit_grants() {
            if self.ledger.free[credit.index()] < units {
                return Err(ProductionIdentityError::CreditExhausted(credit));
            }
        }
        let effect_id = Self::allocate(&mut self.next_effect_id)?;
        let key = EffectKey {
            lineage: self.lineage,
            effect_id,
            effect_generation: 1,
        };
        let identity = EffectIdentity {
            key,
            authority_epoch: self.authority_epoch,
            origin_binding: binding,
            domain: operation.domain(),
            parent,
            operation,
        };
        for &(credit, units) in operation.credit_grants() {
            let index = credit.index();
            self.ledger.free[index] -= units;
            self.ledger.held[index] = self.ledger.held[index]
                .checked_add(units)
                .ok_or(ProductionIdentityError::CounterOverflow)?;
        }
        self.effects.insert(
            effect_id,
            EffectRecord {
                identity,
                current_binding: binding,
                phase: EffectPhase::Registered,
                credit_disposition: CreditDisposition::Held,
                publications: 0,
                terminalizations: 0,
                adoptions: 0,
            },
        );
        self.effect_by_operation.insert(operation, key);
        self.root_live.insert(key);
        self.domain_live[operation.domain().index()].insert(key);
        self.live_children.entry(key).or_default();
        if let ParentIdentity::Effect(parent_key) = parent {
            self.live_children
                .entry(parent_key)
                .or_default()
                .insert(key);
        }
        Self::increment(&mut self.counters.registrations)?;
        Ok(identity)
    }

    fn crash_domain_inner(
        &mut self,
        binding: BindingIdentity,
    ) -> Result<u64, ProductionIdentityError> {
        self.require_active()?;
        self.validate_binding(binding, binding.domain)?;
        let domain_index = binding.domain.index();
        if self.recovery[domain_index].is_some() {
            return Err(ProductionIdentityError::RecoveryAlreadyActive);
        }
        let target_binding_epoch = self.bindings[domain_index]
            .binding_epoch
            .checked_add(1)
            .ok_or(ProductionIdentityError::CounterOverflow)?;
        let domain_revision = self.bindings[domain_index]
            .domain_revision
            .checked_add(1)
            .ok_or(ProductionIdentityError::CounterOverflow)?;
        let revision = Self::allocate(&mut self.next_recovery_revision)?;
        let cohort = self.domain_live[domain_index]
            .iter()
            .filter(|key| {
                self.effects.get(&key.effect_id).is_some_and(|record| {
                    matches!(
                        record.phase,
                        EffectPhase::Registered | EffectPhase::Prepared
                    ) && record.current_binding.binding_epoch == binding.binding_epoch
                })
            })
            .copied()
            .collect::<BTreeSet<_>>();
        self.bindings[domain_index].service = None;
        self.bindings[domain_index].binding_epoch = target_binding_epoch;
        self.bindings[domain_index].domain_revision = domain_revision;
        self.recovery[domain_index] = Some(RecoveryState {
            domain: binding.domain,
            revision,
            crashed_binding_epoch: binding.binding_epoch,
            target_binding_epoch,
            unadopted: cohort.clone(),
            cohort,
            snapshot: None,
            ready: false,
            rebound: false,
        });
        Self::increment(&mut self.counters.crashes)?;
        Ok(target_binding_epoch)
    }

    fn snapshot_domain_inner(
        &mut self,
        root: RootIdentity,
        domain: DomainId,
    ) -> Result<RecoverySnapshot, ProductionIdentityError> {
        self.require_active()?;
        self.validate_root(root)?;
        let state = self.recovery[domain.index()]
            .as_ref()
            .ok_or(ProductionIdentityError::NoRecovery)?;
        if state.snapshot.is_some() || state.ready || state.rebound {
            return Err(ProductionIdentityError::InvalidRecoveryOrder);
        }
        let snapshot = RecoverySnapshot {
            lineage: self.lineage,
            domain,
            crashed_binding_epoch: state.crashed_binding_epoch,
            target_binding_epoch: state.target_binding_epoch,
            revision: state.revision,
            cohort: state
                .cohort
                .iter()
                .map(|key| {
                    self.effects
                        .get(&key.effect_id)
                        .map(|record| record.identity)
                        .ok_or(ProductionIdentityError::UnknownEffect)
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        self.recovery[domain.index()]
            .as_mut()
            .ok_or(ProductionIdentityError::NoRecovery)?
            .snapshot = Some(snapshot.clone());
        Self::increment(&mut self.counters.snapshots)?;
        Ok(snapshot)
    }

    fn ready_domain_inner(
        &mut self,
        snapshot: RecoverySnapshot,
    ) -> Result<ReadyToken, ProductionIdentityError> {
        self.require_active()?;
        self.validate_lineage(snapshot.lineage)?;
        let state = self.recovery[snapshot.domain.index()]
            .as_ref()
            .ok_or(ProductionIdentityError::NoRecovery)?;
        if state.snapshot.as_ref() != Some(&snapshot) {
            return Err(ProductionIdentityError::RecoveryMismatch);
        }
        if state.ready || state.rebound {
            return Err(ProductionIdentityError::InvalidRecoveryOrder);
        }
        self.recovery[snapshot.domain.index()]
            .as_mut()
            .ok_or(ProductionIdentityError::NoRecovery)?
            .ready = true;
        Self::increment(&mut self.counters.ready)?;
        Ok(ReadyToken { snapshot })
    }

    fn rebind_domain_inner(
        &mut self,
        ready: ReadyToken,
        replacement: ServiceInstanceId,
    ) -> Result<BindingIdentity, ProductionIdentityError> {
        self.require_active()?;
        self.validate_lineage(ready.snapshot.lineage)?;
        let domain = ready.snapshot.domain;
        let state = self.recovery[domain.index()]
            .as_ref()
            .ok_or(ProductionIdentityError::NoRecovery)?;
        if state.snapshot.as_ref() != Some(&ready.snapshot) {
            return Err(ProductionIdentityError::RecoveryMismatch);
        }
        if !state.ready || state.rebound || self.bindings[domain.index()].service.is_some() {
            return Err(ProductionIdentityError::InvalidRecoveryOrder);
        }
        let domain_revision = self.bindings[domain.index()]
            .domain_revision
            .checked_add(1)
            .ok_or(ProductionIdentityError::CounterOverflow)?;
        self.bindings[domain.index()].service = Some(replacement);
        self.bindings[domain.index()].domain_revision = domain_revision;
        self.recovery[domain.index()]
            .as_mut()
            .ok_or(ProductionIdentityError::NoRecovery)?
            .rebound = true;
        Self::increment(&mut self.counters.rebinds)?;
        Ok(BindingIdentity {
            lineage: self.lineage,
            domain,
            service: replacement,
            binding_epoch: self.bindings[domain.index()].binding_epoch,
        })
    }

    fn adopt_effect_inner(
        &mut self,
        binding: BindingIdentity,
        effect: EffectIdentity,
    ) -> Result<EffectIdentity, ProductionIdentityError> {
        self.require_active()?;
        self.validate_binding(binding, effect.domain)?;
        let effect_id = self.validate_effect(effect)?;
        let state = self.recovery[effect.domain.index()]
            .as_ref()
            .ok_or(ProductionIdentityError::NoRecovery)?;
        if !state.rebound || !state.unadopted.contains(&effect.key) {
            return Err(ProductionIdentityError::NotAdoptable);
        }
        let record = self
            .effects
            .get(&effect_id)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        if !matches!(
            record.phase,
            EffectPhase::Registered | EffectPhase::Prepared
        ) || record.current_binding.binding_epoch != state.crashed_binding_epoch
        {
            return Err(ProductionIdentityError::NotAdoptable);
        }
        let record = self
            .effects
            .get_mut(&effect_id)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        record.current_binding = binding;
        record.adoptions = record
            .adoptions
            .checked_add(1)
            .ok_or(ProductionIdentityError::CounterOverflow)?;
        self.recovery[effect.domain.index()]
            .as_mut()
            .ok_or(ProductionIdentityError::NoRecovery)?
            .unadopted
            .remove(&effect.key);
        Self::increment(&mut self.counters.adoptions)?;
        Ok(effect)
    }

    fn commit_block_inner(
        &mut self,
        binding: BindingIdentity,
        block: EffectIdentity,
        dma_owners: [EffectIdentity; DMA_OWNER_COUNT],
    ) -> Result<CommitReceipt, ProductionIdentityError> {
        self.require_active()?;
        self.validate_binding(binding, DomainId::VirtIo)?;
        if self.commit.is_some() {
            return Err(ProductionIdentityError::DuplicatePublication);
        }
        if block.operation != OperationClass::BlockRequest {
            return Err(ProductionIdentityError::EffectIdentityMismatch);
        }
        self.validate_effect(block)?;
        let expected_owners = [
            OperationClass::DmaQueueOwnerA,
            OperationClass::DmaQueueOwnerB,
            OperationClass::DmaRequestOwner,
        ];
        for (owner, expected) in dma_owners.into_iter().zip(expected_owners) {
            if owner.operation != expected {
                return Err(ProductionIdentityError::EffectIdentityMismatch);
            }
            self.validate_effect(owner)?;
            if owner.parent != ParentIdentity::Effect(block.key) {
                return Err(ProductionIdentityError::WrongParent);
            }
        }
        if self.effects.len() != EFFECT_COUNT {
            return Err(ProductionIdentityError::MissingParent);
        }
        for operation in OperationClass::ALL {
            let key = self
                .effect_by_operation
                .get(&operation)
                .ok_or(ProductionIdentityError::UnknownEffect)?;
            let record = self
                .effects
                .get(&key.effect_id)
                .ok_or(ProductionIdentityError::UnknownEffect)?;
            if record.phase != EffectPhase::Prepared {
                return Err(ProductionIdentityError::InvalidEffectState);
            }
            self.validate_binding(record.current_binding, operation.domain())?;
        }
        let sequence = Self::allocate(&mut self.next_commit_sequence)?;
        let syscall = self
            .effect(OperationClass::FilesystemSyscall)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        let filesystem = self
            .effect(OperationClass::FilesystemRead)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        let receipt = CommitReceipt {
            syscall,
            filesystem,
            block,
            dma_owners,
            root: self.root_identity(),
            binding,
            domain_revision: self.bindings[DomainId::VirtIo.index()].domain_revision,
            device: self.device,
            sequence,
        };
        for operation in OperationClass::ALL {
            self.move_operation_credits(
                operation,
                CreditDisposition::Held,
                CreditDisposition::Committed,
            )?;
            let key = self
                .effect_by_operation
                .get(&operation)
                .copied()
                .ok_or(ProductionIdentityError::UnknownEffect)?;
            let record = self
                .effects
                .get_mut(&key.effect_id)
                .ok_or(ProductionIdentityError::UnknownEffect)?;
            record.phase = EffectPhase::Committed;
            record.credit_disposition = CreditDisposition::Committed;
        }
        let block_record = self
            .effects
            .get_mut(&block.key.effect_id)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        block_record.publications = block_record
            .publications
            .checked_add(1)
            .ok_or(ProductionIdentityError::CounterOverflow)?;
        self.commit = Some(receipt);
        Self::increment(&mut self.counters.commits)?;
        Ok(receipt)
    }

    fn revoke_begin_inner(
        &mut self,
        root: RootIdentity,
    ) -> Result<RevokeTicket, ProductionIdentityError> {
        self.require_active()?;
        self.validate_root(root)?;
        let authority_epoch = self
            .authority_epoch
            .checked_add(1)
            .ok_or(ProductionIdentityError::CounterOverflow)?;
        let closure_revision = self
            .closure_revision
            .checked_add(1)
            .ok_or(ProductionIdentityError::CounterOverflow)?;
        let sequence = Self::allocate(&mut self.next_revoke_sequence)?;
        let frozen_credits = core::array::from_fn(|index| {
            self.ledger.held[index] + self.ledger.committed[index] + self.ledger.retained[index]
        });
        let ticket = RevokeTicket {
            lineage: self.lineage,
            closed_authority_epoch: self.authority_epoch,
            authority_epoch,
            closure_revision,
            sequence,
            frozen_effects: self.root_live.iter().copied().collect(),
            frozen_credits,
        };
        self.authority_epoch = authority_epoch;
        self.closure_revision = closure_revision;
        self.root_phase = RootPhase::Closing;
        self.revoke = Some(ticket.clone());
        Self::increment(&mut self.counters.revoke_begins)?;
        Ok(ticket)
    }

    fn validate_commit_receipt(
        &self,
        receipt: CommitReceipt,
    ) -> Result<(), ProductionIdentityError> {
        self.validate_stored_commit_receipt(receipt)?;
        if receipt.device.device_generation != self.device.device_generation {
            return Err(ProductionIdentityError::StaleDeviceGeneration);
        }
        Ok(())
    }

    fn validate_stored_commit_receipt(
        &self,
        receipt: CommitReceipt,
    ) -> Result<(), ProductionIdentityError> {
        if self.commit != Some(receipt) {
            return Err(ProductionIdentityError::CommitReceiptMismatch);
        }
        if receipt.device.lineage != self.lineage {
            return Err(ProductionIdentityError::WrongRegistry);
        }
        Ok(())
    }

    fn complete_backend_inner(
        &mut self,
        receipt: CommitReceipt,
    ) -> Result<(), ProductionIdentityError> {
        self.validate_commit_receipt(receipt)?;
        if self.tombstone.is_some() {
            return Err(ProductionIdentityError::InvalidTombstone);
        }
        let record = self
            .effects
            .get(&receipt.block.key.effect_id)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        if record.phase != EffectPhase::Committed || self.backend_outcome.is_some() {
            return Err(ProductionIdentityError::InvalidEffectState);
        }
        self.effects
            .get_mut(&receipt.block.key.effect_id)
            .ok_or(ProductionIdentityError::UnknownEffect)?
            .phase = EffectPhase::BackendCompleted;
        self.backend_outcome = Some(BackendOutcome::Data);
        Self::increment(&mut self.counters.device_completions)?;
        Ok(())
    }

    fn acknowledge_iotlb_inner(
        &mut self,
        receipt: CommitReceipt,
    ) -> Result<(), ProductionIdentityError> {
        self.validate_commit_receipt(receipt)?;
        if self.tombstone.is_some() {
            return Err(ProductionIdentityError::InvalidTombstone);
        }
        if self.backend_outcome != Some(BackendOutcome::Data) {
            return Err(ProductionIdentityError::BackendNotComplete);
        }
        let block = self
            .effects
            .get(&receipt.block.key.effect_id)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        if block.phase != EffectPhase::BackendCompleted {
            return Err(ProductionIdentityError::InvalidEffectState);
        }
        for owner in receipt.dma_owners {
            let record = self
                .effects
                .get(&owner.key.effect_id)
                .ok_or(ProductionIdentityError::UnknownEffect)?;
            if record.phase != EffectPhase::Committed {
                return Err(ProductionIdentityError::InvalidEffectState);
            }
        }
        for owner in receipt.dma_owners {
            self.terminalize(owner.key, EffectPhase::Completed)?;
        }
        self.terminalize(receipt.block.key, EffectPhase::Completed)?;
        Self::increment(&mut self.counters.iotlb_acks)?;
        Ok(())
    }

    fn publish_guest_reply_inner(
        &mut self,
        syscall: EffectIdentity,
        filesystem: EffectIdentity,
        block_commit: CommitReceipt,
    ) -> Result<GuestReplyReceipt, ProductionIdentityError> {
        if self.root_phase == RootPhase::Revoked {
            return Err(ProductionIdentityError::InvalidEffectState);
        }
        self.validate_stored_commit_receipt(block_commit)?;
        if self.guest_reply.is_some() {
            return Err(ProductionIdentityError::DuplicatePublication);
        }
        let outcome = self
            .backend_outcome
            .ok_or(ProductionIdentityError::BackendNotComplete)?;
        if syscall.operation != OperationClass::FilesystemSyscall
            || filesystem.operation != OperationClass::FilesystemRead
            || filesystem.parent != ParentIdentity::Effect(syscall.key)
            || syscall != block_commit.syscall
            || filesystem != block_commit.filesystem
        {
            return Err(ProductionIdentityError::WrongParent);
        }
        self.validate_effect(syscall)?;
        self.validate_effect(filesystem)?;
        for identity in [syscall, filesystem] {
            let record = self
                .effects
                .get(&identity.key.effect_id)
                .ok_or(ProductionIdentityError::UnknownEffect)?;
            if record.phase != EffectPhase::Committed {
                return Err(ProductionIdentityError::InvalidEffectState);
            }
        }
        let block_record = self
            .effects
            .get(&block_commit.block.key.effect_id)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        if block_record.phase != EffectPhase::Completed {
            return Err(ProductionIdentityError::DeviceNotQuiescent);
        }
        let sequence = Self::allocate(&mut self.next_guest_reply_sequence)?;
        self.effects
            .get_mut(&syscall.key.effect_id)
            .ok_or(ProductionIdentityError::UnknownEffect)?
            .publications = 1;
        self.terminalize(filesystem.key, EffectPhase::Completed)?;
        self.terminalize(syscall.key, EffectPhase::Completed)?;
        let receipt = GuestReplyReceipt {
            syscall,
            filesystem,
            block_commit_sequence: block_commit.sequence,
            outcome,
            sequence,
        };
        self.guest_reply = Some(receipt);
        Self::increment(&mut self.counters.guest_replies)?;
        Ok(receipt)
    }

    fn validate_revoke_ticket(&self, ticket: &RevokeTicket) -> Result<(), ProductionIdentityError> {
        self.validate_lineage(ticket.lineage)?;
        if self.revoke.as_ref() != Some(ticket)
            || ticket.authority_epoch != self.authority_epoch
            || ticket.closure_revision != self.closure_revision
            || self.root_phase != RootPhase::Closing
        {
            return Err(ProductionIdentityError::InvalidRevokeTicket);
        }
        Ok(())
    }

    fn retain_reset_timeout_inner(
        &mut self,
        ticket: RevokeTicket,
        receipt: CommitReceipt,
    ) -> Result<TombstoneToken, ProductionIdentityError> {
        self.validate_revoke_ticket(&ticket)?;
        self.validate_commit_receipt(receipt)?;
        if self.tombstone.is_some() {
            return Err(ProductionIdentityError::InvalidTombstone);
        }
        for identity in [
            receipt.block,
            receipt.dma_owners[0],
            receipt.dma_owners[1],
            receipt.dma_owners[2],
        ] {
            let record = self
                .effects
                .get(&identity.key.effect_id)
                .ok_or(ProductionIdentityError::UnknownEffect)?;
            if !matches!(
                record.phase,
                EffectPhase::Committed | EffectPhase::BackendCompleted
            ) || record.credit_disposition != CreditDisposition::Committed
            {
                return Err(ProductionIdentityError::InvalidEffectState);
            }
        }
        let token = TombstoneToken {
            lineage: self.lineage,
            id: Self::allocate(&mut self.next_tombstone_id)?,
            kind: TombstoneKind::Reset,
            closure_revision: ticket.closure_revision,
            block: receipt.block.key,
            dma_owners: receipt.dma_owners.map(EffectIdentity::key),
            old_device: self.device,
        };
        for operation in [
            OperationClass::BlockRequest,
            OperationClass::DmaQueueOwnerA,
            OperationClass::DmaQueueOwnerB,
            OperationClass::DmaRequestOwner,
        ] {
            self.move_operation_credits(
                operation,
                CreditDisposition::Committed,
                CreditDisposition::Retained,
            )?;
            let key = self
                .effect_by_operation
                .get(&operation)
                .copied()
                .ok_or(ProductionIdentityError::UnknownEffect)?;
            let record = self
                .effects
                .get_mut(&key.effect_id)
                .ok_or(ProductionIdentityError::UnknownEffect)?;
            record.phase = EffectPhase::Tombstoned;
            record.credit_disposition = CreditDisposition::Retained;
        }
        self.tombstone = Some(TombstoneRecord {
            token,
            reset_retry: None,
            iotlb_retry: None,
        });
        Self::increment(&mut self.counters.reset_timeouts)?;
        Ok(token)
    }

    fn retry_after_reset_inner(
        &mut self,
        ticket: RevokeTicket,
        tombstone: TombstoneToken,
    ) -> Result<ResetRetryToken, ProductionIdentityError> {
        self.validate_revoke_ticket(&ticket)?;
        let record = self
            .tombstone
            .ok_or(ProductionIdentityError::InvalidTombstone)?;
        if record.token != tombstone
            || tombstone.kind != TombstoneKind::Reset
            || record.reset_retry.is_some()
            || record.iotlb_retry.is_some()
        {
            return Err(ProductionIdentityError::InvalidTombstone);
        }
        self.validate_lineage(tombstone.lineage)?;
        if tombstone.closure_revision != ticket.closure_revision
            || tombstone.old_device != self.device
        {
            return Err(ProductionIdentityError::InvalidTombstone);
        }
        let device_generation = self
            .device
            .device_generation
            .checked_add(1)
            .ok_or(ProductionIdentityError::CounterOverflow)?;
        let new_device = DeviceIdentity {
            device_generation,
            ..self.device
        };
        let retry = ResetRetryToken {
            tombstone,
            new_device,
            sequence: Self::allocate(&mut self.next_retry_sequence)?,
        };
        self.device = new_device;
        self.backend_outcome = Some(BackendOutcome::IndeterminateAfterReset);
        self.tombstone
            .as_mut()
            .ok_or(ProductionIdentityError::InvalidTombstone)?
            .reset_retry = Some(retry);
        Self::increment(&mut self.counters.reset_retries)?;
        Ok(retry)
    }

    fn retain_iotlb_timeout_inner(
        &mut self,
        ticket: RevokeTicket,
        reset_retry: ResetRetryToken,
    ) -> Result<TombstoneToken, ProductionIdentityError> {
        self.validate_revoke_ticket(&ticket)?;
        let record = self
            .tombstone
            .ok_or(ProductionIdentityError::InvalidTombstone)?;
        if record.token.kind != TombstoneKind::Reset
            || record.reset_retry != Some(reset_retry)
            || record.iotlb_retry.is_some()
            || reset_retry.new_device != self.device
            || self.backend_outcome != Some(BackendOutcome::IndeterminateAfterReset)
        {
            return Err(ProductionIdentityError::InvalidRetry);
        }
        let token = TombstoneToken {
            lineage: self.lineage,
            id: Self::allocate(&mut self.next_tombstone_id)?,
            kind: TombstoneKind::Iotlb,
            closure_revision: ticket.closure_revision,
            block: record.token.block,
            dma_owners: record.token.dma_owners,
            old_device: self.device,
        };
        let record = self
            .tombstone
            .as_mut()
            .ok_or(ProductionIdentityError::InvalidTombstone)?;
        record.token = token;
        record.iotlb_retry = None;
        Self::increment(&mut self.counters.iotlb_timeouts)?;
        Ok(token)
    }

    fn retry_iotlb_inner(
        &mut self,
        ticket: RevokeTicket,
        tombstone: TombstoneToken,
    ) -> Result<IotlbRetryToken, ProductionIdentityError> {
        self.validate_revoke_ticket(&ticket)?;
        let record = self
            .tombstone
            .ok_or(ProductionIdentityError::InvalidTombstone)?;
        if record.token != tombstone
            || tombstone.kind != TombstoneKind::Iotlb
            || record.reset_retry.is_none()
            || record.iotlb_retry.is_some()
            || tombstone.old_device != self.device
        {
            return Err(ProductionIdentityError::InvalidTombstone);
        }
        let retry = IotlbRetryToken {
            tombstone,
            device: self.device,
            sequence: Self::allocate(&mut self.next_retry_sequence)?,
        };
        self.tombstone
            .as_mut()
            .ok_or(ProductionIdentityError::InvalidTombstone)?
            .iotlb_retry = Some(retry);
        Self::increment(&mut self.counters.iotlb_retries)?;
        Ok(retry)
    }

    fn acknowledge_retry_iotlb_inner(
        &mut self,
        retry: IotlbRetryToken,
    ) -> Result<(), ProductionIdentityError> {
        let tombstone = self
            .tombstone
            .ok_or(ProductionIdentityError::InvalidTombstone)?;
        if tombstone.iotlb_retry != Some(retry) || retry.device != self.device {
            return Err(ProductionIdentityError::InvalidRetry);
        }
        self.validate_lineage(retry.tombstone.lineage)?;
        for key in retry.tombstone.dma_owners {
            let record = self
                .effects
                .get(&key.effect_id)
                .ok_or(ProductionIdentityError::UnknownEffect)?;
            if record.phase != EffectPhase::Tombstoned
                || record.credit_disposition != CreditDisposition::Retained
            {
                return Err(ProductionIdentityError::InvalidTombstone);
            }
        }
        let block = self
            .effects
            .get(&retry.tombstone.block.effect_id)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        if block.phase != EffectPhase::Tombstoned
            || block.credit_disposition != CreditDisposition::Retained
        {
            return Err(ProductionIdentityError::InvalidTombstone);
        }
        for key in retry.tombstone.dma_owners {
            self.terminalize(key, EffectPhase::Completed)?;
        }
        self.terminalize(retry.tombstone.block, EffectPhase::Completed)?;
        self.tombstone = None;
        Self::increment(&mut self.counters.iotlb_acks)?;
        Ok(())
    }

    fn revoke_next_inner(
        &mut self,
        ticket: RevokeTicket,
    ) -> Result<ClosureStep, ProductionIdentityError> {
        self.validate_revoke_ticket(&ticket)?;
        let mut selected = None;
        for key in &self.root_live {
            if !ticket.frozen_effects.contains(key) {
                return Err(ProductionIdentityError::InvariantViolation);
            }
            Self::increment(&mut self.counters.child_index_checks)?;
            let children = self
                .live_children
                .get(key)
                .ok_or(ProductionIdentityError::UnknownEffect)?;
            if children.is_empty() {
                selected = Some(*key);
                break;
            }
        }
        let key = selected.ok_or(ProductionIdentityError::ClosureIncomplete)?;
        let record = self
            .effects
            .get(&key.effect_id)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        let from = record.phase;
        if matches!(
            from,
            EffectPhase::Committed | EffectPhase::BackendCompleted | EffectPhase::Tombstoned
        ) {
            return Err(ProductionIdentityError::DeviceNotQuiescent);
        }
        if !matches!(from, EffectPhase::Registered | EffectPhase::Prepared) {
            return Err(ProductionIdentityError::InvalidEffectState);
        }
        let identity = record.identity;
        Self::increment(&mut self.counters.root_index_selections)?;
        self.terminalize(key, EffectPhase::Aborted)?;
        Ok(ClosureStep {
            effect: identity,
            from,
            to: EffectPhase::Aborted,
        })
    }

    fn revoke_complete_inner(
        &mut self,
        ticket: RevokeTicket,
    ) -> Result<ClosureResult, ProductionIdentityError> {
        self.validate_revoke_ticket(&ticket)?;
        if let Some(tombstone) = self.tombstone {
            return Ok(ClosureResult::IndeterminateAfterReset {
                tombstone: Box::new(tombstone.token),
                retained_credits: self.ledger.retained,
            });
        }
        if !self.root_live.is_empty() {
            return Err(ProductionIdentityError::ClosureIncomplete);
        }
        if self
            .ledger
            .held
            .iter()
            .chain(self.ledger.committed.iter())
            .chain(self.ledger.retained.iter())
            .any(|units| *units != 0)
        {
            return Err(ProductionIdentityError::ClosureIncomplete);
        }
        self.root_phase = RootPhase::Revoked;
        Ok(ClosureResult::Revoked {
            closure_revision: ticket.closure_revision,
            terminalizations: self.counters.terminalizations,
        })
    }

    fn move_operation_credits(
        &mut self,
        operation: OperationClass,
        from: CreditDisposition,
        to: CreditDisposition,
    ) -> Result<(), ProductionIdentityError> {
        for &(credit, units) in operation.credit_grants() {
            let index = credit.index();
            let source = match from {
                CreditDisposition::Held => &mut self.ledger.held[index],
                CreditDisposition::Committed => &mut self.ledger.committed[index],
                CreditDisposition::Returned => &mut self.ledger.returned[index],
                CreditDisposition::Retained => &mut self.ledger.retained[index],
            };
            *source = source
                .checked_sub(units)
                .ok_or(ProductionIdentityError::InvariantViolation)?;
            let target = match to {
                CreditDisposition::Held => &mut self.ledger.held[index],
                CreditDisposition::Committed => &mut self.ledger.committed[index],
                CreditDisposition::Returned => &mut self.ledger.returned[index],
                CreditDisposition::Retained => &mut self.ledger.retained[index],
            };
            *target = target
                .checked_add(units)
                .ok_or(ProductionIdentityError::CounterOverflow)?;
        }
        Ok(())
    }

    fn terminalize(
        &mut self,
        key: EffectKey,
        terminal: EffectPhase,
    ) -> Result<(), ProductionIdentityError> {
        if !terminal.is_terminal() {
            return Err(ProductionIdentityError::InvalidEffectState);
        }
        let record = self
            .effects
            .get(&key.effect_id)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        if record.phase.is_terminal() || record.terminalizations != 0 {
            return Err(ProductionIdentityError::InvalidEffectState);
        }
        let children = self
            .live_children
            .get(&key)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        if !children.is_empty() {
            return Err(ProductionIdentityError::ClosureIncomplete);
        }
        let identity = record.identity;
        let disposition = record.credit_disposition;
        match (terminal, disposition) {
            (EffectPhase::Aborted, CreditDisposition::Held)
            | (EffectPhase::Completed, CreditDisposition::Committed)
            | (EffectPhase::Completed, CreditDisposition::Retained) => {}
            _ => return Err(ProductionIdentityError::InvalidEffectState),
        }
        self.move_operation_credits(identity.operation, disposition, CreditDisposition::Returned)?;
        let record = self
            .effects
            .get_mut(&key.effect_id)
            .ok_or(ProductionIdentityError::UnknownEffect)?;
        record.phase = terminal;
        record.credit_disposition = CreditDisposition::Returned;
        record.terminalizations = 1;
        if !self.root_live.remove(&key) || !self.domain_live[identity.domain.index()].remove(&key) {
            return Err(ProductionIdentityError::InvariantViolation);
        }
        if let ParentIdentity::Effect(parent) = identity.parent {
            let removed = self
                .live_children
                .get_mut(&parent)
                .ok_or(ProductionIdentityError::InvariantViolation)?
                .remove(&key);
            if !removed {
                return Err(ProductionIdentityError::InvariantViolation);
            }
        }
        self.closure_order.push(key);
        Self::increment(&mut self.counters.terminalizations)?;
        Ok(())
    }

    /// Audits identity, ancestry, indexes, typed credits, recovery, device,
    /// publication, terminalization, closure, and allocator invariants.
    pub fn check_invariants(&self) -> Result<(), ProductionIdentityInvariant> {
        self.check_identity_tree()?;
        self.check_reverse_indexes()?;
        self.check_credits()?;
        self.check_recovery()?;
        self.check_publications()?;
        self.check_tombstone()?;
        self.check_root_closure()?;
        self.check_allocators()?;
        Ok(())
    }

    fn check_identity_tree(&self) -> Result<(), ProductionIdentityInvariant> {
        if self.effects.len() != self.effect_by_operation.len() || self.effects.len() > EFFECT_COUNT
        {
            return Err(ProductionIdentityInvariant::IdentityTree);
        }
        for (&effect_id, record) in &self.effects {
            let identity = record.identity;
            if identity.key.effect_id != effect_id
                || identity.key.effect_generation != 1
                || identity.key.lineage != self.lineage
                || identity.authority_epoch == 0
                || identity.authority_epoch > self.authority_epoch
                || identity.domain != identity.operation.domain()
                || identity.origin_binding.lineage != self.lineage
                || identity.origin_binding.domain != identity.domain
                || record.current_binding.lineage != self.lineage
                || record.current_binding.domain != identity.domain
                || self.effect_by_operation.get(&identity.operation) != Some(&identity.key)
            {
                return Err(ProductionIdentityInvariant::IdentityTree);
            }
            let expected_parent =
                if let Some(parent_operation) = identity.operation.parent_operation() {
                    let parent = self
                        .effect_by_operation
                        .get(&parent_operation)
                        .ok_or(ProductionIdentityInvariant::IdentityTree)?;
                    ParentIdentity::Effect(*parent)
                } else {
                    ParentIdentity::Root(self.lineage)
                };
            if identity.parent != expected_parent {
                return Err(ProductionIdentityInvariant::IdentityTree);
            }
            match identity.parent {
                ParentIdentity::Root(lineage) if lineage == self.lineage => {}
                ParentIdentity::Effect(parent)
                    if self.effects.contains_key(&parent.effect_id)
                        && parent.lineage == self.lineage => {}
                _ => return Err(ProductionIdentityInvariant::IdentityTree),
            }
            let valid_credit_state = matches!(
                (record.phase, record.credit_disposition),
                (
                    EffectPhase::Registered | EffectPhase::Prepared,
                    CreditDisposition::Held
                ) | (
                    EffectPhase::Committed | EffectPhase::BackendCompleted,
                    CreditDisposition::Committed
                ) | (EffectPhase::Tombstoned, CreditDisposition::Retained)
                    | (
                        EffectPhase::Completed | EffectPhase::Aborted,
                        CreditDisposition::Returned
                    )
            );
            if !valid_credit_state {
                return Err(ProductionIdentityInvariant::EffectCreditState);
            }
            if record.phase.is_terminal() != (record.terminalizations == 1)
                || record.terminalizations > 1
            {
                return Err(ProductionIdentityInvariant::Terminalization);
            }
        }
        Ok(())
    }

    fn check_reverse_indexes(&self) -> Result<(), ProductionIdentityInvariant> {
        let mut expected_root = BTreeSet::new();
        let mut expected_domains: [BTreeSet<EffectKey>; DOMAIN_COUNT] =
            core::array::from_fn(|_| BTreeSet::new());
        let mut expected_children = self
            .effects
            .values()
            .map(|record| (record.identity.key, BTreeSet::new()))
            .collect::<BTreeMap<_, _>>();
        for record in self.effects.values() {
            if record.phase.is_terminal() {
                continue;
            }
            expected_root.insert(record.identity.key);
            expected_domains[record.identity.domain.index()].insert(record.identity.key);
            if let ParentIdentity::Effect(parent) = record.identity.parent {
                expected_children
                    .get_mut(&parent)
                    .ok_or(ProductionIdentityInvariant::ReverseIndex)?
                    .insert(record.identity.key);
            }
        }
        if self.root_live != expected_root
            || self.domain_live != expected_domains
            || self.live_children != expected_children
        {
            return Err(ProductionIdentityInvariant::ReverseIndex);
        }
        Ok(())
    }

    fn check_credits(&self) -> Result<(), ProductionIdentityInvariant> {
        let mut held = [0_u64; CREDIT_CLASS_COUNT];
        let mut committed = [0_u64; CREDIT_CLASS_COUNT];
        let mut returned = [0_u64; CREDIT_CLASS_COUNT];
        let mut retained = [0_u64; CREDIT_CLASS_COUNT];
        for record in self.effects.values() {
            let target = match record.credit_disposition {
                CreditDisposition::Held => &mut held,
                CreditDisposition::Committed => &mut committed,
                CreditDisposition::Returned => &mut returned,
                CreditDisposition::Retained => &mut retained,
            };
            for &(credit, units) in record.identity.operation.credit_grants() {
                target[credit.index()] = target[credit.index()]
                    .checked_add(units)
                    .ok_or(ProductionIdentityInvariant::CreditConservation)?;
            }
        }
        if self.ledger.held != held
            || self.ledger.committed != committed
            || self.ledger.returned != returned
            || self.ledger.retained != retained
        {
            return Err(ProductionIdentityInvariant::CreditConservation);
        }
        for credit in CreditClass::ALL {
            let index = credit.index();
            if self.ledger.capacity[index] != credit.capacity()
                || self.ledger.free[index]
                    + held[index]
                    + committed[index]
                    + returned[index]
                    + retained[index]
                    != credit.capacity()
            {
                return Err(ProductionIdentityInvariant::CreditConservation);
            }
        }
        Ok(())
    }

    fn check_recovery(&self) -> Result<(), ProductionIdentityInvariant> {
        for domain in DomainId::ALL {
            let binding = &self.bindings[domain.index()];
            let Some(recovery) = &self.recovery[domain.index()] else {
                if binding.service.is_none() {
                    return Err(ProductionIdentityInvariant::Recovery);
                }
                continue;
            };
            if recovery.domain != domain
                || recovery.target_binding_epoch != binding.binding_epoch
                || recovery.crashed_binding_epoch >= recovery.target_binding_epoch
                || !recovery.unadopted.is_subset(&recovery.cohort)
                || (recovery.ready && recovery.snapshot.is_none())
                || (recovery.rebound && !recovery.ready)
                || (recovery.rebound != binding.service.is_some())
            {
                return Err(ProductionIdentityInvariant::Recovery);
            }
            if let Some(snapshot) = &recovery.snapshot {
                let snapshot_keys = snapshot
                    .cohort
                    .iter()
                    .map(|identity| identity.key)
                    .collect::<BTreeSet<_>>();
                if snapshot.lineage != self.lineage
                    || snapshot.domain != domain
                    || snapshot.revision != recovery.revision
                    || snapshot.crashed_binding_epoch != recovery.crashed_binding_epoch
                    || snapshot.target_binding_epoch != recovery.target_binding_epoch
                    || snapshot_keys != recovery.cohort
                {
                    return Err(ProductionIdentityInvariant::Recovery);
                }
            }
            for key in &recovery.cohort {
                let record = self
                    .effects
                    .get(&key.effect_id)
                    .ok_or(ProductionIdentityInvariant::Recovery)?;
                if record.identity.domain != domain {
                    return Err(ProductionIdentityInvariant::Recovery);
                }
                let expected_epoch = if recovery.unadopted.contains(key) {
                    recovery.crashed_binding_epoch
                } else {
                    recovery.target_binding_epoch
                };
                if record.current_binding.binding_epoch != expected_epoch {
                    return Err(ProductionIdentityInvariant::Recovery);
                }
            }
        }
        Ok(())
    }

    fn check_publications(&self) -> Result<(), ProductionIdentityInvariant> {
        if self.counters.registrations != self.effects.len() as u64
            || self.counters.commits != u64::from(self.commit.is_some())
            || self.counters.guest_replies != u64::from(self.guest_reply.is_some())
            || self.counters.terminalizations != self.closure_order.len() as u64
            || self
                .closure_order
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != self.closure_order.len()
        {
            return Err(ProductionIdentityInvariant::Publication);
        }
        let block_publications = self
            .effect(OperationClass::BlockRequest)
            .and_then(|identity| self.effects.get(&identity.key.effect_id))
            .map_or(0, |record| record.publications);
        if block_publications != u8::from(self.commit.is_some()) {
            return Err(ProductionIdentityInvariant::Publication);
        }
        if let Some(commit) = self.commit {
            let expected_owners = [
                OperationClass::DmaQueueOwnerA,
                OperationClass::DmaQueueOwnerB,
                OperationClass::DmaRequestOwner,
            ];
            if commit.block.operation != OperationClass::BlockRequest
                || commit.syscall.operation != OperationClass::FilesystemSyscall
                || commit.filesystem.operation != OperationClass::FilesystemRead
                || commit.filesystem.parent != ParentIdentity::Effect(commit.syscall.key)
                || commit.block.parent != ParentIdentity::Effect(commit.filesystem.key)
                || commit.root.lineage != self.lineage
                || commit.root.authority_epoch != commit.block.authority_epoch
                || commit.device.lineage != self.lineage
                || commit.binding.domain != DomainId::VirtIo
                || commit.domain_revision == 0
            {
                return Err(ProductionIdentityInvariant::Publication);
            }
            for (owner, operation) in commit.dma_owners.into_iter().zip(expected_owners) {
                if owner.operation != operation
                    || owner.parent != ParentIdentity::Effect(commit.block.key)
                {
                    return Err(ProductionIdentityInvariant::Publication);
                }
            }
        }
        let syscall_publications = self
            .effect(OperationClass::FilesystemSyscall)
            .and_then(|identity| self.effects.get(&identity.key.effect_id))
            .map_or(0, |record| record.publications);
        if syscall_publications != u8::from(self.guest_reply.is_some()) {
            return Err(ProductionIdentityInvariant::Publication);
        }
        if let Some(reply) = self.guest_reply {
            let syscall = self
                .effects
                .get(&reply.syscall.key.effect_id)
                .ok_or(ProductionIdentityInvariant::Publication)?;
            let filesystem = self
                .effects
                .get(&reply.filesystem.key.effect_id)
                .ok_or(ProductionIdentityInvariant::Publication)?;
            if syscall.phase != EffectPhase::Completed
                || filesystem.phase != EffectPhase::Completed
                || self.commit.map(CommitReceipt::sequence) != Some(reply.block_commit_sequence)
                || self.backend_outcome != Some(reply.outcome)
            {
                return Err(ProductionIdentityInvariant::Publication);
            }
        }
        if let Some(outcome) = self.backend_outcome {
            let block = self
                .effect(OperationClass::BlockRequest)
                .and_then(|identity| self.effects.get(&identity.key.effect_id))
                .ok_or(ProductionIdentityInvariant::Publication)?;
            let valid_phase = match outcome {
                BackendOutcome::Data => matches!(
                    block.phase,
                    EffectPhase::BackendCompleted
                        | EffectPhase::Tombstoned
                        | EffectPhase::Completed
                ),
                BackendOutcome::IndeterminateAfterReset => {
                    matches!(
                        block.phase,
                        EffectPhase::Tombstoned | EffectPhase::Completed
                    )
                }
            };
            if !valid_phase {
                return Err(ProductionIdentityInvariant::Publication);
            }
        }
        Ok(())
    }

    fn check_tombstone(&self) -> Result<(), ProductionIdentityInvariant> {
        if let Some(tombstone) = self.tombstone {
            if tombstone.token.lineage != self.lineage
                || tombstone.token.closure_revision != self.closure_revision
                || tombstone.token.old_device.lineage != self.lineage
            {
                return Err(ProductionIdentityInvariant::Tombstone);
            }
            for key in core::iter::once(tombstone.token.block).chain(tombstone.token.dma_owners) {
                let record = self
                    .effects
                    .get(&key.effect_id)
                    .ok_or(ProductionIdentityInvariant::Tombstone)?;
                if record.phase != EffectPhase::Tombstoned
                    || record.credit_disposition != CreditDisposition::Retained
                {
                    return Err(ProductionIdentityInvariant::Tombstone);
                }
            }
            match tombstone.token.kind {
                TombstoneKind::Reset => {
                    if tombstone.iotlb_retry.is_some() {
                        return Err(ProductionIdentityInvariant::Tombstone);
                    }
                    if let Some(retry) = tombstone.reset_retry {
                        if retry.tombstone != tombstone.token
                            || retry.new_device != self.device
                            || retry.new_device.device_generation
                                != tombstone.token.old_device.device_generation + 1
                            || self.backend_outcome != Some(BackendOutcome::IndeterminateAfterReset)
                        {
                            return Err(ProductionIdentityInvariant::Tombstone);
                        }
                    } else if self.device != tombstone.token.old_device {
                        return Err(ProductionIdentityInvariant::Tombstone);
                    }
                }
                TombstoneKind::Iotlb => {
                    let reset_retry = tombstone
                        .reset_retry
                        .ok_or(ProductionIdentityInvariant::Tombstone)?;
                    if reset_retry.new_device != self.device
                        || tombstone.token.old_device != self.device
                        || self.backend_outcome != Some(BackendOutcome::IndeterminateAfterReset)
                    {
                        return Err(ProductionIdentityInvariant::Tombstone);
                    }
                    if let Some(retry) = tombstone.iotlb_retry
                        && (retry.tombstone != tombstone.token || retry.device != self.device)
                    {
                        return Err(ProductionIdentityInvariant::Tombstone);
                    }
                }
            }
        } else if self.ledger.retained.iter().any(|units| *units != 0) {
            return Err(ProductionIdentityInvariant::Tombstone);
        }
        Ok(())
    }

    fn check_root_closure(&self) -> Result<(), ProductionIdentityInvariant> {
        match self.root_phase {
            RootPhase::Active => {
                if self.revoke.is_some() {
                    return Err(ProductionIdentityInvariant::RootClosure);
                }
            }
            RootPhase::Closing | RootPhase::Revoked => {
                let ticket = self
                    .revoke
                    .as_ref()
                    .ok_or(ProductionIdentityInvariant::RootClosure)?;
                if ticket.lineage != self.lineage
                    || ticket.authority_epoch != self.authority_epoch
                    || ticket.closed_authority_epoch.checked_add(1) != Some(ticket.authority_epoch)
                    || ticket.closure_revision != self.closure_revision
                    || ticket
                        .frozen_effects
                        .iter()
                        .any(|key| !self.effects.contains_key(&key.effect_id))
                {
                    return Err(ProductionIdentityInvariant::RootClosure);
                }
            }
        }
        if self.root_phase == RootPhase::Revoked
            && (!self.root_live.is_empty()
                || self
                    .ledger
                    .held
                    .iter()
                    .chain(self.ledger.committed.iter())
                    .chain(self.ledger.retained.iter())
                    .any(|units| *units != 0))
        {
            return Err(ProductionIdentityInvariant::RootClosure);
        }
        Ok(())
    }

    fn check_allocators(&self) -> Result<(), ProductionIdentityInvariant> {
        let max_effect = self.effects.keys().next_back().copied().unwrap_or(0);
        if self.next_effect_id <= max_effect
            || self.next_effect_id == 0
            || self.next_commit_sequence == 0
            || self.next_revoke_sequence == 0
            || self.next_recovery_revision == 0
            || self.next_tombstone_id == 0
            || self.next_retry_sequence == 0
            || self.next_guest_reply_sequence == 0
            || self.counters.unrelated_index_visits != 0
        {
            return Err(ProductionIdentityInvariant::Allocator);
        }
        if self
            .commit
            .is_some_and(|receipt| receipt.sequence >= self.next_commit_sequence)
            || self
                .revoke
                .as_ref()
                .is_some_and(|ticket| ticket.sequence >= self.next_revoke_sequence)
            || self
                .guest_reply
                .is_some_and(|receipt| receipt.sequence >= self.next_guest_reply_sequence)
            || self.tombstone.is_some_and(|record| {
                record.token.id >= self.next_tombstone_id
                    || record
                        .reset_retry
                        .is_some_and(|retry| retry.sequence >= self.next_retry_sequence)
                    || record
                        .iotlb_retry
                        .is_some_and(|retry| retry.sequence >= self.next_retry_sequence)
            })
        {
            return Err(ProductionIdentityInvariant::Allocator);
        }
        Ok(())
    }
}
