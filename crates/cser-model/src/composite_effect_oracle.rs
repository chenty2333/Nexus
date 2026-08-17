//! Independent oracle for one heterogeneous composite CSER effect.
//!
//! The model deliberately shares no commands, records, codecs, or transition
//! helpers with `cser-core`.  One [`EffectId`] owns two fixed components:
//! logical reply settlement and DMA retirement.  Authority fencing is common
//! to the effect, while claims and terminal progress remain component-local.
//! In particular, a retired physical claim may receive a resource-local reuse
//! permit while the reply component is still live.

use crate::{EffectId, ExecutorCoordinate, ExecutorId, OperationId};

pub use crate::ComponentId;

/// Fixed claim classes in the bounded composite profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimKind {
    /// The logical output remains owed until exact acknowledgement or tombstone.
    ReplyOutput,
    /// The submitted queue slot cannot be reused before reset and IRQ drain.
    QueueSlot,
    /// The pinned page cannot return to an allocator before mapping retirement.
    PinnedPage,
    /// The old IOVA cannot be reassigned before completed invalidation.
    IovaMapping,
}

impl ClaimKind {
    /// Every claim in stable projection order.
    pub const ALL: [Self; 4] = [
        Self::ReplyOutput,
        Self::QueueSlot,
        Self::PinnedPage,
        Self::IovaMapping,
    ];

    /// Returns the component that owns this claim.
    #[must_use]
    pub const fn component(self) -> ComponentId {
        match self {
            Self::ReplyOutput => ComponentId::Reply,
            Self::QueueSlot | Self::PinnedPage | Self::IovaMapping => ComponentId::Dma,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::ReplyOutput => 0,
            Self::QueueSlot => 1,
            Self::PinnedPage => 2,
            Self::IovaMapping => 3,
        }
    }

    const fn is_physical(self) -> bool {
        !matches!(self, Self::ReplyOutput)
    }
}

/// Stable identity of one logical or physical resource.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResourceId(u64);

impl ResourceId {
    /// Constructs a resource identity.
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

/// Resource coordinates supplied when a composite effect is registered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositeResources {
    /// Logical reply/output slot.
    pub reply_output: ResourceId,
    /// Device queue slot.
    pub queue_slot: ResourceId,
    /// Allocator-owned pinned page or persistent arena slot.
    pub pinned_page: ResourceId,
    /// IOMMU-visible address range.
    pub iova_mapping: ResourceId,
}

impl CompositeResources {
    /// Returns the resource assigned to one claim kind.
    #[must_use]
    pub const fn get(self, kind: ClaimKind) -> ResourceId {
        match kind {
            ClaimKind::ReplyOutput => self.reply_output,
            ClaimKind::QueueSlot => self.queue_slot,
            ClaimKind::PinnedPage => self.pinned_page,
            ClaimKind::IovaMapping => self.iova_mapping,
        }
    }

    const fn unique(self) -> bool {
        let values = [
            self.reply_output.0,
            self.queue_slot.0,
            self.pinned_page.0,
            self.iova_mapping.0,
        ];
        values[0] != values[1]
            && values[0] != values[2]
            && values[0] != values[3]
            && values[1] != values[2]
            && values[1] != values[3]
            && values[2] != values[3]
    }
}

/// Rejection emitted by the independent composite oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositeError {
    /// Revocation or release permanently closed principal authority.
    GateClosed,
    /// An authority observation names an old executor coordinate or epoch.
    StaleAuthority,
    /// The requested transition is not legal for the current authority state.
    WrongAuthorityState,
    /// The requested component is at an incompatible lifecycle stage.
    WrongComponentState,
    /// Another reply claimant currently owns the settlement gate.
    GateClaimed,
    /// A reply acknowledgement or intent names a reclaimed claim.
    StaleReplyClaim,
    /// Device evidence names the wrong effect, resource, or device generation.
    StaleDeviceEvidence,
    /// Required reset, IRQ drain, invalidation, or allocator evidence is absent.
    EvidenceOutOfOrder,
    /// A device or resource generation failed to advance monotonically.
    FreshnessRollback,
    /// The named claim remains live and therefore cannot be reused.
    ClaimStillLive,
    /// The named claim has already received a permit or entered a new generation.
    ClaimAlreadyReused,
    /// Logical output claims do not admit physical resource reuse.
    UnsupportedReuse,
    /// A requested reuse generation is not exactly the successor generation.
    ReuseGenerationMismatch,
    /// A reuse bearer does not match the one outstanding permit.
    StaleReusePermit,
    /// The parent effect still has a live component or claim.
    EffectNotRetired,
}

/// Shared authority state of the parent effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositeAuthority {
    /// The current executor may advance component work.
    Active,
    /// Executor authority is fenced while kernel custody survives.
    Fenced,
    /// Revocation permanently closed executor authority.
    Revoked,
}

/// Aggregate lifecycle derived from both components and all claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EscapeState {
    /// Neither component crossed an irreversible commit point.
    Unescaped,
    /// At least one component committed and no claim has discharged yet.
    Escaped,
    /// Some component or claim terminalized while other work remains.
    PartiallyDischarged,
    /// Every component is terminal and every old-generation claim is discharged.
    Retired,
    /// The already-retired parent record was explicitly released.
    Released,
}

/// Public reply settlement state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyState {
    /// Reply publication has not committed.
    Staged,
    /// A committed output obligation is open for settlement.
    Open {
        /// Monotonic settlement generation.
        generation: u64,
    },
    /// One live executor coordinate owns settlement.
    Claimed {
        /// Executor coordinate that owns the claim.
        claimant: ExecutorCoordinate,
        /// Monotonic settlement generation.
        generation: u64,
    },
    /// External apply intent is durable.
    ApplyIntentDurable {
        /// Executor coordinate that owns the claim.
        claimant: ExecutorCoordinate,
        /// Monotonic settlement generation.
        generation: u64,
    },
    /// External apply occurred but acknowledgement is not durable.
    AppliedUnacknowledged {
        /// Executor coordinate that owns the claim.
        claimant: ExecutorCoordinate,
        /// Monotonic settlement generation.
        generation: u64,
    },
    /// A crash requires exact reconciliation before settlement.
    ReconciliationRequired {
        /// Generation offered to the next claimant.
        generation: u64,
        /// Whether prior external apply was already observed.
        applied: bool,
    },
    /// Reply/output settlement completed exactly once.
    Settled,
    /// Kernel closure recorded a terminal non-publication outcome.
    Tombstoned,
    /// Revocation won before reply commit.
    Aborted,
}

impl ReplyState {
    const fn committed(self) -> bool {
        !matches!(self, Self::Staged | Self::Aborted)
    }

    const fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Tombstoned | Self::Aborted)
    }
}

/// Logical outcome of the DMA component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaOutcome {
    /// Queue publication has not committed.
    Staged,
    /// The device may still complete the submitted request.
    Pending,
    /// An exact current-generation IRQ/completion was accepted.
    Completed,
    /// Reset made the old submitted outcome unknowable.
    IndeterminateAfterReset,
    /// Revocation won before queue publication.
    Aborted,
}

impl DmaOutcome {
    const fn committed(self) -> bool {
        !matches!(self, Self::Staged | Self::Aborted)
    }

    const fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::IndeterminateAfterReset | Self::Aborted
        )
    }
}

/// Lifecycle of one component-local claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimState {
    /// The component has not committed this claim.
    Staged,
    /// The old generation remains exclusively retained.
    Live,
    /// Typed evidence discharged the old generation.
    Discharged,
    /// A one-shot permit authorizes exactly the next generation.
    ReusePermitted {
        /// Exact generation authorized for activation.
        next_generation: u64,
    },
    /// The resource entered the next generation without reviving the old claim.
    Reused {
        /// Active successor generation.
        generation: u64,
    },
}

impl ClaimState {
    const fn live(self) -> bool {
        matches!(self, Self::Live)
    }

    const fn discharged(self) -> bool {
        matches!(
            self,
            Self::Discharged | Self::ReusePermitted { .. } | Self::Reused { .. }
        )
    }
}

/// Exact shared-authority observation consumed by a state-changing command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityObservation {
    effect: EffectId,
    executor: ExecutorCoordinate,
    authority_epoch: u64,
}

impl AuthorityObservation {
    /// Returns the observed operation.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.effect.operation()
    }

    /// Returns the exact observed effect identity.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the observed executor coordinate.
    #[must_use]
    pub const fn executor(self) -> ExecutorCoordinate {
        self.executor
    }

    /// Returns the observed authority epoch.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Substitutes an operation identity for negative testing.
    #[must_use]
    pub const fn with_operation(mut self, operation: OperationId) -> Self {
        self.effect = EffectId::new(operation, self.effect.sequence()).unwrap();
        self
    }

    /// Substitutes an exact effect identity for negative testing.
    #[must_use]
    pub const fn with_effect(mut self, effect: EffectId) -> Self {
        self.effect = effect;
        self
    }

    /// Substitutes an executor coordinate for negative testing.
    #[must_use]
    pub const fn with_executor(mut self, executor: ExecutorCoordinate) -> Self {
        self.executor = executor;
        self
    }

    /// Substitutes an authority epoch for negative testing.
    #[must_use]
    pub const fn with_authority_epoch(mut self, epoch: u64) -> Self {
        self.authority_epoch = epoch;
        self
    }
}

/// One-shot bearer for the reply component's settlement gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyClaim {
    effect: EffectId,
    claimant: ExecutorCoordinate,
    generation: u64,
    nonce: u64,
}

impl ReplyClaim {
    /// Returns the operation identity.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.effect.operation()
    }

    /// Returns the exact effect identity bound to this claim.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the claimant executor coordinate.
    #[must_use]
    pub const fn claimant(self) -> ExecutorCoordinate {
        self.claimant
    }

    /// Returns the settlement generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the one-shot claim nonce.
    #[must_use]
    pub const fn nonce(self) -> u64 {
        self.nonce
    }

    /// Substitutes the operation identity for negative testing.
    #[must_use]
    pub const fn with_operation(mut self, operation: OperationId) -> Self {
        self.effect = EffectId::new(operation, self.effect.sequence()).unwrap();
        self
    }

    /// Substitutes an exact effect identity for negative testing.
    #[must_use]
    pub const fn with_effect(mut self, effect: EffectId) -> Self {
        self.effect = effect;
        self
    }

    /// Substitutes the claimant for negative testing.
    #[must_use]
    pub const fn with_claimant(mut self, claimant: ExecutorCoordinate) -> Self {
        self.claimant = claimant;
        self
    }

    /// Substitutes the settlement generation for negative testing.
    #[must_use]
    pub const fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    /// Substitutes the nonce for negative testing.
    #[must_use]
    pub const fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }
}

/// Device completion event captured before any reset-generation advance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaEvent {
    effect: EffectId,
    resource_generation: u64,
    device_generation: u64,
}

impl DmaEvent {
    /// Returns the parent operation.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.effect.operation()
    }

    /// Returns the exact effect identity bound to this event.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the DMA allocation generation.
    #[must_use]
    pub const fn resource_generation(self) -> u64 {
        self.resource_generation
    }

    /// Returns the device generation that emitted the event.
    #[must_use]
    pub const fn device_generation(self) -> u64 {
        self.device_generation
    }

    /// Substitutes the operation identity for negative testing.
    #[must_use]
    pub const fn with_operation(mut self, operation: OperationId) -> Self {
        self.effect = EffectId::new(operation, self.effect.sequence()).unwrap();
        self
    }

    /// Substitutes an exact effect identity for negative testing.
    #[must_use]
    pub const fn with_effect(mut self, effect: EffectId) -> Self {
        self.effect = effect;
        self
    }

    /// Substitutes the resource generation for negative testing.
    #[must_use]
    pub const fn with_resource_generation(mut self, generation: u64) -> Self {
        self.resource_generation = generation;
        self
    }

    /// Substitutes the device generation for negative testing.
    #[must_use]
    pub const fn with_device_generation(mut self, generation: u64) -> Self {
        self.device_generation = generation;
        self
    }
}

/// Typed device-retirement evidence for the exact old DMA generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaEvidence {
    effect: EffectId,
    resource_generation: u64,
    subject_device_generation: u64,
    observation_device_generation: u64,
}

impl DmaEvidence {
    /// Returns the parent operation.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.effect.operation()
    }

    /// Returns the exact effect identity bound to this evidence.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the retained resource generation.
    #[must_use]
    pub const fn resource_generation(self) -> u64 {
        self.resource_generation
    }

    /// Returns the old device generation being retired.
    #[must_use]
    pub const fn subject_device_generation(self) -> u64 {
        self.subject_device_generation
    }

    /// Returns the fresh generation in which retirement was observed.
    #[must_use]
    pub const fn observation_device_generation(self) -> u64 {
        self.observation_device_generation
    }

    /// Substitutes the operation identity for negative testing.
    #[must_use]
    pub const fn with_operation(mut self, operation: OperationId) -> Self {
        self.effect = EffectId::new(operation, self.effect.sequence()).unwrap();
        self
    }

    /// Substitutes an exact effect identity for negative testing.
    #[must_use]
    pub const fn with_effect(mut self, effect: EffectId) -> Self {
        self.effect = effect;
        self
    }

    /// Substitutes the resource generation for negative testing.
    #[must_use]
    pub const fn with_resource_generation(mut self, generation: u64) -> Self {
        self.resource_generation = generation;
        self
    }

    /// Substitutes the old device generation for negative testing.
    #[must_use]
    pub const fn with_subject_device_generation(mut self, generation: u64) -> Self {
        self.subject_device_generation = generation;
        self
    }

    /// Substitutes the observation generation for negative testing.
    #[must_use]
    pub const fn with_observation_device_generation(mut self, generation: u64) -> Self {
        self.observation_device_generation = generation;
        self
    }
}

/// One-shot resource-local permission for a successor generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReusePermit {
    effect: EffectId,
    kind: ClaimKind,
    actor: ExecutorCoordinate,
    authority_epoch: u64,
    resource: ResourceId,
    retired_generation: u64,
    next_generation: u64,
    device_generation: u64,
    nonce: u64,
}

impl ReusePermit {
    /// Returns the parent operation whose old claim was discharged.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.effect.operation()
    }

    /// Returns the exact effect identity bound to this permit.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the claim kind authorized for reuse.
    #[must_use]
    pub const fn kind(self) -> ClaimKind {
        self.kind
    }

    /// Returns the executor coordinate to which this bearer was issued.
    #[must_use]
    pub const fn actor(self) -> ExecutorCoordinate {
        self.actor
    }

    /// Returns the parent authority epoch to which this bearer was issued.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the exact resource identity.
    #[must_use]
    pub const fn resource(self) -> ResourceId {
        self.resource
    }

    /// Returns the retired generation.
    #[must_use]
    pub const fn retired_generation(self) -> u64 {
        self.retired_generation
    }

    /// Returns the authorized successor generation.
    #[must_use]
    pub const fn next_generation(self) -> u64 {
        self.next_generation
    }

    /// Returns the device freshness generation bound to the permit.
    #[must_use]
    pub const fn device_generation(self) -> u64 {
        self.device_generation
    }

    /// Returns the one-shot permit nonce.
    #[must_use]
    pub const fn nonce(self) -> u64 {
        self.nonce
    }

    /// Substitutes the operation identity for negative testing.
    #[must_use]
    pub const fn with_operation(mut self, operation: OperationId) -> Self {
        self.effect = EffectId::new(operation, self.effect.sequence()).unwrap();
        self
    }

    /// Substitutes an exact effect identity for negative testing.
    #[must_use]
    pub const fn with_effect(mut self, effect: EffectId) -> Self {
        self.effect = effect;
        self
    }

    /// Substitutes the executor coordinate for negative testing.
    #[must_use]
    pub const fn with_actor(mut self, actor: ExecutorCoordinate) -> Self {
        self.actor = actor;
        self
    }

    /// Substitutes the authority epoch for negative testing.
    #[must_use]
    pub const fn with_authority_epoch(mut self, epoch: u64) -> Self {
        self.authority_epoch = epoch;
        self
    }

    /// Substitutes the resource identity for negative testing.
    #[must_use]
    pub const fn with_resource(mut self, resource: ResourceId) -> Self {
        self.resource = resource;
        self
    }

    /// Substitutes the successor generation for negative testing.
    #[must_use]
    pub const fn with_next_generation(mut self, generation: u64) -> Self {
        self.next_generation = generation;
        self
    }

    /// Substitutes the nonce for negative testing.
    #[must_use]
    pub const fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }
}

/// Stable projection of one component-local claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimProjection {
    /// Exact parent effect identity.
    pub effect: EffectId,
    /// Component that owns the claim.
    pub component: ComponentId,
    /// Typed claim class.
    pub kind: ClaimKind,
    /// Stable resource identity.
    pub resource: ResourceId,
    /// Generation enrolled by the old effect.
    pub enrolled_generation: u64,
    /// Current claim lifecycle.
    pub state: ClaimState,
    /// Durable next-generation reservation retained across executor crashes.
    pub pending_reuse: Option<ReuseReservationProjection>,
}

/// Stable projection of one authority-bound resource reuse reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReuseReservationProjection {
    /// Executor coordinate that owns the current bearer.
    pub actor: ExecutorCoordinate,
    /// Parent authority epoch that owns the current bearer.
    pub authority_epoch: u64,
    /// Exact successor resource generation reserved.
    pub next_generation: u64,
    /// Device freshness generation observed when the bearer was issued.
    pub device_generation: u64,
    /// One-shot bearer nonce.
    pub nonce: u64,
}

/// Stable projection of one logical component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentProjection {
    /// Exact parent effect identity.
    pub effect: EffectId,
    /// Component identity.
    pub component: ComponentId,
    /// Whether the component crossed its commit point.
    pub committed: bool,
    /// Whether its logical obligation is terminal.
    pub terminal: bool,
    /// Number of old-generation claims that remain live.
    pub live_claims: usize,
}

/// Stable projection of the complete composite effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositeProjection {
    /// Exact effect identity shared by reply and DMA.
    pub effect: EffectId,
    /// Shared executor authority.
    pub authority: CompositeAuthority,
    /// Monotonic shared authority epoch.
    pub authority_epoch: u64,
    /// Current executor coordinate, absent between fence and rebind.
    pub live_executor: Option<ExecutorCoordinate>,
    /// Number of accepted executor crashes.
    pub crash_generation: u64,
    /// Aggregate escape and discharge state.
    pub escape: EscapeState,
    /// Reply component state.
    pub reply: ReplyState,
    /// DMA logical outcome.
    pub dma: DmaOutcome,
    /// Device generation enrolled at queue commit.
    pub enrolled_device_generation: u64,
    /// Current device freshness generation.
    pub active_device_generation: u64,
    /// Whether exact reset evidence was accepted.
    pub reset_accepted: bool,
    /// Whether exact IRQ-drain evidence was accepted.
    pub irq_drained: bool,
    /// Whether exact IOTLB invalidation evidence was accepted.
    pub iotlb_invalidated: bool,
    /// Whether the allocator relinquished the old page lease.
    pub allocator_released: bool,
    /// Component-local claims in [`ClaimKind::ALL`] order.
    pub claims: [ClaimProjection; 4],
    /// Number of successful state-changing transitions.
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplyClaimStage {
    Fresh,
    Intent,
    Applied,
    ReconcileIntent,
    ReconcileApplied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClaimRecord {
    kind: ClaimKind,
    resource: ResourceId,
    enrolled_generation: u64,
    state: ClaimState,
    pending_reuse: Option<ReuseReservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReuseReservation {
    actor: ExecutorCoordinate,
    authority_epoch: u64,
    next_generation: u64,
    device_generation: u64,
    nonce: u64,
}

/// Independent executable model for one heterogeneous escaped effect.
///
/// The fixed shape intentionally avoids an arbitrary workflow graph.  It is a
/// clean-room semantic oracle for a profile whose catalog contains exactly one
/// reply component and one DMA component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositeEffectOracle {
    effect: EffectId,
    origin_executor: ExecutorId,
    authority: CompositeAuthority,
    authority_epoch: u64,
    root_live: bool,
    live_executor: Option<ExecutorCoordinate>,
    last_executor: ExecutorCoordinate,
    crash_generation: u64,
    reply: ReplyState,
    reply_claim_stage: Option<ReplyClaimStage>,
    active_reply_nonce: Option<u64>,
    next_reply_nonce: u64,
    dma: DmaOutcome,
    dma_resource_generation: u64,
    enrolled_device_generation: u64,
    active_device_generation: u64,
    reset_accepted: bool,
    irq_drained: bool,
    iotlb_invalidated: bool,
    allocator_released: bool,
    claims: [ClaimRecord; 4],
    next_permit_nonce: u64,
    released: bool,
    revision: u64,
}

impl CompositeEffectOracle {
    /// Registers one staged composite effect under a live executor.
    ///
    /// Resource identities must be pairwise distinct.  All operation and
    /// executor coordinates must be non-zero.
    #[must_use]
    pub fn new(
        effect: EffectId,
        executor: ExecutorCoordinate,
        resource_generation: u64,
        device_generation: u64,
        resources: CompositeResources,
    ) -> Self {
        assert!(
            resource_generation != 0 && resource_generation != u64::MAX,
            "resource generation must admit one successor"
        );
        assert!(device_generation != 0, "device generation must be non-zero");
        assert!(resources.unique(), "resource identities must be unique");
        let claims = core::array::from_fn(|index| {
            let kind = ClaimKind::ALL[index];
            ClaimRecord {
                kind,
                resource: resources.get(kind),
                enrolled_generation: resource_generation,
                state: ClaimState::Staged,
                pending_reuse: None,
            }
        });
        let model = Self {
            effect,
            origin_executor: executor.executor(),
            authority: CompositeAuthority::Active,
            authority_epoch: 1,
            root_live: true,
            live_executor: Some(executor),
            last_executor: executor,
            crash_generation: 0,
            reply: ReplyState::Staged,
            reply_claim_stage: None,
            active_reply_nonce: None,
            next_reply_nonce: 1,
            dma: DmaOutcome::Staged,
            dma_resource_generation: resource_generation,
            enrolled_device_generation: device_generation,
            active_device_generation: device_generation,
            reset_accepted: false,
            irq_drained: false,
            iotlb_invalidated: false,
            allocator_released: false,
            claims,
            next_permit_nonce: 1,
            released: false,
            revision: 0,
        };
        debug_assert!(model.check_invariants());
        model
    }

    /// Captures the exact live coordinates used by executor commands.
    pub fn observe_authority(&self) -> Result<AuthorityObservation, CompositeError> {
        if !self.root_live {
            return Err(CompositeError::WrongAuthorityState);
        }
        Ok(AuthorityObservation {
            effect: self.effect,
            executor: self
                .live_executor
                .ok_or(CompositeError::WrongAuthorityState)?,
            authority_epoch: self.authority_epoch,
        })
    }

    /// Returns the complete stable projection.
    #[must_use]
    pub fn projection(&self) -> CompositeProjection {
        CompositeProjection {
            effect: self.effect,
            authority: self.authority,
            authority_epoch: self.authority_epoch,
            live_executor: self.live_executor,
            crash_generation: self.crash_generation,
            escape: self.escape_state(),
            reply: self.reply,
            dma: self.dma,
            enrolled_device_generation: self.enrolled_device_generation,
            active_device_generation: self.active_device_generation,
            reset_accepted: self.reset_accepted,
            irq_drained: self.irq_drained,
            iotlb_invalidated: self.iotlb_invalidated,
            allocator_released: self.allocator_released,
            claims: core::array::from_fn(|index| self.claim_projection(ClaimKind::ALL[index])),
            revision: self.revision,
        }
    }

    /// Returns one component projection.
    #[must_use]
    pub fn component(&self, component: ComponentId) -> ComponentProjection {
        let (committed, terminal) = match component {
            ComponentId::Reply => (self.reply.committed(), self.reply.terminal()),
            ComponentId::Dma => (self.dma.committed(), self.dma.terminal()),
            _ => (false, false),
        };
        ComponentProjection {
            effect: self.effect,
            component,
            committed,
            terminal,
            live_claims: ClaimKind::ALL
                .iter()
                .filter(|kind| {
                    kind.component() == component && self.claims[kind.index()].state.live()
                })
                .count(),
        }
    }

    /// Returns one claim projection.
    #[must_use]
    pub fn claim(&self, kind: ClaimKind) -> ClaimProjection {
        self.claim_projection(kind)
    }

    /// Commits queue publication and activates all three DMA claims.
    pub fn commit_dma(&mut self, observation: AuthorityObservation) -> Result<(), CompositeError> {
        self.require_active(observation)?;
        if self.dma != DmaOutcome::Staged {
            return Err(CompositeError::WrongComponentState);
        }
        self.dma = DmaOutcome::Pending;
        for kind in [
            ClaimKind::QueueSlot,
            ClaimKind::PinnedPage,
            ClaimKind::IovaMapping,
        ] {
            self.claims[kind.index()].state = ClaimState::Live;
        }
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Commits the logical output obligation under the same parent identity.
    pub fn commit_reply(
        &mut self,
        observation: AuthorityObservation,
    ) -> Result<(), CompositeError> {
        self.require_active(observation)?;
        if self.reply != ReplyState::Staged {
            return Err(CompositeError::WrongComponentState);
        }
        self.reply = ReplyState::Open { generation: 1 };
        self.claims[ClaimKind::ReplyOutput.index()].state = ClaimState::Live;
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Captures a current-generation DMA completion event.
    pub fn dma_completion_event(&self) -> Result<DmaEvent, CompositeError> {
        if self.dma != DmaOutcome::Pending {
            return Err(CompositeError::WrongComponentState);
        }
        Ok(DmaEvent {
            effect: self.effect,
            resource_generation: self.dma_resource_generation,
            device_generation: self.active_device_generation,
        })
    }

    /// Accepts an exact current-generation IRQ/completion.
    pub fn accept_dma_completion(&mut self, event: DmaEvent) -> Result<(), CompositeError> {
        if event.effect != self.effect
            || event.resource_generation != self.dma_resource_generation
            || event.device_generation != self.active_device_generation
            || event.device_generation != self.enrolled_device_generation
            || self.reset_accepted
        {
            return Err(CompositeError::StaleDeviceEvidence);
        }
        if self.dma != DmaOutcome::Pending {
            return Err(CompositeError::WrongComponentState);
        }
        self.dma = DmaOutcome::Completed;
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Fences one exact live executor while preserving both components.
    pub fn fence_executor(
        &mut self,
        crashed_executor: ExecutorCoordinate,
    ) -> Result<(), CompositeError> {
        if !self.root_live || self.live_executor != Some(crashed_executor) {
            return Err(CompositeError::StaleAuthority);
        }
        self.root_live = false;
        self.live_executor = None;
        self.crash_generation = next_generation_of(self.crash_generation);
        self.authority_epoch = next_generation_of(self.authority_epoch);
        if self.authority != CompositeAuthority::Revoked {
            self.authority = CompositeAuthority::Fenced;
        }
        self.reclaim_reply_claim();
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Installs a strictly newer generation of the operation's executor after
    /// snapshot, Ready, and Rebind.
    pub fn rebind(&mut self, successor: ExecutorCoordinate) -> Result<(), CompositeError> {
        if self.root_live {
            return Err(CompositeError::WrongAuthorityState);
        }
        if successor.executor() != self.origin_executor
            || successor.generation() <= self.last_executor.generation()
        {
            return Err(CompositeError::StaleAuthority);
        }
        self.root_live = true;
        self.live_executor = Some(successor);
        self.last_executor = successor;
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Adopts a wholly precommit fenced parent effect.
    ///
    /// Once either component commits, kernel custody remains authoritative and
    /// recovery proceeds only through component-local settlement or retirement.
    pub fn adopt_effect(
        &mut self,
        observation: AuthorityObservation,
    ) -> Result<(), CompositeError> {
        self.require_observation(observation)?;
        if self.authority == CompositeAuthority::Revoked || self.released {
            return Err(CompositeError::GateClosed);
        }
        if self.authority != CompositeAuthority::Fenced {
            return Err(CompositeError::WrongAuthorityState);
        }
        if self.reply != ReplyState::Staged || self.dma != DmaOutcome::Staged {
            return Err(CompositeError::WrongComponentState);
        }
        self.authority = CompositeAuthority::Active;
        self.authority_epoch = next_generation_of(self.authority_epoch);
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Permanently revokes executor authority through the same observed epoch.
    ///
    /// Staged components abort atomically.  Committed obligations and live
    /// claims remain in kernel custody until their own typed terminal paths.
    pub fn begin_revoke(
        &mut self,
        observation: AuthorityObservation,
    ) -> Result<(), CompositeError> {
        self.require_observation(observation)?;
        if self.authority == CompositeAuthority::Revoked || self.released {
            return Err(CompositeError::GateClosed);
        }
        self.authority = CompositeAuthority::Revoked;
        self.authority_epoch = next_generation_of(self.authority_epoch);
        self.abort_staged_components();
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Claims the committed reply component for an exact executor coordinate.
    ///
    /// A fresh successor rebound to a fenced postcommit parent may settle this
    /// component without adopting the parent effect or physical DMA custody.
    pub fn claim_reply(
        &mut self,
        observation: AuthorityObservation,
    ) -> Result<ReplyClaim, CompositeError> {
        self.require_observation(observation)?;
        if self.authority == CompositeAuthority::Revoked || self.released {
            return Err(CompositeError::GateClosed);
        }
        if !matches!(
            self.authority,
            CompositeAuthority::Active | CompositeAuthority::Fenced
        ) {
            return Err(CompositeError::WrongAuthorityState);
        }
        let (generation, stage) = match self.reply {
            ReplyState::Open { generation } => (generation, ReplyClaimStage::Fresh),
            ReplyState::ReconciliationRequired {
                generation,
                applied,
            } => (
                generation,
                if applied {
                    ReplyClaimStage::ReconcileApplied
                } else {
                    ReplyClaimStage::ReconcileIntent
                },
            ),
            ReplyState::Claimed { .. }
            | ReplyState::ApplyIntentDurable { .. }
            | ReplyState::AppliedUnacknowledged { .. } => {
                return Err(CompositeError::GateClaimed);
            }
            _ => return Err(CompositeError::WrongComponentState),
        };
        let nonce = self.next_reply_nonce;
        self.next_reply_nonce = next_generation_of(self.next_reply_nonce);
        self.active_reply_nonce = Some(nonce);
        self.reply_claim_stage = Some(stage);
        self.reply = ReplyState::Claimed {
            claimant: observation.executor,
            generation,
        };
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(ReplyClaim {
            effect: self.effect,
            claimant: observation.executor,
            generation,
            nonce,
        })
    }

    /// Persists a write-ahead external apply intent for a fresh reply claim.
    pub fn record_reply_apply_intent(&mut self, claim: ReplyClaim) -> Result<(), CompositeError> {
        self.require_reply_claim(claim)?;
        if self.reply_claim_stage != Some(ReplyClaimStage::Fresh) {
            return Err(CompositeError::WrongComponentState);
        }
        self.reply_claim_stage = Some(ReplyClaimStage::Intent);
        self.reply = ReplyState::ApplyIntentDurable {
            claimant: claim.claimant,
            generation: claim.generation,
        };
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Records exact evidence that reply/output apply occurred.
    pub fn record_reply_applied(&mut self, claim: ReplyClaim) -> Result<(), CompositeError> {
        self.require_reply_claim(claim)?;
        self.reply_claim_stage = Some(match self.reply_claim_stage {
            Some(ReplyClaimStage::Intent) => ReplyClaimStage::Applied,
            Some(ReplyClaimStage::ReconcileIntent) => ReplyClaimStage::ReconcileApplied,
            _ => return Err(CompositeError::WrongComponentState),
        });
        self.reply = ReplyState::AppliedUnacknowledged {
            claimant: claim.claimant,
            generation: claim.generation,
        };
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Accepts terminal reply acknowledgement exactly once.
    ///
    /// Settlement and release of the publication-slot claim are distinct
    /// durable transitions. A crash after this acknowledgement therefore
    /// preserves a settled component with one retained logical claim until
    /// [`Self::retire_reply_output`] accepts the exact release fact.
    pub fn accept_reply_ack(&mut self, claim: ReplyClaim) -> Result<(), CompositeError> {
        self.require_reply_claim(claim)?;
        if !matches!(
            self.reply_claim_stage,
            Some(ReplyClaimStage::Applied | ReplyClaimStage::ReconcileApplied)
        ) {
            return Err(CompositeError::WrongComponentState);
        }
        self.reply = ReplyState::Settled;
        self.reply_claim_stage = None;
        self.active_reply_nonce = None;
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Retires the logical publication-slot claim after durable settlement.
    pub fn retire_reply_output(&mut self) -> Result<(), CompositeError> {
        if self.reply != ReplyState::Settled
            || self.claims[ClaimKind::ReplyOutput.index()].state != ClaimState::Live
        {
            return Err(CompositeError::WrongComponentState);
        }
        self.discharge_claim(ClaimKind::ReplyOutput);
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Terminates a committed reply without publication under kernel closure.
    pub fn tombstone_reply(&mut self) -> Result<(), CompositeError> {
        if !matches!(
            self.authority,
            CompositeAuthority::Fenced | CompositeAuthority::Revoked
        ) {
            return Err(CompositeError::WrongAuthorityState);
        }
        if !matches!(
            self.reply,
            ReplyState::Open { .. } | ReplyState::ReconciliationRequired { .. }
        ) {
            return Err(CompositeError::WrongComponentState);
        }
        self.reply = ReplyState::Tombstoned;
        self.reply_claim_stage = None;
        self.active_reply_nonce = None;
        self.discharge_claim(ClaimKind::ReplyOutput);
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Advances device freshness monotonically before accepting retirement evidence.
    pub fn advance_device_generation(&mut self, generation: u64) -> Result<(), CompositeError> {
        if generation <= self.active_device_generation {
            return Err(CompositeError::FreshnessRollback);
        }
        for kind in [
            ClaimKind::QueueSlot,
            ClaimKind::PinnedPage,
            ClaimKind::IovaMapping,
        ] {
            let record = &mut self.claims[kind.index()];
            if matches!(record.state, ClaimState::ReusePermitted { .. }) {
                record.state = ClaimState::Discharged;
                record.pending_reuse = None;
            }
        }
        self.active_device_generation = generation;
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Captures exact old-subject/new-observation coordinates for retirement.
    #[must_use]
    pub const fn dma_retirement_evidence(&self) -> DmaEvidence {
        DmaEvidence {
            effect: self.effect,
            resource_generation: self.dma_resource_generation,
            subject_device_generation: self.enrolled_device_generation,
            observation_device_generation: self.active_device_generation,
        }
    }

    /// Accepts reset evidence and terminalizes a still-pending DMA outcome as
    /// indeterminate without discharging any physical claim.
    pub fn accept_reset(&mut self, evidence: DmaEvidence) -> Result<(), CompositeError> {
        self.require_dma_evidence(evidence)?;
        if self.reset_accepted {
            return Err(CompositeError::WrongComponentState);
        }
        self.dma = match self.dma {
            DmaOutcome::Pending => DmaOutcome::IndeterminateAfterReset,
            DmaOutcome::Completed => DmaOutcome::Completed,
            _ => return Err(CompositeError::WrongComponentState),
        };
        self.reset_accepted = true;
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Accepts IRQ/completion drain after reset and discharges only the queue claim.
    pub fn accept_irq_drain(&mut self, evidence: DmaEvidence) -> Result<(), CompositeError> {
        self.require_dma_evidence(evidence)?;
        if !self.reset_accepted {
            return Err(CompositeError::EvidenceOutOfOrder);
        }
        if self.irq_drained {
            return Err(CompositeError::WrongComponentState);
        }
        self.irq_drained = true;
        self.discharge_claim(ClaimKind::QueueSlot);
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Accepts completed IOTLB invalidation and discharges only the IOVA claim.
    pub fn accept_iotlb_invalidation(
        &mut self,
        evidence: DmaEvidence,
    ) -> Result<(), CompositeError> {
        self.require_dma_evidence(evidence)?;
        if !self.irq_drained {
            return Err(CompositeError::EvidenceOutOfOrder);
        }
        if self.iotlb_invalidated {
            return Err(CompositeError::WrongComponentState);
        }
        self.iotlb_invalidated = true;
        self.discharge_claim(ClaimKind::IovaMapping);
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Accepts allocator lease relinquishment after invalidation and discharges
    /// only the pinned-page claim.
    pub fn accept_allocator_release(
        &mut self,
        evidence: DmaEvidence,
    ) -> Result<(), CompositeError> {
        self.require_dma_evidence(evidence)?;
        if !self.iotlb_invalidated {
            return Err(CompositeError::EvidenceOutOfOrder);
        }
        if self.allocator_released {
            return Err(CompositeError::WrongComponentState);
        }
        self.allocator_released = true;
        self.discharge_claim(ClaimKind::PinnedPage);
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Evaluates the resource-local reuse predicate without mutating the model.
    ///
    /// Parent retirement and reply terminality are intentionally absent from
    /// this predicate.
    #[must_use]
    pub fn reuse_is_admissible(&self, kind: ClaimKind, next_generation: u64) -> bool {
        kind.is_physical()
            && self.claims[kind.index()].state == ClaimState::Discharged
            && next_generation == next_generation_of(self.claims[kind.index()].enrolled_generation)
            && self.physical_evidence_complete(kind)
    }

    /// Issues a one-shot permit for exactly the next resource generation.
    pub fn issue_reuse_permit(
        &mut self,
        observation: AuthorityObservation,
        kind: ClaimKind,
        next_generation: u64,
    ) -> Result<ReusePermit, CompositeError> {
        self.require_observation(observation)?;
        if self.authority == CompositeAuthority::Revoked || self.released {
            return Err(CompositeError::GateClosed);
        }
        if !kind.is_physical() {
            return Err(CompositeError::UnsupportedReuse);
        }
        let record = self.claims[kind.index()];
        match record.state {
            ClaimState::Staged | ClaimState::Live => {
                return Err(CompositeError::ClaimStillLive);
            }
            ClaimState::ReusePermitted { .. } | ClaimState::Reused { .. } => {
                return Err(CompositeError::ClaimAlreadyReused);
            }
            ClaimState::Discharged => {}
        }
        if next_generation != next_generation_of(record.enrolled_generation) {
            return Err(CompositeError::ReuseGenerationMismatch);
        }
        if !self.physical_evidence_complete(kind) {
            return Err(CompositeError::EvidenceOutOfOrder);
        }
        let nonce = self.next_permit_nonce;
        self.next_permit_nonce = next_generation_of(self.next_permit_nonce);
        let reservation = ReuseReservation {
            actor: observation.executor,
            authority_epoch: observation.authority_epoch,
            next_generation,
            device_generation: self.active_device_generation,
            nonce,
        };
        self.claims[kind.index()].state = ClaimState::ReusePermitted { next_generation };
        self.claims[kind.index()].pending_reuse = Some(reservation);
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(ReusePermit {
            effect: self.effect,
            kind,
            actor: reservation.actor,
            authority_epoch: reservation.authority_epoch,
            resource: record.resource,
            retired_generation: record.enrolled_generation,
            next_generation,
            device_generation: self.active_device_generation,
            nonce,
        })
    }

    /// Reissues a durable pending reservation to a successor authority epoch.
    ///
    /// Executor death invalidates the old bearer, but does not release the
    /// exact successor generation. Only a strictly newer rebound actor may
    /// replace the reservation owner and receive a fresh one-shot nonce.
    pub fn reclaim_reuse_permit(
        &mut self,
        observation: AuthorityObservation,
        kind: ClaimKind,
    ) -> Result<ReusePermit, CompositeError> {
        self.require_observation(observation)?;
        if self.authority == CompositeAuthority::Revoked || self.released {
            return Err(CompositeError::GateClosed);
        }
        if !kind.is_physical() {
            return Err(CompositeError::UnsupportedReuse);
        }
        let record = self.claims[kind.index()];
        let previous = match (record.state, record.pending_reuse) {
            (ClaimState::ReusePermitted { next_generation }, Some(pending))
                if pending.next_generation == next_generation =>
            {
                pending
            }
            _ => return Err(CompositeError::StaleReusePermit),
        };
        if previous.authority_epoch >= observation.authority_epoch
            || previous.actor == observation.executor
        {
            return Err(CompositeError::GateClaimed);
        }
        let nonce = self.next_permit_nonce;
        self.next_permit_nonce = next_generation_of(self.next_permit_nonce);
        let reservation = ReuseReservation {
            actor: observation.executor,
            authority_epoch: observation.authority_epoch,
            next_generation: previous.next_generation,
            device_generation: self.active_device_generation,
            nonce,
        };
        self.claims[kind.index()].pending_reuse = Some(reservation);
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(ReusePermit {
            effect: self.effect,
            kind,
            actor: reservation.actor,
            authority_epoch: reservation.authority_epoch,
            resource: record.resource,
            retired_generation: record.enrolled_generation,
            next_generation: reservation.next_generation,
            device_generation: reservation.device_generation,
            nonce: reservation.nonce,
        })
    }

    /// Consumes an exact permit and records successor-generation activation.
    pub fn activate_reuse(&mut self, permit: ReusePermit) -> Result<(), CompositeError> {
        if self.released {
            return Err(CompositeError::GateClosed);
        }
        if !permit.kind.is_physical() {
            return Err(CompositeError::StaleReusePermit);
        }
        let record = self.claims[permit.kind.index()];
        let expected = ReuseReservation {
            actor: permit.actor,
            authority_epoch: permit.authority_epoch,
            next_generation: permit.next_generation,
            device_generation: permit.device_generation,
            nonce: permit.nonce,
        };
        if permit.effect != self.effect
            || self.live_executor != Some(permit.actor)
            || self.authority_epoch != permit.authority_epoch
            || permit.resource != record.resource
            || permit.retired_generation != record.enrolled_generation
            || permit.device_generation != self.active_device_generation
            || record.pending_reuse != Some(expected)
            || record.state
                != (ClaimState::ReusePermitted {
                    next_generation: permit.next_generation,
                })
        {
            return Err(CompositeError::StaleReusePermit);
        }
        self.claims[permit.kind.index()].state = ClaimState::Reused {
            generation: permit.next_generation,
        };
        self.claims[permit.kind.index()].pending_reuse = None;
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Releases the parent record only after complete component retirement.
    pub fn release_effect(&mut self) -> Result<(), CompositeError> {
        if self.released {
            return Err(CompositeError::GateClosed);
        }
        if !self.retired() {
            return Err(CompositeError::EffectNotRetired);
        }
        self.released = true;
        self.bump_revision();
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Checks authority, claim conservation, evidence order, and terminality.
    #[must_use]
    pub fn check_invariants(&self) -> bool {
        if self.authority_epoch == 0
            || self.next_reply_nonce == 0
            || self.next_permit_nonce == 0
            || self.dma_resource_generation == 0
            || self.enrolled_device_generation == 0
            || self.active_device_generation < self.enrolled_device_generation
            || self.root_live != self.live_executor.is_some()
            || self.last_executor.executor() != self.origin_executor
            || self
                .live_executor
                .is_some_and(|executor| executor.executor() != self.origin_executor)
        {
            return false;
        }
        if self.authority == CompositeAuthority::Active && !self.root_live {
            return false;
        }
        if self.released && !self.retired() {
            return false;
        }
        if self.claims.iter().enumerate().any(|(index, claim)| {
            claim.kind != ClaimKind::ALL[index]
                || claim.enrolled_generation != self.dma_resource_generation
                || matches!(claim.state, ClaimState::ReusePermitted { .. })
                    != claim.pending_reuse.is_some()
                || claim.pending_reuse.is_some_and(|pending| {
                    pending.actor.executor() != self.origin_executor
                        || pending.actor.executor().get() == 0
                        || pending.actor.generation().get() == 0
                        || pending.authority_epoch == 0
                        || pending.authority_epoch > self.authority_epoch
                        || pending.next_generation != next_generation_of(claim.enrolled_generation)
                        || pending.device_generation != self.active_device_generation
                        || pending.nonce == 0
                        || (pending.authority_epoch == self.authority_epoch
                            && self.live_executor != Some(pending.actor))
                })
        }) {
            return false;
        }
        if !self.reply_claim_invariant() || !self.dma_claim_invariant() {
            return false;
        }
        if self.irq_drained && !self.reset_accepted
            || self.iotlb_invalidated && !self.irq_drained
            || self.allocator_released && !self.iotlb_invalidated
        {
            return false;
        }
        if self.reset_accepted
            && (self.active_device_generation <= self.enrolled_device_generation
                || !matches!(
                    self.dma,
                    DmaOutcome::Completed | DmaOutcome::IndeterminateAfterReset
                ))
        {
            return false;
        }
        if self.dma != DmaOutcome::Aborted
            && (self.claims[ClaimKind::QueueSlot.index()].state.discharged() != self.irq_drained
                || self.claims[ClaimKind::IovaMapping.index()]
                    .state
                    .discharged()
                    != self.iotlb_invalidated
                || self.claims[ClaimKind::PinnedPage.index()]
                    .state
                    .discharged()
                    != self.allocator_released)
        {
            return false;
        }
        true
    }

    fn require_observation(&self, observation: AuthorityObservation) -> Result<(), CompositeError> {
        if !self.root_live {
            return Err(CompositeError::WrongAuthorityState);
        }
        if observation.effect != self.effect
            || self.live_executor != Some(observation.executor)
            || observation.authority_epoch != self.authority_epoch
        {
            return Err(CompositeError::StaleAuthority);
        }
        Ok(())
    }

    fn require_active(&self, observation: AuthorityObservation) -> Result<(), CompositeError> {
        self.require_observation(observation)?;
        if self.authority == CompositeAuthority::Revoked || self.released {
            return Err(CompositeError::GateClosed);
        }
        if self.authority != CompositeAuthority::Active {
            return Err(CompositeError::WrongAuthorityState);
        }
        Ok(())
    }

    fn require_reply_claim(&self, claim: ReplyClaim) -> Result<(), CompositeError> {
        if claim.effect != self.effect || self.active_reply_nonce != Some(claim.nonce) {
            return Err(CompositeError::StaleReplyClaim);
        }
        match self.reply {
            ReplyState::Claimed {
                claimant,
                generation,
            }
            | ReplyState::ApplyIntentDurable {
                claimant,
                generation,
            }
            | ReplyState::AppliedUnacknowledged {
                claimant,
                generation,
            } if claimant == claim.claimant && generation == claim.generation => Ok(()),
            _ => Err(CompositeError::StaleReplyClaim),
        }
    }

    fn require_dma_evidence(&self, evidence: DmaEvidence) -> Result<(), CompositeError> {
        if evidence.effect != self.effect
            || evidence.resource_generation != self.dma_resource_generation
            || evidence.subject_device_generation != self.enrolled_device_generation
            || evidence.observation_device_generation != self.active_device_generation
            || evidence.observation_device_generation <= evidence.subject_device_generation
        {
            return Err(CompositeError::StaleDeviceEvidence);
        }
        Ok(())
    }

    fn reclaim_reply_claim(&mut self) {
        self.reply = match (self.reply, self.reply_claim_stage) {
            (ReplyState::Claimed { generation, .. }, Some(ReplyClaimStage::ReconcileIntent)) => {
                ReplyState::ReconciliationRequired {
                    generation: next_generation_of(generation),
                    applied: false,
                }
            }
            (ReplyState::Claimed { generation, .. }, Some(ReplyClaimStage::ReconcileApplied)) => {
                ReplyState::ReconciliationRequired {
                    generation: next_generation_of(generation),
                    applied: true,
                }
            }
            (ReplyState::Claimed { generation, .. }, _) => ReplyState::Open {
                generation: next_generation_of(generation),
            },
            (ReplyState::ApplyIntentDurable { generation, .. }, _) => {
                ReplyState::ReconciliationRequired {
                    generation: next_generation_of(generation),
                    applied: false,
                }
            }
            (ReplyState::AppliedUnacknowledged { generation, .. }, _) => {
                ReplyState::ReconciliationRequired {
                    generation: next_generation_of(generation),
                    applied: true,
                }
            }
            (
                ReplyState::ReconciliationRequired {
                    generation,
                    applied,
                },
                _,
            ) => ReplyState::ReconciliationRequired {
                generation: next_generation_of(generation),
                applied,
            },
            (state, _) => state,
        };
        self.reply_claim_stage = None;
        self.active_reply_nonce = None;
    }

    fn abort_staged_components(&mut self) {
        if self.reply == ReplyState::Staged {
            self.reply = ReplyState::Aborted;
            self.discharge_claim(ClaimKind::ReplyOutput);
        }
        if self.dma == DmaOutcome::Staged {
            self.dma = DmaOutcome::Aborted;
            for kind in [
                ClaimKind::QueueSlot,
                ClaimKind::PinnedPage,
                ClaimKind::IovaMapping,
            ] {
                self.discharge_claim(kind);
            }
        }
    }

    fn discharge_claim(&mut self, kind: ClaimKind) {
        self.claims[kind.index()].state = ClaimState::Discharged;
        self.claims[kind.index()].pending_reuse = None;
    }

    fn physical_evidence_complete(&self, kind: ClaimKind) -> bool {
        match kind {
            ClaimKind::ReplyOutput => false,
            ClaimKind::QueueSlot => self.reset_accepted && self.irq_drained,
            ClaimKind::IovaMapping => {
                self.reset_accepted && self.irq_drained && self.iotlb_invalidated
            }
            ClaimKind::PinnedPage => {
                self.reset_accepted
                    && self.irq_drained
                    && self.iotlb_invalidated
                    && self.allocator_released
            }
        }
    }

    fn claim_projection(&self, kind: ClaimKind) -> ClaimProjection {
        let record = self.claims[kind.index()];
        ClaimProjection {
            effect: self.effect,
            component: kind.component(),
            kind,
            resource: record.resource,
            enrolled_generation: record.enrolled_generation,
            state: record.state,
            pending_reuse: record
                .pending_reuse
                .map(|pending| ReuseReservationProjection {
                    actor: pending.actor,
                    authority_epoch: pending.authority_epoch,
                    next_generation: pending.next_generation,
                    device_generation: pending.device_generation,
                    nonce: pending.nonce,
                }),
        }
    }

    fn retired(&self) -> bool {
        self.reply.terminal()
            && self.dma.terminal()
            && self.claims.iter().all(|claim| claim.state.discharged())
    }

    fn escape_state(&self) -> EscapeState {
        if self.released {
            EscapeState::Released
        } else if self.retired() {
            EscapeState::Retired
        } else if !self.reply.committed() && !self.dma.committed() {
            EscapeState::Unescaped
        } else if self.reset_accepted
            || self.reply.terminal()
            || self.dma.terminal()
            || self.claims.iter().any(|claim| claim.state.discharged())
        {
            EscapeState::PartiallyDischarged
        } else {
            EscapeState::Escaped
        }
    }

    fn reply_claim_invariant(&self) -> bool {
        let output = self.claims[ClaimKind::ReplyOutput.index()].state;
        let has_claim = matches!(
            self.reply,
            ReplyState::Claimed { .. }
                | ReplyState::ApplyIntentDurable { .. }
                | ReplyState::AppliedUnacknowledged { .. }
        );
        if has_claim != self.active_reply_nonce.is_some()
            || has_claim != self.reply_claim_stage.is_some()
        {
            return false;
        }
        match self.reply {
            ReplyState::Staged => output == ClaimState::Staged,
            ReplyState::Open { .. }
            | ReplyState::Claimed { .. }
            | ReplyState::ApplyIntentDurable { .. }
            | ReplyState::AppliedUnacknowledged { .. }
            | ReplyState::ReconciliationRequired { .. } => output == ClaimState::Live,
            ReplyState::Settled => {
                matches!(output, ClaimState::Live | ClaimState::Discharged)
            }
            ReplyState::Tombstoned | ReplyState::Aborted => output == ClaimState::Discharged,
        }
    }

    fn dma_claim_invariant(&self) -> bool {
        let physical = [
            self.claims[ClaimKind::QueueSlot.index()].state,
            self.claims[ClaimKind::PinnedPage.index()].state,
            self.claims[ClaimKind::IovaMapping.index()].state,
        ];
        match self.dma {
            DmaOutcome::Staged => physical.iter().all(|state| *state == ClaimState::Staged),
            DmaOutcome::Aborted => physical
                .iter()
                .all(|state| *state == ClaimState::Discharged),
            DmaOutcome::Pending | DmaOutcome::Completed | DmaOutcome::IndeterminateAfterReset => {
                physical
                    .iter()
                    .all(|state| !matches!(state, ClaimState::Staged))
            }
        }
    }

    fn bump_revision(&mut self) {
        self.revision = next_generation_of(self.revision);
    }
}

const fn next_generation_of(generation: u64) -> u64 {
    match generation.checked_add(1) {
        Some(next) => next,
        None => panic!("bounded composite oracle generation exhausted"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executor(id: u64, generation: u64) -> ExecutorCoordinate {
        ExecutorCoordinate::new(
            ExecutorId::new(id).unwrap(),
            crate::ExecutorGeneration::new(generation).unwrap(),
        )
    }

    #[test]
    fn release_closes_a_durable_reuse_permit() {
        let effect = EffectId::new(OperationId::new(1).unwrap(), 1).unwrap();
        let mut oracle = CompositeEffectOracle::new(
            effect,
            executor(1, 1),
            1,
            1,
            CompositeResources {
                reply_output: ResourceId::new(11),
                queue_slot: ResourceId::new(12),
                pinned_page: ResourceId::new(13),
                iova_mapping: ResourceId::new(14),
            },
        );
        let authority = oracle.observe_authority().unwrap();
        oracle.commit_dma(authority).unwrap();
        oracle.commit_reply(authority).unwrap();
        oracle.fence_executor(executor(1, 1)).unwrap();
        oracle.tombstone_reply().unwrap();
        oracle.advance_device_generation(2).unwrap();
        let evidence = oracle.dma_retirement_evidence();
        oracle.accept_reset(evidence).unwrap();
        oracle.accept_irq_drain(evidence).unwrap();
        oracle.accept_iotlb_invalidation(evidence).unwrap();
        oracle.accept_allocator_release(evidence).unwrap();
        oracle.rebind(executor(1, 2)).unwrap();
        let authority = oracle.observe_authority().unwrap();
        let permit = oracle
            .issue_reuse_permit(authority, ClaimKind::QueueSlot, 2)
            .unwrap();
        oracle.release_effect().unwrap();
        assert_eq!(
            oracle.activate_reuse(permit),
            Err(CompositeError::GateClosed)
        );
        assert!(oracle.check_invariants());
    }
}
