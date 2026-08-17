// SPDX-License-Identifier: MPL-2.0

//! Feature-only bridge between portable CSER device claims and the real OSTD
//! VirtIO owner typestates.
//!
//! This module deliberately creates no second resource ledger. Queue, PCI,
//! pinned-page, reset, and IOTLB authority stays inside
//! `nexus-ostd-virtio`; the portable core owns only durable obligation and
//! claim state. The bridge converts opaque hardware owners into verifier-bound
//! core commands while retaining every linear hardware owner on rejection.
//!
//! The production functions in this module call the real facade operations:
//! `PreparedPublishIntent::apply` publishes `avail.idx`, reset evidence can
//! only be built from `ProductionResetAck`, and IOTLB evidence can only be
//! built from `ProductionClosureReceipt`. The unit tests at the bottom are
//! adapter contract models. They do not execute PCI, VirtIO, an IRQ controller,
//! an IOMMU, QEMU, or physical hardware.

use cser_core::{
    ChargeAccountId, ClaimId, ClaimKindId, ClaimScope, Command, CommandRequest, CommitIntent,
    ComponentId, CoreError, DEVICE_CLAIM_IOVA, DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT,
    DEVICE_COMMIT_RECEIPT_SCHEMA, DEVICE_DOMAIN, DEVICE_EVIDENCE_IOTLB,
    DEVICE_EVIDENCE_IRQ_DRAINED, DEVICE_EVIDENCE_RESET, DEVICE_OBLIGATION_DMA,
    DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, DeviceGeneration, DeviceScopeId, Digest,
    EffectFactChallenge, EffectFactKind, EffectReceiptVerifier, Engine, EvidenceChallenge,
    EvidenceKindId, ExternalOutcome, PrincipalIncarnation, ReceiptSchemaId, ReceiptVerifier,
    ResourceGeneration, ResourceId, VerificationError, VerifiedEffectObservation,
    VerifiedObservation, VerifierIdentity,
};
#[cfg(feature = "cser-core-dma-recovery")]
use cser_core::{ProviderCoordinate, ProviderGeneration, ProviderId, WorldId};
#[cfg(any(feature = "cser-production", feature = "cser-core-dma-recovery"))]
use cser_core::{VerifierBinding, VerifierGeneration};
use nexus_ostd_virtio::{
    BootQuarantineGuard, DeviceBdf, DeviceSessionIdentity, InterruptCause,
    InterruptCompletionProgress, InterruptReceipt, NotificationDisposition,
    PreparationPublishFailure, ProductionClosureProgress, ProductionClosureReceipt,
    ProductionDevice, ProductionIotlbBeginFailure, ProductionResetAck, PublishedRequest,
    ReceiptedPreparedRequest,
};
use sha2::{Digest as _, Sha256};

#[cfg(feature = "cser-production")]
use super::core_production_registry::{
    DEVICE_COMMIT_IMPLEMENTATION_DIGEST, DEVICE_RECEIPT_IMPLEMENTATION_DIGEST,
    STANDARD_DMA_PROVIDER,
};

#[cfg(not(feature = "cser-production"))]
const DEVICE_RECEIPT_IMPLEMENTATION_DIGEST: Digest = Digest::new([0x61; 32]);
#[cfg(not(feature = "cser-production"))]
const DEVICE_COMMIT_IMPLEMENTATION_DIGEST: Digest = Digest::new([0x62; 32]);

/// Exact provider coordinate used by the isolated profile-5 DMA recovery
/// scheme. It deliberately matches the production DMA provider coordinate,
/// while remaining available when the mutually-exclusive production module
/// is not compiled.
#[cfg(feature = "cser-core-dma-recovery")]
pub(crate) const DMA_RECOVERY_PROVIDER: ProviderCoordinate = ProviderCoordinate::new(
    match WorldId::new(1) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    },
    match ProviderId::new(2) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    },
    match ProviderGeneration::new(1) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    },
);

#[cfg(feature = "cser-production")]
const fn dma_provider_coordinate() -> cser_core::ProviderCoordinate {
    STANDARD_DMA_PROVIDER
}

#[cfg(feature = "cser-core-dma-recovery")]
const fn dma_provider_coordinate() -> ProviderCoordinate {
    DMA_RECOVERY_PROVIDER
}

/// One experiment-owned device resource coordinate.
///
/// This is deliberately raw and independent of `cser_core::ResourceId`: the
/// baseline can persist and compare exactly the same coordinate without
/// importing a CSER claim or engine authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExperimentDmaResource {
    resource: u64,
    generation: u64,
}

impl ExperimentDmaResource {
    pub(crate) const fn new(resource: u64, generation: u64) -> Option<Self> {
        if resource == 0 || generation == 0 {
            None
        } else {
            Some(Self {
                resource,
                generation,
            })
        }
    }

    pub(crate) const fn resource(self) -> u64 {
        self.resource
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

/// Completed physical quarantine bound to one experiment resource coordinate.
///
/// There is intentionally no public constructor.  The only constructor below
/// consumes observations from a live `BootQuarantineGuard`, whose creation
/// performed the real PCI fence, status-zero reset, two empty ISR reads, and
/// completed remapped-IOTLB invalidation.  This is descriptive evidence only:
/// it grants no queue, DMA, device activation, or CSER retirement authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExperimentDmaQuiescence {
    bdf: DeviceBdf,
    device_scope: u64,
    resource: ExperimentDmaResource,
    successor_generation: u64,
    isr_reads: usize,
    completed_iotlb_pages: usize,
}

impl ExperimentDmaQuiescence {
    pub(crate) const fn device_bdf(self) -> DeviceBdf {
        self.bdf
    }

    pub(crate) const fn device_scope(self) -> u64 {
        self.device_scope
    }

    pub(crate) const fn resource(self) -> ExperimentDmaResource {
        self.resource
    }

    pub(crate) const fn successor_generation(self) -> u64 {
        self.successor_generation
    }

    pub(crate) const fn isr_reads(self) -> usize {
        self.isr_reads
    }

    pub(crate) const fn completed_iotlb_pages(self) -> usize {
        self.completed_iotlb_pages
    }
}

/// Why a boot-quarantine observation cannot become experiment evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExperimentDmaQuiescenceError {
    NonOlderResourceGeneration {
        resource_generation: u64,
        successor_generation: u64,
    },
    ResetNotObserved,
    IrqDrainIncomplete,
    IotlbIncomplete,
}

/// Binds completed real boot quarantine to one raw experiment resource.
///
/// The guard stays retained by the caller, so constructing this receipt cannot
/// release the device or manufacture ordinary production-device authority.
pub(crate) fn run_experiment_quiescence(
    guard: &BootQuarantineGuard,
    resource: ExperimentDmaResource,
) -> Result<ExperimentDmaQuiescence, ExperimentDmaQuiescenceError> {
    let observation = guard.observation();
    validate_experiment_quiescence(
        resource.generation,
        guard.observed_generation(),
        observation.reset_status_zero(),
        observation.consecutive_empty_isr_reads(),
        observation.iotlb_used_remapped_iova(),
        observation.iotlb_completed_trigger_pages(),
    )?;
    Ok(ExperimentDmaQuiescence {
        bdf: guard.device_bdf(),
        device_scope: guard.device_scope().get(),
        resource,
        successor_generation: guard.observed_generation(),
        isr_reads: observation.isr_reads(),
        completed_iotlb_pages: observation.iotlb_completed_trigger_pages(),
    })
}

fn validate_experiment_quiescence(
    resource_generation: u64,
    successor_generation: u64,
    reset_status_zero: bool,
    consecutive_empty_isr_reads: usize,
    remapped_iotlb: bool,
    completed_iotlb_pages: usize,
) -> Result<(), ExperimentDmaQuiescenceError> {
    if resource_generation >= successor_generation {
        return Err(ExperimentDmaQuiescenceError::NonOlderResourceGeneration {
            resource_generation,
            successor_generation,
        });
    }
    if !reset_status_zero {
        return Err(ExperimentDmaQuiescenceError::ResetNotObserved);
    }
    if consecutive_empty_isr_reads < 2 {
        return Err(ExperimentDmaQuiescenceError::IrqDrainIncomplete);
    }
    if !remapped_iotlb || completed_iotlb_pages == 0 {
        return Err(ExperimentDmaQuiescenceError::IotlbIncomplete);
    }
    Ok(())
}

/// One durable claim/resource coordinate in a hardware cohort.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreDmaClaim {
    claim: ClaimId,
    resource: ResourceId,
    generation: ResourceGeneration,
    units: u64,
}

impl CoreDmaClaim {
    pub(crate) const fn new(
        claim: ClaimId,
        resource: ResourceId,
        generation: ResourceGeneration,
        units: u64,
    ) -> Self {
        Self {
            claim,
            resource,
            generation,
            units,
        }
    }

    pub(crate) const fn claim(self) -> ClaimId {
        self.claim
    }

    pub(crate) const fn resource(self) -> ResourceId {
        self.resource
    }

    pub(crate) const fn generation(self) -> ResourceGeneration {
        self.generation
    }

    pub(crate) const fn units(self) -> u64 {
        self.units
    }
}

/// Exact queue, page, and IOVA claims retained by one real request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreDmaClaims {
    queue: CoreDmaClaim,
    pinned_pages: CoreDmaClaim,
    iova: CoreDmaClaim,
}

impl CoreDmaClaims {
    pub(crate) const fn new(
        queue: CoreDmaClaim,
        pinned_pages: CoreDmaClaim,
        iova: CoreDmaClaim,
    ) -> Self {
        Self {
            queue,
            pinned_pages,
            iova,
        }
    }

    pub(crate) const fn claim(self, role: ClaimRole) -> CoreDmaClaim {
        match role {
            ClaimRole::Queue => self.queue,
            ClaimRole::PinnedPages => self.pinned_pages,
            ClaimRole::Iova => self.iova,
        }
    }
}

/// Rejection while binding a hardware request to core claim coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreDmaBindingError {
    ZeroBinding,
    ZeroUnits,
    DuplicateClaim,
    DuplicateResource,
    InvalidHardwareGeneration,
}

/// Complete cross-generation binding for one resource reuse reservation.
///
/// Keeping these coordinates together prevents an adapter from accidentally
/// combining a successor claim with a different actor, generation, or
/// provider contract while translating the request into the portable core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreReuseReservation {
    role: ClaimRole,
    effect: cser_core::EffectId,
    actor: PrincipalIncarnation,
    binding_generation: u64,
    next_claim: ClaimId,
    units: u64,
    reuse_contract: Digest,
}

impl CoreReuseReservation {
    pub(crate) const fn new(
        role: ClaimRole,
        effect: cser_core::EffectId,
        actor: PrincipalIncarnation,
        binding_generation: u64,
        next_claim: ClaimId,
        units: u64,
        reuse_contract: Digest,
    ) -> Self {
        Self {
            role,
            effect,
            actor,
            binding_generation,
            next_claim,
            units,
            reuse_contract,
        }
    }
}

/// Descriptive cross-layer binding for one device-visible DMA obligation.
///
/// This value grants no queue, DMA, reset, or IOTLB authority. Those remain in
/// the non-copyable facade owners accepted by the functions below.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreDmaCohort {
    effect: cser_core::EffectId,
    component: Option<ComponentId>,
    origin: PrincipalIncarnation,
    binding_generation: u64,
    account: ChargeAccountId,
    scope: DeviceScopeId,
    hardware: DeviceSessionIdentity,
    claims: CoreDmaClaims,
}

impl CoreDmaCohort {
    pub(crate) fn bind(
        effect: cser_core::EffectId,
        origin: PrincipalIncarnation,
        binding_generation: u64,
        account: ChargeAccountId,
        hardware: DeviceSessionIdentity,
        claims: CoreDmaClaims,
    ) -> Result<Self, CoreDmaBindingError> {
        Self::bind_optional(
            effect,
            None,
            origin,
            binding_generation,
            account,
            hardware,
            claims,
        )
    }

    pub(crate) fn bind_component(
        effect: cser_core::EffectId,
        component: ComponentId,
        origin: PrincipalIncarnation,
        binding_generation: u64,
        account: ChargeAccountId,
        hardware: DeviceSessionIdentity,
        claims: CoreDmaClaims,
    ) -> Result<Self, CoreDmaBindingError> {
        Self::bind_optional(
            effect,
            Some(component),
            origin,
            binding_generation,
            account,
            hardware,
            claims,
        )
    }

    fn bind_optional(
        effect: cser_core::EffectId,
        component: Option<ComponentId>,
        origin: PrincipalIncarnation,
        binding_generation: u64,
        account: ChargeAccountId,
        hardware: DeviceSessionIdentity,
        claims: CoreDmaClaims,
    ) -> Result<Self, CoreDmaBindingError> {
        if binding_generation == 0 {
            return Err(CoreDmaBindingError::ZeroBinding);
        }
        if hardware.device_generation() == 0 {
            return Err(CoreDmaBindingError::InvalidHardwareGeneration);
        }
        if claims.queue.units == 0 || claims.pinned_pages.units == 0 || claims.iova.units == 0 {
            return Err(CoreDmaBindingError::ZeroUnits);
        }
        if claims.queue.claim == claims.pinned_pages.claim
            || claims.queue.claim == claims.iova.claim
            || claims.pinned_pages.claim == claims.iova.claim
        {
            return Err(CoreDmaBindingError::DuplicateClaim);
        }
        if claims.queue.resource == claims.pinned_pages.resource
            || claims.queue.resource == claims.iova.resource
            || claims.pinned_pages.resource == claims.iova.resource
        {
            return Err(CoreDmaBindingError::DuplicateResource);
        }
        let bdf = hardware.device_bdf();
        let packed = (u64::from(bdf.bus()) << 16)
            | (u64::from(bdf.device()) << 8)
            | u64::from(bdf.function());
        let scope =
            DeviceScopeId::new(packed + 1).expect("packed PCI coordinates plus one are non-zero");
        Ok(Self {
            effect,
            component,
            origin,
            binding_generation,
            account,
            scope,
            hardware,
            claims,
        })
    }

    pub(crate) const fn effect(self) -> cser_core::EffectId {
        self.effect
    }

    pub(crate) const fn component(self) -> Option<ComponentId> {
        self.component
    }

    pub(crate) const fn scope(self) -> DeviceScopeId {
        self.scope
    }

    pub(crate) const fn hardware(self) -> DeviceSessionIdentity {
        self.hardware
    }

    pub(crate) const fn create_estate(self) -> CommandRequest {
        CommandRequest::CreateEstate {
            effect: self.effect,
            origin: self.origin,
            binding_generation: self.binding_generation,
            domain: DEVICE_DOMAIN,
            obligation: DEVICE_OBLIGATION_DMA,
            charge_account: self.account,
        }
    }

    pub(crate) const fn enroll_claims(self) -> [CommandRequest; 3] {
        [
            self.add_claim(ClaimRole::Queue),
            self.add_claim(ClaimRole::PinnedPages),
            self.add_claim(ClaimRole::Iova),
        ]
    }

    pub(crate) const fn prepare(self) -> CommandRequest {
        match self.component {
            Some(_) => CommandRequest::PrepareCompositeEffect {
                effect: self.effect,
                actor: self.origin,
                binding_generation: self.binding_generation,
            },
            None => CommandRequest::PrepareEffect {
                effect: self.effect,
                actor: self.origin,
                binding_generation: self.binding_generation,
            },
        }
    }

    pub(crate) const fn record_commit_intent(self, operation: Digest) -> CommandRequest {
        match self.component {
            Some(component) => CommandRequest::RecordComponentCommitIntent {
                effect: self.effect,
                component,
                actor: self.origin,
                binding_generation: self.binding_generation,
                operation,
            },
            None => CommandRequest::RecordCommitIntent {
                effect: self.effect,
                actor: self.origin,
                binding_generation: self.binding_generation,
                operation,
            },
        }
    }

    pub(crate) const fn reserve_reuse(self, reservation: CoreReuseReservation) -> CommandRequest {
        let claim = self.claim(reservation.role);
        match self.component {
            Some(component) => CommandRequest::ReserveComponentReuse {
                effect: reservation.effect,
                component,
                actor: reservation.actor,
                binding_generation: reservation.binding_generation,
                claim: reservation.next_claim,
                kind: reservation.role.claim_kind(),
                scope: ClaimScope::Device(self.scope),
                resource: claim.resource,
                expected_generation: claim.generation,
                units: reservation.units,
                reuse_contract: reservation.reuse_contract,
            },
            None => CommandRequest::ReserveReuse {
                effect: reservation.effect,
                actor: reservation.actor,
                binding_generation: reservation.binding_generation,
                claim: reservation.next_claim,
                domain: DEVICE_DOMAIN,
                kind: reservation.role.claim_kind(),
                scope: ClaimScope::Device(self.scope),
                resource: claim.resource,
                expected_generation: claim.generation,
                units: reservation.units,
                reuse_contract: reservation.reuse_contract,
            },
        }
    }

    const fn add_claim(self, role: ClaimRole) -> CommandRequest {
        let claim = self.claim(role);
        match self.component {
            Some(component) => CommandRequest::AddComponentClaim {
                effect: self.effect,
                component,
                actor: self.origin,
                binding_generation: self.binding_generation,
                claim: claim.claim,
                kind: role.claim_kind(),
                scope: ClaimScope::Device(self.scope),
                resource: claim.resource,
                resource_generation: claim.generation,
                units: claim.units,
            },
            None => CommandRequest::AddClaim {
                effect: self.effect,
                actor: self.origin,
                binding_generation: self.binding_generation,
                claim: claim.claim,
                domain: DEVICE_DOMAIN,
                kind: role.claim_kind(),
                scope: ClaimScope::Device(self.scope),
                resource: claim.resource,
                resource_generation: claim.generation,
                units: claim.units,
            },
        }
    }

    pub(crate) const fn claim(self, role: ClaimRole) -> CoreDmaClaim {
        match role {
            ClaimRole::Queue => self.claims.queue,
            ClaimRole::PinnedPages => self.claims.pinned_pages,
            ClaimRole::Iova => self.claims.iova,
        }
    }
}

/// Fixed semantic role of one member of the three-claim DMA cohort.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClaimRole {
    Queue,
    PinnedPages,
    Iova,
}

impl ClaimRole {
    const fn claim_kind(self) -> ClaimKindId {
        match self {
            Self::Queue => DEVICE_CLAIM_QUEUE_SLOT,
            Self::PinnedPages => DEVICE_CLAIM_PINNED_PAGE,
            Self::Iova => DEVICE_CLAIM_IOVA,
        }
    }
}

/// Exact durable core challenge and physical DMA cohort fixed before queue
/// publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueueCommitBinding {
    cohort: CoreDmaCohort,
    authority_generation: u64,
    intent_nonce: u64,
    operation: Digest,
}

impl QueueCommitBinding {
    fn from_challenge(
        challenge: &EffectFactChallenge,
        cohort: CoreDmaCohort,
    ) -> Result<Self, CoreError> {
        if challenge.kind() != EffectFactKind::CommitOutcome
            || challenge.effect() != cohort.effect
            || challenge.component() != cohort.component
            || challenge.domain() != DEVICE_DOMAIN
            || challenge.obligation() != DEVICE_OBLIGATION_DMA
            || challenge.actor() != cohort.origin
            || challenge.generation() == 0
            || challenge.nonce() == 0
            || challenge.operation().is_zero()
            || challenge.predecessor().is_some()
            || challenge.expected_verifier() != DEVICE_VERIFIER
            || challenge.expected_receipt_schema() != DEVICE_COMMIT_RECEIPT_SCHEMA
            || challenge.current_observation().binding() != cohort.binding_generation
            || challenge.current_observation().device().get() != cohort.hardware.device_generation()
            || !dma_effect_scope_matches(challenge, DEVICE_COMMIT_RECEIPT_SCHEMA)
        {
            return Err(CoreError::VerificationFailed);
        }
        Ok(Self {
            cohort,
            authority_generation: challenge.generation(),
            intent_nonce: challenge.nonce(),
            operation: challenge.operation(),
        })
    }

    fn matches_challenge(self, challenge: &EffectFactChallenge) -> bool {
        challenge.kind() == EffectFactKind::CommitOutcome
            && challenge.effect() == self.cohort.effect
            && challenge.component() == self.cohort.component
            && challenge.domain() == DEVICE_DOMAIN
            && challenge.obligation() == DEVICE_OBLIGATION_DMA
            && challenge.actor() == self.cohort.origin
            && challenge.generation() == self.authority_generation
            && challenge.nonce() == self.intent_nonce
            && challenge.operation() == self.operation
            && challenge.predecessor().is_none()
            && challenge.expected_verifier() == DEVICE_VERIFIER
            && challenge.expected_receipt_schema() == DEVICE_COMMIT_RECEIPT_SCHEMA
            && challenge.current_observation().binding() == self.cohort.binding_generation
            && challenge.current_observation().device().get()
                == self.cohort.hardware.device_generation()
            && dma_effect_scope_matches(challenge, DEVICE_COMMIT_RECEIPT_SCHEMA)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueueCommitObservation {
    binding: QueueCommitBinding,
    attempt_owner: u64,
    attempt_sequence: u64,
    preparation_digest: u64,
    notification: NotificationDisposition,
    digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetirementEvent {
    Reset(ClaimRole),
    IrqDrained,
    Iotlb(ClaimRole),
}

impl RetirementEvent {
    const fn role(self) -> ClaimRole {
        match self {
            Self::Reset(role) | Self::Iotlb(role) => role,
            Self::IrqDrained => ClaimRole::Queue,
        }
    }

    const fn kind(self) -> EvidenceKindId {
        match self {
            Self::Reset(_) => DEVICE_EVIDENCE_RESET,
            Self::IrqDrained => DEVICE_EVIDENCE_IRQ_DRAINED,
            Self::Iotlb(_) => DEVICE_EVIDENCE_IOTLB,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Reset(_) => 1,
            Self::IrqDrained => 2,
            Self::Iotlb(_) => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetirementObservation {
    event: RetirementEvent,
    component: Option<ComponentId>,
    hardware: DeviceSessionIdentity,
    attempt_owner: u64,
    attempt_sequence: u64,
    successor_generation: u64,
    completed_pages: usize,
    irq_queue_observed: bool,
    digest: Digest,
}

#[derive(Clone, Copy)]
struct CoreQueueCommitVerifier {
    binding: QueueCommitBinding,
}

impl EffectReceiptVerifier for CoreQueueCommitVerifier {
    type Receipt = QueueCommitObservation;

    fn identity(&self) -> VerifierIdentity {
        dma_verifier_identity(
            DEVICE_COMMIT_RECEIPT_SCHEMA,
            DEVICE_COMMIT_IMPLEMENTATION_DIGEST,
        )
    }

    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        if !self.binding.matches_challenge(challenge)
            || receipt.binding != self.binding
            || receipt.attempt_owner == 0
            || receipt.attempt_sequence == 0
            || receipt.preparation_digest == 0
            || receipt.notification == NotificationDisposition::AlreadyResolved
            || receipt.digest.is_zero()
            || receipt.digest != queue_commit_digest(receipt)
            || !dma_effect_scope_matches(challenge, DEVICE_COMMIT_RECEIPT_SCHEMA)
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedEffectObservation::commit(
            challenge.current_observation(),
            ExternalOutcome::Success,
            receipt.digest,
        ))
    }
}

#[derive(Clone, Copy)]
struct CoreRetirementVerifier {
    cohort: CoreDmaCohort,
}

impl ReceiptVerifier for CoreRetirementVerifier {
    type Receipt = RetirementObservation;

    fn identity(&self) -> VerifierIdentity {
        dma_verifier_identity(DEVICE_RECEIPT_SCHEMA, DEVICE_RECEIPT_IMPLEMENTATION_DIGEST)
    }

    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        let role = receipt.event.role();
        let claim = self.cohort.claim(role);
        let old_generation = receipt.hardware.device_generation();
        let current_generation = challenge.current_observation().device().get();
        let current_is_valid = match receipt.event {
            RetirementEvent::Reset(_) => {
                current_generation == old_generation
                    || current_generation == receipt.successor_generation
            }
            RetirementEvent::IrqDrained | RetirementEvent::Iotlb(_) => {
                current_generation == receipt.successor_generation
            }
        };
        let page_count_is_valid = match receipt.event {
            RetirementEvent::Reset(_) | RetirementEvent::IrqDrained => receipt.completed_pages == 3,
            RetirementEvent::Iotlb(_) => receipt.completed_pages == 3,
        };
        let irq_observation_is_valid = match receipt.event {
            RetirementEvent::IrqDrained => receipt.irq_queue_observed,
            RetirementEvent::Reset(_) | RetirementEvent::Iotlb(_) => !receipt.irq_queue_observed,
        };
        if challenge.effect() != self.cohort.effect
            || challenge.component() != self.cohort.component
            || challenge.claim() != claim.claim
            || challenge.domain() != DEVICE_DOMAIN
            || challenge.kind() != receipt.event.kind()
            || challenge.scope() != ClaimScope::Device(self.cohort.scope)
            || challenge.resource() != claim.resource
            || challenge.resource_generation() != claim.generation
            || challenge.subject().device().get() != old_generation
            || receipt.component != self.cohort.component
            || receipt.hardware != self.cohort.hardware
            || old_generation.checked_add(1) != Some(receipt.successor_generation)
            || !current_is_valid
            || !page_count_is_valid
            || !irq_observation_is_valid
            || receipt.attempt_owner == 0
            || receipt.attempt_sequence == 0
            || receipt.digest.is_zero()
            || receipt.digest != retirement_digest(receipt)
            || !dma_evidence_scope_matches(challenge, DEVICE_RECEIPT_SCHEMA)
        {
            return Err(VerificationError::Rejected);
        }
        let successor = DeviceGeneration::new(receipt.successor_generation)
            .map_err(|_| VerificationError::Rejected)?;
        Ok(VerifiedObservation::new(
            challenge.subject(),
            challenge.current_observation().with_device(successor),
            receipt.digest,
        ))
    }
}

#[cfg(any(feature = "cser-production", feature = "cser-core-dma-recovery"))]
fn dma_verifier_identity(
    schema: ReceiptSchemaId,
    implementation_digest: Digest,
) -> VerifierIdentity {
    let binding = VerifierBinding::new(
        DEVICE_VERIFIER,
        VerifierGeneration::new(1).expect("standard verifier generation is non-zero"),
        schema,
        implementation_digest,
    )
    .expect("standard device verifier binding is valid");
    VerifierIdentity::new_exact(binding)
}

#[cfg(not(any(feature = "cser-production", feature = "cser-core-dma-recovery")))]
fn dma_verifier_identity(
    schema: ReceiptSchemaId,
    _implementation_digest: Digest,
) -> VerifierIdentity {
    VerifierIdentity::new(DEVICE_VERIFIER, 1, schema)
        .expect("legacy device verifier identity is valid")
}

#[cfg(any(feature = "cser-production", feature = "cser-core-dma-recovery"))]
fn dma_binding(schema: ReceiptSchemaId) -> Option<VerifierBinding> {
    let implementation_digest = match schema {
        DEVICE_RECEIPT_SCHEMA => DEVICE_RECEIPT_IMPLEMENTATION_DIGEST,
        DEVICE_COMMIT_RECEIPT_SCHEMA => DEVICE_COMMIT_IMPLEMENTATION_DIGEST,
        _ => return None,
    };
    VerifierBinding::new(
        DEVICE_VERIFIER,
        VerifierGeneration::new(1).ok()?,
        schema,
        implementation_digest,
    )
    .ok()
}

#[cfg(any(feature = "cser-production", feature = "cser-core-dma-recovery"))]
fn dma_effect_scope_matches(challenge: &EffectFactChallenge, schema: ReceiptSchemaId) -> bool {
    match (
        challenge.verification_scope(),
        challenge.expected_verifier_binding(),
    ) {
        (None, None) => false,
        (Some(scope), Some(binding)) => {
            scope.world() == dma_provider_coordinate().world()
                && scope.provider() == dma_provider_coordinate()
                && scope.verifier_binding() == binding
                && Some(binding) == dma_binding(schema)
        }
        _ => false,
    }
}

#[cfg(not(any(feature = "cser-production", feature = "cser-core-dma-recovery")))]
fn dma_effect_scope_matches(challenge: &EffectFactChallenge, _schema: ReceiptSchemaId) -> bool {
    challenge.verification_scope().is_none() && challenge.expected_verifier_binding().is_none()
}

#[cfg(any(feature = "cser-production", feature = "cser-core-dma-recovery"))]
fn dma_evidence_scope_matches(challenge: &EvidenceChallenge, schema: ReceiptSchemaId) -> bool {
    match (
        challenge.verification_scope(),
        challenge.expected_verifier_binding(),
    ) {
        (None, None) => false,
        (Some(scope), Some(binding)) => {
            scope.world() == dma_provider_coordinate().world()
                && scope.provider() == dma_provider_coordinate()
                && scope.verifier_binding() == binding
                && Some(binding) == dma_binding(schema)
        }
        _ => false,
    }
}

#[cfg(not(any(feature = "cser-production", feature = "cser-core-dma-recovery")))]
fn dma_evidence_scope_matches(challenge: &EvidenceChallenge, _schema: ReceiptSchemaId) -> bool {
    challenge.verification_scope().is_none() && challenge.expected_verifier_binding().is_none()
}

/// Linear durable intent and exact core/DMA binding fixed before publication.
#[derive(Debug)]
#[must_use = "publish with this exact authority or retain it for recovery"]
pub(crate) struct CoreQueuePublishAuthority {
    intent: CommitIntent,
    binding: QueueCommitBinding,
}

/// Challenge binding rejected before hardware publication. The durable intent
/// remains owned by the failure.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CoreQueueBindFailure {
    pub(crate) error: CoreError,
    pub(crate) intent: CommitIntent,
}

/// Binds one durable commit intent and one DMA cohort while the authoritative
/// core projection is observed. The returned linear wrapper is the only input
/// accepted by real queue publication.
pub(crate) fn bind_queue_commit(
    engine: &Engine,
    intent: CommitIntent,
    cohort: CoreDmaCohort,
) -> Result<CoreQueuePublishAuthority, CoreQueueBindFailure> {
    let challenge = match engine.commit_outcome_challenge(&intent) {
        Ok(challenge) => challenge,
        Err(error) => return Err(CoreQueueBindFailure { error, intent }),
    };
    let binding = match QueueCommitBinding::from_challenge(&challenge, cohort) {
        Ok(binding) => binding,
        Err(error) => return Err(CoreQueueBindFailure { error, intent }),
    };
    Ok(CoreQueuePublishAuthority { intent, binding })
}

/// Queue publication rejected before or during the real facade preflight.
pub(crate) enum CoreQueuePublishFailure {
    BindingMismatch {
        owner: ReceiptedPreparedRequest,
        authority: CoreQueuePublishAuthority,
    },
    Hardware {
        failure: PreparationPublishFailure,
        authority: CoreQueuePublishAuthority,
    },
    NotificationAlreadyResolved {
        request: PublishedRequest,
        authority: CoreQueuePublishAuthority,
    },
}

/// A real device-visible request paired with its post-publication observation.
pub(crate) struct CorePublishedQueue {
    request: PublishedRequest,
    observation: QueueCommitObservation,
    authority: CoreQueuePublishAuthority,
}

/// Failure after real queue publication; the complete source-exact publication
/// and its core authority remain retained for retry, reset, or reconciliation.
pub(crate) struct CoreQueueCommitFailure {
    pub(crate) error: CoreError,
    pub(crate) published: CorePublishedQueue,
}

/// A real published request plus its verifier-minted durable acknowledgement.
pub(crate) struct CoreCommittedQueue {
    request: PublishedRequest,
    acknowledgement: Command,
}

impl CoreCommittedQueue {
    pub(crate) fn into_parts(self) -> (PublishedRequest, Command) {
        (self.request, self.acknowledgement)
    }
}

/// Applies the real `avail.idx` Release publication and resolves its queue
/// notification. No core commit outcome is minted before this function returns.
//
// The error deliberately returns the exact non-clone queue owner. Boxing it
// would introduce an allocation failure after descriptor preparation or
// publication, precisely where the adapter must fail closed with authority.
#[allow(clippy::result_large_err)]
pub(crate) fn publish_real_queue(
    device: &ProductionDevice,
    owner: ReceiptedPreparedRequest,
    authority: CoreQueuePublishAuthority,
) -> Result<CorePublishedQueue, CoreQueuePublishFailure> {
    if owner.identity() != authority.binding.cohort.hardware {
        return Err(CoreQueuePublishFailure::BindingMismatch { owner, authority });
    }
    let preparation_digest = owner.receipt().digest();
    let attempt = owner.attempt();
    let intent = match device.preflight_publish(owner, authority.binding.cohort.hardware) {
        Ok(intent) => intent,
        Err(failure) => {
            return Err(CoreQueuePublishFailure::Hardware { failure, authority });
        }
    };
    let mut request = intent.apply();
    let notification = request.notify();
    if notification == NotificationDisposition::AlreadyResolved {
        return Err(CoreQueuePublishFailure::NotificationAlreadyResolved { request, authority });
    }
    let observation = queue_commit_observation(
        authority.binding,
        attempt.owner_id(),
        attempt.sequence(),
        preparation_digest,
        notification,
    );
    Ok(CorePublishedQueue {
        request,
        observation,
        authority,
    })
}

impl CorePublishedQueue {
    /// Verifies the real publication against one exact durable commit intent.
    /// A rejected race returns both the hardware request and linear intent.
    //
    // The large failure is the recovery handle itself. Do not heap-box it
    // after queue publication: allocation failure would discard authority.
    #[allow(clippy::result_large_err)]
    pub(crate) fn verify_commit(
        self,
        engine: &Engine,
    ) -> Result<CoreCommittedQueue, CoreQueueCommitFailure> {
        let verifier = CoreQueueCommitVerifier {
            binding: self.authority.binding,
        };
        let outcome = match engine.verify_commit_outcome(
            &self.authority.intent,
            &verifier,
            &self.observation,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                return Err(CoreQueueCommitFailure {
                    error,
                    published: self,
                });
            }
        };
        let Self {
            request,
            observation,
            authority,
        } = self;
        let CoreQueuePublishAuthority { intent, binding } = authority;
        match intent.acknowledge(outcome) {
            Ok(acknowledgement) => Ok(CoreCommittedQueue {
                request,
                acknowledgement,
            }),
            Err(failure) => Err(CoreQueueCommitFailure {
                error: failure.error().clone(),
                published: CorePublishedQueue {
                    request,
                    observation,
                    authority: CoreQueuePublishAuthority {
                        intent: failure.into_intent(),
                        binding,
                    },
                },
            }),
        }
    }
}

/// Delegates the hard-IRQ ISR acknowledgement to the real retained request.
pub(crate) fn acknowledge_real_irq(request: &mut PublishedRequest) -> InterruptReceipt {
    request.ack_interrupt()
}

/// Delegates task-context completion to the real queue owner. A not-ready or
/// failed result still contains the facade's complete request/reset authority.
pub(crate) fn complete_real_irq(
    request: PublishedRequest,
    receipt: InterruptReceipt,
) -> InterruptCompletionProgress {
    request.complete_after_interrupt(receipt)
}

/// Reset acknowledgement after applying the facade's exact generation plan.
pub(crate) struct CoreResetEvidence {
    reset: ProductionResetAck,
    observation: RetirementObservation,
}

/// Reset binding rejection. The real acknowledgement remains available.
pub(crate) struct CoreResetEvidenceFailure {
    pub(crate) error: CoreError,
    pub(crate) reset: ProductionResetAck,
}

/// Applies the real facade generation fence and retains the reset owner until
/// every core reset/IRQ fact is durably accepted.
pub(crate) fn apply_real_reset_generation(
    device: &mut ProductionDevice,
    mut reset: ProductionResetAck,
    cohort: CoreDmaCohort,
) -> Result<CoreResetEvidence, CoreResetEvidenceFailure> {
    if reset.identity() != cohort.hardware || reset.retained_dma_pages() != 3 {
        return Err(CoreResetEvidenceFailure {
            error: CoreError::VerificationFailed,
            reset,
        });
    }
    let attempt = reset.attempt();
    let next = match device.prepare_generation_advance(&mut reset) {
        Ok(plan) => plan.apply(),
        Err(_) => {
            return Err(CoreResetEvidenceFailure {
                error: CoreError::VerificationFailed,
                reset,
            });
        }
    };
    let observation = retirement_observation(
        RetirementEvent::Reset(ClaimRole::Queue),
        cohort,
        attempt.owner_id(),
        attempt.sequence(),
        next,
        reset.retained_dma_pages(),
    );
    Ok(CoreResetEvidence { reset, observation })
}

impl CoreResetEvidence {
    /// Verifies one member of the reset cohort against the engine state
    /// observed immediately before that member's durable transition.
    ///
    /// The queue member advances the per-device generation. Callers must
    /// therefore verify and transact members sequentially rather than minting
    /// every command from one stale pre-reset projection.
    pub(crate) fn reset_command(
        &self,
        engine: &Engine,
        cohort: CoreDmaCohort,
        role: ClaimRole,
    ) -> Result<Command, CoreError> {
        self.command(engine, cohort, RetirementEvent::Reset(role))
    }

    /// Binds queue retirement to the exact real VirtIO ISR-status receipt that
    /// authorized task-context completion. A descriptive reset receipt alone
    /// cannot manufacture the IRQ-drained fact.
    pub(crate) fn irq_drained_command(
        &self,
        engine: &Engine,
        cohort: CoreDmaCohort,
        irq: InterruptReceipt,
    ) -> Result<Command, CoreError> {
        if irq.identity() != self.observation.hardware
            || irq.attempt().owner_id() != self.observation.attempt_owner
            || irq.attempt().sequence() != self.observation.attempt_sequence
            || !matches!(
                irq.cause(),
                InterruptCause::Queue | InterruptCause::QueueAndConfiguration
            )
        {
            return Err(CoreError::VerificationFailed);
        }
        let mut receipt = self.observation;
        receipt.event = RetirementEvent::IrqDrained;
        receipt.irq_queue_observed = true;
        receipt.digest = retirement_digest(&receipt);
        verify_retirement(engine, cohort, receipt)
    }

    fn command(
        &self,
        engine: &Engine,
        cohort: CoreDmaCohort,
        event: RetirementEvent,
    ) -> Result<Command, CoreError> {
        let mut receipt = self.observation;
        receipt.event = event;
        receipt.digest = retirement_digest(&receipt);
        verify_retirement(engine, cohort, receipt)
    }

    /// Starts the real IOTLB closure only after all reset facts and the final
    /// ISR drain have won their durable core transitions.
    //
    // Both failure variants retain a unique reset/IOTLB owner. Keeping that
    // owner inline avoids introducing a new allocation failure after reset.
    #[allow(clippy::result_large_err)]
    pub(crate) fn begin_iotlb(
        self,
        engine: &Engine,
        device: &ProductionDevice,
        cohort: CoreDmaCohort,
        inject_one_pending: bool,
    ) -> Result<ProductionClosureProgress, CoreIotlbBeginFailure> {
        for (role, kind) in [
            (ClaimRole::Queue, DEVICE_EVIDENCE_RESET),
            (ClaimRole::PinnedPages, DEVICE_EVIDENCE_RESET),
            (ClaimRole::Iova, DEVICE_EVIDENCE_RESET),
            (ClaimRole::Queue, DEVICE_EVIDENCE_IRQ_DRAINED),
        ] {
            if !evidence_was_accepted(engine, cohort, role, kind) {
                return Err(CoreIotlbBeginFailure::CoreNotDurable {
                    error: CoreError::EvidenceOutOfOrder,
                    reset: self,
                });
            }
        }
        let hardware = self.observation;
        device
            .begin_iotlb(self.reset, inject_one_pending)
            .map_err(|failure| CoreIotlbBeginFailure::Hardware { failure, hardware })
    }
}

/// IOTLB begin failure which retains either the adapter wrapper or the facade's
/// exact reset owner.
pub(crate) enum CoreIotlbBeginFailure {
    CoreNotDurable {
        error: CoreError,
        reset: CoreResetEvidence,
    },
    Hardware {
        failure: ProductionIotlbBeginFailure,
        hardware: RetirementObservation,
    },
}

/// Applied real IOTLB closure awaiting page/IOVA core retirement transitions.
pub(crate) struct CoreIotlbEvidence {
    closure: ProductionClosureReceipt,
    observation: RetirementObservation,
}

/// IOTLB binding rejection which retains the exact closure receipt.
pub(crate) struct CoreIotlbEvidenceFailure {
    pub(crate) error: CoreError,
    pub(crate) closure: ProductionClosureReceipt,
}

/// Applies the real facade quiescence plan after its three-owner IOTLB receipt.
pub(crate) fn apply_real_iotlb_closure(
    device: &mut ProductionDevice,
    mut closure: ProductionClosureReceipt,
    cohort: CoreDmaCohort,
) -> Result<CoreIotlbEvidence, CoreIotlbEvidenceFailure> {
    if closure.identity() != cohort.hardware || closure.completed_pages() != 3 {
        return Err(CoreIotlbEvidenceFailure {
            error: CoreError::VerificationFailed,
            closure,
        });
    }
    let successor_generation = match cohort.hardware.device_generation().checked_add(1) {
        Some(generation) => generation,
        None => {
            return Err(CoreIotlbEvidenceFailure {
                error: CoreError::VerificationFailed,
                closure,
            });
        }
    };
    let attempt = closure.attempt();
    let completed_pages = closure.completed_pages();
    let plan = match device.prepare_quiescence_apply(&mut closure) {
        Ok(plan) => plan,
        Err(_) => {
            return Err(CoreIotlbEvidenceFailure {
                error: CoreError::VerificationFailed,
                closure,
            });
        }
    };
    let applied_identity = plan.apply();
    if applied_identity != cohort.hardware {
        return Err(CoreIotlbEvidenceFailure {
            error: CoreError::VerificationFailed,
            closure,
        });
    }
    let observation = retirement_observation(
        RetirementEvent::Iotlb(ClaimRole::PinnedPages),
        cohort,
        attempt.owner_id(),
        attempt.sequence(),
        successor_generation,
        completed_pages,
    );
    Ok(CoreIotlbEvidence {
        closure,
        observation,
    })
}

impl CoreIotlbEvidence {
    pub(crate) fn retirement_commands(
        &self,
        engine: &Engine,
        cohort: CoreDmaCohort,
    ) -> Result<[Command; 2], CoreError> {
        Ok([
            self.command(engine, cohort, ClaimRole::PinnedPages)?,
            self.command(engine, cohort, ClaimRole::Iova)?,
        ])
    }

    fn command(
        &self,
        engine: &Engine,
        cohort: CoreDmaCohort,
        role: ClaimRole,
    ) -> Result<Command, CoreError> {
        let mut receipt = self.observation;
        receipt.event = RetirementEvent::Iotlb(role);
        receipt.digest = retirement_digest(&receipt);
        verify_retirement(engine, cohort, receipt)
    }

    pub(crate) fn into_receipt(self) -> ProductionClosureReceipt {
        self.closure
    }
}

fn verify_retirement(
    engine: &Engine,
    cohort: CoreDmaCohort,
    receipt: RetirementObservation,
) -> Result<Command, CoreError> {
    let verifier = CoreRetirementVerifier { cohort };
    let role = receipt.event.role();
    match cohort.component {
        Some(component) => engine.verify_component_retirement_evidence(
            cohort.effect,
            component,
            cohort.claim(role).claim,
            receipt.event.kind(),
            &verifier,
            &receipt,
        ),
        None => engine.verify_retirement_evidence(
            cohort.effect,
            cohort.claim(role).claim,
            receipt.event.kind(),
            &verifier,
            &receipt,
        ),
    }
    .map(|evidence| evidence.submit())
}

fn evidence_was_accepted(
    engine: &Engine,
    cohort: CoreDmaCohort,
    role: ClaimRole,
    kind: EvidenceKindId,
) -> bool {
    match cohort.component {
        Some(component) => engine.component_retirement_evidence_accepted(
            cohort.effect,
            component,
            cohort.claim(role).claim,
            kind,
        ),
        None => engine.retirement_evidence_accepted(cohort.effect, cohort.claim(role).claim, kind),
    }
    .unwrap_or(false)
}

fn queue_commit_observation(
    binding: QueueCommitBinding,
    attempt_owner: u64,
    attempt_sequence: u64,
    preparation_digest: u64,
    notification: NotificationDisposition,
) -> QueueCommitObservation {
    let mut observation = QueueCommitObservation {
        binding,
        attempt_owner,
        attempt_sequence,
        preparation_digest,
        notification,
        digest: Digest::ZERO,
    };
    observation.digest = queue_commit_digest(&observation);
    observation
}

fn retirement_observation(
    event: RetirementEvent,
    cohort: CoreDmaCohort,
    attempt_owner: u64,
    attempt_sequence: u64,
    successor_generation: u64,
    completed_pages: usize,
) -> RetirementObservation {
    let mut observation = RetirementObservation {
        event,
        component: cohort.component,
        hardware: cohort.hardware,
        attempt_owner,
        attempt_sequence,
        successor_generation,
        completed_pages,
        irq_queue_observed: false,
        digest: Digest::ZERO,
    };
    observation.digest = retirement_digest(&observation);
    observation
}

fn queue_commit_digest(observation: &QueueCommitObservation) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.ostd.cser-core.dma.queue-commit.v3");
    hash_queue_binding(&mut hasher, observation.binding);
    hasher.update(observation.attempt_owner.to_le_bytes());
    hasher.update(observation.attempt_sequence.to_le_bytes());
    hasher.update(observation.preparation_digest.to_le_bytes());
    hasher.update([match observation.notification {
        NotificationDisposition::Kicked => 1,
        NotificationDisposition::Suppressed => 2,
        NotificationDisposition::AlreadyResolved => 3,
    }]);
    Digest::new(hasher.finalize().into())
}

fn hash_queue_binding(hasher: &mut Sha256, binding: QueueCommitBinding) {
    let cohort = binding.cohort;
    hasher.update(cohort.effect.root().get().to_le_bytes());
    hasher.update(cohort.effect.sequence().to_le_bytes());
    hash_component(hasher, cohort.component);
    hasher.update(cohort.origin.principal().get().to_le_bytes());
    hasher.update(cohort.origin.generation().to_le_bytes());
    hasher.update(cohort.binding_generation.to_le_bytes());
    hasher.update(cohort.account.get().to_le_bytes());
    hasher.update(cohort.scope.get().to_le_bytes());
    hash_hardware(hasher, cohort.hardware);
    for role in [ClaimRole::Queue, ClaimRole::PinnedPages, ClaimRole::Iova] {
        let claim = cohort.claim(role);
        hasher.update(claim.claim.get().to_le_bytes());
        hasher.update(claim.resource.get().to_le_bytes());
        hasher.update(claim.generation.get().to_le_bytes());
        hasher.update(claim.units.to_le_bytes());
    }
    hasher.update(binding.authority_generation.to_le_bytes());
    hasher.update(binding.intent_nonce.to_le_bytes());
    hasher.update(binding.operation.bytes());
}

fn retirement_digest(observation: &RetirementObservation) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.ostd.cser-core.dma.retirement.v2");
    hasher.update([observation.event.tag()]);
    hasher.update([match observation.event.role() {
        ClaimRole::Queue => 1,
        ClaimRole::PinnedPages => 2,
        ClaimRole::Iova => 3,
    }]);
    hash_component(&mut hasher, observation.component);
    hash_hardware(&mut hasher, observation.hardware);
    hasher.update(observation.attempt_owner.to_le_bytes());
    hasher.update(observation.attempt_sequence.to_le_bytes());
    hasher.update(observation.successor_generation.to_le_bytes());
    hasher.update((observation.completed_pages as u64).to_le_bytes());
    hasher.update([u8::from(observation.irq_queue_observed)]);
    Digest::new(hasher.finalize().into())
}

fn hash_component(hasher: &mut Sha256, component: Option<ComponentId>) {
    match component {
        Some(component) => {
            hasher.update([1]);
            hasher.update(component.get().to_le_bytes());
        }
        None => hasher.update([0]),
    }
}

fn hash_hardware(hasher: &mut Sha256, hardware: DeviceSessionIdentity) {
    let bdf = hardware.device_bdf();
    hasher.update(hardware.device_session().to_le_bytes());
    hasher.update([bdf.bus(), bdf.device(), bdf.function()]);
    hasher.update(hardware.queue().to_le_bytes());
    hasher.update(hardware.descriptor_token().to_le_bytes());
    hasher.update(hardware.device_generation().to_le_bytes());
}

#[cfg(ktest)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use cser_core::{
        AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, BootGeneration,
        ComponentCommitOperation, CoreLimits, DMA_ARENA_REUSE_COMPOSITE, Freshness,
        JournalGeneration, PrincipalId, REPLY_CLAIM_PUBLICATION_SLOT, RegistryInstance, RootId,
        SnapshotId, TransitionOutput, TransitionReceipt, TxError, WorldId, standard_catalog,
    };
    use ostd::prelude::ktest;

    struct Harness {
        engine: Engine,
        journal: Vec<u8>,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                engine: Engine::new_scoped_legacy_compatibility(
                    WorldId::new(1).unwrap(),
                    standard_catalog(),
                    CoreLimits::bounded_default(),
                    freshness(1),
                ),
                journal: Vec::new(),
            }
        }

        fn tx<C: Into<Command>>(&mut self, command: C) -> Result<TransitionReceipt, CoreError> {
            let journal = &mut self.journal;
            self.engine
                .transact(command, |record| {
                    journal.extend_from_slice(record.bytes());
                    Ok::<(), ()>(())
                })
                .map_err(|error| match error {
                    TxError::Core(error) => error,
                    TxError::Journal(error) => CoreError::Journal(error),
                    TxError::Persist(()) => unreachable!("memory append cannot fail"),
                })
        }

        fn output<C: Into<Command>>(&mut self, command: C) -> TransitionOutput {
            self.tx(command).unwrap().into_output()
        }
    }

    #[ktest]
    fn component_cohort_routes_profile_two_commands_and_rejects_cross_component_receipts() {
        let mut harness = Harness::new();
        let legacy = cohort(90, 1);
        let cohort = CoreDmaCohort::bind_component(
            legacy.effect,
            AGENT_COMPONENT_DMA,
            legacy.origin,
            legacy.binding_generation,
            legacy.account,
            legacy.hardware,
            legacy.claims,
        )
        .unwrap();
        assert_eq!(cohort.component(), Some(AGENT_COMPONENT_DMA));

        harness
            .tx(CommandRequest::CreateCompositeEffect {
                effect: cohort.effect,
                origin: cohort.origin,
                binding_generation: cohort.binding_generation,
                kind: AGENT_OPERATION_COMPOSITE,
                charge_account: cohort.account,
            })
            .unwrap();
        for command in cohort.enroll_claims() {
            assert!(matches!(
                &command,
                CommandRequest::AddComponentClaim {
                    component: AGENT_COMPONENT_DMA,
                    ..
                }
            ));
            harness.tx(command).unwrap();
        }
        harness
            .tx(CommandRequest::AddComponentClaim {
                effect: cohort.effect,
                component: AGENT_COMPONENT_REPLY,
                actor: cohort.origin,
                binding_generation: cohort.binding_generation,
                claim: id::<ClaimId>(9_901),
                kind: REPLY_CLAIM_PUBLICATION_SLOT,
                scope: ClaimScope::Logical,
                resource: id::<ResourceId>(9_902),
                resource_generation: id::<ResourceGeneration>(1),
                units: 1,
            })
            .unwrap();
        assert!(matches!(
            cohort.prepare(),
            CommandRequest::PrepareCompositeEffect { .. }
        ));
        harness.tx(cohort.prepare()).unwrap();

        let commit_request = cohort.record_commit_intent(digest(0x61));
        assert!(matches!(
            &commit_request,
            CommandRequest::RecordComponentCommitIntent {
                component: AGENT_COMPONENT_DMA,
                ..
            }
        ));
        let intent = match harness.output(CommandRequest::RecordCompositeCommitIntents {
            effect: cohort.effect,
            actor: cohort.origin,
            binding_generation: cohort.binding_generation,
            operations: vec![
                ComponentCommitOperation::new(AGENT_COMPONENT_REPLY, digest(0x60)),
                ComponentCommitOperation::new(AGENT_COMPONENT_DMA, digest(0x61)),
            ],
        }) {
            TransitionOutput::CompositeCommitIntents(intents) => intents
                .into_iter()
                .find(|intent| intent.component() == Some(AGENT_COMPONENT_DMA))
                .expect("atomic arm returns the DMA component intent"),
            other => panic!("expected atomic composite commit intents, got {other:?}"),
        };
        assert_eq!(intent.component(), Some(AGENT_COMPONENT_DMA));

        let mut wrong_component = cohort;
        wrong_component.component = Some(AGENT_COMPONENT_REPLY);
        let failure = bind_queue_commit(&harness.engine, intent, wrong_component)
            .expect_err("a reply component cannot consume the DMA commit intent");
        assert_eq!(failure.error, CoreError::VerificationFailed);
        let authority = bind_queue_commit(&harness.engine, failure.intent, cohort)
            .unwrap_or_else(|_| panic!("the exact DMA component must bind"));
        let CoreQueuePublishAuthority { intent, binding } = authority;
        let observation =
            queue_commit_observation(binding, 7, 9, 0xfeed, NotificationDisposition::Kicked);
        let verifier = CoreQueueCommitVerifier { binding };
        let outcome = harness
            .engine
            .verify_commit_outcome(&intent, &verifier, &observation)
            .unwrap();
        harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();

        let reuse = cohort.reserve_reuse(CoreReuseReservation::new(
            ClaimRole::Queue,
            cohort.effect,
            cohort.origin,
            cohort.binding_generation,
            id::<ClaimId>(903),
            1,
            digest(0xda),
        ));
        assert!(matches!(
            reuse,
            CommandRequest::ReserveComponentReuse {
                component: AGENT_COMPONENT_DMA,
                ..
            }
        ));

        let reset = retirement_observation(
            RetirementEvent::Reset(ClaimRole::Queue),
            cohort,
            11,
            12,
            2,
            3,
        );
        let command = verify_retirement(&harness.engine, cohort, reset).unwrap();
        harness.tx(command).unwrap();
        assert_eq!(
            harness.engine.component_retirement_evidence_accepted(
                cohort.effect,
                AGENT_COMPONENT_DMA,
                cohort.claim(ClaimRole::Queue).claim,
                DEVICE_EVIDENCE_RESET,
            ),
            Ok(true)
        );

        let before = harness.engine.projection_digest();
        let mut forged = reset;
        forged.event = RetirementEvent::Reset(ClaimRole::PinnedPages);
        forged.component = Some(AGENT_COMPONENT_REPLY);
        forged.digest = retirement_digest(&forged);
        assert_eq!(
            verify_retirement(&harness.engine, cohort, forged),
            Err(CoreError::VerificationFailed)
        );
        assert_eq!(harness.engine.projection_digest(), before);
    }

    #[ktest]
    fn contract_model_retains_then_retires_and_reuses_queue_pages_and_iova() {
        let mut harness = Harness::new();
        let cohort = cohort(1, 1);
        enroll_and_commit(&mut harness, cohort);

        for role in [ClaimRole::Queue, ClaimRole::PinnedPages, ClaimRole::Iova] {
            assert_eq!(
                harness
                    .engine
                    .check_reusable(cohort.claim(role).resource, cohort.claim(role).generation),
                Err(CoreError::ResourceRetained)
            );
        }

        let reset =
            retirement_observation(RetirementEvent::Reset(ClaimRole::Queue), cohort, 7, 9, 2, 3);
        for role in [ClaimRole::Queue, ClaimRole::PinnedPages, ClaimRole::Iova] {
            let mut receipt = reset;
            receipt.event = RetirementEvent::Reset(role);
            receipt.digest = retirement_digest(&receipt);
            let command = verify_retirement(&harness.engine, cohort, receipt).unwrap();
            harness.tx(command).unwrap();
            assert_eq!(
                harness.engine.component_retirement_evidence_accepted(
                    cohort.effect,
                    AGENT_COMPONENT_DMA,
                    cohort.claim(role).claim,
                    DEVICE_EVIDENCE_RESET,
                ),
                Ok(true)
            );
        }

        let mut irq = reset;
        irq.event = RetirementEvent::IrqDrained;
        irq.irq_queue_observed = true;
        irq.digest = retirement_digest(&irq);
        let command = verify_retirement(&harness.engine, cohort, irq).unwrap();
        harness.tx(command).unwrap();
        assert_eq!(
            harness.engine.check_reusable(
                cohort.claim(ClaimRole::Queue).resource,
                cohort.claim(ClaimRole::Queue).generation,
            ),
            Ok(())
        );

        for role in [ClaimRole::PinnedPages, ClaimRole::Iova] {
            let mut receipt = reset;
            receipt.event = RetirementEvent::Iotlb(role);
            receipt.digest = retirement_digest(&receipt);
            let command = verify_retirement(&harness.engine, cohort, receipt).unwrap();
            harness.tx(command).unwrap();
            assert_eq!(
                harness
                    .engine
                    .check_reusable(cohort.claim(role).resource, cohort.claim(role).generation),
                Ok(())
            );
        }

        let replacement = cohort_with_resources(
            2,
            2,
            CoreDmaClaims::new(
                CoreDmaClaim::new(
                    id::<ClaimId>(401),
                    cohort.claim(ClaimRole::Queue).resource,
                    id::<ResourceGeneration>(2),
                    cohort.claim(ClaimRole::Queue).units,
                ),
                CoreDmaClaim::new(
                    id::<ClaimId>(402),
                    cohort.claim(ClaimRole::PinnedPages).resource,
                    id::<ResourceGeneration>(2),
                    cohort.claim(ClaimRole::PinnedPages).units,
                ),
                CoreDmaClaim::new(
                    id::<ClaimId>(403),
                    cohort.claim(ClaimRole::Iova).resource,
                    id::<ResourceGeneration>(2),
                    cohort.claim(ClaimRole::Iova).units,
                ),
            ),
        );
        create_dma_composite_effect(&mut harness, replacement);
        for (role, next_claim) in [
            (ClaimRole::Queue, id::<ClaimId>(401)),
            (ClaimRole::PinnedPages, id::<ClaimId>(402)),
            (ClaimRole::Iova, id::<ClaimId>(403)),
        ] {
            let permit = match harness.output(cohort.reserve_reuse(CoreReuseReservation::new(
                role,
                replacement.effect,
                replacement.origin,
                replacement.binding_generation,
                next_claim,
                cohort.claim(role).units,
                digest(0xdb),
            ))) {
                TransitionOutput::ReusePermit(permit) => permit,
                other => panic!("expected reuse permit, got {other:?}"),
            };
            assert_eq!(permit.generation().get(), 2);
            harness.tx(permit.activate()).unwrap();
        }
        assert_eq!(
            harness
                .engine
                .component(replacement.effect, AGENT_COMPONENT_DMA)
                .unwrap()
                .retained_claims,
            3
        );
        harness.tx(replacement.prepare()).unwrap();
        let intent = record_dma_composite_intent(&mut harness, replacement, digest(0x31));
        let challenge = harness.engine.commit_outcome_challenge(&intent).unwrap();
        assert_eq!(challenge.current_observation().device().get(), 2);
        bind_queue_commit(&harness.engine, intent, replacement)
            .unwrap_or_else(|_| panic!("activated generation-two cohort must bind"));
    }

    #[ktest]
    fn contract_model_rejects_late_old_generation_ack_without_mutation() {
        let mut harness = Harness::new();
        let first = cohort(10, 1);
        enroll_and_commit(&mut harness, first);
        let reset = retirement_observation(
            RetirementEvent::Reset(ClaimRole::Queue),
            first,
            11,
            12,
            2,
            3,
        );
        let command = verify_retirement(&harness.engine, first, reset).unwrap();
        harness.tx(command).unwrap();

        let second = cohort(11, 2);
        enroll_and_commit(&mut harness, second);
        let before = harness.engine.projection_digest();
        for event in [
            RetirementEvent::Reset(ClaimRole::Queue),
            RetirementEvent::IrqDrained,
            RetirementEvent::Iotlb(ClaimRole::PinnedPages),
            RetirementEvent::Iotlb(ClaimRole::Iova),
        ] {
            let stale = retirement_observation(event, first, 11, 12, 2, 3);
            assert_eq!(
                verify_retirement(&harness.engine, second, stale),
                Err(CoreError::VerificationFailed)
            );
            assert_eq!(harness.engine.projection_digest(), before);
        }
        assert_eq!(
            harness.engine.check_reusable(
                second.claim(ClaimRole::Queue).resource,
                second.claim(ClaimRole::Queue).generation,
            ),
            Err(CoreError::ResourceRetained)
        );
    }

    #[ktest]
    fn queue_publication_binding_rejects_foreign_cohort_and_preserves_intent() {
        let mut harness = Harness::new();
        let exact = cohort(20, 1);
        let intent = enroll_and_intent(&mut harness, exact, digest(0x41));
        let mut foreign = cohort(21, 1);
        foreign.hardware = exact.hardware;

        let before = harness.engine.projection_digest();
        let failure = bind_queue_commit(&harness.engine, intent, foreign)
            .expect_err("foreign effect/cohort must not bind a durable commit intent");
        assert_eq!(failure.error, CoreError::VerificationFailed);
        assert_eq!(failure.intent.effect(), exact.effect);
        assert_eq!(harness.engine.projection_digest(), before);
    }

    #[ktest]
    fn queue_commit_receipt_rejects_cross_intent_and_exact_challenge_mismatches() {
        let mut harness = Harness::new();
        let first = cohort(30, 1);
        let first_intent = enroll_and_intent(&mut harness, first, digest(0x51));
        let first_authority = bind_queue_commit(&harness.engine, first_intent, first)
            .unwrap_or_else(|_| panic!("first exact challenge binds"));
        let CoreQueuePublishAuthority {
            intent: first_intent,
            binding: first_binding,
        } = first_authority;
        let observation =
            queue_commit_observation(first_binding, 7, 9, 0xfeed, NotificationDisposition::Kicked);
        let first_verifier = CoreQueueCommitVerifier {
            binding: first_binding,
        };
        harness
            .engine
            .verify_commit_outcome(&first_intent, &first_verifier, &observation)
            .expect("source-exact challenge and queue observation verify");

        let mut second = cohort(31, 1);
        second.hardware = first.hardware;
        let second_intent = enroll_and_intent(&mut harness, second, digest(0x52));
        let second_authority = bind_queue_commit(&harness.engine, second_intent, second)
            .unwrap_or_else(|_| panic!("second exact challenge binds"));
        let CoreQueuePublishAuthority {
            intent: second_intent,
            binding: second_binding,
        } = second_authority;
        let second_verifier = CoreQueueCommitVerifier {
            binding: second_binding,
        };
        assert_eq!(
            harness
                .engine
                .verify_commit_outcome(&second_intent, &second_verifier, &observation,),
            Err(CoreError::VerificationFailed),
            "one physical publication cannot satisfy another intent/cohort"
        );

        let before = harness.engine.projection_digest();
        let mut forged = observation;
        forged.binding.authority_generation += 1;
        forged.digest = queue_commit_digest(&forged);
        assert_queue_commit_rejected(&harness.engine, &first_intent, first_binding, forged);

        let mut forged = observation;
        forged.binding.intent_nonce += 1;
        forged.digest = queue_commit_digest(&forged);
        assert_queue_commit_rejected(&harness.engine, &first_intent, first_binding, forged);

        let mut forged = observation;
        forged.binding.operation = digest(0x53);
        forged.digest = queue_commit_digest(&forged);
        assert_queue_commit_rejected(&harness.engine, &first_intent, first_binding, forged);

        let mut forged = observation;
        forged.binding.cohort.effect = second.effect;
        forged.digest = queue_commit_digest(&forged);
        assert_queue_commit_rejected(&harness.engine, &first_intent, first_binding, forged);
        assert_eq!(harness.engine.projection_digest(), before);
    }

    #[ktest]
    fn queue_commit_binding_keeps_authority_epoch_distinct_from_root_binding() {
        let mut harness = Harness::new();
        let first = cohort(32, 1);
        create_dma_composite_effect(&mut harness, first);
        harness
            .tx(CommandRequest::FenceIncarnation {
                root: first.effect.root(),
                crashed: first.origin,
                binding_generation: 1,
            })
            .unwrap();
        let snapshot = harness
            .engine
            .snapshot_root(first.effect.root(), id::<SnapshotId>(1))
            .unwrap();
        harness.tx(snapshot.record()).unwrap();

        let successor = PrincipalIncarnation::new(id::<PrincipalId>(32), 2).unwrap();
        harness
            .tx(CommandRequest::Ready {
                root: first.effect.root(),
                snapshot: id::<SnapshotId>(1),
                successor,
            })
            .unwrap();
        harness
            .tx(CommandRequest::Rebind {
                root: first.effect.root(),
                snapshot: id::<SnapshotId>(1),
                successor,
                binding_generation: 2,
            })
            .unwrap();

        let mut replacement = first;
        replacement.effect = cser_core::EffectId::new(first.effect.root(), 2).unwrap();
        replacement.origin = successor;
        replacement.binding_generation = 2;
        let intent = enroll_and_intent(&mut harness, replacement, digest(0x53));
        let challenge = harness.engine.commit_outcome_challenge(&intent).unwrap();
        assert_ne!(challenge.generation(), replacement.binding_generation);
        assert_eq!(
            challenge.current_observation().binding(),
            replacement.binding_generation
        );
        let before = harness.engine.projection_digest();
        let mut wrong_binding = replacement;
        wrong_binding.binding_generation = 1;
        let failure = bind_queue_commit(&harness.engine, intent, wrong_binding)
            .expect_err("stale root binding must fail before publication");
        assert_eq!(failure.error, CoreError::VerificationFailed);

        let mut wrong_device = replacement;
        wrong_device.hardware = cohort_with_resources(32, 2, replacement.claims).hardware;
        let failure = bind_queue_commit(&harness.engine, failure.intent, wrong_device)
            .expect_err("stale device freshness must fail before publication");
        assert_eq!(failure.error, CoreError::VerificationFailed);
        assert_eq!(harness.engine.projection_digest(), before);

        bind_queue_commit(&harness.engine, failure.intent, replacement)
            .unwrap_or_else(|_| panic!("independent authority and binding generations must bind"));
    }

    fn enroll_and_commit(harness: &mut Harness, cohort: CoreDmaCohort) {
        let intent = enroll_and_intent(harness, cohort, digest(77));
        let authority = bind_queue_commit(&harness.engine, intent, cohort)
            .unwrap_or_else(|_| panic!("exact queue challenge binds"));
        let CoreQueuePublishAuthority { intent, binding } = authority;
        let observation =
            queue_commit_observation(binding, 7, 9, 0xfeed, NotificationDisposition::Kicked);
        let verifier = CoreQueueCommitVerifier { binding };
        let outcome = harness
            .engine
            .verify_commit_outcome(&intent, &verifier, &observation)
            .unwrap();
        harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    }

    fn enroll_and_intent(
        harness: &mut Harness,
        cohort: CoreDmaCohort,
        operation: Digest,
    ) -> CommitIntent {
        create_dma_composite(harness, cohort);
        harness.tx(cohort.prepare()).unwrap();
        record_dma_composite_intent(harness, cohort, operation)
    }

    fn create_dma_composite(harness: &mut Harness, cohort: CoreDmaCohort) {
        create_dma_composite_effect(harness, cohort);
        for command in cohort.enroll_claims() {
            harness.tx(command).unwrap();
        }
    }

    fn create_dma_composite_effect(harness: &mut Harness, cohort: CoreDmaCohort) {
        assert_eq!(cohort.component(), Some(AGENT_COMPONENT_DMA));
        harness
            .tx(CommandRequest::CreateCompositeEffect {
                effect: cohort.effect,
                origin: cohort.origin,
                binding_generation: cohort.binding_generation,
                kind: DMA_ARENA_REUSE_COMPOSITE,
                charge_account: cohort.account,
            })
            .unwrap();
    }

    fn record_dma_composite_intent(
        harness: &mut Harness,
        cohort: CoreDmaCohort,
        operation: Digest,
    ) -> CommitIntent {
        match harness.output(CommandRequest::RecordCompositeCommitIntents {
            effect: cohort.effect,
            actor: cohort.origin,
            binding_generation: cohort.binding_generation,
            operations: vec![ComponentCommitOperation::new(
                AGENT_COMPONENT_DMA,
                operation,
            )],
        }) {
            TransitionOutput::CompositeCommitIntents(mut intents) if intents.len() == 1 => {
                let intent = intents.remove(0);
                assert_eq!(intent.component(), Some(AGENT_COMPONENT_DMA));
                intent
            }
            other => panic!("expected one atomic DMA component intent, got {other:?}"),
        }
    }

    fn assert_queue_commit_rejected(
        engine: &Engine,
        intent: &CommitIntent,
        binding: QueueCommitBinding,
        observation: QueueCommitObservation,
    ) {
        let verifier = CoreQueueCommitVerifier { binding };
        assert_eq!(
            engine.verify_commit_outcome(intent, &verifier, &observation),
            Err(CoreError::VerificationFailed)
        );
    }

    fn cohort(root: u64, device_generation: u64) -> CoreDmaCohort {
        cohort_with_resources(
            root,
            device_generation,
            CoreDmaClaims::new(
                CoreDmaClaim::new(
                    id::<ClaimId>(101),
                    id::<ResourceId>(root * 10 + 1),
                    id::<ResourceGeneration>(1),
                    1,
                ),
                CoreDmaClaim::new(
                    id::<ClaimId>(102),
                    id::<ResourceId>(root * 10 + 2),
                    id::<ResourceGeneration>(1),
                    3,
                ),
                CoreDmaClaim::new(
                    id::<ClaimId>(103),
                    id::<ResourceId>(root * 10 + 3),
                    id::<ResourceGeneration>(1),
                    3,
                ),
            ),
        )
    }

    fn cohort_with_resources(
        root: u64,
        device_generation: u64,
        claims: CoreDmaClaims,
    ) -> CoreDmaCohort {
        let root_id = id::<RootId>(root);
        let principal = id::<PrincipalId>(root);
        let hardware = DeviceSessionIdentity::from_coordinates(
            0x4e58_0000 + root,
            DeviceBdf::from_coordinates(0, 1, 0),
            0,
            1,
            device_generation,
        );
        CoreDmaCohort::bind_component(
            cser_core::EffectId::new(root_id, 1).unwrap(),
            AGENT_COMPONENT_DMA,
            PrincipalIncarnation::new(principal, 1).unwrap(),
            1,
            id::<ChargeAccountId>(root),
            hardware,
            claims,
        )
        .unwrap()
    }

    fn freshness(device: u64) -> Freshness {
        Freshness::new(
            id::<BootGeneration>(1),
            id::<RegistryInstance>(1),
            1,
            id::<DeviceGeneration>(device),
            id::<JournalGeneration>(1),
        )
        .unwrap()
    }

    fn digest(value: u8) -> Digest {
        let mut bytes = [0; 32];
        bytes[0] = value;
        Digest::new(bytes)
    }

    #[ktest]
    fn experiment_quiescence_rejects_each_missing_hardware_fact() {
        assert_eq!(
            validate_experiment_quiescence(1, 2, false, 2, true, 1),
            Err(ExperimentDmaQuiescenceError::ResetNotObserved)
        );
        assert_eq!(
            validate_experiment_quiescence(1, 2, true, 1, true, 1),
            Err(ExperimentDmaQuiescenceError::IrqDrainIncomplete)
        );
        assert_eq!(
            validate_experiment_quiescence(1, 2, true, 2, false, 1),
            Err(ExperimentDmaQuiescenceError::IotlbIncomplete)
        );
        assert_eq!(
            validate_experiment_quiescence(2, 2, true, 2, true, 1),
            Err(ExperimentDmaQuiescenceError::NonOlderResourceGeneration {
                resource_generation: 2,
                successor_generation: 2,
            })
        );
    }

    #[ktest]
    fn experiment_quiescence_accepts_exact_completed_facts() {
        assert_eq!(
            validate_experiment_quiescence(4, 5, true, 2, true, 1),
            Ok(())
        );
        assert_eq!(ExperimentDmaResource::new(0, 1), None);
        assert_eq!(ExperimentDmaResource::new(1, 0), None);
    }

    trait NonZeroId: Sized {
        fn from_nonzero(value: u64) -> Self;
    }

    macro_rules! impl_nonzero_id {
        ($($type:ty),+ $(,)?) => {
            $(
                impl NonZeroId for $type {
                    fn from_nonzero(value: u64) -> Self {
                        <$type>::new(value).unwrap()
                    }
                }
            )+
        };
    }

    impl_nonzero_id!(
        BootGeneration,
        ChargeAccountId,
        ClaimId,
        DeviceGeneration,
        JournalGeneration,
        PrincipalId,
        RegistryInstance,
        ResourceGeneration,
        ResourceId,
        RootId,
        SnapshotId,
    );

    fn id<T: NonZeroId>(value: u64) -> T {
        T::from_nonzero(value)
    }
}
