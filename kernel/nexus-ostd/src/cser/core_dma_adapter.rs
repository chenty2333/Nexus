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
    CoreError, DEVICE_CLAIM_IOVA, DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT,
    DEVICE_COMMIT_RECEIPT_SCHEMA, DEVICE_DOMAIN, DEVICE_EVIDENCE_IOTLB,
    DEVICE_EVIDENCE_IRQ_DRAINED, DEVICE_EVIDENCE_RESET, DEVICE_OBLIGATION_DMA,
    DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, DeviceGeneration, DeviceScopeId, Digest,
    EffectFactChallenge, EffectReceiptVerifier, Engine, EvidenceChallenge, EvidenceKindId,
    ExternalOutcome, PrincipalIncarnation, ReceiptVerifier, ResourceGeneration, ResourceId,
    VerificationError, VerifiedEffectObservation, VerifiedObservation, VerifierIdentity,
};
use nexus_ostd_virtio::{
    DeviceSessionIdentity, InterruptCause, InterruptCompletionProgress, InterruptReceipt,
    NotificationDisposition, PreparationPublishFailure, ProductionClosureProgress,
    ProductionClosureReceipt, ProductionDevice, ProductionIotlbBeginFailure, ProductionResetAck,
    PublishedRequest, ReceiptedPreparedRequest,
};
use sha2::{Digest as _, Sha256};

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

/// Descriptive cross-layer binding for one device-visible DMA obligation.
///
/// This value grants no queue, DMA, reset, or IOTLB authority. Those remain in
/// the non-copyable facade owners accepted by the functions below.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreDmaCohort {
    effect: cser_core::EffectId,
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
        CommandRequest::PrepareEffect {
            effect: self.effect,
            actor: self.origin,
            binding_generation: self.binding_generation,
        }
    }

    pub(crate) const fn record_commit_intent(self, operation: Digest) -> CommandRequest {
        CommandRequest::RecordCommitIntent {
            effect: self.effect,
            actor: self.origin,
            binding_generation: self.binding_generation,
            operation,
        }
    }

    pub(crate) const fn reserve_reuse(
        self,
        role: ClaimRole,
        effect: cser_core::EffectId,
        actor: PrincipalIncarnation,
        binding_generation: u64,
        next_claim: ClaimId,
        units: u64,
    ) -> CommandRequest {
        let claim = self.claim(role);
        CommandRequest::ReserveReuse {
            effect,
            actor,
            binding_generation,
            claim: next_claim,
            domain: DEVICE_DOMAIN,
            kind: role.claim_kind(),
            scope: ClaimScope::Device(self.scope),
            resource: claim.resource,
            expected_generation: claim.generation,
            units,
        }
    }

    const fn add_claim(self, role: ClaimRole) -> CommandRequest {
        let claim = self.claim(role);
        CommandRequest::AddClaim {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueueCommitObservation {
    hardware: DeviceSessionIdentity,
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
    cohort: CoreDmaCohort,
}

impl EffectReceiptVerifier for CoreQueueCommitVerifier {
    type Receipt = QueueCommitObservation;

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new(DEVICE_VERIFIER, 1, DEVICE_COMMIT_RECEIPT_SCHEMA)
            .expect("standard device verifier identity is valid")
    }

    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        if challenge.effect() != self.cohort.effect
            || challenge.domain() != DEVICE_DOMAIN
            || challenge.obligation() != DEVICE_OBLIGATION_DMA
            || challenge.actor() != self.cohort.origin
            || receipt.hardware != self.cohort.hardware
            || receipt.hardware.device_generation()
                != challenge.current_observation().device().get()
            || receipt.attempt_owner == 0
            || receipt.attempt_sequence == 0
            || receipt.preparation_digest == 0
            || receipt.notification == NotificationDisposition::AlreadyResolved
            || receipt.digest.is_zero()
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
        VerifierIdentity::new(DEVICE_VERIFIER, 1, DEVICE_RECEIPT_SCHEMA)
            .expect("standard device verifier identity is valid")
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
            || challenge.claim() != claim.claim
            || challenge.domain() != DEVICE_DOMAIN
            || challenge.kind() != receipt.event.kind()
            || challenge.scope() != ClaimScope::Device(self.cohort.scope)
            || challenge.resource() != claim.resource
            || challenge.resource_generation() != claim.generation
            || challenge.subject().device().get() != old_generation
            || receipt.hardware != self.cohort.hardware
            || old_generation.checked_add(1) != Some(receipt.successor_generation)
            || !current_is_valid
            || !page_count_is_valid
            || !irq_observation_is_valid
            || receipt.attempt_owner == 0
            || receipt.attempt_sequence == 0
            || receipt.digest.is_zero()
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

/// Queue publication rejected before or during the real facade preflight.
pub(crate) enum CoreQueuePublishFailure {
    BindingMismatch(ReceiptedPreparedRequest),
    Hardware(PreparationPublishFailure),
    NotificationAlreadyResolved(PublishedRequest),
}

/// A real device-visible request paired with its post-publication observation.
pub(crate) struct CorePublishedQueue {
    request: PublishedRequest,
    observation: QueueCommitObservation,
}

/// Failure after real queue publication; the complete request and core intent
/// remain retained for reset or reconciliation.
pub(crate) struct CoreQueueCommitFailure {
    pub(crate) error: CoreError,
    pub(crate) request: PublishedRequest,
    pub(crate) intent: CommitIntent,
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
    cohort: CoreDmaCohort,
) -> Result<CorePublishedQueue, CoreQueuePublishFailure> {
    if owner.identity() != cohort.hardware {
        return Err(CoreQueuePublishFailure::BindingMismatch(owner));
    }
    let preparation_digest = owner.receipt().digest();
    let attempt = owner.attempt();
    let intent = device
        .preflight_publish(owner, cohort.hardware)
        .map_err(CoreQueuePublishFailure::Hardware)?;
    let mut request = intent.apply();
    let notification = request.notify();
    if notification == NotificationDisposition::AlreadyResolved {
        return Err(CoreQueuePublishFailure::NotificationAlreadyResolved(
            request,
        ));
    }
    let observation = queue_commit_observation(
        cohort.hardware,
        attempt.owner_id(),
        attempt.sequence(),
        preparation_digest,
        notification,
    );
    Ok(CorePublishedQueue {
        request,
        observation,
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
        intent: CommitIntent,
        cohort: CoreDmaCohort,
    ) -> Result<CoreCommittedQueue, CoreQueueCommitFailure> {
        let verifier = CoreQueueCommitVerifier { cohort };
        let outcome = match engine.verify_commit_outcome(&intent, &verifier, &self.observation) {
            Ok(outcome) => outcome,
            Err(error) => {
                return Err(CoreQueueCommitFailure {
                    error,
                    request: self.request,
                    intent,
                });
            }
        };
        match intent.acknowledge(outcome) {
            Ok(acknowledgement) => Ok(CoreCommittedQueue {
                request: self.request,
                acknowledgement,
            }),
            Err(failure) => Err(CoreQueueCommitFailure {
                error: failure.error().clone(),
                request: self.request,
                intent: failure.into_intent(),
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
        cohort.hardware,
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
        cohort.hardware,
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
    engine
        .verify_retirement_evidence(
            cohort.effect,
            cohort.claim(role).claim,
            receipt.event.kind(),
            &verifier,
            &receipt,
        )
        .map(|evidence| evidence.submit())
}

fn evidence_was_accepted(
    engine: &Engine,
    cohort: CoreDmaCohort,
    role: ClaimRole,
    kind: EvidenceKindId,
) -> bool {
    engine
        .retirement_evidence_accepted(cohort.effect, cohort.claim(role).claim, kind)
        .unwrap_or(false)
}

fn queue_commit_observation(
    hardware: DeviceSessionIdentity,
    attempt_owner: u64,
    attempt_sequence: u64,
    preparation_digest: u64,
    notification: NotificationDisposition,
) -> QueueCommitObservation {
    let mut observation = QueueCommitObservation {
        hardware,
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
    hardware: DeviceSessionIdentity,
    attempt_owner: u64,
    attempt_sequence: u64,
    successor_generation: u64,
    completed_pages: usize,
) -> RetirementObservation {
    let mut observation = RetirementObservation {
        event,
        hardware,
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
    hasher.update(b"nexus.ostd.cser-core.dma.queue-commit.v1");
    hash_hardware(&mut hasher, observation.hardware);
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

fn retirement_digest(observation: &RetirementObservation) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.ostd.cser-core.dma.retirement.v1");
    hasher.update([observation.event.tag()]);
    hasher.update([match observation.event.role() {
        ClaimRole::Queue => 1,
        ClaimRole::PinnedPages => 2,
        ClaimRole::Iova => 3,
    }]);
    hash_hardware(&mut hasher, observation.hardware);
    hasher.update(observation.attempt_owner.to_le_bytes());
    hasher.update(observation.attempt_sequence.to_le_bytes());
    hasher.update(observation.successor_generation.to_le_bytes());
    hasher.update((observation.completed_pages as u64).to_le_bytes());
    hasher.update([u8::from(observation.irq_queue_observed)]);
    Digest::new(hasher.finalize().into())
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
    use alloc::vec::Vec;
    use cser_core::{
        BootGeneration, CoreLimits, Freshness, JournalGeneration, PrincipalId, RegistryInstance,
        RootId, TransitionOutput, TransitionReceipt, TxError, standard_catalog,
    };
    use nexus_ostd_virtio::DeviceBdf;
    use ostd::prelude::ktest;

    struct Harness {
        engine: Engine,
        journal: Vec<u8>,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                engine: Engine::new(
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

        let reset = retirement_observation(
            RetirementEvent::Reset(ClaimRole::Queue),
            cohort.hardware,
            7,
            9,
            2,
            3,
        );
        for role in [ClaimRole::Queue, ClaimRole::PinnedPages, ClaimRole::Iova] {
            let mut receipt = reset;
            receipt.event = RetirementEvent::Reset(role);
            receipt.digest = retirement_digest(&receipt);
            let command = verify_retirement(&harness.engine, cohort, receipt).unwrap();
            harness.tx(command).unwrap();
            assert_eq!(
                harness.engine.retirement_evidence_accepted(
                    cohort.effect,
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

        let replacement = cohort_with_resources(2, 2, cohort.claims);
        harness.tx(replacement.create_estate()).unwrap();
        for (role, next_claim) in [
            (ClaimRole::Queue, id::<ClaimId>(401)),
            (ClaimRole::PinnedPages, id::<ClaimId>(402)),
            (ClaimRole::Iova, id::<ClaimId>(403)),
        ] {
            let permit = match harness.output(cohort.reserve_reuse(
                role,
                replacement.effect,
                replacement.origin,
                replacement.binding_generation,
                next_claim,
                cohort.claim(role).units,
            )) {
                TransitionOutput::ReusePermit(permit) => permit,
                other => panic!("expected reuse permit, got {other:?}"),
            };
            assert_eq!(permit.generation().get(), 2);
            harness.tx(permit.activate()).unwrap();
        }
        assert_eq!(
            harness
                .engine
                .estate(replacement.effect)
                .unwrap()
                .retained_claims,
            3
        );
    }

    #[ktest]
    fn contract_model_rejects_late_old_generation_ack_without_mutation() {
        let mut harness = Harness::new();
        let first = cohort(10, 1);
        enroll_and_commit(&mut harness, first);
        let reset = retirement_observation(
            RetirementEvent::Reset(ClaimRole::Queue),
            first.hardware,
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
            let stale = retirement_observation(event, first.hardware, 11, 12, 2, 3);
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

    fn enroll_and_commit(harness: &mut Harness, cohort: CoreDmaCohort) {
        harness.tx(cohort.create_estate()).unwrap();
        for command in cohort.enroll_claims() {
            harness.tx(command).unwrap();
        }
        harness.tx(cohort.prepare()).unwrap();
        let intent = match harness.output(cohort.record_commit_intent(digest(77))) {
            TransitionOutput::CommitIntent(intent) => intent,
            other => panic!("expected commit intent, got {other:?}"),
        };
        let observation = queue_commit_observation(
            cohort.hardware,
            7,
            9,
            0xfeed,
            NotificationDisposition::Kicked,
        );
        let verifier = CoreQueueCommitVerifier { cohort };
        let outcome = harness
            .engine
            .verify_commit_outcome(&intent, &verifier, &observation)
            .unwrap();
        harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
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
        CoreDmaCohort::bind(
            cser_core::EffectId::new(root_id, 1).unwrap(),
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
    );

    fn id<T: NonZeroId>(value: u64) -> T {
        T::from_nonzero(value)
    }
}
