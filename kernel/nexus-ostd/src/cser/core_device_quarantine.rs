// SPDX-License-Identifier: MPL-2.0

//! OSTD/VirtIO implementation of the portable boot-quarantine boundary.
//!
//! Hardware ownership remains in `nexus-ostd-virtio`; this module only binds
//! its linear guard and trusted device generation to the recovery coordinator.

#[cfg(feature = "cser-production")]
use super::core_production_registry::{
    DEVICE_RECEIPT_IMPLEMENTATION_DIGEST, PRODUCTION_WORLD, STANDARD_DMA_PROVIDER,
};
use cser_core::{
    ClaimScope, ComponentClaimProjection, ComponentId, DEVICE_CLAIM_IOVA, DEVICE_CLAIM_PINNED_PAGE,
    DEVICE_DOMAIN, DEVICE_EVIDENCE_IOTLB, DEVICE_EVIDENCE_IRQ_DRAINED, DEVICE_EVIDENCE_RESET,
    DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, DeviceGeneration, Digest, EffectId, EvidenceChallenge,
    ExecutorBinding, Freshness, ProviderCoordinate, ReceiptSchemaId, ReceiptVerifier,
    ResourceGeneration, ResourceId, VerificationError, VerifiedObservation, VerifierBinding,
    VerifierGeneration, VerifierIdentity, WorldId,
};
#[cfg(not(feature = "cser-production"))]
use cser_core::{ProviderGeneration, ProviderId};
use nexus_ostd_virtio::{
    ActivatedBootDevice, BootClaimCoordinateError, BootClaimCoordinates,
    BootClaimQuarantineReceipts, BootDeviceScope, BootGlobalIotlbInvalidationReceipt,
    BootQuarantineFailure, BootQuarantineGuard, BootQuarantineRequest, BootReceiptBindingError,
    BootVirtioIsrEmptyReceipt, BootVirtioStatusResetReceipt, PersistentDmaArenaLayout,
    ProductionDeviceClaimError, quarantine_production_device,
};
use sha2::{Digest as _, Sha256};

use super::core_reboot::{BootDeviceQuarantine, BootDeviceQuarantineGuard};

#[cfg(not(feature = "cser-production"))]
const DEVICE_RECEIPT_IMPLEMENTATION_DIGEST: Digest = Digest::new([0x61; 32]);

#[cfg(not(feature = "cser-production"))]
const NONPRODUCTION_DMA_PROVIDER: ProviderCoordinate = ProviderCoordinate::new(
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

#[cfg(not(feature = "cser-production"))]
const fn quarantine_provider_coordinate() -> ProviderCoordinate {
    NONPRODUCTION_DMA_PROVIDER
}

#[cfg(feature = "cser-production")]
const fn quarantine_provider_coordinate() -> ProviderCoordinate {
    STANDARD_DMA_PROVIDER
}

#[cfg(feature = "cser-production")]
const fn quarantine_world() -> WorldId {
    PRODUCTION_WORLD
}

#[cfg(not(feature = "cser-production"))]
const fn quarantine_world() -> WorldId {
    NONPRODUCTION_DMA_PROVIDER.world()
}

/// One request to fence the fixed production device at a trusted generation.
pub(crate) struct OstdVirtioBootQuarantine {
    generation: DeviceGeneration,
}

impl OstdVirtioBootQuarantine {
    /// Binds physical quarantine to a generation selected from the trusted
    /// anchor high-water. Construction itself does not touch hardware.
    pub(crate) const fn new(generation: DeviceGeneration) -> Self {
        Self { generation }
    }
}

impl BootDeviceQuarantine for OstdVirtioBootQuarantine {
    type Error = BootQuarantineFailure;
    type Guard = BootQuarantineGuard;

    fn quarantine_all(self) -> Result<Self::Guard, Self::Error> {
        let request = BootQuarantineRequest::new(self.generation.get())
            .expect("core device generations are non-zero");
        quarantine_production_device(request)
    }
}

impl BootDeviceQuarantineGuard for BootQuarantineGuard {
    type Error = ProductionDeviceClaimError;
    type Activation = ActivatedBootDevice;

    fn observed_generation(&self) -> DeviceGeneration {
        DeviceGeneration::new(BootQuarantineGuard::observed_generation(self))
            .expect("quarantine provider returns a non-zero generation")
    }

    fn try_activate(self) -> Result<Self::Activation, (Self, Self::Error)> {
        match BootQuarantineGuard::try_activate(self) {
            Ok(device) => Ok(device),
            Err(failure) => {
                let error = failure.error();
                let guard = failure.into_guard();
                Err((guard, error))
            }
        }
    }
}

/// Failure while binding replayed core coordinates to the retained guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OstdBootClaimBindingError {
    LogicalClaim,
    Coordinate(BootClaimCoordinateError),
    Hardware(BootReceiptBindingError),
}

/// Current core authority independently observed before a raw hardware
/// quarantine receipt is bound. VirtIO remains hardware-only, so this CSER
/// context is retained by the quarantine adapter rather than pushed into the
/// transport crate.
#[derive(Clone, Copy)]
pub(crate) struct OstdBootReceiptCurrent {
    observation: Freshness,
    binding: ExecutorBinding,
}

impl OstdBootReceiptCurrent {
    pub(crate) const fn new(observation: Freshness, binding: ExecutorBinding) -> Self {
        Self {
            observation,
            binding,
        }
    }
}

#[derive(Clone, Copy)]
struct OstdBootReceiptContext {
    subject: Freshness,
    subject_binding: ExecutorBinding,
    observation: Freshness,
    observation_binding: ExecutorBinding,
}

impl OstdBootReceiptContext {
    const fn for_reset(
        claim: ComponentClaimProjection,
        current: OstdBootReceiptCurrent,
        successor: DeviceGeneration,
    ) -> Self {
        Self {
            subject: claim.enrolled_freshness,
            subject_binding: claim.enrolled_binding,
            observation: current.observation.with_device(successor),
            observation_binding: current.binding,
        }
    }

    const fn current(claim: ComponentClaimProjection, current: OstdBootReceiptCurrent) -> Self {
        Self {
            subject: claim.enrolled_freshness,
            subject_binding: claim.enrolled_binding,
            observation: current.observation,
            observation_binding: current.binding,
        }
    }
}

/// Raw reset receipt plus the durable core authority coordinates it attests.
pub(crate) struct OstdBootResetReceipt {
    raw: BootVirtioStatusResetReceipt,
    context: OstdBootReceiptContext,
}

impl OstdBootResetReceipt {
    const fn subject(&self) -> Freshness {
        self.context.subject
    }

    const fn subject_binding(&self) -> ExecutorBinding {
        self.context.subject_binding
    }

    const fn observation(&self) -> Freshness {
        self.context.observation
    }

    const fn observation_binding(&self) -> ExecutorBinding {
        self.context.observation_binding
    }
}

/// Raw ISR-drain receipt plus the durable core authority coordinates it
/// attests.
pub(crate) struct OstdBootIrqReceipt {
    raw: BootVirtioIsrEmptyReceipt,
    context: OstdBootReceiptContext,
}

impl OstdBootIrqReceipt {
    const fn subject(&self) -> Freshness {
        self.context.subject
    }

    const fn subject_binding(&self) -> ExecutorBinding {
        self.context.subject_binding
    }

    const fn observation(&self) -> Freshness {
        self.context.observation
    }

    const fn observation_binding(&self) -> ExecutorBinding {
        self.context.observation_binding
    }
}

/// Raw global-IOTLB receipt plus the durable core authority coordinates it
/// attests.
pub(crate) struct OstdBootIotlbReceipt {
    raw: BootGlobalIotlbInvalidationReceipt,
    context: OstdBootReceiptContext,
}

impl OstdBootIotlbReceipt {
    const fn subject(&self) -> Freshness {
        self.context.subject
    }

    const fn subject_binding(&self) -> ExecutorBinding {
        self.context.subject_binding
    }

    const fn observation(&self) -> Freshness {
        self.context.observation
    }

    const fn observation_binding(&self) -> ExecutorBinding {
        self.context.observation_binding
    }

    pub(crate) const fn resource_reuse_authorized(&self) -> bool {
        self.raw.resource_reuse_authorized()
    }
}

/// Projects whole-device quarantine observations onto one component-local
/// replayed claim. The returned values remain raw hardware observations until
/// each production verifier receives a separately derived core context.
pub(crate) fn project_replayed_component_claim(
    guard: &BootQuarantineGuard,
    claim: ComponentClaimProjection,
) -> Result<BootClaimQuarantineReceipts, OstdBootClaimBindingError> {
    let ClaimScope::Device(scope) = claim.scope else {
        return Err(OstdBootClaimBindingError::LogicalClaim);
    };
    let scope = BootDeviceScope::new(scope.get()).map_err(OstdBootClaimBindingError::Coordinate)?;
    let coordinates = BootClaimCoordinates::new_component(
        scope,
        claim.effect.operation().get(),
        claim.effect.sequence(),
        claim.component.get(),
        claim.claim.get(),
        claim.kind.get(),
        claim.resource.get(),
        claim.resource_generation.get(),
        claim.units,
        claim.enrolled_freshness.device().get(),
    )
    .map_err(OstdBootClaimBindingError::Coordinate)?;
    guard
        .project_claim_quarantine(coordinates)
        .map_err(OstdBootClaimBindingError::Hardware)
}

/// Combines the reset's raw hardware fact with independently derived core
/// authority. This runs immediately before reset verification, rather than
/// copying the verifier challenge back into the receipt.
pub(crate) fn bind_replayed_reset_receipt(
    raw: BootVirtioStatusResetReceipt,
    claim: ComponentClaimProjection,
    current: OstdBootReceiptCurrent,
) -> OstdBootResetReceipt {
    let successor = DeviceGeneration::new(raw.successor_generation())
        .expect("quarantine provider returns a non-zero generation");
    OstdBootResetReceipt {
        raw,
        context: OstdBootReceiptContext::for_reset(claim, current, successor),
    }
}

/// Combines the ISR-drain's raw hardware fact with the current core authority
/// observed after any preceding reset evidence was accepted.
pub(crate) fn bind_replayed_irq_receipt(
    raw: BootVirtioIsrEmptyReceipt,
    claim: ComponentClaimProjection,
    current: OstdBootReceiptCurrent,
) -> OstdBootIrqReceipt {
    OstdBootIrqReceipt {
        raw,
        context: OstdBootReceiptContext::current(claim, current),
    }
}

/// Combines the IOTLB raw hardware fact with the current core authority
/// observed after any preceding reset evidence was accepted.
pub(crate) fn bind_replayed_iotlb_receipt(
    raw: BootGlobalIotlbInvalidationReceipt,
    claim: ComponentClaimProjection,
    current: OstdBootReceiptCurrent,
) -> OstdBootIotlbReceipt {
    OstdBootIotlbReceipt {
        raw,
        context: OstdBootReceiptContext::current(claim, current),
    }
}

#[derive(Clone, Copy)]
struct ReplayedClaim {
    effect: EffectId,
    component: ComponentId,
    claim: cser_core::ClaimId,
    kind: cser_core::ClaimKindId,
    scope: ClaimScope,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
    units: u64,
    enrolled_freshness: Freshness,
    enrolled_binding: ExecutorBinding,
}

impl From<ComponentClaimProjection> for ReplayedClaim {
    fn from(claim: ComponentClaimProjection) -> Self {
        Self {
            effect: claim.effect,
            component: claim.component,
            claim: claim.claim,
            kind: claim.kind,
            scope: claim.scope,
            resource: claim.resource,
            resource_generation: claim.resource_generation,
            units: claim.units,
            enrolled_freshness: claim.enrolled_freshness,
            enrolled_binding: claim.enrolled_binding,
        }
    }
}

/// Exact replay projection expected by a boot-quarantine verifier.
#[derive(Clone, Copy)]
pub(crate) struct OstdBootClaimVerifier {
    claim: ReplayedClaim,
}

impl OstdBootClaimVerifier {
    pub(crate) const fn new_component(claim: ComponentClaimProjection) -> Self {
        Self {
            claim: ReplayedClaim {
                effect: claim.effect,
                component: claim.component,
                claim: claim.claim,
                kind: claim.kind,
                scope: claim.scope,
                resource: claim.resource,
                resource_generation: claim.resource_generation,
                units: claim.units,
                enrolled_freshness: claim.enrolled_freshness,
                enrolled_binding: claim.enrolled_binding,
            },
        }
    }

    fn challenge_matches(
        &self,
        challenge: &EvidenceChallenge,
        coordinates: BootClaimCoordinates,
        expected_kind: cser_core::EvidenceKindId,
    ) -> bool {
        let ClaimScope::Device(scope) = self.claim.scope else {
            return false;
        };
        challenge.effect() == self.claim.effect
            && challenge.component() == self.claim.component
            && challenge.claim() == self.claim.claim
            && challenge.domain() == DEVICE_DOMAIN
            && challenge.kind() == expected_kind
            && challenge.scope() == self.claim.scope
            && challenge.expected_verifier() == DEVICE_VERIFIER
            && challenge.expected_receipt_schema() == DEVICE_RECEIPT_SCHEMA
            && challenge.resource() == self.claim.resource
            && challenge.resource_generation() == self.claim.resource_generation
            && challenge.subject() == self.claim.enrolled_freshness
            && challenge.subject_binding() == self.claim.enrolled_binding
            && coordinates.scope().get() == scope.get()
            && coordinates.effect_root() == self.claim.effect.operation().get()
            && coordinates.effect_sequence() == self.claim.effect.sequence()
            && coordinates.component() == Some(self.claim.component.get())
            && coordinates.claim() == self.claim.claim.get()
            && coordinates.claim_kind() == self.claim.kind.get()
            && coordinates.resource() == self.claim.resource.get()
            && coordinates.resource_generation() == self.claim.resource_generation.get()
            && coordinates.units() == self.claim.units
            && coordinates.subject_device_generation()
                == self.claim.enrolled_freshness.device().get()
            && quarantine_scope_matches(challenge, DEVICE_RECEIPT_SCHEMA)
    }
}

fn quarantine_verifier_identity() -> VerifierIdentity {
    let binding = VerifierBinding::new(
        DEVICE_VERIFIER,
        VerifierGeneration::new(1).expect("standard verifier generation is non-zero"),
        DEVICE_RECEIPT_SCHEMA,
        DEVICE_RECEIPT_IMPLEMENTATION_DIGEST,
    )
    .expect("standard device receipt verifier binding is valid");
    VerifierIdentity::new_exact(binding)
}

fn quarantine_scope_matches(challenge: &EvidenceChallenge, schema: ReceiptSchemaId) -> bool {
    let Ok(binding) = VerifierBinding::new(
        DEVICE_VERIFIER,
        VerifierGeneration::new(1).expect("standard verifier generation is non-zero"),
        schema,
        DEVICE_RECEIPT_IMPLEMENTATION_DIGEST,
    ) else {
        return false;
    };
    let scope = challenge.verification_scope();
    scope.world() == quarantine_world()
        && scope.provider() == quarantine_provider_coordinate()
        && scope.operation() == challenge.effect().operation()
        && scope.verifier_binding() == binding
        && challenge.expected_verifier_binding() == binding
}

impl ReceiptVerifier for OstdBootClaimVerifier {
    type Receipt = OstdBootResetReceipt;

    fn identity(&self) -> VerifierIdentity {
        quarantine_verifier_identity()
    }

    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        let successor = DeviceGeneration::new(receipt.raw.successor_generation())
            .map_err(|_| VerificationError::Rejected)?;
        let current_device = challenge.current_observation().device();
        if !self.challenge_matches(challenge, receipt.raw.claim(), DEVICE_EVIDENCE_RESET)
            || receipt.subject() != challenge.subject()
            || receipt.subject_binding() != challenge.subject_binding()
            || receipt.observation() != challenge.current_observation().with_device(successor)
            || receipt.observation_binding() != challenge.current_binding()
            || receipt.raw.old_generation() != challenge.subject().device().get()
            || !receipt.raw.reset_status_zero()
            || !receipt.raw.bus_master_disabled()
            || !receipt.raw.intx_masked()
            || (current_device != challenge.subject().device() && current_device != successor)
            || successor.get() <= receipt.raw.old_generation()
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new_bound(
            receipt.subject(),
            receipt.subject_binding(),
            receipt.observation(),
            receipt.observation_binding(),
            reset_digest(receipt),
        ))
    }
}

/// Verifier for the distinct ISR drain observation after reset was accepted.
pub(crate) struct OstdBootIrqVerifier {
    claim: ReplayedClaim,
}

impl OstdBootIrqVerifier {
    pub(crate) const fn new_component(claim: ComponentClaimProjection) -> Self {
        Self {
            claim: OstdBootClaimVerifier::new_component(claim).claim,
        }
    }
}

impl ReceiptVerifier for OstdBootIrqVerifier {
    type Receipt = OstdBootIrqReceipt;

    fn identity(&self) -> VerifierIdentity {
        quarantine_verifier_identity()
    }

    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        let coordinates = receipt.raw.claim();
        let reset_verifier = OstdBootClaimVerifier { claim: self.claim };
        if !reset_verifier.challenge_matches(challenge, coordinates, DEVICE_EVIDENCE_IRQ_DRAINED)
            || receipt.subject() != challenge.subject()
            || receipt.subject_binding() != challenge.subject_binding()
            || receipt.observation() != challenge.current_observation()
            || receipt.observation_binding() != challenge.current_binding()
            || !receipt.raw.intx_masked()
            || receipt.raw.isr_reads() < 2
            || receipt.raw.consecutive_empty_reads() < 2
            || receipt.raw.successor_generation() != challenge.current_observation().device().get()
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new_bound(
            receipt.subject(),
            receipt.subject_binding(),
            receipt.observation(),
            receipt.observation_binding(),
            irq_digest(receipt),
        ))
    }
}

/// QEMU restart-protocol verifier which combines the global invalidation with
/// an independently withheld, journal-bound PFN/IOVA arena.
///
/// This verifier deliberately rejects physical hardware. QEMU process
/// termination supplies the transaction-drain boundary that the current OSTD
/// VT-d API cannot observe as DWD/DRD descriptor bits on a real machine.
pub(crate) struct QemuArenaIotlbVerifier {
    claim: ReplayedClaim,
    layout: PersistentDmaArenaLayout,
    layout_digest: Digest,
    component_commit_operation: Option<Digest>,
    arena_withheld: bool,
    qemu_detected: bool,
}

impl QemuArenaIotlbVerifier {
    pub(crate) const fn new_component(
        claim: ComponentClaimProjection,
        layout: PersistentDmaArenaLayout,
        layout_digest: Digest,
        component_commit_operation: Option<Digest>,
        arena_withheld: bool,
        qemu_detected: bool,
    ) -> Self {
        Self {
            claim: OstdBootClaimVerifier::new_component(claim).claim,
            layout,
            layout_digest,
            component_commit_operation,
            arena_withheld,
            qemu_detected,
        }
    }
}

impl ReceiptVerifier for QemuArenaIotlbVerifier {
    type Receipt = OstdBootIotlbReceipt;

    fn identity(&self) -> VerifierIdentity {
        quarantine_verifier_identity()
    }

    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        let reset_verifier = OstdBootClaimVerifier { claim: self.claim };
        let arena_claim = matches!(
            self.claim.kind,
            DEVICE_CLAIM_PINNED_PAGE | DEVICE_CLAIM_IOVA
        ) && self.claim.units == self.layout.page_count() as u64;
        if !reset_verifier.challenge_matches(challenge, receipt.raw.claim(), DEVICE_EVIDENCE_IOTLB)
            || !arena_claim
            || !self.qemu_detected
            || !self.arena_withheld
            || self.layout_digest.is_zero()
            || self.component_commit_operation != Some(self.layout_digest)
            || receipt.subject() != challenge.subject()
            || receipt.subject_binding() != challenge.subject_binding()
            || receipt.observation() != challenge.current_observation()
            || receipt.observation_binding() != challenge.current_binding()
            || receipt.raw.old_generation() != challenge.subject().device().get()
            || receipt.raw.successor_generation() != challenge.current_observation().device().get()
            || !receipt.raw.used_remapped_iova()
            || receipt.raw.completed_trigger_pages() == 0
            || !receipt.raw.global_invalidation()
            || !receipt.raw.shared_second_stage_source_contract()
            || receipt.raw.dma_transaction_drain_observed()
            || receipt.raw.resource_reuse_authorized()
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new_bound(
            receipt.subject(),
            receipt.subject_binding(),
            receipt.observation(),
            receipt.observation_binding(),
            qemu_arena_iotlb_digest(receipt, self.layout, self.layout_digest),
        ))
    }
}

fn reset_digest(receipt: &OstdBootResetReceipt) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus-cser-boot-reset-v1");
    hash_coordinates(&mut hasher, receipt.raw.claim());
    let bdf = receipt.raw.device_bdf();
    hasher.update([bdf.bus(), bdf.device(), bdf.function()]);
    hasher.update(receipt.raw.old_generation().to_le_bytes());
    hasher.update(receipt.raw.successor_generation().to_le_bytes());
    hasher.update([
        receipt.raw.reset_status_zero() as u8,
        receipt.raw.bus_master_disabled() as u8,
        receipt.raw.intx_masked() as u8,
    ]);
    hash_receipt_context(&mut hasher, receipt.context);
    Digest::new(hasher.finalize().into())
}

fn irq_digest(receipt: &OstdBootIrqReceipt) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus-cser-boot-isr-empty-v1");
    hash_coordinates(&mut hasher, receipt.raw.claim());
    let bdf = receipt.raw.device_bdf();
    hasher.update([bdf.bus(), bdf.device(), bdf.function()]);
    hasher.update(receipt.raw.successor_generation().to_le_bytes());
    hasher.update(receipt.raw.observed_isr_bits().to_le_bytes());
    hasher.update((receipt.raw.isr_reads() as u64).to_le_bytes());
    hasher.update((receipt.raw.consecutive_empty_reads() as u64).to_le_bytes());
    hasher.update([receipt.raw.intx_masked() as u8]);
    hash_receipt_context(&mut hasher, receipt.context);
    Digest::new(hasher.finalize().into())
}

fn qemu_arena_iotlb_digest(
    receipt: &OstdBootIotlbReceipt,
    layout: PersistentDmaArenaLayout,
    layout_digest: Digest,
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus-cser-qemu-arena-iotlb-v1");
    hash_coordinates(&mut hasher, receipt.raw.claim());
    let bdf = receipt.raw.device_bdf();
    hasher.update([bdf.bus(), bdf.device(), bdf.function()]);
    hasher.update(receipt.raw.old_generation().to_le_bytes());
    hasher.update(receipt.raw.successor_generation().to_le_bytes());
    hasher.update(layout.version().to_le_bytes());
    hasher.update((layout.page_count() as u64).to_le_bytes());
    hasher.update((layout.paddr_base() as u64).to_le_bytes());
    hasher.update((layout.daddr_base() as u64).to_le_bytes());
    hasher.update(layout_digest.bytes());
    hasher.update([
        receipt.raw.used_remapped_iova() as u8,
        receipt.raw.global_invalidation() as u8,
        receipt.raw.shared_second_stage_source_contract() as u8,
        1, // QEMU process-restart protocol, never physical hardware.
    ]);
    hash_receipt_context(&mut hasher, receipt.context);
    Digest::new(hasher.finalize().into())
}

fn hash_coordinates(hasher: &mut Sha256, coordinates: BootClaimCoordinates) {
    hasher.update(coordinates.scope().get().to_le_bytes());
    hasher.update(coordinates.effect_root().to_le_bytes());
    hasher.update(coordinates.effect_sequence().to_le_bytes());
    match coordinates.component() {
        Some(component) => {
            hasher.update([1]);
            hasher.update(component.to_le_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(coordinates.claim().to_le_bytes());
    hasher.update(coordinates.claim_kind().to_le_bytes());
    hasher.update(coordinates.resource().to_le_bytes());
    hasher.update(coordinates.resource_generation().to_le_bytes());
    hasher.update(coordinates.units().to_le_bytes());
    hasher.update(coordinates.subject_device_generation().to_le_bytes());
}

fn hash_receipt_context(hasher: &mut Sha256, context: OstdBootReceiptContext) {
    hash_freshness(hasher, context.subject);
    hash_executor_binding(hasher, context.subject_binding);
    hash_freshness(hasher, context.observation);
    hash_executor_binding(hasher, context.observation_binding);
}

fn hash_freshness(hasher: &mut Sha256, freshness: Freshness) {
    hasher.update(freshness.boot().get().to_le_bytes());
    hasher.update(freshness.registry().get().to_le_bytes());
    hasher.update(freshness.device().get().to_le_bytes());
    hasher.update(freshness.journal().get().to_le_bytes());
}

fn hash_executor_binding(hasher: &mut Sha256, binding: ExecutorBinding) {
    let executor = binding.executor();
    hasher.update(executor.executor().get().to_le_bytes());
    hasher.update(executor.generation().get().to_le_bytes());
    hasher.update(binding.authority_epoch().to_le_bytes());
}

#[cfg(any(test, ktest))]
mod tests {
    use super::{OstdBootReceiptContext, hash_receipt_context};
    use cser_core::{
        BootGeneration, DeviceGeneration, ExecutorBinding, ExecutorCoordinate, ExecutorGeneration,
        ExecutorId, Freshness, JournalGeneration, RegistryInstance,
    };
    use sha2::{Digest as _, Sha256};

    const fn freshness(device: u64) -> Freshness {
        Freshness::new(
            match BootGeneration::new(1) {
                Ok(value) => value,
                Err(_) => unreachable!(),
            },
            match RegistryInstance::new(2) {
                Ok(value) => value,
                Err(_) => unreachable!(),
            },
            match DeviceGeneration::new(device) {
                Ok(value) => value,
                Err(_) => unreachable!(),
            },
            match JournalGeneration::new(3) {
                Ok(value) => value,
                Err(_) => unreachable!(),
            },
        )
    }

    const fn binding(authority_epoch: u64) -> ExecutorBinding {
        let executor = ExecutorCoordinate::new(
            match ExecutorId::new(4) {
                Ok(value) => value,
                Err(_) => unreachable!(),
            },
            match ExecutorGeneration::new(5) {
                Ok(value) => value,
                Err(_) => unreachable!(),
            },
        );
        match ExecutorBinding::new(executor, authority_epoch) {
            Ok(value) => value,
            Err(_) => unreachable!(),
        }
    }

    fn context_digest(context: OstdBootReceiptContext) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hash_receipt_context(&mut hasher, context);
        hasher.finalize().into()
    }

    #[cfg_attr(test, test)]
    #[cfg_attr(ktest, ktest)]
    fn receipt_codec_binds_both_executor_authority_coordinates() {
        let subject = freshness(6);
        let observation = freshness(7);
        let context = OstdBootReceiptContext {
            subject,
            subject_binding: binding(8),
            observation,
            observation_binding: binding(9),
        };
        let changed_subject = OstdBootReceiptContext {
            subject_binding: binding(10),
            ..context
        };
        let changed_observation = OstdBootReceiptContext {
            observation_binding: binding(11),
            ..context
        };

        assert_ne!(context_digest(context), context_digest(changed_subject));
        assert_ne!(context_digest(context), context_digest(changed_observation));
    }
}
