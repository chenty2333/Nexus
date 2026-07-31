// SPDX-License-Identifier: MPL-2.0

//! OSTD/VirtIO implementation of the portable boot-quarantine boundary.
//!
//! Hardware ownership remains in `nexus-ostd-virtio`; this module only binds
//! its linear guard and trusted device generation to the recovery coordinator.

use cser_core::{
    ClaimProjection, ClaimScope, ComponentClaimProjection, ComponentId, DEVICE_CLAIM_IOVA,
    DEVICE_CLAIM_PINNED_PAGE, DEVICE_DOMAIN, DEVICE_EVIDENCE_IOTLB, DEVICE_EVIDENCE_IRQ_DRAINED,
    DEVICE_EVIDENCE_RESET, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, DeviceGeneration, Digest,
    EffectId, EvidenceChallenge, Freshness, ReceiptVerifier, ResourceGeneration, ResourceId,
    VerificationError, VerifiedObservation, VerifierIdentity,
};
use nexus_ostd_virtio::{
    ActivatedBootDevice, BootClaimCoordinateError, BootClaimCoordinates,
    BootClaimQuarantineReceipts, BootDeviceScope, BootGlobalIotlbInvalidationReceipt,
    BootQuarantineFailure, BootQuarantineGuard, BootQuarantineRequest, BootReceiptBindingError,
    BootVirtioIsrEmptyReceipt, BootVirtioStatusResetReceipt, PersistentDmaArenaLayout,
    ProductionDeviceClaimError, quarantine_production_device,
};
use sha2::{Digest as _, Sha256};

use super::core_reboot::{BootDeviceQuarantine, BootDeviceQuarantineGuard};

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

/// Projects whole-device quarantine observations onto one exact replayed claim.
///
/// The returned IOTLB receipt remains descriptive only. In particular, this
/// helper does not turn a global invalidation into page/IOVA custody or reuse
/// authority.
pub(crate) fn project_replayed_claim(
    guard: &BootQuarantineGuard,
    claim: ClaimProjection,
) -> Result<BootClaimQuarantineReceipts, OstdBootClaimBindingError> {
    let ClaimScope::Device(scope) = claim.scope else {
        return Err(OstdBootClaimBindingError::LogicalClaim);
    };
    let scope = BootDeviceScope::new(scope.get()).map_err(OstdBootClaimBindingError::Coordinate)?;
    let coordinates = BootClaimCoordinates::new(
        scope,
        claim.effect.root().get(),
        claim.effect.sequence(),
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

/// Projects whole-device quarantine observations onto one component-local
/// replayed claim, preserving the component coordinate in every receipt.
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
        claim.effect.root().get(),
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

#[derive(Clone, Copy)]
struct ReplayedClaim {
    effect: EffectId,
    component: Option<ComponentId>,
    claim: cser_core::ClaimId,
    kind: cser_core::ClaimKindId,
    scope: ClaimScope,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
    units: u64,
    enrolled_freshness: Freshness,
}

impl From<ClaimProjection> for ReplayedClaim {
    fn from(claim: ClaimProjection) -> Self {
        Self {
            effect: claim.effect,
            component: None,
            claim: claim.claim,
            kind: claim.kind,
            scope: claim.scope,
            resource: claim.resource,
            resource_generation: claim.resource_generation,
            units: claim.units,
            enrolled_freshness: claim.enrolled_freshness,
        }
    }
}

impl From<ComponentClaimProjection> for ReplayedClaim {
    fn from(claim: ComponentClaimProjection) -> Self {
        Self {
            effect: claim.effect,
            component: Some(claim.component),
            claim: claim.claim,
            kind: claim.kind,
            scope: claim.scope,
            resource: claim.resource,
            resource_generation: claim.resource_generation,
            units: claim.units,
            enrolled_freshness: claim.enrolled_freshness,
        }
    }
}

/// Exact replay projection expected by a boot-quarantine verifier.
#[derive(Clone, Copy)]
pub(crate) struct OstdBootClaimVerifier {
    claim: ReplayedClaim,
}

impl OstdBootClaimVerifier {
    pub(crate) const fn new(claim: ClaimProjection) -> Self {
        Self {
            claim: ReplayedClaim {
                effect: claim.effect,
                component: None,
                claim: claim.claim,
                kind: claim.kind,
                scope: claim.scope,
                resource: claim.resource,
                resource_generation: claim.resource_generation,
                units: claim.units,
                enrolled_freshness: claim.enrolled_freshness,
            },
        }
    }

    pub(crate) const fn new_component(claim: ComponentClaimProjection) -> Self {
        Self {
            claim: ReplayedClaim {
                effect: claim.effect,
                component: Some(claim.component),
                claim: claim.claim,
                kind: claim.kind,
                scope: claim.scope,
                resource: claim.resource,
                resource_generation: claim.resource_generation,
                units: claim.units,
                enrolled_freshness: claim.enrolled_freshness,
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
            && challenge.resource() == self.claim.resource
            && challenge.resource_generation() == self.claim.resource_generation
            && challenge.subject() == self.claim.enrolled_freshness
            && coordinates.scope().get() == scope.get()
            && coordinates.effect_root() == self.claim.effect.root().get()
            && coordinates.effect_sequence() == self.claim.effect.sequence()
            && coordinates.component() == self.claim.component.map(ComponentId::get)
            && coordinates.claim() == self.claim.claim.get()
            && coordinates.claim_kind() == self.claim.kind.get()
            && coordinates.resource() == self.claim.resource.get()
            && coordinates.resource_generation() == self.claim.resource_generation.get()
            && coordinates.units() == self.claim.units
            && coordinates.subject_device_generation()
                == self.claim.enrolled_freshness.device().get()
    }
}

impl ReceiptVerifier for OstdBootClaimVerifier {
    type Receipt = BootVirtioStatusResetReceipt;

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new(DEVICE_VERIFIER, 1, DEVICE_RECEIPT_SCHEMA)
            .expect("standard device verifier identity is valid")
    }

    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        let successor = DeviceGeneration::new(receipt.successor_generation())
            .map_err(|_| VerificationError::Rejected)?;
        let current_device = challenge.current_observation().device();
        if !self.challenge_matches(challenge, receipt.claim(), DEVICE_EVIDENCE_RESET)
            || receipt.old_generation() != challenge.subject().device().get()
            || !receipt.reset_status_zero()
            || !receipt.bus_master_disabled()
            || !receipt.intx_masked()
            || (current_device != challenge.subject().device() && current_device != successor)
            || successor.get() <= receipt.old_generation()
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new(
            challenge.subject(),
            challenge.current_observation().with_device(successor),
            reset_digest(receipt),
        ))
    }
}

/// Verifier for the distinct ISR drain observation after reset was accepted.
pub(crate) struct OstdBootIrqVerifier {
    claim: ReplayedClaim,
}

impl OstdBootIrqVerifier {
    pub(crate) const fn new(claim: ClaimProjection) -> Self {
        Self {
            claim: OstdBootClaimVerifier::new(claim).claim,
        }
    }

    pub(crate) const fn new_component(claim: ComponentClaimProjection) -> Self {
        Self {
            claim: OstdBootClaimVerifier::new_component(claim).claim,
        }
    }
}

impl ReceiptVerifier for OstdBootIrqVerifier {
    type Receipt = BootVirtioIsrEmptyReceipt;

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new(DEVICE_VERIFIER, 1, DEVICE_RECEIPT_SCHEMA)
            .expect("standard device verifier identity is valid")
    }

    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        let coordinates = receipt.claim();
        let reset_verifier = OstdBootClaimVerifier { claim: self.claim };
        if !reset_verifier.challenge_matches(challenge, coordinates, DEVICE_EVIDENCE_IRQ_DRAINED)
            || !receipt.intx_masked()
            || receipt.isr_reads() < 2
            || receipt.consecutive_empty_reads() < 2
            || receipt.successor_generation() != challenge.current_observation().device().get()
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new(
            challenge.subject(),
            challenge.current_observation(),
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
    type Receipt = BootGlobalIotlbInvalidationReceipt;

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new(DEVICE_VERIFIER, 1, DEVICE_RECEIPT_SCHEMA)
            .expect("standard device verifier identity is valid")
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
        if !reset_verifier.challenge_matches(challenge, receipt.claim(), DEVICE_EVIDENCE_IOTLB)
            || !arena_claim
            || !self.qemu_detected
            || !self.arena_withheld
            || self.layout_digest.is_zero()
            || self.component_commit_operation != Some(self.layout_digest)
            || receipt.old_generation() != challenge.subject().device().get()
            || receipt.successor_generation() != challenge.current_observation().device().get()
            || !receipt.used_remapped_iova()
            || receipt.completed_trigger_pages() == 0
            || !receipt.global_invalidation()
            || !receipt.shared_second_stage_source_contract()
            || receipt.dma_transaction_drain_observed()
            || receipt.resource_reuse_authorized()
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new(
            challenge.subject(),
            challenge.current_observation(),
            qemu_arena_iotlb_digest(receipt, self.layout, self.layout_digest),
        ))
    }
}

fn reset_digest(receipt: &BootVirtioStatusResetReceipt) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus-cser-boot-reset-v1");
    hash_coordinates(&mut hasher, receipt.claim());
    let bdf = receipt.device_bdf();
    hasher.update([bdf.bus(), bdf.device(), bdf.function()]);
    hasher.update(receipt.old_generation().to_le_bytes());
    hasher.update(receipt.successor_generation().to_le_bytes());
    hasher.update([
        receipt.reset_status_zero() as u8,
        receipt.bus_master_disabled() as u8,
        receipt.intx_masked() as u8,
    ]);
    Digest::new(hasher.finalize().into())
}

fn irq_digest(receipt: &BootVirtioIsrEmptyReceipt) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus-cser-boot-isr-empty-v1");
    hash_coordinates(&mut hasher, receipt.claim());
    let bdf = receipt.device_bdf();
    hasher.update([bdf.bus(), bdf.device(), bdf.function()]);
    hasher.update(receipt.successor_generation().to_le_bytes());
    hasher.update(receipt.observed_isr_bits().to_le_bytes());
    hasher.update((receipt.isr_reads() as u64).to_le_bytes());
    hasher.update((receipt.consecutive_empty_reads() as u64).to_le_bytes());
    hasher.update([receipt.intx_masked() as u8]);
    Digest::new(hasher.finalize().into())
}

fn qemu_arena_iotlb_digest(
    receipt: &BootGlobalIotlbInvalidationReceipt,
    layout: PersistentDmaArenaLayout,
    layout_digest: Digest,
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus-cser-qemu-arena-iotlb-v1");
    hash_coordinates(&mut hasher, receipt.claim());
    let bdf = receipt.device_bdf();
    hasher.update([bdf.bus(), bdf.device(), bdf.function()]);
    hasher.update(receipt.old_generation().to_le_bytes());
    hasher.update(receipt.successor_generation().to_le_bytes());
    hasher.update(layout.version().to_le_bytes());
    hasher.update((layout.page_count() as u64).to_le_bytes());
    hasher.update((layout.paddr_base() as u64).to_le_bytes());
    hasher.update((layout.daddr_base() as u64).to_le_bytes());
    hasher.update(layout_digest.bytes());
    hasher.update([
        receipt.used_remapped_iova() as u8,
        receipt.global_invalidation() as u8,
        receipt.shared_second_stage_source_contract() as u8,
        1, // QEMU process-restart protocol, never physical hardware.
    ]);
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
