// SPDX-License-Identifier: MPL-2.0

//! OSTD/VirtIO implementation of the portable boot-quarantine boundary.
//!
//! Hardware ownership remains in `nexus-ostd-virtio`; this module only binds
//! its linear guard and trusted device generation to the recovery coordinator.

use cser_core::{
    ClaimProjection, ClaimScope, DEVICE_DOMAIN, DEVICE_EVIDENCE_IRQ_DRAINED, DEVICE_EVIDENCE_RESET,
    DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, DeviceGeneration, Digest, EvidenceChallenge,
    ReceiptVerifier, VerificationError, VerifiedObservation, VerifierIdentity,
};
use nexus_ostd_virtio::{
    ActivatedBootDevice, BootClaimCoordinateError, BootClaimCoordinates,
    BootClaimQuarantineReceipts, BootDeviceScope, BootQuarantineFailure, BootQuarantineGuard,
    BootQuarantineRequest, BootReceiptBindingError, BootVirtioIsrEmptyReceipt,
    BootVirtioStatusResetReceipt, ProductionDeviceClaimError, quarantine_production_device,
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

/// Exact replay projection expected by a boot-quarantine verifier.
#[derive(Clone, Copy)]
pub(crate) struct OstdBootClaimVerifier {
    claim: ClaimProjection,
}

impl OstdBootClaimVerifier {
    pub(crate) const fn new(claim: ClaimProjection) -> Self {
        Self { claim }
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
    claim: ClaimProjection,
}

impl OstdBootIrqVerifier {
    pub(crate) const fn new(claim: ClaimProjection) -> Self {
        Self { claim }
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
        let reset_verifier = OstdBootClaimVerifier::new(self.claim);
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

fn hash_coordinates(hasher: &mut Sha256, coordinates: BootClaimCoordinates) {
    hasher.update(coordinates.scope().get().to_le_bytes());
    hasher.update(coordinates.effect_root().to_le_bytes());
    hasher.update(coordinates.effect_sequence().to_le_bytes());
    hasher.update(coordinates.claim().to_le_bytes());
    hasher.update(coordinates.claim_kind().to_le_bytes());
    hasher.update(coordinates.resource().to_le_bytes());
    hasher.update(coordinates.resource_generation().to_le_bytes());
    hasher.update(coordinates.units().to_le_bytes());
    hasher.update(coordinates.subject_device_generation().to_le_bytes());
}
