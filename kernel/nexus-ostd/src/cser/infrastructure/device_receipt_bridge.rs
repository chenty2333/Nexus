// SPDX-License-Identifier: MPL-2.0

//! Provider-neutral verification bridge into Registry-owned device evidence.
//!
//! Concrete hardware receipts stay outside the Registry dependency cone. A
//! narrow kernel adapter exposes their read-only projection through the view
//! traits below; this module rechecks every coordinate before constructing the
//! private infrastructure records. Digests are correlation fingerprints, not
//! authenticity or transition authority.

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::super::{
    DeviceClosureReceiptView, DeviceIndeterminateReceiptView, DevicePreparedReceiptView,
    DeviceRollbackEvidenceKind, DeviceRollbackReceiptView,
};
use super::{
    DeviceEnvelope, DeviceHardwareReceipt, DeviceReservationCoordinates, DeviceRollbackReceipt,
    InfrastructureError, PreparedDeviceIdentity, ResourceKey,
};

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(in super::super) struct VerifiedDeviceClosure {
    pub(in super::super) preparation_owner_id: u64,
    pub(in super::super) preparation_sequence: u64,
    pub(in super::super) device: DeviceEnvelope,
}

fn validate_owned_device(
    owned_device: ResourceKey,
    packed_device_bdf: u64,
    device_generation: u64,
) -> Result<(), InfrastructureError> {
    if owned_device.namespace() == 0
        || owned_device.id() != packed_device_bdf
        || owned_device.generation() != device_generation
    {
        return Err(InfrastructureError::InvalidReceipt);
    }
    Ok(())
}

pub(in super::super) fn verify_preparation(
    coordinates: DeviceReservationCoordinates,
    receipt: &(impl DevicePreparedReceiptView + ?Sized),
) -> Result<(DeviceHardwareReceipt, PreparedDeviceIdentity), InfrastructureError> {
    validate_owned_device(
        coordinates.owned_device,
        receipt.packed_device_bdf(),
        receipt.device_generation(),
    )?;
    if receipt.queue() != coordinates.queue
        || receipt.device_generation() != coordinates.device_generation
        || receipt.dma_owner_count() != 3
        || receipt.dma_share_count() != 3
        || receipt.transport_claim_count() == 0
        || receipt.receipt_digest() == 0
        || receipt.preparation_owner_id() == 0
        || receipt.preparation_sequence() == 0
    {
        return Err(InfrastructureError::InvalidReceipt);
    }
    let device = DeviceEnvelope::new(
        receipt.device_session(),
        receipt.queue(),
        receipt.descriptor_token(),
        receipt.device_generation(),
    )
    .map_err(|_| InfrastructureError::InvalidReceipt)?;
    let hardware = DeviceHardwareReceipt {
        owned_device: coordinates.owned_device,
        device,
        operation_digest: coordinates.operation_digest,
        actor_slot: coordinates.actor_slot,
        actor_generation: coordinates.actor_generation,
        hardware_receipt_digest: receipt.receipt_digest(),
        preparation_owner_id: receipt.preparation_owner_id(),
        preparation_sequence: receipt.preparation_sequence(),
    };
    let prepared = PreparedDeviceIdentity {
        preparation_id: coordinates.preparation_id,
        preparation_generation: coordinates.generation,
        owned_device: coordinates.owned_device,
        device,
        operation_digest: coordinates.operation_digest,
        actor_slot: coordinates.actor_slot,
        actor_generation: coordinates.actor_generation,
        hardware_receipt_digest: receipt.receipt_digest(),
        preparation_owner_id: receipt.preparation_owner_id(),
        preparation_sequence: receipt.preparation_sequence(),
    };
    Ok((hardware, prepared))
}

pub(in super::super) fn verify_rollback(
    coordinates: DeviceReservationCoordinates,
    receipt: &(impl DeviceRollbackReceiptView + ?Sized),
) -> Result<DeviceRollbackReceipt, InfrastructureError> {
    validate_owned_device(
        coordinates.owned_device,
        receipt.packed_device_bdf(),
        coordinates.device_generation,
    )?;
    let request = (
        receipt.request_packed_device_bdf(),
        receipt.request_queue(),
        receipt.request_device_generation(),
    );
    let valid_lineage = match (receipt.kind(), request) {
        (DeviceRollbackEvidenceKind::UnexposedFailure, (None, None, None)) => {
            receipt.quiescent_device_generation() == coordinates.device_generation
        }
        (
            DeviceRollbackEvidenceKind::PreparedCancellation,
            (Some(request_bdf), Some(request_queue), Some(request_generation)),
        ) => {
            request_bdf == receipt.packed_device_bdf()
                && request_queue == coordinates.queue
                && request_generation == coordinates.device_generation
                && coordinates.device_generation.checked_add(1)
                    == Some(receipt.quiescent_device_generation())
        }
        _ => false,
    };
    if receipt.attempt_device_generation() != coordinates.device_generation
        || receipt.receipt_digest() == 0
        || receipt.preparation_owner_id() == 0
        || receipt.preparation_sequence() == 0
        || !valid_lineage
    {
        return Err(InfrastructureError::InvalidReceipt);
    }
    Ok(DeviceRollbackReceipt {
        owned_device: coordinates.owned_device,
        queue: coordinates.queue,
        device_generation: coordinates.device_generation,
        operation_digest: coordinates.operation_digest,
        actor_slot: coordinates.actor_slot,
        actor_generation: coordinates.actor_generation,
        rollback_receipt_digest: receipt.receipt_digest(),
        preparation_owner_id: receipt.preparation_owner_id(),
        preparation_sequence: receipt.preparation_sequence(),
    })
}

pub(in super::super) fn verify_indeterminate(
    coordinates: DeviceReservationCoordinates,
    observation: &(impl DeviceIndeterminateReceiptView + ?Sized),
) -> Result<(u64, u64, u64), InfrastructureError> {
    validate_owned_device(
        coordinates.owned_device,
        observation.packed_device_bdf(),
        coordinates.device_generation,
    )?;
    if observation.attempt_device_generation() != coordinates.device_generation
        || observation.observation_digest() == 0
        || observation.preparation_owner_id() == 0
        || observation.preparation_sequence() == 0
    {
        return Err(InfrastructureError::InvalidReceipt);
    }
    Ok((
        observation.preparation_owner_id(),
        observation.preparation_sequence(),
        observation.observation_digest(),
    ))
}

pub(in super::super) fn verify_closure(
    prepared: PreparedDeviceIdentity,
    closure: &(impl DeviceClosureReceiptView + ?Sized),
) -> Result<VerifiedDeviceClosure, InfrastructureError> {
    validate_owned_device(
        prepared.owned_device,
        closure.packed_device_bdf(),
        closure.device_generation(),
    )?;
    if closure.preparation_owner_id() != prepared.preparation_owner_id
        || closure.preparation_sequence() != prepared.preparation_sequence
        || closure.device_session() != prepared.device.device_session()
        || closure.queue() != prepared.device.queue()
        || closure.descriptor_token() != prepared.device.descriptor_token()
        || closure.device_generation() != prepared.device.device_generation()
        || closure.completed_pages() != 3
    {
        return Err(InfrastructureError::InvalidReceipt);
    }
    Ok(VerifiedDeviceClosure {
        preparation_owner_id: closure.preparation_owner_id(),
        preparation_sequence: closure.preparation_sequence(),
        device: prepared.device,
    })
}
