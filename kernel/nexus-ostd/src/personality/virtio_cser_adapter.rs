// SPDX-License-Identifier: MPL-2.0

//! Narrow dependency adapter from the OSTD VirtIO facade to the CSER Registry.
//!
//! The facade owns nonconstructible hardware receipts. The Registry owns
//! provider-neutral read-only view traits and independently validates every
//! coordinate before minting its own opaque bearer. Keeping every concrete
//! implementation and call edge here prevents hardware types from entering
//! the Registry or host-model dependency cone.

use crate::effect_registry::{
    DeviceApplyIntent, DeviceClosureReceipt, DeviceClosureReceiptView,
    DeviceIndeterminateReceiptView, DevicePreparationRegistryFailure, DevicePreparedReceiptView,
    DeviceRollbackEvidenceKind, DeviceRollbackReceiptView, EffectRegistry,
    MaterializedDeviceTicket, PreparedDeviceIdentity, PreparedDeviceTicket,
};
use nexus_ostd_virtio::{
    DeviceBdf, PreparationIndeterminate, PreparationReceipt, PreparationRollbackKind,
    PreparationRollbackReceipt, ProductionClosureReceipt,
};

const fn packed_bdf(bdf: DeviceBdf) -> u64 {
    ((bdf.bus() as u64) << 16) | ((bdf.device() as u64) << 8) | bdf.function() as u64
}

impl DevicePreparedReceiptView for PreparationReceipt {
    fn preparation_owner_id(&self) -> u64 {
        PreparationReceipt::attempt(self).owner_id()
    }

    fn preparation_sequence(&self) -> u64 {
        PreparationReceipt::attempt(self).sequence()
    }

    fn device_session(&self) -> u64 {
        PreparationReceipt::identity(self).device_session()
    }

    fn packed_device_bdf(&self) -> u64 {
        packed_bdf(PreparationReceipt::identity(self).device_bdf())
    }

    fn queue(&self) -> u16 {
        PreparationReceipt::identity(self).queue()
    }

    fn descriptor_token(&self) -> u16 {
        PreparationReceipt::identity(self).descriptor_token()
    }

    fn device_generation(&self) -> u64 {
        PreparationReceipt::identity(self).device_generation()
    }

    fn dma_owner_count(&self) -> usize {
        usize::from(PreparationReceipt::dma_owner_count(self))
    }

    fn dma_share_count(&self) -> usize {
        usize::from(PreparationReceipt::dma_share_count(self))
    }

    fn transport_claim_count(&self) -> usize {
        usize::from(PreparationReceipt::transport_claim_count(self))
    }

    fn receipt_digest(&self) -> u64 {
        PreparationReceipt::digest(self)
    }
}

impl DeviceRollbackReceiptView for PreparationRollbackReceipt {
    fn preparation_owner_id(&self) -> u64 {
        PreparationRollbackReceipt::attempt(self).owner_id()
    }

    fn preparation_sequence(&self) -> u64 {
        PreparationRollbackReceipt::attempt(self).sequence()
    }

    fn packed_device_bdf(&self) -> u64 {
        packed_bdf(PreparationRollbackReceipt::device_bdf(self))
    }

    fn attempt_device_generation(&self) -> u64 {
        PreparationRollbackReceipt::device_generation(self)
    }

    fn quiescent_device_generation(&self) -> u64 {
        PreparationRollbackReceipt::quiescent_device_generation(self)
    }

    fn kind(&self) -> DeviceRollbackEvidenceKind {
        match PreparationRollbackReceipt::kind(self) {
            PreparationRollbackKind::UnexposedFailure => {
                DeviceRollbackEvidenceKind::UnexposedFailure
            }
            PreparationRollbackKind::PreparedCancellation => {
                DeviceRollbackEvidenceKind::PreparedCancellation
            }
        }
    }

    fn request_packed_device_bdf(&self) -> Option<u64> {
        PreparationRollbackReceipt::request_identity(self)
            .map(|identity| packed_bdf(identity.device_bdf()))
    }

    fn request_queue(&self) -> Option<u16> {
        PreparationRollbackReceipt::request_identity(self).map(|identity| identity.queue())
    }

    fn request_device_generation(&self) -> Option<u64> {
        PreparationRollbackReceipt::request_identity(self)
            .map(|identity| identity.device_generation())
    }

    fn receipt_digest(&self) -> u64 {
        PreparationRollbackReceipt::digest(self)
    }
}

impl DeviceIndeterminateReceiptView for PreparationIndeterminate {
    fn preparation_owner_id(&self) -> u64 {
        PreparationIndeterminate::attempt(self).owner_id()
    }

    fn preparation_sequence(&self) -> u64 {
        PreparationIndeterminate::attempt(self).sequence()
    }

    fn packed_device_bdf(&self) -> u64 {
        packed_bdf(PreparationIndeterminate::device_bdf(self))
    }

    fn attempt_device_generation(&self) -> u64 {
        PreparationIndeterminate::device_generation(self)
    }

    fn observation_digest(&self) -> u64 {
        PreparationIndeterminate::observation_digest(self)
    }
}

impl DeviceClosureReceiptView for ProductionClosureReceipt {
    fn preparation_owner_id(&self) -> u64 {
        ProductionClosureReceipt::attempt(self).owner_id()
    }

    fn preparation_sequence(&self) -> u64 {
        ProductionClosureReceipt::attempt(self).sequence()
    }

    fn device_session(&self) -> u64 {
        ProductionClosureReceipt::identity(self).device_session()
    }

    fn packed_device_bdf(&self) -> u64 {
        packed_bdf(ProductionClosureReceipt::identity(self).device_bdf())
    }

    fn queue(&self) -> u16 {
        ProductionClosureReceipt::identity(self).queue()
    }

    fn descriptor_token(&self) -> u16 {
        ProductionClosureReceipt::identity(self).descriptor_token()
    }

    fn device_generation(&self) -> u64 {
        ProductionClosureReceipt::identity(self).device_generation()
    }

    fn completed_pages(&self) -> usize {
        ProductionClosureReceipt::completed_pages(self)
    }
}

pub(crate) fn acknowledge_prepared(
    registry: &mut EffectRegistry,
    intent: DeviceApplyIntent,
    receipt: &PreparationReceipt,
) -> Result<
    (PreparedDeviceTicket, PreparedDeviceIdentity),
    DevicePreparationRegistryFailure<DeviceApplyIntent>,
> {
    registry.acknowledge_device_prepared_from_view(intent, receipt)
}

pub(crate) fn acknowledge_rollback(
    registry: &mut EffectRegistry,
    intent: DeviceApplyIntent,
    receipt: &PreparationRollbackReceipt,
) -> Result<(), DevicePreparationRegistryFailure<DeviceApplyIntent>> {
    registry.acknowledge_device_rollback_from_view(intent, receipt)
}

pub(crate) fn retain_indeterminate(
    registry: &mut EffectRegistry,
    intent: DeviceApplyIntent,
    observation: &PreparationIndeterminate,
) -> Result<u64, DevicePreparationRegistryFailure<DeviceApplyIntent>> {
    registry.retain_device_indeterminate_from_view(intent, observation)
}

pub(crate) fn install_materialized_closure(
    registry: &mut EffectRegistry,
    ticket: MaterializedDeviceTicket,
    registry_closure: &DeviceClosureReceipt,
    closure: &ProductionClosureReceipt,
) -> Result<(), DevicePreparationRegistryFailure<MaterializedDeviceTicket>> {
    registry.install_materialized_device_closure_from_view(ticket, registry_closure, closure)
}
