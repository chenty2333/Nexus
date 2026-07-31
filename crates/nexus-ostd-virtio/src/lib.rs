// SPDX-License-Identifier: MPL-2.0

//! Safe facade for Nexus's OSTD 0.18.0 VirtIO block ownership substrate.
//!
//! The public API contains no raw pointer, unsafe function, raw PCI root, or
//! copyable hardware owner. All unsafe operations are confined to the four
//! private implementation modules below. Their invariants are documented at
//! each unsafe operation and summarized in the crate README.
//!
//! This extraction preserves the separate-boot Stage 5B polling experiment and
//! adds a safe INTx/ISR/one-shot completion facade for an IRQ successor. It
//! does not itself establish physical-hardware identity, IRQ-controller drain,
//! or crash-persistent page/IOVA custody.

#![no_std]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

// These are the only modules allowed to contain unsafe code. They are private
// so downstream `#![deny(unsafe_code)]` kernels can only use the safe exports
// below, not the raw HAL, MMIO, DMA, queue, or PCI configuration operations.
#[allow(unsafe_code)]
mod boot_quarantine;
#[allow(unsafe_code)]
mod dma;
#[allow(unsafe_code)]
mod pci;
#[allow(unsafe_code)]
mod production;

pub use boot_quarantine::{
    ActivatedBootDevice, BootActivationFailure, BootClaimCoordinateError, BootClaimCoordinateField,
    BootClaimCoordinates, BootClaimQuarantineReceipts, BootDeviceScope,
    BootGlobalIotlbInvalidationReceipt, BootQuarantineError, BootQuarantineFailure,
    BootQuarantineGuard, BootQuarantineObservation, BootQuarantineRequest,
    BootQuarantineRequestError, BootReceiptBindingError, BootVirtioIsrEmptyReceipt,
    BootVirtioStatusResetReceipt, quarantine_production_device,
};
pub use dma::{
    OwnerKind, PersistentDmaArenaError, PersistentDmaArenaLayout, PersistentDmaArenaObservation,
    install_persistent_dma_arena, owner_address, persistent_dma_arena_layout,
    persistent_dma_arena_observation, qemu_hypervisor_detected,
};
pub use pci::{
    DeviceBdf, IntxRoute, IntxTransitionError, IntxTransitionFailure, MaskedIntx,
    PciDiscoveryError, Root, UnmaskedIntx, discover_and_own_bars,
};
pub use production::{
    CancelledRequest, CompletedRequest, CompletionFailure, CompletionMode, CompletionProbeProgress,
    CompletionProgress, DeviceSessionIdentity, FailedCompletion, HardwareIntentError,
    HardwareIntentFailure, InterruptCause, InterruptCompletionProgress, InterruptNotReadyReason,
    InterruptReceipt, NotificationDisposition, PendingCompletion, PreparationAttemptIdentity,
    PreparationEvidenceError, PreparationEvidenceFailure, PreparationFailureEvidence,
    PreparationIndeterminate, PreparationPublishFailure, PreparationReceipt,
    PreparationRollbackError, PreparationRollbackKind, PreparationRollbackReceipt,
    PreparationStartPermit, PrepareReadError, PrepareReadFailure, PreparedCancelIntent,
    PreparedGenerationAdvance, PreparedPublishIntent, PreparedPublishedResetIntent,
    PreparedQuiescenceApply, PreparedRequest, PreparedRequestResetIntent,
    ProductionClosureProgress, ProductionClosureReceipt, ProductionDevice,
    ProductionDeviceClaimError, ProductionIotlbBeginError, ProductionIotlbBeginFailure,
    ProductionIotlbRetryError, ProductionIotlbRetryFailure, ProductionIotlbTombstone,
    ProductionResetAck, ProductionResetRetryError, ProductionResetRetryFailure,
    ProductionResetTombstone, PublishedRequest, QuiescenceApplyError, ReceiptedPreparedRequest,
    ResetGenerationError, StartedPreparationFailureEvidence, StartedPrepareReadFailure,
    UnregisteredCancellationError, UnregisteredCancelledRequest, UnregisteredPreparedCancellation,
};
