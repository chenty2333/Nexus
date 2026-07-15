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
//! does not itself install an OSTD IRQ actor or establish interrupt delivery,
//! same-boot integration, SMP correctness, or production-identity preservation.

#![no_std]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

// These are the only modules allowed to contain unsafe code. They are private
// so downstream `#![deny(unsafe_code)]` kernels can only use the safe exports
// below, not the raw HAL, MMIO, DMA, queue, or PCI configuration operations.
#[allow(unsafe_code)]
mod dma;
#[allow(unsafe_code)]
mod pci;
#[allow(unsafe_code)]
mod portal;
#[allow(unsafe_code)]
mod production;

pub use dma::{OwnerKind, owner_address};
pub use pci::{
    DeviceBdf, IntxRoute, IntxTransitionError, IntxTransitionFailure, MaskedIntx, Root,
    UnmaskedIntx, discover_and_own_bars,
};
pub use portal::{
    BindingToken, ClosureProgress, ClosureReceipt, EffectAuthority, IotlbTombstone, Operation,
    Portal, RegisterError, ResetAck, ResetTombstone, Session, SessionNamespaceIsolationReceipt,
    SessionOpenError, Terminal, assert_session_namespace_isolation, terminal_label,
};
pub use production::{
    CancelledRequest, CompletedRequest, CompletionFailure, CompletionMode, CompletionProbeProgress,
    CompletionProgress, DeviceSessionIdentity, FailedCompletion, HardwareIntentError,
    HardwareIntentFailure, InterruptCause, InterruptCompletionProgress, InterruptNotReadyReason,
    InterruptReceipt, NotificationDisposition, PendingCompletion, PrepareReadError,
    PreparedCancelIntent, PreparedGenerationAdvance, PreparedPublishedResetIntent,
    PreparedQuiescenceApply, PreparedRequest, PreparedRequestResetIntent,
    ProductionClosureProgress, ProductionClosureReceipt, ProductionDevice,
    ProductionIotlbTombstone, ProductionResetAck, ProductionResetTombstone, PublishIdentityError,
    PublishedRequest, QuiescenceApplyError, ResetGenerationError, UnregisteredCancellationError,
    UnregisteredCancelledRequest, UnregisteredPreparedCancellation,
};
