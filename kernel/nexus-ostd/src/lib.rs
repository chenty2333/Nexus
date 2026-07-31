// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

#[cfg(not(any(
    feature = "cser-production",
    feature = "cser-core-reply-recovery",
    feature = "cser-core-dma-recovery",
    feature = "cser-core-tpm-anchor",
)))]
compile_error!("one CSER core runtime profile must be selected");

#[cfg(any(
    all(feature = "cser-production", feature = "cser-core-reply-recovery"),
    all(feature = "cser-production", feature = "cser-core-dma-recovery"),
    all(feature = "cser-production", feature = "cser-core-tpm-anchor"),
    all(
        feature = "cser-core-reply-recovery",
        feature = "cser-core-dma-recovery"
    ),
    all(feature = "cser-core-reply-recovery", feature = "cser-core-tpm-anchor"),
    all(feature = "cser-core-dma-recovery", feature = "cser-core-tpm-anchor"),
))]
compile_error!("CSER runtime profiles are mutually exclusive");

#[cfg(any(feature = "cser-production", feature = "cser-core-reply-recovery"))]
#[path = "cser/core_reply_adapter.rs"]
mod core_reply_adapter;

#[cfg(any(
    feature = "cser-production",
    feature = "cser-core-reply-recovery",
    feature = "cser-core-dma-recovery"
))]
#[path = "cser/core_runtime.rs"]
mod core_runtime;

#[cfg(feature = "cser-core-reply-recovery")]
#[path = "cser/core_runtime_slice.rs"]
mod core_runtime_slice;

#[cfg(feature = "cser-production")]
#[path = "cser/core_portal_vnext.rs"]
mod core_portal_vnext;

#[cfg(feature = "cser-production")]
#[path = "cser/core_production_registry.rs"]
mod core_production_registry;

#[cfg(feature = "cser-production")]
#[path = "cser/core_supervisor_vnext.rs"]
mod core_supervisor_vnext;

#[cfg(feature = "cser-production")]
#[path = "cser/core_reboot.rs"]
mod core_reboot;

#[cfg(any(feature = "cser-production", feature = "cser-core-dma-recovery"))]
#[path = "cser/core_dma_adapter.rs"]
mod core_dma_adapter;

#[cfg(feature = "cser-core-dma-recovery")]
#[path = "cser/core_dma_runtime.rs"]
mod core_dma_runtime;

#[cfg(any(feature = "cser-production", feature = "cser-core-tpm-anchor"))]
#[path = "cser/core_tpm_anchor.rs"]
mod core_tpm_anchor;

#[cfg(feature = "cser-production")]
#[path = "cser/core_pio_journal.rs"]
mod core_pio_journal;

#[cfg(feature = "cser-production")]
#[path = "cser/core_reply_outbox.rs"]
mod core_reply_outbox;

#[cfg(feature = "cser-production")]
#[path = "cser/core_device_quarantine.rs"]
mod core_device_quarantine;

#[cfg(feature = "cser-production")]
#[path = "cser/core_dma_arena_allocator.rs"]
mod core_dma_arena_allocator;

#[cfg(feature = "cser-production")]
#[path = "cser/core_persistent_runtime.rs"]
mod core_persistent_runtime;

#[cfg(feature = "cser-production")]
#[ostd::main]
fn kernel_main() {
    core_persistent_runtime::launch()
}

#[cfg(feature = "cser-core-reply-recovery")]
#[ostd::main]
fn kernel_main() {
    core_runtime_slice::launch()
}

#[cfg(feature = "cser-core-dma-recovery")]
#[ostd::main]
fn kernel_main() {
    core_dma_runtime::launch()
}

#[cfg(feature = "cser-core-tpm-anchor")]
#[ostd::main]
fn kernel_main() {
    core_tpm_anchor::launch()
}
