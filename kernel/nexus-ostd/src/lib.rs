// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

#[cfg(not(any(
    feature = "cser-production",
    feature = "cser-core-reply-recovery",
    feature = "cser-core-dma-recovery",
    feature = "cser-core-tpm-anchor",
    feature = "cser-smp-smoke",
    feature = "cser-pio-journal-ktest",
    feature = "cser-tool-dma-experiment",
    feature = "cser-tool-dma-baseline-experiment",
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
    all(feature = "cser-production", feature = "cser-smp-smoke"),
    all(feature = "cser-core-reply-recovery", feature = "cser-smp-smoke"),
    all(feature = "cser-core-dma-recovery", feature = "cser-smp-smoke"),
    all(feature = "cser-core-tpm-anchor", feature = "cser-smp-smoke"),
    all(feature = "cser-production", feature = "cser-pio-journal-ktest"),
    all(
        feature = "cser-core-reply-recovery",
        feature = "cser-pio-journal-ktest"
    ),
    all(feature = "cser-core-dma-recovery", feature = "cser-pio-journal-ktest"),
    all(feature = "cser-core-tpm-anchor", feature = "cser-pio-journal-ktest"),
    all(feature = "cser-smp-smoke", feature = "cser-pio-journal-ktest"),
    all(
        feature = "cser-pio-journal-ktest",
        feature = "cser-tool-dma-experiment"
    ),
    all(
        feature = "cser-pio-journal-ktest",
        feature = "cser-tool-dma-baseline-experiment"
    ),
    all(feature = "cser-production", feature = "cser-tool-dma-experiment"),
    all(
        feature = "cser-production",
        feature = "cser-tool-dma-baseline-experiment"
    ),
    all(
        feature = "cser-core-reply-recovery",
        feature = "cser-tool-dma-experiment"
    ),
    all(
        feature = "cser-core-reply-recovery",
        feature = "cser-tool-dma-baseline-experiment"
    ),
    all(
        feature = "cser-core-dma-recovery",
        feature = "cser-tool-dma-experiment"
    ),
    all(
        feature = "cser-core-dma-recovery",
        feature = "cser-tool-dma-baseline-experiment"
    ),
    all(feature = "cser-core-tpm-anchor", feature = "cser-tool-dma-experiment"),
    all(
        feature = "cser-core-tpm-anchor",
        feature = "cser-tool-dma-baseline-experiment"
    ),
    all(
        feature = "cser-tool-dma-experiment",
        feature = "cser-tool-dma-baseline-experiment"
    ),
    all(feature = "cser-smp-smoke", feature = "cser-tool-dma-experiment"),
    all(
        feature = "cser-smp-smoke",
        feature = "cser-tool-dma-baseline-experiment"
    ),
))]
compile_error!("CSER runtime profiles are mutually exclusive");

#[cfg(any(feature = "cser-production", feature = "cser-core-reply-recovery"))]
#[path = "cser/core_reply_adapter.rs"]
mod core_reply_adapter;

#[cfg(any(
    feature = "cser-production",
    feature = "cser-core-reply-recovery",
    feature = "cser-core-dma-recovery",
    feature = "cser-smp-smoke",
    feature = "cser-tool-dma-experiment"
))]
#[path = "cser/core_runtime.rs"]
mod core_runtime;

#[cfg(feature = "cser-core-reply-recovery")]
#[path = "cser/core_runtime_slice.rs"]
mod core_runtime_slice;

#[cfg(feature = "cser-smp-smoke")]
#[path = "cser/core_smp_smoke.rs"]
mod core_smp_smoke;

#[cfg(feature = "cser-production")]
#[path = "cser/core_portal_vnext.rs"]
mod core_portal_vnext;

#[cfg(feature = "cser-production")]
#[path = "cser/core_production_registry.rs"]
mod core_production_registry;

#[cfg(feature = "cser-production")]
#[path = "cser/core_supervisor_vnext.rs"]
mod core_supervisor_vnext;

#[cfg(any(
    feature = "cser-production",
    feature = "cser-tool-dma-experiment",
    feature = "cser-tool-dma-baseline-experiment",
    feature = "cser-pio-journal-ktest",
))]
#[path = "cser/core_reboot.rs"]
mod core_reboot;

#[cfg(any(
    feature = "cser-production",
    feature = "cser-core-dma-recovery",
    feature = "cser-tool-dma-experiment",
    feature = "cser-tool-dma-baseline-experiment",
))]
#[path = "cser/core_dma_adapter.rs"]
mod core_dma_adapter;

#[cfg(any(
    feature = "cser-tool-dma-experiment",
    feature = "cser-tool-dma-baseline-experiment",
))]
#[path = "cser/core_experiment_dma_flow.rs"]
mod core_experiment_dma_flow;

#[cfg(feature = "cser-core-dma-recovery")]
#[path = "cser/core_dma_runtime.rs"]
mod core_dma_runtime;

#[cfg(any(
    feature = "cser-production",
    feature = "cser-core-tpm-anchor",
    feature = "cser-tool-dma-experiment",
    feature = "cser-tool-dma-baseline-experiment",
))]
#[path = "cser/core_tpm_anchor.rs"]
mod core_tpm_anchor;

#[cfg(any(
    feature = "cser-production",
    feature = "cser-tool-dma-experiment",
    feature = "cser-tool-dma-baseline-experiment",
    feature = "cser-pio-journal-ktest",
))]
#[path = "cser/core_pio_journal.rs"]
mod core_pio_journal;

#[cfg(feature = "cser-production")]
#[path = "cser/core_reply_outbox.rs"]
mod core_reply_outbox;

#[cfg(any(
    feature = "cser-production",
    feature = "cser-tool-dma-experiment",
    feature = "cser-tool-dma-baseline-experiment",
))]
#[path = "cser/core_device_quarantine.rs"]
mod core_device_quarantine;

#[cfg(any(
    feature = "cser-production",
    feature = "cser-tool-dma-experiment",
    feature = "cser-tool-dma-baseline-experiment",
))]
#[path = "cser/core_dma_arena_allocator.rs"]
mod core_dma_arena_allocator;

#[cfg(any(
    feature = "cser-production",
    feature = "cser-tool-dma-experiment",
    feature = "cser-tool-dma-baseline-experiment",
))]
#[path = "cser/core_qemu_persistent_boot.rs"]
mod core_qemu_persistent_boot;

#[cfg(feature = "cser-production")]
#[path = "cser/core_persistent_runtime.rs"]
mod core_persistent_runtime;

#[cfg(any(
    feature = "cser-tool-dma-experiment",
    feature = "cser-tool-dma-baseline-experiment",
))]
#[path = "cser/core_crash_probe.rs"]
mod core_crash_probe;

#[cfg(any(
    feature = "cser-tool-dma-experiment",
    feature = "cser-tool-dma-baseline-experiment",
))]
#[path = "cser/core_tool_uart.rs"]
mod core_tool_uart;

#[cfg(feature = "cser-tool-dma-experiment")]
#[path = "cser/core_tool_adapter.rs"]
mod core_tool_adapter;

#[cfg(feature = "cser-tool-dma-experiment")]
#[path = "cser/core_tool_dma_runtime.rs"]
mod core_tool_dma_runtime;

#[cfg(feature = "cser-tool-dma-experiment")]
#[path = "cser/core_cser_tool_experiment.rs"]
mod core_cser_tool_experiment;

#[cfg(feature = "cser-tool-dma-experiment")]
#[path = "cser/core_cser_qemu_runtime.rs"]
mod core_cser_qemu_runtime;

#[cfg(feature = "cser-tool-dma-baseline-experiment")]
#[path = "cser/core_baseline_runtime.rs"]
mod core_baseline_runtime;

#[cfg(feature = "cser-tool-dma-baseline-experiment")]
#[path = "cser/core_baseline_experiment.rs"]
mod core_baseline_experiment;

#[cfg(feature = "cser-tool-dma-baseline-experiment")]
#[path = "cser/core_baseline_qemu_runtime.rs"]
mod core_baseline_qemu_runtime;

#[cfg(any(
    feature = "cser-tool-dma-experiment",
    feature = "cser-tool-dma-baseline-experiment",
))]
#[path = "cser/core_experiment_runtime.rs"]
mod core_experiment_runtime;

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

#[cfg(feature = "cser-smp-smoke")]
#[ostd::main]
fn kernel_main() {
    core_smp_smoke::launch()
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

#[cfg(feature = "cser-tool-dma-experiment")]
#[ostd::main]
fn kernel_main() {
    core_experiment_runtime::launch_cser()
}

#[cfg(feature = "cser-tool-dma-baseline-experiment")]
#[ostd::main]
fn kernel_main() {
    core_experiment_runtime::launch_baseline()
}
