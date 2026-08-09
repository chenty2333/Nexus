// SPDX-License-Identifier: MPL-2.0

//! Temporary kernel entry points for the two comparable tool-plus-DMA profiles.
//!
//! These entry points intentionally own neither the CSER production registry
//! nor the experiment controller.  They make the new profiles linkable under
//! the same OSTD/QEMU device envelope, reserve COM2/COM3 through the two
//! guest-side transports. A successful UART exchange is only a transport
//! smoke check until the tool catalog is recovered through an ATA/TPM-backed
//! CSER runtime and a real VirtIO owner is bound to that same runtime.

use alloc::sync::Arc;
#[cfg(feature = "cser-tool-dma-experiment")]
use ostd::prelude::println;
use ostd::task::{Task, TaskOptions};

#[cfg(feature = "cser-tool-dma-experiment")]
pub(crate) fn launch_cser() -> ! {
    launch(
        run_cser_profile,
        "tool-DMA CSER experiment manager task builds",
    )
}

#[cfg(feature = "cser-tool-dma-baseline-experiment")]
pub(crate) fn launch_baseline() -> ! {
    launch(
        run_baseline_profile,
        "tool-DMA baseline experiment manager task builds",
    )
}

#[cfg(feature = "cser-tool-handoff-experiment")]
pub(crate) fn launch_handoff() -> ! {
    launch(
        run_handoff_profile,
        "logical CSER handoff experiment manager task builds",
    )
}

#[cfg(feature = "cser-tool-handoff-baseline-experiment")]
pub(crate) fn launch_handoff_baseline() -> ! {
    launch(
        run_handoff_baseline_profile,
        "logical independent-finalizer handoff manager task builds",
    )
}

fn launch(run: fn(), message: &'static str) -> ! {
    let manager = Arc::new(TaskOptions::new(run).build().expect(message));
    manager.run();
    Task::yield_now();
    unreachable!("the experiment manager powers the machine off")
}

#[cfg(feature = "cser-tool-dma-experiment")]
fn run_cser_profile() {
    super::core_cser_qemu_runtime::run();
}

#[cfg(feature = "cser-tool-dma-baseline-experiment")]
fn run_baseline_profile() {
    super::core_baseline_qemu_runtime::run();
}

#[cfg(feature = "cser-tool-handoff-experiment")]
fn run_handoff_profile() {
    super::core_cser_handoff_qemu_runtime::run();
}

#[cfg(feature = "cser-tool-handoff-baseline-experiment")]
fn run_handoff_baseline_profile() {
    super::core_baseline_handoff_qemu_runtime::run();
}

/// The initial integrated path has one fixed run identity so the guest-side
/// wire format, Unix-socket bridge, durable HTTP operation and COM3 barrier
/// can be exercised end-to-end before the matrix runner provisions per-trial
/// identities. This is intentionally not a retirement receipt: the CSER arm
/// still has to verify and persist the queried endpoint record through its
/// component-local adapter.
#[cfg(feature = "cser-tool-dma-experiment")]
fn tool_round_trip_and_barrier() {
    const RUN: [u8; 16] = [0x42; 16];
    let mut tool =
        super::core_tool_uart::ToolUart::acquire().expect("tool-DMA experiment profile owns COM2");
    let operation = super::core_tool_uart::OperationKey::new(b"tool-dma-smoke")
        .expect("fixed tool operation key is valid");
    let request = super::core_tool_uart::ToolRequest::new(
        super::core_tool_uart::ToolRunId::new(RUN),
        operation,
        b"tool-dma-e2e",
    )
    .expect("fixed tool request is within the bounded transport limit");
    let reply = tool
        .transact(&request)
        .expect("tool bridge returned a matching reply");
    assert!(
        (200..300).contains(&reply.status),
        "tool endpoint rejected fixed E2E request"
    );

    let mut crash = super::core_crash_probe::CrashProbe::acquire()
        .expect("tool-DMA experiment profile owns COM3");
    crash
        .barrier(
            super::core_crash_probe::CrashRunId::new(RUN),
            // Host matrix protocol assigns `post_endpoint_apply` the stable
            // numeric cutpoint 3; that mapping is carried in its receipt.
            super::core_crash_probe::CrashCutpoint::new(3),
        )
        .expect("host acknowledged exact post-endpoint-apply barrier");
}
