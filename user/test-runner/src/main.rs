//! Minimal userspace test runner (Phase B+).
//!
//! In later phases this binary will be loaded by the kernel and will exercise
//! syscall conformance tests (especially MUST syscalls).
//!
//! For now this is a tiny `int 0x80` conformance runner intended to be loaded by
//! the kernel bring-up path (ring3) and report results via the shared page +
//! `int3`.
//!
//! The default `_start` entrypoint is assembled and linked by `build.rs`.
//! Selected smoke scenarios can swap in a Rust-defined entry symbol instead.

#![no_std]
#![no_main]
#![cfg_attr(
    all(
        not(axle_test_runner_rust_entry = "reactor_smoke"),
        not(axle_test_runner_rust_entry = "component_smoke"),
        not(axle_test_runner_rust_entry = "perf_smoke")
    ),
    forbid(unsafe_code)
)]
#![cfg_attr(
    any(
        axle_test_runner_rust_entry = "reactor_smoke",
        axle_test_runner_rust_entry = "component_smoke",
        axle_test_runner_rust_entry = "perf_smoke"
    ),
    deny(unsafe_op_in_unsafe_fn)
)]
#![cfg_attr(
    any(
        axle_test_runner_rust_entry = "reactor_smoke",
        axle_test_runner_rust_entry = "component_smoke",
        axle_test_runner_rust_entry = "perf_smoke"
    ),
    deny(clippy::undocumented_unsafe_blocks)
)]

#[cfg(any(
    axle_test_runner_rust_entry = "reactor_smoke",
    axle_test_runner_rust_entry = "component_smoke"
))]
extern crate alloc;

use core::panic::PanicInfo;

#[cfg(axle_test_runner_rust_entry = "component_smoke")]
mod component_smoke;
#[cfg(axle_test_runner_rust_entry = "perf_smoke")]
mod perf_smoke;
#[cfg(axle_test_runner_rust_entry = "reactor_smoke")]
mod reactor_smoke;

#[cfg(axle_test_runner_rust_entry = "component_smoke")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    component_smoke::report_panic()
}

#[cfg(axle_test_runner_rust_entry = "reactor_smoke")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    reactor_smoke::report_panic()
}

#[cfg(axle_test_runner_rust_entry = "perf_smoke")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    perf_smoke::report_panic()
}

#[cfg(all(
    not(axle_test_runner_rust_entry = "reactor_smoke"),
    not(axle_test_runner_rust_entry = "component_smoke"),
    not(axle_test_runner_rust_entry = "perf_smoke")
))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
