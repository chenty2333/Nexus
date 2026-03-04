//! Minimal userspace test runner (Phase B+).
//!
//! In later phases this binary will be loaded by the kernel and will exercise
//! syscall conformance tests (especially MUST syscalls).
//!
//! For now we provide a skeleton that can be wired to the kernel's syscall ABI.

#![no_std]
#![no_main]

use axle_types::syscall_numbers::{
    AXLE_SYS_HANDLE_CLOSE, AXLE_SYS_OBJECT_WAIT_ASYNC, AXLE_SYS_OBJECT_WAIT_ONE,
    AXLE_SYS_PORT_CREATE, AXLE_SYS_PORT_QUEUE, AXLE_SYS_PORT_WAIT, AXLE_SYS_TIMER_CANCEL,
    AXLE_SYS_TIMER_CREATE, AXLE_SYS_TIMER_SET, SyscallNumber,
};
use axle_types::{
    zx_clock_t, zx_duration_t, zx_handle_t, zx_port_packet_t, zx_signals_t, zx_status_t, zx_time_t,
};
use core::panic::PanicInfo;

/// Phase-B bootstrap syscall numbers from the shared ABI source.
const BOOTSTRAP_SYSCALLS: [SyscallNumber; 9] = [
    AXLE_SYS_HANDLE_CLOSE,
    AXLE_SYS_OBJECT_WAIT_ONE,
    AXLE_SYS_OBJECT_WAIT_ASYNC,
    AXLE_SYS_PORT_CREATE,
    AXLE_SYS_PORT_QUEUE,
    AXLE_SYS_PORT_WAIT,
    AXLE_SYS_TIMER_CREATE,
    AXLE_SYS_TIMER_SET,
    AXLE_SYS_TIMER_CANCEL,
];

// Compile-time witness that userspace runner consumes shared ABI types.
const _ABI_TYPES_WITNESS: Option<(
    zx_handle_t,
    zx_signals_t,
    zx_time_t,
    zx_duration_t,
    zx_clock_t,
    zx_port_packet_t,
    zx_status_t,
)> = None;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Userspace entry point.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    let _ = BOOTSTRAP_SYSCALLS;

    // TODO(B): once the kernel has a debug log syscall, print here.
    // TODO(B): run a tiny conformance suite:
    // - handle_close invalid handle
    // - port_create/port_queue/port_wait basic
    // - timer_create/timer_set/timer_cancel
    loop {
        core::hint::spin_loop();
    }
}
