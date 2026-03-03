//! Minimal userspace test runner (Phase B+).
//!
//! In later phases this binary will be loaded by the kernel and will exercise
//! syscall conformance tests (especially MUST syscalls).
//!
//! For now we provide a skeleton that can be wired to the kernel's syscall ABI.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Userspace entry point.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // TODO(B): once the kernel has a debug log syscall, print here.
    // TODO(B): run a tiny conformance suite:
    // - handle_close invalid handle
    // - port_create/port_queue/port_wait basic
    // - timer_create/timer_set/timer_cancel
    loop {
        core::hint::spin_loop();
    }
}
