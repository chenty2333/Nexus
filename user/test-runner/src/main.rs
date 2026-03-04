//! Minimal userspace test runner (Phase B+).
//!
//! In later phases this binary will be loaded by the kernel and will exercise
//! syscall conformance tests (especially MUST syscalls).
//!
//! For now we provide a skeleton that can be wired to the kernel's syscall ABI.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use nexus_test_runner::run_int80_smoke;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Userspace entry point.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // In current bring-up this binary is not launched by the kernel yet.
    // Keep the same smoke assertions callable here so userspace wiring can
    // reuse them without changing test semantics.
    let _ = run_int80_smoke();
    loop {
        core::hint::spin_loop();
    }
}
