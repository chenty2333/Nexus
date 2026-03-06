//! Minimal userspace test runner (Phase B+).
//!
//! In later phases this binary will be loaded by the kernel and will exercise
//! syscall conformance tests (especially MUST syscalls).
//!
//! For now this is a tiny `int 0x80` conformance runner intended to be loaded by
//! the kernel bring-up path (ring3) and report results via the shared page +
//! `int3`.
//!
//! The `_start` entrypoint is assembled and linked by `build.rs`, keeping this
//! crate itself free of Rust-level unsafe code.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
