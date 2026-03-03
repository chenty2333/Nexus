//! Syscall entry/dispatch scaffolding (Phase B).
//!
//! In the Zircon model, userspace typically calls into the vDSO stubs,
//! which then enters the kernel with a syscall number and arguments.
//!
//! This module will eventually:
//! - validate arguments
//! - perform handle lookup (CSpace + rights + revocation)
//! - dispatch to object-specific handlers (Channel/Port/Timer/etc)

#![allow(dead_code)]

pub fn init() {
    // Placeholder.
}
