//! x86_64 architecture support (very early bring-up).

pub mod cpu;
pub mod idt;
pub mod int80;
pub mod log;
pub mod serial;

/// Early arch init (before heap/interrupts).
pub fn init() {
    // Safe to call multiple times; serial init is idempotent.
    serial::init();
}
