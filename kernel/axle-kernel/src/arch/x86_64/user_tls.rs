//! Minimal x86_64 guest-thread TLS-base helpers.

use x86_64::registers::model_specific::Msr;

const IA32_FS_BASE: u32 = 0xC000_0100;

/// Read the current CPU's user-visible FS base.
pub(crate) fn read_fs_base() -> u64 {
    // SAFETY: reading IA32_FS_BASE is a local CPU register access with no
    // aliasing or lifetime requirements. Axle uses this only on x86_64 CPUs
    // that already entered long mode and support the MSR.
    unsafe { Msr::new(IA32_FS_BASE).read() }
}

/// Program the current CPU's user-visible FS base.
pub(crate) fn write_fs_base(base: u64) {
    // SAFETY: writing IA32_FS_BASE only updates the current CPU's user FS base.
    // Axle does not use FS for kernel percpu state, so restoring the saved
    // guest thread value before returning to user mode is sound.
    unsafe {
        Msr::new(IA32_FS_BASE).write(base);
    }
}
