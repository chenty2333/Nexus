//! QEMU-specific helpers for the bring-up / conformance environment.

/// QEMU `isa-debug-exit` I/O port (when enabled via `-device isa-debug-exit,...`).
const DEBUG_EXIT_PORT: u16 = 0xF4;

/// Exit QEMU with a given debug-exit code.
///
/// QEMU encodes the process exit status as `(code << 1) | 1`.
pub fn exit(code: u16) -> ! {
    // SAFETY: `out` to the `isa-debug-exit` port is a QEMU-defined contract.
    // When not running under QEMU or without the device enabled, this is a harmless
    // I/O port write during bring-up.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") DEBUG_EXIT_PORT,
            in("ax") code,
            options(nomem, nostack, preserves_flags),
        );
    }

    crate::arch::cpu::halt_loop();
}

pub fn exit_success() -> ! {
    exit(0x10)
}

pub fn exit_failure() -> ! {
    exit(0x11)
}
