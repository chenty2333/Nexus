//! CPU helpers.

/// Halt the CPU in a loop.
pub fn halt_loop() -> ! {
    loop {
        halt();
    }
}

/// Execute a single HLT instruction.
pub fn halt() {
    // Safety: `hlt` is safe at CPL0; when interrupts are disabled this will just idle forever.
    unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)) }
}
