//! CPU helpers.
use x86_64::instructions::hlt;

/// Halt the CPU in a loop.
pub fn halt_loop() -> ! {
    loop {
        halt();
    }
}

/// Execute a single HLT instruction.
pub fn halt() {
    hlt();
}
