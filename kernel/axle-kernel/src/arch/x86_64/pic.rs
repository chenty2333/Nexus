//! Legacy 8259 PIC helpers.
//!
//! Axle uses the local APIC for interrupts. During early bring-up we mask the
//! legacy PIC to avoid stray IRQs when IF is enabled.

use x86_64::instructions::port::Port;

/// Mask all IRQ lines on the legacy 8259 PIC.
pub fn mask_all() {
    // SAFETY: programming the PIC uses fixed I/O ports on x86 PC platforms.
    // We only do this during early boot, before enabling external interrupts.
    unsafe {
        let mut master: Port<u8> = Port::new(0x21);
        let mut slave: Port<u8> = Port::new(0xA1);
        master.write(0xFF);
        slave.write(0xFF);
    }
}
