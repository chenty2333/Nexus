//! Trap/exception/interrupt scaffolding (Phase B).
//!
//! TODO: build full fault handlers, IRQ handlers, and IPI handling.

use crate::arch;

pub fn init() {
    arch::idt::init_int80_gate(arch::int80::entry_addr());
}
