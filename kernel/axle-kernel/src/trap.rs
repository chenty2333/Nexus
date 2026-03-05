//! Trap/exception/interrupt scaffolding (Phase B).
//!
//! TODO: build full fault handlers, IRQ handlers, and IPI handling.

use crate::arch;

pub fn init() {
    arch::idt::init(arch::int80::entry_addr(), arch::breakpoint::entry_addr());
}
