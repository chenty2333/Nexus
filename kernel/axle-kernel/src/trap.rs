//! Trap/exception/interrupt bring-up.
//!
//! The bootstrap kernel now installs concrete fault, timer/APIC, and IPI
//! entry points here; this file remains intentionally thin glue over the arch
//! handlers rather than a TODO placeholder.

use crate::arch;

pub fn init() {
    arch::idt::init(
        arch::int80::entry_addr(),
        arch::breakpoint::entry_addr(),
        arch::fault::invalid_opcode_entry_addr(),
        arch::fault::page_fault_entry_addr(),
        arch::fault::gp_fault_entry_addr(),
        arch::fault::double_fault_entry_addr(),
        arch::timer::entry_addr(),
        arch::apic::spurious_entry_addr(),
        arch::apic::error_entry_addr(),
        arch::ipi::test_entry_addr(),
        arch::ipi::tlb_entry_addr(),
        arch::ipi::reschedule_entry_addr(),
    );
}
