//! Minimal IDT setup for early syscall trap bring-up.

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    zero: u32,
}

impl IdtEntry {
    const MISSING: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attr: 0,
        offset_mid: 0,
        offset_high: 0,
        zero: 0,
    };

    fn new(handler: usize, selector: u16, type_attr: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector,
            ist: 0,
            type_attr,
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            zero: 0,
        }
    }
}

#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}

static mut IDT: [IdtEntry; 256] = [IdtEntry::MISSING; 256];

/// Install the minimal IDT needed for:
/// - `int 0x80` syscalls from ring3
/// - `int3` breakpoint exit from ring3 (temporary bring-up bridge)
pub fn init(int80_handler: usize, breakpoint_handler: usize) {
    let selector = current_cs();

    // Type attrs:
    // - P=1
    // - DPL=3 (callable from CPL3)
    // - Gate type=0xE (interrupt gate)
    let user_callable_int_gate: u8 = 0xEE;

    // SAFETY: we are in single-core early bring-up; mutating the static IDT table is serialized.
    unsafe {
        IDT[0x80] = IdtEntry::new(int80_handler, selector, user_callable_int_gate);
        IDT[3] = IdtEntry::new(breakpoint_handler, selector, user_callable_int_gate);
    }
    load_idt();
}

fn current_cs() -> u16 {
    let cs: u16;
    // SAFETY: reading CS into a general-purpose register is side-effect free.
    unsafe {
        core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    cs
}

fn load_idt() {
    let idtr = Idtr {
        limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
        base: core::ptr::addr_of!(IDT) as u64,
    };

    // SAFETY: `idtr` points to a valid in-memory descriptor for the static IDT table.
    unsafe {
        core::arch::asm!("lidt [{0}]", in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }
}
