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

    fn new(handler: usize, selector: u16, type_attr: u8, ist: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector,
            ist,
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
/// - basic fault diagnostics (#PF/#GP/#DF)
pub fn init(
    int80_handler: usize,
    breakpoint_handler: usize,
    page_fault_handler: usize,
    gp_fault_handler: usize,
    double_fault_handler: usize,
    timer_handler: usize,
    apic_spurious_handler: usize,
    apic_error_handler: usize,
    ipi_test_handler: usize,
    ipi_tlb_handler: usize,
    ipi_reschedule_handler: usize,
) {
    let selector = current_cs();

    // Type attrs:
    // - P=1
    // - DPL=3 (callable from CPL3)
    // - Gate type=0xE (interrupt gate)
    let user_callable_int_gate: u8 = 0xEE;

    // Type attrs:
    // - P=1
    // - DPL=0 (kernel only)
    // - Gate type=0xE (interrupt gate)
    let kernel_int_gate: u8 = 0x8E;

    // SAFETY: we are in single-core early bring-up; mutating the static IDT table is serialized.
    unsafe {
        IDT[0x80] = IdtEntry::new(int80_handler, selector, user_callable_int_gate, 0);
        IDT[3] = IdtEntry::new(breakpoint_handler, selector, user_callable_int_gate, 0);

        // Fault handlers (kernel-only). Keep double fault on IST1 and use a separate fault IST
        // for #PF/#GP so a fault taken during blocked kernel work does not reuse the current
        // kernel stack top.
        IDT[14] = IdtEntry::new(
            page_fault_handler,
            selector,
            kernel_int_gate,
            crate::arch::gdt::IST_FAULT_INDEX,
        );
        IDT[13] = IdtEntry::new(
            gp_fault_handler,
            selector,
            kernel_int_gate,
            crate::arch::gdt::IST_FAULT_INDEX,
        );
        IDT[8] = IdtEntry::new(
            double_fault_handler,
            selector,
            kernel_int_gate,
            crate::arch::gdt::IST_DOUBLE_FAULT_INDEX,
        );

        // Local APIC IRQs (kernel-only). Keep them on the current kernel stack: trap/syscall
        // paths may re-enable interrupts while blocked, and re-entering a shared IRQ IST would
        // reset `rsp` back to that IST top and corrupt the suspended return chain.
        IDT[crate::arch::apic::TIMER_VECTOR] =
            IdtEntry::new(timer_handler, selector, kernel_int_gate, 0);
        IDT[crate::arch::apic::SPURIOUS_VECTOR] =
            IdtEntry::new(apic_spurious_handler, selector, kernel_int_gate, 0);
        IDT[crate::arch::apic::ERROR_VECTOR] =
            IdtEntry::new(apic_error_handler, selector, kernel_int_gate, 0);

        // Fixed-vector IPI used by SMP conformance. (Kernel-only.)
        IDT[crate::arch::ipi::TEST_VECTOR] =
            IdtEntry::new(ipi_test_handler, selector, kernel_int_gate, 0);
        IDT[crate::arch::ipi::TLB_SHOOTDOWN_VECTOR] =
            IdtEntry::new(ipi_tlb_handler, selector, kernel_int_gate, 0);
        IDT[crate::arch::ipi::RESCHEDULE_VECTOR] =
            IdtEntry::new(ipi_reschedule_handler, selector, kernel_int_gate, 0);
    }
    load_idt();
}

/// Load the current static IDT on the calling CPU.
pub fn load() {
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
