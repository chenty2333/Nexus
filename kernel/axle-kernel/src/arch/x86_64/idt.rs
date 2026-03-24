//! Minimal IDT setup for early syscall trap bring-up.

use core::cell::UnsafeCell;

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

struct IdtStorage(UnsafeCell<[IdtEntry; 256]>);

// SAFETY: IDT is only mutated during single-core early boot (init) and then
// read-only from all CPUs via `lidt`. The UnsafeCell is needed to allow
// interior mutability without `static mut`.
unsafe impl Sync for IdtStorage {}

static IDT: IdtStorage = IdtStorage(UnsafeCell::new([IdtEntry::MISSING; 256]));

/// Install the minimal IDT needed for:
/// - `int 0x80` syscalls from ring3
/// - `int3` breakpoint exit from ring3 (temporary bring-up bridge)
/// - basic fault diagnostics (#PF/#GP/#DF)
pub fn init(
    int80_handler: usize,
    breakpoint_handler: usize,
    invalid_opcode_handler: usize,
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
        let idt = &mut *IDT.0.get();
        idt[0x80] = IdtEntry::new(int80_handler, selector, user_callable_int_gate, 0);
        idt[3] = IdtEntry::new(breakpoint_handler, selector, user_callable_int_gate, 0);
        // #UD does not need its own IST -- it is a non-nesting fault and can use
        // the interrupted kernel stack safely.
        idt[6] = IdtEntry::new(
            invalid_opcode_handler,
            selector,
            kernel_int_gate,
            0,
        );

        // Fault handlers (kernel-only). #PF and #GP each get a separate IST so
        // a nested exception (e.g. #GP inside #PF handler) does not overwrite
        // the outer frame.
        idt[14] = IdtEntry::new(
            page_fault_handler,
            selector,
            kernel_int_gate,
            crate::arch::gdt::IST_PF_INDEX,
        );
        idt[13] = IdtEntry::new(
            gp_fault_handler,
            selector,
            kernel_int_gate,
            crate::arch::gdt::IST_GP_INDEX,
        );
        idt[8] = IdtEntry::new(
            double_fault_handler,
            selector,
            kernel_int_gate,
            crate::arch::gdt::IST_DOUBLE_FAULT_INDEX,
        );

        // Local APIC IRQs (kernel-only). Keep them on the current kernel stack: trap/syscall
        // paths may re-enable interrupts while blocked, and re-entering a shared IRQ IST would
        // reset `rsp` back to that IST top and corrupt the suspended return chain.
        idt[crate::arch::apic::TIMER_VECTOR] =
            IdtEntry::new(timer_handler, selector, kernel_int_gate, 0);
        idt[crate::arch::apic::SPURIOUS_VECTOR] =
            IdtEntry::new(apic_spurious_handler, selector, kernel_int_gate, 0);
        idt[crate::arch::apic::ERROR_VECTOR] =
            IdtEntry::new(apic_error_handler, selector, kernel_int_gate, 0);

        // Fixed-vector IPI used by SMP conformance. (Kernel-only.)
        idt[crate::arch::ipi::TEST_VECTOR] =
            IdtEntry::new(ipi_test_handler, selector, kernel_int_gate, 0);
        idt[crate::arch::ipi::TLB_SHOOTDOWN_VECTOR] =
            IdtEntry::new(ipi_tlb_handler, selector, kernel_int_gate, 0);
        idt[crate::arch::ipi::RESCHEDULE_VECTOR] =
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
        base: IDT.0.get() as u64,
    };

    // SAFETY: `idtr` points to a valid in-memory descriptor for the static IDT table.
    // Use `addr_of!` to avoid creating a reference to the packed struct.
    unsafe {
        core::arch::asm!("lidt [{0}]", in(reg) core::ptr::addr_of!(idtr), options(readonly, nostack, preserves_flags));
    }
}
