//! x86_64 architecture support (very early bring-up).

use x86_64::registers::model_specific::{Efer, EferFlags};

pub const MAX_CPUS: usize = 16;
pub const MAX_APIC_IDS: usize = 256;

pub mod apic;
pub mod breakpoint;
pub mod cpu;
pub mod cpuid;
pub mod fault;
pub mod fpu;
pub mod gdt;
pub mod idt;
pub mod int80;
#[cfg(feature = "hardware-irq")]
pub(crate) mod ioapic;
pub mod ipi;
pub mod log;
pub mod pci;
pub mod percpu;
pub mod pic;
pub mod pmu;
pub mod pvh;
pub mod qemu;
pub mod serial;
pub mod syscall;
pub mod timer;
pub mod tlb;
pub mod user_tls;

/// Early arch init (before heap/interrupts).
pub fn init() {
    // Safe to call multiple times; serial init is idempotent.
    serial::init();
    cpuid::log_boot_cpu_info();
    enable_no_execute();

    // Install a real GDT/TSS so ring3 can enter the kernel through the IDT.
    let _ = gdt::init();
    percpu::init();
    tlb::init_cpu();
    syscall::init_cpu();
    fpu::init_cpu();
    pmu::init_cpu();
}

/// Minimal AP init: load GDT/TSS/IDT, set per-CPU base, enable local APIC, and
/// arm the CPU-local scheduler tick.
pub fn init_ap(apic_id: usize) {
    serial::init();
    enable_no_execute();
    let _ = gdt::init_for_apic_id(apic_id);
    idt::load();
    percpu::init_for_apic_id(apic_id);
    tlb::init_cpu();
    syscall::init_cpu();
    fpu::init_cpu();
    pmu::init_cpu();
    timer::init_ap();
}

fn enable_no_execute() {
    // SAFETY: enabling NXE only turns on hardware interpretation of the NX bit
    // in page-table entries while preserving the rest of EFER. Axle already
    // runs in long mode before calling this helper.
    unsafe {
        Efer::update(|flags| flags.insert(EferFlags::NO_EXECUTE_ENABLE));
    }
}
