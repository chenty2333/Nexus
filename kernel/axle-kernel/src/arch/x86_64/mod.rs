//! x86_64 architecture support (very early bring-up).

pub mod apic;
pub mod breakpoint;
pub mod cpu;
pub mod cpuid;
pub mod fault;
pub mod gdt;
pub mod idt;
pub mod int80;
pub mod log;
pub mod pic;
pub mod pvh;
pub mod qemu;
pub mod serial;
pub mod timer;

/// Early arch init (before heap/interrupts).
pub fn init() {
    // Safe to call multiple times; serial init is idempotent.
    serial::init();
    cpuid::log_boot_cpu_info();

    // Install a real GDT/TSS so ring3 can enter the kernel through the IDT.
    let _ = gdt::init();
}
