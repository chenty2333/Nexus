//! Axle kernel (Phase B bring-up skeleton).
//!
//! This is intentionally tiny: boot -> serial -> halt.
//! The goal is to provide a concrete place for BSP init, SMP bring-up, and syscall/trap scaffolding.

#![no_std]
#![no_main]

mod arch;
mod smp;
mod syscall;
mod trap;

use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Use the minimal serial logger even in panic.
    kprintln!("KERNEL PANIC: {info}");
    arch::cpu::halt_loop();
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    arch::init();

    kprintln!("Axle kernel: hello from _start()");
    kprintln!("(Phase B skeleton)");

    // TODO(B): install IDT, enable interrupts, init heap, bring up SMP, etc.
    trap::init();
    syscall::init();
    smp::init();

    arch::cpu::halt_loop();
}
