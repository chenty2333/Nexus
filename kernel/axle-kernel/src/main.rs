//! Axle kernel (Phase B bring-up skeleton).
//!
//! This is intentionally tiny: boot -> serial -> halt.
//! The goal is to provide a concrete place for BSP init, SMP bring-up, and syscall/trap scaffolding.

#![no_std]
#![no_main]

mod arch;
mod bringup;
mod futex;
mod kalloc;
mod object;
mod page_table;
mod pmm;
mod port_queue;
mod smp;
mod syscall;
mod task;
mod time;
mod trap;
mod userspace;

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
    pmm::init();
    kalloc::init_late_heap();

    kprintln!("Axle kernel: hello from _start()");
    kprintln!("(Phase B skeleton)");

    syscall::init();
    trap::init();

    // Hardware interrupt bring-up.
    arch::pic::mask_all();
    time::init();
    arch::timer::init_bsp();

    // Mutate bootstrap page tables (userspace map) before bringing up APs.
    let user_entry = userspace::prepare();

    smp::init();

    // Bring-up bridge: execute conformance in ring3 (userspace) and report results via `int3`.
    userspace::enter(user_entry);
}
