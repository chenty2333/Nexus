//! Local APIC timer bring-up (wakeup source).
//!
//! We use the local APIC timer in TSC-deadline mode when available. This gives
//! a stable periodic wakeup without needing PIT/HPET calibration.

use core::sync::atomic::{AtomicBool, Ordering};
use raw_cpuid::CpuId;
use x86_64::registers::model_specific::Msr;

use crate::arch::apic;

const IA32_TSC_DEADLINE: u32 = 0x6E0;

// 1ms tick is enough to avoid busy-waiting and keep conformance stable.
const TICK_NS: u64 = 1_000_000;

static TICKS_ALL_CPUS: AtomicBool = AtomicBool::new(false);
static USE_TSC_DEADLINE: AtomicBool = AtomicBool::new(false);

/// Initialize the BSP local APIC + a periodic timer interrupt.
pub fn init_bsp() {
    let tsc_deadline = CpuId::new()
        .get_feature_info()
        .is_some_and(|fi| fi.has_tsc_deadline());

    USE_TSC_DEADLINE.store(tsc_deadline, Ordering::Relaxed);
    TICKS_ALL_CPUS.store(true, Ordering::Relaxed);

    apic::init_bsp();

    if tsc_deadline {
        // Put the APIC timer in TSC-deadline mode (already configured by `apic::init_bsp()`).
        arm_next_tick();
    } else {
        // Periodic mode runs from the initial count configured in `apic::init_bsp()`.
        //
        // NOTE: without calibration this is only "some periodic interrupt". We
        // keep conformance deadlines coarse so this is sufficient for now.
        crate::kprintln!("timer: TSC-deadline unsupported; using periodic APIC timer");
    }
}

/// Initialize an AP local timer using the same per-CPU periodic wakeup contract as the BSP.
pub fn init_ap() {
    let tsc_deadline = CpuId::new()
        .get_feature_info()
        .is_some_and(|fi| fi.has_tsc_deadline());

    crate::arch::apic::init_ap(true);

    if tsc_deadline {
        USE_TSC_DEADLINE.store(true, Ordering::Relaxed);
        arm_next_tick();
    }
    TICKS_ALL_CPUS.store(true, Ordering::Relaxed);
}

/// Phase-one scheduler shape: every online CPU receives a local tick. TSC-deadline is preferred,
/// but a coarse periodic APIC timer is still good enough to preserve basic time slicing and wake
/// processing on fallback hardware.
pub fn ticks_all_cpus() -> bool {
    TICKS_ALL_CPUS.load(Ordering::Relaxed)
}

fn arm_next_tick() {
    let now = crate::time::rdtsc();
    let delta = crate::time::ns_to_tsc(TICK_NS);
    let deadline = now.wrapping_add(delta);

    // SAFETY: writing IA32_TSC_DEADLINE arms the local APIC timer in
    // TSC-deadline mode. Requires CPU support + APIC timer configured to
    // TSC-deadline.
    unsafe {
        Msr::new(IA32_TSC_DEADLINE).write(deadline);
    }
}

/// Called from the timer interrupt handler.
fn on_tick() {
    crate::time::on_tick();
    crate::wait::on_tick();
}

// --- IDT entry stub ---

core::arch::global_asm!(
    r#"
    .global axle_timer_entry
    .type axle_timer_entry, @function
axle_timer_entry:
    // Save a conservative snapshot of registers.
    push r15
    push r14
    push r13
    push r12
    push rbx
    push rbp
    push r11
    push rcx
    push r9
    push r8
    push r10
    push rdx
    push rsi
    push rdi
    push rax

    mov rdi, rsp
    lea rsi, [rsp + 15*8]
    call {rust_handler}

    // Restore the interrupted/trap-updated rax before returning to user mode.
    mov rax, [rsp + 0]
    add rsp, 8
    pop rdi
    pop rsi
    pop rdx
    pop r10
    pop r8
    pop r9
    pop rcx
    pop r11
    pop rbp
    pop rbx
    pop r12
    pop r13
    pop r14
    pop r15
    iretq
    .size axle_timer_entry, .-axle_timer_entry
    "#,
    rust_handler = sym axle_timer_rust,
);

unsafe extern "C" {
    fn axle_timer_entry();
}

/// Address of the timer interrupt handler entry stub.
pub fn entry_addr() -> usize {
    axle_timer_entry as *const () as usize
}

extern "C" fn axle_timer_rust(frame: &mut crate::arch::int80::TrapFrame, cpu_frame: *mut u64) {
    // Acknowledge first, then drive higher-level timer logic.
    apic::eoi();

    let from_user = if cpu_frame.is_null() {
        false
    } else {
        // SAFETY: the timer stub passes the pointer to the CPU-saved IRET frame. Reading the CS
        // slot is valid for both kernel- and user-origin interrupts.
        unsafe { (*cpu_frame.add(1) & 0b11) == 0b11 }
    };
    on_tick();
    let now = crate::time::now_ns();
    let needs_trap_exit = crate::object::timer_interrupt_requires_trap_exit(now).unwrap_or(false);
    crate::trace::record_timer_fire(from_user, needs_trap_exit);
    if from_user && needs_trap_exit {
        let _ = crate::object::finish_timer_interrupt(frame, cpu_frame);
    }

    if USE_TSC_DEADLINE.load(Ordering::Relaxed) {
        arm_next_tick();
    }
}

/// For tests/diagnostics.
#[allow(dead_code)]
pub fn tick_ns() -> u64 {
    TICK_NS
}
