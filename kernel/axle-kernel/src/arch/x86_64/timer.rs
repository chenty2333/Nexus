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

static USE_TSC_DEADLINE: AtomicBool = AtomicBool::new(false);

/// Initialize the BSP local APIC + a periodic timer interrupt.
pub fn init_bsp() {
    let tsc_deadline = CpuId::new()
        .get_feature_info()
        .is_some_and(|fi| fi.has_tsc_deadline());

    USE_TSC_DEADLINE.store(tsc_deadline, Ordering::Relaxed);

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
    crate::object::on_tick();
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
    call {rust_handler}

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

extern "C" fn axle_timer_rust(_frame: *const u8) {
    // Acknowledge first, then drive higher-level timer logic.
    apic::eoi();
    on_tick();

    if USE_TSC_DEADLINE.load(Ordering::Relaxed) {
        arm_next_tick();
    }
}

/// For tests/diagnostics.
#[allow(dead_code)]
pub fn tick_ns() -> u64 {
    TICK_NS
}
