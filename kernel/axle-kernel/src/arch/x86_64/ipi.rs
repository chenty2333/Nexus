//! Fixed-vector IPI support (bring-up / conformance).
//!
//! We use this for a simple SMP sanity check:
//! BSP sends a fixed-vector IPI to an AP, AP runs this handler and increments
//! an ack counter, BSP observes the counter change.

use core::sync::atomic::{AtomicU64, Ordering};

use raw_cpuid::CpuId;

use crate::arch::apic;

pub const TEST_VECTOR: usize = 0x40;

const MAX_CPUS: usize = 16;

static IPI_ACK_COUNT: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Current ack counter value for `apic_id`.
pub fn ack_count(apic_id: usize) -> u64 {
    if apic_id >= MAX_CPUS {
        return 0;
    }
    IPI_ACK_COUNT[apic_id].load(Ordering::Acquire)
}

// --- IDT entry stub (kernel-only) ---

core::arch::global_asm!(
    r#"
    .global axle_ipi_test_entry
    .type axle_ipi_test_entry, @function
axle_ipi_test_entry:
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
    .size axle_ipi_test_entry, .-axle_ipi_test_entry
    "#,
    rust_handler = sym axle_ipi_test_rust,
);

unsafe extern "C" {
    fn axle_ipi_test_entry();
}

/// Address of the IPI handler entry stub for IDT installation.
pub fn entry_addr() -> usize {
    axle_ipi_test_entry as *const () as usize
}

extern "C" fn axle_ipi_test_rust(_frame: *const u8) {
    // Acknowledge first to minimize time spent in-service.
    apic::eoi();

    let apic_id = CpuId::new()
        .get_feature_info()
        .map(|fi| fi.initial_local_apic_id() as usize)
        .unwrap_or(0);

    if apic_id < MAX_CPUS {
        let _ = IPI_ACK_COUNT[apic_id].fetch_add(1, Ordering::AcqRel);
    }
}
