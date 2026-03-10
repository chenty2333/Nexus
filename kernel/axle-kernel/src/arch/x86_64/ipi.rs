//! Fixed-vector IPI support (bring-up / conformance / TLB shootdown / reschedule).

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use raw_cpuid::CpuId;
use spin::Mutex;

use crate::arch::apic;

pub const TEST_VECTOR: usize = 0x40;
pub const TLB_SHOOTDOWN_VECTOR: usize = 0x41;
pub const RESCHEDULE_VECTOR: usize = 0x42;

const MAX_CPUS: usize = 16;

static IPI_ACK_COUNT: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static TLB_SHOOTDOWN_ACK: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static TLB_SHOOTDOWN_MODE: AtomicU8 = AtomicU8::new(0);
static TLB_SHOOTDOWN_PAGE: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TLB_SHOOTDOWN_LOCK: Mutex<()> = Mutex::new(());

const TLB_MODE_NONE: u8 = 0;
const TLB_MODE_PAGE: u8 = 1;
const TLB_MODE_FULL: u8 = 2;

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
    .macro AXLE_IPI_ENTRY name, rust
    .global \name
    .type \name, @function
\name:
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
    call \rust

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
    .size \name, .-\name
    .endm

    AXLE_IPI_ENTRY axle_ipi_test_entry, {rust_test}
    AXLE_IPI_ENTRY axle_ipi_tlb_entry, {rust_tlb}
    AXLE_IPI_ENTRY axle_ipi_reschedule_entry, {rust_resched}
    "#,
    rust_test = sym axle_ipi_test_rust,
    rust_tlb = sym axle_ipi_tlb_rust,
    rust_resched = sym axle_ipi_reschedule_rust,
);

unsafe extern "C" {
    fn axle_ipi_test_entry();
    fn axle_ipi_tlb_entry();
    fn axle_ipi_reschedule_entry();
}

/// Address of the IPI test handler entry stub for IDT installation.
pub fn test_entry_addr() -> usize {
    axle_ipi_test_entry as *const () as usize
}

/// Address of the TLB shootdown IPI handler entry stub for IDT installation.
pub fn tlb_entry_addr() -> usize {
    axle_ipi_tlb_entry as *const () as usize
}

/// Address of the reschedule IPI handler entry stub for IDT installation.
pub fn reschedule_entry_addr() -> usize {
    axle_ipi_reschedule_entry as *const () as usize
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

extern "C" fn axle_ipi_tlb_rust(_frame: *const u8) {
    apic::eoi();

    let apic_id = CpuId::new()
        .get_feature_info()
        .map(|fi| fi.initial_local_apic_id() as usize)
        .unwrap_or(0);
    match TLB_SHOOTDOWN_MODE.load(Ordering::Acquire) {
        TLB_MODE_PAGE => {
            let page = TLB_SHOOTDOWN_PAGE.load(Ordering::Acquire);
            if page != 0 {
                crate::arch::tlb::flush_page_local(page);
            }
        }
        TLB_MODE_FULL => crate::arch::tlb::flush_all_local(),
        _ => {}
    }

    if apic_id < MAX_CPUS {
        let _ = TLB_SHOOTDOWN_ACK[apic_id].fetch_add(1, Ordering::AcqRel);
    }
}

extern "C" fn axle_ipi_reschedule_rust(_frame: *const u8) {
    // The waking CPU updates scheduler state before sending this IPI.
    // The target CPU only needs an interrupt to break out of `hlt`/trap blocking.
    apic::eoi();
}

#[allow(dead_code)]
fn tlb_ack_count(apic_id: usize) -> u64 {
    if apic_id >= MAX_CPUS {
        return 0;
    }
    TLB_SHOOTDOWN_ACK[apic_id].load(Ordering::Acquire)
}

#[allow(dead_code)]
pub fn shootdown_page(va: u64) {
    let _guard = TLB_SHOOTDOWN_LOCK.lock();
    TLB_SHOOTDOWN_MODE.store(TLB_MODE_PAGE, Ordering::Release);
    TLB_SHOOTDOWN_PAGE.store(va, Ordering::Release);

    let local_apic_id = apic::this_apic_id() as usize;
    crate::smp::for_each_online_cpu(|apic_id| {
        if apic_id == local_apic_id {
            return;
        }

        let before = tlb_ack_count(apic_id);
        apic::send_fixed_ipi(apic_id as u32, TLB_SHOOTDOWN_VECTOR as u8);

        let start = crate::time::rdtsc();
        let delta = crate::time::ns_to_tsc(250_000_000);
        while tlb_ack_count(apic_id) == before {
            core::hint::spin_loop();
            if delta != 0 && crate::time::rdtsc().wrapping_sub(start) > delta {
                break;
            }
        }
    });

    TLB_SHOOTDOWN_PAGE.store(0, Ordering::Release);
    TLB_SHOOTDOWN_MODE.store(TLB_MODE_NONE, Ordering::Release);
}

pub fn shootdown_all(apic_ids: &[usize]) {
    let _guard = TLB_SHOOTDOWN_LOCK.lock();
    TLB_SHOOTDOWN_MODE.store(TLB_MODE_FULL, Ordering::Release);
    TLB_SHOOTDOWN_PAGE.store(0, Ordering::Release);

    for &apic_id in apic_ids {
        if apic_id == apic::this_apic_id() as usize {
            continue;
        }
        let before = tlb_ack_count(apic_id);
        apic::send_fixed_ipi(apic_id as u32, TLB_SHOOTDOWN_VECTOR as u8);

        let start = crate::time::rdtsc();
        let delta = crate::time::ns_to_tsc(250_000_000);
        while tlb_ack_count(apic_id) == before {
            core::hint::spin_loop();
            if delta != 0 && crate::time::rdtsc().wrapping_sub(start) > delta {
                break;
            }
        }
    }

    TLB_SHOOTDOWN_MODE.store(TLB_MODE_NONE, Ordering::Release);
}

/// Send one reschedule IPI to `apic_id`.
pub fn send_reschedule(apic_id: usize) {
    if apic_id >= MAX_CPUS {
        return;
    }
    apic::send_fixed_ipi(apic_id as u32, RESCHEDULE_VECTOR as u8);
}
