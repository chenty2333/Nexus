//! Fixed-vector IPI support (bring-up / conformance / TLB shootdown / reschedule).

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use axle_page_table::PageRange;
use axle_types::status::ZX_ERR_TIMED_OUT;
use axle_types::zx_status_t;
use spin::Mutex;

use crate::arch::apic;

pub const TEST_VECTOR: usize = 0x40;
pub const TLB_SHOOTDOWN_VECTOR: usize = 0x41;
pub const RESCHEDULE_VECTOR: usize = 0x42;

const MAX_CPUS: usize = super::MAX_APIC_IDS;

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
    .size \name, .-\name
    .endm

    AXLE_IPI_ENTRY axle_ipi_test_entry, {rust_test}
    AXLE_IPI_ENTRY axle_ipi_tlb_entry, {rust_tlb}

    .global axle_ipi_reschedule_entry
    .type axle_ipi_reschedule_entry, @function
axle_ipi_reschedule_entry:
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
    call {rust_resched}

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
    .size axle_ipi_reschedule_entry, .-axle_ipi_reschedule_entry
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

    let apic_id = apic::this_apic_id() as usize;

    if apic_id < MAX_CPUS {
        let _ = IPI_ACK_COUNT[apic_id].fetch_add(1, Ordering::AcqRel);
    }
}

extern "C" fn axle_ipi_tlb_rust(_frame: *const u8) {
    // Read shootdown parameters into locals BEFORE sending EOI so that the
    // initiator cannot overwrite them with a new request once we de-assert
    // the in-service bit.
    let mode = TLB_SHOOTDOWN_MODE.load(Ordering::Acquire);
    let page = TLB_SHOOTDOWN_PAGE.load(Ordering::Acquire);

    match mode {
        TLB_MODE_PAGE => {
            if page != 0 {
                crate::arch::tlb::flush_page_local(page);
            }
        }
        TLB_MODE_FULL => crate::arch::tlb::flush_all_local(),
        _ => {}
    }

    let apic_id = apic::this_apic_id() as usize;
    if apic_id < MAX_CPUS {
        let _ = TLB_SHOOTDOWN_ACK[apic_id].fetch_add(1, Ordering::AcqRel);
    }

    // EOI after ack so the initiator observes the ack before we can take
    // another IPI on the same vector.
    apic::eoi();
}

extern "C" fn axle_ipi_reschedule_rust(
    frame: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *mut u64,
) {
    // The waking CPU updates scheduler state before sending this IPI.
    // If this hit user mode, turn it into an immediate trap-exit so the target CPU can observe
    // `reschedule_requested` without waiting for a later syscall or timer edge.
    apic::eoi();
    let from_user = if cpu_frame.is_null() {
        false
    } else {
        // SAFETY: the reschedule IPI stub passes the pointer to the CPU-saved IRET frame.
        // Reading the saved CS slot is valid for both kernel- and user-origin interrupts.
        unsafe { (*cpu_frame.add(1) & 0b11) == 0b11 }
    };
    crate::trace::record_sched_irq_enter(from_user);
    crate::trace::record_resched_ipi(from_user);
    let mut trap_exit_taken = false;
    if from_user {
        trap_exit_taken = crate::object::finish_reschedule_interrupt(frame, cpu_frame).is_ok();
    }
    crate::trace::record_sched_irq_exit(from_user, trap_exit_taken);
}

#[allow(dead_code)]
fn tlb_ack_count(apic_id: usize) -> u64 {
    if apic_id >= MAX_CPUS {
        return 0;
    }
    TLB_SHOOTDOWN_ACK[apic_id].load(Ordering::Acquire)
}

fn apic_id_mask(apic_ids: &[usize]) -> u64 {
    let mut mask = 0_u64;
    for &apic_id in apic_ids {
        if apic_id < u64::BITS as usize {
            mask |= 1_u64 << apic_id;
        }
    }
    mask
}

#[allow(dead_code)]
pub fn shootdown_page(va: u64) -> Result<(), zx_status_t> {
    let mut remote_cpus = Vec::new();
    let local_apic_id = apic::this_apic_id() as usize;
    crate::smp::for_each_online_cpu(|apic_id| {
        if apic_id != local_apic_id {
            remote_cpus.push(apic_id);
        }
    });
    shootdown_page_targets(va, &remote_cpus)
}

pub fn shootdown_range(apic_ids: &[usize], range: PageRange) -> Result<(), zx_status_t> {
    let mut page = range.base();
    while page < range.end() {
        shootdown_page_targets(page, apic_ids)?;
        page = page.wrapping_add(axle_page_table::PAGE_SIZE);
    }
    Ok(())
}

fn shootdown_page_targets(va: u64, apic_ids: &[usize]) -> Result<(), zx_status_t> {
    let _guard = TLB_SHOOTDOWN_LOCK.lock();
    TLB_SHOOTDOWN_MODE.store(TLB_MODE_PAGE, Ordering::Release);
    TLB_SHOOTDOWN_PAGE.store(va, Ordering::Release);

    let mut result = Ok(());
    let mut target_mask = 0_u64;
    for &apic_id in apic_ids {
        if result.is_err() {
            break;
        }
        if apic_id < u64::BITS as usize {
            target_mask |= 1_u64 << apic_id;
        }

        let before = tlb_ack_count(apic_id);
        apic::send_fixed_ipi(apic_id as u32, TLB_SHOOTDOWN_VECTOR as u8);

        let start = crate::time::rdtsc();
        let delta = crate::time::ns_to_tsc(250_000_000);
        while tlb_ack_count(apic_id) == before {
            core::hint::spin_loop();
            if delta != 0 && crate::time::rdtsc().wrapping_sub(start) > delta {
                crate::kprintln!(
                    "ipi: page shootdown timed out waiting for cpu{} ack",
                    apic_id
                );
                result = Err(ZX_ERR_TIMED_OUT);
                break;
            }
        }
    }

    crate::trace::record_tlb_shootdown_page(va, target_mask);

    TLB_SHOOTDOWN_PAGE.store(0, Ordering::Release);
    TLB_SHOOTDOWN_MODE.store(TLB_MODE_NONE, Ordering::Release);
    result
}

pub fn shootdown_all(apic_ids: &[usize]) -> Result<(), zx_status_t> {
    let _guard = TLB_SHOOTDOWN_LOCK.lock();
    TLB_SHOOTDOWN_MODE.store(TLB_MODE_FULL, Ordering::Release);
    TLB_SHOOTDOWN_PAGE.store(0, Ordering::Release);
    crate::trace::record_tlb_shootdown_all(apic_id_mask(apic_ids));

    let mut result = Ok(());
    for &apic_id in apic_ids {
        if result.is_err() {
            break;
        }
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
                crate::kprintln!(
                    "ipi: full shootdown timed out waiting for cpu{} ack",
                    apic_id
                );
                result = Err(ZX_ERR_TIMED_OUT);
                break;
            }
        }
    }

    TLB_SHOOTDOWN_MODE.store(TLB_MODE_NONE, Ordering::Release);
    result
}

/// Send one reschedule IPI to `apic_id`.
pub fn send_reschedule(apic_id: usize) {
    if apic_id >= MAX_CPUS {
        return;
    }
    apic::send_fixed_ipi(apic_id as u32, RESCHEDULE_VECTOR as u8);
}
