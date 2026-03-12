//! SMP bring-up scaffolding (Phase B).
//!
//! TODO:
//! - detect CPU count from bootloader
//! - bring up APs (trampoline + per-CPU stack)
//! - per-CPU data + IPI

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use raw_cpuid::CpuId;

const TRAMPOLINE_PADDR: u64 = 0x7000;
const MAX_CPUS: usize = crate::arch::MAX_CPUS;
const MAX_APIC_IDS: usize = crate::arch::MAX_APIC_IDS; // must match `ap_trampoline_params` in assembly
const AP_STACK_SIZE: usize = 16 * 1024;

pub const fn max_cpus() -> usize {
    MAX_CPUS
}

#[repr(C)]
struct ApTrampolineParams {
    cr3: u64,
    entry: u64,
    stacks: [u64; MAX_APIC_IDS],
}

#[repr(align(16))]
#[derive(Clone, Copy)]
struct AlignedApStack([u8; AP_STACK_SIZE]);

static mut AP_STACKS: [AlignedApStack; MAX_CPUS] = [AlignedApStack([0; AP_STACK_SIZE]); MAX_CPUS];

static AP_ONLINE: [AtomicBool; MAX_APIC_IDS] = [const { AtomicBool::new(false) }; MAX_APIC_IDS];
static APIC_ID_TO_SLOT: [AtomicUsize; MAX_APIC_IDS] =
    [const { AtomicUsize::new(usize::MAX) }; MAX_APIC_IDS];
static NEXT_CPU_SLOT: AtomicUsize = AtomicUsize::new(1);

core::arch::global_asm!(
    include_str!("arch/x86_64/ap_trampoline.S"),
    options(att_syntax)
);

unsafe extern "C" {
    static ap_trampoline_start: u8;
    static ap_trampoline_end: u8;
    static ap_trampoline_params: u8;
}

fn read_cr3() -> u64 {
    let cr3: u64;
    // SAFETY: reading CR3 is side-effect free.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

fn delay_us(us: u64) {
    let start = crate::time::rdtsc();
    let delta = crate::time::ns_to_tsc(us.saturating_mul(1000));
    if delta == 0 {
        // Worst-case fallback: approximate delay.
        for _ in 0..(us.saturating_mul(1000)) {
            core::hint::spin_loop();
        }
        return;
    }
    while crate::time::rdtsc().wrapping_sub(start) < delta {
        core::hint::spin_loop();
    }
}

fn ap_stack_top(slot: usize) -> u64 {
    // SAFETY: AP_STACKS is a static backing store; slots are clamped to MAX_CPUS.
    let base = unsafe { core::ptr::addr_of!(AP_STACKS[slot]) as u64 };
    base + (AP_STACK_SIZE as u64)
}

extern "C" fn ap_entry(apic_id: u64) -> ! {
    let apic_id_usize = apic_id as usize;
    let cpu_slot = register_apic_slot(apic_id_usize);

    crate::arch::init_ap();

    if apic_id_usize < MAX_APIC_IDS
        && AP_ONLINE[apic_id_usize]
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        crate::kprintln!("cpu{} online", cpu_slot);
    }

    crate::object::run_current_cpu_idle_loop()
}

fn bootstrap_trampoline() {
    let src_start = core::ptr::addr_of!(ap_trampoline_start) as usize;
    let src_end = core::ptr::addr_of!(ap_trampoline_end) as usize;
    let len = src_end.saturating_sub(src_start);
    assert!(len > 0 && len <= 4096);

    // SAFETY: we copy the trampoline bytes into low physical memory that is
    // currently identity-mapped and reserved for SIPI startup.
    unsafe {
        core::ptr::copy_nonoverlapping(src_start as *const u8, TRAMPOLINE_PADDR as *mut u8, len);
    }

    let params_off = (core::ptr::addr_of!(ap_trampoline_params) as usize).saturating_sub(src_start);
    let params_ptr = (TRAMPOLINE_PADDR as usize + params_off) as *mut ApTrampolineParams;

    let cr3 = read_cr3();
    let entry = ap_entry as *const () as u64;

    // SAFETY: params live in the copied trampoline page.
    unsafe {
        core::ptr::write_volatile(&mut (*params_ptr).cr3, cr3);
        core::ptr::write_volatile(&mut (*params_ptr).entry, entry);

        for apic_id in 0..MAX_APIC_IDS {
            core::ptr::write_volatile(&mut (*params_ptr).stacks[apic_id], 0);
        }
    }
}

fn install_trampoline_stack(candidate_apic_id: usize, stack_top: u64) {
    let src_start = core::ptr::addr_of!(ap_trampoline_start) as usize;
    let params_off = (core::ptr::addr_of!(ap_trampoline_params) as usize).saturating_sub(src_start);
    let params_ptr = (TRAMPOLINE_PADDR as usize + params_off) as *mut ApTrampolineParams;
    // SAFETY: the trampoline params live in the copied low-memory page, and BSP-only bring-up
    // mutates one candidate slot before sending INIT/SIPI to that APIC id.
    unsafe {
        core::ptr::write_volatile(&mut (*params_ptr).stacks[candidate_apic_id], stack_top);
    }
}

fn online_ap_count() -> usize {
    AP_ONLINE
        .iter()
        .filter(|online| online.load(Ordering::Acquire))
        .count()
}

pub fn cpu_slot_for_apic_id(apic_id: usize) -> Option<usize> {
    (apic_id < MAX_APIC_IDS)
        .then(|| APIC_ID_TO_SLOT[apic_id].load(Ordering::Acquire))
        .filter(|slot| *slot != usize::MAX)
}

fn register_apic_slot(apic_id: usize) -> usize {
    assert!(
        apic_id < MAX_APIC_IDS,
        "smp: apic_id {} exceeds MAX_APIC_IDS",
        apic_id
    );
    if let Some(slot) = cpu_slot_for_apic_id(apic_id) {
        return slot;
    }

    let slot = NEXT_CPU_SLOT.fetch_add(1, Ordering::AcqRel);
    assert!(slot < MAX_CPUS, "smp: cpu slot {} exceeds MAX_CPUS", slot);
    match APIC_ID_TO_SLOT[apic_id].compare_exchange(
        usize::MAX,
        slot,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => slot,
        Err(existing) if existing != usize::MAX => existing,
        Err(_) => unreachable!("compare_exchange returned sentinel after allocation"),
    }
}

fn first_online_apic_id() -> Option<usize> {
    AP_ONLINE
        .iter()
        .enumerate()
        .find_map(|(apic_id, online)| online.load(Ordering::Acquire).then_some(apic_id))
}

#[allow(dead_code)]
pub fn for_each_online_cpu(mut f: impl FnMut(usize)) {
    let bsp_id = crate::arch::apic::this_apic_id() as usize;
    for apic_id in 0..MAX_APIC_IDS {
        if apic_id == bsp_id || AP_ONLINE[apic_id].load(Ordering::Acquire) {
            f(apic_id);
        }
    }
}

pub fn init() {
    // Bring-up CPU enumeration: rely on CPUID's "max logical processors".
    let cpuid = CpuId::new();
    let mut cpu_count = cpuid
        .get_feature_info()
        .map(|fi| fi.max_logical_processor_ids() as usize)
        .unwrap_or(1);
    if cpu_count == 0 {
        cpu_count = 1;
    }
    cpu_count = cpu_count.min(MAX_CPUS);

    let bsp_id = crate::arch::apic::this_apic_id() as usize;
    assert!(
        bsp_id < MAX_APIC_IDS,
        "smp: bsp apic_id {} exceeds MAX_APIC_IDS",
        bsp_id
    );
    NEXT_CPU_SLOT.store(1, Ordering::Release);
    for online in &AP_ONLINE {
        online.store(false, Ordering::Release);
    }
    for slot in &APIC_ID_TO_SLOT {
        slot.store(usize::MAX, Ordering::Release);
    }
    APIC_ID_TO_SLOT[bsp_id].store(0, Ordering::Release);

    bootstrap_trampoline();

    let sipi_vector = (TRAMPOLINE_PADDR / 4096) as u8;

    let target_ap_count = cpu_count.saturating_sub(1);
    let mut next_stack_slot = 0usize;
    for candidate_apic_id in 0..MAX_APIC_IDS {
        if next_stack_slot >= target_ap_count {
            break;
        }
        if candidate_apic_id == bsp_id {
            continue;
        }

        install_trampoline_stack(candidate_apic_id, ap_stack_top(next_stack_slot));

        crate::arch::apic::send_init_ipi(candidate_apic_id as u32);
        delay_us(10_000);

        crate::arch::apic::send_startup_ipi(candidate_apic_id as u32, sipi_vector);
        delay_us(200);
        crate::arch::apic::send_startup_ipi(candidate_apic_id as u32, sipi_vector);
        delay_us(200);
        let mut spins = 0u64;
        while !AP_ONLINE[candidate_apic_id].load(Ordering::Acquire) {
            core::hint::spin_loop();
            spins = spins.wrapping_add(1);
            if spins > 10_000_000 {
                break;
            }
        }
        if AP_ONLINE[candidate_apic_id].load(Ordering::Acquire) {
            next_stack_slot += 1;
        }
    }

    crate::kprintln!("smp: requested cpu_count={}", cpu_count);
    if online_ap_count() < target_ap_count {
        crate::kprintln!(
            "smp: online_ap_count={} target_ap_count={}",
            online_ap_count(),
            target_ap_count
        );
    }

    // Minimal SMP sanity check: BSP sends a fixed-vector IPI to one AP and
    // waits for it to ack via the IPI handler.
    if cpu_count > 1 {
        if let Some(dest) = first_online_apic_id() {
            let before = crate::arch::ipi::ack_count(dest);

            crate::arch::apic::send_fixed_ipi(dest as u32, crate::arch::ipi::TEST_VECTOR as u8);

            let start = crate::time::rdtsc();
            let delta = crate::time::ns_to_tsc(250_000_000); // 250ms
            while crate::arch::ipi::ack_count(dest) == before {
                core::hint::spin_loop();
                if delta != 0 && crate::time::rdtsc().wrapping_sub(start) > delta {
                    break;
                }
            }

            let ok = crate::arch::ipi::ack_count(dest) != before;
            crate::kprintln!(
                "smp: ipi_ack={} dest={} vector=0x{:02x}",
                if ok { 1 } else { 0 },
                dest,
                crate::arch::ipi::TEST_VECTOR
            );
        }
    }
}
