//! SMP bring-up scaffolding (Phase B).
//!
//! TODO:
//! - detect CPU count from bootloader
//! - bring up APs (trampoline + per-CPU stack)
//! - per-CPU data + IPI

use core::sync::atomic::{AtomicBool, Ordering};

use raw_cpuid::CpuId;

const TRAMPOLINE_PADDR: u64 = 0x7000;
const MAX_CPUS: usize = 16; // must match `ap_trampoline_params` in assembly
const AP_STACK_SIZE: usize = 16 * 1024;

pub const fn max_cpus() -> usize {
    MAX_CPUS
}

#[repr(C)]
struct ApTrampolineParams {
    cr3: u64,
    entry: u64,
    stacks: [u64; MAX_CPUS],
}

#[repr(align(16))]
#[derive(Clone, Copy)]
struct AlignedApStack([u8; AP_STACK_SIZE]);

static mut AP_STACKS: [AlignedApStack; MAX_CPUS] = [AlignedApStack([0; AP_STACK_SIZE]); MAX_CPUS];

static AP_ONLINE: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

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

fn ap_stack_top(apic_id: usize) -> u64 {
    // SAFETY: AP_STACKS is a static backing store; APIC ids are clamped to MAX_CPUS.
    let base = unsafe { core::ptr::addr_of!(AP_STACKS[apic_id]) as u64 };
    base + (AP_STACK_SIZE as u64)
}

extern "C" fn ap_entry(apic_id: u64) -> ! {
    let apic_id_usize = apic_id as usize;

    crate::arch::init_ap();

    if apic_id_usize < MAX_CPUS {
        AP_ONLINE[apic_id_usize].store(true, Ordering::Release);
    }

    crate::kprintln!("cpu{} online", apic_id);

    crate::object::run_current_cpu_idle_loop()
}

fn bootstrap_trampoline(cpu_count: usize) {
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

        for apic_id in 0..MAX_CPUS {
            let sp = if apic_id < cpu_count {
                ap_stack_top(apic_id)
            } else {
                0
            };
            core::ptr::write_volatile(&mut (*params_ptr).stacks[apic_id], sp);
        }
    }
}

#[allow(dead_code)]
pub fn for_each_online_cpu(mut f: impl FnMut(usize)) {
    let bsp_id = crate::arch::apic::this_apic_id() as usize;
    for apic_id in 0..MAX_CPUS {
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

    bootstrap_trampoline(cpu_count);

    let sipi_vector = (TRAMPOLINE_PADDR / 4096) as u8;

    for apic_id in 0..cpu_count {
        if apic_id == bsp_id {
            continue;
        }

        crate::arch::apic::send_init_ipi(apic_id as u32);
        delay_us(10_000);

        crate::arch::apic::send_startup_ipi(apic_id as u32, sipi_vector);
        delay_us(200);
        crate::arch::apic::send_startup_ipi(apic_id as u32, sipi_vector);
        delay_us(200);
    }

    // Wait for APs.
    for apic_id in 0..cpu_count {
        if apic_id == bsp_id {
            continue;
        }

        let mut spins = 0u64;
        while !AP_ONLINE[apic_id].load(Ordering::Acquire) {
            core::hint::spin_loop();
            spins = spins.wrapping_add(1);
            if spins > 50_000_000 {
                crate::kprintln!("smp: cpu{} did not come online", apic_id);
                break;
            }
        }
    }

    crate::kprintln!("smp: requested cpu_count={}", cpu_count);

    // Minimal SMP sanity check: BSP sends a fixed-vector IPI to one AP and
    // waits for it to ack via the IPI handler.
    if cpu_count > 1 {
        let mut dest = None;
        for apic_id in 0..cpu_count {
            if apic_id != bsp_id {
                dest = Some(apic_id);
                break;
            }
        }

        if let Some(dest) = dest {
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
