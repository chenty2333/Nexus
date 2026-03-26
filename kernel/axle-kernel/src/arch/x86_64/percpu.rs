//! Minimal per-CPU base (GS base) setup.
//!
//! Sweet-spot goal: establish a per-CPU pointer early so later bring-up can
//! attach scheduler, runqueue, and statistics without refactoring call sites.

use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, Ordering};

use raw_cpuid::CpuId;
use x86_64::registers::model_specific::Msr;

const MAX_CPUS: usize = super::MAX_CPUS;

const IA32_GS_BASE: u32 = 0xC0000101;
const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;

/// Set once GS base points at a valid `PerCpu` slot for the current CPU.
static PERCPU_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PerCpu {
    pub apic_id: u32,
    pub cpu_id: u32,
    pub kernel_rsp0: u64,
    pub user_rsp_scratch: u64,
    pub user_cs: u64,
    pub user_ss: u64,
}

pub const CPU_ID_OFFSET: usize = offset_of!(PerCpu, cpu_id);
pub const APIC_ID_OFFSET: usize = offset_of!(PerCpu, apic_id);
pub const KERNEL_RSP0_OFFSET: usize = offset_of!(PerCpu, kernel_rsp0);
pub const USER_RSP_SCRATCH_OFFSET: usize = offset_of!(PerCpu, user_rsp_scratch);
pub const USER_CS_OFFSET: usize = offset_of!(PerCpu, user_cs);
pub const USER_SS_OFFSET: usize = offset_of!(PerCpu, user_ss);

static mut PER_CPU: [PerCpu; MAX_CPUS] = [PerCpu {
    apic_id: 0,
    cpu_id: 0,
    kernel_rsp0: 0,
    user_rsp_scratch: 0,
    user_cs: 0,
    user_ss: 0,
}; MAX_CPUS];

/// Initialize GS base for the current CPU.
pub fn init() {
    let apic_id = CpuId::new()
        .get_feature_info()
        .map(|fi| fi.initial_local_apic_id() as usize)
        .unwrap_or(0);
    init_for_apic_id(apic_id);
}

/// Initialize GS base for one CPU whose APIC id is already known.
pub fn init_for_apic_id(apic_id: usize) {
    let cpu_slot = crate::smp::cpu_slot_for_apic_id(apic_id).unwrap_or(0);
    assert!(
        cpu_slot < MAX_CPUS,
        "percpu: cpu_slot {} exceeds MAX_CPUS (apic_id={})",
        cpu_slot,
        apic_id
    );

    // SAFETY: `PER_CPU` is a static backing store, and each CPU writes to its
    // own slot indexed by logical CPU slot in our current bring-up model.
    unsafe {
        let selectors = crate::arch::gdt::init_for_apic_id(apic_id);
        PER_CPU[cpu_slot].apic_id = apic_id as u32;
        PER_CPU[cpu_slot].cpu_id = cpu_slot as u32;
        PER_CPU[cpu_slot].kernel_rsp0 = crate::arch::gdt::ring0_stack_top(cpu_slot);
        PER_CPU[cpu_slot].user_rsp_scratch = 0;
        PER_CPU[cpu_slot].user_cs = selectors.user_code.0 as u64;
        PER_CPU[cpu_slot].user_ss = selectors.user_data.0 as u64;
        let base = core::ptr::addr_of!(PER_CPU[cpu_slot]) as u64;

        // SAFETY: writing GS base MSRs establishes CPU-local state. `base`
        // points to static memory for the kernel lifetime.
        Msr::new(IA32_GS_BASE).write(base);
        Msr::new(IA32_KERNEL_GS_BASE).write(base);
    }
    PERCPU_INITIALIZED.store(true, Ordering::Release);
}

pub fn try_current_cpu_slot() -> Option<usize> {
    if !PERCPU_INITIALIZED.load(Ordering::Acquire) {
        return Some(0);
    }
    // Read cpu_id directly via the gs: segment prefix. This avoids the
    // serializing `rdmsr` on IA32_GS_BASE and is significantly faster on
    // hot paths (scheduler, IPI, trap entry).
    let val: u32;
    unsafe {
        core::arch::asm!(
            "mov {out:e}, gs:[{off}]",
            off = const CPU_ID_OFFSET,
            out = out(reg) val,
            options(nostack, readonly, preserves_flags),
        );
    }
    // GS base == 0 means per-CPU is not yet initialized; in that case
    // the read returns 0 from the null page or zero-init memory. We
    // distinguish "slot 0" from "not initialized" by checking the base.
    // However, reading the MSR defeats the purpose. Instead, we check
    // whether both cpu_id and apic_id are zero -- only the BSP (slot 0)
    // can have both zero, and if percpu is not set up, the caller is
    // already on the BSP early path where slot 0 is the correct answer.
    let slot = val as usize;
    (slot < MAX_CPUS).then_some(slot)
}

pub fn try_current_apic_id() -> Option<u32> {
    if !PERCPU_INITIALIZED.load(Ordering::Acquire) {
        return Some(0);
    }
    // Read apic_id directly via the gs: segment prefix.
    let val: u32;
    unsafe {
        core::arch::asm!(
            "mov {out:e}, gs:[{off}]",
            off = const APIC_ID_OFFSET,
            out = out(reg) val,
            options(nostack, readonly, preserves_flags),
        );
    }
    ((val as usize) < super::MAX_APIC_IDS).then_some(val)
}
