//! Minimal per-CPU base (GS base) setup.
//!
//! Sweet-spot goal: establish a per-CPU pointer early so later bring-up can
//! attach scheduler, runqueue, and statistics without refactoring call sites.

use core::mem::offset_of;

use raw_cpuid::CpuId;
use x86_64::registers::model_specific::Msr;

const MAX_CPUS: usize = super::MAX_CPUS;

const IA32_GS_BASE: u32 = 0xC0000101;
const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;

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
        let selectors = crate::arch::gdt::init();
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
}
