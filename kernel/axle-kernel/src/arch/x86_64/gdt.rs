//! GDT/TSS setup for ring3 bring-up.
//!
//! We keep this intentionally minimal:
//! - kernel code/data segments
//! - user code/data segments
//! - per-CPU TSS with a ring0 stack (RSP0) so `int 0x80` from ring3 can switch stacks.
//!   (Sharing a TSS across CPUs breaks once the TSS is marked busy on the BSP.)

use core::sync::atomic::{AtomicBool, Ordering};

use raw_cpuid::CpuId;
use spin::Once;
use x86_64::VirtAddr;
use x86_64::instructions::segmentation::Segment;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

/// Segment selectors used by Axle.
#[derive(Clone, Copy, Debug)]
pub struct Selectors {
    /// Kernel code segment.
    pub kernel_code: SegmentSelector,
    /// Kernel data segment.
    pub kernel_data: SegmentSelector,
    /// User code segment (Ring3).
    pub user_code: SegmentSelector,
    /// User data segment (Ring3).
    pub user_data: SegmentSelector,
    /// TSS segment.
    pub tss: SegmentSelector,
}

const MAX_CPUS: usize = super::MAX_CPUS;
const RING0_STACK_SIZE: u64 = 32 * 1024;
const IST_STACK_SIZE: u64 = 32 * 1024;
pub const IST_DOUBLE_FAULT_INDEX: u8 = 1;
/// IST for #PF (page fault).
pub const IST_PF_INDEX: u8 = 3;
/// IST for #GP (general protection). Separate from #PF to prevent nested
/// exception stack corruption (#PF inside #GP handler or vice versa).
pub const IST_GP_INDEX: u8 = 4;

#[repr(align(16))]
#[derive(Clone, Copy)]
struct AlignedRing0Stack([u8; RING0_STACK_SIZE as usize]);

// 32 KiB ring0 stack for ring3->ring0 transitions, per CPU.
static mut RING0_STACKS: [AlignedRing0Stack; MAX_CPUS] =
    [AlignedRing0Stack([0; RING0_STACK_SIZE as usize]); MAX_CPUS];

#[repr(align(16))]
#[derive(Clone, Copy)]
struct AlignedIstStack([u8; IST_STACK_SIZE as usize]);

static mut IST1_STACKS: [AlignedIstStack; MAX_CPUS] =
    [AlignedIstStack([0; IST_STACK_SIZE as usize]); MAX_CPUS];
static mut IST3_STACKS: [AlignedIstStack; MAX_CPUS] =
    [AlignedIstStack([0; IST_STACK_SIZE as usize]); MAX_CPUS];
static mut IST4_STACKS: [AlignedIstStack; MAX_CPUS] =
    [AlignedIstStack([0; IST_STACK_SIZE as usize]); MAX_CPUS];

static TSS: [Once<TaskStateSegment>; MAX_CPUS] = [const { Once::new() }; MAX_CPUS];
static GDT: [Once<(GlobalDescriptorTable, Selectors)>; MAX_CPUS] =
    [const { Once::new() }; MAX_CPUS];
static LOADED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

pub(crate) fn ring0_stack_top(cpu: usize) -> u64 {
    assert!(
        cpu < MAX_CPUS,
        "gdt: ring0 stack cpu {} exceeds MAX_CPUS",
        cpu
    );
    // SAFETY: ring0 stacks are statically allocated for the kernel lifetime.
    let stack_start = unsafe { VirtAddr::from_ptr(core::ptr::addr_of!(RING0_STACKS[cpu])) };
    (stack_start + RING0_STACK_SIZE).as_u64()
}

/// Initialize and load GDT + TSS.
///
/// Safe to call multiple times per CPU (idempotent).
pub fn init() -> &'static Selectors {
    if let (Some(cpu_slot), Some(apic_id)) = (
        crate::arch::percpu::try_current_cpu_slot(),
        crate::arch::percpu::try_current_apic_id(),
    ) {
        return init_cpu(cpu_slot, apic_id as usize);
    }

    let apic_id = CpuId::new()
        .get_feature_info()
        .map(|fi| fi.initial_local_apic_id() as usize)
        .unwrap_or(0);
    init_for_apic_id(apic_id)
}

pub(crate) fn init_for_apic_id(apic_id: usize) -> &'static Selectors {
    init_cpu(
        crate::smp::cpu_slot_for_apic_id(apic_id).unwrap_or(0),
        apic_id,
    )
}

fn init_cpu(cpu: usize, apic_id: usize) -> &'static Selectors {
    assert!(
        cpu < MAX_CPUS,
        "gdt: cpu_slot {} exceeds MAX_CPUS (apic_id={})",
        cpu,
        apic_id
    );

    let tss = TSS[cpu].call_once(|| {
        let mut tss = TaskStateSegment::new();

        // SAFETY: stacks are statically allocated and live for the whole kernel lifetime.
        let stack_start = unsafe { VirtAddr::from_ptr(core::ptr::addr_of!(RING0_STACKS[cpu])) };
        let stack_end = stack_start + RING0_STACK_SIZE;
        tss.privilege_stack_table[0] = stack_end;

        // IST1 for double fault. (IDT uses IST index 1, which maps to table[0].)
        // SAFETY: stacks are statically allocated and live for the whole kernel lifetime.
        let ist_start = unsafe { VirtAddr::from_ptr(core::ptr::addr_of!(IST1_STACKS[cpu])) };
        let ist_end = ist_start + IST_STACK_SIZE;
        tss.interrupt_stack_table[0] = ist_end;
        // Keep faults on a dedicated IST so a #PF taken while already handling kernel work
        // does not reuse the current kernel stack top.
        let fault_ist_start = unsafe { VirtAddr::from_ptr(core::ptr::addr_of!(IST3_STACKS[cpu])) };
        let fault_ist_end = fault_ist_start + IST_STACK_SIZE;
        tss.interrupt_stack_table[2] = fault_ist_end;
        // IST4 for #GP -- separate from #PF (IST3) so a nested #GP inside a #PF
        // handler (or vice versa) does not overwrite the outer exception frame.
        let gp_ist_start = unsafe { VirtAddr::from_ptr(core::ptr::addr_of!(IST4_STACKS[cpu])) };
        let gp_ist_end = gp_ist_start + IST_STACK_SIZE;
        tss.interrupt_stack_table[3] = gp_ist_end;
        tss
    });

    let gdt_and_selectors = GDT[cpu].call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let kernel_code = gdt.append(Descriptor::kernel_code_segment());
        let kernel_data = gdt.append(Descriptor::kernel_data_segment());
        let user_data = gdt.append(Descriptor::user_data_segment());
        let user_code = gdt.append(Descriptor::user_code_segment());
        let tss_sel = gdt.append(Descriptor::tss_segment(tss));
        (
            gdt,
            Selectors {
                kernel_code,
                kernel_data,
                user_code,
                user_data,
                tss: tss_sel,
            },
        )
    });

    if LOADED[cpu].swap(true, Ordering::AcqRel) {
        return &gdt_and_selectors.1;
    }

    {
        gdt_and_selectors.0.load();

        // SAFETY: GDT/TSS live for the whole kernel lifetime (static Once storage).
        unsafe {
            use x86_64::instructions::segmentation::{CS, DS, ES, SS};
            use x86_64::instructions::tables::load_tss;

            let sel = &gdt_and_selectors.1;
            CS::set_reg(sel.kernel_code);
            DS::set_reg(sel.kernel_data);
            ES::set_reg(sel.kernel_data);
            SS::set_reg(sel.kernel_data);
            load_tss(sel.tss);
        }
    }

    &gdt_and_selectors.1
}
