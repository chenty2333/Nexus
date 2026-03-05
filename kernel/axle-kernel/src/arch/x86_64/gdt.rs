//! GDT/TSS setup for ring3 bring-up.
//!
//! We keep this intentionally minimal:
//! - kernel code/data segments
//! - user code/data segments
//! - one TSS with a ring0 stack (RSP0) so `int 0x80` from ring3 can switch stacks.

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

const RING0_STACK_SIZE: u64 = 16 * 1024;

#[repr(align(16))]
struct AlignedRing0Stack([u8; RING0_STACK_SIZE as usize]);

// 16 KiB ring0 stack for ring3->ring0 transitions.
static mut RING0_STACK: AlignedRing0Stack = AlignedRing0Stack([0; RING0_STACK_SIZE as usize]);

static TSS: Once<TaskStateSegment> = Once::new();
static GDT: Once<(GlobalDescriptorTable, Selectors)> = Once::new();
static LOADED: Once<()> = Once::new();

/// Initialize and load GDT + TSS.
///
/// Safe to call multiple times (idempotent).
pub fn init() -> &'static Selectors {
    let tss = TSS.call_once(|| {
        let mut tss = TaskStateSegment::new();
        let stack_start = VirtAddr::from_ptr(core::ptr::addr_of!(RING0_STACK));
        let stack_end = stack_start + RING0_STACK_SIZE;
        tss.privilege_stack_table[0] = stack_end;
        tss
    });

    let gdt_and_selectors = GDT.call_once(|| {
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

    LOADED.call_once(|| {
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
    });

    &gdt_and_selectors.1
}
