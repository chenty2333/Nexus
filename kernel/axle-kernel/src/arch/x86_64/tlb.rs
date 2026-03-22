//! x86_64 TLB maintenance helpers and address-space activation policy.

use core::sync::atomic::{AtomicU64, Ordering};

use axle_page_table::PageRange;
use axle_types::zx_status_t;
use x86_64::PhysAddr;
use x86_64::instructions::tlb::{InvPcidCommand, Pcid, flush_pcid};
use x86_64::registers::control::{Cr3, Cr3Flags, Cr4, Cr4Flags};
use x86_64::structures::paging::PhysFrame;

static PCID_ENABLED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddressSpaceSwitchKind {
    LegacyCr3 = 0,
    PcidFlush = 1,
    PcidNoFlush = 2,
    SameAddressSpaceSkip = 3,
}

pub fn init_cpu() {
    if !crate::arch::cpuid::supports_pcid() {
        PCID_ENABLED.store(0, Ordering::Release);
        return;
    }

    let (frame, cr3_low_bits) = Cr3::read_raw();
    if cr3_low_bits != 0 {
        // SAFETY: clearing the low CR3 tag bits keeps the already-active root
        // frame loaded while satisfying the ISA prerequisite before enabling
        // CR4.PCIDE.
        unsafe {
            Cr3::write(frame, Cr3Flags::empty());
        }
    }

    // SAFETY: CPUID confirmed PCID support and the active CR3 low bits were
    // normalized to zero above, which is the required enable sequence.
    unsafe {
        Cr4::update(|flags| flags.insert(Cr4Flags::PCID));
    }
    PCID_ENABLED.store(1, Ordering::Release);
}

pub fn pcid_enabled() -> bool {
    PCID_ENABLED.load(Ordering::Acquire) != 0
}

pub fn invpcid_enabled() -> bool {
    crate::arch::cpuid::supports_invpcid()
}

pub fn pcid_for_address_space(address_space_id: u64) -> Option<u16> {
    if !pcid_enabled() {
        return None;
    }
    let value = u16::try_from(address_space_id).ok()?;
    if value >= 4096 {
        return None;
    }
    Some(value)
}

fn current_pcid() -> Option<Pcid> {
    if !pcid_enabled() {
        return None;
    }
    Some(Cr3::read_pcid().1)
}

fn frame_from_root_paddr(root_paddr: u64) -> PhysFrame {
    PhysFrame::containing_address(PhysAddr::new(root_paddr))
}

fn flush_single_pcid(pcid: Pcid) {
    if !invpcid_enabled() {
        return;
    }
    // SAFETY: CPUID confirmed INVPCID support, and the PCID came from the
    // active CR3 state or the kernel's bounded address-space tag allocator.
    unsafe {
        flush_pcid(InvPcidCommand::Single(pcid));
    }
    crate::trace::record_tlb_invpcid_single(pcid.value());
}

pub fn activate_root(
    root_paddr: u64,
    pcid: Option<u16>,
    flush_context: bool,
) -> AddressSpaceSwitchKind {
    let frame = frame_from_root_paddr(root_paddr);
    match pcid.and_then(|value| Pcid::new(value).ok()) {
        Some(pcid) if pcid_enabled() => {
            if flush_context {
                if invpcid_enabled() {
                    flush_single_pcid(pcid);
                    // SAFETY: the target root frame is one kernel-owned page-table
                    // root and the PCID came from the bounded kernel allocator.
                    unsafe {
                        Cr3::write_pcid_no_flush(frame, pcid);
                    }
                } else {
                    // SAFETY: same root/PCID invariants as above; this variant
                    // requests the architected PCID-local flush.
                    unsafe {
                        Cr3::write_pcid(frame, pcid);
                    }
                }
                AddressSpaceSwitchKind::PcidFlush
            } else {
                // SAFETY: the target root frame is one kernel-owned page-table
                // root and the PCID came from the bounded kernel allocator.
                unsafe {
                    Cr3::write_pcid_no_flush(frame, pcid);
                }
                AddressSpaceSwitchKind::PcidNoFlush
            }
        }
        _ => {
            // SAFETY: the root frame was either the currently loaded CR3 or one
            // freshly cloned kernel template with preserved kernel mappings.
            unsafe {
                Cr3::write(frame, Cr3Flags::empty());
            }
            AddressSpaceSwitchKind::LegacyCr3
        }
    }
}

/// Flush one virtual address from the current CPU's TLB.
pub fn flush_page_local(va: u64) {
    unsafe {
        // SAFETY: `invlpg` is the architected local invalidation primitive for
        // one canonical virtual address in the current address space.
        core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
    }
    crate::trace::record_tlb_flush_page(va);
}

/// Flush one aligned virtual-address range from the current CPU's TLB.
pub fn flush_range_local(range: PageRange) {
    let mut va = range.base();
    while va < range.end() {
        flush_page_local(va);
        va = va.wrapping_add(axle_page_table::PAGE_SIZE);
    }
}

/// Flush the current CPU's TLB for the active address-space context.
pub fn flush_all_local() {
    if let Some(pcid) = current_pcid() {
        if invpcid_enabled() {
            flush_single_pcid(pcid);
        } else {
            let (frame, _) = Cr3::read_pcid();
            unsafe {
                // SAFETY: re-writing the active root and PCID requests the
                // architected PCID-local flush for the current address space.
                Cr3::write_pcid(frame, pcid);
            }
        }
    } else {
        let (frame, flags) = Cr3::read();
        unsafe {
            // SAFETY: reloading the current CR3 frame is the architected
            // fallback full-TLB flush when PCID is not enabled.
            Cr3::write(frame, flags);
        }
    }
    crate::trace::record_tlb_flush_all();
}

/// Flush one page locally and request remote CPUs to invalidate the same page.
#[allow(dead_code)]
pub fn flush_page_global(va: u64) -> Result<(), zx_status_t> {
    flush_page_local(va);
    crate::arch::ipi::shootdown_page(va)
}
