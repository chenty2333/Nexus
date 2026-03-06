//! Minimal TLB maintenance helpers for bootstrap page-table mutation.

/// Flush one virtual address from the current CPU's TLB.
pub fn flush_page_local(va: u64) {
    unsafe {
        // SAFETY: `invlpg` is the architected local invalidation primitive for one
        // canonical virtual address in the current address space.
        core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
    }
}

/// Flush the current CPU's TLB by reloading CR3.
pub fn flush_all_local() {
    let cr3: u64;
    unsafe {
        // SAFETY: reading and reloading CR3 on the current CPU is the standard full-TLB
        // flush mechanism for the active address space.
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

/// Flush one page locally and request remote CPUs to invalidate the same page.
pub fn flush_page_global(va: u64) {
    flush_page_local(va);
    crate::arch::ipi::shootdown_page(va);
}
