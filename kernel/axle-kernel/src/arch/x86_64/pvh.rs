//! PVH entry note/stub for direct `qemu -kernel <elf>` boot.
//!
//! QEMU's direct ELF loader on x86_64 expects a Xen PVH note.
//! This module publishes that note and provides a tiny entry stub that sets
//! a known-good stack before transferring control to Rust `_start`.

use core::arch::global_asm;

global_asm!(
    r#"
    .section .note.Xen, "a"
    .align 4
    .long 4, 4, 18
    .asciz "Xen"
    .align 4
    .long axle_pvh_entry32

    .section .text.axle_pvh, "ax"
    .global axle_pvh_entry32
    .type axle_pvh_entry32, @function

    .code32
axle_pvh_entry32:
    cli

    movl %ebx, axle_pvh_start_info_paddr

    movl $pvh_pml4, %eax
    movl %eax, %cr3

    movl %cr4, %eax
    orl $(1 << 5), %eax
    movl %eax, %cr4

    movl $0xC0000080, %ecx
    rdmsr
    orl $(1 << 8), %eax
    wrmsr

    movl %cr0, %eax
    orl $(1 << 31), %eax
    orl $1, %eax
    movl %eax, %cr0

    lgdt pvh_gdt_ptr
    ljmp $0x08, $axle_pvh_entry64

    .code64
axle_pvh_entry64:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    xorw %ax, %ax
    movw %ax, %fs
    movw %ax, %gs

    leaq axle_pvh_stack_top(%rip), %rsp
    andq $-16, %rsp
    xorq %rbp, %rbp
    call _start
1:
    hlt
    jmp 1b
    .size axle_pvh_entry32, .-axle_pvh_entry32

    .align 8
pvh_gdt:
    .quad 0x0000000000000000
    .quad 0x00AF9A000000FFFF
    .quad 0x00AF92000000FFFF
pvh_gdt_end:

pvh_gdt_ptr:
    .word pvh_gdt_end - pvh_gdt - 1
    .long pvh_gdt

    .section .data.axle_pvh_pt, "aw"
    .align 4096
    .global pvh_pml4
pvh_pml4:
    .quad pvh_pdpt + 0x003
    .zero 4096 - 8

    .align 4096
    .global pvh_pdpt
pvh_pdpt:
    .quad pvh_pd + 0x003
    .zero 4096 - 8

    .align 4096
    .global pvh_pd
pvh_pd:
    .set pvh_i, 0
    .rept 512
      .quad (pvh_i << 21) + 0x083
      .set pvh_i, pvh_i + 1
    .endr

    .section .bss.axle_pvh_stack, "aw", @nobits
    .align 16
axle_pvh_stack:
    .space 131072
axle_pvh_stack_top:

    .section .data.axle_pvh_boot, "aw"
    .align 8
    .global axle_pvh_start_info_paddr
axle_pvh_start_info_paddr:
    .quad 0
"#,
    options(att_syntax)
);

unsafe extern "C" {
    static axle_pvh_start_info_paddr: u64;
}

/// Xen PVH boot `start_info`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct HvmStartInfo {
    pub(crate) magic: u32,
    pub(crate) version: u32,
    pub(crate) flags: u32,
    pub(crate) nr_modules: u32,
    pub(crate) modlist_paddr: u64,
    pub(crate) cmdline_paddr: u64,
    pub(crate) rsdp_paddr: u64,
    pub(crate) memmap_paddr: u64,
    pub(crate) memmap_entries: u32,
    pub(crate) _reserved: u32,
}

/// Xen PVH memory-map entry.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct HvmMemmapEntry {
    pub(crate) addr: u64,
    pub(crate) size_bytes: u64,
    pub(crate) entry_type: u32,
    pub(crate) _reserved: u32,
}

/// Xen PVH module-list entry.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct HvmModlistEntry {
    pub(crate) paddr: u64,
    pub(crate) size_bytes: u64,
    pub(crate) cmdline_paddr: u64,
    pub(crate) _reserved: u64,
}

pub(crate) const HVM_MEMMAP_TYPE_RAM: u32 = 1;

pub(crate) fn start_info_paddr() -> u64 {
    unsafe {
        // SAFETY: the PVH entry stub stores the bootloader-provided physical address in this
        // static before transferring control to Rust `_start`.
        core::ptr::read_volatile(core::ptr::addr_of!(axle_pvh_start_info_paddr))
    }
}

pub(crate) fn start_info() -> Option<&'static HvmStartInfo> {
    let paddr = start_info_paddr();
    if paddr == 0 {
        return None;
    }
    Some(unsafe {
        // SAFETY: PVH guarantees `start_info_paddr` points to a valid `hvm_start_info`
        // structure in identity-mapped low memory for the duration of early boot.
        &*(paddr as *const HvmStartInfo)
    })
}

pub(crate) fn memmap_entries(start: &HvmStartInfo) -> &'static [HvmMemmapEntry] {
    if start.memmap_entries == 0 || start.memmap_paddr == 0 {
        return &[];
    }
    unsafe {
        // SAFETY: the PVH `start_info` describes a contiguous memory-map table that remains
        // valid in identity-mapped low memory during kernel bring-up.
        core::slice::from_raw_parts(
            start.memmap_paddr as *const HvmMemmapEntry,
            start.memmap_entries as usize,
        )
    }
}

pub(crate) fn modules(start: &HvmStartInfo) -> &'static [HvmModlistEntry] {
    if start.nr_modules == 0 || start.modlist_paddr == 0 {
        return &[];
    }
    unsafe {
        // SAFETY: the PVH `start_info` describes a contiguous module list that remains valid
        // in identity-mapped low memory during kernel bring-up.
        core::slice::from_raw_parts(
            start.modlist_paddr as *const HvmModlistEntry,
            start.nr_modules as usize,
        )
    }
}
