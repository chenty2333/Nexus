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
    .space 32768
axle_pvh_stack_top:
"#,
    options(att_syntax)
);
