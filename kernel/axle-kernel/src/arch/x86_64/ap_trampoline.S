// AP startup trampoline (SIPI target).
//
// This blob is copied by the BSP to physical 0x7000 and started via SIPI
// vector 0x07. It brings the AP into 64-bit long mode using the BSP's CR3 and
// then jumps to a Rust entry point provided in `ap_trampoline_params`.
//
// Keep the entire blob within one 4KiB page.

.set AP_BASE, 0x7000
.set PM_ENTRY_OFF, ap_pm_entry - ap_trampoline_start
.set LM_ENTRY_OFF, ap_lm_entry - ap_trampoline_start
.set PARAMS_OFF, ap_trampoline_params - ap_trampoline_start
.set GDT_OFF, ap_gdt - ap_trampoline_start
.set GDT_PTR_OFF, ap_gdt_ptr - ap_trampoline_start

.section .text.ap_trampoline, "ax"
.global ap_trampoline_start
.global ap_trampoline_end
.global ap_trampoline_params

.code16
ap_trampoline_start:
    cli
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss

    // Temporary real-mode stack (within the trampoline page).
    movw $(AP_BASE + 0x0FF0), %sp

    movw $AP_BASE + GDT_PTR_OFF, %bx
    lgdt (%bx)

    // Enter protected mode.
    movl %cr0, %eax
    orl $0x1, %eax
    movl %eax, %cr0

    ljmp $0x08, $AP_BASE + PM_ENTRY_OFF

.code32
ap_pm_entry:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movl $(AP_BASE + 0x0FF0), %esp

    // Load the BSP's CR3 (identity-mapped page tables).
    movl $AP_BASE + PARAMS_OFF, %esi
    movl 0x00(%esi), %eax           // params.cr3 (low 32 bits)
    movl %eax, %cr3

    // Enable PAE.
    movl %cr4, %eax
    orl $(1 << 5), %eax
    movl %eax, %cr4

    // Enable long mode (EFER.LME).
    movl $0xC0000080, %ecx
    rdmsr
    orl $(1 << 8), %eax
    wrmsr

    // Enable paging.
    movl %cr0, %eax
    orl $(1 << 31), %eax
    movl %eax, %cr0

    // Far jump to 64-bit code segment.
    ljmp $0x18, $AP_BASE + LM_ENTRY_OFF

.code64
ap_lm_entry:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    xorw %ax, %ax
    movw %ax, %fs
    movw %ax, %gs

    // params pointer in rsi.
    movabs $AP_BASE + PARAMS_OFF, %rsi

    // Determine APIC id via CPUID leaf 1 (EBX[31:24]).
    movl $1, %eax
    cpuid
    shrl $24, %ebx

    // Load per-AP stack top: params.stacks[apic_id].
    movzbl %bl, %ecx
    lea 0x10(%rsi), %rdx            // &params.stacks[0]
    mov (%rdx,%rcx,8), %rsp
    andq $-16, %rsp

    // Call Rust entry: rdi = apic_id, rax = params.entry.
    movzbl %bl, %edi
    mov 0x08(%rsi), %rax
    call *%rax

1:
    hlt
    jmp 1b

// ---- Data (within trampoline page) ----

.align 8
ap_gdt:
    .quad 0x0000000000000000
    // 0x08: 32-bit code segment
    .quad 0x00CF9A000000FFFF
    // 0x10: data segment
    .quad 0x00CF92000000FFFF
    // 0x18: 64-bit code segment (L=1)
    .quad 0x00AF9A000000FFFF
ap_gdt_end:

ap_gdt_ptr:
    .word ap_gdt_end - ap_gdt - 1
    .long AP_BASE + GDT_OFF

.align 8
ap_trampoline_params:
    // u64 cr3
    .quad 0
    // u64 entry
    .quad 0
    // stacks[16] (filled by BSP; indexed by APIC id)
    .rept 16
      .quad 0
    .endr

ap_trampoline_end:
