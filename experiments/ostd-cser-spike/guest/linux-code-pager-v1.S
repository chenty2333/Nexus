# SPDX-License-Identifier: MPL-2.0

.global _start
.section .text
_start:
    # Ask the kernel portal to materialize the retained ELF image page, but do
    # not publish the guest PTE yet.
    mov     $0x4c600001, %eax
    syscall

    # A genuine user-mode page fault models pager-v1 crashing in the gap
    # between image-frame preparation and PTE publication.
    mov     $0x00800000, %eax
crash_load:
    mov     (%rax), %rbx

spin:
    pause
    jmp     spin
