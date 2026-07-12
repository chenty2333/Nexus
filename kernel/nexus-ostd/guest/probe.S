# SPDX-License-Identifier: MPL-2.0

.global _start
.section .text
_start:
    mov     $0x43534552, %eax
    syscall

    mov     $0x00800000, %eax
faulting_load:
    mov     (%rax), %rbx

spin:
    pause
    jmp     spin

