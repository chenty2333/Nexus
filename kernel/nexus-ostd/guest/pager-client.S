# SPDX-License-Identifier: MPL-2.0

.global _start
.section .text
_start:
    mov     $0x00401000, %eax
faulting_load:
    mov     (%rax), %rbx

    mov     $0x50410001, %eax
    syscall

spin:
    pause
    jmp     spin
