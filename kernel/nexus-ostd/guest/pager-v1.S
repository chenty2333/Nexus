# SPDX-License-Identifier: MPL-2.0

.global _start
.section .text
_start:
    mov     $0x50420001, %eax
    syscall

    mov     $0x00401000, %eax
crash_load:
    mov     (%rax), %rbx

spin:
    pause
    jmp     spin
