# SPDX-License-Identifier: MPL-2.0

.global _start
.section .text
_start:
    mov     $0x4c610001, %eax
    syscall

    mov     $0x4c610002, %eax
    syscall

    mov     $0x4c610003, %eax
    syscall

    mov     $0x4c610004, %eax
    syscall

    mov     $0x4c610005, %eax
    syscall

    mov     $0x4c610006, %eax
    syscall

spin:
    pause
    jmp     spin
