# SPDX-License-Identifier: MPL-2.0

.global _start
.section .text
_start:
    mov     $0x50430001, %eax
    syscall

    mov     $0x50430002, %eax
    syscall

    mov     $0x50430003, %eax
    syscall

    mov     $0x50430004, %eax
    syscall

    mov     $0x50430005, %eax
    syscall

    mov     $0x50430006, %eax
    syscall

spin:
    pause
    jmp     spin
