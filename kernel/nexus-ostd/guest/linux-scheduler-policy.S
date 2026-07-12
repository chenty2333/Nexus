# SPDX-License-Identifier: MPL-2.0

.global _start
.section .text
_start:
    # Publish a scoped scheduling proposal for linux-hello.
    mov     $0x4c700001, %eax
    syscall

    # Crash the user-space policy before the proposal can commit. The kernel
    # must clear it and select linux-hello on its next FIFO fallback attempt.
    mov     $0x00800000, %eax
crash_load:
    mov     (%rax), %rbx

spin:
    pause
    jmp     spin
