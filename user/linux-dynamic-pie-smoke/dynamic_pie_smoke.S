.section .rodata
dynamic_main_path:
    .asciz "/bin/linux-dynamic-pie-main"

.section .text
.globl _start
_start:
    xor %rdx, %rdx
    xor %rsi, %rsi
    lea dynamic_main_path(%rip), %rdi
    lea dynamic_main_path(%rip), %rax
    push %rdx
    push %rax
    mov %rsp, %rsi
    mov $59, %rax
    syscall

    mov %rax, %rdi
    neg %rdi
    mov $60, %rax
    syscall
