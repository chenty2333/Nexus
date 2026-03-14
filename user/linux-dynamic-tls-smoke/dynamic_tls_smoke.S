.section .text
.global _start
.type _start, @function
_start:
    sub $16, %rsp
    lea dynamic_main_path(%rip), %rdi
    lea dynamic_main_path(%rip), %rax
    mov %rax, 0(%rsp)
    xor %eax, %eax
    mov %rax, 8(%rsp)
    mov %rsp, %rsi
    xor %edx, %edx
    mov $59, %eax
    syscall

    neg %eax
    mov %eax, %edi
    mov $60, %eax
    syscall

.section .rodata
dynamic_main_path:
    .asciz "/bin/linux-dynamic-tls-main"
