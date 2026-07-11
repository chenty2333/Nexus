.section .rodata
dynamic_main_path:
    .asciz "/bin/linux-dynamic-runtime-main"

.section .text
.global _start
.type _start, @function
_start:
    lea dynamic_main_path(%rip), %rdi
    lea dynamic_main_path(%rip), %rax
    pushq $0
    pushq %rax
    movq %rsp, %rsi
    xor %rdx, %rdx
    mov $59, %eax
    syscall

    mov $127, %edi
    mov $60, %eax
    syscall
