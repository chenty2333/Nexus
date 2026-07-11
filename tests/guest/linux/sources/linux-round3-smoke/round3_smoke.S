.section .bss
.align 8
thread_flag:
    .quad 0

.section .text
.global _start
.type _start, @function
_start:
    sub $16384, %rsp

    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx
    mov $34, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail
    lea 8192(%rax), %rsi

    mov $0x10f00, %rdi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail
    jz thread_child

wait_thread:
    cmpq $1, thread_flag(%rip)
    jne wait_thread

    mov $57, %eax
    syscall
    test %rax, %rax
    js fail
    jz first_child
    mov %rax, %r12

    mov $-1, %edi
    lea 0(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12, %rax
    jne fail
    cmpl $1792, 0(%rsp)
    jne fail

    mov $-1, %edi
    lea 8(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %rax, %rax
    jle fail
    cmp %r12, %rax
    je fail
    cmpl $0, 8(%rsp)
    jne fail

    mov $-1, %edi
    lea 16(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp $-10, %rax
    jne fail

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmp $success_message_len, %rax
    jne fail

    mov $231, %eax
    xor %edi, %edi
    syscall

thread_child:
    movq $1, thread_flag(%rip)
    mov $60, %eax
    xor %edi, %edi
    syscall

first_child:
    mov $57, %eax
    syscall
    test %rax, %rax
    js fail
    jz grandchild

    mov $231, %eax
    mov $7, %edi
    syscall

grandchild:
    lea hello_path(%rip), %rdi
    lea hello_argv(%rip), %rsi
    lea empty_env(%rip), %rdx
    mov $59, %eax
    syscall
    test %rax, %rax
    js fail

fail:
    mov $231, %eax
    mov $1, %edi
    syscall

.section .rodata
hello_path:
    .asciz "/bin/linux-hello"
success_message:
    .ascii "round3 ok\n"
success_message_end:
.set success_message_len, success_message_end - success_message

.section .data
.align 8
hello_argv:
    .quad hello_path
    .quad 0
empty_env:
    .quad 0
