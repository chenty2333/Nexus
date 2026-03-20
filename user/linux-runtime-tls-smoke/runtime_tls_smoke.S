.section .bss
.align 8
thread_flag:
    .quad 0
.align 8
thread_fs_value:
    .quad 0

.section .data
.align 8
fork_shared_value:
    .quad 0

.section .rodata
success_message:
    .ascii "runtime tls ok\n"
success_message_len = . - success_message

.section .text
.global _start
.type _start, @function
_start:
    sub $4096, %rsp

    mov $0x1002, %edi
    movabs $0x1122334455667788, %rsi
    mov $158, %eax
    syscall
    test %rax, %rax
    jne fail_1

    mov $0x1003, %edi
    lea 0(%rsp), %rsi
    mov $158, %eax
    syscall
    test %rax, %rax
    jne fail_2

    movabs $0x1122334455667788, %rax
    cmp %rax, 0(%rsp)
    jne fail_3

    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx
    mov $34, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_4
    lea 8192(%rax), %rsi

    mov $0x90f00, %rdi
    xor %edx, %edx
    xor %r10d, %r10d
    movabs $0x8877665544332211, %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_5
    jz thread_child

wait_thread:
    mov thread_flag(%rip), %rax
    test %rax, %rax
    jz wait_thread
    cmpq $1, %rax
    jne fail_6

    movabs $0x8877665544332211, %rax
    cmp %rax, thread_fs_value(%rip)
    jne fail_7

    mov $0x1003, %edi
    lea 8(%rsp), %rsi
    mov $158, %eax
    syscall
    test %rax, %rax
    jne fail_8

    movabs $0x1122334455667788, %rax
    cmp %rax, 8(%rsp)
    jne fail_9

    movabs $0x123456789abcdef0, %rax
    mov %rax, fork_shared_value(%rip)

    mov $57, %eax
    syscall
    test %rax, %rax
    js fail_10
    jz fork_child
    mov %rax, %r12

    mov $-1, %edi
    lea 16(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12, %rax
    jne fail_11
    cmpl $0, 16(%rsp)
    jne fail_12

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmpq $success_message_len, %rax
    jne fail_13

    xor %edi, %edi
    mov $231, %eax
    syscall

thread_child:
    sub $16, %rsp
    mov $0x1003, %edi
    lea thread_fs_value(%rip), %rsi
    mov $158, %eax
    syscall
    test %rax, %rax
    jne thread_fail
    movabs $0x8877665544332211, %rax
    cmp %rax, thread_fs_value(%rip)
    jne thread_fail
    movq $1, thread_flag(%rip)
    xor %edi, %edi
    mov $60, %eax
    syscall

thread_fail:
    movq $2, thread_flag(%rip)
    mov $60, %eax
    mov $1, %edi
    syscall

fork_child:
    mov $0x1003, %edi
    lea 24(%rsp), %rsi
    mov $158, %eax
    syscall
    test %rax, %rax
    jne fork_fail
    movabs $0x1122334455667788, %rax
    cmp %rax, 24(%rsp)
    jne fork_fail
    movabs $0x123456789abcdef0, %rax
    cmp %rax, fork_shared_value(%rip)
    jne fork_fail
    xor %edi, %edi
    mov $60, %eax
    syscall

fork_fail:
    mov $60, %eax
    mov $7, %edi
    syscall

fail_1: mov $1, %edi; jmp fail_exit
fail_2: mov $2, %edi; jmp fail_exit
fail_3: mov $3, %edi; jmp fail_exit
fail_4: mov $4, %edi; jmp fail_exit
fail_5: mov $5, %edi; jmp fail_exit
fail_6: mov $6, %edi; jmp fail_exit
fail_7: mov $7, %edi; jmp fail_exit
fail_8: mov $8, %edi; jmp fail_exit
fail_9: mov $9, %edi; jmp fail_exit
fail_10: mov $10, %edi; jmp fail_exit
fail_11: mov $11, %edi; jmp fail_exit
fail_12: mov $12, %edi; jmp fail_exit
fail_13: mov $13, %edi; jmp fail_exit

fail_exit:
    mov $231, %eax
    syscall
