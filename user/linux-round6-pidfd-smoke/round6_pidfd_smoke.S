.section .rodata
success_message:
    .ascii "round6 pidfd ok\n"
success_message_len = . - success_message

.section .text
.global _start
.type _start, @function
_start:
    sub $256, %rsp

    lea 0(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_1

    mov $57, %eax
    syscall
    test %rax, %rax
    js fail_2
    jz child

    mov %eax, %r12d

    mov 0(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_3

    mov %r12d, %edi
    xor %esi, %esi
    mov $434, %eax
    syscall
    test %rax, %rax
    js fail_4
    mov %eax, %r13d

    xor %edi, %edi
    mov $291, %eax
    syscall
    test %rax, %rax
    js fail_5
    mov %eax, %r14d

    movl $0x00000001, 16(%rsp)
    movq $0x66, 20(%rsp)
    mov %r14d, %edi
    mov $1, %esi
    mov %r13d, %edx
    lea 16(%rsp), %r10
    mov $233, %eax
    syscall
    test %rax, %rax
    js fail_6

    mov %r13d, %edi
    mov $9, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $424, %eax
    syscall
    test %rax, %rax
    js fail_7

    mov %r14d, %edi
    lea 32(%rsp), %rsi
    mov $1, %edx
    mov $-1, %r10d
    mov $232, %eax
    syscall
    cmpq $1, %rax
    jne fail_8
    mov 32(%rsp), %r11d
    test $0x1, %r11d
    jz fail_9
    cmpq $0x66, 36(%rsp)
    jne fail_10

    mov %r12d, %edi
    lea 64(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne fail_11
    mov 64(%rsp), %r11d
    and $0x7f, %r11d
    cmp $9, %r11d
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

child:
    mov 4(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne child_fail_1

    mov 0(%rsp), %edi
    lea 128(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall

child_fail_1:
    mov $111, %edi
    mov $60, %eax
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
    mov $60, %eax
    syscall
