.section .rodata
success_msg:
    .ascii "round6 signalfd ok\n"
success_msg_end:
signal_mask:
    .quad 512

.section .text
.global _start
.type _start, @function
_start:
    sub $320, %rsp

    mov $0, %edi
    lea signal_mask(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $14, %eax
    syscall
    test %rax, %rax
    js fail_1

    mov $-1, %edi
    lea signal_mask(%rip), %rsi
    mov $8, %edx
    mov $0x800, %r10d
    mov $289, %eax
    syscall
    test %rax, %rax
    js fail_2
    mov %eax, %r12d

    mov %r12d, %edi
    lea 128(%rsp), %rsi
    mov $128, %edx
    xor %eax, %eax
    syscall
    cmpq $-11, %rax
    jne fail_3

    mov $-1, %edi
    lea signal_mask(%rip), %rsi
    mov $8, %edx
    xor %r10d, %r10d
    mov $289, %eax
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

    movl $0x00000001, 0(%rsp)
    movq $0x88, 4(%rsp)
    mov %r14d, %edi
    mov $1, %esi
    mov %r13d, %edx
    lea 0(%rsp), %r10
    mov $233, %eax
    syscall
    test %rax, %rax
    js fail_6

    mov $39, %eax
    syscall
    test %rax, %rax
    js fail_7
    mov %eax, %r15d

    mov %r15d, %edi
    mov $10, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    js fail_8

    mov %r14d, %edi
    lea 16(%rsp), %rsi
    mov $4, %edx
    mov $-1, %r10d
    mov $232, %eax
    syscall
    cmpq $1, %rax
    jne fail_9
    mov 16(%rsp), %r11d
    test $0x1, %r11d
    jz fail_10
    cmpq $0x88, 20(%rsp)
    jne fail_11

    mov %r13d, %edi
    lea 32(%rsp), %rsi
    mov $128, %edx
    xor %eax, %eax
    syscall
    cmpq $128, %rax
    jne fail_12
    mov 32(%rsp), %r11d
    cmp $10, %r11d
    jne fail_13

    mov %r14d, %edi
    lea 16(%rsp), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    mov $232, %eax
    syscall
    test %rax, %rax
    jne fail_14

    mov $1, %edi
    lea success_msg(%rip), %rsi
    mov $(success_msg_end - success_msg), %edx
    mov $1, %eax
    syscall
    cmpq $(success_msg_end - success_msg), %rax
    jne fail_15

    xor %edi, %edi
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
fail_14: mov $14, %edi; jmp fail_exit
fail_15: mov $15, %edi; jmp fail_exit

fail_exit:
    neg %edi
    mov $60, %eax
    syscall
