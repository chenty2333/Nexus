.section .rodata
success_msg:
    .ascii "round6 eventfd ok\n"
success_msg_end:
write_qword:
    .quad 7

.section .text
.global _start
.type _start, @function
_start:
    sub $128, %rsp

    xor %edi, %edi
    xor %esi, %esi
    mov $290, %eax
    syscall
    test %rax, %rax
    js fail_1
    mov %eax, %r12d

    xor %edi, %edi
    mov $0x800, %esi
    mov $290, %eax
    syscall
    test %rax, %rax
    js fail_2
    mov %eax, %r14d

    mov %r14d, %edi
    lea 40(%rsp), %rsi
    mov $8, %edx
    xor %eax, %eax
    syscall
    cmpq $-11, %rax
    jne fail_2

    xor %edi, %edi
    mov $291, %eax
    syscall
    test %rax, %rax
    js fail_3
    mov %eax, %r13d

    movl $0x00000001, 0(%rsp)
    movq $0x66, 4(%rsp)
    mov %r13d, %edi
    mov $1, %esi
    mov %r12d, %edx
    lea 0(%rsp), %r10
    mov $233, %eax
    syscall
    test %rax, %rax
    js fail_4

    mov %r12d, %edi
    lea write_qword(%rip), %rsi
    mov $8, %edx
    mov $1, %eax
    syscall
    cmpq $8, %rax
    jne fail_5

    mov %r13d, %edi
    lea 16(%rsp), %rsi
    mov $4, %edx
    mov $-1, %r10d
    mov $232, %eax
    syscall
    cmpq $1, %rax
    jne fail_6
    mov 16(%rsp), %r11d
    test $0x1, %r11d
    jz fail_7
    cmpq $0x66, 20(%rsp)
    jne fail_8

    mov %r12d, %edi
    lea 32(%rsp), %rsi
    mov $8, %edx
    xor %eax, %eax
    syscall
    cmpq $8, %rax
    jne fail_9
    mov 32(%rsp), %r11
    cmpq $7, %r11
    jne fail_10

    mov %r13d, %edi
    lea 16(%rsp), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    mov $232, %eax
    syscall
    test %rax, %rax
    jne fail_11

    mov $1, %edi
    lea success_msg(%rip), %rsi
    mov $(success_msg_end - success_msg), %edx
    mov $1, %eax
    syscall
    cmpq $(success_msg_end - success_msg), %rax
    jne fail_12

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

fail_exit:
    neg %edi
    mov $60, %eax
    syscall
