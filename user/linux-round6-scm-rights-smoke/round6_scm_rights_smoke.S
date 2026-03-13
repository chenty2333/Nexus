.section .rodata
success_message:
    .ascii "round6 scm_rights ok\n"
success_message_len = . - success_message
send_byte:
    .byte 0x52
pipe_byte:
    .byte 0x50

.section .text
.global _start
.type _start, @function
_start:
    sub $512, %rsp

    lea 0(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_1
    mov 0(%rsp), %r12d
    mov 4(%rsp), %r13d

    mov $1, %edi
    mov $1, %esi
    xor %edx, %edx
    lea 8(%rsp), %r10
    mov $53, %eax
    syscall
    test %rax, %rax
    js fail_2
    mov 8(%rsp), %r14d
    mov 12(%rsp), %r15d

    lea send_byte(%rip), %rax
    mov %rax, 16(%rsp)
    movq $1, 24(%rsp)

    movq $20, 96(%rsp)
    movl $1, 104(%rsp)
    movl $1, 108(%rsp)
    mov %r13d, 112(%rsp)

    movq $0, 32(%rsp)
    movl $0, 40(%rsp)
    movl $0, 44(%rsp)
    lea 16(%rsp), %rax
    mov %rax, 48(%rsp)
    movq $1, 56(%rsp)
    lea 96(%rsp), %rax
    mov %rax, 64(%rsp)
    movq $24, 72(%rsp)
    movl $0, 80(%rsp)
    movl $0, 84(%rsp)

    mov %r14d, %edi
    lea 32(%rsp), %rsi
    xor %edx, %edx
    mov $46, %eax
    syscall
    cmpq $1, %rax
    jne fail_3

    mov %r13d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_4

    lea 320(%rsp), %rax
    mov %rax, 128(%rsp)
    movq $1, 136(%rsp)

    movq $0, 144(%rsp)
    movl $0, 152(%rsp)
    movl $0, 156(%rsp)
    lea 128(%rsp), %rax
    mov %rax, 160(%rsp)
    movq $1, 168(%rsp)
    lea 208(%rsp), %rax
    mov %rax, 176(%rsp)
    movq $32, 184(%rsp)
    movl $0, 192(%rsp)
    movl $0, 196(%rsp)

    mov %r15d, %edi
    lea 144(%rsp), %rsi
    xor %edx, %edx
    mov $47, %eax
    syscall
    cmpq $1, %rax
    jne fail_5

    cmpb $0x52, 320(%rsp)
    jne fail_6
    cmpq $24, 184(%rsp)
    jne fail_7
    cmpl $0, 192(%rsp)
    jne fail_8
    cmpq $20, 208(%rsp)
    jne fail_9
    cmpl $1, 216(%rsp)
    jne fail_10
    cmpl $1, 220(%rsp)
    jne fail_11

    mov 224(%rsp), %r11d
    test %r11d, %r11d
    jle fail_12

    mov %r11d, %edi
    lea pipe_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmpq $1, %rax
    jne fail_13

    mov %r12d, %edi
    lea 480(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmpq $1, %rax
    jne fail_14
    cmpb $0x50, 480(%rsp)
    jne fail_15

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmpq $success_message_len, %rax
    jne fail_19

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
fail_19: mov $19, %edi; jmp fail_exit

fail_exit:
    mov $60, %eax
    syscall
