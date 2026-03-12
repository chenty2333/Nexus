.section .text
.global _start
.type _start, @function
_start:
    sub $256, %rsp

    xor %edi, %edi
    mov $291, %eax
    syscall
    test %rax, %rax
    js fail_1
    mov %rax, %r12

    lea 0(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_2

    movl $0x80000001, 16(%rsp)
    movq $0x11, 20(%rsp)
    mov %r12d, %edi
    mov $1, %esi
    mov 0(%rsp), %edx
    lea 16(%rsp), %r10
    mov $233, %eax
    syscall
    test %rax, %rax
    js fail_3

    mov 4(%rsp), %edi
    lea pipe_byte_p(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmpq $1, %rax
    jne fail_4

    mov %r12d, %edi
    lea 32(%rsp), %rsi
    mov $4, %edx
    mov $-1, %r10d
    mov $232, %eax
    syscall
    cmpq $1, %rax
    jne fail_5
    mov 32(%rsp), %r11d
    test $0x1, %r11d
    jz fail_6
    cmpq $0x11, 36(%rsp)
    jne fail_7

    mov 0(%rsp), %edi
    lea 80(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmpq $1, %rax
    jne fail_8
    cmpb $0x50, 80(%rsp)
    jne fail_9

    mov %r12d, %edi
    lea 32(%rsp), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    mov $232, %eax
    syscall
    test %rax, %rax
    jne fail_10

    movl $0x40000001, 16(%rsp)
    movq $0x22, 20(%rsp)
    mov %r12d, %edi
    mov $3, %esi
    mov 0(%rsp), %edx
    lea 16(%rsp), %r10
    mov $233, %eax
    syscall
    test %rax, %rax
    js fail_11

    mov 4(%rsp), %edi
    lea pipe_byte_q(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmpq $1, %rax
    jne fail_12

    mov %r12d, %edi
    lea 32(%rsp), %rsi
    mov $4, %edx
    mov $-1, %r10d
    mov $232, %eax
    syscall
    cmpq $1, %rax
    jne fail_13
    mov 32(%rsp), %r11d
    test $0x1, %r11d
    jz fail_14
    cmpq $0x22, 36(%rsp)
    jne fail_15

    mov %r12d, %edi
    lea 32(%rsp), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    mov $232, %eax
    syscall
    test %rax, %rax
    jne fail_16

    mov 0(%rsp), %edi
    lea 81(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmpq $1, %rax
    jne fail_17
    cmpb $0x51, 81(%rsp)
    jne fail_18

    mov $1, %edi
    mov $1, %esi
    xor %edx, %edx
    lea 88(%rsp), %r10
    mov $53, %eax
    syscall
    test %rax, %rax
    js fail_19

    movl $0x00000001, 16(%rsp)
    movq $0x33, 20(%rsp)
    mov %r12d, %edi
    mov $1, %esi
    mov 88(%rsp), %edx
    lea 16(%rsp), %r10
    mov $233, %eax
    syscall
    test %rax, %rax
    js fail_20

    mov 92(%rsp), %edi
    lea socket_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmpq $1, %rax
    jne fail_21

    mov %r12d, %edi
    lea 32(%rsp), %rsi
    mov $4, %edx
    mov $-1, %r10d
    mov $232, %eax
    syscall
    cmpq $1, %rax
    jne fail_22
    mov 32(%rsp), %r11d
    test $0x1, %r11d
    jz fail_23
    cmpq $0x33, 36(%rsp)
    jne fail_24

    mov %r12d, %edi
    lea 32(%rsp), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    mov $232, %eax
    syscall
    cmpq $1, %rax
    jne fail_25
    mov 32(%rsp), %r11d
    test $0x1, %r11d
    jz fail_26
    cmpq $0x33, 36(%rsp)
    jne fail_27

    mov 88(%rsp), %edi
    lea 82(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmpq $1, %rax
    jne fail_28
    cmpb $0x53, 82(%rsp)
    jne fail_29

    mov %r12d, %edi
    lea 32(%rsp), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    mov $232, %eax
    syscall
    test %rax, %rax
    jne fail_30

    mov $-100, %edi
    lea hello_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_31
    mov %eax, 96(%rsp)

    movl $0x00000001, 16(%rsp)
    movq $0x44, 20(%rsp)
    mov %r12d, %edi
    mov $1, %esi
    mov 96(%rsp), %edx
    lea 16(%rsp), %r10
    mov $233, %eax
    syscall
    test %rax, %rax
    js fail_32

    mov %r12d, %edi
    lea 32(%rsp), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    mov $232, %eax
    syscall
    cmpq $1, %rax
    jne fail_33
    mov 32(%rsp), %r11d
    test $0x1, %r11d
    jz fail_34
    cmpq $0x44, 36(%rsp)
    jne fail_35

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmp $success_message_len, %rax
    jne fail_36

    mov $231, %eax
    xor %edi, %edi
    syscall

fail_1:
    mov $1, %edi
    jmp fail_code
fail_2:
    mov $2, %edi
    jmp fail_code
fail_3:
    mov $3, %edi
    jmp fail_code
fail_4:
    mov $4, %edi
    jmp fail_code
fail_5:
    mov $5, %edi
    jmp fail_code
fail_6:
    mov $6, %edi
    jmp fail_code
fail_7:
    mov $7, %edi
    jmp fail_code
fail_8:
    mov $8, %edi
    jmp fail_code
fail_9:
    mov $9, %edi
    jmp fail_code
fail_10:
    mov $10, %edi
    jmp fail_code
fail_11:
    mov $11, %edi
    jmp fail_code
fail_12:
    mov $12, %edi
    jmp fail_code
fail_13:
    mov $13, %edi
    jmp fail_code
fail_14:
    mov $14, %edi
    jmp fail_code
fail_15:
    mov $15, %edi
    jmp fail_code
fail_16:
    mov $16, %edi
    jmp fail_code
fail_17:
    mov $17, %edi
    jmp fail_code
fail_18:
    mov $18, %edi
    jmp fail_code
fail_19:
    mov $19, %edi
    jmp fail_code
fail_20:
    mov $20, %edi
    jmp fail_code
fail_21:
    mov $21, %edi
    jmp fail_code
fail_22:
    mov $22, %edi
    jmp fail_code
fail_23:
    mov $23, %edi
    jmp fail_code
fail_24:
    mov $24, %edi
    jmp fail_code
fail_25:
    mov $25, %edi
    jmp fail_code
fail_26:
    mov $26, %edi
    jmp fail_code
fail_27:
    mov $27, %edi
    jmp fail_code
fail_28:
    mov $28, %edi
    jmp fail_code
fail_29:
    mov $29, %edi
    jmp fail_code
fail_30:
    mov $30, %edi
    jmp fail_code
fail_31:
    mov $31, %edi
    jmp fail_code
fail_32:
    mov $32, %edi
    jmp fail_code
fail_33:
    mov $33, %edi
    jmp fail_code
fail_34:
    mov $34, %edi
    jmp fail_code
fail_35:
    mov $35, %edi
    jmp fail_code
fail_36:
    mov $36, %edi
    jmp fail_code

fail_code:
    mov $231, %eax
    syscall

.section .rodata
hello_path:
    .asciz "/bin/linux-hello"
success_message:
    .ascii "round5 epoll ok\n"
success_message_end:
.set success_message_len, success_message_end - success_message
pipe_byte_p:
    .byte 0x50
pipe_byte_q:
    .byte 0x51
socket_byte:
    .byte 0x53
