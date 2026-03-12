.section .text
.global _start
.type _start, @function
_start:
    sub $256, %rsp

    mov $39, %eax
    syscall
    cmp $1, %rax
    jne fail
    mov %rax, %r12

    mov $186, %eax
    syscall
    cmp $1, %rax
    jne fail
    mov %rax, %r13

    mov $0, %edi
    lea sigusr1_mask(%rip), %rsi
    lea 0(%rsp), %rdx
    mov $8, %r10d
    mov $14, %eax
    syscall
    test %rax, %rax
    js fail
    cmpq $0, 0(%rsp)
    jne fail

    mov $0, %edi
    xor %esi, %esi
    lea 8(%rsp), %rdx
    mov $8, %r10d
    mov $14, %eax
    syscall
    test %rax, %rax
    js fail
    mov sigusr1_mask(%rip), %r11
    cmp %r11, 8(%rsp)
    jne fail

    mov $2, %edi
    lea zero_mask(%rip), %rsi
    lea 16(%rsp), %rdx
    mov $8, %r10d
    mov $14, %eax
    syscall
    test %rax, %rax
    js fail
    cmp %r11, 16(%rsp)
    jne fail

    mov $10, %edi
    lea ignore_action(%rip), %rsi
    lea 24(%rsp), %rdx
    mov $8, %r10d
    mov $13, %eax
    syscall
    test %rax, %rax
    js fail
    cmpq $0, 24(%rsp)
    jne fail

    mov %r12d, %edi
    mov $10, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    js fail

    mov %r12d, %edi
    mov %r13d, %esi
    mov $10, %edx
    mov $234, %eax
    syscall
    test %rax, %rax
    js fail

    mov $12, %edi
    lea no_restart_action(%rip), %rsi
    lea 32(%rsp), %rdx
    mov $8, %r10d
    mov $13, %eax
    syscall
    test %rax, %rax
    js fail
    cmpq $0, 32(%rsp)
    jne fail

    mov $57, %eax
    syscall
    test %rax, %rax
    js fail
    je child_no_restart
    mov %rax, %r14

    mov %r14, %rdi
    lea 40(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    mov $-4, %r11
    cmp %r11, %rax
    jne fail
    cmpq $1, no_restart_hits(%rip)
    jne fail

    mov %r14, %rdi
    lea 40(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14, %rax
    jne fail
    cmpq $0, 40(%rsp)
    jne fail

    mov $12, %edi
    lea restart_action(%rip), %rsi
    lea 48(%rsp), %rdx
    mov $8, %r10d
    mov $13, %eax
    syscall
    test %rax, %rax
    js fail
    lea handler_no_restart(%rip), %r11
    cmp %r11, 48(%rsp)
    jne fail

    mov $57, %eax
    syscall
    test %rax, %rax
    js fail
    je child_restart
    mov %rax, %r15

    mov %r15, %rdi
    lea 56(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r15, %rax
    jne fail
    cmpq $1, restart_hits(%rip)
    jne fail
    cmpq $0, 56(%rsp)
    jne fail

    mov $12, %edi
    lea no_restart_action(%rip), %rsi
    lea 144(%rsp), %rdx
    mov $8, %r10d
    mov $13, %eax
    syscall
    test %rax, %rax
    js fail

    lea 64(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail

    mov $57, %eax
    syscall
    test %rax, %rax
    js fail
    je child_read_no_restart
    mov %rax, %r14

    mov 68(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    js fail

    mov 64(%rsp), %edi
    mov 64(%rsp), %edi
    lea 80(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmpq $2, no_restart_hits(%rip)
    je 7f
    cmpq $2, restart_hits(%rip)
    je fail_27
    mov $-11, %r11
    cmp %r11, %rax
    je fail_25
    test %rax, %rax
    je fail_26
    jmp fail_22
7:
    mov $-4, %r11
    cmp %r11, %rax
    jne fail_21

    mov 64(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    js fail
    mov %r14d, %edi
    lea 72(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14, %rax
    jne fail_23
    cmpq $0, 72(%rsp)
    jne fail_24

    mov $12, %edi
    lea restart_action(%rip), %rsi
    lea 152(%rsp), %rdx
    mov $8, %r10d
    mov $13, %eax
    syscall
    test %rax, %rax
    js fail

    lea 88(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail

    mov $57, %eax
    syscall
    test %rax, %rax
    js fail
    je child_read_restart
    mov %rax, %r15

    mov 92(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    js fail

    mov 88(%rsp), %edi
    mov 88(%rsp), %edi
    lea 104(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmpq $2, restart_hits(%rip)
    jne fail_32
    cmpq $1, %rax
    jne fail_31
    cmpb $0x52, 104(%rsp)
    jne fail_33

    mov 88(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    js fail
    mov %r15d, %edi
    lea 96(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r15, %rax
    jne fail_34
    cmpq $0, 96(%rsp)
    jne fail_35

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

child_no_restart:
    mov %r12d, %edi
    mov $12, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    js child_fail
    mov $50000000, %ecx
1:
    dec %ecx
    jne 1b
    mov $231, %eax
    xor %edi, %edi
    syscall

child_restart:
    mov %r12d, %edi
    mov $12, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    js child_fail
    mov $50000000, %ecx
2:
    dec %ecx
    jne 2b
    mov $231, %eax
    xor %edi, %edi
    syscall

child_read_no_restart:
    mov $50000000, %ecx
3:
    dec %ecx
    jne 3b
    mov %r12d, %edi
    mov $12, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    js child_fail
    mov $50000000, %ecx
4:
    dec %ecx
    jne 4b
    mov $231, %eax
    xor %edi, %edi
    syscall

child_read_restart:
    mov $50000000, %ecx
5:
    dec %ecx
    jne 5b
    mov %r12d, %edi
    mov $12, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    js child_fail
    mov $50000000, %ecx
6:
    dec %ecx
    jne 6b
    mov 92(%rsp), %edi
    lea restart_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmpq $1, %rax
    jne child_fail
    mov $231, %eax
    xor %edi, %edi
    syscall

restorer:
    mov $15, %eax
    syscall
    ud2

handler_no_restart:
    incq no_restart_hits(%rip)
    ret

handler_restart:
    incq restart_hits(%rip)
    ret

child_fail:
    mov $231, %eax
    mov $2, %edi
    syscall

fail:
    mov $1, %edi
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

fail_code:
    mov $231, %eax
    syscall

.section .rodata
success_message:
    .ascii "round4 signal ok\n"
success_message_end:
.set success_message_len, success_message_end - success_message

.section .data
.align 8
sigusr1_mask:
    .quad 0x200
zero_mask:
    .quad 0
ignore_action:
    .quad 1
    .quad 0
    .quad 0
    .quad 0
no_restart_action:
    .quad handler_no_restart
    .quad 0x04000000
    .quad restorer
    .quad 0
restart_action:
    .quad handler_restart
    .quad 0x14000000
    .quad restorer
    .quad 0
no_restart_hits:
    .quad 0
restart_hits:
    .quad 0
restart_byte:
    .byte 0x52
