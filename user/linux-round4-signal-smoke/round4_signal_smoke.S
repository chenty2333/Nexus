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

fail:
    mov $231, %eax
    mov $1, %edi
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
