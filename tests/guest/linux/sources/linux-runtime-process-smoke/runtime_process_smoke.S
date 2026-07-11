.section .rodata
success_message:
    .ascii "runtime process ok\n"
success_message_len = . - success_message
runtime_process_path:
    .asciz "bin/linux-runtime-process-smoke"
root_path:
    .asciz "/"
empty_path:
    .asciz ""

.section .text
.global _start
.type _start, @function
_start:
    sub $128, %rsp

    mov $102, %eax
    syscall
    test %rax, %rax
    jne fail_1

    mov $107, %eax
    syscall
    test %rax, %rax
    jne fail_2

    mov $104, %eax
    syscall
    test %rax, %rax
    jne fail_3

    mov $108, %eax
    syscall
    test %rax, %rax
    jne fail_4

    mov $110, %eax
    syscall
    test %rax, %rax
    js fail_5

    lea runtime_process_path(%rip), %rdi
    mov $4, %esi
    mov $21, %eax
    syscall
    test %rax, %rax
    jne fail_6

    lea runtime_process_path(%rip), %rdi
    mov $2, %esi
    mov $21, %eax
    syscall
    cmpq $-13, %rax
    jne fail_7

    mov $-100, %edi
    lea root_path(%rip), %rsi
    mov $1, %edx
    mov $269, %eax
    syscall
    test %rax, %rax
    jne fail_8

    mov $-100, %edi
    lea runtime_process_path(%rip), %rsi
    mov $0x200000, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_9
    mov %eax, %r12d

    mov %r12d, %edi
    lea empty_path(%rip), %rsi
    mov $4, %edx
    mov $0x1000, %r10d
    mov $439, %eax
    syscall
    test %rax, %rax
    jne fail_10

    xor %edi, %edi
    mov $3, %esi
    xor %edx, %edx
    lea 0(%rsp), %r10
    xor %r8d, %r8d
    mov $302, %eax
    syscall
    test %rax, %rax
    jne fail_11

    mov 0(%rsp), %rax
    cmpq $0x10000, %rax
    jb fail_12
    mov 8(%rsp), %rcx
    cmp %rax, %rcx
    jb fail_13

    xor %edi, %edi
    mov $7, %esi
    xor %edx, %edx
    lea 16(%rsp), %r10
    xor %r8d, %r8d
    mov $302, %eax
    syscall
    test %rax, %rax
    jne fail_14

    mov 16(%rsp), %rax
    cmpq $64, %rax
    jb fail_15

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_16

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmpq $success_message_len, %rax
    jne fail_17

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
fail_16: mov $16, %edi; jmp fail_exit
fail_17: mov $17, %edi; jmp fail_exit

fail_exit:
    mov $60, %eax
    syscall
