.section .bss
.align 8
futex_a:
    .long 0
    .long 0
futex_b:
    .long 0
    .long 0
waiter1_entered:
    .quad 0
waiter2_entered:
    .quad 0
waiter3_entered:
    .quad 0
waiter1_result:
    .quad 0
waiter2_result:
    .quad 0
waiter3_result:
    .quad 0

.section .text
.global _start
.type _start, @function
_start:
    sub $256, %rsp

    movq $-1, waiter1_result(%rip)
    movq $-1, waiter2_result(%rip)
    movq $-1, waiter3_result(%rip)

    xor %edi, %edi
    mov $32768, %esi
    mov $3, %edx
    mov $34, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_1
    mov %rax, %rbx

    movl $1, futex_a(%rip)
    lea futex_a(%rip), %rdi
    mov $128, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $202, %eax
    syscall
    mov $-11, %r11
    cmp %r11, %rax
    jne fail_2
    movl $0, futex_a(%rip)

    lea 8192(%rbx), %rsi
    mov $0x10f00, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_3
    jz waiter1

waiter1_entered_spin:
    cmpq $1, waiter1_entered(%rip)
    jne waiter1_entered_spin

wake_waiter1:
    lea futex_a(%rip), %rdi
    mov $129, %esi
    mov $1, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $202, %eax
    syscall
    test %rax, %rax
    js fail_4
    cmpq $1, %rax
    jne wake_waiter1

waiter1_done_spin:
    cmpq $0, waiter1_result(%rip)
    jne waiter1_done_spin

    movq $0, waiter2_entered(%rip)
    movq $0, waiter3_entered(%rip)
    movq $-1, waiter2_result(%rip)
    movq $-1, waiter3_result(%rip)

    lea 16384(%rbx), %rsi
    mov $0x10f00, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_5
    jz waiter2

    lea 24576(%rbx), %rsi
    mov $0x10f00, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_6
    jz waiter3

waiter23_entered_spin:
    cmpq $1, waiter2_entered(%rip)
    jne waiter23_entered_spin
    cmpq $1, waiter3_entered(%rip)
    jne waiter23_entered_spin

requeue_first:
    lea futex_a(%rip), %rdi
    mov $131, %esi
    mov $1, %edx
    mov $1, %r10d
    lea futex_b(%rip), %r8
    xor %r9d, %r9d
    mov $202, %eax
    syscall
    test %rax, %rax
    js fail_7
    cmpq $1, %rax
    jne requeue_first

one_waiter_woken_spin:
    cmpq $0, waiter2_result(%rip)
    je wake_requeued
    cmpq $0, waiter3_result(%rip)
    je wake_requeued
    jmp one_waiter_woken_spin

wake_requeued:
    lea futex_b(%rip), %rdi
    mov $129, %esi
    mov $1, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $202, %eax
    syscall
    test %rax, %rax
    js fail_8
    cmpq $1, %rax
    je both_waiters_done_spin
    cmpq $0, %rax
    jne fail_9

requeue_second:
    lea futex_a(%rip), %rdi
    mov $131, %esi
    xor %edx, %edx
    mov $1, %r10d
    lea futex_b(%rip), %r8
    xor %r9d, %r9d
    mov $202, %eax
    syscall
    test %rax, %rax
    js fail_10
    test %rax, %rax
    jne fail_11
    jmp wake_requeued

both_waiters_done_spin:
    cmpq $0, waiter2_result(%rip)
    jne both_waiters_done_spin
    cmpq $0, waiter3_result(%rip)
    jne both_waiters_done_spin

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmp $success_message_len, %rax
    jne fail_12

    mov $231, %eax
    xor %edi, %edi
    syscall

waiter1:
    movq $1, waiter1_entered(%rip)
    lea futex_a(%rip), %rdi
    mov $128, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $202, %eax
    syscall
    mov %rax, waiter1_result(%rip)
    mov $60, %eax
    xor %edi, %edi
    syscall

waiter2:
    movq $1, waiter2_entered(%rip)
    lea futex_a(%rip), %rdi
    mov $128, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $202, %eax
    syscall
    mov %rax, waiter2_result(%rip)
    mov $60, %eax
    xor %edi, %edi
    syscall

waiter3:
    movq $1, waiter3_entered(%rip)
    lea futex_a(%rip), %rdi
    mov $128, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $202, %eax
    syscall
    mov %rax, waiter3_result(%rip)
    mov $60, %eax
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

fail_code:
    mov $231, %eax
    syscall

.section .rodata
success_message:
    .ascii "round4 futex ok\n"
success_message_end:
.set success_message_len, success_message_end - success_message
