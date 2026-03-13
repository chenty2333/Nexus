.section .bss
.align 8
bitset_futex:
    .long 0
    .long 0
bitset_waiter1_entered:
    .quad 0
bitset_waiter2_entered:
    .quad 0
bitset_waiter1_result:
    .quad 0
bitset_waiter2_result:
    .quad 0

owner_ready:
    .quad 0
owner_release:
    .quad 0
owner_tid_slot:
    .quad 0
owner_result:
    .quad 0
robust_read_head:
    .quad 0
robust_read_len:
    .quad 0

.align 8
robust_head:
    .quad 0
    .quad 0
    .quad 0
robust_node:
    .quad 0
robust_node_futex:
    .long 0
    .long 0

.section .text
.global _start
.type _start, @function
_start:
    sub $256, %rsp

    movq $-1, bitset_waiter1_result(%rip)
    movq $-1, bitset_waiter2_result(%rip)
    movq $-1, owner_result(%rip)

    xor %edi, %edi
    mov $65536, %esi
    mov $3, %edx
    mov $34, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_1
    mov %rax, %rbx

    lea 8192(%rbx), %rsi
    mov $0x10f00, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_2
    jz bitset_waiter1

    lea 16384(%rbx), %rsi
    mov $0x10f00, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_3
    jz bitset_waiter2

bitset_waiters_entered_spin:
    cmpq $1, bitset_waiter1_entered(%rip)
    jne bitset_waiters_entered_spin
    cmpq $1, bitset_waiter2_entered(%rip)
    jne bitset_waiters_entered_spin

    lea bitset_futex(%rip), %rdi
    mov $138, %esi
    mov $1, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $2, %r9d
    mov $202, %eax
    syscall
    cmpq $1, %rax
    jne fail_4

bitset_waiter2_done_spin:
    cmpq $0, bitset_waiter2_result(%rip)
    jne bitset_waiter2_done_spin
    cmpq $-1, bitset_waiter1_result(%rip)
    jne fail_5

    lea bitset_futex(%rip), %rdi
    mov $138, %esi
    mov $1, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $4, %r9d
    mov $202, %eax
    syscall
    test %rax, %rax
    jne fail_6

    lea bitset_futex(%rip), %rdi
    mov $138, %esi
    mov $1, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $1, %r9d
    mov $202, %eax
    syscall
    cmpq $1, %rax
    jne fail_7

bitset_waiter1_done_spin:
    cmpq $0, bitset_waiter1_result(%rip)
    jne bitset_waiter1_done_spin

    movq $0, owner_ready(%rip)
    movq $0, owner_release(%rip)
    movq $0, owner_tid_slot(%rip)
    movq $-1, owner_result(%rip)
    movq $0, robust_read_head(%rip)
    movq $0, robust_read_len(%rip)
    movq $0, robust_head(%rip)
    movq $0, robust_head+8(%rip)
    movq $0, robust_head+16(%rip)
    movq $0, robust_node(%rip)
    movl $0, robust_node_futex(%rip)

    lea 24576(%rbx), %rsi
    mov $0x10f00, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_8
    jz robust_owner

robust_owner_ready_spin:
    cmpq $1, owner_ready(%rip)
    je release_robust_owner
    movq owner_result(%rip), %rax
    cmpq $0, %rax
    jg fail_9
    jmp robust_owner_ready_spin

release_robust_owner:
    movq $1, owner_release(%rip)

robust_owner_died_spin:
    mov robust_node_futex(%rip), %eax
    test $0x40000000, %eax
    jz robust_owner_died_spin
    test $0x3fffffff, %eax
    jne fail_10
    cmpq $0, owner_result(%rip)
    jne fail_11

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

bitset_waiter1:
    movq $1, bitset_waiter1_entered(%rip)
    lea bitset_futex(%rip), %rdi
    mov $137, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $1, %r9d
    mov $202, %eax
    syscall
    mov %rax, bitset_waiter1_result(%rip)
    mov $60, %eax
    xor %edi, %edi
    syscall

bitset_waiter2:
    movq $1, bitset_waiter2_entered(%rip)
    lea bitset_futex(%rip), %rdi
    mov $137, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $2, %r9d
    mov $202, %eax
    syscall
    mov %rax, bitset_waiter2_result(%rip)
    mov $60, %eax
    xor %edi, %edi
    syscall

robust_owner:
    mov $186, %eax
    syscall
    test %rax, %rax
    js robust_fail_1
    mov %rax, owner_tid_slot(%rip)

    lea robust_node(%rip), %rax
    mov %rax, robust_head(%rip)
    movq $8, robust_head+8(%rip)
    movq $0, robust_head+16(%rip)
    lea robust_head(%rip), %rax
    mov %rax, robust_node(%rip)
    mov owner_tid_slot(%rip), %eax
    mov %eax, robust_node_futex(%rip)

    lea robust_head(%rip), %rdi
    mov $24, %rsi
    mov $273, %eax
    syscall
    test %rax, %rax
    jne robust_fail_2

    xor %edi, %edi
    lea robust_read_head(%rip), %rsi
    lea robust_read_len(%rip), %rdx
    mov $274, %eax
    syscall
    test %rax, %rax
    jne robust_fail_3

    lea robust_head(%rip), %rax
    cmp %rax, robust_read_head(%rip)
    jne robust_fail_4
    cmpq $24, robust_read_len(%rip)
    jne robust_fail_5

    movq $0, owner_result(%rip)
    movq $1, owner_ready(%rip)

robust_owner_release_spin:
    cmpq $1, owner_release(%rip)
    jne robust_owner_release_spin
    mov $60, %eax
    xor %edi, %edi
    syscall

robust_fail_1:
    movq $1, owner_result(%rip)
    movq $1, owner_ready(%rip)
    mov $60, %eax
    mov $1, %edi
    syscall
robust_fail_2:
    movq $2, owner_result(%rip)
    movq $1, owner_ready(%rip)
    mov $60, %eax
    mov $2, %edi
    syscall
robust_fail_3:
    movq $3, owner_result(%rip)
    movq $1, owner_ready(%rip)
    mov $60, %eax
    mov $3, %edi
    syscall
robust_fail_4:
    movq $4, owner_result(%rip)
    movq $1, owner_ready(%rip)
    mov $60, %eax
    mov $4, %edi
    syscall
robust_fail_5:
    movq $5, owner_result(%rip)
    movq $1, owner_ready(%rip)
    mov $60, %eax
    mov $5, %edi
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
    mov owner_result(%rip), %rdi
    add $16, %edi
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
    .ascii "round6 futex ok\n"
success_message_end:
.set success_message_len, success_message_end - success_message
