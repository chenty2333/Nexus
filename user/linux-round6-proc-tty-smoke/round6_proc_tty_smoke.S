.section .rodata
success_message:
    .ascii "round6 proc_tty ok\n"
success_message_len = . - success_message
child_task_status_path:
    .asciz "/proc/2/task/2/status"
child_task_stat_path:
    .asciz "/proc/2/task/2/stat"
state_stopped_line:
    .ascii "State:\tT\n"
state_stopped_line_len = . - state_stopped_line
thread_stat_stopped_fragment:
    .ascii ") T "
thread_stat_stopped_fragment_len = . - thread_stat_stopped_fragment
sigchld_mask:
    .quad 0x0000000000010000
sync_byte:
    .byte 0x51
resume_byte:
    .byte 0x52
tty_byte:
    .byte 0x74

.section .text
.global _start
.type _start, @function
_start:
    sub $4096, %rsp

    mov $0, %edi
    lea sigchld_mask(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $14, %eax
    syscall
    test %rax, %rax
    jne fail_1

    mov $-1, %edi
    lea sigchld_mask(%rip), %rsi
    mov $8, %edx
    xor %r10d, %r10d
    mov $289, %eax
    syscall
    test %rax, %rax
    js fail_2
    mov %eax, %r15d

    lea 0(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_3

    lea 8(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_4

    mov $57, %eax
    syscall
    test %rax, %rax
    js fail_5
    jz child_entry
    mov %eax, %r14d
    cmp $2, %r14d
    jne fail_6

    mov 4(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_7

    mov 8(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_8

    mov 0(%rsp), %edi
    lea 32(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmpq $1, %rax
    jne fail_9

    mov 0(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_10

    mov %r14d, %edi
    lea 1024(%rsp), %rsi
    mov $2, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14d, %eax
    jne fail_11

    mov 1024(%rsp), %r11d
    mov %r11d, %r10d
    and $0xff, %r10d
    cmp $0x7f, %r10d
    jne fail_12
    shr $8, %r11d
    and $0xff, %r11d
    cmp $21, %r11d
    jne fail_13

    mov %r15d, %edi
    lea 2048(%rsp), %rsi
    mov $128, %edx
    xor %eax, %eax
    syscall
    cmpq $128, %rax
    jne fail_14
    cmpl $17, 2048(%rsp)
    jne fail_15
    cmpl $5, 2056(%rsp)
    jne fail_16
    cmpl %r14d, 2060(%rsp)
    jne fail_17
    cmpl $21, 2088(%rsp)
    jne fail_18

    mov $-100, %edi
    lea child_task_status_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_19
    mov %eax, %r12d

    mov %r12d, %edi
    lea 1536(%rsp), %rsi
    mov $256, %edx
    xor %eax, %eax
    syscall
    cmpq $0, %rax
    jle fail_20
    mov %rax, %r13

    lea 1536(%rsp), %rdi
    mov %r13, %rsi
    lea state_stopped_line(%rip), %rdx
    mov $state_stopped_line_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_21

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_22

    mov $-100, %edi
    lea child_task_stat_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_23
    mov %eax, %r12d

    mov %r12d, %edi
    lea 1792(%rsp), %rsi
    mov $256, %edx
    xor %eax, %eax
    syscall
    cmpq $0, %rax
    jle fail_24
    mov %rax, %r13

    lea 1792(%rsp), %rdi
    mov %r13, %rsi
    lea thread_stat_stopped_fragment(%rip), %rdx
    mov $thread_stat_stopped_fragment_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_25

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_26

    mov %r14d, %edi
    mov $1, %esi
    mov $109, %eax
    syscall
    test %rax, %rax
    jne fail_27

    mov %r14d, %edi
    mov $18, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    jne fail_28

    mov %r14d, %edi
    lea 1024(%rsp), %rsi
    mov $8, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14d, %eax
    jne fail_29
    mov 1024(%rsp), %r11d
    cmp $0xffff, %r11d
    jne fail_30

    mov 12(%rsp), %edi
    lea resume_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmpq $1, %rax
    jne fail_36

    mov 12(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_37

    mov %r14d, %edi
    lea 1024(%rsp), %rsi
    mov $2, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14d, %eax
    jne fail_38

    mov 1024(%rsp), %r11d
    mov %r11d, %r10d
    and $0xff, %r10d
    cmp $0x7f, %r10d
    jne fail_39
    shr $8, %r11d
    and $0xff, %r11d
    cmp $22, %r11d
    jne fail_40

    mov %r15d, %edi
    lea 2304(%rsp), %rsi
    mov $128, %edx
    xor %eax, %eax
    syscall
    cmpq $128, %rax
    jne fail_41
    cmpl $17, 2304(%rsp)
    jne fail_42
    cmpl $5, 2312(%rsp)
    jne fail_43
    cmpl %r14d, 2316(%rsp)
    jne fail_44
    cmpl $22, 2344(%rsp)
    jne fail_45

    mov %r14d, %edi
    mov $1, %esi
    mov $109, %eax
    syscall
    test %rax, %rax
    jne fail_46

    mov %r14d, %edi
    mov $18, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    jne fail_47

    mov %r14d, %edi
    lea 1024(%rsp), %rsi
    mov $8, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14d, %eax
    jne fail_48
    mov 1024(%rsp), %r11d
    cmp $0xffff, %r11d
    jne fail_49

    mov %r15d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_50

    mov %r14d, %edi
    lea 1024(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14d, %eax
    jne fail_51
    cmpl $0, 1024(%rsp)
    jne fail_52

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmpq $success_message_len, %rax
    jne fail_53

    xor %edi, %edi
    mov $60, %eax
    syscall

child_entry:
    mov %r15d, %edi
    mov $3, %eax
    syscall

    mov 0(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne child_fail

    mov 12(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne child_fail

    xor %edi, %edi
    xor %esi, %esi
    mov $109, %eax
    syscall
    test %rax, %rax
    jne child_fail

    mov 4(%rsp), %edi
    lea sync_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmpq $1, %rax
    jne child_fail

    mov 4(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne child_fail

    xor %edi, %edi
    lea 40(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    test %eax, %eax
    jns child_fail

    mov 8(%rsp), %edi
    lea 41(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmpq $1, %rax
    jne child_fail

    mov 8(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne child_fail

    xor %edi, %edi
    xor %esi, %esi
    mov $109, %eax
    syscall
    test %rax, %rax
    jne child_fail

    mov $1, %edi
    lea tty_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmpq $1, %rax
    jne child_fail

    xor %edi, %edi
    mov $60, %eax
    syscall

child_fail:
    mov $101, %edi
    mov $60, %eax
    syscall

contains_bytes:
    push %rbx
    cmp %rcx, %rsi
    jb contains_not_found
    xor %r8d, %r8d
contains_outer:
    mov %rsi, %r9
    sub %r8, %r9
    cmp %rcx, %r9
    jb contains_not_found
    lea (%rdi,%r8), %r11
    xor %r10d, %r10d
contains_inner:
    cmp %rcx, %r10
    je contains_found
    movzbq (%r11,%r10,1), %rax
    movzbq (%rdx,%r10,1), %rbx
    cmp %rbx, %rax
    jne contains_next
    inc %r10
    jmp contains_inner
contains_next:
    inc %r8
    jmp contains_outer
contains_found:
    mov $1, %eax
    pop %rbx
    ret
contains_not_found:
    xor %eax, %eax
    pop %rbx
    ret

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
fail_18: mov $18, %edi; jmp fail_exit
fail_19: mov $19, %edi; jmp fail_exit
fail_20: mov $20, %edi; jmp fail_exit
fail_21: mov $21, %edi; jmp fail_exit
fail_22: mov $22, %edi; jmp fail_exit
fail_23: mov $23, %edi; jmp fail_exit
fail_24: mov $24, %edi; jmp fail_exit
fail_25: mov $25, %edi; jmp fail_exit
fail_26: mov $26, %edi; jmp fail_exit
fail_27: mov $27, %edi; jmp fail_exit
fail_28: mov $28, %edi; jmp fail_exit
fail_29: mov $29, %edi; jmp fail_exit
fail_30: mov $30, %edi; jmp fail_exit
fail_36: mov $36, %edi; jmp fail_exit
fail_37: mov $37, %edi; jmp fail_exit
fail_38: mov $38, %edi; jmp fail_exit
fail_39: mov $39, %edi; jmp fail_exit
fail_40: mov $40, %edi; jmp fail_exit
fail_41: mov $41, %edi; jmp fail_exit
fail_42: mov $42, %edi; jmp fail_exit
fail_43: mov $43, %edi; jmp fail_exit
fail_44: mov $44, %edi; jmp fail_exit
fail_45: mov $45, %edi; jmp fail_exit
fail_46: mov $46, %edi; jmp fail_exit
fail_47: mov $47, %edi; jmp fail_exit
fail_48: mov $48, %edi; jmp fail_exit
fail_49: mov $49, %edi; jmp fail_exit
fail_50: mov $50, %edi; jmp fail_exit
fail_51: mov $51, %edi; jmp fail_exit
fail_52: mov $52, %edi; jmp fail_exit
fail_53: mov $53, %edi; jmp fail_exit

fail_exit:
    mov $60, %eax
    syscall
