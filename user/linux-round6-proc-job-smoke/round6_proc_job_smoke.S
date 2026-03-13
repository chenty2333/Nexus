.section .rodata
success_message:
    .ascii "round6 proc_job ok\n"
success_message_len = . - success_message
proc_fd_message:
    .ascii "proc-fd bridge ok\n"
proc_fd_message_len = . - proc_fd_message
status_path:
    .asciz "/proc/self/status"
fd_dir_path:
    .asciz "/proc/self/fd"
fd_stdout_path:
    .asciz "/proc/self/fd/1"
status_name_prefix:
    .ascii "Name:\tlinux-round6-proc-job-smoke\n"
status_name_prefix_len = . - status_name_prefix
status_pgid_line:
    .ascii "Pgid:\t1\n"
status_pgid_line_len = . - status_pgid_line
status_sid_line:
    .ascii "Sid:\t1\n"
status_sid_line_len = . - status_sid_line
dirent_name_0:
    .ascii "0\0"
dirent_name_0_len = . - dirent_name_0
dirent_name_1:
    .ascii "1\0"
dirent_name_1_len = . - dirent_name_1
dirent_name_2:
    .ascii "2\0"
dirent_name_2_len = . - dirent_name_2
ack_byte:
    .byte 0x41

.section .text
.global _start
.type _start, @function
_start:
    sub $4096, %rsp

    mov $111, %eax
    syscall
    cmpq $1, %rax
    jne fail_1

    xor %edi, %edi
    mov $121, %eax
    syscall
    cmpq $1, %rax
    jne fail_2

    xor %edi, %edi
    mov $124, %eax
    syscall
    cmpq $1, %rax
    jne fail_3

    mov $-100, %edi
    lea status_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_4
    mov %eax, %r12d

    mov %r12d, %edi
    lea 128(%rsp), %rsi
    mov $512, %edx
    xor %eax, %eax
    syscall
    cmpq $0, %rax
    jle fail_5
    mov %rax, %r13

    lea 128(%rsp), %rdi
    mov %r13, %rsi
    lea status_name_prefix(%rip), %rdx
    mov $status_name_prefix_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_6

    lea 128(%rsp), %rdi
    mov %r13, %rsi
    lea status_pgid_line(%rip), %rdx
    mov $status_pgid_line_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_7

    lea 128(%rsp), %rdi
    mov %r13, %rsi
    lea status_sid_line(%rip), %rdx
    mov $status_sid_line_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_8

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_9

    mov $-100, %edi
    lea fd_dir_path(%rip), %rsi
    mov $0x10000, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_open_fd_dir_errno
    mov %eax, %r12d

    mov %r12d, %edi
    lea 768(%rsp), %rsi
    mov $512, %edx
    mov $217, %eax
    syscall
    cmpq $0, %rax
    jle fail_11
    mov %rax, %r13

    lea 768(%rsp), %rdi
    mov %r13, %rsi
    lea dirent_name_0(%rip), %rdx
    mov $dirent_name_0_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_12

    lea 768(%rsp), %rdi
    mov %r13, %rsi
    lea dirent_name_1(%rip), %rdx
    mov $dirent_name_1_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_13

    lea 768(%rsp), %rdi
    mov %r13, %rsi
    lea dirent_name_2(%rip), %rdx
    mov $dirent_name_2_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_14

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_15

    mov $-100, %edi
    lea fd_stdout_path(%rip), %rsi
    mov $0x1, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_16
    mov %eax, %r12d

    mov %r12d, %edi
    lea proc_fd_message(%rip), %rsi
    mov $proc_fd_message_len, %edx
    mov $1, %eax
    syscall
    cmpq $proc_fd_message_len, %rax
    jne fail_17

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_18

    lea 0(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_19
    lea 8(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_19

    mov $57, %eax
    syscall
    test %rax, %rax
    js fail_20
    jz child_same_group
    mov %eax, %r14d

    mov 4(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_21
    mov 8(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_21

    mov 0(%rsp), %edi
    lea 64(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmpq $1, %rax
    jne fail_21

    mov %r14d, %edi
    mov $9, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    jne fail_22

    xor %edi, %edi
    lea 1152(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14d, %eax
    jne fail_23
    mov 1152(%rsp), %r11d
    and $0x7f, %r11d
    cmp $9, %r11d
    jne fail_24

    mov 0(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_25
    mov 12(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_26

    lea 16(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_27
    lea 24(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_27

    mov $57, %eax
    syscall
    test %rax, %rax
    js fail_28
    jz child_setpgid
    mov %eax, %r14d

    mov 20(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_29
    mov 24(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_29

    mov 16(%rsp), %edi
    lea 65(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmpq $1, %rax
    jne fail_29

    mov %r14d, %edi
    mov $121, %eax
    syscall
    cmp %r14d, %eax
    jne fail_30

    mov %r14d, %edi
    mov $124, %eax
    syscall
    cmpq $1, %rax
    jne fail_31

    neg %r14d
    mov %r14d, %edi
    mov $9, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    jne fail_32

    mov %r14d, %edi
    neg %edi
    lea 1152(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    neg %r14d
    cmp %r14d, %eax
    jne fail_33
    mov 1152(%rsp), %r11d
    and $0x7f, %r11d
    cmp $9, %r11d
    jne fail_34

    mov 16(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_35
    mov 28(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_36

    lea 32(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_37
    lea 40(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_37

    mov $57, %eax
    syscall
    test %rax, %rax
    js fail_38
    jz child_setsid
    mov %eax, %r14d

    mov 36(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_39
    mov 40(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_39

    mov 32(%rsp), %edi
    lea 66(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmpq $1, %rax
    jne fail_39

    mov %r14d, %edi
    mov $121, %eax
    syscall
    cmp %r14d, %eax
    jne fail_40

    mov %r14d, %edi
    mov $124, %eax
    syscall
    cmp %r14d, %eax
    jne fail_41

    neg %r14d
    mov %r14d, %edi
    mov $9, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    jne fail_42

    mov %r14d, %edi
    neg %edi
    lea 1152(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    neg %r14d
    cmp %r14d, %eax
    jne fail_43
    mov 1152(%rsp), %r11d
    and $0x7f, %r11d
    cmp $9, %r11d
    jne fail_44

    mov 32(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_45
    mov 44(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_46

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmpq $success_message_len, %rax
    jne fail_47

    xor %edi, %edi
    mov $60, %eax
    syscall

child_same_group:
    mov 0(%rsp), %edi
    mov $3, %eax
    syscall
    mov 12(%rsp), %edi
    mov $3, %eax
    syscall
    mov 4(%rsp), %edi
    lea ack_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmpq $1, %rax
    jne child_fail_1
    mov 4(%rsp), %edi
    mov $3, %eax
    syscall
    mov 8(%rsp), %edi
    lea 67(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
child_fail_1:
    mov $101, %edi
    mov $60, %eax
    syscall

child_setpgid:
    mov 16(%rsp), %edi
    mov $3, %eax
    syscall
    mov 28(%rsp), %edi
    mov $3, %eax
    syscall
    xor %edi, %edi
    xor %esi, %esi
    mov $109, %eax
    syscall
    test %rax, %rax
    jne child_fail_2
    mov $39, %eax
    syscall
    mov %eax, %r12d
    xor %edi, %edi
    mov $121, %eax
    syscall
    cmp %r12d, %eax
    jne child_fail_2
    xor %edi, %edi
    mov $124, %eax
    syscall
    cmpq $1, %rax
    jne child_fail_2
    mov 20(%rsp), %edi
    lea ack_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmpq $1, %rax
    jne child_fail_2
    mov 20(%rsp), %edi
    mov $3, %eax
    syscall
    mov 24(%rsp), %edi
    lea 68(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
child_fail_2:
    mov $102, %edi
    mov $60, %eax
    syscall

child_setsid:
    mov 32(%rsp), %edi
    mov $3, %eax
    syscall
    mov 44(%rsp), %edi
    mov $3, %eax
    syscall
    mov $39, %eax
    syscall
    mov %eax, %r12d
    mov $112, %eax
    syscall
    cmp %r12d, %eax
    jne child_fail_3
    mov $111, %eax
    syscall
    cmp %r12d, %eax
    jne child_fail_3
    xor %edi, %edi
    mov $124, %eax
    syscall
    cmp %r12d, %eax
    jne child_fail_3
    mov 36(%rsp), %edi
    lea ack_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmpq $1, %rax
    jne child_fail_3
    mov 36(%rsp), %edi
    mov $3, %eax
    syscall
    mov 40(%rsp), %edi
    lea 69(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
child_fail_3:
    mov $103, %edi
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
fail_open_fd_dir_errno:
    mov %eax, %edi
    neg %edi
    add $100, %edi
    jmp fail_exit
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
fail_31: mov $31, %edi; jmp fail_exit
fail_32: mov $32, %edi; jmp fail_exit
fail_33: mov $33, %edi; jmp fail_exit
fail_34: mov $34, %edi; jmp fail_exit
fail_35: mov $35, %edi; jmp fail_exit
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

fail_exit:
    mov $60, %eax
    syscall
