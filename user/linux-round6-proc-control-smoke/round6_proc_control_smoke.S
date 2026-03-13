.section .rodata
success_message:
    .ascii "round6 proc_control ok\n"
success_message_len = . - success_message
comm_path:
    .asciz "/proc/self/comm"
cmdline_path:
    .asciz "/proc/self/cmdline"
task_dir_path:
    .asciz "/proc/self/task"
task_status_path:
    .asciz "/proc/self/task/1/status"
comm_expected:
    .ascii "linux-round6-proc-control-smoke\n"
comm_expected_len = . - comm_expected
cmdline_expected:
    .ascii "linux-round6-proc-control-smoke\0"
cmdline_expected_len = . - cmdline_expected
task_pid_line:
    .ascii "Pid:\t1\n"
task_pid_line_len = . - task_pid_line
dirent_name_1:
    .ascii "1\0"
dirent_name_1_len = . - dirent_name_1
ack_byte:
    .byte 0x41

.section .text
.global _start
.type _start, @function
_start:
    sub $4096, %rsp

    mov $-100, %edi
    lea comm_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_1
    mov %eax, %r12d

    mov %r12d, %edi
    lea 256(%rsp), %rsi
    mov $128, %edx
    xor %eax, %eax
    syscall
    cmpq $0, %rax
    jle fail_2
    mov %rax, %r13

    lea 256(%rsp), %rdi
    mov %r13, %rsi
    lea comm_expected(%rip), %rdx
    mov $comm_expected_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_3

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_4

    mov $-100, %edi
    lea cmdline_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_5
    mov %eax, %r12d

    mov %r12d, %edi
    lea 384(%rsp), %rsi
    mov $128, %edx
    xor %eax, %eax
    syscall
    cmpq $0, %rax
    jle fail_6
    mov %rax, %r13

    lea 384(%rsp), %rdi
    mov %r13, %rsi
    lea cmdline_expected(%rip), %rdx
    mov $cmdline_expected_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_7

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_8

    mov $-100, %edi
    lea task_dir_path(%rip), %rsi
    mov $0x10000, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_9
    mov %eax, %r12d

    mov %r12d, %edi
    lea 512(%rsp), %rsi
    mov $256, %edx
    mov $217, %eax
    syscall
    cmpq $0, %rax
    jle fail_10
    mov %rax, %r13

    lea 512(%rsp), %rdi
    mov %r13, %rsi
    lea dirent_name_1(%rip), %rdx
    mov $dirent_name_1_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_11

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_12

    mov $-100, %edi
    lea task_status_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_13
    mov %eax, %r12d

    mov %r12d, %edi
    lea 768(%rsp), %rsi
    mov $256, %edx
    xor %eax, %eax
    syscall
    cmpq $0, %rax
    jle fail_14
    mov %rax, %r13

    lea 768(%rsp), %rdi
    mov %r13, %rsi
    lea task_pid_line(%rip), %rdx
    mov $task_pid_line_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_15

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_16

    lea 0(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_17
    lea 8(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_17

    mov $57, %eax
    syscall
    test %rax, %rax
    js fail_18
    jz child_entry
    mov %eax, %r14d

    mov 4(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_19
    mov 8(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_19

    mov 0(%rsp), %edi
    lea 32(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmpq $1, %rax
    jne fail_20

    mov 0(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_21

    mov %r14d, %edi
    mov $19, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    jne fail_22

    mov %r14d, %edi
    lea 1024(%rsp), %rsi
    mov $2, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14d, %eax
    jne fail_23

    mov 1024(%rsp), %r11d
    mov %r11d, %r10d
    and $0xff, %r10d
    cmp $0x7f, %r10d
    jne fail_24
    shr $8, %r11d
    and $0xff, %r11d
    cmp $19, %r11d
    jne fail_25

    mov %r14d, %edi
    mov $18, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    jne fail_26

    mov %r14d, %edi
    lea 1024(%rsp), %rsi
    mov $8, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14d, %eax
    jne fail_27
    mov 1024(%rsp), %r11d
    cmp $0xffff, %r11d
    jne fail_28

    mov 12(%rsp), %edi
    lea ack_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmpq $1, %rax
    jne fail_29

    mov 12(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_30

    mov %r14d, %edi
    lea 1024(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14d, %eax
    jne fail_31
    cmpl $0, 1024(%rsp)
    jne fail_32

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmpq $success_message_len, %rax
    jne fail_33

    xor %edi, %edi
    mov $60, %eax
    syscall

child_entry:
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
    jne child_fail

    mov 4(%rsp), %edi
    mov $3, %eax
    syscall

    mov 8(%rsp), %edi
    lea 40(%rsp), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmpq $1, %rax
    jne child_fail

    mov 8(%rsp), %edi
    mov $3, %eax
    syscall

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
fail_31: mov $31, %edi; jmp fail_exit
fail_32: mov $32, %edi; jmp fail_exit
fail_33: mov $33, %edi; jmp fail_exit

fail_exit:
    mov $60, %eax
    syscall
