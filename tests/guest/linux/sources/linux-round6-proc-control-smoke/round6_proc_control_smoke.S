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
child_task_dir_path:
    .asciz "/proc/2/task"
child_task_comm_path:
    .asciz "/proc/2/task/2/comm"
child_task_status_path:
    .asciz "/proc/2/task/2/status"
comm_expected:
    .ascii "linux-round6-proc-control-smoke\n"
comm_expected_len = . - comm_expected
cmdline_expected:
    .ascii "linux-round6-proc-control-smoke\0"
cmdline_expected_len = . - cmdline_expected
task_pid_line:
    .ascii "Pid:\t1\n"
task_pid_line_len = . - task_pid_line
child_pid_line:
    .ascii "Pid:\t2\n"
child_pid_line_len = . - child_pid_line
child_tgid_line:
    .ascii "Tgid:\t2\n"
child_tgid_line_len = . - child_tgid_line
dirent_name_1:
    .ascii "1\0"
dirent_name_1_len = . - dirent_name_1
dirent_name_2:
    .ascii "2\0"
dirent_name_2_len = . - dirent_name_2
sigchld_mask:
    .quad 0x0000000000010000
ack_byte:
    .byte 0x41

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
    js fail_1
    mov %eax, %r15d

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
    cmp $2, %r14d
    jne fail_18

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

    mov $-100, %edi
    lea child_task_dir_path(%rip), %rsi
    mov $0x10000, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_22
    mov %eax, %r12d

    mov %r12d, %edi
    lea 1280(%rsp), %rsi
    mov $256, %edx
    mov $217, %eax
    syscall
    cmpq $0, %rax
    jle fail_23
    mov %rax, %r13

    lea 1280(%rsp), %rdi
    mov %r13, %rsi
    lea dirent_name_2(%rip), %rdx
    mov $dirent_name_2_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_24

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_25

    mov $-100, %edi
    lea child_task_comm_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_26
    mov %eax, %r12d

    mov %r12d, %edi
    lea 1536(%rsp), %rsi
    mov $128, %edx
    xor %eax, %eax
    syscall
    cmpq $0, %rax
    jle fail_27
    mov %rax, %r13

    lea 1536(%rsp), %rdi
    mov %r13, %rsi
    lea comm_expected(%rip), %rdx
    mov $comm_expected_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_28

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_29

    mov $-100, %edi
    lea child_task_status_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_30
    mov %eax, %r12d

    mov %r12d, %edi
    lea 1792(%rsp), %rsi
    mov $256, %edx
    xor %eax, %eax
    syscall
    cmpq $0, %rax
    jle fail_31
    mov %rax, %r13

    lea 1792(%rsp), %rdi
    mov %r13, %rsi
    lea child_pid_line(%rip), %rdx
    mov $child_pid_line_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_32

    lea 1792(%rsp), %rdi
    mov %r13, %rsi
    lea child_tgid_line(%rip), %rdx
    mov $child_tgid_line_len, %ecx
    call contains_bytes
    test %eax, %eax
    jz fail_33

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_34

    mov %r14d, %edi
    mov $20, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    jne fail_35

    mov %r14d, %edi
    lea 1024(%rsp), %rsi
    mov $2, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14d, %eax
    jne fail_36

    mov 1024(%rsp), %r11d
    mov %r11d, %r10d
    and $0xff, %r10d
    cmp $0x7f, %r10d
    jne fail_37
    shr $8, %r11d
    and $0xff, %r11d
    cmp $20, %r11d
    jne fail_38

    mov %r15d, %edi
    lea 2048(%rsp), %rsi
    mov $128, %edx
    xor %eax, %eax
    syscall
    cmpq $128, %rax
    jne fail_39
    cmpl $17, 2048(%rsp)
    jne fail_40
    cmpl $5, 2056(%rsp)
    jne fail_41
    cmpl %r14d, 2060(%rsp)
    jne fail_42
    cmpl $20, 2088(%rsp)
    jne fail_43

    mov %r14d, %edi
    mov $18, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    jne fail_44

    mov %r14d, %edi
    lea 1024(%rsp), %rsi
    mov $8, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14d, %eax
    jne fail_45
    mov 1024(%rsp), %r11d
    cmp $0xffff, %r11d
    jne fail_46

    mov %r15d, %edi
    lea 2176(%rsp), %rsi
    mov $128, %edx
    xor %eax, %eax
    syscall
    cmpq $128, %rax
    jne fail_47
    cmpl $17, 2176(%rsp)
    jne fail_48
    cmpl $6, 2184(%rsp)
    jne fail_49
    cmpl %r14d, 2188(%rsp)
    jne fail_50
    cmpl $18, 2216(%rsp)
    jne fail_51

    mov 12(%rsp), %edi
    lea ack_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmpq $1, %rax
    jne fail_52

    mov 12(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_53

    mov %r15d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_54

    mov %r14d, %edi
    lea 1024(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14d, %eax
    jne fail_55
    cmpl $0, 1024(%rsp)
    jne fail_56

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmpq $success_message_len, %rax
    jne fail_57

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
fail_48: mov $48, %edi; jmp fail_exit
fail_49: mov $49, %edi; jmp fail_exit
fail_50: mov $50, %edi; jmp fail_exit
fail_51: mov $51, %edi; jmp fail_exit
fail_52: mov $52, %edi; jmp fail_exit
fail_53: mov $53, %edi; jmp fail_exit
fail_54: mov $54, %edi; jmp fail_exit
fail_55: mov $55, %edi; jmp fail_exit
fail_56: mov $56, %edi; jmp fail_exit
fail_57: mov $57, %edi; jmp fail_exit

fail_exit:
    mov $60, %eax
    syscall
