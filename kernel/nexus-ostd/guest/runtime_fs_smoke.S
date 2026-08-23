.section .rodata
success_message:
    .ascii "runtime fs ok\n"
success_message_len = . - success_message
runtime_fs_path:
    .asciz "/bin/linux-runtime-fs-smoke"
runtime_fs_path_len = . - runtime_fs_path - 1
tmp_file_path:
    .asciz "/tmp/runtime-fs.bin"
proc_self_path:
    .asciz "/proc/self"
proc_exe_name:
    .asciz "exe"
empty_path:
    .asciz ""
rw_payload:
    .ascii "xy"
rw_payload_len = . - rw_payload
rw_expected:
    .byte 0x00, 0x00, 'x', 'y'
rw_expected_len = . - rw_expected
elf_magic:
    .byte 0x7f, 'E', 'L', 'F'

.section .text
.global _start
.type _start, @function
_start:
    sub $4096, %rsp

    mov $-100, %edi
    lea runtime_fs_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_1
    mov %eax, %r12d

    mov %r12d, %edi
    lea 1024(%rsp), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    mov $17, %eax
    syscall
    cmpq $4, %rax
    jne fail_2

    lea 1024(%rsp), %rdi
    lea elf_magic(%rip), %rsi
    mov $4, %edx
    call bytes_equal
    test %eax, %eax
    jz fail_3

    mov %r12d, %edi
    lea empty_path(%rip), %rsi
    mov $0x1000, %edx
    mov $0x17ff, %r10d
    lea 1536(%rsp), %r8
    mov $332, %eax
    syscall
    test %rax, %rax
    jne fail_4

    mov 1536(%rsp), %eax
    cmp $0x17ff, %eax
    jne fail_5

    movzwl 1564(%rsp), %eax
    and $0xf000, %eax
    cmp $0x8000, %eax
    jne fail_6

    mov 1576(%rsp), %rax
    test %rax, %rax
    jle fail_7

    mov %r12d, %edi
    lea empty_path(%rip), %rsi
    lea 2048(%rsp), %rdx
    mov $0x1000, %r10d
    mov $262, %eax
    syscall
    test %rax, %rax
    jne fail_8

    mov 2096(%rsp), %rax
    test %rax, %rax
    jle fail_9

    mov $-100, %edi
    lea tmp_file_path(%rip), %rsi
    mov $0x242, %edx
    mov $0644, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_10
    mov %eax, %r13d

    mov %r13d, %edi
    lea rw_payload(%rip), %rsi
    mov $rw_payload_len, %edx
    mov $2, %r10d
    mov $18, %eax
    syscall
    cmpq $rw_payload_len, %rax
    jne fail_11

    mov %r13d, %edi
    lea 1024(%rsp), %rsi
    mov $rw_expected_len, %edx
    xor %r10d, %r10d
    mov $17, %eax
    syscall
    cmpq $rw_expected_len, %rax
    jne fail_12

    lea 1024(%rsp), %rdi
    lea rw_expected(%rip), %rsi
    mov $rw_expected_len, %edx
    call bytes_equal
    test %eax, %eax
    jz fail_13

    mov $-100, %edi
    lea proc_self_path(%rip), %rsi
    mov $0x10000, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_14
    mov %eax, %r14d

    mov %r14d, %edi
    lea proc_exe_name(%rip), %rsi
    lea 64(%rsp), %rdx
    mov $128, %r10d
    mov $267, %eax
    syscall
    cmpq $runtime_fs_path_len, %rax
    jne fail_15

    lea 64(%rsp), %rdi
    lea runtime_fs_path(%rip), %rsi
    mov $runtime_fs_path_len, %edx
    call bytes_equal
    test %eax, %eax
    jz fail_16

    mov %r14d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_17

    mov %r13d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_18

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_19

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmpq $success_message_len, %rax
    jne fail_20

    xor %edi, %edi
    mov $60, %eax
    syscall

bytes_equal:
    test %edx, %edx
    je bytes_equal_true
bytes_equal_loop:
    movzbq (%rdi), %rax
    movzbq (%rsi), %rcx
    cmp %cl, %al
    jne bytes_equal_false
    inc %rdi
    inc %rsi
    dec %edx
    jne bytes_equal_loop
bytes_equal_true:
    mov $1, %eax
    ret
bytes_equal_false:
    xor %eax, %eax
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

fail_exit:
    mov $60, %eax
    syscall
