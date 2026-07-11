.section .rodata
success_message:
    .ascii "runtime misc ok\n"
success_message_len = . - success_message
runtime_misc_path:
    .asciz "/bin/linux-runtime-misc-smoke"
runtime_misc_path_len = . - runtime_misc_path - 1
proc_self_exe:
    .asciz "/proc/self/exe"
proc_self_cwd:
    .asciz "/proc/self/cwd"
root_cwd:
    .ascii "/"
root_cwd_len = . - root_cwd
uname_sysname:
    .ascii "NexusOS"
uname_sysname_len = . - uname_sysname
uname_machine:
    .ascii "x86_64"
uname_machine_len = . - uname_machine
elf_magic:
    .byte 0x7f, 'E', 'L', 'F'

.section .text
.global _start
.type _start, @function
_start:
    sub $2048, %rsp

    mov $186, %eax
    syscall
    test %rax, %rax
    jle fail_1
    mov %eax, %r12d

    lea 0(%rsp), %rdi
    mov $218, %eax
    syscall
    cmp %r12d, %eax
    jne fail_2

    mov $-100, %edi
    lea runtime_misc_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_3
    mov %eax, %r13d

    mov %r13d, %edi
    xor %esi, %esi
    mov $2, %edx
    mov $8, %eax
    syscall
    test %rax, %rax
    jle fail_4
    mov %rax, %r14

    mov %r13d, %edi
    xor %esi, %esi
    xor %edx, %edx
    mov $8, %eax
    syscall
    test %rax, %rax
    jne fail_5

    mov %r13d, %edi
    lea 1024(%rsp), %rsi
    mov $4, %edx
    xor %eax, %eax
    syscall
    cmpq $4, %rax
    jne fail_6

    lea 1024(%rsp), %rdi
    lea elf_magic(%rip), %rsi
    mov $4, %edx
    call bytes_equal
    test %eax, %eax
    jz fail_7

    mov %r13d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_8

    lea proc_self_exe(%rip), %rdi
    lea 64(%rsp), %rsi
    mov $128, %edx
    mov $89, %eax
    syscall
    cmpq $runtime_misc_path_len, %rax
    jne fail_9

    lea 64(%rsp), %rdi
    lea runtime_misc_path(%rip), %rsi
    mov $runtime_misc_path_len, %edx
    call bytes_equal
    test %eax, %eax
    jz fail_10

    mov $-100, %edi
    lea proc_self_cwd(%rip), %rsi
    lea 64(%rsp), %rdx
    mov $128, %r10d
    mov $267, %eax
    syscall
    cmpq $root_cwd_len, %rax
    jne fail_11

    lea 64(%rsp), %rdi
    lea root_cwd(%rip), %rsi
    mov $root_cwd_len, %edx
    call bytes_equal
    test %eax, %eax
    jz fail_12

    lea 256(%rsp), %rdi
    mov $63, %eax
    syscall
    test %rax, %rax
    jne fail_13

    lea 256(%rsp), %rdi
    lea uname_sysname(%rip), %rsi
    mov $uname_sysname_len, %edx
    call bytes_equal
    test %eax, %eax
    jz fail_14

    lea 516(%rsp), %rdi
    lea uname_machine(%rip), %rsi
    mov $uname_machine_len, %edx
    call bytes_equal
    test %eax, %eax
    jz fail_15

    lea 768(%rsp), %rdi
    mov $32, %esi
    xor %edx, %edx
    mov $318, %eax
    syscall
    cmpq $32, %rax
    jne fail_16

    lea 768(%rsp), %rdi
    mov $32, %esi
    call buffer_not_all_zero
    test %eax, %eax
    jz fail_17

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmpq $success_message_len, %rax
    jne fail_18

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

buffer_not_all_zero:
    test %esi, %esi
    je buffer_not_all_zero_false
buffer_not_all_zero_loop:
    movzbq (%rdi), %rax
    test %rax, %rax
    jne buffer_not_all_zero_true
    inc %rdi
    dec %esi
    jne buffer_not_all_zero_loop
buffer_not_all_zero_false:
    xor %eax, %eax
    ret
buffer_not_all_zero_true:
    mov $1, %eax
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

fail_exit:
    mov $60, %eax
    syscall
