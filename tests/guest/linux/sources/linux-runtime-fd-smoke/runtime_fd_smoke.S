.section .rodata
success_message:
    .ascii "runtime fd ok\n"
success_message_len = . - success_message
root_cwd:
    .asciz "/"
bin_cwd:
    .asciz "/bin"
bin_runtime_fd_smoke:
    .asciz "linux-runtime-fd-smoke"
pipe_payload:
    .ascii "runtime fd ok\n"
pipe_payload_len = . - pipe_payload

.section .text
.global _start
.type _start, @function
_start:
    sub $4096, %rsp

    lea 64(%rsp), %rdi
    mov $64, %esi
    mov $79, %eax
    syscall
    cmpq $2, %rax
    jne fail_1

    lea 64(%rsp), %rdi
    lea root_cwd(%rip), %rsi
    mov $2, %edx
    call bytes_equal
    test %eax, %eax
    jz fail_2

    lea bin_cwd(%rip), %rdi
    mov $80, %eax
    syscall
    test %rax, %rax
    jne fail_3

    lea 64(%rsp), %rdi
    mov $64, %esi
    mov $79, %eax
    syscall
    cmpq $5, %rax
    jne fail_4

    lea 64(%rsp), %rdi
    lea bin_cwd(%rip), %rsi
    mov $5, %edx
    call bytes_equal
    test %eax, %eax
    jz fail_5

    mov $-100, %edi
    lea bin_runtime_fd_smoke(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail_6
    mov %eax, %r12d

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_7

    lea 0(%rsp), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail_8

    mov 0(%rsp), %r13d
    mov 4(%rsp), %r14d

    mov %r14d, %edi
    mov $7, %esi
    mov $33, %eax
    syscall
    cmp $7, %eax
    jne fail_9

    mov %r14d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_10

    mov $7, %edi
    mov $8, %esi
    mov $0x80000, %edx
    mov $292, %eax
    syscall
    cmp $8, %eax
    jne fail_11

    mov $8, %edi
    mov $1, %esi
    xor %edx, %edx
    mov $72, %eax
    syscall
    cmpq $1, %rax
    jne fail_12

    mov $8, %edi
    mov $2, %esi
    xor %edx, %edx
    mov $72, %eax
    syscall
    test %rax, %rax
    jne fail_13

    mov $8, %edi
    mov $1, %esi
    xor %edx, %edx
    mov $72, %eax
    syscall
    test %rax, %rax
    jne fail_14

    mov $8, %edi
    mov $3, %esi
    xor %edx, %edx
    mov $72, %eax
    syscall
    cmpq $2, %rax
    jne fail_15

    mov $8, %edi
    mov $1030, %esi
    mov $9, %edx
    mov $72, %eax
    syscall
    cmpq $9, %rax
    jne fail_16
    mov %eax, %r15d

    mov %r15d, %edi
    mov $1, %esi
    xor %edx, %edx
    mov $72, %eax
    syscall
    cmpq $1, %rax
    jne fail_17

    mov %r15d, %edi
    lea pipe_payload(%rip), %rsi
    mov $pipe_payload_len, %edx
    mov $1, %eax
    syscall
    cmpq $pipe_payload_len, %rax
    jne fail_18

    mov %r13d, %edi
    lea 128(%rsp), %rsi
    mov $64, %edx
    xor %eax, %eax
    syscall
    cmpq $pipe_payload_len, %rax
    jne fail_19

    lea 128(%rsp), %rdi
    lea pipe_payload(%rip), %rsi
    mov $pipe_payload_len, %edx
    call bytes_equal
    test %eax, %eax
    jz fail_20

    mov %r13d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_21

    mov $7, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_22

    mov $8, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_23

    mov %r15d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail_24

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmpq $success_message_len, %rax
    jne fail_25

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

fail_1:
    mov $1, %edi
    jmp fail_exit
fail_2:
    mov $2, %edi
    jmp fail_exit
fail_3:
    mov $3, %edi
    jmp fail_exit
fail_4:
    mov $4, %edi
    jmp fail_exit
fail_5:
    mov $5, %edi
    jmp fail_exit
fail_6:
    mov $6, %edi
    jmp fail_exit
fail_7:
    mov $7, %edi
    jmp fail_exit
fail_8:
    mov $8, %edi
    jmp fail_exit
fail_9:
    mov $9, %edi
    jmp fail_exit
fail_10:
    mov $10, %edi
    jmp fail_exit
fail_11:
    mov $11, %edi
    jmp fail_exit
fail_12:
    mov $12, %edi
    jmp fail_exit
fail_13:
    mov $13, %edi
    jmp fail_exit
fail_14:
    mov $14, %edi
    jmp fail_exit
fail_15:
    mov $15, %edi
    jmp fail_exit
fail_16:
    mov $16, %edi
    jmp fail_exit
fail_17:
    mov $17, %edi
    jmp fail_exit
fail_18:
    mov $18, %edi
    jmp fail_exit
fail_19:
    mov $19, %edi
    jmp fail_exit
fail_20:
    mov $20, %edi
    jmp fail_exit
fail_21:
    mov $21, %edi
    jmp fail_exit
fail_22:
    mov $22, %edi
    jmp fail_exit
fail_23:
    mov $23, %edi
    jmp fail_exit
fail_24:
    mov $24, %edi
    jmp fail_exit
fail_25:
    mov $25, %edi
    jmp fail_exit

fail_exit:
    mov $60, %eax
    syscall
