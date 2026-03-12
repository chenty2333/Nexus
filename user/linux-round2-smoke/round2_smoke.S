.section .text
.global _start
.type _start, @function
_start:
    sub $12288, %rsp

    lea 0(%rsp), %rdi
    xor %rsi, %rsi
    mov $293, %eax
    syscall
    test %rax, %rax
    js fail

    mov 4(%rsp), %edi
    lea pipe_payload(%rip), %rsi
    mov $pipe_payload_len, %edx
    mov $1, %eax
    syscall
    cmp $pipe_payload_len, %rax
    jne fail

    mov 0(%rsp), %edi
    lea 4256(%rsp), %rsi
    mov $pipe_payload_len, %edx
    xor %eax, %eax
    syscall
    cmp $pipe_payload_len, %rax
    jne fail

    mov 0(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    js fail

    mov 4(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    js fail

    mov $1, %edi
    mov $1, %esi
    xor %edx, %edx
    lea 8(%rsp), %r10
    mov $53, %eax
    syscall
    test %rax, %rax
    js fail

    mov 8(%rsp), %edi
    lea socket_payload(%rip), %rsi
    mov $socket_payload_len, %edx
    mov $1, %eax
    syscall
    cmp $socket_payload_len, %rax
    jne fail

    mov 12(%rsp), %edi
    lea 4256(%rsp), %rsi
    mov $socket_payload_len, %edx
    xor %eax, %eax
    syscall
    cmp $socket_payload_len, %rax
    jne fail

    mov 8(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    js fail

    mov 12(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    js fail

    mov $-100, %rdi
    lea hello_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail
    mov %rax, %r12

    mov %r12d, %edi
    lea 16(%rsp), %rsi
    mov $5, %eax
    syscall
    test %rax, %rax
    js fail

    mov 64(%rsp), %rax
    test %rax, %rax
    jle fail

    mov %r12d, %edi
    lea 4256(%rsp), %rsi
    mov $4, %edx
    xor %eax, %eax
    syscall
    cmp $4, %rax
    jne fail

    cmpb $0x7f, 4256(%rsp)
    jne fail
    cmpb $'E', 4257(%rsp)
    jne fail
    cmpb $'L', 4258(%rsp)
    jne fail
    cmpb $'F', 4259(%rsp)
    jne fail

    xor %edi, %edi
    mov $4096, %esi
    mov $1, %edx
    mov $2, %r10d
    mov %r12d, %r8d
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail
    mov %rax, %r14

    cmpb $0x7f, (%r14)
    jne fail
    cmpb $'E', 1(%r14)
    jne fail
    cmpb $'L', 2(%r14)
    jne fail
    cmpb $'F', 3(%r14)
    jne fail

    mov $-100, %rdi
    lea hello_path(%rip), %rsi
    lea 16(%rsp), %rdx
    xor %r10d, %r10d
    mov $262, %eax
    syscall
    test %rax, %rax
    js fail

    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    js fail

    mov $-100, %rdi
    lea manifests_path(%rip), %rsi
    mov $65536, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail
    mov %rax, %r13

    mov %r13d, %edi
    lea 160(%rsp), %rsi
    mov $4096, %edx
    mov $217, %eax
    syscall
    test %rax, %rax
    jle fail

    movzwl 176(%rsp), %eax
    test %eax, %eax
    jz fail

    mov %r13d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    js fail

    xor %edi, %edi
    mov $12, %eax
    syscall
    test %rax, %rax
    js fail
    mov %rax, %r15

    lea 4096(%r15), %rdi
    mov $12, %eax
    syscall
    test %rax, %rax
    js fail
    cmp %r15, %rax
    jbe fail

    movb $0x5a, (%r15)
    cmpb $0x5a, (%r15)
    jne fail

    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $34, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail
    mov %rax, %rbx

    movabs $0x1122334455667788, %rax
    mov %rax, (%rbx)
    cmp %rax, (%rbx)
    jne fail

    mov %rbx, %rdi
    mov $4096, %esi
    mov $1, %edx
    mov $10, %eax
    syscall
    test %rax, %rax
    js fail

    movabs $0x1122334455667788, %rax
    cmp %rax, (%rbx)
    jne fail

    mov %rbx, %rdi
    mov $4096, %esi
    mov $11, %eax
    syscall
    test %rax, %rax
    js fail

    mov %r14, %rdi
    mov $4096, %esi
    mov $11, %eax
    syscall
    test %rax, %rax
    js fail

    mov $1, %edi
    lea success_message(%rip), %rsi
    mov $success_message_len, %edx
    mov $1, %eax
    syscall
    cmp $success_message_len, %rax
    jne fail

    mov $231, %eax
    xor %edi, %edi
    syscall

fail:
    mov $231, %eax
    mov $1, %edi
    syscall

.section .rodata
pipe_payload:
    .ascii "pipe"
pipe_payload_end:
.set pipe_payload_len, pipe_payload_end - pipe_payload

socket_payload:
    .ascii "sock"
socket_payload_end:
.set socket_payload_len, socket_payload_end - socket_payload

hello_path:
    .asciz "/boot/bin/linux-hello"

manifests_path:
    .asciz "/boot/manifests"

success_message:
    .ascii "round2 ok\n"
success_message_end:
.set success_message_len, success_message_end - success_message
