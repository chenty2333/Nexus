.section .text
.global _start
.type _start, @function
_start:
    sub $32, %rsp

    lea 0(%rsp), %rdi
    xor %rsi, %rsi
    mov $293, %rax
    syscall
    test %rax, %rax
    jne fail

    mov 4(%rsp), %edi
    lea pipe_message(%rip), %rsi
    mov $pipe_message_len, %edx
    mov $1, %eax
    syscall
    cmp $pipe_message_len, %rax
    jne fail

    mov 0(%rsp), %edi
    lea 16(%rsp), %rsi
    mov $pipe_message_len, %edx
    xor %eax, %eax
    syscall
    cmp $pipe_message_len, %rax
    jne fail

    mov $1, %edi
    lea 16(%rsp), %rsi
    mov $pipe_message_len, %edx
    mov $1, %eax
    syscall
    cmp $pipe_message_len, %rax
    jne fail

    mov 0(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail

    mov 4(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail

    mov $1, %edi
    mov $1, %esi
    xor %edx, %edx
    lea 8(%rsp), %r10
    mov $53, %eax
    syscall
    test %rax, %rax
    jne fail

    mov 8(%rsp), %edi
    lea socket_message(%rip), %rsi
    mov $socket_message_len, %edx
    mov $1, %eax
    syscall
    cmp $socket_message_len, %rax
    jne fail

    mov 12(%rsp), %edi
    lea 16(%rsp), %rsi
    mov $socket_message_len, %edx
    xor %eax, %eax
    syscall
    cmp $socket_message_len, %rax
    jne fail

    mov $1, %edi
    lea 16(%rsp), %rsi
    mov $socket_message_len, %edx
    mov $1, %eax
    syscall
    cmp $socket_message_len, %rax
    jne fail

    mov 8(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail

    mov 12(%rsp), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail

    mov $231, %eax
    xor %edi, %edi
    syscall

fail:
    mov $231, %eax
    mov $1, %edi
    syscall

.section .rodata
pipe_message:
    .ascii "pipe\n"
pipe_message_end:
.set pipe_message_len, pipe_message_end - pipe_message

socket_message:
    .ascii "sock\n"
socket_message_end:
.set socket_message_len, socket_message_end - socket_message
