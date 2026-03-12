.section .text
.global _start
.type _start, @function
_start:
    mov $1, %rax
    mov $1, %rdi
    lea message(%rip), %rsi
    mov $message_len, %rdx
    syscall

    mov $231, %rax
    xor %rdi, %rdi
    syscall

.section .rodata
message:
    .ascii "hello from linux-hello\n"
message_end:
.set message_len, message_end - message
