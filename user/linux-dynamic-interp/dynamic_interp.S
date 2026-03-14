.section .text
.global _start
.type _start, @function
_start:
    mov $1, %edi
    lea interp_message(%rip), %rsi
    mov $18, %edx
    mov $1, %eax
    syscall

    xor %edi, %edi
    mov $60, %eax
    syscall

.section .rodata
interp_message:
    .ascii "dynamic interp ok\n"
