.section .text
.global _start
.type _start, @function
_start:
    mov $99, %edi
    mov $60, %eax
    syscall
