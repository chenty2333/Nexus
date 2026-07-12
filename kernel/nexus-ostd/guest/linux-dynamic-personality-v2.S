.section .text
.globl _start
_start:
    mov $0x4d790010, %rax
    syscall
    test %rax, %rax
    jne .Lfail

    mov $0x4d790011, %rax
    syscall
    test %rax, %rax
    jne .Lfail

    mov $0x4d790012, %rax
    syscall
    test %rax, %rax
    jne .Lfail

.Lrecover_next:
    mov $0x4d790013, %rax
    syscall
    cmp $1, %rax
    je .Lexec_commit
    test %rax, %rax
    jne .Lfail

    mov $0x4d790014, %rax
    syscall
    test %rax, %rax
    jne .Lfail
    jmp .Lrecover_next

.Lexec_commit:
    mov $0x4d790020, %rax
    syscall
    test %rax, %rax
    jne .Lfail

    mov $0x4d790021, %rax
    syscall
    test %rax, %rax
    jne .Lfail
    ret

.Lfail:
    ud2
