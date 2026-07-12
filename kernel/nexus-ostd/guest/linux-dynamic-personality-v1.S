.section .text
.globl _start
_start:
    # Observe that the replacement image is fully staged while generation 1
    # is still current.  The kernel returns zero only for that exact state.
    mov $0x4d790001, %rax
    syscall
    test %rax, %rax
    jne .Lfail

    # Crash the first personality through a real user page fault after all
    # staging effects exist but before the ExecTransaction commits.
    movabs $0x0000000000800000, %rax
    mov (%rax), %rax

.Lfail:
    ud2
