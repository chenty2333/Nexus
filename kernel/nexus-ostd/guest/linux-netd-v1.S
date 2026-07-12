# SPDX-License-Identifier: MPL-2.0

# First bounded runtime-network service. The kernel owns immutable syscall and
# transport descriptors. netd-v1 handles the first nine ordinary operations,
# then prepares the tenth operation (accept4) and deliberately faults before
# its commit point. No accept result or guest reply is published by v1.

.equ PORTAL_NEXT,       0x4e740001
.equ PORTAL_PREPARE,    0x4e740002
.equ PORTAL_COMMIT,     0x4e740003
.equ PORTAL_PUBLISH,    0x4e740004
.equ PORTAL_FAIL,       0x4e74ffff

.equ OP_WAIT,           0
.equ OP_NORMAL,         1
.equ OP_ACCEPT,         2
.equ OP_SHUTDOWN,       3
.equ EXPECTED_NORMALS,  9
.equ EXPECTED_FAULT,    0x00800000

.section .text
.global _start
.type _start, @function

_start:
    xor     %r12d, %r12d

.Lnext:
    mov     $PORTAL_NEXT, %eax
    syscall
    cmp     $OP_WAIT, %rax
    je      .Lnext
    cmp     $OP_NORMAL, %rax
    je      .Lnormal
    cmp     $OP_ACCEPT, %rax
    je      .Laccept
    cmp     $OP_SHUTDOWN, %rax
    je      .Lfail_early_shutdown
    jmp     .Lfail_next

.Lnormal:
    # A tenth ordinary descriptor would contradict the retained guest order.
    # Reject it before PREPARE so the diagnostic path cannot mutate transport
    # state and then merely report the count mismatch.
    cmp     $EXPECTED_NORMALS, %r12d
    jge     .Lfail_normal_count

    mov     $PORTAL_PREPARE, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_prepare

    mov     $PORTAL_COMMIT, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_commit

    mov     $PORTAL_PUBLISH, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_publish

    inc     %r12d
    jmp     .Lnext

.Laccept:
    cmp     $EXPECTED_NORMALS, %r12d
    jne     .Lfail_accept_order

    mov     $PORTAL_PREPARE, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_accept_prepare

    # The accept continuation is prepared under binding 1 but has not crossed
    # its transport/result commit point. This real page fault forces explicit
    # snapshot, readiness, rebind, adoption, and completion by netd-v2.
    movabs  $EXPECTED_FAULT, %rax
    mov     (%rax), %rax
    ud2

.Lfail_next:
    mov     $1, %edi
    jmp     .Lfail
.Lfail_prepare:
    mov     $2, %edi
    jmp     .Lfail
.Lfail_commit:
    mov     $3, %edi
    jmp     .Lfail
.Lfail_publish:
    mov     $4, %edi
    jmp     .Lfail
.Lfail_normal_count:
    mov     $5, %edi
    jmp     .Lfail
.Lfail_accept_order:
    mov     $6, %edi
    jmp     .Lfail
.Lfail_accept_prepare:
    mov     $7, %edi
    jmp     .Lfail
.Lfail_early_shutdown:
    mov     $8, %edi

.Lfail:
    mov     $PORTAL_FAIL, %eax
    syscall
    ud2

.size _start, . - _start
.section .note.GNU-stack,"",@progbits
