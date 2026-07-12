# SPDX-License-Identifier: MPL-2.0

# Bounded Stage 6B.2 personality policy. The kernel owns immutable Linux
# descriptors and opaque handles; this task only sequences prepare/commit/
# publish. It deliberately faults after the first committed requeue that moved
# one waiter, before any frozen continuation is published.

.equ PORTAL_NEXT,       0x4c610001
.equ PORTAL_PREPARE,    0x4c610002
.equ PORTAL_COMMIT,     0x4c610003
.equ PORTAL_PUBLISH,    0x4c610004
.equ PORTAL_FAIL,       0x4c61ffff

.equ RESULT_APPLIED,    0
.equ OP_WAKE,           1
.equ OP_REQUEUE,        2
.equ EXPECTED_FAULT,    0x00800000

.section .text
.global _start
.type _start, @function

_start:
.Lnext:
    mov     $PORTAL_NEXT, %eax
    syscall
    mov     %rax, %r12
    cmp     $OP_WAKE, %rax
    je      .Lprepare
    cmp     $OP_REQUEUE, %rax
    jne     .Lfail_next

.Lprepare:
    mov     $PORTAL_PREPARE, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_prepare

    mov     $PORTAL_COMMIT, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_commit

    cmp     $OP_REQUEUE, %r12
    jne     .Lpublish
    cmp     $1, %rdi
    jne     .Lpublish

    # The committed receipt and A -> B migration are already frozen. This load
    # produces a real user page fault before wake/requeue caller publication.
    movabs  $EXPECTED_FAULT, %rax
    mov     (%rax), %rax
    ud2

.Lpublish:
    mov     $PORTAL_PUBLISH, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_publish
    jmp     .Lnext

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
.Lfail:
    mov     $PORTAL_FAIL, %eax
    syscall
    ud2

.size _start, . - _start
.section .note.GNU-stack,"",@progbits
