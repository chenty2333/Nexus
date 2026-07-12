# SPDX-License-Identifier: MPL-2.0

# Fresh Stage 6B.2 replacement. It establishes a snapshot/ready/rebind gate,
# explicitly adopts every crash-cohort effect, proves the old v1 handle stale,
# publishes the one frozen migration receipt, then serves later mutations.

.equ RECOVERY_SNAPSHOT, 0x4c610010
.equ READY,             0x4c610011
.equ REBIND,            0x4c610012
.equ ADOPT_NEXT,        0x4c610013
.equ REPLAY_OLD,        0x4c610014
.equ PUBLISH_FROZEN,    0x4c610015
.equ PORTAL_NEXT,       0x4c610001
.equ PORTAL_PREPARE,    0x4c610002
.equ PORTAL_COMMIT,     0x4c610003
.equ PORTAL_PUBLISH,    0x4c610004
.equ PERSONALITY_DONE,  0x4c610020
.equ PORTAL_FAIL,       0x4c61ffff

.equ OP_WAKE,           1
.equ OP_REQUEUE,        2
.equ OP_SHUTDOWN,       3
.equ STALE_BINDING,     2

.section .text
.global _start
.type _start, @function

_start:
    mov     $RECOVERY_SNAPSHOT, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_snapshot

    mov     $READY, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_ready

    mov     $REBIND, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_rebind

.Ladopt:
    mov     $ADOPT_NEXT, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_adopt
    test    %rdi, %rdi
    jne     .Ladopt

    mov     $REPLAY_OLD, %eax
    syscall
    cmp     $STALE_BINDING, %rax
    jne     .Lfail_replay

    mov     $PUBLISH_FROZEN, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_frozen

.Lnext:
    mov     $PORTAL_NEXT, %eax
    syscall
    mov     %rax, %r12
    cmp     $OP_SHUTDOWN, %rax
    je      .Ldone
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

    mov     $PORTAL_PUBLISH, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_publish
    jmp     .Lnext

.Ldone:
    mov     $PERSONALITY_DONE, %eax
    syscall
    mov     $13, %edi
    jmp     .Lfail

.Lfail_snapshot:
    mov     $1, %edi
    jmp     .Lfail
.Lfail_ready:
    mov     $2, %edi
    jmp     .Lfail
.Lfail_rebind:
    mov     $3, %edi
    jmp     .Lfail
.Lfail_adopt:
    mov     $4, %edi
    jmp     .Lfail
.Lfail_replay:
    mov     $5, %edi
    jmp     .Lfail
.Lfail_frozen:
    mov     $6, %edi
    jmp     .Lfail
.Lfail_next:
    mov     $7, %edi
    jmp     .Lfail
.Lfail_prepare:
    mov     $8, %edi
    jmp     .Lfail
.Lfail_commit:
    mov     $9, %edi
    jmp     .Lfail
.Lfail_publish:
    mov     $10, %edi
.Lfail:
    mov     $PORTAL_FAIL, %eax
    syscall
    ud2

.size _start, . - _start
.section .note.GNU-stack,"",@progbits
