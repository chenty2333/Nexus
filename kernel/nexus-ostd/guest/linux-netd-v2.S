# SPDX-License-Identifier: MPL-2.0

# Fresh bounded runtime-network service. It proves the exact recovery handshake,
# explicitly adopts the prepared accept continuation, rejects its old binding,
# commits and publishes that frozen accept, then serves the remaining ordinary
# operations until the kernel reports that the 22-call guest has shut down.

.equ PORTAL_NEXT,       0x4e740001
.equ PORTAL_PREPARE,    0x4e740002
.equ PORTAL_COMMIT,     0x4e740003
.equ PORTAL_PUBLISH,    0x4e740004
.equ RECOVERY_SNAPSHOT, 0x4e740010
.equ READY,             0x4e740011
.equ REBIND,            0x4e740012
.equ ADOPT_NEXT,        0x4e740013
.equ REPLAY_OLD,        0x4e740014
.equ NETD_DONE,         0x4e740020
.equ PORTAL_FAIL,       0x4e74ffff

.equ OP_WAIT,           0
.equ OP_NORMAL,         1
.equ OP_ACCEPT,         2
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
    # ADOPT_NEXT is a combined recover/adopt control operation. rdi is one when
    # another old-binding effect was adopted and zero when the exact snapshot
    # cohort is exhausted; rax reports the control result.
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

    # v1 prepared accept4 but faulted before commit. The adopted frozen
    # continuation now crosses commit and guest-publication exactly once.
    mov     $PORTAL_COMMIT, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_frozen_commit

    mov     $PORTAL_PUBLISH, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_frozen_publish

.Lnext:
    mov     $PORTAL_NEXT, %eax
    syscall
    cmp     $OP_WAIT, %rax
    je      .Lnext
    cmp     $OP_NORMAL, %rax
    je      .Lnormal
    cmp     $OP_SHUTDOWN, %rax
    je      .Ldone
    cmp     $OP_ACCEPT, %rax
    je      .Lfail_duplicate_accept
    jmp     .Lfail_next

.Lnormal:
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
    mov     $NETD_DONE, %eax
    syscall
    # A successful DONE terminates this UserMode task. Returning is a protocol
    # failure, even if the return value happens to be zero.
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
.Lfail_frozen_commit:
    mov     $6, %edi
    jmp     .Lfail
.Lfail_frozen_publish:
    mov     $7, %edi
    jmp     .Lfail
.Lfail_duplicate_accept:
    mov     $8, %edi
    jmp     .Lfail
.Lfail_next:
    mov     $9, %edi
    jmp     .Lfail
.Lfail_prepare:
    mov     $10, %edi
    jmp     .Lfail
.Lfail_commit:
    mov     $11, %edi
    jmp     .Lfail
.Lfail_publish:
    mov     $12, %edi

.Lfail:
    mov     $PORTAL_FAIL, %eax
    syscall
    ud2

.size _start, . - _start
.section .note.GNU-stack,"",@progbits
