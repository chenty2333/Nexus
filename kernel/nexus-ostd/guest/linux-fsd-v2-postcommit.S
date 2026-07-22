# SPDX-License-Identifier: MPL-2.0

# Postcommit-fault variant of the fresh runtime-filesystem service. It performs
# the same v1 recovery, explicit adoption, and stale-v1 probe as linux-fsd-v2,
# then executes the request. Once FSD_COMMIT returns, the Registry already owns
# one AwaitingPublication flight. This guest faults before FSD_PUBLISH so no v2
# instruction can wake the blocked guest or acknowledge that publication.

.equ FSD_COMMIT,            0x4e740003
.equ FSD_RECOVERY_SNAPSHOT, 0x4e740010
.equ FSD_READY,             0x4e740011
.equ FSD_REBIND,            0x4e740012
.equ FSD_ADOPT_NEXT,        0x4e740013
.equ FSD_REPLAY_OLD,        0x4e740014
.equ FSD_FAIL,              0x4e74ffff

.equ STALE_BINDING,         2
.equ EXPECTED_FAULT,        0x00800000

.section .text
.global _start
.type _start, @function

_start:
    mov     $FSD_RECOVERY_SNAPSHOT, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_snapshot

    mov     $FSD_READY, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_ready

    mov     $FSD_REBIND, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_rebind

.Ladopt:
    mov     $FSD_ADOPT_NEXT, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_adopt
    test    %rdi, %rdi
    jne     .Ladopt

    mov     $FSD_REPLAY_OLD, %eax
    syscall
    cmp     $STALE_BINDING, %rax
    jne     .Lfail_replay

    mov     $FSD_COMMIT, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_commit

    # FSD_COMMIT returned with the exact reply ticket still pending. Fault in
    # user mode before any FSD_PUBLISH portal can transfer the outcome.
    movabs  $EXPECTED_FAULT, %rax
    mov     (%rax), %rax
    ud2

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
.Lfail_commit:
    mov     $6, %edi

.Lfail:
    mov     $FSD_FAIL, %eax
    syscall
    ud2

.size _start, . - _start
.section .note.GNU-stack,"",@progbits
