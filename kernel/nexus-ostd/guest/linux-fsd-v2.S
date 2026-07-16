# SPDX-License-Identifier: MPL-2.0

# Fresh bounded runtime-filesystem service. The numeric portal ABI is compatible
# with the existing raw netd guests so the kernel can use the same UserMode
# command convention. Compatibility does not share semantic identity: fsd has
# its own runner, task binding, request, and effect cohort.
#
# fsd-v2 proves the full recovery handshake, adopts the exact prepared cohort,
# rejects a late command carrying fsd-v1's stale binding, then commits, executes,
# and publishes the frozen request exactly once before terminating explicitly.

.equ FSD_COMMIT,            0x4e740003
.equ FSD_PUBLISH,           0x4e740004
.equ FSD_RECOVERY_SNAPSHOT, 0x4e740010
.equ FSD_READY,             0x4e740011
.equ FSD_REBIND,            0x4e740012
.equ FSD_ADOPT_NEXT,        0x4e740013
.equ FSD_REPLAY_OLD,        0x4e740014
.equ FSD_DONE,              0x4e740020
.equ FSD_FAIL,              0x4e74ffff

.equ STALE_BINDING,         2

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
    # rdi is one when the kernel adopted another member of the exact snapshot
    # cohort and zero when the cohort is exhausted; rax is the control result.
    mov     $FSD_ADOPT_NEXT, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_adopt
    test    %rdi, %rdi
    jne     .Ladopt

    # Deliver the typed Prepare command that fsd-v1 queued before its fault.
    # The command retains v1's TaskKey and old PortalHandle; this v2 syscall is
    # only the recovery supervisor's delivery trigger.
    mov     $FSD_REPLAY_OLD, %eax
    syscall
    cmp     $STALE_BINDING, %rax
    jne     .Lfail_replay

    # The filesystem runner executes the adopted request at this commit gate;
    # publication remains a separate command and can occur exactly once.
    mov     $FSD_COMMIT, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_commit

    mov     $FSD_PUBLISH, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_publish

    mov     $FSD_DONE, %eax
    syscall
    # A successful DONE terminates this UserMode task. Any return is failure.
    mov     $8, %edi
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
.Lfail_commit:
    mov     $6, %edi
    jmp     .Lfail
.Lfail_publish:
    mov     $7, %edi

.Lfail:
    mov     $FSD_FAIL, %eax
    syscall
    ud2

.size _start, . - _start
.section .note.GNU-stack,"",@progbits
