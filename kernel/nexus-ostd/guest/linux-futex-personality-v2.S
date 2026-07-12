# SPDX-License-Identifier: MPL-2.0

# Stage 6B.1 raw replacement personality for the recover scenario.  This
# program checks the complete wait/wake identity, explicit rebind/adoption,
# failure-atomic stale/forged operations, frozen wake count, and duplicate
# commit rejection before reporting personality completion.

.equ SYS_FUTEX,             202
.equ FUTEX_WAIT_PRIVATE,    128
.equ FUTEX_WAKE_PRIVATE,    129
.equ FUTEX_WORD,            0x00401000

.equ WAIT_REGISTER,         0x4c600002
.equ PORTAL_RECV_WAKE,      0x4c600003
.equ RECOVERY_SNAPSHOT,     0x4c600010
.equ READY,                 0x4c600011
.equ REBIND,                0x4c600012
.equ RECOVER_NEXT,          0x4c600013
.equ ADOPT,                 0x4c600014
.equ ENABLE_WAKER,          0x4c600015
.equ WAKE_COMMIT,           0x4c600020
.equ PERSONALITY_DONE,      0x4c600021
.equ UNKNOWN_OPERATION,     0x4c6000fe

.equ APPLIED,               0
.equ STALE_BINDING,         2
.equ IDENTITY_MISMATCH,     4
.equ INVALID_STATE,         5
.equ NO_SUPERVISOR,         6
.equ NOT_ADOPTABLE,         8

.equ AUTHORITY_EPOCH,       101
.equ RECOVER_SCOPE,         40
.equ RECOVER_ASID,          600
.equ ADDRESS_GENERATION,    1
.equ WAIT_EFFECT,           1
.equ WAKE_EFFECT,           2
.equ RECOVER_WAITER_TASK,   500
.equ RECOVER_WAKER_TASK,    501
.equ TOKEN_WAIT,            1
.equ TOKEN_WAKE,            2
.equ BINDING_V1,            1
.equ BINDING_V2,            2

.macro CHECK_WAIT_IDENTITY binding, fail
    cmp     $AUTHORITY_EPOCH, %r10
    jne     \fail
    cmp     $RECOVER_SCOPE, %r12
    jne     \fail
    cmp     $WAIT_EFFECT, %r8
    jne     \fail
    cmp     $RECOVER_WAITER_TASK, %r13
    jne     \fail
    cmp     $TOKEN_WAIT, %r14
    jne     \fail
    cmp     $FUTEX_WORD, %r15
    jne     \fail
    cmp     $RECOVER_ASID, %rbx
    jne     \fail
    cmp     $ADDRESS_GENERATION, %rbp
    jne     \fail
    cmp     $\binding, %r9
    jne     \fail
.endm

.macro CHECK_WAIT_PACKET binding, fail
    cmp     $SYS_FUTEX, %rax
    jne     \fail
    cmp     $FUTEX_WORD, %rdi
    jne     \fail
    cmp     $FUTEX_WAIT_PRIVATE, %rsi
    jne     \fail
    test    %rdx, %rdx
    jne     \fail
    CHECK_WAIT_IDENTITY \binding, \fail
.endm

.macro CHECK_WAKE_PACKET fail
    cmp     $SYS_FUTEX, %rax
    jne     \fail
    cmp     $FUTEX_WORD, %rdi
    jne     \fail
    cmp     $FUTEX_WAKE_PRIVATE, %rsi
    jne     \fail
    cmp     $1, %rdx
    jne     \fail
    cmp     $AUTHORITY_EPOCH, %r10
    jne     \fail
    cmp     $RECOVER_SCOPE, %r12
    jne     \fail
    cmp     $WAKE_EFFECT, %r8
    jne     \fail
    cmp     $RECOVER_WAKER_TASK, %r13
    jne     \fail
    cmp     $TOKEN_WAKE, %r14
    jne     \fail
    cmp     $FUTEX_WORD, %r15
    jne     \fail
    cmp     $RECOVER_ASID, %rbx
    jne     \fail
    cmp     $ADDRESS_GENERATION, %rbp
    jne     \fail
    cmp     $BINDING_V2, %r9
    jne     \fail
.endm

.section .text
.global _start
.type _start, @function

_start:
    # Snapshot exposes the exact old-binding wait without transferring it.
    mov     $RECOVERY_SNAPSHOT, %eax
    syscall
    CHECK_WAIT_PACKET BINDING_V1, .Lsnapshot_fail

    mov     $READY, %eax
    syscall
    cmp     $APPLIED, %rax
    jne     .Lready_fail

    # A syntactically current binding still has no installed supervisor before
    # Rebind.  Rejection must precede any wait-state mutation.
    mov     $BINDING_V2, %r9d
    mov     $WAIT_REGISTER, %eax
    syscall
    cmp     $NO_SUPERVISOR, %rax
    jne     .Lno_supervisor_fail
    mov     $BINDING_V1, %r9d

    mov     $REBIND, %eax
    syscall
    cmp     $APPLIED, %rax
    jne     .Lrebind_fail

    # The snapshot token is now stale even though every non-binding field is
    # exact.  It cannot register or otherwise mutate the existing wait.
    mov     $WAIT_REGISTER, %eax
    syscall
    cmp     $STALE_BINDING, %rax
    jne     .Lstale_after_rebind_fail

    mov     $RECOVER_NEXT, %eax
    syscall
    CHECK_WAIT_PACKET BINDING_V1, .Lrecover_next_fail

    mov     $ADOPT, %eax
    syscall
    cmp     $APPLIED, %rax
    jne     .Ladopt_fail
    CHECK_WAIT_IDENTITY BINDING_V2, .Ladopt_identity_fail

    # Vary only effect identity against the fully current adopted token.
    mov     $999, %r8d
    mov     $ADOPT, %eax
    syscall
    cmp     $IDENTITY_MISMATCH, %rax
    jne     .Lforged_effect_fail
    mov     $WAIT_EFFECT, %r8d

    # Replay the old binding after adoption, then verify that the exact current
    # token cannot be adopted a second time.
    mov     $BINDING_V1, %r9d
    mov     $WAIT_REGISTER, %eax
    syscall
    cmp     $STALE_BINDING, %rax
    jne     .Lstale_after_adopt_fail
    mov     $BINDING_V2, %r9d

    mov     $ADOPT, %eax
    syscall
    cmp     $NOT_ADOPTABLE, %rax
    jne     .Ldouble_adopt_fail

    mov     $ENABLE_WAKER, %eax
    syscall
    cmp     $APPLIED, %rax
    jne     .Lenable_waker_fail

    mov     $PORTAL_RECV_WAKE, %eax
    syscall
    CHECK_WAKE_PACKET .Lrecv_wake_fail

    mov     $WAKE_COMMIT, %eax
    syscall
    cmp     $APPLIED, %rax
    jne     .Lwake_commit_fail
    cmp     $1, %rdi
    jne     .Lwake_count_fail

    # The first result overwrote rdi with the frozen count.  Reconstruct the
    # immutable wake syscall arguments while retaining the full token.
    mov     $FUTEX_WORD, %edi
    mov     $FUTEX_WAKE_PRIVATE, %esi
    mov     $1, %edx
    mov     $WAKE_COMMIT, %eax
    syscall
    cmp     $INVALID_STATE, %rax
    jne     .Lduplicate_wake_fail

    mov     $PERSONALITY_DONE, %eax
    syscall
    # A successful done operation terminates this personality Task in the
    # kernel runner; returning to UserMode is itself a failure.
    mov     $16, %edi
    jmp     .Lfail

.Lsnapshot_fail:
    mov     $1, %edi
    jmp     .Lfail
.Lready_fail:
    mov     $2, %edi
    jmp     .Lfail
.Lno_supervisor_fail:
    mov     $3, %edi
    jmp     .Lfail
.Lrebind_fail:
    mov     $4, %edi
    jmp     .Lfail
.Lstale_after_rebind_fail:
    mov     $5, %edi
    jmp     .Lfail
.Lrecover_next_fail:
    mov     $6, %edi
    jmp     .Lfail
.Ladopt_fail:
    mov     $7, %edi
    jmp     .Lfail
.Ladopt_identity_fail:
    mov     $8, %edi
    jmp     .Lfail
.Lforged_effect_fail:
    mov     $9, %edi
    jmp     .Lfail
.Lstale_after_adopt_fail:
    mov     $10, %edi
    jmp     .Lfail
.Ldouble_adopt_fail:
    mov     $11, %edi
    jmp     .Lfail
.Lenable_waker_fail:
    mov     $12, %edi
    jmp     .Lfail
.Lrecv_wake_fail:
    mov     $13, %edi
    jmp     .Lfail
.Lwake_commit_fail:
    mov     $14, %edi
    jmp     .Lfail
.Lwake_count_fail:
    mov     $15, %edi
    jmp     .Lfail
.Lduplicate_wake_fail:
    mov     $17, %edi

.Lfail:
    mov     $UNKNOWN_OPERATION, %eax
    syscall
    ud2

.Lhalt:
    pause
    jmp     .Lhalt

.size _start, . - _start

.section .note.GNU-stack,"",@progbits
