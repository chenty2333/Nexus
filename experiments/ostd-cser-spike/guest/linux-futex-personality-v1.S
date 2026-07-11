# SPDX-License-Identifier: MPL-2.0

# Stage 6B.1 raw personality v1.  The kernel starts the recover scenario at
# file offset 0 and the watchdog-expiry scenario at file offset 0x200.  Both
# paths register the exact wait token and then take a genuine user page fault;
# expire first receives (but deliberately does not commit) the wake call so the
# crash cohort is exactly {registered wait, captured wake}.

.equ SYS_FUTEX,             202
.equ FUTEX_WAIT_PRIVATE,    128
.equ FUTEX_WAKE_PRIVATE,    129
.equ FUTEX_WORD,            0x00401000

.equ PORTAL_RECV_WAIT,      0x4c600001
.equ WAIT_REGISTER,         0x4c600002
.equ PORTAL_RECV_WAKE,      0x4c600003
.equ UNKNOWN_OPERATION,     0x4c6000fe

.equ APPLIED,               0
.equ AUTHORITY_EPOCH,       101
.equ RECOVER_SCOPE,         40
.equ EXPIRE_SCOPE,          41
.equ RECOVER_ASID,          600
.equ EXPIRE_ASID,           601
.equ ADDRESS_GENERATION,    1
.equ WAIT_EFFECT,           1
.equ WAKE_EFFECT,           2
.equ RECOVER_WAITER_TASK,   500
.equ RECOVER_WAKER_TASK,    501
.equ EXPIRE_WAITER_TASK,    510
.equ EXPIRE_WAKER_TASK,     511
.equ TOKEN_WAIT,            1
.equ TOKEN_WAKE,            2
.equ BINDING_V1,            1
.equ EXPECTED_FAULT_ADDR,   0x00800000

.macro CHECK_WAIT_PACKET scope, asid, task, fail
    cmp     $SYS_FUTEX, %rax
    jne     \fail
    cmp     $FUTEX_WORD, %rdi
    jne     \fail
    cmp     $FUTEX_WAIT_PRIVATE, %rsi
    jne     \fail
    test    %rdx, %rdx
    jne     \fail
    cmp     $AUTHORITY_EPOCH, %r10
    jne     \fail
    cmp     $\scope, %r12
    jne     \fail
    cmp     $WAIT_EFFECT, %r8
    jne     \fail
    cmp     $\task, %r13
    jne     \fail
    cmp     $TOKEN_WAIT, %r14
    jne     \fail
    cmp     $FUTEX_WORD, %r15
    jne     \fail
    cmp     $\asid, %rbx
    jne     \fail
    cmp     $ADDRESS_GENERATION, %rbp
    jne     \fail
    cmp     $BINDING_V1, %r9
    jne     \fail
.endm

.macro CHECK_WAKE_PACKET scope, asid, task, fail
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
    cmp     $\scope, %r12
    jne     \fail
    cmp     $WAKE_EFFECT, %r8
    jne     \fail
    cmp     $\task, %r13
    jne     \fail
    cmp     $TOKEN_WAKE, %r14
    jne     \fail
    cmp     $FUTEX_WORD, %r15
    jne     \fail
    cmp     $\asid, %rbx
    jne     \fail
    cmp     $ADDRESS_GENERATION, %rbp
    jne     \fail
    cmp     $BINDING_V1, %r9
    jne     \fail
.endm

.section .text
.global _start
.global _expire_start
.type _start, @function
.type _expire_start, @function

_start:
    mov     $PORTAL_RECV_WAIT, %eax
    syscall
    CHECK_WAIT_PACKET RECOVER_SCOPE, RECOVER_ASID, RECOVER_WAITER_TASK, .Lrecover_fail

    mov     $WAIT_REGISTER, %eax
    syscall
    cmp     $APPLIED, %rax
    jne     .Lrecover_fail
    jmp     .Lcrash

    # The alternate v1 entry is fixed independently of instruction growth in
    # the recover path; build verification also checks this symbol offset.
    .org 0x200, 0x90

_expire_start:
    mov     $PORTAL_RECV_WAIT, %eax
    syscall
    CHECK_WAIT_PACKET EXPIRE_SCOPE, EXPIRE_ASID, EXPIRE_WAITER_TASK, .Lexpire_wait_fail

    mov     $WAIT_REGISTER, %eax
    syscall
    cmp     $APPLIED, %rax
    jne     .Lexpire_wait_fail

    # The waker has issued WAKE_PRIVATE, but v1 only receives the immutable
    # packet.  No WAKE_COMMIT occurs before the crash.
    mov     $PORTAL_RECV_WAKE, %eax
    syscall
    CHECK_WAKE_PACKET EXPIRE_SCOPE, EXPIRE_ASID, EXPIRE_WAKER_TASK, .Lexpire_wake_fail
    jmp     .Lcrash

.Lrecover_fail:
    mov     $1, %edi
    jmp     .Lfail
.Lexpire_wait_fail:
    mov     $2, %edi
    jmp     .Lfail
.Lexpire_wake_fail:
    mov     $3, %edi

.Lfail:
    mov     $UNKNOWN_OPERATION, %eax
    syscall
    ud2
    jmp     .Lhalt

.Lcrash:
    mov     $EXPECTED_FAULT_ADDR, %eax
    mov     (%rax), %rax

.Lhalt:
    pause
    jmp     .Lhalt

.size _start, _expire_start - _start
.size _expire_start, . - _expire_start

.section .note.GNU-stack,"",@progbits
