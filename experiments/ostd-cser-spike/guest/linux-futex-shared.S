# SPDX-License-Identifier: MPL-2.0

# Raw x86-64 Linux futex input shared by two OSTD Tasks in one VmSpace.
#
# Mapping contract:
#   code base       0x00400000
#   waiter entry    0x00400000 (_start, file offset 0)
#   waker entry     0x00400200 (_waker_start, file offset 0x200)
#   shared word     0x00401000 (mapped separately, initially zero)
#
# The kernel initializes r15 to SCENARIO_RECOVER or SCENARIO_EXPIRE for both
# Tasks.  The custom done/fail syscalls carry role in rdi, scenario in rsi,
# and a source-local failure code in rdx.

.equ SYS_FUTEX,             202
.equ FUTEX_WAIT_PRIVATE,    128
.equ FUTEX_WAKE_PRIVATE,    129

.equ FUTEX_WORD,            0x00401000
.equ SCENARIO_RECOVER,      0
.equ SCENARIO_EXPIRE,       1
.equ ROLE_WAITER,           0
.equ ROLE_WAKER,            1

.equ ERR_EAGAIN,            11
.equ ERR_ETIMEDOUT,         110
.equ GUEST_DONE,            0x4c6000f0
.equ GUEST_FAIL,            0x4c6000ff

.section .text
.global _start
.global _waker_start
.type _start, @function
.type _waker_start, @function

_start:
    cmp     $SCENARIO_EXPIRE, %r15
    ja      waiter_bad_scenario

    # A mismatching private wait is synchronous: it must not enqueue, block,
    # or consume wait credit.
    mov     $SYS_FUTEX, %eax
    mov     $FUTEX_WORD, %edi
    mov     $FUTEX_WAIT_PRIVATE, %esi
    mov     $1, %edx
    xor     %r10d, %r10d
    xor     %r8d, %r8d
    xor     %r9d, %r9d
    syscall
    cmp     $-ERR_EAGAIN, %rax
    jne     waiter_bad_mismatch

    # The matching wait is registered under CSER and blocks until either the
    # committed wake publishes (recover) or watchdog closure aborts (expire).
    # An aborted effect is terminalized by the kernel runner and must not be
    # converted into a fabricated Linux syscall reply in UserMode.
    mov     $SYS_FUTEX, %eax
    mov     $FUTEX_WORD, %edi
    mov     $FUTEX_WAIT_PRIVATE, %esi
    xor     %edx, %edx
    xor     %r10d, %r10d
    xor     %r8d, %r8d
    xor     %r9d, %r9d
    syscall

    cmp     $-ERR_ETIMEDOUT, %rax
    je      waiter_saw_linux_timeout
    test    %r15, %r15
    jne     waiter_resumed_after_abort
    test    %rax, %rax
    jne     waiter_bad_recover_result
    jmp     waiter_done

waiter_done:
    mov     $ROLE_WAITER, %edi
    mov     %r15, %rsi
    xor     %edx, %edx
    mov     $GUEST_DONE, %eax
    syscall
    jmp     halt

waiter_bad_scenario:
    mov     $1, %edx
    jmp     waiter_fail
waiter_bad_mismatch:
    mov     $2, %edx
    jmp     waiter_fail
waiter_saw_linux_timeout:
    mov     $3, %edx
    jmp     waiter_fail
waiter_bad_recover_result:
    mov     $4, %edx
    jmp     waiter_fail
waiter_resumed_after_abort:
    mov     $5, %edx

waiter_fail:
    mov     $ROLE_WAITER, %edi
    mov     %r15, %rsi
    mov     $GUEST_FAIL, %eax
    syscall
    jmp     halt

    # Keep the second Task entry a build-time-stable offset in the same raw
    # binary.  The zero/padding bytes are never executed.
    .org 0x200, 0x90

_waker_start:
    cmp     $SCENARIO_EXPIRE, %r15
    ja      waker_bad_scenario

    # xchg with memory is an atomic store on x86-64.  Requiring the previous
    # value to be zero also catches an accidental second waker/publication.
    mov     $1, %eax
    mov     $FUTEX_WORD, %edi
    xchg    %eax, (%rdi)
    test    %eax, %eax
    jne     waker_bad_old_word

    mov     $SYS_FUTEX, %eax
    mov     $FUTEX_WAKE_PRIVATE, %esi
    mov     $1, %edx
    xor     %r10d, %r10d
    xor     %r8d, %r8d
    xor     %r9d, %r9d
    syscall

    cmp     $-ERR_ETIMEDOUT, %rax
    je      waker_saw_linux_timeout
    test    %r15, %r15
    jne     waker_resumed_after_abort
    cmp     $1, %rax
    jne     waker_bad_recover_result
    jmp     waker_done

waker_done:
    mov     $ROLE_WAKER, %edi
    mov     %r15, %rsi
    xor     %edx, %edx
    mov     $GUEST_DONE, %eax
    syscall
    jmp     halt

waker_bad_scenario:
    mov     $6, %edx
    jmp     waker_fail
waker_bad_old_word:
    mov     $7, %edx
    jmp     waker_fail
waker_saw_linux_timeout:
    mov     $8, %edx
    jmp     waker_fail
waker_bad_recover_result:
    mov     $9, %edx
    jmp     waker_fail
waker_resumed_after_abort:
    mov     $10, %edx

waker_fail:
    mov     $ROLE_WAKER, %edi
    mov     %r15, %rsi
    mov     $GUEST_FAIL, %eax
    syscall

halt:
    pause
    jmp     halt

.size _start, _waker_start - _start
.size _waker_start, . - _waker_start

.section .note.GNU-stack,"",@progbits
