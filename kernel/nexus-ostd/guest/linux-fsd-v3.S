# SPDX-License-Identifier: MPL-2.0

# Fresh postcommit closure trigger for the bounded runtime-filesystem service.
# The committed operation and its publication ticket are kernel-owned, so v3
# has no Registry replacement authority and does not snapshot, rebind, adopt,
# or recommit. It first triggers one failure-atomic stale-authority probe using
# v2's frozen sender and handle, then wakes the original guest publication path
# and terminates.

.equ FSD_PUBLISH,            0x4e740004
.equ FSD_POSTCOMMIT_PROBE,   0x4e740015
.equ FSD_DONE,               0x4e740020
.equ FSD_FAIL,               0x4e74ffff

.equ STALE_AUTHORITY,        1

.section .text
.global _start
.type _start, @function

_start:
    mov     $FSD_POSTCOMMIT_PROBE, %eax
    syscall
    cmp     $STALE_AUTHORITY, %rax
    jne     .Lfail_probe

    mov     $FSD_PUBLISH, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_publish

    mov     $FSD_DONE, %eax
    syscall
    # A successful DONE terminates this UserMode task. Any return is failure.
    mov     $3, %edi
    jmp     .Lfail

.Lfail_probe:
    mov     $1, %edi
    jmp     .Lfail
.Lfail_publish:
    mov     $2, %edi

.Lfail:
    mov     $FSD_FAIL, %eax
    syscall
    ud2

.size _start, . - _start
.section .note.GNU-stack,"",@progbits
