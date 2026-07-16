# SPDX-License-Identifier: MPL-2.0

# First bounded runtime-filesystem service. The numeric portal ABI is compatible
# with the existing raw netd guests so the kernel can use the same UserMode
# command convention. Compatibility does not share semantic identity: fsd has
# its own runner, task binding, request, and effect cohort.
#
# fsd-v1 accepts exactly one filesystem request, prepares it under the old
# binding, then deliberately page-faults before the request commit point. It
# cannot execute the request or publish a guest reply after the fault.

.equ FSD_NEXT,              0x4e740001
.equ FSD_PREPARE,           0x4e740002
.equ FSD_QUEUE_OLD_PREPARE, 0x4e740005
.equ FSD_FAIL,              0x4e74ffff

.equ OP_WAIT,               0
.equ OP_REQUEST,            1
.equ EXPECTED_FAULT,        0x00800000

.section .text
.global _start
.type _start, @function

_start:
.Lrequest:
    mov     $FSD_NEXT, %eax
    syscall
    cmp     $OP_WAIT, %rax
    je      .Lrequest
    cmp     $OP_REQUEST, %rax
    jne     .Lfail_request

    mov     $FSD_PREPARE, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_prepare

    # Queue one typed command carrying this current task generation and the old
    # PortalHandle.  Its delivery is deliberately delayed until after v2 has
    # rebound and adopted the effect.
    mov     $FSD_QUEUE_OLD_PREPARE, %eax
    syscall
    test    %rax, %rax
    jne     .Lfail_queue_old

    # This address is outside create_vm_space's executable mapping. The real
    # CPU page fault is the fsd-v1 crash boundary; COMMIT/PUBLISH are absent.
    movabs  $EXPECTED_FAULT, %rax
    mov     (%rax), %rax
    ud2

.Lfail_request:
    mov     $1, %edi
    jmp     .Lfail
.Lfail_prepare:
    mov     $2, %edi
    jmp     .Lfail
.Lfail_queue_old:
    mov     $3, %edi

.Lfail:
    mov     $FSD_FAIL, %eax
    syscall
    ud2

.size _start, . - _start
.section .note.GNU-stack,"",@progbits
