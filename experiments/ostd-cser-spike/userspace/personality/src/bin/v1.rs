// SPDX-License-Identifier: MPL-2.0

#![no_main]
#![no_std]

use core::{arch::global_asm, panic::PanicInfo};

use linux_raw_sys::general::__NR_write;

const PORTAL_RECV: usize = 0x4c50_0000;
const PREPARE_WRITE: usize = 0x4c50_0001;
const QUEUE_STALE_WRITE: usize = 0x4c50_0002;
const BACKEND_COMMIT: usize = 0x4c52_0001;
const UNKNOWN_SYSCALL: usize = 0x4c5f_0001;

const APPLIED: usize = 0;

global_asm!(
    r#"
    .section .text
    .global _start
_start:
    mov ${portal_recv}, %rax
    syscall

    cmp ${linux_write}, %rax
    jne 1f
    cmp $1, %rdi
    jne 1f
    cmp $23, %rdx
    jne 1f
    cmp $91, %r10
    jne 1f
    cmp $30, %r12
    jne 1f
    cmp $1, %r8
    jne 1f
    cmp $400, %r13
    jne 1f
    cmp $1, %r14
    jne 1f
    cmp $1, %r9
    jne 1f

    mov ${prepare_write}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${backend_commit}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${queue_stale_write}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov 0x800000, %rax
    ud2

1:
    mov ${unknown_syscall}, %rax
    syscall
2:
    pause
    jmp 2b
"#,
    portal_recv = const PORTAL_RECV,
    linux_write = const __NR_write,
    prepare_write = const PREPARE_WRITE,
    backend_commit = const BACKEND_COMMIT,
    queue_stale_write = const QUEUE_STALE_WRITE,
    unknown_syscall = const UNKNOWN_SYSCALL,
    applied = const APPLIED,
    options(att_syntax)
);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
