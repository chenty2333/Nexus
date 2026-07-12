// SPDX-License-Identifier: MPL-2.0

#![no_main]
#![no_std]

use core::{arch::global_asm, panic::PanicInfo};

use linux_raw_sys::general::{__NR_exit_group, __NR_write};

const RECOVERY_SNAPSHOT: usize = 0x4c51_0001;
const READY: usize = 0x4c51_0002;
const REBIND: usize = 0x4c51_0003;
const RECOVER_NEXT: usize = 0x4c51_0004;
const ADOPT: usize = 0x4c51_0005;
const BACKEND_COMMIT: usize = 0x4c52_0001;
const PORTAL_RECV_NEXT: usize = 0x4c51_0007;
const COMMIT_EXIT: usize = 0x4c51_0008;
const PREPARE_EXIT: usize = 0x4c51_0009;
const PERSONALITY_DONE: usize = 0x4c51_000a;
const REPLY_WRITE: usize = 0x4c52_0002;
const REVOKE_PROBE_SETUP: usize = 0x4c53_0001;
const REVOKE_PROBE_BACKEND_COMMIT: usize = 0x4c53_0002;
const REVOKE_PROBE_BEGIN: usize = 0x4c53_0003;
const REVOKE_PROBE_REPLY: usize = 0x4c53_0004;
const REVOKE_PROBE_CLOSURE_NEXT: usize = 0x4c53_0005;
const REVOKE_PROBE_COMPLETE: usize = 0x4c53_0006;
const REVOKE_PROBE_PREPARE: usize = 0x4c53_0007;
const UNKNOWN_SYSCALL: usize = 0x4c5f_0001;

const APPLIED: usize = 0;
const ALREADY_COMMITTED: usize = 1;
const STALE_BINDING: usize = 2;
const STALE_AUTHORITY: usize = 3;
const IDENTITY_MISMATCH: usize = 4;
const INVALID_STATE: usize = 5;
const NO_SUPERVISOR: usize = 6;
const ALREADY_TERMINAL: usize = 7;
const NOT_ADOPTABLE: usize = 8;
const NOT_QUIESCENT: usize = 10;
const UNKNOWN_OPERATION: usize = 11;

global_asm!(
    r#"
    .section .text
    .global _start
_start:
    mov ${recovery_snapshot}, %rax
    syscall
    cmp ${linux_write}, %rax
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

    mov ${ready}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f

    # Send a real full-identity reply while no supervisor is bound.
    mov $2, %r9
    mov ${reply_write}, %rax
    syscall
    cmp ${no_supervisor}, %rax
    jne 1f
    mov $1, %r9

    mov ${rebind}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f

    # The recovery snapshot still carries binding epoch 1, so this is a
    # genuine stale packet after rebind rather than a kernel-local shortcut.
    mov ${reply_write}, %rax
    syscall
    cmp ${stale_binding}, %rax
    jne 1f

    mov ${recover_next}, %rax
    syscall
    cmp ${linux_write}, %rax
    jne 1f
    cmp $1, %rdi
    jne 1f
    cmp $23, %rdx
    jne 1f

    mov ${adopt}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    cmp $2, %r9
    jne 1f

    # With the adopted current token installed, vary only the effect identity.
    mov $999, %r8
    mov ${reply_write}, %rax
    syscall
    cmp ${identity_mismatch}, %rax
    jne 1f
    mov $1, %r8

    # The full current token is otherwise valid; only the opcode is unknown.
    mov ${unknown_syscall}, %rax
    syscall
    cmp ${unknown_operation}, %rax
    jne 1f

    # After explicit adoption, replay the old binding token once more.  This
    # is the strongest stale witness: the live record is already binding 2.
    mov $1, %r9
    mov ${reply_write}, %rax
    syscall
    cmp ${stale_binding}, %rax
    jne 1f
    mov $2, %r9
    mov ${adopt}, %rax
    syscall
    cmp ${not_adoptable}, %rax
    jne 1f
    mov ${backend_commit}, %rax
    syscall
    cmp ${already_committed}, %rax
    jne 1f
    mov ${reply_write}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${reply_write}, %rax
    syscall
    cmp ${already_terminal}, %rax
    jne 1f

    # Scope 31: revoke while the write is prepared but not committed.
    xor %rdi, %rdi
    mov ${revoke_probe_setup}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${revoke_probe_prepare}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${revoke_probe_begin}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${revoke_probe_complete}, %rax
    syscall
    cmp ${not_quiescent}, %rax
    jne 1f
    mov ${revoke_probe_backend_commit}, %rax
    syscall
    cmp ${stale_authority}, %rax
    jne 1f
    mov ${revoke_probe_reply}, %rax
    syscall
    cmp ${stale_authority}, %rax
    jne 1f
    mov ${revoke_probe_closure_next}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${revoke_probe_complete}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f

    # Scope 32: commit first, then revoke and let kernel closure drain it.
    mov $1, %rdi
    mov ${revoke_probe_setup}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${revoke_probe_prepare}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${revoke_probe_backend_commit}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${revoke_probe_begin}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${revoke_probe_complete}, %rax
    syscall
    cmp ${not_quiescent}, %rax
    jne 1f
    mov ${revoke_probe_backend_commit}, %rax
    syscall
    cmp ${stale_authority}, %rax
    jne 1f
    mov ${revoke_probe_reply}, %rax
    syscall
    cmp ${stale_authority}, %rax
    jne 1f
    mov ${revoke_probe_closure_next}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${revoke_probe_complete}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f

    mov ${portal_recv_next}, %rax
    syscall
    cmp ${linux_exit_group}, %rax
    jne 1f
    test %rdi, %rdi
    jne 1f

    # Completion is illegal until exit_group has explicitly prepared its
    # reply; the failed attempt must leave the continuation Captured.
    mov ${commit_exit}, %rax
    syscall
    cmp ${invalid_state}, %rax
    jne 1f
    mov ${prepare_exit}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${commit_exit}, %rax
    syscall
    cmp ${applied}, %rax
    jne 1f
    mov ${commit_exit}, %rax
    syscall
    cmp ${already_terminal}, %rax
    jne 1f
    mov ${personality_done}, %rax
    syscall

1:
    mov ${unknown_syscall}, %rax
    syscall
2:
    pause
    jmp 2b
"#,
    recovery_snapshot = const RECOVERY_SNAPSHOT,
    ready = const READY,
    rebind = const REBIND,
    recover_next = const RECOVER_NEXT,
    linux_write = const __NR_write,
    adopt = const ADOPT,
    backend_commit = const BACKEND_COMMIT,
    portal_recv_next = const PORTAL_RECV_NEXT,
    linux_exit_group = const __NR_exit_group,
    commit_exit = const COMMIT_EXIT,
    prepare_exit = const PREPARE_EXIT,
    personality_done = const PERSONALITY_DONE,
    reply_write = const REPLY_WRITE,
    revoke_probe_setup = const REVOKE_PROBE_SETUP,
    revoke_probe_backend_commit = const REVOKE_PROBE_BACKEND_COMMIT,
    revoke_probe_begin = const REVOKE_PROBE_BEGIN,
    revoke_probe_reply = const REVOKE_PROBE_REPLY,
    revoke_probe_closure_next = const REVOKE_PROBE_CLOSURE_NEXT,
    revoke_probe_complete = const REVOKE_PROBE_COMPLETE,
    revoke_probe_prepare = const REVOKE_PROBE_PREPARE,
    unknown_syscall = const UNKNOWN_SYSCALL,
    applied = const APPLIED,
    already_committed = const ALREADY_COMMITTED,
    stale_binding = const STALE_BINDING,
    stale_authority = const STALE_AUTHORITY,
    identity_mismatch = const IDENTITY_MISMATCH,
    invalid_state = const INVALID_STATE,
    no_supervisor = const NO_SUPERVISOR,
    already_terminal = const ALREADY_TERMINAL,
    not_adoptable = const NOT_ADOPTABLE,
    not_quiescent = const NOT_QUIESCENT,
    unknown_operation = const UNKNOWN_OPERATION,
    options(att_syntax)
);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
