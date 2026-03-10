#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

//! x86_64 architecture helpers that legitimately require `unsafe`.
//!
//! This crate is the fenced home for bootstrap user/kernel ABI shims such as
//! the userspace `int 0x80` syscall trampoline used by Axle's early
//! conformance runner.

#[cfg(not(target_arch = "x86_64"))]
compile_error!("axle-arch-x86_64 only supports x86_64 targets");

/// Invoke Axle's bootstrap `int 0x80` ABI from userspace.
///
/// Arguments map to the current calling convention:
/// - `rax` = syscall number
/// - `rdi/rsi/rdx/r10/r8/r9` = args 0..5
///
/// Returns the raw `zx_status_t` encoded in `rax`.
#[inline(always)]
pub fn int80_syscall(nr: u64, args: [u64; 6]) -> i32 {
    let ret_rax: u64;

    // SAFETY: executes the bootstrap software interrupt ABI used by Axle's
    // userspace conformance runner and returns the kernel-written status in
    // `rax`. Register assignments follow the documented ABI contract.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") nr => ret_rax,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            clobber_abi("sysv64"),
        );
    }

    ret_rax as i32
}

/// Invoke Axle's bootstrap `int 0x80` ABI with two extra stack arguments.
///
/// Arguments map to the current calling convention:
/// - `rax` = syscall number
/// - `rdi/rsi/rdx/r10/r8/r9` = args 0..5
/// - `*(rsp + 0)` and `*(rsp + 8)` = args 6..7
///
/// The kernel trap handler reads args 6+ from the userspace stack snapshot.
#[inline(always)]
pub fn int80_syscall8(nr: u64, args: [u64; 8]) -> i32 {
    let ret_rax: u64;

    // SAFETY: executes the bootstrap software interrupt ABI used by Axle's
    // userspace conformance runner. The first six arguments are passed in the
    // documented register set and args 6..7 are staged on the userspace stack
    // where the trap handler expects them.
    unsafe {
        core::arch::asm!(
            "sub rsp, 16",
            "mov [rsp + 0], {arg6}",
            "mov [rsp + 8], {arg7}",
            "int 0x80",
            "add rsp, 16",
            arg6 = in(reg) args[6],
            arg7 = in(reg) args[7],
            inlateout("rax") nr => ret_rax,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            clobber_abi("sysv64"),
        );
    }

    ret_rax as i32
}

/// Trigger the bootstrap debug exit trap used by the userspace smoke runner.
#[inline(always)]
pub fn debug_break() -> ! {
    // SAFETY: executes the architected `int3` trap used by Axle's QEMU
    // bootstrap harness to hand control back to the kernel after populating
    // the shared result page. The trailing loop keeps the function diverging if
    // execution resumes unexpectedly.
    unsafe {
        core::arch::asm!("int3", options(nomem, nostack));
    }

    loop {
        core::hint::spin_loop();
    }
}
