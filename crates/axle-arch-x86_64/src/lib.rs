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
