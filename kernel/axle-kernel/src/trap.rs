//! Trap/exception/interrupt scaffolding (Phase B).
//!
//! TODO: build IDT, fault handlers, IRQ handlers, IPI.

use axle_types::status::{ZX_ERR_BAD_SYSCALL, ZX_ERR_NOT_SUPPORTED};
use axle_types::syscall_numbers::AXLE_SYS_PORT_CREATE;

use crate::arch;

pub fn init() {
    arch::idt::init_int80_gate(arch::int80::entry_addr());
    int80_self_test();
}

fn int80_self_test() {
    // Unknown syscall id should fail with BAD_SYSCALL.
    let unknown_status = run_int80(u64::MAX);
    if unknown_status != ZX_ERR_BAD_SYSCALL {
        panic!(
            "int80 self-test failed: expected {}, got {}",
            ZX_ERR_BAD_SYSCALL, unknown_status
        );
    }

    // Known syscall id (wired in dispatch) should currently return NOT_SUPPORTED.
    let known_status = run_int80(AXLE_SYS_PORT_CREATE as u64);
    if known_status != ZX_ERR_NOT_SUPPORTED {
        panic!(
            "int80 self-test failed: expected {}, got {} for AXLE_SYS_PORT_CREATE",
            ZX_ERR_NOT_SUPPORTED, known_status
        );
    }

    crate::kprintln!(
        "trap: int80 self-test ok (unknown={}, known={})",
        unknown_status,
        known_status
    );
}

fn run_int80(nr: u64) -> i32 {
    let ret_rax: u64;

    // SAFETY: this executes a software interrupt through the installed 0x80 gate
    // in early boot with zeroed arguments and captures the return status from `rax`.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") nr => ret_rax,
            in("rdi") 0u64,
            in("rsi") 0u64,
            in("rdx") 0u64,
            in("r10") 0u64,
            in("r8") 0u64,
            in("r9") 0u64,
            clobber_abi("sysv64"),
        );
    }

    ret_rax as i32
}
