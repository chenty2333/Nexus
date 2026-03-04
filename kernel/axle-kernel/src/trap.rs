//! Trap/exception/interrupt scaffolding (Phase B).
//!
//! TODO: build IDT, fault handlers, IRQ handlers, IPI.

use axle_types::status::ZX_ERR_BAD_SYSCALL;

use crate::arch;

pub fn init() {
    arch::idt::init_int80_gate(arch::int80::entry_addr());
    int80_self_test();
}

fn int80_self_test() {
    // Use a large unknown syscall number to verify early fallback behavior.
    let mut ret_rax: u64 = 0;

    // SAFETY: this executes a software interrupt through the freshly installed
    // IDT gate in early boot; no user data is involved.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") u64::MAX => ret_rax,
            in("rdi") 0u64,
            in("rsi") 0u64,
            in("rdx") 0u64,
            in("r10") 0u64,
            in("r8") 0u64,
            in("r9") 0u64,
            clobber_abi("sysv64"),
        );
    }

    let status = ret_rax as i32;
    if status != ZX_ERR_BAD_SYSCALL {
        panic!(
            "int80 self-test failed: expected {}, got {}",
            ZX_ERR_BAD_SYSCALL, status
        );
    }

    crate::kprintln!("trap: int80 self-test ok ({})", status);
}
