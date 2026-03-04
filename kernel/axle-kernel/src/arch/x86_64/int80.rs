//! Minimal `int 0x80` syscall entry path.
//!
//! ABI contract locked in this phase:
//! - `rax` = syscall number
//! - `rdi/rsi/rdx/r10/r8/r9` = args 0..5
//! - return `zx_status_t` in `rax`

use axle_types::zx_status_t;

core::arch::global_asm!(
    r#"
    .global axle_int80_entry
    .type axle_int80_entry, @function
axle_int80_entry:
    // Save a full register snapshot for the Rust trap handler.
    push r15
    push r14
    push r13
    push r12
    push rbx
    push rbp
    push r11
    push rcx
    push r9
    push r8
    push r10
    push rdx
    push rsi
    push rdi
    push rax

    mov rdi, rsp
    call {rust_handler}

    // Load syscall return status from frame->rax.
    mov rax, [rsp + 0]

    // Restore interrupted context (except rax, kept as return register).
    add rsp, 8
    pop rdi
    pop rsi
    pop rdx
    pop r10
    pop r8
    pop r9
    pop rcx
    pop r11
    pop rbp
    pop rbx
    pop r12
    pop r13
    pop r14
    pop r15
    iretq
    .size axle_int80_entry, .-axle_int80_entry
    "#,
    rust_handler = sym axle_int80_rust,
);

unsafe extern "C" {
    fn axle_int80_entry();
}

/// Saved register frame passed from the `int 0x80` assembly stub.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TrapFrame {
    /// Syscall number on entry, return status on exit.
    pub rax: u64,
    /// Argument register 0.
    pub rdi: u64,
    /// Argument register 1.
    pub rsi: u64,
    /// Argument register 2.
    pub rdx: u64,
    /// Argument register 3.
    pub r10: u64,
    /// Argument register 4.
    pub r8: u64,
    /// Argument register 5.
    pub r9: u64,
    /// Caller-clobbered scratch.
    pub rcx: u64,
    /// Caller-clobbered scratch.
    pub r11: u64,
    /// Callee-saved.
    pub rbp: u64,
    /// Callee-saved.
    pub rbx: u64,
    /// Callee-saved.
    pub r12: u64,
    /// Callee-saved.
    pub r13: u64,
    /// Callee-saved.
    pub r14: u64,
    /// Callee-saved.
    pub r15: u64,
}

impl TrapFrame {
    /// Syscall number as provided in `rax` on entry.
    pub const fn syscall_nr(&self) -> u64 {
        self.rax
    }

    /// Syscall arguments (up to 6).
    pub const fn args(&self) -> [u64; 6] {
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9]
    }

    /// Write `zx_status_t` return value into `rax`.
    pub fn set_status(&mut self, status: zx_status_t) {
        self.rax = (status as i64) as u64;
    }
}

/// Address of the assembly entry point for IDT installation.
pub fn entry_addr() -> usize {
    axle_int80_entry as *const () as usize
}

extern "C" fn axle_int80_rust(frame: &mut TrapFrame) {
    crate::syscall::invoke_from_trapframe(frame);
}
