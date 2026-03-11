//! Breakpoint (`int3`) entry path used as a temporary "userspace runner exit".
//!
//! This is a bring-up bridge until we have a real userspace exit protocol.

core::arch::global_asm!(
    r#"
    .global axle_breakpoint_entry
    .type axle_breakpoint_entry, @function
axle_breakpoint_entry:
    // Save the same register snapshot layout as the int80 trap frame.
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

    // If the Rust handler returns, restore context and continue.
    mov rax, [rsp + 0]
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
    .size axle_breakpoint_entry, .-axle_breakpoint_entry
    "#,
    rust_handler = sym axle_breakpoint_rust,
);

unsafe extern "C" {
    fn axle_breakpoint_entry();
}

/// Address of the assembly entry point for IDT installation.
pub fn entry_addr() -> usize {
    axle_breakpoint_entry as *const () as usize
}

extern "C" fn axle_breakpoint_rust(_frame: *const u8) {
    crate::userspace::on_breakpoint()
}
