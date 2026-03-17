//! Native x86_64 syscall entry.
//!
//! This path exists alongside the legacy `int 0x80` ABI:
//! - native `ax_*` / `zx_*` userspace can use `SYSCALL`
//! - bootstrap compatibility and conformance can still use `int 0x80`
//! - the trap handler still receives the same logical `TrapFrame + cpu_frame`
//!   shape so the wider kernel trap-exit machinery does not fork

use x86_64::registers::model_specific::Msr;

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;
const EFER_SCE: u64 = 1 << 0;
const RFLAGS_IF: u64 = 1 << 9;
const RFLAGS_DF: u64 = 1 << 10;

core::arch::global_asm!(
    r#"
    .global axle_native_syscall_entry
    .type axle_native_syscall_entry, @function
axle_native_syscall_entry:
    swapgs
    mov gs:[{user_rsp_scratch_offset}], rsp
    mov rsp, gs:[{kernel_rsp0_offset}]

    // Build a synthetic IRET frame so the Rust trap/finish path can keep using
    // the same cpu_frame layout as `int 0x80`.
    push QWORD PTR gs:[{user_ss_offset}]
    push QWORD PTR gs:[{user_rsp_scratch_offset}]
    push r11
    push QWORD PTR gs:[{user_cs_offset}]
    push rcx

    // Save a full logical trap frame. On native `SYSCALL` entry, `rcx` carries
    // the user return RIP and `r11` carries the masked user RFLAGS.
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
    lea rsi, [rsp + 15*8]
    call {rust_handler}

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

    swapgs
    iretq
    .size axle_native_syscall_entry, .-axle_native_syscall_entry
    "#,
    kernel_rsp0_offset = const crate::arch::percpu::KERNEL_RSP0_OFFSET,
    user_rsp_scratch_offset = const crate::arch::percpu::USER_RSP_SCRATCH_OFFSET,
    user_cs_offset = const crate::arch::percpu::USER_CS_OFFSET,
    user_ss_offset = const crate::arch::percpu::USER_SS_OFFSET,
    rust_handler = sym axle_native_syscall_rust,
);

unsafe extern "C" {
    fn axle_native_syscall_entry();
}

pub fn entry_addr() -> usize {
    axle_native_syscall_entry as *const () as usize
}

pub fn init_cpu() {
    if !crate::arch::cpuid::supports_native_syscall() {
        return;
    }

    let selectors = crate::arch::gdt::init();
    let star =
        (u64::from(selectors.user_code.0) << 48) | (u64::from(selectors.kernel_code.0) << 32);
    let fmask = RFLAGS_IF | RFLAGS_DF;

    // SAFETY: these MSRs are programmed once per CPU after GDT/per-CPU setup.
    // `entry_addr` points at a static kernel text stub, the selector values are
    // the currently loaded ring0/ring3 segments, and the EFER update only
    // enables the syscall extension bit.
    unsafe {
        let efer = Msr::new(IA32_EFER).read() | EFER_SCE;
        Msr::new(IA32_EFER).write(efer);
        Msr::new(IA32_STAR).write(star);
        Msr::new(IA32_LSTAR).write(entry_addr() as u64);
        Msr::new(IA32_FMASK).write(fmask);
    }
}

extern "C" fn axle_native_syscall_rust(
    frame: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *const u64,
) {
    crate::trace::record_sys_native_enter(frame.syscall_nr());
    crate::syscall::invoke_from_native_syscall(frame, cpu_frame);
}
