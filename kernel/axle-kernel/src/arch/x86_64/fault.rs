//! Minimal fault/exception handlers for early bring-up.
//!
//! Goal: avoid "silent hang" debugging. For now we:
//! - install handlers for #PF/#GP/#DF
//! - print vector + RIP + error code (+ CR2 for #PF)
//! - halt

use crate::arch;
use crate::kprintln;

const PUSHED_REGS_BYTES: u64 = 15 * 8;

core::arch::global_asm!(
    r#"
    .global axle_pf_entry
    .type axle_pf_entry, @function
axle_pf_entry:
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
    lea rsi, [rsp + {pushed}]
    mov rdx, cr2
    call {rust_pf}
    test al, al
    jnz 2f

    // Unhandled fault: halt.
1:
    hlt
    jmp 1b

2:
    pop rax
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
    add rsp, 8
    iretq
    .size axle_pf_entry, .-axle_pf_entry

    .global axle_ud_entry
    .type axle_ud_entry, @function
axle_ud_entry:
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
    lea rsi, [rsp + {pushed}]
    xor rdx, rdx
    call {rust_ud}
    test al, al
    jnz 2f

1:
    hlt
    jmp 1b

2:
    pop rax
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
    .size axle_ud_entry, .-axle_ud_entry

    .global axle_gp_entry
    .type axle_gp_entry, @function
axle_gp_entry:
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
    lea rsi, [rsp + {pushed}]
    xor rdx, rdx
    call {rust_gp}

1:
    hlt
    jmp 1b
    .size axle_gp_entry, .-axle_gp_entry

    .global axle_df_entry
    .type axle_df_entry, @function
axle_df_entry:
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
    lea rsi, [rsp + {pushed}]
    xor rdx, rdx
    call {rust_df}

1:
    hlt
    jmp 1b
    .size axle_df_entry, .-axle_df_entry
    "#,
    pushed = const PUSHED_REGS_BYTES,
    rust_pf = sym axle_page_fault_rust,
    rust_ud = sym axle_invalid_opcode_rust,
    rust_gp = sym axle_gp_fault_rust,
    rust_df = sym axle_double_fault_rust,
);

unsafe extern "C" {
    fn axle_pf_entry();
    fn axle_ud_entry();
    fn axle_gp_entry();
    fn axle_df_entry();
}

/// Address of the page fault entry point (vector 14).
pub fn page_fault_entry_addr() -> usize {
    axle_pf_entry as *const () as usize
}

/// Address of the invalid opcode entry point (vector 6).
pub fn invalid_opcode_entry_addr() -> usize {
    axle_ud_entry as *const () as usize
}

/// Address of the general protection fault entry point (vector 13).
pub fn gp_fault_entry_addr() -> usize {
    axle_gp_entry as *const () as usize
}

/// Address of the double fault entry point (vector 8).
pub fn double_fault_entry_addr() -> usize {
    axle_df_entry as *const () as usize
}

fn decode_cpu_frame_with_error_code(cpu: *const u64) -> (u64, u64, u64, u64, Option<(u64, u64)>) {
    // Layout on stack (top):
    // - error_code
    // - rip
    // - cs
    // - rflags
    // - rsp (if privilege change)
    // - ss  (if privilege change)
    //
    // We don't rely on the optional rsp/ss unless CS.RPL indicates ring3.
    let error = unsafe { *cpu };
    let rip = unsafe { *cpu.add(1) };
    let cs = unsafe { *cpu.add(2) };
    let rflags = unsafe { *cpu.add(3) };
    let from_user = (cs & 0b11) == 0b11;
    let rsp_ss = if from_user {
        let rsp = unsafe { *cpu.add(4) };
        let ss = unsafe { *cpu.add(5) };
        Some((rsp, ss))
    } else {
        None
    };
    (error, rip, cs, rflags, rsp_ss)
}

fn decode_cpu_frame_without_error(cpu: *const u64) -> (u64, u64, u64, Option<(u64, u64)>) {
    let rip = unsafe { *cpu };
    let cs = unsafe { *cpu.add(1) };
    let rflags = unsafe { *cpu.add(2) };
    let from_user = (cs & 0b11) == 0b11;
    let rsp_ss = if from_user {
        let rsp = unsafe { *cpu.add(3) };
        let ss = unsafe { *cpu.add(4) };
        Some((rsp, ss))
    } else {
        None
    };
    (rip, cs, rflags, rsp_ss)
}

extern "C" fn axle_page_fault_rust(
    regs: &mut crate::arch::int80::TrapFrame,
    cpu: *mut u64,
    cr2: u64,
) -> bool {
    let (error, rip, cs, rflags, rsp_ss) = decode_cpu_frame_with_error_code(cpu.cast_const());
    if crate::fault::handle_page_fault(regs, cpu, cr2, error) {
        return true;
    }
    kprintln!(
        "#PF: rip={:#x} cs={:#x} rflags={:#x} err={:#x} cr2={:#x} from_user={} rsp_ss={:?}",
        rip,
        cs,
        rflags,
        error,
        cr2,
        (cs & 0b11) == 0b11,
        rsp_ss
    );
    arch::cpu::halt_loop();
}

extern "C" fn axle_invalid_opcode_rust(
    regs: &mut crate::arch::int80::TrapFrame,
    cpu: *mut u64,
    _unused: u64,
) -> bool {
    let (rip, cs, rflags, rsp_ss) = decode_cpu_frame_without_error(cpu.cast_const());
    if crate::fault::handle_invalid_opcode(regs, cpu) {
        return true;
    }
    kprintln!(
        "#UD: rip={:#x} cs={:#x} rflags={:#x} from_user={} rsp_ss={:?} rax={:#x} rdi={:#x} rsi={:#x} rdx={:#x} rcx={:#x} r8={:#x} r9={:#x} r10={:#x} r11={:#x}",
        rip,
        cs,
        rflags,
        (cs & 0b11) == 0b11,
        rsp_ss,
        regs.rax,
        regs.rdi,
        regs.rsi,
        regs.rdx,
        regs.rcx,
        regs.r8,
        regs.r9,
        regs.r10,
        regs.r11,
    );
    arch::cpu::halt_loop();
}

extern "C" fn axle_gp_fault_rust(
    regs: &crate::arch::int80::TrapFrame,
    cpu: *const u64,
    _unused: u64,
) -> ! {
    let (error, rip, cs, rflags, rsp_ss) = decode_cpu_frame_with_error_code(cpu);
    let component = crate::userspace::component_summary_snapshot();
    let (kernel_stack_words, kernel_ret_words) = if rsp_ss.is_none() {
        // SAFETY: for a ring0 #GP the CPU pushes {error, rip, cs, rflags} onto the current
        // kernel stack before transferring control here. The pre-fault stack top is therefore
        // the first word immediately after that four-word hardware frame.
        unsafe {
            let rsp = cpu.add(4);
            (
                Some([
                    *rsp.add(0),
                    *rsp.add(1),
                    *rsp.add(2),
                    *rsp.add(3),
                    *rsp.add(4),
                    *rsp.add(5),
                    *rsp.add(6),
                    *rsp.add(7),
                    *rsp.add(8),
                    *rsp.add(9),
                    *rsp.add(10),
                    *rsp.add(11),
                ]),
                Some([*rsp.add(17), *rsp.add(18), *rsp.add(19), *rsp.add(20)]),
            )
        }
    } else {
        (None, None)
    };
    kprintln!(
        "#GP: rip={:#x} cs={:#x} rflags={:#x} err={:#x} from_user={} rsp_ss={:?} kstack={:?} kret={:?} rax={:#x} rdi={:#x} rsi={:#x} rdx={:#x} rcx={:#x} r8={:#x} r9={:#x} r10={:#x} r11={:#x} rbp={:#x} component={:?}",
        rip,
        cs,
        rflags,
        error,
        (cs & 0b11) == 0b11,
        rsp_ss,
        kernel_stack_words,
        kernel_ret_words,
        regs.rax,
        regs.rdi,
        regs.rsi,
        regs.rdx,
        regs.rcx,
        regs.r8,
        regs.r9,
        regs.r10,
        regs.r11,
        regs.rbp,
        component,
    );
    arch::cpu::halt_loop();
}

extern "C" fn axle_double_fault_rust(
    _regs: &crate::arch::int80::TrapFrame,
    cpu: *const u64,
    _unused: u64,
) -> ! {
    let (error, rip, cs, rflags, rsp_ss) = decode_cpu_frame_with_error_code(cpu);
    kprintln!(
        "#DF: rip={:#x} cs={:#x} rflags={:#x} err={:#x} from_user={} rsp_ss={:?}",
        rip,
        cs,
        rflags,
        error,
        (cs & 0b11) == 0b11,
        rsp_ss
    );
    arch::cpu::halt_loop();
}
