use std::fmt::{self, Write as _};
use std::fs;
use std::path::Path;

use anyhow::{Result, bail};

use crate::seed::{
    ChannelHandleOp, ConcurrentSeed, FutexFaultOp, HookId, ProgramOp, SchedHint, SystemKind, WaitOp,
};

const USER_SHARED_BASE: u64 = 0x0000_0001_0000_8000;
const SLOT_OK: usize = 0;
const SLOT_FAIL_CODE: usize = 1;
const SLOT_ROOT_VMAR_H: usize = 62;
const SLOT_SELF_PROCESS_H: usize = 396;
const SLOT_T0_NS: usize = 511;
const SLOT_VM_FAULT_TEST_HOOK_ARM: usize = 431;

const SIG_READABLE: u32 = 0x1;
const SIG_PEER_CLOSED: u32 = 0x4;
const SIG_TIMER_SIGNALED: u32 = 0x8;
const WAIT_ASYNC_EDGE: u32 = 0x2;
const ZX_VM_SPECIFIC_READ_WRITE: u32 = 0x403;
const ZX_RIGHT_SAME_RIGHTS: u32 = 0xffff_ffff;
const ZX_CLOCK_MONOTONIC: u32 = 0;

const AXLE_SYS_HANDLE_CLOSE: u32 = 0;
const AXLE_SYS_OBJECT_WAIT_ONE: u32 = 1;
const AXLE_SYS_OBJECT_WAIT_ASYNC: u32 = 2;
const AXLE_SYS_PORT_CREATE: u32 = 3;
const AXLE_SYS_PORT_WAIT: u32 = 5;
const AXLE_SYS_TIMER_CREATE: u32 = 6;
const AXLE_SYS_TIMER_SET: u32 = 7;
const AXLE_SYS_TIMER_CANCEL: u32 = 8;
const AXLE_SYS_VMO_CREATE: u32 = 9;
const AXLE_SYS_VMAR_MAP: u32 = 10;
const AXLE_SYS_CHANNEL_CREATE: u32 = 13;
const AXLE_SYS_CHANNEL_WRITE: u32 = 14;
const AXLE_SYS_CHANNEL_READ: u32 = 15;
const AXLE_SYS_HANDLE_DUPLICATE: u32 = 18;
const AXLE_SYS_HANDLE_REPLACE: u32 = 19;
const AXLE_SYS_OBJECT_SIGNAL: u32 = 20;
const AXLE_SYS_FUTEX_WAIT: u32 = 21;
const AXLE_SYS_FUTEX_WAKE: u32 = 22;
const AXLE_SYS_FUTEX_REQUEUE: u32 = 23;
const AXLE_SYS_THREAD_CREATE: u32 = 25;
const AXLE_SYS_THREAD_START: u32 = 26;

const FOREVER_DEADLINE: u64 = 0x7fff_ffff_ffff_ffff;
const TICK_NS: u64 = 1_000_000;
const CHILD_STACK_VA: u64 = 0x0000_0001_0001_0000;

const CTRL_TURN: u64 = 0x1000;
const CTRL_DONE: u64 = 0x1004;
const CTRL_CLOCK_CURSOR: u64 = 0x1010;
const CTRL_PORT: u64 = 0x1020;
const CTRL_TIMER0: u64 = 0x1028;
const CTRL_TIMER1: u64 = 0x1030;
const CTRL_ADV_TIMER: u64 = 0x1038;
const CTRL_EVENT_BASE: u64 = 0x1040;
const CTRL_STACK_VMO: u64 = 0x1080;
const CTRL_STACK_ADDR: u64 = 0x1088;
const CTRL_CHILD_THREAD: u64 = 0x1090;
const CTRL_CHANNEL_BASE: u64 = 0x10a0;
const CTRL_FUTEX_VMO: u64 = 0x10d0;
const CTRL_FUTEX_ADDR: u64 = 0x10d8;
const CTRL_FAULT_VMO_BASE: u64 = 0x10e0;
const CTRL_FAULT_ADDR_BASE: u64 = 0x10f8;
const SCRATCH_TX: u64 = 0x1200;
const SCRATCH_RX: u64 = 0x1300;
const SCRATCH_PACKET: u64 = 0x1400;
const SCRATCH_ACTUAL_BYTES: u64 = 0x1500;
const SCRATCH_ACTUAL_HANDLES: u64 = 0x1508;
const SCRATCH_OBSERVED: u64 = 0x1510;

pub fn write_guest_runner(seed: &ConcurrentSeed, out_path: &Path) -> Result<()> {
    let asm = render_guest_runner(seed)?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(out_path, asm)?;
    Ok(())
}

fn render_guest_runner(seed: &ConcurrentSeed) -> Result<String> {
    let mut asm = AsmBuilder::default();
    asm.line(".section .text.axle_userprog, \"ax\"");
    asm.line(".global axle_user_prog_start");
    asm.line(".global axle_user_prog_end");
    asm.label("axle_user_prog_start");
    asm.inst(format_args!("movabs ${USER_SHARED_BASE:#x}, %rbx"));
    asm.inst("movq $0, 8*0(%rbx)");
    asm.inst(format_args!("movq $0, 8*{}(%rbx)", SLOT_FAIL_CODE));
    asm.inst(format_args!("movl $1, {CTRL_TURN}(%rbx)"));
    asm.inst(format_args!("movl $0, {CTRL_DONE}(%rbx)"));
    asm.inst(format_args!("movq $0, {CTRL_CLOCK_CURSOR}(%rbx)"));

    match seed.system {
        SystemKind::WaitPortTimer => emit_wait_port_setup(&mut asm)?,
        SystemKind::FutexFault => emit_futex_fault_setup(&mut asm)?,
        SystemKind::ChannelHandle => emit_channel_handle_setup(&mut asm)?,
    }
    emit_child_thread_start(&mut asm)?;
    emit_actor_run(&mut asm, seed, ActorAsm::A)?;
    emit_actor_done(&mut asm, ActorAsm::A);
    emit_actor_entry(&mut asm, seed, ActorAsm::B)?;
    emit_actor_done(&mut asm, ActorAsm::B);
    emit_common_helpers(&mut asm);
    asm.label("user_fail");
    asm.inst("movq $0, 8*0(%rbx)");
    asm.inst("int3");
    asm.label("axle_user_prog_end");
    Ok(asm.finish())
}

#[derive(Clone, Copy)]
enum ActorAsm {
    A,
    B,
}

impl ActorAsm {
    fn id(self) -> u32 {
        match self {
            Self::A => 1,
            Self::B => 2,
        }
    }

    fn run_label(self) -> &'static str {
        match self {
            Self::A => "actor_a_run",
            Self::B => "actor_b_entry",
        }
    }

    fn done_label(self) -> &'static str {
        match self {
            Self::A => "actor_a_done",
            Self::B => "actor_b_done",
        }
    }

    fn wait_turn_label(self) -> &'static str {
        match self {
            Self::A => "wait_turn_a",
            Self::B => "wait_turn_b",
        }
    }

    fn yield_label(self) -> &'static str {
        match self {
            Self::A => "yield_to_a",
            Self::B => "yield_to_b",
        }
    }
}

#[derive(Default)]
struct AsmBuilder {
    out: String,
}

impl AsmBuilder {
    fn line(&mut self, line: &str) {
        self.out.push_str(line);
        self.out.push('\n');
    }

    fn inst(&mut self, args: impl fmt::Display) {
        let _ = writeln!(self.out, "\t{args}");
    }

    fn label(&mut self, label: &str) {
        let _ = writeln!(self.out, "{label}:");
    }

    fn finish(self) -> String {
        self.out
    }
}

fn emit_setup_assert_ok(asm: &mut AsmBuilder, code: u32) {
    asm.inst("test %rax, %rax");
    let _ = writeln!(asm.out, "\tje setup_ok_{code}");
    asm.inst(format_args!("movq ${code}, 8*{}(%rbx)", SLOT_FAIL_CODE));
    asm.inst("jmp user_fail");
    asm.label(&format!("setup_ok_{code}"));
}

fn emit_deadline(asm: &mut AsmBuilder, reg: &str, ticks: Option<u8>) {
    match ticks {
        Some(ticks) => {
            asm.inst(format_args!("mov 8*{}(%rbx), {reg}", SLOT_T0_NS));
            asm.inst(format_args!("add {CTRL_CLOCK_CURSOR}(%rbx), {reg}"));
            asm.inst(format_args!("add ${}, {reg}", u64::from(ticks) * TICK_NS));
        }
        None => asm.inst(format_args!("movabs ${FOREVER_DEADLINE:#x}, {reg}")),
    }
}

fn emit_turn_yield(asm: &mut AsmBuilder, actor: ActorAsm) {
    asm.inst(format_args!("call {}", actor.yield_label()));
}

fn emit_turn_wait(asm: &mut AsmBuilder, actor: ActorAsm) {
    asm.inst(format_args!("call {}", actor.wait_turn_label()));
}

fn emit_wait_port_setup(asm: &mut AsmBuilder) -> Result<()> {
    asm.inst(format_args!("lea {CTRL_PORT}(%rbx), %rsi"));
    asm.inst("xorl %edi, %edi");
    asm.inst(format_args!("movabs ${AXLE_SYS_PORT_CREATE}, %rax"));
    asm.inst("int $0x80");
    emit_setup_assert_ok(asm, 10);

    for (index, offset) in [CTRL_TIMER0, CTRL_TIMER1, CTRL_ADV_TIMER]
        .into_iter()
        .enumerate()
    {
        asm.inst(format_args!("lea {offset}(%rbx), %rdx"));
        asm.inst("xorl %edi, %edi");
        asm.inst(format_args!("movl ${ZX_CLOCK_MONOTONIC}, %esi"));
        asm.inst(format_args!("movabs ${AXLE_SYS_TIMER_CREATE}, %rax"));
        asm.inst("int $0x80");
        emit_setup_assert_ok(asm, 20 + index as u32);
    }

    for waitable in 0..4_u64 {
        let active = CTRL_EVENT_BASE + waitable * 16;
        let peer = active + 8;
        asm.inst(format_args!("lea {active}(%rbx), %rsi"));
        asm.inst(format_args!("lea {peer}(%rbx), %rdx"));
        asm.inst("xorl %edi, %edi");
        asm.inst(format_args!("movabs ${AXLE_SYS_CHANNEL_CREATE}, %rax"));
        asm.inst("int $0x80");
        emit_setup_assert_ok(asm, 30 + waitable as u32);
    }
    Ok(())
}

fn emit_futex_fault_setup(asm: &mut AsmBuilder) -> Result<()> {
    asm.inst(format_args!("lea {CTRL_ADV_TIMER}(%rbx), %rdx"));
    asm.inst("xorl %edi, %edi");
    asm.inst(format_args!("movl ${ZX_CLOCK_MONOTONIC}, %esi"));
    asm.inst(format_args!("movabs ${AXLE_SYS_TIMER_CREATE}, %rax"));
    asm.inst("int $0x80");
    emit_setup_assert_ok(asm, 40);

    asm.inst(format_args!("lea {CTRL_FUTEX_VMO}(%rbx), %rdx"));
    asm.inst("movabs $0x1000, %rdi");
    asm.inst("xorl %esi, %esi");
    asm.inst(format_args!("movabs ${AXLE_SYS_VMO_CREATE}, %rax"));
    asm.inst("int $0x80");
    emit_setup_assert_ok(asm, 41);
    asm.inst(format_args!("mov 8*{}(%rbx), %rdi", SLOT_ROOT_VMAR_H));
    asm.inst(format_args!("movl ${ZX_VM_SPECIFIC_READ_WRITE}, %esi"));
    asm.inst("movabs $0x10010000, %rdx");
    asm.inst(format_args!("mov {CTRL_FUTEX_VMO}(%rbx), %r10"));
    asm.inst("xor %r8, %r8");
    asm.inst("movabs $0x1000, %r9");
    asm.inst(format_args!("lea {CTRL_FUTEX_ADDR}(%rbx), %rax"));
    asm.inst("sub $8, %rsp");
    asm.inst("mov %rax, (%rsp)");
    asm.inst(format_args!("movabs ${AXLE_SYS_VMAR_MAP}, %rax"));
    asm.inst("int $0x80");
    asm.inst("add $8, %rsp");
    emit_setup_assert_ok(asm, 42);

    for key in 0..3_u64 {
        let vmo = CTRL_FAULT_VMO_BASE + key * 8;
        let addr = CTRL_FAULT_ADDR_BASE + key * 8;
        let va = 0x1002_0000_u64 + key * 0x1000;
        asm.inst(format_args!("lea {vmo}(%rbx), %rdx"));
        asm.inst("movabs $0x1000, %rdi");
        asm.inst("xorl %esi, %esi");
        asm.inst(format_args!("movabs ${AXLE_SYS_VMO_CREATE}, %rax"));
        asm.inst("int $0x80");
        emit_setup_assert_ok(asm, 50 + key as u32);
        asm.inst(format_args!("mov 8*{}(%rbx), %rdi", SLOT_ROOT_VMAR_H));
        asm.inst(format_args!("movl ${ZX_VM_SPECIFIC_READ_WRITE}, %esi"));
        asm.inst(format_args!("movabs ${va:#x}, %rdx"));
        asm.inst(format_args!("mov {vmo}(%rbx), %r10"));
        asm.inst("xor %r8, %r8");
        asm.inst("movabs $0x1000, %r9");
        asm.inst(format_args!("lea {addr}(%rbx), %rax"));
        asm.inst("sub $8, %rsp");
        asm.inst("mov %rax, (%rsp)");
        asm.inst(format_args!("movabs ${AXLE_SYS_VMAR_MAP}, %rax"));
        asm.inst("int $0x80");
        asm.inst("add $8, %rsp");
        emit_setup_assert_ok(asm, 60 + key as u32);
    }
    Ok(())
}

fn emit_channel_handle_setup(asm: &mut AsmBuilder) -> Result<()> {
    asm.inst(format_args!("lea {}(%rbx), %rsi", handle_slot_offset(0)));
    asm.inst(format_args!("lea {}(%rbx), %rdx", handle_slot_offset(1)));
    asm.inst("xorl %edi, %edi");
    asm.inst(format_args!("movabs ${AXLE_SYS_CHANNEL_CREATE}, %rax"));
    asm.inst("int $0x80");
    emit_setup_assert_ok(asm, 70);
    Ok(())
}

fn emit_child_thread_start(asm: &mut AsmBuilder) -> Result<()> {
    asm.inst(format_args!("lea {CTRL_STACK_VMO}(%rbx), %rdx"));
    asm.inst("movabs $0x1000, %rdi");
    asm.inst("xorl %esi, %esi");
    asm.inst(format_args!("movabs ${AXLE_SYS_VMO_CREATE}, %rax"));
    asm.inst("int $0x80");
    emit_setup_assert_ok(asm, 80);

    asm.inst(format_args!("mov 8*{}(%rbx), %rdi", SLOT_ROOT_VMAR_H));
    asm.inst(format_args!("movl ${ZX_VM_SPECIFIC_READ_WRITE}, %esi"));
    asm.inst(format_args!("movabs ${CHILD_STACK_VA:#x}, %rdx"));
    asm.inst(format_args!("mov {CTRL_STACK_VMO}(%rbx), %r10"));
    asm.inst("xor %r8, %r8");
    asm.inst("movabs $0x1000, %r9");
    asm.inst(format_args!("lea {CTRL_STACK_ADDR}(%rbx), %rax"));
    asm.inst("sub $8, %rsp");
    asm.inst("mov %rax, (%rsp)");
    asm.inst(format_args!("movabs ${AXLE_SYS_VMAR_MAP}, %rax"));
    asm.inst("int $0x80");
    asm.inst("add $8, %rsp");
    emit_setup_assert_ok(asm, 81);

    asm.inst(format_args!("mov 8*{}(%rbx), %rdi", SLOT_SELF_PROCESS_H));
    asm.inst("xor %rsi, %rsi");
    asm.inst("xor %rdx, %rdx");
    asm.inst("xor %r10d, %r10d");
    asm.inst(format_args!("lea {CTRL_CHILD_THREAD}(%rbx), %r8"));
    asm.inst(format_args!("movabs ${AXLE_SYS_THREAD_CREATE}, %rax"));
    asm.inst("int $0x80");
    emit_setup_assert_ok(asm, 82);

    asm.inst(format_args!("mov {CTRL_CHILD_THREAD}(%rbx), %rdi"));
    asm.inst("lea actor_b_entry(%rip), %rsi");
    asm.inst(format_args!("mov {CTRL_STACK_ADDR}(%rbx), %rdx"));
    asm.inst("add $0x1000, %rdx");
    asm.inst("xor %r10d, %r10d");
    asm.inst("xor %r8d, %r8d");
    asm.inst(format_args!("movabs ${AXLE_SYS_THREAD_START}, %rax"));
    asm.inst("int $0x80");
    emit_setup_assert_ok(asm, 83);
    Ok(())
}

fn emit_actor_run(asm: &mut AsmBuilder, seed: &ConcurrentSeed, actor: ActorAsm) -> Result<()> {
    asm.label(actor.run_label());
    let program = match actor {
        ActorAsm::A => &seed.program_a,
        ActorAsm::B => &seed.program_b,
    };
    for (index, op) in program.iter().copied().enumerate() {
        asm.label(&format!("{}_step_{index}", actor.run_label()));
        emit_turn_wait(asm, actor);
        match op {
            ProgramOp::Wait(op) => emit_wait_op(asm, seed, actor, op)?,
            ProgramOp::FutexFault(op) => emit_futex_fault_op(asm, seed, actor, op)?,
            ProgramOp::ChannelHandle(op) => emit_channel_handle_op(asm, seed, actor, op)?,
        }
    }
    asm.inst(format_args!("jmp {}", actor.done_label()));
    Ok(())
}

fn emit_actor_done(asm: &mut AsmBuilder, actor: ActorAsm) {
    asm.label(actor.done_label());
    let done_bit = match actor {
        ActorAsm::A => 1,
        ActorAsm::B => 2,
    };
    asm.inst(format_args!("orl ${done_bit}, {CTRL_DONE}(%rbx)"));
    emit_turn_yield(
        asm,
        match actor {
            ActorAsm::A => ActorAsm::B,
            ActorAsm::B => ActorAsm::A,
        },
    );
    match actor {
        ActorAsm::A => {
            asm.label("actor_a_wait_done");
            asm.inst(format_args!("mov {CTRL_DONE}(%rbx), %eax"));
            asm.inst("cmp $3, %eax");
            asm.inst("je actor_success");
            asm.inst(format_args!("lea {CTRL_DONE}(%rbx), %rdi"));
            asm.inst("mov %eax, %esi");
            asm.inst("xorl %edx, %edx");
            asm.inst(format_args!("movabs ${FOREVER_DEADLINE:#x}, %r10"));
            asm.inst(format_args!("movabs ${AXLE_SYS_FUTEX_WAIT}, %rax"));
            asm.inst("int $0x80");
            asm.inst("jmp actor_a_wait_done");
            asm.label("actor_success");
            asm.inst(format_args!("movq $1, 8*{SLOT_OK}(%rbx)"));
            asm.inst("int3");
        }
        ActorAsm::B => {
            asm.label("actor_b_sleep");
            asm.inst(format_args!("lea {CTRL_DONE}(%rbx), %rdi"));
            asm.inst(format_args!("mov {CTRL_DONE}(%rbx), %esi"));
            asm.inst("xorl %edx, %edx");
            asm.inst(format_args!("movabs ${FOREVER_DEADLINE:#x}, %r10"));
            asm.inst(format_args!("movabs ${AXLE_SYS_FUTEX_WAIT}, %rax"));
            asm.inst("int $0x80");
            asm.inst("jmp actor_b_sleep");
        }
    }
}

fn emit_actor_entry(asm: &mut AsmBuilder, seed: &ConcurrentSeed, actor: ActorAsm) -> Result<()> {
    if !matches!(actor, ActorAsm::B) {
        return Ok(());
    }
    asm.label("actor_b_entry");
    asm.inst(format_args!("movabs ${USER_SHARED_BASE:#x}, %rbx"));
    let program = &seed.program_b;
    for (index, op) in program.iter().copied().enumerate() {
        asm.label(&format!("actor_b_entry_step_{index}"));
        emit_turn_wait(asm, actor);
        match op {
            ProgramOp::Wait(op) => emit_wait_op(asm, seed, actor, op)?,
            ProgramOp::FutexFault(op) => emit_futex_fault_op(asm, seed, actor, op)?,
            ProgramOp::ChannelHandle(op) => emit_channel_handle_op(asm, seed, actor, op)?,
        }
    }
    asm.inst("jmp actor_b_done");
    Ok(())
}

fn emit_wait_op(
    asm: &mut AsmBuilder,
    seed: &ConcurrentSeed,
    actor: ActorAsm,
    op: WaitOp,
) -> Result<()> {
    match op {
        WaitOp::SetSignal { waitable, bits } => {
            let handle = waitable_handle_expr(waitable)?;
            asm.inst(format_args!("mov {handle}, %rdi"));
            asm.inst("xorl %esi, %esi");
            asm.inst(format_args!("movl ${:#x}, %edx", user_signal_mask(bits)));
            asm.inst(format_args!("movabs ${AXLE_SYS_OBJECT_SIGNAL}, %rax"));
            asm.inst("int $0x80");
            emit_turn_yield(
                asm,
                match actor {
                    ActorAsm::A => ActorAsm::B,
                    ActorAsm::B => ActorAsm::A,
                },
            );
        }
        WaitOp::ClearSignal { waitable, bits } => {
            let handle = waitable_handle_expr(waitable)?;
            asm.inst(format_args!("mov {handle}, %rdi"));
            asm.inst(format_args!("movl ${:#x}, %esi", user_signal_mask(bits)));
            asm.inst("xorl %edx, %edx");
            asm.inst(format_args!("movabs ${AXLE_SYS_OBJECT_SIGNAL}, %rax"));
            asm.inst("int $0x80");
            emit_turn_yield(asm, actor_other(actor));
        }
        WaitOp::WaitOne {
            waitable,
            bits,
            deadline_ticks,
        } => {
            emit_turn_yield(asm, actor_other(actor));
            let handle = waitable_handle_expr(waitable)?;
            asm.inst(format_args!("lea {SCRATCH_OBSERVED}(%rbx), %r10"));
            asm.inst("movq $0, 0(%r10)");
            asm.inst(format_args!("mov {handle}, %rdi"));
            asm.inst(format_args!("movl ${:#x}, %esi", wait_bits(waitable, bits)));
            emit_deadline(asm, "%rdx", deadline_ticks);
            asm.inst(format_args!("movabs ${AXLE_SYS_OBJECT_WAIT_ONE}, %rax"));
            asm.inst("int $0x80");
        }
        WaitOp::WaitAsync {
            waitable,
            key,
            bits,
            edge,
        } => {
            let handle = waitable_handle_expr(waitable)?;
            asm.inst(format_args!("mov {handle}, %rdi"));
            asm.inst(format_args!("mov {CTRL_PORT}(%rbx), %rsi"));
            asm.inst(format_args!("movabs ${key}, %rdx"));
            asm.inst(format_args!(
                "movl ${:#x}, %r10d",
                wait_bits(waitable, bits)
            ));
            asm.inst(format_args!(
                "movl ${}, %r8d",
                if edge { WAIT_ASYNC_EDGE } else { 0 }
            ));
            asm.inst(format_args!("movabs ${AXLE_SYS_OBJECT_WAIT_ASYNC}, %rax"));
            asm.inst("int $0x80");
            emit_turn_yield(asm, actor_other(actor));
        }
        WaitOp::PortWait { deadline_ticks } => {
            emit_turn_yield(asm, actor_other(actor));
            asm.inst(format_args!("mov {CTRL_PORT}(%rbx), %rdi"));
            emit_deadline(asm, "%rsi", deadline_ticks);
            asm.inst(format_args!("lea {SCRATCH_PACKET}(%rbx), %rdx"));
            asm.inst(format_args!("movabs ${AXLE_SYS_PORT_WAIT}, %rax"));
            asm.inst("int $0x80");
        }
        WaitOp::TimerSet {
            slot,
            deadline_ticks,
        } => {
            let timer = timer_handle_offset(slot)?;
            asm.inst(format_args!("mov {timer}(%rbx), %rdi"));
            asm.inst(format_args!("mov 8*{}(%rbx), %rsi", SLOT_T0_NS));
            asm.inst(format_args!("add {CTRL_CLOCK_CURSOR}(%rbx), %rsi"));
            asm.inst(format_args!(
                "add ${}, %rsi",
                u64::from(deadline_ticks) * TICK_NS
            ));
            asm.inst("xorl %edx, %edx");
            asm.inst(format_args!("movabs ${AXLE_SYS_TIMER_SET}, %rax"));
            asm.inst("int $0x80");
            emit_turn_yield(asm, actor_other(actor));
        }
        WaitOp::TimerCancel { slot } => {
            let timer = timer_handle_offset(slot)?;
            asm.inst(format_args!("mov {timer}(%rbx), %rdi"));
            asm.inst(format_args!("movabs ${AXLE_SYS_TIMER_CANCEL}, %rax"));
            asm.inst("int $0x80");
            emit_turn_yield(asm, actor_other(actor));
        }
        WaitOp::AdvanceTime { ticks } => {
            asm.inst(format_args!(
                "addq ${}, {CTRL_CLOCK_CURSOR}(%rbx)",
                u64::from(ticks) * TICK_NS
            ));
            emit_turn_yield(asm, actor_other(actor));
        }
    }
    if seed
        .hints
        .iter()
        .any(|hint| matches!(hint, SchedHint::YieldHere(HookId::SignalUpdatedBeforeWake)))
        && matches!(op, WaitOp::SetSignal { .. } | WaitOp::ClearSignal { .. })
    {
        emit_turn_yield(asm, actor_other(actor));
    }
    Ok(())
}

fn emit_futex_fault_op(
    asm: &mut AsmBuilder,
    seed: &ConcurrentSeed,
    actor: ActorAsm,
    op: FutexFaultOp,
) -> Result<()> {
    match op {
        FutexFaultOp::FutexStore { key, value } => {
            asm.inst(format_args!("mov {CTRL_FUTEX_ADDR}(%rbx), %rcx"));
            asm.inst(format_args!("movl ${value}, {}(%rcx)", u64::from(key) * 4));
            emit_turn_yield(asm, actor_other(actor));
        }
        FutexFaultOp::FutexWait {
            key,
            expected,
            deadline_ticks,
        } => {
            emit_turn_yield(asm, actor_other(actor));
            asm.inst(format_args!("mov {CTRL_FUTEX_ADDR}(%rbx), %rdi"));
            asm.inst(format_args!("add ${}, %rdi", u64::from(key) * 4));
            asm.inst(format_args!("movl ${expected}, %esi"));
            asm.inst("xorl %edx, %edx");
            emit_deadline(asm, "%r10", deadline_ticks);
            asm.inst(format_args!("movabs ${AXLE_SYS_FUTEX_WAIT}, %rax"));
            asm.inst("int $0x80");
        }
        FutexFaultOp::FutexWake { key, count } => {
            asm.inst(format_args!("mov {CTRL_FUTEX_ADDR}(%rbx), %rdi"));
            asm.inst(format_args!("add ${}, %rdi", u64::from(key) * 4));
            asm.inst(format_args!("movl ${count}, %esi"));
            asm.inst(format_args!("movabs ${AXLE_SYS_FUTEX_WAKE}, %rax"));
            asm.inst("int $0x80");
            emit_turn_yield(asm, actor_other(actor));
        }
        FutexFaultOp::FutexRequeue {
            source,
            target,
            wake_count,
            requeue_count,
        } => {
            asm.inst(format_args!("mov {CTRL_FUTEX_ADDR}(%rbx), %rdi"));
            asm.inst(format_args!("add ${}, %rdi", u64::from(source) * 4));
            asm.inst(format_args!("movl ${wake_count}, %esi"));
            asm.inst("xorl %edx, %edx");
            asm.inst(format_args!("mov {CTRL_FUTEX_ADDR}(%rbx), %r10"));
            asm.inst(format_args!("add ${}, %r10", u64::from(target) * 4));
            asm.inst(format_args!("movl ${requeue_count}, %r8d"));
            asm.inst("xorl %r9d, %r9d");
            asm.inst(format_args!("movabs ${AXLE_SYS_FUTEX_REQUEUE}, %rax"));
            asm.inst("int $0x80");
            emit_turn_yield(asm, actor_other(actor));
        }
        FutexFaultOp::Fault { key } => {
            if seed.hints.iter().any(|hint| {
                matches!(
                    hint,
                    SchedHint::YieldHere(HookId::FaultLeaderClaimed)
                        | SchedHint::PauseThread(HookId::FaultLeaderClaimed, _)
                        | SchedHint::YieldHere(HookId::FaultHeavyPrepareBeforeCommit)
                        | SchedHint::PauseThread(HookId::FaultHeavyPrepareBeforeCommit, _)
                        | SchedHint::YieldHere(HookId::FaultTxBeforeCommit)
                        | SchedHint::PauseThread(HookId::FaultTxBeforeCommit, _)
                )
            }) {
                asm.inst(format_args!(
                    "movq $1, 8*{}(%rbx)",
                    SLOT_VM_FAULT_TEST_HOOK_ARM
                ));
            }
            emit_turn_yield(asm, actor_other(actor));
            let addr = CTRL_FAULT_ADDR_BASE + u64::from(key) * 8;
            asm.inst(format_args!("mov {addr}(%rbx), %rcx"));
            asm.inst("mov (%rcx), %rax");
        }
        FutexFaultOp::AdvanceTime { ticks } => {
            asm.inst(format_args!(
                "addq ${}, {CTRL_CLOCK_CURSOR}(%rbx)",
                u64::from(ticks) * TICK_NS
            ));
            emit_turn_yield(asm, actor_other(actor));
        }
    }
    Ok(())
}

fn emit_channel_handle_op(
    asm: &mut AsmBuilder,
    seed: &ConcurrentSeed,
    actor: ActorAsm,
    op: ChannelHandleOp,
) -> Result<()> {
    match op {
        ChannelHandleOp::ChannelWrite { handle, bytes } => {
            emit_fill_bytes(asm, SCRATCH_TX, bytes);
            asm.inst(format_args!(
                "mov {}(%rbx), %rdi",
                handle_slot_offset(handle)
            ));
            asm.inst("xorl %esi, %esi");
            asm.inst(format_args!("lea {SCRATCH_TX}(%rbx), %rdx"));
            asm.inst(format_args!("movl ${bytes}, %r10d"));
            asm.inst("xorl %r8d, %r8d");
            asm.inst("xorl %r9d, %r9d");
            asm.inst(format_args!("movabs ${AXLE_SYS_CHANNEL_WRITE}, %rax"));
            asm.inst("int $0x80");
            emit_turn_yield(asm, actor_other(actor));
        }
        ChannelHandleOp::ChannelRead { handle } => {
            asm.inst("movq $0, 0x1500(%rbx)");
            asm.inst("movq $0, 0x1508(%rbx)");
            asm.inst(format_args!(
                "mov {}(%rbx), %rdi",
                handle_slot_offset(handle)
            ));
            asm.inst("xorl %esi, %esi");
            asm.inst(format_args!("lea {SCRATCH_RX}(%rbx), %rdx"));
            asm.inst("xorl %r10d, %r10d");
            asm.inst("movl $16, %r8d");
            asm.inst("xorl %r9d, %r9d");
            asm.inst(format_args!("lea {SCRATCH_ACTUAL_BYTES}(%rbx), %rax"));
            asm.inst(format_args!("lea {SCRATCH_ACTUAL_HANDLES}(%rbx), %rcx"));
            asm.inst("sub $16, %rsp");
            asm.inst("mov %rax, 0(%rsp)");
            asm.inst("mov %rcx, 8(%rsp)");
            asm.inst(format_args!("movabs ${AXLE_SYS_CHANNEL_READ}, %rax"));
            asm.inst("int $0x80");
            asm.inst("add $16, %rsp");
            emit_turn_yield(asm, actor_other(actor));
        }
        ChannelHandleOp::ChannelClose { handle } => {
            if seed.hints.iter().any(|hint| {
                matches!(
                    hint,
                    SchedHint::YieldHere(HookId::ChannelCloseBeforeReadDrain)
                )
            }) {
                emit_turn_yield(asm, actor_other(actor));
                emit_turn_wait(asm, actor);
            }
            asm.inst(format_args!(
                "mov {}(%rbx), %rdi",
                handle_slot_offset(handle)
            ));
            asm.inst(format_args!("movabs ${AXLE_SYS_HANDLE_CLOSE}, %rax"));
            asm.inst("int $0x80");
            asm.inst(format_args!(
                "movq $0, {}(%rbx)",
                handle_slot_offset(handle)
            ));
            emit_turn_yield(asm, actor_other(actor));
        }
        ChannelHandleOp::WaitReadable {
            handle,
            deadline_ticks,
        } => {
            emit_turn_yield(asm, actor_other(actor));
            asm.inst(format_args!("lea {SCRATCH_OBSERVED}(%rbx), %r10"));
            asm.inst("movq $0, 0(%r10)");
            asm.inst(format_args!(
                "mov {}(%rbx), %rdi",
                handle_slot_offset(handle)
            ));
            asm.inst(format_args!("movl ${SIG_READABLE:#x}, %esi"));
            emit_deadline(asm, "%rdx", deadline_ticks);
            asm.inst(format_args!("movabs ${AXLE_SYS_OBJECT_WAIT_ONE}, %rax"));
            asm.inst("int $0x80");
        }
        ChannelHandleOp::WaitPeerClosed {
            handle,
            deadline_ticks,
        } => {
            emit_turn_yield(asm, actor_other(actor));
            asm.inst(format_args!("lea {SCRATCH_OBSERVED}(%rbx), %r10"));
            asm.inst("movq $0, 0(%r10)");
            asm.inst(format_args!(
                "mov {}(%rbx), %rdi",
                handle_slot_offset(handle)
            ));
            asm.inst(format_args!("movl ${SIG_PEER_CLOSED:#x}, %esi"));
            emit_deadline(asm, "%rdx", deadline_ticks);
            asm.inst(format_args!("movabs ${AXLE_SYS_OBJECT_WAIT_ONE}, %rax"));
            asm.inst("int $0x80");
        }
        ChannelHandleOp::HandleDuplicate { handle, dst } => {
            asm.inst(format_args!(
                "mov {}(%rbx), %rdi",
                handle_slot_offset(handle)
            ));
            asm.inst(format_args!("movl ${ZX_RIGHT_SAME_RIGHTS:#x}, %esi"));
            asm.inst(format_args!("lea {}(%rbx), %rdx", handle_slot_offset(dst)));
            asm.inst(format_args!("movabs ${AXLE_SYS_HANDLE_DUPLICATE}, %rax"));
            asm.inst("int $0x80");
            emit_turn_yield(asm, actor_other(actor));
        }
        ChannelHandleOp::HandleReplace { handle, dst } => {
            if seed.hints.iter().any(|hint| {
                matches!(
                    hint,
                    SchedHint::PauseThread(HookId::HandleReplaceBeforePublish, _)
                        | SchedHint::YieldHere(HookId::HandleReplaceBeforePublish)
                )
            }) {
                emit_turn_yield(asm, actor_other(actor));
                emit_turn_wait(asm, actor);
            }
            asm.inst(format_args!(
                "mov {}(%rbx), %rdi",
                handle_slot_offset(handle)
            ));
            asm.inst(format_args!("movl ${ZX_RIGHT_SAME_RIGHTS:#x}, %esi"));
            asm.inst(format_args!("lea {}(%rbx), %rdx", handle_slot_offset(dst)));
            asm.inst(format_args!("movabs ${AXLE_SYS_HANDLE_REPLACE}, %rax"));
            asm.inst("int $0x80");
            asm.inst(format_args!(
                "movq $0, {}(%rbx)",
                handle_slot_offset(handle)
            ));
            emit_turn_yield(asm, actor_other(actor));
        }
    }
    Ok(())
}

fn emit_fill_bytes(asm: &mut AsmBuilder, offset: u64, bytes: u8) {
    let qwords = usize::from(bytes).div_ceil(8);
    for index in 0..qwords {
        let value =
            0x1111_0000_0000_0000_u64 ^ ((offset + (index as u64) * 8) << 8) ^ u64::from(bytes);
        asm.inst(format_args!("movabs ${value:#x}, %rax"));
        asm.inst(format_args!(
            "mov %rax, {}(%rbx)",
            offset + (index as u64) * 8
        ));
    }
}

fn emit_common_helpers(asm: &mut AsmBuilder) {
    emit_wait_turn_helper(asm, ActorAsm::A);
    emit_wait_turn_helper(asm, ActorAsm::B);
    emit_yield_helper(asm, ActorAsm::A);
    emit_yield_helper(asm, ActorAsm::B);
}

fn emit_wait_turn_helper(asm: &mut AsmBuilder, actor: ActorAsm) {
    asm.label(actor.wait_turn_label());
    asm.label(&format!("{}_loop", actor.wait_turn_label()));
    asm.inst(format_args!("mov {CTRL_TURN}(%rbx), %eax"));
    asm.inst(format_args!("cmp ${}, %eax", actor.id()));
    asm.inst(format_args!("je {}_done", actor.wait_turn_label()));
    asm.inst(format_args!("lea {CTRL_TURN}(%rbx), %rdi"));
    asm.inst("mov %eax, %esi");
    asm.inst("xorl %edx, %edx");
    asm.inst(format_args!("movabs ${FOREVER_DEADLINE:#x}, %r10"));
    asm.inst(format_args!("movabs ${AXLE_SYS_FUTEX_WAIT}, %rax"));
    asm.inst("int $0x80");
    asm.inst(format_args!("jmp {}_loop", actor.wait_turn_label()));
    asm.label(&format!("{}_done", actor.wait_turn_label()));
    asm.inst("ret");
}

fn emit_yield_helper(asm: &mut AsmBuilder, actor: ActorAsm) {
    asm.label(actor.yield_label());
    asm.inst(format_args!("movl ${}, {CTRL_TURN}(%rbx)", actor.id()));
    asm.inst(format_args!("lea {CTRL_TURN}(%rbx), %rdi"));
    asm.inst("movl $1, %esi");
    asm.inst(format_args!("movabs ${AXLE_SYS_FUTEX_WAKE}, %rax"));
    asm.inst("int $0x80");
    asm.inst("ret");
}

fn waitable_handle_expr(waitable: u8) -> Result<String> {
    if waitable >= 16 {
        return match waitable - 16 {
            0 => Ok(format!("{CTRL_TIMER0}(%rbx)")),
            1 => Ok(format!("{CTRL_TIMER1}(%rbx)")),
            _ => bail!("unsupported timer waitable id {waitable}"),
        };
    }
    let slot = u64::from(waitable % 4);
    Ok(format!("{}(%rbx)", CTRL_EVENT_BASE + slot * 16))
}

fn wait_bits(waitable: u8, bits: u8) -> u32 {
    if waitable >= 16 {
        return SIG_TIMER_SIGNALED;
    }
    user_signal_mask(bits)
}

fn user_signal_mask(bits: u8) -> u32 {
    u32::from(bits) << 24
}

fn timer_handle_offset(slot: u8) -> Result<u64> {
    match slot % 2 {
        0 => Ok(CTRL_TIMER0),
        1 => Ok(CTRL_TIMER1),
        _ => bail!("unsupported timer slot"),
    }
}

fn handle_slot_offset(slot: u8) -> u64 {
    CTRL_CHANNEL_BASE + u64::from(slot % 4) * 8
}

fn actor_other(actor: ActorAsm) -> ActorAsm {
    match actor {
        ActorAsm::A => ActorAsm::B,
        ActorAsm::B => ActorAsm::A,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::ConcurrentSeed;

    #[test]
    fn renders_wait_seed_runner() {
        let seed = ConcurrentSeed::base_corpus(32).remove(0);
        let asm = render_guest_runner(&seed).expect("render wait seed");
        assert!(asm.contains("axle_user_prog_start"));
        assert!(asm.contains("actor_b_entry"));
        assert!(asm.contains("wait_turn_a"));
    }

    #[test]
    fn renders_channel_seed_runner() {
        let seed = ConcurrentSeed::base_corpus(32).remove(4);
        let asm = render_guest_runner(&seed).expect("render channel seed");
        assert!(asm.contains("movabs $13, %rax"));
        assert!(asm.contains("movabs $14, %rax"));
        assert!(asm.contains("movabs $1, %rax"));
    }
}
