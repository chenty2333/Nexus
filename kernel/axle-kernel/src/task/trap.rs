use super::runtime::ProcessState;
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrapExitDisposition {
    Complete,
    BlockCurrent,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UserContext {
    trap: crate::arch::int80::TrapFrame,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
}

impl UserContext {
    fn capture(
        trap: &crate::arch::int80::TrapFrame,
        cpu_frame: *const u64,
    ) -> Result<Self, zx_status_t> {
        if cpu_frame.is_null() {
            return Err(ZX_ERR_BAD_STATE);
        }
        // SAFETY: `cpu_frame` points to the saved user IRET frame created by the CPU on a
        // ring3->ring0 transition. The int80 entry path always provides RIP/CS/RFLAGS/RSP/SS.
        let (rip, cs, rflags, rsp, ss) = unsafe {
            (
                *cpu_frame.add(0),
                *cpu_frame.add(1),
                *cpu_frame.add(2),
                *cpu_frame.add(3),
                *cpu_frame.add(4),
            )
        };
        Ok(Self {
            trap: *trap,
            rip,
            cs,
            rflags,
            rsp,
            ss,
            fs_base: crate::arch::user_tls::read_fs_base(),
        })
    }

    pub(super) fn restore(
        self,
        trap: &mut crate::arch::int80::TrapFrame,
        cpu_frame: *mut u64,
    ) -> Result<(), zx_status_t> {
        if cpu_frame.is_null() {
            return Err(ZX_ERR_BAD_STATE);
        }
        *trap = self.trap;
        // SAFETY: `cpu_frame` points to the mutable IRET frame for the in-flight trap return.
        unsafe {
            *cpu_frame.add(0) = self.rip;
            *cpu_frame.add(1) = self.cs;
            *cpu_frame.add(2) = self.rflags;
            *cpu_frame.add(3) = self.rsp;
            *cpu_frame.add(4) = self.ss;
        }
        crate::arch::user_tls::write_fs_base(self.fs_base);
        Ok(())
    }

    pub(super) fn with_status(mut self, status: zx_status_t) -> Self {
        self.trap.set_status(status);
        self
    }

    pub(crate) fn to_guest_x64_regs(self) -> ax_guest_x64_regs_t {
        ax_guest_x64_regs_t {
            rax: self.trap.rax,
            rdi: self.trap.rdi,
            rsi: self.trap.rsi,
            rdx: self.trap.rdx,
            r10: self.trap.r10,
            r8: self.trap.r8,
            r9: self.trap.r9,
            rcx: self.trap.rcx,
            r11: self.trap.r11,
            rbx: self.trap.rbx,
            rbp: self.trap.rbp,
            r12: self.trap.r12,
            r13: self.trap.r13,
            r14: self.trap.r14,
            r15: self.trap.r15,
            rip: self.rip,
            rsp: self.rsp,
            rflags: self.rflags,
        }
    }

    pub(crate) fn with_guest_x64_regs(mut self, regs: ax_guest_x64_regs_t) -> Self {
        self.trap.rax = regs.rax;
        self.trap.rdi = regs.rdi;
        self.trap.rsi = regs.rsi;
        self.trap.rdx = regs.rdx;
        self.trap.r10 = regs.r10;
        self.trap.r8 = regs.r8;
        self.trap.r9 = regs.r9;
        self.trap.rcx = regs.rcx;
        self.trap.r11 = regs.r11;
        self.trap.rbx = regs.rbx;
        self.trap.rbp = regs.rbp;
        self.trap.r12 = regs.r12;
        self.trap.r13 = regs.r13;
        self.trap.r14 = regs.r14;
        self.trap.r15 = regs.r15;
        self.rip = regs.rip;
        self.rsp = regs.rsp;
        self.rflags = regs.rflags;
        self
    }

    pub(super) fn with_fs_base(mut self, fs_base: u64) -> Self {
        self.fs_base = fs_base;
        self
    }

    pub(super) fn new_user_entry(entry: u64, stack: u64, arg0: u64, arg1: u64) -> Self {
        let selectors = crate::arch::gdt::init();
        let mut trap = crate::arch::int80::TrapFrame::default();
        trap.rdi = arg0;
        trap.rsi = arg1;
        Self {
            trap,
            rip: entry,
            cs: selectors.user_code.0 as u64,
            rflags: 0x202,
            rsp: stack,
            ss: selectors.user_data.0 as u64,
            fs_base: 0,
        }
    }

    #[inline(never)]
    pub(crate) fn enter(self) -> ! {
        use x86_64::instructions::segmentation::{DS, ES, Segment};

        let selectors = crate::arch::gdt::init();
        // SAFETY: Axle installs the user data selector in the current GDT before entering ring3.
        unsafe {
            DS::set_reg(selectors.user_data);
            ES::set_reg(selectors.user_data);
        }

        // SAFETY: `UserContext` stores a complete ring3 register and IRET frame snapshot. The
        // entry helper restores those registers verbatim and finishes with `iretq`.
        crate::arch::user_tls::write_fs_base(self.fs_base);
        unsafe {
            axle_enter_user_context(core::ptr::addr_of!(self));
        }
    }
}

core::arch::global_asm!(
    r#"
    .global axle_enter_user_context
    .type axle_enter_user_context, @function
axle_enter_user_context:
    push QWORD PTR [rdi + 152]
    push QWORD PTR [rdi + 144]
    push QWORD PTR [rdi + 136]
    push QWORD PTR [rdi + 128]
    push QWORD PTR [rdi + 120]

    mov rax, [rdi + 0]
    mov rsi, [rdi + 16]
    mov rdx, [rdi + 24]
    mov r10, [rdi + 32]
    mov r8, [rdi + 40]
    mov r9, [rdi + 48]
    mov rcx, [rdi + 56]
    mov r11, [rdi + 64]
    mov rbp, [rdi + 72]
    mov rbx, [rdi + 80]
    mov r12, [rdi + 88]
    mov r13, [rdi + 96]
    mov r14, [rdi + 104]
    mov r15, [rdi + 112]
    mov rdi, [rdi + 8]
    iretq
    .size axle_enter_user_context, .-axle_enter_user_context
    "#
);

unsafe extern "C" {
    fn axle_enter_user_context(context: *const UserContext) -> !;
}

impl Kernel {
    pub(crate) fn current_thread_guest_x64_regs(
        &self,
    ) -> Result<axle_types::ax_guest_x64_regs_t, zx_status_t> {
        Ok(self
            .current_thread()?
            .context
            .ok_or(ZX_ERR_BAD_STATE)?
            .to_guest_x64_regs())
    }

    pub(crate) fn capture_current_user_context(
        &mut self,
        trap: &crate::arch::int80::TrapFrame,
        cpu_frame: *const u64,
    ) -> Result<(), zx_status_t> {
        let context = UserContext::capture(trap, cpu_frame)?;
        let current_thread_id = self.current_thread_id()?;
        let thread = self
            .threads
            .get_mut(&current_thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        crate::arch::fpu::save_current(&mut thread.fpu_state);
        thread.guest_fs_base = context.fs_base;
        thread.context = Some(context);
        Ok(())
    }

    pub(crate) fn thread_user_context(
        &self,
        thread_id: ThreadId,
    ) -> Result<UserContext, zx_status_t> {
        self.threads
            .get(&thread_id)
            .and_then(|thread| thread.context)
            .ok_or(ZX_ERR_BAD_STATE)
    }

    pub(crate) fn replace_thread_guest_context(
        &mut self,
        thread_id: ThreadId,
        regs: &ax_guest_x64_regs_t,
    ) -> Result<(), zx_status_t> {
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        let Some(context) = thread.context else {
            return Err(ZX_ERR_BAD_STATE);
        };
        thread.context = Some(context.with_guest_x64_regs(*regs));
        Ok(())
    }

    pub(crate) fn set_thread_guest_fs_base(
        &mut self,
        thread_id: ThreadId,
        fs_base: u64,
    ) -> Result<(), zx_status_t> {
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        thread.guest_fs_base = fs_base;
        if let Some(context) = thread.context {
            thread.context = Some(context.with_fs_base(fs_base));
        }
        Ok(())
    }

    pub(crate) fn thread_guest_fs_base(&self, thread_id: ThreadId) -> Result<u64, zx_status_t> {
        Ok(self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .guest_fs_base)
    }

    pub(crate) fn thread_uses_guest_syscall_stop(
        &self,
        thread_id: ThreadId,
    ) -> Result<bool, zx_status_t> {
        Ok(self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .guest_started)
    }

    fn validate_thread_guest_start_regs(
        &self,
        process_id: ProcessId,
        regs: &ax_guest_x64_regs_t,
    ) -> Result<(), zx_status_t> {
        let stack_probe = regs.rsp.checked_sub(8).ok_or(ZX_ERR_INVALID_ARGS)?;
        let entry_ok = self.validate_process_user_mapping_perms(
            process_id,
            regs.rip,
            1,
            MappingPerms::READ | MappingPerms::EXECUTE | MappingPerms::USER,
        );
        let stack_ok = self.validate_process_user_mapping_perms(
            process_id,
            stack_probe,
            8,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
        );
        if !entry_ok || !stack_ok {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        Ok(())
    }

    pub(crate) fn start_thread_guest(
        &mut self,
        thread_id: ThreadId,
        regs: &ax_guest_x64_regs_t,
        allow_idle_spill: bool,
    ) -> Result<(), zx_status_t> {
        let process_id = self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .process_id;
        let process = self.process(process_id)?;
        if process.state != ProcessState::Started {
            return Err(ZX_ERR_BAD_STATE);
        }
        self.validate_thread_guest_start_regs(process_id, regs)?;
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        if !matches!(thread.state, ThreadState::New) {
            return Err(ZX_ERR_BAD_STATE);
        }
        thread.guest_started = true;
        thread.context = Some(
            UserContext::new_user_entry(regs.rip, regs.rsp, 0, 0)
                .with_guest_x64_regs(*regs)
                .with_fs_base(thread.guest_fs_base),
        );
        thread.state = ThreadState::Runnable;
        let queued = thread.queued_on_cpu.is_some();
        let thread_id_copy = thread_id;
        let _ = thread;
        if !queued {
            let target_cpu =
                self.choose_start_cpu(thread_id_copy, StartPlacementPolicy::PreserveAffinity);
            if target_cpu != self.current_cpu_id() {
                crate::trace::record_remote_wake(thread_id_copy, target_cpu);
            }
            self.enqueue_runnable_thread_on_cpu(thread_id_copy, target_cpu)?;
            self.request_reschedule_on_cpu(target_cpu);
            if allow_idle_spill {
                self.maybe_nudge_idle_stealer(target_cpu);
            }
        }
        Ok(())
    }

    pub(crate) fn start_process_guest(
        &mut self,
        process_id: ProcessId,
        thread_id: ThreadId,
        regs: &ax_guest_x64_regs_t,
    ) -> Result<(), zx_status_t> {
        let thread_process_id = self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .process_id;
        if thread_process_id != process_id {
            return Err(ZX_ERR_BAD_STATE);
        }
        self.validate_thread_guest_start_regs(process_id, regs)?;
        let process = self
            .processes
            .get_mut(&process_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?;
        if process.state != ProcessState::Created {
            return Err(ZX_ERR_BAD_STATE);
        }
        process.state = ProcessState::Started;
        let result = self.start_thread_guest(thread_id, regs, true);
        if result.is_err() {
            let process = self
                .processes
                .get_mut(&process_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            process.state = ProcessState::Created;
        }
        result
    }

    fn restore_current_user_context(
        &mut self,
        trap: &mut crate::arch::int80::TrapFrame,
        cpu_frame: *mut u64,
    ) -> Result<(), zx_status_t> {
        let current_thread_id = self.current_thread_id()?;
        let thread = self
            .threads
            .get(&current_thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        crate::arch::fpu::restore_current(&thread.fpu_state);
        let context = thread.context.ok_or(ZX_ERR_BAD_STATE)?;
        context.restore(trap, cpu_frame)
    }

    pub(crate) fn finish_trap_exit(
        &mut self,
        trap: &mut crate::arch::int80::TrapFrame,
        cpu_frame: *mut u64,
        resuming_blocked_current: bool,
    ) -> Result<TrapExitDisposition, zx_status_t> {
        let current_cpu_id = self.current_cpu_id();
        let now = self.current_cpu_now_ns();
        if !resuming_blocked_current {
            self.account_current_runtime_until(now)?;
        }
        if resuming_blocked_current && self.current_thread_id().is_err() {
            if let Some(next_thread_id) = self.pop_runnable_thread() {
                self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                self.sync_current_cpu_tlb_state()?;
                return Ok(TrapExitDisposition::Complete);
            }
            return Ok(TrapExitDisposition::BlockCurrent);
        }
        match self.current_thread()?.state {
            ThreadState::Runnable => {
                if resuming_blocked_current {
                    let current_cpu_id = self.current_cpu_id();
                    let now_ns = now.max(0) as u64;
                    let current_thread_id = self.current_thread_id()?;
                    if let Some(thread) = self.threads.get_mut(&current_thread_id) {
                        if let (Some(enqueued_ns), Some(source_cpu_id), Some(target_cpu_id)) = (
                            thread.remote_wake_enqueued_ns,
                            thread.remote_wake_source_cpu,
                            thread.remote_wake_target_cpu,
                        ) {
                            if target_cpu_id == current_cpu_id {
                                crate::trace::record_remote_wake_latency(
                                    current_thread_id,
                                    source_cpu_id,
                                    target_cpu_id,
                                    now_ns.saturating_sub(enqueued_ns),
                                );
                            }
                        }
                        thread.remote_wake_enqueued_ns = None;
                        thread.remote_wake_source_cpu = None;
                        thread.remote_wake_target_cpu = None;
                    }
                    self.restore_current_user_context(trap, cpu_frame)?;
                    self.arm_current_slice_from(now);
                } else {
                    self.capture_current_user_context(trap, cpu_frame.cast_const())?;
                }
                if !resuming_blocked_current && self.take_reschedule_requested(current_cpu_id) {
                    if let Some(next_thread_id) = self.pop_runnable_thread() {
                        self.requeue_current_thread()?;
                        self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                    }
                }
                self.sync_current_cpu_tlb_state()?;
                Ok(TrapExitDisposition::Complete)
            }
            ThreadState::New => Err(ZX_ERR_BAD_STATE),
            ThreadState::TerminationPending => {
                let thread_id = self.current_thread_id()?;
                self.clear_current_slice_state();
                self.finalize_thread_termination(thread_id)?;
                if let Some(next_thread_id) = self.pop_runnable_thread() {
                    self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                    Ok(TrapExitDisposition::Complete)
                } else {
                    self.clear_current_thread_slot();
                    Ok(TrapExitDisposition::BlockCurrent)
                }
            }
            ThreadState::Suspended => {
                self.clear_current_slice_state();
                if let Some(next_thread_id) = self.pop_runnable_thread() {
                    self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                    Ok(TrapExitDisposition::Complete)
                } else {
                    self.clear_current_thread_slot();
                    Ok(TrapExitDisposition::BlockCurrent)
                }
            }
            ThreadState::Terminated => {
                self.clear_current_slice_state();
                if let Some(next_thread_id) = self.pop_runnable_thread() {
                    self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                    Ok(TrapExitDisposition::Complete)
                } else {
                    self.clear_current_thread_slot();
                    Ok(TrapExitDisposition::BlockCurrent)
                }
            }
            ThreadState::Blocked { .. } => {
                if !resuming_blocked_current {
                    self.capture_current_user_context(trap, cpu_frame.cast_const())?;
                }
                self.clear_current_slice_state();
                if let Some(next_thread_id) = self.pop_runnable_thread() {
                    self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                    Ok(TrapExitDisposition::Complete)
                } else {
                    Ok(TrapExitDisposition::BlockCurrent)
                }
            }
        }
    }
}
