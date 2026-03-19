use super::super::*;

impl StarnixKernel {
    pub(in crate::starnix) fn sys_getpid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        complete_syscall(stop_state, tgid as u64)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_getppid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let parent_tgid = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .parent_tgid
            .unwrap_or(0);
        complete_syscall(stop_state, parent_tgid as u64)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_getuid(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_getgid(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_geteuid(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_getegid(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_gettid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        complete_syscall(stop_state, task_id as u64)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_arch_prctl(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let code = stop_state.regs.rdi;
        let addr = stop_state.regs.rsi;
        let thread_handle = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .thread_handle;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;

        let result = match code {
            LINUX_ARCH_SET_FS => {
                match zx_status_result(ax_thread_set_guest_x64_fs_base(thread_handle, addr, 0)) {
                    Ok(()) => 0,
                    Err(status) => linux_errno(map_guest_start_status_to_errno(status)),
                }
            }
            LINUX_ARCH_GET_FS => {
                let mut fs_base = 0u64;
                match zx_status_result(ax_thread_get_guest_x64_fs_base(
                    thread_handle,
                    0,
                    &mut fs_base,
                )) {
                    Ok(()) => match write_guest_u64(session, addr, fs_base) {
                        Ok(()) => 0,
                        Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
                    },
                    Err(status) => linux_errno(map_guest_start_status_to_errno(status)),
                }
            }
            LINUX_ARCH_SET_GS | LINUX_ARCH_GET_GS => linux_errno(LINUX_EINVAL),
            _ => linux_errno(LINUX_EINVAL),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_set_tid_address(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let clear_child_tid = stop_state.regs.rdi;
        self.tasks
            .get_mut(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .clear_child_tid = clear_child_tid;
        complete_syscall(stop_state, task_id as u64)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_prlimit64(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let pid = linux_arg_i32(stop_state.regs.rdi);
        let resource = linux_arg_i32(stop_state.regs.rsi);
        let new_limit_addr = stop_state.regs.rdx;
        let old_limit_addr = stop_state.regs.r10;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let result = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            resources.prlimit64(session, tgid, pid, resource, new_limit_addr, old_limit_addr)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }
}
