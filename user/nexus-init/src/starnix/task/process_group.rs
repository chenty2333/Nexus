use super::super::*;

impl StarnixKernel {
    pub(in crate::starnix) fn target_tgid_for_pid_arg(
        &self,
        caller_tgid: i32,
        pid: i32,
    ) -> Result<i32, zx_status_t> {
        if pid == 0 {
            return Ok(caller_tgid);
        }
        if pid < 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        if self.groups.contains_key(&pid) {
            Ok(pid)
        } else {
            Err(ZX_ERR_NOT_FOUND)
        }
    }

    pub(in crate::starnix) fn task_pgid(&self, task_id: i32) -> Result<i32, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        self.groups
            .get(&tgid)
            .map(|group| group.pgid)
            .ok_or(ZX_ERR_BAD_STATE)
    }

    pub(in crate::starnix) fn sys_getpgrp(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let pgid = self.task_pgid(task_id)?;
        complete_syscall(stop_state, pgid as u64)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_getpgid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let caller_tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let pid = stop_state.regs.rdi as u32 as i32;
        let result = match self.target_tgid_for_pid_arg(caller_tgid, pid) {
            Ok(target_tgid) => self
                .groups
                .get(&target_tgid)
                .map(|group| group.pgid as u64)
                .ok_or(ZX_ERR_NOT_FOUND)
                .unwrap_or_else(|_| linux_errno(LINUX_ESRCH)),
            Err(ZX_ERR_INVALID_ARGS) => linux_errno(LINUX_EINVAL),
            Err(_) => linux_errno(LINUX_ESRCH),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_setpgid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let caller_tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let caller_sid = self.task_sid(task_id)?;
        let pid = stop_state.regs.rdi as u32 as i32;
        let pgid = stop_state.regs.rsi as u32 as i32;
        let target_tgid = if pid == 0 { caller_tgid } else { pid };
        let new_pgid = if pgid == 0 { target_tgid } else { pgid };
        let result = if target_tgid <= 0 || new_pgid <= 0 {
            linux_errno(LINUX_EINVAL)
        } else {
            let target_group = match self.groups.get(&target_tgid) {
                Some(group) => group,
                None => {
                    complete_syscall(stop_state, linux_errno(LINUX_ESRCH))?;
                    return Ok(SyscallAction::Resume);
                }
            };
            if target_group.sid != caller_sid {
                linux_errno(LINUX_EPERM)
            } else if matches!(target_group.state, ThreadGroupState::Zombie { .. })
                || (target_tgid != caller_tgid && target_group.parent_tgid != Some(caller_tgid))
            {
                linux_errno(LINUX_ESRCH)
            } else if target_group.sid == target_tgid
                || (new_pgid != target_tgid && !self.session_has_pgid(caller_sid, new_pgid))
            {
                linux_errno(LINUX_EPERM)
            } else {
                self.groups
                    .get_mut(&target_tgid)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .pgid = new_pgid;
                self.refresh_session_foreground_pgid(caller_sid);
                0
            }
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }
}
