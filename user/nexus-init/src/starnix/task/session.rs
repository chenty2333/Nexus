use super::super::*;

impl StarnixKernel {
    pub(in crate::starnix) fn task_sid(&self, task_id: i32) -> Result<i32, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        self.groups
            .get(&tgid)
            .map(|group| group.sid)
            .ok_or(ZX_ERR_BAD_STATE)
    }

    pub(in crate::starnix) fn session_has_pgid(&self, sid: i32, pgid: i32) -> bool {
        self.groups
            .values()
            .any(|group| group.sid == sid && group.pgid == pgid)
    }

    pub(in crate::starnix) fn foreground_pgid(&self, sid: i32) -> Option<i32> {
        self.foreground_pgid_by_sid.get(&sid).copied()
    }

    pub(in crate::starnix) fn refresh_session_foreground_pgid(&mut self, sid: i32) {
        let current = self.foreground_pgid_by_sid.get(&sid).copied();
        if current.is_some_and(|pgid| self.session_has_pgid(sid, pgid)) {
            return;
        }
        let replacement = self
            .groups
            .values()
            .find(|group| group.sid == sid)
            .map(|group| group.pgid);
        match replacement {
            Some(pgid) => {
                self.foreground_pgid_by_sid.insert(sid, pgid);
            }
            None => {
                let _ = self.foreground_pgid_by_sid.remove(&sid);
            }
        }
    }

    pub(in crate::starnix) fn sys_getsid(
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
                .map(|group| group.sid as u64)
                .ok_or(ZX_ERR_NOT_FOUND)
                .unwrap_or_else(|_| linux_errno(LINUX_ESRCH)),
            Err(ZX_ERR_INVALID_ARGS) => linux_errno(LINUX_EINVAL),
            Err(_) => linux_errno(LINUX_ESRCH),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_setsid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let result = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            if group.pgid == tgid {
                linux_errno(LINUX_EPERM)
            } else {
                group.sid = tgid;
                group.pgid = tgid;
                if let Some(resources) = group.resources.as_mut() {
                    resources.fs.set_controlling_tty(None);
                }
                tgid as u64
            }
        };
        if result == tgid as u64 {
            self.foreground_pgid_by_sid.insert(tgid, tgid);
        }
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }
}
