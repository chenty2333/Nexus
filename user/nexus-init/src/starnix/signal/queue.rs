use super::super::*;

impl StarnixKernel {
    pub(in crate::starnix) fn shared_sigchld_info(&self, tgid: i32) -> Option<LinuxSigChldInfo> {
        self.groups.get(&tgid).and_then(|group| group.sigchld_info)
    }

    pub(in crate::starnix) fn clear_shared_signal_state(
        &mut self,
        tgid: i32,
        signal: i32,
    ) -> Result<(), zx_status_t> {
        if signal == LINUX_SIGCHLD
            && let Some(group) = self.groups.get_mut(&tgid)
        {
            group.sigchld_info = None;
        }
        Ok(())
    }

    pub(in crate::starnix) fn queue_sigchld_to_parent(
        &mut self,
        child_tgid: i32,
        info: LinuxSigChldInfo,
    ) -> Result<(), zx_status_t> {
        let Some(parent_tgid) = self
            .groups
            .get(&child_tgid)
            .and_then(|group| group.parent_tgid)
        else {
            return Ok(());
        };
        let bit = linux_signal_bit(LINUX_SIGCHLD).ok_or(ZX_ERR_INVALID_ARGS)?;
        let Some(parent) = self.groups.get_mut(&parent_tgid) else {
            return Ok(());
        };
        if matches!(parent.state, ThreadGroupState::Zombie { .. }) {
            return Ok(());
        }
        parent.shared_pending |= bit;
        parent.sigchld_info = Some(info);
        self.refresh_signalfds_for_group(parent_tgid)
    }

    pub(in crate::starnix) fn clear_job_control_pending(
        &mut self,
        tgid: i32,
    ) -> Result<(), zx_status_t> {
        let mask = job_control_signal_mask();
        if let Some(group) = self.groups.get_mut(&tgid) {
            group.shared_pending &= !mask;
        }
        let task_ids = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .task_ids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        for task_id in task_ids {
            if let Some(task) = self.tasks.get_mut(&task_id) {
                task.signals.pending &= !mask;
            }
        }
        Ok(())
    }

    pub(in crate::starnix) fn enter_group_stop(
        &mut self,
        tgid: i32,
        signal: i32,
    ) -> Result<(), zx_status_t> {
        {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            if matches!(group.state, ThreadGroupState::Zombie { .. }) {
                return Ok(());
            }
            group.state = ThreadGroupState::Stopped;
            group.last_stop_signal = Some(signal);
            group.stop_wait_pending = true;
            group.continued_wait_pending = false;
        }
        self.queue_sigchld_to_parent(
            tgid,
            LinuxSigChldInfo {
                pid: tgid,
                status: signal,
                code: LINUX_CLD_STOPPED,
            },
        )?;
        self.refresh_pidfds_for_group(tgid)?;
        self.refresh_signalfds_for_group(tgid)?;
        self.maybe_wake_parent_waiter(tgid)?;
        self.service_pending_waiters()
    }

    pub(in crate::starnix) fn continue_thread_group(
        &mut self,
        tgid: i32,
        stdout: &mut Vec<u8>,
    ) -> Result<u64, zx_status_t> {
        let was_stopped = {
            let Some(group) = self.groups.get_mut(&tgid) else {
                return Ok(linux_errno(LINUX_ESRCH));
            };
            match group.state {
                ThreadGroupState::Zombie { .. } => return Ok(linux_errno(LINUX_ESRCH)),
                ThreadGroupState::Running => false,
                ThreadGroupState::Stopped => {
                    group.state = ThreadGroupState::Running;
                    group.continued_wait_pending = true;
                    true
                }
            }
        };
        self.clear_job_control_pending(tgid)?;
        self.refresh_pidfds_for_group(tgid)?;
        self.refresh_signalfds_for_group(tgid)?;
        if !was_stopped {
            return Ok(0);
        }
        self.queue_sigchld_to_parent(
            tgid,
            LinuxSigChldInfo {
                pid: tgid,
                status: LINUX_SIGCONT,
                code: LINUX_CLD_CONTINUED,
            },
        )?;
        self.maybe_wake_parent_waiter(tgid)?;
        self.service_pending_waiters()?;
        let task_ids = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .task_ids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let mut running_tasks = Vec::new();
        let mut waiting_tasks = Vec::new();
        for task_id in task_ids {
            match self.tasks.get(&task_id).map(|task| &task.state) {
                Some(TaskState::Running) => running_tasks.push(task_id),
                Some(TaskState::Waiting(_)) => waiting_tasks.push(task_id),
                None => {}
            }
        }
        for task_id in running_tasks {
            let sidecar = self
                .tasks
                .get(&task_id)
                .map(|task| task.carrier.sidecar_vmo)
                .ok_or(ZX_ERR_BAD_STATE)?;
            let stop_state = ax_guest_stop_state_read(sidecar)?;
            self.writeback_and_resume(task_id, &stop_state)?;
        }
        for task_id in waiting_tasks {
            self.retry_waiting_task(task_id, stdout)?;
        }
        Ok(0)
    }

    pub(in crate::starnix) fn queue_signal_to_group(
        &mut self,
        tgid: i32,
        signal: i32,
        stdout: &mut Vec<u8>,
    ) -> Result<u64, zx_status_t> {
        let Some(group) = self.groups.get(&tgid) else {
            return Ok(linux_errno(LINUX_ESRCH));
        };
        if matches!(group.state, ThreadGroupState::Zombie { .. }) {
            return Ok(linux_errno(LINUX_ESRCH));
        }
        if signal == 0 {
            return Ok(0);
        }
        if signal == LINUX_SIGCONT {
            return self.continue_thread_group(tgid, stdout);
        }
        let bit = linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
        self.groups
            .get_mut(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .shared_pending |= bit;
        self.refresh_signalfds_for_group(tgid)?;
        Ok(0)
    }

    pub(in crate::starnix) fn queue_signal_to_process_group(
        &mut self,
        pgid: i32,
        signal: i32,
        stdout: &mut Vec<u8>,
    ) -> Result<u64, zx_status_t> {
        let target_tgids = self
            .groups
            .iter()
            .filter_map(|(tgid, group)| {
                (group.pgid == pgid && !matches!(group.state, ThreadGroupState::Zombie { .. }))
                    .then_some(*tgid)
            })
            .collect::<Vec<_>>();
        if target_tgids.is_empty() {
            return Ok(linux_errno(LINUX_ESRCH));
        }
        if signal == 0 {
            return Ok(0);
        }
        if signal == LINUX_SIGCONT {
            for tgid in target_tgids {
                let _ = self.continue_thread_group(tgid, stdout)?;
            }
            return Ok(0);
        }
        let bit = linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
        for tgid in &target_tgids {
            self.groups
                .get_mut(tgid)
                .ok_or(ZX_ERR_BAD_STATE)?
                .shared_pending |= bit;
        }
        for tgid in target_tgids {
            self.refresh_signalfds_for_group(tgid)?;
        }
        Ok(0)
    }

    pub(in crate::starnix) fn queue_signal_to_task(
        &mut self,
        tgid: i32,
        tid: i32,
        signal: i32,
        stdout: &mut Vec<u8>,
    ) -> Result<u64, zx_status_t> {
        let Some(task) = self.tasks.get(&tid) else {
            return Ok(linux_errno(LINUX_ESRCH));
        };
        if task.tgid != tgid
            || self
                .groups
                .get(&tgid)
                .is_some_and(|group| matches!(group.state, ThreadGroupState::Zombie { .. }))
        {
            return Ok(linux_errno(LINUX_ESRCH));
        }
        if signal == 0 {
            return Ok(0);
        }
        if signal == LINUX_SIGCONT {
            return self.continue_thread_group(tgid, stdout);
        }
        let bit = linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
        self.tasks
            .get_mut(&tid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .signals
            .pending |= bit;
        self.refresh_signalfds_for_group(tgid)?;
        Ok(0)
    }
}
