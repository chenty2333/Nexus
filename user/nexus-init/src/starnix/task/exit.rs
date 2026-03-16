use super::super::*;

fn read_guest_robust_list_head(
    session: zx_handle_t,
    head_addr: u64,
) -> Result<(u64, i64, u64), zx_status_t> {
    Ok((
        read_guest_u64(session, head_addr)?,
        read_guest_i64(session, head_addr + 8)?,
        read_guest_u64(session, head_addr + 16)?,
    ))
}

impl StarnixKernel {
    pub(in crate::starnix) fn finalize_group_zombie(
        &mut self,
        tgid: i32,
        wait_status: i32,
        exit_code: i32,
    ) -> Result<(), zx_status_t> {
        let child_tgids = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .child_tgids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        if tgid != self.root_tgid {
            for child_tgid in child_tgids {
                if child_tgid == self.root_tgid {
                    continue;
                }
                if let Some(root) = self.groups.get_mut(&self.root_tgid) {
                    root.child_tgids.insert(child_tgid);
                }
                if let Some(child) = self.groups.get_mut(&child_tgid) {
                    child.parent_tgid = Some(self.root_tgid);
                }
            }
        }
        let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(resources) = group.resources.take() {
            let _ = zx_task_kill(resources.process_handle);
            let _ = zx_handle_close(resources.process_handle);
            drop(resources);
        }
        group.image = None;
        group.shared_pending = 0;
        group.state = ThreadGroupState::Zombie {
            wait_status,
            exit_code,
        };
        group.last_stop_signal = None;
        group.stop_wait_pending = false;
        group.continued_wait_pending = false;
        group.sigchld_info = None;
        self.refresh_pidfds_for_group(tgid)?;
        self.maybe_wake_parent_waiter(tgid)
    }

    pub(in crate::starnix) fn finalize_group_exit(
        &mut self,
        tgid: i32,
        code: i32,
    ) -> Result<(), zx_status_t> {
        let wait_status = (code & 0xff) << 8;
        self.queue_sigchld_to_parent(
            tgid,
            LinuxSigChldInfo {
                pid: tgid,
                status: code,
                code: LINUX_CLD_EXITED,
            },
        )?;
        self.finalize_group_zombie(tgid, wait_status, code)?;
        self.service_pending_waiters()
    }

    pub(in crate::starnix) fn finalize_group_signal_exit(
        &mut self,
        tgid: i32,
        signal: i32,
    ) -> Result<(), zx_status_t> {
        let wait_status = signal & 0x7f;
        let exit_code = 128 + signal;
        self.queue_sigchld_to_parent(
            tgid,
            LinuxSigChldInfo {
                pid: tgid,
                status: signal,
                code: LINUX_CLD_KILLED,
            },
        )?;
        self.finalize_group_zombie(tgid, wait_status, exit_code)?;
        self.service_pending_waiters()
    }

    pub(in crate::starnix) fn remove_group_tasks(&mut self, tgid: i32) -> Result<(), zx_status_t> {
        let task_ids = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .task_ids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        for member_id in &task_ids {
            if let Some(task) = self.tasks.get(member_id)
                && let TaskState::Waiting(wait) = task.state
            {
                self.cancel_task_wait(*member_id, wait);
            }
            self.process_clear_child_tid_on_exit(*member_id);
            self.process_robust_list_on_exit(*member_id);
            if let Some(task) = self.tasks.remove(member_id) {
                task.carrier.kill_and_close();
            }
        }
        self.groups
            .get_mut(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .task_ids
            .clear();
        Ok(())
    }

    pub(in crate::starnix) fn exit_task(
        &mut self,
        task_id: i32,
        code: i32,
    ) -> Result<(), zx_status_t> {
        if let Some(task) = self.tasks.get(&task_id)
            && let TaskState::Waiting(wait) = task.state
        {
            self.cancel_task_wait(task_id, wait);
        }
        self.process_clear_child_tid_on_exit(task_id);
        self.process_robust_list_on_exit(task_id);
        let task = self.tasks.remove(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
        task.carrier.kill_and_close();
        let tgid = task.tgid;
        let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        group.task_ids.remove(&task_id);
        if group.task_ids.is_empty() {
            self.finalize_group_exit(tgid, code)?;
        }
        Ok(())
    }

    pub(in crate::starnix) fn exit_group(
        &mut self,
        task_id: i32,
        code: i32,
    ) -> Result<(), zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        self.remove_group_tasks(tgid)?;
        self.finalize_group_exit(tgid, code)
    }

    pub(in crate::starnix) fn exit_group_from_signal(
        &mut self,
        task_id: i32,
        signal: i32,
    ) -> Result<(), zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        self.remove_group_tasks(tgid)?;
        self.finalize_group_signal_exit(tgid, signal)
    }

    pub(in crate::starnix) fn process_robust_list_on_exit(&mut self, task_id: i32) {
        let Some((tgid, session, robust)) = self.tasks.get(&task_id).and_then(|task| {
            task.robust_list
                .map(|robust| (task.tgid, task.carrier.session_handle, robust))
        }) else {
            return;
        };
        let Ok((mut next, futex_offset, list_op_pending)) =
            read_guest_robust_list_head(session, robust.head_addr)
        else {
            return;
        };

        let mut walked = 0usize;
        while next != 0 && next != robust.head_addr && walked < LINUX_ROBUST_LIST_LIMIT {
            let entry_addr = next;
            next = match read_guest_u64(session, entry_addr) {
                Ok(next) => next,
                Err(_) => break,
            };
            self.process_robust_entry_on_exit(task_id, tgid, session, entry_addr, futex_offset);
            walked += 1;
        }

        if list_op_pending != 0 && list_op_pending != robust.head_addr {
            self.process_robust_entry_on_exit(
                task_id,
                tgid,
                session,
                list_op_pending,
                futex_offset,
            );
        }
    }

    pub(in crate::starnix) fn process_clear_child_tid_on_exit(&mut self, task_id: i32) {
        let Some((tgid, session, clear_child_tid)) = self.tasks.get(&task_id).and_then(|task| {
            (task.clear_child_tid != 0).then_some((
                task.tgid,
                task.carrier.session_handle,
                task.clear_child_tid,
            ))
        }) else {
            return;
        };
        if write_guest_u32(session, clear_child_tid, 0).is_err() {
            return;
        }
        let key = Self::private_futex_key_for_tgid(tgid, clear_child_tid);
        let _ = self.wake_futex_waiters(key, 1, LINUX_FUTEX_BITSET_MATCH_ANY);
    }

    pub(in crate::starnix) fn process_robust_entry_on_exit(
        &mut self,
        task_id: i32,
        tgid: i32,
        session: zx_handle_t,
        entry_addr: u64,
        futex_offset: i64,
    ) {
        let futex_addr = if futex_offset >= 0 {
            entry_addr.checked_add(futex_offset as u64)
        } else {
            entry_addr.checked_sub(futex_offset.unsigned_abs())
        };
        let Some(futex_addr) = futex_addr else {
            return;
        };
        let Ok(word) = read_guest_u32(session, futex_addr) else {
            return;
        };
        if (word & LINUX_FUTEX_TID_MASK) != (task_id as u32 & LINUX_FUTEX_TID_MASK) {
            return;
        }
        let new_word = (word & LINUX_FUTEX_WAITERS) | LINUX_FUTEX_OWNER_DIED;
        if write_guest_u32(session, futex_addr, new_word).is_err() {
            return;
        }
        let key = Self::private_futex_key_for_tgid(tgid, futex_addr);
        let _ = self.wake_futex_waiters(key, 1, LINUX_FUTEX_BITSET_MATCH_ANY);
    }
}
