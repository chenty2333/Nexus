use super::super::*;

pub(in crate::starnix) fn fork_task_signals(parent_blocked: u64) -> TaskSignals {
    TaskSignals {
        blocked: parent_blocked,
        pending: 0,
    }
}

pub(in crate::starnix) fn fork_sigactions(
    parent_sigactions: &BTreeMap<i32, LinuxSigAction>,
) -> BTreeMap<i32, LinuxSigAction> {
    parent_sigactions.clone()
}

impl StarnixKernel {
    pub(in crate::starnix) fn sys_clone(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let flags = stop_state.regs.rdi;
        let child_stack = stop_state.regs.rsi;
        let parent_tid_addr = stop_state.regs.rdx;
        let child_tid_addr = stop_state.regs.r10;
        let tls = stop_state.regs.r8;
        let exit_signal = flags & 0xff;
        let supported = LINUX_CLONE_VM
            | LINUX_CLONE_FS
            | LINUX_CLONE_FILES
            | LINUX_CLONE_SIGHAND
            | LINUX_CLONE_SETTLS
            | LINUX_CLONE_THREAD;
        let required = LINUX_CLONE_VM
            | LINUX_CLONE_FS
            | LINUX_CLONE_FILES
            | LINUX_CLONE_SIGHAND
            | LINUX_CLONE_THREAD;
        if (flags & required) != required
            || (flags & !(supported | 0xff)) != 0
            || exit_signal != 0
            || parent_tid_addr != 0
            || child_tid_addr != 0
            || ((flags & LINUX_CLONE_SETTLS) == 0 && tls != 0)
        {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let process_handle = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .resources
            .as_ref()
            .ok_or(ZX_ERR_BAD_STATE)?
            .process_handle;
        let packet_key = self.alloc_packet_key()?;
        let child_tid = self.alloc_tid()?;
        let parent_blocked = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .signals
            .blocked;
        let parent_thread_handle = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .thread_handle;
        let child_carrier = match create_thread_carrier(process_handle, self.port, packet_key) {
            Ok(carrier) => carrier,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_start_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let child_fs_base = if (flags & LINUX_CLONE_SETTLS) != 0 {
            tls
        } else {
            let mut inherited = 0u64;
            if let Err(status) = zx_status_result(ax_thread_get_guest_x64_fs_base(
                parent_thread_handle,
                0,
                &mut inherited,
            )) {
                child_carrier.close();
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_start_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
            inherited
        };
        if let Err(status) = zx_status_result(ax_thread_set_guest_x64_fs_base(
            child_carrier.thread_handle,
            child_fs_base,
            0,
        )) {
            child_carrier.close();
            complete_syscall(
                stop_state,
                linux_errno(map_guest_start_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }

        let mut child_regs = stop_state.regs;
        child_regs.rax = 0;
        child_regs.rip = child_regs
            .rip
            .checked_add(AX_GUEST_X64_SYSCALL_INSN_LEN)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if child_stack != 0 {
            child_regs.rsp = child_stack;
        }
        let start_status = ax_thread_start_guest(child_carrier.thread_handle, &child_regs, 0);
        if let Err(status) = zx_status_result(start_status) {
            child_carrier.close();
            complete_syscall(
                stop_state,
                linux_errno(map_guest_start_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }

        self.tasks.insert(
            child_tid,
            LinuxTask {
                tid: child_tid,
                tgid,
                carrier: child_carrier,
                state: TaskState::Running,
                signals: fork_task_signals(parent_blocked),
                clear_child_tid: 0,
                robust_list: None,
                active_signal: None,
            },
        );
        self.groups
            .get_mut(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .task_ids
            .insert(child_tid);
        complete_syscall(stop_state, child_tid as u64)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_fork(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let parent_tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let parent_session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let parent_blocked = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .signals
            .blocked;
        let parent_thread_handle = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .thread_handle;
        let (task_image, namespace) = {
            let group = self.groups.get(&parent_tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let image = group.image.clone().ok_or(ZX_ERR_BAD_STATE)?;
            let namespace = group
                .resources
                .as_ref()
                .ok_or(ZX_ERR_BAD_STATE)?
                .fs
                .namespace
                .clone();
            (image, namespace)
        };
        let parent_sigactions = fork_sigactions(
            &self
                .groups
                .get(&parent_tgid)
                .ok_or(ZX_ERR_BAD_STATE)?
                .sigactions,
        );
        let (parent_pgid, parent_sid) = {
            let parent_group = self.groups.get(&parent_tgid).ok_or(ZX_ERR_BAD_STATE)?;
            (parent_group.pgid, parent_group.sid)
        };
        let (_, _, image_vmo) = match open_exec_image_from_namespace(&namespace, &task_image.path) {
            Ok(opened) => opened,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let mut inherited_fs_base = 0u64;
        if let Err(status) = zx_status_result(ax_thread_get_guest_x64_fs_base(
            parent_thread_handle,
            0,
            &mut inherited_fs_base,
        )) {
            let _ = zx_handle_close(image_vmo);
            complete_syscall(
                stop_state,
                linux_errno(map_guest_start_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }

        let child_tgid = self.alloc_tid()?;
        let packet_key = self.alloc_packet_key()?;
        let prepared = match prepare_process_carrier(
            self.parent_process,
            self.port,
            packet_key,
            image_vmo,
            &task_image.exec_blob,
        ) {
            Ok(prepared) => prepared,
            Err(status) => {
                let _ = zx_handle_close(image_vmo);
                complete_syscall(
                    stop_state,
                    linux_errno(map_exec_prepare_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let _ = zx_handle_close(image_vmo);
        if let Err(status) = zx_status_result(ax_thread_set_guest_x64_fs_base(
            prepared.carrier.thread_handle,
            inherited_fs_base,
            0,
        )) {
            prepared.close();
            complete_syscall(
                stop_state,
                linux_errno(map_guest_start_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }

        let child_resources = {
            let parent_resources = self
                .groups
                .get(&parent_tgid)
                .ok_or(ZX_ERR_BAD_STATE)?
                .resources
                .as_ref()
                .ok_or(ZX_ERR_BAD_STATE)?;
            match parent_resources.fork_clone(
                prepared.process_handle,
                prepared.root_vmar,
                parent_session,
                prepared.carrier.session_handle,
            ) {
                Ok(resources) => resources,
                Err(status) => {
                    prepared.close();
                    complete_syscall(stop_state, linux_errno(map_vm_status_to_errno(status)))?;
                    return Ok(SyscallAction::Resume);
                }
            }
        };

        let mut child_regs = stop_state.regs;
        child_regs.rax = 0;
        child_regs.rip = child_regs
            .rip
            .checked_add(AX_GUEST_X64_SYSCALL_INSN_LEN)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let (child_resources, child_carrier) =
            match start_prepared_carrier_guest(prepared, &child_regs, child_resources) {
                Ok(started) => started,
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_start_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            };

        let mut task_ids = BTreeSet::new();
        task_ids.insert(child_tgid);
        self.tasks.insert(
            child_tgid,
            LinuxTask {
                tid: child_tgid,
                tgid: child_tgid,
                carrier: child_carrier,
                state: TaskState::Running,
                signals: fork_task_signals(parent_blocked),
                clear_child_tid: 0,
                robust_list: None,
                active_signal: None,
            },
        );
        self.groups.insert(
            child_tgid,
            LinuxThreadGroup {
                tgid: child_tgid,
                leader_tid: child_tgid,
                parent_tgid: Some(parent_tgid),
                pgid: parent_pgid,
                sid: parent_sid,
                child_tgids: BTreeSet::new(),
                task_ids,
                state: ThreadGroupState::Running,
                last_stop_signal: None,
                stop_wait_pending: false,
                continued_wait_pending: false,
                shared_pending: 0,
                sigchld_info: None,
                sigactions: parent_sigactions,
                image: Some(task_image),
                resources: Some(child_resources),
            },
        );
        self.groups
            .get_mut(&parent_tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .child_tgids
            .insert(child_tgid);
        complete_syscall(stop_state, child_tgid as u64)?;
        Ok(SyscallAction::Resume)
    }
}
