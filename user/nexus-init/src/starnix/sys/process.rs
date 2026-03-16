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
                tgid as u64
            }
        };
        if result == tgid as u64 {
            self.foreground_pgid_by_sid.insert(tgid, tgid);
        }
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

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
                signals: TaskSignals {
                    blocked: parent_blocked,
                    pending: 0,
                },
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
                .namespace
                .clone();
            (image, namespace)
        };
        let parent_sigactions = self
            .groups
            .get(&parent_tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .sigactions
            .clone();
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

        for range in &task_image.writable_ranges {
            if let Err(status) = copy_guest_region(
                parent_session,
                prepared.carrier.session_handle,
                range.base,
                range.len,
            ) {
                prepared.close();
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        }
        if let Err(status) = copy_guest_region(
            parent_session,
            prepared.carrier.session_handle,
            USER_STACK_VA,
            USER_STACK_BYTES,
        ) {
            prepared.close();
            complete_syscall(
                stop_state,
                linux_errno(map_guest_memory_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }

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
                signals: TaskSignals {
                    blocked: parent_blocked,
                    pending: 0,
                },
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

    pub(in crate::starnix) fn sys_execve(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            if group.leader_tid != task_id || group.task_ids.len() != 1 {
                complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
                return Ok(SyscallAction::Resume);
            }
        }

        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let path = match read_guest_c_string(session, stop_state.regs.rdi, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let mut args = match read_guest_string_array(session, stop_state.regs.rsi, 128) {
            Ok(args) => args,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let env = match read_guest_string_array(session, stop_state.regs.rdx, 128) {
            Ok(env) => env,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let (resolved_path, image_bytes, image_vmo) = {
            let namespace = &self
                .groups
                .get(&tgid)
                .ok_or(ZX_ERR_BAD_STATE)?
                .resources
                .as_ref()
                .ok_or(ZX_ERR_BAD_STATE)?
                .namespace;
            match open_exec_image_from_namespace(namespace, &path) {
                Ok((resolved_path, image_bytes, image_vmo)) => {
                    (resolved_path, image_bytes, image_vmo)
                }
                Err(status) => {
                    complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                    return Ok(SyscallAction::Resume);
                }
            }
        };
        if args.is_empty() {
            args.push(resolved_path.clone());
        }
        let mut stack_random = [0u8; 16];
        fill_random_bytes(&mut self.random_state, &mut stack_random);
        let task_image = match build_task_image(
            &resolved_path,
            &args,
            &env,
            &image_bytes,
            stack_random,
            |interp_path| {
                let namespace = &self
                    .groups
                    .get(&tgid)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .resources
                    .as_ref()
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .namespace;
                read_exec_image_bytes_from_namespace(namespace, interp_path).map(|(_, bytes)| bytes)
            },
        ) {
            Ok(image) => image,
            Err(status) => {
                let _ = zx_handle_close(image_vmo);
                let errno = map_exec_status_to_errno(status);
                complete_syscall(stop_state, linux_errno(errno))?;
                return Ok(SyscallAction::Resume);
            }
        };
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
                let errno = map_exec_prepare_status_to_errno(status);
                complete_syscall(stop_state, linux_errno(errno))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let _ = zx_handle_close(image_vmo);

        let mut new_resources = {
            let resources = self
                .groups
                .get(&tgid)
                .ok_or(ZX_ERR_BAD_STATE)?
                .resources
                .as_ref()
                .ok_or(ZX_ERR_BAD_STATE)?;
            match resources.exec_replace(prepared.process_handle, prepared.root_vmar) {
                Ok(resources) => resources,
                Err(status) => {
                    prepared.close();
                    let errno = map_vm_status_to_errno(status);
                    complete_syscall(stop_state, linux_errno(errno))?;
                    return Ok(SyscallAction::Resume);
                }
            }
        };
        if let Err(status) = new_resources.install_exec_writable_ranges(&task_image.writable_ranges)
        {
            prepared.close();
            let errno = map_vm_status_to_errno(status);
            complete_syscall(stop_state, linux_errno(errno))?;
            return Ok(SyscallAction::Resume);
        }
        match new_resources.install_initial_tls(prepared.carrier.session_handle, &task_image) {
            Ok(Some(fs_base)) => {
                if let Err(status) = zx_status_result(ax_thread_set_guest_x64_fs_base(
                    prepared.carrier.thread_handle,
                    fs_base,
                    0,
                )) {
                    prepared.close();
                    let errno = map_guest_start_status_to_errno(status);
                    complete_syscall(stop_state, linux_errno(errno))?;
                    return Ok(SyscallAction::Resume);
                }
            }
            Ok(None) => {}
            Err(status) => {
                prepared.close();
                let errno = map_vm_status_to_errno(status);
                complete_syscall(stop_state, linux_errno(errno))?;
                return Ok(SyscallAction::Resume);
            }
        }
        let regs = linux_guest_initial_regs(prepared.prepared_entry, prepared.prepared_stack);
        let (new_resources, new_carrier) =
            match start_prepared_carrier_guest(prepared, &regs, new_resources) {
                Ok(started) => started,
                Err(status) => {
                    let errno = map_guest_start_status_to_errno(status);
                    complete_syscall(stop_state, linux_errno(errno))?;
                    return Ok(SyscallAction::Resume);
                }
            };

        let old_carrier = {
            let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
            let old_carrier = task.carrier;
            task.carrier = new_carrier;
            task.clear_child_tid = 0;
            task.active_signal = None;
            task.robust_list = None;
            old_carrier
        };
        let old_resources = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            group.image = Some(task_image);
            group
                .resources
                .replace(new_resources)
                .ok_or(ZX_ERR_BAD_STATE)?
        };
        let _ = zx_task_kill(old_resources.process_handle);
        old_carrier.close();
        drop(old_resources);
        Ok(SyscallAction::LeaveStopped)
    }

    pub(in crate::starnix) fn sys_wait4(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let target_pid = stop_state.regs.rdi as u32 as i32;
        let status_addr = stop_state.regs.rsi;
        let options = stop_state.regs.rdx;
        let rusage_addr = stop_state.regs.r10;
        let supported_options = LINUX_WNOHANG | LINUX_WUNTRACED | LINUX_WCONTINUED;
        if (options & !supported_options) != 0 || rusage_addr != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let parent_tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let child_tgids = self
            .groups
            .get(&parent_tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .child_tgids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let mut has_match = false;
        for child_tgid in child_tgids {
            if !self.wait_matches(parent_tgid, target_pid, child_tgid) {
                continue;
            }
            has_match = true;
            if let Some(event) =
                self.wait_event_for_child(parent_tgid, target_pid, child_tgid, options)
            {
                let wait_status = match event {
                    WaitChildEvent::Zombie { status } | WaitChildEvent::Stopped { status } => {
                        status
                    }
                    WaitChildEvent::Continued => LINUX_WAIT_STATUS_CONTINUED,
                };
                if status_addr != 0 {
                    write_guest_bytes(
                        self.tasks
                            .get(&task_id)
                            .ok_or(ZX_ERR_BAD_STATE)?
                            .carrier
                            .session_handle,
                        status_addr,
                        &wait_status.to_ne_bytes(),
                    )
                    .map_err(|status| {
                        linux_status_from_errno(map_guest_write_status_to_errno(status))
                    })?;
                }
                self.consume_wait_event(child_tgid, event)?;
                complete_syscall(stop_state, child_tgid as u64)?;
                if matches!(event, WaitChildEvent::Zombie { .. }) {
                    self.reap_group(child_tgid)?;
                }
                return Ok(SyscallAction::Resume);
            }
        }
        if !has_match {
            complete_syscall(stop_state, linux_errno(LINUX_ECHILD))?;
            return Ok(SyscallAction::Resume);
        }
        if (options & LINUX_WNOHANG) != 0 {
            complete_syscall(stop_state, 0)?;
            return Ok(SyscallAction::Resume);
        }

        let wait = WaitState {
            restartable: true,
            kind: WaitKind::Wait4 {
                target_pid,
                status_addr,
                options,
            },
        };
        self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state = TaskState::Waiting(wait);
        self.deliver_or_interrupt_wait(task_id, wait, stop_state)
    }
}
