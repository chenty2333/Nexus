use super::super::*;

pub(in crate::starnix) fn reset_exec_sigactions(sigactions: &mut BTreeMap<i32, LinuxSigAction>) {
    sigactions.retain(|_, action| action.handler == LINUX_SIG_IGN);
}

pub(in crate::starnix) fn reset_task_after_exec(task: &mut LinuxTask) {
    task.clear_child_tid = 0;
    task.active_signal = None;
    task.robust_list = None;
}

impl StarnixKernel {
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
                .fs
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
                    .fs
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
            reset_task_after_exec(task);
            old_carrier
        };
        let old_resources = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            group.image = Some(task_image);
            reset_exec_sigactions(&mut group.sigactions);
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
}
