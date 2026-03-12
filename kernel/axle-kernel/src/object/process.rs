use super::*;
use axle_types::status::ZX_ERR_OUT_OF_RANGE;

/// Return the bootstrap current-process handle seeded into the current process.
pub fn bootstrap_self_process_handle() -> Option<zx_handle_t> {
    with_state_mut(|state| {
        state.with_registry(|registry| Ok(Some(registry.bootstrap_self_process_handle)))
    })
    .ok()
    .flatten()
}

/// Return the bootstrap current-thread handle seeded into the current process.
pub fn bootstrap_self_thread_handle() -> Option<zx_handle_t> {
    with_state_mut(|state| {
        state.with_registry(|registry| Ok(Some(registry.bootstrap_self_thread_handle)))
    })
    .ok()
    .flatten()
}

/// Return the bootstrap current-process image layout.
pub fn bootstrap_process_image_layout() -> Option<crate::task::ProcessImageLayout> {
    with_state_mut(|state| {
        state.with_registry(|registry| Ok(Some(registry.bootstrap_process_image_layout.clone())))
    })
    .ok()
    .flatten()
}

/// Return the bootstrap current-thread koid.
pub fn bootstrap_self_thread_koid() -> Option<zx_koid_t> {
    with_kernel(|kernel| kernel.current_thread_koid()).ok()
}

/// Create a new thread object in the target process and return a handle.
pub fn create_thread(
    process_handle: zx_handle_t,
    options: u32,
) -> Result<zx_handle_t, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved =
            state.lookup_handle(process_handle, crate::task::HandleRights::MANAGE_THREAD)?;
        let process = state.with_objects(|objects| {
            Ok(match objects.get(resolved.object_key()) {
                Some(KernelObject::Process(process)) => *process,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;

        let (thread_id, koid) =
            state.with_kernel_mut(|kernel| kernel.create_thread(process.process_id))?;
        let object_id = state.alloc_object_id();
        state.with_objects_mut(|objects| {
            objects.insert(
                object_id,
                KernelObject::Thread(ThreadObject {
                    process_id: process.process_id,
                    thread_id,
                    koid,
                }),
            )?;
            Ok(())
        })?;
        match state.alloc_handle_for_object(object_id, handle::thread_default_rights()) {
            Ok(handle) => Ok(handle),
            Err(err) => {
                let _ = state.with_objects_mut(|objects| Ok(objects.remove(object_id)));
                Err(err)
            }
        }
    })
}

/// Create a new process object plus its root VMAR and return both handles.
pub fn create_process(
    parent_process_handle: zx_handle_t,
    options: u32,
) -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved = state.lookup_handle(
            parent_process_handle,
            crate::task::HandleRights::MANAGE_PROCESS,
        )?;
        state.with_objects(|objects| match objects.get(resolved.object_key()) {
            Some(KernelObject::Process(_)) => Ok(()),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })?;

        let created = state.with_kernel_mut(|kernel| kernel.create_process())?;

        let process_object_id = state.alloc_object_id();
        state.with_objects_mut(|objects| {
            objects.insert(
                process_object_id,
                KernelObject::Process(ProcessObject {
                    process_id: created.process_id(),
                    koid: created.koid(),
                }),
            )?;
            Ok(())
        })?;

        let vmar_object_id = state.alloc_object_id();
        state.with_objects_mut(|objects| {
            objects.insert(
                vmar_object_id,
                KernelObject::Vmar(VmarObject {
                    process_id: created.process_id(),
                    address_space_id: created.address_space_id(),
                    vmar_id: created.root_vmar().id(),
                    base: created.root_vmar().base(),
                    len: created.root_vmar().len(),
                    mapping_caps: vm::root_vmar_mapping_caps(),
                }),
            )?;
            Ok(())
        })?;

        let process_handle = match state
            .alloc_handle_for_object(process_object_id, handle::process_default_rights())
        {
            Ok(handle) => handle,
            Err(err) => {
                let _ = state.with_objects_mut(|objects| {
                    let _ = objects.remove(process_object_id);
                    let _ = objects.remove(vmar_object_id);
                    Ok(())
                });
                return Err(err);
            }
        };
        let root_vmar_handle =
            match state.alloc_handle_for_object(vmar_object_id, handle::vmar_default_rights()) {
                Ok(handle) => handle,
                Err(err) => {
                    let _ = state.close_handle(process_handle);
                    let _ = state.with_objects_mut(|objects| {
                        let _ = objects.remove(process_object_id);
                        let _ = objects.remove(vmar_object_id);
                        Ok(())
                    });
                    return Err(err);
                }
            };
        Ok((process_handle, root_vmar_handle))
    })
}

/// Install one internal process image into a newly created process and return start parameters.
pub fn prepare_process_start(
    process_handle: zx_handle_t,
    image_vmo_handle: zx_handle_t,
    options: u32,
) -> Result<crate::task::PreparedProcessStart, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved_process =
            state.lookup_handle(process_handle, crate::task::HandleRights::MANAGE_PROCESS)?;
        let process = state.with_objects(|objects| {
            Ok(match objects.get(resolved_process.object_key()) {
                Some(KernelObject::Process(process)) => *process,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;

        let resolved_vmo = state.lookup_handle(
            image_vmo_handle,
            crate::task::HandleRights::READ
                | crate::task::HandleRights::EXECUTE
                | crate::task::HandleRights::MAP,
        )?;
        let image_vmo = state.with_objects(|objects| {
            Ok(match objects.get(resolved_vmo.object_key()) {
                Some(KernelObject::Vmo(vmo)) => vmo.clone(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        let layout = resolve_process_image_layout(state, &image_vmo)?;

        state.with_kernel_mut(|kernel| {
            kernel.prepare_process_start(process.process_id, image_vmo.global_vmo_id, &layout)
        })
    })
}

/// Reserve one Linux-flavored exec-prepare helper without overloading the generic launch path.
pub fn prepare_linux_exec(
    process_handle: zx_handle_t,
    image_vmo_handle: zx_handle_t,
    options: u32,
    exec_spec: &[u8],
) -> Result<crate::task::PreparedProcessStart, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    let header =
        axle_types::ax_linux_exec_spec_header_t::decode(exec_spec).ok_or(ZX_ERR_INVALID_ARGS)?;
    let stack_bytes_len =
        usize::try_from(header.stack_bytes_len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let stack_image = exec_spec
        .get(
            axle_types::ax_linux_exec_spec_header_t::BYTE_LEN
                ..axle_types::ax_linux_exec_spec_header_t::BYTE_LEN
                    .checked_add(stack_bytes_len)
                    .ok_or(ZX_ERR_OUT_OF_RANGE)?,
        )
        .ok_or(ZX_ERR_INVALID_ARGS)?;
    if header.version != axle_types::guest::AX_LINUX_EXEC_SPEC_V1 || header.flags != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    let prepared = with_state_mut(|state| {
        let resolved_process =
            state.lookup_handle(process_handle, crate::task::HandleRights::MANAGE_PROCESS)?;
        let process = state.with_objects(|objects| {
            Ok(match objects.get(resolved_process.object_key()) {
                Some(KernelObject::Process(process)) => *process,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;

        let resolved_vmo = state.lookup_handle(
            image_vmo_handle,
            crate::task::HandleRights::READ
                | crate::task::HandleRights::EXECUTE
                | crate::task::HandleRights::MAP,
        )?;
        let image_vmo = state.with_objects(|objects| {
            Ok(match objects.get(resolved_vmo.object_key()) {
                Some(KernelObject::Vmo(vmo)) => vmo.clone(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        let layout = resolve_process_image_layout(state, &image_vmo)?;
        state.with_kernel_mut(|kernel| {
            kernel.prepare_linux_process_start(
                process.process_id,
                image_vmo.global_vmo_id,
                &layout,
                header,
                stack_image,
            )
        })
    })?;
    Ok(prepared)
}

fn resolve_process_image_layout(
    state: &KernelState,
    image_vmo: &VmoObject,
) -> Result<crate::task::ProcessImageLayout, zx_status_t> {
    if let Some(layout) = image_vmo.image_layout.clone() {
        return Ok(layout);
    }
    crate::userspace::parse_elf_process_image_layout(image_vmo.size_bytes, |offset, len| {
        state.with_vm_mut(|vm| vm.read_vmo_bytes(image_vmo, offset, len))
    })
}

/// Start a previously created thread at one user entry point.
pub fn start_thread(
    thread_handle: zx_handle_t,
    entry: zx_vaddr_t,
    stack: zx_vaddr_t,
    arg0: u64,
    arg1: u64,
) -> Result<(), zx_status_t> {
    if entry == 0 || stack == 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved =
            state.lookup_handle(thread_handle, crate::task::HandleRights::MANAGE_THREAD)?;
        let thread = state.with_objects(|objects| {
            Ok(match objects.get(resolved.object_key()) {
                Some(KernelObject::Thread(thread)) => *thread,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        if !state.with_kernel(|kernel| {
            Ok(kernel.validate_process_user_mapping_perms(
                thread.process_id,
                entry,
                1,
                MappingPerms::READ | MappingPerms::EXECUTE | MappingPerms::USER,
            ))
        })? {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let stack_probe = stack.checked_sub(8).ok_or(ZX_ERR_INVALID_ARGS)?;
        if !state.with_kernel(|kernel| {
            Ok(kernel.validate_process_user_mapping_perms(
                thread.process_id,
                stack_probe,
                8,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            ))
        })? {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        state.with_kernel_mut(|kernel| {
            kernel.start_thread(thread.thread_id, entry, stack, arg0, arg1)
        })
    })
}

/// Start a newly created process by starting one thread in its address space.
pub fn start_process(
    process_handle: zx_handle_t,
    thread_handle: zx_handle_t,
    entry: zx_vaddr_t,
    stack: zx_vaddr_t,
    arg_handle: zx_handle_t,
    arg1: u64,
) -> Result<(), zx_status_t> {
    if entry == 0 || stack == 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved_process =
            state.lookup_handle(process_handle, crate::task::HandleRights::MANAGE_PROCESS)?;
        let process = state.with_objects(|objects| {
            Ok(match objects.get(resolved_process.object_key()) {
                Some(KernelObject::Process(process)) => *process,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;

        let resolved_thread =
            state.lookup_handle(thread_handle, crate::task::HandleRights::MANAGE_THREAD)?;
        let thread = state.with_objects(|objects| {
            Ok(match objects.get(resolved_thread.object_key()) {
                Some(KernelObject::Thread(thread)) => *thread,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        if thread.process_id != process.process_id {
            return Err(ZX_ERR_BAD_STATE);
        }

        if !state.with_kernel(|kernel| {
            Ok(kernel.validate_process_user_mapping_perms(
                process.process_id,
                entry,
                1,
                MappingPerms::READ | MappingPerms::EXECUTE | MappingPerms::USER,
            ))
        })? {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let stack_probe = stack.checked_sub(8).ok_or(ZX_ERR_INVALID_ARGS)?;
        if !state.with_kernel(|kernel| {
            Ok(kernel.validate_process_user_mapping_perms(
                process.process_id,
                stack_probe,
                8,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            ))
        })? {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        start_process_with_transferred_arg_handle(
            state,
            process.process_id,
            thread.thread_id,
            entry,
            stack,
            arg_handle,
            arg1,
        )
    })
}

fn install_start_arg_handle(
    state: &KernelState,
    process_id: u64,
    arg_handle: zx_handle_t,
) -> Result<zx_handle_t, zx_status_t> {
    if arg_handle == ZX_HANDLE_INVALID {
        return Ok(ZX_HANDLE_INVALID);
    }

    let transferred =
        state.snapshot_handle_for_transfer(arg_handle, crate::task::HandleRights::TRANSFER)?;
    state.install_transferred_handle_in_process(process_id, transferred)
}

fn rollback_start_arg_handle(
    state: &KernelState,
    process_id: u64,
    child_arg_handle: zx_handle_t,
) -> Result<(), zx_status_t> {
    if child_arg_handle == ZX_HANDLE_INVALID {
        return Ok(());
    }

    let resolved = state.resolve_handle_raw_in_process(process_id, child_arg_handle)?;
    let object_key = resolved.object_key();
    let action = state.with_objects(|objects| {
        Ok(objects
            .get(object_key)
            .map(close_handle_action_for_live_object)
            .unwrap_or(CloseHandleAction::None))
    })?;
    state.close_handle_in_process(process_id, child_arg_handle)?;
    if state.object_handle_count(object_key) == 0 {
        finalize_last_handle_close(state, object_key, action)?;
    }
    Ok(())
}

fn start_process_with_transferred_arg_handle(
    state: &KernelState,
    process_id: u64,
    thread_id: u64,
    entry: zx_vaddr_t,
    stack: zx_vaddr_t,
    arg_handle: zx_handle_t,
    arg1: u64,
) -> Result<(), zx_status_t> {
    let child_arg_handle = install_start_arg_handle(state, process_id, arg_handle)?;
    let result = state.with_kernel_mut(|kernel| {
        kernel.start_process(
            process_id,
            thread_id,
            entry,
            stack,
            child_arg_handle as u64,
            arg1,
        )
    });
    if let Err(status) = result {
        rollback_start_arg_handle(state, process_id, child_arg_handle)?;
        return Err(status);
    }
    Ok(())
}

/// Kill one process or thread handle with minimal bootstrap semantics.
pub fn task_kill(handle: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        enum KillTarget {
            Process(u64),
            Thread(u64),
        }

        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let target = state.with_objects(|objects| {
            Ok(match objects.get(resolved.object_key()) {
                Some(KernelObject::Process(process)) => KillTarget::Process(process.process_id),
                Some(KernelObject::Thread(thread)) => KillTarget::Thread(thread.thread_id),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        match target {
            KillTarget::Process(process_id) => {
                require_handle_rights(resolved, crate::task::HandleRights::MANAGE_PROCESS)?;
                state.with_kernel_mut(|kernel| kernel.kill_process(process_id))?;
            }
            KillTarget::Thread(thread_id) => {
                require_handle_rights(resolved, crate::task::HandleRights::MANAGE_THREAD)?;
                state.with_kernel_mut(|kernel| kernel.kill_thread(thread_id))?;
            }
        }
        sync_task_lifecycle(state)
    })
}

#[cfg(test)]
mod tests {
    use super::{
        install_start_arg_handle, rollback_start_arg_handle,
        start_process_with_transferred_arg_handle,
    };
    use crate::object::KernelState;
    use axle_types::handle::ZX_HANDLE_INVALID;
    use axle_types::status::ZX_ERR_BAD_HANDLE;

    fn bootstrap_self_process_handle(state: &KernelState) -> axle_types::zx_handle_t {
        state
            .with_registry(|registry| Ok(registry.bootstrap_self_process_handle))
            .expect("bootstrap self process handle")
    }

    #[test]
    fn start_arg_handle_installs_into_child_process() {
        let state = KernelState::new();
        let child = state
            .with_kernel_mut(|kernel| kernel.create_process())
            .expect("create child process");
        let parent_handle = bootstrap_self_process_handle(&state);
        let object_key = state
            .resolve_handle_raw(parent_handle)
            .expect("resolve parent handle")
            .object_key();

        let child_handle = install_start_arg_handle(&state, child.process_id(), parent_handle)
            .expect("install arg handle in child");

        assert_ne!(child_handle, ZX_HANDLE_INVALID);
        assert_eq!(state.object_handle_count(object_key), 2);
        let resolved = state
            .resolve_handle_raw_in_process(child.process_id(), child_handle)
            .expect("resolve child handle");
        assert_eq!(resolved.object_key(), object_key);

        rollback_start_arg_handle(&state, child.process_id(), child_handle)
            .expect("rollback installed child handle");
        assert_eq!(state.object_handle_count(object_key), 1);
        assert_eq!(
            state
                .resolve_handle_raw_in_process(child.process_id(), child_handle)
                .expect_err("child handle must be gone"),
            ZX_ERR_BAD_HANDLE
        );
    }

    #[test]
    fn start_process_rolls_back_installed_arg_handle_on_kernel_failure() {
        let state = KernelState::new();
        let child = state
            .with_kernel_mut(|kernel| kernel.create_process())
            .expect("create child process");
        let parent_handle = bootstrap_self_process_handle(&state);
        let object_key = state
            .resolve_handle_raw(parent_handle)
            .expect("resolve parent handle")
            .object_key();

        let status = start_process_with_transferred_arg_handle(
            &state,
            child.process_id(),
            u64::MAX,
            0x1000,
            0x2000,
            parent_handle,
            0,
        )
        .expect_err("kernel start_process should fail for missing thread");

        assert_eq!(status, ZX_ERR_BAD_HANDLE);
        assert_eq!(state.object_handle_count(object_key), 1);
    }
}

/// Suspend one process or thread and return a token whose close resumes it.
pub fn task_suspend(handle: zx_handle_t) -> Result<zx_handle_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let target = state.with_objects(|objects| {
            Ok(match objects.get(resolved.object_key()) {
                Some(KernelObject::Process(process)) => SuspendTarget::Process {
                    process_id: process.process_id,
                },
                Some(KernelObject::Thread(thread)) => SuspendTarget::Thread {
                    thread_id: thread.thread_id,
                },
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        match target {
            SuspendTarget::Process { process_id } => {
                require_handle_rights(resolved, crate::task::HandleRights::MANAGE_PROCESS)?;
                state.with_kernel_mut(|kernel| kernel.suspend_process(process_id))?;
            }
            SuspendTarget::Thread { thread_id } => {
                require_handle_rights(resolved, crate::task::HandleRights::MANAGE_THREAD)?;
                state.with_kernel_mut(|kernel| kernel.suspend_thread(thread_id))?;
            }
        }

        let object_id = state.alloc_object_id();
        state.with_objects_mut(|objects| {
            objects.insert(
                object_id,
                KernelObject::SuspendToken(SuspendTokenObject { target }),
            )?;
            Ok(())
        })?;
        let token_handle = match state
            .alloc_handle_for_object(object_id, handle::suspend_token_default_rights())
        {
            Ok(handle) => handle,
            Err(err) => {
                let _ = state.with_objects_mut(|objects| Ok(objects.remove(object_id)));
                let _ = match target {
                    SuspendTarget::Process { process_id } => {
                        state.with_kernel_mut(|kernel| kernel.resume_process(process_id))
                    }
                    SuspendTarget::Thread { thread_id } => {
                        state.with_kernel_mut(|kernel| kernel.resume_thread(thread_id))
                    }
                };
                return Err(err);
            }
        };
        Ok(token_handle)
    })
}

pub(super) fn task_signals(
    state: &KernelState,
    object: &KernelObject,
) -> Option<Result<Signals, zx_status_t>> {
    match object {
        KernelObject::Process(process) => {
            Some(state.with_kernel(|kernel| kernel.process_signals(process.process_id)))
        }
        KernelObject::Thread(thread) => {
            Some(state.with_kernel(|kernel| kernel.thread_signals(thread.thread_id)))
        }
        _ => None,
    }
}

pub(super) fn close_suspend_token(
    state: &KernelState,
    object_key: ObjectKey,
    target: SuspendTarget,
) -> Result<(), zx_status_t> {
    if state.object_handle_count(object_key) != 0 {
        return Ok(());
    }
    state.with_reactor_mut(|reactor| {
        reactor.remove_waitable(object_key);
        Ok(())
    })?;
    let _ = state.begin_logical_destroy(object_key)?;
    let result = match target {
        SuspendTarget::Process { process_id } => {
            match state.with_kernel_mut(|kernel| kernel.resume_process(process_id)) {
                Ok(()) | Err(ZX_ERR_BAD_STATE) => Ok(()),
                Err(status) => Err(status),
            }
        }
        SuspendTarget::Thread { thread_id } => {
            match state.with_kernel_mut(|kernel| kernel.resume_thread(thread_id)) {
                Ok(()) | Err(ZX_ERR_BAD_STATE) => Ok(()),
                Err(status) => Err(status),
            }
        }
    };
    state.finish_logical_destroy(object_key);
    result
}

fn task_object_ids(state: &KernelState) -> Vec<ObjectKey> {
    state
        .with_registry(|registry| {
            Ok(registry
                .iter()
                .filter_map(|(object_key, object)| {
                    matches!(object, KernelObject::Process(_) | KernelObject::Thread(_))
                        .then_some(object_key)
                })
                .collect())
        })
        .unwrap_or_default()
}

fn process_object_handle_count(state: &KernelState, process_id: u64) -> usize {
    state
        .with_registry(|registry| {
            Ok(registry
                .iter()
                .filter_map(|(object_key, object)| match object {
                    KernelObject::Process(process) if process.process_id == process_id => {
                        Some(registry.handle_refcount(object_key))
                    }
                    _ => None,
                })
                .sum())
        })
        .unwrap_or(0)
}

fn maybe_reap_process_record(state: &KernelState, process_id: u64) -> Result<(), zx_status_t> {
    if process_object_handle_count(state, process_id) != 0 {
        return Ok(());
    }
    let can_reap = match state.with_kernel(|kernel| kernel.can_reap_process(process_id)) {
        Ok(can_reap) => can_reap,
        Err(ZX_ERR_BAD_HANDLE) => return Ok(()),
        Err(status) => return Err(status),
    };
    if can_reap {
        state.with_kernel_mut(|kernel| kernel.reap_process(process_id))?;
    }
    Ok(())
}

fn reap_terminated_task_objects(state: &KernelState) -> Result<(), zx_status_t> {
    loop {
        let (thread_candidates, process_candidates) = state.with_registry(|registry| {
            let thread_candidates = registry
                .iter()
                .filter_map(|(object_key, object)| match object {
                    KernelObject::Thread(thread) if registry.handle_refcount(object_key) == 0 => {
                        Some((object_key, thread.thread_id, thread.process_id))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();

            let process_candidates = registry
                .iter()
                .filter_map(|(object_key, object)| match object {
                    KernelObject::Process(process) if registry.handle_refcount(object_key) == 0 => {
                        Some((object_key, process.process_id))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();

            Ok((thread_candidates, process_candidates))
        })?;

        let thread_reaps = thread_candidates
            .into_iter()
            .filter(|(_, thread_id, _)| {
                state
                    .with_kernel(|kernel| kernel.thread_is_terminated(*thread_id))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();

        let process_reaps = process_candidates
            .into_iter()
            .filter(|(_, process_id)| {
                state
                    .with_kernel(|kernel| kernel.process_is_terminated(*process_id))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();

        if thread_reaps.is_empty() && process_reaps.is_empty() {
            break;
        }

        for (object_id, thread_id, process_id) in thread_reaps {
            if state.object_handle_count(object_id) != 0 {
                continue;
            }
            state.forget_guest_session(thread_id);
            state.with_reactor_mut(|reactor| {
                reactor.remove_waitable(object_id);
                Ok(())
            })?;
            state.with_objects_mut(|objects| {
                let _ = objects.remove(object_id);
                Ok(())
            })?;
            // Lifecycle sync runs opportunistically on multiple CPUs, so another CPU may have
            // already reaped the kernel thread record after we built this zero-handle snapshot.
            match state.with_kernel_mut(|kernel| kernel.reap_thread(thread_id)) {
                Ok(reaped_process_id) => maybe_reap_process_record(state, reaped_process_id)?,
                Err(ZX_ERR_BAD_HANDLE) => maybe_reap_process_record(state, process_id)?,
                Err(status) => return Err(status),
            }
        }

        for (object_id, process_id) in process_reaps {
            if state.object_handle_count(object_id) != 0 {
                continue;
            }
            state.with_reactor_mut(|reactor| {
                reactor.remove_waitable(object_id);
                Ok(())
            })?;
            state.with_objects_mut(|objects| {
                let _ = objects.remove(object_id);
                Ok(())
            })?;
            maybe_reap_process_record(state, process_id)?;
        }
    }

    Ok(())
}

pub(crate) fn sync_task_lifecycle(state: &KernelState) -> Result<(), zx_status_t> {
    for object_id in task_object_ids(state) {
        let _ = publish_object_signals(state, object_id);
    }
    reap_terminated_task_objects(state)
}
