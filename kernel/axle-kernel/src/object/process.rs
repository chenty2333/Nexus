use super::*;

/// Return the bootstrap current-process handle seeded into the current process.
pub fn bootstrap_self_process_handle() -> Option<zx_handle_t> {
    let mut guard = STATE.lock();
    let state = guard.as_mut()?;
    Some(state.bootstrap_self_process_handle)
}

/// Return the bootstrap current-thread handle seeded into the current process.
pub fn bootstrap_self_thread_handle() -> Option<zx_handle_t> {
    let mut guard = STATE.lock();
    let state = guard.as_mut()?;
    Some(state.bootstrap_self_thread_handle)
}

/// Return the bootstrap current-process image layout.
pub fn bootstrap_process_image_layout() -> Option<crate::task::ProcessImageLayout> {
    let mut guard = STATE.lock();
    let state = guard.as_mut()?;
    Some(state.bootstrap_process_image_layout.clone())
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
        let process = match state.objects.get(&resolved.object_id()) {
            Some(KernelObject::Process(process)) => *process,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };

        let (thread_id, koid) =
            state.with_kernel_mut(|kernel| kernel.create_thread(process.process_id))?;
        let object_id = state.alloc_object_id();
        state.objects.insert(
            object_id,
            KernelObject::Thread(ThreadObject {
                process_id: process.process_id,
                thread_id,
                koid,
            }),
        );
        match state.alloc_handle_for_object(object_id, handle::thread_default_rights()) {
            Ok(handle) => Ok(handle),
            Err(err) => {
                let _ = state.objects.remove(&object_id);
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
        match state.objects.get(&resolved.object_id()) {
            Some(KernelObject::Process(_)) => {}
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        }

        let created = state.with_kernel_mut(|kernel| kernel.create_process())?;

        let process_object_id = state.alloc_object_id();
        state.objects.insert(
            process_object_id,
            KernelObject::Process(ProcessObject {
                process_id: created.process_id(),
                koid: created.koid(),
            }),
        );

        let vmar_object_id = state.alloc_object_id();
        state.objects.insert(
            vmar_object_id,
            KernelObject::Vmar(VmarObject {
                process_id: created.process_id(),
                address_space_id: created.address_space_id(),
                vmar_id: created.root_vmar().id(),
                base: created.root_vmar().base(),
                len: created.root_vmar().len(),
                mapping_caps: vm::root_vmar_mapping_caps(),
            }),
        );

        let process_handle = match state
            .alloc_handle_for_object(process_object_id, handle::process_default_rights())
        {
            Ok(handle) => handle,
            Err(err) => {
                let _ = state.objects.remove(&process_object_id);
                let _ = state.objects.remove(&vmar_object_id);
                return Err(err);
            }
        };
        let root_vmar_handle =
            match state.alloc_handle_for_object(vmar_object_id, handle::vmar_default_rights()) {
                Ok(handle) => handle,
                Err(err) => {
                    let _ = state.close_handle(process_handle);
                    let _ = state.objects.remove(&process_object_id);
                    let _ = state.objects.remove(&vmar_object_id);
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
        let process = match state.objects.get(&resolved_process.object_id()) {
            Some(KernelObject::Process(process)) => *process,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };

        let resolved_vmo = state.lookup_handle(
            image_vmo_handle,
            crate::task::HandleRights::READ | crate::task::HandleRights::MAP,
        )?;
        let image_vmo = match state.objects.get(&resolved_vmo.object_id()) {
            Some(KernelObject::Vmo(vmo)) => vmo.clone(),
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        let layout = image_vmo.image_layout.ok_or(ZX_ERR_NOT_SUPPORTED)?;

        state.with_kernel_mut(|kernel| {
            kernel.prepare_process_start(process.process_id, image_vmo.global_vmo_id, &layout)
        })
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
        let thread = match state.objects.get(&resolved.object_id()) {
            Some(KernelObject::Thread(thread)) => *thread,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        if !state.with_kernel(|kernel| {
            Ok(kernel.validate_process_user_ptr(thread.process_id, entry, 1))
        })? {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let stack_probe = stack.checked_sub(8).ok_or(ZX_ERR_INVALID_ARGS)?;
        if !state.with_kernel(|kernel| {
            Ok(kernel.validate_process_user_ptr(thread.process_id, stack_probe, 8))
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
    if arg_handle != ZX_HANDLE_INVALID {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }

    with_state_mut(|state| {
        let resolved_process =
            state.lookup_handle(process_handle, crate::task::HandleRights::MANAGE_PROCESS)?;
        let process = match state.objects.get(&resolved_process.object_id()) {
            Some(KernelObject::Process(process)) => *process,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };

        let resolved_thread =
            state.lookup_handle(thread_handle, crate::task::HandleRights::MANAGE_THREAD)?;
        let thread = match state.objects.get(&resolved_thread.object_id()) {
            Some(KernelObject::Thread(thread)) => *thread,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        if thread.process_id != process.process_id {
            return Err(ZX_ERR_BAD_STATE);
        }

        if !state.with_kernel(|kernel| {
            Ok(kernel.validate_process_user_ptr(process.process_id, entry, 1))
        })? {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let stack_probe = stack.checked_sub(8).ok_or(ZX_ERR_INVALID_ARGS)?;
        if !state.with_kernel(|kernel| {
            Ok(kernel.validate_process_user_ptr(process.process_id, stack_probe, 8))
        })? {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        state.with_kernel_mut(|kernel| {
            kernel.start_process(
                process.process_id,
                thread.thread_id,
                entry,
                stack,
                arg_handle as u64,
                arg1,
            )
        })
    })
}

/// Kill one process or thread handle with minimal bootstrap semantics.
pub fn task_kill(handle: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let result = match state.objects.get(&resolved.object_id()) {
            Some(KernelObject::Process(process)) => {
                require_handle_rights(resolved, crate::task::HandleRights::MANAGE_PROCESS)?;
                state.with_kernel_mut(|kernel| kernel.kill_process(process.process_id))
            }
            Some(KernelObject::Thread(thread)) => {
                require_handle_rights(resolved, crate::task::HandleRights::MANAGE_THREAD)?;
                state.with_kernel_mut(|kernel| kernel.kill_thread(thread.thread_id))
            }
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        };
        result?;
        sync_task_lifecycle(state)
    })
}

/// Suspend one process or thread and return a token whose close resumes it.
pub fn task_suspend(handle: zx_handle_t, out_token: *mut zx_handle_t) -> Result<(), zx_status_t> {
    if out_token.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let target = match state.objects.get(&resolved.object_id()) {
            Some(KernelObject::Process(process)) => {
                require_handle_rights(resolved, crate::task::HandleRights::MANAGE_PROCESS)?;
                state.with_kernel_mut(|kernel| kernel.suspend_process(process.process_id))?;
                SuspendTarget::Process {
                    process_id: process.process_id,
                }
            }
            Some(KernelObject::Thread(thread)) => {
                require_handle_rights(resolved, crate::task::HandleRights::MANAGE_THREAD)?;
                state.with_kernel_mut(|kernel| kernel.suspend_thread(thread.thread_id))?;
                SuspendTarget::Thread {
                    thread_id: thread.thread_id,
                }
            }
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };

        let object_id = state.alloc_object_id();
        state.objects.insert(
            object_id,
            KernelObject::SuspendToken(SuspendTokenObject { target }),
        );
        let token_handle = match state
            .alloc_handle_for_object(object_id, handle::suspend_token_default_rights())
        {
            Ok(handle) => handle,
            Err(err) => {
                let _ = state.objects.remove(&object_id);
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
        state.with_kernel_mut(|kernel| {
            let thread_id = kernel.current_thread_info()?.thread_id();
            kernel.copyout_thread_user(thread_id, out_token, token_handle)
        })
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
    state: &mut KernelState,
    object_id: u64,
    target: SuspendTarget,
) -> Result<(), zx_status_t> {
    if state.object_handle_count(object_id) != 0 {
        return Ok(());
    }
    state.observers.remove_waitable(object_id);
    let _ = state.objects.remove(&object_id);
    state.forget_object_handle_refs(object_id);
    match target {
        SuspendTarget::Process { process_id } => {
            if let Err(status) = state.with_kernel_mut(|kernel| kernel.resume_process(process_id))
                && status != ZX_ERR_BAD_STATE
            {
                return Err(status);
            }
        }
        SuspendTarget::Thread { thread_id } => {
            if let Err(status) = state.with_kernel_mut(|kernel| kernel.resume_thread(thread_id))
                && status != ZX_ERR_BAD_STATE
            {
                return Err(status);
            }
        }
    }
    Ok(())
}

fn task_object_ids(state: &KernelState) -> Vec<u64> {
    state
        .objects
        .iter()
        .filter_map(|(object_id, object)| {
            matches!(object, KernelObject::Process(_) | KernelObject::Thread(_))
                .then_some(*object_id)
        })
        .collect()
}

fn process_object_handle_count(state: &KernelState, process_id: u64) -> usize {
    state
        .objects
        .iter()
        .filter_map(|(object_id, object)| match object {
            KernelObject::Process(process) if process.process_id == process_id => {
                Some(state.object_handle_count(*object_id))
            }
            _ => None,
        })
        .sum()
}

fn maybe_reap_process_record(state: &mut KernelState, process_id: u64) -> Result<(), zx_status_t> {
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

fn reap_terminated_task_objects(state: &mut KernelState) -> Result<(), zx_status_t> {
    loop {
        let thread_reaps = state
            .objects
            .iter()
            .filter_map(|(object_id, object)| match object {
                KernelObject::Thread(thread)
                    if state.object_handle_count(*object_id) == 0
                        && state
                            .with_kernel(|kernel| kernel.thread_is_terminated(thread.thread_id))
                            .unwrap_or(false) =>
                {
                    Some((*object_id, thread.thread_id, thread.process_id))
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        let process_reaps = state
            .objects
            .iter()
            .filter_map(|(object_id, object)| match object {
                KernelObject::Process(process)
                    if state.object_handle_count(*object_id) == 0
                        && state
                            .with_kernel(|kernel| kernel.process_is_terminated(process.process_id))
                            .unwrap_or(false) =>
                {
                    Some((*object_id, process.process_id))
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        if thread_reaps.is_empty() && process_reaps.is_empty() {
            break;
        }

        for (object_id, thread_id, process_id) in thread_reaps {
            state.observers.remove_waitable(object_id);
            let _ = state.objects.remove(&object_id);
            state.forget_object_handle_refs(object_id);
            let _ = state.with_kernel_mut(|kernel| kernel.reap_thread(thread_id))?;
            maybe_reap_process_record(state, process_id)?;
        }

        for (object_id, process_id) in process_reaps {
            state.observers.remove_waitable(object_id);
            let _ = state.objects.remove(&object_id);
            state.forget_object_handle_refs(object_id);
            maybe_reap_process_record(state, process_id)?;
        }
    }

    Ok(())
}

pub(crate) fn sync_task_lifecycle(state: &mut KernelState) -> Result<(), zx_status_t> {
    for object_id in task_object_ids(state) {
        let _ = publish_object_signals(state, object_id);
    }
    reap_terminated_task_objects(state)
}
