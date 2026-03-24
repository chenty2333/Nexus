use axle_core::Packet;
use axle_types::guest::{
    AX_GUEST_ARCH_X86_64, AX_GUEST_STOP_REASON_X64_SYSCALL, AX_GUEST_STOP_STATE_V1,
    AX_GUEST_X64_SYSCALL_INSN_LEN,
};
use axle_types::status::{
    ZX_ERR_ALREADY_BOUND, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_STATE, ZX_ERR_INVALID_ARGS,
    ZX_ERR_OUT_OF_RANGE, ZX_ERR_WRONG_TYPE,
};
use axle_types::{ax_guest_stop_state_t, zx_handle_t, zx_status_t};

use super::*;

const X64_SYSCALL_INSN: [u8; 2] = [0x0f, 0x05];

/// Create one guest-session object that binds a supervised guest thread to a
/// sidecar VMO and supervisor port.
pub fn create_guest_session(
    thread_handle: zx_handle_t,
    sidecar_vmo_handle: zx_handle_t,
    port_handle: zx_handle_t,
    packet_key: u64,
    options: u32,
) -> Result<zx_handle_t, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved_thread =
            state.lookup_handle(thread_handle, crate::task::HandleRights::MANAGE_THREAD)?;
        let thread = state.with_objects(|objects| {
            Ok(match objects.get(resolved_thread.object_key()) {
                Some(KernelObject::Thread(thread)) => *thread,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;

        if state.guest_session_key(thread.thread_id).is_some() {
            return Err(ZX_ERR_ALREADY_BOUND);
        }

        let resolved_sidecar = state.lookup_handle(
            sidecar_vmo_handle,
            crate::task::HandleRights::READ | crate::task::HandleRights::WRITE,
        )?;
        let sidecar_vmo = state.with_objects(|objects| {
            Ok(match objects.get(resolved_sidecar.object_key()) {
                Some(KernelObject::Vmo(vmo)) => vmo.clone(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        if sidecar_vmo.size_bytes < ax_guest_stop_state_t::BYTE_LEN as u64 {
            return Err(ZX_ERR_OUT_OF_RANGE);
        }

        let resolved_port = state.lookup_handle(port_handle, crate::task::HandleRights::WRITE)?;
        let port_object = state.with_objects(|objects| {
            Ok(match objects.get(resolved_port.object_key()) {
                Some(KernelObject::Port(_)) => resolved_port.object_key(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;

        let object_key = state.alloc_object_id();
        state.with_objects_mut(|objects| {
            objects.insert(
                object_key,
                KernelObject::GuestSession(GuestSessionObject {
                    thread_id: thread.thread_id,
                    sidecar_vmo,
                    port_object,
                    packet_key,
                    stop_seq: 0,
                    stopped_seq: None,
                }),
            )?;
            Ok(())
        })?;
        if let Err(status) = state.note_guest_session(thread.thread_id, object_key) {
            let _ = state.with_objects_mut(|objects| Ok(objects.remove(object_key)));
            return Err(status);
        }
        match state.alloc_handle_for_object(object_key, handle::guest_session_default_rights()) {
            Ok(handle) => Ok(handle),
            Err(status) => {
                state.forget_guest_session(thread.thread_id);
                let _ = state.with_objects_mut(|objects| Ok(objects.remove(object_key)));
                Err(status)
            }
        }
    })
}

/// Resume one stopped guest thread after the supervisor updated the sidecar
/// stop-state snapshot.
pub fn resume_guest_session(
    session_handle: zx_handle_t,
    stop_seq: u64,
    options: u32,
) -> Result<(), zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved = state.lookup_handle(session_handle, crate::task::HandleRights::WRITE)?;
        let object_key = resolved.object_key();
        let session = state.with_objects(|objects| {
            Ok(match objects.get(object_key) {
                Some(KernelObject::GuestSession(session)) => session.clone(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        if session.stopped_seq != Some(stop_seq) {
            return Err(ZX_ERR_BAD_STATE);
        }

        let bytes = state.with_vm_mut(|vm| {
            vm.read_vmo_bytes(&session.sidecar_vmo, 0, ax_guest_stop_state_t::BYTE_LEN)
        })?;
        let stop_state = ax_guest_stop_state_t::decode(&bytes).ok_or(ZX_ERR_INVALID_ARGS)?;
        if stop_state.version != AX_GUEST_STOP_STATE_V1
            || stop_state.arch != AX_GUEST_ARCH_X86_64
            || stop_state.stop_seq != stop_seq
        {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        // Merge the sequence-number re-validation, session update, and thread
        // wake into a single objects-lock hold to close the TOCTOU window
        // between the outer check and the state mutation.
        state.with_objects_mut(|objects| {
            let Some(KernelObject::GuestSession(session)) = objects.get_mut(object_key) else {
                return Err(ZX_ERR_BAD_STATE);
            };
            if session.stopped_seq != Some(stop_seq) {
                return Err(ZX_ERR_BAD_STATE);
            }
            session.stopped_seq = None;
            Ok(session.thread_id)
        })?;
        state.with_kernel_mut(|kernel| {
            kernel.replace_thread_guest_context(session.thread_id, &stop_state.regs)?;
            kernel.wake_thread(session.thread_id, crate::task::WakeReason::PreserveContext)
        })
    })
}

/// Read guest userspace bytes through one stopped or running guest session.
pub fn read_guest_memory(
    session_handle: zx_handle_t,
    guest_addr: u64,
    len: usize,
) -> Result<Vec<u8>, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(session_handle, crate::task::HandleRights::READ)?;
        let object_key = resolved.object_key();
        let session = state.with_objects(|objects| {
            Ok(match objects.get(object_key) {
                Some(KernelObject::GuestSession(session)) => session.clone(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        state.with_kernel_mut(|kernel| {
            kernel.read_thread_user_bytes(session.thread_id, guest_addr, len)
        })
    })
}

/// Copy kernel-owned bytes into one supervised guest session's userspace memory.
pub fn write_guest_memory(
    session_handle: zx_handle_t,
    guest_addr: u64,
    bytes: &[u8],
) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(session_handle, crate::task::HandleRights::WRITE)?;
        let object_key = resolved.object_key();
        let session = state.with_objects(|objects| {
            Ok(match objects.get(object_key) {
                Some(KernelObject::GuestSession(session)) => session.clone(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        state.with_kernel_mut(|kernel| {
            kernel.write_thread_user_bytes(session.thread_id, guest_addr, bytes)
        })
    })
}

pub(crate) fn handle_invalid_opcode_trap(
    state: &KernelState,
    trap: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *mut u64,
    resuming_blocked_current: bool,
) -> Result<TrapBlock<bool>, zx_status_t> {
    if resuming_blocked_current {
        return finish_guest_trap_resume(state, trap, cpu_frame, true);
    }

    let Some((thread_id, session_key)) = current_guest_session(state)? else {
        return Ok(TrapBlock::Ready(false));
    };
    if !is_syscall_invalid_opcode(cpu_frame.cast_const())? {
        return Ok(TrapBlock::Ready(false));
    }

    handle_guest_syscall_stop(state, trap, cpu_frame, thread_id, session_key, 0)
}

pub(crate) fn handle_native_syscall_trap(
    state: &KernelState,
    trap: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *mut u64,
    resuming_blocked_current: bool,
) -> Result<TrapBlock<bool>, zx_status_t> {
    if resuming_blocked_current {
        return finish_guest_trap_resume(state, trap, cpu_frame, true);
    }

    let Some((thread_id, session_key)) = current_guest_session(state)? else {
        return Ok(TrapBlock::Ready(false));
    };
    handle_guest_syscall_stop(
        state,
        trap,
        cpu_frame,
        thread_id,
        session_key,
        AX_GUEST_X64_SYSCALL_INSN_LEN,
    )
}

fn current_guest_session(state: &KernelState) -> Result<Option<(u64, ObjectKey)>, zx_status_t> {
    state.with_kernel(|kernel| {
        let thread = match kernel.current_thread_info() {
            Ok(thread) => thread,
            Err(ZX_ERR_BAD_STATE) => return Ok(None),
            Err(status) => return Err(status),
        };
        let guest_started = match kernel.thread_uses_guest_syscall_stop(thread.thread_id()) {
            Ok(guest_started) => guest_started,
            Err(ZX_ERR_BAD_STATE) => return Ok(None),
            Err(status) => return Err(status),
        };
        if !guest_started {
            return Ok(None);
        }
        Ok(state
            .guest_session_key(thread.thread_id())
            .map(|session_key| (thread.thread_id(), session_key)))
    })
}

fn handle_guest_syscall_stop(
    state: &KernelState,
    trap: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *mut u64,
    thread_id: u64,
    session_key: ObjectKey,
    stop_rip_adjust: u64,
) -> Result<TrapBlock<bool>, zx_status_t> {
    let session = state.with_objects(|objects| {
        Ok(match objects.get(session_key) {
            Some(KernelObject::GuestSession(session)) => session.clone(),
            Some(_) => return Err(ZX_ERR_BAD_STATE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        })
    })?;

    let (stop_seq, stop_state, disposition, lifecycle_dirty) = state.with_kernel_mut(|kernel| {
        kernel.capture_current_user_context(trap, cpu_frame.cast_const())?;
        if stop_rip_adjust != 0 {
            let context = kernel.thread_user_context(thread_id)?;
            let mut regs = context.to_guest_x64_regs();
            regs.rip = regs
                .rip
                .checked_sub(stop_rip_adjust)
                .ok_or(ZX_ERR_BAD_STATE)?;
            kernel.replace_thread_guest_context(thread_id, &regs)?;
        }
        let context = kernel.thread_user_context(thread_id)?;
        let stop_seq = session.stop_seq.saturating_add(1);
        let stop_state = ax_guest_stop_state_t {
            version: AX_GUEST_STOP_STATE_V1,
            arch: AX_GUEST_ARCH_X86_64,
            stop_reason: AX_GUEST_STOP_REASON_X64_SYSCALL,
            stop_seq,
            regs: context.to_guest_x64_regs(),
        };
        kernel.park_current(crate::task::WaitRegistration::Sleep, None)?;
        let disposition = kernel.finish_trap_exit(trap, cpu_frame, false)?;
        let lifecycle_dirty = kernel.take_task_lifecycle_dirty();
        Ok((stop_seq, stop_state, disposition, lifecycle_dirty))
    })?;
    let encoded = stop_state.encode();
    state.with_vm_mut(|vm| vm.write_vmo_bytes(&session.sidecar_vmo, 0, &encoded))?;
    state.with_objects_mut(|objects| {
        let Some(KernelObject::GuestSession(session)) = objects.get_mut(session_key) else {
            return Err(ZX_ERR_BAD_STATE);
        };
        if session.stopped_seq.is_some() {
            return Err(ZX_ERR_BAD_STATE);
        }
        session.stop_seq = stop_seq;
        session.stopped_seq = Some(stop_seq);
        Ok(())
    })?;
    queue_stop_packet(state, &session, stop_seq)?;

    if lifecycle_dirty {
        sync_task_lifecycle(state)?;
    }
    Ok(match disposition {
        crate::task::TrapExitDisposition::Complete => TrapBlock::Ready(true),
        crate::task::TrapExitDisposition::BlockCurrent => TrapBlock::BlockCurrent,
    })
}

fn finish_guest_trap_resume(
    state: &KernelState,
    trap: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *mut u64,
    resuming_blocked_current: bool,
) -> Result<TrapBlock<bool>, zx_status_t> {
    let disposition = state.with_kernel_mut(|kernel| {
        kernel.finish_trap_exit(trap, cpu_frame, resuming_blocked_current)
    })?;
    let lifecycle_dirty = state.with_kernel_mut(|kernel| Ok(kernel.take_task_lifecycle_dirty()))?;
    if lifecycle_dirty {
        sync_task_lifecycle(state)?;
    }
    Ok(match disposition {
        crate::task::TrapExitDisposition::Complete => TrapBlock::Ready(true),
        crate::task::TrapExitDisposition::BlockCurrent => TrapBlock::BlockCurrent,
    })
}

fn is_syscall_invalid_opcode(cpu_frame: *const u64) -> Result<bool, zx_status_t> {
    if cpu_frame.is_null() {
        return Err(ZX_ERR_BAD_STATE);
    }
    // SAFETY: x86_64 #UD without an error code saves the user IRET frame as
    // {rip, cs, rflags, rsp, ss}; `cpu_frame` points to the first slot.
    let rip = unsafe { *cpu_frame };
    crate::userspace::ensure_user_range_resident(rip, X64_SYSCALL_INSN.len(), false)?;
    let mut bytes = [0u8; X64_SYSCALL_INSN.len()];
    crate::userspace::read_validated_user_bytes(rip, &mut bytes);
    Ok(bytes == X64_SYSCALL_INSN)
}

fn queue_stop_packet(
    state: &KernelState,
    session: &GuestSessionObject,
    stop_seq: u64,
) -> Result<(), zx_status_t> {
    let packet = Packet::user_with_data(
        session.packet_key,
        0,
        [stop_seq, u64::from(AX_GUEST_STOP_REASON_X64_SYSCALL), 0, 0],
    );
    state.with_objects_mut(|objects| {
        let Some(KernelObject::Port(port)) = objects.get_mut(session.port_object) else {
            return Err(ZX_ERR_BAD_STATE);
        };
        port.queue_user(packet).map_err(map_port_error)
    })?;
    publish_object_signals(state, session.port_object)
}
