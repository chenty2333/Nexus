//! Trap-facing fault bridge and current-process user-range residency helpers.

extern crate alloc;

use axle_types::status::{ZX_ERR_INVALID_ARGS, ZX_ERR_OUT_OF_RANGE};
use axle_types::zx_status_t;

fn fault_block_trace_flags(
    key: crate::task::fault::FaultInFlightKey,
    wake_thread: Option<u64>,
) -> u64 {
    let key_kind = match key {
        crate::task::fault::FaultInFlightKey::LocalPage { .. } => 0_u64,
        crate::task::fault::FaultInFlightKey::SharedVmoPage { .. } => 1_u64,
    };
    key_kind | (u64::from(u8::from(wake_thread.is_some())) << 8)
}

fn fault_resume_trace_args(
    key: crate::task::fault::FaultInFlightKey,
    thread_id: u64,
) -> (u64, u64) {
    match key {
        crate::task::fault::FaultInFlightKey::LocalPage {
            address_space_id,
            page_base,
        } => (page_base, thread_id | (address_space_id << 32)),
        crate::task::fault::FaultInFlightKey::SharedVmoPage {
            global_vmo_id,
            page_offset,
        } => (
            page_offset,
            thread_id | (global_vmo_id.raw() << 32) | (1_u64 << 63),
        ),
    }
}

/// Validate a user pointer against the current thread's address-space policy.
pub fn validate_current_user_ptr(ptr: u64, len: usize) -> bool {
    let Ok(valid) = crate::object::with_state_mut(|state| {
        let address_space_id = state.with_kernel(|kernel| kernel.current_address_space_id())?;
        state.with_vm_mut(|vm| Ok(vm.validate_user_ptr(address_space_id, ptr, len)))
    }) else {
        return false;
    };
    valid
}

/// Ensure the current thread's user range is resident before raw kernel access.
pub fn ensure_current_user_range_resident(
    ptr: u64,
    len: usize,
    for_write: bool,
) -> Result<(), zx_status_t> {
    if len == 0 {
        return Ok(());
    }

    let page_bytes = crate::userspace::USER_PAGE_BYTES;
    let start = ptr - (ptr % page_bytes);
    let end = ptr
        .checked_add(len as u64)
        .and_then(|limit| {
            let rem = limit % page_bytes;
            if rem == 0 {
                Some(limit)
            } else {
                limit.checked_add(page_bytes - rem)
            }
        })
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;

    crate::object::with_state_mut(|state| {
        let address_space_id = state.with_kernel(|kernel| kernel.current_address_space_id())?;
        if !state.with_vm_mut(|vm| Ok(vm.validate_user_ptr(address_space_id, ptr, len)))? {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let mut page_va = start;
        while page_va < end {
            state.with_vm_mut(|vm| {
                vm.ensure_user_page_resident_serialized(address_space_id, page_va, for_write)
            })?;
            page_va = page_va.checked_add(page_bytes).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        }
        Ok(())
    })
}

/// Try to resolve a bootstrap user-mode page fault.
pub fn handle_page_fault(
    trap: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *mut u64,
    cr2: u64,
    error: u64,
) -> bool {
    crate::trace::record_fault_enter(cr2, error);
    // SAFETY: x86_64 faults with an error code place that code at `cpu_frame[0]`,
    // followed by the user IRET frame {rip, cs, rflags, rsp, ss}. The generic
    // trap-exit/context helpers expect a pointer to the first IRET slot.
    let user_cpu_frame = unsafe { cpu_frame.add(1) };
    let kernel_handle = match crate::object::kernel_handle() {
        Ok(kernel) => kernel,
        Err(_) => return false,
    };

    crate::object::run_trap_blocking(|resuming_blocked_current| {
        if resuming_blocked_current {
            return crate::object::with_state_mut(|state| {
                let disposition = state.with_kernel_mut(|kernel| {
                    kernel.finish_trap_exit(trap, user_cpu_frame, true)
                })?;
                let lifecycle_dirty =
                    state.with_kernel_mut(|kernel| Ok(kernel.take_task_lifecycle_dirty()))?;
                if lifecycle_dirty {
                    crate::object::sync_task_lifecycle(state)?;
                }
                Ok(match disposition {
                    crate::task::TrapExitDisposition::Complete => {
                        crate::object::TrapBlock::Ready(true)
                    }
                    crate::task::TrapExitDisposition::BlockCurrent => {
                        crate::object::TrapBlock::BlockCurrent
                    }
                })
            });
        }

        let (thread_id, address_space_id) = crate::object::with_state_mut(|state| {
            let thread_id =
                state.with_kernel(|kernel| Ok(kernel.current_thread_info()?.thread_id()))?;
            let address_space_id = state.with_kernel(|kernel| kernel.current_address_space_id())?;
            Ok((thread_id, address_space_id))
        })?;

        let result = crate::object::with_state_mut(|state| {
            state.with_vm_mut(|vm| {
                Ok(vm.handle_page_fault_serialized(
                    kernel_handle.clone(),
                    address_space_id,
                    thread_id,
                    cr2,
                    error,
                ))
            })
        })?;

        match result {
            crate::task::fault::PageFaultSerializedResult::Handled => {
                crate::trace::record_fault_handled(cr2, error);
                let cpu_id = crate::arch::apic::this_apic_id() as usize;
                let _ = crate::object::with_state_mut(|state| {
                    state.with_vm_mut(|vm| vm.sync_current_cpu_tlb_state(address_space_id, cpu_id))
                });
                Ok(crate::object::TrapBlock::Ready(true))
            }
            crate::task::fault::PageFaultSerializedResult::Unhandled => {
                crate::trace::record_fault_unhandled(cr2, error);
                Ok(crate::object::TrapBlock::Ready(false))
            }
            crate::task::fault::PageFaultSerializedResult::BlockCurrent { key, wake_thread } => {
                crate::trace::record_fault_block(cr2, fault_block_trace_flags(key, wake_thread));
                crate::object::with_state_mut(|state| {
                    let (disposition, lifecycle_dirty) = state.with_kernel_mut(|kernel| {
                        kernel.capture_current_user_context(trap, user_cpu_frame.cast_const())?;
                        kernel
                            .park_current(crate::task::WaitRegistration::VmFault { key }, None)?;
                        if let Some(thread_id) = wake_thread {
                            let (arg0, arg1) = fault_resume_trace_args(key, thread_id);
                            crate::trace::record_fault_resume(arg0, arg1);
                            kernel
                                .wake_thread(thread_id, crate::task::WakeReason::PreserveContext)?;
                        }
                        let disposition = kernel.finish_trap_exit(trap, user_cpu_frame, false)?;
                        let lifecycle_dirty = kernel.take_task_lifecycle_dirty();
                        Ok((disposition, lifecycle_dirty))
                    })?;
                    if lifecycle_dirty {
                        crate::object::sync_task_lifecycle(state)?;
                    }
                    Ok(match disposition {
                        crate::task::TrapExitDisposition::Complete => {
                            crate::object::TrapBlock::Ready(true)
                        }
                        crate::task::TrapExitDisposition::BlockCurrent => {
                            crate::object::TrapBlock::BlockCurrent
                        }
                    })
                })
            }
        }
    })
    .unwrap_or(false)
}

/// Try to route one user-mode invalid-opcode trap into the generic guest-stop
/// supervision path.
pub fn handle_invalid_opcode(
    trap: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *mut u64,
) -> bool {
    crate::object::run_trap_blocking(|resuming_blocked_current| {
        crate::object::with_state_mut(|state| {
            crate::object::guest::handle_invalid_opcode_trap(
                state,
                trap,
                cpu_frame,
                resuming_blocked_current,
            )
        })
    })
    .unwrap_or(false)
}
