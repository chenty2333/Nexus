//! Wait/reactor/timer slice for blocking waits, async waits, and timer-driven wakeups.

extern crate alloc;

use alloc::vec::Vec;

use axle_core::{Packet, PortError, Signals, WaitAsyncOptions};
use axle_types::packet::ZX_PKT_TYPE_USER;
use axle_types::status::{
    ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_STATE, ZX_ERR_INVALID_ARGS, ZX_ERR_SHOULD_WAIT, ZX_ERR_TIMED_OUT,
    ZX_ERR_WRONG_TYPE, ZX_OK,
};
use axle_types::{zx_handle_t, zx_port_packet_t, zx_signals_t, zx_status_t};

use crate::object::{self, KernelObject};
use crate::port_queue::port_packet_from_core;

/// Queue a user packet into a port.
pub fn queue_port_packet(handle: zx_handle_t, packet: zx_port_packet_t) -> Result<(), zx_status_t> {
    if packet.type_ != ZX_PKT_TYPE_USER {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    object::with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_id = resolved.object_id();
        {
            let obj = state.objects.get_mut(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;
            let port = match obj {
                KernelObject::Port(port) => port,
                KernelObject::Process(_)
                | KernelObject::SuspendToken(_)
                | KernelObject::Socket(_)
                | KernelObject::Channel(_)
                | KernelObject::EventPair(_)
                | KernelObject::Timer(_)
                | KernelObject::Thread(_)
                | KernelObject::Vmo(_)
                | KernelObject::Vmar(_) => {
                    return Err(ZX_ERR_WRONG_TYPE);
                }
            };
            object::require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;

            let pkt = Packet::user_with_data(packet.key, packet.status, packet.user.u64);
            port.queue_user(pkt).map_err(object::map_port_error)?;
        }

        let _ = notify_waitable_signals_changed(state, object_id);
        Ok(())
    })
}

/// Pop one packet from a port queue.
pub fn wait_port_packet(handle: zx_handle_t) -> Result<zx_port_packet_t, zx_status_t> {
    object::with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_id = resolved.object_id();
        let pkt = {
            let obj = state.objects.get_mut(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;
            let port = match obj {
                KernelObject::Port(port) => port,
                KernelObject::Process(_)
                | KernelObject::SuspendToken(_)
                | KernelObject::Socket(_)
                | KernelObject::Channel(_)
                | KernelObject::EventPair(_)
                | KernelObject::Timer(_)
                | KernelObject::Thread(_)
                | KernelObject::Vmo(_)
                | KernelObject::Vmar(_) => {
                    return Err(ZX_ERR_WRONG_TYPE);
                }
            };
            object::require_handle_rights(resolved, crate::task::HandleRights::READ)?;
            port.pop().map_err(object::map_port_error)?
        };

        let _ = notify_waitable_signals_changed(state, object_id);
        Ok(port_packet_from_core(pkt))
    })
}

/// Wait for a packet on a port until `deadline`.
///
/// - `deadline == 0`: non-blocking poll; returns `ZX_ERR_SHOULD_WAIT` if empty.
/// - `deadline == i64::MAX`: wait forever.
pub fn port_wait(
    handle: zx_handle_t,
    deadline: i64,
    out_ptr: *mut zx_port_packet_t,
) -> Result<(), zx_status_t> {
    object::with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_id = resolved.object_id();
        let thread_id = state
            .with_kernel(|kernel| kernel.current_thread_info())?
            .thread_id();
        let packet = {
            let obj = state.objects.get_mut(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;
            let port = match obj {
                KernelObject::Port(port) => port,
                KernelObject::Process(_)
                | KernelObject::SuspendToken(_)
                | KernelObject::Socket(_)
                | KernelObject::Channel(_)
                | KernelObject::EventPair(_)
                | KernelObject::Timer(_)
                | KernelObject::Thread(_)
                | KernelObject::Vmo(_)
                | KernelObject::Vmar(_) => {
                    return Err(ZX_ERR_WRONG_TYPE);
                }
            };
            object::require_handle_rights(resolved, crate::task::HandleRights::READ)?;
            port.pop()
        };

        match packet {
            Ok(packet) => {
                let packet = port_packet_from_core(packet);
                state.with_kernel_mut(|kernel| {
                    kernel.copyout_thread_user(thread_id, out_ptr, packet)
                })?;
                let _ = notify_waitable_signals_changed(state, object_id);
                Ok(())
            }
            Err(PortError::ShouldWait) => {
                if deadline == 0 {
                    return Err(ZX_ERR_SHOULD_WAIT);
                }
                object::require_handle_rights(resolved, crate::task::HandleRights::WAIT)?;
                let deadline = if deadline == i64::MAX {
                    None
                } else {
                    let now = crate::time::now_ns();
                    if deadline <= now {
                        let _ = on_tick_locked(state);
                        let packet = {
                            let obj = state.objects.get_mut(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;
                            let port = match obj {
                                KernelObject::Port(port) => port,
                                KernelObject::Process(_)
                                | KernelObject::SuspendToken(_)
                                | KernelObject::Socket(_)
                                | KernelObject::Channel(_)
                                | KernelObject::EventPair(_)
                                | KernelObject::Timer(_)
                                | KernelObject::Thread(_)
                                | KernelObject::Vmo(_)
                                | KernelObject::Vmar(_) => {
                                    return Err(ZX_ERR_WRONG_TYPE);
                                }
                            };
                            port.pop()
                        };
                        return match packet {
                            Ok(packet) => {
                                let packet = port_packet_from_core(packet);
                                state.with_kernel_mut(|kernel| {
                                    kernel.copyout_thread_user(thread_id, out_ptr, packet)
                                })?;
                                let _ = notify_waitable_signals_changed(state, object_id);
                                Ok(())
                            }
                            Err(PortError::ShouldWait) => Err(ZX_ERR_TIMED_OUT),
                            Err(err) => Err(object::map_port_error(err)),
                        };
                    }
                    Some(deadline)
                };
                state.with_kernel_mut(|kernel| {
                    kernel.park_current(
                        crate::task::WaitRegistration::Port {
                            port_object_id: object_id,
                            packet_ptr: out_ptr as u64,
                        },
                        deadline,
                    )
                })?;
                Ok(())
            }
            Err(err) => Err(object::map_port_error(err)),
        }
    })
}

/// Wait for one of the specified signals on a waitable object.
pub fn object_wait_one(
    handle: zx_handle_t,
    watched: zx_signals_t,
    deadline: i64,
    observed_ptr: *mut zx_signals_t,
) -> Result<(), zx_status_t> {
    let watched = Signals::from_bits(watched);
    if watched.is_empty() {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    object::with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WAIT)?;
        let object_id = resolved.object_id();
        let observed = object::signals_for_object_id(state, object_id)?;
        let thread_id = state
            .with_kernel(|kernel| kernel.current_thread_info())?
            .thread_id();
        if observed.intersects(watched) {
            state.with_kernel_mut(|kernel| {
                kernel.copyout_thread_user(thread_id, observed_ptr, observed.bits())
            })?;
            return Ok(());
        }

        if deadline != i64::MAX && deadline <= crate::time::now_ns() {
            let _ = on_tick_locked(state);
            let observed = object::signals_for_object_id(state, object_id)?;
            state.with_kernel_mut(|kernel| {
                kernel.copyout_thread_user(thread_id, observed_ptr, observed.bits())
            })?;
            if observed.intersects(watched) {
                return Ok(());
            }
            return Err(ZX_ERR_TIMED_OUT);
        }

        let deadline = if deadline == i64::MAX {
            None
        } else {
            Some(deadline)
        };
        state.with_kernel_mut(|kernel| {
            kernel.park_current(
                crate::task::WaitRegistration::Signal {
                    object_id,
                    watched,
                    observed_ptr: observed_ptr as u64,
                },
                deadline,
            )
        })?;
        Ok(())
    })
}

#[allow(dead_code)]
pub(crate) fn sleep_until(deadline: i64) -> Result<(), zx_status_t> {
    if deadline <= crate::time::now_ns() {
        return Ok(());
    }
    object::with_state_mut(|state| {
        state.with_kernel_mut(|kernel| {
            kernel.park_current(crate::task::WaitRegistration::Sleep, Some(deadline))
        })
    })
}

/// Register a one-shot async wait and deliver a signal packet into `port` when fired.
pub fn object_wait_async(
    waitable: zx_handle_t,
    port_handle: zx_handle_t,
    key: u64,
    signals: zx_signals_t,
    options: WaitAsyncOptions,
) -> Result<(), zx_status_t> {
    if signals == 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    object::with_state_mut(|state| {
        let waitable = state.lookup_handle(waitable, crate::task::HandleRights::WAIT)?;
        let resolved_port = state.lookup_handle(port_handle, crate::task::HandleRights::empty())?;
        let waitable_id = waitable.object_id();
        let port_id = resolved_port.object_id();

        let current = object::signals_for_object_id(state, waitable_id)?;
        let watched = Signals::from_bits(signals);
        let now = crate::time::now_ns();

        {
            let obj = state.objects.get_mut(&port_id).ok_or(ZX_ERR_BAD_HANDLE)?;
            let port = match obj {
                KernelObject::Port(port) => port,
                KernelObject::Process(_)
                | KernelObject::SuspendToken(_)
                | KernelObject::Socket(_)
                | KernelObject::Channel(_)
                | KernelObject::EventPair(_)
                | KernelObject::Timer(_)
                | KernelObject::Thread(_)
                | KernelObject::Vmo(_)
                | KernelObject::Vmar(_) => {
                    return Err(ZX_ERR_WRONG_TYPE);
                }
            };
            object::require_handle_rights(resolved_port, crate::task::HandleRights::WRITE)?;
            port.wait_async(waitable_id, key, watched, options, current, now)
                .map_err(object::map_port_error)?;
        }

        let _ = notify_waitable_signals_changed(state, port_id);
        Ok(())
    })
}

/// Called from the timer interrupt handler.
///
/// Fires due timers and notifies `wait_async` observers.
pub fn on_tick() {
    let _ = object::with_state_mut(|state| on_tick_locked(state));
}

fn on_tick_locked(state: &mut object::KernelState) -> Result<(), zx_status_t> {
    let now = crate::time::now_ns();
    let fired = poll_due_timers_at(state, now);
    for fired_object_id in fired {
        let _ = notify_waitable_signals_changed(state, fired_object_id);
    }
    wake_expired_waits(state, now)?;
    let _ = state.with_kernel_mut(|kernel| kernel.sync_current_cpu_tlb_state());
    Ok(())
}

pub(crate) fn notify_waitable_signals_changed(
    state: &mut object::KernelState,
    waitable_id: u64,
) -> Result<(), zx_status_t> {
    let current = object::signals_for_object_id(state, waitable_id)?;
    let now = crate::time::now_ns();
    wake_signal_waiters(state, waitable_id, current)?;

    let port_ids: Vec<u64> = state
        .objects
        .iter()
        .filter_map(|(id, obj)| matches!(obj, KernelObject::Port(_)).then_some(*id))
        .collect();

    for port_id in port_ids {
        {
            let Some(KernelObject::Port(port)) = state.objects.get_mut(&port_id) else {
                continue;
            };
            port.on_signals_changed(waitable_id, current, now);
        }
        wake_port_waiters(state, port_id)?;
    }
    if matches!(state.objects.get(&waitable_id), Some(KernelObject::Port(_))) {
        wake_port_waiters(state, waitable_id)?;
    }
    Ok(())
}

fn wake_signal_waiters(
    state: &mut object::KernelState,
    waitable_id: u64,
    current: Signals,
) -> Result<(), zx_status_t> {
    let waiters =
        state.with_kernel_mut(|kernel| Ok(kernel.signal_waiters_ready(waitable_id, current)))?;
    for waiter in waiters {
        let status = match state.with_kernel_mut(|kernel| {
            kernel.copyout_thread_user(waiter.thread_id(), waiter.observed_ptr(), current.bits())
        }) {
            Ok(()) => ZX_OK,
            Err(err) => err,
        };
        state.with_kernel_mut(|kernel| {
            let _ = kernel.complete_waiter(
                waiter.thread_id(),
                waiter.seq(),
                crate::task::WakeReason::Status(status),
            )?;
            Ok(())
        })?;
    }
    Ok(())
}

fn wake_port_waiters(state: &mut object::KernelState, port_id: u64) -> Result<(), zx_status_t> {
    let waiters = state.with_kernel_mut(|kernel| Ok(kernel.port_waiters(port_id)))?;
    if waiters.is_empty() {
        return Ok(());
    }

    for waiter in waiters {
        let packet = {
            let Some(KernelObject::Port(port)) = state.objects.get_mut(&port_id) else {
                return Err(ZX_ERR_BAD_STATE);
            };
            match port.pop() {
                Ok(packet) => packet,
                Err(PortError::ShouldWait) => break,
                Err(err) => {
                    state.with_kernel_mut(|kernel| {
                        let _ = kernel.complete_waiter(
                            waiter.thread_id(),
                            waiter.seq(),
                            crate::task::WakeReason::Status(object::map_port_error(err)),
                        )?;
                        Ok(())
                    })?;
                    continue;
                }
            }
        };
        let packet = port_packet_from_core(packet);
        let status = match state.with_kernel_mut(|kernel| {
            kernel.copyout_thread_user(waiter.thread_id(), waiter.packet_ptr(), packet)
        }) {
            Ok(()) => ZX_OK,
            Err(err) => err,
        };
        state.with_kernel_mut(|kernel| {
            let _ = kernel.complete_waiter(
                waiter.thread_id(),
                waiter.seq(),
                crate::task::WakeReason::Status(status),
            )?;
            Ok(())
        })?;
    }
    Ok(())
}

fn wake_expired_waits(state: &mut object::KernelState, now: i64) -> Result<(), zx_status_t> {
    let expired = state.with_kernel_mut(|kernel| Ok(kernel.expire_waits_for_tick(now)))?;
    for expired_wait in expired {
        let thread_id = expired_wait.thread_id();
        let reason = match expired_wait.registration() {
            crate::task::WaitRegistration::Sleep => crate::task::WakeReason::Status(ZX_OK),
            crate::task::WaitRegistration::Signal {
                object_id,
                watched,
                observed_ptr,
            } => {
                let observed = object::signals_for_object_id(state, object_id)?;
                let status = match state.with_kernel_mut(|kernel| {
                    kernel.copyout_thread_user(
                        thread_id,
                        observed_ptr as *mut zx_signals_t,
                        observed.bits(),
                    )
                }) {
                    Ok(()) if observed.intersects(watched) => ZX_OK,
                    Ok(()) => ZX_ERR_TIMED_OUT,
                    Err(err) => err,
                };
                crate::task::WakeReason::Status(status)
            }
            crate::task::WaitRegistration::Port {
                port_object_id,
                packet_ptr,
            } => {
                let packet = {
                    let Some(KernelObject::Port(port)) = state.objects.get_mut(&port_object_id)
                    else {
                        return Err(ZX_ERR_BAD_STATE);
                    };
                    port.pop()
                };
                let status = match packet {
                    Ok(packet) => {
                        let packet = port_packet_from_core(packet);
                        match state.with_kernel_mut(|kernel| {
                            kernel.copyout_thread_user(
                                thread_id,
                                packet_ptr as *mut zx_port_packet_t,
                                packet,
                            )
                        }) {
                            Ok(()) => ZX_OK,
                            Err(err) => err,
                        }
                    }
                    Err(PortError::ShouldWait) => ZX_ERR_TIMED_OUT,
                    Err(err) => object::map_port_error(err),
                };
                crate::task::WakeReason::Status(status)
            }
            crate::task::WaitRegistration::Futex { .. }
            | crate::task::WaitRegistration::VmFault { .. } => {
                crate::task::WakeReason::Status(ZX_ERR_TIMED_OUT)
            }
        };
        state.with_kernel_mut(|kernel| kernel.wake_thread(thread_id, reason))?;
    }
    Ok(())
}

pub(crate) fn poll_due_timers_at(state: &mut object::KernelState, now: i64) -> Vec<u64> {
    let fired = state.timers.poll(now);
    if fired.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for fired_id in fired {
        for (object_id, obj) in state.objects.iter() {
            let KernelObject::Timer(timer) = obj else {
                continue;
            };
            if timer.timer_id == fired_id {
                out.push(*object_id);
            }
        }
    }
    out
}
