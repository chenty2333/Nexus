//! Wait/reactor/timer slice for blocking waits, async waits, and timer-driven wakeups.

extern crate alloc;

use crate::object::{self, KernelObject};
use crate::port_queue::port_packet_from_core;
use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec::Vec;
use axle_core::{ObjectKey, Packet, Signals, WaitAsyncOptions, WaitAsyncRegistration};
use axle_types::packet::ZX_PKT_TYPE_USER;
use axle_types::status::{
    ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_STATE, ZX_ERR_INVALID_ARGS, ZX_ERR_SHOULD_WAIT, ZX_ERR_TIMED_OUT,
    ZX_ERR_WRONG_TYPE, ZX_OK,
};
use axle_types::{zx_handle_t, zx_port_packet_t, zx_signals_t, zx_status_t};

#[derive(Clone, Copy, Debug)]
pub(crate) struct UserSignalsSink(u64);

impl UserSignalsSink {
    pub(crate) fn new(ptr: *mut zx_signals_t) -> Result<Self, zx_status_t> {
        if ptr.is_null() {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        Ok(Self(ptr as u64))
    }

    pub(crate) const fn ptr(self) -> *mut zx_signals_t {
        self.0 as *mut zx_signals_t
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct UserPortPacketSink(u64);

impl UserPortPacketSink {
    pub(crate) fn new(ptr: *mut zx_port_packet_t) -> Result<Self, zx_status_t> {
        if ptr.is_null() {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        Ok(Self(ptr as u64))
    }

    pub(crate) const fn ptr(self) -> *mut zx_port_packet_t {
        self.0 as *mut zx_port_packet_t
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitOneOutcome {
    Completed { observed: zx_signals_t },
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PortWaitOutcome {
    Completed { packet: zx_port_packet_t },
    Resumed,
    Blocked,
}

fn queue_kernel_signal_packet(
    state: &object::KernelState,
    port_key: ObjectKey,
    packet: Packet,
) -> bool {
    let queued = state
        .with_registry_mut(|registry| {
            let Some(KernelObject::Port(port)) = registry.get_mut(port_key) else {
                return Ok(false);
            };
            Ok(port.queue_kernel(packet).is_ok())
        })
        .unwrap_or(false);
    queued
}

fn pop_port_packet_locked(
    state: &object::KernelState,
    port_key: ObjectKey,
) -> Result<Packet, zx_status_t> {
    let packet = state.with_registry_mut(|registry| {
        let Some(KernelObject::Port(port)) = registry.get_mut(port_key) else {
            return Err(ZX_ERR_BAD_STATE);
        };
        port.pop().map_err(object::map_port_error)
    })?;
    state.with_reactor_mut(|reactor| {
        reactor
            .observers_mut()
            .flush_port(port_key, |target_port_id, pending| {
                queue_kernel_signal_packet(state, target_port_id, pending)
            });
        Ok(())
    })?;
    Ok(packet)
}

fn port_current_signals(
    state: &object::KernelState,
    port_key: ObjectKey,
) -> Result<Signals, zx_status_t> {
    state.with_registry(|registry| {
        let Some(KernelObject::Port(port)) = registry.get(port_key) else {
            return Err(ZX_ERR_BAD_STATE);
        };
        Ok(port.signals())
    })
}

fn publish_port_signals_changed(
    state: &object::KernelState,
    port_key: ObjectKey,
) -> Result<(), zx_status_t> {
    let current = port_current_signals(state, port_key)?;
    publish_signals_changed(state, port_key, current)
}

fn require_port_object(
    state: &object::KernelState,
    object_key: ObjectKey,
) -> Result<(), zx_status_t> {
    state.with_registry(|registry| {
        let obj = registry.get(object_key).ok_or(ZX_ERR_BAD_HANDLE)?;
        match obj {
            KernelObject::Port(_) => Ok(()),
            KernelObject::Job(_)
            | KernelObject::Process(_)
            | KernelObject::SuspendToken(_)
            | KernelObject::GuestSession(_)
            | KernelObject::Socket(_)
            | KernelObject::Channel(_)
            | KernelObject::EventPair(_)
            | KernelObject::Timer(_)
            | KernelObject::Interrupt(_)
            | KernelObject::DmaRegion(_)
            | KernelObject::PciDevice(_)
            | KernelObject::RevocationGroup(_)
            | KernelObject::Thread(_)
            | KernelObject::Vmo(_)
            | KernelObject::Vmar(_) => Err(ZX_ERR_WRONG_TYPE),
        }
    })
}

fn queue_user_port_packet(
    state: &object::KernelState,
    object_key: ObjectKey,
    packet: Packet,
) -> Result<(), zx_status_t> {
    let result = state.with_registry_mut(|registry| {
        let obj = registry.get_mut(object_key).ok_or(ZX_ERR_BAD_HANDLE)?;
        let port = match obj {
            KernelObject::Port(port) => port,
            KernelObject::Job(_)
            | KernelObject::Process(_)
            | KernelObject::SuspendToken(_)
            | KernelObject::GuestSession(_)
            | KernelObject::Socket(_)
            | KernelObject::Channel(_)
            | KernelObject::EventPair(_)
            | KernelObject::Timer(_)
            | KernelObject::Interrupt(_)
            | KernelObject::DmaRegion(_)
            | KernelObject::PciDevice(_)
            | KernelObject::RevocationGroup(_)
            | KernelObject::Thread(_)
            | KernelObject::Vmo(_)
            | KernelObject::Vmar(_) => return Err(ZX_ERR_WRONG_TYPE),
        };
        port.queue_user(packet).map_err(object::map_port_error)
    });
    result
}

/// Queue a user packet into a port.
pub fn queue_port_packet(handle: zx_handle_t, packet: zx_port_packet_t) -> Result<(), zx_status_t> {
    if packet.type_ != ZX_PKT_TYPE_USER {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    object::with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_key = resolved.object_key();
        object::require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;
        let pkt = Packet::user_with_data(packet.key, packet.status, packet.user.u64);
        queue_user_port_packet(state, object_key, pkt)?;

        publish_port_signals_changed(state, object_key)
    })
}

/// Wait for a packet on a port until `deadline`.
///
/// - `deadline == 0`: non-blocking poll; returns `ZX_ERR_SHOULD_WAIT` if empty.
/// - `deadline == i64::MAX`: wait forever.
pub fn port_wait(
    handle: zx_handle_t,
    deadline: i64,
    sink: UserPortPacketSink,
) -> Result<PortWaitOutcome, zx_status_t> {
    object::with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_key = resolved.object_key();
        require_port_object(state, object_key)?;
        object::require_handle_rights(resolved, crate::task::HandleRights::READ)?;
        let packet = pop_port_packet_locked(state, object_key);

        match packet {
            Ok(packet) => {
                let packet = port_packet_from_core(packet);
                publish_port_signals_changed(state, object_key)?;
                Ok(PortWaitOutcome::Completed { packet })
            }
            Err(ZX_ERR_SHOULD_WAIT) => {
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
                        let packet = pop_port_packet_locked(state, object_key);
                        return match packet {
                            Ok(packet) => {
                                let packet = port_packet_from_core(packet);
                                publish_port_signals_changed(state, object_key)?;
                                Ok(PortWaitOutcome::Completed { packet })
                            }
                            Err(ZX_ERR_SHOULD_WAIT) => Err(ZX_ERR_TIMED_OUT),
                            Err(err) => Err(err),
                        };
                    }
                    Some(deadline)
                };
                let (thread_id, wait_seq) = state.with_kernel_mut(|kernel| {
                    let thread_id = kernel.current_thread_info()?.thread_id();
                    let wait_seq = kernel.park_current_with_seq(
                        crate::task::WaitRegistration::Port {
                            port_object: object_key,
                            packet_ptr: sink.raw(),
                            revocation: axle_core::RevocationSet::one(resolved.revocation_ref()),
                        },
                        deadline,
                    )?;
                    Ok((thread_id, wait_seq))
                })?;
                match pop_port_packet_locked(state, object_key) {
                    Ok(packet) => {
                        let _ = state.with_kernel_mut(|kernel| {
                            kernel.cancel_waiter_if_seq(thread_id, wait_seq)
                        })?;
                        let packet = port_packet_from_core(packet);
                        publish_port_signals_changed(state, object_key)?;
                        Ok(PortWaitOutcome::Completed { packet })
                    }
                    Err(ZX_ERR_SHOULD_WAIT) => {
                        let still_waiting = state.with_kernel(|kernel| {
                            let registration = kernel.thread_wait_registration(thread_id)?;
                            let seq = kernel.thread_wait_seq(thread_id)?;
                            Ok(matches!(
                                registration,
                                Some(crate::task::WaitRegistration::Port { port_object, .. })
                                    if port_object == object_key
                            ) && seq == Some(wait_seq))
                        })?;
                        if still_waiting {
                            Ok(PortWaitOutcome::Blocked)
                        } else {
                            Ok(PortWaitOutcome::Resumed)
                        }
                    }
                    Err(err) => {
                        let canceled = state.with_kernel_mut(|kernel| {
                            kernel.cancel_waiter_if_seq(thread_id, wait_seq)
                        })?;
                        if canceled {
                            Err(err)
                        } else {
                            Ok(PortWaitOutcome::Resumed)
                        }
                    }
                }
            }
            Err(err) => Err(err),
        }
    })
}

/// Wait for one of the specified signals on a waitable object.
pub fn object_wait_one(
    handle: zx_handle_t,
    watched: zx_signals_t,
    deadline: i64,
    sink: UserSignalsSink,
) -> Result<WaitOneOutcome, zx_status_t> {
    let watched = Signals::from_bits(watched);
    if watched.is_empty() {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    object::with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WAIT)?;
        let object_key = resolved.object_key();
        let observed = object::signals_for_object_id(state, object_key)?;
        if observed.intersects(watched) {
            return Ok(WaitOneOutcome::Completed {
                observed: observed.bits(),
            });
        }

        if deadline != i64::MAX && deadline <= crate::time::now_ns() {
            let _ = on_tick_locked(state);
            let observed = object::signals_for_object_id(state, object_key)?;
            if observed.intersects(watched) {
                return Ok(WaitOneOutcome::Completed {
                    observed: observed.bits(),
                });
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
                    object_key,
                    watched,
                    observed_ptr: sink.raw(),
                    revocation: axle_core::RevocationSet::one(resolved.revocation_ref()),
                },
                deadline,
            )
        })?;
        Ok(WaitOneOutcome::Blocked)
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
        let waitable_key = waitable.object_key();
        let port_key = resolved_port.object_key();

        let current = object::signals_for_object_id(state, waitable_key)?;
        let watched = Signals::from_bits(signals);
        let now = crate::time::now_ns();

        require_port_object(state, port_key)?;
        object::require_handle_rights(resolved_port, crate::task::HandleRights::WRITE)?;
        state.with_reactor_mut(|reactor| {
            reactor
                .observers_mut()
                .wait_async(
                    WaitAsyncRegistration {
                        port: port_key,
                        waitable: waitable_key,
                        revocation: axle_core::RevocationSet::pair(
                            waitable.revocation_ref(),
                            resolved_port.revocation_ref(),
                        ),
                        key,
                        watched,
                        options,
                    },
                    current,
                    now,
                    |target_port_id, packet| {
                        queue_kernel_signal_packet(state, target_port_id, packet)
                    },
                )
                .map_err(object::map_port_error)
        })?;

        publish_port_signals_changed(state, port_key)
    })
}

/// Called from the timer interrupt handler.
///
/// Fires due timers and notifies `wait_async` observers.
pub fn on_tick() {
    let _ = object::with_state_mut(|state| on_tick_locked(state));
}

fn on_tick_locked(state: &object::KernelState) -> Result<(), zx_status_t> {
    let now = crate::time::now_ns();
    let polled = state.with_kernel_mut(|kernel| Ok(kernel.poll_reactor(now)))?;
    for event in polled.into_events() {
        match event {
            crate::task::ReactorPollEvent::TimerFired(timer_id) => {
                object::publish_timer_fired(state, timer_id)?;
            }
            crate::task::ReactorPollEvent::WaitExpired(expired_wait) => {
                wake_expired_waits(state, alloc::vec![expired_wait])?;
            }
        }
    }
    let _ = state.with_kernel_mut(|kernel| kernel.sync_current_cpu_tlb_state());
    Ok(())
}

pub(crate) fn publish_signals_changed(
    state: &object::KernelState,
    waitable_key: ObjectKey,
    current: Signals,
) -> Result<(), zx_status_t> {
    const MAX_PROPAGATION_DEPTH: usize = 1024;

    let mut pending = VecDeque::from([(waitable_key, current)]);
    let mut queued = BTreeSet::from([waitable_key]);
    let mut iterations = 0usize;

    while let Some((current_waitable_key, current)) = pending.pop_front() {
        iterations += 1;
        if iterations > MAX_PROPAGATION_DEPTH {
            crate::kprintln!(
                "warn: signal propagation exceeded {} iterations, stopping",
                MAX_PROPAGATION_DEPTH
            );
            break;
        }
        let _ = queued.remove(&current_waitable_key);
        let now = crate::time::now_ns();
        wake_signal_waiters(state, current_waitable_key, current)?;

        let changed_ports = state.with_reactor_mut(|reactor| {
            Ok(reactor.observers_mut().on_signals_changed(
                current_waitable_key,
                current,
                now,
                |port_id, packet| queue_kernel_signal_packet(state, port_id, packet),
            ))
        })?;

        if state.with_registry(|registry| {
            Ok(matches!(
                registry.get(current_waitable_key),
                Some(KernelObject::Port(_))
            ))
        })? {
            wake_port_waiters(state, current_waitable_key)?;
            let refreshed = port_current_signals(state, current_waitable_key)?;
            if refreshed != current && queued.insert(current_waitable_key) {
                pending.push_back((current_waitable_key, refreshed));
            }
        }

        for port_id in changed_ports {
            let current = port_current_signals(state, port_id)?;
            if queued.insert(port_id) {
                pending.push_back((port_id, current));
            }
        }
    }
    Ok(())
}

fn wake_signal_waiters(
    state: &object::KernelState,
    waitable_key: ObjectKey,
    current: Signals,
) -> Result<(), zx_status_t> {
    let waiters =
        state.with_kernel_mut(|kernel| Ok(kernel.signal_waiters_ready(waitable_key, current)))?;
    for waiter in waiters {
        let status = match state.copyout_thread_user(
            waiter.thread_id(),
            waiter.observed_ptr(),
            current.bits(),
        ) {
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

fn wake_port_waiters(state: &object::KernelState, port_key: ObjectKey) -> Result<(), zx_status_t> {
    let waiters = state.with_kernel_mut(|kernel| Ok(kernel.port_waiters(port_key)))?;
    if waiters.is_empty() {
        return Ok(());
    }

    for waiter in waiters {
        let packet = match pop_port_packet_locked(state, port_key) {
            Ok(packet) => packet,
            Err(ZX_ERR_SHOULD_WAIT) => break,
            Err(err) => {
                state.with_kernel_mut(|kernel| {
                    let _ = kernel.complete_waiter(
                        waiter.thread_id(),
                        waiter.seq(),
                        crate::task::WakeReason::Status(err),
                    )?;
                    Ok(())
                })?;
                continue;
            }
        };
        let packet = port_packet_from_core(packet);
        let status =
            match state.copyout_thread_user(waiter.thread_id(), waiter.packet_ptr(), packet) {
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

fn wake_expired_waits(
    state: &object::KernelState,
    expired: Vec<crate::task::ExpiredWait>,
) -> Result<(), zx_status_t> {
    for expired_wait in expired {
        let thread_id = expired_wait.thread_id();
        let reason = match expired_wait.registration() {
            crate::task::WaitRegistration::Sleep => crate::task::WakeReason::Status(ZX_OK),
            crate::task::WaitRegistration::Signal {
                object_key,
                watched,
                observed_ptr,
                ..
            } => {
                let observed = object::signals_for_object_id(state, object_key)?;
                let status = match state.copyout_thread_user(
                    thread_id,
                    observed_ptr as *mut zx_signals_t,
                    observed.bits(),
                ) {
                    Ok(()) if observed.intersects(watched) => ZX_OK,
                    Ok(()) => ZX_ERR_TIMED_OUT,
                    Err(err) => err,
                };
                crate::task::WakeReason::Status(status)
            }
            crate::task::WaitRegistration::Port {
                port_object,
                packet_ptr,
                ..
            } => {
                let packet = pop_port_packet_locked(state, port_object);
                let status = match packet {
                    Ok(packet) => {
                        let packet = port_packet_from_core(packet);
                        let status = match state.copyout_thread_user(
                            thread_id,
                            packet_ptr as *mut zx_port_packet_t,
                            packet,
                        ) {
                            Ok(()) => ZX_OK,
                            Err(err) => err,
                        };
                        let _ = publish_port_signals_changed(state, port_object);
                        status
                    }
                    Err(ZX_ERR_SHOULD_WAIT) => ZX_ERR_TIMED_OUT,
                    Err(err) => err,
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
