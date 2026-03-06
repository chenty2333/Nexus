//! Minimal kernel object table wired through the bootstrap kernel/process model.

extern crate alloc;

use alloc::collections::BTreeMap;

use axle_core::{
    Capability, Packet, PacketKind, Port, PortError, Signals, TimerError, TimerId, TimerService,
    WaitAsyncOptions,
};
use axle_types::clock::ZX_CLOCK_MONOTONIC;
use axle_types::packet::{ZX_PKT_TYPE_SIGNAL_ONE, ZX_PKT_TYPE_USER};
use axle_types::status::{
    ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_STATE, ZX_ERR_INVALID_ARGS,
    ZX_ERR_NOT_FOUND, ZX_ERR_SHOULD_WAIT, ZX_ERR_TIMED_OUT, ZX_ERR_WRONG_TYPE, ZX_OK,
};
use axle_types::{zx_clock_t, zx_handle_t, zx_packet_user_t, zx_port_packet_t, zx_status_t};
use axle_types::{zx_packet_signal_t, zx_signals_t};
use spin::Mutex;

const PORT_CAPACITY: usize = 64;
const PORT_KERNEL_RESERVE: usize = 16;
const DEFAULT_OBJECT_GENERATION: u32 = 0;

/// Kernel object kinds needed in current phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// Port object.
    Port,
    /// Timer object.
    Timer,
}

#[derive(Debug)]
struct TimerObject {
    timer_id: TimerId,
    clock_id: zx_clock_t,
}

#[derive(Debug)]
enum KernelObject {
    Port(Port),
    Timer(TimerObject),
}

#[derive(Debug)]
struct KernelState {
    kernel: crate::task::Kernel,
    objects: BTreeMap<u64, KernelObject>,
    next_object_id: u64,
    timers: TimerService,
}

impl KernelState {
    fn new() -> Self {
        Self {
            kernel: crate::task::Kernel::bootstrap(),
            objects: BTreeMap::new(),
            next_object_id: 1,
            timers: TimerService::new(),
        }
    }

    fn alloc_object_id(&mut self) -> u64 {
        let id = self.next_object_id;
        self.next_object_id = self.next_object_id.wrapping_add(1);
        id
    }

    fn alloc_handle_for_object(
        &mut self,
        object_id: u64,
        rights: crate::task::HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        let cap = Capability::new(object_id, rights.bits(), DEFAULT_OBJECT_GENERATION);
        self.kernel.alloc_handle_for_current_process(cap)
    }

    fn lookup_handle(
        &self,
        raw: zx_handle_t,
        required_rights: crate::task::HandleRights,
    ) -> Result<crate::task::ResolvedHandle, zx_status_t> {
        self.kernel.lookup_current_handle(raw, required_rights)
    }

    fn close_handle(&mut self, raw: zx_handle_t) -> Result<(), zx_status_t> {
        self.kernel.close_current_handle(raw)
    }

    fn validate_current_user_ptr(&self, ptr: u64, len: usize) -> bool {
        self.kernel.validate_current_user_ptr(ptr, len)
    }
}

static STATE: Mutex<Option<KernelState>> = Mutex::new(None);

/// Initialize global kernel object state.
pub fn init() {
    let mut guard = STATE.lock();
    if guard.is_none() {
        *guard = Some(KernelState::new());
    }
}

fn with_state_mut<T>(
    f: impl FnOnce(&mut KernelState) -> Result<T, zx_status_t>,
) -> Result<T, zx_status_t> {
    let mut guard = STATE.lock();
    let state = guard.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
    f(state)
}

/// Create a new Port object and return a handle.
pub fn create_port(options: u32) -> Result<zx_handle_t, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let object_id = state.alloc_object_id();
        state.objects.insert(
            object_id,
            KernelObject::Port(Port::new(PORT_CAPACITY, PORT_KERNEL_RESERVE)),
        );

        match state.alloc_handle_for_object(object_id, port_default_rights()) {
            Ok(h) => Ok(h),
            Err(e) => {
                let _ = state.objects.remove(&object_id);
                Err(e)
            }
        }
    })
}

/// Validate a user pointer against the current thread's address-space policy.
pub fn validate_current_user_ptr(ptr: u64, len: usize) -> bool {
    let mut guard = STATE.lock();
    let Some(state) = guard.as_mut() else {
        return false;
    };
    state.validate_current_user_ptr(ptr, len)
}

/// Create a new Timer object and return a handle.
pub fn create_timer(options: u32, clock_id: zx_clock_t) -> Result<zx_handle_t, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if clock_id != ZX_CLOCK_MONOTONIC {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let timer_id = state.timers.create_timer();
        let object_id = state.alloc_object_id();
        state.objects.insert(
            object_id,
            KernelObject::Timer(TimerObject { timer_id, clock_id }),
        );

        match state.alloc_handle_for_object(object_id, timer_default_rights()) {
            Ok(h) => Ok(h),
            Err(e) => {
                let _ = state.objects.remove(&object_id);
                Err(e)
            }
        }
    })
}

/// Ensure a handle is valid and references a Port object.
#[allow(dead_code)]
pub fn ensure_port_handle(handle: zx_handle_t) -> Result<(), zx_status_t> {
    ensure_handle_kind(handle, ObjectKind::Port)
}

/// Ensure a handle is valid and references a Timer object.
#[allow(dead_code)]
pub fn ensure_timer_handle(handle: zx_handle_t) -> Result<(), zx_status_t> {
    ensure_handle_kind(handle, ObjectKind::Timer)
}

/// Arm or re-arm a timer.
pub fn timer_set(handle: zx_handle_t, deadline: i64, _slack: i64) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_id = resolved.object_id();
        let timer_id = match state.objects.get(&object_id) {
            Some(KernelObject::Timer(timer)) => timer.timer_id,
            Some(KernelObject::Port(_)) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;

        state
            .timers
            .set(timer_id, deadline)
            .map_err(map_timer_error)
            .and_then(|()| {
                // Re-arming clears `SIGNALED`, which affects EDGE-triggered observers.
                let _ = notify_waitable_signals_changed(state, object_id);

                // Fire immediately if the deadline is already in the past.
                let now = crate::time::now_ns();
                let fired = poll_due_timers_at(state, now);
                for fired_object_id in fired {
                    let _ = notify_waitable_signals_changed(state, fired_object_id);
                }
                Ok(())
            })
    })
}

/// Cancel a timer.
pub fn timer_cancel(handle: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_id = resolved.object_id();
        let timer_id = match state.objects.get(&object_id) {
            Some(KernelObject::Timer(timer)) => timer.timer_id,
            Some(KernelObject::Port(_)) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;

        state
            .timers
            .cancel(timer_id)
            .map_err(map_timer_error)
            .and_then(|()| {
                let _ = notify_waitable_signals_changed(state, object_id);
                Ok(())
            })
    })
}

/// Queue a user packet into a port.
pub fn queue_port_packet(handle: zx_handle_t, packet: zx_port_packet_t) -> Result<(), zx_status_t> {
    if packet.type_ != ZX_PKT_TYPE_USER {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_id = resolved.object_id();
        {
            let obj = state.objects.get_mut(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;
            let port = match obj {
                KernelObject::Port(port) => port,
                KernelObject::Timer(_) => return Err(ZX_ERR_WRONG_TYPE),
            };
            require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;

            let pkt = Packet::user_with_data(packet.key, packet.status, packet.user.u64);
            port.queue_user(pkt).map_err(map_port_error)?;
        }

        // Port queue state changed; notify async observers waiting on port readability/writability.
        let _ = notify_waitable_signals_changed(state, object_id);
        Ok(())
    })
}

/// Pop one packet from a port queue.
pub fn wait_port_packet(handle: zx_handle_t) -> Result<zx_port_packet_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_id = resolved.object_id();
        let pkt = {
            let obj = state.objects.get_mut(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;
            let port = match obj {
                KernelObject::Port(port) => port,
                KernelObject::Timer(_) => return Err(ZX_ERR_WRONG_TYPE),
            };
            require_handle_rights(resolved, crate::task::HandleRights::READ)?;
            port.pop().map_err(map_port_error)?
        };

        // Port queue state changed; notify async observers waiting on port readability/writability.
        let _ = notify_waitable_signals_changed(state, object_id);

        match pkt.kind {
            PacketKind::User => Ok(zx_port_packet_t {
                key: pkt.key,
                type_: ZX_PKT_TYPE_USER,
                status: pkt.status,
                user: zx_packet_user_t { u64: pkt.user },
            }),
            PacketKind::Signal => {
                let sig = zx_packet_signal_t {
                    trigger: pkt.trigger.bits(),
                    observed: pkt.observed.bits(),
                    count: pkt.count as u64,
                    timestamp: pkt.timestamp,
                    reserved1: 0,
                };
                Ok(zx_port_packet_t {
                    key: pkt.key,
                    type_: ZX_PKT_TYPE_SIGNAL_ONE,
                    status: ZX_OK,
                    user: sig.to_user(),
                })
            }
        }
    })
}

/// Wait for a packet on a port until `deadline`.
///
/// - `deadline == 0`: non-blocking poll; returns `ZX_ERR_SHOULD_WAIT` if empty.
/// - `deadline == i64::MAX`: wait forever.
pub fn port_wait(handle: zx_handle_t, deadline: i64) -> Result<zx_port_packet_t, zx_status_t> {
    loop {
        match wait_port_packet(handle) {
            Ok(pkt) => return Ok(pkt),
            Err(ZX_ERR_SHOULD_WAIT) => {
                if deadline == 0 {
                    return Err(ZX_ERR_SHOULD_WAIT);
                }
                let now = crate::time::now_ns();
                if deadline != i64::MAX && deadline <= now {
                    return Err(ZX_ERR_TIMED_OUT);
                }

                x86_64::instructions::interrupts::enable_and_hlt();
                x86_64::instructions::interrupts::disable();
            }
            Err(e) => return Err(e),
        }
    }
}

/// Snapshot current signals for a waitable object.
pub fn object_signals(handle: zx_handle_t) -> Result<zx_signals_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WAIT)?;
        let object_id = resolved.object_id();
        signals_for_object_id(state, object_id).map(|s| s.bits())
    })
}

/// Wait for one of the specified signals on a waitable object.
///
/// Sweet-spot bring-up implementation:
/// - no scheduler yet, but the CPU sleeps (`sti; hlt`) instead of busy-waiting
/// - monotonic time comes from `time::now_ns()`
/// - timer deadlines are driven by a periodic APIC timer interrupt
pub fn object_wait_one(
    handle: zx_handle_t,
    watched: zx_signals_t,
    deadline: i64,
) -> Result<(zx_status_t, zx_signals_t), zx_status_t> {
    let watched = Signals::from_bits(watched);
    if watched.is_empty() {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    loop {
        // Lock scope so we can drop it before sleeping.
        let observed = {
            let mut guard = STATE.lock();
            let state = guard.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            let resolved = state.lookup_handle(handle, crate::task::HandleRights::WAIT)?;
            let object_id = resolved.object_id();
            signals_for_object_id(state, object_id)?
        };

        if observed.intersects(watched) {
            return Ok((ZX_OK, observed.bits()));
        }

        let now = crate::time::now_ns();
        if deadline != i64::MAX && deadline <= now {
            // Ensure we don't miss a timer that becomes due right at the timeout
            // boundary (coarse periodic ticks can otherwise make this flaky).
            on_tick();

            let observed = {
                let mut guard = STATE.lock();
                let state = guard.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
                let resolved = state.lookup_handle(handle, crate::task::HandleRights::WAIT)?;
                let object_id = resolved.object_id();
                signals_for_object_id(state, object_id)?
            };
            if observed.intersects(watched) {
                return Ok((ZX_OK, observed.bits()));
            }
            return Ok((ZX_ERR_TIMED_OUT, observed.bits()));
        }

        // Sleep until the next interrupt (timer tick, IPI, ...), then re-check.
        x86_64::instructions::interrupts::enable_and_hlt();
        x86_64::instructions::interrupts::disable();
    }
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

    with_state_mut(|state| {
        let waitable = state.lookup_handle(waitable, crate::task::HandleRights::WAIT)?;
        let resolved_port = state.lookup_handle(port_handle, crate::task::HandleRights::empty())?;
        let waitable_id = waitable.object_id();
        let port_id = resolved_port.object_id();

        let current = signals_for_object_id(state, waitable_id)?;

        let watched = Signals::from_bits(signals);
        let now = crate::time::now_ns();

        // Register observer on the port.
        {
            let obj = state.objects.get_mut(&port_id).ok_or(ZX_ERR_BAD_HANDLE)?;
            let port = match obj {
                KernelObject::Port(port) => port,
                KernelObject::Timer(_) => return Err(ZX_ERR_WRONG_TYPE),
            };
            require_handle_rights(resolved_port, crate::task::HandleRights::WRITE)?;
            port.wait_async(waitable_id, key, watched, options, current, now)
                .map_err(map_port_error)?;
        }

        // Port queue may now contain a freshly enqueued signal packet (level-triggered immediate fire).
        let _ = notify_waitable_signals_changed(state, port_id);
        Ok(())
    })
}

/// Close a handle in CSpace.
///
/// This currently only updates CSpace state (slot free + tag bump).
/// Object lifecycle finalization is deferred to later phases.
pub fn close_handle(raw: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| state.close_handle(raw))
}

/// Called from the timer interrupt handler.
///
/// Fires due timers and notifies `wait_async` observers.
pub fn on_tick() {
    let _ = with_state_mut(|state| {
        let now = crate::time::now_ns();
        let fired = poll_due_timers_at(state, now);
        for fired_object_id in fired {
            let _ = notify_waitable_signals_changed(state, fired_object_id);
        }
        Ok(())
    });
}

fn ensure_handle_kind(handle: zx_handle_t, expected: ObjectKind) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_id = resolved.object_id();
        let obj = state.objects.get(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;

        let kind = match obj {
            KernelObject::Port(port) => {
                let _ = port.len();
                ObjectKind::Port
            }
            KernelObject::Timer(timer) => {
                let _ = timer.clock_id;
                let _ = timer.timer_id.raw();
                ObjectKind::Timer
            }
        };

        if kind == expected {
            Ok(())
        } else {
            Err(ZX_ERR_WRONG_TYPE)
        }
    })
}

fn require_handle_rights(
    resolved: crate::task::ResolvedHandle,
    required_rights: crate::task::HandleRights,
) -> Result<(), zx_status_t> {
    if resolved.rights().contains(required_rights) {
        Ok(())
    } else {
        Err(axle_types::status::ZX_ERR_ACCESS_DENIED)
    }
}

fn port_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
}

fn timer_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::WRITE
}

fn signals_for_object_id(state: &KernelState, object_id: u64) -> Result<Signals, zx_status_t> {
    let obj = state.objects.get(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;
    match obj {
        KernelObject::Port(port) => Ok(port.signals()),
        KernelObject::Timer(timer) => {
            let signaled = state
                .timers
                .is_signaled(timer.timer_id)
                .map_err(map_timer_error)?;
            Ok(if signaled {
                Signals::TIMER_SIGNALED
            } else {
                Signals::NONE
            })
        }
    }
}

fn notify_waitable_signals_changed(
    state: &mut KernelState,
    waitable_id: u64,
) -> Result<(), zx_status_t> {
    let current = signals_for_object_id(state, waitable_id)?;
    let now = crate::time::now_ns();

    // Collect port ids first to avoid aliasing `state.objects` borrows.
    let port_ids: alloc::vec::Vec<u64> = state
        .objects
        .iter()
        .filter_map(|(id, obj)| matches!(obj, KernelObject::Port(_)).then_some(*id))
        .collect();

    for port_id in port_ids {
        let Some(KernelObject::Port(port)) = state.objects.get_mut(&port_id) else {
            continue;
        };
        port.on_signals_changed(waitable_id, current, now);
    }
    Ok(())
}

fn poll_due_timers_at(state: &mut KernelState, now: i64) -> alloc::vec::Vec<u64> {
    let fired = state.timers.poll(now);
    if fired.is_empty() {
        return alloc::vec::Vec::new();
    }

    let mut out = alloc::vec::Vec::new();
    for fired_id in fired {
        for (object_id, obj) in state.objects.iter() {
            let KernelObject::Timer(t) = obj else {
                continue;
            };
            if t.timer_id == fired_id {
                out.push(*object_id);
            }
        }
    }
    out
}

fn map_port_error(err: PortError) -> zx_status_t {
    match err {
        PortError::ShouldWait => ZX_ERR_SHOULD_WAIT,
        PortError::AlreadyExists => ZX_ERR_ALREADY_EXISTS,
        PortError::NotFound => ZX_ERR_NOT_FOUND,
    }
}

fn map_timer_error(err: TimerError) -> zx_status_t {
    match err {
        TimerError::NotFound => ZX_ERR_BAD_HANDLE,
    }
}
