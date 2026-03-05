//! Minimal kernel object table + CSpace wiring (single-process bootstrap model).

extern crate alloc;

use alloc::collections::BTreeMap;

use axle_core::handle::Handle;
use axle_core::{
    CSpace, CSpaceError, Capability, FakeClock, Packet, PacketKind, Port, PortError, Signals,
    TimerError, TimerId, TimerService, WaitAsyncOptions,
};
use axle_types::clock::ZX_CLOCK_MONOTONIC;
use axle_types::packet::{ZX_PKT_TYPE_SIGNAL_ONE, ZX_PKT_TYPE_USER};
use axle_types::status::{
    ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_STATE, ZX_ERR_INTERNAL,
    ZX_ERR_INVALID_ARGS, ZX_ERR_NO_RESOURCES, ZX_ERR_NOT_FOUND, ZX_ERR_SHOULD_WAIT,
    ZX_ERR_WRONG_TYPE, ZX_OK,
};
use axle_types::{zx_clock_t, zx_handle_t, zx_packet_user_t, zx_port_packet_t, zx_status_t};
use axle_types::{zx_packet_signal_t, zx_signals_t};
use spin::Mutex;

const CSPACE_MAX_SLOTS: u16 = 16_384;
const CSPACE_QUARANTINE_LEN: usize = 256;
const DEFAULT_RIGHTS: u32 = u32::MAX;
const DEFAULT_OBJECT_GENERATION: u32 = 0;

const PORT_CAPACITY: usize = 64;
const PORT_KERNEL_RESERVE: usize = 16;

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
    cspace: CSpace,
    objects: BTreeMap<u64, KernelObject>,
    next_object_id: u64,
    clock: FakeClock,
    timers: TimerService,
}

impl KernelState {
    fn new() -> Self {
        Self {
            cspace: CSpace::new(CSPACE_MAX_SLOTS, CSPACE_QUARANTINE_LEN),
            objects: BTreeMap::new(),
            next_object_id: 1,
            clock: FakeClock::new(),
            timers: TimerService::new(),
        }
    }

    fn alloc_object_id(&mut self) -> u64 {
        let id = self.next_object_id;
        self.next_object_id = self.next_object_id.wrapping_add(1);
        id
    }

    fn alloc_handle_for_object(&mut self, object_id: u64) -> Result<zx_handle_t, zx_status_t> {
        let cap = Capability::new(object_id, DEFAULT_RIGHTS, DEFAULT_OBJECT_GENERATION);
        let h = self.cspace.alloc(cap).map_err(map_alloc_error)?;
        Ok(h.raw())
    }

    fn lookup_object_id(&self, raw: zx_handle_t) -> Result<u64, zx_status_t> {
        let h = Handle::from_raw(raw).map_err(|_| ZX_ERR_BAD_HANDLE)?;
        let cap = self.cspace.get(h).map_err(map_lookup_error)?;
        Ok(cap.object_id())
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

        match state.alloc_handle_for_object(object_id) {
            Ok(h) => Ok(h),
            Err(e) => {
                let _ = state.objects.remove(&object_id);
                Err(e)
            }
        }
    })
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

        match state.alloc_handle_for_object(object_id) {
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
        let object_id = state.lookup_object_id(handle)?;
        let timer_id = match state.objects.get(&object_id) {
            Some(KernelObject::Timer(timer)) => timer.timer_id,
            Some(KernelObject::Port(_)) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };

        state
            .timers
            .set(timer_id, deadline)
            .map_err(map_timer_error)
            .and_then(|()| {
                // Re-arming clears `SIGNALED`, which affects EDGE-triggered observers.
                let _ = notify_waitable_signals_changed(state, object_id);

                // For bring-up we only have a fake clock; fire due timers at current time.
                let fired = fire_due_timers(state);
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
        let object_id = state.lookup_object_id(handle)?;
        let timer_id = match state.objects.get(&object_id) {
            Some(KernelObject::Timer(timer)) => timer.timer_id,
            Some(KernelObject::Port(_)) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };

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
        let object_id = state.lookup_object_id(handle)?;
        {
            let obj = state.objects.get_mut(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;
            let port = match obj {
                KernelObject::Port(port) => port,
                KernelObject::Timer(_) => return Err(ZX_ERR_WRONG_TYPE),
            };

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
        let object_id = state.lookup_object_id(handle)?;
        let pkt = {
            let obj = state.objects.get_mut(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;
            let port = match obj {
                KernelObject::Port(port) => port,
                KernelObject::Timer(_) => return Err(ZX_ERR_WRONG_TYPE),
            };
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
                    timestamp: 0,
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

/// Snapshot current signals for a waitable object.
pub fn object_signals(handle: zx_handle_t) -> Result<zx_signals_t, zx_status_t> {
    with_state_mut(|state| {
        let object_id = state.lookup_object_id(handle)?;
        signals_for_object_id(state, object_id).map(|s| s.bits())
    })
}

/// Register a one-shot async wait and deliver a signal packet into `port` when fired.
pub fn object_wait_async(
    waitable: zx_handle_t,
    port_handle: zx_handle_t,
    key: u64,
    signals: zx_signals_t,
    edge_triggered: bool,
) -> Result<(), zx_status_t> {
    if signals == 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let waitable_id = state.lookup_object_id(waitable)?;
        let port_id = state.lookup_object_id(port_handle)?;

        let current = signals_for_object_id(state, waitable_id)?;

        let opts = WaitAsyncOptions { edge_triggered };
        let watched = Signals::from_bits(signals);

        // Register observer on the port.
        {
            let obj = state.objects.get_mut(&port_id).ok_or(ZX_ERR_BAD_HANDLE)?;
            let port = match obj {
                KernelObject::Port(port) => port,
                KernelObject::Timer(_) => return Err(ZX_ERR_WRONG_TYPE),
            };
            port.wait_async(waitable_id, key, watched, opts, current)
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
    with_state_mut(|state| {
        let h = Handle::from_raw(raw).map_err(|_| ZX_ERR_BAD_HANDLE)?;
        let _ = state.cspace.get(h).map_err(map_lookup_error)?;
        state.cspace.close(h).map_err(map_lookup_error)?;
        Ok(())
    })
}

fn ensure_handle_kind(handle: zx_handle_t, expected: ObjectKind) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let object_id = state.lookup_object_id(handle)?;
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
        port.on_signals_changed(waitable_id, current);
    }
    Ok(())
}

fn fire_due_timers(state: &mut KernelState) -> alloc::vec::Vec<u64> {
    let now = state.clock.now();
    let fired = state.timers.advance_clock(&mut state.clock, now);
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

fn map_alloc_error(err: CSpaceError) -> zx_status_t {
    match err {
        CSpaceError::NoSlots => ZX_ERR_NO_RESOURCES,
        CSpaceError::Handle(_) => ZX_ERR_INTERNAL,
        CSpaceError::BadHandle => ZX_ERR_BAD_HANDLE,
    }
}

fn map_lookup_error(_err: CSpaceError) -> zx_status_t {
    ZX_ERR_BAD_HANDLE
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
