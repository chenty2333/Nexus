//! Minimal kernel object table wired through the bootstrap kernel/process model.

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use axle_core::{
    Capability, Packet, PacketKind, Port, PortError, Signals, TimerError, TimerId, TimerService,
    WaitAsyncOptions,
};
use axle_mm::{MappingPerms, VmarId, VmoId};
use axle_types::clock::ZX_CLOCK_MONOTONIC;
use axle_types::packet::{ZX_PKT_TYPE_SIGNAL_ONE, ZX_PKT_TYPE_USER};
use axle_types::status::{
    ZX_ERR_ACCESS_DENIED, ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_STATE,
    ZX_ERR_BUFFER_TOO_SMALL, ZX_ERR_INVALID_ARGS, ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED,
    ZX_ERR_PEER_CLOSED, ZX_ERR_SHOULD_WAIT, ZX_ERR_TIMED_OUT, ZX_ERR_WRONG_TYPE, ZX_OK,
};
use axle_types::vm::{ZX_VM_PERM_EXECUTE, ZX_VM_PERM_READ, ZX_VM_PERM_WRITE, ZX_VM_SPECIFIC};
use axle_types::{zx_clock_t, zx_handle_t, zx_packet_user_t, zx_port_packet_t, zx_status_t};
use axle_types::{zx_packet_signal_t, zx_signals_t};
use spin::Mutex;

const PORT_CAPACITY: usize = 64;
const PORT_KERNEL_RESERVE: usize = 16;
const CHANNEL_CAPACITY: usize = 64;
const DEFAULT_OBJECT_GENERATION: u32 = 0;

/// Kernel object kinds needed in current phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// Channel endpoint object.
    Channel,
    /// Port object.
    Port,
    /// Timer object.
    Timer,
    /// VMO object.
    Vmo,
    /// VMAR object.
    Vmar,
}

#[derive(Debug)]
struct TimerObject {
    timer_id: TimerId,
    clock_id: zx_clock_t,
}

#[derive(Clone, Debug)]
struct ChannelMessage {
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct ChannelEndpoint {
    peer_object_id: u64,
    messages: VecDeque<ChannelMessage>,
    peer_closed: bool,
    closed: bool,
}

impl ChannelEndpoint {
    fn new(peer_object_id: u64) -> Self {
        Self {
            peer_object_id,
            messages: VecDeque::new(),
            peer_closed: false,
            closed: false,
        }
    }

    fn is_readable(&self) -> bool {
        !self.messages.is_empty()
    }

    fn writable_via_peer(&self, peer: &ChannelEndpoint) -> bool {
        !self.peer_closed && !peer.closed && peer.messages.len() < CHANNEL_CAPACITY
    }
}

#[derive(Clone, Copy, Debug)]
struct VmoObject {
    process_id: u64,
    address_space_id: u64,
    vmo_id: VmoId,
    size_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct VmarObject {
    process_id: u64,
    address_space_id: u64,
    vmar_id: VmarId,
    base: u64,
    len: u64,
}

#[derive(Debug)]
enum KernelObject {
    Channel(ChannelEndpoint),
    Port(Port),
    Timer(TimerObject),
    Vmo(VmoObject),
    Vmar(VmarObject),
}

/// Result of a successful channel read.
#[derive(Debug)]
pub struct ChannelReadResult {
    /// Message bytes copied out to userspace.
    pub bytes: Vec<u8>,
    /// Number of bytes in the dequeued message.
    pub actual_bytes: u32,
    /// Number of transferred handles.
    pub actual_handles: u32,
}

#[derive(Debug)]
struct KernelState {
    kernel: crate::task::Kernel,
    objects: BTreeMap<u64, KernelObject>,
    next_object_id: u64,
    timers: TimerService,
    bootstrap_root_vmar_handle: zx_handle_t,
}

impl KernelState {
    fn new() -> Self {
        let mut state = Self {
            kernel: crate::task::Kernel::bootstrap(),
            objects: BTreeMap::new(),
            next_object_id: 1,
            timers: TimerService::new(),
            bootstrap_root_vmar_handle: 0,
        };

        let root = state
            .kernel
            .current_root_vmar()
            .expect("bootstrap root VMAR must exist");
        let object_id = state.alloc_object_id();
        state.objects.insert(
            object_id,
            KernelObject::Vmar(VmarObject {
                process_id: root.process_id(),
                address_space_id: root.address_space_id(),
                vmar_id: root.vmar_id(),
                base: root.base(),
                len: root.len(),
            }),
        );
        state.bootstrap_root_vmar_handle = state
            .alloc_handle_for_object(object_id, vmar_default_rights())
            .expect("bootstrap root VMAR handle allocation must succeed");
        state
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

/// Return the bootstrap root VMAR handle seeded into the current process.
pub fn bootstrap_root_vmar_handle() -> Option<zx_handle_t> {
    let mut guard = STATE.lock();
    let state = guard.as_mut()?;
    Some(state.bootstrap_root_vmar_handle)
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

/// Create a channel endpoint pair and return both handles.
pub fn create_channel(options: u32) -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let left_object_id = state.alloc_object_id();
        let right_object_id = state.alloc_object_id();
        state.objects.insert(
            left_object_id,
            KernelObject::Channel(ChannelEndpoint::new(right_object_id)),
        );
        state.objects.insert(
            right_object_id,
            KernelObject::Channel(ChannelEndpoint::new(left_object_id)),
        );

        let left_handle =
            match state.alloc_handle_for_object(left_object_id, channel_default_rights()) {
                Ok(handle) => handle,
                Err(e) => {
                    let _ = state.objects.remove(&left_object_id);
                    let _ = state.objects.remove(&right_object_id);
                    return Err(e);
                }
            };
        let right_handle =
            match state.alloc_handle_for_object(right_object_id, channel_default_rights()) {
                Ok(handle) => handle,
                Err(e) => {
                    let _ = state.close_handle(left_handle);
                    let _ = state.objects.remove(&left_object_id);
                    let _ = state.objects.remove(&right_object_id);
                    return Err(e);
                }
            };

        Ok((left_handle, right_handle))
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

/// Try to resolve a bootstrap user-mode page fault.
pub fn handle_page_fault(cr2: u64, error: u64) -> bool {
    const PF_PRESENT: u64 = 1 << 0;
    const PF_WRITE: u64 = 1 << 1;
    const PF_USER: u64 = 1 << 2;

    if (error & (PF_PRESENT | PF_WRITE | PF_USER)) != (PF_PRESENT | PF_WRITE | PF_USER) {
        return false;
    }

    let mut guard = STATE.lock();
    let Some(state) = guard.as_mut() else {
        return false;
    };
    state.kernel.handle_current_page_fault(cr2, error)
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

/// Create an anonymous VMO and return a handle.
pub fn create_vmo(size: u64, options: u32) -> Result<zx_handle_t, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let created = state.kernel.create_current_anonymous_vmo(size)?;
        let object_id = state.alloc_object_id();
        state.objects.insert(
            object_id,
            KernelObject::Vmo(VmoObject {
                process_id: created.process_id(),
                address_space_id: created.address_space_id(),
                vmo_id: created.vmo_id(),
                size_bytes: created.size_bytes(),
            }),
        );

        match state.alloc_handle_for_object(object_id, vmo_default_rights()) {
            Ok(h) => Ok(h),
            Err(e) => {
                let _ = state.objects.remove(&object_id);
                Err(e)
            }
        }
    })
}

/// Write one copied message into the peer side of a channel.
pub fn channel_write(
    handle: zx_handle_t,
    options: u32,
    bytes: Vec<u8>,
    num_handles: u32,
) -> Result<(), zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if num_handles != 0 {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }

    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_id = resolved.object_id();
        let peer_object_id = {
            let endpoint = match state.objects.get(&object_id) {
                Some(KernelObject::Channel(endpoint)) => endpoint,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };
            require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;
            endpoint.peer_object_id
        };

        {
            let peer = match state.objects.get_mut(&peer_object_id) {
                Some(KernelObject::Channel(peer)) => peer,
                Some(_) => return Err(ZX_ERR_BAD_STATE),
                None => return Err(ZX_ERR_PEER_CLOSED),
            };
            if peer.closed {
                return Err(ZX_ERR_PEER_CLOSED);
            }
            if peer.messages.len() >= CHANNEL_CAPACITY {
                return Err(ZX_ERR_SHOULD_WAIT);
            }
            peer.messages.push_back(ChannelMessage { bytes });
        }

        let _ = notify_waitable_signals_changed(state, object_id);
        let _ = notify_waitable_signals_changed(state, peer_object_id);
        Ok(())
    })
}

/// Read one copied message from a channel endpoint.
pub fn channel_read(
    handle: zx_handle_t,
    options: u32,
    num_bytes: u32,
    _num_handles: u32,
) -> Result<ChannelReadResult, (zx_status_t, u32, u32)> {
    if options != 0 {
        return Err((ZX_ERR_INVALID_ARGS, 0, 0));
    }

    let mut guard = STATE.lock();
    let state = guard.as_mut().ok_or((ZX_ERR_BAD_STATE, 0, 0))?;
    let resolved = state
        .lookup_handle(handle, crate::task::HandleRights::empty())
        .map_err(|e| (e, 0, 0))?;
    let object_id = resolved.object_id();
    let peer_object_id = {
        let endpoint = match state.objects.get(&object_id) {
            Some(KernelObject::Channel(endpoint)) => endpoint,
            Some(_) => return Err((ZX_ERR_WRONG_TYPE, 0, 0)),
            None => return Err((ZX_ERR_BAD_HANDLE, 0, 0)),
        };
        require_handle_rights(resolved, crate::task::HandleRights::READ).map_err(|e| (e, 0, 0))?;
        if let Some(message) = endpoint.messages.front() {
            let actual_bytes =
                u32::try_from(message.bytes.len()).map_err(|_| (ZX_ERR_BAD_STATE, 0, 0))?;
            if num_bytes < actual_bytes {
                return Err((ZX_ERR_BUFFER_TOO_SMALL, actual_bytes, 0));
            }
        } else if endpoint.peer_closed {
            return Err((ZX_ERR_PEER_CLOSED, 0, 0));
        } else {
            return Err((ZX_ERR_SHOULD_WAIT, 0, 0));
        }
        endpoint.peer_object_id
    };

    let message = {
        let endpoint = match state.objects.get_mut(&object_id) {
            Some(KernelObject::Channel(endpoint)) => endpoint,
            Some(_) => return Err((ZX_ERR_WRONG_TYPE, 0, 0)),
            None => return Err((ZX_ERR_BAD_HANDLE, 0, 0)),
        };
        endpoint
            .messages
            .pop_front()
            .ok_or((ZX_ERR_BAD_STATE, 0, 0))?
    };
    let actual_bytes = u32::try_from(message.bytes.len()).map_err(|_| (ZX_ERR_BAD_STATE, 0, 0))?;

    let _ = notify_waitable_signals_changed(state, object_id);
    let _ = notify_waitable_signals_changed(state, peer_object_id);

    Ok(ChannelReadResult {
        bytes: message.bytes,
        actual_bytes,
        actual_handles: 0,
    })
}

/// Map a VMO into a VMAR at an exact offset.
#[allow(clippy::too_many_arguments)]
pub fn vmar_map(
    vmar_handle: zx_handle_t,
    options: u32,
    vmar_offset: u64,
    vmo_handle: zx_handle_t,
    vmo_offset: u64,
    len: u64,
) -> Result<u64, zx_status_t> {
    let perms = mapping_perms_from_options(options, true)?;

    with_state_mut(|state| {
        let resolved_vmar = state.lookup_handle(vmar_handle, crate::task::HandleRights::empty())?;
        let resolved_vmo = state.lookup_handle(vmo_handle, crate::task::HandleRights::empty())?;
        let vmar = match state.objects.get(&resolved_vmar.object_id()) {
            Some(KernelObject::Vmar(vmar)) => *vmar,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        let vmo = match state.objects.get(&resolved_vmo.object_id()) {
            Some(KernelObject::Vmo(vmo)) => *vmo,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };

        require_vm_mapping_rights(resolved_vmar, perms)?;
        require_vm_mapping_rights(resolved_vmo, perms)?;
        let _ = vmo.size_bytes;
        state.kernel.map_current_vmo_into_vmar(
            vmar.address_space_id,
            vmar.vmar_id,
            vmo.address_space_id,
            vmo.vmo_id,
            vmar_offset,
            vmo_offset,
            len,
            perms,
        )
    })
}

/// Unmap a previously installed VMAR range.
pub fn vmar_unmap(vmar_handle: zx_handle_t, addr: u64, len: u64) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved_vmar = state.lookup_handle(vmar_handle, crate::task::HandleRights::empty())?;
        let vmar = match state.objects.get(&resolved_vmar.object_id()) {
            Some(KernelObject::Vmar(vmar)) => *vmar,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        let _ = (vmar.process_id, vmar.base, vmar.len);
        require_handle_rights(resolved_vmar, crate::task::HandleRights::WRITE)?;
        state
            .kernel
            .unmap_current_vmar(vmar.address_space_id, vmar.vmar_id, addr, len)
    })
}

/// Change permissions on an existing VMAR range.
pub fn vmar_protect(
    vmar_handle: zx_handle_t,
    options: u32,
    addr: u64,
    len: u64,
) -> Result<(), zx_status_t> {
    let perms = mapping_perms_from_options(options, false)?;

    with_state_mut(|state| {
        let resolved_vmar = state.lookup_handle(vmar_handle, crate::task::HandleRights::empty())?;
        let vmar = match state.objects.get(&resolved_vmar.object_id()) {
            Some(KernelObject::Vmar(vmar)) => *vmar,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        let _ = (vmar.process_id, vmar.base, vmar.len);
        require_vm_mapping_rights(resolved_vmar, perms)?;
        state
            .kernel
            .protect_current_vmar(vmar.address_space_id, vmar.vmar_id, addr, len, perms)
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
            Some(KernelObject::Channel(_))
            | Some(KernelObject::Port(_))
            | Some(KernelObject::Vmo(_))
            | Some(KernelObject::Vmar(_)) => return Err(ZX_ERR_WRONG_TYPE),
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
            Some(KernelObject::Channel(_))
            | Some(KernelObject::Port(_))
            | Some(KernelObject::Vmo(_))
            | Some(KernelObject::Vmar(_)) => return Err(ZX_ERR_WRONG_TYPE),
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
                KernelObject::Channel(_)
                | KernelObject::Timer(_)
                | KernelObject::Vmo(_)
                | KernelObject::Vmar(_) => {
                    return Err(ZX_ERR_WRONG_TYPE);
                }
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
                KernelObject::Channel(_)
                | KernelObject::Timer(_)
                | KernelObject::Vmo(_)
                | KernelObject::Vmar(_) => {
                    return Err(ZX_ERR_WRONG_TYPE);
                }
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
                KernelObject::Channel(_)
                | KernelObject::Timer(_)
                | KernelObject::Vmo(_)
                | KernelObject::Vmar(_) => {
                    return Err(ZX_ERR_WRONG_TYPE);
                }
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

/// Close a handle in CSpace and apply minimal object-specific side effects.
pub fn close_handle(raw: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(raw, crate::task::HandleRights::empty())?;
        let object_id = resolved.object_id();
        let peer_object_id = match state.objects.get(&object_id) {
            Some(KernelObject::Channel(endpoint)) => Some(endpoint.peer_object_id),
            Some(_) => None,
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        state.close_handle(raw)?;

        if let Some(peer_object_id) = peer_object_id {
            if let Some(KernelObject::Channel(endpoint)) = state.objects.get_mut(&object_id) {
                endpoint.closed = true;
            }
            if let Some(KernelObject::Channel(peer)) = state.objects.get_mut(&peer_object_id) {
                peer.peer_closed = true;
            }
            let _ = notify_waitable_signals_changed(state, object_id);
            let _ = notify_waitable_signals_changed(state, peer_object_id);
        }
        Ok(())
    })
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
            KernelObject::Channel(endpoint) => {
                let _ = (
                    endpoint.peer_object_id,
                    endpoint.messages.len(),
                    endpoint.peer_closed,
                    endpoint.closed,
                );
                ObjectKind::Channel
            }
            KernelObject::Port(port) => {
                let _ = port.len();
                ObjectKind::Port
            }
            KernelObject::Timer(timer) => {
                let _ = timer.clock_id;
                let _ = timer.timer_id.raw();
                ObjectKind::Timer
            }
            KernelObject::Vmo(vmo) => {
                let _ = (
                    vmo.process_id,
                    vmo.address_space_id,
                    vmo.vmo_id.raw(),
                    vmo.size_bytes,
                );
                ObjectKind::Vmo
            }
            KernelObject::Vmar(vmar) => {
                let _ = (
                    vmar.process_id,
                    vmar.address_space_id,
                    vmar.vmar_id.raw(),
                    vmar.base,
                    vmar.len,
                );
                ObjectKind::Vmar
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
        Err(ZX_ERR_ACCESS_DENIED)
    }
}

fn channel_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
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

fn vmo_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
}

fn vmar_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
}

fn require_vm_mapping_rights(
    resolved: crate::task::ResolvedHandle,
    perms: MappingPerms,
) -> Result<(), zx_status_t> {
    require_handle_rights(resolved, crate::task::HandleRights::READ)?;
    if perms.contains(MappingPerms::WRITE) {
        require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;
    }
    Ok(())
}

fn mapping_perms_from_options(
    options: u32,
    require_specific: bool,
) -> Result<MappingPerms, zx_status_t> {
    let allowed = ZX_VM_PERM_READ
        | ZX_VM_PERM_WRITE
        | ZX_VM_PERM_EXECUTE
        | if require_specific { ZX_VM_SPECIFIC } else { 0 };
    if (options & !allowed) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if require_specific && (options & ZX_VM_SPECIFIC) == 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if (options & ZX_VM_PERM_EXECUTE) != 0 {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    let has_read = (options & ZX_VM_PERM_READ) != 0;
    let has_write = (options & ZX_VM_PERM_WRITE) != 0;
    if !has_read {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    let mut perms = MappingPerms::READ | MappingPerms::USER;
    if has_write {
        perms |= MappingPerms::WRITE;
    }
    Ok(perms)
}

fn signals_for_object_id(state: &KernelState, object_id: u64) -> Result<Signals, zx_status_t> {
    let obj = state.objects.get(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;
    match obj {
        KernelObject::Channel(endpoint) => {
            let mut signals = Signals::NONE;
            if endpoint.is_readable() {
                signals = signals | Signals::CHANNEL_READABLE;
            }
            if endpoint.peer_closed {
                signals = signals | Signals::CHANNEL_PEER_CLOSED;
            } else {
                let peer = match state.objects.get(&endpoint.peer_object_id) {
                    Some(KernelObject::Channel(peer)) => peer,
                    Some(_) | None => return Err(ZX_ERR_BAD_STATE),
                };
                if endpoint.writable_via_peer(peer) {
                    signals = signals | Signals::CHANNEL_WRITABLE;
                }
            }
            Ok(signals)
        }
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
        KernelObject::Vmo(_) | KernelObject::Vmar(_) => Ok(Signals::NONE),
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
