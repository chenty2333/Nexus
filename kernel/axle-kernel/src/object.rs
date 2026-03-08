//! Minimal kernel object table wired through the bootstrap kernel/process model.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;

use axle_core::{
    Capability, Packet, PortError, Signals, TimerError, TimerId, TimerService, TransferredCap,
    WaitAsyncOptions,
};
use axle_mm::{MappingPerms, VmarAllocMode, VmarId, VmarPlacementPolicy};
use axle_types::clock::ZX_CLOCK_MONOTONIC;
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::koid::ZX_KOID_INVALID;
use axle_types::packet::ZX_PKT_TYPE_USER;
use axle_types::rights::{ZX_RIGHT_SAME_RIGHTS, ZX_RIGHTS_ALL};
use axle_types::socket::{ZX_SOCKET_DATAGRAM, ZX_SOCKET_PEEK, ZX_SOCKET_STREAM};
use axle_types::status::{
    ZX_ERR_ACCESS_DENIED, ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_STATE,
    ZX_ERR_BUFFER_TOO_SMALL, ZX_ERR_INVALID_ARGS, ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED,
    ZX_ERR_OUT_OF_RANGE, ZX_ERR_PEER_CLOSED, ZX_ERR_SHOULD_WAIT, ZX_ERR_TIMED_OUT,
    ZX_ERR_WRONG_TYPE, ZX_OK,
};
use axle_types::vm::{
    ZX_VM_ALIGN_BASE, ZX_VM_ALIGN_MASK, ZX_VM_CAN_MAP_EXECUTE, ZX_VM_CAN_MAP_READ,
    ZX_VM_CAN_MAP_SPECIFIC, ZX_VM_CAN_MAP_WRITE, ZX_VM_COMPACT, ZX_VM_OFFSET_IS_UPPER_LIMIT,
    ZX_VM_PERM_EXECUTE, ZX_VM_PERM_READ, ZX_VM_PERM_WRITE, ZX_VM_SPECIFIC,
};
use axle_types::zx_signals_t;
use axle_types::{
    zx_clock_t, zx_futex_t, zx_handle_t, zx_koid_t, zx_port_packet_t, zx_rights_t, zx_status_t,
    zx_vaddr_t,
};
use core::mem::size_of;
use spin::Mutex;

use crate::port_queue::{KernelPort, port_packet_from_core};

const PORT_CAPACITY: usize = 64;
const PORT_KERNEL_RESERVE: usize = 16;
const CHANNEL_CAPACITY: usize = 64;
const SOCKET_STREAM_CAPACITY: usize = 4096;
const DEFAULT_OBJECT_GENERATION: u32 = 0;

enum TrapBlock<T> {
    Ready(T),
    BlockCurrent,
}

/// Kernel object kinds needed in current phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// Process object.
    Process,
    /// Suspend token object.
    SuspendToken,
    /// Socket endpoint object.
    Socket,
    /// Channel endpoint object.
    Channel,
    /// EventPair endpoint object.
    EventPair,
    /// Port object.
    Port,
    /// Timer object.
    Timer,
    /// VMO object.
    Vmo,
    /// VMAR object.
    Vmar,
    /// Thread object.
    Thread,
}

#[derive(Debug)]
struct TimerObject {
    timer_id: TimerId,
    clock_id: zx_clock_t,
}

#[derive(Clone, Debug)]
pub(crate) enum ChannelPayload {
    Copied(Vec<u8>),
    Loaned(crate::task::LoanedUserPages),
}

#[derive(Clone, Debug)]
struct ChannelMessage {
    payload: ChannelPayload,
    handles: Vec<TransferredCap>,
}

#[derive(Debug)]
struct ChannelEndpoint {
    peer_object_id: u64,
    owner_process_id: u64,
    messages: VecDeque<ChannelMessage>,
    peer_closed: bool,
    closed: bool,
}

impl ChannelEndpoint {
    fn new(peer_object_id: u64, owner_process_id: u64) -> Self {
        Self {
            peer_object_id,
            owner_process_id,
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

impl ChannelPayload {
    fn actual_bytes(&self) -> Result<u32, zx_status_t> {
        match self {
            Self::Copied(bytes) => u32::try_from(bytes.len()).map_err(|_| ZX_ERR_BAD_STATE),
            Self::Loaned(loaned) => Ok(loaned.len()),
        }
    }
}

impl ChannelMessage {
    fn actual_bytes(&self) -> Result<u32, zx_status_t> {
        self.payload.actual_bytes()
    }

    fn actual_handles(&self) -> Result<u32, zx_status_t> {
        u32::try_from(self.handles.len()).map_err(|_| ZX_ERR_BAD_STATE)
    }
}

#[derive(Debug)]
struct EventPairEndpoint {
    peer_object_id: u64,
    user_signals: Signals,
    peer_closed: bool,
    closed: bool,
}

impl EventPairEndpoint {
    fn new(peer_object_id: u64) -> Self {
        Self {
            peer_object_id,
            user_signals: Signals::NONE,
            peer_closed: false,
            closed: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketSide {
    A,
    B,
}

#[derive(Clone, Copy, Debug)]
struct SocketEndpoint {
    core_id: u64,
    peer_object_id: u64,
    side: SocketSide,
}

#[derive(Debug)]
struct ByteRing {
    buf: Vec<u8>,
    head: usize,
    len: usize,
}

impl ByteRing {
    fn with_capacity(capacity: usize) -> Result<Self, zx_status_t> {
        let mut buf = Vec::new();
        buf.try_reserve_exact(capacity)
            .map_err(|_| axle_types::status::ZX_ERR_NO_MEMORY)?;
        buf.resize(capacity, 0);
        Ok(Self {
            buf,
            head: 0,
            len: 0,
        })
    }

    fn capacity(&self) -> usize {
        self.buf.len()
    }

    fn available_read(&self) -> usize {
        self.len
    }

    fn available_write(&self) -> usize {
        self.capacity().saturating_sub(self.len)
    }

    fn write(&mut self, bytes: &[u8]) -> usize {
        if bytes.is_empty() || self.available_write() == 0 {
            return 0;
        }
        let written = bytes.len().min(self.available_write());
        for (idx, byte) in bytes.iter().take(written).enumerate() {
            let tail = (self.head + self.len + idx) % self.capacity();
            self.buf[tail] = *byte;
        }
        self.len += written;
        written
    }

    fn read(&mut self, len: usize, consume: bool) -> Result<Vec<u8>, zx_status_t> {
        let to_copy = len.min(self.available_read());
        let mut out = Vec::new();
        out.try_reserve_exact(to_copy)
            .map_err(|_| axle_types::status::ZX_ERR_NO_MEMORY)?;
        for idx in 0..to_copy {
            let at = (self.head + idx) % self.capacity();
            out.push(self.buf[at]);
        }
        if consume {
            self.head = (self.head + to_copy) % self.capacity();
            self.len -= to_copy;
        }
        Ok(out)
    }
}

#[derive(Debug)]
struct SocketCore {
    dir_ab: ByteRing,
    dir_ba: ByteRing,
    open_a: bool,
    open_b: bool,
}

impl SocketCore {
    fn new_stream(capacity: usize) -> Result<Self, zx_status_t> {
        Ok(Self {
            dir_ab: ByteRing::with_capacity(capacity)?,
            dir_ba: ByteRing::with_capacity(capacity)?,
            open_a: true,
            open_b: true,
        })
    }

    fn signals_for(&self, side: SocketSide) -> Signals {
        let (readable, writable, peer_open) = match side {
            SocketSide::A => (
                self.dir_ba.available_read() != 0,
                self.dir_ab.available_write() != 0,
                self.open_b,
            ),
            SocketSide::B => (
                self.dir_ab.available_read() != 0,
                self.dir_ba.available_write() != 0,
                self.open_a,
            ),
        };
        let mut signals = Signals::NONE;
        if readable {
            signals = signals | Signals::SOCKET_READABLE;
        }
        if peer_open && writable {
            signals = signals | Signals::SOCKET_WRITABLE;
        }
        if !peer_open {
            signals = signals | Signals::SOCKET_PEER_CLOSED;
        }
        signals
    }

    fn write(&mut self, side: SocketSide, bytes: &[u8]) -> Result<usize, zx_status_t> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let (queue, peer_open) = match side {
            SocketSide::A => (&mut self.dir_ab, self.open_b),
            SocketSide::B => (&mut self.dir_ba, self.open_a),
        };
        if !peer_open {
            return Err(ZX_ERR_PEER_CLOSED);
        }
        let written = queue.write(bytes);
        if written == 0 {
            return Err(ZX_ERR_SHOULD_WAIT);
        }
        Ok(written)
    }

    fn read(
        &mut self,
        side: SocketSide,
        len: usize,
        consume: bool,
    ) -> Result<Vec<u8>, zx_status_t> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let (queue, peer_open) = match side {
            SocketSide::A => (&mut self.dir_ba, self.open_b),
            SocketSide::B => (&mut self.dir_ab, self.open_a),
        };
        if queue.available_read() == 0 {
            return Err(if peer_open {
                ZX_ERR_SHOULD_WAIT
            } else {
                ZX_ERR_PEER_CLOSED
            });
        }
        queue.read(len, consume)
    }

    fn close_side(&mut self, side: SocketSide) {
        match side {
            SocketSide::A => self.open_a = false,
            SocketSide::B => self.open_b = false,
        }
    }

    fn fully_closed(&self) -> bool {
        !self.open_a && !self.open_b
    }

    fn buffered_bytes(&self) -> usize {
        self.dir_ab.available_read() + self.dir_ba.available_read()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SocketTelemetrySnapshot {
    pub(crate) current_buffered_bytes: u64,
    pub(crate) peak_buffered_bytes: u64,
    pub(crate) short_write_count: u64,
    pub(crate) write_should_wait_count: u64,
}

#[derive(Clone, Debug)]
struct VmoObject {
    creator_process_id: u64,
    global_vmo_id: axle_mm::GlobalVmoId,
    kind: axle_mm::VmoKind,
    size_bytes: u64,
    image_layout: Option<crate::task::ProcessImageLayout>,
}

#[derive(Clone, Copy, Debug)]
struct VmarMappingCaps {
    max_perms: MappingPerms,
    can_map_specific: bool,
}

#[derive(Clone, Copy, Debug)]
struct VmarMappingRequest {
    perms: MappingPerms,
    specific: bool,
}

#[derive(Clone, Copy, Debug)]
struct VmarAllocateRequest {
    mapping_caps: VmarMappingCaps,
    align: u64,
    mode: VmarAllocMode,
    offset_is_upper_limit: bool,
    child_policy: VmarPlacementPolicy,
}

#[derive(Clone, Copy, Debug)]
struct VmarObject {
    process_id: u64,
    address_space_id: u64,
    vmar_id: VmarId,
    base: u64,
    len: u64,
    mapping_caps: VmarMappingCaps,
}

#[derive(Clone, Copy, Debug)]
struct ThreadObject {
    process_id: u64,
    thread_id: u64,
    koid: zx_koid_t,
}

#[derive(Clone, Copy, Debug)]
struct ProcessObject {
    process_id: u64,
    koid: zx_koid_t,
}

#[derive(Clone, Copy, Debug)]
enum SuspendTarget {
    Process { process_id: u64 },
    Thread { thread_id: u64 },
}

#[derive(Clone, Copy, Debug)]
struct SuspendTokenObject {
    target: SuspendTarget,
}

#[derive(Debug)]
enum KernelObject {
    Process(ProcessObject),
    SuspendToken(SuspendTokenObject),
    Socket(SocketEndpoint),
    Channel(ChannelEndpoint),
    EventPair(EventPairEndpoint),
    Port(KernelPort),
    Timer(TimerObject),
    Vmo(VmoObject),
    Vmar(VmarObject),
    Thread(ThreadObject),
}

/// Result of a successful channel read.
#[derive(Debug)]
pub(crate) struct ChannelReadResult {
    /// Dequeued payload.
    pub(crate) payload: ChannelPayload,
    /// Dequeued handles, installed into the current process.
    pub(crate) handles: Vec<zx_handle_t>,
    /// Number of bytes in the dequeued message.
    pub(crate) actual_bytes: u32,
    /// Number of transferred handles.
    pub(crate) actual_handles: u32,
}

const USER_SIGNAL_MASK: Signals = Signals::USER_SIGNAL_0
    .union(Signals::USER_SIGNAL_1)
    .union(Signals::USER_SIGNAL_2)
    .union(Signals::USER_SIGNAL_3)
    .union(Signals::USER_SIGNAL_4)
    .union(Signals::USER_SIGNAL_5)
    .union(Signals::USER_SIGNAL_6)
    .union(Signals::USER_SIGNAL_7);

#[derive(Debug)]
struct KernelState {
    kernel: Arc<Mutex<crate::task::Kernel>>,
    objects: BTreeMap<u64, KernelObject>,
    socket_cores: BTreeMap<u64, SocketCore>,
    socket_telemetry: SocketTelemetrySnapshot,
    object_handle_refs: BTreeMap<u64, usize>,
    next_object_id: u64,
    next_socket_core_id: u64,
    timers: TimerService,
    bootstrap_self_process_handle: zx_handle_t,
    bootstrap_root_vmar_handle: zx_handle_t,
    bootstrap_self_thread_handle: zx_handle_t,
    bootstrap_self_code_vmo_handle: zx_handle_t,
    bootstrap_process_image_layout: crate::task::ProcessImageLayout,
}

impl KernelState {
    fn new() -> Self {
        let mut state = Self {
            kernel: Arc::new(Mutex::new(crate::task::Kernel::bootstrap())),
            objects: BTreeMap::new(),
            socket_cores: BTreeMap::new(),
            socket_telemetry: SocketTelemetrySnapshot::default(),
            object_handle_refs: BTreeMap::new(),
            next_object_id: 1,
            next_socket_core_id: 1,
            timers: TimerService::new(),
            bootstrap_self_process_handle: 0,
            bootstrap_root_vmar_handle: 0,
            bootstrap_self_thread_handle: 0,
            bootstrap_self_code_vmo_handle: 0,
            bootstrap_process_image_layout: crate::task::ProcessImageLayout::bootstrap_conformance(
            ),
        };

        let process = state
            .with_kernel(|kernel| kernel.current_process_info())
            .expect("bootstrap current process must exist");
        let process_koid = state
            .with_kernel(|kernel| kernel.current_process_koid())
            .expect("bootstrap current process koid must exist");
        let object_id = state.alloc_object_id();
        state.objects.insert(
            object_id,
            KernelObject::Process(ProcessObject {
                process_id: process.process_id(),
                koid: process_koid,
            }),
        );
        state.bootstrap_self_process_handle = state
            .alloc_handle_for_object(object_id, process_default_rights())
            .expect("bootstrap self process handle allocation must succeed");

        let root = state
            .with_kernel(|kernel| kernel.current_root_vmar())
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
                mapping_caps: root_vmar_mapping_caps(),
            }),
        );
        state.bootstrap_root_vmar_handle = state
            .alloc_handle_for_object(object_id, vmar_default_rights())
            .expect("bootstrap root VMAR handle allocation must succeed");

        let thread = state
            .with_kernel(|kernel| kernel.current_thread_info())
            .expect("bootstrap current thread must exist");
        let object_id = state.alloc_object_id();
        state.objects.insert(
            object_id,
            KernelObject::Thread(ThreadObject {
                process_id: thread.process_id(),
                thread_id: thread.thread_id(),
                koid: thread.koid(),
            }),
        );
        state.bootstrap_self_thread_handle = state
            .alloc_handle_for_object(object_id, thread_default_rights())
            .expect("bootstrap self thread handle allocation must succeed");

        let address_space_id = state
            .with_core(|kernel| kernel.process_address_space_id(process.process_id()))
            .expect("bootstrap current process address space must exist");
        if let Ok(imported) = state.with_vm_mut(|vm| {
            vm.import_bootstrap_process_image_for_address_space(
                process.process_id(),
                address_space_id,
            )
        }) {
            state.bootstrap_process_image_layout = imported.layout();
            let object_id = state.alloc_object_id();
            state.objects.insert(
                object_id,
                KernelObject::Vmo(VmoObject {
                    creator_process_id: imported.code_vmo().process_id(),
                    global_vmo_id: imported.code_vmo().global_vmo_id(),
                    kind: axle_mm::VmoKind::PagerBacked,
                    size_bytes: imported.code_vmo().size_bytes(),
                    image_layout: Some(imported.layout()),
                }),
            );
            state.bootstrap_self_code_vmo_handle = state
                .alloc_handle_for_object(object_id, bootstrap_code_vmo_rights())
                .expect("bootstrap self code vmo handle allocation must succeed");
        }

        state
    }

    fn alloc_object_id(&mut self) -> u64 {
        let id = self.next_object_id;
        self.next_object_id = self.next_object_id.wrapping_add(1);
        id
    }

    fn alloc_socket_core_id(&mut self) -> u64 {
        let id = self.next_socket_core_id;
        self.next_socket_core_id = self.next_socket_core_id.wrapping_add(1);
        id
    }

    fn note_socket_write(&mut self, requested: usize, written: usize, buffered_after: usize) {
        if written == 0 && requested != 0 {
            self.socket_telemetry.write_should_wait_count = self
                .socket_telemetry
                .write_should_wait_count
                .wrapping_add(1);
            return;
        }
        if written < requested {
            self.socket_telemetry.short_write_count =
                self.socket_telemetry.short_write_count.wrapping_add(1);
        }
        self.socket_telemetry.current_buffered_bytes = self
            .socket_telemetry
            .current_buffered_bytes
            .saturating_add(written as u64);
        self.socket_telemetry.peak_buffered_bytes = self
            .socket_telemetry
            .peak_buffered_bytes
            .max(buffered_after as u64);
    }

    fn note_socket_read(&mut self, consumed: usize) {
        self.socket_telemetry.current_buffered_bytes = self
            .socket_telemetry
            .current_buffered_bytes
            .saturating_sub(consumed as u64);
    }

    fn note_socket_core_drop(&mut self, core: &SocketCore) {
        self.socket_telemetry.current_buffered_bytes = self
            .socket_telemetry
            .current_buffered_bytes
            .saturating_sub(core.buffered_bytes() as u64);
    }

    fn with_core<T>(
        &self,
        f: impl FnOnce(&crate::task::Kernel) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        let kernel = self.kernel.lock();
        f(&kernel)
    }

    fn with_core_mut<T>(
        &self,
        f: impl FnOnce(&mut crate::task::Kernel) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        let mut kernel = self.kernel.lock();
        f(&mut kernel)
    }

    fn vm_handle(&self) -> Result<Arc<Mutex<crate::task::VmDomain>>, zx_status_t> {
        let kernel = self.kernel.lock();
        Ok(kernel.vm_handle())
    }

    fn with_vm_mut<T>(
        &self,
        f: impl FnOnce(&mut crate::task::VmDomain) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        let vm = self.vm_handle()?;
        let mut vm = vm.lock();
        f(&mut vm)
    }

    fn with_kernel<T>(
        &self,
        f: impl FnOnce(&crate::task::Kernel) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        self.with_core(f)
    }

    fn with_kernel_mut<T>(
        &self,
        f: impl FnOnce(&mut crate::task::Kernel) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        self.with_core_mut(f)
    }

    fn alloc_handle_for_object(
        &mut self,
        object_id: u64,
        rights: crate::task::HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        let cap = Capability::new(object_id, rights.bits(), DEFAULT_OBJECT_GENERATION);
        let handle = self.with_core_mut(|kernel| kernel.alloc_handle_for_current_process(cap))?;
        self.object_handle_refs
            .entry(object_id)
            .and_modify(|count| *count += 1)
            .or_insert(1);
        Ok(handle)
    }

    fn lookup_handle(
        &self,
        raw: zx_handle_t,
        required_rights: crate::task::HandleRights,
    ) -> Result<crate::task::ResolvedHandle, zx_status_t> {
        self.with_core(|kernel| kernel.lookup_current_handle(raw, required_rights))
    }

    fn close_handle(&mut self, raw: zx_handle_t) -> Result<(), zx_status_t> {
        let object_id = self
            .lookup_handle(raw, crate::task::HandleRights::empty())?
            .object_id();
        self.with_core_mut(|kernel| kernel.close_current_handle(raw))?;
        self.decrement_object_handle_ref(object_id);
        Ok(())
    }

    fn duplicate_handle(
        &mut self,
        raw: zx_handle_t,
        rights: crate::task::HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        let object_id = self
            .lookup_handle(raw, crate::task::HandleRights::empty())?
            .object_id();
        let handle = self.with_core_mut(|kernel| kernel.duplicate_current_handle(raw, rights))?;
        self.object_handle_refs
            .entry(object_id)
            .and_modify(|count| *count += 1)
            .or_insert(1);
        Ok(handle)
    }

    fn replace_handle(
        &mut self,
        raw: zx_handle_t,
        rights: crate::task::HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        self.with_core_mut(|kernel| kernel.replace_current_handle(raw, rights))
    }

    fn snapshot_handle_for_transfer(
        &self,
        raw: zx_handle_t,
        rights: crate::task::HandleRights,
    ) -> Result<TransferredCap, zx_status_t> {
        self.with_core(|kernel| kernel.snapshot_current_handle_for_transfer(raw, rights))
    }

    fn install_transferred_handle(
        &mut self,
        transferred: TransferredCap,
    ) -> Result<zx_handle_t, zx_status_t> {
        let object_id = transferred.capability().object_id();
        let handle =
            self.with_core_mut(|kernel| kernel.install_handle_in_current_process(transferred))?;
        self.object_handle_refs
            .entry(object_id)
            .and_modify(|count| *count += 1)
            .or_insert(1);
        Ok(handle)
    }

    fn object_handle_count(&self, object_id: u64) -> usize {
        self.object_handle_refs
            .get(&object_id)
            .copied()
            .unwrap_or(0)
    }

    fn forget_object_handle_refs(&mut self, object_id: u64) {
        let _ = self.object_handle_refs.remove(&object_id);
    }

    fn decrement_object_handle_ref(&mut self, object_id: u64) {
        match self.object_handle_refs.get_mut(&object_id) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                self.object_handle_refs.remove(&object_id);
            }
            None => {}
        }
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

/// Return the bootstrap current-process code-image VMO handle, if seeded.
pub fn bootstrap_self_code_vmo_handle() -> Option<zx_handle_t> {
    let mut guard = STATE.lock();
    let state = guard.as_mut()?;
    (state.bootstrap_self_code_vmo_handle != 0).then_some(state.bootstrap_self_code_vmo_handle)
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

pub(crate) fn socket_telemetry_snapshot() -> SocketTelemetrySnapshot {
    let mut guard = STATE.lock();
    let Some(state) = guard.as_mut() else {
        return SocketTelemetrySnapshot::default();
    };
    state.socket_telemetry
}

pub(crate) fn capture_current_user_context(
    trap: &crate::arch::int80::TrapFrame,
    cpu_frame: *const u64,
) -> Result<(), zx_status_t> {
    with_kernel_mut(|kernel| kernel.capture_current_user_context(trap, cpu_frame))
}

pub(crate) fn finish_syscall(
    trap: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *mut u64,
) -> Result<(), zx_status_t> {
    run_trap_blocking(|resuming_blocked_current| {
        with_state_mut(|state| {
            let disposition = state.with_kernel_mut(|kernel| {
                kernel.finish_trap_exit(trap, cpu_frame, resuming_blocked_current)
            })?;
            let lifecycle_dirty =
                state.with_kernel_mut(|kernel| Ok(kernel.take_task_lifecycle_dirty()))?;
            if lifecycle_dirty {
                sync_task_lifecycle(state)?;
            }
            Ok(match disposition {
                crate::task::TrapExitDisposition::Complete => TrapBlock::Ready(()),
                crate::task::TrapExitDisposition::BlockCurrent => TrapBlock::BlockCurrent,
            })
        })
    })
}

#[allow(dead_code)]
pub(crate) fn resolve_current_futex_key_relaxed(
    user_addr: zx_vaddr_t,
) -> Result<axle_mm::FutexKey, zx_status_t> {
    with_kernel_mut(|kernel| kernel.resolve_current_futex_key_relaxed(user_addr))
}

fn read_current_futex_word(user_addr: zx_vaddr_t) -> Result<zx_futex_t, zx_status_t> {
    if (user_addr & 0x3) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if !crate::userspace::validate_user_ptr(user_addr, size_of::<zx_futex_t>()) {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let ptr = user_addr as *const zx_futex_t;
    // SAFETY: the user range was validated above and the word is read-only here.
    unsafe { Ok(core::ptr::read_unaligned(ptr)) }
}

#[allow(dead_code)]
pub(crate) fn resolve_current_futex_key(
    user_addr: zx_vaddr_t,
) -> Result<axle_mm::FutexKey, zx_status_t> {
    with_kernel_mut(|kernel| kernel.resolve_current_futex_key(user_addr))
}

fn with_state_mut<T>(
    f: impl FnOnce(&mut KernelState) -> Result<T, zx_status_t>,
) -> Result<T, zx_status_t> {
    let mut guard = STATE.lock();
    let state = guard.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
    f(state)
}

fn kernel_handle() -> Result<Arc<Mutex<crate::task::Kernel>>, zx_status_t> {
    let guard = STATE.lock();
    let state = guard.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
    Ok(state.kernel.clone())
}

fn vm_handle() -> Result<Arc<Mutex<crate::task::VmDomain>>, zx_status_t> {
    let kernel = kernel_handle()?;
    let kernel = kernel.lock();
    Ok(kernel.vm_handle())
}

fn fault_handle() -> Result<Arc<Mutex<crate::task::FaultTable>>, zx_status_t> {
    let kernel = kernel_handle()?;
    let kernel = kernel.lock();
    Ok(kernel.fault_handle())
}

fn with_core_mut<T>(
    f: impl FnOnce(&mut crate::task::Kernel) -> Result<T, zx_status_t>,
) -> Result<T, zx_status_t> {
    let kernel = kernel_handle()?;
    let mut kernel = kernel.lock();
    f(&mut kernel)
}

fn with_core<T>(
    f: impl FnOnce(&crate::task::Kernel) -> Result<T, zx_status_t>,
) -> Result<T, zx_status_t> {
    let kernel = kernel_handle()?;
    let kernel = kernel.lock();
    f(&kernel)
}

fn with_vm_mut<T>(
    f: impl FnOnce(&mut crate::task::VmDomain) -> Result<T, zx_status_t>,
) -> Result<T, zx_status_t> {
    let vm = vm_handle()?;
    let mut vm = vm.lock();
    f(&mut vm)
}

fn with_vm<T>(
    f: impl FnOnce(&crate::task::VmDomain) -> Result<T, zx_status_t>,
) -> Result<T, zx_status_t> {
    let vm = vm_handle()?;
    let vm = vm.lock();
    f(&vm)
}

fn with_kernel_mut<T>(
    f: impl FnOnce(&mut crate::task::Kernel) -> Result<T, zx_status_t>,
) -> Result<T, zx_status_t> {
    with_core_mut(f)
}

fn with_kernel<T>(
    f: impl FnOnce(&crate::task::Kernel) -> Result<T, zx_status_t>,
) -> Result<T, zx_status_t> {
    with_core(f)
}

fn block_current_trap_until_runnable() {
    x86_64::instructions::interrupts::enable_and_hlt();
    x86_64::instructions::interrupts::disable();
}

fn run_trap_blocking<T>(
    mut f: impl FnMut(bool) -> Result<TrapBlock<T>, zx_status_t>,
) -> Result<T, zx_status_t> {
    let mut resuming_blocked_current = false;
    loop {
        match f(resuming_blocked_current)? {
            TrapBlock::Ready(value) => return Ok(value),
            TrapBlock::BlockCurrent => {
                resuming_blocked_current = true;
                block_current_trap_until_runnable();
            }
        }
    }
}

/// Create a new Port object and return a handle.
pub fn create_port(options: u32) -> Result<zx_handle_t, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let object_id = state.alloc_object_id();
        let port = state.with_kernel_mut(|kernel| {
            KernelPort::new(kernel, PORT_CAPACITY, PORT_KERNEL_RESERVE)
        })?;
        state.objects.insert(object_id, KernelObject::Port(port));

        match state.alloc_handle_for_object(object_id, port_default_rights()) {
            Ok(h) => Ok(h),
            Err(e) => {
                if let Some(KernelObject::Port(port)) = state.objects.remove(&object_id) {
                    let _ = state.with_kernel_mut(|kernel| port.destroy(kernel));
                }
                Err(e)
            }
        }
    })
}

/// Create a socket endpoint pair and return both handles.
pub fn create_socket(options: u32) -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    match options {
        ZX_SOCKET_STREAM => {}
        ZX_SOCKET_DATAGRAM => return Err(ZX_ERR_NOT_SUPPORTED),
        _ => return Err(ZX_ERR_INVALID_ARGS),
    }

    with_state_mut(|state| {
        let core_id = state.alloc_socket_core_id();
        let core = SocketCore::new_stream(SOCKET_STREAM_CAPACITY)?;
        state.socket_cores.insert(core_id, core);

        let left_object_id = state.alloc_object_id();
        let right_object_id = state.alloc_object_id();
        state.objects.insert(
            left_object_id,
            KernelObject::Socket(SocketEndpoint {
                core_id,
                peer_object_id: right_object_id,
                side: SocketSide::A,
            }),
        );
        state.objects.insert(
            right_object_id,
            KernelObject::Socket(SocketEndpoint {
                core_id,
                peer_object_id: left_object_id,
                side: SocketSide::B,
            }),
        );

        let left_handle =
            match state.alloc_handle_for_object(left_object_id, socket_default_rights()) {
                Ok(handle) => handle,
                Err(err) => {
                    let _ = state.objects.remove(&left_object_id);
                    let _ = state.objects.remove(&right_object_id);
                    let _ = state.socket_cores.remove(&core_id);
                    return Err(err);
                }
            };
        let right_handle =
            match state.alloc_handle_for_object(right_object_id, socket_default_rights()) {
                Ok(handle) => handle,
                Err(err) => {
                    let _ = state.close_handle(left_handle);
                    let _ = state.objects.remove(&left_object_id);
                    let _ = state.objects.remove(&right_object_id);
                    let _ = state.socket_cores.remove(&core_id);
                    return Err(err);
                }
            };

        Ok((left_handle, right_handle))
    })
}

/// Create a channel endpoint pair and return both handles.
pub fn create_channel(options: u32) -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let owner_process_id = state
            .with_kernel(|kernel| kernel.current_process_info())?
            .process_id();
        let left_object_id = state.alloc_object_id();
        let right_object_id = state.alloc_object_id();
        state.objects.insert(
            left_object_id,
            KernelObject::Channel(ChannelEndpoint::new(right_object_id, owner_process_id)),
        );
        state.objects.insert(
            right_object_id,
            KernelObject::Channel(ChannelEndpoint::new(left_object_id, owner_process_id)),
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

fn release_channel_payload(state: &mut KernelState, payload: ChannelPayload) {
    if let ChannelPayload::Loaned(loaned) = payload {
        let _ = state.with_vm_mut(|vm| {
            vm.release_loaned_user_pages(&loaned);
            Ok(())
        });
    }
}

fn retain_transferred_handles(state: &mut KernelState, handles: &[TransferredCap]) {
    for transferred in handles {
        state
            .object_handle_refs
            .entry(transferred.capability().object_id())
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }
}

fn release_transferred_handles(state: &mut KernelState, handles: &[TransferredCap]) {
    for transferred in handles {
        state.decrement_object_handle_ref(transferred.capability().object_id());
    }
}

fn release_channel_message(state: &mut KernelState, message: ChannelMessage) {
    release_transferred_handles(state, &message.handles);
    release_channel_payload(state, message.payload);
}

fn drain_channel_messages(
    state: &mut KernelState,
    messages: impl IntoIterator<Item = ChannelMessage>,
) {
    for message in messages {
        release_channel_message(state, message);
    }
}

fn channel_endpoint_address_space_id(
    state: &KernelState,
    endpoint: &ChannelEndpoint,
) -> Result<u64, zx_status_t> {
    state.with_core(|kernel| kernel.process_address_space_id(endpoint.owner_process_id))
}

pub(crate) fn try_loan_current_user_pages(
    ptr: u64,
    len: usize,
) -> Result<Option<crate::task::LoanedUserPages>, zx_status_t> {
    let address_space_id = with_core(|kernel| {
        let process = kernel.current_process_info()?;
        kernel.process_address_space_id(process.process_id())
    })?;
    with_vm_mut(|vm| vm.try_loan_user_pages(address_space_id, ptr, len))
}

pub(crate) fn try_remap_loaned_channel_read(
    dst_base: u64,
    loaned: &crate::task::LoanedUserPages,
) -> Result<bool, zx_status_t> {
    let address_space_id = with_core(|kernel| {
        let process = kernel.current_process_info()?;
        kernel.process_address_space_id(process.process_id())
    })?;
    with_vm_mut(|vm| vm.try_remap_loaned_channel_read(address_space_id, dst_base, loaned))
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
        match state.alloc_handle_for_object(object_id, thread_default_rights()) {
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
                mapping_caps: root_vmar_mapping_caps(),
            }),
        );

        let process_handle =
            match state.alloc_handle_for_object(process_object_id, process_default_rights()) {
                Ok(handle) => handle,
                Err(err) => {
                    let _ = state.objects.remove(&process_object_id);
                    let _ = state.objects.remove(&vmar_object_id);
                    return Err(err);
                }
            };
        let root_vmar_handle =
            match state.alloc_handle_for_object(vmar_object_id, vmar_default_rights()) {
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
        let token_handle =
            match state.alloc_handle_for_object(object_id, suspend_token_default_rights()) {
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

/// Create an EventPair endpoint pair and return both handles.
pub fn create_eventpair(options: u32) -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let left_object_id = state.alloc_object_id();
        let right_object_id = state.alloc_object_id();
        state.objects.insert(
            left_object_id,
            KernelObject::EventPair(EventPairEndpoint::new(right_object_id)),
        );
        state.objects.insert(
            right_object_id,
            KernelObject::EventPair(EventPairEndpoint::new(left_object_id)),
        );

        let left_handle =
            match state.alloc_handle_for_object(left_object_id, eventpair_default_rights()) {
                Ok(handle) => handle,
                Err(e) => {
                    let _ = state.objects.remove(&left_object_id);
                    let _ = state.objects.remove(&right_object_id);
                    return Err(e);
                }
            };
        let right_handle =
            match state.alloc_handle_for_object(right_object_id, eventpair_default_rights()) {
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
    with_kernel(|kernel| Ok(kernel.validate_current_user_ptr(ptr, len))).unwrap_or(false)
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
    let address_space_id = with_core(|kernel| {
        let process = kernel.current_process_info()?;
        kernel.process_address_space_id(process.process_id())
    })?;
    let vm = vm_handle()?;
    let faults = fault_handle()?;
    if !with_vm(|vm| Ok(vm.validate_user_ptr(address_space_id, ptr, len)))? {
        return Err(ZX_ERR_INVALID_ARGS);
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

    let mut page_va = start;
    while page_va < end {
        crate::task::ensure_user_page_resident_serialized(
            vm.clone(),
            faults.clone(),
            address_space_id,
            page_va,
            for_write,
        )?;
        page_va = page_va.checked_add(page_bytes).ok_or(ZX_ERR_OUT_OF_RANGE)?;
    }
    Ok(())
}

/// Try to resolve a bootstrap user-mode page fault.
pub fn handle_page_fault(
    trap: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *mut u64,
    cr2: u64,
    error: u64,
) -> bool {
    // SAFETY: x86_64 faults with an error code place that code at `cpu_frame[0]`,
    // followed by the user IRET frame {rip, cs, rflags, rsp, ss}. The generic
    // trap-exit/context helpers expect a pointer to the first IRET slot.
    let user_cpu_frame = unsafe { cpu_frame.add(1) };
    let vm = match vm_handle() {
        Ok(vm) => vm,
        Err(_) => return false,
    };
    let faults = match fault_handle() {
        Ok(faults) => faults,
        Err(_) => return false,
    };
    let kernel = match kernel_handle() {
        Ok(kernel) => kernel,
        Err(_) => return false,
    };
    run_trap_blocking(|resuming_blocked_current| {
        if resuming_blocked_current {
            return with_state_mut(|state| {
                let disposition = state.with_kernel_mut(|kernel| {
                    kernel.finish_trap_exit(trap, user_cpu_frame, true)
                })?;
                let lifecycle_dirty =
                    state.with_kernel_mut(|kernel| Ok(kernel.take_task_lifecycle_dirty()))?;
                if lifecycle_dirty {
                    sync_task_lifecycle(state)?;
                }
                Ok(match disposition {
                    crate::task::TrapExitDisposition::Complete => TrapBlock::Ready(true),
                    crate::task::TrapExitDisposition::BlockCurrent => TrapBlock::BlockCurrent,
                })
            });
        }

        let (thread_id, address_space_id) = with_core(|kernel| {
            let process = kernel.current_process_info()?;
            let thread = kernel.current_thread_info()?;
            Ok((
                thread.thread_id(),
                kernel.process_address_space_id(process.process_id())?,
            ))
        })?;

        match crate::task::handle_page_fault_serialized(
            kernel.clone(),
            vm.clone(),
            faults.clone(),
            address_space_id,
            thread_id,
            cr2,
            error,
        ) {
            crate::task::PageFaultSerializedResult::Handled => {
                let cpu_id = crate::arch::apic::this_apic_id() as usize;
                let _ = with_vm_mut(|vm| {
                    let _ = vm.sync_current_cpu_tlb_state(address_space_id, cpu_id);
                    Ok(())
                });
                Ok(TrapBlock::Ready(true))
            }
            crate::task::PageFaultSerializedResult::Unhandled => Ok(TrapBlock::Ready(false)),
            crate::task::PageFaultSerializedResult::BlockCurrent { key, wake_thread } => {
                with_kernel_mut(|kernel| {
                    kernel.capture_current_user_context(trap, user_cpu_frame.cast_const())?;
                    kernel.enqueue_current_fault_wait(key)?;
                    if let Some(thread_id) = wake_thread {
                        kernel.make_thread_runnable_preserving_context(thread_id)?;
                    }
                    let disposition = kernel.finish_trap_exit(trap, user_cpu_frame, false)?;
                    let lifecycle_dirty = kernel.take_task_lifecycle_dirty();
                    Ok((disposition, lifecycle_dirty))
                })
                .and_then(|(disposition, lifecycle_dirty)| {
                    with_state_mut(|state| {
                        if lifecycle_dirty {
                            sync_task_lifecycle(state)?;
                        }
                        Ok(match disposition {
                            crate::task::TrapExitDisposition::Complete => TrapBlock::Ready(true),
                            crate::task::TrapExitDisposition::BlockCurrent => {
                                TrapBlock::BlockCurrent
                            }
                        })
                    })
                })
            }
        }
    })
    .unwrap_or(false)
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
        let object_id = state.alloc_object_id();
        let global_vmo_id = state.with_kernel_mut(|kernel| Ok(kernel.allocate_global_vmo_id()))?;
        let (process_id, address_space_id) = state.with_core(|kernel| {
            let process = kernel.current_process_info()?;
            let address_space_id = kernel.process_address_space_id(process.process_id())?;
            Ok((process.process_id(), address_space_id))
        })?;
        let created = state.with_vm_mut(|vm| {
            vm.create_anonymous_vmo_for_address_space(
                process_id,
                address_space_id,
                size,
                global_vmo_id,
            )
        })?;
        state.objects.insert(
            object_id,
            KernelObject::Vmo(VmoObject {
                creator_process_id: created.process_id(),
                global_vmo_id: created.global_vmo_id(),
                kind: axle_mm::VmoKind::Anonymous,
                size_bytes: created.size_bytes(),
                image_layout: None,
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

/// Read bytes from one VMO into a kernel-owned buffer.
pub fn vmo_read(handle: zx_handle_t, offset: u64, len: usize) -> Result<Vec<u8>, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let vmo = match state.objects.get(&resolved.object_id()) {
            Some(KernelObject::Vmo(vmo)) => vmo.clone(),
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        require_handle_rights(resolved, crate::task::HandleRights::READ)?;
        state.with_vm_mut(|vm| vm.read_vmo_bytes(vmo.global_vmo_id, offset, len))
    })
}

/// Write bytes into one VMO from a kernel-owned buffer.
pub fn vmo_write(handle: zx_handle_t, offset: u64, bytes: &[u8]) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let vmo = match state.objects.get(&resolved.object_id()) {
            Some(KernelObject::Vmo(vmo)) => vmo.clone(),
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;
        state.with_vm_mut(|vm| vm.write_vmo_bytes(vmo.global_vmo_id, offset, bytes))
    })
}

/// Resize one VMO.
pub fn vmo_set_size(handle: zx_handle_t, size: u64) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_id = resolved.object_id();
        let vmo = match state.objects.get(&object_id) {
            Some(KernelObject::Vmo(vmo)) => vmo.clone(),
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;
        state.with_vm_mut(|vm| vm.set_vmo_size(vmo.global_vmo_id, size))?;
        let Some(KernelObject::Vmo(vmo)) = state.objects.get_mut(&object_id) else {
            return Err(ZX_ERR_BAD_STATE);
        };
        vmo.size_bytes = size;
        Ok(())
    })
}

/// Write bytes into one stream socket.
pub fn socket_write(handle: zx_handle_t, options: u32, bytes: &[u8]) -> Result<usize, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let endpoint = match state.objects.get(&resolved.object_id()) {
            Some(KernelObject::Socket(endpoint)) => *endpoint,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;

        let write_result = {
            let core = state
                .socket_cores
                .get_mut(&endpoint.core_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            match core.write(endpoint.side, bytes) {
                Ok(written) => Ok((written, core.buffered_bytes())),
                Err(ZX_ERR_SHOULD_WAIT) => Err((ZX_ERR_SHOULD_WAIT, core.buffered_bytes())),
                Err(e) => Err((e, core.buffered_bytes())),
            }
        };
        let (written, buffered_after) = match write_result {
            Ok(result) => result,
            Err((ZX_ERR_SHOULD_WAIT, buffered_after)) => {
                state.note_socket_write(bytes.len(), 0, buffered_after);
                return Err(ZX_ERR_SHOULD_WAIT);
            }
            Err((e, _)) => return Err(e),
        };
        state.note_socket_write(bytes.len(), written, buffered_after);

        let _ = notify_waitable_signals_changed(state, resolved.object_id());
        let _ = notify_waitable_signals_changed(state, endpoint.peer_object_id);
        Ok(written)
    })
}

/// Read bytes from one stream socket.
pub fn socket_read(handle: zx_handle_t, options: u32, len: usize) -> Result<Vec<u8>, zx_status_t> {
    let peek = match options {
        0 => false,
        ZX_SOCKET_PEEK => true,
        _ => return Err(ZX_ERR_INVALID_ARGS),
    };

    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let endpoint = match state.objects.get(&resolved.object_id()) {
            Some(KernelObject::Socket(endpoint)) => *endpoint,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        require_handle_rights(resolved, crate::task::HandleRights::READ)?;

        let bytes = {
            let core = state
                .socket_cores
                .get_mut(&endpoint.core_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            core.read(endpoint.side, len, !peek)?
        };

        if !peek {
            state.note_socket_read(bytes.len());
            let _ = notify_waitable_signals_changed(state, resolved.object_id());
            let _ = notify_waitable_signals_changed(state, endpoint.peer_object_id);
        }
        Ok(bytes)
    })
}

/// Write one copied message into the peer side of a channel.
pub fn channel_write(
    handle: zx_handle_t,
    options: u32,
    payload: ChannelPayload,
    handles: Vec<zx_handle_t>,
) -> Result<(), zx_status_t> {
    if options != 0 {
        let _ = with_state_mut(|state| {
            release_channel_payload(state, payload);
            Ok(())
        });
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let mut payload = Some(payload);
        let mut transferred = Vec::new();
        let resolved = match state.lookup_handle(handle, crate::task::HandleRights::empty()) {
            Ok(resolved) => resolved,
            Err(status) => {
                if let Some(payload) = payload.take() {
                    release_channel_payload(state, payload);
                }
                return Err(status);
            }
        };
        let object_id = resolved.object_id();
        let peer_object_id = {
            let endpoint = match state.objects.get(&object_id) {
                Some(KernelObject::Channel(endpoint)) => endpoint,
                Some(_) => {
                    if let Some(payload) = payload.take() {
                        release_channel_payload(state, payload);
                    }
                    return Err(ZX_ERR_WRONG_TYPE);
                }
                None => {
                    if let Some(payload) = payload.take() {
                        release_channel_payload(state, payload);
                    }
                    return Err(ZX_ERR_BAD_HANDLE);
                }
            };
            if let Err(status) = require_handle_rights(resolved, crate::task::HandleRights::WRITE) {
                if let Some(payload) = payload.take() {
                    release_channel_payload(state, payload);
                }
                return Err(status);
            }
            endpoint.peer_object_id
        };

        let receiver_address_space_id = {
            let peer = match state.objects.get(&peer_object_id) {
                Some(KernelObject::Channel(peer)) => peer,
                Some(_) => {
                    if let Some(payload) = payload.take() {
                        release_channel_payload(state, payload);
                    }
                    return Err(ZX_ERR_BAD_STATE);
                }
                None => {
                    if let Some(payload) = payload.take() {
                        release_channel_payload(state, payload);
                    }
                    return Err(ZX_ERR_PEER_CLOSED);
                }
            };
            if peer.closed {
                if let Some(payload) = payload.take() {
                    release_channel_payload(state, payload);
                }
                return Err(ZX_ERR_PEER_CLOSED);
            }
            if peer.messages.len() >= CHANNEL_CAPACITY {
                if let Some(payload) = payload.take() {
                    release_channel_payload(state, payload);
                }
                return Err(ZX_ERR_SHOULD_WAIT);
            }
            channel_endpoint_address_space_id(state, peer)?
        };

        if let Some(ChannelPayload::Loaned(loaned)) = payload.as_mut()
            && let Err(status) = state.with_vm_mut(|vm| {
                vm.prepare_loaned_channel_write(loaned, receiver_address_space_id)
            })
        {
            if let Some(released) = payload.take() {
                release_channel_payload(state, released);
            }
            return Err(status);
        }

        let mut seen_handles = BTreeSet::new();
        for raw in &handles {
            if !seen_handles.insert(*raw) {
                if let Some(released) = payload.take() {
                    release_channel_payload(state, released);
                }
                return Err(ZX_ERR_INVALID_ARGS);
            }
            match state.snapshot_handle_for_transfer(*raw, crate::task::HandleRights::TRANSFER) {
                Ok(entry) => transferred.push(entry),
                Err(status) => {
                    if let Some(released) = payload.take() {
                        release_channel_payload(state, released);
                    }
                    return Err(status);
                }
            }
        }

        let peer_status = match state.objects.get(&peer_object_id) {
            Some(KernelObject::Channel(peer)) if peer.closed => Some(ZX_ERR_PEER_CLOSED),
            Some(KernelObject::Channel(peer)) if peer.messages.len() >= CHANNEL_CAPACITY => {
                Some(ZX_ERR_SHOULD_WAIT)
            }
            Some(KernelObject::Channel(_)) => None,
            Some(_) => Some(ZX_ERR_BAD_STATE),
            None => Some(ZX_ERR_PEER_CLOSED),
        };
        if let Some(status) = peer_status {
            if let Some(payload) = payload.take() {
                release_channel_payload(state, payload);
            }
            return Err(status);
        }

        retain_transferred_handles(state, &transferred);
        let message = ChannelMessage {
            payload: payload.take().ok_or(ZX_ERR_BAD_STATE)?,
            handles: transferred,
        };
        match state.objects.get_mut(&peer_object_id) {
            Some(KernelObject::Channel(peer)) => peer.messages.push_back(message),
            Some(_) => return Err(ZX_ERR_BAD_STATE),
            None => return Err(ZX_ERR_PEER_CLOSED),
        }

        for raw in handles {
            state.close_handle(raw)?;
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
    num_handles: u32,
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
    let (peer_object_id, transferred_handles) = {
        let endpoint = match state.objects.get(&object_id) {
            Some(KernelObject::Channel(endpoint)) => endpoint,
            Some(_) => return Err((ZX_ERR_WRONG_TYPE, 0, 0)),
            None => return Err((ZX_ERR_BAD_HANDLE, 0, 0)),
        };
        require_handle_rights(resolved, crate::task::HandleRights::READ).map_err(|e| (e, 0, 0))?;
        if let Some(message) = endpoint.messages.front() {
            let actual_bytes = message.actual_bytes().map_err(|e| (e, 0, 0))?;
            let actual_handles = message.actual_handles().map_err(|e| (e, 0, 0))?;
            if num_bytes < actual_bytes {
                return Err((ZX_ERR_BUFFER_TOO_SMALL, actual_bytes, actual_handles));
            }
            if num_handles < actual_handles {
                return Err((ZX_ERR_BUFFER_TOO_SMALL, actual_bytes, actual_handles));
            }
            (endpoint.peer_object_id, message.handles.clone())
        } else if endpoint.peer_closed {
            return Err((ZX_ERR_PEER_CLOSED, 0, 0));
        } else {
            return Err((ZX_ERR_SHOULD_WAIT, 0, 0));
        }
    };

    let mut installed_handles = Vec::new();
    for transferred in transferred_handles {
        match state.install_transferred_handle(transferred) {
            Ok(raw) => installed_handles.push(raw),
            Err(status) => {
                for raw in installed_handles {
                    let _ = state.close_handle(raw);
                }
                return Err((status, 0, 0));
            }
        }
    }

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
    let actual_bytes = message.actual_bytes().map_err(|e| (e, 0, 0))?;
    let actual_handles = message.actual_handles().map_err(|e| (e, 0, 0))?;
    release_transferred_handles(state, &message.handles);

    let _ = notify_waitable_signals_changed(state, object_id);
    let _ = notify_waitable_signals_changed(state, peer_object_id);

    Ok(ChannelReadResult {
        payload: message.payload,
        handles: installed_handles,
        actual_bytes,
        actual_handles,
    })
}

pub(crate) fn release_channel_read_result(result: ChannelReadResult) {
    let _ = with_state_mut(|state| {
        release_channel_payload(state, result.payload);
        Ok(())
    });
}

/// Duplicate one handle, optionally dropping rights.
pub fn duplicate_handle(
    handle: zx_handle_t,
    rights: zx_rights_t,
) -> Result<zx_handle_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::DUPLICATE)?;
        let derived_rights = normalize_requested_rights(resolved, rights)?;
        state.duplicate_handle(handle, derived_rights)
    })
}

/// Replace one handle with a new handle that carries equal-or-fewer rights.
pub fn replace_handle(
    handle: zx_handle_t,
    rights: zx_rights_t,
) -> Result<zx_handle_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::DUPLICATE)?;
        let derived_rights = normalize_requested_rights(resolved, rights)?;
        state.replace_handle(handle, derived_rights)
    })
}

/// Signal the local side of an EventPair.
pub fn object_signal(
    handle: zx_handle_t,
    clear_mask: zx_signals_t,
    set_mask: zx_signals_t,
) -> Result<(), zx_status_t> {
    let clear = Signals::from_bits(clear_mask);
    let set = Signals::from_bits(set_mask);
    if !clear.without(USER_SIGNAL_MASK).is_empty() || !set.without(USER_SIGNAL_MASK).is_empty() {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::SIGNAL)?;
        let endpoint = match state.objects.get_mut(&resolved.object_id()) {
            Some(KernelObject::EventPair(endpoint)) => endpoint,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        endpoint.user_signals = endpoint.user_signals.without(clear).union(set);
        let _ = notify_waitable_signals_changed(state, resolved.object_id());
        Ok(())
    })
}

/// Signal the peer side of an EventPair.
pub fn object_signal_peer(
    handle: zx_handle_t,
    clear_mask: zx_signals_t,
    set_mask: zx_signals_t,
) -> Result<(), zx_status_t> {
    let clear = Signals::from_bits(clear_mask);
    let set = Signals::from_bits(set_mask);
    if !clear.without(USER_SIGNAL_MASK).is_empty() || !set.without(USER_SIGNAL_MASK).is_empty() {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let peer_object_id = {
            let endpoint = match state.objects.get(&resolved.object_id()) {
                Some(KernelObject::EventPair(endpoint)) => endpoint,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };
            require_handle_rights(resolved, crate::task::HandleRights::SIGNAL_PEER)?;
            if endpoint.peer_closed {
                return Err(ZX_ERR_PEER_CLOSED);
            }
            endpoint.peer_object_id
        };

        let peer = match state.objects.get_mut(&peer_object_id) {
            Some(KernelObject::EventPair(peer)) => peer,
            Some(_) => return Err(ZX_ERR_BAD_STATE),
            None => return Err(ZX_ERR_PEER_CLOSED),
        };
        if peer.closed {
            return Err(ZX_ERR_PEER_CLOSED);
        }
        peer.user_signals = peer.user_signals.without(clear).union(set);
        let _ = notify_waitable_signals_changed(state, peer_object_id);
        Ok(())
    })
}

/// Allocate one child VMAR from an existing parent VMAR.
#[allow(clippy::too_many_arguments)]
pub fn vmar_allocate(
    parent_vmar_handle: zx_handle_t,
    options: u32,
    offset: u64,
    len: u64,
) -> Result<(zx_handle_t, u64), zx_status_t> {
    let request = vmar_allocate_request_from_options(options, offset)?;

    with_state_mut(|state| {
        let resolved_parent =
            state.lookup_handle(parent_vmar_handle, crate::task::HandleRights::empty())?;
        let parent = match state.objects.get(&resolved_parent.object_id()) {
            Some(KernelObject::Vmar(vmar)) => *vmar,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };

        require_vmar_control_rights(resolved_parent)?;
        require_vmar_child_mapping_caps(parent.mapping_caps, request.mapping_caps)?;
        if (request.mode == VmarAllocMode::Specific || request.offset_is_upper_limit)
            && !parent.mapping_caps.can_map_specific
        {
            return Err(ZX_ERR_ACCESS_DENIED);
        }

        let cpu_id = crate::arch::apic::this_apic_id() as usize;
        let child = state.with_vm_mut(|vm| {
            vm.allocate_subvmar(
                parent.address_space_id,
                cpu_id,
                parent.vmar_id,
                offset,
                len,
                request.align,
                request.mode,
                request.offset_is_upper_limit,
                request.child_policy,
            )
        })?;
        let object_id = state.alloc_object_id();
        state.objects.insert(
            object_id,
            KernelObject::Vmar(VmarObject {
                process_id: parent.process_id,
                address_space_id: parent.address_space_id,
                vmar_id: child.id(),
                base: child.base(),
                len: child.len(),
                mapping_caps: request.mapping_caps,
            }),
        );

        let child_handle = match state.alloc_handle_for_object(object_id, vmar_default_rights()) {
            Ok(handle) => handle,
            Err(err) => {
                let _ = state.objects.remove(&object_id);
                let _ =
                    state.with_vm_mut(|vm| vm.destroy_vmar(parent.address_space_id, child.id()));
                return Err(err);
            }
        };

        Ok((child_handle, child.base()))
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
    let request = mapping_request_from_options(options, vmar_offset)?;

    with_state_mut(|state| {
        let resolved_vmar = state.lookup_handle(vmar_handle, crate::task::HandleRights::empty())?;
        let resolved_vmo = state.lookup_handle(vmo_handle, crate::task::HandleRights::empty())?;
        let vmar = match state.objects.get(&resolved_vmar.object_id()) {
            Some(KernelObject::Vmar(vmar)) => *vmar,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        let vmo = match state.objects.get(&resolved_vmo.object_id()) {
            Some(KernelObject::Vmo(vmo)) => vmo.clone(),
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };

        require_vm_mapping_rights(resolved_vmar, request.perms)?;
        require_vm_mapping_rights(resolved_vmo, request.perms)?;
        require_vmar_mapping_caps(vmar.mapping_caps, request.perms, request.specific)?;
        let cpu_id = crate::arch::apic::this_apic_id() as usize;
        state.with_vm_mut(|vm| {
            vm.map_vmo_into_vmar(
                vmar.address_space_id,
                cpu_id,
                vmar.vmar_id,
                vmo.global_vmo_id,
                request.specific.then_some(vmar_offset),
                vmo_offset,
                len,
                request.perms,
            )
        })
    })
}

/// Destroy one child VMAR and recursively unmap mappings inside it.
pub fn vmar_destroy(vmar_handle: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved_vmar = state.lookup_handle(vmar_handle, crate::task::HandleRights::empty())?;
        let vmar = match state.objects.get(&resolved_vmar.object_id()) {
            Some(KernelObject::Vmar(vmar)) => *vmar,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        require_vmar_control_rights(resolved_vmar)?;
        state.with_vm_mut(|vm| vm.destroy_vmar(vmar.address_space_id, vmar.vmar_id))?;
        let _ = state.objects.remove(&resolved_vmar.object_id());
        Ok(())
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
        state.with_vm_mut(|vm| vm.unmap_vmar(vmar.address_space_id, vmar.vmar_id, addr, len))
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
        require_vmar_mapping_caps(vmar.mapping_caps, perms, false)?;
        state.with_vm_mut(|vm| {
            vm.protect_vmar(vmar.address_space_id, vmar.vmar_id, addr, len, perms)
        })
    })
}

fn validate_futex_wait_owner(
    state: &KernelState,
    key: axle_mm::FutexKey,
    owner_handle: zx_handle_t,
) -> Result<zx_koid_t, zx_status_t> {
    if owner_handle == ZX_HANDLE_INVALID {
        return Ok(ZX_KOID_INVALID);
    }
    let resolved = state.lookup_handle(owner_handle, crate::task::HandleRights::empty())?;
    let thread = match state.objects.get(&resolved.object_id()) {
        Some(KernelObject::Thread(thread)) => *thread,
        Some(_) => return Err(ZX_ERR_WRONG_TYPE),
        None => return Err(ZX_ERR_BAD_HANDLE),
    };
    let current = state.with_kernel(|kernel| kernel.current_thread_info())?;
    if thread.thread_id == current.thread_id()
        || state
            .with_kernel(|kernel| Ok(kernel.thread_is_waiting_on_futex(thread.thread_id, key)))?
    {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(thread.koid)
}

fn validate_futex_requeue_owner(
    state: &KernelState,
    source: axle_mm::FutexKey,
    target: axle_mm::FutexKey,
    owner_handle: zx_handle_t,
) -> Result<zx_koid_t, zx_status_t> {
    if owner_handle == ZX_HANDLE_INVALID {
        return Ok(ZX_KOID_INVALID);
    }
    let resolved = state.lookup_handle(owner_handle, crate::task::HandleRights::empty())?;
    let thread = match state.objects.get(&resolved.object_id()) {
        Some(KernelObject::Thread(thread)) => *thread,
        Some(_) => return Err(ZX_ERR_WRONG_TYPE),
        None => return Err(ZX_ERR_BAD_HANDLE),
    };
    if state
        .with_kernel(|kernel| Ok(kernel.thread_is_waiting_on_futex(thread.thread_id, source)))?
        || state
            .with_kernel(|kernel| Ok(kernel.thread_is_waiting_on_futex(thread.thread_id, target)))?
    {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(thread.koid)
}

/// Wait on a futex word until another thread wakes it or the deadline expires.
pub fn futex_wait(
    value_ptr: zx_vaddr_t,
    current_value: zx_futex_t,
    new_futex_owner: zx_handle_t,
    deadline: i64,
) -> Result<(), zx_status_t> {
    let observed = read_current_futex_word(value_ptr)?;
    if observed != current_value {
        return Err(ZX_ERR_BAD_STATE);
    }
    let key = resolve_current_futex_key(value_ptr)?;

    let blocked_on_scheduler = with_state_mut(|state| {
        let owner_koid = validate_futex_wait_owner(state, key, new_futex_owner)?;
        if deadline == i64::MAX {
            state.with_kernel_mut(|kernel| kernel.enqueue_current_futex_wait(key, owner_koid))?;
            Ok(true)
        } else {
            Ok(false)
        }
    })?;

    if blocked_on_scheduler {
        return Ok(());
    }

    let mut registered = false;
    loop {
        let still_waiting = with_state_mut(|state| {
            if !registered {
                let owner_koid = validate_futex_wait_owner(state, key, new_futex_owner)?;
                state
                    .with_kernel_mut(|kernel| kernel.enqueue_current_futex_wait(key, owner_koid))?;
                registered = true;
            }
            let current = state.with_kernel(|kernel| kernel.current_thread_info())?;
            state.with_kernel(|kernel| {
                Ok(kernel.thread_is_waiting_on_futex(current.thread_id(), key))
            })
        })?;
        if !still_waiting {
            return Ok(());
        }

        let now = crate::time::now_ns();
        if deadline != i64::MAX && deadline <= now {
            with_state_mut(|state| {
                let _ = state.with_kernel_mut(|kernel| kernel.cancel_current_futex_wait())?;
                Ok(())
            })?;
            return Err(ZX_ERR_TIMED_OUT);
        }

        x86_64::instructions::interrupts::enable_and_hlt();
        x86_64::instructions::interrupts::disable();
    }
}

/// Wake up to `wake_count` waiters from one futex.
pub fn futex_wake(value_ptr: zx_vaddr_t, wake_count: u32) -> Result<(), zx_status_t> {
    let key = resolve_current_futex_key_relaxed(value_ptr)?;
    with_state_mut(|state| {
        let _ = state.with_kernel_mut(|kernel| {
            kernel.wake_futex_waiters(key, wake_count as usize, ZX_KOID_INVALID, false)
        })?;
        Ok(())
    })
}

/// Move waiters from one futex queue to another.
pub fn futex_requeue(
    value_ptr: zx_vaddr_t,
    wake_count: u32,
    current_value: zx_futex_t,
    requeue_ptr: zx_vaddr_t,
    requeue_count: u32,
    new_requeue_owner: zx_handle_t,
) -> Result<(), zx_status_t> {
    let source_key = resolve_current_futex_key(value_ptr)?;
    let target_key = resolve_current_futex_key(requeue_ptr)?;
    if source_key == target_key {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let observed = read_current_futex_word(value_ptr)?;
    if observed != current_value {
        return Err(ZX_ERR_BAD_STATE);
    }

    with_state_mut(|state| {
        let owner_koid =
            validate_futex_requeue_owner(state, source_key, target_key, new_requeue_owner)?;
        let _ = state.with_kernel_mut(|kernel| {
            kernel.requeue_futex_waiters(
                source_key,
                target_key,
                wake_count as usize,
                requeue_count as usize,
                owner_koid,
            )
        })?;
        Ok(())
    })
}

/// Report the current futex owner koid, or `ZX_KOID_INVALID` when unlocked.
pub fn futex_get_owner(value_ptr: zx_vaddr_t) -> Result<zx_koid_t, zx_status_t> {
    let key = resolve_current_futex_key_relaxed(value_ptr)?;
    with_state_mut(|state| state.with_kernel(|kernel| Ok(kernel.futex_owner(key))))
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
            Some(KernelObject::Process(_))
            | Some(KernelObject::SuspendToken(_))
            | Some(KernelObject::Socket(_))
            | Some(KernelObject::Channel(_))
            | Some(KernelObject::EventPair(_))
            | Some(KernelObject::Port(_))
            | Some(KernelObject::Thread(_))
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
            Some(KernelObject::Process(_))
            | Some(KernelObject::SuspendToken(_))
            | Some(KernelObject::Socket(_))
            | Some(KernelObject::Channel(_))
            | Some(KernelObject::EventPair(_))
            | Some(KernelObject::Port(_))
            | Some(KernelObject::Thread(_))
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
            require_handle_rights(resolved, crate::task::HandleRights::READ)?;
            port.pop().map_err(map_port_error)?
        };

        // Port queue state changed; notify async observers waiting on port readability/writability.
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
    loop {
        match wait_port_packet(handle) {
            Ok(pkt) => {
                with_state_mut(|state| {
                    let thread_id = state
                        .with_kernel(|kernel| kernel.current_thread_info())?
                        .thread_id();
                    state.with_kernel_mut(|kernel| {
                        kernel.copyout_thread_user(thread_id, out_ptr, pkt)
                    })
                })?;
                return Ok(());
            }
            Err(ZX_ERR_SHOULD_WAIT) => {
                if deadline == 0 {
                    return Err(ZX_ERR_SHOULD_WAIT);
                }
                let blocked_on_scheduler = with_state_mut(|state| {
                    let resolved = state.lookup_handle(handle, crate::task::HandleRights::WAIT)?;
                    let object_id = resolved.object_id();
                    if deadline == i64::MAX {
                        state.with_kernel_mut(|kernel| {
                            kernel.enqueue_current_port_wait(object_id, out_ptr)
                        })?;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                })?;
                if blocked_on_scheduler {
                    return Ok(());
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
    observed_ptr: *mut zx_signals_t,
) -> Result<(), zx_status_t> {
    let watched = Signals::from_bits(watched);
    if watched.is_empty() {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    loop {
        {
            let mut guard = STATE.lock();
            let state = guard.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            let resolved = state.lookup_handle(handle, crate::task::HandleRights::WAIT)?;
            let object_id = resolved.object_id();
            let observed = signals_for_object_id(state, object_id)?;
            if observed.intersects(watched) {
                let thread_id = state
                    .with_kernel(|kernel| kernel.current_thread_info())?
                    .thread_id();
                state.with_kernel_mut(|kernel| {
                    kernel.copyout_thread_user(thread_id, observed_ptr, observed.bits())
                })?;
                return Ok(());
            }
            if deadline == i64::MAX {
                state.with_kernel_mut(|kernel| {
                    kernel.enqueue_current_signal_wait(object_id, watched, observed_ptr)
                })?;
                return Ok(());
            }
        };

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
            with_state_mut(|state| {
                let thread_id = state
                    .with_kernel(|kernel| kernel.current_thread_info())?
                    .thread_id();
                state.with_kernel_mut(|kernel| {
                    kernel.copyout_thread_user(thread_id, observed_ptr, observed.bits())
                })
            })?;
            if observed.intersects(watched) {
                return Ok(());
            }
            return Err(ZX_ERR_TIMED_OUT);
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
        let peer_link = match state.objects.get(&object_id) {
            Some(KernelObject::Socket(endpoint)) => Some(endpoint.peer_object_id),
            Some(KernelObject::Channel(endpoint)) => Some(endpoint.peer_object_id),
            Some(KernelObject::EventPair(endpoint)) => Some(endpoint.peer_object_id),
            Some(_) => None,
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        let suspend_target = match state.objects.get(&object_id) {
            Some(KernelObject::SuspendToken(token)) => Some(token.target),
            _ => None,
        };
        state.close_handle(raw)?;

        if let Some(target) = suspend_target
            && state.object_handle_count(object_id) == 0
        {
            let _ = state.objects.remove(&object_id);
            state.forget_object_handle_refs(object_id);
            match target {
                SuspendTarget::Process { process_id } => {
                    if let Err(status) =
                        state.with_kernel_mut(|kernel| kernel.resume_process(process_id))
                        && status != ZX_ERR_BAD_STATE
                    {
                        return Err(status);
                    }
                }
                SuspendTarget::Thread { thread_id } => {
                    if let Err(status) =
                        state.with_kernel_mut(|kernel| kernel.resume_thread(thread_id))
                        && status != ZX_ERR_BAD_STATE
                    {
                        return Err(status);
                    }
                }
            }
        }

        if let Some(peer_object_id) = peer_link
            && state.object_handle_count(object_id) == 0
        {
            let removed = state.objects.remove(&object_id);
            state.forget_object_handle_refs(object_id);
            match removed {
                Some(KernelObject::Socket(endpoint)) => {
                    let should_drop_core = match state.socket_cores.get_mut(&endpoint.core_id) {
                        Some(core) => {
                            core.close_side(endpoint.side);
                            core.fully_closed()
                        }
                        None => return Err(ZX_ERR_BAD_STATE),
                    };
                    if should_drop_core {
                        if let Some(core) = state.socket_cores.remove(&endpoint.core_id) {
                            state.note_socket_core_drop(&core);
                        }
                    }
                }
                Some(KernelObject::Channel(mut endpoint)) => {
                    endpoint.closed = true;
                    let drained = endpoint.messages.drain(..).collect::<Vec<_>>();
                    drain_channel_messages(state, drained);
                    if let Some(KernelObject::Channel(peer)) =
                        state.objects.get_mut(&peer_object_id)
                    {
                        peer.peer_closed = true;
                    }
                }
                Some(KernelObject::EventPair(_)) => {
                    if let Some(KernelObject::EventPair(peer)) =
                        state.objects.get_mut(&peer_object_id)
                    {
                        peer.peer_closed = true;
                    }
                }
                Some(other) => {
                    state.objects.insert(object_id, other);
                }
                None => {}
            }
            let _ = notify_waitable_signals_changed(state, object_id);
            let _ = notify_waitable_signals_changed(state, peer_object_id);
        }
        if matches!(state.objects.get(&object_id), Some(KernelObject::Port(_)))
            && state.object_handle_count(object_id) == 0
        {
            let Some(KernelObject::Port(port)) = state.objects.remove(&object_id) else {
                return Err(ZX_ERR_BAD_STATE);
            };
            state.forget_object_handle_refs(object_id);
            state.with_kernel_mut(|kernel| port.destroy(kernel))?;
        }
        sync_task_lifecycle(state)?;
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
        let _ = state.with_kernel_mut(|kernel| kernel.sync_current_cpu_tlb_state());
        Ok(())
    });
}

fn ensure_handle_kind(handle: zx_handle_t, expected: ObjectKind) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_id = resolved.object_id();
        let obj = state.objects.get(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;

        let kind = match obj {
            KernelObject::Process(process) => {
                let _ = (process.process_id, process.koid);
                ObjectKind::Process
            }
            KernelObject::SuspendToken(_) => ObjectKind::SuspendToken,
            KernelObject::Socket(endpoint) => {
                let _ = (endpoint.core_id, endpoint.peer_object_id, endpoint.side);
                ObjectKind::Socket
            }
            KernelObject::Channel(endpoint) => {
                let _ = (
                    endpoint.peer_object_id,
                    endpoint.messages.len(),
                    endpoint.peer_closed,
                    endpoint.closed,
                );
                ObjectKind::Channel
            }
            KernelObject::EventPair(endpoint) => {
                let _ = (
                    endpoint.peer_object_id,
                    endpoint.user_signals.bits(),
                    endpoint.peer_closed,
                    endpoint.closed,
                );
                ObjectKind::EventPair
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
                    vmo.creator_process_id,
                    vmo.global_vmo_id.raw(),
                    matches!(vmo.kind, axle_mm::VmoKind::Anonymous),
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
                    vmar.mapping_caps.max_perms.bits(),
                    vmar.mapping_caps.can_map_specific,
                );
                ObjectKind::Vmar
            }
            KernelObject::Thread(thread) => {
                let _ = (thread.process_id, thread.thread_id, thread.koid);
                ObjectKind::Thread
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

fn normalize_requested_rights(
    resolved: crate::task::ResolvedHandle,
    requested: zx_rights_t,
) -> Result<crate::task::HandleRights, zx_status_t> {
    if requested == ZX_RIGHT_SAME_RIGHTS {
        return Ok(resolved.rights());
    }
    if (requested & !ZX_RIGHTS_ALL) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if (requested & !resolved.rights().bits()) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(crate::task::HandleRights::from_zx_rights(requested))
}

fn channel_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
}

fn socket_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
}

fn process_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::INSPECT
        | crate::task::HandleRights::MANAGE_PROCESS
        | crate::task::HandleRights::MANAGE_THREAD
}

fn suspend_token_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::empty()
}

fn eventpair_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::SIGNAL
        | crate::task::HandleRights::SIGNAL_PEER
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
        | crate::task::HandleRights::MAP
}

fn bootstrap_code_vmo_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::MAP
}

fn vmar_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
        | crate::task::HandleRights::MAP
}

fn root_vmar_mapping_caps() -> VmarMappingCaps {
    VmarMappingCaps {
        max_perms: MappingPerms::READ
            | MappingPerms::WRITE
            | MappingPerms::EXECUTE
            | MappingPerms::USER,
        can_map_specific: true,
    }
}

fn thread_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::INSPECT
        | crate::task::HandleRights::MANAGE_THREAD
}

fn require_vm_mapping_rights(
    resolved: crate::task::ResolvedHandle,
    perms: MappingPerms,
) -> Result<(), zx_status_t> {
    require_handle_rights(resolved, crate::task::HandleRights::MAP)?;
    require_handle_rights(resolved, crate::task::HandleRights::READ)?;
    if perms.contains(MappingPerms::WRITE) {
        require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;
    }
    Ok(())
}

fn require_vmar_control_rights(resolved: crate::task::ResolvedHandle) -> Result<(), zx_status_t> {
    require_handle_rights(resolved, crate::task::HandleRights::MAP)?;
    require_handle_rights(resolved, crate::task::HandleRights::WRITE)
}

fn require_vmar_mapping_caps(
    caps: VmarMappingCaps,
    perms: MappingPerms,
    require_specific: bool,
) -> Result<(), zx_status_t> {
    if !caps.max_perms.contains(perms) {
        return Err(ZX_ERR_ACCESS_DENIED);
    }
    if require_specific && !caps.can_map_specific {
        return Err(ZX_ERR_ACCESS_DENIED);
    }
    Ok(())
}

fn require_vmar_child_mapping_caps(
    parent: VmarMappingCaps,
    requested: VmarMappingCaps,
) -> Result<(), zx_status_t> {
    if !parent.max_perms.contains(requested.max_perms) {
        return Err(ZX_ERR_ACCESS_DENIED);
    }
    if requested.can_map_specific && !parent.can_map_specific {
        return Err(ZX_ERR_ACCESS_DENIED);
    }
    Ok(())
}

fn mapping_request_from_options(
    options: u32,
    vmar_offset: u64,
) -> Result<VmarMappingRequest, zx_status_t> {
    let allowed = ZX_VM_PERM_READ | ZX_VM_PERM_WRITE | ZX_VM_PERM_EXECUTE | ZX_VM_SPECIFIC;
    if (options & !allowed) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let specific = (options & ZX_VM_SPECIFIC) != 0;
    if !specific && vmar_offset != 0 {
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
    Ok(VmarMappingRequest { perms, specific })
}

fn mapping_perms_from_options(
    options: u32,
    require_specific: bool,
) -> Result<MappingPerms, zx_status_t> {
    if !require_specific && (options & ZX_VM_SPECIFIC) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let request = mapping_request_from_options(options, if require_specific { 1 } else { 0 })?;
    if require_specific && !request.specific {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(request.perms)
}

fn vmar_mapping_caps_from_allocate_options(options: u32) -> Result<VmarMappingCaps, zx_status_t> {
    let allowed =
        ZX_VM_CAN_MAP_READ | ZX_VM_CAN_MAP_WRITE | ZX_VM_CAN_MAP_EXECUTE | ZX_VM_CAN_MAP_SPECIFIC;
    if (options & !allowed) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if (options & ZX_VM_CAN_MAP_EXECUTE) != 0 {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }

    let mut max_perms = MappingPerms::USER;
    if (options & ZX_VM_CAN_MAP_READ) != 0 {
        max_perms |= MappingPerms::READ;
    }
    if (options & ZX_VM_CAN_MAP_WRITE) != 0 {
        max_perms |= MappingPerms::WRITE;
    }

    Ok(VmarMappingCaps {
        max_perms,
        can_map_specific: (options & ZX_VM_CAN_MAP_SPECIFIC) != 0,
    })
}

fn vmar_allocate_request_from_options(
    options: u32,
    offset: u64,
) -> Result<VmarAllocateRequest, zx_status_t> {
    let align = vmar_allocate_align_from_options(options)?;
    let allowed = ZX_VM_CAN_MAP_READ
        | ZX_VM_CAN_MAP_WRITE
        | ZX_VM_CAN_MAP_EXECUTE
        | ZX_VM_CAN_MAP_SPECIFIC
        | ZX_VM_SPECIFIC
        | ZX_VM_OFFSET_IS_UPPER_LIMIT
        | ZX_VM_COMPACT
        | ZX_VM_ALIGN_MASK;
    if (options & !allowed) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let specific = (options & ZX_VM_SPECIFIC) != 0;
    let offset_is_upper_limit = (options & ZX_VM_OFFSET_IS_UPPER_LIMIT) != 0;
    let compact = (options & ZX_VM_COMPACT) != 0;
    if specific && offset_is_upper_limit {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if !specific && !offset_is_upper_limit && offset != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(VmarAllocateRequest {
        mapping_caps: vmar_mapping_caps_from_allocate_options(
            options
                & !(ZX_VM_SPECIFIC
                    | ZX_VM_OFFSET_IS_UPPER_LIMIT
                    | ZX_VM_COMPACT
                    | ZX_VM_ALIGN_MASK),
        )?,
        align,
        mode: if specific {
            VmarAllocMode::Specific
        } else {
            VmarAllocMode::Randomized
        },
        offset_is_upper_limit,
        child_policy: if compact {
            VmarPlacementPolicy::Compact
        } else {
            VmarPlacementPolicy::Randomized
        },
    })
}

fn vmar_allocate_align_from_options(options: u32) -> Result<u64, zx_status_t> {
    let encoded = (options & ZX_VM_ALIGN_MASK) >> ZX_VM_ALIGN_BASE;
    if encoded == 0 {
        return Ok(axle_mm::PAGE_SIZE);
    }
    let align = 1_u64.checked_shl(encoded).ok_or(ZX_ERR_INVALID_ARGS)?;
    Ok(core::cmp::max(axle_mm::PAGE_SIZE, align))
}

fn signals_for_object_id(state: &KernelState, object_id: u64) -> Result<Signals, zx_status_t> {
    let obj = state.objects.get(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;
    match obj {
        KernelObject::Process(process) => {
            state.with_kernel(|kernel| kernel.process_signals(process.process_id))
        }
        KernelObject::SuspendToken(_) => Ok(Signals::NONE),
        KernelObject::Socket(endpoint) => {
            let core = state
                .socket_cores
                .get(&endpoint.core_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            Ok(core.signals_for(endpoint.side))
        }
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
        KernelObject::EventPair(endpoint) => {
            let mut signals = endpoint.user_signals;
            if endpoint.peer_closed {
                signals = signals | Signals::OBJECT_PEER_CLOSED;
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
        KernelObject::Thread(thread) => {
            state.with_kernel(|kernel| kernel.thread_signals(thread.thread_id))
        }
        KernelObject::Vmo(_) | KernelObject::Vmar(_) => Ok(Signals::NONE),
    }
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
            let _ = state.objects.remove(&object_id);
            state.forget_object_handle_refs(object_id);
            let _ = state.with_kernel_mut(|kernel| kernel.reap_thread(thread_id))?;
            maybe_reap_process_record(state, process_id)?;
        }

        for (object_id, process_id) in process_reaps {
            let _ = state.objects.remove(&object_id);
            state.forget_object_handle_refs(object_id);
            maybe_reap_process_record(state, process_id)?;
        }
    }

    Ok(())
}

fn sync_task_lifecycle(state: &mut KernelState) -> Result<(), zx_status_t> {
    for object_id in task_object_ids(state) {
        let _ = notify_waitable_signals_changed(state, object_id);
    }
    reap_terminated_task_objects(state)
}

fn notify_waitable_signals_changed(
    state: &mut KernelState,
    waitable_id: u64,
) -> Result<(), zx_status_t> {
    let current = signals_for_object_id(state, waitable_id)?;
    let now = crate::time::now_ns();
    wake_signal_waiters(state, waitable_id, current)?;

    // Collect port ids first to avoid aliasing `state.objects` borrows.
    let port_ids: alloc::vec::Vec<u64> = state
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
    state: &mut KernelState,
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
        state.with_kernel_mut(|kernel| kernel.make_thread_runnable(waiter.thread_id(), status))?;
    }
    Ok(())
}

fn wake_port_waiters(state: &mut KernelState, port_id: u64) -> Result<(), zx_status_t> {
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
                        kernel.make_thread_runnable(waiter.thread_id(), map_port_error(err))
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
        state.with_kernel_mut(|kernel| kernel.make_thread_runnable(waiter.thread_id(), status))?;
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
