//! Minimal kernel object table wired through the bootstrap kernel/process model.

extern crate alloc;

pub(crate) mod handle;
pub(crate) mod process;
pub(crate) mod transport;
pub(crate) mod vm;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;

use axle_core::{
    Capability, ObserverRegistry, PortError, Signals, TimerError, TimerId, TransferredCap,
};
use axle_mm::{MappingPerms, VmarAllocMode, VmarId, VmarPlacementPolicy};
use axle_types::clock::ZX_CLOCK_MONOTONIC;
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::koid::ZX_KOID_INVALID;
use axle_types::rights::{ZX_RIGHT_SAME_RIGHTS, ZX_RIGHTS_ALL};
use axle_types::socket::{ZX_SOCKET_DATAGRAM, ZX_SOCKET_PEEK, ZX_SOCKET_STREAM};
use axle_types::status::{
    ZX_ERR_ACCESS_DENIED, ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_STATE,
    ZX_ERR_BUFFER_TOO_SMALL, ZX_ERR_INVALID_ARGS, ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED,
    ZX_ERR_PEER_CLOSED, ZX_ERR_SHOULD_WAIT, ZX_ERR_TIMED_OUT, ZX_ERR_WRONG_TYPE,
};
use axle_types::vm::{
    ZX_VM_ALIGN_BASE, ZX_VM_ALIGN_MASK, ZX_VM_CAN_MAP_EXECUTE, ZX_VM_CAN_MAP_READ,
    ZX_VM_CAN_MAP_SPECIFIC, ZX_VM_CAN_MAP_WRITE, ZX_VM_COMPACT, ZX_VM_OFFSET_IS_UPPER_LIMIT,
    ZX_VM_PERM_EXECUTE, ZX_VM_PERM_READ, ZX_VM_PERM_WRITE, ZX_VM_SPECIFIC,
};
use axle_types::zx_signals_t;
use axle_types::{
    zx_clock_t, zx_futex_t, zx_handle_t, zx_koid_t, zx_rights_t, zx_status_t, zx_vaddr_t,
};
use core::mem::size_of;
use spin::Mutex;

use crate::port_queue::KernelPort;

const PORT_CAPACITY: usize = 64;
const PORT_KERNEL_RESERVE: usize = 16;
const CHANNEL_CAPACITY: usize = 64;
const SOCKET_STREAM_CAPACITY: usize = 4096;
const DEFAULT_OBJECT_GENERATION: u32 = 0;

pub(crate) enum TrapBlock<T> {
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
pub(crate) struct TimerObject {
    pub(crate) timer_id: TimerId,
    clock_id: zx_clock_t,
}

#[derive(Debug)]
pub(crate) struct FragmentedChannelPayload {
    pub(crate) head: Vec<u8>,
    pub(crate) body: Option<crate::task::LoanedUserPages>,
    pub(crate) tail: Vec<u8>,
    pub(crate) len: u32,
}

#[derive(Debug)]
pub(crate) enum ChannelPayload {
    Copied(Vec<u8>),
    Loaned(crate::task::LoanedUserPages),
    Fragmented(FragmentedChannelPayload),
}

#[derive(Debug)]
struct ChannelMessage {
    payload: ChannelPayload,
    handles: Vec<TransferredCap>,
}

#[derive(Debug)]
pub(crate) struct ChannelEndpoint {
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
    pub(crate) fn actual_bytes(&self) -> Result<u32, zx_status_t> {
        match self {
            Self::Copied(bytes) => u32::try_from(bytes.len()).map_err(|_| ZX_ERR_BAD_STATE),
            Self::Loaned(loaned) => Ok(loaned.len()),
            Self::Fragmented(payload) => Ok(payload.len),
        }
    }

    pub(crate) fn loaned_body_mut(&mut self) -> Option<&mut crate::task::LoanedUserPages> {
        match self {
            Self::Loaned(loaned) => Some(loaned),
            Self::Fragmented(payload) => payload.body.as_mut(),
            Self::Copied(_) => None,
        }
    }

    pub(crate) fn into_loaned_body(self) -> Option<crate::task::LoanedUserPages> {
        match self {
            Self::Loaned(loaned) => Some(loaned),
            Self::Fragmented(payload) => payload.body,
            Self::Copied(_) => None,
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
pub(crate) struct EventPairEndpoint {
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
pub(crate) struct SocketEndpoint {
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

#[derive(Clone, Copy, Debug)]
pub(crate) enum VmoBackingScope {
    LocalPrivate {
        owner_address_space_id: u64,
        local_vmo_id: axle_mm::VmoId,
    },
    GlobalShared,
}

#[derive(Clone, Debug)]
pub(crate) struct VmoObject {
    creator_process_id: u64,
    global_vmo_id: axle_mm::GlobalVmoId,
    backing_scope: VmoBackingScope,
    kind: axle_mm::VmoKind,
    size_bytes: u64,
    image_layout: Option<crate::task::ProcessImageLayout>,
}

impl VmoObject {
    pub(crate) const fn creator_process_id(&self) -> u64 {
        self.creator_process_id
    }

    pub(crate) const fn global_vmo_id(&self) -> axle_mm::GlobalVmoId {
        self.global_vmo_id
    }

    pub(crate) const fn backing_scope(&self) -> VmoBackingScope {
        self.backing_scope
    }
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
pub(crate) struct VmarObject {
    process_id: u64,
    address_space_id: u64,
    vmar_id: VmarId,
    base: u64,
    len: u64,
    mapping_caps: VmarMappingCaps,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ThreadObject {
    process_id: u64,
    thread_id: u64,
    koid: zx_koid_t,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProcessObject {
    process_id: u64,
    koid: zx_koid_t,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum SuspendTarget {
    Process { process_id: u64 },
    Thread { thread_id: u64 },
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SuspendTokenObject {
    target: SuspendTarget,
}

#[derive(Debug)]
pub(crate) enum KernelObject {
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
pub(crate) struct KernelState {
    kernel: Arc<Mutex<crate::task::Kernel>>,
    pub(crate) objects: BTreeMap<u64, KernelObject>,
    socket_cores: BTreeMap<u64, SocketCore>,
    socket_telemetry: SocketTelemetrySnapshot,
    object_handle_refs: BTreeMap<u64, usize>,
    next_object_id: u64,
    next_socket_core_id: u64,
    pub(crate) observers: ObserverRegistry,
    timer_object_ids: BTreeMap<TimerId, u64>,
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
            observers: ObserverRegistry::new(),
            timer_object_ids: BTreeMap::new(),
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
            .alloc_handle_for_object(object_id, handle::process_default_rights())
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
                mapping_caps: vm::root_vmar_mapping_caps(),
            }),
        );
        state.bootstrap_root_vmar_handle = state
            .alloc_handle_for_object(object_id, handle::vmar_default_rights())
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
            .alloc_handle_for_object(object_id, handle::thread_default_rights())
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
                    backing_scope: VmoBackingScope::GlobalShared,
                    kind: axle_mm::VmoKind::PagerBacked,
                    size_bytes: imported.code_vmo().size_bytes(),
                    image_layout: Some(
                        imported
                            .layout()
                            .rebased_for_loaded_image()
                            .expect("bootstrap code image layout must rebase"),
                    ),
                }),
            );
            state.bootstrap_self_code_vmo_handle = state
                .alloc_handle_for_object(object_id, handle::bootstrap_code_vmo_rights())
                .expect("bootstrap self code vmo handle allocation must succeed");
        }

        state
    }

    fn alloc_object_id(&mut self) -> u64 {
        let id = self.next_object_id;
        self.next_object_id = self.next_object_id.wrapping_add(1);
        id
    }

    fn note_timer_object(&mut self, timer_id: TimerId, object_id: u64) {
        let _ = self.timer_object_ids.insert(timer_id, object_id);
    }

    fn forget_timer_object(&mut self, timer_id: TimerId) {
        let _ = self.timer_object_ids.remove(&timer_id);
    }

    fn timer_object_id(&self, timer_id: TimerId) -> Option<u64> {
        self.timer_object_ids.get(&timer_id).copied()
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

    fn current_address_space_id(&self) -> Option<crate::task::AddressSpaceId> {
        self.with_core(|kernel| kernel.current_address_space_id())
            .ok()
    }

    fn apply_tlb_commit_reqs(&self, reqs: &[crate::task::TlbCommitReq]) -> Result<(), zx_status_t> {
        let vm = self.vm_handle()?;
        crate::task::apply_tlb_commit_reqs(
            &vm,
            crate::arch::apic::this_apic_id() as usize,
            self.current_address_space_id(),
            reqs,
        )
    }

    fn retire_bootstrap_frames_after_quiescence(
        &self,
        barrier_address_spaces: &[crate::task::AddressSpaceId],
        retired_frames: &[crate::task::RetiredFrame],
    ) -> Result<(), zx_status_t> {
        let vm = self.vm_handle()?;
        crate::task::retire_bootstrap_frames_after_quiescence(
            &vm,
            crate::arch::apic::this_apic_id() as usize,
            self.current_address_space_id(),
            barrier_address_spaces,
            retired_frames,
        )
    }

    pub(crate) fn with_kernel<T>(
        &self,
        f: impl FnOnce(&crate::task::Kernel) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        self.with_core(f)
    }

    pub(crate) fn with_kernel_mut<T>(
        &self,
        f: impl FnOnce(&mut crate::task::Kernel) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        self.with_core_mut(f)
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
                process::sync_task_lifecycle(state)?;
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

pub(crate) fn with_state_mut<T>(
    f: impl FnOnce(&mut KernelState) -> Result<T, zx_status_t>,
) -> Result<T, zx_status_t> {
    let mut guard = STATE.lock();
    let state = guard.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
    f(state)
}

pub(crate) fn kernel_handle() -> Result<Arc<Mutex<crate::task::Kernel>>, zx_status_t> {
    let guard = STATE.lock();
    let state = guard.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
    Ok(state.kernel.clone())
}

fn vm_handle() -> Result<Arc<Mutex<crate::task::VmDomain>>, zx_status_t> {
    let kernel = kernel_handle()?;
    let kernel = kernel.lock();
    Ok(kernel.vm_handle())
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

pub(crate) fn run_trap_blocking<T>(
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

        match state.alloc_handle_for_object(object_id, handle::port_default_rights()) {
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

        let left_handle = match state
            .alloc_handle_for_object(left_object_id, handle::eventpair_default_rights())
        {
            Ok(handle) => handle,
            Err(e) => {
                let _ = state.objects.remove(&left_object_id);
                let _ = state.objects.remove(&right_object_id);
                return Err(e);
            }
        };
        let right_handle = match state
            .alloc_handle_for_object(right_object_id, handle::eventpair_default_rights())
        {
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

/// Create a new Timer object and return a handle.
pub fn create_timer(options: u32, clock_id: zx_clock_t) -> Result<zx_handle_t, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if clock_id != ZX_CLOCK_MONOTONIC {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let timer_id = state.with_kernel_mut(|kernel| Ok(kernel.create_timer_object()))?;
        let object_id = state.alloc_object_id();
        state.objects.insert(
            object_id,
            KernelObject::Timer(TimerObject { timer_id, clock_id }),
        );
        state.note_timer_object(timer_id, object_id);

        match state.alloc_handle_for_object(object_id, handle::timer_default_rights()) {
            Ok(h) => Ok(h),
            Err(e) => {
                let _ = state.objects.remove(&object_id);
                state.forget_timer_object(timer_id);
                let _ = state.with_kernel_mut(|kernel| {
                    kernel
                        .destroy_timer_object(timer_id)
                        .map_err(map_timer_error)
                });
                Err(e)
            }
        }
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
        publish_object_signals(state, resolved.object_id())
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
        publish_object_signals(state, peer_object_id)
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
    with_state_mut(|state| {
        let owner_koid = validate_futex_wait_owner(state, key, new_futex_owner)?;
        let deadline = if deadline == i64::MAX {
            None
        } else {
            let now = crate::time::now_ns();
            if deadline <= now {
                return Err(ZX_ERR_TIMED_OUT);
            }
            Some(deadline)
        };
        state.with_kernel_mut(|kernel| {
            kernel.park_current(
                crate::task::WaitRegistration::Futex { key, owner_koid },
                deadline,
            )
        })
    })?;
    Ok(())
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

        let now = crate::time::now_ns();
        let current = state.with_kernel_mut(|kernel| {
            kernel
                .set_timer_object(timer_id, deadline, now)
                .map(|fired| {
                    if fired {
                        Signals::TIMER_SIGNALED
                    } else {
                        Signals::NONE
                    }
                })
                .map_err(map_timer_error)
        })?;
        crate::wait::publish_signals_changed(state, object_id, current)
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

        state.with_kernel_mut(|kernel| {
            kernel
                .cancel_timer_object(timer_id)
                .map_err(map_timer_error)
        })?;
        crate::wait::publish_signals_changed(state, object_id, Signals::NONE)
    })
}

/// Snapshot current signals for a waitable object.
pub fn object_signals(handle: zx_handle_t) -> Result<zx_signals_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WAIT)?;
        let object_id = resolved.object_id();
        signals_for_object_id(state, object_id).map(|s| s.bits())
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

        if let Some(target) = suspend_target {
            process::close_suspend_token(state, object_id, target)?;
        }

        if let Some(peer_object_id) = peer_link
            && state.object_handle_count(object_id) == 0
        {
            state.observers.remove_waitable(object_id);
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
                    transport::drain_channel_messages(state, drained);
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
            if let Err(status) = publish_object_signals(state, peer_object_id)
                && status != ZX_ERR_BAD_HANDLE
            {
                return Err(status);
            }
        }
        if matches!(state.objects.get(&object_id), Some(KernelObject::Port(_)))
            && state.object_handle_count(object_id) == 0
        {
            state.observers.remove_port(object_id);
            state.observers.remove_waitable(object_id);
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
                    matches!(vmo.backing_scope, VmoBackingScope::GlobalShared),
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

pub(crate) fn require_handle_rights(
    resolved: crate::task::ResolvedHandle,
    required_rights: crate::task::HandleRights,
) -> Result<(), zx_status_t> {
    if resolved.rights().contains(required_rights) {
        Ok(())
    } else {
        Err(ZX_ERR_ACCESS_DENIED)
    }
}

pub(crate) fn publish_object_signals(
    state: &mut KernelState,
    object_id: u64,
) -> Result<(), zx_status_t> {
    let current = signals_for_object_id(state, object_id)?;
    crate::wait::publish_signals_changed(state, object_id, current)
}

pub(crate) fn publish_timer_fired(
    state: &mut KernelState,
    timer_id: TimerId,
) -> Result<(), zx_status_t> {
    let object_id = state.timer_object_id(timer_id).ok_or(ZX_ERR_BAD_STATE)?;
    crate::wait::publish_signals_changed(state, object_id, Signals::TIMER_SIGNALED)
}

pub(crate) fn signals_for_object_id(
    state: &KernelState,
    object_id: u64,
) -> Result<Signals, zx_status_t> {
    let obj = state.objects.get(&object_id).ok_or(ZX_ERR_BAD_HANDLE)?;
    if let Some(result) = process::task_signals(state, obj) {
        return result;
    }
    if let Some(result) = transport::transport_signals(state, obj) {
        return result;
    }
    match obj {
        KernelObject::SuspendToken(_) => Ok(Signals::NONE),
        KernelObject::EventPair(endpoint) => {
            let mut signals = endpoint.user_signals;
            if endpoint.peer_closed {
                signals = signals | Signals::OBJECT_PEER_CLOSED;
            }
            Ok(signals)
        }
        KernelObject::Port(port) => Ok(port.signals()),
        KernelObject::Timer(timer) => {
            let signaled = state.with_kernel(|kernel| {
                kernel
                    .timer_object_signaled(timer.timer_id)
                    .map_err(map_timer_error)
            })?;
            Ok(if signaled {
                Signals::TIMER_SIGNALED
            } else {
                Signals::NONE
            })
        }
        KernelObject::Vmo(_) | KernelObject::Vmar(_) => Ok(Signals::NONE),
        KernelObject::Process(_)
        | KernelObject::Socket(_)
        | KernelObject::Channel(_)
        | KernelObject::Thread(_) => Err(ZX_ERR_BAD_STATE),
    }
}

pub(crate) fn sync_task_lifecycle(state: &mut KernelState) -> Result<(), zx_status_t> {
    process::sync_task_lifecycle(state)
}

pub(crate) fn map_port_error(err: PortError) -> zx_status_t {
    match err {
        PortError::ShouldWait => ZX_ERR_SHOULD_WAIT,
        PortError::AlreadyExists => ZX_ERR_ALREADY_EXISTS,
        PortError::NotFound => ZX_ERR_NOT_FOUND,
    }
}

pub(crate) fn map_timer_error(err: TimerError) -> zx_status_t {
    match err {
        TimerError::NotFound => ZX_ERR_BAD_HANDLE,
    }
}
