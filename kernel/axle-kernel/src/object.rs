//! Minimal kernel object table wired through the bootstrap kernel/process model.

extern crate alloc;

pub(crate) mod device;
pub(crate) mod guest;
pub(crate) mod handle;
pub(crate) mod process;
pub(crate) mod revocation;
pub(crate) mod transport;
pub(crate) mod vm;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;

use axle_core::{
    Capability, ObjectKey, PortError, RevocationGroupToken, Signals, TimerError, TimerId,
    TransferredCap,
};
use axle_mm::{
    MappingCachePolicy, MappingClonePolicy, MappingPerms, VmarAllocMode, VmarId,
    VmarPlacementPolicy,
};
use axle_types::clock::ZX_CLOCK_MONOTONIC;
use axle_types::dma::{
    AX_DMA_REGION_INFO_FLAG_IDENTITY_IOVA, AX_DMA_REGION_INFO_FLAG_PHYSICALLY_CONTIGUOUS,
    AX_DMA_SEGMENT_INFO_FLAG_IDENTITY_IOVA, AX_DMA_SEGMENT_INFO_FLAG_PHYSICALLY_CONTIGUOUS,
    ax_dma_region_info_t, ax_dma_segment_info_t,
};
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::interrupt::{
    AX_INTERRUPT_INFO_FLAG_TRIGGERABLE, AX_INTERRUPT_MODE_LEGACY, AX_INTERRUPT_MODE_MSI,
    AX_INTERRUPT_MODE_MSIX, AX_INTERRUPT_MODE_VIRTUAL, ZX_INTERRUPT_VIRTUAL, ax_interrupt_info_t,
};
use axle_types::koid::ZX_KOID_INVALID;
use axle_types::rights::{ZX_RIGHT_SAME_RIGHTS, ZX_RIGHTS_ALL};
use axle_types::socket::{ZX_SOCKET_DATAGRAM, ZX_SOCKET_PEEK, ZX_SOCKET_STREAM};
use axle_types::status::{
    ZX_ERR_ACCESS_DENIED, ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_STATE,
    ZX_ERR_BUFFER_TOO_SMALL, ZX_ERR_INVALID_ARGS, ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED,
    ZX_ERR_OUT_OF_RANGE, ZX_ERR_PEER_CLOSED, ZX_ERR_SHOULD_WAIT, ZX_ERR_TIMED_OUT,
    ZX_ERR_WRONG_TYPE,
};
use axle_types::vm::{
    ZX_VM_ALIGN_BASE, ZX_VM_ALIGN_MASK, ZX_VM_CAN_MAP_EXECUTE, ZX_VM_CAN_MAP_READ,
    ZX_VM_CAN_MAP_SPECIFIC, ZX_VM_CAN_MAP_WRITE, ZX_VM_CLONE_COW, ZX_VM_CLONE_SHARE, ZX_VM_COMPACT,
    ZX_VM_MAP_MMIO, ZX_VM_OFFSET_IS_UPPER_LIMIT, ZX_VM_PERM_EXECUTE, ZX_VM_PERM_READ,
    ZX_VM_PERM_WRITE, ZX_VM_PRIVATE_CLONE, ZX_VM_SPECIFIC,
};
use axle_types::zx_signals_t;
use axle_types::{
    zx_clock_t, zx_futex_t, zx_handle_t, zx_koid_t, zx_rights_t, zx_status_t, zx_vaddr_t,
};
use core::mem::size_of;
use spin::{Mutex, Once};

use crate::port_queue::KernelPort;

const PORT_CAPACITY: usize = 64;
const PORT_KERNEL_RESERVE: usize = 16;
const CHANNEL_CAPACITY: usize = 64;
const SOCKET_STREAM_CAPACITY: usize = 4096;
const SOCKET_DATAGRAM_CAPACITY_BYTES: usize = 4096;
const SOCKET_DATAGRAM_CAPACITY_MESSAGES: usize = 64;
const BOOTSTRAP_REACTOR_CPU_COUNT: usize = 16;

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
    /// Interrupt object.
    Interrupt,
    /// DMA region object.
    DmaRegion,
    /// PCI/device resource object.
    PciDevice,
    /// Revocation-group object.
    RevocationGroup,
    /// Supervised guest-session object.
    GuestSession,
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct InterruptObject {
    pending_count: u64,
    masked: bool,
    mode: u32,
    vector: u32,
    triggerable: bool,
}

#[derive(Debug)]
pub(crate) struct DmaRegionObject {
    source_vmo_object: ObjectKey,
    source_offset: u64,
    size_bytes: u64,
    options: u32,
    pin: axle_mm::PinToken,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RevocationGroupObject {
    token: RevocationGroupToken,
}

impl RevocationGroupObject {
    pub(crate) const fn token(self) -> RevocationGroupToken {
        self.token
    }
}

impl DmaRegionObject {
    pub(crate) const fn source_vmo_object(&self) -> ObjectKey {
        self.source_vmo_object
    }

    pub(crate) const fn source_offset(&self) -> u64 {
        self.source_offset
    }

    pub(crate) const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub(crate) const fn options(&self) -> u32 {
        self.options
    }

    pub(crate) fn lookup_paddr(&self, offset: u64) -> Result<u64, zx_status_t> {
        if offset >= self.size_bytes {
            return Err(ZX_ERR_OUT_OF_RANGE);
        }
        let page_size = crate::userspace::USER_PAGE_BYTES;
        let page_offset = offset & !(page_size - 1);
        let byte_offset = offset - page_offset;
        let page_index =
            usize::try_from(page_offset / page_size).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let frame_id = *self
            .pin
            .frame_ids()
            .get(page_index)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        Ok(frame_id.raw() + byte_offset)
    }

    pub(crate) fn lookup_iova(&self, offset: u64) -> Result<u64, zx_status_t> {
        self.lookup_paddr(offset)
    }

    pub(crate) fn info(&self) -> Result<ax_dma_region_info_t, zx_status_t> {
        let mut flags = AX_DMA_REGION_INFO_FLAG_IDENTITY_IOVA;
        if self.is_physically_contiguous() {
            flags |= AX_DMA_REGION_INFO_FLAG_PHYSICALLY_CONTIGUOUS;
        }
        Ok(ax_dma_region_info_t {
            size_bytes: self.size_bytes,
            options: self.options,
            flags,
            segment_count: self.segment_count(),
            reserved0: 0,
            paddr_base: self.lookup_paddr(0)?,
            iova_base: self.lookup_iova(0)?,
        })
    }

    pub(crate) fn segment_count(&self) -> u32 {
        self.segments().count() as u32
    }

    pub(crate) fn segment_info(
        &self,
        segment_index: u32,
    ) -> Result<ax_dma_segment_info_t, zx_status_t> {
        self.segments()
            .nth(segment_index as usize)
            .ok_or(ZX_ERR_OUT_OF_RANGE)
    }

    fn segments(&self) -> impl Iterator<Item = ax_dma_segment_info_t> + '_ {
        let page_size = crate::userspace::USER_PAGE_BYTES;
        let frame_count = self.pin.frame_ids().len();
        let last_index = frame_count.saturating_sub(1);
        let region_size = self.size_bytes;
        let base_offset = self.source_offset;

        let mut start_index = 0usize;
        core::iter::from_fn(move || {
            if start_index >= frame_count {
                return None;
            }

            let start_frame = self.pin.frame_ids()[start_index];
            let mut end_index = start_index;
            while end_index + 1 < frame_count {
                let current = self.pin.frame_ids()[end_index];
                let next = self.pin.frame_ids()[end_index + 1];
                if current.raw().saturating_add(page_size) != next.raw() {
                    break;
                }
                end_index += 1;
            }

            let segment_offset = start_index as u64 * page_size;
            let covered_pages = end_index.saturating_sub(start_index) + 1;
            let mut segment_size = covered_pages as u64 * page_size;
            if end_index == last_index {
                segment_size = region_size.saturating_sub(segment_offset);
            }
            start_index = end_index + 1;

            Some(ax_dma_segment_info_t {
                offset_bytes: segment_offset,
                size_bytes: segment_size,
                flags: AX_DMA_SEGMENT_INFO_FLAG_IDENTITY_IOVA
                    | AX_DMA_SEGMENT_INFO_FLAG_PHYSICALLY_CONTIGUOUS,
                reserved0: 0,
                paddr_base: start_frame.raw() + (base_offset & (page_size - 1)),
                iova_base: start_frame.raw() + (base_offset & (page_size - 1)),
            })
        })
    }

    fn is_physically_contiguous(&self) -> bool {
        let frames = self.pin.frame_ids();
        if frames.len() <= 1 {
            return true;
        }
        let step = crate::userspace::USER_PAGE_BYTES;
        frames
            .windows(2)
            .all(|pair| pair[0].raw().saturating_add(step) == pair[1].raw())
    }

    fn release(self, frames: &mut axle_mm::FrameTable) {
        self.pin.release(frames);
    }
}

impl InterruptObject {
    fn new(mode: u32, vector: u32, triggerable: bool) -> Self {
        Self {
            pending_count: 0,
            masked: false,
            mode,
            vector,
            triggerable,
        }
    }

    fn info(&self, handle: zx_handle_t) -> ax_interrupt_info_t {
        ax_interrupt_info_t {
            handle,
            mode: self.mode,
            vector: self.vector,
            flags: if self.triggerable {
                AX_INTERRUPT_INFO_FLAG_TRIGGERABLE
            } else {
                0
            },
            reserved0: 0,
        }
    }

    pub(crate) fn set_metadata(&mut self, mode: u32, vector: u32, triggerable: bool) {
        self.mode = mode;
        self.vector = vector;
        self.triggerable = triggerable;
    }

    fn signals(self) -> Signals {
        if self.pending_count != 0 && !self.masked {
            Signals::INTERRUPT_SIGNALED
        } else {
            Signals::NONE
        }
    }

    fn trigger(&mut self, count: u64) -> Result<Signals, zx_status_t> {
        self.pending_count = self
            .pending_count
            .checked_add(count)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        Ok(self.signals())
    }

    fn ack(&mut self) -> Result<Signals, zx_status_t> {
        if self.pending_count == 0 {
            return Err(ZX_ERR_BAD_STATE);
        }
        self.pending_count -= 1;
        Ok(self.signals())
    }

    fn mask(&mut self) -> Signals {
        self.masked = true;
        self.signals()
    }

    fn unmask(&mut self) -> Signals {
        self.masked = false;
        self.signals()
    }
}

#[derive(Debug)]
pub(crate) struct ChannelFragmentPage {
    owner_cpu: usize,
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct ChannelFragment {
    page: ChannelFragmentPage,
    len: u16,
}

impl ChannelFragment {
    pub(crate) fn len(&self) -> usize {
        self.len as usize
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.page.bytes[..self.len()]
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        let len = self.len();
        &mut self.page.bytes[..len]
    }

    fn into_page(self) -> ChannelFragmentPage {
        self.page
    }
}

#[derive(Debug)]
pub(crate) struct FragmentedChannelPayload {
    pub(crate) head: Option<ChannelFragment>,
    pub(crate) body: Option<crate::task::LoanedUserPages>,
    pub(crate) tail: Option<ChannelFragment>,
    pub(crate) len: u32,
}

#[derive(Debug)]
pub(crate) enum ChannelPayload {
    Copied(Vec<u8>),
    Loaned(crate::task::LoanedUserPages),
    Fragmented(FragmentedChannelPayload),
}

#[derive(Debug)]
struct ChannelMsgDesc {
    payload: ChannelPayload,
    handles: Vec<TransferredCap>,
    actual_bytes: u32,
    actual_handles: u32,
}

#[derive(Debug)]
pub(crate) struct ChannelEndpoint {
    peer_object: ObjectKey,
    owner_process_id: u64,
    messages: VecDeque<ChannelMsgDesc>,
    peer_closed: bool,
    closed: bool,
}

impl ChannelEndpoint {
    fn new(peer_object: ObjectKey, owner_process_id: u64) -> Self {
        Self {
            peer_object,
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
}

impl ChannelMsgDesc {
    fn new(payload: ChannelPayload, handles: Vec<TransferredCap>) -> Result<Self, zx_status_t> {
        let actual_bytes = payload.actual_bytes()?;
        let actual_handles = u32::try_from(handles.len()).map_err(|_| ZX_ERR_BAD_STATE)?;
        Ok(Self {
            payload,
            handles,
            actual_bytes,
            actual_handles,
        })
    }

    fn actual_bytes(&self) -> u32 {
        self.actual_bytes
    }

    fn actual_handles(&self) -> u32 {
        self.actual_handles
    }

    fn handles(&self) -> &[TransferredCap] {
        &self.handles
    }

    fn is_fragmented(&self) -> bool {
        matches!(self.payload, ChannelPayload::Fragmented(_))
    }

    fn into_parts(self) -> (ChannelPayload, Vec<TransferredCap>) {
        (self.payload, self.handles)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EventPairEndpoint {
    peer_object: ObjectKey,
    user_signals: Signals,
    peer_closed: bool,
    closed: bool,
}

impl EventPairEndpoint {
    fn new(peer_object: ObjectKey) -> Self {
        Self {
            peer_object,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketMode {
    Stream,
    Datagram,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SocketEndpoint {
    core_id: u64,
    peer_object: ObjectKey,
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
struct DatagramQueue {
    messages: VecDeque<Vec<u8>>,
    buffered_bytes: usize,
    capacity_bytes: usize,
    capacity_messages: usize,
}

impl DatagramQueue {
    fn with_capacity(capacity_bytes: usize, capacity_messages: usize) -> Self {
        Self {
            messages: VecDeque::new(),
            buffered_bytes: 0,
            capacity_bytes,
            capacity_messages,
        }
    }

    fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    fn queued_messages(&self) -> usize {
        self.messages.len()
    }

    fn can_accept_more(&self) -> bool {
        self.buffered_bytes < self.capacity_bytes && self.messages.len() < self.capacity_messages
    }

    fn write(&mut self, bytes: &[u8]) -> Result<usize, zx_status_t> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if bytes.len() > self.capacity_bytes {
            return Err(ZX_ERR_OUT_OF_RANGE);
        }
        let next_bytes = self
            .buffered_bytes
            .checked_add(bytes.len())
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if self.messages.len() >= self.capacity_messages || next_bytes > self.capacity_bytes {
            return Err(ZX_ERR_SHOULD_WAIT);
        }
        let mut message = Vec::new();
        message
            .try_reserve_exact(bytes.len())
            .map_err(|_| axle_types::status::ZX_ERR_NO_MEMORY)?;
        message.extend_from_slice(bytes);
        self.buffered_bytes = next_bytes;
        self.messages.push_back(message);
        Ok(bytes.len())
    }

    fn read(&mut self, len: usize, consume: bool) -> Result<(Vec<u8>, bool), zx_status_t> {
        if len == 0 {
            return Ok((Vec::new(), false));
        }
        let Some(message) = self.messages.front() else {
            return Err(ZX_ERR_SHOULD_WAIT);
        };
        let truncated = message.len() > len;
        let actual = message.len().min(len);
        let mut out = Vec::new();
        out.try_reserve_exact(actual)
            .map_err(|_| axle_types::status::ZX_ERR_NO_MEMORY)?;
        out.extend_from_slice(&message[..actual]);
        if consume {
            let consumed = self.messages.pop_front().ok_or(ZX_ERR_BAD_STATE)?;
            self.buffered_bytes = self.buffered_bytes.saturating_sub(consumed.len());
        }
        Ok((out, truncated))
    }
}

#[derive(Debug)]
enum SocketQueue {
    Stream(ByteRing),
    Datagram(DatagramQueue),
}

#[derive(Debug)]
struct SocketCore {
    mode: SocketMode,
    dir_ab: SocketQueue,
    dir_ba: SocketQueue,
    open_a: bool,
    open_b: bool,
}

impl SocketCore {
    fn new_stream(capacity: usize) -> Result<Self, zx_status_t> {
        Ok(Self {
            mode: SocketMode::Stream,
            dir_ab: SocketQueue::Stream(ByteRing::with_capacity(capacity)?),
            dir_ba: SocketQueue::Stream(ByteRing::with_capacity(capacity)?),
            open_a: true,
            open_b: true,
        })
    }

    fn new_datagram(capacity_bytes: usize, capacity_messages: usize) -> Self {
        Self {
            mode: SocketMode::Datagram,
            dir_ab: SocketQueue::Datagram(DatagramQueue::with_capacity(
                capacity_bytes,
                capacity_messages,
            )),
            dir_ba: SocketQueue::Datagram(DatagramQueue::with_capacity(
                capacity_bytes,
                capacity_messages,
            )),
            open_a: true,
            open_b: true,
        }
    }

    fn mode(&self) -> SocketMode {
        self.mode
    }

    fn buffered_bytes(&self) -> usize {
        match (&self.dir_ab, &self.dir_ba) {
            (SocketQueue::Stream(ab), SocketQueue::Stream(ba)) => {
                ab.available_read() + ba.available_read()
            }
            (SocketQueue::Datagram(ab), SocketQueue::Datagram(ba)) => {
                ab.buffered_bytes() + ba.buffered_bytes()
            }
            _ => 0,
        }
    }

    fn buffered_messages(&self) -> usize {
        match (&self.dir_ab, &self.dir_ba) {
            (SocketQueue::Datagram(ab), SocketQueue::Datagram(ba)) => {
                ab.queued_messages() + ba.queued_messages()
            }
            _ => 0,
        }
    }

    fn signals_for(&self, side: SocketSide) -> Signals {
        let (readable, writable, peer_open) = match side {
            SocketSide::A => (
                match &self.dir_ba {
                    SocketQueue::Stream(queue) => queue.available_read() != 0,
                    SocketQueue::Datagram(queue) => queue.queued_messages() != 0,
                },
                match &self.dir_ab {
                    SocketQueue::Stream(queue) => queue.available_write() != 0,
                    SocketQueue::Datagram(queue) => queue.can_accept_more(),
                },
                self.open_b,
            ),
            SocketSide::B => (
                match &self.dir_ab {
                    SocketQueue::Stream(queue) => queue.available_read() != 0,
                    SocketQueue::Datagram(queue) => queue.queued_messages() != 0,
                },
                match &self.dir_ba {
                    SocketQueue::Stream(queue) => queue.available_write() != 0,
                    SocketQueue::Datagram(queue) => queue.can_accept_more(),
                },
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
        match queue {
            SocketQueue::Stream(queue) => {
                let written = queue.write(bytes);
                if written == 0 {
                    return Err(ZX_ERR_SHOULD_WAIT);
                }
                Ok(written)
            }
            SocketQueue::Datagram(queue) => queue.write(bytes),
        }
    }

    fn read(
        &mut self,
        side: SocketSide,
        len: usize,
        consume: bool,
    ) -> Result<(Vec<u8>, bool), zx_status_t> {
        let (queue, peer_open) = match side {
            SocketSide::A => (&mut self.dir_ba, self.open_b),
            SocketSide::B => (&mut self.dir_ab, self.open_a),
        };
        match queue {
            SocketQueue::Stream(queue) => {
                if len == 0 {
                    return Ok((Vec::new(), false));
                }
                if queue.available_read() == 0 {
                    return Err(if peer_open {
                        ZX_ERR_SHOULD_WAIT
                    } else {
                        ZX_ERR_PEER_CLOSED
                    });
                }
                queue.read(len, consume).map(|bytes| (bytes, false))
            }
            SocketQueue::Datagram(queue) => {
                if queue.queued_messages() == 0 {
                    return Err(if peer_open {
                        ZX_ERR_SHOULD_WAIT
                    } else {
                        ZX_ERR_PEER_CLOSED
                    });
                }
                queue.read(len, consume)
            }
        }
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
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SocketTelemetrySnapshot {
    pub(crate) current_buffered_bytes: u64,
    pub(crate) peak_buffered_bytes: u64,
    pub(crate) short_write_count: u64,
    pub(crate) write_should_wait_count: u64,
    pub(crate) datagram_current_buffered_bytes: u64,
    pub(crate) datagram_peak_buffered_bytes: u64,
    pub(crate) datagram_current_buffered_messages: u64,
    pub(crate) datagram_peak_buffered_messages: u64,
    pub(crate) datagram_write_count: u64,
    pub(crate) datagram_read_count: u64,
    pub(crate) datagram_write_should_wait_count: u64,
    pub(crate) datagram_truncated_read_count: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ChannelTelemetrySnapshot {
    pub(crate) desc_enqueued_count: u64,
    pub(crate) desc_dequeued_count: u64,
    pub(crate) desc_reclaimed_count: u64,
    pub(crate) desc_drained_count: u64,
    pub(crate) fragmented_desc_count: u64,
    pub(crate) fragmented_bytes_total: u64,
    pub(crate) fragment_pool_new_count: u64,
    pub(crate) fragment_pool_reuse_count: u64,
    pub(crate) fragment_pool_local_free_count: u64,
    pub(crate) fragment_pool_remote_free_count: u64,
    pub(crate) fragment_pool_cached_current: u64,
    pub(crate) fragment_pool_cached_peak: u64,
}

#[derive(Debug, Default)]
struct ChannelFragmentPool {
    local_cache: BTreeMap<usize, Vec<ChannelFragmentPage>>,
    remote_returns: BTreeMap<usize, Vec<ChannelFragmentPage>>,
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

    pub(crate) const fn kind(&self) -> axle_mm::VmoKind {
        self.kind
    }

    pub(crate) const fn size_bytes(&self) -> u64 {
        self.size_bytes
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
    cache_policy: MappingCachePolicy,
    clone_policy: MappingClonePolicy,
    specific: bool,
    private_clone: bool,
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

#[derive(Clone, Debug)]
pub(crate) struct GuestSessionObject {
    thread_id: u64,
    sidecar_vmo: VmoObject,
    port_object: ObjectKey,
    packet_key: u64,
    stop_seq: u64,
    stopped_seq: Option<u64>,
}

#[derive(Debug)]
pub(crate) enum KernelObject {
    Process(ProcessObject),
    SuspendToken(SuspendTokenObject),
    GuestSession(GuestSessionObject),
    Socket(SocketEndpoint),
    Channel(ChannelEndpoint),
    EventPair(EventPairEndpoint),
    Port(KernelPort),
    Timer(TimerObject),
    Interrupt(InterruptObject),
    DmaRegion(DmaRegionObject),
    PciDevice(device::PciDeviceObject),
    RevocationGroup(RevocationGroupObject),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectSlotState {
    Live,
    Dying,
    Retired,
}

#[derive(Debug)]
struct ObjectSlot {
    generation: u32,
    state: ObjectSlotState,
    handle_refcount: usize,
    kernel_refcount: usize,
    payload: Option<KernelObject>,
}

impl ObjectSlot {
    fn reserved_live(generation: u32) -> Self {
        Self {
            generation,
            state: ObjectSlotState::Live,
            handle_refcount: 0,
            kernel_refcount: 0,
            payload: None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ObjectRegistry {
    slots: Vec<ObjectSlot>,
    free_slots: VecDeque<usize>,
    timer_object_ids: BTreeMap<TimerId, ObjectKey>,
    guest_session_thread_ids: BTreeMap<u64, ObjectKey>,
    bootstrap_self_process_handle: zx_handle_t,
    bootstrap_root_vmar_handle: zx_handle_t,
    bootstrap_self_thread_handle: zx_handle_t,
    bootstrap_self_code_vmo_handle: zx_handle_t,
    bootstrap_echo_provider_code_vmo_handle: zx_handle_t,
    bootstrap_echo_client_code_vmo_handle: zx_handle_t,
    bootstrap_controller_worker_code_vmo_handle: zx_handle_t,
    bootstrap_starnix_kernel_code_vmo_handle: zx_handle_t,
    bootstrap_linux_hello_code_vmo_handle: zx_handle_t,
    bootstrap_net_pci_device_handle: zx_handle_t,
    bootstrap_real_net_pci_device_handle: zx_handle_t,
    bootstrap_process_image_layout: crate::task::ProcessImageLayout,
}

impl ObjectRegistry {
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            free_slots: VecDeque::new(),
            timer_object_ids: BTreeMap::new(),
            guest_session_thread_ids: BTreeMap::new(),
            bootstrap_self_process_handle: 0,
            bootstrap_root_vmar_handle: 0,
            bootstrap_self_thread_handle: 0,
            bootstrap_self_code_vmo_handle: 0,
            bootstrap_echo_provider_code_vmo_handle: 0,
            bootstrap_echo_client_code_vmo_handle: 0,
            bootstrap_controller_worker_code_vmo_handle: 0,
            bootstrap_starnix_kernel_code_vmo_handle: 0,
            bootstrap_linux_hello_code_vmo_handle: 0,
            bootstrap_net_pci_device_handle: 0,
            bootstrap_real_net_pci_device_handle: 0,
            bootstrap_process_image_layout: crate::task::ProcessImageLayout::bootstrap_conformance(
            ),
        }
    }

    fn slot_index(object_id: u64) -> Option<usize> {
        usize::try_from(object_id.checked_sub(1)?).ok()
    }

    fn key_matches(slot: &ObjectSlot, key: ObjectKey) -> bool {
        slot.generation == key.generation()
    }

    fn object_key_for_slot(index: usize, slot: &ObjectSlot) -> Option<ObjectKey> {
        let object_id = u64::try_from(index.checked_add(1)?).ok()?;
        Some(ObjectKey::new(object_id, slot.generation))
    }

    fn reserve_object_key(&mut self) -> ObjectKey {
        if let Some(index) = self.free_slots.pop_front() {
            let slot = &mut self.slots[index];
            debug_assert!(matches!(slot.state, ObjectSlotState::Retired));
            debug_assert!(slot.payload.is_none());
            debug_assert_eq!(slot.handle_refcount, 0);
            debug_assert_eq!(slot.kernel_refcount, 0);
            *slot = ObjectSlot::reserved_live(slot.generation);
            return Self::object_key_for_slot(index, slot)
                .expect("retired slot index must encode to object key");
        }

        let generation = 0;
        self.slots.push(ObjectSlot::reserved_live(generation));
        let index = self
            .slots
            .len()
            .checked_sub(1)
            .expect("pushed slot must leave one index");
        Self::object_key_for_slot(index, &self.slots[index])
            .expect("new slot index must encode to object key")
    }

    fn publish_reserved_object(
        &mut self,
        key: ObjectKey,
        object: KernelObject,
    ) -> Result<(), zx_status_t> {
        let slot = self.slot_any_mut(key).ok_or(ZX_ERR_BAD_HANDLE)?;
        if !matches!(slot.state, ObjectSlotState::Live) {
            return Err(ZX_ERR_BAD_HANDLE);
        }
        if slot.payload.is_some() {
            return Err(ZX_ERR_BAD_STATE);
        }
        slot.payload = Some(object);
        Ok(())
    }

    fn discard_reserved_object(&mut self, key: ObjectKey) {
        let Some(index) = Self::slot_index(key.object_id()) else {
            return;
        };
        let Some(slot) = self.slots.get_mut(index) else {
            return;
        };
        if !Self::key_matches(slot, key)
            || !matches!(slot.state, ObjectSlotState::Live)
            || slot.payload.is_some()
        {
            return;
        }
        slot.state = ObjectSlotState::Dying;
        self.maybe_retire(index);
    }

    pub(crate) fn get(&self, key: ObjectKey) -> Option<&KernelObject> {
        self.slot_live(key)?.payload.as_ref()
    }

    pub(crate) fn get_mut(&mut self, key: ObjectKey) -> Option<&mut KernelObject> {
        self.slot_mut_live(key)?.payload.as_mut()
    }

    fn get_any(&self, key: ObjectKey) -> Option<&KernelObject> {
        self.slot_any(key)?.payload.as_ref()
    }

    fn get_any_mut(&mut self, key: ObjectKey) -> Option<&mut KernelObject> {
        self.slot_any_mut(key)?.payload.as_mut()
    }

    pub(crate) fn insert(
        &mut self,
        key: ObjectKey,
        object: KernelObject,
    ) -> Result<(), zx_status_t> {
        self.publish_reserved_object(key, object)
    }

    pub(crate) fn remove(&mut self, key: ObjectKey) -> Option<KernelObject> {
        let index = Self::slot_index(key.object_id())?;
        let slot = self.slot_any_mut(key)?;
        let payload = slot.payload.take()?;
        slot.state = ObjectSlotState::Dying;
        self.maybe_retire(index);
        Some(payload)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (ObjectKey, &KernelObject)> {
        self.iter_live()
    }

    fn live_key_for_object_id(&self, object_id: u64) -> Option<ObjectKey> {
        let slot = self.slots.get(Self::slot_index(object_id)?)?;
        if !matches!(slot.state, ObjectSlotState::Live) || slot.payload.is_none() {
            return None;
        }
        Self::object_key_for_slot(Self::slot_index(object_id)?, slot)
    }

    fn capability_for_object(
        &self,
        key: ObjectKey,
        rights: crate::task::HandleRights,
    ) -> Capability {
        Capability::new(key.object_id(), rights.bits(), key.generation())
    }

    fn begin_logical_destroy(&mut self, key: ObjectKey) -> Result<KernelObject, zx_status_t> {
        let slot = self.slot_mut_live(key).ok_or(ZX_ERR_BAD_HANDLE)?;
        slot.state = ObjectSlotState::Dying;
        slot.payload.take().ok_or(ZX_ERR_BAD_STATE)
    }

    fn finish_logical_destroy(&mut self, key: ObjectKey) {
        let Some(index) = Self::slot_index(key.object_id()) else {
            return;
        };
        let Some(slot) = self.slots.get(index) else {
            return;
        };
        if !Self::key_matches(slot, key) {
            return;
        }
        self.maybe_retire(index);
    }

    fn increment_handle_ref(&mut self, key: ObjectKey) -> Result<(), zx_status_t> {
        let slot = self.slot_any_mut(key).ok_or(ZX_ERR_BAD_HANDLE)?;
        slot.handle_refcount = slot.handle_refcount.saturating_add(1);
        Ok(())
    }

    fn decrement_handle_ref(&mut self, key: ObjectKey) {
        let Some(index) = Self::slot_index(key.object_id()) else {
            return;
        };
        let Some(slot) = self.slots.get_mut(index) else {
            return;
        };
        if !Self::key_matches(slot, key) {
            return;
        }
        if slot.handle_refcount != 0 {
            slot.handle_refcount -= 1;
        }
        self.maybe_retire(index);
    }

    pub(crate) fn handle_refcount(&self, key: ObjectKey) -> usize {
        self.slot_any(key)
            .map(|slot| slot.handle_refcount)
            .unwrap_or(0)
    }

    fn retain_kernel_ref(&mut self, key: ObjectKey) -> Result<(), zx_status_t> {
        let slot = self.slot_any_mut(key).ok_or(ZX_ERR_BAD_HANDLE)?;
        slot.kernel_refcount = slot.kernel_refcount.saturating_add(1);
        Ok(())
    }

    fn release_kernel_ref(&mut self, key: ObjectKey) {
        let Some(index) = Self::slot_index(key.object_id()) else {
            return;
        };
        let Some(slot) = self.slots.get_mut(index) else {
            return;
        };
        if !Self::key_matches(slot, key) {
            return;
        }
        if slot.kernel_refcount != 0 {
            slot.kernel_refcount -= 1;
        }
        self.maybe_retire(index);
    }

    fn iter_live(&self) -> impl Iterator<Item = (ObjectKey, &KernelObject)> {
        self.slots.iter().enumerate().filter_map(|(index, slot)| {
            if !matches!(slot.state, ObjectSlotState::Live) {
                return None;
            }
            let payload = slot.payload.as_ref()?;
            Some((Self::object_key_for_slot(index, slot)?, payload))
        })
    }

    fn slot_live(&self, key: ObjectKey) -> Option<&ObjectSlot> {
        let slot = self.slot_any(key)?;
        if !matches!(slot.state, ObjectSlotState::Live) || slot.payload.is_none() {
            return None;
        }
        Some(slot)
    }

    fn slot_mut_live(&mut self, key: ObjectKey) -> Option<&mut ObjectSlot> {
        let slot = self.slot_any_mut(key)?;
        if !matches!(slot.state, ObjectSlotState::Live) || slot.payload.is_none() {
            return None;
        }
        Some(slot)
    }

    fn slot_any(&self, key: ObjectKey) -> Option<&ObjectSlot> {
        let slot = self.slots.get(Self::slot_index(key.object_id())?)?;
        if !Self::key_matches(slot, key) || matches!(slot.state, ObjectSlotState::Retired) {
            return None;
        }
        Some(slot)
    }

    fn slot_any_mut(&mut self, key: ObjectKey) -> Option<&mut ObjectSlot> {
        let slot = self.slots.get_mut(Self::slot_index(key.object_id())?)?;
        if !Self::key_matches(slot, key) || matches!(slot.state, ObjectSlotState::Retired) {
            return None;
        }
        Some(slot)
    }

    fn maybe_retire(&mut self, index: usize) {
        let Some(slot) = self.slots.get_mut(index) else {
            return;
        };
        if !matches!(slot.state, ObjectSlotState::Dying)
            || slot.payload.is_some()
            || slot.handle_refcount != 0
            || slot.kernel_refcount != 0
        {
            return;
        }
        slot.state = ObjectSlotState::Retired;
        slot.generation = slot.generation.wrapping_add(1);
        self.free_slots.push_back(index);
    }
}

pub(crate) struct TransportCore {
    socket_cores: BTreeMap<u64, SocketCore>,
    socket_telemetry: SocketTelemetrySnapshot,
    channel_telemetry: ChannelTelemetrySnapshot,
    channel_fragment_pool: ChannelFragmentPool,
    next_socket_core_id: u64,
}

impl TransportCore {
    fn new() -> Self {
        Self {
            socket_cores: BTreeMap::new(),
            socket_telemetry: SocketTelemetrySnapshot::default(),
            channel_telemetry: ChannelTelemetrySnapshot::default(),
            channel_fragment_pool: ChannelFragmentPool::default(),
            next_socket_core_id: 1,
        }
    }
}

pub(crate) struct KernelState {
    kernel: Arc<Mutex<crate::task::Kernel>>,
    registry: Arc<Mutex<ObjectRegistry>>,
    transport: Arc<Mutex<TransportCore>>,
    reactor: Arc<Mutex<crate::task::Reactor>>,
    vm: Arc<crate::task::VmFacade>,
}

impl KernelState {
    fn new() -> Self {
        let (vm, address_space_id) = crate::task::VmFacade::bootstrap();
        let reactor = Arc::new(Mutex::new(crate::task::Reactor::new(
            BOOTSTRAP_REACTOR_CPU_COUNT,
        )));
        let state = Self {
            kernel: Arc::new(Mutex::new(crate::task::Kernel::bootstrap(
                vm.clone(),
                reactor.clone(),
                address_space_id,
            ))),
            registry: Arc::new(Mutex::new(ObjectRegistry::new())),
            transport: Arc::new(Mutex::new(TransportCore::new())),
            reactor,
            vm,
        };

        let process = state
            .with_kernel(|kernel| kernel.current_process_info())
            .expect("bootstrap current process must exist");
        let process_koid = state
            .with_kernel(|kernel| kernel.current_process_koid())
            .expect("bootstrap current process koid must exist");
        let process_object_id = state.alloc_object_id();
        state
            .with_registry_mut(|registry| {
                registry.insert(
                    process_object_id,
                    KernelObject::Process(ProcessObject {
                        process_id: process.process_id(),
                        koid: process_koid,
                    }),
                )?;
                Ok(())
            })
            .expect("bootstrap process object insert must succeed");
        let process_handle = state
            .alloc_handle_for_object(process_object_id, handle::process_default_rights())
            .expect("bootstrap self process handle allocation must succeed");
        state
            .with_registry_mut(|registry| {
                registry.bootstrap_self_process_handle = process_handle;
                Ok(())
            })
            .expect("bootstrap self process handle publish must succeed");

        let root = state
            .with_kernel(|kernel| kernel.current_root_vmar())
            .expect("bootstrap root VMAR must exist");
        let root_vmar_object_id = state.alloc_object_id();
        state
            .with_registry_mut(|registry| {
                registry.insert(
                    root_vmar_object_id,
                    KernelObject::Vmar(VmarObject {
                        process_id: root.process_id(),
                        address_space_id: root.address_space_id(),
                        vmar_id: root.vmar_id(),
                        base: root.base(),
                        len: root.len(),
                        mapping_caps: vm::root_vmar_mapping_caps(),
                    }),
                )?;
                Ok(())
            })
            .expect("bootstrap root vmar object insert must succeed");
        let root_vmar_handle = state
            .alloc_handle_for_object(root_vmar_object_id, handle::vmar_default_rights())
            .expect("bootstrap root VMAR handle allocation must succeed");
        state
            .with_registry_mut(|registry| {
                registry.bootstrap_root_vmar_handle = root_vmar_handle;
                Ok(())
            })
            .expect("bootstrap root vmar handle publish must succeed");

        let thread = state
            .with_kernel(|kernel| kernel.current_thread_info())
            .expect("bootstrap current thread must exist");
        let thread_object_id = state.alloc_object_id();
        state
            .with_registry_mut(|registry| {
                registry.insert(
                    thread_object_id,
                    KernelObject::Thread(ThreadObject {
                        process_id: thread.process_id(),
                        thread_id: thread.thread_id(),
                        koid: thread.koid(),
                    }),
                )?;
                Ok(())
            })
            .expect("bootstrap thread object insert must succeed");
        let thread_handle = state
            .alloc_handle_for_object(thread_object_id, handle::thread_default_rights())
            .expect("bootstrap self thread handle allocation must succeed");
        state
            .with_registry_mut(|registry| {
                registry.bootstrap_self_thread_handle = thread_handle;
                Ok(())
            })
            .expect("bootstrap self thread handle publish must succeed");

        let address_space_id = state
            .with_kernel(|kernel| kernel.process_address_space_id(process.process_id()))
            .expect("bootstrap current process address space must exist");
        if let Ok(imported) = state.with_vm_mut(|vm| {
            vm.import_bootstrap_process_image_for_address_space(
                process.process_id(),
                address_space_id,
            )
        }) {
            state
                .with_registry_mut(|registry| {
                    registry.bootstrap_process_image_layout = imported.layout();
                    Ok(())
                })
                .expect("bootstrap image layout publish must succeed");
            let code_vmo_object_id = state.alloc_object_id();
            state
                .with_registry_mut(|registry| {
                    registry.insert(
                        code_vmo_object_id,
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
                    )?;
                    Ok(())
                })
                .expect("bootstrap code vmo object insert must succeed");
            let code_vmo_handle = state
                .alloc_handle_for_object(code_vmo_object_id, handle::bootstrap_code_vmo_rights())
                .expect("bootstrap self code vmo handle allocation must succeed");
            state
                .with_registry_mut(|registry| {
                    registry.bootstrap_self_code_vmo_handle = code_vmo_handle;
                    Ok(())
                })
                .expect("bootstrap code vmo handle publish must succeed");
        }

        let bootstrap_component_images = [
            (
                crate::userspace::qemu_loader_echo_provider_size as fn() -> Option<u64>,
                crate::userspace::read_qemu_loader_echo_provider_at
                    as fn(u64, &mut [u8]) -> Result<(), zx_status_t>,
            ),
            (
                crate::userspace::qemu_loader_echo_client_size as fn() -> Option<u64>,
                crate::userspace::read_qemu_loader_echo_client_at
                    as fn(u64, &mut [u8]) -> Result<(), zx_status_t>,
            ),
            (
                crate::userspace::qemu_loader_controller_worker_size as fn() -> Option<u64>,
                crate::userspace::read_qemu_loader_controller_worker_at
                    as fn(u64, &mut [u8]) -> Result<(), zx_status_t>,
            ),
            (
                crate::userspace::qemu_loader_starnix_kernel_size as fn() -> Option<u64>,
                crate::userspace::read_qemu_loader_starnix_kernel_at
                    as fn(u64, &mut [u8]) -> Result<(), zx_status_t>,
            ),
            (
                crate::userspace::qemu_loader_linux_hello_size as fn() -> Option<u64>,
                crate::userspace::read_qemu_loader_linux_hello_at
                    as fn(u64, &mut [u8]) -> Result<(), zx_status_t>,
            ),
        ];
        let mut bootstrap_component_handles = [0; 5];
        for (index, (size_fn, read_at)) in bootstrap_component_images.iter().enumerate() {
            let Some(size_bytes) = size_fn() else {
                continue;
            };
            let global_vmo_id = state
                .with_kernel_mut(|kernel| Ok(kernel.allocate_global_vmo_id()))
                .expect("bootstrap component image global VMO id allocation must succeed");
            let imported = state
                .with_vm_mut(|vm| {
                    vm.create_pager_file_vmo_for_address_space(
                        process.process_id(),
                        address_space_id,
                        size_bytes,
                        *read_at,
                        global_vmo_id,
                    )
                })
                .expect("bootstrap component image VMO import must succeed");
            let object_id = state.alloc_object_id();
            state
                .with_registry_mut(|registry| {
                    registry.insert(
                        object_id,
                        KernelObject::Vmo(VmoObject {
                            creator_process_id: imported.process_id(),
                            global_vmo_id: imported.global_vmo_id(),
                            backing_scope: VmoBackingScope::GlobalShared,
                            kind: axle_mm::VmoKind::PagerBacked,
                            size_bytes: imported.size_bytes(),
                            image_layout: None,
                        }),
                    )?;
                    Ok(())
                })
                .expect("bootstrap component image VMO object insert must succeed");
            let handle = state
                .alloc_handle_for_object(object_id, handle::bootstrap_code_vmo_rights())
                .expect("bootstrap component image VMO handle allocation must succeed");
            bootstrap_component_handles[index] = handle;
        }
        state
            .with_registry_mut(|registry| {
                registry.bootstrap_echo_provider_code_vmo_handle = bootstrap_component_handles[0];
                registry.bootstrap_echo_client_code_vmo_handle = bootstrap_component_handles[1];
                registry.bootstrap_controller_worker_code_vmo_handle =
                    bootstrap_component_handles[2];
                registry.bootstrap_starnix_kernel_code_vmo_handle = bootstrap_component_handles[3];
                registry.bootstrap_linux_hello_code_vmo_handle = bootstrap_component_handles[4];
                Ok(())
            })
            .expect("bootstrap component image handle publish must succeed");

        device::seed_bootstrap_net_pci_device(&state)
            .expect("bootstrap net pci device handle publish must succeed");
        device::seed_real_net_pci_device(&state)
            .expect("real net pci device handle publish must succeed");

        state
    }

    fn reserve_object_key(&self) -> ObjectKey {
        let mut registry = self.registry.lock();
        registry.reserve_object_key()
    }

    fn alloc_object_id(&self) -> ObjectKey {
        self.reserve_object_key()
    }

    fn publish_reserved_object(
        &self,
        key: ObjectKey,
        object: KernelObject,
    ) -> Result<(), zx_status_t> {
        self.with_registry_mut(|registry| registry.publish_reserved_object(key, object))
    }

    fn discard_reserved_object(&self, key: ObjectKey) {
        self.registry.lock().discard_reserved_object(key);
    }

    fn capability_for_object(
        &self,
        key: ObjectKey,
        rights: crate::task::HandleRights,
    ) -> Capability {
        let registry = self.registry.lock();
        debug_assert!(registry.get(key).is_some());
        registry.capability_for_object(key, rights)
    }

    fn begin_logical_destroy(&self, key: ObjectKey) -> Result<KernelObject, zx_status_t> {
        self.with_registry_mut(|registry| registry.begin_logical_destroy(key))
    }

    fn finish_logical_destroy(&self, key: ObjectKey) {
        self.registry.lock().finish_logical_destroy(key);
    }

    fn note_timer_object(&self, timer_id: TimerId, key: ObjectKey) -> Result<(), zx_status_t> {
        self.with_registry_mut(|registry| {
            registry.retain_kernel_ref(key)?;
            let _ = registry.timer_object_ids.insert(timer_id, key);
            Ok(())
        })
    }

    fn note_guest_session(&self, thread_id: u64, key: ObjectKey) -> Result<(), zx_status_t> {
        self.with_registry_mut(|registry| {
            registry.retain_kernel_ref(key)?;
            let _ = registry.guest_session_thread_ids.insert(thread_id, key);
            Ok(())
        })
    }

    fn forget_timer_object(&self, timer_id: TimerId) {
        let mut registry = self.registry.lock();
        if let Some(key) = registry.timer_object_ids.remove(&timer_id) {
            registry.release_kernel_ref(key);
        }
    }

    fn forget_guest_session(&self, thread_id: u64) {
        let mut registry = self.registry.lock();
        if let Some(key) = registry.guest_session_thread_ids.remove(&thread_id) {
            registry.release_kernel_ref(key);
        }
    }

    fn timer_object_key(&self, timer_id: TimerId) -> Option<ObjectKey> {
        self.registry
            .lock()
            .timer_object_ids
            .get(&timer_id)
            .copied()
    }

    fn guest_session_key(&self, thread_id: u64) -> Option<ObjectKey> {
        self.registry
            .lock()
            .guest_session_thread_ids
            .get(&thread_id)
            .copied()
    }

    pub(crate) fn with_registry<T>(
        &self,
        f: impl FnOnce(&ObjectRegistry) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        let registry = self.registry.lock();
        f(&registry)
    }

    pub(crate) fn with_registry_mut<T>(
        &self,
        f: impl FnOnce(&mut ObjectRegistry) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        let mut registry = self.registry.lock();
        f(&mut registry)
    }

    pub(crate) fn with_objects<T>(
        &self,
        f: impl FnOnce(&ObjectRegistry) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        self.with_registry(f)
    }

    pub(crate) fn with_objects_mut<T>(
        &self,
        f: impl FnOnce(&mut ObjectRegistry) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        self.with_registry_mut(f)
    }

    pub(crate) fn with_transport<T>(
        &self,
        f: impl FnOnce(&TransportCore) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        let transport = self.transport.lock();
        f(&transport)
    }

    pub(crate) fn with_transport_mut<T>(
        &self,
        f: impl FnOnce(&mut TransportCore) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        let mut transport = self.transport.lock();
        f(&mut transport)
    }

    pub(crate) fn with_reactor<T>(
        &self,
        f: impl FnOnce(&crate::task::Reactor) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        let reactor = self.reactor.lock();
        f(&reactor)
    }

    pub(crate) fn with_reactor_mut<T>(
        &self,
        f: impl FnOnce(&mut crate::task::Reactor) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        let mut reactor = self.reactor.lock();
        f(&mut reactor)
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

    fn with_vm_mut<T>(
        &self,
        f: impl FnOnce(&crate::task::VmFacade) -> Result<T, zx_status_t>,
    ) -> Result<T, zx_status_t> {
        f(&self.vm)
    }

    fn with_frames_mut<T>(&self, f: impl FnOnce(&mut axle_mm::FrameTable) -> T) -> T {
        self.vm.with_frames_mut(f)
    }

    fn current_address_space_id(&self) -> Option<crate::task::AddressSpaceId> {
        self.with_core(|kernel| kernel.current_address_space_id())
            .ok()
    }

    fn apply_tlb_commit_reqs(&self, reqs: &[crate::task::TlbCommitReq]) -> Result<(), zx_status_t> {
        self.vm.apply_tlb_commit_reqs(
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
        self.vm.retire_bootstrap_frames_after_quiescence(
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

static STATE: Once<KernelState> = Once::new();

fn state() -> Result<&'static KernelState, zx_status_t> {
    STATE.get().ok_or(ZX_ERR_BAD_STATE)
}

/// Initialize global kernel object state.
pub fn init() {
    let _ = STATE.call_once(KernelState::new);
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
    finish_syscall_inner(trap, cpu_frame, false).map(|_| ())
}

pub(crate) fn finish_syscall_native(
    trap: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *mut u64,
) -> Result<bool, zx_status_t> {
    finish_syscall_inner(trap, cpu_frame, true)
}

fn finish_syscall_inner(
    trap: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *mut u64,
    allow_native_sysret: bool,
) -> Result<bool, zx_status_t> {
    let initial_thread_id =
        with_kernel_mut(|kernel| Ok(kernel.current_thread_info()?.thread_id())).ok();
    let mut blocked_current = false;
    run_trap_blocking(|resuming_blocked_current| {
        blocked_current |= resuming_blocked_current;
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
    })?;

    if !allow_native_sysret || blocked_current {
        return Ok(false);
    }
    let final_thread_id =
        with_kernel_mut(|kernel| Ok(kernel.current_thread_info()?.thread_id())).ok();
    Ok(initial_thread_id.is_some()
        && initial_thread_id == final_thread_id
        && crate::arch::syscall::sysret_eligible(cpu_frame.cast_const()))
}

pub(crate) fn handle_native_syscall_entry(
    trap: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *mut u64,
) -> Result<bool, zx_status_t> {
    run_trap_blocking(|resuming_blocked_current| {
        with_state_mut(|state| {
            guest::handle_native_syscall_trap(state, trap, cpu_frame, resuming_blocked_current)
        })
    })
}

pub(crate) fn finish_timer_interrupt(
    trap: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *mut u64,
) -> Result<(), zx_status_t> {
    run_trap_blocking(|resuming_blocked_current| {
        with_state_mut(|state| {
            let disposition = state.with_kernel_mut(|kernel| {
                if !resuming_blocked_current {
                    kernel.note_current_cpu_timer_tick(crate::time::now_ns())?;
                }
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

pub(crate) fn finish_reschedule_interrupt(
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

pub(crate) fn timer_interrupt_requires_trap_exit(now: i64) -> Result<bool, zx_status_t> {
    with_kernel_mut(|kernel| kernel.timer_interrupt_requires_trap_exit(now))
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
    f: impl FnOnce(&KernelState) -> Result<T, zx_status_t>,
) -> Result<T, zx_status_t> {
    f(state()?)
}

pub(crate) fn kernel_handle() -> Result<Arc<Mutex<crate::task::Kernel>>, zx_status_t> {
    Ok(state()?.kernel.clone())
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

pub(crate) fn run_current_cpu_idle_loop() -> ! {
    loop {
        match with_state_mut(|state| {
            let lifecycle_dirty =
                state.with_kernel_mut(|kernel| Ok(kernel.take_task_lifecycle_dirty()))?;
            if lifecycle_dirty {
                process::sync_task_lifecycle(state)?;
            }
            state.with_kernel_mut(|kernel| kernel.take_current_cpu_idle_context())
        }) {
            Ok(Some(context)) => context.enter(),
            Ok(None) => block_current_trap_until_runnable(),
            Err(status) => panic!("idle loop failed: {status}"),
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
        state.with_objects_mut(|objects| {
            objects.insert(object_id, KernelObject::Port(port))?;
            Ok(())
        })?;

        match state.alloc_handle_for_object(object_id, handle::port_default_rights()) {
            Ok(h) => Ok(h),
            Err(e) => {
                if let Some(KernelObject::Port(port)) =
                    state.with_objects_mut(|objects| Ok(objects.remove(object_id)))?
                {
                    let _ = state.with_kernel_mut(|kernel| port.destroy(kernel));
                }
                Err(e)
            }
        }
    })
}

/// Query one telemetry snapshot for a port object.
pub fn port_get_info(handle: zx_handle_t) -> Result<axle_types::ax_port_info_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        let object_key = resolved.object_key();
        let port = state.with_registry(|registry| {
            let Some(KernelObject::Port(port)) = registry.get(object_key) else {
                return Err(ZX_ERR_WRONG_TYPE);
            };
            Ok(port.telemetry_snapshot())
        })?;
        let observer = state
            .with_reactor(|reactor| Ok(reactor.observers().port_telemetry_snapshot(object_key)))?;
        Ok(axle_types::ax_port_info_t {
            capacity: port.capacity,
            kernel_reserve: port.kernel_reserve,
            current_depth: port.current_depth,
            peak_depth: port.peak_depth,
            user_queue_count: port.user_queue_count,
            user_should_wait_count: port.user_should_wait_count,
            user_reserve_hit_count: port.user_reserve_hit_count,
            user_full_hit_count: port.user_full_hit_count,
            kernel_queue_count: port.kernel_queue_count,
            kernel_should_wait_count: port.kernel_should_wait_count,
            pop_count: port.pop_count,
            pending_current: observer.pending_current,
            pending_peak: observer.pending_peak,
            pending_new_count: observer.pending_new_count,
            pending_merge_count: observer.pending_merge_count,
            pending_flush_delivered_count: observer.flush_delivered_count,
            depth_sample_count: port.depth_sample_count,
            depth_p50: port.depth_p50,
            depth_p90: port.depth_p90,
            depth_p99: port.depth_p99,
            reserved0: 0,
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
        state.with_objects_mut(|objects| {
            objects.insert(
                left_object_id,
                KernelObject::EventPair(EventPairEndpoint::new(right_object_id)),
            )?;
            objects.insert(
                right_object_id,
                KernelObject::EventPair(EventPairEndpoint::new(left_object_id)),
            )?;
            Ok(())
        })?;

        let left_handle = match state
            .alloc_handle_for_object(left_object_id, handle::eventpair_default_rights())
        {
            Ok(handle) => handle,
            Err(e) => {
                let _ = state.with_objects_mut(|objects| {
                    let _ = objects.remove(left_object_id);
                    let _ = objects.remove(right_object_id);
                    Ok(())
                });
                return Err(e);
            }
        };
        let right_handle = match state
            .alloc_handle_for_object(right_object_id, handle::eventpair_default_rights())
        {
            Ok(handle) => handle,
            Err(e) => {
                let _ = state.close_handle(left_handle);
                let _ = state.with_objects_mut(|objects| {
                    let _ = objects.remove(left_object_id);
                    let _ = objects.remove(right_object_id);
                    Ok(())
                });
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
        state.with_objects_mut(|objects| {
            objects.insert(
                object_id,
                KernelObject::Timer(TimerObject { timer_id, clock_id }),
            )?;
            Ok(())
        })?;
        state.note_timer_object(timer_id, object_id)?;

        match state.alloc_handle_for_object(object_id, handle::timer_default_rights()) {
            Ok(h) => Ok(h),
            Err(e) => {
                let _ = state.with_objects_mut(|objects| Ok(objects.remove(object_id)));
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

/// Create a virtual interrupt object and return a handle.
pub fn create_interrupt(options: u32) -> Result<zx_handle_t, zx_status_t> {
    if options != ZX_INTERRUPT_VIRTUAL {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let object_id = state.alloc_object_id();
        state.with_objects_mut(|objects| {
            objects.insert(
                object_id,
                KernelObject::Interrupt(InterruptObject::new(AX_INTERRUPT_MODE_VIRTUAL, 0, true)),
            )?;
            Ok(())
        })?;
        match state.alloc_handle_for_object(object_id, handle::interrupt_default_rights()) {
            Ok(handle) => Ok(handle),
            Err(err) => {
                let _ = state.with_objects_mut(|objects| Ok(objects.remove(object_id)));
                Err(err)
            }
        }
    })
}

/// Acknowledge one pending interrupt packet.
pub fn interrupt_ack(handle: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WRITE)?;
        let object_key = resolved.object_key();
        let current = state.with_objects_mut(|objects| {
            let interrupt = match objects.get_mut(object_key) {
                Some(KernelObject::Interrupt(interrupt)) => interrupt,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };
            interrupt.ack()
        })?;
        crate::wait::publish_signals_changed(state, object_key, current)
    })
}

/// Return one metadata snapshot for an interrupt object.
pub fn interrupt_get_info(handle: zx_handle_t) -> Result<ax_interrupt_info_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        state.with_objects(|objects| match objects.get(resolved.object_key()) {
            Some(KernelObject::Interrupt(interrupt)) => Ok(interrupt.info(handle)),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })
    })
}

/// Mask one interrupt object without discarding pending counts.
pub fn interrupt_mask(handle: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WRITE)?;
        let object_key = resolved.object_key();
        let current = state.with_objects_mut(|objects| {
            let interrupt = match objects.get_mut(object_key) {
                Some(KernelObject::Interrupt(interrupt)) => interrupt,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };
            Ok(interrupt.mask())
        })?;
        crate::wait::publish_signals_changed(state, object_key, current)
    })
}

/// Unmask one interrupt object and republish its current pending state.
pub fn interrupt_unmask(handle: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WRITE)?;
        let object_key = resolved.object_key();
        let current = state.with_objects_mut(|objects| {
            let interrupt = match objects.get_mut(object_key) {
                Some(KernelObject::Interrupt(interrupt)) => interrupt,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };
            Ok(interrupt.unmask())
        })?;
        crate::wait::publish_signals_changed(state, object_key, current)
    })
}

/// Software-trigger one virtual interrupt object.
pub fn ax_interrupt_trigger(handle: zx_handle_t, count: u64) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WRITE)?;
        let object_key = resolved.object_key();
        let current = state.with_objects_mut(|objects| {
            let interrupt = match objects.get_mut(object_key) {
                Some(KernelObject::Interrupt(interrupt)) => interrupt,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };
            if !interrupt.triggerable {
                return Err(ZX_ERR_NOT_SUPPORTED);
            }
            interrupt.trigger(count)
        })?;
        crate::wait::publish_signals_changed(state, object_key, current)
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
        state.with_objects_mut(|objects| {
            let endpoint = match objects.get_mut(resolved.object_key()) {
                Some(KernelObject::EventPair(endpoint)) => endpoint,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };
            endpoint.user_signals = endpoint.user_signals.without(clear).union(set);
            Ok(())
        })?;
        publish_object_signals(state, resolved.object_key())
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
        let peer_object = {
            let (peer_object, peer_closed) = state.with_objects(|objects| {
                Ok(match objects.get(resolved.object_key()) {
                    Some(KernelObject::EventPair(endpoint)) => {
                        (endpoint.peer_object, endpoint.peer_closed)
                    }
                    Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                    None => return Err(ZX_ERR_BAD_HANDLE),
                })
            })?;
            require_handle_rights(resolved, crate::task::HandleRights::SIGNAL_PEER)?;
            if peer_closed {
                return Err(ZX_ERR_PEER_CLOSED);
            }
            peer_object
        };

        state.with_objects_mut(|objects| {
            let peer = match objects.get_mut(peer_object) {
                Some(KernelObject::EventPair(peer)) => peer,
                Some(_) => return Err(ZX_ERR_BAD_STATE),
                None => return Err(ZX_ERR_PEER_CLOSED),
            };
            if peer.closed {
                return Err(ZX_ERR_PEER_CLOSED);
            }
            peer.user_signals = peer.user_signals.without(clear).union(set);
            Ok(())
        })?;
        publish_object_signals(state, peer_object)
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
    let thread = state.with_objects(|objects| {
        Ok(match objects.get(resolved.object_key()) {
            Some(KernelObject::Thread(thread)) => *thread,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        })
    })?;
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
    let thread = state.with_objects(|objects| {
        Ok(match objects.get(resolved.object_key()) {
            Some(KernelObject::Thread(thread)) => *thread,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        })
    })?;
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
        let object_key = resolved.object_key();
        let timer_id = state.with_objects(|objects| {
            Ok(match objects.get(object_key) {
                Some(KernelObject::Timer(timer)) => timer.timer_id,
                Some(KernelObject::Process(_))
                | Some(KernelObject::SuspendToken(_))
                | Some(KernelObject::GuestSession(_))
                | Some(KernelObject::Socket(_))
                | Some(KernelObject::Channel(_))
                | Some(KernelObject::EventPair(_))
                | Some(KernelObject::Port(_))
                | Some(KernelObject::Interrupt(_))
                | Some(KernelObject::PciDevice(_))
                | Some(KernelObject::RevocationGroup(_))
                | Some(KernelObject::DmaRegion(_))
                | Some(KernelObject::Thread(_))
                | Some(KernelObject::Vmo(_))
                | Some(KernelObject::Vmar(_)) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
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
        crate::wait::publish_signals_changed(state, object_key, current)
    })
}

/// Cancel a timer.
pub fn timer_cancel(handle: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_key = resolved.object_key();
        let timer_id = state.with_objects(|objects| {
            Ok(match objects.get(object_key) {
                Some(KernelObject::Timer(timer)) => timer.timer_id,
                Some(KernelObject::Process(_))
                | Some(KernelObject::SuspendToken(_))
                | Some(KernelObject::GuestSession(_))
                | Some(KernelObject::Socket(_))
                | Some(KernelObject::Channel(_))
                | Some(KernelObject::EventPair(_))
                | Some(KernelObject::Port(_))
                | Some(KernelObject::Interrupt(_))
                | Some(KernelObject::PciDevice(_))
                | Some(KernelObject::RevocationGroup(_))
                | Some(KernelObject::DmaRegion(_))
                | Some(KernelObject::Thread(_))
                | Some(KernelObject::Vmo(_))
                | Some(KernelObject::Vmar(_)) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;

        state.with_kernel_mut(|kernel| {
            kernel
                .cancel_timer_object(timer_id)
                .map_err(map_timer_error)
        })?;
        crate::wait::publish_signals_changed(state, object_key, Signals::NONE)
    })
}

/// Snapshot current signals for a waitable object.
pub fn object_signals(handle: zx_handle_t) -> Result<zx_signals_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WAIT)?;
        let object_key = resolved.object_key();
        signals_for_object_id(state, object_key).map(|s| s.bits())
    })
}

#[derive(Clone, Copy, Debug)]
enum CloseHandleAction {
    None,
    SuspendToken { target: SuspendTarget },
    GuestSession { thread_id: u64 },
    Socket { peer_object: ObjectKey },
    Channel { peer_object: ObjectKey },
    EventPair { peer_object: ObjectKey },
    Port,
    Timer,
    Interrupt,
    DmaRegion,
    PciDevice,
    RevocationGroup,
    Vmo,
    Vmar,
}

fn close_handle_action_for_live_object(object: &KernelObject) -> CloseHandleAction {
    match object {
        KernelObject::SuspendToken(token) => CloseHandleAction::SuspendToken {
            target: token.target,
        },
        KernelObject::GuestSession(session) => CloseHandleAction::GuestSession {
            thread_id: session.thread_id,
        },
        KernelObject::Socket(endpoint) => CloseHandleAction::Socket {
            peer_object: endpoint.peer_object,
        },
        KernelObject::Channel(endpoint) => CloseHandleAction::Channel {
            peer_object: endpoint.peer_object,
        },
        KernelObject::EventPair(endpoint) => CloseHandleAction::EventPair {
            peer_object: endpoint.peer_object,
        },
        KernelObject::Port(_) => CloseHandleAction::Port,
        KernelObject::Timer(_) => CloseHandleAction::Timer,
        KernelObject::Interrupt(_) => CloseHandleAction::Interrupt,
        KernelObject::DmaRegion(_) => CloseHandleAction::DmaRegion,
        KernelObject::PciDevice(_) => CloseHandleAction::PciDevice,
        KernelObject::RevocationGroup(_) => CloseHandleAction::RevocationGroup,
        KernelObject::Vmo(_) => CloseHandleAction::Vmo,
        KernelObject::Vmar(_) => CloseHandleAction::Vmar,
        KernelObject::Process(_) | KernelObject::Thread(_) => CloseHandleAction::None,
    }
}

fn finalize_last_handle_close(
    state: &KernelState,
    object_key: ObjectKey,
    action: CloseHandleAction,
) -> Result<(), zx_status_t> {
    match action {
        CloseHandleAction::None => Ok(()),
        CloseHandleAction::SuspendToken { target } => {
            process::close_suspend_token(state, object_key, target)
        }
        CloseHandleAction::GuestSession { thread_id } => {
            let removed = state.begin_logical_destroy(object_key)?;
            let result = match removed {
                KernelObject::GuestSession(session) => {
                    state.forget_guest_session(thread_id);
                    let kill_status = state.with_kernel_mut(|kernel| kernel.kill_thread(thread_id));
                    if let Err(status) = kill_status
                        && status != ZX_ERR_BAD_HANDLE
                        && status != ZX_ERR_BAD_STATE
                    {
                        return Err(status);
                    }
                    if session.stopped_seq.is_some() || kill_status.is_ok() {
                        process::sync_task_lifecycle(state)?;
                    }
                    Ok(())
                }
                _ => Err(ZX_ERR_BAD_STATE),
            };
            state.finish_logical_destroy(object_key);
            result
        }
        CloseHandleAction::Socket { peer_object } => {
            state.with_reactor_mut(|reactor| {
                reactor.remove_waitable(object_key);
                Ok(())
            })?;
            let removed = state.begin_logical_destroy(object_key)?;
            let result = match removed {
                KernelObject::Socket(endpoint) => state.with_transport_mut(|transport| {
                    let should_drop_core = match transport.socket_cores.get_mut(&endpoint.core_id) {
                        Some(core) => {
                            core.close_side(endpoint.side);
                            core.fully_closed()
                        }
                        None => return Err(ZX_ERR_BAD_STATE),
                    };
                    if should_drop_core
                        && let Some(core) = transport.socket_cores.remove(&endpoint.core_id)
                    {
                        transport.note_socket_core_drop(&core);
                    }
                    Ok(())
                }),
                _ => Err(ZX_ERR_BAD_STATE),
            };
            state.finish_logical_destroy(object_key);
            result?;
            if let Err(status) = publish_object_signals(state, peer_object)
                && status != ZX_ERR_BAD_HANDLE
            {
                return Err(status);
            }
            Ok(())
        }
        CloseHandleAction::Channel { peer_object } => {
            state.with_reactor_mut(|reactor| {
                reactor.remove_waitable(object_key);
                Ok(())
            })?;
            let removed = state.begin_logical_destroy(object_key)?;
            let result = match removed {
                KernelObject::Channel(mut endpoint) => {
                    endpoint.closed = true;
                    let drained = endpoint.messages.drain(..).collect::<Vec<_>>();
                    transport::drain_channel_messages(state, drained);
                    state.with_objects_mut(|objects| {
                        if let Some(KernelObject::Channel(peer)) = objects.get_mut(peer_object) {
                            peer.peer_closed = true;
                        }
                        Ok(())
                    })
                }
                _ => Err(ZX_ERR_BAD_STATE),
            };
            state.finish_logical_destroy(object_key);
            result?;
            if let Err(status) = publish_object_signals(state, peer_object)
                && status != ZX_ERR_BAD_HANDLE
            {
                return Err(status);
            }
            Ok(())
        }
        CloseHandleAction::EventPair { peer_object } => {
            state.with_reactor_mut(|reactor| {
                reactor.remove_waitable(object_key);
                Ok(())
            })?;
            let removed = state.begin_logical_destroy(object_key)?;
            let result = match removed {
                KernelObject::EventPair(_) => state.with_objects_mut(|objects| {
                    if let Some(KernelObject::EventPair(peer)) = objects.get_mut(peer_object) {
                        peer.peer_closed = true;
                    }
                    Ok(())
                }),
                _ => Err(ZX_ERR_BAD_STATE),
            };
            state.finish_logical_destroy(object_key);
            result?;
            if let Err(status) = publish_object_signals(state, peer_object)
                && status != ZX_ERR_BAD_HANDLE
            {
                return Err(status);
            }
            Ok(())
        }
        CloseHandleAction::Port => {
            state.with_reactor_mut(|reactor| {
                reactor.remove_port(object_key);
                reactor.remove_waitable(object_key);
                Ok(())
            })?;
            let removed = state.begin_logical_destroy(object_key)?;
            let result = match removed {
                KernelObject::Port(port) => state.with_kernel_mut(|kernel| port.destroy(kernel)),
                _ => Err(ZX_ERR_BAD_STATE),
            };
            state.finish_logical_destroy(object_key);
            result
        }
        CloseHandleAction::Timer => {
            state.with_reactor_mut(|reactor| {
                reactor.remove_waitable(object_key);
                Ok(())
            })?;
            let removed = state.begin_logical_destroy(object_key)?;
            let timer_id = match removed {
                KernelObject::Timer(timer) => timer.timer_id,
                _ => {
                    state.finish_logical_destroy(object_key);
                    return Err(ZX_ERR_BAD_STATE);
                }
            };
            state.forget_timer_object(timer_id);
            let result = state.with_kernel_mut(|kernel| {
                kernel
                    .destroy_timer_object(timer_id)
                    .map_err(map_timer_error)
            });
            state.finish_logical_destroy(object_key);
            result
        }
        CloseHandleAction::Interrupt => {
            state.with_reactor_mut(|reactor| {
                reactor.remove_waitable(object_key);
                Ok(())
            })?;
            let _ = state.begin_logical_destroy(object_key)?;
            state.finish_logical_destroy(object_key);
            Ok(())
        }
        CloseHandleAction::DmaRegion => {
            let removed = state.begin_logical_destroy(object_key)?;
            let result = match removed {
                KernelObject::DmaRegion(region) => {
                    state.with_frames_mut(|frames| region.release(frames));
                    Ok(())
                }
                _ => Err(ZX_ERR_BAD_STATE),
            };
            state.finish_logical_destroy(object_key);
            result
        }
        CloseHandleAction::PciDevice => {
            let removed = state.begin_logical_destroy(object_key)?;
            let result = match removed {
                KernelObject::PciDevice(device) => {
                    device::release_pci_device_resources(state, device);
                    Ok(())
                }
                _ => Err(ZX_ERR_BAD_STATE),
            };
            state.finish_logical_destroy(object_key);
            result
        }
        CloseHandleAction::RevocationGroup => {
            let _ = state.begin_logical_destroy(object_key)?;
            state.finish_logical_destroy(object_key);
            Ok(())
        }
        CloseHandleAction::Vmo | CloseHandleAction::Vmar => {
            let _ = state.begin_logical_destroy(object_key)?;
            state.finish_logical_destroy(object_key);
            Ok(())
        }
    }
}

/// Close a handle in CSpace and apply minimal object-specific side effects.
pub fn close_handle(raw: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.resolve_handle_raw(raw)?;
        let object_key = resolved.object_key();
        let action = state.with_objects(|objects| {
            Ok(objects
                .get(object_key)
                .map(close_handle_action_for_live_object)
                .unwrap_or(CloseHandleAction::None))
        })?;
        state.close_handle(raw)?;

        if state.object_handle_count(object_key) == 0 {
            finalize_last_handle_close(state, object_key, action)?;
        }
        sync_task_lifecycle(state)?;
        Ok(())
    })
}

fn ensure_handle_kind(handle: zx_handle_t, expected: ObjectKind) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_key = resolved.object_key();
        let kind = state.with_objects(|objects| {
            let obj = objects.get(object_key).ok_or(ZX_ERR_BAD_HANDLE)?;
            Ok(match obj {
                KernelObject::Process(process) => {
                    let _ = (process.process_id, process.koid);
                    ObjectKind::Process
                }
                KernelObject::SuspendToken(_) => ObjectKind::SuspendToken,
                KernelObject::GuestSession(session) => {
                    let _ = (
                        session.thread_id,
                        session.sidecar_vmo.global_vmo_id().raw(),
                        session.port_object.object_id(),
                        session.packet_key,
                        session.stop_seq,
                        session.stopped_seq,
                    );
                    ObjectKind::GuestSession
                }
                KernelObject::Socket(endpoint) => {
                    let _ = (endpoint.core_id, endpoint.peer_object, endpoint.side);
                    ObjectKind::Socket
                }
                KernelObject::Channel(endpoint) => {
                    let _ = (
                        endpoint.peer_object,
                        endpoint.messages.len(),
                        endpoint.peer_closed,
                        endpoint.closed,
                    );
                    ObjectKind::Channel
                }
                KernelObject::EventPair(endpoint) => {
                    let _ = (
                        endpoint.peer_object,
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
                KernelObject::Interrupt(interrupt) => {
                    let _ = (
                        interrupt.pending_count,
                        interrupt.masked,
                        interrupt.mode,
                        interrupt.vector,
                        interrupt.triggerable,
                    );
                    ObjectKind::Interrupt
                }
                KernelObject::DmaRegion(region) => {
                    let _ = (
                        region.source_vmo_object.object_id(),
                        region.source_offset,
                        region.size_bytes,
                        region.options,
                        region.pin.frame_ids().len(),
                    );
                    ObjectKind::DmaRegion
                }
                KernelObject::PciDevice(device) => {
                    let _ = (
                        device.vendor_id,
                        device.device_id,
                        device
                            .bars
                            .first()
                            .map(|bar| bar.object.object_id())
                            .unwrap_or(0),
                        device
                            .bars
                            .first()
                            .and_then(|bar| bar.backing_object)
                            .map(ObjectKey::object_id)
                            .unwrap_or(0),
                        device.queue_pairs,
                        device.queue_size,
                    );
                    ObjectKind::PciDevice
                }
                KernelObject::RevocationGroup(group) => {
                    let _ = (group.token().id().raw(), group.token().generation());
                    ObjectKind::RevocationGroup
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
            })
        })?;

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
    state: &KernelState,
    object_key: ObjectKey,
) -> Result<(), zx_status_t> {
    let current = signals_for_object_id(state, object_key)?;
    crate::wait::publish_signals_changed(state, object_key, current)
}

pub(crate) fn publish_timer_fired(
    state: &KernelState,
    timer_id: TimerId,
) -> Result<(), zx_status_t> {
    let object_key = state.timer_object_key(timer_id).ok_or(ZX_ERR_BAD_STATE)?;
    crate::wait::publish_signals_changed(state, object_key, Signals::TIMER_SIGNALED)
}

pub(crate) fn signals_for_object_id(
    state: &KernelState,
    object_key: ObjectKey,
) -> Result<Signals, zx_status_t> {
    state.with_objects(|objects| {
        let obj = objects.get(object_key).ok_or(ZX_ERR_BAD_HANDLE)?;
        match obj {
            KernelObject::Process(process) => {
                state.with_kernel(|kernel| kernel.process_signals(process.process_id))
            }
            KernelObject::Thread(thread) => {
                state.with_kernel(|kernel| kernel.thread_signals(thread.thread_id))
            }
            KernelObject::GuestSession(_) => Ok(Signals::NONE),
            KernelObject::Socket(endpoint) => state.with_transport(|transport| {
                let core = transport
                    .socket_cores
                    .get(&endpoint.core_id)
                    .ok_or(ZX_ERR_BAD_STATE)?;
                Ok(core.signals_for(endpoint.side))
            }),
            KernelObject::Channel(endpoint) => {
                let mut signals = Signals::NONE;
                if endpoint.is_readable() {
                    signals = signals | Signals::CHANNEL_READABLE;
                }
                if endpoint.peer_closed {
                    signals = signals | Signals::CHANNEL_PEER_CLOSED;
                } else {
                    let peer = match objects.get(endpoint.peer_object) {
                        Some(KernelObject::Channel(peer)) => peer,
                        _ => return Err(ZX_ERR_BAD_STATE),
                    };
                    if endpoint.writable_via_peer(peer) {
                        signals = signals | Signals::CHANNEL_WRITABLE;
                    }
                }
                Ok(signals)
            }
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
            KernelObject::Interrupt(interrupt) => Ok(interrupt.signals()),
            KernelObject::DmaRegion(_)
            | KernelObject::PciDevice(_)
            | KernelObject::RevocationGroup(_)
            | KernelObject::Vmo(_)
            | KernelObject::Vmar(_) => Ok(Signals::NONE),
        }
    })
}

pub(crate) fn sync_task_lifecycle(state: &KernelState) -> Result<(), zx_status_t> {
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
