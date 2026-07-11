// SPDX-License-Identifier: MPL-2.0

use core::{ptr, ptr::NonNull};

use ostd::{
    mm::{
        HasDaddr, HasPaddr, HasSize, PAGE_SIZE,
        dma::{DmaCoherent, PendingDmaUnmap},
    },
    sync::SpinLock,
};
use virtio_drivers::{BufferDirection, Hal, PhysAddr};

use crate::pci;

const REQUEST_OFFSET: usize = 0;
const REQUEST_LEN: usize = 16;
const DATA_OFFSET: usize = REQUEST_OFFSET + REQUEST_LEN;
const DATA_LEN: usize = 512;
const RESPONSE_OFFSET: usize = DATA_OFFSET + DATA_LEN;
const RESPONSE_LEN: usize = 1;
const RESPONSE_NOT_READY: u8 = 3;
const OWNER_COUNT: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerKind {
    QueueDriver,
    QueueDevice,
    Request,
}

impl OwnerKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::QueueDriver => "queue_driver",
            Self::QueueDevice => "queue_device",
            Self::Request => "request",
        }
    }

    const fn slot(self) -> usize {
        match self {
            Self::QueueDriver => 0,
            Self::QueueDevice => 1,
            Self::Request => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerState {
    Active,
    RetiredAfterReset,
    QuarantinedAfterUnsafeDrop,
}

#[derive(Clone, Copy)]
struct ShareRecord {
    original: usize,
    len: usize,
    direction: BufferDirection,
    active: bool,
}

impl ShareRecord {
    const EMPTY: Self = Self {
        original: 0,
        len: 0,
        direction: BufferDirection::DriverToDevice,
        active: false,
    };
}

struct DmaOwner {
    kind: OwnerKind,
    generation: u64,
    state: OwnerState,
    dma: DmaCoherent,
    paddr: usize,
    daddr: usize,
    vaddr: NonNull<u8>,
    shares: [ShareRecord; 3],
    share_count: usize,
    unshare_count: usize,
}

impl DmaOwner {
    fn new(kind: OwnerKind, generation: u64, dma: DmaCoherent) -> Self {
        let paddr = dma.paddr();
        let daddr = dma.daddr();
        // SAFETY: the ledger retains the unique `DmaCoherent` owner until
        // reset and IOTLB closure. Nexus creates no overlapping independent
        // access through VmReader/VmWriter; VirtIO and the ledger use this one
        // owner-bound raw mapping under the queue/reset protocol.
        let vaddr = unsafe { dma.as_non_null_ptr_exclusive() };
        assert_eq!(dma.size(), PAGE_SIZE);
        assert_eq!(
            vaddr.as_ptr() as usize % PAGE_SIZE,
            0,
            "DMA CPU address is page aligned"
        );
        assert_ne!(daddr, paddr, "Stage 5B requires a non-identity IOVA");
        Self {
            kind,
            generation,
            state: OwnerState::Active,
            dma,
            paddr,
            daddr,
            vaddr,
            shares: [ShareRecord::EMPTY; 3],
            share_count: 0,
            unshare_count: 0,
        }
    }
}

// SAFETY: the raw pointer designates the DMA allocation owned by `dma`; all
// access is synchronized by the ledger or the VirtIO queue protocol, and the
// allocation itself is valid for cross-CPU coherent DMA.
unsafe impl Send for DmaOwner {}

struct DmaLedger {
    generation: u64,
    device_exposed: bool,
    reset_acked: bool,
    owners: [Option<DmaOwner>; OWNER_COUNT],
}

impl DmaLedger {
    const fn new() -> Self {
        Self {
            generation: 0,
            device_exposed: false,
            reset_acked: false,
            owners: [const { None }; OWNER_COUNT],
        }
    }
}

static DMA_LEDGER: SpinLock<DmaLedger> = SpinLock::new(DmaLedger::new());

pub fn begin_generation(generation: u64) {
    assert_ne!(generation, 0);
    let mut ledger = DMA_LEDGER.lock();
    assert_eq!(ledger.generation, 0, "previous DMA generation still live");
    assert!(ledger.owners.iter().all(Option::is_none));
    ledger.generation = generation;
    ledger.device_exposed = false;
    ledger.reset_acked = false;
}

pub fn mark_queue_exposed(generation: u64) {
    let mut ledger = DMA_LEDGER.lock();
    assert_eq!(ledger.generation, generation);
    assert!(!ledger.device_exposed);
    assert!(ledger.owners[OwnerKind::QueueDriver.slot()].is_some());
    assert!(ledger.owners[OwnerKind::QueueDevice.slot()].is_some());
    ledger.device_exposed = true;
}

pub fn arm_request_bounce(generation: u64) -> (usize, usize) {
    let dma = DmaCoherent::alloc(1, true).expect("allocate request bounce page");
    let mut owner = DmaOwner::new(OwnerKind::Request, generation, dma);
    // The status output must start at NOT_READY. If the device fails to write
    // it, completion cannot be mistaken for success merely because DMA pages
    // are initially zeroed.
    // SAFETY: this byte is inside the exclusively owned request DMA page and
    // the page has not yet been published to a device.
    unsafe {
        ptr::write(
            owner.vaddr.as_ptr().add(RESPONSE_OFFSET),
            RESPONSE_NOT_READY,
        );
    }

    let receipt = (owner.paddr, owner.daddr);
    let mut ledger = DMA_LEDGER.lock();
    assert_eq!(ledger.generation, generation);
    let slot = OwnerKind::Request.slot();
    assert!(ledger.owners[slot].is_none());
    owner.state = OwnerState::Active;
    ledger.owners[slot] = Some(owner);
    receipt
}

pub fn request_share_counts(generation: u64) -> (usize, usize) {
    let ledger = DMA_LEDGER.lock();
    assert_eq!(ledger.generation, generation);
    let owner = ledger.owners[OwnerKind::Request.slot()]
        .as_ref()
        .expect("request owner retained");
    (owner.share_count, owner.unshare_count)
}

#[must_use = "dropping DMA closure authority permanently retains the reset generation"]
pub struct DmaClosureAuthority {
    generation: u64,
}

pub(crate) struct ResetAcknowledged {
    generation: u64,
}

/// Records the external device-quiescence proof before queue retirement.
///
/// # Safety
///
/// The caller must have observed whole-device reset status zero for this
/// generation and disabled bus mastering for the exact device owning all
/// mappings in the ledger.
pub(crate) unsafe fn acknowledge_device_reset(generation: u64) -> ResetAcknowledged {
    let mut ledger = DMA_LEDGER.lock();
    assert_eq!(ledger.generation, generation);
    assert!(!ledger.reset_acked, "reset acknowledged twice");
    ledger.reset_acked = true;
    ResetAcknowledged { generation }
}

pub(crate) fn seal_queue_retirement(reset: ResetAcknowledged) -> DmaClosureAuthority {
    let ledger = DMA_LEDGER.lock();
    assert_eq!(ledger.generation, reset.generation);
    assert!(ledger.reset_acked);
    for kind in [OwnerKind::QueueDriver, OwnerKind::QueueDevice] {
        assert_eq!(
            ledger.owners[kind.slot()]
                .as_ref()
                .expect("queue owner retained")
                .state,
            OwnerState::RetiredAfterReset
        );
    }
    assert_eq!(
        ledger.owners[OwnerKind::Request.slot()]
            .as_ref()
            .expect("request owner retained")
            .state,
        OwnerState::Active
    );
    DmaClosureAuthority {
        generation: reset.generation,
    }
}

pub fn retained_pages(generation: u64) -> usize {
    let ledger = DMA_LEDGER.lock();
    assert_eq!(ledger.generation, generation);
    ledger.owners.iter().flatten().count()
}

pub fn owner_address(generation: u64, kind: OwnerKind) -> (usize, usize) {
    let ledger = DMA_LEDGER.lock();
    assert_eq!(ledger.generation, generation);
    let owner = ledger.owners[kind.slot()]
        .as_ref()
        .expect("DMA owner retained");
    (owner.paddr, owner.daddr)
}

fn allocate_queue_owner(pages: usize, direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
    if pages != 1 {
        return (0, NonNull::dangling());
    }

    let kind = match direction {
        BufferDirection::DriverToDevice => OwnerKind::QueueDriver,
        BufferDirection::DeviceToDriver => OwnerKind::QueueDevice,
        BufferDirection::Both => return (0, NonNull::dangling()),
    };

    let Ok(dma) = DmaCoherent::alloc(pages, true) else {
        return (0, NonNull::dangling());
    };
    let mut ledger = DMA_LEDGER.lock();
    let generation = ledger.generation;
    assert_ne!(generation, 0, "queue DMA allocated outside a generation");
    let slot = kind.slot();
    assert!(ledger.owners[slot].is_none(), "duplicate queue DMA owner");
    let owner = DmaOwner::new(kind, generation, dma);
    let daddr = u64::try_from(owner.daddr).expect("IOVA fits VirtIO PhysAddr");
    let vaddr = owner.vaddr;
    ledger.owners[slot] = Some(owner);
    (daddr, vaddr)
}

fn retire_queue_owner(device_address: PhysAddr, vaddr: NonNull<u8>, pages: usize) -> i32 {
    assert_eq!(pages, 1);
    let device_address = usize::try_from(device_address).expect("VirtIO IOVA fits usize");
    let mut ledger = DMA_LEDGER.lock();
    let generation = ledger.generation;
    let reset_acked = ledger.reset_acked;
    let index = ledger
        .owners
        .iter()
        .position(|owner| {
            owner.as_ref().is_some_and(|owner| {
                matches!(owner.kind, OwnerKind::QueueDriver | OwnerKind::QueueDevice)
                    && owner.daddr == device_address
            })
        })
        .expect("matching queue DMA owner");

    if !ledger.device_exposed {
        let owner = ledger.owners[index]
            .take()
            .expect("pre-exposure queue owner");
        assert_eq!(owner.vaddr, vaddr);
        drop(ledger);
        // This owner was never published to the device, so ordinary
        // fail-closed OSTD teardown is sufficient for constructor rollback.
        drop(owner.dma);
        return 0;
    }

    let owner = ledger.owners[index].as_mut().expect("queue DMA owner");
    assert_eq!(owner.generation, generation);
    assert_eq!(owner.vaddr, vaddr);
    assert_eq!(owner.state, OwnerState::Active);
    owner.state = if reset_acked {
        OwnerState::RetiredAfterReset
    } else {
        // Losing a live Session must quarantine, not release, memory which a
        // device may still access. No closure path can consume this state.
        OwnerState::QuarantinedAfterUnsafeDrop
    };
    0
}

fn expected_share(index: usize) -> (usize, usize, BufferDirection) {
    match index {
        0 => (REQUEST_OFFSET, REQUEST_LEN, BufferDirection::DriverToDevice),
        1 => (DATA_OFFSET, DATA_LEN, BufferDirection::DeviceToDriver),
        2 => (
            RESPONSE_OFFSET,
            RESPONSE_LEN,
            BufferDirection::DeviceToDriver,
        ),
        _ => panic!("unexpected VirtIO share call"),
    }
}

unsafe fn share_request(buffer: NonNull<[u8]>, direction: BufferDirection) -> PhysAddr {
    // SAFETY: the VirtIO queue promises a valid non-empty buffer for this call.
    let len = unsafe { buffer.as_ref().len() };
    let original_ptr = buffer.as_ptr().cast::<u8>();
    let original = original_ptr as usize;
    let mut ledger = DMA_LEDGER.lock();
    let owner = ledger.owners[OwnerKind::Request.slot()]
        .as_mut()
        .expect("request bounce armed before queue.add");
    assert_eq!(owner.state, OwnerState::Active);
    let index = owner.share_count;
    let (offset, expected_len, expected_direction) = expected_share(index);
    assert_eq!(len, expected_len);
    assert_eq!(direction, expected_direction);
    assert!(!owner.shares[index].active);

    if matches!(
        direction,
        BufferDirection::DriverToDevice | BufferDirection::Both
    ) {
        // SAFETY: both ranges are valid, disjoint, and exactly `len` bytes;
        // the device has not received the destination IOVA yet.
        unsafe {
            ptr::copy_nonoverlapping(original_ptr, owner.vaddr.as_ptr().add(offset), len);
        }
    }

    owner.shares[index] = ShareRecord {
        original,
        len,
        direction,
        active: true,
    };
    owner.share_count += 1;
    let device_address = owner
        .daddr
        .checked_add(offset)
        .expect("request IOVA range overflow");
    u64::try_from(device_address).expect("request IOVA fits VirtIO PhysAddr")
}

unsafe fn unshare_request(
    device_address: PhysAddr,
    buffer: NonNull<[u8]>,
    direction: BufferDirection,
) {
    // SAFETY: the VirtIO queue promises this is the matching live buffer.
    let len = unsafe { buffer.as_ref().len() };
    let original_ptr = buffer.as_ptr().cast::<u8>();
    let original = original_ptr as usize;
    let device_address = usize::try_from(device_address).expect("request IOVA fits usize");
    let mut ledger = DMA_LEDGER.lock();
    let owner = ledger.owners[OwnerKind::Request.slot()]
        .as_mut()
        .expect("request owner retained through pop_used");
    let index = owner.unshare_count;
    let (offset, expected_len, expected_direction) = expected_share(index);
    let record = owner.shares[index];
    assert!(record.active);
    assert_eq!(record.original, original);
    assert_eq!(record.len, len);
    assert_eq!(record.direction, direction);
    assert_eq!(expected_len, len);
    assert_eq!(expected_direction, direction);
    assert_eq!(
        owner
            .daddr
            .checked_add(offset)
            .expect("request IOVA range overflow"),
        device_address
    );

    if matches!(
        direction,
        BufferDirection::DeviceToDriver | BufferDirection::Both
    ) {
        // SAFETY: reset has not started, the matching used descriptor proves
        // the device is done with this range, and both buffers are valid.
        unsafe {
            ptr::copy_nonoverlapping(owner.vaddr.as_ptr().add(offset), original_ptr, len);
        }
    }

    owner.shares[index].active = false;
    owner.unshare_count += 1;
}

pub struct OstdHal;

// SAFETY: every returned DMA/MMIO pointer is tied to an owner retained in a
// static ledger, and request sharing validates the exact three-buffer layout.
unsafe impl Hal for OstdHal {
    fn dma_alloc(pages: usize, direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        allocate_queue_owner(pages, direction)
    }

    unsafe fn dma_dealloc(paddr: PhysAddr, vaddr: NonNull<u8>, pages: usize) -> i32 {
        retire_queue_owner(paddr, vaddr, pages)
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, size: usize) -> NonNull<u8> {
        // SAFETY: `pci` retains the unique BAR owners until all transports are
        // gone and validates that this subrange is fully contained.
        unsafe { pci::mmio_phys_to_virt(paddr, size) }
    }

    unsafe fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> PhysAddr {
        // SAFETY: forwarded from the VirtIO queue under its buffer contract.
        unsafe { share_request(buffer, direction) }
    }

    unsafe fn unshare(paddr: PhysAddr, buffer: NonNull<[u8]>, direction: BufferDirection) {
        // SAFETY: forwarded from the matching VirtIO used-chain recycle.
        unsafe { unshare_request(paddr, buffer, direction) }
    }
}

fn take_after_reset(generation: u64, kind: OwnerKind) -> DmaOwner {
    let mut ledger = DMA_LEDGER.lock();
    assert_eq!(ledger.generation, generation);
    assert!(ledger.reset_acked, "IOTLB teardown before reset ack");
    {
        let owner = ledger.owners[kind.slot()]
            .as_ref()
            .expect("DMA owner retained until teardown");
        assert_eq!(owner.generation, generation);
        match kind {
            OwnerKind::QueueDriver | OwnerKind::QueueDevice => {
                assert_eq!(owner.state, OwnerState::RetiredAfterReset);
            }
            OwnerKind::Request => assert_eq!(owner.state, OwnerState::Active),
        }
    }
    ledger.owners[kind.slot()]
        .take()
        .expect("validated DMA owner remains retained")
}

fn finish_generation(generation: u64) {
    let mut ledger = DMA_LEDGER.lock();
    assert_eq!(ledger.generation, generation);
    assert!(ledger.reset_acked);
    assert!(ledger.owners.iter().all(Option::is_none));
    ledger.generation = 0;
    ledger.device_exposed = false;
    ledger.reset_acked = false;
}

#[must_use = "dropping an IOTLB tombstone fail-closes but loses its recovery handle"]
pub struct IotlbTombstone {
    generation: u64,
    kind: OwnerKind,
    pending: Option<PendingDmaUnmap>,
    completed: usize,
}

impl IotlbTombstone {
    pub fn retained_pages(&self) -> usize {
        usize::from(self.pending.is_some()) + retained_pages(self.generation)
    }

    pub const fn pending_kind(&self) -> OwnerKind {
        self.kind
    }

    pub fn failure_retained(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| pending.failure().is_some())
    }

    pub fn retry(mut self, poll_budget: usize) -> ClosureProgress {
        assert_ne!(poll_budget, 0);
        let mut polls = 0;

        loop {
            if polls == poll_budget {
                return ClosureProgress::Pending(self);
            }
            polls += 1;
            let pending = self.pending.take().expect("pending owner is present");
            match pending.poll_complete() {
                Ok(unmapped) => {
                    assert_eq!(unmapped.size(), PAGE_SIZE);
                    drop(unmapped);
                    self.completed += 1;
                    if self.completed == OWNER_COUNT {
                        finish_generation(self.generation);
                        return ClosureProgress::Complete(ClosureReceipt {
                            generation: self.generation,
                            completed_pages: self.completed,
                        });
                    }

                    self.kind = match self.completed {
                        1 => OwnerKind::QueueDriver,
                        2 => OwnerKind::QueueDevice,
                        _ => unreachable!(),
                    };
                    let owner = take_after_reset(self.generation, self.kind);
                    // SAFETY: a whole-device reset was acknowledged before
                    // the owner was made available by `take_after_reset`.
                    self.pending = Some(unsafe { owner.dma.begin_unmap_invalidate() });
                }
                Err(pending) => {
                    let failed = pending.failure().is_some();
                    self.pending = Some(pending);
                    if failed {
                        return ClosureProgress::Pending(self);
                    }
                }
            }
        }
    }
}

#[must_use = "closure receipt must be consumed to publish portal quiescence"]
pub struct ClosureReceipt {
    generation: u64,
    completed_pages: usize,
}

impl ClosureReceipt {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn completed_pages(&self) -> usize {
        self.completed_pages
    }
}

#[must_use = "DMA closure must complete or retain its IOTLB tombstone"]
pub enum ClosureProgress {
    Complete(ClosureReceipt),
    Pending(IotlbTombstone),
}

pub fn begin_closure(authority: DmaClosureAuthority, inject_one_pending: bool) -> ClosureProgress {
    let generation = authority.generation;
    assert_eq!(retained_pages(generation), OWNER_COUNT);
    let owner = take_after_reset(generation, OwnerKind::Request);
    // SAFETY: `take_after_reset` only yields an owner after whole-device reset
    // acknowledgement and queue retirement.
    let mut pending = unsafe { owner.dma.begin_unmap_invalidate() };
    if inject_one_pending {
        pending.inject_one_pending_poll();
    }
    IotlbTombstone {
        generation,
        kind: OwnerKind::Request,
        pending: Some(pending),
        completed: 0,
    }
    .retry(if inject_one_pending { 1 } else { 1024 })
}
