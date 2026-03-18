use core::mem::size_of;
use core::ptr;

pub(crate) const PAGE_SIZE: u64 = 4096;
pub(crate) const QUEUE_SIZE: usize = 4;
pub(crate) const BUFFER_STRIDE: u64 = 256;

pub(crate) const REGS_OFFSET: u64 = 0;
pub(crate) const TX_QUEUE_OFFSET: u64 = PAGE_SIZE;
pub(crate) const TX_BUFFER_OFFSET: u64 = 2 * PAGE_SIZE;
pub(crate) const RX_QUEUE_OFFSET: u64 = 3 * PAGE_SIZE;
pub(crate) const RX_BUFFER_OFFSET: u64 = 4 * PAGE_SIZE;
pub(crate) const QUEUE_VMO_BYTES: u64 = 5 * PAGE_SIZE;

pub(crate) const MMIO_MAGIC: u32 = 0x7472_6976; // "virt" little-endian
pub(crate) const MMIO_VERSION: u32 = 2;
pub(crate) const MMIO_DEVICE_ID_NET: u32 = 1;
pub(crate) const MMIO_VENDOR_ID_AXLE: u32 = 0x4158_4c45; // "AXLE"
pub(crate) const MMIO_FEATURE_CSUM: u32 = 1 << 0;

pub(crate) const MMIO_STATUS_ACKNOWLEDGE: u32 = 1 << 0;
pub(crate) const MMIO_STATUS_DRIVER: u32 = 1 << 1;
pub(crate) const MMIO_STATUS_FEATURES_OK: u32 = 1 << 3;
pub(crate) const MMIO_STATUS_DRIVER_OK: u32 = 1 << 4;

pub(crate) const MMIO_NOTIFY_TX: u32 = 1;
pub(crate) const MMIO_NOTIFY_RX: u32 = 2;
pub(crate) const MMIO_INTERRUPT_RX_COMPLETE: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct VirtioMmioRegs {
    pub(crate) magic: u32,
    pub(crate) version: u32,
    pub(crate) device_id: u32,
    pub(crate) vendor_id: u32,
    pub(crate) device_features: u32,
    pub(crate) driver_features: u32,
    pub(crate) status: u32,
    pub(crate) tx_queue_size: u32,
    pub(crate) rx_queue_size: u32,
    pub(crate) tx_queue_ready: u32,
    pub(crate) rx_queue_ready: u32,
    pub(crate) queue_notify: u32,
    pub(crate) interrupt_status: u32,
    pub(crate) tx_notify_count: u32,
    pub(crate) rx_complete_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct VirtqDesc {
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) flags: u16,
    pub(crate) next: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VirtqAvail {
    pub(crate) flags: u16,
    pub(crate) idx: u16,
    pub(crate) ring: [u16; QUEUE_SIZE],
    pub(crate) used_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VirtqUsedElem {
    pub(crate) id: u32,
    pub(crate) len: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VirtqUsed {
    pub(crate) flags: u16,
    pub(crate) idx: u16,
    pub(crate) ring: [VirtqUsedElem; QUEUE_SIZE],
    pub(crate) avail_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VirtioNetHdr {
    pub(crate) flags: u8,
    pub(crate) gso_type: u8,
    pub(crate) hdr_len: u16,
    pub(crate) gso_size: u16,
    pub(crate) csum_start: u16,
    pub(crate) csum_offset: u16,
}

pub(crate) const fn frame_len(payload_len: usize) -> usize {
    size_of::<VirtioNetHdr>() + payload_len
}

pub(crate) const fn empty_avail() -> VirtqAvail {
    VirtqAvail {
        flags: 0,
        idx: 0,
        ring: [0; QUEUE_SIZE],
        used_event: 0,
    }
}

pub(crate) const fn empty_used() -> VirtqUsed {
    VirtqUsed {
        flags: 0,
        idx: 0,
        ring: [VirtqUsedElem { id: 0, len: 0 }; QUEUE_SIZE],
        avail_event: 0,
    }
}

pub(crate) fn init_regs(mapped_base: u64) {
    write_regs(
        mapped_base,
        VirtioMmioRegs {
            magic: MMIO_MAGIC,
            version: MMIO_VERSION,
            device_id: MMIO_DEVICE_ID_NET,
            vendor_id: MMIO_VENDOR_ID_AXLE,
            device_features: MMIO_FEATURE_CSUM,
            tx_queue_size: QUEUE_SIZE as u32,
            rx_queue_size: QUEUE_SIZE as u32,
            ..VirtioMmioRegs::default()
        },
    );
}

pub(crate) fn read_regs(mapped_base: u64) -> VirtioMmioRegs {
    // SAFETY: the register page is inside the mapped contiguous VMO and this
    // transport slice treats it as one single packed control block.
    unsafe { ptr::read_volatile((mapped_base + REGS_OFFSET) as *const VirtioMmioRegs) }
}

pub(crate) fn write_regs(mapped_base: u64, regs: VirtioMmioRegs) {
    // SAFETY: the register page is inside the mapped contiguous VMO and this
    // transport slice writes one whole control block during clearly separated
    // control-plane phases.
    unsafe { ptr::write_volatile((mapped_base + REGS_OFFSET) as *mut VirtioMmioRegs, regs) }
}

pub(crate) const fn buffer_offset(base_offset: u64, slot: usize) -> u64 {
    base_offset + (slot as u64 * BUFFER_STRIDE)
}

pub(crate) const fn buffer_paddr(queue_paddr: u64, base_offset: u64, slot: usize) -> u64 {
    queue_paddr + buffer_offset(base_offset, slot)
}

fn queue_desc_ptr(mapped_base: u64, queue_offset: u64, desc_index: usize) -> *mut VirtqDesc {
    ((mapped_base + queue_offset) as *mut VirtqDesc).wrapping_add(desc_index)
}

fn queue_avail_ptr(mapped_base: u64, queue_offset: u64) -> *mut VirtqAvail {
    (mapped_base + queue_offset + 64) as *mut VirtqAvail
}

fn queue_used_ptr(mapped_base: u64, queue_offset: u64) -> *mut VirtqUsed {
    (mapped_base + queue_offset + 128) as *mut VirtqUsed
}

pub(crate) fn write_desc(mapped_base: u64, queue_offset: u64, desc_index: usize, desc: VirtqDesc) {
    // SAFETY: the descriptor table lives in mapped shared memory and each slot
    // is written by exactly one owner before publication.
    unsafe { ptr::write_volatile(queue_desc_ptr(mapped_base, queue_offset, desc_index), desc) }
}

pub(crate) fn read_desc(mapped_base: u64, queue_offset: u64, desc_index: usize) -> VirtqDesc {
    // SAFETY: the descriptor table lives in mapped shared memory and ownership
    // is transferred only after the publishing fence/kick.
    unsafe { ptr::read_volatile(queue_desc_ptr(mapped_base, queue_offset, desc_index)) }
}

pub(crate) fn write_avail(mapped_base: u64, queue_offset: u64, avail: VirtqAvail) {
    // SAFETY: the avail ring header lives in mapped shared memory and is
    // single-writer from the driver side.
    unsafe { ptr::write_volatile(queue_avail_ptr(mapped_base, queue_offset), avail) }
}

pub(crate) fn read_avail(mapped_base: u64, queue_offset: u64) -> VirtqAvail {
    // SAFETY: the avail ring header lives in mapped shared memory and is read
    // by the device side only after the kick boundary.
    unsafe { ptr::read_volatile(queue_avail_ptr(mapped_base, queue_offset)) }
}

pub(crate) fn write_used(mapped_base: u64, queue_offset: u64, used: VirtqUsed) {
    // SAFETY: the used ring header lives in mapped shared memory and is
    // single-writer from the device side.
    unsafe { ptr::write_volatile(queue_used_ptr(mapped_base, queue_offset), used) }
}

pub(crate) fn read_used(mapped_base: u64, queue_offset: u64) -> VirtqUsed {
    // SAFETY: the used ring header lives in mapped shared memory and is read
    // by the driver side only after completion publication.
    unsafe { ptr::read_volatile(queue_used_ptr(mapped_base, queue_offset)) }
}
