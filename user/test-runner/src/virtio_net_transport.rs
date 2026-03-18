use core::mem::size_of;
use core::ptr;

pub(crate) const PAGE_SIZE: u64 = 4096;
pub(crate) const QUEUE_SIZE: usize = 4;
pub(crate) const QUEUE_PAIR_COUNT: usize = 2;
pub(crate) const BUFFER_STRIDE: u64 = 256;
pub(crate) const REGISTER_VMO_BYTES: u64 = PAGE_SIZE;

pub(crate) const QUEUE_PAIR_BYTES: u64 = 4 * PAGE_SIZE;
pub(crate) const QUEUE_VMO_BYTES: u64 = QUEUE_PAIR_COUNT as u64 * QUEUE_PAIR_BYTES;

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
pub(crate) const PCI_VENDOR_ID_AXLE: u16 = 0x4158;
pub(crate) const PCI_DEVICE_ID_NET: u16 = 0x0001;
pub(crate) const PCI_CLASS_NETWORK: u8 = 0x02;
pub(crate) const PCI_SUBCLASS_ETHERNET: u8 = 0x00;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct PciConfigPage {
    pub(crate) vendor_id: u16,
    pub(crate) device_id: u16,
    pub(crate) command: u16,
    pub(crate) status: u16,
    pub(crate) revision_id: u8,
    pub(crate) prog_if: u8,
    pub(crate) subclass: u8,
    pub(crate) class_code: u8,
    pub(crate) bar0_paddr: u64,
    pub(crate) bar0_size: u32,
    pub(crate) device_features: u32,
    pub(crate) queue_pairs: u32,
    pub(crate) queue_size: u32,
    pub(crate) reserved0: u32,
    pub(crate) reserved1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct VirtioMmioHeader {
    pub(crate) magic: u32,
    pub(crate) version: u32,
    pub(crate) device_id: u32,
    pub(crate) vendor_id: u32,
    pub(crate) device_features: u32,
    pub(crate) driver_features: u32,
    pub(crate) status: u32,
    pub(crate) queue_pairs: u32,
    pub(crate) queue_size: u32,
    pub(crate) queue_pair_stride: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct VirtioQueueRegs {
    pub(crate) tx_queue_ready: u32,
    pub(crate) rx_queue_ready: u32,
    pub(crate) notify_value: u32,
    pub(crate) interrupt_status: u32,
    pub(crate) tx_notify_count: u32,
    pub(crate) rx_complete_count: u32,
    pub(crate) reserved0: u32,
    pub(crate) reserved1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct VirtioMmioRegs {
    pub(crate) header: VirtioMmioHeader,
    pub(crate) queues: [VirtioQueueRegs; QUEUE_PAIR_COUNT],
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

pub(crate) const fn tx_queue_offset(pair: usize) -> u64 {
    pair as u64 * QUEUE_PAIR_BYTES
}

pub(crate) const fn tx_buffer_offset(pair: usize) -> u64 {
    tx_queue_offset(pair) + PAGE_SIZE
}

pub(crate) const fn rx_queue_offset(pair: usize) -> u64 {
    tx_queue_offset(pair) + 2 * PAGE_SIZE
}

pub(crate) const fn rx_buffer_offset(pair: usize) -> u64 {
    tx_queue_offset(pair) + 3 * PAGE_SIZE
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
            header: VirtioMmioHeader {
                magic: MMIO_MAGIC,
                version: MMIO_VERSION,
                device_id: MMIO_DEVICE_ID_NET,
                vendor_id: MMIO_VENDOR_ID_AXLE,
                device_features: MMIO_FEATURE_CSUM,
                queue_pairs: QUEUE_PAIR_COUNT as u32,
                queue_size: QUEUE_SIZE as u32,
                queue_pair_stride: QUEUE_PAIR_BYTES as u32,
                ..VirtioMmioHeader::default()
            },
            ..VirtioMmioRegs::default()
        },
    );
}

pub(crate) fn init_pci_config(mapped_base: u64, bar0_paddr: u64) {
    write_pci_config(
        mapped_base,
        PciConfigPage {
            vendor_id: PCI_VENDOR_ID_AXLE,
            device_id: PCI_DEVICE_ID_NET,
            class_code: PCI_CLASS_NETWORK,
            subclass: PCI_SUBCLASS_ETHERNET,
            bar0_paddr,
            bar0_size: REGISTER_VMO_BYTES as u32,
            device_features: MMIO_FEATURE_CSUM,
            queue_pairs: QUEUE_PAIR_COUNT as u32,
            queue_size: QUEUE_SIZE as u32,
            ..PciConfigPage::default()
        },
    );
}

pub(crate) fn read_pci_config(mapped_base: u64) -> PciConfigPage {
    // SAFETY: the bootstrap config page is one mapped PCI-shaped control page
    // owned by the synthetic device side and read as one packed record.
    unsafe { ptr::read_volatile(mapped_base as *const PciConfigPage) }
}

pub(crate) fn write_pci_config(mapped_base: u64, config: PciConfigPage) {
    // SAFETY: bootstrap setup owns the synthetic PCI config page and writes it
    // as one packed control-plane record before driver discovery.
    unsafe { ptr::write_volatile(mapped_base as *mut PciConfigPage, config) }
}

pub(crate) fn read_header(mapped_base: u64) -> VirtioMmioHeader {
    // SAFETY: the register header lives at the front of one mapped MMIO-style
    // page and is read as a single packed control-plane record.
    unsafe { ptr::read_volatile(mapped_base as *const VirtioMmioHeader) }
}

pub(crate) fn write_header(mapped_base: u64, header: VirtioMmioHeader) {
    // SAFETY: the driver side owns the global transport header and writes it as
    // one packed control-plane record before queue handoff.
    unsafe { ptr::write_volatile(mapped_base as *mut VirtioMmioHeader, header) }
}

pub(crate) fn read_regs(mapped_base: u64) -> VirtioMmioRegs {
    // SAFETY: bootstrap diagnostics may snapshot the full register page after
    // the transport round has completed and queue-local writers are quiescent.
    unsafe { ptr::read_volatile(mapped_base as *const VirtioMmioRegs) }
}

pub(crate) fn write_regs(mapped_base: u64, regs: VirtioMmioRegs) {
    // SAFETY: bootstrap setup owns the full register page before workers are
    // launched and may initialize it as one packed record.
    unsafe { ptr::write_volatile(mapped_base as *mut VirtioMmioRegs, regs) }
}

fn queue_regs_ptr(mapped_base: u64, pair: usize) -> *mut VirtioQueueRegs {
    ((mapped_base + size_of::<VirtioMmioHeader>() as u64) as *mut VirtioQueueRegs)
        .wrapping_add(pair)
}

pub(crate) fn read_queue_regs(mapped_base: u64, pair: usize) -> VirtioQueueRegs {
    // SAFETY: each queue-pair register block is one fixed record inside the
    // mapped MMIO-style page and is read independently from other pairs.
    unsafe { ptr::read_volatile(queue_regs_ptr(mapped_base, pair)) }
}

pub(crate) fn write_queue_regs(mapped_base: u64, pair: usize, regs: VirtioQueueRegs) {
    // SAFETY: one queue-pair register block has one writer at a time:
    // bootstrap driver setup before handoff, then the owning worker for
    // notify/completion accounting.
    unsafe { ptr::write_volatile(queue_regs_ptr(mapped_base, pair), regs) }
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
