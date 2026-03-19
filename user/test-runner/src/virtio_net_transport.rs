use core::mem::size_of;
use core::ptr;

pub(crate) const PAGE_SIZE: u64 = 4096;
pub(crate) const QUEUE_SIZE: usize = 4;
pub(crate) const QUEUE_PAIR_COUNT: usize = 2;
pub(crate) const TOTAL_QUEUE_COUNT: usize = QUEUE_PAIR_COUNT * 2;
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
    pub(crate) tx_desc_addr: u64,
    pub(crate) tx_avail_addr: u64,
    pub(crate) tx_used_addr: u64,
    pub(crate) rx_desc_addr: u64,
    pub(crate) rx_avail_addr: u64,
    pub(crate) rx_used_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioPciCommonCfg {
    pub(crate) magic: u32,
    pub(crate) version: u32,
    pub(crate) device_id: u32,
    pub(crate) vendor_id: u32,
    pub(crate) device_feature_select: u32,
    pub(crate) device_features: u32,
    pub(crate) driver_feature_select: u32,
    pub(crate) driver_features: u32,
    pub(crate) device_status: u32,
    pub(crate) num_queues: u32,
    pub(crate) queue_pairs: u32,
    pub(crate) queue_select: u32,
    pub(crate) queue_size: u32,
    pub(crate) queue_enable: u32,
    pub(crate) queue_notify_off: u32,
    pub(crate) queue_desc_addr: u64,
    pub(crate) queue_avail_addr: u64,
    pub(crate) queue_used_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioQueueState {
    pub(crate) ready: u32,
    pub(crate) notify_value: u32,
    pub(crate) notify_count: u32,
    pub(crate) complete_count: u32,
    pub(crate) interrupt_status: u32,
    pub(crate) size: u32,
    pub(crate) notify_off: u32,
    pub(crate) desc_addr: u64,
    pub(crate) avail_addr: u64,
    pub(crate) used_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioPciRegs {
    pub(crate) common: VirtioPciCommonCfg,
    pub(crate) queues: [VirtioQueueState; TOTAL_QUEUE_COUNT],
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

pub(crate) const fn tx_queue_index(pair: usize) -> usize {
    pair * 2
}

pub(crate) const fn rx_queue_index(pair: usize) -> usize {
    pair * 2 + 1
}

pub(crate) const fn tx_queue_notify_value(pair: usize) -> u32 {
    tx_queue_index(pair) as u32
}

pub(crate) const fn rx_queue_notify_value(pair: usize) -> u32 {
    rx_queue_index(pair) as u32
}

pub(crate) const fn tx_desc_paddr(queue_paddr: u64, pair: usize) -> u64 {
    queue_paddr + tx_queue_offset(pair)
}

pub(crate) const fn tx_avail_paddr(queue_paddr: u64, pair: usize) -> u64 {
    tx_desc_paddr(queue_paddr, pair) + 64
}

pub(crate) const fn tx_used_paddr(queue_paddr: u64, pair: usize) -> u64 {
    tx_desc_paddr(queue_paddr, pair) + 128
}

pub(crate) const fn rx_desc_paddr(queue_paddr: u64, pair: usize) -> u64 {
    queue_paddr + rx_queue_offset(pair)
}

pub(crate) const fn rx_avail_paddr(queue_paddr: u64, pair: usize) -> u64 {
    rx_desc_paddr(queue_paddr, pair) + 64
}

pub(crate) const fn rx_used_paddr(queue_paddr: u64, pair: usize) -> u64 {
    rx_desc_paddr(queue_paddr, pair) + 128
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
    let mut regs = VirtioPciRegs {
        common: VirtioPciCommonCfg {
            magic: MMIO_MAGIC,
            version: MMIO_VERSION,
            device_id: MMIO_DEVICE_ID_NET,
            vendor_id: MMIO_VENDOR_ID_AXLE,
            device_features: MMIO_FEATURE_CSUM,
            num_queues: TOTAL_QUEUE_COUNT as u32,
            queue_pairs: QUEUE_PAIR_COUNT as u32,
            ..VirtioPciCommonCfg::default()
        },
        ..VirtioPciRegs::default()
    };
    for queue in 0..TOTAL_QUEUE_COUNT {
        regs.queues[queue].size = QUEUE_SIZE as u32;
        regs.queues[queue].notify_off = queue as u32;
    }
    refresh_selected_queue(&mut regs, 0);
    write_regs(mapped_base, regs);
}

pub(crate) fn driver_select_queue(mapped_base: u64, queue_index: usize) {
    let mut regs = read_regs(mapped_base);
    refresh_selected_queue(&mut regs, queue_index);
    write_regs(mapped_base, regs);
}

pub(crate) fn driver_program_queue(
    mapped_base: u64,
    queue_index: usize,
    desc_addr: u64,
    avail_addr: u64,
    used_addr: u64,
) {
    let mut queue = read_queue_state(mapped_base, queue_index);
    queue.ready = 1;
    queue.desc_addr = desc_addr;
    queue.avail_addr = avail_addr;
    queue.used_addr = used_addr;
    write_queue_state(mapped_base, queue_index, queue);

    let mut regs = read_regs(mapped_base);
    refresh_selected_queue(&mut regs, queue_index);
    write_regs(mapped_base, regs);
}

fn refresh_selected_queue(regs: &mut VirtioPciRegs, queue_index: usize) {
    let queue = regs.queues[queue_index];
    regs.common.queue_select = queue_index as u32;
    regs.common.queue_size = queue.size;
    regs.common.queue_enable = queue.ready;
    regs.common.queue_notify_off = queue.notify_off;
    regs.common.queue_desc_addr = queue.desc_addr;
    regs.common.queue_avail_addr = queue.avail_addr;
    regs.common.queue_used_addr = queue.used_addr;
}

fn read_regs(mapped_base: u64) -> VirtioPciRegs {
    // SAFETY: the BAR0 control window is one packed control-plane record and is
    // read only at explicit bootstrap synchronization points.
    unsafe { ptr::read_volatile(mapped_base as *const VirtioPciRegs) }
}

pub(crate) fn read_header(mapped_base: u64) -> VirtioMmioHeader {
    let regs = read_regs(mapped_base);
    VirtioMmioHeader {
        magic: regs.common.magic,
        version: regs.common.version,
        device_id: regs.common.device_id,
        vendor_id: regs.common.vendor_id,
        device_features: regs.common.device_features,
        driver_features: regs.common.driver_features,
        status: regs.common.device_status,
        queue_pairs: regs.common.queue_pairs,
        queue_size: QUEUE_SIZE as u32,
        queue_pair_stride: QUEUE_PAIR_BYTES as u32,
    }
}

pub(crate) fn write_header(mapped_base: u64, header: VirtioMmioHeader) {
    let mut regs = read_regs(mapped_base);
    regs.common.driver_feature_select = 0;
    regs.common.driver_features = header.driver_features;
    regs.common.device_status = header.status;
    write_regs(mapped_base, regs);
}

pub(crate) fn read_queue_regs(mapped_base: u64, pair: usize) -> VirtioQueueRegs {
    let tx = read_queue_state(mapped_base, tx_queue_index(pair));
    let rx = read_queue_state(mapped_base, rx_queue_index(pair));
    VirtioQueueRegs {
        tx_queue_ready: tx.ready,
        rx_queue_ready: rx.ready,
        notify_value: if rx.complete_count != 0 {
            rx.notify_value
        } else {
            tx.notify_value
        },
        interrupt_status: rx.interrupt_status,
        tx_notify_count: tx.notify_count,
        rx_complete_count: rx.complete_count,
        tx_desc_addr: tx.desc_addr,
        tx_avail_addr: tx.avail_addr,
        tx_used_addr: tx.used_addr,
        rx_desc_addr: rx.desc_addr,
        rx_avail_addr: rx.avail_addr,
        rx_used_addr: rx.used_addr,
    }
}

pub(crate) fn write_queue_regs(mapped_base: u64, pair: usize, regs: VirtioQueueRegs) {
    let tx_index = tx_queue_index(pair);
    let rx_index = rx_queue_index(pair);

    let mut tx = read_queue_state(mapped_base, tx_index);
    tx.ready = regs.tx_queue_ready;
    tx.notify_value = regs.notify_value;
    tx.notify_count = regs.tx_notify_count;
    tx.desc_addr = regs.tx_desc_addr;
    tx.avail_addr = regs.tx_avail_addr;
    tx.used_addr = regs.tx_used_addr;
    write_queue_state(mapped_base, tx_index, tx);

    let mut rx = read_queue_state(mapped_base, rx_index);
    rx.ready = regs.rx_queue_ready;
    rx.notify_value = regs.notify_value;
    rx.complete_count = regs.rx_complete_count;
    rx.interrupt_status = regs.interrupt_status;
    rx.desc_addr = regs.rx_desc_addr;
    rx.avail_addr = regs.rx_avail_addr;
    rx.used_addr = regs.rx_used_addr;
    write_queue_state(mapped_base, rx_index, rx);

    let mut full = read_regs(mapped_base);
    let selected = full.common.queue_select as usize;
    if selected == tx_index || selected == rx_index {
        refresh_selected_queue(&mut full, selected);
        write_regs(mapped_base, full);
    }
}

fn write_regs(mapped_base: u64, regs: VirtioPciRegs) {
    // SAFETY: bootstrap setup and queue owners write one packed BAR0 register
    // image only at explicit handoff points.
    unsafe { ptr::write_volatile(mapped_base as *mut VirtioPciRegs, regs) }
}

fn queue_state_ptr(mapped_base: u64, queue_index: usize) -> *mut VirtioQueueState {
    let regs = mapped_base as *mut VirtioPciRegs;
    // SAFETY: pointer arithmetic stays within the fixed BAR0 register window.
    unsafe {
        ptr::addr_of_mut!((*regs).queues)
            .cast::<VirtioQueueState>()
            .add(queue_index)
    }
}

fn read_queue_state(mapped_base: u64, queue_index: usize) -> VirtioQueueState {
    // SAFETY: each queue-state record lives inside the mapped BAR0 window and
    // is read independently from other queues.
    unsafe {
        ptr::read_volatile(queue_state_ptr(mapped_base, queue_index) as *const VirtioQueueState)
    }
}

fn write_queue_state(mapped_base: u64, queue_index: usize, state: VirtioQueueState) {
    // SAFETY: one queue state has one owner at a time: bootstrap driver setup
    // before first handoff, then the owning worker for notify/completion.
    unsafe { ptr::write_volatile(queue_state_ptr(mapped_base, queue_index), state) }
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

pub(crate) fn read_desc_at(desc_base: u64, desc_index: usize) -> VirtqDesc {
    // SAFETY: the descriptor table base is one mapped shared-memory address,
    // and readers only access slots that the published ring points at.
    unsafe { ptr::read_volatile((desc_base as *const VirtqDesc).add(desc_index)) }
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

pub(crate) fn read_avail_at(avail_base: u64) -> VirtqAvail {
    // SAFETY: the avail ring header base is one mapped shared-memory address,
    // and the device side only reads it after the notify boundary.
    unsafe { ptr::read_volatile(avail_base as *const VirtqAvail) }
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

pub(crate) fn write_used_at(used_base: u64, used: VirtqUsed) {
    // SAFETY: the used ring header base is one mapped shared-memory address,
    // and the device side is the only writer for one queue at a time.
    unsafe { ptr::write_volatile(used_base as *mut VirtqUsed, used) }
}

pub(crate) fn read_used_at(used_base: u64) -> VirtqUsed {
    // SAFETY: the used ring header base is one mapped shared-memory address,
    // and the driver reads it only after completion publication.
    unsafe { ptr::read_volatile(used_base as *const VirtqUsed) }
}

pub(crate) fn map_dma_addr(mapped_queue_base: u64, queue_paddr: u64, addr: u64) -> Option<u64> {
    if addr < queue_paddr {
        return None;
    }
    let offset = addr - queue_paddr;
    (offset < QUEUE_VMO_BYTES).then_some(mapped_queue_base + offset)
}
