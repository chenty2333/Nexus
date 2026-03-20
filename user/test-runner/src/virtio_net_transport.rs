use core::ptr;

pub(crate) use axle_virtio_transport::{
    BUFFER_STRIDE, CONFIG_VMO_BYTES, MMIO_DEVICE_ID_NET, MMIO_FEATURE_CSUM,
    MMIO_INTERRUPT_RX_COMPLETE, MMIO_MAGIC, MMIO_STATUS_ACKNOWLEDGE, MMIO_STATUS_DRIVER,
    MMIO_STATUS_DRIVER_OK, MMIO_STATUS_FEATURES_OK, MMIO_VENDOR_ID_AXLE, MMIO_VERSION, PAGE_SIZE,
    PCI_CLASS_NETWORK, PCI_DEVICE_ID_NET, PCI_SUBCLASS_ETHERNET, PCI_VENDOR_ID_AXLE,
    QUEUE_PAIR_COUNT, QUEUE_SIZE, QUEUE_VMO_BYTES, REGISTER_VMO_BYTES, VirtioMmioHeader,
    VirtioNetHdr, VirtioPciDiscovery, VirtioPciRegs, VirtioQueueRegs, VirtqAvail, VirtqDesc,
    VirtqUsed, VirtqUsedElem, buffer_offset, buffer_paddr, empty_avail, empty_used,
    frame_header_bytes, frame_len, map_dma_addr, rx_avail_paddr, rx_buffer_offset, rx_desc_paddr,
    rx_queue_index, rx_queue_notify_value, rx_queue_offset, rx_used_paddr, tx_avail_paddr,
    tx_buffer_offset, tx_desc_paddr, tx_queue_index, tx_queue_notify_value, tx_queue_offset,
    tx_used_paddr,
};

pub(crate) fn discover_pci_transport(mapped_base: u64) -> Option<VirtioPciDiscovery> {
    // SAFETY: the exported config alias is a fixed read-only byte span.
    let bytes =
        unsafe { core::slice::from_raw_parts(mapped_base as *const u8, CONFIG_VMO_BYTES as usize) };
    axle_virtio_transport::discover_pci_transport(bytes)
}

pub(crate) fn init_regs(mapped_base: u64) {
    write_regs(mapped_base, axle_virtio_transport::initial_regs());
}

pub(crate) fn driver_select_queue(mapped_base: u64, queue_index: usize) {
    let mut regs = read_regs(mapped_base);
    axle_virtio_transport::driver_select_queue(&mut regs, queue_index);
    write_regs(mapped_base, regs);
}

pub(crate) fn driver_program_queue(
    mapped_base: u64,
    queue_index: usize,
    desc_addr: u64,
    avail_addr: u64,
    used_addr: u64,
) {
    let mut regs = read_regs(mapped_base);
    axle_virtio_transport::driver_program_queue(
        &mut regs,
        queue_index,
        desc_addr,
        avail_addr,
        used_addr,
    );
    write_regs(mapped_base, regs);
}

pub(crate) fn read_header(mapped_base: u64) -> VirtioMmioHeader {
    axle_virtio_transport::read_header(&read_regs(mapped_base))
}

pub(crate) fn write_header(mapped_base: u64, header: VirtioMmioHeader) {
    let mut regs = read_regs(mapped_base);
    axle_virtio_transport::write_header(&mut regs, header);
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

pub(crate) fn write_queue_regs(mapped_base: u64, pair: usize, queue_regs: VirtioQueueRegs) {
    let tx_index = tx_queue_index(pair);
    let rx_index = rx_queue_index(pair);

    let mut tx = read_queue_state(mapped_base, tx_index);
    tx.ready = queue_regs.tx_queue_ready;
    tx.notify_value = queue_regs.notify_value;
    tx.notify_count = queue_regs.tx_notify_count;
    tx.desc_addr = queue_regs.tx_desc_addr;
    tx.avail_addr = queue_regs.tx_avail_addr;
    tx.used_addr = queue_regs.tx_used_addr;
    write_queue_state(mapped_base, tx_index, tx);

    let mut rx = read_queue_state(mapped_base, rx_index);
    rx.ready = queue_regs.rx_queue_ready;
    rx.notify_value = queue_regs.notify_value;
    rx.complete_count = queue_regs.rx_complete_count;
    rx.interrupt_status = queue_regs.interrupt_status;
    rx.desc_addr = queue_regs.rx_desc_addr;
    rx.avail_addr = queue_regs.rx_avail_addr;
    rx.used_addr = queue_regs.rx_used_addr;
    write_queue_state(mapped_base, rx_index, rx);

    refresh_selected_queue_common(mapped_base, tx_index, tx);
    refresh_selected_queue_common(mapped_base, rx_index, rx);
}

fn read_regs(mapped_base: u64) -> VirtioPciRegs {
    // SAFETY: the BAR0 control window contains one packed register image.
    unsafe { ptr::read_volatile(mapped_base as *const VirtioPciRegs) }
}

fn write_regs(mapped_base: u64, regs: VirtioPciRegs) {
    // SAFETY: bootstrap setup and queue owners write the packed BAR0 image at explicit handoff points.
    unsafe { ptr::write_volatile(mapped_base as *mut VirtioPciRegs, regs) }
}

fn read_queue_state(
    mapped_base: u64,
    queue_index: usize,
) -> axle_virtio_transport::VirtioQueueState {
    let regs_ptr = mapped_base as *const VirtioPciRegs;
    // SAFETY: the BAR0 register image is one valid mapped `VirtioPciRegs`, and this reads exactly
    // one queue-state slot with volatile semantics.
    unsafe { ptr::read_volatile(ptr::addr_of!((*regs_ptr).queues[queue_index])) }
}

fn write_queue_state(
    mapped_base: u64,
    queue_index: usize,
    queue: axle_virtio_transport::VirtioQueueState,
) {
    let regs_ptr = mapped_base as *mut VirtioPciRegs;
    // SAFETY: the BAR0 register image is one valid mapped `VirtioPciRegs`, and each queue-state
    // slot has one writer per queue pair during the smoke transport.
    unsafe { ptr::write_volatile(ptr::addr_of_mut!((*regs_ptr).queues[queue_index]), queue) }
}

fn refresh_selected_queue_common(
    mapped_base: u64,
    queue_index: usize,
    queue: axle_virtio_transport::VirtioQueueState,
) {
    let regs_ptr = mapped_base as *mut VirtioPciRegs;
    // SAFETY: the common-config header lives in the same mapped BAR0 register image; only the
    // selected-queue mirror fields are updated, and only when the current selection matches this
    // queue slot.
    unsafe {
        let selected = ptr::read_volatile(ptr::addr_of!((*regs_ptr).common.queue_select)) as usize;
        if selected != queue_index {
            return;
        }
        ptr::write_volatile(ptr::addr_of_mut!((*regs_ptr).common.queue_size), queue.size);
        ptr::write_volatile(
            ptr::addr_of_mut!((*regs_ptr).common.queue_enable),
            queue.ready,
        );
        ptr::write_volatile(
            ptr::addr_of_mut!((*regs_ptr).common.queue_notify_off),
            queue.notify_off,
        );
        ptr::write_volatile(
            ptr::addr_of_mut!((*regs_ptr).common.queue_desc_addr),
            queue.desc_addr,
        );
        ptr::write_volatile(
            ptr::addr_of_mut!((*regs_ptr).common.queue_avail_addr),
            queue.avail_addr,
        );
        ptr::write_volatile(
            ptr::addr_of_mut!((*regs_ptr).common.queue_used_addr),
            queue.used_addr,
        );
    }
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
    // SAFETY: the descriptor table lives in mapped shared memory and each slot is written by one owner before publication.
    unsafe { ptr::write_volatile(queue_desc_ptr(mapped_base, queue_offset, desc_index), desc) }
}

pub(crate) fn read_desc(mapped_base: u64, queue_offset: u64, desc_index: usize) -> VirtqDesc {
    // SAFETY: the descriptor table lives in mapped shared memory and ownership transfers only after publication.
    unsafe { ptr::read_volatile(queue_desc_ptr(mapped_base, queue_offset, desc_index)) }
}

pub(crate) fn read_desc_at(desc_base: u64, desc_index: usize) -> VirtqDesc {
    // SAFETY: the descriptor table base is one mapped shared-memory address and readers only access published slots.
    unsafe { ptr::read_volatile((desc_base as *const VirtqDesc).add(desc_index)) }
}

pub(crate) fn write_avail(mapped_base: u64, queue_offset: u64, avail: VirtqAvail) {
    // SAFETY: the avail ring header lives in mapped shared memory and is single-writer from the driver side.
    unsafe { ptr::write_volatile(queue_avail_ptr(mapped_base, queue_offset), avail) }
}

pub(crate) fn read_avail(mapped_base: u64, queue_offset: u64) -> VirtqAvail {
    // SAFETY: the avail ring header lives in mapped shared memory and is read after the notify boundary.
    unsafe { ptr::read_volatile(queue_avail_ptr(mapped_base, queue_offset)) }
}

pub(crate) fn read_avail_at(avail_base: u64) -> VirtqAvail {
    // SAFETY: the avail ring header base is a mapped shared-memory address and readers only use it after publish.
    unsafe { ptr::read_volatile(avail_base as *const VirtqAvail) }
}

pub(crate) fn write_used(mapped_base: u64, queue_offset: u64, used: VirtqUsed) {
    // SAFETY: the used ring header lives in mapped shared memory and is single-writer from the device side.
    unsafe { ptr::write_volatile(queue_used_ptr(mapped_base, queue_offset), used) }
}

pub(crate) fn read_used(mapped_base: u64, queue_offset: u64) -> VirtqUsed {
    // SAFETY: the used ring header lives in mapped shared memory and is read after completion publication.
    unsafe { ptr::read_volatile(queue_used_ptr(mapped_base, queue_offset)) }
}

pub(crate) fn write_used_at(used_base: u64, used: VirtqUsed) {
    // SAFETY: the used ring header base is a mapped shared-memory address and the device side is the only writer.
    unsafe { ptr::write_volatile(used_base as *mut VirtqUsed, used) }
}

pub(crate) fn read_used_at(used_base: u64) -> VirtqUsed {
    // SAFETY: the used ring header base is a mapped shared-memory address and the driver reads it after completion publication.
    unsafe { ptr::read_volatile(used_base as *const VirtqUsed) }
}
