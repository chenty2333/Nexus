//! Shared no_std transport/layout helpers for the current virtio-style bootstrap net path.

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

use core::mem::size_of;

/// The current page size assumed by the bootstrap transport layout.
pub const PAGE_SIZE: u64 = 4096;
/// Descriptor slots per TX/RX queue.
pub const QUEUE_SIZE: usize = 4;
/// Queue pairs exported by the current bootstrap device.
pub const QUEUE_PAIR_COUNT: usize = 2;
/// Total virtqueues across all queue pairs.
pub const TOTAL_QUEUE_COUNT: usize = QUEUE_PAIR_COUNT * 2;
/// Bytes reserved for one `virtio_net_hdr` + payload slot.
pub const BUFFER_STRIDE: u64 = 256;
/// Size of the synthetic PCI config window.
pub const CONFIG_VMO_BYTES: u64 = PAGE_SIZE;
/// Size of the BAR0/common-config register window.
pub const REGISTER_VMO_BYTES: u64 = PAGE_SIZE;
/// Bytes reserved per TX/RX queue pair inside the queue VMO.
pub const QUEUE_PAIR_BYTES: u64 = 4 * PAGE_SIZE;
/// Total bytes reserved for all queue pairs.
pub const QUEUE_VMO_BYTES: u64 = QUEUE_PAIR_COUNT as u64 * QUEUE_PAIR_BYTES;

/// Synthetic virtio MMIO magic.
pub const MMIO_MAGIC: u32 = 0x7472_6976;
/// Synthetic virtio MMIO version.
pub const MMIO_VERSION: u32 = 2;
/// Synthetic device id used by the bootstrap net device.
pub const MMIO_DEVICE_ID_NET: u32 = 1;
/// Synthetic vendor id used by the bootstrap net device.
pub const MMIO_VENDOR_ID_AXLE: u32 = 0x4158_4c45;
/// Narrow checksum feature bit currently negotiated by the bootstrap transport.
pub const MMIO_FEATURE_CSUM: u32 = 1 << 0;

/// Virtio device status bit: acknowledge.
pub const MMIO_STATUS_ACKNOWLEDGE: u32 = 1 << 0;
/// Virtio device status bit: driver present.
pub const MMIO_STATUS_DRIVER: u32 = 1 << 1;
/// Virtio device status bit: features accepted.
pub const MMIO_STATUS_FEATURES_OK: u32 = 1 << 3;
/// Virtio device status bit: queues enabled.
pub const MMIO_STATUS_DRIVER_OK: u32 = 1 << 2;

/// Notify value written for one TX queue.
pub const MMIO_NOTIFY_TX: u32 = 1;
/// Notify value written for one RX queue.
pub const MMIO_NOTIFY_RX: u32 = 2;
/// RX completion interrupt bit.
pub const MMIO_INTERRUPT_RX_COMPLETE: u32 = 1;

/// Synthetic PCI vendor id used by the bootstrap device export.
pub const PCI_VENDOR_ID_AXLE: u16 = 0x4158;
/// Synthetic PCI device id used by the bootstrap device export.
pub const PCI_DEVICE_ID_NET: u16 = 0x0001;
/// PCI class code for network controllers.
pub const PCI_CLASS_NETWORK: u8 = 0x02;
/// PCI subclass code for ethernet controllers.
pub const PCI_SUBCLASS_ETHERNET: u8 = 0x00;
/// Vendor-specific capability id.
pub const PCI_CAP_ID_VENDOR: u8 = 0x09;
/// Capability type: common config.
pub const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
/// Capability type: notify config.
pub const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
/// Capability type: ISR config.
pub const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
/// Capability type: device config.
pub const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
/// Conventional PCI capability pointer location.
pub const PCI_CAP_PTR_OFFSET: usize = 0x34;

/// One vendor capability region exported from the synthetic PCI config space.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioPciCapRegion {
    /// BAR index hosting this capability.
    pub bar: u8,
    /// Offset inside that BAR.
    pub offset: u32,
    /// Capability byte length.
    pub length: u32,
}

/// The capability-discovery result exported by the bootstrap PCI config window.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioPciDiscovery {
    /// Exported vendor id.
    pub vendor_id: u16,
    /// Exported device id.
    pub device_id: u16,
    /// Exported class code.
    pub class_code: u8,
    /// Exported subclass code.
    pub subclass: u8,
    /// Common config capability.
    pub common: VirtioPciCapRegion,
    /// Notify capability.
    pub notify: VirtioPciCapRegion,
    /// Notify-off multiplier.
    pub notify_multiplier: u32,
    /// ISR capability.
    pub isr: VirtioPciCapRegion,
    /// Device config capability.
    pub device: VirtioPciCapRegion,
}

/// Driver-visible MMIO header snapshot derived from the BAR0 register block.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioMmioHeader {
    pub magic: u32,
    pub version: u32,
    pub device_id: u32,
    pub vendor_id: u32,
    pub device_features: u32,
    pub driver_features: u32,
    pub status: u32,
    pub queue_pairs: u32,
    pub queue_size: u32,
    pub queue_pair_stride: u32,
}

/// One aggregated TX/RX queue-pair register snapshot.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioQueueRegs {
    pub tx_queue_ready: u32,
    pub rx_queue_ready: u32,
    pub notify_value: u32,
    pub interrupt_status: u32,
    pub tx_notify_count: u32,
    pub rx_complete_count: u32,
    pub tx_desc_addr: u64,
    pub tx_avail_addr: u64,
    pub tx_used_addr: u64,
    pub rx_desc_addr: u64,
    pub rx_avail_addr: u64,
    pub rx_used_addr: u64,
}

/// The common-config view stored in the synthetic BAR0 register page.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioPciCommonCfg {
    pub magic: u32,
    pub version: u32,
    pub device_id: u32,
    pub vendor_id: u32,
    pub device_feature_select: u32,
    pub device_features: u32,
    pub driver_feature_select: u32,
    pub driver_features: u32,
    pub device_status: u32,
    pub num_queues: u32,
    pub queue_pairs: u32,
    pub queue_select: u32,
    pub queue_size: u32,
    pub queue_enable: u32,
    pub queue_notify_off: u32,
    pub queue_desc_addr: u64,
    pub queue_avail_addr: u64,
    pub queue_used_addr: u64,
}

/// Runtime state for one queue.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioQueueState {
    pub ready: u32,
    pub notify_value: u32,
    pub notify_count: u32,
    pub complete_count: u32,
    pub interrupt_status: u32,
    pub size: u32,
    pub notify_off: u32,
    pub desc_addr: u64,
    pub avail_addr: u64,
    pub used_addr: u64,
}

/// Full BAR0 register image for the bootstrap transport.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioPciRegs {
    pub common: VirtioPciCommonCfg,
    pub queues: [VirtioQueueState; TOTAL_QUEUE_COUNT],
}

/// One split-ring descriptor.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// One split-ring avail header.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; QUEUE_SIZE],
    pub used_event: u16,
}

/// One used-ring element.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

/// One split-ring used header.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; QUEUE_SIZE],
    pub avail_event: u16,
}

/// Narrow virtio-net header shape used by the bootstrap dataplane.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

/// Discover transport capabilities from one read-only PCI config-space byte slice.
pub fn discover_pci_transport(config_bytes: &[u8]) -> Option<VirtioPciDiscovery> {
    let mut discovery = VirtioPciDiscovery {
        vendor_id: read_cfg_u16(config_bytes, 0x00)?,
        device_id: read_cfg_u16(config_bytes, 0x02)?,
        subclass: read_cfg_u8(config_bytes, 0x0a)?,
        class_code: read_cfg_u8(config_bytes, 0x0b)?,
        ..VirtioPciDiscovery::default()
    };

    let mut cap_off = usize::from(read_cfg_u8(config_bytes, PCI_CAP_PTR_OFFSET)?);
    while cap_off != 0 {
        if read_cfg_u8(config_bytes, cap_off)? != PCI_CAP_ID_VENDOR {
            cap_off = usize::from(read_cfg_u8(config_bytes, cap_off + 1)?);
            continue;
        }

        match read_cfg_u8(config_bytes, cap_off + 3)? {
            VIRTIO_PCI_CAP_COMMON_CFG => {
                discovery.common = read_cap_region(config_bytes, cap_off)?;
            }
            VIRTIO_PCI_CAP_NOTIFY_CFG => {
                discovery.notify = read_cap_region(config_bytes, cap_off)?;
                discovery.notify_multiplier = read_cfg_u32(config_bytes, cap_off + 16)?;
            }
            VIRTIO_PCI_CAP_ISR_CFG => {
                discovery.isr = read_cap_region(config_bytes, cap_off)?;
            }
            VIRTIO_PCI_CAP_DEVICE_CFG => {
                discovery.device = read_cap_region(config_bytes, cap_off)?;
            }
            _ => {}
        }
        cap_off = usize::from(read_cfg_u8(config_bytes, cap_off + 1)?);
    }

    (discovery.common.length != 0
        && discovery.notify.length != 0
        && discovery.isr.length != 0
        && discovery.device.length != 0)
        .then_some(discovery)
}

/// Return the offset of one TX queue page.
pub const fn tx_queue_offset(pair: usize) -> u64 {
    pair as u64 * QUEUE_PAIR_BYTES
}

/// Return the offset of one TX payload page.
pub const fn tx_buffer_offset(pair: usize) -> u64 {
    tx_queue_offset(pair) + PAGE_SIZE
}

/// Return the offset of one RX queue page.
pub const fn rx_queue_offset(pair: usize) -> u64 {
    tx_queue_offset(pair) + 2 * PAGE_SIZE
}

/// Return the offset of one RX payload page.
pub const fn rx_buffer_offset(pair: usize) -> u64 {
    tx_queue_offset(pair) + 3 * PAGE_SIZE
}

/// Return the full frame length for one payload.
pub const fn frame_len(payload_len: usize) -> usize {
    size_of::<VirtioNetHdr>() + payload_len
}

/// Return the TX queue index for one queue pair.
pub const fn tx_queue_index(pair: usize) -> usize {
    pair * 2
}

/// Return the RX queue index for one queue pair.
pub const fn rx_queue_index(pair: usize) -> usize {
    pair * 2 + 1
}

/// Return the notify value for one TX queue.
pub const fn tx_queue_notify_value(pair: usize) -> u32 {
    tx_queue_index(pair) as u32
}

/// Return the notify value for one RX queue.
pub const fn rx_queue_notify_value(pair: usize) -> u32 {
    rx_queue_index(pair) as u32
}

/// Return the TX descriptor DMA address for one queue pair.
pub const fn tx_desc_paddr(queue_paddr: u64, pair: usize) -> u64 {
    queue_paddr + tx_queue_offset(pair)
}

/// Return the TX avail DMA address for one queue pair.
pub const fn tx_avail_paddr(queue_paddr: u64, pair: usize) -> u64 {
    tx_desc_paddr(queue_paddr, pair) + 64
}

/// Return the TX used DMA address for one queue pair.
pub const fn tx_used_paddr(queue_paddr: u64, pair: usize) -> u64 {
    tx_desc_paddr(queue_paddr, pair) + 128
}

/// Return the RX descriptor DMA address for one queue pair.
pub const fn rx_desc_paddr(queue_paddr: u64, pair: usize) -> u64 {
    queue_paddr + rx_queue_offset(pair)
}

/// Return the RX avail DMA address for one queue pair.
pub const fn rx_avail_paddr(queue_paddr: u64, pair: usize) -> u64 {
    rx_desc_paddr(queue_paddr, pair) + 64
}

/// Return the RX used DMA address for one queue pair.
pub const fn rx_used_paddr(queue_paddr: u64, pair: usize) -> u64 {
    rx_desc_paddr(queue_paddr, pair) + 128
}

/// Return one zeroed avail header.
pub const fn empty_avail() -> VirtqAvail {
    VirtqAvail {
        flags: 0,
        idx: 0,
        ring: [0; QUEUE_SIZE],
        used_event: 0,
    }
}

/// Return one zeroed used header.
pub const fn empty_used() -> VirtqUsed {
    VirtqUsed {
        flags: 0,
        idx: 0,
        ring: [VirtqUsedElem { id: 0, len: 0 }; QUEUE_SIZE],
        avail_event: 0,
    }
}

/// Return one BAR0 register image in the device-reset state.
pub fn initial_regs() -> VirtioPciRegs {
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
    let mut queue = 0;
    while queue < TOTAL_QUEUE_COUNT {
        regs.queues[queue].size = QUEUE_SIZE as u32;
        regs.queues[queue].notify_off = queue as u32;
        queue += 1;
    }
    refresh_selected_queue(&mut regs, 0);
    regs
}

/// Update the selected-queue view for one queue index.
pub fn driver_select_queue(regs: &mut VirtioPciRegs, queue_index: usize) {
    refresh_selected_queue(regs, queue_index);
}

/// Program one queue DMA triplet and mark that queue ready.
pub fn driver_program_queue(
    regs: &mut VirtioPciRegs,
    queue_index: usize,
    desc_addr: u64,
    avail_addr: u64,
    used_addr: u64,
) {
    let mut queue = regs.queues[queue_index];
    queue.ready = 1;
    queue.desc_addr = desc_addr;
    queue.avail_addr = avail_addr;
    queue.used_addr = used_addr;
    regs.queues[queue_index] = queue;
    refresh_selected_queue(regs, queue_index);
}

/// Derive one driver-facing MMIO header snapshot from the BAR0 register image.
pub fn read_header(regs: &VirtioPciRegs) -> VirtioMmioHeader {
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

/// Apply driver-selected feature/status fields back to the BAR0 register image.
pub fn write_header(regs: &mut VirtioPciRegs, header: VirtioMmioHeader) {
    regs.common.driver_feature_select = 0;
    regs.common.driver_features = header.driver_features;
    regs.common.device_status = header.status;
}

/// Read one queue-pair register aggregate.
pub fn read_queue_regs(regs: &VirtioPciRegs, pair: usize) -> VirtioQueueRegs {
    let tx = regs.queues[tx_queue_index(pair)];
    let rx = regs.queues[rx_queue_index(pair)];
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

/// Update one queue-pair register aggregate.
pub fn write_queue_regs(regs: &mut VirtioPciRegs, pair: usize, queue_regs: VirtioQueueRegs) {
    let tx_index = tx_queue_index(pair);
    let rx_index = rx_queue_index(pair);

    let mut tx = regs.queues[tx_index];
    tx.ready = queue_regs.tx_queue_ready;
    tx.notify_value = queue_regs.notify_value;
    tx.notify_count = queue_regs.tx_notify_count;
    tx.desc_addr = queue_regs.tx_desc_addr;
    tx.avail_addr = queue_regs.tx_avail_addr;
    tx.used_addr = queue_regs.tx_used_addr;
    regs.queues[tx_index] = tx;

    let mut rx = regs.queues[rx_index];
    rx.ready = queue_regs.rx_queue_ready;
    rx.notify_value = queue_regs.notify_value;
    rx.complete_count = queue_regs.rx_complete_count;
    rx.interrupt_status = queue_regs.interrupt_status;
    rx.desc_addr = queue_regs.rx_desc_addr;
    rx.avail_addr = queue_regs.rx_avail_addr;
    rx.used_addr = queue_regs.rx_used_addr;
    regs.queues[rx_index] = rx;

    let selected = regs.common.queue_select as usize;
    if selected == tx_index || selected == rx_index {
        refresh_selected_queue(regs, selected);
    }
}

/// Return one buffer offset inside one TX/RX payload page.
pub const fn buffer_offset(base_offset: u64, slot: usize) -> u64 {
    base_offset + (slot as u64 * BUFFER_STRIDE)
}

/// Return one DMA address for a packet slot.
pub const fn buffer_paddr(queue_paddr: u64, base_offset: u64, slot: usize) -> u64 {
    queue_paddr + buffer_offset(base_offset, slot)
}

/// Return the serialized header size for one frame.
pub const fn frame_header_bytes() -> u64 {
    size_of::<VirtioNetHdr>() as u64
}

/// Translate one DMA address back into the mapped queue window when it lies inside that region.
pub fn map_dma_addr(mapped_queue_base: u64, queue_paddr: u64, addr: u64) -> Option<u64> {
    if addr < queue_paddr {
        return None;
    }
    let offset = addr - queue_paddr;
    (offset < QUEUE_VMO_BYTES).then_some(mapped_queue_base + offset)
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

fn read_cap_region(config_bytes: &[u8], cap_offset: usize) -> Option<VirtioPciCapRegion> {
    Some(VirtioPciCapRegion {
        bar: read_cfg_u8(config_bytes, cap_offset + 4)?,
        offset: read_cfg_u32(config_bytes, cap_offset + 8)?,
        length: read_cfg_u32(config_bytes, cap_offset + 12)?,
    })
}

fn read_cfg_u8(config_bytes: &[u8], offset: usize) -> Option<u8> {
    config_bytes.get(offset).copied()
}

fn read_cfg_u16(config_bytes: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = config_bytes.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_cfg_u32(config_bytes: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = config_bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}
