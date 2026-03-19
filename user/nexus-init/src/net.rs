use core::arch::x86_64::__cpuid;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering, fence};

use axle_arch_x86_64::native_syscall8;
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::status::ZX_OK;
use axle_types::syscall_numbers::AXLE_SYS_VMAR_MAP;
use axle_types::{zx_handle_t, zx_signals_t, zx_status_t};
use axle_virtio_transport::{
    BUFFER_STRIDE, CONFIG_VMO_BYTES, MMIO_DEVICE_ID_NET, MMIO_FEATURE_CSUM,
    MMIO_INTERRUPT_RX_COMPLETE, MMIO_MAGIC, MMIO_STATUS_ACKNOWLEDGE, MMIO_STATUS_DRIVER,
    MMIO_STATUS_DRIVER_OK, MMIO_STATUS_FEATURES_OK, MMIO_VENDOR_ID_AXLE, MMIO_VERSION, PAGE_SIZE,
    PCI_CLASS_NETWORK, PCI_DEVICE_ID_NET, PCI_SUBCLASS_ETHERNET, PCI_VENDOR_ID_AXLE,
    QUEUE_PAIR_COUNT, QUEUE_SIZE, QUEUE_VMO_BYTES, REGISTER_VMO_BYTES, VirtioMmioHeader,
    VirtioNetHdr, VirtioPciDiscovery, VirtioPciRegs, VirtioQueueRegs, VirtqAvail, VirtqDesc,
    VirtqUsed, VirtqUsedElem, buffer_offset, buffer_paddr, empty_avail, empty_used,
    frame_header_bytes, frame_len, map_dma_addr, read_header as read_transport_header,
    read_queue_regs as read_transport_queue_regs, rx_avail_paddr, rx_buffer_offset, rx_desc_paddr,
    rx_queue_index, rx_queue_notify_value, rx_queue_offset, rx_used_paddr, tx_avail_paddr,
    tx_buffer_offset, tx_desc_paddr, tx_queue_index, tx_queue_notify_value, tx_queue_offset,
    tx_used_paddr,
};
use libzircon::dma::{
    ZX_DMA_PERM_DEVICE_READ, ZX_DMA_PERM_DEVICE_WRITE, ZX_DMA_REGION_INFO_FLAG_IDENTITY_IOVA,
    ZX_DMA_REGION_INFO_FLAG_PHYSICALLY_CONTIGUOUS,
};
use libzircon::interrupt::{
    ZX_INTERRUPT_INFO_FLAG_TRIGGERABLE, ZX_INTERRUPT_MODE_VIRTUAL, zx_interrupt_info_t,
};
use libzircon::pci::{
    ZX_PCI_BAR_FLAG_MMIO, ZX_PCI_CONFIG_FLAG_MMIO, ZX_PCI_CONFIG_FLAG_READ_ONLY,
    ZX_PCI_INTERRUPT_GROUP_READY, ZX_PCI_INTERRUPT_GROUP_RX_COMPLETE,
    ZX_PCI_INTERRUPT_GROUP_TX_KICK, ZX_PCI_INTERRUPT_MODE_INFO_FLAG_ACTIVE,
    ZX_PCI_INTERRUPT_MODE_INFO_FLAG_SUPPORTED, ZX_PCI_INTERRUPT_MODE_INFO_FLAG_TRIGGERABLE,
    ZX_PCI_INTERRUPT_MODE_VIRTUAL, zx_pci_bar_info_t, zx_pci_config_info_t, zx_pci_device_info_t,
    zx_pci_interrupt_info_t, zx_pci_interrupt_mode_info_t,
};
use libzircon::signals::{ZX_INTERRUPT_SIGNALED, ZX_TASK_TERMINATED};
use libzircon::vm::{ZX_VM_MAP_MMIO, ZX_VM_PERM_READ, ZX_VM_PERM_WRITE};
use libzircon::{
    ax_dma_region_get_info, ax_interrupt_trigger, ax_pci_device_get_bar, ax_pci_device_get_config,
    ax_pci_device_get_info, ax_pci_device_get_interrupt, ax_pci_device_get_interrupt_mode,
    ax_pci_device_set_interrupt_mode, ax_vmo_pin, zx_dma_region_info_t, zx_handle_close,
    zx_interrupt_ack, zx_interrupt_get_info, zx_object_wait_one, zx_task_kill, zx_thread_create,
    zx_thread_start, zx_vmo_create_contiguous,
};

use crate::{SLOT_ROOT_VMAR_H, SLOT_SELF_PROCESS_H, SLOT_T0_NS, read_slot, write_slot};

const SLOT_BOOTSTRAP_NET_PCI_DEVICE_H: usize = 648;

const SLOT_NET_FAILURE_STEP: usize = 928;
const SLOT_NET_READY_IRQ_CREATE: usize = 929;
const SLOT_NET_TX_IRQ_CREATE: usize = 930;
const SLOT_NET_RX_IRQ_CREATE: usize = 931;
const SLOT_NET_QUEUE_VMO_CREATE: usize = 932;
const SLOT_NET_QUEUE_LOOKUP: usize = 933;
const SLOT_NET_QUEUE_MAP: usize = 934;
const SLOT_NET_WORKER_THREAD_CREATE: usize = 935;
const SLOT_NET_WORKER_THREAD_START: usize = 936;
const SLOT_NET_READY_WAIT: usize = 937;
const SLOT_NET_READY_ACK: usize = 938;
const SLOT_NET_TX_KICK: usize = 939;
const SLOT_NET_WORKER_WAIT_KICK: usize = 940;
const SLOT_NET_WORKER_ACK_KICK: usize = 941;
const SLOT_NET_WORKER_TRIGGER_RX: usize = 942;
const SLOT_NET_RX_WAIT: usize = 943;
const SLOT_NET_RX_ACK: usize = 944;
const SLOT_NET_TX_USED_IDX: usize = 945;
const SLOT_NET_RX_USED_IDX: usize = 946;
const SLOT_NET_TX_USED_LEN: usize = 947;
const SLOT_NET_RX_USED_LEN: usize = 948;
const SLOT_NET_PACKET_BYTES: usize = 949;
const SLOT_NET_PACKET_MATCH: usize = 950;
const SLOT_NET_DRIVER_CPU: usize = 951;
const SLOT_NET_WORKER_CPU: usize = 952;
const SLOT_NET_PRESENT: usize = 953;
const SLOT_NET_CONFIG_BACKING_CREATE: usize = 978;
const SLOT_NET_CONFIG_LOOKUP: usize = 979;
const SLOT_NET_CONFIG_ALIAS_CREATE: usize = 980;
const SLOT_NET_CONFIG_ALIAS_LOOKUP: usize = 981;
const SLOT_NET_CONFIG_ALIAS_MATCH: usize = 982;
const SLOT_NET_CONFIG_ALIAS_MAP: usize = 983;
const SLOT_NET_CONFIG_BACKING_MAP: usize = 984;
const SLOT_NET_REG_BACKING_CREATE: usize = 985;
const SLOT_NET_REG_LOOKUP: usize = 986;
const SLOT_NET_REG_BACKING_MAP: usize = 987;
const SLOT_NET_BAR0_CREATE: usize = 988;
const SLOT_NET_BAR0_LOOKUP: usize = 989;
const SLOT_NET_BAR0_MATCH: usize = 990;
const SLOT_NET_BAR0_MAP: usize = 991;
const SLOT_NET_MMIO_READY: usize = 992;
const SLOT_NET_MMIO_DEVICE_FEATURES: usize = 993;
const SLOT_NET_MMIO_DRIVER_FEATURES: usize = 994;
const SLOT_NET_MMIO_STATUS: usize = 995;
const SLOT_NET_QUEUE_PAIRS: usize = 996;
const SLOT_NET_WORKER_CPU1: usize = 997;
const SLOT_NET_TX_NOTIFY_COUNT: usize = 998;
const SLOT_NET_RX_COMPLETE_COUNT: usize = 999;
const SLOT_NET_PACKET_COUNT: usize = 1000;
const SLOT_NET_PACKET_MATCH_COUNT: usize = 1001;
const SLOT_NET_BATCH_CYCLES: usize = 1002;
const SLOT_NET_TX_NOTIFY_MASK: usize = 1003;
const SLOT_NET_RX_COMPLETE_MASK: usize = 1004;
const SLOT_NET_TX_READY_MASK: usize = 1005;
const SLOT_NET_RX_READY_MASK: usize = 1006;
const SLOT_NET_PCI_VENDOR_ID: usize = 1007;
const SLOT_NET_REG_PIN_CREATE: usize = 1008;
const SLOT_NET_CONFIG_PIN_CREATE: usize = 1009;
const SLOT_NET_CONFIG_ALIAS_PIN_CREATE: usize = 1010;
const SLOT_NET_QUEUE_PIN_CREATE: usize = 1011;
const SLOT_NET_BAR0_PIN_CREATE: usize = 1012;
const SLOT_NET_PCI_IRQ_MODE_INFO: usize = 1013;
const SLOT_NET_PCI_IRQ_MODE_FLAGS: usize = 1014;
const SLOT_NET_PCI_IRQ_MODE_BASE_VECTOR: usize = 1015;
const SLOT_NET_PCI_IRQ_MODE_VECTOR_COUNT: usize = 1016;
const SLOT_NET_BAR0_DMA_INFO: usize = 1017;
const SLOT_NET_BAR0_DMA_FLAGS: usize = 1018;
const SLOT_NET_BAR0_DMA_IOVA: usize = 1019;
const SLOT_NET_QUEUE_DMA_INFO: usize = 1020;
const SLOT_NET_QUEUE_DMA_FLAGS: usize = 1021;
const SLOT_NET_QUEUE_DMA_IOVA: usize = 1022;
const SLOT_NET_PCI_CONFIG_INFO: usize = 1023;
const SLOT_NET_PCI_CONFIG_FLAGS: usize = 1024;
const SLOT_NET_PCI_CONFIG_MAP_OPTIONS: usize = 1025;
const SLOT_NET_PCI_CONFIG_MAP: usize = 1026;
const SLOT_NET_PCI_CONFIG_CAPS_OK: usize = 1027;
const SLOT_NET_PCI_CONFIG_COMMON_BAR: usize = 1028;
const SLOT_NET_PCI_CONFIG_COMMON_OFFSET: usize = 1029;
const SLOT_NET_PCI_CONFIG_NOTIFY_OFFSET: usize = 1030;
const SLOT_NET_PCI_CONFIG_ISR_OFFSET: usize = 1031;
const SLOT_NET_PCI_CONFIG_DEVICE_OFFSET: usize = 1032;
const SLOT_NET_PCI_IRQ_MODE_SET: usize = 1033;

const STEP_ROOT_VMAR: u64 = 1;
const STEP_SELF_PROCESS: u64 = 2;
const STEP_READY_IRQ_CREATE: u64 = 3;
const STEP_TX_IRQ_CREATE: u64 = 4;
const STEP_RX_IRQ_CREATE: u64 = 5;
const STEP_REG_BACKING_MAP: u64 = 9;
const STEP_CONFIG_BACKING_CREATE: u64 = 10;
const STEP_CONFIG_PIN_CREATE: u64 = 11;
const STEP_QUEUE_VMO_CREATE: u64 = 18;
const STEP_QUEUE_PIN_CREATE: u64 = 19;
const STEP_QUEUE_MAP: u64 = 21;
const STEP_BAR0_CREATE: u64 = 22;
const STEP_BAR0_PIN_CREATE: u64 = 23;
const STEP_BAR0_MAP: u64 = 25;
const STEP_WORKER_THREAD_CREATE: u64 = 26;
const STEP_WORKER_THREAD_START: u64 = 27;
const STEP_READY_WAIT: u64 = 28;
const STEP_READY_ACK: u64 = 29;
const STEP_MMIO_READY: u64 = 30;
const STEP_TX_KICK: u64 = 31;
const STEP_RX_WAIT: u64 = 32;
const STEP_RX_ACK: u64 = 33;
const STEP_WORKER_WAIT_KICK: u64 = 34;
const STEP_WORKER_ACK_KICK: u64 = 35;
const STEP_WORKER_TRIGGER_RX: u64 = 36;
const STEP_TX_USED: u64 = 37;
const STEP_RX_USED: u64 = 38;
const STEP_PACKET_MATCH: u64 = 39;
const STEP_PCI_IRQ_MODE_INFO: u64 = 40;
const STEP_BAR0_DMA_INFO: u64 = 41;
const STEP_QUEUE_DMA_INFO: u64 = 42;
const STEP_PCI_CONFIG_INFO: u64 = 43;
const STEP_PCI_CONFIG_MAP: u64 = 44;
const STEP_PCI_CONFIG_CAPS: u64 = 45;
const STEP_PCI_IRQ_MODE_SET: u64 = 46;

const WAIT_TIMEOUT_NS: u64 = 5_000_000_000;
const WORKER_STACK_BYTES: usize = 4096;
const PACKET_COUNT: usize = QUEUE_PAIR_COUNT * QUEUE_SIZE;
const PACKET_PAYLOAD_BYTES: usize = 32;
const PAYLOAD_TEMPLATE: [u8; PACKET_PAYLOAD_BYTES] = *b"axle-net-smoke-loopback-packet!!";

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct WorkerStack([u8; WORKER_STACK_BYTES]);

#[derive(Clone, Copy, Default)]
struct NetSummary {
    failure_step: u64,
    ready_irq_create: i64,
    tx_irq_create: i64,
    rx_irq_create: i64,
    reg_backing_create: i64,
    reg_pin_create: i64,
    reg_dma_lookup: i64,
    reg_backing_map: i64,
    pci_config_info: i64,
    pci_config_flags: u64,
    pci_config_map_options: u64,
    pci_config_map: i64,
    pci_config_caps_ok: u64,
    pci_config_common_bar: u64,
    pci_config_common_offset: u64,
    pci_config_notify_offset: u64,
    pci_config_isr_offset: u64,
    pci_config_device_offset: u64,
    pci_irq_mode_info: i64,
    pci_irq_mode_set: i64,
    pci_irq_mode_flags: u64,
    pci_irq_mode_base_vector: u64,
    pci_irq_mode_vector_count: u64,
    config_backing_create: i64,
    config_pin_create: i64,
    config_dma_lookup: i64,
    config_alias_create: i64,
    config_alias_pin_create: i64,
    config_alias_dma_lookup: i64,
    config_alias_map: i64,
    config_backing_map: i64,
    queue_vmo_create: i64,
    queue_pin_create: i64,
    queue_dma_lookup: i64,
    queue_dma_info: i64,
    queue_dma_flags: u64,
    queue_dma_iova: u64,
    queue_map: i64,
    bar0_create: i64,
    bar0_pin_create: i64,
    bar0_dma_lookup: i64,
    bar0_dma_info: i64,
    bar0_dma_flags: u64,
    bar0_dma_iova: u64,
    bar0_map: i64,
    worker_thread_create: i64,
    worker_thread_start: i64,
    ready_wait: i64,
    ready_ack: i64,
    tx_kick: i64,
    worker_wait_kick: i64,
    worker_ack_kick: i64,
    worker_trigger_rx: i64,
    rx_wait: i64,
    rx_ack: i64,
    tx_used_idx: u64,
    rx_used_idx: u64,
    tx_used_len: u64,
    rx_used_len: u64,
    packet_bytes: u64,
    packet_count: u64,
    packet_match: u64,
    packet_match_count: u64,
    batch_cycles: u64,
    driver_cpu: u64,
    worker_cpu: u64,
    worker_cpu1: u64,
    queue_pairs: u64,
    config_alias_match: u64,
    bar0_match: u64,
    pci_vendor_id: u64,
    mmio_ready: u64,
    mmio_device_features: u64,
    mmio_driver_features: u64,
    mmio_status: u64,
    tx_notify_count: u64,
    rx_complete_count: u64,
    tx_notify_mask: u64,
    rx_complete_mask: u64,
    tx_ready_mask: u64,
    rx_ready_mask: u64,
}

static NET_READY_IRQS: [AtomicU64; QUEUE_PAIR_COUNT] =
    [const { AtomicU64::new(ZX_HANDLE_INVALID) }; QUEUE_PAIR_COUNT];
static NET_TX_IRQS: [AtomicU64; QUEUE_PAIR_COUNT] =
    [const { AtomicU64::new(ZX_HANDLE_INVALID) }; QUEUE_PAIR_COUNT];
static NET_RX_IRQS: [AtomicU64; QUEUE_PAIR_COUNT] =
    [const { AtomicU64::new(ZX_HANDLE_INVALID) }; QUEUE_PAIR_COUNT];
static NET_REG_DEVICE_BASE: AtomicU64 = AtomicU64::new(0);
static NET_QUEUE_BASE: AtomicU64 = AtomicU64::new(0);
static NET_QUEUE_IOVA: AtomicU64 = AtomicU64::new(0);
static NET_WORKER_CPUS: [AtomicU64; QUEUE_PAIR_COUNT] =
    [const { AtomicU64::new(0) }; QUEUE_PAIR_COUNT];
static NET_WORKER_WAIT_KICK_STATUS: [AtomicU64; QUEUE_PAIR_COUNT] =
    [const { AtomicU64::new(0) }; QUEUE_PAIR_COUNT];
static NET_WORKER_ACK_KICK_STATUS: [AtomicU64; QUEUE_PAIR_COUNT] =
    [const { AtomicU64::new(0) }; QUEUE_PAIR_COUNT];
static NET_WORKER_TRIGGER_RX_STATUS: [AtomicU64; QUEUE_PAIR_COUNT] =
    [const { AtomicU64::new(0) }; QUEUE_PAIR_COUNT];
static NET_WORKER_FAILURE_STEP: [AtomicU64; QUEUE_PAIR_COUNT] =
    [const { AtomicU64::new(0) }; QUEUE_PAIR_COUNT];
static mut NET_WORKER_STACKS: [WorkerStack; QUEUE_PAIR_COUNT] =
    [WorkerStack([0; WORKER_STACK_BYTES]); QUEUE_PAIR_COUNT];

const OWNED_PCI_DEVICE: usize = 0;
const OWNED_CONFIG_VMO: usize = 1;
const OWNED_QUEUE_VMO: usize = 2;
const OWNED_QUEUE_DMA: usize = 3;
const OWNED_BAR0_VMO: usize = 4;
const OWNED_BAR0_DMA: usize = 5;
const OWNED_HANDLE_COUNT: usize = 6;

pub(crate) fn run_root_dataplane() -> i32 {
    let summary = run_net_bringup();
    write_summary(&summary);
    i32::from(summary.failure_step != 0)
}

fn run_net_bringup() -> NetSummary {
    let mut summary = NetSummary {
        packet_bytes: PACKET_PAYLOAD_BYTES as u64,
        packet_count: PACKET_COUNT as u64,
        driver_cpu: current_cpu_apic_id(),
        queue_pairs: QUEUE_PAIR_COUNT as u64,
        ..NetSummary::default()
    };
    let root_vmar = read_slot(SLOT_ROOT_VMAR_H) as zx_handle_t;
    if root_vmar == ZX_HANDLE_INVALID {
        summary.failure_step = STEP_ROOT_VMAR;
        return summary;
    }
    let self_process = read_slot(SLOT_SELF_PROCESS_H) as zx_handle_t;
    if self_process == ZX_HANDLE_INVALID {
        summary.failure_step = STEP_SELF_PROCESS;
        return summary;
    }
    let mut owned_handles = [ZX_HANDLE_INVALID; OWNED_HANDLE_COUNT];
    owned_handles[OWNED_PCI_DEVICE] = read_slot(SLOT_BOOTSTRAP_NET_PCI_DEVICE_H) as zx_handle_t;
    if owned_handles[OWNED_PCI_DEVICE] == ZX_HANDLE_INVALID {
        summary.failure_step = STEP_CONFIG_BACKING_CREATE;
        return summary;
    }

    let mut pci_config = zx_pci_config_info_t::default();
    summary.pci_config_info =
        ax_pci_device_get_config(owned_handles[OWNED_PCI_DEVICE], &mut pci_config) as i64;
    summary.pci_config_flags = u64::from(pci_config.flags);
    summary.pci_config_map_options = u64::from(pci_config.map_options);
    if summary.pci_config_info != ZX_OK as i64 {
        summary.failure_step = STEP_PCI_CONFIG_INFO;
        close_handle_sets(&[], &owned_handles);
        return summary;
    }
    owned_handles[OWNED_CONFIG_VMO] = pci_config.handle;

    let mut pci_info = zx_pci_device_info_t::default();
    summary.config_pin_create =
        ax_pci_device_get_info(owned_handles[OWNED_PCI_DEVICE], &mut pci_info) as i64;
    if summary.config_pin_create != ZX_OK as i64 {
        summary.failure_step = STEP_CONFIG_PIN_CREATE;
        close_handle_sets(&[], &owned_handles);
        return summary;
    }
    summary.pci_vendor_id = u64::from(pci_info.vendor_id);

    let Some(config_base) = map_driver_config(root_vmar, pci_config, &mut summary, &owned_handles)
    else {
        close_handle_sets(&[], &owned_handles);
        return summary;
    };
    let Some(discovery) = discover_pci_transport(config_base) else {
        summary.failure_step = STEP_PCI_CONFIG_CAPS;
        close_handle_sets(&[], &owned_handles);
        return summary;
    };
    summary.pci_config_common_bar = u64::from(discovery.common.bar);
    summary.pci_config_common_offset = u64::from(discovery.common.offset);
    summary.pci_config_notify_offset = u64::from(discovery.notify.offset);
    summary.pci_config_isr_offset = u64::from(discovery.isr.offset);
    summary.pci_config_device_offset = u64::from(discovery.device.offset);
    summary.pci_config_caps_ok = u64::from(validate_pci_discovery(&pci_info, &discovery));
    summary.config_alias_match = summary.pci_config_caps_ok;
    if summary.pci_config_caps_ok != 1 {
        summary.failure_step = STEP_PCI_CONFIG_CAPS;
        close_handle_sets(&[], &owned_handles);
        return summary;
    }

    summary.pci_irq_mode_set = ax_pci_device_set_interrupt_mode(
        owned_handles[OWNED_PCI_DEVICE],
        ZX_PCI_INTERRUPT_MODE_VIRTUAL,
    ) as i64;
    if summary.pci_irq_mode_set != ZX_OK as i64 {
        summary.failure_step = STEP_PCI_IRQ_MODE_SET;
        close_handle_sets(&[], &owned_handles);
        return summary;
    }

    let mut irq_mode = zx_pci_interrupt_mode_info_t::default();
    summary.pci_irq_mode_info = ax_pci_device_get_interrupt_mode(
        owned_handles[OWNED_PCI_DEVICE],
        ZX_PCI_INTERRUPT_MODE_VIRTUAL,
        &mut irq_mode,
    ) as i64;
    summary.pci_irq_mode_flags = u64::from(irq_mode.flags);
    summary.pci_irq_mode_base_vector = u64::from(irq_mode.base_vector);
    summary.pci_irq_mode_vector_count = u64::from(irq_mode.vector_count);
    if summary.pci_irq_mode_info != ZX_OK as i64
        || irq_mode.mode != ZX_PCI_INTERRUPT_MODE_VIRTUAL
        || (irq_mode.flags
            & (ZX_PCI_INTERRUPT_MODE_INFO_FLAG_SUPPORTED
                | ZX_PCI_INTERRUPT_MODE_INFO_FLAG_ACTIVE
                | ZX_PCI_INTERRUPT_MODE_INFO_FLAG_TRIGGERABLE))
            != (ZX_PCI_INTERRUPT_MODE_INFO_FLAG_SUPPORTED
                | ZX_PCI_INTERRUPT_MODE_INFO_FLAG_ACTIVE
                | ZX_PCI_INTERRUPT_MODE_INFO_FLAG_TRIGGERABLE)
        || irq_mode.base_vector != 0
        || irq_mode.vector_count != pci_info.queue_pairs * pci_info.interrupt_groups
    {
        summary.failure_step = STEP_PCI_IRQ_MODE_INFO;
        close_handle_sets(&[], &owned_handles);
        return summary;
    }

    let mut ready_irqs = [ZX_HANDLE_INVALID; QUEUE_PAIR_COUNT];
    for (pair, ready_irq) in ready_irqs.iter_mut().enumerate() {
        let mut info = zx_pci_interrupt_info_t::default();
        let status = ax_pci_device_get_interrupt(
            owned_handles[OWNED_PCI_DEVICE],
            ZX_PCI_INTERRUPT_GROUP_READY,
            pair as u32,
            &mut info,
        ) as i64;
        aggregate_status(&mut summary.ready_irq_create, status);
        if status != ZX_OK as i64 {
            summary.failure_step = STEP_READY_IRQ_CREATE;
            close_handles(&ready_irqs);
            close_handle_sets(&[], &owned_handles);
            return summary;
        }
        let mut irq_info = zx_interrupt_info_t::default();
        let info_status = zx_interrupt_get_info(info.handle, &mut irq_info) as i64;
        aggregate_status(&mut summary.ready_irq_create, info_status);
        if info_status != ZX_OK as i64
            || info.mode != ZX_INTERRUPT_MODE_VIRTUAL
            || irq_info.mode != info.mode
            || irq_info.vector != info.vector
            || (irq_info.flags & ZX_INTERRUPT_INFO_FLAG_TRIGGERABLE) == 0
        {
            summary.failure_step = STEP_READY_IRQ_CREATE;
            close_handles(&ready_irqs);
            close_handle_sets(&[], &owned_handles);
            return summary;
        }
        *ready_irq = info.handle;
    }

    let mut tx_irqs = [ZX_HANDLE_INVALID; QUEUE_PAIR_COUNT];
    for (pair, tx_irq) in tx_irqs.iter_mut().enumerate() {
        let mut info = zx_pci_interrupt_info_t::default();
        let status = ax_pci_device_get_interrupt(
            owned_handles[OWNED_PCI_DEVICE],
            ZX_PCI_INTERRUPT_GROUP_TX_KICK,
            pair as u32,
            &mut info,
        ) as i64;
        aggregate_status(&mut summary.tx_irq_create, status);
        if status != ZX_OK as i64 {
            summary.failure_step = STEP_TX_IRQ_CREATE;
            close_handles(&tx_irqs);
            close_handles(&ready_irqs);
            close_handle_sets(&[], &owned_handles);
            return summary;
        }
        let mut irq_info = zx_interrupt_info_t::default();
        let info_status = zx_interrupt_get_info(info.handle, &mut irq_info) as i64;
        aggregate_status(&mut summary.tx_irq_create, info_status);
        if info_status != ZX_OK as i64
            || info.mode != ZX_INTERRUPT_MODE_VIRTUAL
            || irq_info.mode != info.mode
            || irq_info.vector != info.vector
            || (irq_info.flags & ZX_INTERRUPT_INFO_FLAG_TRIGGERABLE) == 0
        {
            summary.failure_step = STEP_TX_IRQ_CREATE;
            close_handles(&tx_irqs);
            close_handles(&ready_irqs);
            close_handle_sets(&[], &owned_handles);
            return summary;
        }
        *tx_irq = info.handle;
    }

    let mut rx_irqs = [ZX_HANDLE_INVALID; QUEUE_PAIR_COUNT];
    for (pair, rx_irq) in rx_irqs.iter_mut().enumerate() {
        let mut info = zx_pci_interrupt_info_t::default();
        let status = ax_pci_device_get_interrupt(
            owned_handles[OWNED_PCI_DEVICE],
            ZX_PCI_INTERRUPT_GROUP_RX_COMPLETE,
            pair as u32,
            &mut info,
        ) as i64;
        aggregate_status(&mut summary.rx_irq_create, status);
        if status != ZX_OK as i64 {
            summary.failure_step = STEP_RX_IRQ_CREATE;
            close_handles(&rx_irqs);
            close_handles(&tx_irqs);
            close_handles(&ready_irqs);
            close_handle_sets(&[], &owned_handles);
            return summary;
        }
        let mut irq_info = zx_interrupt_info_t::default();
        let info_status = zx_interrupt_get_info(info.handle, &mut irq_info) as i64;
        aggregate_status(&mut summary.rx_irq_create, info_status);
        if info_status != ZX_OK as i64
            || info.mode != ZX_INTERRUPT_MODE_VIRTUAL
            || irq_info.mode != info.mode
            || irq_info.vector != info.vector
            || (irq_info.flags & ZX_INTERRUPT_INFO_FLAG_TRIGGERABLE) == 0
        {
            summary.failure_step = STEP_RX_IRQ_CREATE;
            close_handles(&rx_irqs);
            close_handles(&tx_irqs);
            close_handles(&ready_irqs);
            close_handle_sets(&[], &owned_handles);
            return summary;
        }
        *rx_irq = info.handle;
    }

    let mut pci_bar = zx_pci_bar_info_t::default();
    summary.bar0_create = ax_pci_device_get_bar(
        owned_handles[OWNED_PCI_DEVICE],
        u32::from(discovery.common.bar),
        &mut pci_bar,
    ) as i64;
    if summary.bar0_create != ZX_OK as i64 {
        summary.failure_step = STEP_BAR0_CREATE;
        close_handle_sets(&[&rx_irqs, &tx_irqs, &ready_irqs], &owned_handles);
        return summary;
    }
    owned_handles[OWNED_BAR0_VMO] = pci_bar.handle;

    summary.bar0_pin_create = ax_vmo_pin(
        owned_handles[OWNED_BAR0_VMO],
        0,
        pci_bar.size,
        ZX_DMA_PERM_DEVICE_READ | ZX_DMA_PERM_DEVICE_WRITE,
        &mut owned_handles[OWNED_BAR0_DMA],
    ) as i64;
    if summary.bar0_pin_create != ZX_OK as i64 {
        summary.failure_step = STEP_BAR0_PIN_CREATE;
        close_handle_sets(&[&rx_irqs, &tx_irqs, &ready_irqs], &owned_handles);
        return summary;
    }

    let mut bar0_dma = zx_dma_region_info_t::default();
    summary.bar0_dma_info =
        ax_dma_region_get_info(owned_handles[OWNED_BAR0_DMA], &mut bar0_dma) as i64;
    summary.bar0_dma_iova = bar0_dma.iova_base;
    summary.bar0_dma_flags = u64::from(bar0_dma.flags);
    summary.bar0_dma_lookup = ZX_OK as i64;
    if summary.bar0_dma_info != ZX_OK as i64 {
        summary.failure_step = STEP_BAR0_DMA_INFO;
        close_handle_sets(&[&rx_irqs, &tx_irqs, &ready_irqs], &owned_handles);
        return summary;
    }
    summary.bar0_match = u64::from(
        pci_bar.size == REGISTER_VMO_BYTES
            && bar0_dma.iova_base != 0
            && bar0_dma.size_bytes == pci_bar.size
            && bar0_dma.options == (ZX_DMA_PERM_DEVICE_READ | ZX_DMA_PERM_DEVICE_WRITE)
            && (bar0_dma.flags & ZX_DMA_REGION_INFO_FLAG_IDENTITY_IOVA) != 0
            && (bar0_dma.flags & ZX_DMA_REGION_INFO_FLAG_PHYSICALLY_CONTIGUOUS) != 0
            && (pci_bar.flags & ZX_PCI_BAR_FLAG_MMIO) != 0
            && (pci_bar.map_options & ZX_VM_MAP_MMIO) != 0
            && discovery.common.bar == 0,
    );

    let mut reg_device_base = 0u64;
    summary.reg_backing_map = zx_vmar_map_local(
        root_vmar,
        ZX_VM_PERM_READ | ZX_VM_PERM_WRITE,
        0,
        owned_handles[OWNED_BAR0_VMO],
        0,
        pci_bar.size,
        &mut reg_device_base,
    ) as i64;
    if summary.reg_backing_map != ZX_OK as i64 {
        summary.failure_step = STEP_REG_BACKING_MAP;
        close_handle_sets(&[&rx_irqs, &tx_irqs, &ready_irqs], &owned_handles);
        return summary;
    }
    init_regs(reg_device_base);

    summary.queue_vmo_create =
        zx_vmo_create_contiguous(QUEUE_VMO_BYTES, 0, &mut owned_handles[OWNED_QUEUE_VMO]) as i64;
    if summary.queue_vmo_create != ZX_OK as i64 {
        summary.failure_step = STEP_QUEUE_VMO_CREATE;
        close_handle_sets(&[&rx_irqs, &tx_irqs, &ready_irqs], &owned_handles);
        return summary;
    }

    summary.queue_pin_create = ax_vmo_pin(
        owned_handles[OWNED_QUEUE_VMO],
        0,
        QUEUE_VMO_BYTES,
        ZX_DMA_PERM_DEVICE_READ | ZX_DMA_PERM_DEVICE_WRITE,
        &mut owned_handles[OWNED_QUEUE_DMA],
    ) as i64;
    if summary.queue_pin_create != ZX_OK as i64 {
        summary.failure_step = STEP_QUEUE_PIN_CREATE;
        close_handle_sets(&[&rx_irqs, &tx_irqs, &ready_irqs], &owned_handles);
        return summary;
    }

    let mut queue_dma = zx_dma_region_info_t::default();
    summary.queue_dma_info =
        ax_dma_region_get_info(owned_handles[OWNED_QUEUE_DMA], &mut queue_dma) as i64;
    summary.queue_dma_iova = queue_dma.iova_base;
    summary.queue_dma_flags = u64::from(queue_dma.flags);
    summary.queue_dma_lookup = ZX_OK as i64;
    if summary.queue_dma_info != ZX_OK as i64 {
        summary.failure_step = STEP_QUEUE_DMA_INFO;
        close_handle_sets(&[&rx_irqs, &tx_irqs, &ready_irqs], &owned_handles);
        return summary;
    }
    if queue_dma.size_bytes != QUEUE_VMO_BYTES
        || queue_dma.options != (ZX_DMA_PERM_DEVICE_READ | ZX_DMA_PERM_DEVICE_WRITE)
        || (queue_dma.flags & ZX_DMA_REGION_INFO_FLAG_IDENTITY_IOVA) == 0
        || (queue_dma.flags & ZX_DMA_REGION_INFO_FLAG_PHYSICALLY_CONTIGUOUS) == 0
    {
        summary.failure_step = STEP_QUEUE_DMA_INFO;
        close_handle_sets(&[&rx_irqs, &tx_irqs, &ready_irqs], &owned_handles);
        return summary;
    }

    let mut mapped_queue_base = 0u64;
    summary.queue_map = zx_vmar_map_local(
        root_vmar,
        ZX_VM_PERM_READ | ZX_VM_PERM_WRITE,
        0,
        owned_handles[OWNED_QUEUE_VMO],
        0,
        QUEUE_VMO_BYTES,
        &mut mapped_queue_base,
    ) as i64;
    if summary.queue_map != ZX_OK as i64 {
        summary.failure_step = STEP_QUEUE_MAP;
        close_handle_sets(&[&rx_irqs, &tx_irqs, &ready_irqs], &owned_handles);
        return summary;
    }
    init_transport_memory(mapped_queue_base);

    let reg_driver_base = match map_driver_bar0(
        root_vmar,
        pci_bar,
        discovery.common.offset,
        &mut summary,
        &owned_handles,
    ) {
        Some(base) => base,
        None => {
            close_handle_sets(&[&rx_irqs, &tx_irqs, &ready_irqs], &owned_handles);
            return summary;
        }
    };

    NET_REG_DEVICE_BASE.store(reg_device_base, Ordering::Release);
    NET_QUEUE_BASE.store(mapped_queue_base, Ordering::Release);
    NET_QUEUE_IOVA.store(queue_dma.iova_base, Ordering::Release);
    for pair in 0..QUEUE_PAIR_COUNT {
        NET_READY_IRQS[pair].store(ready_irqs[pair], Ordering::Release);
        NET_TX_IRQS[pair].store(tx_irqs[pair], Ordering::Release);
        NET_RX_IRQS[pair].store(rx_irqs[pair], Ordering::Release);
        NET_WORKER_CPUS[pair].store(0, Ordering::Release);
        NET_WORKER_WAIT_KICK_STATUS[pair].store(0, Ordering::Release);
        NET_WORKER_ACK_KICK_STATUS[pair].store(0, Ordering::Release);
        NET_WORKER_TRIGGER_RX_STATUS[pair].store(0, Ordering::Release);
        NET_WORKER_FAILURE_STEP[pair].store(0, Ordering::Release);
    }

    let mut worker_threads = [ZX_HANDLE_INVALID; QUEUE_PAIR_COUNT];
    for worker_thread in &mut worker_threads {
        let status = zx_thread_create(self_process, 0, worker_thread) as i64;
        aggregate_status(&mut summary.worker_thread_create, status);
        if status != ZX_OK as i64 {
            summary.failure_step = STEP_WORKER_THREAD_CREATE;
            close_workers_and_handles(
                &worker_threads,
                &[&rx_irqs, &tx_irqs, &ready_irqs],
                &owned_handles,
            );
            return summary;
        }
    }

    for pair in 0..QUEUE_PAIR_COUNT {
        let status = zx_thread_start(
            worker_threads[pair],
            net_worker_entry as *const () as usize as u64,
            worker_stack_top(pair),
            pair as u64,
            0,
        ) as i64;
        aggregate_status(&mut summary.worker_thread_start, status);
        if status != ZX_OK as i64 {
            summary.failure_step = STEP_WORKER_THREAD_START;
            close_workers_and_handles(
                &worker_threads,
                &[&rx_irqs, &tx_irqs, &ready_irqs],
                &owned_handles,
            );
            return summary;
        }
    }

    for pair in 0..QUEUE_PAIR_COUNT {
        let mut observed = 0;
        let status = zx_object_wait_one(
            ready_irqs[pair],
            ZX_INTERRUPT_SIGNALED,
            wait_deadline(),
            &mut observed,
        ) as i64;
        aggregate_status(&mut summary.ready_wait, status);
        if status != ZX_OK as i64 {
            summary.failure_step = STEP_READY_WAIT;
            close_workers_and_handles(
                &worker_threads,
                &[&rx_irqs, &tx_irqs, &ready_irqs],
                &owned_handles,
            );
            return summary;
        }
        let status = zx_interrupt_ack(ready_irqs[pair]) as i64;
        aggregate_status(&mut summary.ready_ack, status);
        if status != ZX_OK as i64 {
            summary.failure_step = STEP_READY_ACK;
            close_workers_and_handles(
                &worker_threads,
                &[&rx_irqs, &tx_irqs, &ready_irqs],
                &owned_handles,
            );
            return summary;
        }
    }

    if !configure_driver_transport(reg_driver_base, &mut summary, pci_info, queue_dma.iova_base) {
        summary.failure_step = STEP_MMIO_READY;
        close_workers_and_handles(
            &worker_threads,
            &[&rx_irqs, &tx_irqs, &ready_irqs],
            &owned_handles,
        );
        return summary;
    }
    prepare_tx_packets(mapped_queue_base, queue_dma.iova_base);
    prepare_rx_buffers(mapped_queue_base, queue_dma.iova_base);

    let batch_start = axle_arch_x86_64::rdtsc();
    for &tx_irq in &tx_irqs {
        let status = ax_interrupt_trigger(tx_irq, 1) as i64;
        aggregate_status(&mut summary.tx_kick, status);
        if status != ZX_OK as i64 {
            summary.failure_step = STEP_TX_KICK;
            close_workers_and_handles(
                &worker_threads,
                &[&rx_irqs, &tx_irqs, &ready_irqs],
                &owned_handles,
            );
            return summary;
        }
    }

    for &rx_irq in &rx_irqs {
        let mut observed = 0;
        let status = zx_object_wait_one(
            rx_irq,
            ZX_INTERRUPT_SIGNALED,
            wait_deadline(),
            &mut observed,
        ) as i64;
        aggregate_status(&mut summary.rx_wait, status);
        if status != ZX_OK as i64 {
            summary.failure_step = STEP_RX_WAIT;
            close_workers_and_handles(
                &worker_threads,
                &[&rx_irqs, &tx_irqs, &ready_irqs],
                &owned_handles,
            );
            return summary;
        }
    }
    summary.batch_cycles = axle_arch_x86_64::rdtsc().wrapping_sub(batch_start);

    for &rx_irq in &rx_irqs {
        let status = zx_interrupt_ack(rx_irq) as i64;
        aggregate_status(&mut summary.rx_ack, status);
        if status != ZX_OK as i64 {
            summary.failure_step = STEP_RX_ACK;
            close_workers_and_handles(
                &worker_threads,
                &[&rx_irqs, &tx_irqs, &ready_irqs],
                &owned_handles,
            );
            return summary;
        }
    }

    summary.worker_cpu = NET_WORKER_CPUS[0].load(Ordering::Acquire);
    summary.worker_cpu1 = NET_WORKER_CPUS[1].load(Ordering::Acquire);
    aggregate_status(
        &mut summary.worker_wait_kick,
        NET_WORKER_WAIT_KICK_STATUS[0].load(Ordering::Acquire) as i64,
    );
    aggregate_status(
        &mut summary.worker_wait_kick,
        NET_WORKER_WAIT_KICK_STATUS[1].load(Ordering::Acquire) as i64,
    );
    aggregate_status(
        &mut summary.worker_ack_kick,
        NET_WORKER_ACK_KICK_STATUS[0].load(Ordering::Acquire) as i64,
    );
    aggregate_status(
        &mut summary.worker_ack_kick,
        NET_WORKER_ACK_KICK_STATUS[1].load(Ordering::Acquire) as i64,
    );
    aggregate_status(
        &mut summary.worker_trigger_rx,
        NET_WORKER_TRIGGER_RX_STATUS[0].load(Ordering::Acquire) as i64,
    );
    aggregate_status(
        &mut summary.worker_trigger_rx,
        NET_WORKER_TRIGGER_RX_STATUS[1].load(Ordering::Acquire) as i64,
    );

    let header = read_header(reg_driver_base);
    summary.mmio_device_features = header.device_features as u64;
    summary.mmio_driver_features = header.driver_features as u64;
    summary.mmio_status = header.status as u64;
    summary.queue_pairs = header.queue_pairs as u64;
    for pair in 0..QUEUE_PAIR_COUNT {
        let tx_used = read_used(mapped_queue_base, tx_queue_offset(pair));
        let rx_used = read_used(mapped_queue_base, rx_queue_offset(pair));
        if read_queue_regs(reg_driver_base, pair).tx_queue_ready == 1 {
            summary.tx_ready_mask |= 1u64 << pair;
        }
        if read_queue_regs(reg_driver_base, pair).rx_queue_ready == 1 {
            summary.rx_ready_mask |= 1u64 << pair;
        }
        let regs = read_queue_regs(reg_driver_base, pair);
        if regs.tx_notify_count != 0 {
            summary.tx_notify_mask |= 1u64 << pair;
        }
        if (regs.interrupt_status & MMIO_INTERRUPT_RX_COMPLETE) != 0 && regs.rx_complete_count != 0
        {
            summary.rx_complete_mask |= 1u64 << pair;
        }
        summary.tx_notify_count = summary
            .tx_notify_count
            .saturating_add(regs.tx_notify_count as u64);
        summary.rx_complete_count = summary
            .rx_complete_count
            .saturating_add(regs.rx_complete_count as u64);
        summary.tx_used_idx = summary.tx_used_idx.saturating_add(tx_used.idx as u64);
        summary.rx_used_idx = summary.rx_used_idx.saturating_add(rx_used.idx as u64);
        if tx_used.idx != 0 {
            summary.tx_used_len = tx_used.ring[usize::from(tx_used.idx - 1)].len as u64;
        }
        if rx_used.idx != 0 {
            summary.rx_used_len = rx_used.ring[usize::from(rx_used.idx - 1)].len as u64;
        }
    }

    if summary.worker_wait_kick != ZX_OK as i64 {
        summary.failure_step = STEP_WORKER_WAIT_KICK;
    } else if summary.worker_ack_kick != ZX_OK as i64 {
        summary.failure_step = STEP_WORKER_ACK_KICK;
    } else if summary.worker_trigger_rx != ZX_OK as i64 {
        summary.failure_step = STEP_WORKER_TRIGGER_RX;
    } else if summary.tx_used_idx != PACKET_COUNT as u64 {
        summary.failure_step = STEP_TX_USED;
    } else if summary.rx_used_idx != PACKET_COUNT as u64 {
        summary.failure_step = STEP_RX_USED;
    } else {
        summary.packet_match_count = count_packet_matches(mapped_queue_base) as u64;
        summary.packet_match = u64::from(summary.packet_match_count == PACKET_COUNT as u64);
        if summary.packet_match != 1 {
            summary.failure_step = STEP_PACKET_MATCH;
        }
    }

    for pair in 0..QUEUE_PAIR_COUNT {
        let worker_failure = NET_WORKER_FAILURE_STEP[pair].load(Ordering::Acquire);
        if summary.failure_step == 0 && worker_failure != 0 {
            summary.failure_step = worker_failure;
        }
    }

    close_workers_and_handles(
        &worker_threads,
        &[&rx_irqs, &tx_irqs, &ready_irqs],
        &owned_handles,
    );
    summary
}

fn map_driver_config(
    root_vmar: zx_handle_t,
    config: zx_pci_config_info_t,
    summary: &mut NetSummary,
    owned_handles: &[zx_handle_t; OWNED_HANDLE_COUNT],
) -> Option<u64> {
    if config.handle == ZX_HANDLE_INVALID
        || config.size != CONFIG_VMO_BYTES
        || (config.flags & ZX_PCI_CONFIG_FLAG_MMIO) == 0
        || (config.flags & ZX_PCI_CONFIG_FLAG_READ_ONLY) == 0
        || (config.map_options & ZX_VM_MAP_MMIO) == 0
    {
        summary.failure_step = STEP_PCI_CONFIG_INFO;
        return None;
    }

    let mut config_base = 0u64;
    summary.pci_config_map = zx_vmar_map_local(
        root_vmar,
        ZX_VM_PERM_READ | config.map_options,
        0,
        owned_handles[OWNED_CONFIG_VMO],
        0,
        config.size,
        &mut config_base,
    ) as i64;
    if summary.pci_config_map != ZX_OK as i64 {
        summary.failure_step = STEP_PCI_CONFIG_MAP;
        return None;
    }

    Some(config_base)
}

fn validate_pci_discovery(info: &zx_pci_device_info_t, discovery: &VirtioPciDiscovery) -> bool {
    discovery.vendor_id == PCI_VENDOR_ID_AXLE
        && discovery.device_id == PCI_DEVICE_ID_NET
        && discovery.class_code == PCI_CLASS_NETWORK
        && discovery.subclass == PCI_SUBCLASS_ETHERNET
        && info.vendor_id == discovery.vendor_id
        && info.device_id == discovery.device_id
        && info.class_code == discovery.class_code
        && info.subclass == discovery.subclass
        && info.device_features == MMIO_FEATURE_CSUM
        && info.queue_pairs == QUEUE_PAIR_COUNT as u32
        && info.queue_size == QUEUE_SIZE as u32
        && info.bar_count == 1
        && discovery.common.bar == 0
        && discovery.notify.bar == 0
        && discovery.isr.bar == 0
        && discovery.device.bar == 0
        && discovery.common.length != 0
        && discovery.notify.length != 0
        && discovery.isr.length != 0
        && discovery.device.length != 0
}

fn map_driver_bar0(
    root_vmar: zx_handle_t,
    bar: zx_pci_bar_info_t,
    common_offset: u32,
    summary: &mut NetSummary,
    owned_handles: &[zx_handle_t; OWNED_HANDLE_COUNT],
) -> Option<u64> {
    if bar.handle == ZX_HANDLE_INVALID
        || bar.size != REGISTER_VMO_BYTES
        || u64::from(common_offset) >= bar.size
    {
        summary.failure_step = STEP_BAR0_CREATE;
        return None;
    }

    let mut bar0_driver_base = 0u64;
    summary.bar0_map = zx_vmar_map_local(
        root_vmar,
        ZX_VM_PERM_READ | ZX_VM_PERM_WRITE | bar.map_options,
        0,
        owned_handles[OWNED_BAR0_VMO],
        0,
        bar.size,
        &mut bar0_driver_base,
    ) as i64;
    if summary.bar0_map != ZX_OK as i64 {
        summary.failure_step = STEP_BAR0_MAP;
        return None;
    }

    Some(bar0_driver_base + u64::from(common_offset))
}

fn configure_driver_transport(
    reg_base: u64,
    summary: &mut NetSummary,
    info: zx_pci_device_info_t,
    queue_iova: u64,
) -> bool {
    let header = read_header(reg_base);
    let expected_device_features = info.device_features;
    if header.magic != MMIO_MAGIC
        || header.version != MMIO_VERSION
        || header.device_id != MMIO_DEVICE_ID_NET
        || header.vendor_id != MMIO_VENDOR_ID_AXLE
        || header.device_features != expected_device_features
        || header.queue_pairs != info.queue_pairs
        || header.queue_size != info.queue_size
    {
        return false;
    }

    let mut new_header = header;
    new_header.driver_features = header.device_features & MMIO_FEATURE_CSUM;
    new_header.status = MMIO_STATUS_ACKNOWLEDGE
        | MMIO_STATUS_DRIVER
        | MMIO_STATUS_FEATURES_OK
        | MMIO_STATUS_DRIVER_OK;
    write_header(reg_base, new_header);

    for pair in 0..QUEUE_PAIR_COUNT {
        driver_select_queue(reg_base, tx_queue_index(pair));
        driver_program_queue(
            reg_base,
            tx_queue_index(pair),
            tx_desc_paddr(queue_iova, pair),
            tx_avail_paddr(queue_iova, pair),
            tx_used_paddr(queue_iova, pair),
        );
        driver_select_queue(reg_base, rx_queue_index(pair));
        driver_program_queue(
            reg_base,
            rx_queue_index(pair),
            rx_desc_paddr(queue_iova, pair),
            rx_avail_paddr(queue_iova, pair),
            rx_used_paddr(queue_iova, pair),
        );
    }

    summary.mmio_ready = 1;
    true
}

extern "C" fn net_worker_entry(pair_raw: u64, _arg1: u64) -> ! {
    let pair = pair_raw as usize;
    if pair >= QUEUE_PAIR_COUNT {
        park_forever();
    }

    NET_WORKER_CPUS[pair].store(current_cpu_apic_id(), Ordering::Release);
    let ready_irq = NET_READY_IRQS[pair].load(Ordering::Acquire) as zx_handle_t;
    let tx_irq = NET_TX_IRQS[pair].load(Ordering::Acquire) as zx_handle_t;
    let rx_irq = NET_RX_IRQS[pair].load(Ordering::Acquire) as zx_handle_t;
    let reg_base = NET_REG_DEVICE_BASE.load(Ordering::Acquire);
    let queue_base = NET_QUEUE_BASE.load(Ordering::Acquire);
    let queue_iova = NET_QUEUE_IOVA.load(Ordering::Acquire);

    fence(Ordering::SeqCst);
    let _ = ax_interrupt_trigger(ready_irq, 1);

    let mut observed: zx_signals_t = 0;
    let wait_status = zx_object_wait_one(
        tx_irq,
        ZX_INTERRUPT_SIGNALED,
        wait_deadline(),
        &mut observed,
    );
    NET_WORKER_WAIT_KICK_STATUS[pair].store(wait_status as i64 as u64, Ordering::Release);
    if wait_status != ZX_OK {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_WORKER_WAIT_KICK, Ordering::Release);
        park_forever();
    }
    let ack_status = zx_interrupt_ack(tx_irq);
    NET_WORKER_ACK_KICK_STATUS[pair].store(ack_status as i64 as u64, Ordering::Release);
    if ack_status != ZX_OK {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_WORKER_ACK_KICK, Ordering::Release);
        park_forever();
    }

    fence(Ordering::SeqCst);
    let header = read_header(reg_base);
    let queue_regs = read_queue_regs(reg_base, pair);
    let expected_status = MMIO_STATUS_ACKNOWLEDGE
        | MMIO_STATUS_DRIVER
        | MMIO_STATUS_FEATURES_OK
        | MMIO_STATUS_DRIVER_OK;
    if header.driver_features != MMIO_FEATURE_CSUM
        || header.status != expected_status
        || header.queue_pairs != QUEUE_PAIR_COUNT as u32
        || header.queue_size != QUEUE_SIZE as u32
        || queue_regs.tx_queue_ready != 1
        || queue_regs.rx_queue_ready != 1
        || queue_regs.tx_desc_addr == 0
        || queue_regs.tx_avail_addr == 0
        || queue_regs.tx_used_addr == 0
        || queue_regs.rx_desc_addr == 0
        || queue_regs.rx_avail_addr == 0
        || queue_regs.rx_used_addr == 0
    {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_MMIO_READY, Ordering::Release);
        park_forever();
    }

    let mut queue_regs = queue_regs;
    queue_regs.notify_value = tx_queue_notify_value(pair);
    queue_regs.tx_notify_count = queue_regs.tx_notify_count.saturating_add(1);
    write_queue_regs(reg_base, pair, queue_regs);

    let Some(tx_desc_base) = map_dma_addr(queue_base, queue_iova, queue_regs.tx_desc_addr) else {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_MMIO_READY, Ordering::Release);
        park_forever();
    };
    let Some(tx_avail_base) = map_dma_addr(queue_base, queue_iova, queue_regs.tx_avail_addr) else {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_MMIO_READY, Ordering::Release);
        park_forever();
    };
    let Some(tx_used_base) = map_dma_addr(queue_base, queue_iova, queue_regs.tx_used_addr) else {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_MMIO_READY, Ordering::Release);
        park_forever();
    };
    let Some(rx_desc_base) = map_dma_addr(queue_base, queue_iova, queue_regs.rx_desc_addr) else {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_MMIO_READY, Ordering::Release);
        park_forever();
    };
    let Some(rx_avail_base) = map_dma_addr(queue_base, queue_iova, queue_regs.rx_avail_addr) else {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_MMIO_READY, Ordering::Release);
        park_forever();
    };
    let Some(rx_used_base) = map_dma_addr(queue_base, queue_iova, queue_regs.rx_used_addr) else {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_MMIO_READY, Ordering::Release);
        park_forever();
    };
    let tx_avail = read_avail_at(tx_avail_base);
    let rx_avail = read_avail_at(rx_avail_base);
    if tx_avail.idx != QUEUE_SIZE as u16 || rx_avail.idx != QUEUE_SIZE as u16 {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_WORKER_WAIT_KICK, Ordering::Release);
        park_forever();
    }

    let mut tx_used = empty_used();
    let mut rx_used = empty_used();
    tx_used.idx = QUEUE_SIZE as u16;
    rx_used.idx = QUEUE_SIZE as u16;

    for slot in 0..QUEUE_SIZE {
        let tx_head = tx_avail.ring[slot];
        let rx_head = rx_avail.ring[slot];
        let tx_desc = read_desc_at(tx_desc_base, usize::from(tx_head));
        let rx_desc = read_desc_at(rx_desc_base, usize::from(rx_head));
        let tx_offset = tx_desc.addr.saturating_sub(queue_iova);
        let rx_offset = rx_desc.addr.saturating_sub(queue_iova);
        if tx_offset >= QUEUE_VMO_BYTES || rx_offset >= QUEUE_VMO_BYTES {
            NET_WORKER_FAILURE_STEP[pair].store(STEP_WORKER_WAIT_KICK, Ordering::Release);
            park_forever();
        }
        let copy_len = core::cmp::min(tx_desc.len, rx_desc.len);
        copy_frame(
            queue_base + tx_offset,
            queue_base + rx_offset,
            copy_len as usize,
        );
        tx_used.ring[slot] = VirtqUsedElem {
            id: u32::from(tx_head),
            len: copy_len,
        };
        rx_used.ring[slot] = VirtqUsedElem {
            id: u32::from(rx_head),
            len: copy_len,
        };
    }
    write_used_at(tx_used_base, tx_used);
    write_used_at(rx_used_base, rx_used);

    queue_regs = read_queue_regs(reg_base, pair);
    queue_regs.notify_value = rx_queue_notify_value(pair);
    queue_regs.interrupt_status |= MMIO_INTERRUPT_RX_COMPLETE;
    queue_regs.rx_complete_count = queue_regs.rx_complete_count.saturating_add(1);
    write_queue_regs(reg_base, pair, queue_regs);

    fence(Ordering::SeqCst);
    let trigger_status = ax_interrupt_trigger(rx_irq, 1);
    NET_WORKER_TRIGGER_RX_STATUS[pair].store(trigger_status as i64 as u64, Ordering::Release);
    if trigger_status != ZX_OK {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_WORKER_TRIGGER_RX, Ordering::Release);
    }
    park_forever()
}

fn init_transport_memory(mapped_queue_base: u64) {
    for pair in 0..QUEUE_PAIR_COUNT {
        zero_page(mapped_queue_base + tx_queue_offset(pair));
        zero_page(mapped_queue_base + tx_buffer_offset(pair));
        zero_page(mapped_queue_base + rx_queue_offset(pair));
        zero_page(mapped_queue_base + rx_buffer_offset(pair));
    }
}

fn prepare_tx_packets(mapped_queue_base: u64, queue_iova: u64) {
    for pair in 0..QUEUE_PAIR_COUNT {
        let mut tx_avail = empty_avail();
        tx_avail.idx = QUEUE_SIZE as u16;
        for slot in 0..QUEUE_SIZE {
            tx_avail.ring[slot] = slot as u16;
            write_desc(
                mapped_queue_base,
                tx_queue_offset(pair),
                slot,
                VirtqDesc {
                    addr: buffer_paddr(queue_iova, tx_buffer_offset(pair), slot),
                    len: frame_len(PACKET_PAYLOAD_BYTES) as u32,
                    flags: 0,
                    next: 0,
                },
            );
            write_header_block(
                mapped_queue_base + buffer_offset(tx_buffer_offset(pair), slot),
                VirtioNetHdr::default(),
            );
            let payload = payload_for(pair, slot);
            write_bytes(
                mapped_queue_base
                    + buffer_offset(tx_buffer_offset(pair), slot)
                    + frame_header_bytes(),
                &payload,
            );
        }
        write_avail(mapped_queue_base, tx_queue_offset(pair), tx_avail);
        write_used(mapped_queue_base, tx_queue_offset(pair), empty_used());
    }
}

fn prepare_rx_buffers(mapped_queue_base: u64, queue_iova: u64) {
    for pair in 0..QUEUE_PAIR_COUNT {
        let mut rx_avail = empty_avail();
        rx_avail.idx = QUEUE_SIZE as u16;
        for slot in 0..QUEUE_SIZE {
            rx_avail.ring[slot] = slot as u16;
            write_desc(
                mapped_queue_base,
                rx_queue_offset(pair),
                slot,
                VirtqDesc {
                    addr: buffer_paddr(queue_iova, rx_buffer_offset(pair), slot),
                    len: frame_len(PACKET_PAYLOAD_BYTES) as u32,
                    flags: 0,
                    next: 0,
                },
            );
            zero_bytes(
                mapped_queue_base + buffer_offset(rx_buffer_offset(pair), slot),
                BUFFER_STRIDE as usize,
            );
        }
        write_avail(mapped_queue_base, rx_queue_offset(pair), rx_avail);
        write_used(mapped_queue_base, rx_queue_offset(pair), empty_used());
    }
}

fn payload_for(pair: usize, slot: usize) -> [u8; PACKET_PAYLOAD_BYTES] {
    let mut payload = PAYLOAD_TEMPLATE;
    let tag = (pair * QUEUE_SIZE + slot) as u8;
    payload[0] = payload[0].wrapping_add(tag);
    payload[PACKET_PAYLOAD_BYTES - 1] ^= tag;
    payload
}

fn count_packet_matches(mapped_queue_base: u64) -> usize {
    let mut matches = 0;
    for pair in 0..QUEUE_PAIR_COUNT {
        for slot in 0..QUEUE_SIZE {
            let mut received = [0u8; PACKET_PAYLOAD_BYTES];
            read_bytes(
                mapped_queue_base
                    + buffer_offset(rx_buffer_offset(pair), slot)
                    + frame_header_bytes(),
                &mut received,
            );
            if received == payload_for(pair, slot) {
                matches += 1;
            }
        }
    }
    matches
}

fn write_header_block(addr: u64, header: VirtioNetHdr) {
    // SAFETY: `addr` points at one writable header slot inside the mapped shared buffer window.
    unsafe { ptr::write_volatile(addr as *mut VirtioNetHdr, header) }
}

fn write_bytes(addr: u64, bytes: &[u8]) {
    for (index, byte) in bytes.iter().enumerate() {
        // SAFETY: the destination lies inside writable shared buffer memory and is initialized before publication.
        unsafe { ptr::write_volatile((addr as *mut u8).add(index), *byte) }
    }
}

fn read_bytes(addr: u64, out: &mut [u8]) {
    for (index, byte) in out.iter_mut().enumerate() {
        // SAFETY: the source lies inside readable shared buffer memory and is consumed after completion publication.
        *byte = unsafe { ptr::read_volatile((addr as *const u8).add(index)) };
    }
}

fn copy_frame(src: u64, dst: u64, len: usize) {
    for index in 0..len {
        // SAFETY: both source and destination lie inside the mapped shared queue/buffer pages.
        let value = unsafe { ptr::read_volatile((src as *const u8).add(index)) };
        // SAFETY: see above.
        unsafe { ptr::write_volatile((dst as *mut u8).add(index), value) };
    }
}

fn zero_bytes(addr: u64, len: usize) {
    for index in 0..len {
        // SAFETY: the queue/buffer memory stays mapped writable for the full duration of the bootstrap smoke.
        unsafe { ptr::write_volatile((addr as *mut u8).add(index), 0) }
    }
}

fn zero_page(addr: u64) {
    zero_bytes(addr, PAGE_SIZE as usize);
}

fn discover_pci_transport(mapped_base: u64) -> Option<VirtioPciDiscovery> {
    // SAFETY: the exported config alias is one fixed read-only byte span.
    let bytes =
        unsafe { core::slice::from_raw_parts(mapped_base as *const u8, CONFIG_VMO_BYTES as usize) };
    axle_virtio_transport::discover_pci_transport(bytes)
}

fn init_regs(mapped_base: u64) {
    write_regs(mapped_base, axle_virtio_transport::initial_regs());
}

fn driver_select_queue(mapped_base: u64, queue_index: usize) {
    let mut regs = read_regs(mapped_base);
    axle_virtio_transport::driver_select_queue(&mut regs, queue_index);
    write_regs(mapped_base, regs);
}

fn driver_program_queue(
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

fn read_header(mapped_base: u64) -> VirtioMmioHeader {
    read_transport_header(&read_regs(mapped_base))
}

fn write_header(mapped_base: u64, header: VirtioMmioHeader) {
    let mut regs = read_regs(mapped_base);
    axle_virtio_transport::write_header(&mut regs, header);
    write_regs(mapped_base, regs);
}

fn read_queue_regs(mapped_base: u64, pair: usize) -> VirtioQueueRegs {
    read_transport_queue_regs(&read_regs(mapped_base), pair)
}

fn write_queue_regs(mapped_base: u64, pair: usize, queue_regs: VirtioQueueRegs) {
    let mut regs = read_regs(mapped_base);
    axle_virtio_transport::write_queue_regs(&mut regs, pair, queue_regs);
    write_regs(mapped_base, regs);
}

fn read_regs(mapped_base: u64) -> VirtioPciRegs {
    // SAFETY: the BAR0 control window contains one packed register image.
    unsafe { ptr::read_volatile(mapped_base as *const VirtioPciRegs) }
}

fn write_regs(mapped_base: u64, regs: VirtioPciRegs) {
    // SAFETY: bootstrap setup and queue owners write the packed BAR0 image only at explicit handoff points.
    unsafe { ptr::write_volatile(mapped_base as *mut VirtioPciRegs, regs) }
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

fn write_desc(mapped_base: u64, queue_offset: u64, desc_index: usize, desc: VirtqDesc) {
    // SAFETY: the descriptor table lives in mapped shared memory and each slot is written by one owner before publication.
    unsafe { ptr::write_volatile(queue_desc_ptr(mapped_base, queue_offset, desc_index), desc) }
}

fn read_desc_at(desc_base: u64, desc_index: usize) -> VirtqDesc {
    // SAFETY: the descriptor table base is a mapped shared-memory address and readers only access published slots.
    unsafe { ptr::read_volatile((desc_base as *const VirtqDesc).add(desc_index)) }
}

fn write_avail(mapped_base: u64, queue_offset: u64, avail: VirtqAvail) {
    // SAFETY: the avail ring header lives in mapped shared memory and is single-writer from the driver side.
    unsafe { ptr::write_volatile(queue_avail_ptr(mapped_base, queue_offset), avail) }
}

fn read_avail_at(avail_base: u64) -> VirtqAvail {
    // SAFETY: the avail ring header base is a mapped shared-memory address and readers use it after publish.
    unsafe { ptr::read_volatile(avail_base as *const VirtqAvail) }
}

fn write_used(mapped_base: u64, queue_offset: u64, used: VirtqUsed) {
    // SAFETY: the used ring header lives in mapped shared memory and is single-writer from the device side.
    unsafe { ptr::write_volatile(queue_used_ptr(mapped_base, queue_offset), used) }
}

fn read_used(mapped_base: u64, queue_offset: u64) -> VirtqUsed {
    // SAFETY: the used ring header lives in mapped shared memory and is read after completion publication.
    unsafe { ptr::read_volatile(queue_used_ptr(mapped_base, queue_offset)) }
}

fn write_used_at(used_base: u64, used: VirtqUsed) {
    // SAFETY: the used ring header base is a mapped shared-memory address and the device side is the only writer.
    unsafe { ptr::write_volatile(used_base as *mut VirtqUsed, used) }
}

fn aggregate_status(dst: &mut i64, status: i64) {
    if *dst == 0 && status != ZX_OK as i64 {
        *dst = status;
    }
}

fn current_cpu_apic_id() -> u64 {
    u64::from((__cpuid(1).ebx >> 24) & 0xff)
}

fn worker_stack_top(pair: usize) -> u64 {
    // SAFETY: each dedicated stack belongs to one worker and is passed to `zx_thread_start` once per run.
    let base = unsafe { ptr::addr_of_mut!(NET_WORKER_STACKS[pair].0) as *mut u8 as usize };
    (base + WORKER_STACK_BYTES) as u64
}

fn zx_vmar_map_local(
    vmar: zx_handle_t,
    options: u32,
    vmar_offset: u64,
    vmo: zx_handle_t,
    vmo_offset: u64,
    len: u64,
    mapped_addr: &mut u64,
) -> zx_status_t {
    native_syscall8(
        AXLE_SYS_VMAR_MAP as u64,
        [
            vmar,
            options as u64,
            vmar_offset,
            vmo,
            vmo_offset,
            len,
            mapped_addr as *mut u64 as u64,
            0,
        ],
    )
}

fn wait_deadline() -> i64 {
    read_slot(SLOT_T0_NS)
        .saturating_add(WAIT_TIMEOUT_NS)
        .min(i64::MAX as u64) as i64
}

fn close_workers_and_handles(
    worker_threads: &[zx_handle_t],
    handle_sets: &[&[zx_handle_t]],
    singles: &[zx_handle_t],
) {
    for &worker_thread in worker_threads {
        if worker_thread != ZX_HANDLE_INVALID {
            let _ = zx_task_kill(worker_thread);
            let mut observed: zx_signals_t = 0;
            let _ = zx_object_wait_one(
                worker_thread,
                ZX_TASK_TERMINATED,
                wait_deadline(),
                &mut observed,
            );
            let _ = zx_handle_close(worker_thread);
        }
    }
    close_handle_sets(handle_sets, singles);
}

fn close_handle_sets(handle_sets: &[&[zx_handle_t]], singles: &[zx_handle_t]) {
    for handles in handle_sets {
        close_handles(handles);
    }
    close_handles(singles);
}

fn close_handles(handles: &[zx_handle_t]) {
    for &handle in handles {
        if handle != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(handle);
        }
    }
}

fn park_forever() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

fn write_summary(summary: &NetSummary) {
    write_slot(SLOT_NET_PRESENT, 1);
    write_slot(SLOT_NET_FAILURE_STEP, summary.failure_step);
    write_slot(SLOT_NET_READY_IRQ_CREATE, summary.ready_irq_create as u64);
    write_slot(SLOT_NET_TX_IRQ_CREATE, summary.tx_irq_create as u64);
    write_slot(SLOT_NET_RX_IRQ_CREATE, summary.rx_irq_create as u64);
    write_slot(SLOT_NET_QUEUE_VMO_CREATE, summary.queue_vmo_create as u64);
    write_slot(SLOT_NET_QUEUE_LOOKUP, summary.queue_dma_lookup as u64);
    write_slot(SLOT_NET_QUEUE_MAP, summary.queue_map as u64);
    write_slot(
        SLOT_NET_WORKER_THREAD_CREATE,
        summary.worker_thread_create as u64,
    );
    write_slot(
        SLOT_NET_WORKER_THREAD_START,
        summary.worker_thread_start as u64,
    );
    write_slot(SLOT_NET_READY_WAIT, summary.ready_wait as u64);
    write_slot(SLOT_NET_READY_ACK, summary.ready_ack as u64);
    write_slot(SLOT_NET_TX_KICK, summary.tx_kick as u64);
    write_slot(SLOT_NET_WORKER_WAIT_KICK, summary.worker_wait_kick as u64);
    write_slot(SLOT_NET_WORKER_ACK_KICK, summary.worker_ack_kick as u64);
    write_slot(SLOT_NET_WORKER_TRIGGER_RX, summary.worker_trigger_rx as u64);
    write_slot(SLOT_NET_RX_WAIT, summary.rx_wait as u64);
    write_slot(SLOT_NET_RX_ACK, summary.rx_ack as u64);
    write_slot(SLOT_NET_TX_USED_IDX, summary.tx_used_idx);
    write_slot(SLOT_NET_RX_USED_IDX, summary.rx_used_idx);
    write_slot(SLOT_NET_TX_USED_LEN, summary.tx_used_len);
    write_slot(SLOT_NET_RX_USED_LEN, summary.rx_used_len);
    write_slot(SLOT_NET_PACKET_BYTES, summary.packet_bytes);
    write_slot(SLOT_NET_PACKET_MATCH, summary.packet_match);
    write_slot(SLOT_NET_DRIVER_CPU, summary.driver_cpu);
    write_slot(SLOT_NET_WORKER_CPU, summary.worker_cpu);
    write_slot(
        SLOT_NET_CONFIG_BACKING_CREATE,
        summary.config_backing_create as u64,
    );
    write_slot(SLOT_NET_CONFIG_LOOKUP, summary.config_dma_lookup as u64);
    write_slot(
        SLOT_NET_CONFIG_ALIAS_CREATE,
        summary.config_alias_create as u64,
    );
    write_slot(
        SLOT_NET_CONFIG_ALIAS_LOOKUP,
        summary.config_alias_dma_lookup as u64,
    );
    write_slot(SLOT_NET_CONFIG_ALIAS_MATCH, summary.config_alias_match);
    write_slot(SLOT_NET_CONFIG_ALIAS_MAP, summary.config_alias_map as u64);
    write_slot(
        SLOT_NET_CONFIG_BACKING_MAP,
        summary.config_backing_map as u64,
    );
    write_slot(
        SLOT_NET_REG_BACKING_CREATE,
        summary.reg_backing_create as u64,
    );
    write_slot(SLOT_NET_REG_LOOKUP, summary.reg_dma_lookup as u64);
    write_slot(SLOT_NET_REG_BACKING_MAP, summary.reg_backing_map as u64);
    write_slot(SLOT_NET_PCI_CONFIG_INFO, summary.pci_config_info as u64);
    write_slot(SLOT_NET_PCI_CONFIG_FLAGS, summary.pci_config_flags);
    write_slot(
        SLOT_NET_PCI_CONFIG_MAP_OPTIONS,
        summary.pci_config_map_options,
    );
    write_slot(SLOT_NET_PCI_CONFIG_MAP, summary.pci_config_map as u64);
    write_slot(SLOT_NET_PCI_CONFIG_CAPS_OK, summary.pci_config_caps_ok);
    write_slot(
        SLOT_NET_PCI_CONFIG_COMMON_BAR,
        summary.pci_config_common_bar,
    );
    write_slot(
        SLOT_NET_PCI_CONFIG_COMMON_OFFSET,
        summary.pci_config_common_offset,
    );
    write_slot(
        SLOT_NET_PCI_CONFIG_NOTIFY_OFFSET,
        summary.pci_config_notify_offset,
    );
    write_slot(
        SLOT_NET_PCI_CONFIG_ISR_OFFSET,
        summary.pci_config_isr_offset,
    );
    write_slot(
        SLOT_NET_PCI_CONFIG_DEVICE_OFFSET,
        summary.pci_config_device_offset,
    );
    write_slot(SLOT_NET_PCI_IRQ_MODE_INFO, summary.pci_irq_mode_info as u64);
    write_slot(SLOT_NET_PCI_IRQ_MODE_SET, summary.pci_irq_mode_set as u64);
    write_slot(SLOT_NET_PCI_IRQ_MODE_FLAGS, summary.pci_irq_mode_flags);
    write_slot(
        SLOT_NET_PCI_IRQ_MODE_BASE_VECTOR,
        summary.pci_irq_mode_base_vector,
    );
    write_slot(
        SLOT_NET_PCI_IRQ_MODE_VECTOR_COUNT,
        summary.pci_irq_mode_vector_count,
    );
    write_slot(SLOT_NET_BAR0_CREATE, summary.bar0_create as u64);
    write_slot(SLOT_NET_BAR0_LOOKUP, summary.bar0_dma_lookup as u64);
    write_slot(SLOT_NET_BAR0_DMA_INFO, summary.bar0_dma_info as u64);
    write_slot(SLOT_NET_BAR0_DMA_FLAGS, summary.bar0_dma_flags);
    write_slot(SLOT_NET_BAR0_DMA_IOVA, summary.bar0_dma_iova);
    write_slot(SLOT_NET_BAR0_MATCH, summary.bar0_match);
    write_slot(SLOT_NET_BAR0_MAP, summary.bar0_map as u64);
    write_slot(SLOT_NET_MMIO_READY, summary.mmio_ready);
    write_slot(SLOT_NET_MMIO_DEVICE_FEATURES, summary.mmio_device_features);
    write_slot(SLOT_NET_MMIO_DRIVER_FEATURES, summary.mmio_driver_features);
    write_slot(SLOT_NET_MMIO_STATUS, summary.mmio_status);
    write_slot(SLOT_NET_QUEUE_PAIRS, summary.queue_pairs);
    write_slot(SLOT_NET_WORKER_CPU1, summary.worker_cpu1);
    write_slot(SLOT_NET_TX_NOTIFY_COUNT, summary.tx_notify_count);
    write_slot(SLOT_NET_RX_COMPLETE_COUNT, summary.rx_complete_count);
    write_slot(SLOT_NET_PACKET_COUNT, summary.packet_count);
    write_slot(SLOT_NET_PACKET_MATCH_COUNT, summary.packet_match_count);
    write_slot(SLOT_NET_BATCH_CYCLES, summary.batch_cycles);
    write_slot(SLOT_NET_TX_NOTIFY_MASK, summary.tx_notify_mask);
    write_slot(SLOT_NET_RX_COMPLETE_MASK, summary.rx_complete_mask);
    write_slot(SLOT_NET_TX_READY_MASK, summary.tx_ready_mask);
    write_slot(SLOT_NET_RX_READY_MASK, summary.rx_ready_mask);
    write_slot(SLOT_NET_PCI_VENDOR_ID, summary.pci_vendor_id);
    write_slot(SLOT_NET_REG_PIN_CREATE, summary.reg_pin_create as u64);
    write_slot(SLOT_NET_CONFIG_PIN_CREATE, summary.config_pin_create as u64);
    write_slot(
        SLOT_NET_CONFIG_ALIAS_PIN_CREATE,
        summary.config_alias_pin_create as u64,
    );
    write_slot(SLOT_NET_QUEUE_PIN_CREATE, summary.queue_pin_create as u64);
    write_slot(SLOT_NET_QUEUE_DMA_INFO, summary.queue_dma_info as u64);
    write_slot(SLOT_NET_QUEUE_DMA_FLAGS, summary.queue_dma_flags);
    write_slot(SLOT_NET_QUEUE_DMA_IOVA, summary.queue_dma_iova);
    write_slot(SLOT_NET_BAR0_PIN_CREATE, summary.bar0_pin_create as u64);
}
