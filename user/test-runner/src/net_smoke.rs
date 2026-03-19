use core::alloc::{GlobalAlloc, Layout};
use core::arch::x86_64::__cpuid;
use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering, fence};

use crate::virtio_net_transport::{
    BUFFER_STRIDE, MMIO_DEVICE_ID_NET, MMIO_FEATURE_CSUM, MMIO_INTERRUPT_RX_COMPLETE, MMIO_MAGIC,
    MMIO_STATUS_ACKNOWLEDGE, MMIO_STATUS_DRIVER, MMIO_STATUS_DRIVER_OK, MMIO_STATUS_FEATURES_OK,
    MMIO_VENDOR_ID_AXLE, MMIO_VERSION, PAGE_SIZE, PCI_CLASS_NETWORK, PCI_DEVICE_ID_NET,
    PCI_SUBCLASS_ETHERNET, PCI_VENDOR_ID_AXLE, QUEUE_PAIR_COUNT, QUEUE_SIZE, QUEUE_VMO_BYTES,
    REGISTER_VMO_BYTES, VirtioNetHdr, VirtioQueueRegs, VirtqDesc, buffer_offset, buffer_paddr,
    driver_program_queue, driver_select_queue, empty_avail, empty_used, frame_len, init_regs,
    map_dma_addr, read_avail_at, read_desc_at, read_header, read_queue_regs, read_used,
    rx_avail_paddr, rx_buffer_offset, rx_desc_paddr, rx_queue_notify_value, rx_queue_offset,
    rx_used_paddr, tx_avail_paddr, tx_buffer_offset, tx_desc_paddr, tx_queue_notify_value,
    tx_queue_offset, tx_used_paddr, write_avail, write_desc, write_header, write_queue_regs,
    write_used, write_used_at,
};
use axle_arch_x86_64::{debug_break, native_syscall8, rdtsc};
use libzircon::dma::{ZX_DMA_PERM_DEVICE_READ, ZX_DMA_PERM_DEVICE_WRITE};
use libzircon::handle::ZX_HANDLE_INVALID;
use libzircon::interrupt::{
    ZX_INTERRUPT_INFO_FLAG_TRIGGERABLE, ZX_INTERRUPT_MODE_VIRTUAL, zx_interrupt_info_t,
};
use libzircon::pci::{
    ZX_PCI_BAR_FLAG_MMIO, ZX_PCI_INTERRUPT_GROUP_READY, ZX_PCI_INTERRUPT_GROUP_RX_COMPLETE,
    ZX_PCI_INTERRUPT_GROUP_TX_KICK, zx_pci_bar_info_t, zx_pci_device_info_t,
    zx_pci_interrupt_info_t,
};
use libzircon::signals::{ZX_INTERRUPT_SIGNALED, ZX_TASK_TERMINATED};
use libzircon::status::ZX_OK;
use libzircon::syscall_numbers::AXLE_SYS_VMAR_MAP;
use libzircon::vm::{ZX_VM_MAP_MMIO, ZX_VM_PERM_READ, ZX_VM_PERM_WRITE};
use libzircon::{
    ax_dma_region_lookup_iova, ax_interrupt_trigger, ax_pci_device_get_bar, ax_pci_device_get_info,
    ax_pci_device_get_interrupt, ax_vmo_pin, zx_handle_close, zx_handle_t, zx_interrupt_ack,
    zx_interrupt_get_info, zx_object_wait_one, zx_signals_t, zx_status_t, zx_task_kill,
    zx_thread_create, zx_thread_start, zx_vmo_create_contiguous,
};

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;
const SLOT_OK: usize = 0;
const SLOT_ROOT_VMAR_H: usize = 62;
const SLOT_SELF_PROCESS_H: usize = 396;
const SLOT_BOOTSTRAP_NET_PCI_DEVICE_H: usize = 648;
const SLOT_T0_NS: usize = 511;

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

const STEP_PANIC: u64 = u64::MAX;
const STEP_ROOT_VMAR: u64 = 1;
const STEP_SELF_PROCESS: u64 = 2;
const STEP_READY_IRQ_CREATE: u64 = 3;
const STEP_TX_IRQ_CREATE: u64 = 4;
const STEP_RX_IRQ_CREATE: u64 = 5;
const STEP_REG_BACKING_MAP: u64 = 9;
const STEP_CONFIG_BACKING_CREATE: u64 = 10;
const STEP_CONFIG_PIN_CREATE: u64 = 11;
const STEP_CONFIG_ALIAS_DMA_LOOKUP: u64 = 15;
const STEP_QUEUE_VMO_CREATE: u64 = 18;
const STEP_QUEUE_PIN_CREATE: u64 = 19;
const STEP_QUEUE_DMA_LOOKUP: u64 = 20;
const STEP_QUEUE_MAP: u64 = 21;
const STEP_BAR0_CREATE: u64 = 22;
const STEP_BAR0_PIN_CREATE: u64 = 23;
const STEP_BAR0_DMA_LOOKUP: u64 = 24;
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

const WAIT_TIMEOUT_NS: u64 = 5_000_000_000;
const WORKER_STACK_BYTES: usize = 4096;
const HEAP_BYTES: usize = 16 * 1024;
const PACKET_COUNT: usize = QUEUE_PAIR_COUNT * QUEUE_SIZE;

const PAYLOAD_TEMPLATE: [u8; 32] = *b"axle-net-smoke-loopback-packet!!";
const PACKET_PAYLOAD_BYTES: usize = PAYLOAD_TEMPLATE.len();

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct WorkerStack([u8; WORKER_STACK_BYTES]);
#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
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
    queue_map: i64,
    bar0_create: i64,
    bar0_pin_create: i64,
    bar0_dma_lookup: i64,
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
static NET_QUEUE_PADDR: AtomicU64 = AtomicU64::new(0);
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
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);

const OWNED_PCI_DEVICE: usize = 0;
const OWNED_QUEUE_VMO: usize = 1;
const OWNED_QUEUE_DMA: usize = 2;
const OWNED_BAR0_VMO: usize = 3;
const OWNED_BAR0_DMA: usize = 4;
const OWNED_HANDLE_COUNT: usize = 5;

// SAFETY: this allocator serves only the single-process bootstrap smoke. It
// monotonically carves aligned ranges from one fixed static buffer and never
// reuses freed memory.
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align_mask = layout.align().saturating_sub(1);
        let size = layout.size();
        let mut current = HEAP_NEXT.load(Ordering::Relaxed);

        loop {
            let aligned = (current + align_mask) & !align_mask;
            let Some(next) = aligned.checked_add(size) else {
                return ptr::null_mut();
            };
            if next > HEAP_BYTES {
                return ptr::null_mut();
            }
            match HEAP_NEXT.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // SAFETY: the bump pointer hands out one unique,
                    // non-overlapping slice inside the dedicated static heap.
                    let base = unsafe { ptr::addr_of_mut!(HEAP.0).cast::<u8>() as usize };
                    return (base + aligned) as *mut u8;
                }
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_start() -> ! {
    let summary = run_net_smoke();
    write_summary(&summary);
    write_slot(SLOT_OK, 1);
    debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    write_slot(SLOT_NET_PRESENT, 1);
    write_slot(SLOT_NET_FAILURE_STEP, STEP_PANIC);
    write_slot(SLOT_OK, 1);
    debug_break()
}

fn run_net_smoke() -> NetSummary {
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

    let mut pci_info = zx_pci_device_info_t::default();
    summary.config_pin_create =
        ax_pci_device_get_info(owned_handles[OWNED_PCI_DEVICE], &mut pci_info) as i64;
    if summary.config_pin_create != ZX_OK as i64 {
        summary.failure_step = STEP_CONFIG_PIN_CREATE;
        close_handle_sets(&[], &owned_handles);
        return summary;
    }
    summary.pci_vendor_id = u64::from(pci_info.vendor_id);
    summary.config_alias_match = u64::from(
        pci_info.vendor_id == PCI_VENDOR_ID_AXLE
            && pci_info.device_id == PCI_DEVICE_ID_NET
            && pci_info.class_code == PCI_CLASS_NETWORK
            && pci_info.subclass == PCI_SUBCLASS_ETHERNET
            && pci_info.device_features == MMIO_FEATURE_CSUM
            && pci_info.queue_pairs == QUEUE_PAIR_COUNT as u32
            && pci_info.queue_size == QUEUE_SIZE as u32
            && pci_info.bar_count == 1,
    );
    if summary.config_alias_match != 1 {
        summary.failure_step = STEP_CONFIG_ALIAS_DMA_LOOKUP;
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
    summary.bar0_create =
        ax_pci_device_get_bar(owned_handles[OWNED_PCI_DEVICE], 0, &mut pci_bar) as i64;
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

    let mut bar0_paddr = 0u64;
    summary.bar0_dma_lookup =
        ax_dma_region_lookup_iova(owned_handles[OWNED_BAR0_DMA], 0, &mut bar0_paddr) as i64;
    if summary.bar0_dma_lookup != ZX_OK as i64 {
        summary.failure_step = STEP_BAR0_DMA_LOOKUP;
        close_handle_sets(&[&rx_irqs, &tx_irqs, &ready_irqs], &owned_handles);
        return summary;
    }
    summary.bar0_match = u64::from(
        pci_bar.size == REGISTER_VMO_BYTES
            && bar0_paddr != 0
            && (pci_bar.flags & ZX_PCI_BAR_FLAG_MMIO) != 0
            && (pci_bar.map_options & ZX_VM_MAP_MMIO) != 0,
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

    let mut queue_paddr = 0u64;
    summary.queue_dma_lookup =
        ax_dma_region_lookup_iova(owned_handles[OWNED_QUEUE_DMA], 0, &mut queue_paddr) as i64;
    if summary.queue_dma_lookup != ZX_OK as i64 {
        summary.failure_step = STEP_QUEUE_DMA_LOOKUP;
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

    let reg_driver_base = match map_driver_bar0(root_vmar, pci_bar, &mut summary, &owned_handles) {
        Some(base) => base,
        None => {
            close_handle_sets(&[&rx_irqs, &tx_irqs, &ready_irqs], &owned_handles);
            return summary;
        }
    };

    NET_REG_DEVICE_BASE.store(reg_device_base, Ordering::Release);
    NET_QUEUE_BASE.store(mapped_queue_base, Ordering::Release);
    NET_QUEUE_PADDR.store(queue_paddr, Ordering::Release);
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

    for &ready_irq in &ready_irqs {
        let mut observed: zx_signals_t = 0;
        let status = zx_object_wait_one(
            ready_irq,
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
    }

    for &ready_irq in &ready_irqs {
        let status = zx_interrupt_ack(ready_irq) as i64;
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

    if !configure_driver_transport(reg_driver_base, &mut summary, pci_info, queue_paddr) {
        summary.failure_step = STEP_MMIO_READY;
        close_workers_and_handles(
            &worker_threads,
            &[&rx_irqs, &tx_irqs, &ready_irqs],
            &owned_handles,
        );
        return summary;
    }

    prepare_tx_packets(mapped_queue_base, queue_paddr);
    prepare_rx_buffers(mapped_queue_base, queue_paddr);
    fence(Ordering::SeqCst);

    let batch_start = rdtsc();
    for &tx_irq in &tx_irqs {
        let status = ax_interrupt_trigger(tx_irq, QUEUE_SIZE as u64) as i64;
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
        let mut observed: zx_signals_t = 0;
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
    summary.batch_cycles = rdtsc().wrapping_sub(batch_start);

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

    fence(Ordering::SeqCst);
    for pair in 0..QUEUE_PAIR_COUNT {
        summary.worker_cpu = NET_WORKER_CPUS[0].load(Ordering::Acquire);
        summary.worker_cpu1 = NET_WORKER_CPUS[1].load(Ordering::Acquire);
        aggregate_status(
            &mut summary.worker_wait_kick,
            NET_WORKER_WAIT_KICK_STATUS[pair].load(Ordering::Acquire) as i64,
        );
        aggregate_status(
            &mut summary.worker_ack_kick,
            NET_WORKER_ACK_KICK_STATUS[pair].load(Ordering::Acquire) as i64,
        );
        aggregate_status(
            &mut summary.worker_trigger_rx,
            NET_WORKER_TRIGGER_RX_STATUS[pair].load(Ordering::Acquire) as i64,
        );
    }

    let header = read_header(reg_driver_base);
    summary.mmio_device_features = header.device_features as u64;
    summary.mmio_driver_features = header.driver_features as u64;
    summary.mmio_status = header.status as u64;
    summary.queue_pairs = header.queue_pairs as u64;
    for pair in 0..QUEUE_PAIR_COUNT {
        let queue_regs = read_queue_regs(reg_driver_base, pair);
        if queue_regs.tx_queue_ready != 0 {
            summary.tx_ready_mask |= 1u64 << pair;
        }
        if queue_regs.rx_queue_ready != 0 {
            summary.rx_ready_mask |= 1u64 << pair;
        }
        if queue_regs.tx_notify_count != 0 {
            summary.tx_notify_mask |= 1u64 << pair;
        }
        if queue_regs.rx_complete_count != 0
            || (queue_regs.interrupt_status & MMIO_INTERRUPT_RX_COMPLETE) != 0
        {
            summary.rx_complete_mask |= 1u64 << pair;
        }
        summary.tx_notify_count = summary
            .tx_notify_count
            .saturating_add(queue_regs.tx_notify_count as u64);
        summary.rx_complete_count = summary
            .rx_complete_count
            .saturating_add(queue_regs.rx_complete_count as u64);

        let tx_used = read_used(mapped_queue_base, tx_queue_offset(pair));
        let rx_used = read_used(mapped_queue_base, rx_queue_offset(pair));
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

fn map_driver_bar0(
    root_vmar: zx_handle_t,
    bar: zx_pci_bar_info_t,
    summary: &mut NetSummary,
    owned_handles: &[zx_handle_t; OWNED_HANDLE_COUNT],
) -> Option<u64> {
    if bar.handle == ZX_HANDLE_INVALID || bar.size != REGISTER_VMO_BYTES {
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

    Some(bar0_driver_base)
}

fn configure_driver_transport(
    reg_base: u64,
    summary: &mut NetSummary,
    info: zx_pci_device_info_t,
    queue_paddr: u64,
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
        driver_select_queue(reg_base, crate::virtio_net_transport::tx_queue_index(pair));
        driver_program_queue(
            reg_base,
            crate::virtio_net_transport::tx_queue_index(pair),
            tx_desc_paddr(queue_paddr, pair),
            tx_avail_paddr(queue_paddr, pair),
            tx_used_paddr(queue_paddr, pair),
        );
        driver_select_queue(reg_base, crate::virtio_net_transport::rx_queue_index(pair));
        driver_program_queue(
            reg_base,
            crate::virtio_net_transport::rx_queue_index(pair),
            rx_desc_paddr(queue_paddr, pair),
            rx_avail_paddr(queue_paddr, pair),
            rx_used_paddr(queue_paddr, pair),
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
    let queue_paddr = NET_QUEUE_PADDR.load(Ordering::Acquire);

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

    let Some(tx_desc_base) = map_dma_addr(queue_base, queue_paddr, queue_regs.tx_desc_addr) else {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_MMIO_READY, Ordering::Release);
        park_forever();
    };
    let Some(tx_avail_base) = map_dma_addr(queue_base, queue_paddr, queue_regs.tx_avail_addr)
    else {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_MMIO_READY, Ordering::Release);
        park_forever();
    };
    let Some(tx_used_base) = map_dma_addr(queue_base, queue_paddr, queue_regs.tx_used_addr) else {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_MMIO_READY, Ordering::Release);
        park_forever();
    };
    let Some(rx_desc_base) = map_dma_addr(queue_base, queue_paddr, queue_regs.rx_desc_addr) else {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_MMIO_READY, Ordering::Release);
        park_forever();
    };
    let Some(rx_avail_base) = map_dma_addr(queue_base, queue_paddr, queue_regs.rx_avail_addr)
    else {
        NET_WORKER_FAILURE_STEP[pair].store(STEP_MMIO_READY, Ordering::Release);
        park_forever();
    };
    let Some(rx_used_base) = map_dma_addr(queue_base, queue_paddr, queue_regs.rx_used_addr) else {
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
        let tx_offset = tx_desc.addr.saturating_sub(queue_paddr);
        let rx_offset = rx_desc.addr.saturating_sub(queue_paddr);
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
        tx_used.ring[slot] = crate::virtio_net_transport::VirtqUsedElem {
            id: u32::from(tx_head),
            len: copy_len,
        };
        rx_used.ring[slot] = crate::virtio_net_transport::VirtqUsedElem {
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

fn prepare_tx_packets(mapped_queue_base: u64, queue_paddr: u64) {
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
                    addr: buffer_paddr(queue_paddr, tx_buffer_offset(pair), slot),
                    len: frame_len(PACKET_PAYLOAD_BYTES) as u32,
                    flags: 0,
                    next: 0,
                },
            );
            write_header_block(
                mapped_queue_base + buffer_offset(tx_buffer_offset(pair), slot),
                VirtioNetHdr {
                    flags: 0,
                    gso_type: 0,
                    hdr_len: 0,
                    gso_size: 0,
                    csum_start: 0,
                    csum_offset: 0,
                },
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

fn prepare_rx_buffers(mapped_queue_base: u64, queue_paddr: u64) {
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
                    addr: buffer_paddr(queue_paddr, rx_buffer_offset(pair), slot),
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

fn frame_header_bytes() -> u64 {
    core::mem::size_of::<VirtioNetHdr>() as u64
}

fn write_header_block(addr: u64, header: VirtioNetHdr) {
    // SAFETY: `addr` points at one writable header slot inside the mapped
    // shared buffer window, and we copy plain bytes without aliases.
    unsafe { ptr::write_volatile(addr as *mut VirtioNetHdr, header) }
}

fn write_bytes(addr: u64, bytes: &[u8]) {
    for (index, byte) in bytes.iter().enumerate() {
        // SAFETY: the destination lies inside writable shared buffer memory,
        // and each byte is initialized before the descriptor is published.
        unsafe { ptr::write_volatile((addr as *mut u8).add(index), *byte) }
    }
}

fn read_bytes(addr: u64, out: &mut [u8]) {
    for (index, byte) in out.iter_mut().enumerate() {
        // SAFETY: the source lies inside readable shared buffer memory and is
        // consumed only after completion publication.
        *byte = unsafe { ptr::read_volatile((addr as *const u8).add(index)) };
    }
}

fn copy_frame(src: u64, dst: u64, len: usize) {
    for index in 0..len {
        // SAFETY: both source and destination lie inside the mapped shared
        // queue/buffer pages owned by this smoke transport.
        let value = unsafe { ptr::read_volatile((src as *const u8).add(index)) };
        // SAFETY: see above; the device side publishes the copied bytes before
        // signaling completion.
        unsafe { ptr::write_volatile((dst as *mut u8).add(index), value) };
    }
}

fn zero_bytes(addr: u64, len: usize) {
    for index in 0..len {
        // SAFETY: the queue/buffer memory stays mapped writable for the full
        // duration of the smoke.
        unsafe { ptr::write_volatile((addr as *mut u8).add(index), 0) }
    }
}

fn zero_page(addr: u64) {
    zero_bytes(addr, PAGE_SIZE as usize);
}

fn aggregate_status(dst: &mut i64, status: i64) {
    if *dst == 0 && status != ZX_OK as i64 {
        *dst = status;
    }
}

fn current_cpu_apic_id() -> u64 {
    // SAFETY: CPUID leaf 1 is always available on the x86_64 bootstrap target,
    // and reading the local APIC id is side-effect free.
    u64::from((__cpuid(1).ebx >> 24) & 0xff)
}

fn worker_stack_top(pair: usize) -> u64 {
    // SAFETY: each dedicated stack belongs only to one net smoke worker and is
    // passed to `zx_thread_start` exactly once per run.
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

fn read_slot(slot: usize) -> u64 {
    let slots = USER_SHARED_BASE as *const u64;
    // SAFETY: the kernel maps the bootstrap shared summary pages at
    // `USER_SHARED_BASE`.
    unsafe { slots.add(slot).read_volatile() }
}

fn write_slot(slot: usize, value: u64) {
    let slots = USER_SHARED_BASE as *mut u64;
    // SAFETY: the kernel maps the bootstrap shared summary pages at
    // `USER_SHARED_BASE`.
    unsafe { slots.add(slot).write_volatile(value) }
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
    write_slot(SLOT_NET_BAR0_CREATE, summary.bar0_create as u64);
    write_slot(SLOT_NET_BAR0_LOOKUP, summary.bar0_dma_lookup as u64);
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
    write_slot(SLOT_NET_BAR0_PIN_CREATE, summary.bar0_pin_create as u64);
}
