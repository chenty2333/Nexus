use core::alloc::{GlobalAlloc, Layout};
use core::arch::x86_64::__cpuid;
use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering, fence};

use crate::virtio_net_transport::{
    BUFFER_STRIDE, MMIO_DEVICE_ID_NET, MMIO_FEATURE_CSUM, MMIO_INTERRUPT_RX_COMPLETE, MMIO_MAGIC,
    MMIO_NOTIFY_RX, MMIO_NOTIFY_TX, MMIO_STATUS_ACKNOWLEDGE, MMIO_STATUS_DRIVER,
    MMIO_STATUS_DRIVER_OK, MMIO_STATUS_FEATURES_OK, MMIO_VENDOR_ID_AXLE, MMIO_VERSION, PAGE_SIZE,
    QUEUE_SIZE, QUEUE_VMO_BYTES, RX_BUFFER_OFFSET, RX_QUEUE_OFFSET, TX_BUFFER_OFFSET,
    TX_QUEUE_OFFSET, VirtioMmioRegs, VirtioNetHdr, VirtqAvail, VirtqDesc, empty_avail, empty_used,
    frame_len, init_regs, read_avail, read_regs, read_used, write_avail, write_desc, write_regs,
    write_used,
};
use axle_arch_x86_64::{debug_break, native_syscall8, rdtsc};
use libzircon::handle::ZX_HANDLE_INVALID;
use libzircon::interrupt::ZX_INTERRUPT_VIRTUAL;
use libzircon::signals::{ZX_INTERRUPT_SIGNALED, ZX_TASK_TERMINATED};
use libzircon::status::ZX_OK;
use libzircon::syscall_numbers::AXLE_SYS_VMAR_MAP;
use libzircon::vm::{ZX_VM_PERM_READ, ZX_VM_PERM_WRITE};
use libzircon::{
    ax_interrupt_trigger, ax_vmo_lookup_paddr, zx_handle_close, zx_handle_t, zx_interrupt_ack,
    zx_interrupt_create, zx_object_wait_one, zx_signals_t, zx_status_t, zx_task_kill,
    zx_thread_create, zx_thread_start, zx_vmo_create_contiguous,
};

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;
const SLOT_OK: usize = 0;
const SLOT_ROOT_VMAR_H: usize = 62;
const SLOT_SELF_PROCESS_H: usize = 396;
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
const SLOT_NET_MMIO_READY: usize = 978;
const SLOT_NET_MMIO_DEVICE_FEATURES: usize = 979;
const SLOT_NET_MMIO_DRIVER_FEATURES: usize = 980;
const SLOT_NET_MMIO_STATUS: usize = 981;
const SLOT_NET_TX_NOTIFY_COUNT: usize = 982;
const SLOT_NET_RX_COMPLETE_COUNT: usize = 983;
const SLOT_NET_PACKET_COUNT: usize = 984;
const SLOT_NET_PACKET_MATCH_COUNT: usize = 985;
const SLOT_NET_BATCH_CYCLES: usize = 986;

const STEP_PANIC: u64 = u64::MAX;
const STEP_ROOT_VMAR: u64 = 1;
const STEP_SELF_PROCESS: u64 = 2;
const STEP_READY_IRQ_CREATE: u64 = 3;
const STEP_TX_IRQ_CREATE: u64 = 4;
const STEP_RX_IRQ_CREATE: u64 = 5;
const STEP_QUEUE_VMO_CREATE: u64 = 6;
const STEP_QUEUE_LOOKUP: u64 = 7;
const STEP_QUEUE_MAP: u64 = 8;
const STEP_WORKER_THREAD_CREATE: u64 = 9;
const STEP_WORKER_THREAD_START: u64 = 10;
const STEP_READY_WAIT: u64 = 11;
const STEP_READY_ACK: u64 = 12;
const STEP_MMIO_READY: u64 = 13;
const STEP_TX_KICK: u64 = 14;
const STEP_RX_WAIT: u64 = 15;
const STEP_RX_ACK: u64 = 16;
const STEP_WORKER_WAIT_KICK: u64 = 17;
const STEP_WORKER_ACK_KICK: u64 = 18;
const STEP_WORKER_TRIGGER_RX: u64 = 19;
const STEP_TX_USED: u64 = 20;
const STEP_RX_USED: u64 = 21;
const STEP_PACKET_MATCH: u64 = 22;

const WAIT_TIMEOUT_NS: u64 = 5_000_000_000;
const WORKER_STACK_BYTES: usize = 4096;
const HEAP_BYTES: usize = 16 * 1024;
const PACKET_BATCH_COUNT: usize = QUEUE_SIZE;

const PAYLOAD_TEMPLATE: [u8; 32] = *b"axle-net-smoke-loopback-packet!!";
const PACKET_PAYLOAD_BYTES: usize = PAYLOAD_TEMPLATE.len();

#[repr(C, align(16))]
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
    queue_vmo_create: i64,
    queue_lookup: i64,
    queue_map: i64,
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
    mmio_ready: u64,
    mmio_device_features: u64,
    mmio_driver_features: u64,
    mmio_status: u64,
    tx_notify_count: u64,
    rx_complete_count: u64,
}

static NET_READY_IRQ: AtomicU64 = AtomicU64::new(ZX_HANDLE_INVALID);
static NET_TX_IRQ: AtomicU64 = AtomicU64::new(ZX_HANDLE_INVALID);
static NET_RX_IRQ: AtomicU64 = AtomicU64::new(ZX_HANDLE_INVALID);
static NET_SHARED_BASE: AtomicU64 = AtomicU64::new(0);
static NET_SHARED_PADDR: AtomicU64 = AtomicU64::new(0);
static NET_WORKER_CPU: AtomicU64 = AtomicU64::new(0);
static NET_WORKER_WAIT_KICK_STATUS: AtomicU64 = AtomicU64::new(0);
static NET_WORKER_ACK_KICK_STATUS: AtomicU64 = AtomicU64::new(0);
static NET_WORKER_TRIGGER_RX_STATUS: AtomicU64 = AtomicU64::new(0);
static NET_WORKER_FAILURE_STEP: AtomicU64 = AtomicU64::new(0);
static mut NET_WORKER_STACK: WorkerStack = WorkerStack([0; WORKER_STACK_BYTES]);
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);

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
        packet_count: PACKET_BATCH_COUNT as u64,
        driver_cpu: current_cpu_apic_id(),
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

    let mut ready_irq = ZX_HANDLE_INVALID;
    summary.ready_irq_create = zx_interrupt_create(ZX_INTERRUPT_VIRTUAL, &mut ready_irq) as i64;
    if summary.ready_irq_create != ZX_OK as i64 {
        summary.failure_step = STEP_READY_IRQ_CREATE;
        return summary;
    }

    let mut tx_irq = ZX_HANDLE_INVALID;
    summary.tx_irq_create = zx_interrupt_create(ZX_INTERRUPT_VIRTUAL, &mut tx_irq) as i64;
    if summary.tx_irq_create != ZX_OK as i64 {
        summary.failure_step = STEP_TX_IRQ_CREATE;
        let _ = zx_handle_close(ready_irq);
        return summary;
    }

    let mut rx_irq = ZX_HANDLE_INVALID;
    summary.rx_irq_create = zx_interrupt_create(ZX_INTERRUPT_VIRTUAL, &mut rx_irq) as i64;
    if summary.rx_irq_create != ZX_OK as i64 {
        summary.failure_step = STEP_RX_IRQ_CREATE;
        let _ = zx_handle_close(tx_irq);
        let _ = zx_handle_close(ready_irq);
        return summary;
    }

    let mut queue_vmo = ZX_HANDLE_INVALID;
    summary.queue_vmo_create = zx_vmo_create_contiguous(QUEUE_VMO_BYTES, 0, &mut queue_vmo) as i64;
    if summary.queue_vmo_create != ZX_OK as i64 {
        summary.failure_step = STEP_QUEUE_VMO_CREATE;
        close_handles(&[rx_irq, tx_irq, ready_irq]);
        return summary;
    }

    let mut queue_paddr = 0u64;
    summary.queue_lookup = ax_vmo_lookup_paddr(queue_vmo, 0, &mut queue_paddr) as i64;
    if summary.queue_lookup != ZX_OK as i64 {
        summary.failure_step = STEP_QUEUE_LOOKUP;
        close_handles(&[queue_vmo, rx_irq, tx_irq, ready_irq]);
        return summary;
    }

    let mut mapped_addr = 0u64;
    summary.queue_map = zx_vmar_map_local(
        root_vmar,
        ZX_VM_PERM_READ | ZX_VM_PERM_WRITE,
        0,
        queue_vmo,
        0,
        QUEUE_VMO_BYTES,
        &mut mapped_addr,
    ) as i64;
    if summary.queue_map != ZX_OK as i64 {
        summary.failure_step = STEP_QUEUE_MAP;
        close_handles(&[queue_vmo, rx_irq, tx_irq, ready_irq]);
        return summary;
    }

    init_transport_memory(mapped_addr);

    NET_READY_IRQ.store(ready_irq, Ordering::Release);
    NET_TX_IRQ.store(tx_irq, Ordering::Release);
    NET_RX_IRQ.store(rx_irq, Ordering::Release);
    NET_SHARED_BASE.store(mapped_addr, Ordering::Release);
    NET_SHARED_PADDR.store(queue_paddr, Ordering::Release);
    NET_WORKER_CPU.store(0, Ordering::Release);
    NET_WORKER_WAIT_KICK_STATUS.store(0, Ordering::Release);
    NET_WORKER_ACK_KICK_STATUS.store(0, Ordering::Release);
    NET_WORKER_TRIGGER_RX_STATUS.store(0, Ordering::Release);
    NET_WORKER_FAILURE_STEP.store(0, Ordering::Release);

    let mut worker_thread = ZX_HANDLE_INVALID;
    summary.worker_thread_create = zx_thread_create(self_process, 0, &mut worker_thread) as i64;
    if summary.worker_thread_create != ZX_OK as i64 {
        summary.failure_step = STEP_WORKER_THREAD_CREATE;
        close_handles(&[queue_vmo, rx_irq, tx_irq, ready_irq]);
        return summary;
    }

    summary.worker_thread_start = zx_thread_start(
        worker_thread,
        net_worker_entry as *const () as usize as u64,
        worker_stack_top(),
        0,
        0,
    ) as i64;
    if summary.worker_thread_start != ZX_OK as i64 {
        summary.failure_step = STEP_WORKER_THREAD_START;
        close_handles(&[worker_thread, queue_vmo, rx_irq, tx_irq, ready_irq]);
        return summary;
    }

    let mut observed: zx_signals_t = 0;
    summary.ready_wait = zx_object_wait_one(
        ready_irq,
        ZX_INTERRUPT_SIGNALED,
        wait_deadline(),
        &mut observed,
    ) as i64;
    if summary.ready_wait != ZX_OK as i64 {
        summary.failure_step = STEP_READY_WAIT;
        close_worker_and_handles(worker_thread, &[queue_vmo, rx_irq, tx_irq, ready_irq]);
        return summary;
    }
    summary.ready_ack = zx_interrupt_ack(ready_irq) as i64;
    if summary.ready_ack != ZX_OK as i64 {
        summary.failure_step = STEP_READY_ACK;
        close_worker_and_handles(worker_thread, &[queue_vmo, rx_irq, tx_irq, ready_irq]);
        return summary;
    }

    if !configure_driver_transport(mapped_addr, &mut summary) {
        summary.failure_step = STEP_MMIO_READY;
        close_worker_and_handles(worker_thread, &[queue_vmo, rx_irq, tx_irq, ready_irq]);
        return summary;
    }

    prepare_tx_packets(mapped_addr, queue_paddr);
    prepare_rx_buffers(mapped_addr, queue_paddr);
    fence(Ordering::SeqCst);

    let batch_start = rdtsc();
    summary.tx_kick = ax_interrupt_trigger(tx_irq, PACKET_BATCH_COUNT as u64) as i64;
    if summary.tx_kick != ZX_OK as i64 {
        summary.failure_step = STEP_TX_KICK;
        close_worker_and_handles(worker_thread, &[queue_vmo, rx_irq, tx_irq, ready_irq]);
        return summary;
    }

    observed = 0;
    summary.rx_wait = zx_object_wait_one(
        rx_irq,
        ZX_INTERRUPT_SIGNALED,
        wait_deadline(),
        &mut observed,
    ) as i64;
    if summary.rx_wait != ZX_OK as i64 {
        summary.failure_step = STEP_RX_WAIT;
        close_worker_and_handles(worker_thread, &[queue_vmo, rx_irq, tx_irq, ready_irq]);
        return summary;
    }
    summary.batch_cycles = rdtsc().wrapping_sub(batch_start);
    summary.rx_ack = zx_interrupt_ack(rx_irq) as i64;
    if summary.rx_ack != ZX_OK as i64 {
        summary.failure_step = STEP_RX_ACK;
        close_worker_and_handles(worker_thread, &[queue_vmo, rx_irq, tx_irq, ready_irq]);
        return summary;
    }

    fence(Ordering::SeqCst);
    summary.worker_wait_kick = NET_WORKER_WAIT_KICK_STATUS.load(Ordering::Acquire) as i64;
    summary.worker_ack_kick = NET_WORKER_ACK_KICK_STATUS.load(Ordering::Acquire) as i64;
    summary.worker_trigger_rx = NET_WORKER_TRIGGER_RX_STATUS.load(Ordering::Acquire) as i64;
    summary.worker_cpu = NET_WORKER_CPU.load(Ordering::Acquire);

    let regs = read_regs(mapped_addr);
    let tx_used = read_used(mapped_addr, TX_QUEUE_OFFSET);
    let rx_used = read_used(mapped_addr, RX_QUEUE_OFFSET);
    summary.mmio_device_features = regs.device_features as u64;
    summary.mmio_driver_features = regs.driver_features as u64;
    summary.mmio_status = regs.status as u64;
    summary.tx_notify_count = regs.tx_notify_count as u64;
    summary.rx_complete_count = regs.rx_complete_count as u64;
    summary.tx_used_idx = tx_used.idx as u64;
    summary.rx_used_idx = rx_used.idx as u64;
    if tx_used.idx != 0 {
        summary.tx_used_len = tx_used.ring[usize::from(tx_used.idx - 1)].len as u64;
    }
    if rx_used.idx != 0 {
        summary.rx_used_len = rx_used.ring[usize::from(rx_used.idx - 1)].len as u64;
    }

    if summary.worker_wait_kick != ZX_OK as i64 {
        summary.failure_step = STEP_WORKER_WAIT_KICK;
    } else if summary.worker_ack_kick != ZX_OK as i64 {
        summary.failure_step = STEP_WORKER_ACK_KICK;
    } else if summary.worker_trigger_rx != ZX_OK as i64 {
        summary.failure_step = STEP_WORKER_TRIGGER_RX;
    } else if summary.tx_used_idx != PACKET_BATCH_COUNT as u64 {
        summary.failure_step = STEP_TX_USED;
    } else if summary.rx_used_idx != PACKET_BATCH_COUNT as u64 {
        summary.failure_step = STEP_RX_USED;
    } else {
        summary.packet_match_count = count_packet_matches(mapped_addr) as u64;
        summary.packet_match = u64::from(summary.packet_match_count == PACKET_BATCH_COUNT as u64);
        if summary.packet_match != 1 {
            summary.failure_step = STEP_PACKET_MATCH;
        }
    }

    let worker_failure = NET_WORKER_FAILURE_STEP.load(Ordering::Acquire);
    if summary.failure_step == 0 && worker_failure != 0 {
        summary.failure_step = worker_failure;
    }

    close_worker_and_handles(worker_thread, &[queue_vmo, rx_irq, tx_irq, ready_irq]);
    summary
}

fn configure_driver_transport(mapped_addr: u64, summary: &mut NetSummary) -> bool {
    let mut regs = read_regs(mapped_addr);
    let expected_device_features = MMIO_FEATURE_CSUM;
    if regs.magic != MMIO_MAGIC
        || regs.version != MMIO_VERSION
        || regs.device_id != MMIO_DEVICE_ID_NET
        || regs.vendor_id != MMIO_VENDOR_ID_AXLE
        || regs.device_features != expected_device_features
        || regs.tx_queue_size != QUEUE_SIZE as u32
        || regs.rx_queue_size != QUEUE_SIZE as u32
    {
        return false;
    }
    regs.driver_features = regs.device_features & MMIO_FEATURE_CSUM;
    regs.status = MMIO_STATUS_ACKNOWLEDGE
        | MMIO_STATUS_DRIVER
        | MMIO_STATUS_FEATURES_OK
        | MMIO_STATUS_DRIVER_OK;
    regs.tx_queue_ready = 1;
    regs.rx_queue_ready = 1;
    regs.queue_notify = 0;
    regs.interrupt_status = 0;
    regs.tx_notify_count = 0;
    regs.rx_complete_count = 0;
    write_regs(mapped_addr, regs);
    summary.mmio_ready = 1;
    true
}

extern "C" fn net_worker_entry(_arg0: u64, _arg1: u64) -> ! {
    NET_WORKER_CPU.store(current_cpu_apic_id(), Ordering::Release);
    let ready_irq = NET_READY_IRQ.load(Ordering::Acquire) as zx_handle_t;
    let tx_irq = NET_TX_IRQ.load(Ordering::Acquire) as zx_handle_t;
    let rx_irq = NET_RX_IRQ.load(Ordering::Acquire) as zx_handle_t;
    let mapped_base = NET_SHARED_BASE.load(Ordering::Acquire);
    let queue_paddr = NET_SHARED_PADDR.load(Ordering::Acquire);

    init_regs(mapped_base);
    fence(Ordering::SeqCst);
    let _ = ax_interrupt_trigger(ready_irq, 1);

    let mut observed: zx_signals_t = 0;
    let wait_status = zx_object_wait_one(
        tx_irq,
        ZX_INTERRUPT_SIGNALED,
        wait_deadline(),
        &mut observed,
    );
    NET_WORKER_WAIT_KICK_STATUS.store(wait_status as i64 as u64, Ordering::Release);
    if wait_status != ZX_OK {
        NET_WORKER_FAILURE_STEP.store(STEP_WORKER_WAIT_KICK, Ordering::Release);
        park_forever();
    }
    let ack_status = zx_interrupt_ack(tx_irq);
    NET_WORKER_ACK_KICK_STATUS.store(ack_status as i64 as u64, Ordering::Release);
    if ack_status != ZX_OK {
        NET_WORKER_FAILURE_STEP.store(STEP_WORKER_ACK_KICK, Ordering::Release);
        park_forever();
    }

    fence(Ordering::SeqCst);
    let mut regs = read_regs(mapped_base);
    let expected_status = MMIO_STATUS_ACKNOWLEDGE
        | MMIO_STATUS_DRIVER
        | MMIO_STATUS_FEATURES_OK
        | MMIO_STATUS_DRIVER_OK;
    if regs.driver_features != MMIO_FEATURE_CSUM
        || regs.status != expected_status
        || regs.tx_queue_ready != 1
        || regs.rx_queue_ready != 1
    {
        NET_WORKER_FAILURE_STEP.store(STEP_MMIO_READY, Ordering::Release);
        park_forever();
    }
    regs.queue_notify = MMIO_NOTIFY_TX;
    regs.tx_notify_count = regs.tx_notify_count.saturating_add(1);
    write_regs(mapped_base, regs);

    let tx_avail = read_avail(mapped_base, TX_QUEUE_OFFSET);
    let rx_avail = read_avail(mapped_base, RX_QUEUE_OFFSET);
    if tx_avail.idx != PACKET_BATCH_COUNT as u16 || rx_avail.idx != PACKET_BATCH_COUNT as u16 {
        NET_WORKER_FAILURE_STEP.store(STEP_WORKER_WAIT_KICK, Ordering::Release);
        park_forever();
    }

    let mut tx_used = empty_used();
    let mut rx_used = empty_used();
    tx_used.idx = PACKET_BATCH_COUNT as u16;
    rx_used.idx = PACKET_BATCH_COUNT as u16;

    for slot in 0..PACKET_BATCH_COUNT {
        let tx_head = tx_avail.ring[slot];
        let rx_head = rx_avail.ring[slot];
        let tx_desc = crate::virtio_net_transport::read_desc(
            mapped_base,
            TX_QUEUE_OFFSET,
            usize::from(tx_head),
        );
        let rx_desc = crate::virtio_net_transport::read_desc(
            mapped_base,
            RX_QUEUE_OFFSET,
            usize::from(rx_head),
        );
        let tx_offset = tx_desc.addr.saturating_sub(queue_paddr);
        let rx_offset = rx_desc.addr.saturating_sub(queue_paddr);
        if tx_offset >= QUEUE_VMO_BYTES || rx_offset >= QUEUE_VMO_BYTES {
            NET_WORKER_FAILURE_STEP.store(STEP_WORKER_WAIT_KICK, Ordering::Release);
            park_forever();
        }
        let copy_len = core::cmp::min(tx_desc.len, rx_desc.len);
        copy_frame(
            mapped_base + tx_offset,
            mapped_base + rx_offset,
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
    write_used(mapped_base, TX_QUEUE_OFFSET, tx_used);
    write_used(mapped_base, RX_QUEUE_OFFSET, rx_used);

    regs = read_regs(mapped_base);
    regs.queue_notify = MMIO_NOTIFY_RX;
    regs.interrupt_status |= MMIO_INTERRUPT_RX_COMPLETE;
    regs.rx_complete_count = regs.rx_complete_count.saturating_add(1);
    write_regs(mapped_base, regs);

    fence(Ordering::SeqCst);
    let trigger_status = ax_interrupt_trigger(rx_irq, 1);
    NET_WORKER_TRIGGER_RX_STATUS.store(trigger_status as i64 as u64, Ordering::Release);
    if trigger_status != ZX_OK {
        NET_WORKER_FAILURE_STEP.store(STEP_WORKER_TRIGGER_RX, Ordering::Release);
    }
    park_forever()
}

fn init_transport_memory(mapped_base: u64) {
    zero_page(mapped_base);
    zero_page(mapped_base + TX_QUEUE_OFFSET);
    zero_page(mapped_base + TX_BUFFER_OFFSET);
    zero_page(mapped_base + RX_QUEUE_OFFSET);
    zero_page(mapped_base + RX_BUFFER_OFFSET);
}

fn prepare_tx_packets(mapped_base: u64, queue_paddr: u64) {
    let mut tx_avail = empty_avail();
    tx_avail.idx = PACKET_BATCH_COUNT as u16;
    for slot in 0..PACKET_BATCH_COUNT {
        tx_avail.ring[slot] = slot as u16;
        write_desc(
            mapped_base,
            TX_QUEUE_OFFSET,
            slot,
            VirtqDesc {
                addr: crate::virtio_net_transport::buffer_paddr(
                    queue_paddr,
                    TX_BUFFER_OFFSET,
                    slot,
                ),
                len: frame_len(PACKET_PAYLOAD_BYTES) as u32,
                flags: 0,
                next: 0,
            },
        );
        write_header(
            mapped_base + crate::virtio_net_transport::buffer_offset(TX_BUFFER_OFFSET, slot),
            VirtioNetHdr {
                flags: 0,
                gso_type: 0,
                hdr_len: 0,
                gso_size: 0,
                csum_start: 0,
                csum_offset: 0,
            },
        );
        let payload = payload_for(slot);
        write_bytes(
            mapped_base
                + crate::virtio_net_transport::buffer_offset(TX_BUFFER_OFFSET, slot)
                + frame_header_bytes(),
            &payload,
        );
    }
    write_avail(mapped_base, TX_QUEUE_OFFSET, tx_avail);
    write_used(mapped_base, TX_QUEUE_OFFSET, empty_used());
}

fn prepare_rx_buffers(mapped_base: u64, queue_paddr: u64) {
    let mut rx_avail = empty_avail();
    rx_avail.idx = PACKET_BATCH_COUNT as u16;
    for slot in 0..PACKET_BATCH_COUNT {
        rx_avail.ring[slot] = slot as u16;
        write_desc(
            mapped_base,
            RX_QUEUE_OFFSET,
            slot,
            VirtqDesc {
                addr: crate::virtio_net_transport::buffer_paddr(
                    queue_paddr,
                    RX_BUFFER_OFFSET,
                    slot,
                ),
                len: frame_len(PACKET_PAYLOAD_BYTES) as u32,
                flags: 0,
                next: 0,
            },
        );
        zero_bytes(
            mapped_base + crate::virtio_net_transport::buffer_offset(RX_BUFFER_OFFSET, slot),
            BUFFER_STRIDE as usize,
        );
    }
    write_avail(mapped_base, RX_QUEUE_OFFSET, rx_avail);
    write_used(mapped_base, RX_QUEUE_OFFSET, empty_used());
}

fn payload_for(slot: usize) -> [u8; PACKET_PAYLOAD_BYTES] {
    let mut payload = PAYLOAD_TEMPLATE;
    payload[0] = payload[0].wrapping_add(slot as u8);
    payload[PACKET_PAYLOAD_BYTES - 1] ^= slot as u8;
    payload
}

fn count_packet_matches(mapped_base: u64) -> usize {
    let mut matches = 0;
    for slot in 0..PACKET_BATCH_COUNT {
        let mut received = [0u8; PACKET_PAYLOAD_BYTES];
        read_bytes(
            mapped_base
                + crate::virtio_net_transport::buffer_offset(RX_BUFFER_OFFSET, slot)
                + frame_header_bytes(),
            &mut received,
        );
        if received == payload_for(slot) {
            matches += 1;
        }
    }
    matches
}

fn frame_header_bytes() -> u64 {
    core::mem::size_of::<VirtioNetHdr>() as u64
}

fn write_header(addr: u64, header: VirtioNetHdr) {
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

fn current_cpu_apic_id() -> u64 {
    // SAFETY: CPUID leaf 1 is always available on the x86_64 bootstrap target,
    // and reading the local APIC id is side-effect free.
    u64::from((unsafe { __cpuid(1) }.ebx >> 24) & 0xff)
}

fn worker_stack_top() -> u64 {
    // SAFETY: this dedicated stack belongs only to the net smoke worker and is
    // passed to `zx_thread_start` exactly once per run.
    let base = unsafe { ptr::addr_of_mut!(NET_WORKER_STACK.0) as *mut u8 as usize };
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

fn close_worker_and_handles(worker_thread: zx_handle_t, handles: &[zx_handle_t]) {
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
    close_handles(handles);
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
    write_slot(SLOT_NET_QUEUE_LOOKUP, summary.queue_lookup as u64);
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
    write_slot(SLOT_NET_MMIO_READY, summary.mmio_ready);
    write_slot(SLOT_NET_MMIO_DEVICE_FEATURES, summary.mmio_device_features);
    write_slot(SLOT_NET_MMIO_DRIVER_FEATURES, summary.mmio_driver_features);
    write_slot(SLOT_NET_MMIO_STATUS, summary.mmio_status);
    write_slot(SLOT_NET_TX_NOTIFY_COUNT, summary.tx_notify_count);
    write_slot(SLOT_NET_RX_COMPLETE_COUNT, summary.rx_complete_count);
    write_slot(SLOT_NET_PACKET_COUNT, summary.packet_count);
    write_slot(SLOT_NET_PACKET_MATCH_COUNT, summary.packet_match_count);
    write_slot(SLOT_NET_BATCH_CYCLES, summary.batch_cycles);
}
