use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_arch_x86_64::{debug_break, native_syscall8};
use libzircon::dma::{ZX_DMA_PERM_DEVICE_READ, ZX_DMA_PERM_DEVICE_WRITE};
use libzircon::handle::ZX_HANDLE_INVALID;
use libzircon::interrupt::{
    ZX_INTERRUPT_INFO_FLAG_TRIGGERABLE, ZX_INTERRUPT_MODE_VIRTUAL, ZX_INTERRUPT_VIRTUAL,
    zx_interrupt_info_t,
};
use libzircon::signals::ZX_INTERRUPT_SIGNALED;
use libzircon::status::{ZX_ERR_TIMED_OUT, ZX_OK};
use libzircon::syscall_numbers::AXLE_SYS_VMAR_MAP;
use libzircon::vm::{ZX_VM_MAP_MMIO, ZX_VM_PERM_READ, ZX_VM_PERM_WRITE};
use libzircon::{
    ax_dma_region_lookup_paddr, ax_interrupt_trigger, ax_vmo_lookup_paddr, ax_vmo_pin, zx_handle_t,
    zx_interrupt_ack, zx_interrupt_create, zx_interrupt_get_info, zx_interrupt_mask,
    zx_interrupt_unmask, zx_object_wait_one, zx_signals_t, zx_status_t, zx_vmo_create_contiguous,
    zx_vmo_create_physical, zx_vmo_read, zx_vmo_write,
};

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;
const PAGE_SIZE: u64 = 4096;
const HEAP_BYTES: usize = 16 * 1024;
const SLOT_OK: usize = 0;
const SLOT_ROOT_VMAR_H: usize = 62;
const SLOT_DEVICE_FAILURE_STEP: usize = 896;
const SLOT_DEVICE_INTERRUPT_CREATE: usize = 897;
const SLOT_DEVICE_INTERRUPT_WAIT_INITIAL: usize = 898;
const SLOT_DEVICE_INTERRUPT_WAIT_INITIAL_OBSERVED: usize = 899;
const SLOT_DEVICE_INTERRUPT_TRIGGER: usize = 900;
const SLOT_DEVICE_INTERRUPT_WAIT_SIGNALED: usize = 901;
const SLOT_DEVICE_INTERRUPT_WAIT_SIGNALED_OBSERVED: usize = 902;
const SLOT_DEVICE_INTERRUPT_MASK: usize = 903;
const SLOT_DEVICE_INTERRUPT_TRIGGER_MASKED: usize = 904;
const SLOT_DEVICE_INTERRUPT_WAIT_MASKED: usize = 905;
const SLOT_DEVICE_INTERRUPT_UNMASK: usize = 906;
const SLOT_DEVICE_INTERRUPT_WAIT_UNMASKED: usize = 907;
const SLOT_DEVICE_INTERRUPT_WAIT_UNMASKED_OBSERVED: usize = 908;
const SLOT_DEVICE_INTERRUPT_ACK1: usize = 909;
const SLOT_DEVICE_INTERRUPT_ACK2: usize = 910;
const SLOT_DEVICE_INTERRUPT_WAIT_DRAINED: usize = 911;
const SLOT_DEVICE_INTERRUPT_INFO: usize = 938;
const SLOT_DEVICE_INTERRUPT_MODE: usize = 939;
const SLOT_DEVICE_INTERRUPT_VECTOR: usize = 940;
const SLOT_DEVICE_INTERRUPT_FLAGS: usize = 941;
const SLOT_DEVICE_CONTIG_CREATE: usize = 912;
const SLOT_DEVICE_CONTIG_LOOKUP0: usize = 913;
const SLOT_DEVICE_CONTIG_LOOKUP1: usize = 914;
const SLOT_DEVICE_CONTIG_PADDR0: usize = 915;
const SLOT_DEVICE_CONTIG_PADDR1: usize = 916;
const SLOT_DEVICE_CONTIG_IS_CONTIGUOUS: usize = 917;
const SLOT_DEVICE_CONTIG_MAP: usize = 918;
const SLOT_DEVICE_CONTIG_WRITE: usize = 919;
const SLOT_DEVICE_CONTIG_READ: usize = 920;
const SLOT_DEVICE_CONTIG_READ_MATCH: usize = 921;
const SLOT_DEVICE_PHYSICAL_CREATE: usize = 922;
const SLOT_DEVICE_PHYSICAL_LOOKUP: usize = 923;
const SLOT_DEVICE_PHYSICAL_PADDR: usize = 924;
const SLOT_DEVICE_PHYSICAL_MATCHES_CONTIG0: usize = 925;
const SLOT_DEVICE_PHYSICAL_MAP: usize = 926;
const SLOT_DEVICE_PRESENT: usize = 927;
const SLOT_DEVICE_CONTIG_PIN_CREATE: usize = 928;
const SLOT_DEVICE_CONTIG_PIN_LOOKUP0: usize = 929;
const SLOT_DEVICE_CONTIG_PIN_LOOKUP1: usize = 930;
const SLOT_DEVICE_CONTIG_PIN_PADDR0: usize = 931;
const SLOT_DEVICE_CONTIG_PIN_PADDR1: usize = 932;
const SLOT_DEVICE_CONTIG_PIN_MATCHES: usize = 933;
const SLOT_DEVICE_PHYSICAL_PIN_CREATE: usize = 934;
const SLOT_DEVICE_PHYSICAL_PIN_LOOKUP: usize = 935;
const SLOT_DEVICE_PHYSICAL_PIN_PADDR: usize = 936;
const SLOT_DEVICE_PHYSICAL_PIN_MATCHES: usize = 937;

const STEP_PANIC: u64 = u64::MAX;
const STEP_ROOT_VMAR: u64 = 1;
const STEP_INTERRUPT_CREATE: u64 = 2;
const STEP_INTERRUPT_WAIT_INITIAL: u64 = 3;
const STEP_INTERRUPT_TRIGGER: u64 = 4;
const STEP_INTERRUPT_WAIT_SIGNALED: u64 = 5;
const STEP_INTERRUPT_MASK: u64 = 6;
const STEP_INTERRUPT_TRIGGER_MASKED: u64 = 7;
const STEP_INTERRUPT_WAIT_MASKED: u64 = 8;
const STEP_INTERRUPT_UNMASK: u64 = 9;
const STEP_INTERRUPT_WAIT_UNMASKED: u64 = 10;
const STEP_INTERRUPT_ACK1: u64 = 11;
const STEP_INTERRUPT_ACK2: u64 = 12;
const STEP_INTERRUPT_WAIT_DRAINED: u64 = 13;
const STEP_INTERRUPT_INFO: u64 = 28;
const STEP_CONTIG_CREATE: u64 = 14;
const STEP_CONTIG_LOOKUP0: u64 = 15;
const STEP_CONTIG_LOOKUP1: u64 = 16;
const STEP_CONTIG_PIN_CREATE: u64 = 17;
const STEP_CONTIG_PIN_LOOKUP0: u64 = 18;
const STEP_CONTIG_PIN_LOOKUP1: u64 = 19;
const STEP_CONTIG_MAP: u64 = 20;
const STEP_CONTIG_WRITE: u64 = 21;
const STEP_CONTIG_READ: u64 = 22;
const STEP_PHYSICAL_CREATE: u64 = 23;
const STEP_PHYSICAL_LOOKUP: u64 = 24;
const STEP_PHYSICAL_PIN_CREATE: u64 = 25;
const STEP_PHYSICAL_PIN_LOOKUP: u64 = 26;
const STEP_PHYSICAL_MAP: u64 = 27;

const CONTIG_TEST_OFFSET: u64 = 128;
const CONTIG_TEST_BYTES: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);

// SAFETY: this allocator serves one bootstrap test process, returns unique
// non-overlapping bumps from one static buffer, honors alignment, and never
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
                    // SAFETY: the bump pointer guarantees a unique slice of the static heap.
                    let base = unsafe { core::ptr::addr_of_mut!(HEAP.0).cast::<u8>() as usize };
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
    run_device_smoke();
    write_slot(SLOT_OK, 1);
    debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_PANIC);
    write_slot(SLOT_OK, 1);
    debug_break()
}

fn run_device_smoke() {
    write_slot(SLOT_DEVICE_PRESENT, 1);
    let root_vmar = read_slot(SLOT_ROOT_VMAR_H) as zx_handle_t;
    if root_vmar == ZX_HANDLE_INVALID {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_ROOT_VMAR);
        return;
    }

    let mut interrupt = ZX_HANDLE_INVALID;
    let status = zx_interrupt_create(ZX_INTERRUPT_VIRTUAL, &mut interrupt);
    write_status(SLOT_DEVICE_INTERRUPT_CREATE, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_INTERRUPT_CREATE);
        return;
    }

    let mut interrupt_info = zx_interrupt_info_t::default();
    let status = zx_interrupt_get_info(interrupt, &mut interrupt_info);
    write_status(SLOT_DEVICE_INTERRUPT_INFO, status);
    write_slot(SLOT_DEVICE_INTERRUPT_MODE, u64::from(interrupt_info.mode));
    write_slot(
        SLOT_DEVICE_INTERRUPT_VECTOR,
        u64::from(interrupt_info.vector),
    );
    write_slot(SLOT_DEVICE_INTERRUPT_FLAGS, u64::from(interrupt_info.flags));
    if status != ZX_OK
        || interrupt_info.mode != ZX_INTERRUPT_MODE_VIRTUAL
        || interrupt_info.vector != 0
        || (interrupt_info.flags & ZX_INTERRUPT_INFO_FLAG_TRIGGERABLE) == 0
    {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_INTERRUPT_INFO);
        return;
    }

    let mut observed: zx_signals_t = 0;
    let status = zx_object_wait_one(interrupt, ZX_INTERRUPT_SIGNALED, 0, &mut observed);
    write_status(SLOT_DEVICE_INTERRUPT_WAIT_INITIAL, status);
    write_slot(SLOT_DEVICE_INTERRUPT_WAIT_INITIAL_OBSERVED, observed as u64);
    if status != ZX_ERR_TIMED_OUT {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_INTERRUPT_WAIT_INITIAL);
        return;
    }

    let status = ax_interrupt_trigger(interrupt, 1);
    write_status(SLOT_DEVICE_INTERRUPT_TRIGGER, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_INTERRUPT_TRIGGER);
        return;
    }

    observed = 0;
    let status = zx_object_wait_one(interrupt, ZX_INTERRUPT_SIGNALED, 0, &mut observed);
    write_status(SLOT_DEVICE_INTERRUPT_WAIT_SIGNALED, status);
    write_slot(
        SLOT_DEVICE_INTERRUPT_WAIT_SIGNALED_OBSERVED,
        observed as u64,
    );
    if status != ZX_OK || (observed & ZX_INTERRUPT_SIGNALED) == 0 {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_INTERRUPT_WAIT_SIGNALED);
        return;
    }

    let status = zx_interrupt_mask(interrupt);
    write_status(SLOT_DEVICE_INTERRUPT_MASK, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_INTERRUPT_MASK);
        return;
    }

    let status = ax_interrupt_trigger(interrupt, 1);
    write_status(SLOT_DEVICE_INTERRUPT_TRIGGER_MASKED, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_INTERRUPT_TRIGGER_MASKED);
        return;
    }

    observed = 0;
    let status = zx_object_wait_one(interrupt, ZX_INTERRUPT_SIGNALED, 0, &mut observed);
    write_status(SLOT_DEVICE_INTERRUPT_WAIT_MASKED, status);
    if status != ZX_ERR_TIMED_OUT {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_INTERRUPT_WAIT_MASKED);
        return;
    }

    let status = zx_interrupt_unmask(interrupt);
    write_status(SLOT_DEVICE_INTERRUPT_UNMASK, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_INTERRUPT_UNMASK);
        return;
    }

    observed = 0;
    let status = zx_object_wait_one(interrupt, ZX_INTERRUPT_SIGNALED, 0, &mut observed);
    write_status(SLOT_DEVICE_INTERRUPT_WAIT_UNMASKED, status);
    write_slot(
        SLOT_DEVICE_INTERRUPT_WAIT_UNMASKED_OBSERVED,
        observed as u64,
    );
    if status != ZX_OK || (observed & ZX_INTERRUPT_SIGNALED) == 0 {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_INTERRUPT_WAIT_UNMASKED);
        return;
    }

    let status = zx_interrupt_ack(interrupt);
    write_status(SLOT_DEVICE_INTERRUPT_ACK1, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_INTERRUPT_ACK1);
        return;
    }

    let status = zx_interrupt_ack(interrupt);
    write_status(SLOT_DEVICE_INTERRUPT_ACK2, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_INTERRUPT_ACK2);
        return;
    }

    observed = 0;
    let status = zx_object_wait_one(interrupt, ZX_INTERRUPT_SIGNALED, 0, &mut observed);
    write_status(SLOT_DEVICE_INTERRUPT_WAIT_DRAINED, status);
    if status != ZX_ERR_TIMED_OUT {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_INTERRUPT_WAIT_DRAINED);
        return;
    }

    let mut contig = ZX_HANDLE_INVALID;
    let status = zx_vmo_create_contiguous(2 * PAGE_SIZE, 0, &mut contig);
    write_status(SLOT_DEVICE_CONTIG_CREATE, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_CONTIG_CREATE);
        return;
    }

    let mut contig_paddr0 = 0u64;
    let status = ax_vmo_lookup_paddr(contig, 0, &mut contig_paddr0);
    write_status(SLOT_DEVICE_CONTIG_LOOKUP0, status);
    write_slot(SLOT_DEVICE_CONTIG_PADDR0, contig_paddr0);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_CONTIG_LOOKUP0);
        return;
    }

    let mut contig_paddr1 = 0u64;
    let status = ax_vmo_lookup_paddr(contig, PAGE_SIZE, &mut contig_paddr1);
    write_status(SLOT_DEVICE_CONTIG_LOOKUP1, status);
    write_slot(SLOT_DEVICE_CONTIG_PADDR1, contig_paddr1);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_CONTIG_LOOKUP1);
        return;
    }
    write_slot(
        SLOT_DEVICE_CONTIG_IS_CONTIGUOUS,
        u64::from(contig_paddr1 == contig_paddr0 + PAGE_SIZE),
    );

    let mut contig_region = ZX_HANDLE_INVALID;
    let status = ax_vmo_pin(
        contig,
        0,
        2 * PAGE_SIZE,
        ZX_DMA_PERM_DEVICE_READ | ZX_DMA_PERM_DEVICE_WRITE,
        &mut contig_region,
    );
    write_status(SLOT_DEVICE_CONTIG_PIN_CREATE, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_CONTIG_PIN_CREATE);
        return;
    }

    let mut contig_pin_paddr0 = 0u64;
    let status = ax_dma_region_lookup_paddr(contig_region, 0, &mut contig_pin_paddr0);
    write_status(SLOT_DEVICE_CONTIG_PIN_LOOKUP0, status);
    write_slot(SLOT_DEVICE_CONTIG_PIN_PADDR0, contig_pin_paddr0);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_CONTIG_PIN_LOOKUP0);
        return;
    }

    let mut contig_pin_paddr1 = 0u64;
    let status = ax_dma_region_lookup_paddr(contig_region, PAGE_SIZE, &mut contig_pin_paddr1);
    write_status(SLOT_DEVICE_CONTIG_PIN_LOOKUP1, status);
    write_slot(SLOT_DEVICE_CONTIG_PIN_PADDR1, contig_pin_paddr1);
    write_slot(
        SLOT_DEVICE_CONTIG_PIN_MATCHES,
        u64::from(contig_pin_paddr0 == contig_paddr0 && contig_pin_paddr1 == contig_paddr1),
    );
    if status != ZX_OK || contig_pin_paddr0 != contig_paddr0 || contig_pin_paddr1 != contig_paddr1 {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_CONTIG_PIN_LOOKUP1);
        return;
    }

    let mut mapped_contig = 0u64;
    let status = zx_vmar_map_local(
        root_vmar,
        ZX_VM_PERM_READ | ZX_VM_PERM_WRITE,
        0,
        contig,
        0,
        2 * PAGE_SIZE,
        &mut mapped_contig,
    );
    write_status(SLOT_DEVICE_CONTIG_MAP, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_CONTIG_MAP);
        return;
    }

    let status = zx_vmo_write(contig, &CONTIG_TEST_BYTES, CONTIG_TEST_OFFSET);
    write_status(SLOT_DEVICE_CONTIG_WRITE, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_CONTIG_WRITE);
        return;
    }

    let mut readback = [0u8; CONTIG_TEST_BYTES.len()];
    let status = zx_vmo_read(contig, &mut readback, CONTIG_TEST_OFFSET);
    write_status(SLOT_DEVICE_CONTIG_READ, status);
    write_slot(
        SLOT_DEVICE_CONTIG_READ_MATCH,
        u64::from(readback == CONTIG_TEST_BYTES),
    );
    if status != ZX_OK || readback != CONTIG_TEST_BYTES {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_CONTIG_READ);
        return;
    }

    let mut physical = ZX_HANDLE_INVALID;
    let status = zx_vmo_create_physical(contig_paddr0, PAGE_SIZE, 0, &mut physical);
    write_status(SLOT_DEVICE_PHYSICAL_CREATE, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_PHYSICAL_CREATE);
        return;
    }

    let mut physical_paddr = 0u64;
    let status = ax_vmo_lookup_paddr(physical, 0, &mut physical_paddr);
    write_status(SLOT_DEVICE_PHYSICAL_LOOKUP, status);
    write_slot(SLOT_DEVICE_PHYSICAL_PADDR, physical_paddr);
    write_slot(
        SLOT_DEVICE_PHYSICAL_MATCHES_CONTIG0,
        u64::from(physical_paddr == contig_paddr0),
    );
    if status != ZX_OK || physical_paddr != contig_paddr0 {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_PHYSICAL_LOOKUP);
        return;
    }

    let mut physical_region = ZX_HANDLE_INVALID;
    let status = ax_vmo_pin(
        physical,
        0,
        PAGE_SIZE,
        ZX_DMA_PERM_DEVICE_READ | ZX_DMA_PERM_DEVICE_WRITE,
        &mut physical_region,
    );
    write_status(SLOT_DEVICE_PHYSICAL_PIN_CREATE, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_PHYSICAL_PIN_CREATE);
        return;
    }

    let mut physical_pin_paddr = 0u64;
    let status = ax_dma_region_lookup_paddr(physical_region, 0, &mut physical_pin_paddr);
    write_status(SLOT_DEVICE_PHYSICAL_PIN_LOOKUP, status);
    write_slot(SLOT_DEVICE_PHYSICAL_PIN_PADDR, physical_pin_paddr);
    write_slot(
        SLOT_DEVICE_PHYSICAL_PIN_MATCHES,
        u64::from(physical_pin_paddr == physical_paddr),
    );
    if status != ZX_OK || physical_pin_paddr != physical_paddr {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_PHYSICAL_PIN_LOOKUP);
        return;
    }

    let mut mapped_physical = 0u64;
    let status = zx_vmar_map_local(
        root_vmar,
        ZX_VM_PERM_READ | ZX_VM_MAP_MMIO,
        0,
        physical,
        0,
        PAGE_SIZE,
        &mut mapped_physical,
    );
    write_status(SLOT_DEVICE_PHYSICAL_MAP, status);
    if status != ZX_OK {
        write_slot(SLOT_DEVICE_FAILURE_STEP, STEP_PHYSICAL_MAP);
    }
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

fn read_slot(slot: usize) -> u64 {
    let slots = USER_SHARED_BASE as *const u64;
    // SAFETY: the kernel maps the bootstrap shared summary page at `USER_SHARED_BASE`.
    unsafe { slots.add(slot).read_volatile() }
}

fn write_slot(slot: usize, value: u64) {
    let slots = USER_SHARED_BASE as *mut u64;
    // SAFETY: the kernel maps the bootstrap shared summary page at `USER_SHARED_BASE`.
    unsafe { slots.add(slot).write_volatile(value) }
}

fn write_status(slot: usize, status: zx_status_t) {
    write_slot(slot, status as i64 as u64);
}
