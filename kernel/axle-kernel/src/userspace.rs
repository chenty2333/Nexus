//! Minimal ring3 bring-up for the userspace conformance runner.
//!
//! This is intentionally a bootstrap bridge:
//! - single address space (kernel + one userspace image mapped into same CR3)
//! - userspace calls syscalls via `int 0x80`
//! - userspace signals completion via `int3`
//!
//! The immediate purpose is to force correctness work in:
//! - copyin/copyout validation
//! - user pointer boundaries
//! - ring3 -> ring0 transitions (TSS/RSP0)

extern crate alloc;

use alloc::alloc::{Layout, alloc_zeroed};
use x86_64::instructions::segmentation::Segment;

// --- Userspace virtual layout (in current single-address-space model) ---

pub(crate) const USER_PAGE_BYTES: u64 = 0x1000;
pub(crate) const USER_CODE_PAGE_COUNT: usize = 8;
pub(crate) const USER_CODE_BYTES: u64 = USER_PAGE_BYTES * USER_CODE_PAGE_COUNT as u64;
pub(crate) const USER_REGION_BYTES: u64 = 0x20_0000;
pub(crate) const USER_CODE_VA: u64 = 0x0000_0001_0000_0000; // 4 GiB
pub(crate) const USER_SHARED_VA: u64 = USER_CODE_VA + USER_CODE_BYTES;
pub(crate) const USER_STACK_VA: u64 = USER_SHARED_VA + USER_PAGE_BYTES;
const USER_STACK_TOP: u64 = USER_STACK_VA + USER_PAGE_BYTES;
pub(crate) const USER_VM_TEST_VA: u64 = USER_CODE_VA + 0x10_000;

// --- QEMU loader handoff for external userspace runner ELF ---
//
// Conformance harness uses `-device loader,file=...,addr=...` to drop the ELF bytes
// into guest RAM, plus a second loader device to write the byte length.
const USER_RUNNER_ELF_PADDR: u64 = 0x0100_0000;
const USER_RUNNER_ELF_SIZE_PADDR: u64 = USER_RUNNER_ELF_PADDR - 8;
const USER_RUNNER_ELF_MAX_BYTES: usize = 128 * 1024;

// --- Shared summary slots (u64) written by userspace ---

const SLOT_OK: usize = 0;

// Match the existing kernel bring-up summary keys so `specs/conformance/scenarios/*.toml`
// don't need churn when we move execution from ring0 to ring3.
const SLOT_UNKNOWN: usize = 1;
const SLOT_CLOSE_INVALID: usize = 2;
const SLOT_PORT_CREATE_BAD_OPTS: usize = 3;
const SLOT_PORT_CREATE_NULL_OUT: usize = 4;
const SLOT_BAD_WAIT: usize = 5;
const SLOT_PORT_WAIT_NULL_OUT: usize = 6;
const SLOT_EMPTY_WAIT: usize = 7;
const SLOT_PORT_QUEUE_NULL_PKT: usize = 8;
const SLOT_PORT_QUEUE_BAD_TYPE: usize = 9;
const SLOT_QUEUE: usize = 10;
const SLOT_WAIT: usize = 11;
const SLOT_TIMER_CREATE_BAD_OPTS: usize = 12;
const SLOT_TIMER_CREATE_BAD_CLOCK: usize = 13;
const SLOT_TIMER_CREATE_NULL_OUT: usize = 14;
const SLOT_PORT_WAIT_WRONG_TYPE: usize = 15;
const SLOT_PORT_QUEUE_WRONG_TYPE: usize = 16;
const SLOT_TIMER_SET_WRONG_TYPE: usize = 17;
const SLOT_TIMER_CANCEL_WRONG_TYPE: usize = 18;
const SLOT_WAIT_ONE_UNSIGNALED: usize = 19;
const SLOT_WAIT_ONE_UNSIGNALED_OBS: usize = 20;
const SLOT_WAIT_ASYNC: usize = 21;
const SLOT_TIMER_SET_IMMEDIATE: usize = 22;
const SLOT_WAIT_SIGNAL: usize = 23;
const SLOT_SIGNAL_TRIGGER: usize = 24;
const SLOT_SIGNAL_OBSERVED: usize = 25;
const SLOT_SIGNAL_COUNT: usize = 26;
const SLOT_WAIT_ONE_SIGNALED: usize = 27;
const SLOT_WAIT_ONE_SIGNALED_OBS: usize = 28;
const SLOT_TIMER_SET: usize = 29;
const SLOT_TIMER_CANCEL: usize = 30;
const SLOT_TIMER_CLOSE: usize = 31;
const SLOT_TIMER_CLOSE_AGAIN: usize = 32;
const SLOT_CLOSE: usize = 33;
const SLOT_CLOSE_AGAIN: usize = 34;
const SLOT_PORT_H: usize = 35;
const SLOT_TIMER_H: usize = 36;
const SLOT_WAIT_ONE_FUTURE_TIMEOUT: usize = 37;
const SLOT_WAIT_ONE_FUTURE_TIMEOUT_OBS: usize = 38;
const SLOT_WAIT_ONE_FUTURE_OK: usize = 39;
const SLOT_WAIT_ONE_FUTURE_OK_OBS: usize = 40;
const SLOT_WAIT_ASYNC_BAD_OPTIONS: usize = 41;
const SLOT_WAIT_ASYNC_TS: usize = 42;
const SLOT_WAIT_SIGNAL_TS: usize = 43;
const SLOT_SIGNAL_TIMESTAMP: usize = 44;
const SLOT_SIGNAL_TIMESTAMP_OK: usize = 45;
const SLOT_WAIT_ASYNC_BOOT: usize = 46;
const SLOT_WAIT_SIGNAL_BOOT: usize = 47;
const SLOT_SIGNAL_BOOT_TIMESTAMP: usize = 48;
const SLOT_SIGNAL_BOOT_TIMESTAMP_OK: usize = 49;
const SLOT_EDGE_WAIT_ASYNC: usize = 50;
const SLOT_EDGE_EMPTY_WAIT: usize = 51;
const SLOT_EDGE_SIGNAL_WAIT: usize = 52;
const SLOT_EDGE_SIGNAL_KEY: usize = 53;
const SLOT_RESERVE_QUEUE_FULL: usize = 54;
const SLOT_RESERVE_WAIT_ASYNC: usize = 55;
const SLOT_RESERVE_SIGNAL_AFTER_USERS_OK: usize = 56;
const SLOT_RESERVE_SIGNAL_TYPE: usize = 57;
const SLOT_PENDING_WAIT_ASYNC: usize = 58;
const SLOT_PENDING_SIGNAL_WAIT: usize = 59;
const SLOT_PENDING_SIGNAL_COUNT: usize = 60;
const SLOT_PENDING_MERGE_OK: usize = 61;
const SLOT_ROOT_VMAR_H: usize = 62;
const SLOT_VMO_CREATE_BAD_OPTS: usize = 63;
const SLOT_VMO_CREATE_NULL_OUT: usize = 64;
const SLOT_VMO_CREATE: usize = 65;
const SLOT_VMO_H: usize = 66;
const SLOT_VMAR_MAP_BAD_TYPE: usize = 67;
const SLOT_VMAR_MAP_BAD_OPTS: usize = 68;
const SLOT_VMAR_MAP: usize = 69;
const SLOT_VMAR_MAP_ADDR: usize = 70;
const SLOT_VMAR_MAP_WRITE_OK: usize = 71;
const SLOT_VMAR_OVERLAP: usize = 72;
const SLOT_VMAR_PROTECT: usize = 73;
const SLOT_VMAR_REPROTECT: usize = 74;
const SLOT_VMAR_UNMAP: usize = 75;
const SLOT_VMAR_REMAP: usize = 76;
const SLOT_CHANNEL_CREATE_BAD_OPTS: usize = 77;
const SLOT_CHANNEL_CREATE_NULL_OUT0: usize = 78;
const SLOT_CHANNEL_CREATE_NULL_OUT1: usize = 79;
const SLOT_CHANNEL_CREATE: usize = 80;
const SLOT_CHANNEL_H0: usize = 81;
const SLOT_CHANNEL_H1: usize = 82;
const SLOT_CHANNEL_READ_EMPTY: usize = 83;
const SLOT_CHANNEL_WRITE: usize = 84;
const SLOT_CHANNEL_WAIT_READABLE: usize = 85;
const SLOT_CHANNEL_WAIT_READABLE_OK: usize = 86;
const SLOT_CHANNEL_READ: usize = 87;
const SLOT_CHANNEL_READ_ACTUAL_BYTES: usize = 88;
const SLOT_CHANNEL_READ_ACTUAL_HANDLES: usize = 89;
const SLOT_CHANNEL_READ_MATCH: usize = 90;
const SLOT_CHANNEL_CLOSE_PEER: usize = 91;
const SLOT_CHANNEL_WRITE_PEER_CLOSED: usize = 92;
const SLOT_CHANNEL_READ_PEER_CLOSED: usize = 93;
const SLOT_CHANNEL_WAIT_PEER_CLOSED: usize = 94;
const SLOT_CHANNEL_WAIT_PEER_CLOSED_OBS: usize = 95;
const SLOT_EVENTPAIR_CREATE_BAD_OPTS: usize = 96;
const SLOT_EVENTPAIR_CREATE_NULL_OUT0: usize = 97;
const SLOT_EVENTPAIR_CREATE_NULL_OUT1: usize = 98;
const SLOT_EVENTPAIR_CREATE: usize = 99;
const SLOT_EVENTPAIR_H0: usize = 100;
const SLOT_EVENTPAIR_H1: usize = 101;
const SLOT_EVENTPAIR_SIGNAL_BAD_MASK: usize = 102;
const SLOT_EVENTPAIR_SIGNAL_PEER: usize = 103;
const SLOT_EVENTPAIR_WAIT_SIGNAL: usize = 104;
const SLOT_EVENTPAIR_WAIT_SIGNAL_OBS: usize = 105;
const SLOT_EVENTPAIR_CLOSE_PEER: usize = 106;
const SLOT_EVENTPAIR_WAIT_PEER_CLOSED: usize = 107;
const SLOT_EVENTPAIR_WAIT_PEER_CLOSED_OBS: usize = 108;
const SLOT_CHANNEL_LOAN_TX_VMO_CREATE: usize = 109;
const SLOT_CHANNEL_LOAN_TX_MAP: usize = 110;
const SLOT_CHANNEL_LOAN_RX_VMO_CREATE: usize = 111;
const SLOT_CHANNEL_LOAN_RX_MAP: usize = 112;
const SLOT_CHANNEL_LOAN_CREATE: usize = 113;
const SLOT_CHANNEL_LOAN_WRITE: usize = 114;
const SLOT_CHANNEL_LOAN_READ: usize = 115;
const SLOT_CHANNEL_LOAN_ACTUAL_BYTES: usize = 116;
const SLOT_CHANNEL_LOAN_SNAPSHOT_OK: usize = 117;

const SLOT_MAX: usize = SLOT_CHANNEL_LOAN_SNAPSHOT_OK;
const SLOT_T0_NS: usize = 511;

#[repr(align(4096))]
#[derive(Clone, Copy)]
struct AlignedPage([u8; 4096]);
#[repr(align(4096))]
struct AlignedPageTable([u64; 512]);

static mut USER_CODE_PAGES: [AlignedPage; USER_CODE_PAGE_COUNT] =
    [AlignedPage([0; 4096]); USER_CODE_PAGE_COUNT];
static mut USER_SHARED_PAGE: AlignedPage = AlignedPage([0; 4096]);
static mut USER_STACK_PAGE: AlignedPage = AlignedPage([0; 4096]);

static mut USER_PD: AlignedPageTable = AlignedPageTable([0; 512]);
static mut USER_PT: AlignedPageTable = AlignedPageTable([0; 512]);

// PVH boot page tables (identity-mapped, used as the active CR3).
unsafe extern "C" {
    static mut pvh_pml4: [u64; 512];
    static mut pvh_pdpt: [u64; 512];
}

// Page table flag bits (x86_64).
const PTE_P: u64 = 1 << 0;
const PTE_W: u64 = 1 << 1;
const PTE_U: u64 = 1 << 2;

fn phys_of<T>(p: *const T) -> u64 {
    // In the current PVH identity mapping, physical == virtual for kernel static data.
    p as u64
}

pub(crate) fn user_code_page_paddr(index: usize) -> u64 {
    assert!(index < USER_CODE_PAGE_COUNT);
    phys_of(core::ptr::addr_of!(USER_CODE_PAGES)) + (index as u64) * USER_PAGE_BYTES
}

pub(crate) fn user_shared_page_paddr() -> u64 {
    phys_of(core::ptr::addr_of!(USER_SHARED_PAGE))
}

pub(crate) fn user_stack_page_paddr() -> u64 {
    phys_of(core::ptr::addr_of!(USER_STACK_PAGE))
}

fn user_page_index(user_va: u64) -> Option<usize> {
    if user_va < USER_CODE_VA || user_va >= (USER_CODE_VA + USER_REGION_BYTES) {
        return None;
    }
    if user_va & (USER_PAGE_BYTES - 1) != 0 {
        return None;
    }
    usize::try_from((user_va - USER_CODE_VA) / USER_PAGE_BYTES).ok()
}

pub(crate) fn alloc_bootstrap_cow_page(src_paddr: u64) -> Option<u64> {
    let dst = alloc_bootstrap_zeroed_page()?;
    unsafe {
        // SAFETY: both the source physical address and destination pointer are currently
        // identity-mapped kernel addresses spanning one bootstrap page.
        core::ptr::copy_nonoverlapping(
            src_paddr as *const u8,
            dst as *mut u8,
            USER_PAGE_BYTES as usize,
        );
    }
    Some(dst)
}

pub(crate) fn alloc_bootstrap_zeroed_page() -> Option<u64> {
    let layout =
        Layout::from_size_align(USER_PAGE_BYTES as usize, USER_PAGE_BYTES as usize).ok()?;
    let dst = unsafe {
        // SAFETY: the bootstrap allocator honors the requested alignment. The returned
        // page stays owned by the kernel for the rest of bring-up.
        alloc_zeroed(layout)
    };
    if dst.is_null() {
        return None;
    }
    Some(dst as u64)
}

pub(crate) fn install_user_page_frame(user_va: u64, paddr: u64, writable: bool) -> Result<(), ()> {
    if paddr & (USER_PAGE_BYTES - 1) != 0 {
        return Err(());
    }
    let index = user_page_index(user_va).ok_or(())?;
    let mut entry = paddr | (PTE_P | PTE_U);
    if writable {
        entry |= PTE_W;
    }

    unsafe {
        // SAFETY: USER_PT is the active page table page for the fixed bootstrap user region.
        USER_PT.0[index] = entry;
    }
    Ok(())
}

pub(crate) fn clear_user_page_frame(user_va: u64) -> Result<(), ()> {
    let index = user_page_index(user_va).ok_or(())?;
    unsafe {
        // SAFETY: USER_PT is the active page table page for the fixed bootstrap user region.
        USER_PT.0[index] = 0;
    }
    Ok(())
}

pub(crate) fn set_user_page_writable(user_va: u64, writable: bool) -> Result<(), ()> {
    let index = user_page_index(user_va).ok_or(())?;
    unsafe {
        // SAFETY: USER_PT is the active page table page for the fixed bootstrap user region.
        let entry = &mut USER_PT.0[index];
        if (*entry & PTE_P) == 0 {
            return Err(());
        }
        if writable {
            *entry |= PTE_W;
        } else {
            *entry &= !PTE_W;
        }
    }
    Ok(())
}

fn map_userspace_pages() {
    // SAFETY: early bring-up is single-core; page table mutation is serialized.
    unsafe {
        let pml4 = core::ptr::addr_of_mut!(pvh_pml4).cast::<u64>();
        let pdpt = core::ptr::addr_of_mut!(pvh_pdpt).cast::<u64>();
        let user_pd = core::ptr::addr_of_mut!(USER_PD).cast::<u64>();
        let user_pt = core::ptr::addr_of_mut!(USER_PT).cast::<u64>();

        // Allow user mappings under PML4[0] by setting U=1 at the top level.
        *pml4.add(0) |= PTE_U;

        // Install PDPT[4] -> USER_PD (maps VA 4GiB..5GiB).
        *pdpt.add(4) = phys_of(core::ptr::addr_of!(USER_PD)) | (PTE_P | PTE_W | PTE_U);

        // USER_PD[0] -> USER_PT (maps VA 4GiB..4GiB+2MiB).
        *user_pd.add(0) = phys_of(core::ptr::addr_of!(USER_PT)) | (PTE_P | PTE_W | PTE_U);

        // Map the user code pages, followed by the shared page and stack page.
        for index in 0..USER_CODE_PAGE_COUNT {
            *user_pt.add(index) = user_code_page_paddr(index) | (PTE_P | PTE_W | PTE_U);
        }
        *user_pt.add(USER_CODE_PAGE_COUNT) =
            phys_of(core::ptr::addr_of!(USER_SHARED_PAGE)) | (PTE_P | PTE_W | PTE_U);
        *user_pt.add(USER_CODE_PAGE_COUNT + 1) =
            phys_of(core::ptr::addr_of!(USER_STACK_PAGE)) | (PTE_P | PTE_U);

        // Flush TLB by reloading CR3.
        crate::arch::tlb::flush_all_local();
    }
}

unsafe extern "C" {
    static axle_user_prog_start: u8;
    static axle_user_prog_end: u8;
}

fn load_user_program_embedded() {
    // SAFETY: symbols are defined by `global_asm!` below and form a contiguous region.
    unsafe {
        let start = core::ptr::addr_of!(axle_user_prog_start);
        let end = core::ptr::addr_of!(axle_user_prog_end);
        let len = end.offset_from(start) as usize;
        let src = core::slice::from_raw_parts(start, len);

        if len > USER_CODE_BYTES as usize {
            panic!(
                "userspace: program too large for bootstrap code region (len={})",
                len
            );
        }

        let dst = core::ptr::addr_of_mut!(USER_CODE_PAGES).cast::<u8>();
        // Use `ptr::copy` (memmove semantics) to avoid relying on non-overlap
        // across toolchain/linker layouts during bring-up.
        core::ptr::copy(src.as_ptr(), dst, len);
        core::ptr::write_bytes(dst.add(len), 0, USER_CODE_BYTES as usize - len);
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

fn try_load_user_program_from_qemu_loader() -> Option<u64> {
    // SAFETY: conformance harness loads these bytes into identity-mapped RAM.
    let size = unsafe { core::ptr::read_unaligned(USER_RUNNER_ELF_SIZE_PADDR as *const u64) };
    if size == 0 || size as usize > USER_RUNNER_ELF_MAX_BYTES {
        return None;
    }

    // SAFETY: we trust the loader-provided size bound above.
    let blob =
        unsafe { core::slice::from_raw_parts(USER_RUNNER_ELF_PADDR as *const u8, size as usize) };

    if blob.len() < core::mem::size_of::<Elf64Ehdr>() {
        return None;
    }
    if &blob[0..4] != b"\x7FELF" {
        return None;
    }

    let ehdr = unsafe { core::ptr::read_unaligned(blob.as_ptr() as *const Elf64Ehdr) };
    // 64-bit little-endian.
    if ehdr.e_ident[4] != 2 || ehdr.e_ident[5] != 1 {
        return None;
    }
    // ET_EXEC.
    if ehdr.e_type != 2 {
        return None;
    }
    // EM_X86_64.
    if ehdr.e_machine != 0x3E {
        return None;
    }
    if ehdr.e_phentsize as usize != core::mem::size_of::<Elf64Phdr>() {
        panic!("userspace: unexpected phdr size {}", ehdr.e_phentsize);
    }

    let phoff = ehdr.e_phoff as usize;
    let phnum = ehdr.e_phnum as usize;
    let phsize = phnum
        .checked_mul(core::mem::size_of::<Elf64Phdr>())
        .and_then(|n| n.checked_add(phoff))
        .unwrap_or(usize::MAX);
    if phsize > blob.len() {
        panic!("userspace: phdr table out of range");
    }

    // Load PT_LOAD segments into the mapped user code page.
    for i in 0..phnum {
        let off = phoff + i * core::mem::size_of::<Elf64Phdr>();
        let ph = unsafe { core::ptr::read_unaligned(blob.as_ptr().add(off) as *const Elf64Phdr) };
        const PT_LOAD: u32 = 1;
        if ph.p_type != PT_LOAD {
            continue;
        }

        let file_off = ph.p_offset as usize;
        let file_sz = ph.p_filesz as usize;
        let mem_sz = ph.p_memsz as usize;

        let file_end = file_off.checked_add(file_sz).unwrap_or(usize::MAX);
        if file_end > blob.len() {
            panic!("userspace: segment file range out of bounds");
        }

        let vaddr = ph.p_vaddr;
        let vend = vaddr.checked_add(ph.p_memsz).unwrap_or(u64::MAX);
        if vaddr < USER_CODE_VA || vend > USER_SHARED_VA {
            panic!(
                "userspace: segment vaddr out of range vaddr={:#x} memsz={:#x}",
                vaddr, ph.p_memsz
            );
        }

        // SAFETY: vaddr range is mapped by `map_userspace_pages()`.
        unsafe {
            let dst = vaddr as *mut u8;
            core::ptr::copy_nonoverlapping(blob.as_ptr().add(file_off), dst, file_sz);
            if mem_sz > file_sz {
                core::ptr::write_bytes(dst.add(file_sz), 0, mem_sz - file_sz);
            }
        }
    }

    if ehdr.e_entry < USER_CODE_VA || ehdr.e_entry >= USER_SHARED_VA {
        panic!("userspace: entry out of range {:#x}", ehdr.e_entry);
    }

    Some(ehdr.e_entry)
}

/// Validate a user pointer for a copyin/copyout of `len` bytes.
///
/// Bring-up rule: pointers must be fully contained within the mapped shared page
/// or the mapped stack page (so the kernel never faults on bad pointers).
pub fn validate_user_ptr(ptr: u64, len: usize) -> bool {
    crate::object::validate_current_user_ptr(ptr, len)
}

fn shared_slots() -> &'static mut [u64] {
    // SAFETY: shared page is always mapped and 8-byte aligned; we only use it after mapping.
    unsafe { core::slice::from_raw_parts_mut(USER_SHARED_VA as *mut u64, 512) }
}

/// Called by the breakpoint handler to print the userspace-produced summary.
pub fn on_breakpoint() -> ! {
    let slots = shared_slots();
    if slots[SLOT_OK] != 1 {
        crate::kprintln!("userspace: conformance reported failure (ok=0)");
        crate::arch::qemu::exit_failure();
    }

    crate::kprintln!(
        "kernel: int80 conformance ok (unknown={}, close_invalid={}, port_create_bad_opts={}, port_create_null_out={}, bad_wait={}, port_wait_null_out={}, empty_wait={}, port_queue_null_pkt={}, port_queue_bad_type={}, queue={}, wait={}, timer_create_bad_opts={}, timer_create_bad_clock={}, timer_create_null_out={}, port_wait_wrong_type={}, port_queue_wrong_type={}, timer_set_wrong_type={}, timer_cancel_wrong_type={}, wait_one_unsignaled={}, wait_one_unsignaled_observed={}, wait_async={}, timer_set_immediate={}, wait_signal={}, signal_trigger={}, signal_observed={}, signal_count={}, wait_one_signaled={}, wait_one_signaled_observed={}, wait_one_future_timeout={}, wait_one_future_timeout_observed={}, wait_one_future_ok={}, wait_one_future_ok_observed={}, wait_async_bad_options={}, wait_async_ts={}, wait_signal_ts={}, signal_timestamp={}, signal_timestamp_ok={}, wait_async_boot={}, wait_signal_boot={}, signal_boot_timestamp={}, signal_boot_timestamp_ok={}, edge_wait_async={}, edge_empty_wait={}, edge_signal_wait={}, edge_signal_key={}, reserve_queue_full={}, reserve_wait_async={}, reserve_signal_after_users_ok={}, reserve_signal_type={}, pending_wait_async={}, pending_signal_wait={}, pending_signal_count={}, pending_merge_ok={}, vmo_create_bad_opts={}, vmo_create_null_out={}, vmo_create={}, vmar_map_bad_type={}, vmar_map_bad_opts={}, vmar_map={}, vmar_map_addr={}, vmar_map_write_ok={}, vmar_overlap={}, vmar_protect={}, vmar_reprotect={}, vmar_unmap={}, vmar_remap={}, channel_create_bad_opts={}, channel_create_null_out0={}, channel_create_null_out1={}, channel_create={}, channel_read_empty={}, channel_write={}, channel_wait_readable={}, channel_wait_readable_ok={}, channel_read={}, channel_read_actual_bytes={}, channel_read_actual_handles={}, channel_read_match={}, channel_close_peer={}, channel_write_peer_closed={}, channel_read_peer_closed={}, channel_wait_peer_closed={}, channel_wait_peer_closed_observed={}, eventpair_create_bad_opts={}, eventpair_create_null_out0={}, eventpair_create_null_out1={}, eventpair_create={}, eventpair_signal_bad_mask={}, eventpair_signal_peer={}, eventpair_wait_signal={}, eventpair_wait_signal_observed={}, eventpair_close_peer={}, eventpair_wait_peer_closed={}, eventpair_wait_peer_closed_observed={}, channel_loan_tx_vmo_create={}, channel_loan_tx_map={}, channel_loan_rx_vmo_create={}, channel_loan_rx_map={}, channel_loan_create={}, channel_loan_write={}, channel_loan_read={}, channel_loan_actual_bytes={}, channel_loan_snapshot_ok={}, timer_set={}, timer_cancel={}, timer_close={}, timer_close_again={}, close={}, close_again={}, root_vmar_h={}, port_h={}, timer_h={}, vmo_h={}, channel_h0={}, channel_h1={}, eventpair_h0={}, eventpair_h1={})",
        slots[SLOT_UNKNOWN] as i64,
        slots[SLOT_CLOSE_INVALID] as i64,
        slots[SLOT_PORT_CREATE_BAD_OPTS] as i64,
        slots[SLOT_PORT_CREATE_NULL_OUT] as i64,
        slots[SLOT_BAD_WAIT] as i64,
        slots[SLOT_PORT_WAIT_NULL_OUT] as i64,
        slots[SLOT_EMPTY_WAIT] as i64,
        slots[SLOT_PORT_QUEUE_NULL_PKT] as i64,
        slots[SLOT_PORT_QUEUE_BAD_TYPE] as i64,
        slots[SLOT_QUEUE] as i64,
        slots[SLOT_WAIT] as i64,
        slots[SLOT_TIMER_CREATE_BAD_OPTS] as i64,
        slots[SLOT_TIMER_CREATE_BAD_CLOCK] as i64,
        slots[SLOT_TIMER_CREATE_NULL_OUT] as i64,
        slots[SLOT_PORT_WAIT_WRONG_TYPE] as i64,
        slots[SLOT_PORT_QUEUE_WRONG_TYPE] as i64,
        slots[SLOT_TIMER_SET_WRONG_TYPE] as i64,
        slots[SLOT_TIMER_CANCEL_WRONG_TYPE] as i64,
        slots[SLOT_WAIT_ONE_UNSIGNALED] as i64,
        slots[SLOT_WAIT_ONE_UNSIGNALED_OBS] as i64,
        slots[SLOT_WAIT_ASYNC] as i64,
        slots[SLOT_TIMER_SET_IMMEDIATE] as i64,
        slots[SLOT_WAIT_SIGNAL] as i64,
        slots[SLOT_SIGNAL_TRIGGER] as i64,
        slots[SLOT_SIGNAL_OBSERVED] as i64,
        slots[SLOT_SIGNAL_COUNT],
        slots[SLOT_WAIT_ONE_SIGNALED] as i64,
        slots[SLOT_WAIT_ONE_SIGNALED_OBS] as i64,
        slots[SLOT_WAIT_ONE_FUTURE_TIMEOUT] as i64,
        slots[SLOT_WAIT_ONE_FUTURE_TIMEOUT_OBS] as i64,
        slots[SLOT_WAIT_ONE_FUTURE_OK] as i64,
        slots[SLOT_WAIT_ONE_FUTURE_OK_OBS] as i64,
        slots[SLOT_WAIT_ASYNC_BAD_OPTIONS] as i64,
        slots[SLOT_WAIT_ASYNC_TS] as i64,
        slots[SLOT_WAIT_SIGNAL_TS] as i64,
        slots[SLOT_SIGNAL_TIMESTAMP] as i64,
        slots[SLOT_SIGNAL_TIMESTAMP_OK] as i64,
        slots[SLOT_WAIT_ASYNC_BOOT] as i64,
        slots[SLOT_WAIT_SIGNAL_BOOT] as i64,
        slots[SLOT_SIGNAL_BOOT_TIMESTAMP] as i64,
        slots[SLOT_SIGNAL_BOOT_TIMESTAMP_OK] as i64,
        slots[SLOT_EDGE_WAIT_ASYNC] as i64,
        slots[SLOT_EDGE_EMPTY_WAIT] as i64,
        slots[SLOT_EDGE_SIGNAL_WAIT] as i64,
        slots[SLOT_EDGE_SIGNAL_KEY] as i64,
        slots[SLOT_RESERVE_QUEUE_FULL] as i64,
        slots[SLOT_RESERVE_WAIT_ASYNC] as i64,
        slots[SLOT_RESERVE_SIGNAL_AFTER_USERS_OK] as i64,
        slots[SLOT_RESERVE_SIGNAL_TYPE] as i64,
        slots[SLOT_PENDING_WAIT_ASYNC] as i64,
        slots[SLOT_PENDING_SIGNAL_WAIT] as i64,
        slots[SLOT_PENDING_SIGNAL_COUNT] as i64,
        slots[SLOT_PENDING_MERGE_OK] as i64,
        slots[SLOT_VMO_CREATE_BAD_OPTS] as i64,
        slots[SLOT_VMO_CREATE_NULL_OUT] as i64,
        slots[SLOT_VMO_CREATE] as i64,
        slots[SLOT_VMAR_MAP_BAD_TYPE] as i64,
        slots[SLOT_VMAR_MAP_BAD_OPTS] as i64,
        slots[SLOT_VMAR_MAP] as i64,
        slots[SLOT_VMAR_MAP_ADDR] as i64,
        slots[SLOT_VMAR_MAP_WRITE_OK] as i64,
        slots[SLOT_VMAR_OVERLAP] as i64,
        slots[SLOT_VMAR_PROTECT] as i64,
        slots[SLOT_VMAR_REPROTECT] as i64,
        slots[SLOT_VMAR_UNMAP] as i64,
        slots[SLOT_VMAR_REMAP] as i64,
        slots[SLOT_CHANNEL_CREATE_BAD_OPTS] as i64,
        slots[SLOT_CHANNEL_CREATE_NULL_OUT0] as i64,
        slots[SLOT_CHANNEL_CREATE_NULL_OUT1] as i64,
        slots[SLOT_CHANNEL_CREATE] as i64,
        slots[SLOT_CHANNEL_READ_EMPTY] as i64,
        slots[SLOT_CHANNEL_WRITE] as i64,
        slots[SLOT_CHANNEL_WAIT_READABLE] as i64,
        slots[SLOT_CHANNEL_WAIT_READABLE_OK] as i64,
        slots[SLOT_CHANNEL_READ] as i64,
        slots[SLOT_CHANNEL_READ_ACTUAL_BYTES] as i64,
        slots[SLOT_CHANNEL_READ_ACTUAL_HANDLES] as i64,
        slots[SLOT_CHANNEL_READ_MATCH] as i64,
        slots[SLOT_CHANNEL_CLOSE_PEER] as i64,
        slots[SLOT_CHANNEL_WRITE_PEER_CLOSED] as i64,
        slots[SLOT_CHANNEL_READ_PEER_CLOSED] as i64,
        slots[SLOT_CHANNEL_WAIT_PEER_CLOSED] as i64,
        slots[SLOT_CHANNEL_WAIT_PEER_CLOSED_OBS] as i64,
        slots[SLOT_EVENTPAIR_CREATE_BAD_OPTS] as i64,
        slots[SLOT_EVENTPAIR_CREATE_NULL_OUT0] as i64,
        slots[SLOT_EVENTPAIR_CREATE_NULL_OUT1] as i64,
        slots[SLOT_EVENTPAIR_CREATE] as i64,
        slots[SLOT_EVENTPAIR_SIGNAL_BAD_MASK] as i64,
        slots[SLOT_EVENTPAIR_SIGNAL_PEER] as i64,
        slots[SLOT_EVENTPAIR_WAIT_SIGNAL] as i64,
        slots[SLOT_EVENTPAIR_WAIT_SIGNAL_OBS] as i64,
        slots[SLOT_EVENTPAIR_CLOSE_PEER] as i64,
        slots[SLOT_EVENTPAIR_WAIT_PEER_CLOSED] as i64,
        slots[SLOT_EVENTPAIR_WAIT_PEER_CLOSED_OBS] as i64,
        slots[SLOT_CHANNEL_LOAN_TX_VMO_CREATE] as i64,
        slots[SLOT_CHANNEL_LOAN_TX_MAP] as i64,
        slots[SLOT_CHANNEL_LOAN_RX_VMO_CREATE] as i64,
        slots[SLOT_CHANNEL_LOAN_RX_MAP] as i64,
        slots[SLOT_CHANNEL_LOAN_CREATE] as i64,
        slots[SLOT_CHANNEL_LOAN_WRITE] as i64,
        slots[SLOT_CHANNEL_LOAN_READ] as i64,
        slots[SLOT_CHANNEL_LOAN_ACTUAL_BYTES] as i64,
        slots[SLOT_CHANNEL_LOAN_SNAPSHOT_OK] as i64,
        slots[SLOT_TIMER_SET] as i64,
        slots[SLOT_TIMER_CANCEL] as i64,
        slots[SLOT_TIMER_CLOSE] as i64,
        slots[SLOT_TIMER_CLOSE_AGAIN] as i64,
        slots[SLOT_CLOSE] as i64,
        slots[SLOT_CLOSE_AGAIN] as i64,
        slots[SLOT_ROOT_VMAR_H],
        slots[SLOT_PORT_H],
        slots[SLOT_TIMER_H],
        slots[SLOT_VMO_H],
        slots[SLOT_CHANNEL_H0],
        slots[SLOT_CHANNEL_H1],
        slots[SLOT_EVENTPAIR_H0],
        slots[SLOT_EVENTPAIR_H1]
    );

    crate::arch::qemu::exit_success();
}

/// Enter ring3 and run the embedded userspace conformance program.
pub fn prepare() -> u64 {
    map_userspace_pages();
    let entry = try_load_user_program_from_qemu_loader().unwrap_or_else(|| {
        load_user_program_embedded();
        USER_CODE_VA
    });

    // Zero shared slots and set `ok=0` pessimistically.
    let slots = shared_slots();
    for i in 0..=SLOT_MAX {
        slots[i] = 0;
    }
    // Provide a monotonic baseline so the runner can construct future deadlines
    // without introducing a new syscall ABI.
    slots[SLOT_T0_NS] = crate::time::now_ns() as u64;
    slots[SLOT_ROOT_VMAR_H] = crate::object::bootstrap_root_vmar_handle().unwrap_or(0) as u64;

    entry
}

/// Enter ring3 at `entry` and run until the conformance runner exits via `int3`.
pub fn enter(entry: u64) -> ! {
    let selectors = crate::arch::gdt::init();

    // SAFETY: we build a valid iret frame to transition to ring3 using the installed GDT selectors.
    unsafe {
        use x86_64::instructions::segmentation::{DS, ES};

        DS::set_reg(selectors.user_data);
        ES::set_reg(selectors.user_data);

        let stack = USER_STACK_TOP;
        // Keep interrupts disabled during early bring-up. We only rely on software
        // traps (`int 0x80`, `int3`) and do not yet have handlers for hardware IRQs.
        let rflags: u64 = 0x002; // bit1 set, IF=0

        core::arch::asm!(
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = in(reg) selectors.user_data.0 as u64,
            rsp = in(reg) stack,
            rflags = in(reg) rflags,
            cs = in(reg) selectors.user_code.0 as u64,
            rip = in(reg) entry,
            options(noreturn),
        );
    }
}

/// Convenience wrapper (prepare + enter).
pub fn run() -> ! {
    let entry = prepare();
    enter(entry)
}

// --- Embedded userspace program (one page) ---

core::arch::global_asm!(
    include_str!("../../../specs/conformance/runner/int80_conformance.S"),
    options(att_syntax)
);

// Compile-time witness: slot indices must fit in one page of u64 slots.
const _: () = assert!(SLOT_MAX < 512);
