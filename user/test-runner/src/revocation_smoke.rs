use core::alloc::{GlobalAlloc, Layout};
use core::fmt;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_arch_x86_64::debug_break;
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::rights::ZX_RIGHT_SAME_RIGHTS;
use axle_types::signals::ZX_USER_SIGNAL_0;
use axle_types::status::{ZX_ERR_BAD_HANDLE, ZX_OK};
use axle_types::{zx_handle_t, zx_revocation_group_info_t, zx_signals_t};
use libzircon::{
    ax_console_write, ax_handle_duplicate_revocable, ax_revocation_group_create,
    ax_revocation_group_get_info, ax_revocation_group_revoke, zx_channel_create, zx_channel_read,
    zx_channel_write, zx_eventpair_create, zx_handle_close, zx_handle_duplicate,
    zx_object_signal_peer, zx_object_wait_one,
};

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;
const SLOT_OK: usize = 0;
const HEAP_BYTES: usize = 8 * 1024;

const STEP_PANIC: u64 = u64::MAX;
const STEP_EVENTPAIR_CREATE: u64 = 1;
const STEP_GROUP_CREATE: u64 = 2;
const STEP_INFO_BEFORE: u64 = 3;
const STEP_DUP_REVOCABLE: u64 = 4;
const STEP_DUP_INHERITED: u64 = 5;
const STEP_CHANNEL_CREATE: u64 = 6;
const STEP_CHANNEL_WRITE: u64 = 7;
const STEP_CHANNEL_READ: u64 = 8;
const STEP_REVOKE: u64 = 9;
const STEP_INFO_AFTER: u64 = 10;
const STEP_BASE_SIGNAL: u64 = 11;
const STEP_BASE_WAIT: u64 = 12;
const STEP_INHERITED_WAIT: u64 = 13;
const STEP_TRANSFERRED_WAIT: u64 = 14;
const STEP_INHERITED_DUP: u64 = 15;
const STEP_DUP_AFTER_REVOKE: u64 = 16;
const STEP_DUP_AFTER_REVOKE_DUP: u64 = 17;

#[derive(Clone, Copy, Default)]
struct RevocationSummary {
    failure_step: u64,
    eventpair_create: i64,
    group_create: i64,
    info_before: i64,
    group_epoch_before: u32,
    group_generation_before: u32,
    dup_revocable: i64,
    dup_inherited: i64,
    inherited_distinct: u64,
    channel_create: i64,
    channel_write: i64,
    channel_read: i64,
    transferred_actual_handles: u32,
    revoke: i64,
    info_after: i64,
    group_epoch_after: u32,
    group_generation_after: u32,
    base_signal: i64,
    base_wait: i64,
    base_wait_observed: u32,
    inherited_wait_bad_handle: i64,
    transferred_wait_bad_handle: i64,
    inherited_dup_bad_handle: i64,
    dup_after_revoke: i64,
    dup_after_revoke_dup: i64,
}

#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);

struct FixedBuf<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> FixedBuf<N> {
    const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl<const N: usize> fmt::Write for FixedBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        if self.len.saturating_add(bytes.len()) > N {
            return Err(fmt::Error);
        }
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

// SAFETY: this allocator is only used by the bootstrap revocation smoke. It monotonically carves
// aligned, non-overlapping ranges out of one fixed static heap and never reuses freed memory.
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
                    // SAFETY: each successful bump allocation hands out a unique region within
                    // the dedicated static heap backing this single bootstrap binary.
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
    let summary = run_revocation_smoke();
    emit_summary(&summary);
    write_slot(SLOT_OK, 1);
    debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    let summary = RevocationSummary {
        failure_step: STEP_PANIC,
        ..RevocationSummary::default()
    };
    emit_summary(&summary);
    write_slot(SLOT_OK, 1);
    debug_break()
}

fn run_revocation_smoke() -> RevocationSummary {
    let mut summary = RevocationSummary::default();
    let mut base = ZX_HANDLE_INVALID;
    let mut peer = ZX_HANDLE_INVALID;
    summary.eventpair_create = zx_eventpair_create(0, &mut base, &mut peer) as i64;
    if summary.eventpair_create != ZX_OK as i64 {
        summary.failure_step = STEP_EVENTPAIR_CREATE;
        return summary;
    }

    let mut group = ZX_HANDLE_INVALID;
    summary.group_create = ax_revocation_group_create(0, &mut group) as i64;
    if summary.group_create != ZX_OK as i64 {
        summary.failure_step = STEP_GROUP_CREATE;
        let _ = zx_handle_close(base);
        let _ = zx_handle_close(peer);
        return summary;
    }

    let mut info = zx_revocation_group_info_t::default();
    summary.info_before = ax_revocation_group_get_info(group, &mut info) as i64;
    if summary.info_before != ZX_OK as i64 {
        summary.failure_step = STEP_INFO_BEFORE;
        close_handles(&[base, peer, group]);
        return summary;
    }
    summary.group_epoch_before = info.epoch;
    summary.group_generation_before = info.generation;

    let mut delegated = ZX_HANDLE_INVALID;
    summary.dup_revocable =
        ax_handle_duplicate_revocable(base, ZX_RIGHT_SAME_RIGHTS, group, &mut delegated) as i64;
    if summary.dup_revocable != ZX_OK as i64 {
        summary.failure_step = STEP_DUP_REVOCABLE;
        close_handles(&[base, peer, group]);
        return summary;
    }

    let mut inherited = ZX_HANDLE_INVALID;
    summary.dup_inherited =
        zx_handle_duplicate(delegated, ZX_RIGHT_SAME_RIGHTS, &mut inherited) as i64;
    summary.inherited_distinct =
        u64::from(inherited != delegated && inherited != ZX_HANDLE_INVALID);
    if summary.dup_inherited != ZX_OK as i64 || summary.inherited_distinct != 1 {
        summary.failure_step = STEP_DUP_INHERITED;
        close_handles(&[base, peer, group, delegated, inherited]);
        return summary;
    }

    let mut ch0 = ZX_HANDLE_INVALID;
    let mut ch1 = ZX_HANDLE_INVALID;
    summary.channel_create = zx_channel_create(0, &mut ch0, &mut ch1) as i64;
    if summary.channel_create != ZX_OK as i64 {
        summary.failure_step = STEP_CHANNEL_CREATE;
        close_handles(&[base, peer, group, delegated, inherited]);
        return summary;
    }

    let handles = [delegated];
    summary.channel_write = zx_channel_write(ch0, 0, ptr::null(), 0, handles.as_ptr(), 1) as i64;
    if summary.channel_write != ZX_OK as i64 {
        summary.failure_step = STEP_CHANNEL_WRITE;
        close_handles(&[base, peer, group, delegated, inherited, ch0, ch1]);
        return summary;
    }

    let mut out_handle = ZX_HANDLE_INVALID;
    let mut actual_bytes = 0u32;
    let mut actual_handles = 0u32;
    let mut dummy = [0u8; 1];
    summary.channel_read = zx_channel_read(
        ch1,
        0,
        dummy.as_mut_ptr(),
        &mut out_handle,
        0,
        1,
        &mut actual_bytes,
        &mut actual_handles,
    ) as i64;
    summary.transferred_actual_handles = actual_handles;
    if summary.channel_read != ZX_OK as i64 || actual_handles != 1 {
        summary.failure_step = STEP_CHANNEL_READ;
        close_handles(&[base, peer, group, inherited, ch0, ch1, out_handle]);
        return summary;
    }

    summary.revoke = ax_revocation_group_revoke(group) as i64;
    if summary.revoke != ZX_OK as i64 {
        summary.failure_step = STEP_REVOKE;
        close_handles(&[base, peer, group, inherited, ch0, ch1, out_handle]);
        return summary;
    }

    info = zx_revocation_group_info_t::default();
    summary.info_after = ax_revocation_group_get_info(group, &mut info) as i64;
    if summary.info_after != ZX_OK as i64 {
        summary.failure_step = STEP_INFO_AFTER;
        close_handles(&[base, peer, group, inherited, ch0, ch1, out_handle]);
        return summary;
    }
    summary.group_epoch_after = info.epoch;
    summary.group_generation_after = info.generation;

    summary.base_signal = zx_object_signal_peer(peer, 0, ZX_USER_SIGNAL_0) as i64;
    if summary.base_signal != ZX_OK as i64 {
        summary.failure_step = STEP_BASE_SIGNAL;
        close_handles(&[base, peer, group, inherited, ch0, ch1, out_handle]);
        return summary;
    }
    let mut observed = 0u32;
    summary.base_wait = zx_object_wait_one(base, ZX_USER_SIGNAL_0, 0, &mut observed) as i64;
    summary.base_wait_observed = observed;
    if summary.base_wait != ZX_OK as i64 {
        summary.failure_step = STEP_BASE_WAIT;
        close_handles(&[base, peer, group, inherited, ch0, ch1, out_handle]);
        return summary;
    }

    observed = 0;
    summary.inherited_wait_bad_handle =
        zx_object_wait_one(inherited, ZX_USER_SIGNAL_0, 0, &mut observed) as i64;
    if summary.inherited_wait_bad_handle != ZX_ERR_BAD_HANDLE as i64 {
        summary.failure_step = STEP_INHERITED_WAIT;
        close_handles(&[base, peer, group, inherited, ch0, ch1, out_handle]);
        return summary;
    }

    observed = 0;
    summary.transferred_wait_bad_handle =
        zx_object_wait_one(out_handle, ZX_USER_SIGNAL_0, 0, &mut observed) as i64;
    if summary.transferred_wait_bad_handle != ZX_ERR_BAD_HANDLE as i64 {
        summary.failure_step = STEP_TRANSFERRED_WAIT;
        close_handles(&[base, peer, group, inherited, ch0, ch1, out_handle]);
        return summary;
    }

    let mut inherit_dup = ZX_HANDLE_INVALID;
    summary.inherited_dup_bad_handle =
        zx_handle_duplicate(inherited, ZX_RIGHT_SAME_RIGHTS, &mut inherit_dup) as i64;
    if summary.inherited_dup_bad_handle != ZX_ERR_BAD_HANDLE as i64 {
        summary.failure_step = STEP_INHERITED_DUP;
        close_handles(&[
            base,
            peer,
            group,
            inherited,
            ch0,
            ch1,
            out_handle,
            inherit_dup,
        ]);
        return summary;
    }

    let mut delegated_after = ZX_HANDLE_INVALID;
    summary.dup_after_revoke =
        ax_handle_duplicate_revocable(base, ZX_RIGHT_SAME_RIGHTS, group, &mut delegated_after)
            as i64;
    if summary.dup_after_revoke != ZX_OK as i64 {
        summary.failure_step = STEP_DUP_AFTER_REVOKE;
        close_handles(&[
            base,
            peer,
            group,
            inherited,
            ch0,
            ch1,
            out_handle,
            delegated_after,
        ]);
        return summary;
    }

    let mut delegated_after_dup = ZX_HANDLE_INVALID;
    summary.dup_after_revoke_dup = zx_handle_duplicate(
        delegated_after,
        ZX_RIGHT_SAME_RIGHTS,
        &mut delegated_after_dup,
    ) as i64;
    if summary.dup_after_revoke_dup != ZX_OK as i64 {
        summary.failure_step = STEP_DUP_AFTER_REVOKE_DUP;
    }

    close_handles(&[
        base,
        peer,
        group,
        inherited,
        ch0,
        ch1,
        out_handle,
        delegated_after,
        delegated_after_dup,
    ]);
    summary
}

fn close_handles(handles: &[zx_handle_t]) {
    for &handle in handles {
        if handle != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(handle);
        }
    }
}

fn emit_summary(summary: &RevocationSummary) {
    let mut line = FixedBuf::<1024>::new();
    let _ = fmt::write(
        &mut line,
        format_args!(
            "kernel: revocation smoke (rev_present=1, rev_failure_step={}, eventpair_create={}, group_create={}, info_before={}, group_epoch_before={}, group_generation_before={}, dup_revocable={}, dup_inherited={}, inherited_distinct={}, channel_create={}, channel_write={}, channel_read={}, transferred_actual_handles={}, revoke={}, info_after={}, group_epoch_after={}, group_generation_after={}, base_signal={}, base_wait={}, base_wait_observed={}, inherited_wait_bad_handle={}, transferred_wait_bad_handle={}, inherited_dup_bad_handle={}, dup_after_revoke={}, dup_after_revoke_dup={})\n",
            summary.failure_step,
            summary.eventpair_create,
            summary.group_create,
            summary.info_before,
            summary.group_epoch_before,
            summary.group_generation_before,
            summary.dup_revocable,
            summary.dup_inherited,
            summary.inherited_distinct,
            summary.channel_create,
            summary.channel_write,
            summary.channel_read,
            summary.transferred_actual_handles,
            summary.revoke,
            summary.info_after,
            summary.group_epoch_after,
            summary.group_generation_after,
            summary.base_signal,
            summary.base_wait,
            summary.base_wait_observed,
            summary.inherited_wait_bad_handle,
            summary.transferred_wait_bad_handle,
            summary.inherited_dup_bad_handle,
            summary.dup_after_revoke,
            summary.dup_after_revoke_dup,
        ),
    );
    let mut actual = 0usize;
    let _ = ax_console_write(line.as_bytes(), &mut actual);
}

fn write_slot(slot: usize, value: u64) {
    let ptr = (USER_SHARED_BASE as *mut u64).wrapping_add(slot);
    // SAFETY: the bootstrap runner ABI reserves the shared summary page range at USER_SHARED_BASE.
    unsafe { ptr::write_volatile(ptr, value) };
}
