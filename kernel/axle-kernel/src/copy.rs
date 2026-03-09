//! Unified internal data-move service.
//!
//! This slice centralizes plan selection and telemetry for synchronous kernel copy paths.

extern crate alloc;

use alloc::vec::Vec;
use axle_types::status::{
    ZX_ERR_BAD_STATE, ZX_ERR_INVALID_ARGS, ZX_ERR_NO_MEMORY, ZX_ERR_OUT_OF_RANGE,
};
use axle_types::{zx_handle_t, zx_status_t};
use core::mem::size_of;
use spin::Mutex;

use crate::object::{ChannelPayload, FragmentedChannelPayload};
use crate::task::{AddressSpaceId, LoanedUserPages};

const TINY_INLINE_THRESHOLD: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CopyPlan {
    TinyInlineCopy,
    BulkCopyPinned,
    FragmentAssemble,
    RemapLoan,
    ZeroFill,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CopyTelemetrySnapshot {
    pub(crate) tiny_ops: u64,
    pub(crate) tiny_bytes: u64,
    pub(crate) bulk_ops: u64,
    pub(crate) bulk_bytes: u64,
    pub(crate) fragment_ops: u64,
    pub(crate) fragment_bytes: u64,
    pub(crate) remap_ops: u64,
    pub(crate) remap_bytes: u64,
    pub(crate) remap_fallback_ops: u64,
    pub(crate) remap_fallback_bytes: u64,
    pub(crate) zero_fill_ops: u64,
    pub(crate) zero_fill_bytes: u64,
}

struct CopyTelemetry {
    snapshot: CopyTelemetrySnapshot,
}

impl CopyTelemetry {
    const fn new() -> Self {
        Self {
            snapshot: CopyTelemetrySnapshot {
                tiny_ops: 0,
                tiny_bytes: 0,
                bulk_ops: 0,
                bulk_bytes: 0,
                fragment_ops: 0,
                fragment_bytes: 0,
                remap_ops: 0,
                remap_bytes: 0,
                remap_fallback_ops: 0,
                remap_fallback_bytes: 0,
                zero_fill_ops: 0,
                zero_fill_bytes: 0,
            },
        }
    }

    fn note(&mut self, plan: CopyPlan, bytes: usize) {
        let bytes = bytes as u64;
        match plan {
            CopyPlan::TinyInlineCopy => {
                self.snapshot.tiny_ops = self.snapshot.tiny_ops.wrapping_add(1);
                self.snapshot.tiny_bytes = self.snapshot.tiny_bytes.wrapping_add(bytes);
            }
            CopyPlan::BulkCopyPinned => {
                self.snapshot.bulk_ops = self.snapshot.bulk_ops.wrapping_add(1);
                self.snapshot.bulk_bytes = self.snapshot.bulk_bytes.wrapping_add(bytes);
            }
            CopyPlan::FragmentAssemble => {
                self.snapshot.fragment_ops = self.snapshot.fragment_ops.wrapping_add(1);
                self.snapshot.fragment_bytes = self.snapshot.fragment_bytes.wrapping_add(bytes);
            }
            CopyPlan::RemapLoan => {
                self.snapshot.remap_ops = self.snapshot.remap_ops.wrapping_add(1);
                self.snapshot.remap_bytes = self.snapshot.remap_bytes.wrapping_add(bytes);
            }
            CopyPlan::ZeroFill => {
                self.snapshot.zero_fill_ops = self.snapshot.zero_fill_ops.wrapping_add(1);
                self.snapshot.zero_fill_bytes = self.snapshot.zero_fill_bytes.wrapping_add(bytes);
            }
        }
    }

    fn note_remap_fallback(&mut self, bytes: usize) {
        let bytes = bytes as u64;
        self.snapshot.remap_fallback_ops = self.snapshot.remap_fallback_ops.wrapping_add(1);
        self.snapshot.remap_fallback_bytes = self.snapshot.remap_fallback_bytes.wrapping_add(bytes);
    }
}

static TELEMETRY: Mutex<CopyTelemetry> = Mutex::new(CopyTelemetry::new());

#[derive(Clone, Copy, Debug)]
struct ValidatedUserSpan {
    address_space_id: AddressSpaceId,
    base: u64,
    len: usize,
}

impl ValidatedUserSpan {
    const fn new(address_space_id: AddressSpaceId, base: u64, len: usize) -> Self {
        Self {
            address_space_id,
            base,
            len,
        }
    }

    fn subspan(&self, byte_offset: usize, len: usize) -> Result<Self, zx_status_t> {
        let end = byte_offset.checked_add(len).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if end > self.len {
            return Err(ZX_ERR_OUT_OF_RANGE);
        }
        let base = self
            .base
            .checked_add(byte_offset as u64)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        Ok(Self::new(self.address_space_id, base, len))
    }
}

#[derive(Clone, Copy, Debug)]
struct UserCopyCtx {
    address_space_id: AddressSpaceId,
}

impl UserCopyCtx {
    fn current() -> Result<Self, zx_status_t> {
        let kernel = crate::object::kernel_handle()?;
        let kernel = kernel.lock();
        let process = kernel.current_process_info()?;
        let address_space_id = kernel.process_address_space_id(process.process_id())?;
        Ok(Self { address_space_id })
    }

    fn validate_read(&self, ptr: u64, len: usize) -> Result<ValidatedUserSpan, zx_status_t> {
        validate_user_span(self.address_space_id, ptr, len, false)
    }

    fn validate_write(&self, ptr: u64, len: usize) -> Result<ValidatedUserSpan, zx_status_t> {
        validate_user_span(self.address_space_id, ptr, len, true)
    }

    fn try_pin_read(&self, ptr: u64, len: usize) -> Result<Option<LoanedUserPages>, zx_status_t> {
        let kernel = crate::object::kernel_handle()?;
        let vm = { kernel.lock().vm_handle() };
        vm.try_loan_user_pages(self.address_space_id, ptr, len)
    }
}

fn validate_user_span(
    address_space_id: AddressSpaceId,
    ptr: u64,
    len: usize,
    for_write: bool,
) -> Result<ValidatedUserSpan, zx_status_t> {
    if len == 0 {
        return Ok(ValidatedUserSpan::new(address_space_id, ptr, 0));
    }
    if ptr == 0 || !crate::userspace::validate_user_ptr(ptr, len) {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    crate::userspace::ensure_user_range_resident(ptr, len, for_write)?;
    Ok(ValidatedUserSpan::new(address_space_id, ptr, len))
}

fn plan_for_len(len: usize) -> CopyPlan {
    if len <= TINY_INLINE_THRESHOLD {
        CopyPlan::TinyInlineCopy
    } else {
        CopyPlan::BulkCopyPinned
    }
}

fn note_plan(plan: CopyPlan, bytes: usize) {
    TELEMETRY.lock().note(plan, bytes);
}

fn note_remap_fallback(bytes: usize) {
    TELEMETRY.lock().note_remap_fallback(bytes);
}

pub(crate) fn telemetry_snapshot() -> CopyTelemetrySnapshot {
    TELEMETRY.lock().snapshot
}

fn probe_user_bytes(ptr: u64, len: usize) -> Result<(), zx_status_t> {
    if len == 0 {
        return Ok(());
    }
    if ptr == 0 || !crate::userspace::validate_user_ptr(ptr, len) {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(())
}

pub(crate) fn probe_write_value<T>(ptr: *mut T) -> Result<(), zx_status_t> {
    probe_user_bytes(ptr as u64, size_of::<T>())
}

pub(crate) fn probe_read_bytes(ptr: *const u8, len: usize) -> Result<(), zx_status_t> {
    probe_user_bytes(ptr as u64, len)
}

pub(crate) fn probe_resident_write_bytes(ptr: *mut u8, len: usize) -> Result<(), zx_status_t> {
    if len == 0 {
        return Ok(());
    }
    let ctx = UserCopyCtx::current()?;
    ctx.validate_write(ptr as u64, len)?;
    Ok(())
}

pub(crate) fn probe_write_handles(ptr: *mut zx_handle_t, len: usize) -> Result<(), zx_status_t> {
    if len == 0 {
        return Ok(());
    }
    let byte_len = len
        .checked_mul(size_of::<zx_handle_t>())
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    probe_resident_write_bytes(ptr.cast::<u8>(), byte_len)
}

pub(crate) fn copyin_value<T: Copy>(ptr: *const T) -> Result<T, zx_status_t> {
    if ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let ctx = UserCopyCtx::current()?;
    let span = ctx.validate_read(ptr as u64, size_of::<T>())?;
    let mut out = core::mem::MaybeUninit::<T>::uninit();
    let out_bytes = unsafe {
        // SAFETY: `out` points to enough uninitialized storage for exactly one `T`. We only
        // expose it as a mutable byte slice with the same size.
        core::slice::from_raw_parts_mut(out.as_mut_ptr().cast::<u8>(), size_of::<T>())
    };
    crate::userspace::read_validated_user_bytes(span.base, out_bytes);
    note_plan(plan_for_len(out_bytes.len()), out_bytes.len());
    Ok(unsafe {
        // SAFETY: the full object representation was just written by the user-byte copy above.
        out.assume_init()
    })
}

pub(crate) fn copyout_value<T: Copy>(ptr: *mut T, value: T) -> Result<(), zx_status_t> {
    if ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let ctx = UserCopyCtx::current()?;
    let span = ctx.validate_write(ptr as u64, size_of::<T>())?;
    let bytes = unsafe {
        // SAFETY: `value` lives for this scope and we only create an immutable byte view over its
        // exact object representation.
        core::slice::from_raw_parts((&value as *const T).cast::<u8>(), size_of::<T>())
    };
    write_bytes_to_span(span, bytes)
}

pub(crate) fn copyin_bytes(ptr: *const u8, len: usize) -> Result<Vec<u8>, zx_status_t> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let ctx = UserCopyCtx::current()?;
    let span = ctx.validate_read(ptr as u64, len)?;
    let mut out = Vec::new();
    out.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
    out.resize(len, 0);
    crate::userspace::read_validated_user_bytes(span.base, &mut out);
    note_plan(plan_for_len(len), len);
    Ok(out)
}

pub(crate) fn copyout_bytes(ptr: *mut u8, bytes: &[u8]) -> Result<(), zx_status_t> {
    if bytes.is_empty() {
        return Ok(());
    }
    let ctx = UserCopyCtx::current()?;
    let span = ctx.validate_write(ptr as u64, bytes.len())?;
    write_bytes_to_span(span, bytes)
}

pub(crate) fn copyin_handles(
    ptr: *const zx_handle_t,
    len: usize,
) -> Result<Vec<zx_handle_t>, zx_status_t> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let byte_len = len
        .checked_mul(size_of::<zx_handle_t>())
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let raw = copyin_bytes(ptr.cast::<u8>(), byte_len)?;
    let mut handles = Vec::new();
    handles
        .try_reserve_exact(len)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    for chunk in raw.chunks_exact(size_of::<zx_handle_t>()) {
        let bytes: [u8; size_of::<zx_handle_t>()] =
            chunk.try_into().map_err(|_| ZX_ERR_BAD_STATE)?;
        handles.push(zx_handle_t::from_ne_bytes(bytes));
    }
    Ok(handles)
}

pub(crate) fn copyout_handles(
    ptr: *mut zx_handle_t,
    handles: &[zx_handle_t],
) -> Result<(), zx_status_t> {
    if handles.is_empty() {
        return Ok(());
    }
    let byte_len = handles
        .len()
        .checked_mul(size_of::<zx_handle_t>())
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(byte_len)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    for handle in handles {
        raw.extend_from_slice(&handle.to_ne_bytes());
    }
    copyout_bytes(ptr.cast::<u8>(), &raw)
}

fn write_bytes_to_span(span: ValidatedUserSpan, bytes: &[u8]) -> Result<(), zx_status_t> {
    write_bytes_to_span_with_tracking(span, bytes, true)
}

fn write_bytes_to_span_with_tracking(
    span: ValidatedUserSpan,
    bytes: &[u8],
    track: bool,
) -> Result<(), zx_status_t> {
    if bytes.len() != span.len {
        return Err(ZX_ERR_OUT_OF_RANGE);
    }
    crate::userspace::write_validated_user_bytes(span.base, bytes);
    if track {
        note_plan(plan_for_len(bytes.len()), bytes.len());
    }
    Ok(())
}

fn copyout_loaned_to_span(
    span: ValidatedUserSpan,
    byte_offset: usize,
    loaned: &LoanedUserPages,
) -> Result<(), zx_status_t> {
    copyout_loaned_to_span_with_tracking(span, byte_offset, loaned, true)
}

fn copyout_loaned_to_span_with_tracking(
    span: ValidatedUserSpan,
    byte_offset: usize,
    loaned: &LoanedUserPages,
    track: bool,
) -> Result<(), zx_status_t> {
    let len = usize::try_from(loaned.len()).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let page_size = crate::userspace::USER_PAGE_BYTES as usize;
    if len == 0 {
        return Ok(());
    }
    let page_count = len / page_size;
    if page_count != loaned.pages().len() {
        return Err(ZX_ERR_BAD_STATE);
    }
    let dst = span.subspan(byte_offset, len)?;
    for (page_index, frame_id) in loaned.pages().iter().copied().enumerate() {
        let dst_ptr = dst
            .base
            .checked_add((page_index * page_size) as u64)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        crate::userspace::copy_bootstrap_frame_into_validated_user(
            dst_ptr,
            frame_id.raw(),
            page_size,
        );
    }
    if track {
        note_plan(CopyPlan::BulkCopyPinned, len);
    }
    Ok(())
}

fn copy_fragmented_payload_to_span(
    span: ValidatedUserSpan,
    payload: &FragmentedChannelPayload,
) -> Result<(), zx_status_t> {
    let head_len = payload.head.len();
    let body_len = payload
        .body
        .as_ref()
        .map(|loaned| usize::try_from(loaned.len()).map_err(|_| ZX_ERR_OUT_OF_RANGE))
        .transpose()?
        .unwrap_or(0);
    let tail_len = payload.tail.len();
    let total = head_len
        .checked_add(body_len)
        .and_then(|len| len.checked_add(tail_len))
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    if total != span.len || u32::try_from(total).map_err(|_| ZX_ERR_OUT_OF_RANGE)? != payload.len {
        return Err(ZX_ERR_BAD_STATE);
    }

    if let Some(body) = payload.body.as_ref() {
        let body_base = span
            .base
            .checked_add(head_len as u64)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        match crate::object::transport::try_remap_loaned_channel_read(body_base, body) {
            Ok(true) => note_plan(CopyPlan::RemapLoan, body_len),
            Ok(false) => {
                note_remap_fallback(body_len);
                copyout_loaned_to_span_with_tracking(span, head_len, body, false)?;
            }
            Err(err) => return Err(err),
        }
    }

    if head_len != 0 {
        let head = span.subspan(0, head_len)?;
        write_bytes_to_span_with_tracking(head, &payload.head, false)?;
    }
    if tail_len != 0 {
        let tail = span.subspan(head_len + body_len, tail_len)?;
        write_bytes_to_span_with_tracking(tail, &payload.tail, false)?;
    }
    note_plan(CopyPlan::FragmentAssemble, total);
    Ok(())
}

pub(crate) fn write_channel_payload_to_user(
    dst_ptr: *mut u8,
    payload: &ChannelPayload,
) -> Result<(), zx_status_t> {
    let len = usize::try_from(payload.actual_bytes()?).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    if len == 0 {
        return Ok(());
    }
    let ctx = UserCopyCtx::current()?;
    let span = ctx.validate_write(dst_ptr as u64, len)?;
    match payload {
        ChannelPayload::Copied(bytes) => write_bytes_to_span(span, bytes),
        ChannelPayload::Loaned(loaned) => {
            match crate::object::transport::try_remap_loaned_channel_read(span.base, loaned) {
                Ok(true) => {
                    note_plan(CopyPlan::RemapLoan, len);
                    Ok(())
                }
                Ok(false) => {
                    note_remap_fallback(len);
                    copyout_loaned_to_span(span, 0, loaned)
                }
                Err(err) => Err(err),
            }
        }
        ChannelPayload::Fragmented(payload) => copy_fragmented_payload_to_span(span, payload),
    }
}

pub(crate) fn copyout_loaned_bytes(
    ptr: *mut u8,
    loaned: &LoanedUserPages,
) -> Result<(), zx_status_t> {
    let span = UserCopyCtx::current()?.validate_write(
        ptr as u64,
        usize::try_from(loaned.len()).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
    )?;
    copyout_loaned_to_span(span, 0, loaned)
}

pub(crate) fn prepare_channel_write_payload(
    ptr: *const u8,
    len: usize,
) -> Result<ChannelPayload, zx_status_t> {
    if len == 0 {
        return Ok(ChannelPayload::Copied(Vec::new()));
    }

    let ctx = UserCopyCtx::current()?;
    let span = ctx.validate_read(ptr as u64, len)?;
    if let Some(loaned) = ctx.try_pin_read(span.base, len)? {
        note_plan(CopyPlan::RemapLoan, len);
        return Ok(ChannelPayload::Loaned(loaned));
    }

    let start = span.base;
    let end = start.checked_add(len as u64).ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let head_end = if (start & (crate::userspace::USER_PAGE_BYTES - 1)) == 0 {
        start
    } else {
        start
            .checked_add(
                crate::userspace::USER_PAGE_BYTES
                    - (start & (crate::userspace::USER_PAGE_BYTES - 1)),
            )
            .ok_or(ZX_ERR_OUT_OF_RANGE)?
    };
    let body_start = head_end.min(end);
    let body_end = end & !(crate::userspace::USER_PAGE_BYTES - 1);

    if body_end > body_start {
        let head_len = usize::try_from(body_start - start).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let body_len = usize::try_from(body_end - body_start).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let tail_len = usize::try_from(end - body_end).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        if let Some(body) = ctx.try_pin_read(body_start, body_len)? {
            let head = if head_len == 0 {
                Vec::new()
            } else {
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(head_len)
                    .map_err(|_| ZX_ERR_NO_MEMORY)?;
                bytes.resize(head_len, 0);
                crate::userspace::read_validated_user_bytes(span.base, &mut bytes);
                bytes
            };
            let tail = if tail_len == 0 {
                Vec::new()
            } else {
                let tail_base = body_end;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(tail_len)
                    .map_err(|_| ZX_ERR_NO_MEMORY)?;
                bytes.resize(tail_len, 0);
                crate::userspace::read_validated_user_bytes(tail_base, &mut bytes);
                bytes
            };
            note_plan(CopyPlan::FragmentAssemble, len);
            return Ok(ChannelPayload::Fragmented(FragmentedChannelPayload {
                head,
                body: Some(body),
                tail,
                len: u32::try_from(len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
            }));
        }
    }

    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
    bytes.resize(len, 0);
    crate::userspace::read_validated_user_bytes(span.base, &mut bytes);
    note_plan(plan_for_len(len), len);
    Ok(ChannelPayload::Copied(bytes))
}

pub(crate) fn socket_write_from_user(
    handle: zx_handle_t,
    options: u32,
    buffer: *const u8,
    len: usize,
) -> Result<usize, zx_status_t> {
    if len == 0 {
        return crate::object::transport::socket_write(handle, options, &[]);
    }
    let bytes = copyin_bytes(buffer, len)?;
    crate::object::transport::socket_write(handle, options, &bytes)
}

pub(crate) fn socket_read_to_user(
    handle: zx_handle_t,
    options: u32,
    buffer: *mut u8,
    len: usize,
) -> Result<usize, zx_status_t> {
    let bytes = crate::object::transport::socket_read(handle, options, len)?;
    copyout_bytes(buffer, &bytes)?;
    Ok(bytes.len())
}

pub(crate) fn vmo_write_from_user(
    handle: zx_handle_t,
    offset: u64,
    buffer: *const u8,
    len: usize,
) -> Result<(), zx_status_t> {
    let bytes = copyin_bytes(buffer, len)?;
    crate::object::vm::vmo_write(handle, offset, &bytes)
}

pub(crate) fn vmo_read_to_user(
    handle: zx_handle_t,
    offset: u64,
    buffer: *mut u8,
    len: usize,
) -> Result<(), zx_status_t> {
    let bytes = crate::object::vm::vmo_read(handle, offset, len)?;
    copyout_bytes(buffer, &bytes)
}

pub(crate) fn read_bootstrap_frame_bytes(
    frame_paddr: u64,
    byte_offset: usize,
    dst: &mut [u8],
) -> Result<(), zx_status_t> {
    crate::userspace::read_bootstrap_bytes(frame_paddr, byte_offset, dst)
        .ok_or(ZX_ERR_BAD_STATE)?;
    note_plan(plan_for_len(dst.len()), dst.len());
    Ok(())
}

pub(crate) fn write_bootstrap_frame_bytes(
    frame_paddr: u64,
    byte_offset: usize,
    src: &[u8],
) -> Result<(), zx_status_t> {
    crate::userspace::write_bootstrap_bytes(frame_paddr, byte_offset, src)
        .ok_or(ZX_ERR_BAD_STATE)?;
    note_plan(plan_for_len(src.len()), src.len());
    Ok(())
}

pub(crate) fn copy_kernel_bytes(dst: &mut [u8], src: &[u8]) -> Result<(), zx_status_t> {
    if dst.len() != src.len() {
        return Err(ZX_ERR_OUT_OF_RANGE);
    }
    dst.copy_from_slice(src);
    note_plan(plan_for_len(src.len()), src.len());
    Ok(())
}

pub(crate) fn zero_fill(bytes: &mut [u8]) {
    bytes.fill(0);
    note_plan(CopyPlan::ZeroFill, bytes.len());
}

pub(crate) fn write_current_mapping_bytes(dst_ptr: u64, src: &[u8]) {
    crate::userspace::write_current_mapping_bytes(dst_ptr, src);
    note_plan(plan_for_len(src.len()), src.len());
}

pub(crate) fn zero_current_mapping_bytes(dst_ptr: u64, len: usize) {
    crate::userspace::zero_current_mapping_bytes(dst_ptr, len);
    note_plan(CopyPlan::ZeroFill, len);
}
