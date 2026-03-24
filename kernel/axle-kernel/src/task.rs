//! Bootstrap kernel/process/thread/address-space model.
//!
//! This is intentionally minimal:
//! - one global `Kernel` state object
//! - one bootstrap `Process`
//! - one bootstrap `Thread`
//! - one bootstrap `AddressSpace`
//!
//! The goal is to move handle ownership and user-pointer validation behind the
//! same internal model that later phases can extend, without changing the
//! current syscall ABI.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::task::runtime::Job;
use axle_core::handle::Handle;
use axle_core::{
    CSpace, CSpaceError, Capability, ObjectKey, ObserverRegistry, ReactorTimerCore,
    ReactorTimerEvent, RevocationManager, Signals, TimerError, TimerId, TransferredCap,
    WaitDeadlineId,
};
use axle_mm::{
    AddressSpace as VmAddressSpace, AddressSpaceError, AddressSpaceId as VmAddressSpaceId,
    CowFaultResolution, FrameId, FrameTable, FutexKey, GlobalVmoId, LazyAnonFaultResolution,
    LazyVmoFaultResolution, LoanToken, MapRec, MappingCachePolicy, MappingClonePolicy,
    MappingPerms, PageFaultDecision, PageFaultFlags, PteMeta, PteMetaTag, ReverseMapAnchor,
    VmaLookup, Vmar, VmarAllocMode, VmarId, VmarPlacementPolicy, Vmo, VmoId, VmoKind,
};
use axle_page_table::{
    MappingCachePolicy as PtMappingCachePolicy, PageMapping, PageRange, PageTable, PageTableError,
    TxCursor, TxSet,
};
use axle_types::rights::{
    ZX_RIGHT_APPLY_PROFILE, ZX_RIGHT_DESTROY, ZX_RIGHT_DUPLICATE, ZX_RIGHT_ENUMERATE,
    ZX_RIGHT_EXECUTE, ZX_RIGHT_GET_POLICY, ZX_RIGHT_GET_PROPERTY, ZX_RIGHT_INSPECT,
    ZX_RIGHT_MANAGE_JOB, ZX_RIGHT_MANAGE_PROCESS, ZX_RIGHT_MANAGE_THREAD, ZX_RIGHT_MAP,
    ZX_RIGHT_READ, ZX_RIGHT_SET_POLICY, ZX_RIGHT_SET_PROPERTY, ZX_RIGHT_SIGNAL,
    ZX_RIGHT_SIGNAL_PEER, ZX_RIGHT_TRANSFER, ZX_RIGHT_WAIT, ZX_RIGHT_WRITE,
};
use axle_types::status::{
    ZX_ERR_ACCESS_DENIED, ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_STATE,
    ZX_ERR_INTERNAL, ZX_ERR_INVALID_ARGS, ZX_ERR_NO_MEMORY, ZX_ERR_NO_RESOURCES, ZX_ERR_NOT_FOUND,
    ZX_ERR_NOT_SUPPORTED, ZX_ERR_OUT_OF_RANGE, ZX_ERR_SHOULD_WAIT, ZX_OK,
};
use axle_types::{
    ax_guest_x64_regs_t, ax_linux_exec_spec_header_t, zx_handle_t, zx_koid_t, zx_port_packet_t,
    zx_rights_t, zx_signals_t, zx_status_t,
};
use bitflags::bitflags;
use core::mem::size_of;
use raw_cpuid::CpuId;
use spin::Mutex;

mod backing;
mod clone;
mod facade;
pub(crate) mod fault;
mod image;
mod runtime;
mod scheduler;
mod trap;
mod vmo;
mod vmo_object;
mod wait;

use backing::{FilePagerSource, GlobalVmoStore, PagerReadAtFn, PagerSourceHandle};
pub(crate) use facade::{
    VmFacade, bootstrap_user_runner_source_size, read_bootstrap_user_runner_source_at,
};
use fault::{FaultCommitDisposition, FaultPlan, FaultPlanResult, PreparedFaultWork};
pub(crate) use fault::{FaultInFlightKey, FaultTable};
pub(crate) use image::{
    CreatedVmo, KernelVmoBacking, LinuxExecExtraImage, ProcessImageElfInfo, ProcessImageLayout,
    ProcessImageSegment, process_image_default_code_perms,
};
use image::{ImportedProcessImage, align_up_user_page};
use runtime::Process;
#[allow(unused_imports)]
pub(crate) use runtime::{
    CreatedProcess, CurrentProcessInfo, CurrentThreadInfo, ObjectKindTag, PreparedProcessStart,
};
use scheduler::{CpuSchedulerState, StartPlacementPolicy};
pub(crate) use trap::TrapExitDisposition;
use trap::UserContext;
use vmo::VmoResizeResult;
use wait::WaitNode;
pub(crate) use wait::{ExpiredWait, Reactor, ReactorPollEvent, WaitRegistration, WaitSourceKey};

const CSPACE_MAX_SLOTS: u32 = 16_384;
const CSPACE_QUARANTINE_LEN: usize = 256;
const DEFAULT_MAX_INFLIGHT_LOAN_PAGES: Option<u64> = Some(32);
const DEFAULT_MAX_PRIVATE_COW_PAGES: Option<u64> = None;
const FAULT_WAIT_SPIN_LOOPS: usize = 256;
const DEFAULT_TIME_SLICE_NS: i64 = 4_000_000;
const VM_FRAME_DIAGNOSTICS_ENABLED: bool =
    cfg!(debug_assertions) || cfg!(feature = "vm-diagnostics");

type ProcessId = u64;
type ThreadId = u64;
pub(crate) type JobId = u64;
pub(crate) type AddressSpaceId = u64;
type KernelVmoId = GlobalVmoId;

/// TLB synchronization class attached to one committed VM mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitClass {
    Relaxed,
    Strict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TlbInvalidateHint {
    None,
    Range(PageRange),
    Full,
}

/// Post-commit TLB synchronization requirement for one address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TlbCommitReq {
    address_space_id: AddressSpaceId,
    class: CommitClass,
    invalidate_hint: TlbInvalidateHint,
}

impl TlbCommitReq {
    pub(crate) const fn relaxed(address_space_id: AddressSpaceId) -> Self {
        Self {
            address_space_id,
            class: CommitClass::Relaxed,
            invalidate_hint: TlbInvalidateHint::None,
        }
    }

    pub(crate) const fn strict(address_space_id: AddressSpaceId) -> Self {
        Self {
            address_space_id,
            class: CommitClass::Strict,
            invalidate_hint: TlbInvalidateHint::Full,
        }
    }

    pub(crate) const fn strict_range(address_space_id: AddressSpaceId, range: PageRange) -> Self {
        Self {
            address_space_id,
            class: CommitClass::Strict,
            invalidate_hint: TlbInvalidateHint::Range(range),
        }
    }

    pub(crate) const fn address_space_id(self) -> AddressSpaceId {
        self.address_space_id
    }

    pub(crate) const fn class(self) -> CommitClass {
        self.class
    }

    const fn invalidate_hint(self) -> TlbInvalidateHint {
        self.invalidate_hint
    }
}

/// One bootstrap frame that must not be recycled until the relevant TLB state is quiescent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetiredFrame {
    frame_id: FrameId,
}

impl RetiredFrame {
    pub(crate) const fn bootstrap_page(frame_id: FrameId) -> Self {
        Self { frame_id }
    }

    pub(crate) const fn frame_id(self) -> FrameId {
        self.frame_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StrictTlbSyncPlan {
    address_space_id: AddressSpaceId,
    target_epoch: u64,
    current_cpu_id: usize,
    current_cpu_active: bool,
    local_observe: bool,
    local_needs_flush: bool,
    remote_cpus: Vec<usize>,
    op: TlbSyncOp,
}

#[derive(Clone, Copy, Debug)]
struct VmResourceLimits {
    max_private_cow_pages: Option<u64>,
    max_inflight_loan_pages: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default)]
struct VmResourceStats {
    current_private_cow_pages: u64,
    peak_private_cow_pages: u64,
    current_inflight_loan_pages: u64,
    peak_inflight_loan_pages: u64,
    private_cow_quota_hits: u64,
    inflight_loan_quota_hits: u64,
}

#[derive(Clone, Copy, Debug)]
enum VmQuotaExceeded {
    PrivateCowPages { limit: u64, current: u64 },
    InflightLoanPages { limit: u64, current: u64 },
}

#[derive(Debug)]
struct VmResourceState {
    limits: VmResourceLimits,
    private_cow_pages: BTreeSet<u64>,
    private_cow_pending: BTreeSet<u64>,
    stats: VmResourceStats,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CowReservationState {
    AlreadyTracked,
    Reserved,
}

#[derive(Debug)]
#[must_use = "COW reservations must be explicitly committed or released"]
struct CowReservation {
    address_space_id: AddressSpaceId,
    page_base: u64,
    state: CowReservationState,
}

impl CowReservation {
    fn commit(mut self, vm: &mut VmDomain) {
        if matches!(self.state, CowReservationState::Reserved) {
            vm.commit_private_cow_page(self.address_space_id, self.page_base);
            self.state = CowReservationState::AlreadyTracked;
        }
    }

    fn release(mut self, vm: &mut VmDomain) {
        if matches!(self.state, CowReservationState::Reserved) {
            vm.rollback_private_cow_page_reservation(self.address_space_id, self.page_base);
            self.state = CowReservationState::AlreadyTracked;
        }
    }
}

impl Drop for CowReservation {
    fn drop(&mut self) {
        if matches!(self.state, CowReservationState::Reserved) {
            #[cfg(debug_assertions)]
            {
                panic!("CowReservation dropped without explicit commit or release");
            }
            #[cfg(not(debug_assertions))]
            {
                crate::kprintln!(
                    "WARNING: CowReservation dropped without explicit commit or release \
                     (address_space={}, page_base={:#x})",
                    self.address_space_id,
                    self.page_base,
                );
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum WakeReason {
    Status(zx_status_t),
    PreserveContext,
}

impl VmResourceState {
    fn new() -> Self {
        Self {
            limits: VmResourceLimits {
                max_private_cow_pages: DEFAULT_MAX_PRIVATE_COW_PAGES,
                max_inflight_loan_pages: DEFAULT_MAX_INFLIGHT_LOAN_PAGES,
            },
            private_cow_pages: BTreeSet::new(),
            private_cow_pending: BTreeSet::new(),
            stats: VmResourceStats::default(),
        }
    }

    fn stats(&self) -> VmResourceStats {
        self.stats
    }

    fn try_reserve_private_cow_page(
        &mut self,
        page_base: u64,
    ) -> Result<CowReservationState, VmQuotaExceeded> {
        if self.private_cow_pages.contains(&page_base)
            || self.private_cow_pending.contains(&page_base)
        {
            return Ok(CowReservationState::AlreadyTracked);
        }
        let reserved_pages = self.private_cow_pending.len() as u64;
        if let Some(limit) = self.limits.max_private_cow_pages
            && self
                .stats
                .current_private_cow_pages
                .saturating_add(reserved_pages)
                >= limit
        {
            self.stats.private_cow_quota_hits = self.stats.private_cow_quota_hits.wrapping_add(1);
            return Err(VmQuotaExceeded::PrivateCowPages {
                limit,
                current: self
                    .stats
                    .current_private_cow_pages
                    .saturating_add(reserved_pages),
            });
        }
        let _ = self.private_cow_pending.insert(page_base);
        Ok(CowReservationState::Reserved)
    }

    fn commit_private_cow_page(&mut self, page_base: u64) -> bool {
        let _ = self.private_cow_pending.remove(&page_base);
        if !self.private_cow_pages.insert(page_base) {
            return false;
        }
        self.stats.current_private_cow_pages =
            self.stats.current_private_cow_pages.saturating_add(1);
        self.stats.peak_private_cow_pages = self
            .stats
            .peak_private_cow_pages
            .max(self.stats.current_private_cow_pages);
        true
    }

    fn rollback_private_cow_page_reservation(&mut self, page_base: u64) -> bool {
        self.private_cow_pending.remove(&page_base)
    }

    fn clear_private_cow_range(&mut self, base: u64, len: u64) -> u64 {
        let Some(end) = base.checked_add(len) else {
            return 0;
        };
        let removed: Vec<u64> = self.private_cow_pages.range(base..end).copied().collect();
        let removed_count = removed.len() as u64;
        for page_base in removed {
            let _ = self.private_cow_pages.remove(&page_base);
        }
        self.private_cow_pending
            .retain(|page_base| *page_base < base || *page_base >= end);
        self.stats.current_private_cow_pages = self
            .stats
            .current_private_cow_pages
            .saturating_sub(removed_count);
        removed_count
    }

    fn try_reserve_inflight_loan_pages(&mut self, pages: u64) -> Result<(), VmQuotaExceeded> {
        if let Some(limit) = self.limits.max_inflight_loan_pages {
            let requested = self.stats.current_inflight_loan_pages.saturating_add(pages);
            if requested > limit {
                self.stats.inflight_loan_quota_hits =
                    self.stats.inflight_loan_quota_hits.wrapping_add(1);
                return Err(VmQuotaExceeded::InflightLoanPages {
                    limit,
                    current: self.stats.current_inflight_loan_pages,
                });
            }
        }
        self.stats.current_inflight_loan_pages =
            self.stats.current_inflight_loan_pages.saturating_add(pages);
        self.stats.peak_inflight_loan_pages = self
            .stats
            .peak_inflight_loan_pages
            .max(self.stats.current_inflight_loan_pages);
        Ok(())
    }

    fn release_inflight_loan_pages(&mut self, pages: u64) -> u64 {
        let released = pages.min(self.stats.current_inflight_loan_pages);
        self.stats.current_inflight_loan_pages -= released;
        released
    }
}

bitflags! {
    /// Internal handle-rights model used by the bootstrap kernel.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct HandleRights: u32 {
        const DUPLICATE = ZX_RIGHT_DUPLICATE;
        const TRANSFER = ZX_RIGHT_TRANSFER;
        const READ = ZX_RIGHT_READ;
        const WRITE = ZX_RIGHT_WRITE;
        const EXECUTE = ZX_RIGHT_EXECUTE;
        const MAP = ZX_RIGHT_MAP;
        const GET_PROPERTY = ZX_RIGHT_GET_PROPERTY;
        const SET_PROPERTY = ZX_RIGHT_SET_PROPERTY;
        const ENUMERATE = ZX_RIGHT_ENUMERATE;
        const DESTROY = ZX_RIGHT_DESTROY;
        const SET_POLICY = ZX_RIGHT_SET_POLICY;
        const GET_POLICY = ZX_RIGHT_GET_POLICY;
        const SIGNAL = ZX_RIGHT_SIGNAL;
        const SIGNAL_PEER = ZX_RIGHT_SIGNAL_PEER;
        const WAIT = ZX_RIGHT_WAIT;
        const INSPECT = ZX_RIGHT_INSPECT;
        const MANAGE_JOB = ZX_RIGHT_MANAGE_JOB;
        const MANAGE_PROCESS = ZX_RIGHT_MANAGE_PROCESS;
        const MANAGE_THREAD = ZX_RIGHT_MANAGE_THREAD;
        const APPLY_PROFILE = ZX_RIGHT_APPLY_PROFILE;
    }
}

impl HandleRights {
    pub(crate) const fn from_zx_rights(rights: zx_rights_t) -> Self {
        Self::from_bits_retain(rights)
    }
}

/// Full handle-resolution result used by the kernel object layer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ResolvedHandle {
    process_id: ProcessId,
    slot_index: u32,
    slot_tag: u32,
    object_key: ObjectKey,
    rights: HandleRights,
}

/// Kernel-visible description of the bootstrap root VMAR handle target.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RootVmarInfo {
    process_id: ProcessId,
    address_space_id: AddressSpaceId,
    vmar: Vmar,
}

impl RootVmarInfo {
    pub(crate) const fn process_id(self) -> ProcessId {
        self.process_id
    }

    pub(crate) const fn address_space_id(self) -> AddressSpaceId {
        self.address_space_id
    }

    pub(crate) const fn vmar_id(self) -> VmarId {
        self.vmar.id()
    }

    pub(crate) const fn base(self) -> u64 {
        self.vmar.base()
    }

    pub(crate) const fn len(self) -> u64 {
        self.vmar.len()
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FrameRetirePlan {
    retired_frames: Vec<RetiredFrame>,
    barrier_address_spaces: Vec<AddressSpaceId>,
}

impl FrameRetirePlan {
    fn new(retired_frames: Vec<RetiredFrame>, transition_barriers: &[AddressSpaceId]) -> Self {
        let mut barrier_address_spaces = Vec::new();
        if !retired_frames.is_empty() {
            for &address_space_id in transition_barriers {
                push_unique_address_space_id(&mut barrier_address_spaces, address_space_id);
            }
        }
        Self {
            retired_frames,
            barrier_address_spaces,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.retired_frames.is_empty()
    }

    pub(crate) fn retired_frames(&self) -> &[RetiredFrame] {
        &self.retired_frames
    }

    pub(crate) fn barrier_address_spaces(&self) -> &[AddressSpaceId] {
        &self.barrier_address_spaces
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LoanRemapResult {
    remapped: bool,
    tlb_commit: TlbCommitReq,
    retire_plan: FrameRetirePlan,
}

impl LoanRemapResult {
    fn not_remapped(address_space_id: AddressSpaceId) -> Self {
        Self {
            remapped: false,
            tlb_commit: TlbCommitReq::relaxed(address_space_id),
            retire_plan: FrameRetirePlan::default(),
        }
    }

    fn remapped(
        address_space_id: AddressSpaceId,
        range: PageRange,
        retire_plan: FrameRetirePlan,
    ) -> Self {
        Self {
            remapped: true,
            tlb_commit: TlbCommitReq::strict_range(address_space_id, range),
            retire_plan,
        }
    }

    pub(crate) fn did_remap(&self) -> bool {
        self.remapped
    }

    pub(crate) fn tlb_commit(&self) -> TlbCommitReq {
        self.tlb_commit
    }

    pub(crate) fn retire_plan(&self) -> &FrameRetirePlan {
        &self.retire_plan
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ThreadState {
    New,
    Runnable,
    Suspended,
    TerminationPending,
    Terminated,
    Blocked { source: WaitSourceKey },
}

/// Pinned page run loaned from the current process into a kernel object.
#[derive(Debug)]
#[must_use = "loaned user pages must be explicitly released"]
pub(crate) struct LoanedUserPages {
    address_space_id: AddressSpaceId,
    receiver_address_space_id: Option<AddressSpaceId>,
    base: u64,
    len: u32,
    needs_cow: bool,
    budget_pages: u64,
    loan: LoanToken,
}

impl LoanedUserPages {
    pub(crate) const fn address_space_id(&self) -> AddressSpaceId {
        self.address_space_id
    }

    pub(crate) const fn receiver_address_space_id(&self) -> Option<AddressSpaceId> {
        self.receiver_address_space_id
    }

    pub(crate) const fn base(&self) -> u64 {
        self.base
    }

    pub(crate) const fn len(&self) -> u32 {
        self.len
    }

    pub(crate) const fn needs_cow(&self) -> bool {
        self.needs_cow
    }

    pub(crate) fn pages(&self) -> &[FrameId] {
        self.loan.frame_ids()
    }

    fn bind_receiver_address_space(&mut self, address_space_id: AddressSpaceId) {
        self.receiver_address_space_id = Some(address_space_id);
    }

    fn release(self, vm: &mut VmDomain) {
        vm.release_loaned_pages_inner(self.address_space_id, self.budget_pages, self.loan);
    }
}

#[derive(Debug)]
#[must_use = "loan reservations must be explicitly released or committed into LoanedUserPages"]
struct InflightLoanReservation {
    address_space_id: AddressSpaceId,
    pages: u64,
    active: bool,
}

impl InflightLoanReservation {
    fn commit(mut self, base: u64, len: u32, needs_cow: bool, loan: LoanToken) -> LoanedUserPages {
        self.active = false;
        LoanedUserPages {
            address_space_id: self.address_space_id,
            receiver_address_space_id: None,
            base,
            len,
            needs_cow,
            budget_pages: self.pages,
            loan,
        }
    }

    fn release(mut self, vm: &mut VmDomain) {
        if self.active {
            vm.release_inflight_loan_pages(self.address_space_id, self.pages);
            self.active = false;
        }
    }
}

impl Drop for InflightLoanReservation {
    fn drop(&mut self) {
        debug_assert!(
            !self.active,
            "InflightLoanReservation dropped without explicit release or commit"
        );
    }
}

#[derive(Clone, Copy, Debug)]
struct FrameMappingSnapshot {
    anchor: ReverseMapAnchor,
    page_base: u64,
    map_rec: MapRec,
    lookup: VmaLookup,
}

type BootstrapTxCursor = TxCursor<crate::page_table::LockedUserPageTable>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AddressSpaceTxKey {
    address_space_id: AddressSpaceId,
    range_base: u64,
}

impl AddressSpaceTxKey {
    const fn new(address_space_id: AddressSpaceId, range: PageRange) -> Self {
        Self {
            address_space_id,
            range_base: range.base(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct AddressSpaceTxRequest {
    key: AddressSpaceTxKey,
    range: PageRange,
}

impl AddressSpaceTxRequest {
    fn new(address_space_id: AddressSpaceId, range: PageRange) -> Self {
        Self {
            key: AddressSpaceTxKey::new(address_space_id, range),
            range,
        }
    }
}

#[derive(Debug)]
enum AddressSpaceTxParticipant {
    Active {
        key: AddressSpaceTxKey,
        cursor: BootstrapTxCursor,
    },
    Deferred {
        key: AddressSpaceTxKey,
        range: PageRange,
    },
}

#[derive(Debug, Default)]
struct AddressSpaceTxSet {
    participants: Vec<AddressSpaceTxParticipant>,
}

impl AddressSpaceTxSet {
    fn push_active(
        &mut self,
        key: AddressSpaceTxKey,
        cursor: BootstrapTxCursor,
    ) -> Result<(), PageTableError> {
        self.participants
            .push(AddressSpaceTxParticipant::Active { key, cursor });
        Ok(())
    }

    fn push_deferred(&mut self, key: AddressSpaceTxKey, range: PageRange) {
        self.participants
            .push(AddressSpaceTxParticipant::Deferred { key, range });
    }

    fn cursor_mut(&mut self, key: AddressSpaceTxKey) -> Option<&mut BootstrapTxCursor> {
        self.participants
            .iter_mut()
            .find_map(|participant| match participant {
                AddressSpaceTxParticipant::Active {
                    key: participant_key,
                    cursor,
                } if *participant_key == key => Some(cursor),
                _ => None,
            })
    }

    fn commit(self) -> Result<(), PageTableError> {
        let mut active = TxSet::new();
        for participant in self.participants {
            match participant {
                AddressSpaceTxParticipant::Active { key, cursor } => active.push(key, cursor)?,
                AddressSpaceTxParticipant::Deferred { key, range } => {
                    let _ = key;
                    let _ = range;
                }
            }
        }
        active.commit()
    }
}

#[derive(Debug)]
struct ChannelLoanTx {
    tx_set: AddressSpaceTxSet,
    sender_key: AddressSpaceTxKey,
    receiver_key: AddressSpaceTxKey,
}

impl ChannelLoanTx {
    fn sender_cursor_mut(&mut self) -> Option<&mut BootstrapTxCursor> {
        self.tx_set.cursor_mut(self.sender_key)
    }

    fn receiver_cursor_mut(&mut self) -> Option<&mut BootstrapTxCursor> {
        self.tx_set.cursor_mut(self.receiver_key)
    }

    fn commit(self) -> Result<(), PageTableError> {
        self.tx_set.commit()
    }
}

impl ResolvedHandle {
    fn new(process_id: ProcessId, handle: Handle, cap: Capability) -> Result<Self, zx_status_t> {
        let (slot_index, slot_tag) = handle.decode().map_err(|_| ZX_ERR_BAD_HANDLE)?;
        Ok(Self {
            process_id,
            slot_index,
            slot_tag,
            object_key: cap.object_key(),
            rights: HandleRights::from_bits_retain(cap.rights()),
        })
    }

    /// Owning process id.
    pub(crate) const fn process_id(self) -> u64 {
        self.process_id
    }

    /// CSpace slot index encoded in the handle.
    pub(crate) const fn slot_index(self) -> u32 {
        self.slot_index
    }

    /// CSpace slot ABA tag encoded in the handle.
    pub(crate) const fn slot_tag(self) -> u32 {
        self.slot_tag
    }

    /// Target object id from the resolved capability.
    pub(crate) const fn object_id(self) -> u64 {
        self.object_key.object_id()
    }

    /// Target object identity from the resolved capability.
    pub(crate) const fn object_key(self) -> ObjectKey {
        self.object_key
    }

    /// Rights bits carried by the resolved capability.
    pub(crate) const fn rights(self) -> HandleRights {
        self.rights
    }

    /// Capability generation carried by the resolved capability.
    pub(crate) const fn object_generation(self) -> u32 {
        self.object_key.generation()
    }
}

const TLB_CPU_TRACKER_CAPACITY: usize = u64::BITS as usize;

#[derive(Clone, Copy, Debug, Default)]
struct TrackedTlbCpuSet {
    mask: u64,
}

impl TrackedTlbCpuSet {
    fn insert(&mut self, cpu_id: usize) {
        if cpu_id < TLB_CPU_TRACKER_CAPACITY {
            self.mask |= 1_u64 << cpu_id;
        }
    }

    fn remove(&mut self, cpu_id: usize) {
        if cpu_id < TLB_CPU_TRACKER_CAPACITY {
            self.mask &= !(1_u64 << cpu_id);
        }
    }

    fn contains(&self, cpu_id: usize) -> bool {
        cpu_id < TLB_CPU_TRACKER_CAPACITY && (self.mask & (1_u64 << cpu_id)) != 0
    }

    fn iter(self) -> impl Iterator<Item = usize> {
        (0..TLB_CPU_TRACKER_CAPACITY).filter(move |&cpu_id| self.contains(cpu_id))
    }

    fn mask(self) -> u64 {
        self.mask
    }
}

#[derive(Debug)]
struct TlbCpuTracker {
    active: TrackedTlbCpuSet,
    observed_epoch: [u64; TLB_CPU_TRACKER_CAPACITY],
}

impl Default for TlbCpuTracker {
    fn default() -> Self {
        Self {
            active: TrackedTlbCpuSet::default(),
            observed_epoch: [0; TLB_CPU_TRACKER_CAPACITY],
        }
    }
}

impl TlbCpuTracker {
    fn note_active(&mut self, cpu_id: usize) {
        self.active.insert(cpu_id);
    }

    fn note_inactive(&mut self, cpu_id: usize) {
        self.active.remove(cpu_id);
    }

    #[allow(dead_code)]
    fn is_active(&self, cpu_id: usize) -> bool {
        self.active.contains(cpu_id)
    }

    fn note_observed_epoch(&mut self, cpu_id: usize, epoch: u64) {
        if cpu_id < TLB_CPU_TRACKER_CAPACITY {
            self.observed_epoch[cpu_id] = epoch;
        }
    }

    fn observed_epoch(&self, cpu_id: usize) -> u64 {
        if cpu_id < TLB_CPU_TRACKER_CAPACITY {
            self.observed_epoch[cpu_id]
        } else {
            0
        }
    }

    fn plan_strict_sync(
        &mut self,
        current_cpu_id: usize,
        current_cpu_active: bool,
        target_epoch: u64,
        local_already_flushed: bool,
    ) -> TlbCpuSyncShape {
        if current_cpu_active {
            self.note_active(current_cpu_id);
        }
        let local_observe =
            current_cpu_active && self.observed_epoch(current_cpu_id) < target_epoch;
        let local_needs_flush = local_observe && !local_already_flushed;
        let remote_cpus = self
            .active
            .iter()
            .filter(|&cpu_id| cpu_id != current_cpu_id)
            .filter(|&cpu_id| self.observed_epoch(cpu_id) < target_epoch)
            .collect();
        TlbCpuSyncShape {
            active_cpu_mask: self.active.mask(),
            local_observe,
            local_needs_flush,
            remote_cpus,
        }
    }
}

#[derive(Debug)]
struct TlbCpuSyncShape {
    active_cpu_mask: u64,
    local_observe: bool,
    local_needs_flush: bool,
    remote_cpus: Vec<usize>,
}

const TLB_RANGE_FLUSH_PAGE_LIMIT: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
enum TlbSyncOp {
    Full,
    Ranges(Vec<PageRange>),
}

impl TlbSyncOp {
    fn from_hint(hint: TlbInvalidateHint) -> Result<Option<Self>, PageTableError> {
        match hint {
            TlbInvalidateHint::None => Ok(None),
            TlbInvalidateHint::Full => Ok(Some(Self::Full)),
            TlbInvalidateHint::Range(range) => Ok(Some(Self::from_range(range))),
        }
    }

    fn from_range(range: PageRange) -> Self {
        let mut ranges = Vec::with_capacity(1);
        ranges.push(range);
        Self::Ranges(ranges)
    }

    const fn is_full(&self) -> bool {
        matches!(self, Self::Full)
    }

    fn total_pages(&self) -> Result<usize, PageTableError> {
        match self {
            Self::Full => Ok(TLB_RANGE_FLUSH_PAGE_LIMIT.saturating_add(1)),
            Self::Ranges(ranges) => ranges.iter().try_fold(0_usize, |total, range| {
                let pages = usize::try_from(range.len() / crate::userspace::USER_PAGE_BYTES)
                    .map_err(|_| PageTableError::InvalidArgs)?;
                total.checked_add(pages).ok_or(PageTableError::InvalidArgs)
            }),
        }
    }

    fn merge(&mut self, other: Self) -> Result<(), PageTableError> {
        if self.is_full() || other.is_full() {
            *self = Self::Full;
            return Ok(());
        }
        let Self::Ranges(other_ranges) = other else {
            return Ok(());
        };
        let Self::Ranges(ranges) = self else {
            return Ok(());
        };
        for range in other_ranges {
            insert_merged_page_range(ranges, range)?;
        }
        if self.total_pages()? > TLB_RANGE_FLUSH_PAGE_LIMIT {
            *self = Self::Full;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingTlbSync {
    epoch: u64,
    op: TlbSyncOp,
}

#[derive(Debug)]
struct AddressSpace {
    vm: VmAddressSpace,
    page_tables: crate::page_table::UserPageTables,
    tlb_cpus: TlbCpuTracker,
    strict_tlb_epoch: u64,
    pending_tlb_sync: Option<PendingTlbSync>,
    vm_resources: VmResourceState,
    private_clone_vmos: Vec<VmoId>,
}

impl AddressSpace {
    fn bootstrap(
        address_space_id: AddressSpaceId,
        frames: &mut FrameTable,
        vmo_ids: [KernelVmoId; 3],
        layout: &ProcessImageLayout,
    ) -> Self {
        let mut vm = VmAddressSpace::new_with_id(
            VmAddressSpaceId::new(address_space_id),
            crate::userspace::USER_CODE_VA,
            crate::userspace::USER_REGION_BYTES,
        )
        .expect("bootstrap address-space root must be valid");
        let page_tables = crate::page_table::UserPageTables::bootstrap_current(
            crate::arch::tlb::pcid_for_address_space(address_space_id),
        )
        .expect("bootstrap user page tables must exist");

        let code_vmo = vm
            .create_vmo(
                VmoKind::Anonymous,
                crate::userspace::USER_CODE_BYTES,
                vmo_ids[0],
            )
            .expect("bootstrap code vmo allocation must succeed");
        for page_index in 0..crate::userspace::USER_CODE_PAGE_COUNT {
            let code_frame = frames
                .register_existing(crate::userspace::user_code_page_paddr(page_index))
                .expect("bootstrap code frame registration must succeed");
            vm.bind_vmo_frame(
                code_vmo,
                (page_index as u64) * crate::userspace::USER_PAGE_BYTES,
                code_frame,
            )
            .expect("bootstrap code frame binding must succeed");
        }
        if layout.segments().is_empty() {
            vm.map_fixed(
                frames,
                crate::userspace::USER_CODE_VA,
                crate::userspace::USER_CODE_BYTES,
                code_vmo,
                0,
                process_image_default_code_perms() | MappingPerms::USER,
                process_image_default_code_perms() | MappingPerms::USER,
            )
            .expect("bootstrap code mapping must succeed");
        } else {
            for segment in layout.segments() {
                let len = align_up_user_page(segment.mem_size_bytes())
                    .expect("bootstrap segment length must page-align");
                if len == 0 {
                    continue;
                }
                let perms = segment.perms() | MappingPerms::USER;
                vm.map_fixed(
                    frames,
                    segment.vaddr(),
                    len,
                    code_vmo,
                    segment.vmo_offset(),
                    perms,
                    perms,
                )
                .expect("bootstrap code segment mapping must succeed");
            }
        }

        let shared_vmo = vm
            .create_vmo(
                VmoKind::Anonymous,
                crate::userspace::USER_STACK_VA - crate::userspace::USER_SHARED_VA,
                vmo_ids[1],
            )
            .expect("bootstrap shared vmo allocation must succeed");
        for page_index in 0..((crate::userspace::USER_STACK_VA - crate::userspace::USER_SHARED_VA)
            / crate::userspace::USER_PAGE_BYTES)
        {
            let shared_frame = frames
                .register_existing(crate::userspace::user_shared_page_paddr(
                    page_index as usize,
                ))
                .expect("bootstrap shared frame registration must succeed");
            vm.bind_vmo_frame(
                shared_vmo,
                page_index * crate::userspace::USER_PAGE_BYTES,
                shared_frame,
            )
            .expect("bootstrap shared frame binding must succeed");
        }
        vm.map_fixed(
            frames,
            crate::userspace::USER_SHARED_VA,
            crate::userspace::USER_STACK_VA - crate::userspace::USER_SHARED_VA,
            shared_vmo,
            0,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
        )
        .expect("bootstrap shared mapping must succeed");

        let stack_vmo = vm
            .create_vmo(
                VmoKind::Anonymous,
                crate::userspace::USER_STACK_BYTES,
                vmo_ids[2],
            )
            .expect("bootstrap stack vmo allocation must succeed");
        for page_index in 0..crate::userspace::USER_STACK_PAGE_COUNT {
            let stack_frame = frames
                .register_existing(crate::userspace::user_stack_page_paddr(page_index))
                .expect("bootstrap stack frame registration must succeed");
            vm.bind_vmo_frame(
                stack_vmo,
                (page_index as u64) * crate::userspace::USER_PAGE_BYTES,
                stack_frame,
            )
            .expect("bootstrap stack frame binding must succeed");
        }
        vm.map_fixed(
            frames,
            crate::userspace::USER_STACK_VA,
            crate::userspace::USER_STACK_BYTES,
            stack_vmo,
            0,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
        )
        .expect("bootstrap stack mapping must succeed");
        vm.mark_copy_on_write(
            crate::userspace::USER_STACK_VA,
            crate::userspace::USER_STACK_BYTES,
        )
        .expect("bootstrap stack COW arm must succeed");
        debug_assert!(page_tables.validate_descriptor_metadata_range(
            crate::userspace::USER_CODE_VA,
            crate::userspace::USER_CODE_BYTES,
        ));

        Self {
            vm,
            page_tables,
            tlb_cpus: TlbCpuTracker::default(),
            strict_tlb_epoch: 0,
            pending_tlb_sync: None,
            vm_resources: VmResourceState::new(),
            private_clone_vmos: Vec::new(),
        }
    }

    fn validate_user_ptr(&self, ptr: u64, len: usize) -> bool {
        self.vm.contains_range(ptr, len)
    }

    fn lookup_user_mapping(&self, ptr: u64, len: usize) -> Option<VmaLookup> {
        self.vm.lookup_range(ptr, len as u64)
    }

    fn classify_user_page_fault(&self, fault_va: u64, flags: PageFaultFlags) -> PageFaultDecision {
        self.vm.classify_page_fault(fault_va, flags)
    }

    fn page_meta(&self, fault_va: u64) -> Option<PteMeta> {
        self.vm.owned_pte_meta(fault_va)
    }

    fn page_base_for_rmap_anchor(&self, anchor: ReverseMapAnchor) -> Option<u64> {
        self.vm.page_base_for_rmap_anchor(anchor)
    }

    fn lookup_rmap_anchor(&self, anchor: ReverseMapAnchor) -> Option<VmaLookup> {
        self.vm.lookup_rmap_anchor(anchor)
    }

    fn map_record(&self, id: axle_mm::MapId) -> Option<MapRec> {
        self.vm.map_record(id)
    }

    fn map_record_for_va(&self, va: u64) -> Option<MapRec> {
        self.vm.map_record_for_va(va)
    }

    fn snapshot_vmo(&self, global_vmo_id: KernelVmoId) -> Option<Vmo> {
        self.vm.vmo_by_global_id(global_vmo_id).cloned()
    }

    fn root_vmar(&self) -> Vmar {
        self.vm.root_vmar()
    }

    fn vmar(&self, id: VmarId) -> Option<Vmar> {
        self.vm.vmar(id)
    }

    fn allocate_subvmar(
        &mut self,
        cpu_id: usize,
        parent_vmar_id: VmarId,
        offset: u64,
        len: u64,
        align: u64,
        mode: VmarAllocMode,
        offset_is_upper_limit: bool,
        child_policy: VmarPlacementPolicy,
    ) -> Result<Vmar, AddressSpaceError> {
        self.vm.allocate_subvmar(
            cpu_id,
            parent_vmar_id,
            offset,
            len,
            align,
            mode,
            offset_is_upper_limit,
            child_policy,
        )
    }

    fn destroy_vmar(
        &mut self,
        frames: &mut FrameTable,
        vmar_id: VmarId,
    ) -> Result<Vec<(u64, u64)>, AddressSpaceError> {
        self.vm.destroy_vmar(frames, vmar_id)
    }

    fn root_page_table(&self) -> crate::page_table::UserPageTables {
        self.page_tables.clone()
    }

    fn current_invalidate_epoch(&self) -> u64 {
        self.page_tables
            .max_invalidate_epoch()
            .max(self.strict_tlb_epoch)
    }

    fn bump_strict_tlb_epoch(&mut self) {
        self.strict_tlb_epoch = self.current_invalidate_epoch().wrapping_add(1);
    }

    fn validate_descriptor_metadata_range(&self, base: u64, len: u64) -> bool {
        self.page_tables
            .validate_descriptor_metadata_range(base, len)
    }

    fn note_cpu_active(&mut self, cpu_id: usize) {
        self.tlb_cpus.note_active(cpu_id);
        crate::trace::note_tlb_active_mask(self.tlb_cpus.active.mask());
    }

    fn note_cpu_inactive(&mut self, cpu_id: usize) {
        self.tlb_cpus.note_inactive(cpu_id);
        crate::trace::note_tlb_active_mask(self.tlb_cpus.active.mask());
    }

    #[allow(dead_code)]
    fn is_cpu_active(&self, cpu_id: usize) -> bool {
        self.tlb_cpus.is_active(cpu_id)
    }

    fn observe_tlb_epoch(&mut self, cpu_id: usize, epoch: u64) {
        self.tlb_cpus.note_observed_epoch(cpu_id, epoch);
    }

    fn observed_tlb_epoch(&self, cpu_id: usize) -> u64 {
        self.tlb_cpus.observed_epoch(cpu_id)
    }

    fn plan_tlb_sync(
        &mut self,
        current_cpu_id: usize,
        current_cpu_active: bool,
        op: TlbSyncOp,
        local_already_flushed: bool,
    ) -> (u64, TlbCpuSyncShape) {
        self.bump_strict_tlb_epoch();
        let target_epoch = self.current_invalidate_epoch();
        self.pending_tlb_sync = Some(PendingTlbSync {
            epoch: target_epoch,
            op,
        });
        (
            target_epoch,
            self.tlb_cpus.plan_strict_sync(
                current_cpu_id,
                current_cpu_active,
                target_epoch,
                local_already_flushed,
            ),
        )
    }

    fn pending_tlb_sync_op(&self, epoch: u64) -> Option<&TlbSyncOp> {
        self.pending_tlb_sync
            .as_ref()
            .filter(|pending| pending.epoch == epoch)
            .map(|pending| &pending.op)
    }

    fn map_vmo_fixed(
        &mut self,
        frames: &mut FrameTable,
        vmar_id: VmarId,
        base: u64,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
    ) -> Result<(), AddressSpaceError> {
        self.map_vmo_fixed_with_policy(
            frames,
            vmar_id,
            base,
            len,
            vmo_id,
            vmo_offset,
            perms,
            MappingCachePolicy::Cached,
        )
    }

    fn map_vmo_fixed_with_policy(
        &mut self,
        frames: &mut FrameTable,
        vmar_id: VmarId,
        base: u64,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        cache_policy: MappingCachePolicy,
    ) -> Result<(), AddressSpaceError> {
        self.map_vmo_fixed_with_mapping_policy(
            frames,
            vmar_id,
            base,
            len,
            vmo_id,
            vmo_offset,
            perms,
            cache_policy,
            MappingClonePolicy::None,
        )
    }

    fn map_vmo_fixed_with_mapping_policy(
        &mut self,
        frames: &mut FrameTable,
        vmar_id: VmarId,
        base: u64,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        cache_policy: MappingCachePolicy,
        clone_policy: MappingClonePolicy,
    ) -> Result<(), AddressSpaceError> {
        self.map_vmo_fixed_with_max_perms_and_mapping_policy(
            frames,
            vmar_id,
            base,
            len,
            vmo_id,
            vmo_offset,
            perms,
            perms,
            cache_policy,
            clone_policy,
        )
    }

    fn map_vmo_fixed_with_max_perms_and_mapping_policy(
        &mut self,
        frames: &mut FrameTable,
        vmar_id: VmarId,
        base: u64,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        max_perms: MappingPerms,
        cache_policy: MappingCachePolicy,
        clone_policy: MappingClonePolicy,
    ) -> Result<(), AddressSpaceError> {
        self.vm.map_fixed_in_vmar_with_mapping_policy(
            frames,
            vmar_id,
            base,
            len,
            vmo_id,
            vmo_offset,
            perms,
            max_perms,
            cache_policy,
            clone_policy,
        )
    }

    fn map_vmo_anywhere(
        &mut self,
        frames: &mut FrameTable,
        cpu_id: usize,
        vmar_id: VmarId,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
    ) -> Result<u64, AddressSpaceError> {
        self.map_vmo_anywhere_with_policy(
            frames,
            cpu_id,
            vmar_id,
            len,
            vmo_id,
            vmo_offset,
            perms,
            MappingCachePolicy::Cached,
        )
    }

    fn map_vmo_anywhere_with_policy(
        &mut self,
        frames: &mut FrameTable,
        cpu_id: usize,
        vmar_id: VmarId,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        cache_policy: MappingCachePolicy,
    ) -> Result<u64, AddressSpaceError> {
        self.map_vmo_anywhere_with_mapping_policy(
            frames,
            cpu_id,
            vmar_id,
            len,
            vmo_id,
            vmo_offset,
            perms,
            cache_policy,
            MappingClonePolicy::None,
        )
    }

    fn map_vmo_anywhere_with_mapping_policy(
        &mut self,
        frames: &mut FrameTable,
        cpu_id: usize,
        vmar_id: VmarId,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        cache_policy: MappingCachePolicy,
        clone_policy: MappingClonePolicy,
    ) -> Result<u64, AddressSpaceError> {
        self.vm.map_anywhere_in_vmar_with_mapping_policy(
            frames,
            cpu_id,
            vmar_id,
            len,
            vmo_id,
            vmo_offset,
            perms,
            perms,
            axle_mm::PAGE_SIZE,
            cache_policy,
            clone_policy,
        )
    }

    fn unmap(
        &mut self,
        frames: &mut FrameTable,
        vmar_id: VmarId,
        base: u64,
        len: u64,
    ) -> Result<(), AddressSpaceError> {
        self.vm.unmap_in_vmar(frames, vmar_id, base, len)?;
        self.reclaim_unmapped_private_clone_vmos();
        Ok(())
    }

    fn protect(
        &mut self,
        frames: &mut FrameTable,
        vmar_id: VmarId,
        base: u64,
        len: u64,
        new_perms: MappingPerms,
    ) -> Result<(), AddressSpaceError> {
        self.vm
            .protect_in_vmar(frames, vmar_id, base, len, new_perms)
    }

    fn resolve_cow_fault(
        &mut self,
        frames: &mut FrameTable,
        fault_va: u64,
        new_frame_id: axle_mm::FrameId,
    ) -> Result<CowFaultResolution, AddressSpaceError> {
        self.vm.resolve_cow_fault(frames, fault_va, new_frame_id)
    }

    fn resolve_lazy_anon_fault(
        &mut self,
        frames: &mut FrameTable,
        fault_va: u64,
        new_frame_id: axle_mm::FrameId,
    ) -> Result<LazyAnonFaultResolution, AddressSpaceError> {
        self.vm
            .resolve_lazy_anon_fault(frames, fault_va, new_frame_id)
    }

    fn resolve_lazy_vmo_fault(
        &mut self,
        frames: &mut FrameTable,
        fault_va: u64,
        frame_id: axle_mm::FrameId,
    ) -> Result<LazyVmoFaultResolution, AddressSpaceError> {
        self.vm.resolve_lazy_vmo_fault(frames, fault_va, frame_id)
    }

    fn arm_copy_on_write(&mut self, base: u64, len: u64) -> Result<(), AddressSpaceError> {
        self.vm.mark_copy_on_write(base, len)
    }

    fn replace_mapping_frames_copy_on_write(
        &mut self,
        frames: &mut FrameTable,
        base: u64,
        len: u64,
        replacement_frames: &[FrameId],
    ) -> Result<(), AddressSpaceError> {
        self.vm
            .replace_mapping_frames_copy_on_write(frames, base, len, replacement_frames)
    }

    fn try_reserve_private_cow_page(
        &mut self,
        page_base: u64,
    ) -> Result<CowReservationState, VmQuotaExceeded> {
        self.vm_resources.try_reserve_private_cow_page(page_base)
    }

    fn commit_private_cow_page(&mut self, page_base: u64) -> bool {
        self.vm_resources.commit_private_cow_page(page_base)
    }

    fn rollback_private_cow_page_reservation(&mut self, page_base: u64) -> bool {
        self.vm_resources
            .rollback_private_cow_page_reservation(page_base)
    }

    fn clear_private_cow_range(&mut self, base: u64, len: u64) -> u64 {
        self.vm_resources.clear_private_cow_range(base, len)
    }

    fn try_reserve_inflight_loan_pages(&mut self, pages: u64) -> Result<(), VmQuotaExceeded> {
        self.vm_resources.try_reserve_inflight_loan_pages(pages)
    }

    fn release_inflight_loan_pages(&mut self, pages: u64) -> u64 {
        self.vm_resources.release_inflight_loan_pages(pages)
    }

    fn vm_resource_stats(&self) -> VmResourceStats {
        self.vm_resources.stats()
    }
}

#[derive(Debug)]
struct Thread {
    process_id: ProcessId,
    koid: zx_koid_t,
    guest_started: bool,
    guest_fs_base: u64,
    fpu_state: crate::arch::fpu::FpuState,
    state: ThreadState,
    queued_on_cpu: Option<usize>,
    /// CPU this thread is currently running on (set by `activate_thread_on_current_cpu`,
    /// cleared when the thread is no longer the active thread on that CPU).
    /// Enables O(1) lookup instead of scanning all per-CPU scheduler states.
    running_on_cpu: Option<usize>,
    last_cpu: usize,
    runtime_ns: u64,
    wait: WaitNode,
    context: Option<UserContext>,
    suspend_tokens: u32,
    remote_wake_enqueued_ns: Option<u64>,
    remote_wake_source_cpu: Option<usize>,
    remote_wake_target_cpu: Option<usize>,
    /// EEVDF: virtual runtime in ns (weighted). Advances by real_ns * 1024 / weight.
    pub(crate) vruntime: i64,
    /// EEVDF: scheduling weight (default 1024 = nice 0). Higher weight = more CPU time.
    pub(crate) weight: u32,
    /// EEVDF: virtual deadline = eligible_time + (slice_ns * 1024 / weight).
    pub(crate) vdeadline: i64,
    /// EEVDF: eligible time, set to min_vruntime at enqueue. Thread is eligible when
    /// eligible_time <= min_vruntime.
    pub(crate) eligible_time: i64,
}

/// Internal bootstrap kernel model.
#[derive(Debug)]
pub(crate) struct VmDomain {
    address_spaces: BTreeMap<AddressSpaceId, AddressSpace>,
    global_vmos: Arc<Mutex<GlobalVmoStore>>,
    bootstrap_user_runner_global_vmo_id: Option<KernelVmoId>,
    bootstrap_user_code_global_vmo_id: Option<KernelVmoId>,
    #[allow(dead_code)]
    frames: Arc<Mutex<FrameTable>>,
    cow_fault_count: u64,
    vm_private_cow_pages_current: u64,
    vm_private_cow_pages_peak: u64,
    vm_inflight_loan_pages_current: u64,
    vm_inflight_loan_pages_peak: u64,
    vm_private_cow_quota_hits: u64,
    vm_inflight_loan_quota_hits: u64,
    next_global_vmo_id: u64,
    next_address_space_id: AddressSpaceId,
}

#[derive(Debug)]
pub(crate) struct Kernel {
    jobs: BTreeMap<JobId, Job>,
    processes: BTreeMap<ProcessId, Process>,
    threads: BTreeMap<ThreadId, Thread>,
    futexes: crate::futex::FutexTable,
    reactor: Arc<Mutex<Reactor>>,
    cpu_schedulers: BTreeMap<usize, CpuSchedulerState>,
    revocations: RevocationManager,
    next_koid: zx_koid_t,
    next_job_id: JobId,
    next_process_id: ProcessId,
    next_thread_id: ThreadId,
    root_job_id: JobId,
    task_lifecycle_dirty: bool,
    vm: Arc<VmFacade>,
}

impl VmDomain {
    fn global_vmo_store(&self) -> Arc<Mutex<GlobalVmoStore>> {
        Arc::clone(&self.global_vmos)
    }

    fn frame_table(&self) -> Arc<Mutex<FrameTable>> {
        Arc::clone(&self.frames)
    }

    fn with_frames<R>(&self, f: impl FnOnce(&FrameTable) -> R) -> R {
        let frames = self.frames.lock();
        f(&frames)
    }

    fn with_frames_mut<R>(&self, f: impl FnOnce(&mut FrameTable) -> R) -> R {
        let mut frames = self.frames.lock();
        f(&mut frames)
    }

    fn with_address_space_frames_mut<R>(
        &mut self,
        address_space_id: AddressSpaceId,
        f: impl FnOnce(&mut AddressSpace, &mut FrameTable) -> Result<R, zx_status_t>,
    ) -> Result<R, zx_status_t> {
        let frames_handle = self.frame_table();
        let address_space = self
            .address_spaces
            .get_mut(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let mut frames = frames_handle.lock();
        f(address_space, &mut frames)
    }

    fn address_space_ids_importing_global_vmo(
        &self,
        global_vmo_id: KernelVmoId,
    ) -> Vec<AddressSpaceId> {
        self.address_spaces
            .iter()
            .filter_map(|(&address_space_id, address_space)| {
                address_space
                    .imports_global_vmo(global_vmo_id)
                    .then_some(address_space_id)
            })
            .collect()
    }

    fn protect_requires_strict_sync(
        &self,
        address_space_id: AddressSpaceId,
        addr: u64,
        len: u64,
        new_perms: MappingPerms,
    ) -> Result<bool, zx_status_t> {
        if new_perms.contains(MappingPerms::WRITE) && !new_perms.contains(MappingPerms::EXECUTE) {
            return Ok(false);
        }
        let address_space = self
            .address_spaces
            .get(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let page_count = usize::try_from(len / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        for page_index in 0..page_count {
            let va = addr + (page_index as u64) * crate::userspace::USER_PAGE_BYTES;
            if address_space
                .lookup_user_mapping(va, 1)
                .is_some_and(|lookup| {
                    (lookup.perms().contains(MappingPerms::WRITE)
                        && !new_perms.contains(MappingPerms::WRITE))
                        || (lookup.perms().contains(MappingPerms::EXECUTE)
                            != new_perms.contains(MappingPerms::EXECUTE))
                })
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn plan_strict_tlb_sync(
        &mut self,
        address_space_id: AddressSpaceId,
        current_cpu_id: usize,
        current_cpu_active: bool,
        op: TlbSyncOp,
        local_already_flushed: bool,
    ) -> Result<Option<StrictTlbSyncPlan>, zx_status_t> {
        let address_space = self
            .address_spaces
            .get_mut(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let (target_epoch, sync_shape) = address_space.plan_tlb_sync(
            current_cpu_id,
            current_cpu_active,
            op.clone(),
            local_already_flushed,
        );
        if !sync_shape.local_observe && sync_shape.remote_cpus.is_empty() {
            return Ok(None);
        }
        crate::trace::record_tlb_sync_plan(
            address_space_id,
            sync_shape.active_cpu_mask,
            sync_shape.remote_cpus.len(),
            sync_shape.local_needs_flush,
        );
        Ok(Some(StrictTlbSyncPlan {
            address_space_id,
            target_epoch,
            current_cpu_id,
            current_cpu_active,
            local_observe: sync_shape.local_observe,
            local_needs_flush: sync_shape.local_needs_flush,
            remote_cpus: sync_shape.remote_cpus,
            op,
        }))
    }

    fn complete_strict_tlb_sync(&mut self, plan: &StrictTlbSyncPlan) -> Result<(), zx_status_t> {
        let address_space = self
            .address_spaces
            .get_mut(&plan.address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if plan.current_cpu_active && plan.local_observe {
            address_space.observe_tlb_epoch(plan.current_cpu_id, plan.target_epoch);
        }
        for &cpu_id in &plan.remote_cpus {
            address_space.observe_tlb_epoch(cpu_id, plan.target_epoch);
        }
        Ok(())
    }

    fn alloc_address_space_id(&mut self) -> AddressSpaceId {
        let id = self.next_address_space_id;
        self.next_address_space_id = self.next_address_space_id.wrapping_add(1);
        id
    }

    fn alloc_global_vmo_id(&mut self) -> KernelVmoId {
        let id = self.next_global_vmo_id;
        self.next_global_vmo_id = self.next_global_vmo_id.wrapping_add(1);
        KernelVmoId::new(id)
    }
}

impl Kernel {
    fn bootstrap_cpu_id() -> usize {
        CpuId::new()
            .get_feature_info()
            .map(|fi| fi.initial_local_apic_id() as usize)
            .unwrap_or(0)
    }

    pub(crate) fn alloc_handle_for_current_process(
        &mut self,
        cap: Capability,
    ) -> Result<zx_handle_t, zx_status_t> {
        self.current_process_mut()?.alloc_handle_for_capability(cap)
    }

    /// Resolve the current process's handle into full capability metadata.
    pub(crate) fn lookup_current_handle(
        &self,
        raw: zx_handle_t,
        required_rights: HandleRights,
    ) -> Result<ResolvedHandle, zx_status_t> {
        let process_id = self.current_thread()?.process_id;
        self.lookup_handle_in_process(process_id, raw, required_rights)
    }

    pub(crate) fn lookup_handle_in_process(
        &self,
        process_id: ProcessId,
        raw: zx_handle_t,
        required_rights: HandleRights,
    ) -> Result<ResolvedHandle, zx_status_t> {
        let resolved =
            self.process(process_id)?
                .lookup_handle(process_id, raw, &self.revocations)?;
        if !resolved.rights().contains(required_rights) {
            return Err(ZX_ERR_ACCESS_DENIED);
        }
        Ok(resolved)
    }

    pub(crate) fn close_current_handle(&mut self, raw: zx_handle_t) -> Result<(), zx_status_t> {
        let process_id = self.current_thread()?.process_id;
        self.close_handle_in_process(process_id, raw)
    }

    pub(crate) fn close_handle_in_process(
        &mut self,
        process_id: ProcessId,
        raw: zx_handle_t,
    ) -> Result<(), zx_status_t> {
        self.process_mut(process_id)?.close_handle(raw)
    }

    pub(crate) fn duplicate_current_handle(
        &mut self,
        raw: zx_handle_t,
        rights: HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        let _ = self.lookup_current_handle(raw, HandleRights::empty())?;
        self.current_process_mut()?
            .duplicate_handle_derived(raw, rights)
    }

    pub(crate) fn duplicate_current_handle_revocable(
        &mut self,
        raw: zx_handle_t,
        rights: HandleRights,
        group_token: axle_core::RevocationGroupToken,
    ) -> Result<zx_handle_t, zx_status_t> {
        let _ = self.lookup_current_handle(raw, HandleRights::empty())?;
        let revocation = self
            .revocations
            .snapshot(group_token)
            .map_err(|_| ZX_ERR_BAD_HANDLE)?;
        self.current_process_mut()?
            .duplicate_handle_revocable(raw, rights, revocation)
    }

    pub(crate) fn replace_current_handle(
        &mut self,
        raw: zx_handle_t,
        rights: HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        let _ = self.lookup_current_handle(raw, HandleRights::empty())?;
        self.current_process_mut()?
            .replace_handle_derived(raw, rights)
    }

    pub(crate) fn snapshot_current_handle_for_transfer(
        &self,
        raw: zx_handle_t,
        required_rights: HandleRights,
    ) -> Result<TransferredCap, zx_status_t> {
        let _ = self.lookup_current_handle(raw, required_rights)?;
        self.current_process()?
            .snapshot_handle_for_transfer(raw, &self.revocations)
    }

    pub(crate) fn install_handle_in_current_process(
        &mut self,
        transferred: TransferredCap,
    ) -> Result<zx_handle_t, zx_status_t> {
        let process_id = self.current_thread()?.process_id;
        self.install_handle_in_process(process_id, transferred)
    }

    pub(crate) fn install_handle_in_process(
        &mut self,
        process_id: ProcessId,
        transferred: TransferredCap,
    ) -> Result<zx_handle_t, zx_status_t> {
        self.process_mut(process_id)?
            .install_transferred_handle(transferred)
    }

    pub(crate) fn create_revocation_group(&mut self) -> axle_core::RevocationGroupToken {
        self.revocations.create_group()
    }

    pub(crate) fn revoke_group(
        &mut self,
        token: axle_core::RevocationGroupToken,
    ) -> Result<(), zx_status_t> {
        self.revocations
            .revoke(token)
            .map_err(|_| ZX_ERR_BAD_HANDLE)
    }

    pub(crate) fn revocation_group_epoch(
        &self,
        token: axle_core::RevocationGroupToken,
    ) -> Result<u64, zx_status_t> {
        self.revocations
            .snapshot(token)
            .map(|snapshot| snapshot.epoch())
            .map_err(|_| ZX_ERR_BAD_HANDLE)
    }

    pub(crate) fn validate_current_user_ptr(&self, ptr: u64, len: usize) -> bool {
        let Ok(process) = self.current_process() else {
            return false;
        };
        self.with_vm(|vm| {
            vm.address_spaces
                .get(&process.address_space_id)
                .map(|address_space| address_space.validate_user_ptr(ptr, len))
                .unwrap_or(false)
        })
    }

    pub(crate) fn validate_process_user_ptr(
        &self,
        process_id: ProcessId,
        ptr: u64,
        len: usize,
    ) -> bool {
        let Ok(process) = self.process(process_id) else {
            return false;
        };
        self.with_vm(|vm| {
            vm.address_spaces
                .get(&process.address_space_id)
                .map(|address_space| address_space.validate_user_ptr(ptr, len))
                .unwrap_or(false)
        })
    }

    pub(crate) fn validate_process_user_mapping_perms(
        &self,
        process_id: ProcessId,
        ptr: u64,
        len: usize,
        required: MappingPerms,
    ) -> bool {
        let Ok(process) = self.process(process_id) else {
            return false;
        };
        self.with_vm(|vm| {
            vm.lookup_user_mapping(process.address_space_id, ptr, len)
                .is_some_and(|lookup| mapping_satisfies_required_perms(lookup, required))
        })
    }

    pub(crate) fn ensure_current_user_page_resident(
        &mut self,
        page_va: u64,
        for_write: bool,
    ) -> Result<(), zx_status_t> {
        let address_space_id = self.current_process()?.address_space_id;
        self.with_vm_mut(|vm| vm.ensure_user_page_resident(address_space_id, page_va, for_write))
    }

    /// Resolve a current-thread userspace range back to its VMO mapping metadata.
    #[allow(dead_code)]
    pub(crate) fn lookup_current_user_mapping(&self, ptr: u64, len: usize) -> Option<VmaLookup> {
        let process = self.current_process().ok()?;
        self.with_vm(|vm| {
            vm.address_spaces
                .get(&process.address_space_id)
                .and_then(|address_space| address_space.lookup_user_mapping(ptr, len))
        })
    }

    #[allow(dead_code)]
    pub(crate) fn resolve_current_futex_key(
        &self,
        user_addr: u64,
    ) -> Result<FutexKey, zx_status_t> {
        const FUTEX_WORD_BYTES: usize = size_of::<u32>();
        if (user_addr & 0x3) != 0 || !self.validate_current_user_ptr(user_addr, FUTEX_WORD_BYTES) {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        let process_id = self.current_thread()?.process_id;
        let lookup = self
            .lookup_current_user_mapping(user_addr, FUTEX_WORD_BYTES)
            .ok_or(ZX_ERR_INVALID_ARGS)?;
        Ok(FutexKey::from_lookup(process_id, user_addr, lookup))
    }

    #[allow(dead_code)]
    pub(crate) fn resolve_current_futex_key_relaxed(
        &self,
        user_addr: u64,
    ) -> Result<FutexKey, zx_status_t> {
        const FUTEX_WORD_BYTES: usize = size_of::<u32>();
        if (user_addr & 0x3) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let process_id = self.current_thread()?.process_id;
        let process = self.current_process()?;
        self.with_vm(|vm| {
            let address_space = vm
                .address_spaces
                .get(&process.address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            let root = address_space.root_vmar();
            let range_end = user_addr
                .checked_add(FUTEX_WORD_BYTES as u64)
                .ok_or(ZX_ERR_INVALID_ARGS)?;
            let root_end = root
                .base()
                .checked_add(root.len())
                .ok_or(ZX_ERR_BAD_STATE)?;
            if user_addr < root.base() || range_end > root_end {
                return Err(ZX_ERR_INVALID_ARGS);
            }
            if !address_space.validate_user_ptr(user_addr, FUTEX_WORD_BYTES) {
                return Ok(FutexKey::private_anonymous(process_id, user_addr));
            }
            let lookup = address_space
                .lookup_user_mapping(user_addr, FUTEX_WORD_BYTES)
                .ok_or(ZX_ERR_INVALID_ARGS)?;
            Ok(FutexKey::from_lookup(process_id, user_addr, lookup))
        })
    }

    pub(crate) fn try_loan_current_user_pages(
        &mut self,
        ptr: u64,
        len: usize,
    ) -> Result<Option<LoanedUserPages>, zx_status_t> {
        let address_space_id = self.current_process()?.address_space_id;
        self.with_vm_mut(|vm| vm.try_loan_user_pages(address_space_id, ptr, len))
    }

    pub(crate) fn release_loaned_user_pages(&mut self, loaned: LoanedUserPages) {
        self.with_vm_mut(|vm| vm.release_loaned_user_pages(loaned))
    }

    pub(crate) fn prepare_loaned_channel_write(
        &mut self,
        loaned: &mut LoanedUserPages,
        receiver_address_space_id: AddressSpaceId,
    ) -> Result<(), zx_status_t> {
        let req = self
            .with_vm_mut(|vm| vm.prepare_loaned_channel_write(loaned, receiver_address_space_id))?;
        self.apply_tlb_commit_reqs_current(&[req])
    }

    pub(crate) fn try_remap_loaned_channel_read(
        &mut self,
        dst_base: u64,
        loaned: &LoanedUserPages,
    ) -> Result<bool, zx_status_t> {
        let current_address_space_id = self.current_process()?.address_space_id;
        let remap = self.with_vm_mut(|vm| {
            vm.try_remap_loaned_channel_read(current_address_space_id, dst_base, loaned)
        })?;
        self.vm.apply_tlb_commit_reqs(
            self.current_cpu_id(),
            Some(current_address_space_id),
            &[remap.tlb_commit()],
        )?;
        if !remap.retire_plan().is_empty() {
            self.retire_bootstrap_frames_after_quiescence_current(
                remap.retire_plan().barrier_address_spaces(),
                remap.retire_plan().retired_frames(),
            )?;
        }
        Ok(remap.did_remap())
    }

    pub(crate) fn current_root_vmar(&self) -> Result<RootVmarInfo, zx_status_t> {
        let thread = self.current_thread()?;
        let process = self.current_process()?;
        self.with_vm(|vm| {
            let address_space = vm
                .address_spaces
                .get(&process.address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            Ok(RootVmarInfo {
                process_id: thread.process_id,
                address_space_id: process.address_space_id,
                vmar: address_space.root_vmar(),
            })
        })
    }

    pub(crate) fn allocate_subvmar(
        &mut self,
        address_space_id: AddressSpaceId,
        parent_vmar_id: VmarId,
        offset: u64,
        len: u64,
        align: u64,
        mode: VmarAllocMode,
        offset_is_upper_limit: bool,
        child_policy: VmarPlacementPolicy,
    ) -> Result<Vmar, zx_status_t> {
        let cpu_id = self.current_cpu_id();
        self.with_vm_mut(|vm| {
            vm.allocate_subvmar(
                address_space_id,
                cpu_id,
                parent_vmar_id,
                offset,
                len,
                align,
                mode,
                offset_is_upper_limit,
                child_policy,
            )
        })
    }

    pub(crate) fn destroy_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
    ) -> Result<(), zx_status_t> {
        let req = self.with_vm_mut(|vm| vm.destroy_vmar(address_space_id, vmar_id))?;
        self.apply_tlb_commit_reqs_current(&[req])
    }

    pub(crate) fn allocate_global_vmo_id(&mut self) -> KernelVmoId {
        self.with_vm_mut(|vm| vm.alloc_global_vmo_id())
    }

    fn record_vm_resource_telemetry(&self) {
        self.with_vm(|vm| vm.record_vm_resource_telemetry())
    }

    fn log_vm_quota_exceeded(
        &self,
        address_space_id: AddressSpaceId,
        exceeded: VmQuotaExceeded,
        context: &str,
    ) {
        self.with_vm(|vm| vm.log_vm_quota_exceeded(address_space_id, exceeded, context))
    }

    fn reserve_private_cow_page(
        &mut self,
        address_space_id: AddressSpaceId,
        page_base: u64,
    ) -> Result<CowReservation, zx_status_t> {
        self.with_vm_mut(|vm| vm.reserve_private_cow_page(address_space_id, page_base))
    }

    fn clear_private_cow_range(&mut self, address_space_id: AddressSpaceId, base: u64, len: u64) {
        self.with_vm_mut(|vm| vm.clear_private_cow_range(address_space_id, base, len));
    }

    fn reserve_inflight_loan_pages(
        &mut self,
        address_space_id: AddressSpaceId,
        pages: u64,
    ) -> Result<InflightLoanReservation, zx_status_t> {
        self.with_vm_mut(|vm| vm.reserve_inflight_loan_pages(address_space_id, pages))
    }

    fn release_inflight_loan_pages(&mut self, address_space_id: AddressSpaceId, pages: u64) {
        self.with_vm_mut(|vm| vm.release_inflight_loan_pages(address_space_id, pages));
    }

    pub(crate) fn read_thread_user_bytes(
        &mut self,
        thread_id: ThreadId,
        ptr: u64,
        len: usize,
    ) -> Result<Vec<u8>, zx_status_t> {
        let thread = self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        let process = self
            .processes
            .get(&thread.process_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if len == 0 {
            return Ok(Vec::new());
        }
        if !self.with_vm(|vm| vm.validate_user_ptr(process.address_space_id, ptr, len)) {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        let mut out = Vec::new();
        out.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
        out.resize(len, 0);

        let page_bytes = crate::userspace::USER_PAGE_BYTES as usize;
        let mut copied = 0usize;
        while copied < len {
            let src_addr = ptr.checked_add(copied as u64).ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_base = src_addr - (src_addr % crate::userspace::USER_PAGE_BYTES);
            self.with_vm_mut(|vm| {
                vm.ensure_user_page_resident(process.address_space_id, page_base, false)
            })?;
            let lookup = self
                .with_vm(|vm| vm.lookup_user_mapping(process.address_space_id, page_base, 1))
                .ok_or(ZX_ERR_BAD_STATE)?;
            let frame_id = lookup.frame_id().ok_or(ZX_ERR_BAD_STATE)?;
            let page_offset =
                usize::try_from(src_addr - page_base).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let chunk_len = core::cmp::min(page_bytes - page_offset, len - copied);
            crate::copy::read_bootstrap_frame_bytes(
                frame_id.raw(),
                page_offset,
                &mut out[copied..copied + chunk_len],
            )?;
            copied += chunk_len;
        }
        Ok(out)
    }

    pub(crate) fn write_thread_user_bytes(
        &mut self,
        thread_id: ThreadId,
        ptr: u64,
        bytes: &[u8],
    ) -> Result<(), zx_status_t> {
        let thread = self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        let process = self
            .processes
            .get(&thread.process_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let len = bytes.len();
        if len == 0 {
            return Ok(());
        }
        if !self.with_vm(|vm| vm.validate_user_ptr(process.address_space_id, ptr, len)) {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        let page_bytes = crate::userspace::USER_PAGE_BYTES as usize;
        let mut written = 0usize;
        while written < len {
            let dst_addr = ptr.checked_add(written as u64).ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_base = dst_addr - (dst_addr % crate::userspace::USER_PAGE_BYTES);
            self.with_vm_mut(|vm| {
                vm.ensure_user_page_resident(process.address_space_id, page_base, true)
            })?;
            let lookup = self
                .with_vm(|vm| vm.lookup_user_mapping(process.address_space_id, page_base, 1))
                .ok_or(ZX_ERR_BAD_STATE)?;
            let frame_id = lookup.frame_id().ok_or(ZX_ERR_BAD_STATE)?;
            let page_offset =
                usize::try_from(dst_addr - page_base).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let chunk_len = core::cmp::min(page_bytes - page_offset, len - written);
            crate::copy::write_bootstrap_frame_bytes(
                frame_id.raw(),
                page_offset,
                &bytes[written..written + chunk_len],
            )?;
            written += chunk_len;
        }
        Ok(())
    }

    pub(crate) fn copyout_thread_user<T: Copy>(
        &self,
        thread_id: ThreadId,
        ptr: *mut T,
        value: T,
    ) -> Result<(), zx_status_t> {
        if ptr.is_null() {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let thread = self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        let process = self
            .processes
            .get(&thread.process_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let len = size_of::<T>();
        if !self.with_vm(|vm| vm.validate_user_ptr(process.address_space_id, ptr as u64, len)) {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        if len == 0 {
            return Ok(());
        }

        let page_bytes = crate::userspace::USER_PAGE_BYTES as usize;
        // SAFETY: `value` is an in-register copy owned by this function. Reinterpreting its
        // bytes for immediate copyout is sound because `T: Copy` and we never outlive `value`.
        let src = unsafe { core::slice::from_raw_parts((&value as *const T).cast::<u8>(), len) };
        let mut written = 0usize;
        while written < len {
            let dst_addr = (ptr as u64)
                .checked_add(written as u64)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_base = dst_addr - (dst_addr % crate::userspace::USER_PAGE_BYTES);
            self.with_vm_mut(|vm| {
                vm.ensure_user_page_resident(process.address_space_id, page_base, true)
            })?;
            let lookup = self
                .with_vm(|vm| vm.lookup_user_mapping(process.address_space_id, page_base, 1))
                .ok_or(ZX_ERR_BAD_STATE)?;
            let frame_id = lookup.frame_id().ok_or(ZX_ERR_BAD_STATE)?;
            let page_offset =
                usize::try_from(dst_addr - page_base).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let chunk_len = core::cmp::min(page_bytes - page_offset, len - written);
            crate::copy::write_bootstrap_frame_bytes(
                frame_id.raw(),
                page_offset,
                &src[written..written + chunk_len],
            )?;
            written += chunk_len;
        }
        Ok(())
    }

    pub(crate) fn thread_state(&self, thread_id: ThreadId) -> Result<ThreadState, zx_status_t> {
        Ok(self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_STATE)?.state)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn map_current_vmo_into_vmar(
        &mut self,
        vmar_address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        global_vmo_id: KernelVmoId,
        vmar_offset: u64,
        vmo_offset: u64,
        len: u64,
        perms: MappingPerms,
    ) -> Result<u64, zx_status_t> {
        let (mapped, req) = self.with_vm_mut(|vm| {
            vm.map_vmo_into_vmar(
                vmar_address_space_id,
                self.current_cpu_id(),
                vmar_id,
                global_vmo_id,
                Some(vmar_offset),
                vmo_offset,
                len,
                perms,
                MappingClonePolicy::None,
            )
        })?;
        self.apply_tlb_commit_reqs_current(&[req])?;
        Ok(mapped)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn map_current_vmo_into_vmar_anywhere(
        &mut self,
        vmar_address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        global_vmo_id: KernelVmoId,
        vmo_offset: u64,
        len: u64,
        perms: MappingPerms,
    ) -> Result<u64, zx_status_t> {
        let (mapped, req) = self.with_vm_mut(|vm| {
            vm.map_vmo_into_vmar(
                vmar_address_space_id,
                self.current_cpu_id(),
                vmar_id,
                global_vmo_id,
                None,
                vmo_offset,
                len,
                perms,
                MappingClonePolicy::None,
            )
        })?;
        self.apply_tlb_commit_reqs_current(&[req])?;
        Ok(mapped)
    }

    pub(crate) fn unmap_current_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        addr: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        let req = self.with_vm_mut(|vm| vm.unmap_vmar(address_space_id, vmar_id, addr, len))?;
        self.apply_tlb_commit_reqs_current(&[req])
    }

    pub(crate) fn protect_current_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        addr: u64,
        len: u64,
        perms: MappingPerms,
    ) -> Result<(), zx_status_t> {
        let req =
            self.with_vm_mut(|vm| vm.protect_vmar(address_space_id, vmar_id, addr, len, perms))?;
        self.apply_tlb_commit_reqs_current(&[req])
    }

    pub(crate) fn handle_current_page_fault(&mut self, fault_va: u64, error: u64) -> bool {
        let process_id = match self.current_thread() {
            Ok(thread) => thread.process_id,
            Err(_) => return false,
        };
        let address_space_id = match self.processes.get(&process_id) {
            Some(process) => process.address_space_id,
            None => return false,
        };
        self.with_vm_mut(|vm| vm.handle_page_fault(address_space_id, fault_va, error))
    }

    fn alloc_process_id(&mut self) -> ProcessId {
        let id = self.next_process_id;
        self.next_process_id = self.next_process_id.wrapping_add(1);
        id
    }

    fn alloc_job_id(&mut self) -> JobId {
        let id = self.next_job_id;
        self.next_job_id = self.next_job_id.wrapping_add(1);
        id
    }

    fn alloc_thread_id(&mut self) -> ThreadId {
        let id = self.next_thread_id;
        self.next_thread_id = self.next_thread_id.wrapping_add(1);
        id
    }

    fn alloc_koid(&mut self) -> zx_koid_t {
        let id = self.next_koid;
        self.next_koid = self.next_koid.wrapping_add(1);
        id
    }

    fn current_cpu_id(&self) -> usize {
        crate::arch::apic::this_apic_id() as usize
    }

    fn current_cpu_now_ns(&self) -> i64 {
        crate::time::now_ns()
    }

    fn current_thread(&self) -> Result<&Thread, zx_status_t> {
        self.threads
            .get(&self.current_thread_id()?)
            .ok_or(ZX_ERR_BAD_STATE)
    }

    fn process(&self, process_id: ProcessId) -> Result<&Process, zx_status_t> {
        self.processes.get(&process_id).ok_or(ZX_ERR_BAD_STATE)
    }

    fn current_process(&self) -> Result<&Process, zx_status_t> {
        let process_id = self.current_thread()?.process_id;
        self.process(process_id)
    }

    fn current_process_mut(&mut self) -> Result<&mut Process, zx_status_t> {
        let process_id = self.current_thread()?.process_id;
        self.process_mut(process_id)
    }

    fn process_mut(&mut self, process_id: ProcessId) -> Result<&mut Process, zx_status_t> {
        self.processes.get_mut(&process_id).ok_or(ZX_ERR_BAD_STATE)
    }

    pub(crate) fn sync_current_cpu_tlb_state(&mut self) -> Result<(), zx_status_t> {
        let current_cpu_id = self.current_cpu_id();
        let current_address_space_id = self.current_process()?.address_space_id;
        self.with_vm_mut(|vm| {
            vm.sync_current_cpu_tlb_state(current_address_space_id, current_cpu_id)
        })
    }

    fn observe_cpu_tlb_epoch_for_address_space(
        &mut self,
        address_space_id: AddressSpaceId,
        cpu_id: usize,
    ) {
        self.with_vm_mut(|vm| vm.observe_cpu_tlb_epoch_for_address_space(address_space_id, cpu_id));
    }

    pub(crate) fn current_address_space_id(&self) -> Result<AddressSpaceId, zx_status_t> {
        Ok(self.current_process()?.address_space_id)
    }

    fn install_mapping_pages(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        self.with_vm(|vm| vm.install_mapping_pages(address_space_id, base, len))
    }

    fn lock_address_space_tx_set(
        &self,
        requests: &[AddressSpaceTxRequest],
    ) -> Result<AddressSpaceTxSet, zx_status_t> {
        self.with_vm(|vm| vm.lock_address_space_tx_set(requests))
    }

    fn lock_channel_loan_tx(
        &self,
        sender_address_space_id: AddressSpaceId,
        sender_range: PageRange,
        receiver_address_space_id: AddressSpaceId,
        receiver_range: PageRange,
    ) -> Result<ChannelLoanTx, zx_status_t> {
        self.with_vm(|vm| {
            vm.lock_channel_loan_tx(
                sender_address_space_id,
                sender_range,
                receiver_address_space_id,
                receiver_range,
            )
        })
    }

    fn clear_mapping_pages(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        self.with_vm(|vm| vm.clear_mapping_pages(address_space_id, base, len))
    }

    fn update_mapping_pages(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        self.with_vm(|vm| vm.update_mapping_pages(address_space_id, base, len))
    }

    fn resolve_copy_on_write_page(
        &mut self,
        address_space_id: AddressSpaceId,
        fault_va: u64,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| vm.resolve_copy_on_write_page(address_space_id, fault_va))
    }

    fn materialize_lazy_anon_page(
        &mut self,
        address_space_id: AddressSpaceId,
        fault_va: u64,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| vm.materialize_lazy_anon_page(address_space_id, fault_va))
    }

    fn materialize_lazy_vmo_page(
        &mut self,
        address_space_id: AddressSpaceId,
        fault_va: u64,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| vm.materialize_lazy_vmo_page(address_space_id, fault_va))
    }

    fn sync_mapping_pages(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        self.with_vm(|vm| vm.sync_mapping_pages(address_space_id, base, len))
    }

    fn sync_mapping_pages_locked(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
        tx: &mut BootstrapTxCursor,
    ) -> Result<(), zx_status_t> {
        self.with_vm(|vm| vm.sync_mapping_pages_locked(address_space_id, base, len, tx))
    }

    fn mapped_frames_in_range(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
    ) -> Result<Vec<FrameId>, zx_status_t> {
        self.with_vm(|vm| vm.mapped_frames_in_range(address_space_id, base, len))
    }

    fn frame_mappings(&self, frame_id: FrameId) -> Vec<FrameMappingSnapshot> {
        self.with_vm(|vm| vm.frame_mappings(frame_id))
    }

    fn frame_mapping_count(&self, frame_id: FrameId) -> u64 {
        self.with_vm(|vm| vm.frame_mapping_count(frame_id))
    }

    fn validate_frame_mapping_invariants(&self, frame_id: FrameId, context: &str) {
        self.with_vm(|vm| vm.validate_frame_mapping_invariants(frame_id, context))
    }

    fn validate_frame_mapping_invariants_for(&self, frame_ids: &[FrameId], context: &str) {
        self.with_vm(|vm| vm.validate_frame_mapping_invariants_for(frame_ids, context))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MergedStrictTlbReq {
    op: TlbSyncOp,
    local_already_flushed: bool,
}

fn merge_strict_tlb_commit_reqs(
    reqs: &[TlbCommitReq],
) -> Result<alloc::collections::BTreeMap<AddressSpaceId, MergedStrictTlbReq>, zx_status_t> {
    let mut merged = alloc::collections::BTreeMap::new();
    for req in reqs {
        if req.class() != CommitClass::Strict {
            continue;
        }
        let Some(op) = TlbSyncOp::from_hint(req.invalidate_hint()).map_err(map_page_table_error)?
        else {
            continue;
        };
        let initial_op = op.clone();
        let entry = merged
            .entry(req.address_space_id())
            .or_insert_with(|| MergedStrictTlbReq {
                op: initial_op,
                local_already_flushed: !matches!(req.invalidate_hint(), TlbInvalidateHint::Full),
            });
        if entry.op != op {
            entry.op.merge(op).map_err(map_page_table_error)?;
        }
        if matches!(req.invalidate_hint(), TlbInvalidateHint::Full) {
            entry.local_already_flushed = false;
        }
    }
    Ok(merged)
}

fn flush_tlb_sync_op_local(op: &TlbSyncOp) {
    match op {
        TlbSyncOp::Full => crate::arch::tlb::flush_all_local(),
        TlbSyncOp::Ranges(ranges) => {
            for &range in ranges {
                crate::arch::tlb::flush_range_local(range);
            }
        }
    }
}

fn shootdown_tlb_sync_op(op: &TlbSyncOp, remote_cpus: &[usize]) -> Result<(), zx_status_t> {
    match op {
        TlbSyncOp::Full => crate::arch::ipi::shootdown_all(remote_cpus),
        TlbSyncOp::Ranges(ranges) => {
            for &range in ranges {
                crate::arch::ipi::shootdown_range(remote_cpus, range)?;
            }
            Ok(())
        }
    }
}

/// Apply one or more committed TLB requirements against the current CPU and any tracked
/// active peer CPUs for the affected address spaces.
pub(crate) fn apply_tlb_commit_reqs(
    vm_handle: &Arc<Mutex<VmDomain>>,
    current_cpu_id: usize,
    current_address_space_id: Option<AddressSpaceId>,
    reqs: &[TlbCommitReq],
) -> Result<(), zx_status_t> {
    let strict_address_spaces = merge_strict_tlb_commit_reqs(reqs)?;

    for (address_space_id, merged_req) in strict_address_spaces {
        let current_cpu_active = current_address_space_id == Some(address_space_id);
        let plan = {
            let mut vm = vm_handle.lock();
            vm.plan_strict_tlb_sync(
                address_space_id,
                current_cpu_id,
                current_cpu_active,
                merged_req.op.clone(),
                current_cpu_active && merged_req.local_already_flushed,
            )?
        };
        let Some(plan) = plan else {
            continue;
        };

        if plan.local_needs_flush {
            flush_tlb_sync_op_local(&plan.op);
        }
        if !plan.remote_cpus.is_empty() {
            shootdown_tlb_sync_op(&plan.op, &plan.remote_cpus)?;
        }

        let mut vm = vm_handle.lock();
        vm.complete_strict_tlb_sync(&plan)?;
    }

    Ok(())
}

/// Retire bootstrap frames only after every relevant address space has crossed the required
/// TLB quiescent boundary for strict reuse safety.
pub(crate) fn retire_bootstrap_frames_after_quiescence(
    vm_handle: &Arc<Mutex<VmDomain>>,
    current_cpu_id: usize,
    current_address_space_id: Option<AddressSpaceId>,
    barrier_address_spaces: &[AddressSpaceId],
    retired_frames: &[RetiredFrame],
) -> Result<(), zx_status_t> {
    if retired_frames.is_empty() {
        return Ok(());
    }

    let mut reqs = Vec::with_capacity(barrier_address_spaces.len());
    for &address_space_id in barrier_address_spaces {
        reqs.push(TlbCommitReq::strict(address_space_id));
    }
    apply_tlb_commit_reqs(vm_handle, current_cpu_id, current_address_space_id, &reqs)?;

    {
        let vm = vm_handle.lock();
        for retired in retired_frames {
            vm.with_frames_mut(|frames| {
                frames
                    .unregister_existing(retired.frame_id())
                    .map_err(|_| ZX_ERR_BAD_STATE)
            })?;
        }
    }
    for retired in retired_frames {
        crate::userspace::free_bootstrap_page(retired.frame_id().raw());
    }
    Ok(())
}

impl VmDomain {
    pub(crate) fn validate_user_ptr(
        &self,
        address_space_id: AddressSpaceId,
        ptr: u64,
        len: usize,
    ) -> bool {
        self.address_spaces
            .get(&address_space_id)
            .map(|address_space| address_space.validate_user_ptr(ptr, len))
            .unwrap_or(false)
    }

    pub(crate) fn lookup_user_mapping(
        &self,
        address_space_id: AddressSpaceId,
        ptr: u64,
        len: usize,
    ) -> Option<VmaLookup> {
        self.address_spaces
            .get(&address_space_id)
            .and_then(|address_space| address_space.lookup_user_mapping(ptr, len))
    }

    pub(crate) fn snapshot_mapping_vmo(
        &self,
        address_space_id: AddressSpaceId,
        ptr: u64,
        len: usize,
    ) -> Option<(VmaLookup, Vmo)> {
        let address_space = self.address_spaces.get(&address_space_id)?;
        let lookup = address_space.lookup_user_mapping(ptr, len)?;
        let vmo = address_space.vm.vmo(lookup.vmo_id())?.clone();
        Some((lookup, vmo))
    }

    pub(crate) fn root_vmar(&self, address_space_id: AddressSpaceId) -> Result<Vmar, zx_status_t> {
        let address_space = self
            .address_spaces
            .get(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        Ok(address_space.root_vmar())
    }

    pub(crate) fn create_process_address_space(
        &mut self,
    ) -> Result<(AddressSpaceId, Vmar), zx_status_t> {
        let address_space_id = self.alloc_address_space_id();
        let address_space = AddressSpace {
            vm: VmAddressSpace::new_with_id(
                VmAddressSpaceId::new(address_space_id),
                crate::userspace::USER_CODE_VA,
                crate::userspace::USER_REGION_BYTES,
            )
            .map_err(map_address_space_error)?,
            page_tables: crate::page_table::UserPageTables::clone_current_kernel_template(
                crate::arch::tlb::pcid_for_address_space(address_space_id),
            )
            .map_err(map_page_table_error)?,
            tlb_cpus: TlbCpuTracker::default(),
            strict_tlb_epoch: 0,
            pending_tlb_sync: None,
            vm_resources: VmResourceState::new(),
            private_clone_vmos: Vec::new(),
        };
        debug_assert!(
            address_space
                .page_tables
                .validate_descriptor_metadata_range(
                    crate::userspace::USER_CODE_VA,
                    crate::userspace::USER_CODE_BYTES,
                )
        );
        let root_vmar = address_space.root_vmar();
        self.address_spaces.insert(address_space_id, address_space);
        Ok((address_space_id, root_vmar))
    }

    fn record_vm_resource_telemetry(&self) {
        crate::userspace::record_vm_resource_accounting(
            self.vm_private_cow_pages_current,
            self.vm_private_cow_pages_peak,
            self.vm_private_cow_quota_hits,
            self.vm_inflight_loan_pages_current,
            self.vm_inflight_loan_pages_peak,
            self.vm_inflight_loan_quota_hits,
        );
    }

    fn log_vm_quota_exceeded(
        &self,
        address_space_id: AddressSpaceId,
        exceeded: VmQuotaExceeded,
        context: &str,
    ) {
        let stats = self
            .address_spaces
            .get(&address_space_id)
            .map(AddressSpace::vm_resource_stats)
            .unwrap_or_default();
        match exceeded {
            VmQuotaExceeded::PrivateCowPages { limit, current } => crate::kprintln!(
                "kernel: vm private COW quota exceeded (context={}, aspace={}, current={}, limit={}, peak={})",
                context,
                address_space_id,
                current,
                limit,
                stats.peak_private_cow_pages
            ),
            VmQuotaExceeded::InflightLoanPages { limit, current } => crate::kprintln!(
                "kernel: vm in-flight loan quota exceeded (context={}, aspace={}, current={}, limit={}, peak={})",
                context,
                address_space_id,
                current,
                limit,
                stats.peak_inflight_loan_pages
            ),
        }
    }

    fn reserve_private_cow_page(
        &mut self,
        address_space_id: AddressSpaceId,
        page_base: u64,
    ) -> Result<CowReservation, zx_status_t> {
        let reservation = {
            let address_space = self
                .address_spaces
                .get_mut(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            address_space.try_reserve_private_cow_page(page_base)
        };
        match reservation {
            Ok(state) => Ok(CowReservation {
                address_space_id,
                page_base,
                state,
            }),
            Err(exceeded) => {
                self.vm_private_cow_quota_hits = self.vm_private_cow_quota_hits.wrapping_add(1);
                self.record_vm_resource_telemetry();
                self.log_vm_quota_exceeded(address_space_id, exceeded, "reserve_private_cow_page");
                Err(ZX_ERR_NO_RESOURCES)
            }
        }
    }

    fn commit_private_cow_page(&mut self, address_space_id: AddressSpaceId, page_base: u64) {
        let committed = self
            .address_spaces
            .get_mut(&address_space_id)
            .map(|address_space| address_space.commit_private_cow_page(page_base))
            .unwrap_or(false);
        if !committed {
            return;
        }
        self.vm_private_cow_pages_current = self.vm_private_cow_pages_current.saturating_add(1);
        self.vm_private_cow_pages_peak = self
            .vm_private_cow_pages_peak
            .max(self.vm_private_cow_pages_current);
        self.record_vm_resource_telemetry();
    }

    fn rollback_private_cow_page_reservation(
        &mut self,
        address_space_id: AddressSpaceId,
        page_base: u64,
    ) {
        let rolled_back = self
            .address_spaces
            .get_mut(&address_space_id)
            .map(|address_space| address_space.rollback_private_cow_page_reservation(page_base))
            .unwrap_or(false);
        if rolled_back {
            self.record_vm_resource_telemetry();
        }
    }

    fn clear_private_cow_range(&mut self, address_space_id: AddressSpaceId, base: u64, len: u64) {
        let removed = self
            .address_spaces
            .get_mut(&address_space_id)
            .map(|address_space| address_space.clear_private_cow_range(base, len))
            .unwrap_or(0);
        if removed == 0 {
            return;
        }
        self.vm_private_cow_pages_current =
            self.vm_private_cow_pages_current.saturating_sub(removed);
        self.record_vm_resource_telemetry();
    }

    fn reserve_inflight_loan_pages(
        &mut self,
        address_space_id: AddressSpaceId,
        pages: u64,
    ) -> Result<InflightLoanReservation, zx_status_t> {
        let reservation = {
            let address_space = self
                .address_spaces
                .get_mut(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            address_space.try_reserve_inflight_loan_pages(pages)
        };
        match reservation {
            Ok(()) => {
                self.vm_inflight_loan_pages_current =
                    self.vm_inflight_loan_pages_current.saturating_add(pages);
                self.vm_inflight_loan_pages_peak = self
                    .vm_inflight_loan_pages_peak
                    .max(self.vm_inflight_loan_pages_current);
                self.record_vm_resource_telemetry();
                Ok(())
            }
            Err(exceeded) => {
                self.vm_inflight_loan_quota_hits = self.vm_inflight_loan_quota_hits.wrapping_add(1);
                self.record_vm_resource_telemetry();
                self.log_vm_quota_exceeded(
                    address_space_id,
                    exceeded,
                    "reserve_inflight_loan_pages",
                );
                Err(ZX_ERR_SHOULD_WAIT)
            }
        }
        .map(|()| InflightLoanReservation {
            address_space_id,
            pages,
            active: true,
        })
    }

    fn release_inflight_loan_pages(&mut self, address_space_id: AddressSpaceId, pages: u64) {
        let released = self
            .address_spaces
            .get_mut(&address_space_id)
            .map(|address_space| address_space.release_inflight_loan_pages(pages))
            .unwrap_or(0);
        if released == 0 {
            return;
        }
        self.vm_inflight_loan_pages_current =
            self.vm_inflight_loan_pages_current.saturating_sub(released);
        self.record_vm_resource_telemetry();
    }

    fn bind_lazy_vmo_frame(
        &mut self,
        address_space_id: AddressSpaceId,
        page_base: u64,
        frame_id: FrameId,
    ) -> Result<LazyVmoFaultResolution, zx_status_t> {
        self.with_address_space_frames_mut(address_space_id, |address_space, frames| {
            address_space
                .resolve_lazy_vmo_fault(frames, page_base, frame_id)
                .map_err(map_address_space_error)
        })
    }

    pub(crate) fn allocate_subvmar(
        &mut self,
        address_space_id: AddressSpaceId,
        cpu_id: usize,
        parent_vmar_id: VmarId,
        offset: u64,
        len: u64,
        align: u64,
        mode: VmarAllocMode,
        offset_is_upper_limit: bool,
        child_policy: VmarPlacementPolicy,
    ) -> Result<Vmar, zx_status_t> {
        let address_space = self
            .address_spaces
            .get_mut(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        address_space
            .allocate_subvmar(
                cpu_id,
                parent_vmar_id,
                offset,
                len,
                align,
                mode,
                offset_is_upper_limit,
                child_policy,
            )
            .map_err(map_address_space_error)
    }

    pub(crate) fn destroy_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
    ) -> Result<TlbCommitReq, zx_status_t> {
        let affected_ranges = {
            let address_space = self
                .address_spaces
                .get(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            if vmar_id == address_space.root_vmar().id() {
                return Err(ZX_ERR_BAD_STATE);
            }
            if address_space.vmar(vmar_id).is_none() {
                return Err(ZX_ERR_NOT_FOUND);
            }
            address_space.vm.mapped_ranges_in_vmar_subtree(vmar_id)
        };

        let mut affected_frames = Vec::new();
        for (base, len) in affected_ranges.iter().copied() {
            let frames = self.mapped_frames_in_range(address_space_id, base, len)?;
            for frame_id in frames {
                push_unique_frame_id(&mut affected_frames, frame_id);
            }
        }

        let cleared_ranges =
            self.with_address_space_frames_mut(address_space_id, |address_space, frames| {
                address_space
                    .destroy_vmar(frames, vmar_id)
                    .map_err(map_address_space_error)
            })?;
        for (base, len) in cleared_ranges {
            self.clear_private_cow_range(address_space_id, base, len);
            self.clear_mapping_pages(address_space_id, base, len)?;
        }
        self.validate_frame_mapping_invariants_for(&affected_frames, "destroy_vmar");
        Ok(if affected_ranges.is_empty() {
            TlbCommitReq::relaxed(address_space_id)
        } else {
            TlbCommitReq::strict_range(
                address_space_id,
                affected_ranges
                    .into_iter()
                    .try_fold(None, |merged: Option<PageRange>, (base, len)| {
                        let range = PageRange::new(base, len)?;
                        Ok::<_, PageTableError>(Some(match merged {
                            Some(existing) => merge_page_ranges(existing, range)?,
                            None => range,
                        }))
                    })
                    .map_err(map_page_table_error)?
                    .ok_or(ZX_ERR_BAD_STATE)?,
            )
        })
    }

    /// Remove all user-visible mappings from the address space associated with a
    /// terminated process.  This releases frame references held by the VMAs so
    /// physical memory can be reclaimed promptly rather than waiting for the
    /// process to be reaped.
    pub(crate) fn cleanup_process_address_space(
        &mut self,
        address_space_id: AddressSpaceId,
    ) -> Result<TlbCommitReq, zx_status_t> {
        let (root_vmar_id, ranges) = {
            let address_space = self
                .address_spaces
                .get(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            let root = address_space.root_vmar();
            let ranges = address_space.vm.mapped_ranges_in_vmar_subtree(root.id());
            (root.id(), ranges)
        };
        if ranges.is_empty() {
            return Ok(TlbCommitReq::relaxed(address_space_id));
        }
        for (base, len) in ranges.iter().copied() {
            let frames_handle = self.frame_table();
            let address_space = self
                .address_spaces
                .get_mut(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            {
                let mut frames = frames_handle.lock();
                let _ = address_space.unmap(&mut frames, root_vmar_id, base, len);
            }
            self.clear_private_cow_range(address_space_id, base, len);
            let _ = self.clear_mapping_pages(address_space_id, base, len);
        }
        Ok(TlbCommitReq::strict(address_space_id))
    }

    pub(crate) fn ensure_user_page_resident(
        &mut self,
        address_space_id: AddressSpaceId,
        page_va: u64,
        for_write: bool,
    ) -> Result<(), zx_status_t> {
        let page_base = align_down_page(page_va);
        let meta = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.page_meta(page_base))
            .ok_or(ZX_ERR_INVALID_ARGS)?;
        if for_write && !meta.logical_write() {
            return Err(ZX_ERR_ACCESS_DENIED);
        }
        match meta.tag() {
            PteMetaTag::LazyAnon => self.materialize_lazy_anon_page(address_space_id, page_base),
            PteMetaTag::LazyVmo => self.materialize_lazy_vmo_page(address_space_id, page_base),
            PteMetaTag::Present if for_write && meta.cow_shared() => {
                self.resolve_copy_on_write_page(address_space_id, page_base)
            }
            PteMetaTag::Present | PteMetaTag::Phys => Ok(()),
            _ => Err(ZX_ERR_BAD_STATE),
        }
    }

    pub(crate) fn try_loan_user_pages(
        &mut self,
        address_space_id: AddressSpaceId,
        ptr: u64,
        len: usize,
    ) -> Result<Option<LoanedUserPages>, zx_status_t> {
        if len == 0 {
            return Ok(None);
        }

        let page_size = crate::userspace::USER_PAGE_BYTES;
        let len_u64 = u64::try_from(len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        if (ptr & (page_size - 1)) != 0 || (len_u64 & (page_size - 1)) != 0 {
            return Ok(None);
        }

        let Some(lookup) = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.lookup_user_mapping(ptr, len))
        else {
            return Ok(None);
        };

        if !lookup.vmo_kind().supports_page_loan() {
            return Ok(None);
        }

        let page_count = len / (page_size as usize);
        let mut resident_pages = Vec::with_capacity(page_count);
        for page_index in 0..page_count {
            let page_va = ptr + (page_index as u64) * page_size;
            let Some(page_lookup) = self
                .address_spaces
                .get(&address_space_id)
                .and_then(|space| space.lookup_user_mapping(page_va, 1))
            else {
                return Ok(None);
            };
            let Some(frame_id) = page_lookup.frame_id() else {
                return Ok(None);
            };
            resident_pages.push(frame_id);
        }

        let pin = self
            .with_frames_mut(|frames| frames.pin_many(&resident_pages))
            .map_err(|_| ZX_ERR_BAD_STATE)?;
        let budget = match self.reserve_inflight_loan_pages(
            address_space_id,
            u64::try_from(page_count).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
        ) {
            Ok(budget) => budget,
            Err(status) => {
                self.with_frames_mut(|frames| pin.release(frames));
                return Err(status);
            }
        };
        let loan = match self.with_frames_mut(|frames| pin.into_loan(frames)) {
            Ok(loan) => loan,
            Err(_) => {
                budget.release(self);
                return Err(ZX_ERR_BAD_STATE);
            }
        };

        let len_u32 = match u32::try_from(len) {
            Ok(len_u32) => len_u32,
            Err(_) => {
                let frame_ids = loan.frame_ids().to_vec();
                self.with_frames_mut(|frames| loan.release(frames));
                budget.release(self);
                self.validate_frame_mapping_invariants_for(&frame_ids, "try_loan_user_pages");
                return Err(ZX_ERR_OUT_OF_RANGE);
            }
        };
        Ok(Some(budget.commit(
            ptr,
            len_u32,
            lookup.max_perms().contains(MappingPerms::WRITE),
            loan,
        )))
    }

    pub(crate) fn release_loaned_user_pages(&mut self, loaned: LoanedUserPages) {
        loaned.release(self)
    }

    pub(crate) fn prepare_loaned_channel_write(
        &mut self,
        loaned: &mut LoanedUserPages,
        receiver_address_space_id: AddressSpaceId,
    ) -> Result<TlbCommitReq, zx_status_t> {
        if !loaned.needs_cow() {
            loaned.bind_receiver_address_space(receiver_address_space_id);
            return Ok(TlbCommitReq::relaxed(loaned.address_space_id()));
        }

        let len = u64::from(loaned.len());
        let range = PageRange::new(loaned.base(), len).map_err(map_page_table_error)?;
        let mut loan_tx = self.lock_channel_loan_tx(
            loaned.address_space_id(),
            range,
            receiver_address_space_id,
            range,
        )?;
        {
            let address_space = self
                .address_spaces
                .get_mut(&loaned.address_space_id())
                .ok_or(ZX_ERR_BAD_STATE)?;
            address_space
                .arm_copy_on_write(loaned.base(), len)
                .map_err(map_address_space_error)?;
        }
        self.clear_private_cow_range(loaned.address_space_id(), loaned.base(), len);
        loaned.bind_receiver_address_space(receiver_address_space_id);
        let sender_cursor = loan_tx.sender_cursor_mut().ok_or(ZX_ERR_BAD_STATE)?;
        self.sync_mapping_pages_locked(
            loaned.address_space_id(),
            loaned.base(),
            len,
            sender_cursor,
        )?;
        loan_tx.commit().map_err(map_page_table_error)?;
        Ok(TlbCommitReq::strict_range(loaned.address_space_id(), range))
    }

    pub(crate) fn try_remap_loaned_channel_read(
        &mut self,
        current_address_space_id: AddressSpaceId,
        dst_base: u64,
        loaned: &LoanedUserPages,
    ) -> Result<LoanRemapResult, zx_status_t> {
        let Some(receiver_address_space_id) = loaned.receiver_address_space_id() else {
            return Ok(LoanRemapResult::not_remapped(current_address_space_id));
        };

        let len = u64::from(loaned.len());
        if len == 0
            || (dst_base & (crate::userspace::USER_PAGE_BYTES - 1)) != 0
            || (len & (crate::userspace::USER_PAGE_BYTES - 1)) != 0
        {
            return Ok(LoanRemapResult::not_remapped(current_address_space_id));
        }
        if current_address_space_id != receiver_address_space_id {
            return Ok(LoanRemapResult::not_remapped(current_address_space_id));
        }

        let receiver_lookup = self
            .address_spaces
            .get(&receiver_address_space_id)
            .and_then(|space| space.lookup_user_mapping(dst_base, len as usize));
        let Some(receiver_lookup) = receiver_lookup else {
            return Ok(LoanRemapResult::not_remapped(current_address_space_id));
        };
        if receiver_lookup.mapping_base() != dst_base
            || receiver_lookup.mapping_len() != len
            || receiver_lookup.vmo_kind() != VmoKind::Anonymous
            || !receiver_lookup.max_perms().contains(MappingPerms::WRITE)
        {
            return Ok(LoanRemapResult::not_remapped(current_address_space_id));
        }

        let page_count = usize::try_from(len / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        if page_count != loaned.pages().len() {
            return Err(ZX_ERR_BAD_STATE);
        }
        for page_index in 0..page_count {
            let page_va = dst_base + (page_index as u64) * crate::userspace::USER_PAGE_BYTES;
            let meta = self
                .address_spaces
                .get(&receiver_address_space_id)
                .and_then(|space| space.page_meta(page_va))
                .ok_or(ZX_ERR_INVALID_ARGS)?;
            if !meta.logical_write() {
                return Ok(LoanRemapResult::not_remapped(current_address_space_id));
            }
        }

        let replaced_receiver_frames =
            self.mapped_frames_in_range(receiver_address_space_id, dst_base, len)?;
        let sender_range = PageRange::new(loaned.base(), len).map_err(map_page_table_error)?;
        let receiver_range = PageRange::new(dst_base, len).map_err(map_page_table_error)?;
        let mut loan_tx = self.lock_channel_loan_tx(
            loaned.address_space_id(),
            sender_range,
            receiver_address_space_id,
            receiver_range,
        )?;
        self.with_address_space_frames_mut(receiver_address_space_id, |receiver, frames| {
            receiver
                .replace_mapping_frames_copy_on_write(frames, dst_base, len, loaned.pages())
                .map_err(map_address_space_error)
        })?;
        self.clear_private_cow_range(receiver_address_space_id, dst_base, len);
        let receiver_cursor = loan_tx.receiver_cursor_mut().ok_or(ZX_ERR_BAD_STATE)?;
        self.sync_mapping_pages_locked(receiver_address_space_id, dst_base, len, receiver_cursor)?;
        loan_tx.commit().map_err(map_page_table_error)?;
        if let Some(&source_frame_id) = loaned.pages().first() {
            crate::userspace::record_vm_last_remap_source_rmap_count(
                self.frame_mapping_count(source_frame_id),
            );
        }
        self.validate_frame_mapping_invariants_for(
            loaned.pages(),
            "try_remap_loaned_channel_read/source",
        );
        self.validate_frame_mapping_invariants_for(
            &replaced_receiver_frames,
            "try_remap_loaned_channel_read/receiver",
        );
        let retire_plan = self.build_optional_frame_retire_plan(
            &replaced_receiver_frames,
            &[receiver_address_space_id],
        );
        Ok(LoanRemapResult::remapped(
            current_address_space_id,
            receiver_range,
            retire_plan,
        ))
    }

    pub(crate) fn unmap_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        addr: u64,
        len: u64,
    ) -> Result<TlbCommitReq, zx_status_t> {
        let affected_frames = self.mapped_frames_in_range(address_space_id, addr, len)?;
        let frames_handle = self.frame_table();
        let address_space = self
            .address_spaces
            .get_mut(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let _ = address_space.vmar(vmar_id).ok_or(ZX_ERR_NOT_FOUND)?;
        {
            let mut frames = frames_handle.lock();
            address_space
                .unmap(&mut frames, vmar_id, addr, len)
                .map_err(map_address_space_error)?;
        }
        self.clear_private_cow_range(address_space_id, addr, len);
        self.clear_mapping_pages(address_space_id, addr, len)?;
        self.validate_frame_mapping_invariants_for(&affected_frames, "unmap_current_vmar");
        Ok(TlbCommitReq::strict_range(
            address_space_id,
            PageRange::new(addr, len).map_err(map_page_table_error)?,
        ))
    }

    pub(crate) fn protect_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        addr: u64,
        len: u64,
        perms: MappingPerms,
    ) -> Result<TlbCommitReq, zx_status_t> {
        let strict = self.protect_requires_strict_sync(address_space_id, addr, len, perms)?;
        let frames_handle = self.frame_table();
        let address_space = self
            .address_spaces
            .get_mut(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let _ = address_space.vmar(vmar_id).ok_or(ZX_ERR_NOT_FOUND)?;
        {
            let mut frames = frames_handle.lock();
            address_space
                .protect(&mut frames, vmar_id, addr, len, perms)
                .map_err(map_address_space_error)?;
        }
        self.update_mapping_pages(address_space_id, addr, len)?;
        Ok(if strict {
            TlbCommitReq::strict_range(
                address_space_id,
                PageRange::new(addr, len).map_err(map_page_table_error)?,
            )
        } else {
            TlbCommitReq::relaxed(address_space_id)
        })
    }

    fn mapping_access_satisfied(
        &self,
        address_space_id: AddressSpaceId,
        page_base: u64,
        for_write: bool,
    ) -> bool {
        self.address_spaces
            .get(&address_space_id)
            .and_then(|space| space.lookup_user_mapping(page_base, 1))
            .and_then(|lookup| lookup.frame_id().map(|frame_id| (lookup, frame_id)))
            .map(|(lookup, _)| !for_write || lookup.perms().contains(MappingPerms::WRITE))
            .unwrap_or(false)
    }

    fn build_copy_on_write_plan(
        &self,
        address_space_id: AddressSpaceId,
        page_base: u64,
    ) -> Result<FaultPlan, zx_status_t> {
        let lookup = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.lookup_user_mapping(page_base, 1))
            .ok_or(ZX_ERR_BAD_STATE)?;
        if !lookup.vmo_kind().supports_copy_on_write() {
            return Err(ZX_ERR_BAD_STATE);
        }
        let old_frame_id = lookup.frame_id().ok_or(ZX_ERR_BAD_STATE)?;
        Ok(FaultPlan::CopyOnWrite {
            key: FaultInFlightKey::LocalPage {
                address_space_id,
                page_base,
            },
            address_space_id,
            page_base,
            old_frame_id,
        })
    }

    fn build_lazy_vmo_plan(
        &self,
        address_space_id: AddressSpaceId,
        page_base: u64,
    ) -> Result<FaultPlan, zx_status_t> {
        let lookup = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.lookup_user_mapping(page_base, 1))
            .ok_or(ZX_ERR_BAD_STATE)?;
        let page_offset = lookup
            .vmo_offset()
            .checked_sub(lookup.vmo_offset() % crate::userspace::USER_PAGE_BYTES)
            .ok_or(ZX_ERR_BAD_STATE)?;
        Ok(FaultPlan::LazyVmo {
            key: FaultInFlightKey::SharedVmoPage {
                global_vmo_id: lookup.global_vmo_id(),
                page_offset,
            },
            address_space_id,
            page_base,
            global_vmo_id: lookup.global_vmo_id(),
            page_offset,
            vmo_kind: lookup.vmo_kind(),
        })
    }

    fn plan_resident_fault(
        &self,
        address_space_id: AddressSpaceId,
        page_va: u64,
        for_write: bool,
    ) -> Result<FaultPlanResult, zx_status_t> {
        let page_base = align_down_page(page_va);
        let meta = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.page_meta(page_base))
            .ok_or(ZX_ERR_INVALID_ARGS)?;
        if for_write && !meta.logical_write() {
            return Err(ZX_ERR_ACCESS_DENIED);
        }
        if self.mapping_access_satisfied(address_space_id, page_base, for_write) {
            return Ok(FaultPlanResult::Satisfied);
        }
        match meta.tag() {
            PteMetaTag::LazyAnon => Ok(FaultPlanResult::Ready(FaultPlan::LazyAnon {
                key: FaultInFlightKey::LocalPage {
                    address_space_id,
                    page_base,
                },
                address_space_id,
                page_base,
            })),
            PteMetaTag::LazyVmo => Ok(FaultPlanResult::Ready(
                self.build_lazy_vmo_plan(address_space_id, page_base)?,
            )),
            PteMetaTag::Present if for_write && meta.cow_shared() => Ok(FaultPlanResult::Ready(
                self.build_copy_on_write_plan(address_space_id, page_base)?,
            )),
            PteMetaTag::Present | PteMetaTag::Phys => Ok(FaultPlanResult::Satisfied),
            _ => Err(ZX_ERR_BAD_STATE),
        }
    }

    fn plan_trap_fault(
        &self,
        address_space_id: AddressSpaceId,
        fault_va: u64,
        error: u64,
    ) -> FaultPlanResult {
        let page_base = align_down_page(fault_va);
        let mut flags = PageFaultFlags::empty();
        if error & (1 << 0) != 0 {
            flags |= PageFaultFlags::PRESENT;
        }
        if error & (1 << 1) != 0 {
            flags |= PageFaultFlags::WRITE;
        }
        if error & (1 << 2) != 0 {
            flags |= PageFaultFlags::USER;
        }

        let decision = match self.address_spaces.get(&address_space_id) {
            Some(space) => space.classify_user_page_fault(fault_va, flags),
            None => return FaultPlanResult::Unhandled,
        };
        match decision {
            PageFaultDecision::CopyOnWrite => self
                .build_copy_on_write_plan(address_space_id, page_base)
                .map(FaultPlanResult::Ready)
                .unwrap_or(FaultPlanResult::Unhandled),
            PageFaultDecision::NotPresent {
                tag: PteMetaTag::LazyAnon,
            } => FaultPlanResult::Ready(FaultPlan::LazyAnon {
                key: FaultInFlightKey::LocalPage {
                    address_space_id,
                    page_base,
                },
                address_space_id,
                page_base,
            }),
            PageFaultDecision::NotPresent {
                tag: PteMetaTag::LazyVmo,
            } => self
                .build_lazy_vmo_plan(address_space_id, page_base)
                .map(FaultPlanResult::Ready)
                .unwrap_or(FaultPlanResult::Unhandled),
            _ if self.mapping_access_satisfied(
                address_space_id,
                page_base,
                flags.contains(PageFaultFlags::WRITE),
            ) =>
            {
                FaultPlanResult::Satisfied
            }
            _ => FaultPlanResult::Unhandled,
        }
    }

    fn commit_prepared_fault(
        &mut self,
        plan: FaultPlan,
        prepared: &mut PreparedFaultWork,
    ) -> Result<(FaultCommitDisposition, TlbCommitReq), zx_status_t> {
        match plan {
            FaultPlan::CopyOnWrite {
                address_space_id,
                page_base,
                old_frame_id,
                ..
            } => {
                if self.mapping_access_satisfied(address_space_id, page_base, true) {
                    self.sync_mapping_pages(
                        address_space_id,
                        page_base,
                        crate::userspace::USER_PAGE_BYTES,
                    )?;
                    return Ok((
                        FaultCommitDisposition::Resolved,
                        TlbCommitReq::relaxed(address_space_id),
                    ));
                }
                let lookup = self
                    .address_spaces
                    .get(&address_space_id)
                    .and_then(|space| space.lookup_user_mapping(page_base, 1))
                    .ok_or(ZX_ERR_BAD_STATE)?;
                if !lookup.vmo_kind().supports_copy_on_write()
                    || lookup.frame_id() != Some(old_frame_id)
                {
                    return Ok((
                        FaultCommitDisposition::Retry,
                        TlbCommitReq::relaxed(address_space_id),
                    ));
                }
                let meta = self
                    .address_spaces
                    .get(&address_space_id)
                    .and_then(|space| space.page_meta(page_base))
                    .ok_or(ZX_ERR_BAD_STATE)?;
                if !meta.cow_shared() {
                    return Ok((
                        FaultCommitDisposition::Retry,
                        TlbCommitReq::relaxed(address_space_id),
                    ));
                }
                let reserve_private = self.reserve_private_cow_page(address_space_id, page_base)?;
                let cow_result = (|| {
                    let new_frame_paddr = prepared.take_page_paddr().ok_or(ZX_ERR_BAD_STATE)?;
                    self.with_address_space_frames_mut(address_space_id, |address_space, frames| {
                        let new_frame_id = frames
                            .register_existing(new_frame_paddr)
                            .map_err(|_| ZX_ERR_BAD_STATE)?;
                        address_space
                            .resolve_cow_fault(frames, page_base, new_frame_id)
                            .map_err(map_address_space_error)
                    })
                })();
                let resolved = match cow_result {
                    Ok(resolved) => resolved,
                    Err(status) => {
                        reserve_private.release(self);
                        return Err(status);
                    }
                };
                if let Err(status) = self.sync_mapping_pages(
                    address_space_id,
                    resolved.fault_page_base(),
                    crate::userspace::USER_PAGE_BYTES,
                ) {
                    reserve_private.release(self);
                    return Err(status);
                }
                reserve_private.commit(self);
                self.cow_fault_count = self.cow_fault_count.wrapping_add(1);
                crate::userspace::record_vm_cow_fault_count(self.cow_fault_count);
                crate::userspace::record_vm_last_cow_rmap_counts(
                    self.frame_mapping_count(resolved.old_frame_id()),
                    self.frame_mapping_count(resolved.new_frame_id()),
                );
                self.validate_frame_mapping_invariants_for(
                    &[resolved.old_frame_id(), resolved.new_frame_id()],
                    "resolve_copy_on_write_page",
                );
                Ok((
                    FaultCommitDisposition::Resolved,
                    TlbCommitReq::relaxed(address_space_id),
                ))
            }
            FaultPlan::LazyAnon {
                address_space_id,
                page_base,
                ..
            } => {
                if let Some(frame_id) = self
                    .address_spaces
                    .get(&address_space_id)
                    .and_then(|space| space.lookup_user_mapping(page_base, 1))
                    .and_then(|lookup| lookup.frame_id())
                {
                    self.sync_mapping_pages(
                        address_space_id,
                        page_base,
                        crate::userspace::USER_PAGE_BYTES,
                    )?;
                    self.validate_frame_mapping_invariants(frame_id, "materialize_lazy_anon_page");
                    return Ok((
                        FaultCommitDisposition::Resolved,
                        TlbCommitReq::relaxed(address_space_id),
                    ));
                }
                let meta = self
                    .address_spaces
                    .get(&address_space_id)
                    .and_then(|space| space.page_meta(page_base))
                    .ok_or(ZX_ERR_BAD_STATE)?;
                if meta.tag() != PteMetaTag::LazyAnon {
                    return Ok((
                        FaultCommitDisposition::Retry,
                        TlbCommitReq::relaxed(address_space_id),
                    ));
                }
                let new_frame_paddr = prepared.take_page_paddr().ok_or(ZX_ERR_BAD_STATE)?;
                let resolved = self.with_address_space_frames_mut(
                    address_space_id,
                    |address_space, frames| {
                        let new_frame_id = frames
                            .register_existing(new_frame_paddr)
                            .map_err(|_| ZX_ERR_BAD_STATE)?;
                        address_space
                            .resolve_lazy_anon_fault(frames, page_base, new_frame_id)
                            .map_err(map_address_space_error)
                    },
                )?;
                self.sync_mapping_pages(
                    address_space_id,
                    resolved.fault_page_base(),
                    crate::userspace::USER_PAGE_BYTES,
                )?;
                self.validate_frame_mapping_invariants(
                    resolved.new_frame_id(),
                    "materialize_lazy_anon_page",
                );
                Ok((
                    FaultCommitDisposition::Resolved,
                    TlbCommitReq::relaxed(address_space_id),
                ))
            }
            FaultPlan::LazyVmo {
                address_space_id,
                page_base,
                global_vmo_id,
                page_offset,
                ..
            } => {
                if let Some(frame_id) = self
                    .address_spaces
                    .get(&address_space_id)
                    .and_then(|space| space.lookup_user_mapping(page_base, 1))
                    .and_then(|lookup| lookup.frame_id())
                {
                    self.sync_mapping_pages(
                        address_space_id,
                        page_base,
                        crate::userspace::USER_PAGE_BYTES,
                    )?;
                    self.validate_frame_mapping_invariants(frame_id, "materialize_lazy_vmo_page");
                    return Ok((
                        FaultCommitDisposition::Resolved,
                        TlbCommitReq::relaxed(address_space_id),
                    ));
                }
                let lookup = self
                    .address_spaces
                    .get(&address_space_id)
                    .and_then(|space| space.lookup_user_mapping(page_base, 1))
                    .ok_or(ZX_ERR_BAD_STATE)?;
                let current_page_offset = lookup
                    .vmo_offset()
                    .checked_sub(lookup.vmo_offset() % crate::userspace::USER_PAGE_BYTES)
                    .ok_or(ZX_ERR_BAD_STATE)?;
                if lookup.global_vmo_id() != global_vmo_id || current_page_offset != page_offset {
                    return Ok((
                        FaultCommitDisposition::Retry,
                        TlbCommitReq::relaxed(address_space_id),
                    ));
                }
                let meta = self
                    .address_spaces
                    .get(&address_space_id)
                    .and_then(|space| space.page_meta(page_base))
                    .ok_or(ZX_ERR_BAD_STATE)?;
                if meta.tag() != PteMetaTag::LazyVmo {
                    return Ok((
                        FaultCommitDisposition::Retry,
                        TlbCommitReq::relaxed(address_space_id),
                    ));
                }
                let frame_id =
                    self.ensure_global_vmo_frame(global_vmo_id, page_offset, prepared)?;
                let resolved = self.bind_lazy_vmo_frame(address_space_id, page_base, frame_id)?;
                self.sync_mapping_pages(
                    address_space_id,
                    page_base,
                    crate::userspace::USER_PAGE_BYTES,
                )?;
                self.validate_frame_mapping_invariants(
                    resolved.frame_id(),
                    "materialize_lazy_vmo_page",
                );
                Ok((
                    FaultCommitDisposition::Resolved,
                    TlbCommitReq::relaxed(address_space_id),
                ))
            }
        }
    }

    pub(crate) fn handle_page_fault(
        &mut self,
        address_space_id: AddressSpaceId,
        fault_va: u64,
        error: u64,
    ) -> bool {
        let mut flags = PageFaultFlags::empty();
        if error & (1 << 0) != 0 {
            flags |= PageFaultFlags::PRESENT;
        }
        if error & (1 << 1) != 0 {
            flags |= PageFaultFlags::WRITE;
        }
        if error & (1 << 2) != 0 {
            flags |= PageFaultFlags::USER;
        }

        let decision = match self.address_spaces.get(&address_space_id) {
            Some(space) => space.classify_user_page_fault(fault_va, flags),
            None => return false,
        };
        match decision {
            PageFaultDecision::CopyOnWrite => self
                .resolve_copy_on_write_page(address_space_id, fault_va)
                .is_ok(),
            PageFaultDecision::NotPresent {
                tag: PteMetaTag::LazyAnon,
            } => self
                .materialize_lazy_anon_page(address_space_id, fault_va)
                .is_ok(),
            PageFaultDecision::NotPresent {
                tag: PteMetaTag::LazyVmo,
            } => self
                .materialize_lazy_vmo_page(address_space_id, fault_va)
                .is_ok(),
            _ => false,
        }
    }

    pub(crate) fn sync_current_cpu_tlb_state(
        &mut self,
        address_space_id: AddressSpaceId,
        cpu_id: usize,
    ) -> Result<(), zx_status_t> {
        let address_space = self
            .address_spaces
            .get_mut(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        address_space.note_cpu_active(cpu_id);
        let target_epoch = address_space.current_invalidate_epoch();
        if address_space.observed_tlb_epoch(cpu_id) >= target_epoch {
            return Ok(());
        }
        if let Some(op) = address_space.pending_tlb_sync_op(target_epoch) {
            flush_tlb_sync_op_local(op);
        } else {
            crate::arch::tlb::flush_all_local();
        }
        address_space.observe_tlb_epoch(cpu_id, target_epoch);
        Ok(())
    }

    pub(crate) fn current_cpu_needs_tlb_sync(
        &self,
        address_space_id: AddressSpaceId,
        cpu_id: usize,
    ) -> Result<bool, zx_status_t> {
        let address_space = self
            .address_spaces
            .get(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        Ok(address_space.observed_tlb_epoch(cpu_id) < address_space.current_invalidate_epoch())
    }

    fn observe_cpu_tlb_epoch_for_address_space(
        &mut self,
        address_space_id: AddressSpaceId,
        cpu_id: usize,
    ) {
        let Some(address_space) = self.address_spaces.get_mut(&address_space_id) else {
            return;
        };
        address_space.note_cpu_active(cpu_id);
        let target_epoch = address_space.current_invalidate_epoch();
        address_space.observe_tlb_epoch(cpu_id, target_epoch);
    }

    fn root_page_table(
        &self,
        address_space_id: AddressSpaceId,
    ) -> Result<crate::page_table::UserPageTables, zx_status_t> {
        let address_space = self
            .address_spaces
            .get(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        Ok(address_space.root_page_table())
    }

    fn note_cpu_inactive(&mut self, address_space_id: AddressSpaceId, cpu_id: usize) {
        if let Some(address_space) = self.address_spaces.get_mut(&address_space_id) {
            address_space.note_cpu_inactive(cpu_id);
        }
    }

    fn sync_mapping_pages(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        let range = PageRange::new(base, len).map_err(map_page_table_error)?;
        let request = AddressSpaceTxRequest::new(address_space_id, range);
        let mut tx_set = self.lock_address_space_tx_set(&[request])?;
        let tx = tx_set.cursor_mut(request.key).ok_or(ZX_ERR_BAD_STATE)?;
        self.sync_mapping_pages_locked(address_space_id, base, len, tx)?;
        tx_set.commit().map_err(map_page_table_error)?;
        if let Some(address_space) = self.address_spaces.get(&address_space_id) {
            debug_assert!(address_space.validate_descriptor_metadata_range(base, len));
        }
        Ok(())
    }

    fn install_mapping_pages(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        self.sync_mapping_pages(address_space_id, base, len)
    }

    fn update_mapping_pages(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        self.sync_mapping_pages(address_space_id, base, len)
    }

    fn lock_address_space_tx_set(
        &self,
        requests: &[AddressSpaceTxRequest],
    ) -> Result<AddressSpaceTxSet, zx_status_t> {
        let mut ordered = requests.to_vec();
        ordered.sort_unstable_by_key(|request| request.key);

        let mut tx_set = AddressSpaceTxSet::default();
        let mut last_request: Option<AddressSpaceTxRequest> = None;
        for request in ordered {
            if let Some(previous) = last_request {
                if previous.key == request.key {
                    return Err(ZX_ERR_INVALID_ARGS);
                }
                if previous.key.address_space_id == request.key.address_space_id
                    && previous.range.end() > request.range.base()
                {
                    return Err(ZX_ERR_INVALID_ARGS);
                }
            }

            let mut page_table = self
                .address_spaces
                .get(&request.key.address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?
                .root_page_table();
            let cursor = TxCursor::new(
                page_table
                    .lock(request.range)
                    .map_err(map_page_table_error)?,
            );
            tx_set
                .push_active(request.key, cursor)
                .map_err(map_page_table_error)?;

            last_request = Some(request);
        }
        Ok(tx_set)
    }

    fn lock_channel_loan_tx(
        &self,
        sender_address_space_id: AddressSpaceId,
        sender_range: PageRange,
        receiver_address_space_id: AddressSpaceId,
        receiver_range: PageRange,
    ) -> Result<ChannelLoanTx, zx_status_t> {
        if sender_address_space_id == receiver_address_space_id {
            let combined_range =
                merge_page_ranges(sender_range, receiver_range).map_err(map_page_table_error)?;
            let request = AddressSpaceTxRequest::new(sender_address_space_id, combined_range);
            let tx_set = self.lock_address_space_tx_set(&[request])?;
            return Ok(ChannelLoanTx {
                tx_set,
                sender_key: request.key,
                receiver_key: request.key,
            });
        }

        let sender_request = AddressSpaceTxRequest::new(sender_address_space_id, sender_range);
        let receiver_request =
            AddressSpaceTxRequest::new(receiver_address_space_id, receiver_range);
        let tx_set = self.lock_address_space_tx_set(&[sender_request, receiver_request])?;
        Ok(ChannelLoanTx {
            tx_set,
            sender_key: sender_request.key,
            receiver_key: receiver_request.key,
        })
    }

    fn clear_mapping_pages(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        let range = PageRange::new(base, len).map_err(map_page_table_error)?;
        let request = AddressSpaceTxRequest::new(address_space_id, range);
        let mut tx_set = self.lock_address_space_tx_set(&[request])?;
        let tx = tx_set.cursor_mut(request.key).ok_or(ZX_ERR_BAD_STATE)?;
        let page_count = usize::try_from(len / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * crate::userspace::USER_PAGE_BYTES;
            if tx.query(va).map_err(map_page_table_error)?.is_some() {
                tx.unmap(va, crate::userspace::USER_PAGE_BYTES)
                    .map_err(map_page_table_error)?;
            }
        }
        tx_set.commit().map_err(map_page_table_error)?;
        if let Some(address_space) = self.address_spaces.get(&address_space_id) {
            debug_assert!(address_space.validate_descriptor_metadata_range(base, len));
        }
        Ok(())
    }

    fn sync_mapping_pages_locked(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
        tx: &mut BootstrapTxCursor,
    ) -> Result<(), zx_status_t> {
        let address_space = self
            .address_spaces
            .get(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let page_count = usize::try_from(len / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * crate::userspace::USER_PAGE_BYTES;
            let lookup = address_space
                .lookup_user_mapping(va, 1)
                .ok_or(ZX_ERR_BAD_STATE)?;
            match lookup.frame_id() {
                Some(frame_id) => {
                    let mapping = PageMapping::with_cache_policy(
                        frame_id.raw(),
                        lookup.perms().contains(MappingPerms::WRITE),
                        lookup.perms().contains(MappingPerms::EXECUTE),
                        match lookup.cache_policy() {
                            MappingCachePolicy::Cached => PtMappingCachePolicy::Cached,
                            MappingCachePolicy::DeviceMmio => PtMappingCachePolicy::DeviceMmio,
                        },
                    )
                    .map_err(map_page_table_error)?;
                    tx.map(va, crate::userspace::USER_PAGE_BYTES, |_| Ok(mapping))
                        .map_err(map_page_table_error)?;
                }
                None => {
                    if tx.query(va).map_err(map_page_table_error)?.is_some() {
                        tx.unmap(va, crate::userspace::USER_PAGE_BYTES)
                            .map_err(map_page_table_error)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn mapped_frames_in_range(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
    ) -> Result<Vec<FrameId>, zx_status_t> {
        let address_space = self
            .address_spaces
            .get(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let page_count = usize::try_from(len / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let mut frames = Vec::with_capacity(page_count);
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * crate::userspace::USER_PAGE_BYTES;
            let Some(frame_id) = address_space
                .lookup_user_mapping(va, 1)
                .and_then(|lookup| lookup.frame_id())
            else {
                continue;
            };
            push_unique_frame_id(&mut frames, frame_id);
        }
        Ok(frames)
    }

    fn resolve_copy_on_write_page(
        &mut self,
        address_space_id: AddressSpaceId,
        fault_va: u64,
    ) -> Result<(), zx_status_t> {
        let fault_page_base = align_down_page(fault_va);
        let reserve_private = self.reserve_private_cow_page(address_space_id, fault_page_base)?;
        let cow_result = (|| {
            let lookup = self
                .address_spaces
                .get(&address_space_id)
                .and_then(|space| space.lookup_user_mapping(fault_va, 1))
                .ok_or(ZX_ERR_BAD_STATE)?;
            if !lookup.vmo_kind().supports_copy_on_write() {
                return Err(ZX_ERR_BAD_STATE);
            }
            let old_frame_id = lookup.frame_id().ok_or(ZX_ERR_BAD_STATE)?;
            let new_frame_paddr = crate::userspace::alloc_bootstrap_cow_page(old_frame_id.raw())
                .ok_or(ZX_ERR_NO_MEMORY)?;
            self.with_address_space_frames_mut(address_space_id, |address_space, frames| {
                let new_frame_id = frames
                    .register_existing(new_frame_paddr)
                    .map_err(|_| ZX_ERR_BAD_STATE)?;
                address_space
                    .resolve_cow_fault(frames, fault_va, new_frame_id)
                    .map_err(map_address_space_error)
            })
        })();
        let resolved = match cow_result {
            Ok(resolved) => resolved,
            Err(status) => {
                reserve_private.release(self);
                return Err(status);
            }
        };
        if let Err(status) = self.sync_mapping_pages(
            address_space_id,
            resolved.fault_page_base(),
            crate::userspace::USER_PAGE_BYTES,
        ) {
            reserve_private.release(self);
            return Err(status);
        }
        reserve_private.commit(self);
        self.cow_fault_count = self.cow_fault_count.wrapping_add(1);
        crate::userspace::record_vm_cow_fault_count(self.cow_fault_count);
        crate::userspace::record_vm_last_cow_rmap_counts(
            self.frame_mapping_count(resolved.old_frame_id()),
            self.frame_mapping_count(resolved.new_frame_id()),
        );
        self.validate_frame_mapping_invariants_for(
            &[resolved.old_frame_id(), resolved.new_frame_id()],
            "resolve_copy_on_write_page",
        );
        Ok(())
    }

    fn materialize_lazy_anon_page(
        &mut self,
        address_space_id: AddressSpaceId,
        fault_va: u64,
    ) -> Result<(), zx_status_t> {
        if let Some(frame_id) = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.lookup_user_mapping(fault_va, 1))
            .and_then(|lookup| lookup.frame_id())
        {
            self.sync_mapping_pages(
                address_space_id,
                align_down_page(fault_va),
                crate::userspace::USER_PAGE_BYTES,
            )?;
            self.validate_frame_mapping_invariants(frame_id, "materialize_lazy_anon_page");
            return Ok(());
        }

        let new_frame_paddr =
            crate::userspace::alloc_bootstrap_zeroed_page().ok_or(ZX_ERR_NO_MEMORY)?;
        let resolved =
            self.with_address_space_frames_mut(address_space_id, |address_space, frames| {
                let new_frame_id = frames
                    .register_existing(new_frame_paddr)
                    .map_err(|_| ZX_ERR_BAD_STATE)?;
                address_space
                    .resolve_lazy_anon_fault(frames, fault_va, new_frame_id)
                    .map_err(map_address_space_error)
            })?;
        self.sync_mapping_pages(
            address_space_id,
            resolved.fault_page_base(),
            crate::userspace::USER_PAGE_BYTES,
        )?;
        self.validate_frame_mapping_invariants(
            resolved.new_frame_id(),
            "materialize_lazy_anon_page",
        );
        Ok(())
    }

    fn materialize_lazy_vmo_page(
        &mut self,
        address_space_id: AddressSpaceId,
        fault_va: u64,
    ) -> Result<(), zx_status_t> {
        let lookup = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.lookup_user_mapping(fault_va, 1))
            .ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(frame_id) = lookup.frame_id() {
            self.sync_mapping_pages(
                address_space_id,
                align_down_page(fault_va),
                crate::userspace::USER_PAGE_BYTES,
            )?;
            self.validate_frame_mapping_invariants(frame_id, "materialize_lazy_vmo_page");
            return Ok(());
        }

        let page_base = align_down_page(fault_va);
        let page_offset = lookup
            .vmo_offset()
            .checked_sub(lookup.vmo_offset() % crate::userspace::USER_PAGE_BYTES)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let mut prepared = match self.global_vmo_frame(lookup.global_vmo_id(), page_offset)? {
            Some(_) => PreparedFaultWork::None,
            None => match lookup.vmo_kind() {
                VmoKind::Anonymous => PreparedFaultWork::NewPage {
                    paddr: crate::userspace::alloc_bootstrap_zeroed_page()
                        .ok_or(ZX_ERR_NO_MEMORY)?,
                },
                VmoKind::PagerBacked => {
                    let new_frame_paddr =
                        crate::userspace::alloc_bootstrap_zeroed_page().ok_or(ZX_ERR_NO_MEMORY)?;
                    let materialized = self.global_vmos.lock().materialize_page_into(
                        lookup.global_vmo_id(),
                        page_offset,
                        new_frame_paddr,
                    );
                    match materialized {
                        Ok(true) => {}
                        Ok(false) => {
                            crate::userspace::free_bootstrap_page(new_frame_paddr);
                            return Err(ZX_ERR_BAD_STATE);
                        }
                        Err(err) => {
                            crate::userspace::free_bootstrap_page(new_frame_paddr);
                            return Err(err);
                        }
                    }
                    PreparedFaultWork::NewPage {
                        paddr: new_frame_paddr,
                    }
                }
                VmoKind::Physical | VmoKind::Contiguous => return Err(ZX_ERR_BAD_STATE),
            },
        };
        let frame_id =
            self.ensure_global_vmo_frame(lookup.global_vmo_id(), page_offset, &mut prepared)?;
        let resolved = self.bind_lazy_vmo_frame(address_space_id, page_base, frame_id)?;
        prepared.release_unused();
        self.sync_mapping_pages(
            address_space_id,
            page_base,
            crate::userspace::USER_PAGE_BYTES,
        )?;
        self.validate_frame_mapping_invariants(resolved.frame_id(), "materialize_lazy_vmo_page");
        Ok(())
    }

    fn build_required_frame_retire_plan(
        &self,
        frame_ids: &[FrameId],
        transition_barriers: &[AddressSpaceId],
    ) -> Result<FrameRetirePlan, zx_status_t> {
        self.build_required_frame_retire_plan_after_ref_release(frame_ids, transition_barriers, 0)
    }

    fn build_required_frame_retire_plan_after_ref_release(
        &self,
        frame_ids: &[FrameId],
        transition_barriers: &[AddressSpaceId],
        released_ref_count: u32,
    ) -> Result<FrameRetirePlan, zx_status_t> {
        let mut retired_frames = Vec::new();
        let mut unique = Vec::with_capacity(frame_ids.len());
        for &frame_id in frame_ids {
            push_unique_frame_id(&mut unique, frame_id);
        }
        for frame_id in unique {
            let state = self
                .with_frames(|frames| frames.state(frame_id))
                .ok_or(ZX_ERR_BAD_STATE)?;
            let mappings = self.frame_mappings(frame_id);
            let remaining_refs = state
                .ref_count()
                .checked_sub(released_ref_count)
                .ok_or(ZX_ERR_BAD_STATE)?;
            if remaining_refs != 0
                || state.map_count() != 0
                || state.pin_count() != 0
                || state.loan_count() != 0
                || state.rmap_anchor_count() != 0
                || !mappings.is_empty()
            {
                return Err(ZX_ERR_BAD_STATE);
            }
            retired_frames.push(RetiredFrame::bootstrap_page(frame_id));
        }
        Ok(FrameRetirePlan::new(retired_frames, transition_barriers))
    }

    fn build_optional_frame_retire_plan(
        &self,
        frame_ids: &[FrameId],
        transition_barriers: &[AddressSpaceId],
    ) -> FrameRetirePlan {
        let mut retired_frames = Vec::new();
        let mut unique = Vec::with_capacity(frame_ids.len());
        for &frame_id in frame_ids {
            push_unique_frame_id(&mut unique, frame_id);
        }
        for frame_id in unique {
            let Some(state) = self.with_frames(|frames| frames.state(frame_id)) else {
                continue;
            };
            let mappings = self.frame_mappings(frame_id);
            if state.ref_count() == 0
                && state.map_count() == 0
                && state.pin_count() == 0
                && state.loan_count() == 0
                && state.rmap_anchor_count() == 0
                && mappings.is_empty()
            {
                retired_frames.push(RetiredFrame::bootstrap_page(frame_id));
            }
        }
        FrameRetirePlan::new(retired_frames, transition_barriers)
    }

    fn execute_frame_retire_plan_now(&mut self, plan: &FrameRetirePlan) -> Result<(), zx_status_t> {
        if !plan.barrier_address_spaces().is_empty() {
            return Err(ZX_ERR_BAD_STATE);
        }
        for retired in plan.retired_frames() {
            self.with_frames_mut(|frames| {
                frames
                    .unregister_existing(retired.frame_id())
                    .map_err(|_| ZX_ERR_BAD_STATE)
            })?;
        }
        for retired in plan.retired_frames() {
            crate::userspace::free_bootstrap_page(retired.frame_id().raw());
        }
        Ok(())
    }

    fn frame_mappings(&self, frame_id: FrameId) -> Vec<FrameMappingSnapshot> {
        let Some(anchors) = self.with_frames(|frames| frames.rmap_anchors(frame_id)) else {
            return Vec::new();
        };
        let mut mappings = Vec::with_capacity(anchors.len());
        for anchor in anchors {
            let Some(address_space) = self.address_spaces.get(&anchor.address_space_id().raw())
            else {
                continue;
            };
            let Some(page_base) = address_space.page_base_for_rmap_anchor(anchor) else {
                continue;
            };
            let Some(lookup) = address_space.lookup_rmap_anchor(anchor) else {
                continue;
            };
            let Some(map_rec) = address_space
                .map_record_for_va(page_base)
                .or_else(|| address_space.map_record(lookup.map_id()))
            else {
                continue;
            };
            if lookup.frame_id() == Some(frame_id) {
                mappings.push(FrameMappingSnapshot {
                    anchor,
                    page_base,
                    map_rec,
                    lookup,
                });
            }
        }
        mappings
    }

    fn frame_mapping_count(&self, frame_id: FrameId) -> u64 {
        u64::try_from(self.frame_mappings(frame_id).len()).unwrap_or(u64::MAX)
    }

    fn validate_frame_mapping_invariants(&self, frame_id: FrameId, context: &str) {
        if !VM_FRAME_DIAGNOSTICS_ENABLED {
            return;
        }
        let Some(state) = self.with_frames(|frames| frames.state(frame_id)) else {
            return;
        };
        let mappings = self.frame_mappings(frame_id);
        let resolved_count = mappings.len() as u32;
        if state.map_count() == resolved_count && state.rmap_anchor_count() == resolved_count {
            return;
        }

        crate::kprintln!(
            "kernel: frame mapping invariant mismatch (context={}, frame={:#x}, map_count={}, anchor_count={}, resolved_count={}, loan_count={}, pin_count={})",
            context,
            frame_id.raw(),
            state.map_count(),
            state.rmap_anchor_count(),
            resolved_count,
            state.loan_count(),
            state.pin_count(),
        );
        for mapping in &mappings {
            crate::kprintln!(
                "kernel:   mapping aspace={} vmar={} map={} va={:#x} map_base={:#x} map_len={:#x} vmo_offset={:#x} perms={:?} cow={} anchor_page={} anchor_map={}",
                mapping.lookup.address_space_id().raw(),
                mapping.map_rec.vmar_id().raw(),
                mapping.map_rec.id().raw(),
                mapping.page_base,
                mapping.map_rec.base(),
                mapping.map_rec.len(),
                mapping.lookup.vmo_offset(),
                mapping.lookup.perms(),
                mapping.lookup.is_copy_on_write(),
                mapping.anchor.page_delta(),
                mapping.anchor.map_id().raw(),
            );
            debug_assert_eq!(mapping.lookup.vmar_id(), mapping.map_rec.vmar_id());
            debug_assert_eq!(mapping.lookup.map_id(), mapping.map_rec.id());
            debug_assert_eq!(mapping.lookup.mapping_base(), mapping.map_rec.base());
            debug_assert_eq!(mapping.lookup.mapping_len(), mapping.map_rec.len());
        }
        debug_assert_eq!(state.map_count(), resolved_count);
        debug_assert_eq!(state.rmap_anchor_count(), resolved_count);
    }

    fn validate_frame_mapping_invariants_for(&self, frame_ids: &[FrameId], context: &str) {
        if !VM_FRAME_DIAGNOSTICS_ENABLED {
            return;
        }
        let mut unique = Vec::with_capacity(frame_ids.len());
        for &frame_id in frame_ids {
            push_unique_frame_id(&mut unique, frame_id);
        }
        for frame_id in unique {
            self.validate_frame_mapping_invariants(frame_id, context);
        }
    }

    fn release_loaned_pages_inner(
        &mut self,
        address_space_id: AddressSpaceId,
        budget_pages: u64,
        loan: LoanToken,
    ) {
        let frame_ids = loan.frame_ids().to_vec();
        self.with_frames_mut(|frames| loan.release(frames));
        self.release_inflight_loan_pages(address_space_id, budget_pages);
        self.validate_frame_mapping_invariants_for(&frame_ids, "release_loaned_pages_inner");
        let retire_plan = self.build_optional_frame_retire_plan(&frame_ids, &[]);
        debug_assert!(retire_plan.barrier_address_spaces().is_empty());
        let _ = self.execute_frame_retire_plan_now(&retire_plan);
    }
}

fn push_unique_frame_id(frames: &mut Vec<FrameId>, frame_id: FrameId) {
    if !frames.contains(&frame_id) {
        frames.push(frame_id);
    }
}

fn push_unique_address_space_id(
    address_space_ids: &mut Vec<AddressSpaceId>,
    address_space_id: AddressSpaceId,
) {
    if !address_space_ids.contains(&address_space_id) {
        address_space_ids.push(address_space_id);
    }
}

fn merge_page_ranges(left: PageRange, right: PageRange) -> Result<PageRange, PageTableError> {
    let base = left.base().min(right.base());
    let end = left.end().max(right.end());
    let len = end.checked_sub(base).ok_or(PageTableError::InvalidArgs)?;
    PageRange::new(base, len)
}

fn ranges_touch_or_overlap(left: PageRange, right: PageRange) -> bool {
    left.base() <= right.end() && right.base() <= left.end()
}

fn insert_merged_page_range(
    ranges: &mut Vec<PageRange>,
    range: PageRange,
) -> Result<(), PageTableError> {
    let mut merged = range;
    let mut index = 0;
    while index < ranges.len() {
        if ranges_touch_or_overlap(ranges[index], merged) {
            merged = merge_page_ranges(ranges[index], merged)?;
            ranges.remove(index);
            continue;
        }
        if ranges[index].base() > merged.end() {
            break;
        }
        index += 1;
    }
    ranges.insert(index, merged);
    Ok(())
}

fn map_alloc_error(err: CSpaceError) -> zx_status_t {
    match err {
        CSpaceError::NoSlots => ZX_ERR_NO_RESOURCES,
        CSpaceError::Handle(_) => ZX_ERR_INTERNAL,
        CSpaceError::BadHandle => ZX_ERR_BAD_HANDLE,
        CSpaceError::AccessDenied => ZX_ERR_ACCESS_DENIED,
    }
}

fn map_lookup_error(_err: CSpaceError) -> zx_status_t {
    ZX_ERR_BAD_HANDLE
}

fn map_address_space_error(err: AddressSpaceError) -> zx_status_t {
    match err {
        AddressSpaceError::InvalidArgs => ZX_ERR_INVALID_ARGS,
        AddressSpaceError::OutOfRange => ZX_ERR_OUT_OF_RANGE,
        AddressSpaceError::InvalidVmo | AddressSpaceError::InvalidVmar => ZX_ERR_NOT_FOUND,
        AddressSpaceError::InvalidFrame => ZX_ERR_BAD_STATE,
        AddressSpaceError::AlreadyBound | AddressSpaceError::Overlap => ZX_ERR_ALREADY_EXISTS,
        AddressSpaceError::NotFound => ZX_ERR_NOT_FOUND,
        AddressSpaceError::Busy => ZX_ERR_BAD_STATE,
        AddressSpaceError::PermissionIncrease => ZX_ERR_ACCESS_DENIED,
        AddressSpaceError::FrameTable(_) => ZX_ERR_NO_MEMORY,
        AddressSpaceError::NotCopyOnWrite => ZX_ERR_BAD_STATE,
    }
}

fn map_frame_table_error(err: axle_mm::FrameTableError) -> zx_status_t {
    match err {
        axle_mm::FrameTableError::InvalidArgs => ZX_ERR_INVALID_ARGS,
        axle_mm::FrameTableError::AlreadyExists => ZX_ERR_ALREADY_EXISTS,
        axle_mm::FrameTableError::NotFound
        | axle_mm::FrameTableError::CountOverflow
        | axle_mm::FrameTableError::RefUnderflow
        | axle_mm::FrameTableError::PinUnderflow
        | axle_mm::FrameTableError::LoanUnderflow
        | axle_mm::FrameTableError::MissingAnchor
        | axle_mm::FrameTableError::Busy => ZX_ERR_BAD_STATE,
    }
}

fn map_page_table_error(err: PageTableError) -> zx_status_t {
    match err {
        PageTableError::InvalidArgs => ZX_ERR_INVALID_ARGS,
        PageTableError::NotMapped | PageTableError::Backend => ZX_ERR_BAD_STATE,
    }
}

fn mapping_satisfies_required_perms(lookup: VmaLookup, required: MappingPerms) -> bool {
    if required.contains(MappingPerms::READ) && !lookup.perms().contains(MappingPerms::READ) {
        return false;
    }
    if required.contains(MappingPerms::USER) && !lookup.perms().contains(MappingPerms::USER) {
        return false;
    }
    if required.contains(MappingPerms::EXECUTE) && !lookup.perms().contains(MappingPerms::EXECUTE) {
        return false;
    }
    if required.contains(MappingPerms::WRITE)
        && !(lookup.perms().contains(MappingPerms::WRITE)
            || (lookup.is_copy_on_write() && lookup.max_perms().contains(MappingPerms::WRITE)))
    {
        return false;
    }
    true
}

fn align_down_page(value: u64) -> u64 {
    value & !(crate::userspace::USER_PAGE_BYTES - 1)
}
