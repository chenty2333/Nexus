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

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;

use axle_core::handle::Handle;
use axle_core::{CSpace, CSpaceError, Capability, RevocationManager, Signals, TransferredCap};
use axle_mm::{
    AddressSpace as VmAddressSpace, AddressSpaceError, AddressSpaceId as VmAddressSpaceId,
    CowFaultResolution, FrameId, FrameTable, FutexKey, GlobalVmoId, LazyAnonFaultResolution,
    LazyVmoFaultResolution, MapRec, MappingPerms, PageFaultDecision, PageFaultFlags, PteMeta,
    PteMetaTag, ReverseMapAnchor, VmaLookup, Vmar, VmarAllocMode, VmarId, VmarPlacementPolicy, Vmo,
    VmoId, VmoKind,
};
use axle_page_table::{PageMapping, PageRange, PageTable, PageTableError, TxCursor, TxSet};
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
    ZX_ERR_OUT_OF_RANGE, ZX_ERR_SHOULD_WAIT, ZX_OK,
};
use axle_types::{
    zx_handle_t, zx_koid_t, zx_port_packet_t, zx_rights_t, zx_signals_t, zx_status_t,
};
use bitflags::bitflags;
use core::mem::size_of;
use spin::Mutex;

const CSPACE_MAX_SLOTS: u16 = 16_384;
const CSPACE_QUARANTINE_LEN: usize = 256;
const MAX_TRACKED_TLB_CPUS: usize = 64;
const DEFAULT_MAX_INFLIGHT_LOAN_PAGES: Option<u64> = Some(32);
const DEFAULT_MAX_PRIVATE_COW_PAGES: Option<u64> = None;
const FAULT_WAIT_SPIN_LOOPS: usize = 256;
const VM_FRAME_DIAGNOSTICS_ENABLED: bool =
    cfg!(debug_assertions) || cfg!(feature = "vm-diagnostics");

type ProcessId = u64;
type ThreadId = u64;
type AddressSpaceId = u64;
type KernelVmoId = GlobalVmoId;

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
    stats: VmResourceStats,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FaultInFlightKey {
    LocalPage {
        address_space_id: AddressSpaceId,
        page_base: u64,
    },
    SharedVmoPage {
        global_vmo_id: KernelVmoId,
        page_offset: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultEntry {
    in_flight: bool,
    completed_epoch: u64,
    spin_waiters: u32,
    blocked_waiters: BTreeSet<ThreadId>,
    leader_thread: Option<ThreadId>,
    leader_paused_for_test: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FaultWaitToken {
    key: FaultInFlightKey,
    observed_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultClaim {
    Leader,
    Wait(FaultWaitToken),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultBlockingClaim {
    Leader,
    LeaderResume,
    Wait { wake_leader: Option<ThreadId> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultPrepareKind {
    CopyOnWrite,
    LazyAnon,
    LazyVmoAlloc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrapExitDisposition {
    Complete,
    BlockCurrent,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FaultTelemetry {
    leader_claims: u64,
    wait_claims: u64,
    wait_spin_loops: u64,
    retry_total: u64,
    commit_resolved: u64,
    commit_retry: u64,
    prepare_cow: u64,
    prepare_lazy_anon: u64,
    prepare_lazy_vmo_alloc: u64,
}

#[derive(Debug, Default)]
pub(crate) struct FaultTable {
    entries: BTreeMap<FaultInFlightKey, FaultEntry>,
    telemetry: FaultTelemetry,
}

impl FaultTable {
    fn claim(&mut self, key: FaultInFlightKey) -> FaultClaim {
        match self.entries.get_mut(&key) {
            Some(entry) if entry.in_flight => {
                self.telemetry.wait_claims = self.telemetry.wait_claims.wrapping_add(1);
                entry.spin_waiters = entry.spin_waiters.saturating_add(1);
                FaultClaim::Wait(FaultWaitToken {
                    key,
                    observed_epoch: entry.completed_epoch,
                })
            }
            Some(entry) => {
                self.telemetry.leader_claims = self.telemetry.leader_claims.wrapping_add(1);
                entry.in_flight = true;
                FaultClaim::Leader
            }
            None => {
                self.telemetry.leader_claims = self.telemetry.leader_claims.wrapping_add(1);
                self.entries.insert(
                    key,
                    FaultEntry {
                        in_flight: true,
                        completed_epoch: 0,
                        spin_waiters: 0,
                        blocked_waiters: BTreeSet::new(),
                        leader_thread: None,
                        leader_paused_for_test: false,
                    },
                );
                FaultClaim::Leader
            }
        }
    }

    fn claim_blocking(&mut self, key: FaultInFlightKey, thread_id: ThreadId) -> FaultBlockingClaim {
        match self.entries.get_mut(&key) {
            Some(entry) if entry.in_flight && entry.leader_thread == Some(thread_id) => {
                FaultBlockingClaim::LeaderResume
            }
            Some(entry) if entry.in_flight => {
                self.telemetry.wait_claims = self.telemetry.wait_claims.wrapping_add(1);
                let _ = entry.blocked_waiters.insert(thread_id);
                let wake_leader = if entry.leader_paused_for_test {
                    entry.leader_paused_for_test = false;
                    entry.leader_thread
                } else {
                    None
                };
                FaultBlockingClaim::Wait { wake_leader }
            }
            Some(entry) => {
                self.telemetry.leader_claims = self.telemetry.leader_claims.wrapping_add(1);
                entry.in_flight = true;
                entry.leader_thread = Some(thread_id);
                entry.leader_paused_for_test = false;
                FaultBlockingClaim::Leader
            }
            None => {
                self.telemetry.leader_claims = self.telemetry.leader_claims.wrapping_add(1);
                self.entries.insert(
                    key,
                    FaultEntry {
                        in_flight: true,
                        completed_epoch: 0,
                        spin_waiters: 0,
                        blocked_waiters: BTreeSet::new(),
                        leader_thread: Some(thread_id),
                        leader_paused_for_test: false,
                    },
                );
                FaultBlockingClaim::Leader
            }
        }
    }

    fn complete(&mut self, key: FaultInFlightKey) -> Vec<ThreadId> {
        let Some(entry) = self.entries.get_mut(&key) else {
            return Vec::new();
        };
        entry.in_flight = false;
        entry.completed_epoch = entry.completed_epoch.wrapping_add(1);
        let blocked_waiters = entry.blocked_waiters.iter().copied().collect::<Vec<_>>();
        entry.blocked_waiters.clear();
        entry.leader_thread = None;
        entry.leader_paused_for_test = false;
        if entry.spin_waiters == 0 && entry.blocked_waiters.is_empty() {
            let _ = self.entries.remove(&key);
        }
        blocked_waiters
    }

    fn pause_leader_for_test(&mut self, key: FaultInFlightKey, thread_id: ThreadId) {
        if let Some(entry) = self.entries.get_mut(&key) {
            if entry.in_flight && entry.leader_thread == Some(thread_id) {
                entry.leader_paused_for_test = true;
            }
        }
    }

    fn observe_completion(&self, wait: FaultWaitToken) -> bool {
        match self.entries.get(&wait.key) {
            None => true,
            Some(entry) => !entry.in_flight && entry.completed_epoch != wait.observed_epoch,
        }
    }

    fn release_waiter(&mut self, wait: FaultWaitToken) {
        let Some(entry) = self.entries.get_mut(&wait.key) else {
            return;
        };
        if entry.spin_waiters > 0 {
            entry.spin_waiters -= 1;
        }
        if !entry.in_flight && entry.spin_waiters == 0 && entry.blocked_waiters.is_empty() {
            let _ = self.entries.remove(&wait.key);
        }
    }

    fn remove_blocked_waiter(&mut self, key: FaultInFlightKey, thread_id: ThreadId) {
        let Some(entry) = self.entries.get_mut(&key) else {
            return;
        };
        let _ = entry.blocked_waiters.remove(&thread_id);
        if !entry.in_flight && entry.spin_waiters == 0 && entry.blocked_waiters.is_empty() {
            let _ = self.entries.remove(&key);
        }
    }

    fn record_wait_spin_loops(&mut self, loops: u64) {
        self.telemetry.wait_spin_loops = self.telemetry.wait_spin_loops.wrapping_add(loops);
    }

    fn record_prepare(&mut self, kind: FaultPrepareKind) {
        match kind {
            FaultPrepareKind::CopyOnWrite => {
                self.telemetry.prepare_cow = self.telemetry.prepare_cow.wrapping_add(1)
            }
            FaultPrepareKind::LazyAnon => {
                self.telemetry.prepare_lazy_anon = self.telemetry.prepare_lazy_anon.wrapping_add(1)
            }
            FaultPrepareKind::LazyVmoAlloc => {
                self.telemetry.prepare_lazy_vmo_alloc =
                    self.telemetry.prepare_lazy_vmo_alloc.wrapping_add(1)
            }
        }
    }

    fn record_commit_resolved(&mut self) {
        self.telemetry.commit_resolved = self.telemetry.commit_resolved.wrapping_add(1);
    }

    fn record_commit_retry(&mut self) {
        self.telemetry.retry_total = self.telemetry.retry_total.wrapping_add(1);
        self.telemetry.commit_retry = self.telemetry.commit_retry.wrapping_add(1);
    }

    fn telemetry(&self) -> FaultTelemetry {
        self.telemetry
    }
}

#[derive(Debug)]
struct FaultLeaderGuard {
    table: Arc<Mutex<FaultTable>>,
    key: FaultInFlightKey,
    active: bool,
}

impl FaultLeaderGuard {
    fn new(table: Arc<Mutex<FaultTable>>, key: FaultInFlightKey) -> Self {
        Self {
            table,
            key,
            active: true,
        }
    }

    fn complete(mut self) -> Vec<ThreadId> {
        if self.active {
            let waiters = complete_fault(&self.table, self.key);
            self.active = false;
            return waiters;
        }
        Vec::new()
    }
}

impl Drop for FaultLeaderGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut table = self.table.lock();
        let _ = table.complete(self.key);
        self.active = false;
    }
}

impl VmResourceState {
    fn new() -> Self {
        Self {
            limits: VmResourceLimits {
                max_private_cow_pages: DEFAULT_MAX_PRIVATE_COW_PAGES,
                max_inflight_loan_pages: DEFAULT_MAX_INFLIGHT_LOAN_PAGES,
            },
            private_cow_pages: BTreeSet::new(),
            stats: VmResourceStats::default(),
        }
    }

    fn stats(&self) -> VmResourceStats {
        self.stats
    }

    fn try_reserve_private_cow_page(&mut self, page_base: u64) -> Result<bool, VmQuotaExceeded> {
        if self.private_cow_pages.contains(&page_base) {
            return Ok(false);
        }
        if let Some(limit) = self.limits.max_private_cow_pages
            && self.stats.current_private_cow_pages >= limit
        {
            self.stats.private_cow_quota_hits = self.stats.private_cow_quota_hits.wrapping_add(1);
            return Err(VmQuotaExceeded::PrivateCowPages {
                limit,
                current: self.stats.current_private_cow_pages,
            });
        }
        Ok(true)
    }

    fn commit_private_cow_page(&mut self, page_base: u64) -> bool {
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

    fn clear_private_cow_range(&mut self, base: u64, len: u64) -> u64 {
        let Some(end) = base.checked_add(len) else {
            return 0;
        };
        let removed: Vec<u64> = self.private_cow_pages.range(base..end).copied().collect();
        let removed_count = removed.len() as u64;
        for page_base in removed {
            let _ = self.private_cow_pages.remove(&page_base);
        }
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
    slot_index: u16,
    slot_tag: u16,
    object_id: u64,
    rights: HandleRights,
    object_generation: u32,
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

/// Kernel-visible description of the bootstrap current thread.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CurrentThreadInfo {
    process_id: ProcessId,
    thread_id: ThreadId,
    koid: zx_koid_t,
}

/// Kernel-visible description of the bootstrap current process.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CurrentProcessInfo {
    process_id: ProcessId,
}

impl CurrentProcessInfo {
    pub(crate) const fn process_id(self) -> ProcessId {
        self.process_id
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UserContext {
    trap: crate::arch::int80::TrapFrame,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

impl UserContext {
    fn capture(
        trap: &crate::arch::int80::TrapFrame,
        cpu_frame: *const u64,
    ) -> Result<Self, zx_status_t> {
        if cpu_frame.is_null() {
            return Err(ZX_ERR_BAD_STATE);
        }
        // SAFETY: `cpu_frame` points to the saved user IRET frame created by the CPU on a
        // ring3->ring0 transition. The int80 entry path always provides RIP/CS/RFLAGS/RSP/SS.
        let (rip, cs, rflags, rsp, ss) = unsafe {
            (
                *cpu_frame.add(0),
                *cpu_frame.add(1),
                *cpu_frame.add(2),
                *cpu_frame.add(3),
                *cpu_frame.add(4),
            )
        };
        Ok(Self {
            trap: *trap,
            rip,
            cs,
            rflags,
            rsp,
            ss,
        })
    }

    fn restore(
        self,
        trap: &mut crate::arch::int80::TrapFrame,
        cpu_frame: *mut u64,
    ) -> Result<(), zx_status_t> {
        if cpu_frame.is_null() {
            return Err(ZX_ERR_BAD_STATE);
        }
        *trap = self.trap;
        // SAFETY: `cpu_frame` points to the mutable IRET frame for the in-flight trap return.
        unsafe {
            *cpu_frame.add(0) = self.rip;
            *cpu_frame.add(1) = self.cs;
            *cpu_frame.add(2) = self.rflags;
            *cpu_frame.add(3) = self.rsp;
            *cpu_frame.add(4) = self.ss;
        }
        Ok(())
    }

    fn with_status(mut self, status: zx_status_t) -> Self {
        self.trap.set_status(status);
        self
    }

    fn new_user_entry(entry: u64, stack: u64, arg0: u64, arg1: u64) -> Self {
        let selectors = crate::arch::gdt::init();
        let mut trap = crate::arch::int80::TrapFrame::default();
        trap.rdi = arg0;
        trap.rsi = arg1;
        Self {
            trap,
            rip: entry,
            cs: selectors.user_code.0 as u64,
            rflags: 0x002,
            rsp: stack,
            ss: selectors.user_data.0 as u64,
        }
    }
}

impl CurrentThreadInfo {
    pub(crate) const fn process_id(self) -> ProcessId {
        self.process_id
    }

    pub(crate) const fn thread_id(self) -> ThreadId {
        self.thread_id
    }

    pub(crate) const fn koid(self) -> zx_koid_t {
        self.koid
    }
}

/// Kernel-visible description of one current-process VMO.
#[derive(Clone, Debug)]
pub(crate) struct CreatedVmo {
    process_id: ProcessId,
    address_space_id: AddressSpaceId,
    vmo: Vmo,
}

impl CreatedVmo {
    pub(crate) fn process_id(&self) -> ProcessId {
        self.process_id
    }

    pub(crate) fn address_space_id(&self) -> AddressSpaceId {
        self.address_space_id
    }

    pub(crate) fn vmo_id(&self) -> VmoId {
        self.vmo.id()
    }

    pub(crate) fn global_vmo_id(&self) -> KernelVmoId {
        self.vmo.global_id()
    }

    pub(crate) fn size_bytes(&self) -> u64 {
        self.vmo.size_bytes()
    }
}

#[derive(Clone, Debug)]
struct GlobalVmo {
    kind: VmoKind,
    size_bytes: u64,
    frames: Vec<Option<FrameId>>,
}

#[derive(Debug, Default)]
struct GlobalVmoStore {
    entries: BTreeMap<KernelVmoId, GlobalVmo>,
}

impl GlobalVmoStore {
    fn register_snapshot(&mut self, global_vmo_id: KernelVmoId, snapshot: &Vmo) {
        self.entries.insert(
            global_vmo_id,
            GlobalVmo {
                kind: snapshot.kind(),
                size_bytes: snapshot.size_bytes(),
                frames: snapshot.frames().to_vec(),
            },
        );
    }

    fn register_empty(
        &mut self,
        global_vmo_id: KernelVmoId,
        kind: VmoKind,
        size_bytes: u64,
    ) -> Result<(), zx_status_t> {
        if self.entries.contains_key(&global_vmo_id) {
            return Err(ZX_ERR_ALREADY_EXISTS);
        }
        let page_count = usize::try_from(size_bytes / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        self.entries.insert(
            global_vmo_id,
            GlobalVmo {
                kind,
                size_bytes,
                frames: alloc::vec![None; page_count],
            },
        );
        Ok(())
    }

    fn remove(&mut self, global_vmo_id: KernelVmoId) -> Option<GlobalVmo> {
        self.entries.remove(&global_vmo_id)
    }

    fn snapshot(&self, global_vmo_id: KernelVmoId) -> Result<GlobalVmo, zx_status_t> {
        self.entries
            .get(&global_vmo_id)
            .cloned()
            .ok_or(ZX_ERR_BAD_HANDLE)
    }

    fn frame(
        &self,
        global_vmo_id: KernelVmoId,
        offset: u64,
    ) -> Result<Option<FrameId>, zx_status_t> {
        let global_vmo = self.entries.get(&global_vmo_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        if offset & (crate::userspace::USER_PAGE_BYTES - 1) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let page_index = usize::try_from(offset / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        Ok(global_vmo.frames.get(page_index).copied().flatten())
    }

    fn update_frame(
        &mut self,
        global_vmo_id: KernelVmoId,
        offset: u64,
        frame_id: FrameId,
    ) -> Result<(), zx_status_t> {
        let global_vmo = self
            .entries
            .get_mut(&global_vmo_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?;
        if offset & (crate::userspace::USER_PAGE_BYTES - 1) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let page_index = usize::try_from(offset / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let slot = global_vmo
            .frames
            .get_mut(page_index)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        *slot = Some(frame_id);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CreatedProcess {
    process_id: ProcessId,
    koid: zx_koid_t,
    address_space_id: AddressSpaceId,
    root_vmar: Vmar,
}

impl CreatedProcess {
    pub(crate) const fn process_id(self) -> ProcessId {
        self.process_id
    }

    pub(crate) const fn koid(self) -> zx_koid_t {
        self.koid
    }

    pub(crate) const fn address_space_id(self) -> AddressSpaceId {
        self.address_space_id
    }

    pub(crate) const fn root_vmar(self) -> Vmar {
        self.root_vmar
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ThreadState {
    New,
    Runnable,
    Suspended,
    TerminationPending,
    Terminated,
    FutexWait {
        key: FutexKey,
    },
    SignalWait {
        object_id: u64,
        watched: Signals,
        observed_ptr: u64,
    },
    PortWait {
        port_object_id: u64,
        packet_ptr: u64,
    },
    VmFaultWait {
        key: FaultInFlightKey,
    },
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SignalWaiter {
    thread_id: ThreadId,
    observed_ptr: u64,
}

impl SignalWaiter {
    pub(crate) const fn thread_id(self) -> ThreadId {
        self.thread_id
    }

    pub(crate) const fn observed_ptr(self) -> *mut zx_signals_t {
        self.observed_ptr as *mut zx_signals_t
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PortWaiter {
    thread_id: ThreadId,
    packet_ptr: u64,
}

impl PortWaiter {
    pub(crate) const fn thread_id(self) -> ThreadId {
        self.thread_id
    }

    pub(crate) const fn packet_ptr(self) -> *mut zx_port_packet_t {
        self.packet_ptr as *mut zx_port_packet_t
    }
}

/// Pinned page run loaned from the current process into a kernel object.
#[derive(Clone, Debug)]
pub(crate) struct LoanedUserPages {
    address_space_id: AddressSpaceId,
    receiver_address_space_id: Option<AddressSpaceId>,
    base: u64,
    len: u32,
    needs_cow: bool,
    pages: Vec<FrameId>,
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
        &self.pages
    }

    fn bind_receiver_address_space(&mut self, address_space_id: AddressSpaceId) {
        self.receiver_address_space_id = Some(address_space_id);
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
            object_id: cap.object_id(),
            rights: HandleRights::from_bits_retain(cap.rights()),
            object_generation: cap.generation(),
        })
    }

    /// Owning process id.
    pub(crate) const fn process_id(self) -> u64 {
        self.process_id
    }

    /// CSpace slot index encoded in the handle.
    pub(crate) const fn slot_index(self) -> u16 {
        self.slot_index
    }

    /// CSpace slot ABA tag encoded in the handle.
    pub(crate) const fn slot_tag(self) -> u16 {
        self.slot_tag
    }

    /// Target object id from the resolved capability.
    pub(crate) const fn object_id(self) -> u64 {
        self.object_id
    }

    /// Rights bits carried by the resolved capability.
    pub(crate) const fn rights(self) -> HandleRights {
        self.rights
    }

    /// Capability generation carried by the resolved capability.
    pub(crate) const fn object_generation(self) -> u32 {
        self.object_generation
    }
}

#[derive(Debug)]
struct AddressSpace {
    vm: VmAddressSpace,
    page_tables: crate::page_table::UserPageTables,
    active_cpu_mask: u64,
    observed_tlb_epoch: [u64; MAX_TRACKED_TLB_CPUS],
    vm_resources: VmResourceState,
}

impl AddressSpace {
    fn bootstrap(
        address_space_id: AddressSpaceId,
        frames: &mut FrameTable,
        vmo_ids: [KernelVmoId; 3],
    ) -> Self {
        let mut vm = VmAddressSpace::new_with_id(
            VmAddressSpaceId::new(address_space_id),
            crate::userspace::USER_CODE_VA,
            crate::userspace::USER_REGION_BYTES,
        )
        .expect("bootstrap address-space root must be valid");
        let page_tables = crate::page_table::UserPageTables::bootstrap_current()
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
        vm.map_fixed(
            frames,
            crate::userspace::USER_CODE_VA,
            crate::userspace::USER_CODE_BYTES,
            code_vmo,
            0,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::EXECUTE | MappingPerms::USER,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::EXECUTE | MappingPerms::USER,
        )
        .expect("bootstrap code mapping must succeed");

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
                crate::userspace::USER_PAGE_BYTES,
                vmo_ids[2],
            )
            .expect("bootstrap stack vmo allocation must succeed");
        let stack_frame = frames
            .register_existing(crate::userspace::user_stack_page_paddr())
            .expect("bootstrap stack frame registration must succeed");
        vm.bind_vmo_frame(stack_vmo, 0, stack_frame)
            .expect("bootstrap stack frame binding must succeed");
        vm.map_fixed(
            frames,
            crate::userspace::USER_STACK_VA,
            crate::userspace::USER_PAGE_BYTES,
            stack_vmo,
            0,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
        )
        .expect("bootstrap stack mapping must succeed");
        vm.mark_copy_on_write(
            crate::userspace::USER_STACK_VA,
            crate::userspace::USER_PAGE_BYTES,
        )
        .expect("bootstrap stack COW arm must succeed");
        debug_assert!(page_tables.validate_descriptor_metadata_range(
            crate::userspace::USER_CODE_VA,
            crate::userspace::USER_CODE_BYTES,
        ));

        Self {
            vm,
            page_tables,
            active_cpu_mask: 0,
            observed_tlb_epoch: [0; MAX_TRACKED_TLB_CPUS],
            vm_resources: VmResourceState::new(),
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
        self.page_tables.max_invalidate_epoch()
    }

    fn validate_descriptor_metadata_range(&self, base: u64, len: u64) -> bool {
        self.page_tables
            .validate_descriptor_metadata_range(base, len)
    }

    fn note_cpu_active(&mut self, cpu_id: usize) {
        if cpu_id < u64::BITS as usize {
            self.active_cpu_mask |= 1_u64 << cpu_id;
        }
    }

    fn note_cpu_inactive(&mut self, cpu_id: usize) {
        if cpu_id < u64::BITS as usize {
            self.active_cpu_mask &= !(1_u64 << cpu_id);
        }
    }

    #[allow(dead_code)]
    fn is_cpu_active(&self, cpu_id: usize) -> bool {
        cpu_id < u64::BITS as usize && (self.active_cpu_mask & (1_u64 << cpu_id)) != 0
    }

    fn observe_tlb_epoch(&mut self, cpu_id: usize, epoch: u64) {
        if cpu_id < MAX_TRACKED_TLB_CPUS {
            self.observed_tlb_epoch[cpu_id] = epoch;
        }
    }

    fn observed_tlb_epoch(&self, cpu_id: usize) -> u64 {
        if cpu_id < MAX_TRACKED_TLB_CPUS {
            self.observed_tlb_epoch[cpu_id]
        } else {
            0
        }
    }

    fn create_anonymous_vmo(
        &mut self,
        _frames: &mut FrameTable,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<Vmo, AddressSpaceError> {
        let vmo_id = self
            .vm
            .create_vmo(VmoKind::Anonymous, size, global_vmo_id)?;
        self.vm
            .vmo(vmo_id)
            .cloned()
            .ok_or(AddressSpaceError::InvalidVmo)
    }

    fn import_vmo_alias(
        &mut self,
        kind: VmoKind,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<VmoId, AddressSpaceError> {
        self.vm.import_vmo(kind, size, global_vmo_id)
    }

    fn local_vmo_id(&self, global_vmo_id: KernelVmoId) -> Option<VmoId> {
        self.vm.vmo_id_by_global_id(global_vmo_id)
    }

    fn set_vmo_frame(
        &mut self,
        vmo_id: VmoId,
        offset: u64,
        frame_id: FrameId,
    ) -> Result<(), AddressSpaceError> {
        self.vm.set_vmo_frame(vmo_id, offset, frame_id)
    }

    fn mapped_ranges_for_global_vmo(&self, global_vmo_id: KernelVmoId) -> Vec<(u64, u64)> {
        self.vm.mapped_ranges_for_global_vmo(global_vmo_id)
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
        self.vm
            .map_fixed_in_vmar(frames, vmar_id, base, len, vmo_id, vmo_offset, perms, perms)
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
        self.vm.map_anywhere_in_vmar(
            frames,
            cpu_id,
            vmar_id,
            len,
            vmo_id,
            vmo_offset,
            perms,
            perms,
            axle_mm::PAGE_SIZE,
        )
    }

    fn unmap(
        &mut self,
        frames: &mut FrameTable,
        vmar_id: VmarId,
        base: u64,
        len: u64,
    ) -> Result<(), AddressSpaceError> {
        self.vm.unmap_in_vmar(frames, vmar_id, base, len)
    }

    fn protect(
        &mut self,
        vmar_id: VmarId,
        base: u64,
        len: u64,
        new_perms: MappingPerms,
    ) -> Result<(), AddressSpaceError> {
        self.vm.protect_in_vmar(vmar_id, base, len, new_perms)
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

    fn try_reserve_private_cow_page(&mut self, page_base: u64) -> Result<bool, VmQuotaExceeded> {
        self.vm_resources.try_reserve_private_cow_page(page_base)
    }

    fn commit_private_cow_page(&mut self, page_base: u64) -> bool {
        self.vm_resources.commit_private_cow_page(page_base)
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
struct Process {
    koid: zx_koid_t,
    address_space_id: AddressSpaceId,
    cspace: CSpace,
    state: ProcessState,
    suspend_tokens: u32,
}

impl Process {
    fn bootstrap(address_space_id: AddressSpaceId, koid: zx_koid_t) -> Self {
        Self {
            koid,
            address_space_id,
            cspace: CSpace::new(CSPACE_MAX_SLOTS, CSPACE_QUARANTINE_LEN),
            state: ProcessState::Started,
            suspend_tokens: 0,
        }
    }

    fn created(address_space_id: AddressSpaceId, koid: zx_koid_t) -> Self {
        Self {
            koid,
            address_space_id,
            cspace: CSpace::new(CSPACE_MAX_SLOTS, CSPACE_QUARANTINE_LEN),
            state: ProcessState::Created,
            suspend_tokens: 0,
        }
    }

    fn alloc_handle_for_capability(&mut self, cap: Capability) -> Result<zx_handle_t, zx_status_t> {
        let handle = self.cspace.alloc(cap).map_err(map_alloc_error)?;
        Ok(handle.raw())
    }

    fn lookup_handle(
        &self,
        process_id: ProcessId,
        raw: zx_handle_t,
        revocations: &RevocationManager,
    ) -> Result<ResolvedHandle, zx_status_t> {
        let handle = Handle::from_raw(raw).map_err(|_| ZX_ERR_BAD_HANDLE)?;
        let cap = self
            .cspace
            .get_checked(handle, revocations)
            .map_err(map_lookup_error)?;
        ResolvedHandle::new(process_id, handle, cap)
    }

    fn close_handle(&mut self, raw: zx_handle_t) -> Result<(), zx_status_t> {
        let handle = Handle::from_raw(raw).map_err(|_| ZX_ERR_BAD_HANDLE)?;
        let _ = self.cspace.get(handle).map_err(map_lookup_error)?;
        self.cspace.close(handle).map_err(map_lookup_error)?;
        Ok(())
    }

    fn duplicate_handle_derived(
        &mut self,
        raw: zx_handle_t,
        rights: HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        let handle = Handle::from_raw(raw).map_err(|_| ZX_ERR_BAD_HANDLE)?;
        let duplicated = self
            .cspace
            .duplicate_derived(handle, rights.bits())
            .map_err(map_alloc_error)?;
        Ok(duplicated.raw())
    }

    fn replace_handle_derived(
        &mut self,
        raw: zx_handle_t,
        rights: HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        let handle = Handle::from_raw(raw).map_err(|_| ZX_ERR_BAD_HANDLE)?;
        let replaced = self
            .cspace
            .replace_derived(handle, rights.bits())
            .map_err(map_alloc_error)?;
        Ok(replaced.raw())
    }

    fn snapshot_handle_for_transfer(
        &self,
        raw: zx_handle_t,
        revocations: &RevocationManager,
    ) -> Result<TransferredCap, zx_status_t> {
        let handle = Handle::from_raw(raw).map_err(|_| ZX_ERR_BAD_HANDLE)?;
        self.cspace
            .snapshot_checked(handle, revocations)
            .map_err(map_lookup_error)
    }

    fn install_transferred_handle(
        &mut self,
        transferred: TransferredCap,
    ) -> Result<zx_handle_t, zx_status_t> {
        let handle = self
            .cspace
            .install_transfer(transferred)
            .map_err(map_alloc_error)?;
        Ok(handle.raw())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessState {
    Created,
    Started,
    Suspended,
    Terminating,
    Terminated,
}

#[derive(Debug)]
struct Thread {
    process_id: ProcessId,
    koid: zx_koid_t,
    state: ThreadState,
    queued: bool,
    context: Option<UserContext>,
    suspend_tokens: u32,
}

/// Internal bootstrap kernel model.
#[derive(Debug)]
pub(crate) struct VmDomain {
    address_spaces: BTreeMap<AddressSpaceId, AddressSpace>,
    global_vmos: Arc<Mutex<GlobalVmoStore>>,
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
    processes: BTreeMap<ProcessId, Process>,
    threads: BTreeMap<ThreadId, Thread>,
    futexes: crate::futex::FutexTable,
    run_queue: VecDeque<ThreadId>,
    revocations: RevocationManager,
    next_koid: zx_koid_t,
    next_process_id: ProcessId,
    next_thread_id: ThreadId,
    current_thread_id: ThreadId,
    reschedule_requested: bool,
    task_lifecycle_dirty: bool,
    faults: Arc<Mutex<FaultTable>>,
    vm: Arc<Mutex<VmDomain>>,
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
    /// Build the single-process bootstrap kernel model used by the current main branch.
    pub(crate) fn bootstrap() -> Self {
        let mut vm = VmDomain {
            address_spaces: BTreeMap::new(),
            global_vmos: Arc::new(Mutex::new(GlobalVmoStore::default())),
            frames: Arc::new(Mutex::new(FrameTable::new())),
            cow_fault_count: 0,
            vm_private_cow_pages_current: 0,
            vm_private_cow_pages_peak: 0,
            vm_inflight_loan_pages_current: 0,
            vm_inflight_loan_pages_peak: 0,
            vm_private_cow_quota_hits: 0,
            vm_inflight_loan_quota_hits: 0,
            next_global_vmo_id: 1,
            next_address_space_id: 1,
        };
        let bootstrap_vmo_ids = [
            vm.alloc_global_vmo_id(),
            vm.alloc_global_vmo_id(),
            vm.alloc_global_vmo_id(),
        ];
        let address_space_id = vm.alloc_address_space_id();
        let bootstrap_address_space = {
            let mut frames = vm.frames.lock();
            AddressSpace::bootstrap(address_space_id, &mut frames, bootstrap_vmo_ids)
        };
        vm.address_spaces
            .insert(address_space_id, bootstrap_address_space);
        vm.observe_cpu_tlb_epoch_for_address_space(
            address_space_id,
            crate::arch::apic::this_apic_id() as usize,
        );
        for global_vmo_id in bootstrap_vmo_ids {
            vm.register_global_vmo_from_address_space(address_space_id, global_vmo_id)
                .expect("bootstrap global vmo seeding must succeed");
        }

        let vm = Arc::new(Mutex::new(vm));
        let faults = Arc::new(Mutex::new(FaultTable::default()));
        let mut kernel = Self {
            processes: BTreeMap::new(),
            threads: BTreeMap::new(),
            futexes: crate::futex::FutexTable::new(),
            run_queue: VecDeque::new(),
            revocations: RevocationManager::new(),
            next_koid: 1,
            next_process_id: 1,
            next_thread_id: 1,
            current_thread_id: 0,
            reschedule_requested: false,
            task_lifecycle_dirty: false,
            faults,
            vm,
        };
        let process_id = kernel.alloc_process_id();
        let process_koid = kernel.alloc_koid();
        kernel.processes.insert(
            process_id,
            Process::bootstrap(address_space_id, process_koid),
        );

        let thread_id = kernel.alloc_thread_id();
        let thread_koid = kernel.alloc_koid();
        kernel.threads.insert(
            thread_id,
            Thread {
                process_id,
                koid: thread_koid,
                state: ThreadState::Runnable,
                queued: false,
                context: None,
                suspend_tokens: 0,
            },
        );
        kernel.current_thread_id = thread_id;
        kernel
    }

    pub(crate) fn vm_handle(&self) -> Arc<Mutex<VmDomain>> {
        self.vm.clone()
    }

    pub(crate) fn fault_handle(&self) -> Arc<Mutex<FaultTable>> {
        self.faults.clone()
    }

    fn with_vm<T>(&self, f: impl FnOnce(&VmDomain) -> T) -> T {
        let vm = self.vm.lock();
        f(&vm)
    }

    fn with_vm_mut<T>(&self, f: impl FnOnce(&mut VmDomain) -> T) -> T {
        let mut vm = self.vm.lock();
        f(&mut vm)
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
        let resolved = self
            .current_process()?
            .lookup_handle(process_id, raw, &self.revocations)?;
        if !resolved.rights().contains(required_rights) {
            return Err(ZX_ERR_ACCESS_DENIED);
        }
        Ok(resolved)
    }

    pub(crate) fn close_current_handle(&mut self, raw: zx_handle_t) -> Result<(), zx_status_t> {
        self.current_process_mut()?.close_handle(raw)
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
        self.current_process_mut()?
            .install_transferred_handle(transferred)
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

    pub(crate) fn release_loaned_user_pages(&mut self, loaned: &LoanedUserPages) {
        self.with_vm_mut(|vm| vm.release_loaned_user_pages(loaned))
    }

    pub(crate) fn prepare_loaned_channel_write(
        &mut self,
        loaned: &mut LoanedUserPages,
        receiver_address_space_id: AddressSpaceId,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| vm.prepare_loaned_channel_write(loaned, receiver_address_space_id))
    }

    pub(crate) fn try_remap_loaned_channel_read(
        &mut self,
        dst_base: u64,
        loaned: &LoanedUserPages,
    ) -> Result<bool, zx_status_t> {
        let current_address_space_id = self.current_process()?.address_space_id;
        self.with_vm_mut(|vm| {
            vm.try_remap_loaned_channel_read(current_address_space_id, dst_base, loaned)
        })
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
        self.with_vm_mut(|vm| vm.destroy_vmar(address_space_id, vmar_id))
    }

    pub(crate) fn current_thread_info(&self) -> Result<CurrentThreadInfo, zx_status_t> {
        let thread = self.current_thread()?;
        Ok(CurrentThreadInfo {
            process_id: thread.process_id,
            thread_id: self.current_thread_id,
            koid: thread.koid,
        })
    }

    pub(crate) fn current_process_info(&self) -> Result<CurrentProcessInfo, zx_status_t> {
        let thread = self.current_thread()?;
        Ok(CurrentProcessInfo {
            process_id: thread.process_id,
        })
    }

    /// Resolve the address space currently bound to `process_id`.
    pub(crate) fn process_address_space_id(
        &self,
        process_id: ProcessId,
    ) -> Result<AddressSpaceId, zx_status_t> {
        Ok(self.process(process_id)?.address_space_id)
    }

    pub(crate) fn create_process(&mut self) -> Result<CreatedProcess, zx_status_t> {
        let (address_space_id, root_vmar) =
            self.with_vm_mut(|vm| vm.create_process_address_space())?;

        let process_id = self.alloc_process_id();
        let process_koid = self.alloc_koid();
        self.processes
            .insert(process_id, Process::created(address_space_id, process_koid));

        Ok(CreatedProcess {
            process_id,
            koid: process_koid,
            address_space_id,
            root_vmar,
        })
    }

    fn register_global_vmo_from_address_space(
        &mut self,
        address_space_id: AddressSpaceId,
        global_vmo_id: KernelVmoId,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| {
            vm.register_global_vmo_from_address_space(address_space_id, global_vmo_id)
        })
    }

    fn register_empty_global_vmo(
        &mut self,
        global_vmo_id: KernelVmoId,
        kind: VmoKind,
        size_bytes: u64,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| vm.register_empty_global_vmo(global_vmo_id, kind, size_bytes))
    }

    fn import_global_vmo_into_address_space(
        &mut self,
        address_space_id: AddressSpaceId,
        global_vmo_id: KernelVmoId,
    ) -> Result<VmoId, zx_status_t> {
        self.with_vm_mut(|vm| {
            vm.import_global_vmo_into_address_space(address_space_id, global_vmo_id)
        })
    }

    fn update_global_vmo_frame(
        &mut self,
        global_vmo_id: KernelVmoId,
        offset: u64,
        frame_id: FrameId,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| vm.update_global_vmo_frame(global_vmo_id, offset, frame_id))
    }

    fn global_vmo_frame(
        &self,
        global_vmo_id: KernelVmoId,
        offset: u64,
    ) -> Result<Option<FrameId>, zx_status_t> {
        self.with_vm(|vm| vm.global_vmo_frame(global_vmo_id, offset))
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

    fn try_reserve_private_cow_page(
        &mut self,
        address_space_id: AddressSpaceId,
        page_base: u64,
    ) -> Result<bool, zx_status_t> {
        self.with_vm_mut(|vm| vm.try_reserve_private_cow_page(address_space_id, page_base))
    }

    fn commit_private_cow_page(&mut self, address_space_id: AddressSpaceId, page_base: u64) {
        self.with_vm_mut(|vm| vm.commit_private_cow_page(address_space_id, page_base));
    }

    fn clear_private_cow_range(&mut self, address_space_id: AddressSpaceId, base: u64, len: u64) {
        self.with_vm_mut(|vm| vm.clear_private_cow_range(address_space_id, base, len));
    }

    fn try_reserve_inflight_loan_pages(
        &mut self,
        address_space_id: AddressSpaceId,
        pages: u64,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| vm.try_reserve_inflight_loan_pages(address_space_id, pages))
    }

    fn release_inflight_loan_pages(&mut self, address_space_id: AddressSpaceId, pages: u64) {
        self.with_vm_mut(|vm| vm.release_inflight_loan_pages(address_space_id, pages));
    }

    fn publish_address_space_frame_to_global_vmo(
        &mut self,
        address_space_id: AddressSpaceId,
        fault_va: u64,
        frame_id: FrameId,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| {
            vm.publish_address_space_frame_to_global_vmo(address_space_id, fault_va, frame_id)
        })
    }

    pub(crate) fn create_current_anonymous_vmo(
        &mut self,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<CreatedVmo, zx_status_t> {
        let process_id = self.current_thread()?.process_id;
        let address_space_id = self.current_process()?.address_space_id;
        self.with_vm_mut(|vm| {
            vm.create_anonymous_vmo_for_address_space(
                process_id,
                address_space_id,
                size,
                global_vmo_id,
            )
        })
    }

    #[allow(dead_code)]
    pub(crate) fn current_thread_koid(&self) -> Result<zx_koid_t, zx_status_t> {
        Ok(self.current_thread()?.koid)
    }

    pub(crate) fn current_process_koid(&self) -> Result<zx_koid_t, zx_status_t> {
        Ok(self.current_process()?.koid)
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
        if !self.with_vm(|vm| {
            vm.validate_user_ptr(process.address_space_id, ptr as u64, size_of::<T>())
        }) {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        // SAFETY: the pointer was validated against the target thread's userspace mapping.
        unsafe {
            core::ptr::write_unaligned(ptr, value);
        }
        Ok(())
    }

    pub(crate) fn capture_current_user_context(
        &mut self,
        trap: &crate::arch::int80::TrapFrame,
        cpu_frame: *const u64,
    ) -> Result<(), zx_status_t> {
        let context = UserContext::capture(trap, cpu_frame)?;
        let thread = self
            .threads
            .get_mut(&self.current_thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        thread.context = Some(context);
        Ok(())
    }

    fn restore_current_user_context(
        &mut self,
        trap: &mut crate::arch::int80::TrapFrame,
        cpu_frame: *mut u64,
    ) -> Result<(), zx_status_t> {
        let context = self.current_thread()?.context.ok_or(ZX_ERR_BAD_STATE)?;
        context.restore(trap, cpu_frame)
    }

    pub(crate) fn finish_trap_exit(
        &mut self,
        trap: &mut crate::arch::int80::TrapFrame,
        cpu_frame: *mut u64,
        resuming_blocked_current: bool,
    ) -> Result<TrapExitDisposition, zx_status_t> {
        match self.current_thread()?.state {
            ThreadState::Runnable => {
                if resuming_blocked_current {
                    self.restore_current_user_context(trap, cpu_frame)?;
                } else {
                    self.capture_current_user_context(trap, cpu_frame.cast_const())?;
                }
                if !resuming_blocked_current && self.reschedule_requested {
                    self.reschedule_requested = false;
                    if let Some(next_thread_id) = self.pop_runnable_thread() {
                        self.requeue_current_thread()?;
                        self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                    }
                }
                self.sync_current_cpu_tlb_state()?;
                Ok(TrapExitDisposition::Complete)
            }
            ThreadState::New => Err(ZX_ERR_BAD_STATE),
            ThreadState::TerminationPending => {
                let thread_id = self.current_thread_id;
                self.finalize_thread_termination(thread_id)?;
                if let Some(next_thread_id) = self.pop_runnable_thread() {
                    self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                    Ok(TrapExitDisposition::Complete)
                } else {
                    Ok(TrapExitDisposition::BlockCurrent)
                }
            }
            ThreadState::Suspended | ThreadState::Terminated => {
                if let Some(next_thread_id) = self.pop_runnable_thread() {
                    self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                    Ok(TrapExitDisposition::Complete)
                } else {
                    Ok(TrapExitDisposition::BlockCurrent)
                }
            }
            ThreadState::FutexWait { .. }
            | ThreadState::SignalWait { .. }
            | ThreadState::PortWait { .. }
            | ThreadState::VmFaultWait { .. } => {
                if let Some(next_thread_id) = self.pop_runnable_thread() {
                    self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                    Ok(TrapExitDisposition::Complete)
                } else {
                    Ok(TrapExitDisposition::BlockCurrent)
                }
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn enqueue_current_futex_wait(
        &mut self,
        key: FutexKey,
        owner_koid: zx_koid_t,
    ) -> Result<(), zx_status_t> {
        let thread_id = self.current_thread_id;
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if !matches!(thread.state, ThreadState::Runnable) {
            return Err(ZX_ERR_BAD_STATE);
        }
        thread.state = ThreadState::FutexWait { key };
        self.futexes.enqueue_waiter(key, thread_id, owner_koid);
        Ok(())
    }

    pub(crate) fn enqueue_current_signal_wait(
        &mut self,
        object_id: u64,
        watched: Signals,
        observed_ptr: *mut zx_signals_t,
    ) -> Result<(), zx_status_t> {
        let thread = self
            .threads
            .get_mut(&self.current_thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if !matches!(thread.state, ThreadState::Runnable) {
            return Err(ZX_ERR_BAD_STATE);
        }
        thread.state = ThreadState::SignalWait {
            object_id,
            watched,
            observed_ptr: observed_ptr as u64,
        };
        Ok(())
    }

    pub(crate) fn enqueue_current_fault_wait(
        &mut self,
        key: FaultInFlightKey,
    ) -> Result<(), zx_status_t> {
        let thread = self
            .threads
            .get_mut(&self.current_thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if !matches!(thread.state, ThreadState::Runnable) {
            return Err(ZX_ERR_BAD_STATE);
        }
        thread.state = ThreadState::VmFaultWait { key };
        Ok(())
    }

    pub(crate) fn signal_waiters_ready(
        &self,
        object_id: u64,
        current: Signals,
    ) -> Vec<SignalWaiter> {
        self.threads
            .iter()
            .filter_map(|(thread_id, thread)| match thread.state {
                ThreadState::SignalWait {
                    object_id: wait_object_id,
                    watched,
                    observed_ptr,
                } if wait_object_id == object_id && current.intersects(watched) => {
                    Some(SignalWaiter {
                        thread_id: *thread_id,
                        observed_ptr,
                    })
                }
                _ => None,
            })
            .collect()
    }

    pub(crate) fn enqueue_current_port_wait(
        &mut self,
        port_object_id: u64,
        packet_ptr: *mut zx_port_packet_t,
    ) -> Result<(), zx_status_t> {
        let thread = self
            .threads
            .get_mut(&self.current_thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if !matches!(thread.state, ThreadState::Runnable) {
            return Err(ZX_ERR_BAD_STATE);
        }
        thread.state = ThreadState::PortWait {
            port_object_id,
            packet_ptr: packet_ptr as u64,
        };
        Ok(())
    }

    pub(crate) fn port_waiters(&self, port_object_id: u64) -> Vec<PortWaiter> {
        self.threads
            .iter()
            .filter_map(|(thread_id, thread)| match thread.state {
                ThreadState::PortWait {
                    port_object_id: wait_port_object_id,
                    packet_ptr,
                } if wait_port_object_id == port_object_id => Some(PortWaiter {
                    thread_id: *thread_id,
                    packet_ptr,
                }),
                _ => None,
            })
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn cancel_current_futex_wait(&mut self) -> Result<bool, zx_status_t> {
        let thread_id = self.current_thread_id;
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        let ThreadState::FutexWait { key } = thread.state else {
            return Ok(false);
        };
        thread.state = ThreadState::Runnable;
        Ok(self.futexes.cancel_waiter(key, thread_id))
    }

    #[allow(dead_code)]
    pub(crate) fn wake_futex_waiters(
        &mut self,
        key: FutexKey,
        wake_count: usize,
        new_owner_koid: zx_koid_t,
        single_owner: bool,
    ) -> Result<usize, zx_status_t> {
        let result = self
            .futexes
            .wake(key, wake_count, new_owner_koid, single_owner);
        for thread_id in result.woken {
            self.make_thread_runnable(thread_id, ZX_OK)?;
        }
        Ok(result.remaining)
    }

    #[allow(dead_code)]
    pub(crate) fn requeue_futex_waiters(
        &mut self,
        source: FutexKey,
        target: FutexKey,
        wake_count: usize,
        requeue_count: usize,
        target_owner_koid: zx_koid_t,
    ) -> Result<crate::futex::RequeueResult, zx_status_t> {
        let result =
            self.futexes
                .requeue(source, target, wake_count, requeue_count, target_owner_koid);
        for thread_id in &result.woken {
            self.make_thread_runnable(*thread_id, ZX_OK)?;
        }
        for thread in self.threads.values_mut() {
            if matches!(thread.state, ThreadState::FutexWait { key } if key == source) {
                thread.state = ThreadState::FutexWait { key: target };
            }
        }
        Ok(result)
    }

    #[allow(dead_code)]
    pub(crate) fn futex_owner(&self, key: FutexKey) -> zx_koid_t {
        self.futexes.owner(key)
    }

    #[allow(dead_code)]
    pub(crate) fn thread_is_waiting_on_futex(&self, thread_id: ThreadId, key: FutexKey) -> bool {
        self.futexes.is_waiter(key, thread_id)
    }

    pub(crate) fn create_thread(
        &mut self,
        process_id: ProcessId,
    ) -> Result<(ThreadId, zx_koid_t), zx_status_t> {
        let process = self.process(process_id)?;
        if matches!(
            process.state,
            ProcessState::Terminating | ProcessState::Terminated
        ) {
            return Err(ZX_ERR_BAD_STATE);
        }
        let thread_id = self.alloc_thread_id();
        let koid = self.alloc_koid();
        self.threads.insert(
            thread_id,
            Thread {
                process_id,
                koid,
                state: ThreadState::New,
                queued: false,
                context: None,
                suspend_tokens: 0,
            },
        );
        Ok((thread_id, koid))
    }

    pub(crate) fn start_thread(
        &mut self,
        thread_id: ThreadId,
        entry: u64,
        stack: u64,
        arg0: u64,
        arg1: u64,
    ) -> Result<(), zx_status_t> {
        let process_id = self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .process_id;
        let process = self.process(process_id)?;
        if process.state != ProcessState::Started {
            return Err(ZX_ERR_BAD_STATE);
        }
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        if !matches!(thread.state, ThreadState::New) {
            return Err(ZX_ERR_BAD_STATE);
        }
        thread.context = Some(UserContext::new_user_entry(entry, stack, arg0, arg1));
        thread.state = ThreadState::Runnable;
        let queued = thread.queued;
        let thread_id_copy = thread_id;
        let _ = thread;
        if !queued {
            self.enqueue_runnable_thread(thread_id_copy)?;
        }
        Ok(())
    }

    pub(crate) fn start_process(
        &mut self,
        process_id: ProcessId,
        thread_id: ThreadId,
        entry: u64,
        stack: u64,
        arg0: u64,
        arg1: u64,
    ) -> Result<(), zx_status_t> {
        let thread_process_id = self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .process_id;
        if thread_process_id != process_id {
            return Err(ZX_ERR_BAD_STATE);
        }
        let process = self
            .processes
            .get_mut(&process_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?;
        if process.state != ProcessState::Created {
            return Err(ZX_ERR_BAD_STATE);
        }
        process.state = ProcessState::Started;
        let result = self.start_thread(thread_id, entry, stack, arg0, arg1);
        if result.is_err() {
            let process = self
                .processes
                .get_mut(&process_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            process.state = ProcessState::Created;
        }
        result
    }

    pub(crate) fn kill_thread(&mut self, thread_id: ThreadId) -> Result<(), zx_status_t> {
        self.request_thread_termination(thread_id)
    }

    pub(crate) fn kill_process(&mut self, process_id: ProcessId) -> Result<(), zx_status_t> {
        let process = self
            .processes
            .get_mut(&process_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?;
        if matches!(
            process.state,
            ProcessState::Terminating | ProcessState::Terminated
        ) {
            return Ok(());
        }
        process.state = ProcessState::Terminating;
        let thread_ids = self
            .threads
            .iter()
            .filter_map(|(thread_id, thread)| {
                (thread.process_id == process_id).then_some(*thread_id)
            })
            .collect::<Vec<_>>();
        for thread_id in thread_ids {
            self.request_thread_termination(thread_id)?;
        }
        self.maybe_finalize_process_termination(process_id)?;
        Ok(())
    }

    pub(crate) fn suspend_thread(&mut self, thread_id: ThreadId) -> Result<(), zx_status_t> {
        let process_id = self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .process_id;
        let process = self.process(process_id)?;
        if matches!(
            process.state,
            ProcessState::Created | ProcessState::Terminating | ProcessState::Terminated
        ) {
            return Err(ZX_ERR_BAD_STATE);
        }
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        if matches!(
            thread.state,
            ThreadState::New | ThreadState::TerminationPending | ThreadState::Terminated
        ) {
            return Err(ZX_ERR_BAD_STATE);
        }
        thread.suspend_tokens = thread.suspend_tokens.saturating_add(1);
        if matches!(thread.state, ThreadState::Runnable) {
            thread.state = ThreadState::Suspended;
            thread.queued = false;
        }
        if thread_id == self.current_thread_id {
            self.reschedule_requested = true;
        }
        Ok(())
    }

    pub(crate) fn resume_thread(&mut self, thread_id: ThreadId) -> Result<(), zx_status_t> {
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        if thread.suspend_tokens == 0 {
            return Err(ZX_ERR_BAD_STATE);
        }
        thread.suspend_tokens -= 1;
        let _ = thread;
        self.maybe_resume_thread(thread_id)
    }

    pub(crate) fn suspend_process(&mut self, process_id: ProcessId) -> Result<(), zx_status_t> {
        let process = self
            .processes
            .get_mut(&process_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?;
        if matches!(
            process.state,
            ProcessState::Created | ProcessState::Terminating | ProcessState::Terminated
        ) {
            return Err(ZX_ERR_BAD_STATE);
        }
        process.suspend_tokens = process.suspend_tokens.saturating_add(1);
        process.state = ProcessState::Suspended;
        let thread_ids = self
            .threads
            .iter()
            .filter_map(|(thread_id, thread)| {
                (thread.process_id == process_id).then_some(*thread_id)
            })
            .collect::<Vec<_>>();
        for thread_id in thread_ids {
            let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
            if matches!(thread.state, ThreadState::Runnable) {
                thread.state = ThreadState::Suspended;
                thread.queued = false;
            }
            if thread_id == self.current_thread_id {
                self.reschedule_requested = true;
            }
        }
        Ok(())
    }

    pub(crate) fn resume_process(&mut self, process_id: ProcessId) -> Result<(), zx_status_t> {
        let process = self
            .processes
            .get_mut(&process_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?;
        if process.suspend_tokens == 0 || process.state != ProcessState::Suspended {
            return Err(ZX_ERR_BAD_STATE);
        }
        process.suspend_tokens -= 1;
        if process.suspend_tokens == 0 {
            process.state = ProcessState::Started;
        }
        let fully_resumed = process.state != ProcessState::Suspended;
        let thread_ids = self
            .threads
            .iter()
            .filter_map(|(thread_id, thread)| {
                (thread.process_id == process_id).then_some(*thread_id)
            })
            .collect::<Vec<_>>();
        if fully_resumed {
            for thread_id in thread_ids {
                self.maybe_resume_thread(thread_id)?;
            }
        }
        Ok(())
    }

    pub(crate) fn thread_is_terminated(&self, thread_id: ThreadId) -> Result<bool, zx_status_t> {
        let thread = self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        Ok(matches!(thread.state, ThreadState::Terminated))
    }

    pub(crate) fn process_is_terminated(&self, process_id: ProcessId) -> Result<bool, zx_status_t> {
        let process = self.processes.get(&process_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        Ok(matches!(process.state, ProcessState::Terminated))
    }

    pub(crate) fn thread_signals(&self, thread_id: ThreadId) -> Result<Signals, zx_status_t> {
        Ok(if self.thread_is_terminated(thread_id)? {
            Signals::TASK_TERMINATED
        } else {
            Signals::NONE
        })
    }

    pub(crate) fn process_signals(&self, process_id: ProcessId) -> Result<Signals, zx_status_t> {
        Ok(if self.process_is_terminated(process_id)? {
            Signals::TASK_TERMINATED
        } else {
            Signals::NONE
        })
    }

    pub(crate) fn reap_thread(&mut self, thread_id: ThreadId) -> Result<ProcessId, zx_status_t> {
        let thread = self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        if !matches!(thread.state, ThreadState::Terminated) {
            return Err(ZX_ERR_BAD_STATE);
        }
        if thread_id == self.current_thread_id {
            return Err(ZX_ERR_BAD_STATE);
        }
        let process_id = thread.process_id;
        let _ = self.threads.remove(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        Ok(process_id)
    }

    pub(crate) fn can_reap_process(&self, process_id: ProcessId) -> Result<bool, zx_status_t> {
        let process = self.processes.get(&process_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        if !matches!(process.state, ProcessState::Terminated) {
            return Ok(false);
        }
        Ok(self
            .threads
            .values()
            .all(|thread| thread.process_id != process_id))
    }

    pub(crate) fn reap_process(&mut self, process_id: ProcessId) -> Result<(), zx_status_t> {
        if !self.can_reap_process(process_id)? {
            return Err(ZX_ERR_BAD_STATE);
        }
        let _ = self.processes.remove(&process_id).ok_or(ZX_ERR_BAD_STATE)?;
        Ok(())
    }

    pub(crate) fn take_task_lifecycle_dirty(&mut self) -> bool {
        core::mem::take(&mut self.task_lifecycle_dirty)
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
        self.with_vm_mut(|vm| {
            vm.map_vmo_into_vmar(
                vmar_address_space_id,
                self.current_cpu_id(),
                vmar_id,
                global_vmo_id,
                Some(vmar_offset),
                vmo_offset,
                len,
                perms,
            )
        })
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
        self.with_vm_mut(|vm| {
            vm.map_vmo_into_vmar(
                vmar_address_space_id,
                self.current_cpu_id(),
                vmar_id,
                global_vmo_id,
                None,
                vmo_offset,
                len,
                perms,
            )
        })
    }

    pub(crate) fn unmap_current_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        addr: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| vm.unmap_vmar(address_space_id, vmar_id, addr, len))
    }

    pub(crate) fn protect_current_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        addr: u64,
        len: u64,
        perms: MappingPerms,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| vm.protect_vmar(address_space_id, vmar_id, addr, len, perms))
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

    fn current_thread(&self) -> Result<&Thread, zx_status_t> {
        self.threads
            .get(&self.current_thread_id)
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
        self.processes.get_mut(&process_id).ok_or(ZX_ERR_BAD_STATE)
    }

    fn thread_should_be_suspended(&self, thread_id: ThreadId) -> Result<bool, zx_status_t> {
        let thread = self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if thread.suspend_tokens != 0 {
            return Ok(true);
        }
        let process = self.process(thread.process_id)?;
        Ok(process.state == ProcessState::Suspended)
    }

    fn request_thread_termination(&mut self, thread_id: ThreadId) -> Result<(), zx_status_t> {
        let state = self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_HANDLE)?.state;
        match state {
            ThreadState::TerminationPending | ThreadState::Terminated => return Ok(()),
            ThreadState::FutexWait { key } => {
                let _ = self.futexes.cancel_waiter(key, thread_id);
            }
            ThreadState::VmFaultWait { key } => {
                let mut faults = self.faults.lock();
                faults.remove_blocked_waiter(key, thread_id);
            }
            ThreadState::New
            | ThreadState::Runnable
            | ThreadState::Suspended
            | ThreadState::SignalWait { .. }
            | ThreadState::PortWait { .. } => {}
        }

        if thread_id == self.current_thread_id {
            let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
            thread.state = ThreadState::TerminationPending;
            thread.queued = false;
            self.reschedule_requested = true;
            return Ok(());
        }

        self.finalize_thread_termination(thread_id)
    }

    fn finalize_thread_termination(&mut self, thread_id: ThreadId) -> Result<(), zx_status_t> {
        let process_id = self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .process_id;
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if matches!(thread.state, ThreadState::Terminated) {
            return Ok(());
        }
        thread.state = ThreadState::Terminated;
        thread.queued = false;
        thread.context = None;
        self.task_lifecycle_dirty = true;
        if thread_id == self.current_thread_id {
            self.reschedule_requested = true;
        }
        self.maybe_finalize_process_termination(process_id)?;
        Ok(())
    }

    fn maybe_finalize_process_termination(
        &mut self,
        process_id: ProcessId,
    ) -> Result<(), zx_status_t> {
        let all_threads_terminated = self
            .threads
            .values()
            .filter(|thread| thread.process_id == process_id)
            .all(|thread| matches!(thread.state, ThreadState::Terminated));
        let process = self
            .processes
            .get_mut(&process_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?;
        if all_threads_terminated
            && !matches!(
                process.state,
                ProcessState::Created | ProcessState::Terminated
            )
        {
            process.state = ProcessState::Terminated;
            self.task_lifecycle_dirty = true;
        }
        Ok(())
    }

    fn maybe_resume_thread(&mut self, thread_id: ThreadId) -> Result<(), zx_status_t> {
        if self.thread_should_be_suspended(thread_id)? {
            return Ok(());
        }
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if !matches!(thread.state, ThreadState::Suspended) {
            return Ok(());
        }
        thread.state = ThreadState::Runnable;
        let queued = thread.queued;
        let _ = thread;
        if !queued {
            self.enqueue_runnable_thread(thread_id)?;
        }
        self.reschedule_requested = true;
        Ok(())
    }

    fn enqueue_runnable_thread(&mut self, thread_id: ThreadId) -> Result<(), zx_status_t> {
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if thread.queued || !matches!(thread.state, ThreadState::Runnable) {
            return Ok(());
        }
        thread.queued = true;
        self.run_queue.push_back(thread_id);
        Ok(())
    }

    fn enqueue_runnable_thread_front(&mut self, thread_id: ThreadId) -> Result<(), zx_status_t> {
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if thread.queued || !matches!(thread.state, ThreadState::Runnable) {
            return Ok(());
        }
        thread.queued = true;
        self.run_queue.push_front(thread_id);
        Ok(())
    }

    fn requeue_current_thread(&mut self) -> Result<(), zx_status_t> {
        self.enqueue_runnable_thread(self.current_thread_id)
    }

    fn pop_runnable_thread(&mut self) -> Option<ThreadId> {
        while let Some(thread_id) = self.run_queue.pop_front() {
            let Some(thread) = self.threads.get_mut(&thread_id) else {
                continue;
            };
            thread.queued = false;
            if matches!(thread.state, ThreadState::Runnable) {
                return Some(thread_id);
            }
        }
        None
    }

    fn switch_to_thread(
        &mut self,
        thread_id: ThreadId,
        trap: &mut crate::arch::int80::TrapFrame,
        cpu_frame: *mut u64,
    ) -> Result<(), zx_status_t> {
        let current_cpu_id = self.current_cpu_id();
        let current_process_id = self.current_thread()?.process_id;
        let current_address_space_id = self.process(current_process_id)?.address_space_id;
        let next_process_id = self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .process_id;
        let next_address_space_id = self.process(next_process_id)?.address_space_id;
        let next_page_tables = self.with_vm(|vm| vm.root_page_table(next_address_space_id))?;
        let context = self
            .threads
            .get(&thread_id)
            .and_then(|thread| thread.context)
            .ok_or(ZX_ERR_BAD_STATE)?;
        next_page_tables.activate().map_err(map_page_table_error)?;
        if current_address_space_id != next_address_space_id {
            self.with_vm_mut(|vm| vm.note_cpu_inactive(current_address_space_id, current_cpu_id));
        }
        self.observe_cpu_tlb_epoch_for_address_space(next_address_space_id, current_cpu_id);
        context.restore(trap, cpu_frame)?;
        self.current_thread_id = thread_id;
        Ok(())
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

    fn make_thread_runnable_inner(
        &mut self,
        thread_id: ThreadId,
        status: Option<zx_status_t>,
    ) -> Result<(), zx_status_t> {
        let previous_state = self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_STATE)?.state;
        if matches!(
            previous_state,
            ThreadState::TerminationPending | ThreadState::Terminated
        ) {
            return Ok(());
        }
        let hold_suspended = self.thread_should_be_suspended(thread_id)?;
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        let Some(context) = thread.context else {
            return Err(ZX_ERR_BAD_STATE);
        };
        thread.context = Some(match status {
            Some(status) => context.with_status(status),
            None => context,
        });
        thread.state = if hold_suspended {
            ThreadState::Suspended
        } else {
            ThreadState::Runnable
        };
        let was_current = thread_id == self.current_thread_id;
        let _ = thread;
        if !hold_suspended && !was_current {
            if matches!(
                previous_state,
                ThreadState::FutexWait { .. }
                    | ThreadState::SignalWait { .. }
                    | ThreadState::PortWait { .. }
                    | ThreadState::VmFaultWait { .. }
            ) {
                self.enqueue_runnable_thread_front(thread_id)?;
            } else {
                self.enqueue_runnable_thread(thread_id)?;
            }
            self.reschedule_requested = true;
        }
        Ok(())
    }

    pub(crate) fn make_thread_runnable(
        &mut self,
        thread_id: ThreadId,
        status: zx_status_t,
    ) -> Result<(), zx_status_t> {
        self.make_thread_runnable_inner(thread_id, Some(status))
    }

    pub(crate) fn make_thread_runnable_preserving_context(
        &mut self,
        thread_id: ThreadId,
    ) -> Result<(), zx_status_t> {
        self.make_thread_runnable_inner(thread_id, None)
    }

    pub(crate) fn request_reschedule(&mut self) {
        self.reschedule_requested = true;
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

    fn release_pinned_loan_frames(&mut self, pages: &[FrameId]) {
        self.with_vm_mut(|vm| vm.release_pinned_loan_frames(pages))
    }

    fn release_loaned_pages_inner(&mut self, address_space_id: AddressSpaceId, pages: &[FrameId]) {
        self.with_vm_mut(|vm| vm.release_loaned_pages_inner(address_space_id, pages))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultPlanResult {
    Satisfied,
    Ready(FaultPlan),
    Unhandled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultCommitDisposition {
    Resolved,
    Retry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PageFaultSerializedResult {
    Handled,
    BlockCurrent {
        key: FaultInFlightKey,
        wake_thread: Option<ThreadId>,
    },
    Unhandled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedFaultWork {
    None,
    NewPage { paddr: u64 },
}

impl PreparedFaultWork {
    fn take_page_paddr(&mut self) -> Option<u64> {
        match core::mem::replace(self, Self::None) {
            Self::None => None,
            Self::NewPage { paddr } => Some(paddr),
        }
    }

    fn release_unused(self) {
        if let Self::NewPage { paddr } = self {
            crate::userspace::free_bootstrap_page(paddr);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultPlan {
    CopyOnWrite {
        key: FaultInFlightKey,
        address_space_id: AddressSpaceId,
        page_base: u64,
        old_frame_id: FrameId,
    },
    LazyAnon {
        key: FaultInFlightKey,
        address_space_id: AddressSpaceId,
        page_base: u64,
    },
    LazyVmo {
        key: FaultInFlightKey,
        address_space_id: AddressSpaceId,
        page_base: u64,
        global_vmo_id: KernelVmoId,
        page_offset: u64,
        vmo_kind: VmoKind,
    },
}

impl FaultPlan {
    const fn key(self) -> FaultInFlightKey {
        match self {
            Self::CopyOnWrite { key, .. }
            | Self::LazyAnon { key, .. }
            | Self::LazyVmo { key, .. } => key,
        }
    }
}

fn record_fault_telemetry_snapshot(table: &Arc<Mutex<FaultTable>>) {
    let telemetry = {
        let table = table.lock();
        table.telemetry()
    };
    crate::userspace::record_fault_contention_telemetry(
        telemetry.leader_claims,
        telemetry.wait_claims,
        telemetry.wait_spin_loops,
        telemetry.retry_total,
        telemetry.commit_resolved,
        telemetry.commit_retry,
        telemetry.prepare_cow,
        telemetry.prepare_lazy_anon,
        telemetry.prepare_lazy_vmo_alloc,
    );
}

fn update_fault_telemetry(table: &Arc<Mutex<FaultTable>>, f: impl FnOnce(&mut FaultTable)) {
    {
        let mut table = table.lock();
        f(&mut table);
    }
    record_fault_telemetry_snapshot(table);
}

fn claim_fault(table: &Arc<Mutex<FaultTable>>, key: FaultInFlightKey) -> FaultClaim {
    let claim = {
        let mut table = table.lock();
        table.claim(key)
    };
    record_fault_telemetry_snapshot(table);
    claim
}

fn claim_blocking_fault(
    table: &Arc<Mutex<FaultTable>>,
    key: FaultInFlightKey,
    thread_id: ThreadId,
) -> FaultBlockingClaim {
    let claim = {
        let mut table = table.lock();
        table.claim_blocking(key, thread_id)
    };
    record_fault_telemetry_snapshot(table);
    claim
}

fn pause_fault_leader_for_test(
    table: &Arc<Mutex<FaultTable>>,
    key: FaultInFlightKey,
    thread_id: ThreadId,
) {
    {
        let mut table = table.lock();
        table.pause_leader_for_test(key, thread_id);
    }
    record_fault_telemetry_snapshot(table);
}

fn complete_fault(table: &Arc<Mutex<FaultTable>>, key: FaultInFlightKey) -> Vec<ThreadId> {
    let waiters = {
        let mut table = table.lock();
        table.complete(key)
    };
    record_fault_telemetry_snapshot(table);
    waiters
}

fn clone_global_vmo_store(vm_handle: &Arc<Mutex<VmDomain>>) -> Arc<Mutex<GlobalVmoStore>> {
    let vm = vm_handle.lock();
    vm.global_vmo_store()
}

fn wake_fault_waiters(kernel_handle: &Arc<Mutex<Kernel>>, waiters: Vec<ThreadId>) {
    if waiters.is_empty() {
        return;
    }
    let mut kernel = kernel_handle.lock();
    for thread_id in waiters {
        let _ = kernel.make_thread_runnable_preserving_context(thread_id);
    }
}

fn should_pause_fault_leader_for_test() -> bool {
    crate::userspace::consume_vm_fault_leader_pause_hook()
}

fn wait_for_fault_completion(table: &Arc<Mutex<FaultTable>>, wait: FaultWaitToken) {
    let mut observed_spin_loops = 0_u64;
    loop {
        let completed = {
            let table = table.lock();
            table.observe_completion(wait)
        };
        if completed {
            let mut table = table.lock();
            table.release_waiter(wait);
            if observed_spin_loops != 0 {
                table.record_wait_spin_loops(observed_spin_loops);
            }
            let telemetry = table.telemetry();
            drop(table);
            crate::userspace::record_fault_contention_telemetry(
                telemetry.leader_claims,
                telemetry.wait_claims,
                telemetry.wait_spin_loops,
                telemetry.retry_total,
                telemetry.commit_resolved,
                telemetry.commit_retry,
                telemetry.prepare_cow,
                telemetry.prepare_lazy_anon,
                telemetry.prepare_lazy_vmo_alloc,
            );
            return;
        }
        for _ in 0..FAULT_WAIT_SPIN_LOOPS {
            core::hint::spin_loop();
        }
        observed_spin_loops = observed_spin_loops.wrapping_add(FAULT_WAIT_SPIN_LOOPS as u64);
    }
}

fn prepare_fault_work(
    plan: FaultPlan,
    fault_table: &Arc<Mutex<FaultTable>>,
    global_vmo_store: &Arc<Mutex<GlobalVmoStore>>,
) -> Result<PreparedFaultWork, zx_status_t> {
    match plan {
        FaultPlan::CopyOnWrite { old_frame_id, .. } => {
            update_fault_telemetry(fault_table, |table| {
                table.record_prepare(FaultPrepareKind::CopyOnWrite);
            });
            let new_frame_paddr = crate::userspace::alloc_bootstrap_cow_page(old_frame_id.raw())
                .ok_or(ZX_ERR_NO_MEMORY)?;
            Ok(PreparedFaultWork::NewPage {
                paddr: new_frame_paddr,
            })
        }
        FaultPlan::LazyAnon { .. } => {
            update_fault_telemetry(fault_table, |table| {
                table.record_prepare(FaultPrepareKind::LazyAnon);
            });
            let new_frame_paddr =
                crate::userspace::alloc_bootstrap_zeroed_page().ok_or(ZX_ERR_NO_MEMORY)?;
            Ok(PreparedFaultWork::NewPage {
                paddr: new_frame_paddr,
            })
        }
        FaultPlan::LazyVmo {
            vmo_kind,
            global_vmo_id,
            page_offset,
            ..
        } => {
            if global_vmo_store
                .lock()
                .frame(global_vmo_id, page_offset)?
                .is_some()
            {
                return Ok(PreparedFaultWork::None);
            }
            if vmo_kind != VmoKind::Anonymous {
                return Err(ZX_ERR_BAD_STATE);
            }
            update_fault_telemetry(fault_table, |table| {
                table.record_prepare(FaultPrepareKind::LazyVmoAlloc);
            });
            let new_frame_paddr =
                crate::userspace::alloc_bootstrap_zeroed_page().ok_or(ZX_ERR_NO_MEMORY)?;
            Ok(PreparedFaultWork::NewPage {
                paddr: new_frame_paddr,
            })
        }
    }
}

pub(crate) fn ensure_user_page_resident_serialized(
    vm_handle: Arc<Mutex<VmDomain>>,
    fault_handle: Arc<Mutex<FaultTable>>,
    address_space_id: AddressSpaceId,
    page_va: u64,
    for_write: bool,
) -> Result<(), zx_status_t> {
    let global_vmo_store = clone_global_vmo_store(&vm_handle);
    loop {
        let plan = {
            let vm = vm_handle.lock();
            vm.plan_resident_fault(address_space_id, page_va, for_write)?
        };
        match plan {
            FaultPlanResult::Satisfied => {
                let vm = vm_handle.lock();
                vm.sync_mapping_pages(
                    address_space_id,
                    align_down_page(page_va),
                    crate::userspace::USER_PAGE_BYTES,
                )?;
                return Ok(());
            }
            FaultPlanResult::Unhandled => return Err(ZX_ERR_BAD_STATE),
            FaultPlanResult::Ready(plan) => {
                let claim = claim_fault(&fault_handle, plan.key());
                match claim {
                    FaultClaim::Leader => {
                        let guard = FaultLeaderGuard::new(fault_handle.clone(), plan.key());
                        let mut prepared =
                            prepare_fault_work(plan, &fault_handle, &global_vmo_store)?;
                        let outcome = {
                            let mut vm = vm_handle.lock();
                            vm.commit_prepared_fault(plan, &mut prepared)
                        };
                        prepared.release_unused();
                        guard.complete();
                        match outcome? {
                            FaultCommitDisposition::Resolved => {
                                update_fault_telemetry(&fault_handle, |table| {
                                    table.record_commit_resolved();
                                });
                                return Ok(());
                            }
                            FaultCommitDisposition::Retry => {
                                update_fault_telemetry(&fault_handle, |table| {
                                    table.record_commit_retry();
                                });
                                continue;
                            }
                        }
                    }
                    FaultClaim::Wait(wait) => {
                        wait_for_fault_completion(&fault_handle, wait);
                        continue;
                    }
                }
            }
        }
    }
}

pub(crate) fn handle_page_fault_serialized(
    kernel_handle: Arc<Mutex<Kernel>>,
    vm_handle: Arc<Mutex<VmDomain>>,
    fault_handle: Arc<Mutex<FaultTable>>,
    address_space_id: AddressSpaceId,
    thread_id: ThreadId,
    fault_va: u64,
    error: u64,
) -> PageFaultSerializedResult {
    let global_vmo_store = clone_global_vmo_store(&vm_handle);
    loop {
        let plan = {
            let vm = vm_handle.lock();
            vm.plan_trap_fault(address_space_id, fault_va, error)
        };
        match plan {
            FaultPlanResult::Satisfied => {
                let vm = vm_handle.lock();
                return if vm
                    .sync_mapping_pages(
                        address_space_id,
                        align_down_page(fault_va),
                        crate::userspace::USER_PAGE_BYTES,
                    )
                    .is_ok()
                {
                    PageFaultSerializedResult::Handled
                } else {
                    PageFaultSerializedResult::Unhandled
                };
            }
            FaultPlanResult::Unhandled => return PageFaultSerializedResult::Unhandled,
            FaultPlanResult::Ready(plan) => {
                let claim = claim_blocking_fault(&fault_handle, plan.key(), thread_id);
                match claim {
                    FaultBlockingClaim::Leader => {
                        if should_pause_fault_leader_for_test() {
                            pause_fault_leader_for_test(&fault_handle, plan.key(), thread_id);
                            return PageFaultSerializedResult::BlockCurrent {
                                key: plan.key(),
                                wake_thread: None,
                            };
                        }
                        let key = plan.key();
                        let guard = FaultLeaderGuard::new(fault_handle.clone(), key);
                        let mut prepared =
                            match prepare_fault_work(plan, &fault_handle, &global_vmo_store) {
                                Ok(prepared) => prepared,
                                Err(_) => return PageFaultSerializedResult::Unhandled,
                            };
                        let outcome = {
                            let mut vm = vm_handle.lock();
                            vm.commit_prepared_fault(plan, &mut prepared)
                        };
                        prepared.release_unused();
                        let waiters = guard.complete();
                        wake_fault_waiters(&kernel_handle, waiters);
                        match outcome {
                            Ok(FaultCommitDisposition::Resolved) => {
                                update_fault_telemetry(&fault_handle, |table| {
                                    table.record_commit_resolved();
                                });
                                return PageFaultSerializedResult::Handled;
                            }
                            Ok(FaultCommitDisposition::Retry) => {
                                update_fault_telemetry(&fault_handle, |table| {
                                    table.record_commit_retry();
                                });
                                continue;
                            }
                            Err(_) => return PageFaultSerializedResult::Unhandled,
                        }
                    }
                    FaultBlockingClaim::LeaderResume => {
                        let key = plan.key();
                        let guard = FaultLeaderGuard::new(fault_handle.clone(), key);
                        let mut prepared =
                            match prepare_fault_work(plan, &fault_handle, &global_vmo_store) {
                                Ok(prepared) => prepared,
                                Err(_) => return PageFaultSerializedResult::Unhandled,
                            };
                        let outcome = {
                            let mut vm = vm_handle.lock();
                            vm.commit_prepared_fault(plan, &mut prepared)
                        };
                        prepared.release_unused();
                        let waiters = guard.complete();
                        wake_fault_waiters(&kernel_handle, waiters);
                        match outcome {
                            Ok(FaultCommitDisposition::Resolved) => {
                                update_fault_telemetry(&fault_handle, |table| {
                                    table.record_commit_resolved();
                                });
                                return PageFaultSerializedResult::Handled;
                            }
                            Ok(FaultCommitDisposition::Retry) => {
                                update_fault_telemetry(&fault_handle, |table| {
                                    table.record_commit_retry();
                                });
                                continue;
                            }
                            Err(_) => return PageFaultSerializedResult::Unhandled,
                        }
                    }
                    FaultBlockingClaim::Wait { wake_leader } => {
                        return PageFaultSerializedResult::BlockCurrent {
                            key: plan.key(),
                            wake_thread: wake_leader,
                        };
                    }
                }
            }
        }
    }
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
            page_tables: crate::page_table::UserPageTables::clone_current_kernel_template()
                .map_err(map_page_table_error)?,
            active_cpu_mask: 0,
            observed_tlb_epoch: [0; MAX_TRACKED_TLB_CPUS],
            vm_resources: VmResourceState::new(),
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

    fn register_global_vmo_from_address_space(
        &mut self,
        address_space_id: AddressSpaceId,
        global_vmo_id: KernelVmoId,
    ) -> Result<(), zx_status_t> {
        let snapshot = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.snapshot_vmo(global_vmo_id))
            .ok_or(ZX_ERR_BAD_STATE)?;
        self.global_vmos
            .lock()
            .register_snapshot(global_vmo_id, &snapshot);
        Ok(())
    }

    fn register_empty_global_vmo(
        &mut self,
        global_vmo_id: KernelVmoId,
        kind: VmoKind,
        size_bytes: u64,
    ) -> Result<(), zx_status_t> {
        self.global_vmos
            .lock()
            .register_empty(global_vmo_id, kind, size_bytes)
    }

    fn import_global_vmo_into_address_space(
        &mut self,
        address_space_id: AddressSpaceId,
        global_vmo_id: KernelVmoId,
    ) -> Result<VmoId, zx_status_t> {
        let global_vmo = self.global_vmos.lock().snapshot(global_vmo_id)?;
        let address_space = self
            .address_spaces
            .get_mut(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let local_vmo_id = address_space
            .import_vmo_alias(global_vmo.kind, global_vmo.size_bytes, global_vmo_id)
            .map_err(map_address_space_error)?;
        for (page_index, frame_id) in global_vmo.frames.iter().copied().enumerate() {
            let Some(frame_id) = frame_id else {
                continue;
            };
            address_space
                .set_vmo_frame(
                    local_vmo_id,
                    (page_index as u64) * crate::userspace::USER_PAGE_BYTES,
                    frame_id,
                )
                .map_err(map_address_space_error)?;
        }
        Ok(local_vmo_id)
    }

    fn update_global_vmo_frame(
        &mut self,
        global_vmo_id: KernelVmoId,
        offset: u64,
        frame_id: FrameId,
    ) -> Result<(), zx_status_t> {
        self.global_vmos
            .lock()
            .update_frame(global_vmo_id, offset, frame_id)
    }

    fn global_vmo_frame(
        &self,
        global_vmo_id: KernelVmoId,
        offset: u64,
    ) -> Result<Option<FrameId>, zx_status_t> {
        self.global_vmos.lock().frame(global_vmo_id, offset)
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

    fn try_reserve_private_cow_page(
        &mut self,
        address_space_id: AddressSpaceId,
        page_base: u64,
    ) -> Result<bool, zx_status_t> {
        let reservation = {
            let address_space = self
                .address_spaces
                .get_mut(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            address_space.try_reserve_private_cow_page(page_base)
        };
        match reservation {
            Ok(reserved) => Ok(reserved),
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

    fn try_reserve_inflight_loan_pages(
        &mut self,
        address_space_id: AddressSpaceId,
        pages: u64,
    ) -> Result<(), zx_status_t> {
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

    fn publish_address_space_frame_to_global_vmo(
        &mut self,
        address_space_id: AddressSpaceId,
        fault_va: u64,
        frame_id: FrameId,
    ) -> Result<(), zx_status_t> {
        let lookup = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.lookup_user_mapping(fault_va, 1))
            .ok_or(ZX_ERR_BAD_STATE)?;
        let page_offset = lookup
            .vmo_offset()
            .checked_sub(lookup.vmo_offset() % crate::userspace::USER_PAGE_BYTES)
            .ok_or(ZX_ERR_BAD_STATE)?;
        self.update_global_vmo_frame(lookup.global_vmo_id(), page_offset, frame_id)
    }

    fn ensure_global_vmo_frame(
        &mut self,
        global_vmo_id: KernelVmoId,
        page_offset: u64,
        prepared: &mut PreparedFaultWork,
    ) -> Result<FrameId, zx_status_t> {
        if let Some(frame_id) = self.global_vmo_frame(global_vmo_id, page_offset)? {
            return Ok(frame_id);
        }
        let new_frame_paddr = prepared.take_page_paddr().ok_or(ZX_ERR_BAD_STATE)?;
        let new_frame_id = self.with_frames_mut(|frames| {
            frames
                .register_existing(new_frame_paddr)
                .map_err(|_| ZX_ERR_BAD_STATE)
        })?;
        self.update_global_vmo_frame(global_vmo_id, page_offset, new_frame_id)?;
        Ok(new_frame_id)
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

    pub(crate) fn create_anonymous_vmo_for_address_space(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<CreatedVmo, zx_status_t> {
        self.register_empty_global_vmo(global_vmo_id, VmoKind::Anonymous, size)?;
        let local_vmo_id =
            match self.import_global_vmo_into_address_space(address_space_id, global_vmo_id) {
                Ok(vmo_id) => vmo_id,
                Err(err) => {
                    let _ = self.global_vmos.lock().remove(global_vmo_id);
                    return Err(err);
                }
            };
        let vmo = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.vm.vmo(local_vmo_id))
            .cloned()
            .ok_or(ZX_ERR_BAD_STATE)?;
        Ok(CreatedVmo {
            process_id,
            address_space_id,
            vmo,
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
    ) -> Result<(), zx_status_t> {
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
        Ok(())
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

        if lookup.vmo_kind() != VmoKind::Anonymous {
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

        self.with_frames_mut(|frames| frames.pin_and_inc_loan_many(&resident_pages))
            .map_err(|_| ZX_ERR_BAD_STATE)?;
        let pinned = resident_pages;
        self.try_reserve_inflight_loan_pages(
            address_space_id,
            u64::try_from(page_count).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
        )
        .inspect_err(|_| self.release_pinned_loan_frames(&pinned))?;

        let len_u32 = u32::try_from(len).map_err(|_| {
            self.release_loaned_pages_inner(address_space_id, &pinned);
            ZX_ERR_OUT_OF_RANGE
        })?;
        Ok(Some(LoanedUserPages {
            address_space_id,
            receiver_address_space_id: None,
            base: ptr,
            len: len_u32,
            needs_cow: lookup.max_perms().contains(MappingPerms::WRITE),
            pages: pinned,
        }))
    }

    pub(crate) fn release_loaned_user_pages(&mut self, loaned: &LoanedUserPages) {
        self.release_loaned_pages_inner(loaned.address_space_id(), loaned.pages())
    }

    pub(crate) fn prepare_loaned_channel_write(
        &mut self,
        loaned: &mut LoanedUserPages,
        receiver_address_space_id: AddressSpaceId,
    ) -> Result<(), zx_status_t> {
        if !loaned.needs_cow() {
            loaned.bind_receiver_address_space(receiver_address_space_id);
            return Ok(());
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
        loan_tx.commit().map_err(map_page_table_error)
    }

    pub(crate) fn try_remap_loaned_channel_read(
        &mut self,
        current_address_space_id: AddressSpaceId,
        dst_base: u64,
        loaned: &LoanedUserPages,
    ) -> Result<bool, zx_status_t> {
        let Some(receiver_address_space_id) = loaned.receiver_address_space_id() else {
            return Ok(false);
        };

        let len = u64::from(loaned.len());
        if len == 0
            || (dst_base & (crate::userspace::USER_PAGE_BYTES - 1)) != 0
            || (len & (crate::userspace::USER_PAGE_BYTES - 1)) != 0
        {
            return Ok(false);
        }
        if current_address_space_id != receiver_address_space_id {
            return Ok(false);
        }

        let receiver_lookup = self
            .address_spaces
            .get(&receiver_address_space_id)
            .and_then(|space| space.lookup_user_mapping(dst_base, len as usize));
        let Some(receiver_lookup) = receiver_lookup else {
            return Ok(false);
        };
        if receiver_lookup.mapping_base() != dst_base
            || receiver_lookup.mapping_len() != len
            || receiver_lookup.vmo_kind() != VmoKind::Anonymous
            || !receiver_lookup.max_perms().contains(MappingPerms::WRITE)
        {
            return Ok(false);
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
                return Ok(false);
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
        Ok(true)
    }

    pub(crate) fn map_vmo_into_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        cpu_id: usize,
        vmar_id: VmarId,
        global_vmo_id: KernelVmoId,
        fixed_vmar_offset: Option<u64>,
        vmo_offset: u64,
        len: u64,
        perms: MappingPerms,
    ) -> Result<u64, zx_status_t> {
        let local_vmo_id =
            self.import_global_vmo_into_address_space(address_space_id, global_vmo_id)?;
        let frames_handle = self.frame_table();
        let mapped_addr = {
            let address_space = self
                .address_spaces
                .get_mut(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            match fixed_vmar_offset {
                Some(vmar_offset) => {
                    let vmar = address_space.vmar(vmar_id).ok_or(ZX_ERR_NOT_FOUND)?;
                    let mapped_addr = vmar
                        .base()
                        .checked_add(vmar_offset)
                        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
                    {
                        let mut frames = frames_handle.lock();
                        address_space
                            .map_vmo_fixed(
                                &mut frames,
                                vmar_id,
                                mapped_addr,
                                len,
                                local_vmo_id,
                                vmo_offset,
                                perms,
                            )
                            .map_err(map_address_space_error)?;
                    }
                    mapped_addr
                }
                None => {
                    let _ = address_space.vmar(vmar_id).ok_or(ZX_ERR_NOT_FOUND)?;
                    let mut frames = frames_handle.lock();
                    address_space
                        .map_vmo_anywhere(
                            &mut frames,
                            cpu_id,
                            vmar_id,
                            len,
                            local_vmo_id,
                            vmo_offset,
                            perms,
                        )
                        .map_err(map_address_space_error)?
                }
            }
        };
        self.install_mapping_pages(address_space_id, mapped_addr, len)?;
        Ok(mapped_addr)
    }

    pub(crate) fn unmap_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        addr: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
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
        Ok(())
    }

    pub(crate) fn protect_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        addr: u64,
        len: u64,
        perms: MappingPerms,
    ) -> Result<(), zx_status_t> {
        let address_space = self
            .address_spaces
            .get_mut(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let _ = address_space.vmar(vmar_id).ok_or(ZX_ERR_NOT_FOUND)?;
        address_space
            .protect(vmar_id, addr, len, perms)
            .map_err(map_address_space_error)?;
        self.update_mapping_pages(address_space_id, addr, len)
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
        if lookup.vmo_kind() != VmoKind::Anonymous {
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
    ) -> Result<FaultCommitDisposition, zx_status_t> {
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
                    return Ok(FaultCommitDisposition::Resolved);
                }
                let lookup = self
                    .address_spaces
                    .get(&address_space_id)
                    .and_then(|space| space.lookup_user_mapping(page_base, 1))
                    .ok_or(ZX_ERR_BAD_STATE)?;
                if lookup.vmo_kind() != VmoKind::Anonymous
                    || lookup.frame_id() != Some(old_frame_id)
                {
                    return Ok(FaultCommitDisposition::Retry);
                }
                let meta = self
                    .address_spaces
                    .get(&address_space_id)
                    .and_then(|space| space.page_meta(page_base))
                    .ok_or(ZX_ERR_BAD_STATE)?;
                if !meta.cow_shared() {
                    return Ok(FaultCommitDisposition::Retry);
                }
                let reserve_private =
                    self.try_reserve_private_cow_page(address_space_id, page_base)?;
                let new_frame_paddr = prepared.take_page_paddr().ok_or(ZX_ERR_BAD_STATE)?;
                let resolved = self.with_address_space_frames_mut(
                    address_space_id,
                    |address_space, frames| {
                        let new_frame_id = frames
                            .register_existing(new_frame_paddr)
                            .map_err(|_| ZX_ERR_BAD_STATE)?;
                        address_space
                            .resolve_cow_fault(frames, page_base, new_frame_id)
                            .map_err(map_address_space_error)
                    },
                )?;
                self.publish_address_space_frame_to_global_vmo(
                    address_space_id,
                    resolved.fault_page_base(),
                    resolved.new_frame_id(),
                )?;
                self.sync_mapping_pages(
                    address_space_id,
                    resolved.fault_page_base(),
                    crate::userspace::USER_PAGE_BYTES,
                )?;
                if reserve_private {
                    self.commit_private_cow_page(address_space_id, resolved.fault_page_base());
                }
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
                Ok(FaultCommitDisposition::Resolved)
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
                    return Ok(FaultCommitDisposition::Resolved);
                }
                let meta = self
                    .address_spaces
                    .get(&address_space_id)
                    .and_then(|space| space.page_meta(page_base))
                    .ok_or(ZX_ERR_BAD_STATE)?;
                if meta.tag() != PteMetaTag::LazyAnon {
                    return Ok(FaultCommitDisposition::Retry);
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
                self.publish_address_space_frame_to_global_vmo(
                    address_space_id,
                    resolved.fault_page_base(),
                    resolved.new_frame_id(),
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
                Ok(FaultCommitDisposition::Resolved)
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
                    return Ok(FaultCommitDisposition::Resolved);
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
                    return Ok(FaultCommitDisposition::Retry);
                }
                let meta = self
                    .address_spaces
                    .get(&address_space_id)
                    .and_then(|space| space.page_meta(page_base))
                    .ok_or(ZX_ERR_BAD_STATE)?;
                if meta.tag() != PteMetaTag::LazyVmo {
                    return Ok(FaultCommitDisposition::Retry);
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
                Ok(FaultCommitDisposition::Resolved)
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
        crate::arch::tlb::flush_all_local();
        address_space.observe_tlb_epoch(cpu_id, target_epoch);
        Ok(())
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
                    let mapping = PageMapping::new(
                        frame_id.raw(),
                        lookup.perms().contains(MappingPerms::WRITE),
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
        let reserve_private =
            self.try_reserve_private_cow_page(address_space_id, fault_page_base)?;
        let lookup = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.lookup_user_mapping(fault_va, 1))
            .ok_or(ZX_ERR_BAD_STATE)?;
        if lookup.vmo_kind() != VmoKind::Anonymous {
            return Err(ZX_ERR_BAD_STATE);
        }
        let old_frame_id = lookup.frame_id().ok_or(ZX_ERR_BAD_STATE)?;
        let new_frame_paddr = crate::userspace::alloc_bootstrap_cow_page(old_frame_id.raw())
            .ok_or(ZX_ERR_NO_MEMORY)?;
        let resolved =
            self.with_address_space_frames_mut(address_space_id, |address_space, frames| {
                let new_frame_id = frames
                    .register_existing(new_frame_paddr)
                    .map_err(|_| ZX_ERR_BAD_STATE)?;
                address_space
                    .resolve_cow_fault(frames, fault_va, new_frame_id)
                    .map_err(map_address_space_error)
            })?;
        self.publish_address_space_frame_to_global_vmo(
            address_space_id,
            resolved.fault_page_base(),
            resolved.new_frame_id(),
        )?;
        self.sync_mapping_pages(
            address_space_id,
            resolved.fault_page_base(),
            crate::userspace::USER_PAGE_BYTES,
        )?;
        if reserve_private {
            self.commit_private_cow_page(address_space_id, resolved.fault_page_base());
        }
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
        self.publish_address_space_frame_to_global_vmo(
            address_space_id,
            resolved.fault_page_base(),
            resolved.new_frame_id(),
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

    fn release_pinned_loan_frames(&mut self, pages: &[FrameId]) {
        self.with_frames_mut(|frames| frames.dec_loan_and_unpin_many(pages));
    }

    fn release_loaned_pages_inner(&mut self, address_space_id: AddressSpaceId, pages: &[FrameId]) {
        self.release_pinned_loan_frames(pages);
        self.release_inflight_loan_pages(
            address_space_id,
            u64::try_from(pages.len()).unwrap_or(u64::MAX),
        );
        self.validate_frame_mapping_invariants_for(pages, "release_loaned_pages_inner");
    }
}

fn push_unique_frame_id(frames: &mut Vec<FrameId>, frame_id: FrameId) {
    if !frames.contains(&frame_id) {
        frames.push(frame_id);
    }
}

fn merge_page_ranges(left: PageRange, right: PageRange) -> Result<PageRange, PageTableError> {
    let base = left.base().min(right.base());
    let end = left.end().max(right.end());
    let len = end.checked_sub(base).ok_or(PageTableError::InvalidArgs)?;
    PageRange::new(base, len)
}

fn map_alloc_error(err: CSpaceError) -> zx_status_t {
    match err {
        CSpaceError::NoSlots => ZX_ERR_NO_RESOURCES,
        CSpaceError::Handle(_) => ZX_ERR_INTERNAL,
        CSpaceError::BadHandle => ZX_ERR_BAD_HANDLE,
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

fn map_page_table_error(err: PageTableError) -> zx_status_t {
    match err {
        PageTableError::InvalidArgs => ZX_ERR_INVALID_ARGS,
        PageTableError::NotMapped | PageTableError::Backend => ZX_ERR_BAD_STATE,
    }
}

fn align_down_page(value: u64) -> u64 {
    value & !(crate::userspace::USER_PAGE_BYTES - 1)
}
