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
use axle_core::{
    CSpace, CSpaceError, Capability, ObjectKey, ObserverRegistry, ReactorTimerCore,
    ReactorTimerEvent, RevocationManager, Signals, TimerError, TimerId, TransferredCap,
    WaitDeadlineId,
};
use axle_mm::{
    AddressSpace as VmAddressSpace, AddressSpaceError, AddressSpaceId as VmAddressSpaceId,
    CowFaultResolution, FrameId, FrameTable, FutexKey, GlobalVmoId, LazyAnonFaultResolution,
    LazyVmoFaultResolution, LoanToken, MapRec, MappingPerms, PageFaultDecision, PageFaultFlags,
    PteMeta, PteMetaTag, ReverseMapAnchor, VmaLookup, Vmar, VmarAllocMode, VmarId,
    VmarPlacementPolicy, Vmo, VmoId, VmoKind,
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

pub(crate) mod fault;

use fault::{FaultCommitDisposition, FaultPlan, FaultPlanResult, PreparedFaultWork};
pub(crate) use fault::{FaultInFlightKey, FaultTable};

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
pub(crate) type AddressSpaceId = u64;
type KernelVmoId = GlobalVmoId;

/// TLB synchronization class attached to one committed VM mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitClass {
    Relaxed,
    Strict,
}

/// Post-commit TLB synchronization requirement for one address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TlbCommitReq {
    address_space_id: AddressSpaceId,
    class: CommitClass,
}

impl TlbCommitReq {
    pub(crate) const fn relaxed(address_space_id: AddressSpaceId) -> Self {
        Self {
            address_space_id,
            class: CommitClass::Relaxed,
        }
    }

    pub(crate) const fn strict(address_space_id: AddressSpaceId) -> Self {
        Self {
            address_space_id,
            class: CommitClass::Strict,
        }
    }

    pub(crate) const fn address_space_id(self) -> AddressSpaceId {
        self.address_space_id
    }

    pub(crate) const fn class(self) -> CommitClass {
        self.class
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
    local_needs_flush: bool,
    remote_cpus: Vec<usize>,
}

static BOOTSTRAP_USER_RUNNER_SOURCE: Mutex<Option<PagerSourceHandle>> = Mutex::new(None);

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
        debug_assert!(
            !matches!(self.state, CowReservationState::Reserved),
            "CowReservation dropped without explicit commit or release"
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrapExitDisposition {
    Complete,
    BlockCurrent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitRegistration {
    Sleep,
    Futex {
        key: FutexKey,
        owner_koid: zx_koid_t,
    },
    Signal {
        object_key: ObjectKey,
        watched: Signals,
        observed_ptr: u64,
    },
    Port {
        port_object: ObjectKey,
        packet_ptr: u64,
    },
    VmFault {
        key: FaultInFlightKey,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitSourceKey {
    Signals(ObjectKey),
    PortReadable(ObjectKey),
    Futex(FutexKey),
    Fault(FaultInFlightKey),
    None,
}

impl WaitRegistration {
    const fn source_key(self) -> WaitSourceKey {
        match self {
            Self::Sleep => WaitSourceKey::None,
            Self::Futex { key, .. } => WaitSourceKey::Futex(key),
            Self::Signal { object_key, .. } => WaitSourceKey::Signals(object_key),
            Self::Port { port_object, .. } => WaitSourceKey::PortReadable(port_object),
            Self::VmFault { key } => WaitSourceKey::Fault(key),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct WaitNode {
    seq: u64,
    registration: Option<WaitRegistration>,
    deadline: Option<i64>,
}

impl WaitNode {
    fn arm(&mut self, registration: WaitRegistration, deadline: Option<i64>) -> u64 {
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.seq = 1;
        }
        self.registration = Some(registration);
        self.deadline = deadline;
        self.seq
    }

    fn clear(&mut self) {
        self.registration = None;
        self.deadline = None;
    }
}

#[derive(Debug)]
pub(crate) struct Reactor {
    observers: ObserverRegistry,
    signal_waiters: BTreeMap<ObjectKey, VecDeque<ThreadId>>,
    port_waiters: BTreeMap<ObjectKey, VecDeque<ThreadId>>,
    timers: ReactorTimerCore,
}

impl Reactor {
    pub(crate) fn new(cpu_count: usize) -> Self {
        Self {
            observers: ObserverRegistry::new(),
            signal_waiters: BTreeMap::new(),
            port_waiters: BTreeMap::new(),
            timers: ReactorTimerCore::new(cpu_count),
        }
    }

    pub(crate) fn observers(&self) -> &ObserverRegistry {
        &self.observers
    }

    pub(crate) fn observers_mut(&mut self) -> &mut ObserverRegistry {
        &mut self.observers
    }

    pub(crate) fn remove_port(&mut self, port_key: ObjectKey) {
        self.observers.remove_port(port_key);
        let _ = self.port_waiters.remove(&port_key);
    }

    pub(crate) fn remove_waitable(&mut self, waitable_key: ObjectKey) {
        self.observers.remove_waitable(waitable_key);
        let _ = self.signal_waiters.remove(&waitable_key);
    }

    fn push_signal_waiter(&mut self, object_key: ObjectKey, thread_id: ThreadId) {
        self.signal_waiters
            .entry(object_key)
            .or_default()
            .push_back(thread_id);
    }

    fn remove_signal_waiter(&mut self, object_key: ObjectKey, thread_id: ThreadId) {
        let should_remove = if let Some(waiters) = self.signal_waiters.get_mut(&object_key) {
            waiters.retain(|waiter| *waiter != thread_id);
            waiters.is_empty()
        } else {
            false
        };
        if should_remove {
            let _ = self.signal_waiters.remove(&object_key);
        }
    }

    fn push_port_waiter(&mut self, port_object: ObjectKey, thread_id: ThreadId) {
        self.port_waiters
            .entry(port_object)
            .or_default()
            .push_back(thread_id);
    }

    fn remove_port_waiter(&mut self, port_object: ObjectKey, thread_id: ThreadId) {
        let should_remove = if let Some(waiters) = self.port_waiters.get_mut(&port_object) {
            waiters.retain(|waiter| *waiter != thread_id);
            waiters.is_empty()
        } else {
            false
        };
        if should_remove {
            let _ = self.port_waiters.remove(&port_object);
        }
    }

    fn enqueue_wait_source(&mut self, thread_id: ThreadId, registration: WaitRegistration) {
        match registration {
            WaitRegistration::Signal { object_key, .. } => {
                self.push_signal_waiter(object_key, thread_id)
            }
            WaitRegistration::Port { port_object, .. } => {
                self.push_port_waiter(port_object, thread_id)
            }
            WaitRegistration::Sleep
            | WaitRegistration::Futex { .. }
            | WaitRegistration::VmFault { .. } => {}
        }
    }

    fn remove_wait_source_membership(
        &mut self,
        thread_id: ThreadId,
        registration: WaitRegistration,
    ) {
        match registration {
            WaitRegistration::Signal { object_key, .. } => {
                self.remove_signal_waiter(object_key, thread_id)
            }
            WaitRegistration::Port { port_object, .. } => {
                self.remove_port_waiter(port_object, thread_id)
            }
            WaitRegistration::Sleep
            | WaitRegistration::Futex { .. }
            | WaitRegistration::VmFault { .. } => {}
        }
    }

    fn cancel_wait_deadline(&mut self, thread_id: ThreadId, seq: u64) {
        self.timers
            .cancel_wait_deadline(WaitDeadlineId::new(thread_id, seq));
    }

    fn arm_wait_deadline(&mut self, cpu_id: usize, thread_id: ThreadId, seq: u64, deadline: i64) {
        self.timers
            .arm_wait_deadline(cpu_id, WaitDeadlineId::new(thread_id, seq), deadline);
    }

    fn signal_waiter_thread_ids(&self, object_key: ObjectKey) -> Vec<ThreadId> {
        self.signal_waiters
            .get(&object_key)
            .map(|waiters| waiters.iter().copied().collect())
            .unwrap_or_default()
    }

    fn port_waiter_thread_ids(&self, port_object: ObjectKey) -> Vec<ThreadId> {
        self.port_waiters
            .get(&port_object)
            .map(|waiters| waiters.iter().copied().collect())
            .unwrap_or_default()
    }

    pub(crate) fn create_timer_object(&mut self) -> TimerId {
        self.timers.create_timer()
    }

    pub(crate) fn destroy_timer_object(&mut self, timer_id: TimerId) -> Result<(), TimerError> {
        self.timers.remove_timer(timer_id)
    }

    pub(crate) fn set_timer_object(
        &mut self,
        timer_id: TimerId,
        cpu_id: usize,
        deadline: i64,
        now: i64,
    ) -> Result<bool, TimerError> {
        self.timers.set_timer(timer_id, cpu_id, deadline, now)
    }

    pub(crate) fn cancel_timer_object(&mut self, timer_id: TimerId) -> Result<(), TimerError> {
        self.timers.cancel_timer(timer_id)
    }

    pub(crate) fn timer_object_signaled(&self, timer_id: TimerId) -> Result<bool, TimerError> {
        self.timers.is_timer_signaled(timer_id)
    }

    pub(crate) fn poll(&mut self, current_cpu_id: usize, now: i64) -> Vec<ReactorTimerEvent> {
        if crate::arch::timer::ticks_all_cpus() {
            self.timers.poll_slot(current_cpu_id, now)
        } else {
            self.timers.poll_all(now)
        }
    }
}

#[derive(Debug)]
pub(crate) struct VmFacade {
    domain: Arc<Mutex<VmDomain>>,
    faults: Arc<Mutex<FaultTable>>,
}

impl VmFacade {
    pub(crate) fn bootstrap() -> (Arc<Self>, AddressSpaceId) {
        let bootstrap_layout = crate::userspace::bootstrap_process_image_layout()
            .unwrap_or_else(ProcessImageLayout::bootstrap_conformance);
        let bootstrap_loaded_layout = bootstrap_layout
            .rebased_for_loaded_image()
            .unwrap_or_else(|_| ProcessImageLayout::bootstrap_conformance());
        let mut vm = VmDomain {
            address_spaces: BTreeMap::new(),
            global_vmos: Arc::new(Mutex::new(GlobalVmoStore::default())),
            bootstrap_user_runner_global_vmo_id: None,
            bootstrap_user_code_global_vmo_id: None,
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
            AddressSpace::bootstrap(
                address_space_id,
                &mut frames,
                bootstrap_vmo_ids,
                &bootstrap_loaded_layout,
            )
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
        let bootstrap_code_global_vmo_id = vm.alloc_global_vmo_id();
        vm.register_pager_file_global_vmo(
            bootstrap_code_global_vmo_id,
            crate::userspace::USER_CODE_BYTES,
            crate::userspace::read_bootstrap_user_code_image_at,
        )
        .expect("bootstrap code pager vmo registration must succeed");
        vm.bootstrap_user_code_global_vmo_id = Some(bootstrap_code_global_vmo_id);
        if let Some(size_bytes) = crate::userspace::qemu_loader_user_runner_size() {
            let global_vmo_id = vm.alloc_global_vmo_id();
            let source = PagerSourceHandle::new(FilePagerSource {
                size_bytes,
                read_at: crate::userspace::read_qemu_loader_user_runner_at,
            });
            vm.register_pager_source_handle(global_vmo_id, source.clone())
                .expect("bootstrap runner pager vmo registration must succeed");
            vm.bootstrap_user_runner_global_vmo_id = Some(global_vmo_id);
            *BOOTSTRAP_USER_RUNNER_SOURCE.lock() = Some(source);
        }

        (
            Arc::new(Self {
                domain: Arc::new(Mutex::new(vm)),
                faults: Arc::new(Mutex::new(FaultTable::default())),
            }),
            address_space_id,
        )
    }

    pub(crate) fn domain_handle(&self) -> Arc<Mutex<VmDomain>> {
        self.domain.clone()
    }

    pub(crate) fn fault_handle(&self) -> Arc<Mutex<FaultTable>> {
        self.faults.clone()
    }

    pub(crate) fn with_domain<T>(&self, f: impl FnOnce(&VmDomain) -> T) -> T {
        let domain = self.domain.lock();
        f(&domain)
    }

    pub(crate) fn with_domain_mut<T>(&self, f: impl FnOnce(&mut VmDomain) -> T) -> T {
        let mut domain = self.domain.lock();
        f(&mut domain)
    }

    pub(crate) fn validate_user_ptr(
        &self,
        address_space_id: AddressSpaceId,
        ptr: u64,
        len: usize,
    ) -> bool {
        self.with_domain(|vm| vm.validate_user_ptr(address_space_id, ptr, len))
    }

    pub(crate) fn try_loan_user_pages(
        &self,
        address_space_id: AddressSpaceId,
        ptr: u64,
        len: usize,
    ) -> Result<Option<LoanedUserPages>, zx_status_t> {
        self.with_domain_mut(|vm| vm.try_loan_user_pages(address_space_id, ptr, len))
    }

    pub(crate) fn release_loaned_user_pages(&self, loaned: LoanedUserPages) {
        self.with_domain_mut(|vm| vm.release_loaned_user_pages(loaned));
    }

    pub(crate) fn prepare_loaned_channel_write(
        &self,
        loaned: &mut LoanedUserPages,
        receiver_address_space_id: AddressSpaceId,
    ) -> Result<TlbCommitReq, zx_status_t> {
        self.with_domain_mut(|vm| {
            vm.prepare_loaned_channel_write(loaned, receiver_address_space_id)
        })
    }

    pub(crate) fn try_remap_loaned_channel_read(
        &self,
        address_space_id: AddressSpaceId,
        dst_base: u64,
        loaned: &LoanedUserPages,
    ) -> Result<LoanRemapResult, zx_status_t> {
        self.with_domain_mut(|vm| {
            vm.try_remap_loaned_channel_read(address_space_id, dst_base, loaned)
        })
    }

    pub(crate) fn import_bootstrap_process_image_for_address_space(
        &self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
    ) -> Result<ImportedProcessImage, zx_status_t> {
        self.with_domain_mut(|vm| {
            vm.import_bootstrap_process_image_for_address_space(process_id, address_space_id)
        })
    }

    pub(crate) fn apply_tlb_commit_reqs(
        &self,
        current_cpu_id: usize,
        current_address_space_id: Option<AddressSpaceId>,
        reqs: &[TlbCommitReq],
    ) -> Result<(), zx_status_t> {
        apply_tlb_commit_reqs(&self.domain, current_cpu_id, current_address_space_id, reqs)
    }

    pub(crate) fn retire_bootstrap_frames_after_quiescence(
        &self,
        current_cpu_id: usize,
        current_address_space_id: Option<AddressSpaceId>,
        barrier_address_spaces: &[AddressSpaceId],
        retired_frames: &[RetiredFrame],
    ) -> Result<(), zx_status_t> {
        retire_bootstrap_frames_after_quiescence(
            &self.domain,
            current_cpu_id,
            current_address_space_id,
            barrier_address_spaces,
            retired_frames,
        )
    }

    pub(crate) fn create_anonymous_vmo_for_address_space(
        &self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<CreatedVmo, zx_status_t> {
        self.with_domain_mut(|vm| {
            vm.create_anonymous_vmo_for_address_space(
                process_id,
                address_space_id,
                size,
                global_vmo_id,
            )
        })
    }

    pub(crate) fn create_pager_file_vmo_for_address_space(
        &self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
        size_bytes: u64,
        read_at: fn(u64, &mut [u8]) -> Result<(), zx_status_t>,
        global_vmo_id: KernelVmoId,
    ) -> Result<CreatedVmo, zx_status_t> {
        self.with_domain_mut(|vm| {
            vm.create_pager_file_vmo_for_address_space(
                process_id,
                address_space_id,
                size_bytes,
                read_at,
                global_vmo_id,
            )
        })
    }

    pub(crate) fn read_vmo_bytes(
        &self,
        vmo: &crate::object::VmoObject,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, zx_status_t> {
        self.with_domain(|vm| vm.read_vmo_bytes(vmo, offset, len))
    }

    pub(crate) fn write_vmo_bytes(
        &self,
        vmo: &crate::object::VmoObject,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), zx_status_t> {
        self.with_domain_mut(|vm| vm.write_vmo_bytes(vmo, offset, bytes))
    }

    pub(crate) fn set_vmo_size(
        &self,
        vmo: &crate::object::VmoObject,
        new_size: u64,
    ) -> Result<VmoResizeResult, zx_status_t> {
        self.with_domain_mut(|vm| vm.set_vmo_size(vmo, new_size))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn allocate_subvmar(
        &self,
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
        self.with_domain_mut(|vm| {
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
        &self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
    ) -> Result<TlbCommitReq, zx_status_t> {
        self.with_domain_mut(|vm| vm.destroy_vmar(address_space_id, vmar_id))
    }

    pub(crate) fn promote_vmo_object_to_shared(
        &self,
        vmo: &crate::object::VmoObject,
    ) -> Result<bool, zx_status_t> {
        self.with_domain_mut(|vm| vm.promote_vmo_object_to_shared(vmo))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn map_vmo_object_into_vmar(
        &self,
        address_space_id: AddressSpaceId,
        cpu_id: usize,
        vmar_id: VmarId,
        vmo: &crate::object::VmoObject,
        fixed_vmar_offset: Option<u64>,
        vmo_offset: u64,
        len: u64,
        perms: MappingPerms,
    ) -> Result<(u64, TlbCommitReq), zx_status_t> {
        self.with_domain_mut(|vm| {
            vm.map_vmo_object_into_vmar(
                address_space_id,
                cpu_id,
                vmar_id,
                vmo,
                fixed_vmar_offset,
                vmo_offset,
                len,
                perms,
            )
        })
    }

    pub(crate) fn unmap_vmar(
        &self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        addr: u64,
        len: u64,
    ) -> Result<TlbCommitReq, zx_status_t> {
        self.with_domain_mut(|vm| vm.unmap_vmar(address_space_id, vmar_id, addr, len))
    }

    pub(crate) fn protect_vmar(
        &self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        addr: u64,
        len: u64,
        perms: MappingPerms,
    ) -> Result<TlbCommitReq, zx_status_t> {
        self.with_domain_mut(|vm| vm.protect_vmar(address_space_id, vmar_id, addr, len, perms))
    }

    pub(crate) fn sync_current_cpu_tlb_state(
        &self,
        address_space_id: AddressSpaceId,
        cpu_id: usize,
    ) -> Result<(), zx_status_t> {
        self.with_domain_mut(|vm| vm.sync_current_cpu_tlb_state(address_space_id, cpu_id))
    }

    pub(crate) fn ensure_user_page_resident_serialized(
        &self,
        address_space_id: AddressSpaceId,
        page_va: u64,
        for_write: bool,
    ) -> Result<(), zx_status_t> {
        crate::task::fault::ensure_user_page_resident_serialized(
            self.domain.clone(),
            self.faults.clone(),
            address_space_id,
            page_va,
            for_write,
        )
    }

    pub(crate) fn handle_page_fault_serialized(
        &self,
        kernel_handle: Arc<Mutex<Kernel>>,
        address_space_id: AddressSpaceId,
        thread_id: ThreadId,
        fault_va: u64,
        error: u64,
    ) -> crate::task::fault::PageFaultSerializedResult {
        crate::task::fault::handle_page_fault_serialized(
            kernel_handle,
            self.domain.clone(),
            self.faults.clone(),
            address_space_id,
            thread_id,
            fault_va,
            error,
        )
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

#[repr(C)]
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

    pub(crate) fn to_guest_x64_regs(self) -> ax_guest_x64_regs_t {
        ax_guest_x64_regs_t {
            rax: self.trap.rax,
            rdi: self.trap.rdi,
            rsi: self.trap.rsi,
            rdx: self.trap.rdx,
            r10: self.trap.r10,
            r8: self.trap.r8,
            r9: self.trap.r9,
            rcx: self.trap.rcx,
            r11: self.trap.r11,
            rbx: self.trap.rbx,
            rbp: self.trap.rbp,
            r12: self.trap.r12,
            r13: self.trap.r13,
            r14: self.trap.r14,
            r15: self.trap.r15,
            rip: self.rip,
            rsp: self.rsp,
            rflags: self.rflags,
        }
    }

    pub(crate) fn with_guest_x64_regs(mut self, regs: ax_guest_x64_regs_t) -> Self {
        self.trap.rax = regs.rax;
        self.trap.rdi = regs.rdi;
        self.trap.rsi = regs.rsi;
        self.trap.rdx = regs.rdx;
        self.trap.r10 = regs.r10;
        self.trap.r8 = regs.r8;
        self.trap.r9 = regs.r9;
        self.trap.rcx = regs.rcx;
        self.trap.r11 = regs.r11;
        self.trap.rbx = regs.rbx;
        self.trap.rbp = regs.rbp;
        self.trap.r12 = regs.r12;
        self.trap.r13 = regs.r13;
        self.trap.r14 = regs.r14;
        self.trap.r15 = regs.r15;
        self.rip = regs.rip;
        self.rsp = regs.rsp;
        self.rflags = regs.rflags;
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
            rflags: 0x202,
            rsp: stack,
            ss: selectors.user_data.0 as u64,
        }
    }

    pub(crate) fn enter(self) -> ! {
        use x86_64::instructions::segmentation::{DS, ES, Segment};

        let selectors = crate::arch::gdt::init();
        // SAFETY: Axle installs the user data selector in the current GDT before entering ring3.
        unsafe {
            DS::set_reg(selectors.user_data);
            ES::set_reg(selectors.user_data);
        }

        // SAFETY: `UserContext` stores a complete ring3 register and IRET frame snapshot. The
        // entry helper restores those registers verbatim and finishes with `iretq`.
        unsafe {
            axle_enter_user_context(core::ptr::addr_of!(self));
        }
    }
}

core::arch::global_asm!(
    r#"
    .global axle_enter_user_context
    .type axle_enter_user_context, @function
axle_enter_user_context:
    push QWORD PTR [rdi + 152]
    push QWORD PTR [rdi + 144]
    push QWORD PTR [rdi + 136]
    push QWORD PTR [rdi + 128]
    push QWORD PTR [rdi + 120]

    mov rax, [rdi + 0]
    mov rsi, [rdi + 16]
    mov rdx, [rdi + 24]
    mov r10, [rdi + 32]
    mov r8, [rdi + 40]
    mov r9, [rdi + 48]
    mov rcx, [rdi + 56]
    mov r11, [rdi + 64]
    mov rbp, [rdi + 72]
    mov rbx, [rdi + 80]
    mov r12, [rdi + 88]
    mov r13, [rdi + 96]
    mov r14, [rdi + 104]
    mov r15, [rdi + 112]
    mov rdi, [rdi + 8]
    iretq
    .size axle_enter_user_context, .-axle_enter_user_context
    "#
);

unsafe extern "C" {
    fn axle_enter_user_context(context: *const UserContext) -> !;
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProcessImageSegment {
    vaddr: u64,
    vmo_offset: u64,
    file_size_bytes: u64,
    mem_size_bytes: u64,
    perms: MappingPerms,
}

impl ProcessImageSegment {
    pub(crate) const fn new(
        vaddr: u64,
        vmo_offset: u64,
        file_size_bytes: u64,
        mem_size_bytes: u64,
        perms: MappingPerms,
    ) -> Self {
        Self {
            vaddr,
            vmo_offset,
            file_size_bytes,
            mem_size_bytes,
            perms,
        }
    }

    pub(crate) const fn vaddr(self) -> u64 {
        self.vaddr
    }

    pub(crate) const fn vmo_offset(self) -> u64 {
        self.vmo_offset
    }

    pub(crate) const fn file_size_bytes(self) -> u64 {
        self.file_size_bytes
    }

    pub(crate) const fn mem_size_bytes(self) -> u64 {
        self.mem_size_bytes
    }

    pub(crate) const fn perms(self) -> MappingPerms {
        self.perms
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProcessImageElfInfo {
    phdr_vaddr: u64,
    phent: u16,
    phnum: u16,
}

impl ProcessImageElfInfo {
    pub(crate) const fn new(phdr_vaddr: u64, phent: u16, phnum: u16) -> Self {
        Self {
            phdr_vaddr,
            phent,
            phnum,
        }
    }

    pub(crate) const fn phdr_vaddr(self) -> u64 {
        self.phdr_vaddr
    }

    pub(crate) const fn phent(self) -> u16 {
        self.phent
    }

    pub(crate) const fn phnum(self) -> u16 {
        self.phnum
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessImageLayout {
    code_base: u64,
    code_size_bytes: u64,
    entry: u64,
    elf: Option<ProcessImageElfInfo>,
    segments: heapless::Vec<ProcessImageSegment, 16>,
}

impl ProcessImageLayout {
    pub(crate) fn bootstrap_conformance() -> Self {
        Self {
            code_base: crate::userspace::USER_CODE_VA,
            code_size_bytes: crate::userspace::USER_CODE_BYTES,
            entry: crate::userspace::USER_CODE_VA,
            elf: None,
            segments: heapless::Vec::new(),
        }
    }

    pub(crate) fn with_segments(
        code_base: u64,
        code_size_bytes: u64,
        entry: u64,
        segments: &[ProcessImageSegment],
    ) -> Result<Self, zx_status_t> {
        Self::with_segments_and_elf(code_base, code_size_bytes, entry, segments, None)
    }

    pub(crate) fn with_segments_and_elf(
        code_base: u64,
        code_size_bytes: u64,
        entry: u64,
        segments: &[ProcessImageSegment],
        elf: Option<ProcessImageElfInfo>,
    ) -> Result<Self, zx_status_t> {
        let mut stored = heapless::Vec::new();
        for segment in segments {
            stored.push(*segment).map_err(|_| ZX_ERR_NO_RESOURCES)?;
        }
        Ok(Self {
            code_base,
            code_size_bytes,
            entry,
            elf,
            segments: stored,
        })
    }

    pub(crate) fn code_base(&self) -> u64 {
        self.code_base
    }

    pub(crate) fn code_size_bytes(&self) -> u64 {
        self.code_size_bytes
    }

    pub(crate) fn entry(&self) -> u64 {
        self.entry
    }

    pub(crate) fn segments(&self) -> &[ProcessImageSegment] {
        self.segments.as_slice()
    }

    pub(crate) const fn elf(&self) -> Option<ProcessImageElfInfo> {
        self.elf
    }

    pub(crate) fn rebased_for_loaded_image(&self) -> Result<Self, zx_status_t> {
        let mut stored = heapless::Vec::new();
        for segment in &self.segments {
            let rebased_offset = segment
                .vaddr()
                .checked_sub(self.code_base)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            stored
                .push(ProcessImageSegment::new(
                    segment.vaddr(),
                    rebased_offset,
                    segment.file_size_bytes(),
                    segment.mem_size_bytes(),
                    segment.perms(),
                ))
                .map_err(|_| ZX_ERR_NO_RESOURCES)?;
        }
        Ok(Self {
            code_base: self.code_base,
            code_size_bytes: self.code_size_bytes,
            entry: self.entry,
            elf: self.elf,
            segments: stored,
        })
    }
}

pub(crate) const fn process_image_default_code_perms() -> MappingPerms {
    MappingPerms::READ.union(MappingPerms::EXECUTE)
}

const STACK_ARGV0: &[u8] = b"axle-child\0";
const PROCESS_START_STACK_BYTES: u64 = crate::userspace::USER_PAGE_BYTES * 16;
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_ENTRY: u64 = 9;

fn align_up_user_page(value: u64) -> Result<u64, zx_status_t> {
    let align = crate::userspace::USER_PAGE_BYTES;
    value
        .checked_add(align - 1)
        .map(|rounded| rounded & !(align - 1))
        .ok_or(ZX_ERR_OUT_OF_RANGE)
}

fn build_process_start_stack_image(
    stack_base: u64,
    stack_len: u64,
    layout: &ProcessImageLayout,
) -> Result<PreparedStackImage, zx_status_t> {
    let stack_len_usize = usize::try_from(stack_len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let mut auxv = Vec::new();
    auxv.try_reserve_exact(6).map_err(|_| ZX_ERR_NO_MEMORY)?;
    auxv.push((AT_PAGESZ, crate::userspace::USER_PAGE_BYTES));
    auxv.push((AT_ENTRY, layout.entry()));
    if let Some(elf) = layout.elf() {
        auxv.push((AT_PHDR, elf.phdr_vaddr()));
        auxv.push((AT_PHENT, u64::from(elf.phent())));
        auxv.push((AT_PHNUM, u64::from(elf.phnum())));
    }
    auxv.push((AT_NULL, 0));

    let mut words = Vec::new();
    let word_count = 4usize
        .checked_add(auxv.len().checked_mul(2).ok_or(ZX_ERR_OUT_OF_RANGE)?)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    words
        .try_reserve_exact(word_count)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;

    let mut cursor = stack_len_usize;
    cursor = cursor
        .checked_sub(STACK_ARGV0.len())
        .ok_or(ZX_ERR_NO_MEMORY)?;
    let argv0_offset = cursor;
    let argv0_ptr = stack_base
        .checked_add(u64::try_from(argv0_offset).map_err(|_| ZX_ERR_OUT_OF_RANGE)?)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;

    words.push(1);
    words.push(argv0_ptr);
    words.push(0);
    words.push(0);
    for (key, value) in auxv {
        words.push(key);
        words.push(value);
    }

    let words_bytes = words
        .len()
        .checked_mul(size_of::<u64>())
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    cursor = cursor.checked_sub(words_bytes).ok_or(ZX_ERR_NO_MEMORY)?;
    cursor &= !0xFusize;

    let total_bytes = stack_len_usize
        .checked_sub(cursor)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let mut image = Vec::new();
    image
        .try_reserve_exact(total_bytes)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    image.resize(total_bytes, 0);

    for (index, word) in words.iter().enumerate() {
        let start = index * size_of::<u64>();
        image[start..start + size_of::<u64>()].copy_from_slice(&word.to_ne_bytes());
    }
    let string_offset = argv0_offset
        .checked_sub(cursor)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    image[string_offset..string_offset + STACK_ARGV0.len()].copy_from_slice(STACK_ARGV0);

    let stack_pointer = stack_base
        .checked_add(u64::try_from(cursor).map_err(|_| ZX_ERR_OUT_OF_RANGE)?)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let stack_vmo_offset = u64::try_from(cursor).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    Ok(PreparedStackImage {
        stack_pointer,
        stack_vmo_offset,
        image,
    })
}

#[derive(Clone, Debug)]
struct PreparedStackImage {
    stack_pointer: u64,
    stack_vmo_offset: u64,
    image: Vec<u8>,
}

fn validate_linux_exec_stack_spec(
    header: ax_linux_exec_spec_header_t,
    stack_image: &[u8],
) -> Result<(), zx_status_t> {
    if header.stack_bytes_len != stack_image.len() as u64 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if header.stack_pointer == 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let stack_end = header
        .stack_vmo_offset
        .checked_add(header.stack_bytes_len)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    if stack_end > PROCESS_START_STACK_BYTES {
        return Err(ZX_ERR_OUT_OF_RANGE);
    }
    let stack_base = crate::userspace::USER_STACK_VA;
    let stack_limit = stack_base
        .checked_add(PROCESS_START_STACK_BYTES)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    if header.stack_pointer < stack_base || header.stack_pointer > stack_limit {
        return Err(ZX_ERR_OUT_OF_RANGE);
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct ImportedProcessImage {
    code_vmo: CreatedVmo,
    layout: ProcessImageLayout,
}

impl ImportedProcessImage {
    pub(crate) fn layout(&self) -> ProcessImageLayout {
        self.layout.clone()
    }

    pub(crate) const fn code_vmo(&self) -> &CreatedVmo {
        &self.code_vmo
    }
}

#[derive(Clone, Debug)]
pub(crate) struct KernelVmoBacking {
    global_vmo_id: KernelVmoId,
    base_paddr: u64,
    page_count: usize,
    frame_ids: Vec<FrameId>,
    size_bytes: u64,
}

impl KernelVmoBacking {
    pub(crate) fn global_vmo_id(&self) -> KernelVmoId {
        self.global_vmo_id
    }

    pub(crate) fn base_paddr(&self) -> u64 {
        self.base_paddr
    }

    pub(crate) fn page_count(&self) -> usize {
        self.page_count
    }

    pub(crate) fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

/// Result of resizing one VMO, including any frames that must be retired before reuse.
#[derive(Clone, Debug)]
pub(crate) struct VmoResizeResult {
    new_size: u64,
    retired_frames: Vec<RetiredFrame>,
    barrier_address_spaces: Vec<AddressSpaceId>,
}

impl VmoResizeResult {
    fn from_retire_plan(new_size: u64, plan: FrameRetirePlan) -> Self {
        Self {
            new_size,
            retired_frames: plan.retired_frames,
            barrier_address_spaces: plan.barrier_address_spaces,
        }
    }

    pub(crate) const fn new_size(&self) -> u64 {
        self.new_size
    }

    pub(crate) fn retired_frames(&self) -> &[RetiredFrame] {
        &self.retired_frames
    }

    pub(crate) fn barrier_address_spaces(&self) -> &[AddressSpaceId] {
        &self.barrier_address_spaces
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

    fn remapped(address_space_id: AddressSpaceId, retire_plan: FrameRetirePlan) -> Self {
        Self {
            remapped: true,
            tlb_commit: TlbCommitReq::strict(address_space_id),
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

#[derive(Clone, Debug)]
struct GlobalVmo {
    size_bytes: u64,
    source: VmoBackingSource,
}

type PagerReadAtFn = fn(offset: u64, dst: &mut [u8]) -> Result<(), zx_status_t>;

trait PagerReadOnlySource: Send + Sync {
    fn size_bytes(&self) -> u64;

    fn read_bytes(&self, offset: u64, dst: &mut [u8]) -> Result<(), zx_status_t>;

    fn materialize_page(&self, page_offset: u64, dst_paddr: u64) -> Result<(), zx_status_t> {
        let mut scratch = alloc::vec![0; crate::userspace::USER_PAGE_BYTES as usize];
        self.read_bytes(page_offset, &mut scratch)?;
        crate::copy::write_bootstrap_frame_bytes(dst_paddr, 0, &scratch)
    }
}

#[derive(Clone)]
struct PagerSourceHandle(Arc<dyn PagerReadOnlySource>);

impl core::fmt::Debug for PagerSourceHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PagerSourceHandle(..)")
    }
}

impl PagerSourceHandle {
    fn new(source: impl PagerReadOnlySource + 'static) -> Self {
        Self(Arc::new(source))
    }

    fn size_bytes(&self) -> u64 {
        self.0.size_bytes()
    }

    fn read_bytes(&self, offset: u64, dst: &mut [u8]) -> Result<(), zx_status_t> {
        self.0.read_bytes(offset, dst)
    }

    fn materialize_page(&self, page_offset: u64, dst_paddr: u64) -> Result<(), zx_status_t> {
        self.0.materialize_page(page_offset, dst_paddr)
    }
}

#[derive(Clone, Debug)]
struct StaticPagerSource {
    bytes: &'static [u8],
}

impl PagerReadOnlySource for StaticPagerSource {
    fn size_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_bytes(&self, offset: u64, dst: &mut [u8]) -> Result<(), zx_status_t> {
        let end = offset
            .checked_add(dst.len() as u64)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let start = usize::try_from(offset).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let end = usize::try_from(end).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let src = self.bytes.get(start..end).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        crate::copy::copy_kernel_bytes(dst, src)
    }
}

#[derive(Clone, Copy, Debug)]
struct FilePagerSource {
    size_bytes: u64,
    read_at: PagerReadAtFn,
}

impl PagerReadOnlySource for FilePagerSource {
    fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    fn read_bytes(&self, offset: u64, dst: &mut [u8]) -> Result<(), zx_status_t> {
        let end = offset
            .checked_add(dst.len() as u64)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if end > self.size_bytes {
            return Err(ZX_ERR_OUT_OF_RANGE);
        }
        (self.read_at)(offset, dst)
    }
}

#[derive(Clone, Debug)]
enum VmoBackingSource {
    Anonymous {
        frames: Vec<Option<FrameId>>,
    },
    Physical {
        frames: Vec<Option<FrameId>>,
    },
    Contiguous {
        frames: Vec<Option<FrameId>>,
    },
    PagerReadOnly {
        frames: Vec<Option<FrameId>>,
        source: PagerSourceHandle,
    },
}

impl VmoBackingSource {
    fn from_kind(kind: VmoKind, page_count: usize) -> Result<Self, zx_status_t> {
        Ok(match kind {
            VmoKind::Anonymous => Self::Anonymous {
                frames: alloc::vec![None; page_count],
            },
            VmoKind::Physical => Self::Physical {
                frames: alloc::vec![None; page_count],
            },
            VmoKind::Contiguous => Self::Contiguous {
                frames: alloc::vec![None; page_count],
            },
            VmoKind::PagerBacked => return Err(ZX_ERR_INVALID_ARGS),
        })
    }

    fn kind(&self) -> VmoKind {
        match self {
            Self::Anonymous { .. } => VmoKind::Anonymous,
            Self::Physical { .. } => VmoKind::Physical,
            Self::Contiguous { .. } => VmoKind::Contiguous,
            Self::PagerReadOnly { .. } => VmoKind::PagerBacked,
        }
    }

    fn frames(&self) -> &[Option<FrameId>] {
        match self {
            Self::Anonymous { frames }
            | Self::Physical { frames }
            | Self::Contiguous { frames }
            | Self::PagerReadOnly { frames, .. } => frames,
        }
    }

    fn frames_mut(&mut self) -> Option<&mut Vec<Option<FrameId>>> {
        match self {
            Self::Anonymous { frames }
            | Self::Physical { frames }
            | Self::Contiguous { frames }
            | Self::PagerReadOnly { frames, .. } => Some(frames),
        }
    }

    fn read_bytes_into(&self, offset: u64, dst: &mut [u8]) -> Result<bool, zx_status_t> {
        match self {
            Self::PagerReadOnly { source, .. } => {
                source.read_bytes(offset, dst)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn materialize_page_into(&self, page_offset: u64, dst_paddr: u64) -> Result<bool, zx_status_t> {
        match self {
            Self::PagerReadOnly { source, .. } => {
                source.materialize_page(page_offset, dst_paddr)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

#[derive(Debug, Default)]
struct GlobalVmoStore {
    entries: BTreeMap<KernelVmoId, GlobalVmo>,
}

impl GlobalVmoStore {
    fn page_count_for_size(size_bytes: u64) -> Result<usize, zx_status_t> {
        if size_bytes == 0 || (size_bytes & (crate::userspace::USER_PAGE_BYTES - 1)) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        usize::try_from(size_bytes / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)
    }

    fn register_snapshot(
        &mut self,
        global_vmo_id: KernelVmoId,
        snapshot: &Vmo,
    ) -> Result<(), zx_status_t> {
        self.entries.insert(
            global_vmo_id,
            GlobalVmo {
                size_bytes: snapshot.size_bytes(),
                source: VmoBackingSource::from_kind(snapshot.kind(), snapshot.frames().len())?,
            },
        );
        if let Some(global_vmo) = self.entries.get_mut(&global_vmo_id) {
            if let Some(frames) = global_vmo.source.frames_mut() {
                *frames = snapshot.frames().to_vec();
            }
        }
        Ok(())
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
        let page_count = Self::page_count_for_size(size_bytes)?;
        self.entries.insert(
            global_vmo_id,
            GlobalVmo {
                size_bytes,
                source: VmoBackingSource::from_kind(kind, page_count)?,
            },
        );
        Ok(())
    }

    fn register_pager_source(
        &mut self,
        global_vmo_id: KernelVmoId,
        source: PagerSourceHandle,
    ) -> Result<(), zx_status_t> {
        if self.entries.contains_key(&global_vmo_id) {
            return Err(ZX_ERR_ALREADY_EXISTS);
        }
        let size_bytes = source.size_bytes();
        let page_count = Self::page_count_for_size(size_bytes)?;
        self.entries.insert(
            global_vmo_id,
            GlobalVmo {
                size_bytes,
                source: VmoBackingSource::PagerReadOnly {
                    frames: alloc::vec![None; page_count],
                    source,
                },
            },
        );
        Ok(())
    }

    fn register_pager_read_only(
        &mut self,
        global_vmo_id: KernelVmoId,
        bytes: &'static [u8],
    ) -> Result<(), zx_status_t> {
        self.register_pager_source(
            global_vmo_id,
            PagerSourceHandle::new(StaticPagerSource { bytes }),
        )
    }

    fn register_pager_file_source(
        &mut self,
        global_vmo_id: KernelVmoId,
        size_bytes: u64,
        read_at: PagerReadAtFn,
    ) -> Result<(), zx_status_t> {
        self.register_pager_source(
            global_vmo_id,
            PagerSourceHandle::new(FilePagerSource {
                size_bytes,
                read_at,
            }),
        )
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

    fn resize(
        &mut self,
        global_vmo_id: KernelVmoId,
        new_size_bytes: u64,
    ) -> Result<Vec<FrameId>, zx_status_t> {
        let new_page_count = Self::page_count_for_size(new_size_bytes)?;
        let global_vmo = self
            .entries
            .get_mut(&global_vmo_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?;
        let mut dropped = Vec::new();
        let frames = global_vmo.source.frames_mut().ok_or(ZX_ERR_NOT_SUPPORTED)?;
        if new_page_count < frames.len() {
            dropped.extend(frames[new_page_count..].iter().flatten().copied());
        }
        global_vmo.size_bytes = new_size_bytes;
        frames.truncate(new_page_count);
        if new_page_count > frames.len() {
            frames.resize(new_page_count, None);
        }
        Ok(dropped)
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
        Ok(global_vmo
            .source
            .frames()
            .get(page_index)
            .copied()
            .flatten())
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
        let frames = global_vmo.source.frames_mut().ok_or(ZX_ERR_NOT_SUPPORTED)?;
        let slot = frames.get_mut(page_index).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        *slot = Some(frame_id);
        Ok(())
    }

    fn materialize_page_into(
        &self,
        global_vmo_id: KernelVmoId,
        page_offset: u64,
        dst_paddr: u64,
    ) -> Result<bool, zx_status_t> {
        let global_vmo = self.entries.get(&global_vmo_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        global_vmo
            .source
            .materialize_page_into(page_offset, dst_paddr)
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct PreparedProcessStart {
    entry: u64,
    stack_top: u64,
}

impl PreparedProcessStart {
    pub(crate) const fn entry(self) -> u64 {
        self.entry
    }

    pub(crate) const fn stack_top(self) -> u64 {
        self.stack_top
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct SignalWaiter {
    thread_id: ThreadId,
    seq: u64,
    observed_ptr: u64,
}

impl SignalWaiter {
    pub(crate) const fn thread_id(self) -> ThreadId {
        self.thread_id
    }

    pub(crate) const fn seq(self) -> u64 {
        self.seq
    }

    pub(crate) const fn observed_ptr(self) -> *mut zx_signals_t {
        self.observed_ptr as *mut zx_signals_t
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PortWaiter {
    thread_id: ThreadId,
    seq: u64,
    packet_ptr: u64,
}

impl PortWaiter {
    pub(crate) const fn thread_id(self) -> ThreadId {
        self.thread_id
    }

    pub(crate) const fn seq(self) -> u64 {
        self.seq
    }

    pub(crate) const fn packet_ptr(self) -> *mut zx_port_packet_t {
        self.packet_ptr as *mut zx_port_packet_t
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ExpiredWait {
    thread_id: ThreadId,
    registration: WaitRegistration,
}

impl ExpiredWait {
    pub(crate) const fn thread_id(self) -> ThreadId {
        self.thread_id
    }

    pub(crate) const fn registration(self) -> WaitRegistration {
        self.registration
    }
}

#[derive(Debug, Default)]
pub(crate) struct ReactorPollResult {
    events: Vec<ReactorPollEvent>,
}

impl ReactorPollResult {
    pub(crate) fn into_events(self) -> Vec<ReactorPollEvent> {
        self.events
    }
}

#[derive(Debug)]
pub(crate) enum ReactorPollEvent {
    TimerFired(TimerId),
    WaitExpired(ExpiredWait),
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
    ) -> TlbCpuSyncShape {
        if current_cpu_active {
            self.note_active(current_cpu_id);
        }
        let local_needs_flush =
            current_cpu_active && self.observed_epoch(current_cpu_id) < target_epoch;
        let remote_cpus = self
            .active
            .iter()
            .filter(|&cpu_id| cpu_id != current_cpu_id)
            .filter(|&cpu_id| self.observed_epoch(cpu_id) < target_epoch)
            .collect();
        TlbCpuSyncShape {
            local_needs_flush,
            remote_cpus,
        }
    }
}

#[derive(Debug)]
struct TlbCpuSyncShape {
    local_needs_flush: bool,
    remote_cpus: Vec<usize>,
}

#[derive(Debug)]
struct AddressSpace {
    vm: VmAddressSpace,
    page_tables: crate::page_table::UserPageTables,
    tlb_cpus: TlbCpuTracker,
    vm_resources: VmResourceState,
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
        self.tlb_cpus.note_active(cpu_id);
    }

    fn note_cpu_inactive(&mut self, cpu_id: usize) {
        self.tlb_cpus.note_inactive(cpu_id);
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
    ) -> TlbCpuSyncShape {
        let target_epoch = self.current_invalidate_epoch();
        self.tlb_cpus
            .plan_strict_sync(current_cpu_id, current_cpu_active, target_epoch)
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

    fn validate_vmo_resize(
        &self,
        global_vmo_id: KernelVmoId,
        new_size: u64,
    ) -> Result<(), AddressSpaceError> {
        let Some(vmo_id) = self.local_vmo_id(global_vmo_id) else {
            return Ok(());
        };
        self.vm.validate_vmo_resize(vmo_id, new_size)
    }

    fn resize_vmo(
        &mut self,
        global_vmo_id: KernelVmoId,
        new_size: u64,
    ) -> Result<Vec<FrameId>, AddressSpaceError> {
        let Some(vmo_id) = self.local_vmo_id(global_vmo_id) else {
            return Ok(Vec::new());
        };
        self.vm.resize_vmo(vmo_id, new_size)
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

    fn imports_global_vmo(&self, global_vmo_id: KernelVmoId) -> bool {
        self.local_vmo_id(global_vmo_id).is_some()
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
    queued_on_cpu: Option<usize>,
    last_cpu: usize,
    runtime_ns: u64,
    wait: WaitNode,
    context: Option<UserContext>,
    suspend_tokens: u32,
}

#[derive(Debug, Default)]
struct CpuSchedulerState {
    run_queue: VecDeque<ThreadId>,
    current_thread_id: Option<ThreadId>,
    reschedule_requested: bool,
    current_runtime_started_ns: Option<i64>,
    slice_deadline_ns: Option<i64>,
    online: bool,
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
    processes: BTreeMap<ProcessId, Process>,
    threads: BTreeMap<ThreadId, Thread>,
    futexes: crate::futex::FutexTable,
    reactor: Arc<Mutex<Reactor>>,
    cpu_schedulers: BTreeMap<usize, CpuSchedulerState>,
    revocations: RevocationManager,
    next_koid: zx_koid_t,
    next_process_id: ProcessId,
    next_thread_id: ThreadId,
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
    ) -> Result<Option<StrictTlbSyncPlan>, zx_status_t> {
        let address_space = self
            .address_spaces
            .get_mut(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let target_epoch = address_space.current_invalidate_epoch();
        let sync_shape = address_space.plan_tlb_sync(current_cpu_id, current_cpu_active);
        if !sync_shape.local_needs_flush && sync_shape.remote_cpus.is_empty() {
            return Ok(None);
        }
        Ok(Some(StrictTlbSyncPlan {
            address_space_id,
            target_epoch,
            current_cpu_id,
            current_cpu_active,
            local_needs_flush: sync_shape.local_needs_flush,
            remote_cpus: sync_shape.remote_cpus,
        }))
    }

    fn complete_strict_tlb_sync(&mut self, plan: &StrictTlbSyncPlan) -> Result<(), zx_status_t> {
        let address_space = self
            .address_spaces
            .get_mut(&plan.address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if plan.current_cpu_active {
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

    fn cancel_wait_deadline(&mut self, thread_id: ThreadId, seq: u64) {
        self.reactor.lock().cancel_wait_deadline(thread_id, seq);
    }

    pub(crate) fn create_timer_object(&mut self) -> TimerId {
        self.reactor.lock().create_timer_object()
    }

    pub(crate) fn destroy_timer_object(&mut self, timer_id: TimerId) -> Result<(), TimerError> {
        self.reactor.lock().destroy_timer_object(timer_id)
    }

    pub(crate) fn set_timer_object(
        &mut self,
        timer_id: TimerId,
        deadline: i64,
        now: i64,
    ) -> Result<bool, TimerError> {
        let cpu_id = self.current_cpu_id();
        self.reactor
            .lock()
            .set_timer_object(timer_id, cpu_id, deadline, now)
    }

    pub(crate) fn cancel_timer_object(&mut self, timer_id: TimerId) -> Result<(), TimerError> {
        self.reactor.lock().cancel_timer_object(timer_id)
    }

    pub(crate) fn timer_object_signaled(&self, timer_id: TimerId) -> Result<bool, TimerError> {
        self.reactor.lock().timer_object_signaled(timer_id)
    }

    /// Build the single-process bootstrap kernel model used by the current main branch.
    pub(crate) fn bootstrap(
        vm: Arc<VmFacade>,
        reactor: Arc<Mutex<Reactor>>,
        address_space_id: AddressSpaceId,
    ) -> Self {
        let mut kernel = Self {
            processes: BTreeMap::new(),
            threads: BTreeMap::new(),
            futexes: crate::futex::FutexTable::new(),
            reactor,
            cpu_schedulers: BTreeMap::new(),
            revocations: RevocationManager::new(),
            next_koid: 1,
            next_process_id: 1,
            next_thread_id: 1,
            task_lifecycle_dirty: false,
            vm,
        };
        let bootstrap_cpu_id = Self::bootstrap_cpu_id();
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
                queued_on_cpu: None,
                last_cpu: bootstrap_cpu_id,
                runtime_ns: 0,
                wait: WaitNode::default(),
                context: None,
                suspend_tokens: 0,
            },
        );
        kernel.cpu_schedulers.insert(
            bootstrap_cpu_id,
            CpuSchedulerState {
                run_queue: VecDeque::new(),
                current_thread_id: Some(thread_id),
                reschedule_requested: false,
                current_runtime_started_ns: Some(crate::time::now_ns()),
                slice_deadline_ns: crate::time::now_ns().checked_add(DEFAULT_TIME_SLICE_NS),
                online: true,
            },
        );
        kernel
    }

    pub(crate) fn vm_handle(&self) -> Arc<VmFacade> {
        self.vm.clone()
    }

    fn with_vm<T>(&self, f: impl FnOnce(&VmDomain) -> T) -> T {
        self.vm.with_domain(f)
    }

    fn with_vm_mut<T>(&self, f: impl FnOnce(&mut VmDomain) -> T) -> T {
        self.vm.with_domain_mut(f)
    }

    fn with_faults_mut<T>(&self, f: impl FnOnce(&mut FaultTable) -> T) -> T {
        let faults = self.vm.fault_handle();
        let mut faults = faults.lock();
        f(&mut faults)
    }

    fn apply_tlb_commit_reqs_current(&self, reqs: &[TlbCommitReq]) -> Result<(), zx_status_t> {
        self.vm.apply_tlb_commit_reqs(
            self.current_cpu_id(),
            self.current_address_space_id().ok(),
            reqs,
        )
    }

    fn retire_bootstrap_frames_after_quiescence_current(
        &self,
        barrier_address_spaces: &[AddressSpaceId],
        retired_frames: &[RetiredFrame],
    ) -> Result<(), zx_status_t> {
        self.vm.retire_bootstrap_frames_after_quiescence(
            self.current_cpu_id(),
            self.current_address_space_id().ok(),
            barrier_address_spaces,
            retired_frames,
        )
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

    pub(crate) fn current_thread_info(&self) -> Result<CurrentThreadInfo, zx_status_t> {
        let thread = self.current_thread()?;
        Ok(CurrentThreadInfo {
            process_id: thread.process_id,
            thread_id: self.current_thread_id()?,
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

    pub(crate) fn allocate_global_vmo_id(&mut self) -> KernelVmoId {
        self.with_vm_mut(|vm| vm.alloc_global_vmo_id())
    }

    pub(crate) fn create_kernel_vmo_backing(
        &mut self,
        size_bytes: u64,
    ) -> Result<KernelVmoBacking, zx_status_t> {
        if size_bytes == 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let page_size = crate::userspace::USER_PAGE_BYTES;
        let rounded_size = size_bytes
            .checked_add(page_size - 1)
            .map(|value| value & !(page_size - 1))
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let page_count =
            usize::try_from(rounded_size / page_size).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let global_vmo_id = self.allocate_global_vmo_id();
        self.register_empty_global_vmo(global_vmo_id, VmoKind::Anonymous, rounded_size)?;

        let Some(base_paddr) = crate::userspace::alloc_bootstrap_zeroed_pages(page_count) else {
            let _ = self.with_vm_mut(|vm| vm.global_vmos.lock().remove(global_vmo_id));
            return Err(ZX_ERR_NO_MEMORY);
        };

        let created = self.with_vm_mut(|vm| {
            let mut frames = vm.frames.lock();
            let mut global_vmos = vm.global_vmos.lock();
            let mut frame_ids = Vec::with_capacity(page_count);
            for page_index in 0..page_count {
                let paddr = base_paddr + (page_index as u64) * page_size;
                let frame_id = frames.register_existing(paddr).map_err(|err| match err {
                    axle_mm::FrameTableError::InvalidArgs => ZX_ERR_INVALID_ARGS,
                    axle_mm::FrameTableError::AlreadyExists => ZX_ERR_ALREADY_EXISTS,
                    axle_mm::FrameTableError::NotFound
                    | axle_mm::FrameTableError::CountOverflow
                    | axle_mm::FrameTableError::RefUnderflow
                    | axle_mm::FrameTableError::PinUnderflow
                    | axle_mm::FrameTableError::LoanUnderflow
                    | axle_mm::FrameTableError::MissingAnchor
                    | axle_mm::FrameTableError::Busy => ZX_ERR_BAD_STATE,
                })?;
                if let Err(status) = global_vmos.update_frame(
                    global_vmo_id,
                    (page_index as u64) * page_size,
                    frame_id,
                ) {
                    let _ = frames.unregister_existing(frame_id);
                    return Err(status);
                }
                frame_ids.push(frame_id);
            }
            Ok(frame_ids)
        });

        let frame_ids = match created {
            Ok(frame_ids) => frame_ids,
            Err(status) => {
                let _ = self.destroy_kernel_vmo_backing(KernelVmoBacking {
                    global_vmo_id,
                    base_paddr,
                    page_count,
                    frame_ids: Vec::new(),
                    size_bytes: rounded_size,
                });
                return Err(status);
            }
        };

        Ok(KernelVmoBacking {
            global_vmo_id,
            base_paddr,
            page_count,
            frame_ids,
            size_bytes: rounded_size,
        })
    }

    pub(crate) fn destroy_kernel_vmo_backing(
        &mut self,
        backing: KernelVmoBacking,
    ) -> Result<(), zx_status_t> {
        let retire_plan =
            self.with_vm(|vm| vm.build_required_frame_retire_plan(&backing.frame_ids, &[]))?;
        let _ = self.with_vm_mut(|vm| vm.global_vmos.lock().remove(backing.global_vmo_id));
        self.retire_bootstrap_frames_after_quiescence_current(
            retire_plan.barrier_address_spaces(),
            retire_plan.retired_frames(),
        )?;
        Ok(())
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

    pub(crate) fn current_thread_guest_x64_regs(
        &self,
    ) -> Result<axle_types::ax_guest_x64_regs_t, zx_status_t> {
        Ok(self
            .current_thread()?
            .context
            .ok_or(ZX_ERR_BAD_STATE)?
            .to_guest_x64_regs())
    }

    pub(crate) fn current_process_koid(&self) -> Result<zx_koid_t, zx_status_t> {
        Ok(self.current_process()?.koid)
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

    pub(crate) fn capture_current_user_context(
        &mut self,
        trap: &crate::arch::int80::TrapFrame,
        cpu_frame: *const u64,
    ) -> Result<(), zx_status_t> {
        let context = UserContext::capture(trap, cpu_frame)?;
        let current_thread_id = self.current_thread_id()?;
        let thread = self
            .threads
            .get_mut(&current_thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        thread.context = Some(context);
        Ok(())
    }

    pub(crate) fn thread_user_context(
        &self,
        thread_id: ThreadId,
    ) -> Result<UserContext, zx_status_t> {
        self.threads
            .get(&thread_id)
            .and_then(|thread| thread.context)
            .ok_or(ZX_ERR_BAD_STATE)
    }

    pub(crate) fn thread_state(&self, thread_id: ThreadId) -> Result<ThreadState, zx_status_t> {
        Ok(self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_STATE)?.state)
    }

    pub(crate) fn thread_wait_registration(
        &self,
        thread_id: ThreadId,
    ) -> Result<Option<WaitRegistration>, zx_status_t> {
        Ok(self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .wait
            .registration)
    }

    pub(crate) fn replace_thread_guest_context(
        &mut self,
        thread_id: ThreadId,
        regs: &ax_guest_x64_regs_t,
    ) -> Result<(), zx_status_t> {
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        let Some(context) = thread.context else {
            return Err(ZX_ERR_BAD_STATE);
        };
        thread.context = Some(context.with_guest_x64_regs(*regs));
        Ok(())
    }

    fn validate_thread_guest_start_regs(
        &self,
        process_id: ProcessId,
        regs: &ax_guest_x64_regs_t,
    ) -> Result<(), zx_status_t> {
        let stack_probe = regs.rsp.checked_sub(8).ok_or(ZX_ERR_INVALID_ARGS)?;
        if !self.validate_process_user_mapping_perms(
            process_id,
            regs.rip,
            1,
            MappingPerms::READ | MappingPerms::EXECUTE | MappingPerms::USER,
        ) || !self.validate_process_user_mapping_perms(
            process_id,
            stack_probe,
            8,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
        ) {
            return Err(ZX_ERR_INVALID_ARGS);
        }
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
        let current_cpu_id = self.current_cpu_id();
        let now = self.current_cpu_now_ns();
        if !resuming_blocked_current {
            self.account_current_runtime_until(now)?;
        }
        match self.current_thread()?.state {
            ThreadState::Runnable => {
                if resuming_blocked_current {
                    self.restore_current_user_context(trap, cpu_frame)?;
                    self.arm_current_slice_from(now);
                } else {
                    self.capture_current_user_context(trap, cpu_frame.cast_const())?;
                }
                if !resuming_blocked_current && self.take_reschedule_requested(current_cpu_id) {
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
                let thread_id = self.current_thread_id()?;
                self.clear_current_slice_state();
                self.finalize_thread_termination(thread_id)?;
                if let Some(next_thread_id) = self.pop_runnable_thread() {
                    self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                    Ok(TrapExitDisposition::Complete)
                } else {
                    Ok(TrapExitDisposition::BlockCurrent)
                }
            }
            ThreadState::Suspended | ThreadState::Terminated => {
                self.clear_current_slice_state();
                if let Some(next_thread_id) = self.pop_runnable_thread() {
                    self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                    Ok(TrapExitDisposition::Complete)
                } else {
                    Ok(TrapExitDisposition::BlockCurrent)
                }
            }
            ThreadState::Blocked { .. } => {
                if !resuming_blocked_current {
                    self.capture_current_user_context(trap, cpu_frame.cast_const())?;
                }
                self.clear_current_slice_state();
                if let Some(next_thread_id) = self.pop_runnable_thread() {
                    self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                    Ok(TrapExitDisposition::Complete)
                } else {
                    Ok(TrapExitDisposition::BlockCurrent)
                }
            }
        }
    }

    fn push_signal_waiter(&mut self, object_key: ObjectKey, thread_id: ThreadId) {
        self.reactor
            .lock()
            .push_signal_waiter(object_key, thread_id);
    }

    fn remove_signal_waiter(&mut self, object_key: ObjectKey, thread_id: ThreadId) {
        self.reactor
            .lock()
            .remove_signal_waiter(object_key, thread_id);
    }

    fn push_port_waiter(&mut self, port_object: ObjectKey, thread_id: ThreadId) {
        self.reactor.lock().push_port_waiter(port_object, thread_id);
    }

    fn remove_port_waiter(&mut self, port_object: ObjectKey, thread_id: ThreadId) {
        self.reactor
            .lock()
            .remove_port_waiter(port_object, thread_id);
    }

    fn enqueue_wait_source(&mut self, thread_id: ThreadId, registration: WaitRegistration) {
        match registration {
            WaitRegistration::Sleep => {}
            WaitRegistration::Signal { object_key, .. } => {
                self.push_signal_waiter(object_key, thread_id)
            }
            WaitRegistration::Port { port_object, .. } => {
                self.push_port_waiter(port_object, thread_id)
            }
            WaitRegistration::Futex { key, owner_koid } => {
                self.futexes.enqueue_waiter(key, thread_id, owner_koid)
            }
            WaitRegistration::VmFault { .. } => {}
        }
    }

    fn remove_wait_source_membership(
        &mut self,
        thread_id: ThreadId,
        registration: WaitRegistration,
    ) {
        match registration {
            WaitRegistration::Sleep => {}
            WaitRegistration::Signal { object_key, .. } => {
                self.remove_signal_waiter(object_key, thread_id)
            }
            WaitRegistration::Port { port_object, .. } => {
                self.remove_port_waiter(port_object, thread_id)
            }
            WaitRegistration::Futex { key, .. } => {
                let _ = self.futexes.cancel_waiter(key, thread_id);
            }
            WaitRegistration::VmFault { key } => {
                self.with_faults_mut(|faults| {
                    faults.remove_blocked_waiter(key, thread_id);
                });
            }
        }
    }

    fn take_wait_registration_if_seq(
        &mut self,
        thread_id: ThreadId,
        seq: u64,
    ) -> Option<WaitRegistration> {
        let (registration, had_deadline) = {
            let thread = self.threads.get_mut(&thread_id)?;
            if thread.wait.seq != seq {
                return None;
            }
            let registration = thread.wait.registration?;
            let had_deadline = thread.wait.deadline.is_some();
            thread.wait.clear();
            (registration, had_deadline)
        };
        if had_deadline {
            self.cancel_wait_deadline(thread_id, seq);
        }
        Some(registration)
    }

    fn take_wait_registration(&mut self, thread_id: ThreadId) -> Option<(u64, WaitRegistration)> {
        let (seq, registration, had_deadline) = {
            let thread = self.threads.get_mut(&thread_id)?;
            let registration = thread.wait.registration?;
            let seq = thread.wait.seq;
            let had_deadline = thread.wait.deadline.is_some();
            thread.wait.clear();
            (seq, registration, had_deadline)
        };
        if had_deadline {
            self.cancel_wait_deadline(thread_id, seq);
        }
        Some((seq, registration))
    }

    pub(crate) fn park_current(
        &mut self,
        registration: WaitRegistration,
        deadline: Option<i64>,
    ) -> Result<(), zx_status_t> {
        let thread_id = self.current_thread_id()?;
        let source = registration.source_key();
        let seq = {
            let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
            if !matches!(thread.state, ThreadState::Runnable) {
                return Err(ZX_ERR_BAD_STATE);
            }
            thread.state = ThreadState::Blocked { source };
            thread.wait.arm(registration, deadline)
        };
        self.enqueue_wait_source(thread_id, registration);
        if let Some(deadline) = deadline {
            self.reactor
                .lock()
                .arm_wait_deadline(self.current_cpu_id(), thread_id, seq, deadline);
        }
        Ok(())
    }

    pub(crate) fn block_current(
        &mut self,
        registration: WaitRegistration,
    ) -> Result<(), zx_status_t> {
        self.park_current(registration, None)
    }

    pub(crate) fn signal_waiters_ready(
        &self,
        object_key: ObjectKey,
        current: Signals,
    ) -> Vec<SignalWaiter> {
        self.reactor
            .lock()
            .signal_waiter_thread_ids(object_key)
            .iter()
            .filter_map(|thread_id| {
                let thread = self.threads.get(thread_id)?;
                match thread.wait.registration {
                    Some(WaitRegistration::Signal {
                        object_key: wait_object_key,
                        watched,
                        observed_ptr,
                    }) if wait_object_key == object_key && current.intersects(watched) => {
                        Some(SignalWaiter {
                            thread_id: *thread_id,
                            seq: thread.wait.seq,
                            observed_ptr: observed_ptr as u64,
                        })
                    }
                    _ => None,
                }
            })
            .collect()
    }

    pub(crate) fn port_waiters(&self, port_object: ObjectKey) -> Vec<PortWaiter> {
        self.reactor
            .lock()
            .port_waiter_thread_ids(port_object)
            .iter()
            .filter_map(|thread_id| {
                let thread = self.threads.get(thread_id)?;
                match thread.wait.registration {
                    Some(WaitRegistration::Port {
                        port_object: wait_port_object,
                        packet_ptr,
                    }) if wait_port_object == port_object => Some(PortWaiter {
                        thread_id: *thread_id,
                        seq: thread.wait.seq,
                        packet_ptr: packet_ptr as u64,
                    }),
                    _ => None,
                }
            })
            .collect()
    }

    pub(crate) fn complete_waiter(
        &mut self,
        thread_id: ThreadId,
        seq: u64,
        reason: WakeReason,
    ) -> Result<bool, zx_status_t> {
        let Some(registration) = self.take_wait_registration_if_seq(thread_id, seq) else {
            return Ok(false);
        };
        self.remove_wait_source_membership(thread_id, registration);
        self.wake_thread(thread_id, reason)?;
        Ok(true)
    }

    pub(crate) fn complete_waiter_source_removed(
        &mut self,
        thread_id: ThreadId,
        reason: WakeReason,
    ) -> Result<bool, zx_status_t> {
        let Some((_, registration)) = self.take_wait_registration(thread_id) else {
            return Ok(false);
        };
        self.remove_wait_source_membership(thread_id, registration);
        self.wake_thread(thread_id, reason)?;
        Ok(true)
    }

    pub(crate) fn poll_reactor(&mut self, now: i64) -> ReactorPollResult {
        let mut result = ReactorPollResult::default();
        let due = self.reactor.lock().poll(self.current_cpu_id(), now);

        for event in due {
            match event {
                ReactorTimerEvent::TimerFired(timer_id) => {
                    result.events.push(ReactorPollEvent::TimerFired(timer_id));
                }
                ReactorTimerEvent::WaitExpired(wait_id) => {
                    let Some(thread) = self.threads.get(&wait_id.thread_id()) else {
                        continue;
                    };
                    if thread.wait.seq != wait_id.seq() {
                        continue;
                    }
                    let Some(registration) =
                        self.take_wait_registration_if_seq(wait_id.thread_id(), wait_id.seq())
                    else {
                        continue;
                    };
                    self.remove_wait_source_membership(wait_id.thread_id(), registration);
                    result
                        .events
                        .push(ReactorPollEvent::WaitExpired(ExpiredWait {
                            thread_id: wait_id.thread_id(),
                            registration,
                        }));
                }
            }
        }
        result
    }

    fn update_wait_registration(
        &mut self,
        thread_id: ThreadId,
        registration: WaitRegistration,
    ) -> Result<bool, zx_status_t> {
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        let Some(current) = thread.wait.registration else {
            return Ok(false);
        };
        if !matches!(current, WaitRegistration::Futex { .. }) {
            return Ok(false);
        }
        thread.wait.registration = Some(registration);
        thread.state = ThreadState::Blocked {
            source: registration.source_key(),
        };
        Ok(true)
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
            let _ = self.complete_waiter_source_removed(thread_id, WakeReason::Status(ZX_OK))?;
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
            let _ = self.complete_waiter_source_removed(*thread_id, WakeReason::Status(ZX_OK))?;
        }
        for thread_id in &result.requeued_waiters {
            let _ = self.update_wait_registration(
                *thread_id,
                WaitRegistration::Futex {
                    key: target,
                    owner_koid: target_owner_koid,
                },
            )?;
        }
        Ok(result)
    }

    #[allow(dead_code)]
    pub(crate) fn futex_owner(&self, key: FutexKey) -> zx_koid_t {
        self.futexes.owner(key)
    }

    #[allow(dead_code)]
    pub(crate) fn thread_is_waiting_on_futex(&self, thread_id: ThreadId, key: FutexKey) -> bool {
        self.threads
            .get(&thread_id)
            .and_then(|thread| thread.wait.registration)
            .is_some_and(|registration| {
                matches!(registration, WaitRegistration::Futex { key: wait_key, .. } if wait_key == key)
            })
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
        let current_cpu_id = self.current_cpu_id();
        self.threads.insert(
            thread_id,
            Thread {
                process_id,
                koid,
                state: ThreadState::New,
                queued_on_cpu: None,
                last_cpu: current_cpu_id,
                runtime_ns: 0,
                wait: WaitNode::default(),
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
        let stack_probe = stack.checked_sub(8).ok_or(ZX_ERR_INVALID_ARGS)?;
        if !self.validate_process_user_mapping_perms(
            process_id,
            entry,
            1,
            MappingPerms::READ | MappingPerms::EXECUTE | MappingPerms::USER,
        ) || !self.validate_process_user_mapping_perms(
            process_id,
            stack_probe,
            8,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
        ) {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        if !matches!(thread.state, ThreadState::New) {
            return Err(ZX_ERR_BAD_STATE);
        }
        thread.context = Some(UserContext::new_user_entry(entry, stack, arg0, arg1));
        thread.state = ThreadState::Runnable;
        let queued = thread.queued_on_cpu.is_some();
        let thread_id_copy = thread_id;
        let _ = thread;
        if !queued {
            let target_cpu = self.choose_wake_cpu(thread_id_copy);
            self.enqueue_runnable_thread_on_cpu(thread_id_copy, target_cpu)?;
            self.request_reschedule_on_cpu(target_cpu);
        }
        Ok(())
    }

    pub(crate) fn start_thread_guest(
        &mut self,
        thread_id: ThreadId,
        regs: &ax_guest_x64_regs_t,
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
        self.validate_thread_guest_start_regs(process_id, regs)?;
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        if !matches!(thread.state, ThreadState::New) {
            return Err(ZX_ERR_BAD_STATE);
        }
        thread.context =
            Some(UserContext::new_user_entry(regs.rip, regs.rsp, 0, 0).with_guest_x64_regs(*regs));
        thread.state = ThreadState::Runnable;
        let queued = thread.queued_on_cpu.is_some();
        let thread_id_copy = thread_id;
        let _ = thread;
        if !queued {
            let target_cpu = self.choose_wake_cpu(thread_id_copy);
            self.enqueue_runnable_thread_on_cpu(thread_id_copy, target_cpu)?;
            self.request_reschedule_on_cpu(target_cpu);
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
        let stack_probe = stack.checked_sub(8).ok_or(ZX_ERR_INVALID_ARGS)?;
        if !self.validate_process_user_mapping_perms(
            process_id,
            entry,
            1,
            MappingPerms::READ | MappingPerms::EXECUTE | MappingPerms::USER,
        ) || !self.validate_process_user_mapping_perms(
            process_id,
            stack_probe,
            8,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
        ) {
            return Err(ZX_ERR_INVALID_ARGS);
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

    pub(crate) fn start_process_guest(
        &mut self,
        process_id: ProcessId,
        thread_id: ThreadId,
        regs: &ax_guest_x64_regs_t,
    ) -> Result<(), zx_status_t> {
        let thread_process_id = self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .process_id;
        if thread_process_id != process_id {
            return Err(ZX_ERR_BAD_STATE);
        }
        self.validate_thread_guest_start_regs(process_id, regs)?;
        let process = self
            .processes
            .get_mut(&process_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?;
        if process.state != ProcessState::Created {
            return Err(ZX_ERR_BAD_STATE);
        }
        process.state = ProcessState::Started;
        let result = self.start_thread_guest(thread_id, regs);
        if result.is_err() {
            let process = self
                .processes
                .get_mut(&process_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            process.state = ProcessState::Created;
        }
        result
    }

    pub(crate) fn prepare_process_start(
        &mut self,
        process_id: ProcessId,
        global_vmo_id: KernelVmoId,
        layout: &ProcessImageLayout,
    ) -> Result<PreparedProcessStart, zx_status_t> {
        let process = self.process(process_id)?;
        if process.state != ProcessState::Created {
            return Err(ZX_ERR_BAD_STATE);
        }
        self.with_vm_mut(|vm| {
            vm.prepare_process_start(process_id, process.address_space_id, global_vmo_id, layout)
        })
    }

    pub(crate) fn prepare_linux_process_start(
        &mut self,
        process_id: ProcessId,
        global_vmo_id: KernelVmoId,
        layout: &ProcessImageLayout,
        exec_spec: ax_linux_exec_spec_header_t,
        stack_image: &[u8],
    ) -> Result<PreparedProcessStart, zx_status_t> {
        let process = self.process(process_id)?;
        if process.state != ProcessState::Created {
            return Err(ZX_ERR_BAD_STATE);
        }
        self.with_vm_mut(|vm| {
            vm.prepare_linux_process_start(
                process_id,
                process.address_space_id,
                global_vmo_id,
                layout,
                exec_spec,
                stack_image,
            )
        })
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
        let running_cpu_id = self.running_cpu_for_thread(thread_id);
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
            thread.queued_on_cpu = None;
        }
        let _ = thread;
        if let Some(cpu_id) = running_cpu_id {
            self.request_reschedule_on_cpu(cpu_id);
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
            let running_cpu_id = self.running_cpu_for_thread(thread_id);
            let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
            if matches!(thread.state, ThreadState::Runnable) {
                thread.state = ThreadState::Suspended;
                thread.queued_on_cpu = None;
            }
            let _ = thread;
            if let Some(cpu_id) = running_cpu_id {
                self.request_reschedule_on_cpu(cpu_id);
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
        if self.running_cpu_for_thread(thread_id).is_some() {
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

    fn cpu_scheduler(&self, cpu_id: usize) -> Result<&CpuSchedulerState, zx_status_t> {
        self.cpu_schedulers.get(&cpu_id).ok_or(ZX_ERR_BAD_STATE)
    }

    fn cpu_scheduler_mut(&mut self, cpu_id: usize) -> &mut CpuSchedulerState {
        self.cpu_schedulers.entry(cpu_id).or_default()
    }

    fn current_cpu_scheduler(&self) -> Result<&CpuSchedulerState, zx_status_t> {
        self.cpu_scheduler(self.current_cpu_id())
    }

    fn current_cpu_scheduler_mut(&mut self) -> &mut CpuSchedulerState {
        let cpu_id = self.current_cpu_id();
        self.cpu_scheduler_mut(cpu_id)
    }

    fn current_thread_id(&self) -> Result<ThreadId, zx_status_t> {
        self.current_cpu_scheduler()?
            .current_thread_id
            .ok_or(ZX_ERR_BAD_STATE)
    }

    fn current_thread_matches(&self, thread_id: ThreadId) -> bool {
        self.current_thread_id()
            .is_ok_and(|current_thread_id| current_thread_id == thread_id)
    }

    fn running_cpu_for_thread(&self, thread_id: ThreadId) -> Option<usize> {
        self.cpu_schedulers.iter().find_map(|(&cpu_id, scheduler)| {
            (scheduler.current_thread_id == Some(thread_id)).then_some(cpu_id)
        })
    }

    fn cpu_is_online(&self, cpu_id: usize) -> bool {
        self.cpu_schedulers
            .get(&cpu_id)
            .is_some_and(|scheduler| scheduler.online)
    }

    fn cpu_is_idle(&self, cpu_id: usize) -> bool {
        self.cpu_schedulers.get(&cpu_id).is_some_and(|scheduler| {
            scheduler.online
                && scheduler.current_thread_id.is_none()
                && scheduler.run_queue.is_empty()
        })
    }

    pub(crate) fn mark_cpu_online(&mut self, cpu_id: usize) {
        self.cpu_scheduler_mut(cpu_id).online = true;
    }

    fn request_reschedule_on_cpu(&mut self, cpu_id: usize) {
        self.cpu_scheduler_mut(cpu_id).reschedule_requested = true;
        if cpu_id != self.current_cpu_id() && self.cpu_is_online(cpu_id) {
            crate::arch::ipi::send_reschedule(cpu_id);
        }
    }

    fn take_reschedule_requested(&mut self, cpu_id: usize) -> bool {
        core::mem::take(&mut self.cpu_scheduler_mut(cpu_id).reschedule_requested)
    }

    fn choose_wake_cpu(&self, thread_id: ThreadId) -> usize {
        let current_cpu_id = self.current_cpu_id();
        if let Some(running_cpu_id) = self.running_cpu_for_thread(thread_id) {
            return running_cpu_id;
        }
        let preferred_cpu = self
            .threads
            .get(&thread_id)
            .map(|thread| thread.last_cpu)
            .unwrap_or(current_cpu_id);
        // Preserve first-run and wakeup affinity before considering arbitrary idle CPUs.
        // Brand-new threads inherit the creator CPU as `last_cpu`; preferring that CPU avoids
        // remote-first activation on an unrelated AP before the thread has ever executed.
        if self.cpu_is_online(preferred_cpu) && self.cpu_is_idle(preferred_cpu) {
            return preferred_cpu;
        }
        if self.cpu_is_online(preferred_cpu) {
            return preferred_cpu;
        }
        if let Some((&idle_cpu_id, _)) = self.cpu_schedulers.iter().find(|(_, scheduler)| {
            scheduler.online
                && scheduler.current_thread_id.is_none()
                && scheduler.run_queue.is_empty()
        }) {
            return idle_cpu_id;
        }
        if self.cpu_is_online(current_cpu_id) {
            return current_cpu_id;
        }
        current_cpu_id
    }

    fn current_cpu_id(&self) -> usize {
        crate::arch::apic::this_apic_id() as usize
    }

    fn current_cpu_now_ns(&self) -> i64 {
        crate::time::now_ns()
    }

    fn arm_current_slice_from(&mut self, now: i64) {
        let scheduler = self.current_cpu_scheduler_mut();
        scheduler.current_runtime_started_ns = Some(now);
        scheduler.slice_deadline_ns = now.checked_add(DEFAULT_TIME_SLICE_NS);
    }

    fn clear_current_slice_state(&mut self) {
        let scheduler = self.current_cpu_scheduler_mut();
        scheduler.current_runtime_started_ns = None;
        scheduler.slice_deadline_ns = None;
    }

    fn account_current_runtime_until(&mut self, now: i64) -> Result<(), zx_status_t> {
        let current_thread_id = self.current_thread_id()?;
        let scheduler = self.current_cpu_scheduler_mut();
        let Some(started_ns) = scheduler.current_runtime_started_ns else {
            scheduler.current_runtime_started_ns = Some(now);
            return Ok(());
        };
        let elapsed_ns = now.saturating_sub(started_ns).max(0) as u64;
        scheduler.current_runtime_started_ns = Some(now);
        let thread = self
            .threads
            .get_mut(&current_thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        thread.runtime_ns = thread.runtime_ns.saturating_add(elapsed_ns);
        Ok(())
    }

    pub(crate) fn note_current_cpu_timer_tick(&mut self, now: i64) -> Result<(), zx_status_t> {
        let scheduler = self.current_cpu_scheduler_mut();
        if scheduler.current_thread_id.is_none() {
            scheduler.current_runtime_started_ns = None;
            scheduler.slice_deadline_ns = None;
            return Ok(());
        }
        let _ = scheduler;
        self.account_current_runtime_until(now)?;
        if self
            .current_cpu_scheduler()?
            .slice_deadline_ns
            .is_some_and(|deadline| now >= deadline)
        {
            self.current_cpu_scheduler_mut().slice_deadline_ns =
                now.checked_add(DEFAULT_TIME_SLICE_NS);
            self.request_reschedule_on_cpu(self.current_cpu_id());
        }
        Ok(())
    }

    pub(crate) fn timer_interrupt_requires_trap_exit(
        &mut self,
        now: i64,
    ) -> Result<bool, zx_status_t> {
        self.note_current_cpu_timer_tick(now)?;
        if self.current_cpu_scheduler()?.reschedule_requested {
            return Ok(true);
        }
        Ok(!matches!(
            self.current_thread()?.state,
            ThreadState::Runnable
        ))
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
            ThreadState::Blocked { .. } => {
                if let Some((_, registration)) = self.take_wait_registration(thread_id) {
                    self.remove_wait_source_membership(thread_id, registration);
                }
            }
            ThreadState::New | ThreadState::Runnable | ThreadState::Suspended => {}
        }

        if let Some(cpu_id) = self.running_cpu_for_thread(thread_id) {
            let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
            thread.state = ThreadState::TerminationPending;
            thread.queued_on_cpu = None;
            let _ = thread;
            self.request_reschedule_on_cpu(cpu_id);
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
        let running_cpu_id = self.running_cpu_for_thread(thread_id);
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if matches!(thread.state, ThreadState::Terminated) {
            return Ok(());
        }
        thread.state = ThreadState::Terminated;
        thread.queued_on_cpu = None;
        thread.context = None;
        self.task_lifecycle_dirty = true;
        let _ = thread;
        if let Some(cpu_id) = running_cpu_id {
            self.request_reschedule_on_cpu(cpu_id);
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
        let running_cpu_id = self.running_cpu_for_thread(thread_id);
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if !matches!(thread.state, ThreadState::Suspended) {
            return Ok(());
        }
        thread.state = ThreadState::Runnable;
        let queued_on_cpu = thread.queued_on_cpu;
        let _ = thread;
        if let Some(cpu_id) = running_cpu_id {
            self.request_reschedule_on_cpu(cpu_id);
            return Ok(());
        }
        if let Some(cpu_id) = queued_on_cpu {
            self.request_reschedule_on_cpu(cpu_id);
            return Ok(());
        }
        let target_cpu = self.choose_wake_cpu(thread_id);
        self.enqueue_runnable_thread_on_cpu(thread_id, target_cpu)?;
        self.request_reschedule_on_cpu(target_cpu);
        Ok(())
    }

    fn enqueue_runnable_thread(&mut self, thread_id: ThreadId) -> Result<(), zx_status_t> {
        self.enqueue_runnable_thread_on_cpu(thread_id, self.current_cpu_id())
    }

    fn enqueue_runnable_thread_on_cpu(
        &mut self,
        thread_id: ThreadId,
        cpu_id: usize,
    ) -> Result<(), zx_status_t> {
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if thread.queued_on_cpu.is_some() || !matches!(thread.state, ThreadState::Runnable) {
            return Ok(());
        }
        thread.queued_on_cpu = Some(cpu_id);
        let _ = thread;
        self.cpu_scheduler_mut(cpu_id)
            .run_queue
            .push_back(thread_id);
        Ok(())
    }

    fn enqueue_runnable_thread_front(&mut self, thread_id: ThreadId) -> Result<(), zx_status_t> {
        self.enqueue_runnable_thread_front_on_cpu(thread_id, self.current_cpu_id())
    }

    fn enqueue_runnable_thread_front_on_cpu(
        &mut self,
        thread_id: ThreadId,
        cpu_id: usize,
    ) -> Result<(), zx_status_t> {
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if thread.queued_on_cpu.is_some() || !matches!(thread.state, ThreadState::Runnable) {
            return Ok(());
        }
        thread.queued_on_cpu = Some(cpu_id);
        let _ = thread;
        self.cpu_scheduler_mut(cpu_id)
            .run_queue
            .push_front(thread_id);
        Ok(())
    }

    fn requeue_current_thread(&mut self) -> Result<(), zx_status_t> {
        let thread_id = self.current_thread_id()?;
        self.enqueue_runnable_thread_on_cpu(thread_id, self.current_cpu_id())
    }

    fn pop_runnable_thread(&mut self) -> Option<ThreadId> {
        let current_cpu_id = self.current_cpu_id();
        loop {
            let thread_id = self
                .cpu_scheduler_mut(current_cpu_id)
                .run_queue
                .pop_front()?;
            let Some(thread) = self.threads.get_mut(&thread_id) else {
                continue;
            };
            if thread.queued_on_cpu != Some(current_cpu_id) {
                continue;
            }
            thread.queued_on_cpu = None;
            if matches!(thread.state, ThreadState::Runnable) {
                return Some(thread_id);
            }
        }
    }

    fn activate_thread_on_current_cpu(
        &mut self,
        thread_id: ThreadId,
    ) -> Result<UserContext, zx_status_t> {
        let current_cpu_id = self.current_cpu_id();
        let previous_thread_id = self.current_cpu_scheduler()?.current_thread_id;
        let current_address_space_id = if let Some(current_thread_id) = previous_thread_id {
            let process_id = self
                .threads
                .get(&current_thread_id)
                .ok_or(ZX_ERR_BAD_STATE)?
                .process_id;
            Some(self.process(process_id)?.address_space_id)
        } else {
            None
        };
        let next_process_id = self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .process_id;
        let next_address_space_id = self.process(next_process_id)?.address_space_id;
        let next_page_tables = self.with_vm(|vm| vm.root_page_table(next_address_space_id))?;
        let context = self
            .threads
            .get_mut(&thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .context
            .ok_or(ZX_ERR_BAD_STATE)?;
        next_page_tables.activate().map_err(map_page_table_error)?;
        if let Some(current_address_space_id) = current_address_space_id {
            if current_address_space_id != next_address_space_id {
                self.with_vm_mut(|vm| {
                    vm.note_cpu_inactive(current_address_space_id, current_cpu_id)
                });
            }
        }
        self.observe_cpu_tlb_epoch_for_address_space(next_address_space_id, current_cpu_id);
        self.current_cpu_scheduler_mut().current_thread_id = Some(thread_id);
        self.arm_current_slice_from(self.current_cpu_now_ns());
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        thread.last_cpu = current_cpu_id;
        Ok(context)
    }

    pub(crate) fn take_current_cpu_idle_context(
        &mut self,
    ) -> Result<Option<UserContext>, zx_status_t> {
        let current_cpu_id = self.current_cpu_id();
        self.mark_cpu_online(current_cpu_id);
        if self.current_cpu_scheduler()?.current_thread_id.is_some() {
            return Err(ZX_ERR_BAD_STATE);
        }
        let _ = self.take_reschedule_requested(current_cpu_id);
        let Some(thread_id) = self.pop_runnable_thread() else {
            return Ok(None);
        };
        self.activate_thread_on_current_cpu(thread_id).map(Some)
    }

    fn switch_to_thread(
        &mut self,
        thread_id: ThreadId,
        trap: &mut crate::arch::int80::TrapFrame,
        cpu_frame: *mut u64,
    ) -> Result<(), zx_status_t> {
        let context = self.activate_thread_on_current_cpu(thread_id)?;
        context.restore(trap, cpu_frame)?;
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

    pub(crate) fn current_address_space_id(&self) -> Result<AddressSpaceId, zx_status_t> {
        Ok(self.current_process()?.address_space_id)
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
        let running_cpu_id = self.running_cpu_for_thread(thread_id);
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
        if hold_suspended {
            thread.queued_on_cpu = None;
        }
        let queued_on_cpu = thread.queued_on_cpu;
        let _ = thread;
        if hold_suspended {
            if let Some(cpu_id) = running_cpu_id {
                self.request_reschedule_on_cpu(cpu_id);
            }
            return Ok(());
        }
        if let Some(cpu_id) = running_cpu_id {
            self.request_reschedule_on_cpu(cpu_id);
            return Ok(());
        }
        if queued_on_cpu.is_none() {
            let target_cpu = self.choose_wake_cpu(thread_id);
            if matches!(previous_state, ThreadState::Blocked { .. }) {
                self.enqueue_runnable_thread_front_on_cpu(thread_id, target_cpu)?;
            } else {
                self.enqueue_runnable_thread_on_cpu(thread_id, target_cpu)?;
            }
            self.request_reschedule_on_cpu(target_cpu);
        } else if let Some(cpu_id) = queued_on_cpu {
            self.request_reschedule_on_cpu(cpu_id);
        }
        Ok(())
    }

    pub(crate) fn wake_thread(
        &mut self,
        thread_id: ThreadId,
        reason: WakeReason,
    ) -> Result<(), zx_status_t> {
        match reason {
            WakeReason::Status(status) => self.make_thread_runnable_inner(thread_id, Some(status)),
            WakeReason::PreserveContext => self.make_thread_runnable_inner(thread_id, None),
        }
    }

    pub(crate) fn request_reschedule(&mut self) {
        self.request_reschedule_on_cpu(self.current_cpu_id());
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

/// Apply one or more committed TLB requirements against the current CPU and any tracked
/// active peer CPUs for the affected address spaces.
pub(crate) fn apply_tlb_commit_reqs(
    vm_handle: &Arc<Mutex<VmDomain>>,
    current_cpu_id: usize,
    current_address_space_id: Option<AddressSpaceId>,
    reqs: &[TlbCommitReq],
) -> Result<(), zx_status_t> {
    let mut strict_address_spaces = BTreeSet::new();
    for req in reqs {
        if req.class() == CommitClass::Strict {
            strict_address_spaces.insert(req.address_space_id());
        }
    }

    for address_space_id in strict_address_spaces {
        let current_cpu_active = current_address_space_id == Some(address_space_id);
        let plan = {
            let mut vm = vm_handle.lock();
            vm.plan_strict_tlb_sync(address_space_id, current_cpu_id, current_cpu_active)?
        };
        let Some(plan) = plan else {
            continue;
        };

        if plan.local_needs_flush {
            crate::arch::tlb::flush_all_local();
        }
        if !plan.remote_cpus.is_empty() {
            crate::arch::ipi::shootdown_all(&plan.remote_cpus)?;
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
            tlb_cpus: TlbCpuTracker::default(),
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
            .register_snapshot(global_vmo_id, &snapshot)?;
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

    fn register_pager_backed_global_vmo(
        &mut self,
        global_vmo_id: KernelVmoId,
        bytes: &'static [u8],
    ) -> Result<(), zx_status_t> {
        self.global_vmos
            .lock()
            .register_pager_read_only(global_vmo_id, bytes)
    }

    fn register_pager_file_global_vmo(
        &mut self,
        global_vmo_id: KernelVmoId,
        size_bytes: u64,
        read_at: PagerReadAtFn,
    ) -> Result<(), zx_status_t> {
        self.register_pager_source_handle(
            global_vmo_id,
            PagerSourceHandle::new(FilePagerSource {
                size_bytes,
                read_at,
            }),
        )
    }

    fn register_pager_source_handle(
        &mut self,
        global_vmo_id: KernelVmoId,
        source: PagerSourceHandle,
    ) -> Result<(), zx_status_t> {
        self.global_vmos
            .lock()
            .register_pager_source(global_vmo_id, source)
    }

    pub(crate) fn bootstrap_user_runner_global_vmo_id(&self) -> Option<KernelVmoId> {
        self.bootstrap_user_runner_global_vmo_id
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
            .import_vmo_alias(
                global_vmo.source.kind(),
                global_vmo.size_bytes,
                global_vmo_id,
            )
            .map_err(map_address_space_error)?;
        for (page_index, frame_id) in global_vmo.source.frames().iter().copied().enumerate() {
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

    fn promote_local_vmo_to_shared(
        &mut self,
        owner_address_space_id: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<(), zx_status_t> {
        self.register_global_vmo_from_address_space(owner_address_space_id, global_vmo_id)?;
        let (kind, size_bytes) = self
            .address_spaces
            .get(&owner_address_space_id)
            .and_then(|space| space.snapshot_vmo(global_vmo_id))
            .map(|snapshot| (snapshot.kind(), snapshot.size_bytes()))
            .ok_or(ZX_ERR_BAD_STATE)?;
        let address_space = self
            .address_spaces
            .get_mut(&owner_address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let _ = address_space
            .import_vmo_alias(kind, size_bytes, global_vmo_id)
            .map_err(map_address_space_error)?;
        Ok(())
    }

    fn ensure_vmo_backing_for_mapping(
        &mut self,
        target_address_space_id: AddressSpaceId,
        vmo: &crate::object::VmoObject,
    ) -> Result<VmoId, zx_status_t> {
        match vmo.backing_scope() {
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                local_vmo_id,
            } if owner_address_space_id == target_address_space_id => Ok(local_vmo_id),
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                ..
            } => {
                self.promote_local_vmo_to_shared(owner_address_space_id, vmo.global_vmo_id())?;
                self.import_global_vmo_into_address_space(
                    target_address_space_id,
                    vmo.global_vmo_id(),
                )
            }
            crate::object::VmoBackingScope::GlobalShared => self
                .import_global_vmo_into_address_space(target_address_space_id, vmo.global_vmo_id()),
        }
    }

    pub(crate) fn promote_vmo_object_to_shared(
        &mut self,
        vmo: &crate::object::VmoObject,
    ) -> Result<bool, zx_status_t> {
        match vmo.backing_scope() {
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                ..
            } => {
                self.promote_local_vmo_to_shared(owner_address_space_id, vmo.global_vmo_id())?;
                Ok(true)
            }
            crate::object::VmoBackingScope::GlobalShared => Ok(false),
        }
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
        let local_vmo_id =
            self.with_address_space_frames_mut(address_space_id, |address_space, frames| {
                address_space
                    .create_anonymous_vmo(frames, size, global_vmo_id)
                    .map(|vmo| vmo.id())
                    .map_err(map_address_space_error)
            })?;
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

    pub(crate) fn create_pager_backed_vmo_for_address_space(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
        bytes: &'static [u8],
        global_vmo_id: KernelVmoId,
    ) -> Result<CreatedVmo, zx_status_t> {
        self.register_pager_backed_global_vmo(global_vmo_id, bytes)?;
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

    pub(crate) fn create_pager_file_vmo_for_address_space(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
        size_bytes: u64,
        read_at: PagerReadAtFn,
        global_vmo_id: KernelVmoId,
    ) -> Result<CreatedVmo, zx_status_t> {
        self.register_pager_file_global_vmo(global_vmo_id, size_bytes, read_at)?;
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

    pub(crate) fn import_bootstrap_user_runner_vmo_for_address_space(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
    ) -> Result<CreatedVmo, zx_status_t> {
        let global_vmo_id = self
            .bootstrap_user_runner_global_vmo_id
            .ok_or(ZX_ERR_NOT_FOUND)?;
        let local_vmo_id =
            self.import_global_vmo_into_address_space(address_space_id, global_vmo_id)?;
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

    pub(crate) fn import_bootstrap_user_code_vmo_for_address_space(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
    ) -> Result<CreatedVmo, zx_status_t> {
        let global_vmo_id = self
            .bootstrap_user_code_global_vmo_id
            .ok_or(ZX_ERR_NOT_FOUND)?;
        let local_vmo_id =
            self.import_global_vmo_into_address_space(address_space_id, global_vmo_id)?;
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

    pub(crate) fn import_bootstrap_process_image_for_address_space(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
    ) -> Result<ImportedProcessImage, zx_status_t> {
        let code_vmo =
            self.import_bootstrap_user_code_vmo_for_address_space(process_id, address_space_id)?;
        Ok(ImportedProcessImage {
            code_vmo,
            layout: crate::userspace::bootstrap_process_image_layout()
                .unwrap_or_else(ProcessImageLayout::bootstrap_conformance),
        })
    }

    fn map_existing_local_vmo_fixed(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        base: u64,
        len: u64,
        local_vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
    ) -> Result<(), zx_status_t> {
        self.with_address_space_frames_mut(address_space_id, |address_space, frames| {
            address_space
                .map_vmo_fixed(frames, vmar_id, base, len, local_vmo_id, vmo_offset, perms)
                .map_err(map_address_space_error)
        })?;
        self.install_mapping_pages(address_space_id, base, len)?;
        Ok(())
    }

    pub(crate) fn prepare_process_start(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
        global_vmo_id: KernelVmoId,
        layout: &ProcessImageLayout,
    ) -> Result<PreparedProcessStart, zx_status_t> {
        let stack = build_process_start_stack_image(
            crate::userspace::USER_STACK_VA,
            PROCESS_START_STACK_BYTES,
            layout,
        )?;
        self.prepare_process_start_with_stack_image(
            process_id,
            address_space_id,
            global_vmo_id,
            layout,
            layout.entry(),
            stack.stack_pointer,
            stack.stack_vmo_offset,
            &stack.image,
        )
    }

    pub(crate) fn prepare_linux_process_start(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
        global_vmo_id: KernelVmoId,
        layout: &ProcessImageLayout,
        exec_spec: ax_linux_exec_spec_header_t,
        stack_image: &[u8],
    ) -> Result<PreparedProcessStart, zx_status_t> {
        validate_linux_exec_stack_spec(exec_spec, stack_image)?;
        self.prepare_process_start_with_stack_image(
            process_id,
            address_space_id,
            global_vmo_id,
            layout,
            exec_spec.entry,
            exec_spec.stack_pointer,
            exec_spec.stack_vmo_offset,
            stack_image,
        )
    }

    fn prepare_process_start_with_stack_image(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
        global_vmo_id: KernelVmoId,
        layout: &ProcessImageLayout,
        entry: u64,
        stack_pointer: u64,
        stack_vmo_offset: u64,
        stack_image: &[u8],
    ) -> Result<PreparedProcessStart, zx_status_t> {
        let root_vmar_id = {
            let address_space = self
                .address_spaces
                .get(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            let root = address_space.root_vmar();
            root.id()
        };

        let local_vmo_id =
            self.import_global_vmo_into_address_space(address_space_id, global_vmo_id)?;
        if layout.segments().is_empty() {
            self.map_existing_local_vmo_fixed(
                address_space_id,
                root_vmar_id,
                layout.code_base(),
                crate::userspace::USER_CODE_BYTES,
                local_vmo_id,
                0,
                process_image_default_code_perms() | MappingPerms::USER,
            )?;
        } else {
            for segment in layout.segments() {
                let map_base = segment.vaddr() & !(crate::userspace::USER_PAGE_BYTES - 1);
                let map_offset = segment.vmo_offset() & !(crate::userspace::USER_PAGE_BYTES - 1);
                let page_delta = segment
                    .vaddr()
                    .checked_sub(map_base)
                    .ok_or(ZX_ERR_OUT_OF_RANGE)?;
                let len = align_up_user_page(
                    page_delta
                        .checked_add(segment.mem_size_bytes())
                        .ok_or(ZX_ERR_OUT_OF_RANGE)?,
                )?;
                if len == 0 {
                    continue;
                }
                let perms = segment.perms() | MappingPerms::USER;
                if perms.contains(MappingPerms::WRITE) {
                    let private_global_vmo_id = self.alloc_global_vmo_id();
                    let private_vmo = self.create_anonymous_vmo_for_address_space(
                        process_id,
                        address_space_id,
                        len,
                        private_global_vmo_id,
                    )?;
                    self.map_existing_local_vmo_fixed(
                        address_space_id,
                        root_vmar_id,
                        map_base,
                        len,
                        private_vmo.vmo_id(),
                        0,
                        perms,
                    )?;
                    if segment.file_size_bytes() != 0 {
                        let bytes = self.read_shared_vmo_bytes(
                            global_vmo_id,
                            segment.vmo_offset(),
                            usize::try_from(segment.file_size_bytes())
                                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                        )?;
                        self.write_local_vmo_bytes(
                            address_space_id,
                            private_vmo.vmo_id(),
                            page_delta,
                            &bytes,
                        )?;
                    }
                } else {
                    self.map_existing_local_vmo_fixed(
                        address_space_id,
                        root_vmar_id,
                        map_base,
                        len,
                        local_vmo_id,
                        map_offset,
                        perms,
                    )?;
                }
            }
        }

        let stack_global_vmo_id = self.alloc_global_vmo_id();
        let stack_vmo = self.create_anonymous_vmo_for_address_space(
            process_id,
            address_space_id,
            PROCESS_START_STACK_BYTES,
            stack_global_vmo_id,
        )?;
        self.map_existing_local_vmo_fixed(
            address_space_id,
            root_vmar_id,
            crate::userspace::USER_STACK_VA,
            PROCESS_START_STACK_BYTES,
            stack_vmo.vmo_id(),
            0,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
        )?;
        self.write_local_vmo_bytes(
            address_space_id,
            stack_vmo.vmo_id(),
            stack_vmo_offset,
            stack_image,
        )?;

        Ok(PreparedProcessStart {
            entry,
            stack_top: stack_pointer,
        })
    }

    fn local_vmo_snapshot(
        &self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
    ) -> Result<Vmo, zx_status_t> {
        self.address_spaces
            .get(&owner_address_space_id)
            .and_then(|space| space.vm.vmo(local_vmo_id))
            .cloned()
            .ok_or(ZX_ERR_BAD_STATE)
    }

    fn ensure_local_vmo_frame(
        &mut self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
        page_offset: u64,
    ) -> Result<FrameId, zx_status_t> {
        if let Some(frame_id) = self
            .address_spaces
            .get(&owner_address_space_id)
            .and_then(|space| space.vm.vmo(local_vmo_id))
            .and_then(|vmo| vmo.frame_at_offset(page_offset))
        {
            return Ok(frame_id);
        }

        let new_frame_paddr =
            crate::userspace::alloc_bootstrap_zeroed_page().ok_or(ZX_ERR_NO_MEMORY)?;
        let bound =
            self.with_address_space_frames_mut(owner_address_space_id, |address_space, frames| {
                if let Some(frame_id) = address_space
                    .vm
                    .vmo(local_vmo_id)
                    .and_then(|vmo| vmo.frame_at_offset(page_offset))
                {
                    return Ok((frame_id, false));
                }
                let new_frame_id = frames
                    .register_existing(new_frame_paddr)
                    .map_err(|_| ZX_ERR_BAD_STATE)?;
                address_space
                    .set_vmo_frame(local_vmo_id, page_offset, new_frame_id)
                    .map_err(map_address_space_error)?;
                Ok((new_frame_id, true))
            })?;
        if !bound.1 {
            crate::userspace::free_bootstrap_page(new_frame_paddr);
        }
        Ok(bound.0)
    }

    fn attach_local_vmo_page_aliases(
        &mut self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
        page_offset: u64,
        frame_id: FrameId,
    ) -> Result<(), zx_status_t> {
        let page_bases =
            self.with_address_space_frames_mut(owner_address_space_id, |address_space, frames| {
                address_space
                    .vm
                    .materialize_vmo_page_aliases(frames, local_vmo_id, page_offset, frame_id)
                    .map_err(map_address_space_error)
            })?;
        for page_base in page_bases {
            self.sync_mapping_pages(
                owner_address_space_id,
                page_base,
                crate::userspace::USER_PAGE_BYTES,
            )?;
        }
        self.validate_frame_mapping_invariants(frame_id, "attach_local_vmo_page_aliases");
        Ok(())
    }

    fn attach_global_vmo_page_aliases(
        &mut self,
        global_vmo_id: KernelVmoId,
        page_offset: u64,
        frame_id: FrameId,
    ) -> Result<(), zx_status_t> {
        let address_space_ids = self.address_space_ids_importing_global_vmo(global_vmo_id);
        for address_space_id in address_space_ids {
            let Some(local_vmo_id) = self
                .address_spaces
                .get(&address_space_id)
                .and_then(|space| space.local_vmo_id(global_vmo_id))
            else {
                continue;
            };
            let page_bases =
                self.with_address_space_frames_mut(address_space_id, |address_space, frames| {
                    address_space
                        .vm
                        .materialize_vmo_page_aliases(frames, local_vmo_id, page_offset, frame_id)
                        .map_err(map_address_space_error)
                })?;
            for page_base in page_bases {
                self.sync_mapping_pages(
                    address_space_id,
                    page_base,
                    crate::userspace::USER_PAGE_BYTES,
                )?;
            }
        }
        self.validate_frame_mapping_invariants(frame_id, "attach_global_vmo_page_aliases");
        Ok(())
    }

    fn read_shared_vmo_bytes(
        &self,
        global_vmo_id: KernelVmoId,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, zx_status_t> {
        let snapshot = self.global_vmos.lock().snapshot(global_vmo_id)?;
        if !snapshot.source.kind().supports_kernel_read() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        validate_vmo_io_range(snapshot.size_bytes, offset, len)?;
        if len == 0 {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        out.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
        out.resize(len, 0);

        let page_bytes = crate::userspace::USER_PAGE_BYTES as usize;
        let mut copied = 0usize;
        while copied < len {
            let absolute = offset
                .checked_add(copied as u64)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_index = usize::try_from(absolute / crate::userspace::USER_PAGE_BYTES)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let page_byte_offset = usize::try_from(absolute % crate::userspace::USER_PAGE_BYTES)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let chunk_len = core::cmp::min(page_bytes - page_byte_offset, len - copied);
            let dst = &mut out[copied..copied + chunk_len];
            match snapshot.source.frames().get(page_index).copied().flatten() {
                Some(frame_id) => {
                    crate::copy::read_bootstrap_frame_bytes(frame_id.raw(), page_byte_offset, dst)?;
                }
                None if snapshot.source.kind() == VmoKind::Anonymous => {
                    crate::copy::zero_fill(dst);
                }
                None => {
                    if !snapshot.source.read_bytes_into(absolute, dst)? {
                        return Err(ZX_ERR_BAD_STATE);
                    }
                }
            }
            copied += chunk_len;
        }

        Ok(out)
    }

    fn read_local_vmo_bytes(
        &self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, zx_status_t> {
        let snapshot = self.local_vmo_snapshot(owner_address_space_id, local_vmo_id)?;
        if !snapshot.kind().supports_kernel_read() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        validate_vmo_io_range(snapshot.size_bytes(), offset, len)?;
        if len == 0 {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        out.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
        out.resize(len, 0);

        let page_bytes = crate::userspace::USER_PAGE_BYTES as usize;
        let mut copied = 0usize;
        while copied < len {
            let absolute = offset
                .checked_add(copied as u64)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_index = usize::try_from(absolute / crate::userspace::USER_PAGE_BYTES)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let page_byte_offset = usize::try_from(absolute % crate::userspace::USER_PAGE_BYTES)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let chunk_len = core::cmp::min(page_bytes - page_byte_offset, len - copied);
            let dst = &mut out[copied..copied + chunk_len];
            match snapshot.frames().get(page_index).copied().flatten() {
                Some(frame_id) => {
                    crate::copy::read_bootstrap_frame_bytes(frame_id.raw(), page_byte_offset, dst)?;
                }
                None if snapshot.kind() == VmoKind::Anonymous => crate::copy::zero_fill(dst),
                None => return Err(ZX_ERR_BAD_STATE),
            }
            copied += chunk_len;
        }

        Ok(out)
    }

    pub(crate) fn read_vmo_bytes(
        &self,
        vmo: &crate::object::VmoObject,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, zx_status_t> {
        match vmo.backing_scope() {
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                local_vmo_id,
            } => self.read_local_vmo_bytes(owner_address_space_id, local_vmo_id, offset, len),
            crate::object::VmoBackingScope::GlobalShared => {
                self.read_shared_vmo_bytes(vmo.global_vmo_id(), offset, len)
            }
        }
    }

    fn write_shared_vmo_bytes(
        &mut self,
        global_vmo_id: KernelVmoId,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), zx_status_t> {
        let snapshot = self.global_vmos.lock().snapshot(global_vmo_id)?;
        if !snapshot.source.kind().supports_kernel_write() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        validate_vmo_io_range(snapshot.size_bytes, offset, bytes.len())?;
        if bytes.is_empty() {
            return Ok(());
        }

        let page_bytes = crate::userspace::USER_PAGE_BYTES as usize;
        let mut written = 0usize;
        while written < bytes.len() {
            let absolute = offset
                .checked_add(written as u64)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_offset = absolute
                .checked_sub(absolute % crate::userspace::USER_PAGE_BYTES)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_byte_offset = usize::try_from(absolute % crate::userspace::USER_PAGE_BYTES)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let chunk_len = core::cmp::min(page_bytes - page_byte_offset, bytes.len() - written);
            let frame_id = match self.global_vmo_frame(global_vmo_id, page_offset)? {
                Some(frame_id) => frame_id,
                None => match snapshot.source.kind() {
                    VmoKind::Anonymous => {
                        let mut prepared = PreparedFaultWork::NewPage {
                            paddr: crate::userspace::alloc_bootstrap_zeroed_page()
                                .ok_or(ZX_ERR_NO_MEMORY)?,
                        };
                        let frame_id = self.ensure_global_vmo_frame(
                            global_vmo_id,
                            page_offset,
                            &mut prepared,
                        )?;
                        prepared.release_unused();
                        self.attach_global_vmo_page_aliases(global_vmo_id, page_offset, frame_id)?;
                        frame_id
                    }
                    VmoKind::Physical | VmoKind::Contiguous | VmoKind::PagerBacked => {
                        return Err(ZX_ERR_BAD_STATE);
                    }
                },
            };
            crate::copy::write_bootstrap_frame_bytes(
                frame_id.raw(),
                page_byte_offset,
                &bytes[written..written + chunk_len],
            )?;
            written += chunk_len;
        }

        Ok(())
    }

    fn write_local_vmo_bytes(
        &mut self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), zx_status_t> {
        let snapshot = self.local_vmo_snapshot(owner_address_space_id, local_vmo_id)?;
        if !snapshot.kind().supports_kernel_write() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        validate_vmo_io_range(snapshot.size_bytes(), offset, bytes.len())?;
        if bytes.is_empty() {
            return Ok(());
        }

        let page_bytes = crate::userspace::USER_PAGE_BYTES as usize;
        let mut written = 0usize;
        while written < bytes.len() {
            let absolute = offset
                .checked_add(written as u64)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_offset = absolute
                .checked_sub(absolute % crate::userspace::USER_PAGE_BYTES)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_byte_offset = usize::try_from(absolute % crate::userspace::USER_PAGE_BYTES)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let chunk_len = core::cmp::min(page_bytes - page_byte_offset, bytes.len() - written);
            let frame_id = match self
                .address_spaces
                .get(&owner_address_space_id)
                .and_then(|space| space.vm.vmo(local_vmo_id))
                .and_then(|vmo| vmo.frame_at_offset(page_offset))
            {
                Some(frame_id) => frame_id,
                None if snapshot.kind() == VmoKind::Anonymous => {
                    let frame_id = self.ensure_local_vmo_frame(
                        owner_address_space_id,
                        local_vmo_id,
                        page_offset,
                    )?;
                    self.attach_local_vmo_page_aliases(
                        owner_address_space_id,
                        local_vmo_id,
                        page_offset,
                        frame_id,
                    )?;
                    frame_id
                }
                None => return Err(ZX_ERR_BAD_STATE),
            };
            crate::copy::write_bootstrap_frame_bytes(
                frame_id.raw(),
                page_byte_offset,
                &bytes[written..written + chunk_len],
            )?;
            written += chunk_len;
        }

        Ok(())
    }

    pub(crate) fn write_vmo_bytes(
        &mut self,
        vmo: &crate::object::VmoObject,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), zx_status_t> {
        match vmo.backing_scope() {
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                local_vmo_id,
            } => self.write_local_vmo_bytes(owner_address_space_id, local_vmo_id, offset, bytes),
            crate::object::VmoBackingScope::GlobalShared => {
                self.write_shared_vmo_bytes(vmo.global_vmo_id(), offset, bytes)
            }
        }
    }

    fn set_shared_vmo_size(
        &mut self,
        global_vmo_id: KernelVmoId,
        new_size: u64,
    ) -> Result<VmoResizeResult, zx_status_t> {
        if new_size == 0 || (new_size & (crate::userspace::USER_PAGE_BYTES - 1)) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        let snapshot = self.global_vmos.lock().snapshot(global_vmo_id)?;
        if !snapshot.source.kind().supports_resize() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        if new_size == snapshot.size_bytes {
            return Ok(VmoResizeResult {
                new_size,
                retired_frames: Vec::new(),
                barrier_address_spaces: Vec::new(),
            });
        }

        for address_space in self.address_spaces.values() {
            address_space
                .validate_vmo_resize(global_vmo_id, new_size)
                .map_err(map_address_space_error)?;
        }

        let dropped = self.global_vmos.lock().resize(global_vmo_id, new_size)?;
        for address_space in self.address_spaces.values_mut() {
            let _ = address_space
                .resize_vmo(global_vmo_id, new_size)
                .map_err(map_address_space_error)?;
        }
        let retire_plan = self.build_required_frame_retire_plan(&dropped, &[])?;
        Ok(VmoResizeResult::from_retire_plan(new_size, retire_plan))
    }

    fn set_local_vmo_size(
        &mut self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
        new_size: u64,
    ) -> Result<VmoResizeResult, zx_status_t> {
        if new_size == 0 || (new_size & (crate::userspace::USER_PAGE_BYTES - 1)) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        let snapshot = self.local_vmo_snapshot(owner_address_space_id, local_vmo_id)?;
        if !snapshot.kind().supports_resize() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        if new_size == snapshot.size_bytes() {
            return Ok(VmoResizeResult {
                new_size,
                retired_frames: Vec::new(),
                barrier_address_spaces: Vec::new(),
            });
        }

        let dropped = self.with_address_space_frames_mut(
            owner_address_space_id,
            |address_space, _frames| {
                address_space
                    .vm
                    .resize_vmo(local_vmo_id, new_size)
                    .map_err(map_address_space_error)
            },
        )?;
        let retire_plan = self.build_required_frame_retire_plan(&dropped, &[])?;
        Ok(VmoResizeResult::from_retire_plan(new_size, retire_plan))
    }

    pub(crate) fn set_vmo_size(
        &mut self,
        vmo: &crate::object::VmoObject,
        new_size: u64,
    ) -> Result<VmoResizeResult, zx_status_t> {
        match vmo.backing_scope() {
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                local_vmo_id,
            } => self.set_local_vmo_size(owner_address_space_id, local_vmo_id, new_size),
            crate::object::VmoBackingScope::GlobalShared => {
                self.set_shared_vmo_size(vmo.global_vmo_id(), new_size)
            }
        }
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
            TlbCommitReq::strict(address_space_id)
        })
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
        Ok(TlbCommitReq::strict(loaned.address_space_id()))
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
            retire_plan,
        ))
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
    ) -> Result<(u64, TlbCommitReq), zx_status_t> {
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
        Ok((
            mapped_addr,
            if perms.contains(MappingPerms::EXECUTE) {
                TlbCommitReq::strict(address_space_id)
            } else {
                TlbCommitReq::relaxed(address_space_id)
            },
        ))
    }

    pub(crate) fn map_vmo_object_into_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        cpu_id: usize,
        vmar_id: VmarId,
        vmo: &crate::object::VmoObject,
        fixed_vmar_offset: Option<u64>,
        vmo_offset: u64,
        len: u64,
        perms: MappingPerms,
    ) -> Result<(u64, TlbCommitReq), zx_status_t> {
        let local_vmo_id = self.ensure_vmo_backing_for_mapping(address_space_id, vmo)?;
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
        Ok((
            mapped_addr,
            if perms.contains(MappingPerms::EXECUTE) {
                TlbCommitReq::strict(address_space_id)
            } else {
                TlbCommitReq::relaxed(address_space_id)
            },
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
        Ok(TlbCommitReq::strict(address_space_id))
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
        let address_space = self
            .address_spaces
            .get_mut(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let _ = address_space.vmar(vmar_id).ok_or(ZX_ERR_NOT_FOUND)?;
        address_space
            .protect(vmar_id, addr, len, perms)
            .map_err(map_address_space_error)?;
        self.update_mapping_pages(address_space_id, addr, len)?;
        Ok(if strict {
            TlbCommitReq::strict(address_space_id)
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
                if lookup.vmo_kind() != VmoKind::Anonymous
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
                    let mapping = PageMapping::with_perms(
                        frame_id.raw(),
                        lookup.perms().contains(MappingPerms::WRITE),
                        lookup.perms().contains(MappingPerms::EXECUTE),
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
            if lookup.vmo_kind() != VmoKind::Anonymous {
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

pub(crate) fn bootstrap_user_runner_source_size() -> Option<u64> {
    BOOTSTRAP_USER_RUNNER_SOURCE
        .lock()
        .as_ref()
        .map(PagerSourceHandle::size_bytes)
}

pub(crate) fn read_bootstrap_user_runner_source_at(
    offset: u64,
    dst: &mut [u8],
) -> Result<(), zx_status_t> {
    let source = BOOTSTRAP_USER_RUNNER_SOURCE
        .lock()
        .as_ref()
        .cloned()
        .ok_or(ZX_ERR_NOT_FOUND)?;
    source.read_bytes(offset, dst)
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

fn validate_vmo_io_range(size_bytes: u64, offset: u64, len: usize) -> Result<(), zx_status_t> {
    let end = offset
        .checked_add(u64::try_from(len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    if end > size_bytes {
        return Err(ZX_ERR_OUT_OF_RANGE);
    }
    Ok(())
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
