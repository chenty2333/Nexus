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

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use axle_core::handle::Handle;
use axle_core::{CSpace, CSpaceError, Capability, RevocationManager, Signals};
use axle_mm::{
    AddressSpace as VmAddressSpace, AddressSpaceError, CowFaultResolution, FrameId, FrameTable,
    FutexKey, GlobalVmoId, LazyAnonFaultResolution, MappingPerms, PageFaultDecision,
    PageFaultFlags, PteMeta, PteMetaTag, VmaLookup, Vmar, VmarId, Vmo, VmoId, VmoKind,
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
    ZX_ERR_OUT_OF_RANGE, ZX_OK,
};
use axle_types::{
    zx_handle_t, zx_koid_t, zx_port_packet_t, zx_rights_t, zx_signals_t, zx_status_t,
};
use bitflags::bitflags;
use core::mem::size_of;

const CSPACE_MAX_SLOTS: u16 = 16_384;
const CSPACE_QUARANTINE_LEN: usize = 256;

type ProcessId = u64;
type ThreadId = u64;
type AddressSpaceId = u64;
type KernelVmoId = GlobalVmoId;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ThreadState {
    New,
    Runnable,
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

type BootstrapTxCursor = TxCursor<crate::page_table::LockedBootstrapUserPageTable>;

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
}

impl AddressSpace {
    fn bootstrap(frames: &mut FrameTable, vmo_ids: [KernelVmoId; 3]) -> Self {
        let mut vm = VmAddressSpace::new(
            crate::userspace::USER_CODE_VA,
            crate::userspace::USER_REGION_BYTES,
        )
        .expect("bootstrap address-space root must be valid");

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
                crate::userspace::USER_PAGE_BYTES,
                vmo_ids[1],
            )
            .expect("bootstrap shared vmo allocation must succeed");
        let shared_frame = frames
            .register_existing(crate::userspace::user_shared_page_paddr())
            .expect("bootstrap shared frame registration must succeed");
        vm.bind_vmo_frame(shared_vmo, 0, shared_frame)
            .expect("bootstrap shared frame binding must succeed");
        vm.map_fixed(
            frames,
            crate::userspace::USER_SHARED_VA,
            crate::userspace::USER_PAGE_BYTES,
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

        Self { vm }
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
        self.vm.pte_meta(fault_va)
    }

    fn root_vmar(&self) -> Vmar {
        self.vm.root_vmar()
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

    fn map_vmo_fixed(
        &mut self,
        frames: &mut FrameTable,
        base: u64,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
    ) -> Result<(), AddressSpaceError> {
        self.vm
            .map_fixed(frames, base, len, vmo_id, vmo_offset, perms, perms)
    }

    fn unmap(
        &mut self,
        frames: &mut FrameTable,
        base: u64,
        len: u64,
    ) -> Result<(), AddressSpaceError> {
        self.vm.unmap(frames, base, len)
    }

    fn protect(
        &mut self,
        base: u64,
        len: u64,
        new_perms: MappingPerms,
    ) -> Result<(), AddressSpaceError> {
        self.vm.protect(base, len, new_perms)
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
}

#[derive(Debug)]
struct Process {
    koid: zx_koid_t,
    address_space_id: AddressSpaceId,
    cspace: CSpace,
}

impl Process {
    fn bootstrap(address_space_id: AddressSpaceId, koid: zx_koid_t) -> Self {
        Self {
            koid,
            address_space_id,
            cspace: CSpace::new(CSPACE_MAX_SLOTS, CSPACE_QUARANTINE_LEN),
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
}

#[derive(Debug)]
struct Thread {
    process_id: ProcessId,
    koid: zx_koid_t,
    state: ThreadState,
    queued: bool,
    context: Option<UserContext>,
}

/// Internal bootstrap kernel model.
#[derive(Debug)]
pub(crate) struct Kernel {
    processes: BTreeMap<ProcessId, Process>,
    threads: BTreeMap<ThreadId, Thread>,
    address_spaces: BTreeMap<AddressSpaceId, AddressSpace>,
    #[allow(dead_code)]
    frames: FrameTable,
    futexes: crate::futex::FutexTable,
    run_queue: VecDeque<ThreadId>,
    revocations: RevocationManager,
    cow_fault_count: u64,
    next_koid: zx_koid_t,
    next_global_vmo_id: u64,
    next_process_id: ProcessId,
    next_thread_id: ThreadId,
    next_address_space_id: AddressSpaceId,
    current_thread_id: ThreadId,
    reschedule_requested: bool,
}

impl Kernel {
    /// Build the single-process bootstrap kernel model used by the current main branch.
    pub(crate) fn bootstrap() -> Self {
        let mut kernel = Self {
            processes: BTreeMap::new(),
            threads: BTreeMap::new(),
            address_spaces: BTreeMap::new(),
            frames: FrameTable::new(),
            futexes: crate::futex::FutexTable::new(),
            run_queue: VecDeque::new(),
            revocations: RevocationManager::new(),
            cow_fault_count: 0,
            next_koid: 1,
            next_global_vmo_id: 1,
            next_process_id: 1,
            next_thread_id: 1,
            next_address_space_id: 1,
            current_thread_id: 0,
            reschedule_requested: false,
        };
        let bootstrap_vmo_ids = [
            kernel.alloc_global_vmo_id(),
            kernel.alloc_global_vmo_id(),
            kernel.alloc_global_vmo_id(),
        ];
        let bootstrap_address_space =
            AddressSpace::bootstrap(&mut kernel.frames, bootstrap_vmo_ids);

        let address_space_id = kernel.alloc_address_space_id();
        kernel
            .address_spaces
            .insert(address_space_id, bootstrap_address_space);

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
            },
        );
        kernel.current_thread_id = thread_id;
        kernel
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

    pub(crate) fn validate_current_user_ptr(&self, ptr: u64, len: usize) -> bool {
        let Ok(process) = self.current_process() else {
            return false;
        };
        let Some(address_space) = self.address_spaces.get(&process.address_space_id) else {
            return false;
        };
        address_space.validate_user_ptr(ptr, len)
    }

    pub(crate) fn ensure_current_user_range_resident(
        &mut self,
        ptr: u64,
        len: usize,
        for_write: bool,
    ) -> Result<(), zx_status_t> {
        if len == 0 {
            return Ok(());
        }
        if !self.validate_current_user_ptr(ptr, len) {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        let address_space_id = self.current_process()?.address_space_id;
        let start = align_down_page(ptr);
        let end = align_up_page(ptr.checked_add(len as u64).ok_or(ZX_ERR_OUT_OF_RANGE)?)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let mut page_va = start;
        while page_va < end {
            let meta = self
                .address_spaces
                .get(&address_space_id)
                .and_then(|space| space.page_meta(page_va))
                .ok_or(ZX_ERR_INVALID_ARGS)?;
            if for_write && !meta.logical_write() {
                return Err(ZX_ERR_ACCESS_DENIED);
            }
            match meta.tag() {
                PteMetaTag::LazyAnon => {
                    self.materialize_lazy_anon_page(address_space_id, page_va)?;
                }
                PteMetaTag::Present | PteMetaTag::Phys => {
                    if for_write && meta.cow_shared() {
                        self.resolve_copy_on_write_page(address_space_id, page_va)?;
                    }
                }
                _ => return Err(ZX_ERR_BAD_STATE),
            }
            page_va = page_va
                .checked_add(crate::userspace::USER_PAGE_BYTES)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        }
        Ok(())
    }

    /// Resolve a current-thread userspace range back to its VMO mapping metadata.
    #[allow(dead_code)]
    pub(crate) fn lookup_current_user_mapping(&self, ptr: u64, len: usize) -> Option<VmaLookup> {
        let process = self.current_process().ok()?;
        let address_space = self.address_spaces.get(&process.address_space_id)?;
        address_space.lookup_user_mapping(ptr, len)
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
        let address_space = self
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
    }

    pub(crate) fn try_loan_current_user_pages(
        &mut self,
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

        let process = self.current_process()?;
        let address_space_id = process.address_space_id;
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
        let mut pinned = Vec::with_capacity(page_count);
        for page_index in 0..page_count {
            let page_va = ptr + (page_index as u64) * page_size;
            let Some(page_lookup) = self
                .address_spaces
                .get(&address_space_id)
                .and_then(|space| space.lookup_user_mapping(page_va, 1))
            else {
                self.release_loaned_pages_inner(&pinned);
                return Ok(None);
            };
            let Some(frame_id) = page_lookup.frame_id() else {
                self.release_loaned_pages_inner(&pinned);
                return Ok(None);
            };
            self.frames
                .pin(frame_id)
                .map_err(|_| ZX_ERR_BAD_STATE)
                .inspect_err(|_| self.release_loaned_pages_inner(&pinned))?;
            if let Err(_) = self.frames.inc_loan(frame_id) {
                let _ = self.frames.unpin(frame_id);
                self.release_loaned_pages_inner(&pinned);
                return Err(ZX_ERR_BAD_STATE);
            }
            pinned.push(frame_id);
        }

        let len_u32 = u32::try_from(len).map_err(|_| {
            self.release_loaned_pages_inner(&pinned);
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
        self.release_loaned_pages_inner(loaned.pages())
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

        let current_address_space_id = self.current_process()?.address_space_id;
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

        let sender_range = PageRange::new(loaned.base(), len).map_err(map_page_table_error)?;
        let receiver_range = PageRange::new(dst_base, len).map_err(map_page_table_error)?;
        let mut loan_tx = self.lock_channel_loan_tx(
            loaned.address_space_id(),
            sender_range,
            receiver_address_space_id,
            receiver_range,
        )?;
        {
            let receiver = self
                .address_spaces
                .get_mut(&receiver_address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            receiver
                .replace_mapping_frames_copy_on_write(
                    &mut self.frames,
                    dst_base,
                    len,
                    loaned.pages(),
                )
                .map_err(map_address_space_error)?;
        }
        let receiver_cursor = loan_tx.receiver_cursor_mut().ok_or(ZX_ERR_BAD_STATE)?;
        self.sync_mapping_pages_locked(receiver_address_space_id, dst_base, len, receiver_cursor)?;
        loan_tx.commit().map_err(map_page_table_error)?;
        Ok(true)
    }

    pub(crate) fn current_root_vmar(&self) -> Result<RootVmarInfo, zx_status_t> {
        let thread = self.current_thread()?;
        let process = self.current_process()?;
        let address_space = self
            .address_spaces
            .get(&process.address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        Ok(RootVmarInfo {
            process_id: thread.process_id,
            address_space_id: process.address_space_id,
            vmar: address_space.root_vmar(),
        })
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

    pub(crate) fn create_current_anonymous_vmo(
        &mut self,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<CreatedVmo, zx_status_t> {
        let process_id = self.current_thread()?.process_id;
        let address_space_id = self.current_process()?.address_space_id;
        let address_space = self
            .address_spaces
            .get_mut(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let vmo = address_space
            .create_anonymous_vmo(&mut self.frames, size, global_vmo_id)
            .map_err(map_address_space_error)?;
        Ok(CreatedVmo {
            process_id,
            address_space_id,
            vmo,
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
        let address_space = self
            .address_spaces
            .get(&process.address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if !address_space.validate_user_ptr(ptr as u64, size_of::<T>()) {
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

    pub(crate) fn finish_syscall(
        &mut self,
        trap: &mut crate::arch::int80::TrapFrame,
        cpu_frame: *mut u64,
    ) -> Result<(), zx_status_t> {
        match self.current_thread()?.state {
            ThreadState::Runnable => {
                self.capture_current_user_context(trap, cpu_frame.cast_const())?;
                if self.reschedule_requested {
                    self.reschedule_requested = false;
                    if let Some(next_thread_id) = self.pop_runnable_thread() {
                        self.requeue_current_thread()?;
                        self.switch_to_thread(next_thread_id, trap, cpu_frame)?;
                    }
                }
                Ok(())
            }
            ThreadState::New => Err(ZX_ERR_BAD_STATE),
            ThreadState::FutexWait { .. }
            | ThreadState::SignalWait { .. }
            | ThreadState::PortWait { .. } => {
                let next_thread_id = self.pop_runnable_thread().ok_or(ZX_ERR_BAD_STATE)?;
                self.switch_to_thread(next_thread_id, trap, cpu_frame)
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

    pub(crate) fn can_block_current_thread(&self) -> bool {
        !self.run_queue.is_empty()
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
        if !self.processes.contains_key(&process_id) {
            return Err(ZX_ERR_BAD_HANDLE);
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn map_current_vmo_into_vmar(
        &mut self,
        vmar_address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        vmo_address_space_id: AddressSpaceId,
        vmo_id: VmoId,
        vmar_offset: u64,
        vmo_offset: u64,
        len: u64,
        perms: MappingPerms,
    ) -> Result<u64, zx_status_t> {
        if vmar_address_space_id != vmo_address_space_id {
            return Err(ZX_ERR_BAD_STATE);
        }

        let address_space = self
            .address_spaces
            .get_mut(&vmar_address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let root = address_space.root_vmar();
        if root.id() != vmar_id {
            return Err(ZX_ERR_BAD_STATE);
        }
        let mapped_addr = root
            .base()
            .checked_add(vmar_offset)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        address_space
            .map_vmo_fixed(
                &mut self.frames,
                mapped_addr,
                len,
                vmo_id,
                vmo_offset,
                perms,
            )
            .map_err(map_address_space_error)?;
        self.install_mapping_pages(vmar_address_space_id, mapped_addr, len)?;
        Ok(mapped_addr)
    }

    pub(crate) fn unmap_current_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        addr: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        let address_space = self
            .address_spaces
            .get_mut(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if address_space.root_vmar().id() != vmar_id {
            return Err(ZX_ERR_BAD_STATE);
        }
        address_space
            .unmap(&mut self.frames, addr, len)
            .map_err(map_address_space_error)?;
        self.clear_mapping_pages(address_space_id, addr, len)
    }

    pub(crate) fn protect_current_vmar(
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
        if address_space.root_vmar().id() != vmar_id {
            return Err(ZX_ERR_BAD_STATE);
        }
        address_space
            .protect(addr, len, perms)
            .map_err(map_address_space_error)?;
        self.update_mapping_pages(address_space_id, addr, len)
    }

    pub(crate) fn handle_current_page_fault(&mut self, fault_va: u64, error: u64) -> bool {
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

        let process_id = match self.current_thread() {
            Ok(thread) => thread.process_id,
            Err(_) => return false,
        };
        let address_space_id = match self.processes.get(&process_id) {
            Some(process) => process.address_space_id,
            None => return false,
        };

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
            _ => false,
        }
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

    fn enqueue_runnable_thread(&mut self, thread_id: ThreadId) -> Result<(), zx_status_t> {
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if thread.queued || !matches!(thread.state, ThreadState::Runnable) {
            return Ok(());
        }
        thread.queued = true;
        self.run_queue.push_back(thread_id);
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
        let context = self
            .threads
            .get(&thread_id)
            .and_then(|thread| thread.context)
            .ok_or(ZX_ERR_BAD_STATE)?;
        context.restore(trap, cpu_frame)?;
        self.current_thread_id = thread_id;
        Ok(())
    }

    pub(crate) fn make_thread_runnable(
        &mut self,
        thread_id: ThreadId,
        status: zx_status_t,
    ) -> Result<(), zx_status_t> {
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        let Some(context) = thread.context else {
            return Err(ZX_ERR_BAD_STATE);
        };
        thread.context = Some(context.with_status(status));
        thread.state = ThreadState::Runnable;
        let was_current = thread_id == self.current_thread_id;
        let _ = thread;
        if !was_current {
            self.enqueue_runnable_thread(thread_id)?;
            self.reschedule_requested = true;
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

    fn lock_address_space_tx_set(
        &self,
        requests: &[AddressSpaceTxRequest],
    ) -> Result<AddressSpaceTxSet, zx_status_t> {
        let current_address_space_id = self.current_process()?.address_space_id;
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

            if request.key.address_space_id == current_address_space_id {
                let mut page_table = crate::page_table::BootstrapUserPageTable;
                let cursor = TxCursor::new(
                    page_table
                        .lock(request.range)
                        .map_err(map_page_table_error)?,
                );
                tx_set
                    .push_active(request.key, cursor)
                    .map_err(map_page_table_error)?;
            } else {
                tx_set.push_deferred(request.key, request.range);
            }

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
        tx_set.commit().map_err(map_page_table_error)
    }

    fn update_mapping_pages(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        self.sync_mapping_pages(address_space_id, base, len)
    }

    fn resolve_copy_on_write_page(
        &mut self,
        address_space_id: AddressSpaceId,
        fault_va: u64,
    ) -> Result<(), zx_status_t> {
        let lookup = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.lookup_user_mapping(fault_va, 1))
            .ok_or(ZX_ERR_BAD_STATE)?;
        let old_frame_id = lookup.frame_id().ok_or(ZX_ERR_BAD_STATE)?;
        let new_frame_paddr = crate::userspace::alloc_bootstrap_cow_page(old_frame_id.raw())
            .ok_or(ZX_ERR_NO_MEMORY)?;
        let new_frame_id = self
            .frames
            .register_existing(new_frame_paddr)
            .map_err(|_| ZX_ERR_BAD_STATE)?;
        let resolved = {
            let address_space = self
                .address_spaces
                .get_mut(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            address_space
                .resolve_cow_fault(&mut self.frames, fault_va, new_frame_id)
                .map_err(map_address_space_error)?
        };
        self.sync_mapping_pages(
            address_space_id,
            resolved.fault_page_base(),
            crate::userspace::USER_PAGE_BYTES,
        )?;
        self.cow_fault_count = self.cow_fault_count.wrapping_add(1);
        crate::userspace::record_vm_cow_fault_count(self.cow_fault_count);
        Ok(())
    }

    fn materialize_lazy_anon_page(
        &mut self,
        address_space_id: AddressSpaceId,
        fault_va: u64,
    ) -> Result<(), zx_status_t> {
        let new_frame_paddr =
            crate::userspace::alloc_bootstrap_zeroed_page().ok_or(ZX_ERR_NO_MEMORY)?;
        let new_frame_id = self
            .frames
            .register_existing(new_frame_paddr)
            .map_err(|_| ZX_ERR_BAD_STATE)?;
        let resolved = {
            let address_space = self
                .address_spaces
                .get_mut(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            address_space
                .resolve_lazy_anon_fault(&mut self.frames, fault_va, new_frame_id)
                .map_err(map_address_space_error)?
        };
        self.sync_mapping_pages(
            address_space_id,
            resolved.fault_page_base(),
            crate::userspace::USER_PAGE_BYTES,
        )
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
        tx_set.commit().map_err(map_page_table_error)
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

    fn release_loaned_pages_inner(&mut self, pages: &[FrameId]) {
        for &frame_id in pages {
            let _ = self.frames.dec_loan(frame_id);
            let _ = self.frames.unpin(frame_id);
        }
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
        AddressSpaceError::InvalidVmo => ZX_ERR_NOT_FOUND,
        AddressSpaceError::InvalidFrame => ZX_ERR_BAD_STATE,
        AddressSpaceError::AlreadyBound | AddressSpaceError::Overlap => ZX_ERR_ALREADY_EXISTS,
        AddressSpaceError::NotFound => ZX_ERR_NOT_FOUND,
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

fn align_up_page(value: u64) -> Option<u64> {
    value
        .checked_add(crate::userspace::USER_PAGE_BYTES - 1)
        .map(|rounded| rounded & !(crate::userspace::USER_PAGE_BYTES - 1))
}
