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
    FutexKey, GlobalVmoId, MappingPerms, VmaLookup, Vmar, VmarId, Vmo, VmoId, VmoKind,
};
use axle_page_table::{PageMapping, PageTableError, TxCursor};
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
    base: u64,
    len: u32,
    needs_cow: bool,
    pages: Vec<FrameId>,
}

impl LoanedUserPages {
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

    fn root_vmar(&self) -> Vmar {
        self.vm.root_vmar()
    }

    fn create_anonymous_vmo(
        &mut self,
        frames: &mut FrameTable,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<Vmo, AddressSpaceError> {
        let vmo_id = self
            .vm
            .create_vmo(VmoKind::Anonymous, size, global_vmo_id)?;
        let page_count = usize::try_from(size / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| AddressSpaceError::InvalidArgs)?;
        for page_index in 0..page_count {
            let paddr = crate::userspace::alloc_bootstrap_zeroed_page().ok_or(
                AddressSpaceError::FrameTable(axle_mm::FrameTableError::CountOverflow),
            )?;
            let frame_id = frames
                .register_existing(paddr)
                .map_err(AddressSpaceError::FrameTable)?;
            self.vm.bind_vmo_frame(
                vmo_id,
                (page_index as u64) * crate::userspace::USER_PAGE_BYTES,
                frame_id,
            )?;
        }
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

    fn arm_copy_on_write(&mut self, base: u64, len: u64) -> Result<(), AddressSpaceError> {
        self.vm.mark_copy_on_write(base, len)
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
                self.unpin_loaned_pages_inner(&pinned);
                return Ok(None);
            };
            let Some(frame_id) = page_lookup.frame_id() else {
                self.unpin_loaned_pages_inner(&pinned);
                return Ok(None);
            };
            self.frames
                .pin(frame_id)
                .map_err(|_| ZX_ERR_BAD_STATE)
                .inspect_err(|_| self.unpin_loaned_pages_inner(&pinned))?;
            pinned.push(frame_id);
        }

        let len_u32 = u32::try_from(len).map_err(|_| {
            self.unpin_loaned_pages_inner(&pinned);
            ZX_ERR_OUT_OF_RANGE
        })?;
        Ok(Some(LoanedUserPages {
            base: ptr,
            len: len_u32,
            needs_cow: lookup.max_perms().contains(MappingPerms::WRITE),
            pages: pinned,
        }))
    }

    pub(crate) fn release_loaned_user_pages(&mut self, loaned: &LoanedUserPages) {
        self.unpin_loaned_pages_inner(loaned.pages())
    }

    pub(crate) fn arm_loaned_user_pages_copy_on_write(
        &mut self,
        loaned: &LoanedUserPages,
    ) -> Result<(), zx_status_t> {
        if !loaned.needs_cow() {
            return Ok(());
        }

        let process = self.current_process()?;
        let address_space_id = process.address_space_id;
        let len = u64::from(loaned.len());
        {
            let address_space = self
                .address_spaces
                .get_mut(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            address_space
                .arm_copy_on_write(loaned.base(), len)
                .map_err(map_address_space_error)?;
        }
        self.update_mapping_pages(address_space_id, loaned.base(), len)
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
        self.clear_mapping_pages(addr, len)
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
        const PF_PRESENT: u64 = 1 << 0;
        const PF_WRITE: u64 = 1 << 1;
        const PF_USER: u64 = 1 << 2;

        if (error & (PF_PRESENT | PF_WRITE | PF_USER)) != (PF_PRESENT | PF_WRITE | PF_USER) {
            return false;
        }

        let process_id = match self.current_thread() {
            Ok(thread) => thread.process_id,
            Err(_) => return false,
        };
        let address_space_id = match self.processes.get(&process_id) {
            Some(process) => process.address_space_id,
            None => return false,
        };

        let lookup = match self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.lookup_user_mapping(fault_va, 1))
        {
            Some(lookup) if lookup.is_copy_on_write() => lookup,
            _ => return false,
        };

        let old_frame_id = match lookup.frame_id() {
            Some(frame_id) => frame_id,
            None => return false,
        };

        let new_frame_paddr = match crate::userspace::alloc_bootstrap_cow_page(old_frame_id.raw()) {
            Some(paddr) => paddr,
            None => return false,
        };
        let new_frame_id = match self.frames.register_existing(new_frame_paddr) {
            Ok(frame_id) => frame_id,
            Err(_) => return false,
        };

        let resolved = {
            let Some(address_space) = self.address_spaces.get_mut(&address_space_id) else {
                return false;
            };
            match address_space.resolve_cow_fault(&mut self.frames, fault_va, new_frame_id) {
                Ok(resolution) => resolution,
                Err(_) => return false,
            }
        };

        let mut page_table = crate::page_table::BootstrapUserPageTable;
        let mut tx = TxCursor::new(&mut page_table);
        if tx
            .map(
                resolved.fault_page_base(),
                crate::userspace::USER_PAGE_BYTES,
                |_| PageMapping::new(new_frame_paddr, true),
            )
            .is_err()
        {
            return false;
        }
        true
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

    fn current_process(&self) -> Result<&Process, zx_status_t> {
        let process_id = self.current_thread()?.process_id;
        self.processes.get(&process_id).ok_or(ZX_ERR_BAD_STATE)
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
        let address_space = self
            .address_spaces
            .get(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let mut page_table = crate::page_table::BootstrapUserPageTable;
        let mut tx = TxCursor::new(&mut page_table);
        tx.map(base, len, |va| {
            let lookup = address_space
                .lookup_user_mapping(va, 1)
                .ok_or(PageTableError::Backend)?;
            let frame_id = lookup.frame_id().ok_or(PageTableError::Backend)?;
            PageMapping::new(frame_id.raw(), lookup.perms().contains(MappingPerms::WRITE))
        })
        .map_err(map_page_table_error)
    }

    fn clear_mapping_pages(&self, base: u64, len: u64) -> Result<(), zx_status_t> {
        let mut page_table = crate::page_table::BootstrapUserPageTable;
        let mut tx = TxCursor::new(&mut page_table);
        tx.unmap(base, len).map_err(map_page_table_error)
    }

    fn update_mapping_pages(
        &self,
        address_space_id: AddressSpaceId,
        base: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        let address_space = self
            .address_spaces
            .get(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let mut page_table = crate::page_table::BootstrapUserPageTable;
        let mut tx = TxCursor::new(&mut page_table);
        tx.protect(base, len, |va| {
            let lookup = address_space
                .lookup_user_mapping(va, 1)
                .ok_or(PageTableError::Backend)?;
            Ok(lookup.perms().contains(MappingPerms::WRITE))
        })
        .map_err(map_page_table_error)
    }

    fn unpin_loaned_pages_inner(&mut self, pages: &[FrameId]) {
        for &frame_id in pages {
            let _ = self.frames.unpin(frame_id);
        }
    }
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
