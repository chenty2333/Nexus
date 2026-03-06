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

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use axle_core::handle::Handle;
use axle_core::{CSpace, CSpaceError, Capability, RevocationManager};
use axle_mm::{
    AddressSpace as VmAddressSpace, AddressSpaceError, CowFaultResolution, FrameId, FrameTable,
    FutexKey, GlobalVmoId, MappingPerms, VmaLookup, Vmar, VmarId, Vmo, VmoId, VmoKind,
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
    ZX_ERR_OUT_OF_RANGE,
};
use axle_types::{zx_handle_t, zx_rights_t, zx_status_t};
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
    address_space_id: AddressSpaceId,
    cspace: CSpace,
}

impl Process {
    fn bootstrap(address_space_id: AddressSpaceId) -> Self {
        Self {
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
}

/// Internal bootstrap kernel model.
#[derive(Debug)]
pub(crate) struct Kernel {
    processes: BTreeMap<ProcessId, Process>,
    threads: BTreeMap<ThreadId, Thread>,
    address_spaces: BTreeMap<AddressSpaceId, AddressSpace>,
    #[allow(dead_code)]
    frames: FrameTable,
    revocations: RevocationManager,
    next_global_vmo_id: u64,
    next_process_id: ProcessId,
    next_thread_id: ThreadId,
    next_address_space_id: AddressSpaceId,
    current_thread_id: ThreadId,
}

impl Kernel {
    /// Build the single-process bootstrap kernel model used by the current main branch.
    pub(crate) fn bootstrap() -> Self {
        let mut kernel = Self {
            processes: BTreeMap::new(),
            threads: BTreeMap::new(),
            address_spaces: BTreeMap::new(),
            frames: FrameTable::new(),
            revocations: RevocationManager::new(),
            next_global_vmo_id: 1,
            next_process_id: 1,
            next_thread_id: 1,
            next_address_space_id: 1,
            current_thread_id: 0,
        };
        let bootstrap_vmo_ids = [
            kernel.alloc_global_vmo_id(),
            kernel.alloc_global_vmo_id(),
            kernel.alloc_global_vmo_id(),
        ];
        let bootstrap_address_space = AddressSpace::bootstrap(
            &mut kernel.frames,
            bootstrap_vmo_ids,
        );

        let address_space_id = kernel.alloc_address_space_id();
        kernel
            .address_spaces
            .insert(address_space_id, bootstrap_address_space);

        let process_id = kernel.alloc_process_id();
        kernel
            .processes
            .insert(process_id, Process::bootstrap(address_space_id));

        let thread_id = kernel.alloc_thread_id();
        kernel.threads.insert(thread_id, Thread { process_id });
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

        if crate::userspace::install_user_page_frame(
            resolved.fault_page_base(),
            new_frame_paddr,
            true,
        )
        .is_err()
        {
            return false;
        }
        crate::arch::tlb::flush_page_global(resolved.fault_page_base());
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
        let page_count = usize::try_from(len / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * crate::userspace::USER_PAGE_BYTES;
            let lookup = address_space
                .lookup_user_mapping(va, 1)
                .ok_or(ZX_ERR_BAD_STATE)?;
            let frame_id = lookup.frame_id().ok_or(ZX_ERR_BAD_STATE)?;
            crate::userspace::install_user_page_frame(
                va,
                frame_id.raw(),
                lookup.perms().contains(MappingPerms::WRITE),
            )
            .map_err(|_| ZX_ERR_BAD_STATE)?;
            crate::arch::tlb::flush_page_global(va);
        }
        Ok(())
    }

    fn clear_mapping_pages(&self, base: u64, len: u64) -> Result<(), zx_status_t> {
        let page_count = usize::try_from(len / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * crate::userspace::USER_PAGE_BYTES;
            crate::userspace::clear_user_page_frame(va).map_err(|_| ZX_ERR_BAD_STATE)?;
            crate::arch::tlb::flush_page_global(va);
        }
        Ok(())
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
        let page_count = usize::try_from(len / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * crate::userspace::USER_PAGE_BYTES;
            let lookup = address_space
                .lookup_user_mapping(va, 1)
                .ok_or(ZX_ERR_BAD_STATE)?;
            crate::userspace::set_user_page_writable(
                va,
                lookup.perms().contains(MappingPerms::WRITE),
            )
            .map_err(|_| ZX_ERR_BAD_STATE)?;
            crate::arch::tlb::flush_page_global(va);
        }
        Ok(())
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
