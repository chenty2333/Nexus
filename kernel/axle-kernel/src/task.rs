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

use axle_core::handle::Handle;
use axle_core::{CSpace, CSpaceError, Capability, RevocationManager};
use axle_mm::{
    AddressSpace as VmAddressSpace, AddressSpaceError, CowFaultResolution, FrameTable,
    MappingPerms, VmaLookup, VmoKind,
};
use axle_types::status::{
    ZX_ERR_ACCESS_DENIED, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_STATE, ZX_ERR_INTERNAL, ZX_ERR_NO_RESOURCES,
};
use axle_types::{zx_handle_t, zx_status_t};
use bitflags::bitflags;

const CSPACE_MAX_SLOTS: u16 = 16_384;
const CSPACE_QUARANTINE_LEN: usize = 256;

type ProcessId = u64;
type ThreadId = u64;
type AddressSpaceId = u64;

bitflags! {
    /// Internal handle-rights model used by the bootstrap kernel.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct HandleRights: u32 {
        const DUPLICATE = 1 << 0;
        const TRANSFER = 1 << 1;
        const WAIT = 1 << 2;
        const READ = 1 << 3;
        const WRITE = 1 << 4;
        const SIGNAL = 1 << 5;
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
    fn bootstrap(frames: &mut FrameTable) -> Self {
        let mut vm = VmAddressSpace::new(
            crate::userspace::USER_CODE_VA,
            crate::userspace::USER_REGION_BYTES,
        )
        .expect("bootstrap address-space root must be valid");

        let code_vmo = vm
            .create_vmo(VmoKind::Anonymous, crate::userspace::USER_PAGE_BYTES)
            .expect("bootstrap code vmo allocation must succeed");
        let code_frame = frames
            .register_existing(crate::userspace::user_code_page_paddr())
            .expect("bootstrap code frame registration must succeed");
        vm.bind_vmo_frame(code_vmo, 0, code_frame)
            .expect("bootstrap code frame binding must succeed");
        vm.map_fixed(
            frames,
            crate::userspace::USER_CODE_VA,
            crate::userspace::USER_PAGE_BYTES,
            code_vmo,
            0,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::EXECUTE | MappingPerms::USER,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::EXECUTE | MappingPerms::USER,
        )
        .expect("bootstrap code mapping must succeed");

        let shared_vmo = vm
            .create_vmo(VmoKind::Anonymous, crate::userspace::USER_PAGE_BYTES)
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
            .create_vmo(VmoKind::Anonymous, crate::userspace::USER_PAGE_BYTES)
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

    fn resolve_cow_fault(
        &mut self,
        frames: &mut FrameTable,
        fault_va: u64,
        new_frame_id: axle_mm::FrameId,
    ) -> Result<CowFaultResolution, AddressSpaceError> {
        self.vm.resolve_cow_fault(frames, fault_va, new_frame_id)
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
    next_process_id: ProcessId,
    next_thread_id: ThreadId,
    next_address_space_id: AddressSpaceId,
    current_thread_id: ThreadId,
}

impl Kernel {
    /// Build the single-process bootstrap kernel model used by the current main branch.
    pub(crate) fn bootstrap() -> Self {
        let mut frames = FrameTable::new();
        let bootstrap_address_space = AddressSpace::bootstrap(&mut frames);
        let mut kernel = Self {
            processes: BTreeMap::new(),
            threads: BTreeMap::new(),
            address_spaces: BTreeMap::new(),
            frames,
            revocations: RevocationManager::new(),
            next_process_id: 1,
            next_thread_id: 1,
            next_address_space_id: 1,
            current_thread_id: 0,
        };

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
