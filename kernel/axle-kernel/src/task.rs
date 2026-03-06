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
use axle_core::{CSpace, CSpaceError, Capability};
use axle_types::status::{
    ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_STATE, ZX_ERR_INTERNAL, ZX_ERR_NO_RESOURCES,
};
use axle_types::{zx_handle_t, zx_status_t};

const CSPACE_MAX_SLOTS: u16 = 16_384;
const CSPACE_QUARANTINE_LEN: usize = 256;
const DEFAULT_RIGHTS: u32 = u32::MAX;
const DEFAULT_OBJECT_GENERATION: u32 = 0;

type ProcessId = u64;
type ThreadId = u64;
type AddressSpaceId = u64;

#[derive(Clone, Copy, Debug)]
struct UserCopyRegion {
    start: u64,
    len: u64,
}

impl UserCopyRegion {
    const fn new(start: u64, len: u64) -> Self {
        Self { start, len }
    }

    fn contains(self, ptr: u64, len: usize) -> bool {
        if len == 0 {
            return false;
        }
        let len_u64 = len as u64;
        let end = match ptr.checked_add(len_u64) {
            Some(v) => v,
            None => return false,
        };
        ptr >= self.start && end <= self.start.saturating_add(self.len)
    }
}

#[derive(Debug)]
struct AddressSpace {
    user_copy_regions: [UserCopyRegion; 2],
}

impl AddressSpace {
    fn bootstrap() -> Self {
        Self {
            user_copy_regions: [
                UserCopyRegion::new(
                    crate::userspace::USER_SHARED_VA,
                    crate::userspace::USER_PAGE_BYTES,
                ),
                UserCopyRegion::new(
                    crate::userspace::USER_STACK_VA,
                    crate::userspace::USER_PAGE_BYTES,
                ),
            ],
        }
    }

    fn validate_user_ptr(&self, ptr: u64, len: usize) -> bool {
        self.user_copy_regions
            .iter()
            .copied()
            .any(|region| region.contains(ptr, len))
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

    fn alloc_handle_for_object(&mut self, object_id: u64) -> Result<zx_handle_t, zx_status_t> {
        let cap = Capability::new(object_id, DEFAULT_RIGHTS, DEFAULT_OBJECT_GENERATION);
        let handle = self.cspace.alloc(cap).map_err(map_alloc_error)?;
        Ok(handle.raw())
    }

    fn lookup_object_id(&self, raw: zx_handle_t) -> Result<u64, zx_status_t> {
        let handle = Handle::from_raw(raw).map_err(|_| ZX_ERR_BAD_HANDLE)?;
        let cap = self.cspace.get(handle).map_err(map_lookup_error)?;
        Ok(cap.object_id())
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
            next_process_id: 1,
            next_thread_id: 1,
            next_address_space_id: 1,
            current_thread_id: 0,
        };

        let address_space_id = kernel.alloc_address_space_id();
        kernel
            .address_spaces
            .insert(address_space_id, AddressSpace::bootstrap());

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
        object_id: u64,
    ) -> Result<zx_handle_t, zx_status_t> {
        self.current_process_mut()?
            .alloc_handle_for_object(object_id)
    }

    pub(crate) fn lookup_current_object_id(&self, raw: zx_handle_t) -> Result<u64, zx_status_t> {
        self.current_process()?.lookup_object_id(raw)
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
