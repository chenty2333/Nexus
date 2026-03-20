use super::*;

static BOOTSTRAP_USER_RUNNER_SOURCE: Mutex<Option<PagerSourceHandle>> = Mutex::new(None);

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

    pub(crate) fn with_frames_mut<T>(&self, f: impl FnOnce(&mut FrameTable) -> T) -> T {
        self.with_domain_mut(|vm| vm.with_frames_mut(f))
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

    pub(crate) fn create_physical_vmo_global(
        &self,
        base_paddr: u64,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<u64, zx_status_t> {
        self.with_domain_mut(|vm| vm.create_physical_vmo_global(base_paddr, size, global_vmo_id))
    }

    pub(crate) fn create_contiguous_vmo_global(
        &self,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<u64, zx_status_t> {
        self.with_domain_mut(|vm| vm.create_contiguous_vmo_global(size, global_vmo_id))
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

    pub(crate) fn lookup_vmo_paddr(
        &self,
        vmo: &crate::object::VmoObject,
        offset: u64,
    ) -> Result<u64, zx_status_t> {
        self.with_domain(|vm| vm.lookup_vmo_paddr(vmo, offset))
    }

    pub(crate) fn pin_vmo_range(
        &self,
        vmo: &crate::object::VmoObject,
        offset: u64,
        len: u64,
    ) -> Result<axle_mm::PinToken, zx_status_t> {
        self.with_domain_mut(|vm| vm.pin_vmo_range(vmo, offset, len))
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

    pub(crate) fn clone_vmar_mappings(
        &self,
        src_address_space_id: AddressSpaceId,
        src_vmar_id: VmarId,
        dst_address_space_id: AddressSpaceId,
        dst_vmar_id: VmarId,
    ) -> Result<Vec<TlbCommitReq>, zx_status_t> {
        self.with_domain_mut(|vm| {
            vm.clone_vmar_mappings(
                src_address_space_id,
                src_vmar_id,
                dst_address_space_id,
                dst_vmar_id,
            )
        })
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
        cache_policy: MappingCachePolicy,
        private_clone: bool,
        clone_policy: MappingClonePolicy,
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
                cache_policy,
                private_clone,
                clone_policy,
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

impl Kernel {
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
                guest_started: false,
                guest_fs_base: 0,
                fpu_state: crate::arch::fpu::clean_state(),
                state: ThreadState::Runnable,
                queued_on_cpu: None,
                last_cpu: bootstrap_cpu_id,
                runtime_ns: 0,
                wait: WaitNode::default(),
                context: None,
                suspend_tokens: 0,
                remote_wake_enqueued_ns: None,
                remote_wake_source_cpu: None,
                remote_wake_target_cpu: None,
            },
        );
        let now = crate::time::now_ns();
        kernel.cpu_schedulers.insert(
            bootstrap_cpu_id,
            CpuSchedulerState::bootstrap_current(thread_id, now),
        );
        kernel
    }

    pub(crate) fn vm_handle(&self) -> Arc<VmFacade> {
        self.vm.clone()
    }

    pub(super) fn with_vm<T>(&self, f: impl FnOnce(&VmDomain) -> T) -> T {
        self.vm.with_domain(f)
    }

    pub(super) fn with_vm_mut<T>(&self, f: impl FnOnce(&mut VmDomain) -> T) -> T {
        self.vm.with_domain_mut(f)
    }

    pub(super) fn with_faults_mut<T>(&self, f: impl FnOnce(&mut FaultTable) -> T) -> T {
        let faults = self.vm.fault_handle();
        let mut faults = faults.lock();
        f(&mut faults)
    }

    pub(super) fn apply_tlb_commit_reqs_current(
        &self,
        reqs: &[TlbCommitReq],
    ) -> Result<(), zx_status_t> {
        self.vm.apply_tlb_commit_reqs(
            self.current_cpu_id(),
            self.current_address_space_id().ok(),
            reqs,
        )
    }

    pub(super) fn retire_bootstrap_frames_after_quiescence_current(
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
