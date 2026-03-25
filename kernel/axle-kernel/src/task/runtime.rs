use super::*;
use axle_types::koid::ZX_KOID_INVALID;
use axle_types::rights::ZX_RIGHTS_ALL;

/// Kernel-visible description of the bootstrap current thread.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CurrentThreadInfo {
    process_id: ProcessId,
    thread_id: ThreadId,
    koid: zx_koid_t,
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
    pub(super) entry: u64,
    pub(super) stack_top: u64,
}

impl PreparedProcessStart {
    pub(crate) const fn entry(self) -> u64 {
        self.entry
    }

    pub(crate) const fn stack_top(self) -> u64 {
        self.stack_top
    }
}

#[derive(Debug)]
pub(super) struct Process {
    pub(super) koid: zx_koid_t,
    pub(super) address_space_id: AddressSpaceId,
    pub(super) job_id: JobId,
    pub(super) policy_rights_ceiling: HandleRights,
    cspace: CSpace,
    pub(super) state: ProcessState,
    pub(super) suspend_tokens: u32,
}

/// Per-job resource quotas. Each field limits how many live objects of that
/// kind may exist under the job (including descendant processes).
#[derive(Clone, Debug)]
pub(crate) struct JobQuota {
    pub(crate) max_handles: u32,
    pub(crate) max_ports: u32,
    pub(crate) max_timers: u32,
    pub(crate) max_vmos: u32,
    pub(crate) max_vmars: u32,
    pub(crate) max_channels: u32,
    pub(crate) max_sockets: u32,
    pub(crate) max_revocation_groups: u32,
    pub(crate) max_event_pairs: u32,
}

impl JobQuota {
    pub(crate) fn root_default() -> Self {
        Self {
            max_handles: 65536,
            max_ports: 65536,
            max_timers: 65536,
            max_vmos: 65536,
            max_vmars: 65536,
            max_channels: 65536,
            max_sockets: 65536,
            max_revocation_groups: 65536,
            max_event_pairs: 65536,
        }
    }
}

/// Live resource counts for one job node.
#[derive(Clone, Debug, Default)]
pub(crate) struct JobResourceCounters {
    pub(crate) ports: u32,
    pub(crate) timers: u32,
    pub(crate) vmos: u32,
    pub(crate) vmars: u32,
    pub(crate) channels: u32,
    pub(crate) sockets: u32,
    pub(crate) revocation_groups: u32,
    pub(crate) event_pairs: u32,
}

/// Tag identifying which resource counter to check/update.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ObjectKindTag {
    Port,
    Timer,
    Vmo,
    Vmar,
    Channel,
    Socket,
    RevocationGroup,
    EventPair,
}

#[derive(Clone, Debug)]
pub(crate) struct Job {
    pub(super) koid: zx_koid_t,
    pub(super) parent_job_id: Option<JobId>,
    pub(super) child_jobs: Vec<JobId>,
    pub(super) child_processes: Vec<ProcessId>,
    pub(super) policy_rights_ceiling: HandleRights,
    pub(super) object_key: Option<ObjectKey>,
    pub(super) suspend_tokens: u32,
    pub(super) quota: JobQuota,
    pub(super) counters: JobResourceCounters,
}

impl Process {
    pub(super) fn bootstrap(
        address_space_id: AddressSpaceId,
        job_id: JobId,
        policy_rights_ceiling: HandleRights,
        koid: zx_koid_t,
    ) -> Self {
        Self {
            koid,
            address_space_id,
            job_id,
            policy_rights_ceiling,
            cspace: CSpace::new(CSPACE_MAX_SLOTS, CSPACE_QUARANTINE_LEN),
            state: ProcessState::Started,
            suspend_tokens: 0,
        }
    }

    pub(super) fn created(
        address_space_id: AddressSpaceId,
        job_id: JobId,
        policy_rights_ceiling: HandleRights,
        koid: zx_koid_t,
    ) -> Self {
        Self {
            koid,
            address_space_id,
            job_id,
            policy_rights_ceiling,
            cspace: CSpace::new(CSPACE_MAX_SLOTS, CSPACE_QUARANTINE_LEN),
            state: ProcessState::Created,
            suspend_tokens: 0,
        }
    }

    fn apply_handle_policy(&self, rights: HandleRights) -> HandleRights {
        rights & self.policy_rights_ceiling
    }

    pub(super) fn alloc_handle_for_capability(
        &mut self,
        cap: Capability,
    ) -> Result<zx_handle_t, zx_status_t> {
        let cap = Capability::new(
            cap.object_id(),
            self.apply_handle_policy(HandleRights::from_bits_retain(cap.rights()))
                .bits(),
            cap.generation(),
        );
        let handle = self.cspace.alloc(cap).map_err(map_alloc_error)?;
        Ok(handle.raw())
    }

    pub(super) fn lookup_handle(
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

    pub(super) fn close_handle(&mut self, raw: zx_handle_t) -> Result<(), zx_status_t> {
        let handle = Handle::from_raw(raw).map_err(|_| ZX_ERR_BAD_HANDLE)?;
        let _ = self.cspace.get(handle).map_err(map_lookup_error)?;
        self.cspace.close(handle).map_err(map_lookup_error)?;
        Ok(())
    }

    pub(super) fn duplicate_handle_derived(
        &mut self,
        raw: zx_handle_t,
        rights: HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        let rights = self.apply_handle_policy(rights);
        let handle = Handle::from_raw(raw).map_err(|_| ZX_ERR_BAD_HANDLE)?;
        let duplicated = self
            .cspace
            .duplicate_derived(handle, rights.bits())
            .map_err(map_alloc_error)?;
        Ok(duplicated.raw())
    }

    pub(super) fn duplicate_handle_revocable(
        &mut self,
        raw: zx_handle_t,
        rights: HandleRights,
        revocation: axle_core::RevocationRef,
    ) -> Result<zx_handle_t, zx_status_t> {
        let rights = self.apply_handle_policy(rights);
        let handle = Handle::from_raw(raw).map_err(|_| ZX_ERR_BAD_HANDLE)?;
        let duplicated = self
            .cspace
            .duplicate_revocable(handle, rights.bits(), revocation)
            .map_err(map_alloc_error)?;
        Ok(duplicated.raw())
    }

    pub(super) fn replace_handle_derived(
        &mut self,
        raw: zx_handle_t,
        rights: HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        let rights = self.apply_handle_policy(rights);
        let handle = Handle::from_raw(raw).map_err(|_| ZX_ERR_BAD_HANDLE)?;
        let replaced = self
            .cspace
            .replace_derived(handle, rights.bits())
            .map_err(map_alloc_error)?;
        Ok(replaced.raw())
    }

    pub(super) fn snapshot_handle_for_transfer(
        &self,
        raw: zx_handle_t,
        revocations: &RevocationManager,
    ) -> Result<TransferredCap, zx_status_t> {
        let handle = Handle::from_raw(raw).map_err(|_| ZX_ERR_BAD_HANDLE)?;
        self.cspace
            .snapshot_checked(handle, revocations)
            .map_err(map_lookup_error)
    }

    pub(super) fn install_transferred_handle(
        &mut self,
        transferred: TransferredCap,
    ) -> Result<zx_handle_t, zx_status_t> {
        let transferred = TransferredCap::new(
            Capability::new(
                transferred.capability().object_id(),
                self.apply_handle_policy(HandleRights::from_bits_retain(
                    transferred.capability().rights(),
                ))
                .bits(),
                transferred.capability().generation(),
            ),
            transferred.revocation_ref(),
        );
        let handle = self
            .cspace
            .install_transfer(transferred)
            .map_err(map_alloc_error)?;
        Ok(handle.raw())
    }
}

impl Job {
    pub(crate) fn new_root(koid: zx_koid_t) -> Self {
        Self {
            koid,
            parent_job_id: None,
            child_jobs: Vec::new(),
            child_processes: Vec::new(),
            policy_rights_ceiling: HandleRights::from_zx_rights(ZX_RIGHTS_ALL),
            object_key: None,
            suspend_tokens: 0,
            quota: JobQuota::root_default(),
            counters: JobResourceCounters::default(),
        }
    }

    pub(crate) fn new_child(
        parent_job_id: JobId,
        koid: zx_koid_t,
        policy_rights_ceiling: HandleRights,
        parent_quota: &JobQuota,
    ) -> Self {
        Self {
            koid,
            parent_job_id: Some(parent_job_id),
            child_jobs: Vec::new(),
            child_processes: Vec::new(),
            policy_rights_ceiling,
            object_key: None,
            suspend_tokens: 0,
            quota: parent_quota.clone(),
            counters: JobResourceCounters::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProcessState {
    Created,
    Started,
    Suspended,
    Terminating,
    Terminated,
}

impl Kernel {
    pub(crate) fn root_job_id(&self) -> JobId {
        self.root_job_id
    }

    pub(crate) fn job_koid(&self, job_id: JobId) -> Result<zx_koid_t, zx_status_t> {
        Ok(self.jobs.get(&job_id).ok_or(ZX_ERR_BAD_HANDLE)?.koid)
    }

    pub(crate) fn bind_job_object(
        &mut self,
        job_id: JobId,
        object_key: ObjectKey,
    ) -> Result<(), zx_status_t> {
        let job = self.jobs.get_mut(&job_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        job.object_key = Some(object_key);
        Ok(())
    }

    pub(crate) fn job_object_key(&self, job_id: JobId) -> Result<ObjectKey, zx_status_t> {
        self.jobs
            .get(&job_id)
            .and_then(|job| job.object_key)
            .ok_or(ZX_ERR_BAD_HANDLE)
    }

    pub(crate) fn process_job_id(&self, process_id: ProcessId) -> Result<JobId, zx_status_t> {
        Ok(self.process(process_id)?.job_id)
    }

    pub(crate) fn process_policy_rights_ceiling(
        &self,
        process_id: ProcessId,
    ) -> Result<HandleRights, zx_status_t> {
        Ok(self.process(process_id)?.policy_rights_ceiling)
    }

    pub(crate) fn check_job_quota(
        &self,
        job_id: JobId,
        tag: ObjectKindTag,
    ) -> Result<(), zx_status_t> {
        let job = self.jobs.get(&job_id).ok_or(ZX_ERR_BAD_STATE)?;
        let (count, limit) = match tag {
            ObjectKindTag::Port => (job.counters.ports, job.quota.max_ports),
            ObjectKindTag::Timer => (job.counters.timers, job.quota.max_timers),
            ObjectKindTag::Vmo => (job.counters.vmos, job.quota.max_vmos),
            ObjectKindTag::Vmar => (job.counters.vmars, job.quota.max_vmars),
            ObjectKindTag::Channel => (job.counters.channels, job.quota.max_channels),
            ObjectKindTag::Socket => (job.counters.sockets, job.quota.max_sockets),
            ObjectKindTag::RevocationGroup => (
                job.counters.revocation_groups,
                job.quota.max_revocation_groups,
            ),
            ObjectKindTag::EventPair => (job.counters.event_pairs, job.quota.max_event_pairs),
        };
        if count >= limit {
            return Err(ZX_ERR_NO_RESOURCES);
        }
        Ok(())
    }

    pub(crate) fn increment_job_counter(&mut self, job_id: JobId, tag: ObjectKindTag) {
        if let Some(job) = self.jobs.get_mut(&job_id) {
            let counter = match tag {
                ObjectKindTag::Port => &mut job.counters.ports,
                ObjectKindTag::Timer => &mut job.counters.timers,
                ObjectKindTag::Vmo => &mut job.counters.vmos,
                ObjectKindTag::Vmar => &mut job.counters.vmars,
                ObjectKindTag::Channel => &mut job.counters.channels,
                ObjectKindTag::Socket => &mut job.counters.sockets,
                ObjectKindTag::RevocationGroup => &mut job.counters.revocation_groups,
                ObjectKindTag::EventPair => &mut job.counters.event_pairs,
            };
            *counter = counter.saturating_add(1);
        }
    }

    pub(crate) fn decrement_job_counter(&mut self, job_id: JobId, tag: ObjectKindTag) {
        if let Some(job) = self.jobs.get_mut(&job_id) {
            let counter = match tag {
                ObjectKindTag::Port => &mut job.counters.ports,
                ObjectKindTag::Timer => &mut job.counters.timers,
                ObjectKindTag::Vmo => &mut job.counters.vmos,
                ObjectKindTag::Vmar => &mut job.counters.vmars,
                ObjectKindTag::Channel => &mut job.counters.channels,
                ObjectKindTag::Socket => &mut job.counters.sockets,
                ObjectKindTag::RevocationGroup => &mut job.counters.revocation_groups,
                ObjectKindTag::EventPair => &mut job.counters.event_pairs,
            };
            *counter = counter.saturating_sub(1);
        }
    }

    pub(crate) fn current_job_id(&self) -> Result<JobId, zx_status_t> {
        let process_id = self.current_thread()?.process_id;
        Ok(self.process(process_id)?.job_id)
    }

    pub(crate) fn create_job(
        &mut self,
        parent_job_id: JobId,
    ) -> Result<(JobId, zx_koid_t), zx_status_t> {
        let parent = self.jobs.get(&parent_job_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        let parent_policy = parent.policy_rights_ceiling;
        let parent_quota = parent.quota.clone();
        let job_id = self.alloc_job_id();
        let koid = self.alloc_koid();
        self.jobs.insert(
            job_id,
            Job::new_child(parent_job_id, koid, parent_policy, &parent_quota),
        );
        self.jobs
            .get_mut(&parent_job_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .child_jobs
            .push(job_id);
        Ok((job_id, koid))
    }

    pub(crate) fn create_process_in_job(
        &mut self,
        job_id: JobId,
    ) -> Result<CreatedProcess, zx_status_t> {
        let (address_space_id, root_vmar) =
            self.with_vm_mut(|vm| vm.create_process_address_space())?;

        let process_id = self.alloc_process_id();
        let process_koid = self.alloc_koid();
        let policy = self
            .jobs
            .get(&job_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .policy_rights_ceiling;
        self.processes.insert(
            process_id,
            Process::created(address_space_id, job_id, policy, process_koid),
        );
        self.jobs
            .get_mut(&job_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .child_processes
            .push(process_id);

        Ok(CreatedProcess {
            process_id,
            koid: process_koid,
            address_space_id,
            root_vmar,
        })
    }

    pub(crate) fn job_info(&self, job_id: JobId) -> Result<axle_types::ax_job_info_t, zx_status_t> {
        let job = self.jobs.get(&job_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        let live_child_processes = job
            .child_processes
            .iter()
            .filter(|process_id| self.processes.contains_key(process_id))
            .count() as u32;
        Ok(axle_types::ax_job_info_t {
            job_id,
            koid: job.koid,
            parent_koid: job
                .parent_job_id
                .and_then(|parent_id| self.jobs.get(&parent_id).map(|parent| parent.koid))
                .unwrap_or(ZX_KOID_INVALID),
            child_job_count: job.child_jobs.len() as u32,
            child_process_count: live_child_processes,
            policy_rights_ceiling: job.policy_rights_ceiling.bits(),
            reserved0: 0,
        })
    }

    pub(crate) fn set_job_policy(
        &mut self,
        job_id: JobId,
        rights_ceiling: HandleRights,
    ) -> Result<(), zx_status_t> {
        let current = self
            .jobs
            .get(&job_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .policy_rights_ceiling;
        if (rights_ceiling.bits() & !current.bits()) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        self.apply_job_policy_recursive(job_id, rights_ceiling, 0)
    }

    fn apply_job_policy_recursive(
        &mut self,
        job_id: JobId,
        rights_ceiling: HandleRights,
        depth: usize,
    ) -> Result<(), zx_status_t> {
        const MAX_DEPTH: usize = 64;
        if depth >= MAX_DEPTH {
            return Err(ZX_ERR_OUT_OF_RANGE);
        }
        let (effective, child_jobs, child_processes) = {
            let job = self.jobs.get_mut(&job_id).ok_or(ZX_ERR_BAD_HANDLE)?;
            job.policy_rights_ceiling &= rights_ceiling;
            (
                job.policy_rights_ceiling,
                job.child_jobs.clone(),
                job.child_processes.clone(),
            )
        };
        for process_id in child_processes {
            if let Some(process) = self.processes.get_mut(&process_id) {
                process.policy_rights_ceiling &= effective;
            }
        }
        for child_job_id in child_jobs {
            self.apply_job_policy_recursive(child_job_id, effective, depth + 1)?;
        }
        Ok(())
    }

    fn descendant_process_ids(
        &self,
        job_id: JobId,
        out: &mut Vec<ProcessId>,
    ) -> Result<(), zx_status_t> {
        let job = self.jobs.get(&job_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        for &process_id in &job.child_processes {
            if self.processes.contains_key(&process_id) {
                out.push(process_id);
            }
        }
        for &child_job_id in &job.child_jobs {
            self.descendant_process_ids(child_job_id, out)?;
        }
        Ok(())
    }

    pub(crate) fn kill_job(&mut self, job_id: JobId) -> Result<(), zx_status_t> {
        let mut processes = Vec::new();
        self.descendant_process_ids(job_id, &mut processes)?;
        for process_id in processes {
            let _ = self.kill_process(process_id);
        }
        Ok(())
    }

    pub(crate) fn suspend_job(&mut self, job_id: JobId) -> Result<(), zx_status_t> {
        {
            let job = self.jobs.get_mut(&job_id).ok_or(ZX_ERR_BAD_HANDLE)?;
            job.suspend_tokens = job.suspend_tokens.saturating_add(1);
        }
        let mut processes = Vec::new();
        self.descendant_process_ids(job_id, &mut processes)?;
        for process_id in processes {
            self.suspend_process(process_id)?;
        }
        Ok(())
    }

    pub(crate) fn resume_job(&mut self, job_id: JobId) -> Result<(), zx_status_t> {
        {
            let job = self.jobs.get_mut(&job_id).ok_or(ZX_ERR_BAD_HANDLE)?;
            if job.suspend_tokens == 0 {
                return Err(ZX_ERR_BAD_STATE);
            }
            job.suspend_tokens -= 1;
        }
        let mut processes = Vec::new();
        self.descendant_process_ids(job_id, &mut processes)?;
        for process_id in processes {
            let _ = self.resume_process(process_id);
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn current_thread_koid(&self) -> Result<zx_koid_t, zx_status_t> {
        Ok(self.current_thread()?.koid)
    }

    pub(crate) fn current_process_koid(&self) -> Result<zx_koid_t, zx_status_t> {
        Ok(self.current_process()?.koid)
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
        let current_process_id = self.current_thread()?.process_id;
        let job_id = self.process(current_process_id)?.job_id;
        self.create_process_in_job(job_id)
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
                guest_started: false,
                guest_fs_base: 0,
                fpu_state: alloc::boxed::Box::new(crate::arch::fpu::clean_state()),
                state: ThreadState::New,
                queued_on_cpu: None,
                running_on_cpu: None,
                last_cpu: current_cpu_id,
                runtime_ns: 0,
                wait: WaitNode::default(),
                context: None,
                suspend_tokens: 0,
                remote_wake_enqueued_ns: None,
                remote_wake_source_cpu: None,
                remote_wake_target_cpu: None,
                vruntime: 0,
                weight: 1024,
                base_weight: 1024,
                vdeadline: 0,
                eligible_time: 0,
                pi_blocked_on: None,
            },
        );
        self.thread_koid_index.insert(koid, thread_id);
        Ok((thread_id, koid))
    }

    fn start_thread_with_policy(
        &mut self,
        thread_id: ThreadId,
        entry: u64,
        stack: u64,
        arg0: u64,
        arg1: u64,
        placement: StartPlacementPolicy,
        allow_idle_spill: bool,
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
        thread.guest_started = false;
        thread.context = Some(UserContext::new_user_entry(entry, stack, arg0, arg1));
        thread.state = ThreadState::Runnable;
        let queued = thread.queued_on_cpu.is_some();
        let thread_id_copy = thread_id;
        let _ = thread;
        if !queued {
            let target_cpu = self.choose_start_cpu(thread_id_copy, placement);
            if target_cpu != self.current_cpu_id() {
                crate::trace::record_remote_wake(thread_id_copy, target_cpu);
            }
            if target_cpu == self.current_cpu_id() {
                self.enqueue_runnable_thread_front_on_cpu(thread_id_copy, target_cpu)?;
                self.note_direct_handoff_candidate(target_cpu, thread_id_copy);
            } else {
                self.enqueue_runnable_thread_on_cpu(thread_id_copy, target_cpu)?;
            }
            self.request_reschedule_on_cpu(target_cpu);
            if allow_idle_spill {
                self.maybe_nudge_idle_stealer(target_cpu);
            }
        }
        Ok(())
    }

    pub(crate) fn start_thread(
        &mut self,
        thread_id: ThreadId,
        entry: u64,
        stack: u64,
        arg0: u64,
        arg1: u64,
    ) -> Result<(), zx_status_t> {
        self.start_thread_with_policy(
            thread_id,
            entry,
            stack,
            arg0,
            arg1,
            StartPlacementPolicy::PreserveAffinity,
            true,
        )
    }

    pub(crate) fn start_thread_explicit(
        &mut self,
        thread_id: ThreadId,
        entry: u64,
        stack: u64,
        arg0: u64,
        arg1: u64,
    ) -> Result<(), zx_status_t> {
        self.start_thread_with_policy(
            thread_id,
            entry,
            stack,
            arg0,
            arg1,
            StartPlacementPolicy::PreferIdlePeer,
            true,
        )
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
        let result = self.start_thread_with_policy(
            thread_id,
            entry,
            stack,
            arg0,
            arg1,
            StartPlacementPolicy::PreserveAffinity,
            true,
        );
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
        extra_image: Option<&LinuxExecExtraImage<'_>>,
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
                extra_image,
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
            thread.remote_wake_enqueued_ns = None;
            thread.remote_wake_source_cpu = None;
            thread.remote_wake_target_cpu = None;
            let prev_cpu = thread.queued_on_cpu.take();
            let _ = thread;
            if let Some(cpu_id) = prev_cpu {
                self.remove_thread_from_run_queue(thread_id, cpu_id);
            }
        } else {
            let _ = thread;
        }
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
                let prev_cpu = thread.queued_on_cpu.take();
                let _ = thread;
                if let Some(cpu_id) = prev_cpu {
                    self.remove_thread_from_run_queue(thread_id, cpu_id);
                }
            } else {
                let _ = thread;
            }
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
        let koid = thread.koid;
        let _ = self.threads.remove(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        self.thread_koid_index.remove(&koid);
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

    pub(super) fn thread_should_be_suspended(
        &self,
        thread_id: ThreadId,
    ) -> Result<bool, zx_status_t> {
        let thread = self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if thread.suspend_tokens != 0 {
            return Ok(true);
        }
        let process = self.process(thread.process_id)?;
        Ok(process.state == ProcessState::Suspended)
    }

    pub(super) fn request_thread_termination(
        &mut self,
        thread_id: ThreadId,
    ) -> Result<(), zx_status_t> {
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

    pub(super) fn finalize_thread_termination(
        &mut self,
        thread_id: ThreadId,
    ) -> Result<(), zx_status_t> {
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

    pub(super) fn maybe_finalize_process_termination(
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
            let address_space_id = process.address_space_id;
            process.state = ProcessState::Terminated;
            self.task_lifecycle_dirty = true;
            // Release all user-visible mappings so physical memory can be
            // reclaimed before the process is reaped.
            let req = self.with_vm_mut(|vm| vm.cleanup_process_address_space(address_space_id));
            if let Ok(req) = req {
                let _ = self.apply_tlb_commit_reqs_current(&[req]);
            }
        }
        Ok(())
    }

    pub(super) fn maybe_resume_thread(&mut self, thread_id: ThreadId) -> Result<(), zx_status_t> {
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
        self.maybe_nudge_idle_stealer(target_cpu);
        Ok(())
    }
}
