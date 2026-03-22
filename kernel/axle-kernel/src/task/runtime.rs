use super::*;

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
    cspace: CSpace,
    pub(super) state: ProcessState,
    pub(super) suspend_tokens: u32,
}

impl Process {
    pub(super) fn bootstrap(address_space_id: AddressSpaceId, koid: zx_koid_t) -> Self {
        Self {
            koid,
            address_space_id,
            cspace: CSpace::new(CSPACE_MAX_SLOTS, CSPACE_QUARANTINE_LEN),
            state: ProcessState::Started,
            suspend_tokens: 0,
        }
    }

    pub(super) fn created(address_space_id: AddressSpaceId, koid: zx_koid_t) -> Self {
        Self {
            koid,
            address_space_id,
            cspace: CSpace::new(CSPACE_MAX_SLOTS, CSPACE_QUARANTINE_LEN),
            state: ProcessState::Created,
            suspend_tokens: 0,
        }
    }

    pub(super) fn alloc_handle_for_capability(
        &mut self,
        cap: Capability,
    ) -> Result<zx_handle_t, zx_status_t> {
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
        let handle = self
            .cspace
            .install_transfer(transferred)
            .map_err(map_alloc_error)?;
        Ok(handle.raw())
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
                fpu_state: crate::arch::fpu::clean_state(),
                state: ThreadState::New,
                queued_on_cpu: None,
                last_cpu: current_cpu_id,
                runtime_ns: 0,
                wait: WaitNode::default(),
                context: None,
                suspend_tokens: 0,
                remote_wake_enqueued_ns: None,
                remote_wake_source_cpu: None,
                remote_wake_target_cpu: None,
            },
        );
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
            self.enqueue_runnable_thread_on_cpu(thread_id_copy, target_cpu)?;
            self.request_reschedule_on_cpu(target_cpu);
            self.maybe_nudge_idle_stealer(target_cpu);
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
            process.state = ProcessState::Terminated;
            self.task_lifecycle_dirty = true;
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
