use super::*;

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
        if let Some(entry) = self.entries.get_mut(&key)
            && entry.in_flight
            && entry.leader_thread == Some(thread_id)
        {
            entry.leader_paused_for_test = true;
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

    pub(super) fn remove_blocked_waiter(&mut self, key: FaultInFlightKey, thread_id: ThreadId) {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FaultPlanResult {
    Satisfied,
    Ready(FaultPlan),
    Unhandled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FaultCommitDisposition {
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
pub(super) enum PreparedFaultWork {
    None,
    NewPage { paddr: u64 },
}

impl PreparedFaultWork {
    pub(super) fn take_page_paddr(&mut self) -> Option<u64> {
        match core::mem::replace(self, Self::None) {
            Self::None => None,
            Self::NewPage { paddr } => Some(paddr),
        }
    }

    pub(super) fn release_unused(self) {
        if let Self::NewPage { paddr } = self {
            crate::userspace::free_bootstrap_page(paddr);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FaultPlan {
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
        let _ = kernel.complete_waiter_source_removed(thread_id, WakeReason::PreserveContext);
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
            match vmo_kind {
                VmoKind::Anonymous => {
                    update_fault_telemetry(fault_table, |table| {
                        table.record_prepare(FaultPrepareKind::LazyVmoAlloc);
                    });
                    let new_frame_paddr =
                        crate::userspace::alloc_bootstrap_zeroed_page().ok_or(ZX_ERR_NO_MEMORY)?;
                    Ok(PreparedFaultWork::NewPage {
                        paddr: new_frame_paddr,
                    })
                }
                VmoKind::PagerBacked => {
                    update_fault_telemetry(fault_table, |table| {
                        table.record_prepare(FaultPrepareKind::LazyVmoAlloc);
                    });
                    let new_frame_paddr =
                        crate::userspace::alloc_bootstrap_zeroed_page().ok_or(ZX_ERR_NO_MEMORY)?;
                    let materialized = global_vmo_store.lock().materialize_page_into(
                        global_vmo_id,
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
                    Ok(PreparedFaultWork::NewPage {
                        paddr: new_frame_paddr,
                    })
                }
                VmoKind::Physical | VmoKind::Contiguous => Err(ZX_ERR_BAD_STATE),
            }
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
                        let (disposition, tlb_commit) = outcome?;
                        crate::task::apply_tlb_commit_reqs(
                            &vm_handle,
                            crate::arch::apic::this_apic_id() as usize,
                            Some(address_space_id),
                            &[tlb_commit],
                        )?;
                        match disposition {
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
                            Ok((FaultCommitDisposition::Resolved, tlb_commit)) => {
                                if crate::task::apply_tlb_commit_reqs(
                                    &vm_handle,
                                    crate::arch::apic::this_apic_id() as usize,
                                    Some(address_space_id),
                                    &[tlb_commit],
                                )
                                .is_err()
                                {
                                    return PageFaultSerializedResult::Unhandled;
                                }
                                update_fault_telemetry(&fault_handle, |table| {
                                    table.record_commit_resolved();
                                });
                                return PageFaultSerializedResult::Handled;
                            }
                            Ok((FaultCommitDisposition::Retry, _)) => {
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
                            Ok((FaultCommitDisposition::Resolved, tlb_commit)) => {
                                if crate::task::apply_tlb_commit_reqs(
                                    &vm_handle,
                                    crate::arch::apic::this_apic_id() as usize,
                                    Some(address_space_id),
                                    &[tlb_commit],
                                )
                                .is_err()
                                {
                                    return PageFaultSerializedResult::Unhandled;
                                }
                                update_fault_telemetry(&fault_handle, |table| {
                                    table.record_commit_resolved();
                                });
                                return PageFaultSerializedResult::Handled;
                            }
                            Ok((FaultCommitDisposition::Retry, _)) => {
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
