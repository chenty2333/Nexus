// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec, vec::Vec};

use ostd::{
    arch::cpu::context::{CpuException, UserContext},
    mm::{
        CachePolicy, Frame, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty, Vaddr, VmIo,
        VmSpace, tlb::TlbFlushOp,
    },
    prelude::*,
    sync::SpinLock,
    task::{Task, TaskOptions, disable_preempt},
    user::{ReturnReason, UserMode},
};

use crate::{
    TaskData, USER_MAP_ADDR, create_vm_space,
    effect::{EffectToken, EffectWaiter, EffectWaker},
};

const PAGER_V1_TASK_ID: u64 = 410;
const WATCHDOG_TASK_ID: u64 = 411;
const PAGER_V2_TASK_ID: u64 = 412;

const PAGER_V1_PREPARE_IMAGE: usize = 0x4c60_0001;
const PAGER_V2_RECOVERY_SNAPSHOT: usize = 0x4c61_0001;
const PAGER_V2_READY: usize = 0x4c61_0002;
const PAGER_V2_REBIND: usize = 0x4c61_0003;
const PAGER_V2_RECOVER_NEXT: usize = 0x4c61_0004;
const PAGER_V2_ADOPT: usize = 0x4c61_0005;
const PAGER_V2_COMMIT: usize = 0x4c61_0006;

const PAGER_CRASH_ADDR: Vaddr = 0x0080_0000;
const USER_PAGE_FAULT_BIT: usize = 1 << 2;
const INSTRUCTION_PAGE_FAULT_BIT: usize = 1 << 4;

const PAGER_V1_PROGRAM: &[u8] = include_bytes!("../guest/linux-code-pager-v1.bin");
const PAGER_V2_PROGRAM: &[u8] = include_bytes!("../guest/linux-code-pager-v2.bin");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPhase {
    Registered,
    Prepared,
    Adopted,
    Committed,
    Completed,
}

#[derive(Clone, Copy, Debug)]
struct FaultContinuation {
    token: EffectToken,
    binding_epoch: u64,
    thread_id: u64,
    page_address: Vaddr,
    fault_address: Vaddr,
    fault_rip: Vaddr,
    access_bits: usize,
    phase: FaultPhase,
}

struct PagerState {
    services_started: bool,
    service_tasks_started: bool,
    binding_epoch: u64,
    supervisor: Option<u64>,
    fallback_running: bool,
    snapshot_taken: bool,
    replacement_ready: bool,
    continuation: Option<FaultContinuation>,
    prepared_frame: Option<Frame<()>>,
    guest_waker: Option<EffectWaker>,
    mapping_published: bool,
    terminalizations: u64,
    stale_rejections: u64,
    no_supervisor_rejections: u64,
    wake_publications: u64,
    guest_resume_returns: u64,
}

struct PagerScenario {
    token: EffectToken,
    guest_vm: Arc<VmSpace>,
    rx_page_address: Vaddr,
    image_page: Vec<u8>,
    image_checksum: u64,
    state: SpinLock<PagerState>,
}

/// A bounded, single-CPU file-backed pager for the first executable page of
/// `linux-hello`.
///
/// The caller retains the Linux `UserMode`. This object owns the one-shot
/// continuation and the pager service tasks, so a stale user-space pager never
/// receives direct authority to mutate the guest page table or wake the guest.
#[derive(Clone)]
pub(crate) struct LinuxCodePager {
    scenario: Arc<PagerScenario>,
}

impl LinuxCodePager {
    /// Creates a pager for one absent, page-aligned RX mapping.
    ///
    /// `token` is supplied by the Linux personality so the page fault can share
    /// its authority epoch and causal scope while retaining a distinct effect
    /// ID. `image_page` must contain the loader's exact, zero-padded ELF page.
    pub(crate) fn new(
        token: EffectToken,
        guest_vm: Arc<VmSpace>,
        rx_page_address: Vaddr,
        image_page: &[u8],
    ) -> Self {
        assert_eq!(rx_page_address % PAGE_SIZE, 0, "RX page must be aligned");
        assert_eq!(image_page.len(), PAGE_SIZE, "pager owns exactly one page");
        assert!(
            image_page.iter().any(|byte| *byte != 0),
            "entry image page must contain file bytes"
        );

        let guard = disable_preempt();
        let mut cursor = guest_vm
            .cursor_mut(&guard, &(rx_page_address..rx_page_address + PAGE_SIZE))
            .expect("query Linux entry-page slot");
        assert!(
            matches!(cursor.query(), Ok((_, None))),
            "loader must leave the paged entry slot absent"
        );
        drop(cursor);
        drop(guard);

        Self {
            scenario: Arc::new(PagerScenario {
                token,
                guest_vm,
                rx_page_address,
                image_page: image_page.to_vec(),
                image_checksum: image_checksum(image_page),
                state: SpinLock::new(PagerState {
                    services_started: false,
                    service_tasks_started: false,
                    binding_epoch: 1,
                    supervisor: Some(PAGER_V1_TASK_ID),
                    fallback_running: false,
                    snapshot_taken: false,
                    replacement_ready: false,
                    continuation: None,
                    prepared_frame: None,
                    guest_waker: None,
                    mapping_published: false,
                    terminalizations: 0,
                    stale_rejections: 0,
                    no_supervisor_rejections: 0,
                    wake_publications: 0,
                    guest_resume_returns: 0,
                }),
            }),
        }
    }

    /// Opens the fault-registration gate before the guest task becomes
    /// runnable. Service tasks are enqueued separately so scheduler ordering
    /// cannot create a registration-before-start race.
    pub(crate) fn arm(&self) {
        let mut state = self.scenario.state.lock();
        assert!(
            !state.services_started,
            "pager registration gate opens once"
        );
        assert!(!state.service_tasks_started);
        state.services_started = true;
    }

    /// Starts a fresh pager-v1 task plus a kernel watchdog. The watchdog is the
    /// only code that may spawn pager-v2 after the v1 binding has crashed.
    pub(crate) fn start(&self) {
        {
            let mut state = self.scenario.state.lock();
            assert!(state.services_started, "arm pager before starting tasks");
            assert!(
                !state.service_tasks_started,
                "pager service tasks start once"
            );
            state.service_tasks_started = true;
        }

        let pager_v1_vm = Arc::new(create_vm_space(PAGER_V1_PROGRAM));
        let pager_v1_state = self.scenario.clone();
        let pager_v1_task_vm = pager_v1_vm.clone();
        let pager_v1_task = Arc::new(
            TaskOptions::new(move || run_pager_v1(pager_v1_state, pager_v1_task_vm))
                .data(TaskData::new(PAGER_V1_TASK_ID, Some(pager_v1_vm.clone())))
                .build()
                .expect("build Linux code pager v1 task"),
        );

        let watchdog_state = self.scenario.clone();
        let old_task = pager_v1_task.clone();
        let old_vm = pager_v1_vm;
        let watchdog_task = Arc::new(
            TaskOptions::new(move || run_watchdog(watchdog_state, old_task, old_vm))
                .data(TaskData::new(WATCHDOG_TASK_ID, None))
                .build()
                .expect("build Linux code pager watchdog task"),
        );

        println!(
            "LINUX_CODE_PAGER Start workload=linux-hello effect={} authority_epoch={} scope={} rx_page={:#x} image_checksum={:#x} pager_v1={} watchdog={} single_cpu=true",
            self.scenario.token.effect_id,
            self.scenario.token.authority_epoch,
            self.scenario.token.scope_id,
            self.scenario.rx_page_address,
            self.scenario.image_checksum,
            PAGER_V1_TASK_ID,
            WATCHDOG_TASK_ID,
        );
        pager_v1_task.run();
        watchdog_task.run();
    }

    /// Consumes the real instruction-fetch exception currently held by
    /// `user_mode`, registers one continuation, and blocks until pager-v2 has
    /// mapped the image page and synchronized the local TLB.
    pub(crate) fn capture_instruction_fault_and_wait(&self, user_mode: &mut UserMode) {
        let info = match user_mode.context_mut().take_exception() {
            Some(CpuException::PageFault(info)) => info,
            other => panic!("Linux entry expected a real page fault, got {other:?}"),
        };
        assert_eq!(info.error_code.bits() & 1, 0, "entry page is not present");
        assert_ne!(
            info.error_code.bits() & USER_PAGE_FAULT_BIT,
            0,
            "entry fault comes from user mode"
        );
        assert_ne!(
            info.error_code.bits() & INSTRUCTION_PAGE_FAULT_BIT,
            0,
            "entry fault is an instruction fetch"
        );
        assert!(
            (self.scenario.rx_page_address..self.scenario.rx_page_address + PAGE_SIZE)
                .contains(&info.addr),
            "fault address lies in the retained image page"
        );

        let fault_rip = user_mode.context().rip();
        assert_eq!(fault_rip, info.addr, "entry instruction itself must fault");
        let current = Task::current().expect("Linux guest runs in an OSTD task");
        let task_data = current
            .data()
            .downcast_ref::<TaskData>()
            .expect("Linux guest carries Nexus TaskData");
        assert!(
            task_data
                .vm_space
                .as_ref()
                .is_some_and(|vm| Arc::ptr_eq(vm, &self.scenario.guest_vm)),
            "faulting task owns the pager target VmSpace"
        );

        let (fault_waiter, fault_waker) = EffectWaiter::new_pair(self.scenario.token);
        self.scenario.register_fault(
            task_data.id,
            info.addr,
            fault_rip,
            info.error_code.bits(),
            fault_waker,
        );
        println!(
            "LINUX_CODE_PAGER GuestBlocked workload=linux-hello effect={} thread={} rip={:#x} continuation=one-shot",
            self.scenario.token.effect_id, task_data.id, fault_rip,
        );
        fault_waiter.wait();
        drop(fault_waiter);

        assert_eq!(
            user_mode.context().rip(),
            fault_rip,
            "resolved instruction fault resumes at the same RIP"
        );
        self.scenario.observe_guest_resume_return();
    }

    /// Checks the recovery boundary after the Linux guest has executed the
    /// newly mapped entry page.
    pub(crate) fn assert_complete(&self) {
        self.scenario.assert_complete();
    }
}

impl PagerScenario {
    fn register_fault(
        &self,
        thread_id: u64,
        fault_address: Vaddr,
        fault_rip: Vaddr,
        access_bits: usize,
        guest_waker: EffectWaker,
    ) {
        assert_eq!(guest_waker.token(), self.token);
        let binding_epoch = {
            let mut state = self.state.lock();
            assert!(state.services_started);
            assert_eq!(state.binding_epoch, 1);
            assert_eq!(state.supervisor, Some(PAGER_V1_TASK_ID));
            assert!(!state.fallback_running);
            assert!(state.continuation.is_none());
            assert!(state.guest_waker.is_none());
            assert!(!state.mapping_published);
            state.continuation = Some(FaultContinuation {
                token: self.token,
                binding_epoch: state.binding_epoch,
                thread_id,
                page_address: self.rx_page_address,
                fault_address,
                fault_rip,
                access_bits,
                phase: FaultPhase::Registered,
            });
            state.guest_waker = Some(guest_waker);
            state.binding_epoch
        };
        println!(
            "LINUX_CODE_PAGER Register workload=linux-hello effect={} authority_epoch={} scope={} binding_epoch={} thread={} page={:#x} fault_addr={:#x} rip={:#x} access_bits={:#x} backing=elf-image",
            self.token.effect_id,
            self.token.authority_epoch,
            self.token.scope_id,
            binding_epoch,
            thread_id,
            self.rx_page_address,
            fault_address,
            fault_rip,
            access_bits,
        );
    }

    fn fault_is_registered(&self) -> bool {
        self.state
            .lock()
            .continuation
            .as_ref()
            .is_some_and(|fault| fault.phase == FaultPhase::Registered)
    }

    fn prepare_image(&self, presented_binding_epoch: u64) {
        {
            let state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, Some(PAGER_V1_TASK_ID));
            assert_eq!(
                state.continuation.as_ref().unwrap().phase,
                FaultPhase::Registered
            );
            assert!(!state.mapping_published);
        }

        let candidate = FrameAllocOptions::new()
            .alloc_frame()
            .expect("allocate Linux ELF image frame");
        candidate
            .write_bytes(0, &self.image_page)
            .expect("copy retained ELF page into frame");
        let mut round_trip = vec![0; PAGE_SIZE];
        candidate
            .read_bytes(0, &mut round_trip)
            .expect("verify retained ELF page in frame");
        assert_eq!(round_trip, self.image_page);
        assert_eq!(image_checksum(&round_trip), self.image_checksum);

        {
            let mut state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, Some(PAGER_V1_TASK_ID));
            assert!(state.prepared_frame.is_none());
            assert!(!state.mapping_published);
            let fault = state.continuation.as_mut().unwrap();
            assert_eq!(fault.token, self.token);
            assert_eq!(fault.binding_epoch, presented_binding_epoch);
            assert_eq!(fault.page_address, self.rx_page_address);
            assert_eq!(fault.phase, FaultPhase::Registered);
            fault.phase = FaultPhase::Prepared;
            state.prepared_frame = Some(candidate);
        }
        println!(
            "LINUX_CODE_PAGER PrepareImage workload=linux-hello effect={} binding_epoch={} bytes={} image_checksum={:#x} owner=kernel pte_published=false",
            self.token.effect_id, presented_binding_epoch, PAGE_SIZE, self.image_checksum,
        );
    }

    fn crash_v1(&self, presented_binding_epoch: u64) -> u64 {
        let new_binding_epoch = {
            let mut state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, Some(PAGER_V1_TASK_ID));
            assert_eq!(
                state.continuation.as_ref().unwrap().phase,
                FaultPhase::Prepared
            );
            assert!(state.prepared_frame.is_some());
            assert!(!state.mapping_published);
            state.binding_epoch = state
                .binding_epoch
                .checked_add(1)
                .expect("Linux code pager binding epoch overflow");
            state.supervisor = None;
            state.fallback_running = true;
            state.snapshot_taken = false;
            state.replacement_ready = false;
            state.binding_epoch
        };
        println!(
            "LINUX_CODE_PAGER Crash workload=linux-hello supervisor={} previous_binding_epoch={} binding_epoch={} reason=real_user_page_fault image_frame_retained=true pte_published=false",
            PAGER_V1_TASK_ID, presented_binding_epoch, new_binding_epoch,
        );
        new_binding_epoch
    }

    fn has_crashed(&self) -> bool {
        let state = self.state.lock();
        state.binding_epoch == 2 && state.supervisor.is_none() && state.fallback_running
    }

    fn reject_stale_reply(&self, presented_binding_epoch: u64, stage: &'static str) {
        let current_binding_epoch = {
            let mut state = self.state.lock();
            assert_ne!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(
                state.continuation.as_ref().unwrap().phase,
                FaultPhase::Prepared
            );
            assert!(!state.mapping_published);
            assert_eq!(state.wake_publications, 0);
            state.stale_rejections += 1;
            state.binding_epoch
        };
        println!(
            "LINUX_CODE_PAGER REJECT_STALE workload=linux-hello stage={} action=MapAndWake effect={} proposal_binding_epoch={} current_binding_epoch={} pte_published=false guest_wake=false",
            stage, self.token.effect_id, presented_binding_epoch, current_binding_epoch,
        );
    }

    fn recovery_snapshot(&self, presented_binding_epoch: u64) {
        {
            let mut state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, None);
            assert!(state.fallback_running);
            assert!(!state.snapshot_taken);
            assert_eq!(
                state.continuation.as_ref().unwrap().phase,
                FaultPhase::Prepared
            );
            assert!(state.prepared_frame.is_some());
            state.snapshot_taken = true;
        }
        println!(
            "LINUX_CODE_PAGER RecoverySnapshot workload=linux-hello replacement={} binding_epoch={} effect={} phase=Prepared image_frame=true",
            PAGER_V2_TASK_ID, presented_binding_epoch, self.token.effect_id,
        );
    }

    fn ready(&self, presented_binding_epoch: u64) {
        {
            let mut state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, None);
            assert!(state.snapshot_taken);
            assert!(!state.replacement_ready);
            state.replacement_ready = true;
        }
        println!(
            "LINUX_CODE_PAGER Ready workload=linux-hello replacement={} binding_epoch={}",
            PAGER_V2_TASK_ID, presented_binding_epoch,
        );
    }

    fn reject_no_supervisor(&self, presented_binding_epoch: u64) {
        {
            let mut state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, None);
            assert!(state.replacement_ready);
            assert!(!state.mapping_published);
            state.no_supervisor_rejections += 1;
        }
        println!(
            "LINUX_CODE_PAGER REJECT_NO_SUPERVISOR workload=linux-hello stage=pre_rebind action=MapAndWake effect={} binding_epoch={} pte_published=false guest_wake=false",
            self.token.effect_id, presented_binding_epoch,
        );
    }

    fn rebind(&self, presented_binding_epoch: u64) {
        {
            let mut state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, None);
            assert!(state.fallback_running);
            assert!(state.snapshot_taken);
            assert!(state.replacement_ready);
            state.supervisor = Some(PAGER_V2_TASK_ID);
            state.fallback_running = false;
        }
        println!(
            "LINUX_CODE_PAGER Rebind workload=linux-hello replacement={} binding_epoch={} epoch_advanced=false fallback=Standby",
            PAGER_V2_TASK_ID, presented_binding_epoch,
        );
    }

    fn recover_next(&self, presented_binding_epoch: u64) {
        let old_binding_epoch = {
            let state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, Some(PAGER_V2_TASK_ID));
            assert!(state.replacement_ready);
            let fault = state.continuation.as_ref().unwrap();
            assert_eq!(fault.phase, FaultPhase::Prepared);
            fault.binding_epoch
        };
        println!(
            "LINUX_CODE_PAGER RecoverNext workload=linux-hello replacement={} effect={} old_binding_epoch={} phase=Prepared",
            PAGER_V2_TASK_ID, self.token.effect_id, old_binding_epoch,
        );
    }

    fn adopt(&self, presented_binding_epoch: u64) {
        let old_binding_epoch = {
            let mut state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, Some(PAGER_V2_TASK_ID));
            let fault = state.continuation.as_mut().unwrap();
            assert_eq!(fault.token, self.token);
            assert_eq!(fault.binding_epoch, 1);
            assert_eq!(fault.page_address, self.rx_page_address);
            assert_eq!(fault.phase, FaultPhase::Prepared);
            let old_binding_epoch = fault.binding_epoch;
            fault.binding_epoch = presented_binding_epoch;
            fault.phase = FaultPhase::Adopted;
            old_binding_epoch
        };
        println!(
            "LINUX_CODE_PAGER Adopt workload=linux-hello replacement={} effect={} old_binding_epoch={} binding_epoch={} explicit=true",
            PAGER_V2_TASK_ID, self.token.effect_id, old_binding_epoch, presented_binding_epoch,
        );
    }

    fn commit(&self, presented_binding_epoch: u64, pager_vm: &Arc<VmSpace>) {
        assert!(!Arc::ptr_eq(&self.guest_vm, pager_vm));
        self.guest_vm.activate();
        let preempt_guard = disable_preempt();
        let mut cursor = self
            .guest_vm
            .cursor_mut(
                &preempt_guard,
                &(self.rx_page_address..self.rx_page_address + PAGE_SIZE),
            )
            .expect("acquire Linux entry-page cursor");
        assert!(
            matches!(cursor.query(), Ok((_, None))),
            "entry page remains absent until commit"
        );

        {
            let mut state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, Some(PAGER_V2_TASK_ID));
            assert!(!state.mapping_published);
            let fault = *state.continuation.as_ref().unwrap();
            assert_eq!(fault.token, self.token);
            assert_eq!(fault.binding_epoch, presented_binding_epoch);
            assert_eq!(fault.page_address, self.rx_page_address);
            assert_eq!(fault.fault_address, fault.fault_rip);
            assert_eq!(fault.access_bits & USER_PAGE_FAULT_BIT, USER_PAGE_FAULT_BIT);
            assert_eq!(
                fault.access_bits & INSTRUCTION_PAGE_FAULT_BIT,
                INSTRUCTION_PAGE_FAULT_BIT
            );
            assert_eq!(fault.phase, FaultPhase::Adopted);
            let frame = state
                .prepared_frame
                .take()
                .expect("adopted image fault retains its prepared frame");
            cursor.map(
                frame.into(),
                PageProperty::new_user(PageFlags::RX, CachePolicy::Writeback),
            );
            state.continuation.as_mut().unwrap().phase = FaultPhase::Committed;
            state.mapping_published = true;
        }
        println!(
            "LINUX_CODE_PAGER Commit workload=linux-hello replacement={} effect={} binding_epoch={} backing=elf-image image_checksum={:#x} permissions=RX pte_published=true",
            PAGER_V2_TASK_ID, self.token.effect_id, presented_binding_epoch, self.image_checksum,
        );

        let flusher = cursor.flusher();
        flusher.issue_tlb_flush(TlbFlushOp::for_single(self.rx_page_address));
        flusher.dispatch_tlb_flush();
        flusher.sync_tlb_flush();
        drop(cursor);
        drop(preempt_guard);
        pager_vm.activate();
        println!(
            "LINUX_CODE_PAGER TlbSync workload=linux-hello effect={} issue=true dispatch=true synchronize=true cpu=local single_cpu=true",
            self.token.effect_id,
        );

        let guest_waker = {
            let mut state = self.state.lock();
            assert_eq!(
                state.continuation.as_ref().unwrap().phase,
                FaultPhase::Committed
            );
            assert!(state.mapping_published);
            assert_eq!(state.terminalizations, 0);
            assert_eq!(state.wake_publications, 0);
            state.continuation.as_mut().unwrap().phase = FaultPhase::Completed;
            state.terminalizations = 1;
            state.wake_publications = 1;
            state
                .guest_waker
                .take()
                .expect("completed fault retains one guest waker")
        };
        assert!(guest_waker.wake_up());
        drop(guest_waker);
        println!(
            "LINUX_CODE_PAGER Complete workload=linux-hello effect={} terminal=Completed wake=one-shot pte=RX same_rip=true",
            self.token.effect_id,
        );
    }

    fn observe_guest_resume_return(&self) {
        let (thread_id, fault_rip) = {
            let mut state = self.state.lock();
            let fault = *state.continuation.as_ref().unwrap();
            assert_eq!(fault.phase, FaultPhase::Completed);
            assert!(state.mapping_published);
            assert_eq!(state.terminalizations, 1);
            assert_eq!(state.wake_publications, 1);
            assert_eq!(state.guest_resume_returns, 0);
            assert!(state.guest_waker.is_none());
            state.guest_resume_returns = 1;
            (fault.thread_id, fault.fault_rip)
        };
        println!(
            "LINUX_CODE_PAGER GuestResume workload=linux-hello effect={} thread={} rip={:#x} same_rip=true resume_returns=1",
            self.token.effect_id, thread_id, fault_rip,
        );
    }

    fn assert_complete(&self) {
        let state = self.state.lock();
        let fault = state
            .continuation
            .as_ref()
            .expect("entry instruction fault was registered");
        assert!(state.services_started);
        assert!(state.service_tasks_started);
        assert_eq!(state.binding_epoch, 2);
        assert_eq!(state.supervisor, Some(PAGER_V2_TASK_ID));
        assert!(!state.fallback_running);
        assert!(state.snapshot_taken);
        assert!(state.replacement_ready);
        assert_eq!(fault.token, self.token);
        assert_eq!(fault.binding_epoch, 2);
        assert_eq!(fault.page_address, self.rx_page_address);
        assert_eq!(fault.fault_address, fault.fault_rip);
        assert_eq!(fault.phase, FaultPhase::Completed);
        assert!(state.prepared_frame.is_none());
        assert!(state.guest_waker.is_none());
        assert!(state.mapping_published);
        assert_eq!(state.terminalizations, 1);
        assert_eq!(state.stale_rejections, 2);
        assert_eq!(state.no_supervisor_rejections, 1);
        assert_eq!(state.wake_publications, 1);
        assert_eq!(state.guest_resume_returns, 1);
        println!(
            "LINUX_CODE_PAGER PASS workload=linux-hello effect={} backing=elf-image pager_crash_rebind=true old_binding_rejections=2 terminalizations=1 wake_publications=1 resume_returns=1 permissions=RX same_rip=true single_cpu=true bounded=true",
            self.token.effect_id,
        );
    }
}

fn run_pager_v1(scenario: Arc<PagerScenario>, vm_space: Arc<VmSpace>) {
    assert_current_user_task(PAGER_V1_TASK_ID, &vm_space);
    while !scenario.fault_is_registered() {
        Task::yield_now();
    }
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);

    match user_mode.execute(|| false) {
        ReturnReason::UserSyscall => {
            assert_eq!(user_mode.context().rax(), PAGER_V1_PREPARE_IMAGE)
        }
        other => panic!("Linux code pager v1 should prepare its image, got {other:?}"),
    }
    scenario.prepare_image(1);

    vm_space.activate();
    let info = match user_mode.execute(|| false) {
        ReturnReason::UserException => match user_mode.context_mut().take_exception() {
            Some(CpuException::PageFault(info)) => info,
            other => panic!("Linux code pager v1 received unexpected exception: {other:?}"),
        },
        other => panic!("Linux code pager v1 should crash with a page fault, got {other:?}"),
    };
    assert_eq!(info.addr, PAGER_CRASH_ADDR);
    assert_eq!(info.error_code.bits() & 1, 0);
    assert_ne!(info.error_code.bits() & USER_PAGE_FAULT_BIT, 0);
    assert_eq!(scenario.crash_v1(1), 2);
    scenario.reject_stale_reply(1, "post_crash");
    println!(
        "LINUX_CODE_PAGER_V1 EXIT workload=linux-hello task={} reason=real_user_page_fault",
        PAGER_V1_TASK_ID,
    );
}

fn run_watchdog(
    scenario: Arc<PagerScenario>,
    old_pager_task: Arc<Task>,
    old_pager_vm: Arc<VmSpace>,
) {
    assert_current_kernel_task(WATCHDOG_TASK_ID);
    while !scenario.has_crashed() {
        Task::yield_now();
    }
    println!(
        "LINUX_CODE_PAGER Fallback workload=linux-hello binding_epoch=2 action=close_map+wake_gate+retain_image+fresh_spawn"
    );

    let pager_v2_vm = Arc::new(create_vm_space(PAGER_V2_PROGRAM));
    assert!(!Arc::ptr_eq(&old_pager_vm, &pager_v2_vm));
    let pager_v2_state = scenario.clone();
    let pager_v2_task_vm = pager_v2_vm.clone();
    let pager_v2_task = Arc::new(
        TaskOptions::new(move || run_pager_v2(pager_v2_state, pager_v2_task_vm))
            .data(TaskData::new(PAGER_V2_TASK_ID, Some(pager_v2_vm)))
            .build()
            .expect("build fresh Linux code pager v2 task"),
    );
    assert!(!Arc::ptr_eq(&old_pager_task, &pager_v2_task));
    println!(
        "LINUX_CODE_PAGER FreshSpawn workload=linux-hello task={} vm=fresh user_mode=constructed_in_task binding_epoch=2",
        PAGER_V2_TASK_ID,
    );
    pager_v2_task.run();
}

fn run_pager_v2(scenario: Arc<PagerScenario>, vm_space: Arc<VmSpace>) {
    assert_current_user_task(PAGER_V2_TASK_ID, &vm_space);
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);

    loop {
        vm_space.activate();
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => match user_mode.context().rax() {
                PAGER_V2_RECOVERY_SNAPSHOT => scenario.recovery_snapshot(2),
                PAGER_V2_READY => {
                    scenario.ready(2);
                    scenario.reject_no_supervisor(2);
                }
                PAGER_V2_REBIND => {
                    scenario.rebind(2);
                    scenario.reject_stale_reply(1, "post_rebind");
                }
                PAGER_V2_RECOVER_NEXT => scenario.recover_next(2),
                PAGER_V2_ADOPT => scenario.adopt(2),
                PAGER_V2_COMMIT => {
                    scenario.commit(2, &vm_space);
                    println!(
                        "LINUX_CODE_PAGER_V2 EXIT workload=linux-hello task={} reason=commit_complete",
                        PAGER_V2_TASK_ID,
                    );
                    return;
                }
                syscall => panic!("unknown Linux code pager v2 portal syscall {syscall:#x}"),
            },
            ReturnReason::UserException => panic!(
                "fresh Linux code pager v2 unexpectedly faulted: {:?}",
                user_mode.context_mut().take_exception()
            ),
            ReturnReason::KernelEvent => {
                panic!("Linux code pager v2 has no synthetic kernel event")
            }
        }
    }
}

fn assert_current_user_task(expected_id: u64, vm_space: &Arc<VmSpace>) {
    let current = Task::current().expect("user-mode pager runs in an OSTD task");
    let data = current
        .data()
        .downcast_ref::<TaskData>()
        .expect("Linux code pager carries Nexus TaskData");
    assert_eq!(data.id, expected_id);
    assert!(
        data.vm_space
            .as_ref()
            .is_some_and(|vm| Arc::ptr_eq(vm, vm_space))
    );
}

fn assert_current_kernel_task(expected_id: u64) {
    let current = Task::current().expect("Linux code pager watchdog runs in an OSTD task");
    let data = current
        .data()
        .downcast_ref::<TaskData>()
        .expect("Linux code pager watchdog carries Nexus TaskData");
    assert_eq!(data.id, expected_id);
    assert!(data.vm_space.is_none());
}

fn image_checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}
