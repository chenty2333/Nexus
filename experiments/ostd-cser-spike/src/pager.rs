// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;

use ostd::{
    arch::cpu::context::{CpuException, UserContext},
    mm::{
        CachePolicy, Frame, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty, Vaddr, VmSpace,
        tlb::TlbFlushOp,
    },
    prelude::*,
    sync::SpinLock,
    task::{Task, TaskOptions, disable_preempt},
    timer::Jiffies,
    user::{ReturnReason, UserMode},
};

use crate::{
    TaskData, USER_MAP_ADDR, create_vm_space,
    effect::{EffectToken, EffectWaiter, EffectWaker},
};

const PAGER_AUTHORITY_EPOCH: u64 = 71;
const ADDRESS_SPACE_ID: u64 = 1;
const ADDRESS_SPACE_GENERATION: u64 = 1;
const FAULT_ADDR: Vaddr = USER_MAP_ADDR + PAGE_SIZE;
const CLIENT_FAULT_RIP: Vaddr = USER_MAP_ADDR + 5;
const EXPECTED_ACCESS_BITS: usize = 1 << 2;
const WATCHDOG_TICKS: u64 = 8;

const RECOVER_SCOPE_ID: u64 = 20;
const TIMEOUT_SCOPE_ID: u64 = 21;
const RECOVER_FAULT_ID: u64 = 1;
const TIMEOUT_FAULT_ID: u64 = 2;

const RECOVER_CLIENT_TASK_ID: u64 = 300;
const RECOVER_PAGER_V1_TASK_ID: u64 = 301;
const RECOVER_WATCHDOG_TASK_ID: u64 = 302;
const RECOVER_PAGER_V2_TASK_ID: u64 = 303;
const TIMEOUT_CLIENT_TASK_ID: u64 = 310;
const TIMEOUT_PAGER_V1_TASK_ID: u64 = 311;
const TIMEOUT_WATCHDOG_TASK_ID: u64 = 312;

const CLIENT_RESUMED: usize = 0x5041_0001;
const PAGER_PREPARE_ZERO: usize = 0x5042_0001;
const PAGER_RECOVERY_SNAPSHOT: usize = 0x5043_0001;
const PAGER_READY: usize = 0x5043_0002;
const PAGER_REBIND: usize = 0x5043_0003;
const PAGER_RECOVER_NEXT: usize = 0x5043_0004;
const PAGER_ADOPT: usize = 0x5043_0005;
const PAGER_COMMIT: usize = 0x5043_0006;

const CLIENT_PROGRAM: &[u8] = include_bytes!("../guest/pager-client.bin");
const PAGER_V1_PROGRAM: &[u8] = include_bytes!("../guest/pager-v1.bin");
const PAGER_V2_PROGRAM: &[u8] = include_bytes!("../guest/pager-v2.bin");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScenarioKind {
    Recover,
    Timeout,
}

impl ScenarioKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Recover => "recover",
            Self::Timeout => "timeout",
        }
    }

    const fn scope_id(self) -> u64 {
        match self {
            Self::Recover => RECOVER_SCOPE_ID,
            Self::Timeout => TIMEOUT_SCOPE_ID,
        }
    }

    const fn fault_id(self) -> u64 {
        match self {
            Self::Recover => RECOVER_FAULT_ID,
            Self::Timeout => TIMEOUT_FAULT_ID,
        }
    }

    const fn client_task_id(self) -> u64 {
        match self {
            Self::Recover => RECOVER_CLIENT_TASK_ID,
            Self::Timeout => TIMEOUT_CLIENT_TASK_ID,
        }
    }

    const fn pager_v1_task_id(self) -> u64 {
        match self {
            Self::Recover => RECOVER_PAGER_V1_TASK_ID,
            Self::Timeout => TIMEOUT_PAGER_V1_TASK_ID,
        }
    }

    const fn watchdog_task_id(self) -> u64 {
        match self {
            Self::Recover => RECOVER_WATCHDOG_TASK_ID,
            Self::Timeout => TIMEOUT_WATCHDOG_TASK_ID,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScopePhase {
    Active,
    Closing,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPhase {
    Registered,
    Prepared,
    Adopted,
    Committed,
    Completed,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientOutcome {
    Pending,
    Resolved,
    Aborted,
}

#[derive(Clone, Copy, Debug)]
struct FaultRecord {
    effect_id: u64,
    authority_epoch: u64,
    binding_epoch: u64,
    address_space_id: u64,
    address_space_generation: u64,
    thread_id: u64,
    page_address: Vaddr,
    access_bits: usize,
    fault_rip: Vaddr,
    phase: FaultPhase,
}

struct PagerState {
    authority_epoch: u64,
    binding_epoch: u64,
    scope_phase: ScopePhase,
    supervisor: Option<u64>,
    fallback_running: bool,
    snapshot_taken: bool,
    replacement_ready: bool,
    fault: Option<FaultRecord>,
    prepared_frame: Option<Frame<()>>,
    client_waker: Option<EffectWaker>,
    completion_waker: Option<EffectWaker>,
    client_outcome: ClientOutcome,
    free_credit: u64,
    held_credit: u64,
    spent_credit: u64,
    mapping_published: bool,
    cleanup_inflight: bool,
    wake_pending: bool,
    terminalizations: u64,
    stale_rejections: u64,
    pre_rebind_rejections: u64,
    post_rebind_stale_rejections: u64,
    client_finished: bool,
}

struct PagerScenario {
    kind: ScenarioKind,
    client_vm: Arc<VmSpace>,
    state: SpinLock<PagerState>,
}

impl PagerScenario {
    fn new(kind: ScenarioKind, client_vm: Arc<VmSpace>, completion_waker: EffectWaker) -> Self {
        Self {
            kind,
            client_vm,
            state: SpinLock::new(PagerState {
                authority_epoch: PAGER_AUTHORITY_EPOCH,
                binding_epoch: 1,
                scope_phase: ScopePhase::Active,
                supervisor: Some(kind.pager_v1_task_id()),
                fallback_running: false,
                snapshot_taken: false,
                replacement_ready: false,
                fault: None,
                prepared_frame: None,
                client_waker: None,
                completion_waker: Some(completion_waker),
                client_outcome: ClientOutcome::Pending,
                free_credit: 1,
                held_credit: 0,
                spent_credit: 0,
                mapping_published: false,
                cleanup_inflight: false,
                wake_pending: false,
                terminalizations: 0,
                stale_rejections: 0,
                pre_rebind_rejections: 0,
                post_rebind_stale_rejections: 0,
                client_finished: false,
            }),
        }
    }

    fn effect_token(&self) -> EffectToken {
        EffectToken {
            authority_epoch: PAGER_AUTHORITY_EPOCH,
            scope_id: self.kind.scope_id(),
            effect_id: self.kind.fault_id(),
        }
    }

    fn register_fault(&self, fault_rip: Vaddr, access_bits: usize, waker: EffectWaker) {
        let token = self.effect_token();
        assert_eq!(waker.token(), token);

        let binding_epoch = {
            let mut state = self.state.lock();
            assert_eq!(state.scope_phase, ScopePhase::Active);
            assert_eq!(state.supervisor, Some(self.kind.pager_v1_task_id()));
            assert!(state.fault.is_none());
            assert!(state.client_waker.is_none());
            assert_eq!(state.client_outcome, ClientOutcome::Pending);

            let binding_epoch = state.binding_epoch;
            state.fault = Some(FaultRecord {
                effect_id: token.effect_id,
                authority_epoch: token.authority_epoch,
                binding_epoch,
                address_space_id: ADDRESS_SPACE_ID,
                address_space_generation: ADDRESS_SPACE_GENERATION,
                thread_id: self.kind.client_task_id(),
                page_address: FAULT_ADDR,
                access_bits,
                fault_rip,
                phase: FaultPhase::Registered,
            });
            state.client_waker = Some(waker);
            binding_epoch
        };

        println!(
            "PAGER Register scenario={} scope={} fault={} authority_epoch={} binding_epoch={} as={} as_generation={} thread={} addr={:#x} access_bits={:#x} rip={:#x}",
            self.kind.label(),
            token.scope_id,
            token.effect_id,
            token.authority_epoch,
            binding_epoch,
            ADDRESS_SPACE_ID,
            ADDRESS_SPACE_GENERATION,
            self.kind.client_task_id(),
            FAULT_ADDR,
            access_bits,
            fault_rip,
        );
    }

    fn prepare_zero(&self, presented_binding_epoch: u64) {
        {
            let state = self.state.lock();
            assert_eq!(state.scope_phase, ScopePhase::Active);
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, Some(self.kind.pager_v1_task_id()));
            assert_eq!(state.fault.as_ref().unwrap().phase, FaultPhase::Registered);
        }

        // Frame allocation and zeroing happen outside the pager-state gate. The
        // candidate becomes kernel-owned only after the locked revalidation.
        let candidate = FrameAllocOptions::new()
            .alloc_frame()
            .expect("allocate prepared pager zero frame");

        {
            let mut state = self.state.lock();
            assert_eq!(state.scope_phase, ScopePhase::Active);
            assert_eq!(state.authority_epoch, PAGER_AUTHORITY_EPOCH);
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, Some(self.kind.pager_v1_task_id()));
            assert!(state.prepared_frame.is_none());
            assert_eq!(state.free_credit, 1);
            assert_eq!(state.held_credit, 0);
            let fault = *state.fault.as_ref().unwrap();
            assert_eq!(fault.authority_epoch, state.authority_epoch);
            assert_eq!(fault.binding_epoch, presented_binding_epoch);
            assert_eq!(fault.address_space_id, ADDRESS_SPACE_ID);
            assert_eq!(fault.address_space_generation, ADDRESS_SPACE_GENERATION);
            assert_eq!(fault.thread_id, self.kind.client_task_id());
            assert_eq!(fault.page_address, FAULT_ADDR);
            assert_eq!(fault.access_bits, EXPECTED_ACCESS_BITS);
            assert_eq!(fault.phase, FaultPhase::Registered);
            state.fault.as_mut().unwrap().phase = FaultPhase::Prepared;
            state.prepared_frame = Some(candidate);
            state.free_credit = 0;
            state.held_credit = 1;
        }

        println!(
            "PAGER PrepareZero scenario={} fault={} binding_epoch={} owner=kernel credit=Held",
            self.kind.label(),
            self.kind.fault_id(),
            presented_binding_epoch,
        );
    }

    fn crash_v1(&self, presented_binding_epoch: u64) -> u64 {
        let new_binding_epoch = {
            let mut state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, Some(self.kind.pager_v1_task_id()));
            assert_eq!(state.fault.as_ref().unwrap().phase, FaultPhase::Prepared);
            assert!(state.prepared_frame.is_some());

            state.binding_epoch = state
                .binding_epoch
                .checked_add(1)
                .expect("pager binding epoch overflow");
            state.supervisor = None;
            state.fallback_running = true;
            state.snapshot_taken = false;
            state.replacement_ready = false;
            state.binding_epoch
        };

        println!(
            "PAGER Crash scenario={} supervisor={} previous_binding_epoch={} binding_epoch={} reason=user_page_fault prepared_retained=true",
            self.kind.label(),
            self.kind.pager_v1_task_id(),
            presented_binding_epoch,
            new_binding_epoch,
        );
        new_binding_epoch
    }

    fn reject_stale_reply(
        &self,
        presented_binding_epoch: u64,
        stage: &'static str,
        after_rebind: bool,
    ) {
        let current_binding_epoch = {
            let mut state = self.state.lock();
            assert_ne!(state.binding_epoch, presented_binding_epoch);
            assert!(!state.mapping_published);
            state.stale_rejections += 1;
            if after_rebind {
                assert!(state.supervisor.is_some());
                state.post_rebind_stale_rejections += 1;
            }
            state.binding_epoch
        };
        println!(
            "PAGER REJECT_STALE scenario={} stage={} action=Commit proposal_binding_epoch={} current_binding_epoch={} vm_mutation=false",
            self.kind.label(),
            stage,
            presented_binding_epoch,
            current_binding_epoch,
        );
    }

    fn reject_pre_rebind_reply(&self, presented_binding_epoch: u64) {
        {
            let mut state = self.state.lock();
            assert_eq!(state.scope_phase, ScopePhase::Active);
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, None);
            assert!(state.fallback_running);
            assert!(state.snapshot_taken);
            assert!(state.replacement_ready);
            assert_eq!(state.fault.as_ref().unwrap().phase, FaultPhase::Prepared);
            assert!(!state.mapping_published);
            state.pre_rebind_rejections += 1;
        }
        println!(
            "PAGER REJECT_NO_SUPERVISOR scenario={} stage=pre_rebind action=Commit proposal_binding_epoch={} vm_mutation=false",
            self.kind.label(),
            presented_binding_epoch,
        );
    }

    fn assert_crashed(&self) -> u64 {
        let state = self.state.lock();
        assert_eq!(state.supervisor, None);
        assert!(state.fallback_running);
        assert_eq!(state.binding_epoch, 2);
        assert_eq!(state.fault.as_ref().unwrap().phase, FaultPhase::Prepared);
        assert!(state.prepared_frame.is_some());
        state.binding_epoch
    }

    fn fault_is_registered(&self) -> bool {
        self.state
            .lock()
            .fault
            .as_ref()
            .is_some_and(|fault| fault.phase == FaultPhase::Registered)
    }

    fn has_crashed(&self) -> bool {
        let state = self.state.lock();
        state.supervisor.is_none() && state.fallback_running && state.binding_epoch == 2
    }

    fn recovery_snapshot(&self, replacement_task_id: u64, presented_binding_epoch: u64) {
        let (fault_id, phase) = {
            let mut state = self.state.lock();
            assert_eq!(state.scope_phase, ScopePhase::Active);
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, None);
            assert!(state.fallback_running);
            assert!(!state.snapshot_taken);
            state.snapshot_taken = true;
            let fault = state.fault.as_ref().unwrap();
            (fault.effect_id, fault.phase)
        };
        println!(
            "PAGER RecoverySnapshot scenario={} replacement={} binding_epoch={} fault={} phase={:?} prepared=true",
            self.kind.label(),
            replacement_task_id,
            presented_binding_epoch,
            fault_id,
            phase,
        );
    }

    fn ready(&self, replacement_task_id: u64, presented_binding_epoch: u64) {
        {
            let mut state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, None);
            assert!(state.snapshot_taken);
            assert!(!state.replacement_ready);
            state.replacement_ready = true;
        }
        println!(
            "PAGER Ready scenario={} replacement={} binding_epoch={}",
            self.kind.label(),
            replacement_task_id,
            presented_binding_epoch,
        );
    }

    fn rebind(&self, replacement_task_id: u64, presented_binding_epoch: u64) {
        {
            let mut state = self.state.lock();
            assert_eq!(state.scope_phase, ScopePhase::Active);
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, None);
            assert!(state.fallback_running);
            assert!(state.snapshot_taken);
            assert!(state.replacement_ready);
            state.supervisor = Some(replacement_task_id);
            state.fallback_running = false;
        }
        println!(
            "PAGER Rebind scenario={} replacement={} binding_epoch={} epoch_advanced=false pager_fallback=Standby",
            self.kind.label(),
            replacement_task_id,
            presented_binding_epoch,
        );
    }

    fn recover_next(&self, replacement_task_id: u64, presented_binding_epoch: u64) {
        let fault = {
            let state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, Some(replacement_task_id));
            assert!(state.replacement_ready);
            *state.fault.as_ref().unwrap()
        };
        println!(
            "PAGER RecoverNext scenario={} replacement={} fault={} old_binding_epoch={} phase={:?}",
            self.kind.label(),
            replacement_task_id,
            fault.effect_id,
            fault.binding_epoch,
            fault.phase,
        );
    }

    fn adopt(&self, replacement_task_id: u64, presented_binding_epoch: u64) {
        let old_binding_epoch = {
            let mut state = self.state.lock();
            assert_eq!(state.scope_phase, ScopePhase::Active);
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, Some(replacement_task_id));
            let authority_epoch = state.authority_epoch;
            let fault = *state.fault.as_ref().unwrap();
            assert_eq!(fault.authority_epoch, authority_epoch);
            assert_eq!(fault.binding_epoch, 1);
            assert_eq!(fault.address_space_id, ADDRESS_SPACE_ID);
            assert_eq!(fault.address_space_generation, ADDRESS_SPACE_GENERATION);
            assert_eq!(fault.thread_id, self.kind.client_task_id());
            assert_eq!(fault.page_address, FAULT_ADDR);
            assert_eq!(fault.access_bits, EXPECTED_ACCESS_BITS);
            assert_eq!(fault.phase, FaultPhase::Prepared);
            let old_binding_epoch = fault.binding_epoch;
            let fault = state.fault.as_mut().unwrap();
            fault.binding_epoch = presented_binding_epoch;
            fault.phase = FaultPhase::Adopted;
            old_binding_epoch
        };
        println!(
            "PAGER Adopt scenario={} replacement={} fault={} old_binding_epoch={} binding_epoch={} explicit=true",
            self.kind.label(),
            replacement_task_id,
            self.kind.fault_id(),
            old_binding_epoch,
            presented_binding_epoch,
        );
    }

    fn commit(
        &self,
        replacement_task_id: u64,
        presented_binding_epoch: u64,
        pager_vm: &Arc<VmSpace>,
    ) {
        assert!(!Arc::ptr_eq(&self.client_vm, pager_vm));

        // Make the target address space current so this one-CPU experiment
        // exercises a real local TLB invalidation rather than an empty CPU set.
        self.client_vm.activate();
        let preempt_guard = disable_preempt();
        let mut cursor = self
            .client_vm
            .cursor_mut(&preempt_guard, &(FAULT_ADDR..FAULT_ADDR + PAGE_SIZE))
            .expect("acquire exclusive client fault-page cursor");
        assert!(
            matches!(cursor.query(), Ok((_, None))),
            "fault slot is empty"
        );

        {
            let mut state = self.state.lock();
            assert_eq!(state.scope_phase, ScopePhase::Active);
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, Some(replacement_task_id));
            assert_eq!(state.held_credit, 1);
            assert_eq!(state.spent_credit, 0);
            let fault = *state.fault.as_ref().unwrap();
            assert_eq!(fault.effect_id, self.kind.fault_id());
            assert_eq!(fault.authority_epoch, state.authority_epoch);
            assert_eq!(fault.binding_epoch, presented_binding_epoch);
            assert_eq!(fault.address_space_id, ADDRESS_SPACE_ID);
            assert_eq!(fault.address_space_generation, ADDRESS_SPACE_GENERATION);
            assert_eq!(fault.thread_id, self.kind.client_task_id());
            assert_eq!(fault.page_address, FAULT_ADDR);
            assert_eq!(fault.access_bits, EXPECTED_ACCESS_BITS);
            assert_eq!(fault.fault_rip, CLIENT_FAULT_RIP);
            assert_eq!(fault.phase, FaultPhase::Adopted);

            let frame = state
                .prepared_frame
                .take()
                .expect("adopted fault retains one prepared frame");
            cursor.map(
                frame.into(),
                PageProperty::new_user(PageFlags::RW, CachePolicy::Writeback),
            );
            state.fault.as_mut().unwrap().phase = FaultPhase::Committed;
            state.mapping_published = true;
            state.held_credit = 0;
            state.spent_credit = 1;
        }

        println!(
            "PAGER Commit scenario={} replacement={} fault={} binding_epoch={} pte_published=true credit=Spent",
            self.kind.label(),
            replacement_task_id,
            self.kind.fault_id(),
            presented_binding_epoch,
        );

        let flusher = cursor.flusher();
        flusher.issue_tlb_flush(TlbFlushOp::for_single(FAULT_ADDR));
        flusher.dispatch_tlb_flush();
        flusher.sync_tlb_flush();
        drop(cursor);
        drop(preempt_guard);
        pager_vm.activate();

        println!(
            "PAGER TlbSync scenario={} fault={} issue=true dispatch=true synchronize=true cpu=local",
            self.kind.label(),
            self.kind.fault_id(),
        );

        let client_waker = {
            let mut state = self.state.lock();
            assert_eq!(state.fault.as_ref().unwrap().phase, FaultPhase::Committed);
            assert!(state.mapping_published);
            assert_eq!(state.terminalizations, 0);
            state.fault.as_mut().unwrap().phase = FaultPhase::Completed;
            state.client_outcome = ClientOutcome::Resolved;
            state.terminalizations = 1;
            state
                .client_waker
                .take()
                .expect("resolved fault has one client waker")
        };

        println!(
            "PAGER Complete scenario={} fault={} terminal=Completed wake=one-shot",
            self.kind.label(),
            self.kind.fault_id(),
        );
        assert!(client_waker.wake_up());
    }

    fn watchdog_abort(&self) {
        let binding_epoch = self.assert_crashed();
        let start = Jiffies::elapsed().as_u64();
        let deadline = start.saturating_add(WATCHDOG_TICKS);
        println!(
            "PAGER WatchdogArm scenario={} binding_epoch={} start={} deadline={}",
            self.kind.label(),
            binding_epoch,
            start,
            deadline,
        );
        while Jiffies::elapsed().as_u64() < deadline {
            Task::yield_now();
        }

        let (old_authority_epoch, new_authority_epoch, prepared_frame, client_waker) = {
            let mut state = self.state.lock();
            assert_eq!(state.scope_phase, ScopePhase::Active);
            assert_eq!(state.supervisor, None);
            assert!(state.fallback_running);
            assert_eq!(state.fault.as_ref().unwrap().phase, FaultPhase::Prepared);
            assert_eq!(state.held_credit, 1);
            assert_eq!(state.free_credit, 0);
            assert!(!state.cleanup_inflight);
            assert!(!state.wake_pending);
            assert_eq!(state.terminalizations, 0);

            let old_authority_epoch = state.authority_epoch;
            state.authority_epoch = state
                .authority_epoch
                .checked_add(1)
                .expect("pager authority epoch overflow");
            state.scope_phase = ScopePhase::Closing;
            state.cleanup_inflight = true;
            state.wake_pending = true;
            state.fault.as_mut().unwrap().phase = FaultPhase::Aborted;
            state.client_outcome = ClientOutcome::Aborted;
            state.terminalizations = 1;
            let prepared_frame = state
                .prepared_frame
                .take()
                .expect("timeout closure retains the prepared frame until lock-free cleanup");
            let client_waker = state
                .client_waker
                .take()
                .expect("timeout closure retains one client waker until cleanup completes");
            let new_authority_epoch = state.authority_epoch;
            (
                old_authority_epoch,
                new_authority_epoch,
                prepared_frame,
                client_waker,
            )
        };

        println!(
            "PAGER RevokeBegin scenario={} scope={} old_authority_epoch={} authority_epoch={} reason=watchdog_timeout scope_phase=Closing reply_gate=closed cleanup_inflight=true wake_pending=true credit=Held",
            self.kind.label(),
            self.kind.scope_id(),
            old_authority_epoch,
            new_authority_epoch,
        );
        drop(prepared_frame);
        println!(
            "PAGER CleanupDrop scenario={} fault={} prepared_dropped=true outside_lock=true cleanup_inflight=true wake_pending=true credit=Held",
            self.kind.label(),
            self.kind.fault_id(),
        );

        let wake_published = client_waker.wake_up();
        assert!(wake_published);
        drop(client_waker);
        println!(
            "PAGER Abort scenario={} fault={} terminal=Aborted prepared_dropped=true credit=Held cleanup_inflight=true wake_pending=true wake_published=true waker_dropped=true",
            self.kind.label(),
            self.kind.fault_id(),
        );

        {
            let mut state = self.state.lock();
            assert_eq!(state.scope_phase, ScopePhase::Closing);
            assert_eq!(state.authority_epoch, new_authority_epoch);
            assert_eq!(state.supervisor, None);
            assert!(state.fallback_running);
            assert!(state.cleanup_inflight);
            assert!(state.wake_pending);
            assert!(wake_published);
            assert!(state.prepared_frame.is_none());
            assert!(state.client_waker.is_none());
            assert_eq!(state.fault.as_ref().unwrap().phase, FaultPhase::Aborted);
            assert_eq!(state.client_outcome, ClientOutcome::Aborted);
            assert_eq!(state.terminalizations, 1);
            assert_eq!(state.free_credit, 0);
            assert_eq!(state.held_credit, 1);
            assert_eq!(state.spent_credit, 0);

            state.free_credit = 1;
            state.held_credit = 0;
            state.cleanup_inflight = false;
            state.wake_pending = false;
            state.scope_phase = ScopePhase::Revoked;
            state.fallback_running = false;
        }

        println!(
            "PAGER RevokeComplete scenario={} scope={} authority_epoch={} live_effects=0 retained_frames=0 cleanup_inflight=false wake_pending=false wake_published=true waker_dropped=true credit=Returned pager_fallback=Standby",
            self.kind.label(),
            self.kind.scope_id(),
            new_authority_epoch,
        );
    }

    fn client_outcome(&self) -> ClientOutcome {
        self.state.lock().client_outcome
    }

    fn await_revoke_complete(&self) {
        loop {
            let revoked = {
                let state = self.state.lock();
                if state.scope_phase == ScopePhase::Revoked {
                    assert!(!state.cleanup_inflight);
                    assert!(!state.wake_pending);
                    true
                } else {
                    assert_eq!(state.scope_phase, ScopePhase::Closing);
                    assert!(state.cleanup_inflight);
                    assert!(state.wake_pending);
                    false
                }
            };
            if revoked {
                return;
            }
            Task::yield_now();
        }
    }

    fn finish_client(&self) {
        let completion_waker = {
            let mut state = self.state.lock();
            assert!(!state.client_finished);
            assert!(matches!(
                state.client_outcome,
                ClientOutcome::Resolved | ClientOutcome::Aborted
            ));
            assert_eq!(state.terminalizations, 1);
            state.client_finished = true;
            state
                .completion_waker
                .take()
                .expect("scenario completion is published once")
        };
        assert!(completion_waker.wake_up());
    }

    fn assert_final(&self) {
        let state = self.state.lock();
        let fault = state.fault.as_ref().unwrap();
        assert_eq!(fault.effect_id, self.kind.fault_id());
        assert_eq!(fault.thread_id, self.kind.client_task_id());
        assert_eq!(fault.fault_rip, CLIENT_FAULT_RIP);
        assert_eq!(fault.access_bits, EXPECTED_ACCESS_BITS);
        assert!(state.client_finished);
        assert_eq!(state.terminalizations, 1);
        assert!(state.prepared_frame.is_none());
        assert!(state.client_waker.is_none());
        assert!(state.completion_waker.is_none());
        assert!(!state.cleanup_inflight);
        assert!(!state.wake_pending);
        assert_eq!(
            state.free_credit + state.held_credit + state.spent_credit,
            1
        );
        assert!(state.stale_rejections >= 1);

        match self.kind {
            ScenarioKind::Recover => {
                assert_eq!(state.scope_phase, ScopePhase::Active);
                assert_eq!(state.authority_epoch, PAGER_AUTHORITY_EPOCH);
                assert_eq!(state.binding_epoch, 2);
                assert_eq!(state.supervisor, Some(RECOVER_PAGER_V2_TASK_ID));
                assert!(!state.fallback_running);
                assert_eq!(fault.phase, FaultPhase::Completed);
                assert_eq!(state.client_outcome, ClientOutcome::Resolved);
                assert!(state.mapping_published);
                assert_eq!(
                    (state.free_credit, state.held_credit, state.spent_credit),
                    (0, 0, 1)
                );
            }
            ScenarioKind::Timeout => {
                assert_eq!(state.scope_phase, ScopePhase::Revoked);
                assert_eq!(state.authority_epoch, PAGER_AUTHORITY_EPOCH + 1);
                assert_eq!(state.supervisor, None);
                assert!(!state.fallback_running);
                assert_eq!(fault.phase, FaultPhase::Aborted);
                assert_eq!(state.client_outcome, ClientOutcome::Aborted);
                assert!(!state.mapping_published);
                assert_eq!(
                    (state.free_credit, state.held_credit, state.spent_credit),
                    (1, 0, 0)
                );
            }
        }
    }
}

pub fn run_pager_slices() {
    run_scenario(ScenarioKind::Recover);
    run_scenario(ScenarioKind::Timeout);
    println!(
        "PAGER_SLICE PASS scenarios=recover+timeout single_cpu=true zero_page=true single_client=true task_kill=false"
    );
}

fn run_scenario(kind: ScenarioKind) {
    let done_token = EffectToken {
        authority_epoch: PAGER_AUTHORITY_EPOCH,
        scope_id: kind.scope_id(),
        effect_id: 900 + kind.fault_id(),
    };
    let (done_waiter, done_waker) = EffectWaiter::new_pair(done_token);

    let client_vm = Arc::new(create_vm_space(CLIENT_PROGRAM));
    let scenario = Arc::new(PagerScenario::new(kind, client_vm.clone(), done_waker));

    let client_state = scenario.clone();
    let client_task_vm = client_vm.clone();
    let client_task = Arc::new(
        TaskOptions::new(move || run_client(client_state, client_task_vm))
            .data(TaskData::new(kind.client_task_id(), Some(client_vm)))
            .build()
            .expect("build pager client task"),
    );

    let pager_v1_vm = Arc::new(create_vm_space(PAGER_V1_PROGRAM));
    let pager_v1_state = scenario.clone();
    let pager_v1_task_vm = pager_v1_vm.clone();
    let pager_v1_task = Arc::new(
        TaskOptions::new(move || run_pager_v1(pager_v1_state, pager_v1_task_vm))
            .data(TaskData::new(
                kind.pager_v1_task_id(),
                Some(pager_v1_vm.clone()),
            ))
            .build()
            .expect("build pager v1 task"),
    );

    let watchdog_state = scenario.clone();
    let old_task = pager_v1_task.clone();
    let old_vm = pager_v1_vm;
    let watchdog_task = Arc::new(
        TaskOptions::new(move || run_watchdog(watchdog_state, old_task, old_vm))
            .data(TaskData::new(kind.watchdog_task_id(), None))
            .build()
            .expect("build pager watchdog task"),
    );

    println!(
        "PAGER_SCENARIO BEGIN scenario={} scope={} fault={} scheduler_mode=kernel_fifo_fallback",
        kind.label(),
        kind.scope_id(),
        kind.fault_id(),
    );
    client_task.run();
    pager_v1_task.run();
    watchdog_task.run();
    done_waiter.wait();
    drop(done_waiter);

    scenario.assert_final();
    println!(
        "PAGER_SCENARIO PASS scenario={} terminalizations=1",
        kind.label(),
    );
}

fn run_client(scenario: Arc<PagerScenario>, vm_space: Arc<VmSpace>) {
    assert_current_task(scenario.kind.client_task_id(), &vm_space);
    vm_space.activate();

    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);

    let info = match user_mode.execute(|| false) {
        ReturnReason::UserException => match user_mode.context_mut().take_exception() {
            Some(CpuException::PageFault(info)) => info,
            other => panic!("pager client received unexpected exception: {other:?}"),
        },
        other => panic!("pager client should fault before returning {other:?}"),
    };
    assert_eq!(info.addr, FAULT_ADDR);
    assert_eq!(info.error_code.bits() & 1, 0, "fault must be not-present");
    assert_ne!(
        info.error_code.bits() & (1 << 2),
        0,
        "fault must be user-mode"
    );
    let fault_rip = user_mode.context().rip();

    let token = scenario.effect_token();
    let (fault_waiter, fault_waker) = EffectWaiter::new_pair(token);
    scenario.register_fault(fault_rip, info.error_code.bits(), fault_waker);
    println!(
        "PAGER ClientBlocked scenario={} fault={} rip={:#x}",
        scenario.kind.label(),
        scenario.kind.fault_id(),
        fault_rip,
    );
    fault_waiter.wait();
    let outcome = scenario.client_outcome();
    drop(fault_waiter);

    match outcome {
        ClientOutcome::Resolved => {
            vm_space.activate();
            assert_eq!(
                user_mode.context().rip(),
                fault_rip,
                "fault RIP must be unchanged"
            );
            match user_mode.execute(|| false) {
                ReturnReason::UserSyscall => {}
                other => panic!("resolved pager client did not reach success syscall: {other:?}"),
            }
            assert_eq!(user_mode.context().rax(), CLIENT_RESUMED);
            assert_eq!(
                user_mode.context().rbx(),
                0,
                "prepared zero page must read as zero"
            );
            println!(
                "PAGER ClientResume scenario={} fault={} same_rip=true value=0 terminal=Resolved",
                scenario.kind.label(),
                scenario.kind.fault_id(),
            );
        }
        ClientOutcome::Aborted => {
            assert_eq!(user_mode.context().rip(), fault_rip);
            scenario.await_revoke_complete();
            println!(
                "PAGER ClientExit scenario={} fault={} terminal=Aborted cooperative=true",
                scenario.kind.label(),
                scenario.kind.fault_id(),
            );
        }
        ClientOutcome::Pending => panic!("client woke without a terminal pager outcome"),
    }

    scenario.finish_client();
}

fn run_pager_v1(scenario: Arc<PagerScenario>, vm_space: Arc<VmSpace>) {
    assert_current_task(scenario.kind.pager_v1_task_id(), &vm_space);
    while !scenario.fault_is_registered() {
        Task::yield_now();
    }
    vm_space.activate();

    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);
    match user_mode.execute(|| false) {
        ReturnReason::UserSyscall => assert_eq!(user_mode.context().rax(), PAGER_PREPARE_ZERO),
        other => panic!("pager v1 should request prepare before {other:?}"),
    }
    scenario.prepare_zero(1);

    vm_space.activate();
    let info = match user_mode.execute(|| false) {
        ReturnReason::UserException => match user_mode.context_mut().take_exception() {
            Some(CpuException::PageFault(info)) => info,
            other => panic!("pager v1 received unexpected exception: {other:?}"),
        },
        other => panic!("pager v1 should crash with a page fault, got {other:?}"),
    };
    assert_eq!(info.addr, FAULT_ADDR);
    let new_binding_epoch = scenario.crash_v1(1);
    assert_eq!(new_binding_epoch, 2);
    scenario.reject_stale_reply(1, "post_crash", false);
    println!(
        "PAGER_V1 EXIT scenario={} task={} reason=page_fault",
        scenario.kind.label(),
        scenario.kind.pager_v1_task_id(),
    );
}

fn run_watchdog(
    scenario: Arc<PagerScenario>,
    old_pager_task: Arc<Task>,
    old_pager_vm: Arc<VmSpace>,
) {
    assert_current_kernel_task(scenario.kind.watchdog_task_id());
    while !scenario.has_crashed() {
        Task::yield_now();
    }
    let binding_epoch = scenario.assert_crashed();
    println!(
        "PAGER Fallback scenario={} binding_epoch={} action=close_reply_gate+retain+watchdog",
        scenario.kind.label(),
        binding_epoch,
    );

    match scenario.kind {
        ScenarioKind::Recover => {
            let pager_v2_vm = Arc::new(create_vm_space(PAGER_V2_PROGRAM));
            assert!(!Arc::ptr_eq(&old_pager_vm, &pager_v2_vm));
            let pager_v2_state = scenario.clone();
            let pager_v2_task_vm = pager_v2_vm.clone();
            let pager_v2_task = Arc::new(
                TaskOptions::new(move || run_pager_v2(pager_v2_state, pager_v2_task_vm))
                    .data(TaskData::new(RECOVER_PAGER_V2_TASK_ID, Some(pager_v2_vm)))
                    .build()
                    .expect("build fresh pager v2 task"),
            );
            assert!(!Arc::ptr_eq(&old_pager_task, &pager_v2_task));
            println!(
                "PAGER FreshSpawn scenario=recover task={} vm=fresh user_mode=constructed_in_task binding_epoch={}",
                RECOVER_PAGER_V2_TASK_ID, binding_epoch,
            );
            pager_v2_task.run();
        }
        ScenarioKind::Timeout => scenario.watchdog_abort(),
    }
}

fn run_pager_v2(scenario: Arc<PagerScenario>, vm_space: Arc<VmSpace>) {
    assert_current_task(RECOVER_PAGER_V2_TASK_ID, &vm_space);
    vm_space.activate();

    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);
    loop {
        vm_space.activate();
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => match user_mode.context().rax() {
                PAGER_RECOVERY_SNAPSHOT => scenario.recovery_snapshot(RECOVER_PAGER_V2_TASK_ID, 2),
                PAGER_READY => {
                    scenario.ready(RECOVER_PAGER_V2_TASK_ID, 2);
                    scenario.reject_pre_rebind_reply(2);
                }
                PAGER_REBIND => {
                    scenario.rebind(RECOVER_PAGER_V2_TASK_ID, 2);
                    scenario.reject_stale_reply(1, "post_rebind", true);
                }
                PAGER_RECOVER_NEXT => scenario.recover_next(RECOVER_PAGER_V2_TASK_ID, 2),
                PAGER_ADOPT => scenario.adopt(RECOVER_PAGER_V2_TASK_ID, 2),
                PAGER_COMMIT => {
                    scenario.commit(RECOVER_PAGER_V2_TASK_ID, 2, &vm_space);
                    println!(
                        "PAGER_V2 EXIT scenario=recover task={} reason=commit_complete",
                        RECOVER_PAGER_V2_TASK_ID,
                    );
                    return;
                }
                syscall => panic!("unknown pager v2 portal syscall {syscall:#x}"),
            },
            ReturnReason::UserException => {
                panic!(
                    "fresh pager v2 unexpectedly faulted: {:?}",
                    user_mode.context_mut().take_exception()
                )
            }
            ReturnReason::KernelEvent => panic!("pager v2 has no synthetic kernel event"),
        }
    }
}

fn assert_current_task(expected_id: u64, vm_space: &Arc<VmSpace>) {
    let current = Task::current().expect("user-mode probe runs in an OSTD task");
    let data = current
        .data()
        .downcast_ref::<TaskData>()
        .expect("pager task carries Nexus TaskData");
    assert_eq!(data.id, expected_id);
    assert!(
        data.vm_space
            .as_ref()
            .is_some_and(|vm| Arc::ptr_eq(vm, vm_space))
    );
}

fn assert_current_kernel_task(expected_id: u64) {
    let current = Task::current().expect("watchdog runs in an OSTD task");
    let data = current
        .data()
        .downcast_ref::<TaskData>()
        .expect("watchdog task carries Nexus TaskData");
    assert_eq!(data.id, expected_id);
    assert!(data.vm_space.is_none());
}
