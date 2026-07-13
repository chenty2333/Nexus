// SPDX-License-Identifier: MPL-2.0

//! Bounded Stage 6B.1 private-futex recovery micro-slice.
//!
//! This is deliberately independent from the Stage 6A `linux` module.  It
//! observes one private key, one waiter, one waker and one CPU in each of two
//! serial scenarios.  The state below is an implementation receipt, not a
//! unified syscall/futex registry or a general Linux futex implementation.

use alloc::sync::Arc;

use cser_transition_gates::deadline::{
    DeadlineError, DeadlineGate, DeadlineProjection, DeadlineToken,
};
use linux_raw_sys::general::__NR_futex;
use ostd::{
    arch::cpu::context::{CpuException, UserContext},
    mm::{CachePolicy, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty, Vaddr, VmSpace},
    prelude::*,
    sync::SpinLock,
    task::{Task, TaskOptions, disable_preempt},
    timer::Jiffies,
    user::{ReturnReason, UserMode},
};

use crate::{
    TaskData, USER_MAP_ADDR, create_vm_space,
    effect::{EffectToken, EffectWaiter, EffectWaker},
    scheduler::{Binding, CserScheduler, FIRST_FALLBACK_SELECTION_ATTEMPT, ProposalResult},
};

const AUTHORITY_EPOCH: u64 = 101;
const HARNESS_AUTHORITY_EPOCH: u64 = 1;
const FUTEX_ADDR: Vaddr = 0x0040_1000;
const WAKER_ENTRY: Vaddr = USER_MAP_ADDR + 0x200;
const EXPECTED_FAULT_ADDR: Vaddr = 0x0080_0000;
const ADDRESS_SPACE_GENERATION: u64 = 1;

const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;
const WAIT_OPERATION: u64 = 1;
const WAKE_OPERATION: u64 = 2;
const EAGAIN: isize = 11;

const GUEST_DONE: usize = 0x4c60_00f0;
const PORTAL_RECV_WAIT: usize = 0x4c60_0001;
const WAIT_REGISTER: usize = 0x4c60_0002;
const PORTAL_RECV_WAKE: usize = 0x4c60_0003;
const RECOVERY_SNAPSHOT: usize = 0x4c60_0010;
const READY: usize = 0x4c60_0011;
const REBIND: usize = 0x4c60_0012;
const RECOVER_NEXT: usize = 0x4c60_0013;
const ADOPT: usize = 0x4c60_0014;
const ENABLE_WAKER: usize = 0x4c60_0015;
const WAKE_COMMIT: usize = 0x4c60_0020;
const PERSONALITY_DONE: usize = 0x4c60_0021;
const UNKNOWN_PORTAL: usize = 0x4c60_00fe;
const POLICY_PROPOSE_WAITER: usize = 0x4c70_0001;

const GUEST_PROGRAM: &[u8] = include_bytes!("../../guest/linux-futex-shared.bin");
const PERSONALITY_V1_PROGRAM: &[u8] = include_bytes!("../../guest/linux-futex-personality-v1.bin");
const PERSONALITY_V2_PROGRAM: &[u8] = include_bytes!("../../guest/linux-futex-personality-v2.bin");
const SCHEDULER_POLICY_PROGRAM: &[u8] = include_bytes!("../../guest/linux-scheduler-policy.bin");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScenarioKind {
    Recover,
    Expire,
}

impl ScenarioKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Recover => "recover",
            Self::Expire => "expire",
        }
    }

    const fn mode(self) -> usize {
        match self {
            Self::Recover => 0,
            Self::Expire => 1,
        }
    }

    const fn scope_id(self) -> u64 {
        match self {
            Self::Recover => 40,
            Self::Expire => 41,
        }
    }

    const fn address_space_id(self) -> u64 {
        match self {
            Self::Recover => 600,
            Self::Expire => 601,
        }
    }

    const fn harness_scope_id(self) -> u64 {
        match self {
            Self::Recover => 140,
            Self::Expire => 141,
        }
    }

    const fn waiter_task_id(self) -> u64 {
        match self {
            Self::Recover => 500,
            Self::Expire => 510,
        }
    }

    const fn waker_task_id(self) -> u64 {
        match self {
            Self::Recover => 501,
            Self::Expire => 511,
        }
    }

    const fn personality_v1_task_id(self) -> u64 {
        match self {
            Self::Recover => 502,
            Self::Expire => 512,
        }
    }

    const fn watchdog_task_id(self) -> u64 {
        match self {
            Self::Recover => 503,
            Self::Expire => 513,
        }
    }

    const fn personality_entry(self) -> Vaddr {
        match self {
            Self::Recover => USER_MAP_ADDR,
            Self::Expire => USER_MAP_ADDR + 0x200,
        }
    }
}

const RECOVER_PERSONALITY_V2_TASK_ID: u64 = 504;
const RECOVER_POLICY_TASK_ID: u64 = 505;

#[repr(usize)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PortalResult {
    Applied = 0,
    StaleBinding = 2,
    StaleAuthority = 3,
    IdentityMismatch = 4,
    InvalidState = 5,
    NoSupervisor = 6,
    AlreadyTerminal = 7,
    NotAdoptable = 8,
    ScopeClosed = 9,
    NotQuiescent = 10,
    UnknownOperation = 11,
}

impl PortalResult {
    const fn code(self) -> usize {
        self as usize
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Applied => "Applied",
            Self::StaleBinding => "StaleBinding",
            Self::StaleAuthority => "StaleAuthority",
            Self::IdentityMismatch => "IdentityMismatch",
            Self::InvalidState => "InvalidState",
            Self::NoSupervisor => "NoSupervisor",
            Self::AlreadyTerminal => "AlreadyTerminal",
            Self::NotAdoptable => "NotAdoptable",
            Self::ScopeClosed => "ScopeClosed",
            Self::NotQuiescent => "NotQuiescent",
            Self::UnknownOperation => "UnknownOperation",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FutexToken {
    authority_epoch: u64,
    scope_id: u64,
    effect_id: u64,
    task_id: u64,
    operation: u64,
    address_space_id: u64,
    address_space_generation: u64,
    address: u64,
    binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SyscallSnapshot {
    number: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScopePhase {
    Active,
    Closing,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EffectPhase {
    Captured,
    WaitQueued,
    WaitClaimed,
    WakeCommitted,
    Completed,
    Aborted,
}

impl EffectPhase {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Delivery {
    Pending,
    WaitWoken,
    WakeReturned(u32),
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectRecord {
    token: FutexToken,
    syscall: SyscallSnapshot,
    phase: EffectPhase,
    delivery: Delivery,
    terminalizations: u8,
    publications: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveryImage {
    wait: Option<EffectRecord>,
    wake: Option<EffectRecord>,
    queue_wait: Option<u64>,
    frozen_wait: Option<u64>,
    frozen_count: Option<u32>,
    watchdog: DeadlineProjection,
    watchdog_cohort: usize,
    wait_free: u64,
    wait_held: u64,
    wake_free: u64,
    wake_held: u64,
    timer_free: u64,
    timer_held: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Projection {
    scope_phase: ScopePhase,
    authority_epoch: u64,
    binding_epoch: u64,
    supervisor: Option<u64>,
    fallback_running: bool,
    snapshot_taken: bool,
    replacement_ready: bool,
    recovery_revision: u64,
    wait_token: Option<FutexToken>,
    wake_token: Option<FutexToken>,
    wait_phase: Option<EffectPhase>,
    wake_phase: Option<EffectPhase>,
    queue_wait: Option<u64>,
    frozen_wait: Option<u64>,
    frozen_count: Option<u32>,
    wait_free: u64,
    wait_held: u64,
    wake_free: u64,
    wake_held: u64,
    timer_free: u64,
    timer_held: u64,
    watchdog: bool,
    watchdog_cohort: usize,
    wait_waker: bool,
    wake_waker: bool,
    enable_waker: bool,
    publication_pending: bool,
    live_effects: usize,
    blocked_tasks: usize,
    terminalizations: u64,
    wake_publications: u64,
    abort_publications: u64,
    scope_closed: bool,
}

struct FutexState {
    scope_phase: ScopePhase,
    authority_epoch: u64,
    binding_epoch: u64,
    supervisor: Option<u64>,
    fallback_running: bool,
    snapshot_taken: bool,
    snapshot_revision: Option<u64>,
    snapshot_image: Option<RecoveryImage>,
    replacement_ready: bool,
    recovery_revision: u64,
    wait: Option<EffectRecord>,
    wake: Option<EffectRecord>,
    queue_wait: Option<u64>,
    frozen_wait: Option<u64>,
    frozen_count: Option<u32>,
    wait_waker: Option<EffectWaker>,
    wake_waker: Option<EffectWaker>,
    enable_waker: Option<EffectWaker>,
    completion_waker: Option<EffectWaker>,
    waker_enabled: bool,
    watchdog: DeadlineGate,
    watchdog_cohort: usize,
    wait_free: u64,
    wait_held: u64,
    wake_free: u64,
    wake_held: u64,
    timer_free: u64,
    timer_held: u64,
    publication_pending: bool,
    terminalizations: u64,
    wake_publications: u64,
    abort_publications: u64,
    closure_target: usize,
    closure_steps: usize,
    waiter_finished: bool,
    waker_finished: bool,
    personality_finished: bool,
}

impl FutexState {
    fn recovery_image(&self) -> RecoveryImage {
        RecoveryImage {
            wait: self.wait,
            wake: self.wake,
            queue_wait: self.queue_wait,
            frozen_wait: self.frozen_wait,
            frozen_count: self.frozen_count,
            watchdog: self.watchdog.projection(),
            watchdog_cohort: self.watchdog_cohort,
            wait_free: self.wait_free,
            wait_held: self.wait_held,
            wake_free: self.wake_free,
            wake_held: self.wake_held,
            timer_free: self.timer_free,
            timer_held: self.timer_held,
        }
    }

    fn projection(&self) -> Projection {
        let records = [self.wait, self.wake];
        Projection {
            scope_phase: self.scope_phase,
            authority_epoch: self.authority_epoch,
            binding_epoch: self.binding_epoch,
            supervisor: self.supervisor,
            fallback_running: self.fallback_running,
            snapshot_taken: self.snapshot_taken,
            replacement_ready: self.replacement_ready,
            recovery_revision: self.recovery_revision,
            wait_token: self.wait.map(|record| record.token),
            wake_token: self.wake.map(|record| record.token),
            wait_phase: self.wait.map(|record| record.phase),
            wake_phase: self.wake.map(|record| record.phase),
            queue_wait: self.queue_wait,
            frozen_wait: self.frozen_wait,
            frozen_count: self.frozen_count,
            wait_free: self.wait_free,
            wait_held: self.wait_held,
            wake_free: self.wake_free,
            wake_held: self.wake_held,
            timer_free: self.timer_free,
            timer_held: self.timer_held,
            watchdog: self.watchdog.current().is_some(),
            watchdog_cohort: self.watchdog_cohort,
            wait_waker: self.wait_waker.is_some(),
            wake_waker: self.wake_waker.is_some(),
            enable_waker: self.enable_waker.is_some(),
            publication_pending: self.publication_pending,
            live_effects: records
                .iter()
                .flatten()
                .filter(|record| !record.phase.is_terminal())
                .count(),
            blocked_tasks: usize::from(self.wait_waker.is_some())
                + usize::from(self.wake_waker.is_some()),
            terminalizations: self.terminalizations,
            wake_publications: self.wake_publications,
            abort_publications: self.abort_publications,
            scope_closed: self.scope_phase != ScopePhase::Active,
        }
    }

    fn assert_credit_conservation(&self) {
        assert_eq!(self.wait_free + self.wait_held, 1);
        assert_eq!(self.wake_free + self.wake_held, 1);
        assert_eq!(self.timer_free + self.timer_held, 1);
    }
}

struct FutexScenario {
    kind: ScenarioKind,
    guest_vm: Arc<VmSpace>,
    state: SpinLock<FutexState>,
}

impl FutexScenario {
    fn new(kind: ScenarioKind, guest_vm: Arc<VmSpace>, completion_waker: EffectWaker) -> Self {
        Self {
            kind,
            guest_vm,
            state: SpinLock::new(FutexState {
                scope_phase: ScopePhase::Active,
                authority_epoch: AUTHORITY_EPOCH,
                binding_epoch: 1,
                supervisor: Some(kind.personality_v1_task_id()),
                fallback_running: false,
                snapshot_taken: false,
                snapshot_revision: None,
                snapshot_image: None,
                replacement_ready: false,
                recovery_revision: 0,
                wait: None,
                wake: None,
                queue_wait: None,
                frozen_wait: None,
                frozen_count: None,
                wait_waker: None,
                wake_waker: None,
                enable_waker: None,
                completion_waker: Some(completion_waker),
                waker_enabled: false,
                watchdog: DeadlineGate::new(kind.scope_id())
                    .expect("futex watchdog owner is nonzero"),
                watchdog_cohort: 0,
                wait_free: 1,
                wait_held: 0,
                wake_free: 1,
                wake_held: 0,
                timer_free: 1,
                timer_held: 0,
                publication_pending: false,
                terminalizations: 0,
                wake_publications: 0,
                abort_publications: 0,
                closure_target: 0,
                closure_steps: 0,
                waiter_finished: false,
                waker_finished: false,
                personality_finished: false,
            }),
        }
    }

    fn effect_token(&self, effect_id: u64) -> EffectToken {
        EffectToken {
            authority_epoch: AUTHORITY_EPOCH,
            scope_id: self.kind.scope_id(),
            effect_id,
        }
    }

    fn harness_effect_token(&self, effect_id: u64) -> EffectToken {
        EffectToken {
            authority_epoch: HARNESS_AUTHORITY_EPOCH,
            scope_id: self.kind.harness_scope_id(),
            effect_id,
        }
    }

    fn token(&self, effect_id: u64, task_id: u64, operation: u64, binding: u64) -> FutexToken {
        FutexToken {
            authority_epoch: AUTHORITY_EPOCH,
            scope_id: self.kind.scope_id(),
            effect_id,
            task_id,
            operation,
            address_space_id: self.kind.address_space_id(),
            address_space_generation: ADDRESS_SPACE_GENERATION,
            address: FUTEX_ADDR as u64,
            binding_epoch: binding,
        }
    }

    fn projection(&self) -> Projection {
        self.state.lock().projection()
    }

    fn direct_wait_mismatch(&self) -> isize {
        let before = self.projection();
        let preempt_guard = disable_preempt();
        self.guest_vm.activate();
        let observed = self
            .guest_vm
            .reader(FUTEX_ADDR, core::mem::size_of::<u32>())
            .and_then(|reader| reader.atomic_load::<u32>())
            .expect("atomically read mapped private futex word");
        drop(preempt_guard);
        assert_eq!(observed, 0);
        let after = self.projection();
        assert_eq!(before, after, "EAGAIN must not create an effect");
        println!(
            "LINUX_FUTEX Mismatch scenario={} observed={} expected=1 result=EAGAIN effect_created=false wait_credit_held=false mutation=false",
            self.kind.label(),
            observed,
        );
        -EAGAIN
    }

    fn capture_wait(&self, context: &UserContext, waker: EffectWaker) {
        let syscall = syscall_snapshot(context);
        assert_futex_syscall(syscall, FUTEX_WAIT_PRIVATE, 0);
        let token = self.token(1, self.kind.waiter_task_id(), WAIT_OPERATION, 1);
        assert_eq!(waker.token(), self.effect_token(1));
        let mut state = self.state.lock();
        assert_eq!(state.scope_phase, ScopePhase::Active);
        assert_eq!(state.supervisor, Some(self.kind.personality_v1_task_id()));
        assert!(state.wait.is_none());
        assert!(state.wait_waker.is_none());
        state.wait = Some(EffectRecord {
            token,
            syscall,
            phase: EffectPhase::Captured,
            delivery: Delivery::Pending,
            terminalizations: 0,
            publications: 0,
        });
        state.wait_waker = Some(waker);
        state.recovery_revision += 1;
        state.assert_credit_conservation();
        drop(state);
        println!(
            "LINUX_FUTEX Capture scenario={} kind=WAIT authority_epoch={} scope={} effect=1 task={} operation={} asid={} generation={} address={:#x} binding_epoch=1 syscall={} expected=0",
            self.kind.label(),
            AUTHORITY_EPOCH,
            self.kind.scope_id(),
            self.kind.waiter_task_id(),
            WAIT_OPERATION,
            self.kind.address_space_id(),
            ADDRESS_SPACE_GENERATION,
            FUTEX_ADDR,
            __NR_futex,
        );
    }

    fn register_enable_waker(&self, waker: EffectWaker) {
        assert_eq!(waker.token(), self.harness_effect_token(90));
        let mut state = self.state.lock();
        assert!(state.enable_waker.is_none());
        assert!(!state.waker_enabled);
        state.enable_waker = Some(waker);
    }

    fn wait_is_captured(&self) -> bool {
        self.state.lock().wait.is_some()
    }

    fn wake_is_captured(&self) -> bool {
        self.state.lock().wake.is_some()
    }

    fn has_crashed(&self) -> bool {
        let state = self.state.lock();
        state.binding_epoch == 2 && state.supervisor.is_none() && state.fallback_running
    }

    fn deliver_wait(&self, sender: u64) -> Result<(SyscallSnapshot, FutexToken), PortalResult> {
        let state = self.state.lock();
        let before = state.projection();
        let result = if state.scope_phase != ScopePhase::Active {
            Err(PortalResult::ScopeClosed)
        } else if state.supervisor != Some(sender) {
            Err(PortalResult::NoSupervisor)
        } else {
            state
                .wait
                .map(|record| (record.syscall, record.token))
                .ok_or(PortalResult::InvalidState)
        };
        let after = state.projection();
        drop(state);
        self.log_control(
            "RecvWait",
            sender,
            PORTAL_RECV_WAIT,
            result.is_ok(),
            before,
            after,
        );
        result
    }

    fn wait_register(
        &self,
        sender: u64,
        packet: FutexToken,
        linuxd_vm: &Arc<VmSpace>,
    ) -> PortalResult {
        let preempt_guard = disable_preempt();
        let mut state = self.state.lock();
        let before = state.projection();
        let result = (|| {
            validate_current_gate(&state, self.kind, sender, packet)?;
            let record = state.wait.ok_or(PortalResult::InvalidState)?;
            if record.token != packet {
                return Err(PortalResult::IdentityMismatch);
            }
            if record.phase != EffectPhase::Captured || state.queue_wait.is_some() {
                return Err(PortalResult::InvalidState);
            }
            if state.wait_free != 1 || state.wait_held != 0 {
                return Err(PortalResult::InvalidState);
            }

            self.guest_vm.activate();
            let observed = self
                .guest_vm
                .reader(FUTEX_ADDR, core::mem::size_of::<u32>())
                .and_then(|reader| reader.atomic_load::<u32>());
            linuxd_vm.activate();
            let observed = observed.map_err(|_| PortalResult::InvalidState)?;
            if observed != 0 || record.syscall.arg2 != 0 {
                return Err(PortalResult::InvalidState);
            }

            state.wait.as_mut().expect("validated wait remains").phase = EffectPhase::WaitQueued;
            state.queue_wait = Some(record.token.effect_id);
            state.wait_free = 0;
            state.wait_held = 1;
            state.recovery_revision += 1;
            Ok(())
        })()
        .map_or_else(|error| error, |()| PortalResult::Applied);
        state.assert_credit_conservation();
        let after = state.projection();
        drop(state);
        drop(preempt_guard);
        self.assert_and_log_portal(
            "WaitRegister",
            sender,
            WAIT_REGISTER,
            packet,
            result,
            before,
            after,
        );
        if result == PortalResult::Applied {
            println!(
                "LINUX_FUTEX WaitRegister scenario={} observed=0 expected=0 atomic=true queue=1 wait_credit=Held vm_restored=true",
                self.kind.label(),
            );
        }
        result
    }

    fn crash_v1(&self, info_addr: Vaddr) {
        assert_eq!(info_addr, EXPECTED_FAULT_ADDR);
        let mut state = self.state.lock();
        assert_eq!(state.scope_phase, ScopePhase::Active);
        assert_eq!(state.binding_epoch, 1);
        assert_eq!(state.supervisor, Some(self.kind.personality_v1_task_id()));
        assert_eq!(
            state.wait.expect("wait registered").phase,
            EffectPhase::WaitQueued
        );
        if self.kind == ScenarioKind::Expire {
            assert_eq!(
                state.wake.expect("expire wake captured before crash").phase,
                EffectPhase::Captured
            );
        }
        assert_eq!((state.timer_free, state.timer_held), (1, 0));
        let cohort = usize::from(state.wait.is_some()) + usize::from(state.wake.is_some());
        let armed_deadline = Jiffies::elapsed().as_u64().saturating_add(1);
        let old_watchdog = state
            .watchdog
            .arm(armed_deadline)
            .expect("fresh futex watchdog must arm");
        let deadline = armed_deadline.saturating_add(1);
        let watchdog = state
            .watchdog
            .rearm(old_watchdog, deadline)
            .expect("futex recovery must rearm with a fresh generation");
        let before_stale_probe = state.watchdog;
        assert_eq!(
            state.watchdog.expire(old_watchdog, u64::MAX),
            Err(DeadlineError::StaleToken)
        );
        assert_eq!(state.watchdog, before_stale_probe);
        assert_eq!(state.watchdog.current(), Some(watchdog));
        state.binding_epoch = 2;
        state.supervisor = None;
        state.fallback_running = true;
        state.replacement_ready = false;
        state.snapshot_taken = false;
        state.snapshot_revision = None;
        state.snapshot_image = None;
        state.watchdog_cohort = cohort;
        state.timer_free = 0;
        state.timer_held = 1;
        state.recovery_revision += 1;
        state.personality_finished = self.kind == ScenarioKind::Expire;
        state.assert_credit_conservation();
        drop(state);
        println!(
            "LINUX_FUTEX Crash scenario={} personality={} previous_binding_epoch=1 binding_epoch=2 reason=real_user_page_fault fallback=kernel watchdog=armed cohort={}",
            self.kind.label(),
            self.kind.personality_v1_task_id(),
            cohort,
        );
        println!(
            "LINUX_FUTEX WatchdogGate scenario={} action=arm+rearm owner={} old_generation={} generation={} deadline={} stale_old=StaleToken mutation=false",
            self.kind.label(),
            watchdog.owner(),
            old_watchdog.generation(),
            watchdog.generation(),
            watchdog.deadline(),
        );
    }

    fn recovery_snapshot(&self, sender: u64) -> PortalResult {
        let mut state = self.state.lock();
        let before = state.projection();
        let result = if self.kind != ScenarioKind::Recover
            || sender != RECOVER_PERSONALITY_V2_TASK_ID
            || state.scope_phase != ScopePhase::Active
            || state.binding_epoch != 2
            || state.supervisor.is_some()
            || !state.fallback_running
            || state.wait.is_none()
        {
            PortalResult::InvalidState
        } else {
            state.snapshot_taken = true;
            state.snapshot_revision = Some(state.recovery_revision);
            state.snapshot_image = Some(state.recovery_image());
            PortalResult::Applied
        };
        let after = state.projection();
        drop(state);
        self.log_control(
            "Snapshot",
            sender,
            RECOVERY_SNAPSHOT,
            result == PortalResult::Applied,
            before,
            after,
        );
        result
    }

    fn snapshot_wait(&self) -> (SyscallSnapshot, FutexToken) {
        let state = self.state.lock();
        assert!(state.snapshot_taken);
        assert_eq!(state.snapshot_revision, Some(state.recovery_revision));
        assert_eq!(state.snapshot_image, Some(state.recovery_image()));
        let wait = state.wait.expect("snapshot contains the orphan wait");
        (wait.syscall, wait.token)
    }

    fn ready(&self, sender: u64) -> PortalResult {
        let mut state = self.state.lock();
        let before = state.projection();
        let result = if self.kind != ScenarioKind::Recover
            || sender != RECOVER_PERSONALITY_V2_TASK_ID
            || !state.fallback_running
            || state.supervisor.is_some()
            || !state.snapshot_taken
            || state.snapshot_revision != Some(state.recovery_revision)
            || state.snapshot_image != Some(state.recovery_image())
        {
            PortalResult::InvalidState
        } else {
            state.replacement_ready = true;
            PortalResult::Applied
        };
        let after = state.projection();
        drop(state);
        self.log_control(
            "Ready",
            sender,
            READY,
            result == PortalResult::Applied,
            before,
            after,
        );
        result
    }

    fn rebind(&self, sender: u64) -> PortalResult {
        let mut state = self.state.lock();
        let before = state.projection();
        let result = if self.kind != ScenarioKind::Recover
            || sender != RECOVER_PERSONALITY_V2_TASK_ID
            || !state.replacement_ready
            || state.supervisor.is_some()
            || state.snapshot_revision != Some(state.recovery_revision)
            || state.snapshot_image != Some(state.recovery_image())
        {
            PortalResult::InvalidState
        } else {
            state.supervisor = Some(sender);
            state.fallback_running = false;
            state.replacement_ready = false;
            PortalResult::Applied
        };
        let after = state.projection();
        drop(state);
        self.log_control(
            "Rebind",
            sender,
            REBIND,
            result == PortalResult::Applied,
            before,
            after,
        );
        result
    }

    fn recover_next(&self, sender: u64) -> Result<(SyscallSnapshot, FutexToken), PortalResult> {
        let state = self.state.lock();
        let before = state.projection();
        let result = if self.kind != ScenarioKind::Recover
            || state.scope_phase != ScopePhase::Active
            || state.supervisor != Some(sender)
            || state.binding_epoch != 2
        {
            Err(PortalResult::InvalidState)
        } else {
            state
                .wait
                .map(|record| (record.syscall, record.token))
                .ok_or(PortalResult::InvalidState)
        };
        let after = state.projection();
        drop(state);
        self.log_control(
            "RecoverNext",
            sender,
            RECOVER_NEXT,
            result.is_ok(),
            before,
            after,
        );
        result
    }

    fn adopt(&self, sender: u64, packet: FutexToken) -> (PortalResult, Option<FutexToken>) {
        let mut state = self.state.lock();
        let before = state.projection();
        let result = (|| {
            if packet.authority_epoch != state.authority_epoch {
                return Err(PortalResult::StaleAuthority);
            }
            if packet.scope_id != self.kind.scope_id() {
                return Err(PortalResult::IdentityMismatch);
            }
            if state.scope_phase != ScopePhase::Active {
                return Err(PortalResult::ScopeClosed);
            }
            if state.supervisor != Some(sender) {
                return Err(PortalResult::NoSupervisor);
            }
            let record = state.wait.ok_or(PortalResult::IdentityMismatch)?;
            if record.token != packet {
                return Err(PortalResult::IdentityMismatch);
            }
            if packet.binding_epoch == state.binding_epoch || record.phase.is_terminal() {
                return Err(PortalResult::NotAdoptable);
            }
            if packet.binding_epoch > state.binding_epoch || record.phase != EffectPhase::WaitQueued
            {
                return Err(PortalResult::NotAdoptable);
            }
            let mut adopted = packet;
            adopted.binding_epoch = state.binding_epoch;
            assert_eq!(state.watchdog_cohort, 1);
            let watchdog = state.watchdog.current().expect("watchdog is armed");
            state
                .watchdog
                .cancel(watchdog)
                .expect("adoption cancels the current watchdog generation");
            state.watchdog_cohort = 0;
            state.wait.as_mut().expect("validated wait remains").token = adopted;
            state.timer_free = 1;
            state.timer_held = 0;
            state.recovery_revision += 1;
            Ok(adopted)
        })();
        state.assert_credit_conservation();
        let after = state.projection();
        let (portal, adopted) = match result {
            Ok(token) => (PortalResult::Applied, Some(token)),
            Err(error) => (error, None),
        };
        drop(state);
        self.assert_and_log_portal("Adopt", sender, ADOPT, packet, portal, before, after);
        if let Some(token) = adopted {
            println!(
                "LINUX_FUTEX WatchdogCancel scenario=recover effect={} binding_epoch={} timer_credit=Free queued_wait_retained=true",
                token.effect_id, token.binding_epoch,
            );
        }
        (portal, adopted)
    }

    fn enable_waker(&self, sender: u64) -> PortalResult {
        let (result, waker, before, middle) = {
            let mut state = self.state.lock();
            let before = state.projection();
            if state.scope_phase != ScopePhase::Active || state.supervisor != Some(sender) {
                (PortalResult::NoSupervisor, None, before, state.projection())
            } else if state.waker_enabled || state.enable_waker.is_none() {
                (PortalResult::InvalidState, None, before, state.projection())
            } else {
                state.waker_enabled = true;
                state.recovery_revision += 1;
                let waker = state.enable_waker.take();
                (PortalResult::Applied, waker, before, state.projection())
            }
        };
        if let Some(waker) = waker {
            assert!(waker.wake_up());
            drop(waker);
        }
        let after = self.projection();
        assert_eq!(middle, after);
        self.log_control(
            "EnableWaker",
            sender,
            ENABLE_WAKER,
            result == PortalResult::Applied,
            before,
            after,
        );
        result
    }

    fn capture_wake(&self, context: &UserContext, waker: EffectWaker) {
        let syscall = syscall_snapshot(context);
        assert_futex_syscall(syscall, FUTEX_WAKE_PRIVATE, 1);
        let mut state = self.state.lock();
        assert_eq!(state.scope_phase, ScopePhase::Active);
        assert!(state.waker_enabled);
        assert!(state.wake.is_none());
        assert!(state.wake_waker.is_none());
        assert_eq!((state.wake_free, state.wake_held), (1, 0));
        let binding = state.binding_epoch;
        let token = self.token(2, self.kind.waker_task_id(), WAKE_OPERATION, binding);
        assert_eq!(waker.token(), self.effect_token(2));
        state.wake = Some(EffectRecord {
            token,
            syscall,
            phase: EffectPhase::Captured,
            delivery: Delivery::Pending,
            terminalizations: 0,
            publications: 0,
        });
        state.wake_waker = Some(waker);
        state.wake_free = 0;
        state.wake_held = 1;
        state.recovery_revision += 1;
        state.assert_credit_conservation();
        drop(state);
        println!(
            "LINUX_FUTEX Capture scenario={} kind=WAKE authority_epoch={} scope={} effect=2 task={} operation={} asid={} generation={} address={:#x} binding_epoch={} wake_credit=Held max_wake=1",
            self.kind.label(),
            AUTHORITY_EPOCH,
            self.kind.scope_id(),
            self.kind.waker_task_id(),
            WAKE_OPERATION,
            self.kind.address_space_id(),
            ADDRESS_SPACE_GENERATION,
            FUTEX_ADDR,
            binding,
        );
    }

    fn deliver_wake(&self, sender: u64) -> Result<(SyscallSnapshot, FutexToken), PortalResult> {
        let state = self.state.lock();
        let before = state.projection();
        let result = if state.scope_phase != ScopePhase::Active {
            Err(PortalResult::ScopeClosed)
        } else if state.supervisor != Some(sender) {
            Err(PortalResult::NoSupervisor)
        } else {
            state
                .wake
                .map(|record| (record.syscall, record.token))
                .ok_or(PortalResult::InvalidState)
        };
        let after = state.projection();
        drop(state);
        self.log_control(
            "RecvWake",
            sender,
            PORTAL_RECV_WAKE,
            result.is_ok(),
            before,
            after,
        );
        result
    }

    fn wake_commit(&self, sender: u64, packet: FutexToken) -> (PortalResult, u32) {
        let mut state = self.state.lock();
        let before = state.projection();
        let result = (|| {
            validate_current_gate(&state, self.kind, sender, packet)?;
            let wake = state.wake.ok_or(PortalResult::IdentityMismatch)?;
            if wake.token != packet {
                return Err(PortalResult::IdentityMismatch);
            }
            if wake.phase != EffectPhase::Captured {
                return Err(if wake.phase.is_terminal() {
                    PortalResult::AlreadyTerminal
                } else {
                    PortalResult::InvalidState
                });
            }
            let wait_id = state.queue_wait.ok_or(PortalResult::InvalidState)?;
            let wait = state.wait.ok_or(PortalResult::InvalidState)?;
            if wait.phase != EffectPhase::WaitQueued || wait.token.effect_id != wait_id {
                return Err(PortalResult::InvalidState);
            }
            state.queue_wait = None;
            state.frozen_wait = Some(wait_id);
            state.frozen_count = Some(1);
            state.wait.as_mut().expect("validated wait remains").phase = EffectPhase::WaitClaimed;
            state.wake.as_mut().expect("validated wake remains").phase = EffectPhase::WakeCommitted;
            state.recovery_revision += 1;
            Ok(1)
        })();
        let (portal, count) = match result {
            Ok(count) => (PortalResult::Applied, count),
            Err(error) => (error, 0),
        };
        let after = state.projection();
        drop(state);
        self.assert_and_log_portal(
            "WakeCommit",
            sender,
            WAKE_COMMIT,
            packet,
            portal,
            before,
            after,
        );
        if portal == PortalResult::Applied {
            println!(
                "LINUX_FUTEX WakeCommit scenario={} selected_wait=1 frozen_count=1 queue_removed=true wake_credit=Held",
                self.kind.label(),
            );
        }
        (portal, count)
    }

    fn revoke_begin(&self, reason: &'static str) {
        let mut state = self.state.lock();
        assert_eq!(state.scope_phase, ScopePhase::Active);
        let old_epoch = state.authority_epoch;
        state.scope_phase = ScopePhase::Closing;
        state.authority_epoch += 1;
        state.supervisor = None;
        state.fallback_running = false;
        state.replacement_ready = false;
        state.closure_target = [state.wait, state.wake]
            .iter()
            .flatten()
            .filter(|record| !record.phase.is_terminal())
            .count();
        state.recovery_revision += 1;
        let target = state.closure_target;
        drop(state);
        println!(
            "LINUX_FUTEX RevokeBegin scenario={} reason={} closed_epoch={} authority_epoch={} target={} gate=closed",
            self.kind.label(),
            reason,
            old_epoch,
            old_epoch + 1,
            target,
        );
    }

    fn publish_committed_wake(&self) {
        let (wait_waker, wake_waker) = {
            let mut state = self.state.lock();
            assert_eq!(state.scope_phase, ScopePhase::Closing);
            assert_eq!(state.frozen_count, Some(1));
            assert_eq!(
                state.wait.expect("selected wait").phase,
                EffectPhase::WaitClaimed
            );
            assert_eq!(
                state.wake.expect("committed wake").phase,
                EffectPhase::WakeCommitted
            );
            assert!(!state.publication_pending);
            state.wait.as_mut().expect("wait remains").phase = EffectPhase::Completed;
            state.wait.as_mut().expect("wait remains").delivery = Delivery::WaitWoken;
            state.wait.as_mut().expect("wait remains").terminalizations = 1;
            state.wake.as_mut().expect("wake remains").phase = EffectPhase::Completed;
            state.wake.as_mut().expect("wake remains").delivery = Delivery::WakeReturned(1);
            state.wake.as_mut().expect("wake remains").terminalizations = 1;
            state.terminalizations = 2;
            state.closure_steps = 1;
            state.publication_pending = true;
            state.recovery_revision += 1;
            let wait_waker = state
                .wait_waker
                .take()
                .expect("wait continuation owns waker");
            let wake_waker = state
                .wake_waker
                .take()
                .expect("wake continuation owns waker");
            (wait_waker, wake_waker)
        };
        println!(
            "LINUX_FUTEX ClosurePublish scenario=recover phase=terminalize terminalizations=2 wakers_taken=2 credits_returned=false pending=true"
        );
        assert!(wait_waker.wake_up());
        assert!(wake_waker.wake_up());
        drop(wait_waker);
        drop(wake_waker);
        println!(
            "LINUX_FUTEX ClosurePublish scenario=recover phase=wake_outside_lock wait=true wake=true"
        );
        {
            let mut state = self.state.lock();
            assert!(state.publication_pending);
            state.wait.as_mut().expect("wait remains").publications = 1;
            state.wake.as_mut().expect("wake remains").publications = 1;
            state.wait_free = 1;
            state.wait_held = 0;
            state.wake_free = 1;
            state.wake_held = 0;
            state.wake_publications = 1;
            state.publication_pending = false;
            state.assert_credit_conservation();
        }
        println!(
            "LINUX_FUTEX ClosurePublish scenario=recover phase=account publication=1 credits=wait+wake:Free pending=false"
        );
    }

    fn abort_uncommitted(&self) {
        let (wait_waker, wake_waker) = {
            let mut state = self.state.lock();
            assert_eq!(state.scope_phase, ScopePhase::Closing);
            assert_eq!(
                state.wait.expect("queued wait").phase,
                EffectPhase::WaitQueued
            );
            assert_eq!(
                state.wake.expect("captured wake").phase,
                EffectPhase::Captured
            );
            assert_eq!(state.queue_wait, Some(1));
            assert!(!state.publication_pending);
            state.wait.as_mut().expect("wait remains").phase = EffectPhase::Aborted;
            state.wait.as_mut().expect("wait remains").delivery = Delivery::Aborted;
            state.wait.as_mut().expect("wait remains").terminalizations = 1;
            state.wake.as_mut().expect("wake remains").phase = EffectPhase::Aborted;
            state.wake.as_mut().expect("wake remains").delivery = Delivery::Aborted;
            state.wake.as_mut().expect("wake remains").terminalizations = 1;
            state.queue_wait = None;
            state.terminalizations = 2;
            state.closure_steps = 2;
            state.publication_pending = true;
            state.recovery_revision += 1;
            let wait_waker = state
                .wait_waker
                .take()
                .expect("wait continuation owns waker");
            let wake_waker = state
                .wake_waker
                .take()
                .expect("wake continuation owns waker");
            (wait_waker, wake_waker)
        };
        println!(
            "LINUX_FUTEX ClosureAbort scenario=expire phase=terminalize terminalizations=2 delivery=Aborted linux_errno=none wakers_taken=2 credits_returned=false pending=true"
        );
        assert!(wait_waker.wake_up());
        assert!(wake_waker.wake_up());
        drop(wait_waker);
        drop(wake_waker);
        println!(
            "LINUX_FUTEX ClosureAbort scenario=expire phase=wake_outside_lock wait=true wake=true resumed=false"
        );
        {
            let mut state = self.state.lock();
            assert!(state.publication_pending);
            state.wait_free = 1;
            state.wait_held = 0;
            state.wake_free = 1;
            state.wake_held = 0;
            state.timer_free = 1;
            state.timer_held = 0;
            assert!(state.watchdog.current().is_none());
            state.watchdog_cohort = 0;
            state.abort_publications = 2;
            state.publication_pending = false;
            state.assert_credit_conservation();
        }
        println!(
            "LINUX_FUTEX ClosureAbort scenario=expire phase=account abort_wakes=2 credits=wait+wake+timer:Free pending=false etimedout=false"
        );
    }

    fn revoke_complete(&self) -> PortalResult {
        let mut state = self.state.lock();
        let live = [state.wait, state.wake]
            .iter()
            .flatten()
            .filter(|record| !record.phase.is_terminal())
            .count();
        let quiescent = live == 0
            && state.queue_wait.is_none()
            && state.wait_waker.is_none()
            && state.wake_waker.is_none()
            && !state.publication_pending
            && state.watchdog.current().is_none()
            && state.watchdog_cohort == 0
            && (state.wait_free, state.wait_held) == (1, 0)
            && (state.wake_free, state.wake_held) == (1, 0)
            && (state.timer_free, state.timer_held) == (1, 0)
            && state.terminalizations == state.closure_target as u64;
        if !quiescent {
            return PortalResult::NotQuiescent;
        }
        assert_eq!(state.scope_phase, ScopePhase::Closing);
        state.scope_phase = ScopePhase::Revoked;
        drop(state);
        println!(
            "LINUX_FUTEX RevokeComplete scenario={} result=Applied queue=0 live=0 blocked=0 wakers=0 pending=false credits=wait+wake+timer:Free terminalizations=2",
            self.kind.label(),
        );
        PortalResult::Applied
    }

    fn watchdog_timer(&self) -> DeadlineToken {
        self.state
            .lock()
            .watchdog
            .current()
            .expect("watchdog is armed")
    }

    fn delivery(&self, waiter: bool) -> Delivery {
        let state = self.state.lock();
        if waiter {
            state.wait.expect("wait effect exists").delivery
        } else {
            state.wake.expect("wake effect exists").delivery
        }
    }

    fn finish_guest(&self, waiter: bool) {
        let completion = {
            let mut state = self.state.lock();
            if waiter {
                assert!(!state.waiter_finished);
                state.waiter_finished = true;
            } else {
                assert!(!state.waker_finished);
                state.waker_finished = true;
            }
            Self::take_completion_if_finished(&mut state)
        };
        wake_completion(completion);
    }

    fn finish_personality(&self) {
        let completion = {
            let mut state = self.state.lock();
            state.personality_finished = true;
            Self::take_completion_if_finished(&mut state)
        };
        wake_completion(completion);
    }

    fn take_completion_if_finished(state: &mut FutexState) -> Option<EffectWaker> {
        (state.scope_phase == ScopePhase::Revoked
            && state.waiter_finished
            && state.waker_finished
            && state.personality_finished)
            .then(|| state.completion_waker.take())
            .flatten()
    }

    fn assert_final(&self) {
        let state = self.state.lock();
        let wait = state.wait.expect("wait effect exists at closure");
        let wake = state.wake.expect("wake effect exists at closure");
        assert_eq!(state.scope_phase, ScopePhase::Revoked);
        assert_eq!(state.authority_epoch, AUTHORITY_EPOCH + 1);
        assert_eq!(state.terminalizations, 2);
        assert_eq!(wait.terminalizations, 1);
        assert_eq!(wake.terminalizations, 1);
        assert_eq!(state.closure_target, 2);
        assert!(state.waiter_finished && state.waker_finished && state.personality_finished);
        assert!(state.completion_waker.is_none());
        assert!(!state.publication_pending);
        assert!(state.queue_wait.is_none());
        assert!(state.wait_waker.is_none() && state.wake_waker.is_none());
        assert!(state.watchdog.current().is_none());
        assert_eq!(state.watchdog_cohort, 0);
        state.assert_credit_conservation();
        assert_eq!(
            (state.wait_free, state.wake_free, state.timer_free),
            (1, 1, 1)
        );
        match self.kind {
            ScenarioKind::Recover => {
                assert_eq!(state.wake_publications, 1);
                assert_eq!(state.abort_publications, 0);
                assert_eq!((wait.publications, wake.publications), (1, 1));
                assert_eq!(wait.delivery, Delivery::WaitWoken);
                assert_eq!(wake.delivery, Delivery::WakeReturned(1));
            }
            ScenarioKind::Expire => {
                assert_eq!(state.wake_publications, 0);
                assert_eq!(state.abort_publications, 2);
                assert_eq!((wait.publications, wake.publications), (0, 0));
                assert_eq!(wait.delivery, Delivery::Aborted);
                assert_eq!(wake.delivery, Delivery::Aborted);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_and_log_portal(
        &self,
        action: &'static str,
        sender: u64,
        opcode: usize,
        packet: FutexToken,
        result: PortalResult,
        before: Projection,
        after: Projection,
    ) {
        let mutation = before != after;
        if result != PortalResult::Applied {
            assert_eq!(before, after, "rejected portal transition must be atomic");
        }
        println!(
            "LINUX_FUTEX PortalResult scenario={} action={} sender={} opcode={:#x} authority_epoch={} scope={} effect={} task={} operation={} address_space={} generation={} address={:#x} binding_epoch={} result={} mutation={}",
            self.kind.label(),
            action,
            sender,
            opcode,
            packet.authority_epoch,
            packet.scope_id,
            packet.effect_id,
            packet.task_id,
            packet.operation,
            packet.address_space_id,
            packet.address_space_generation,
            packet.address,
            packet.binding_epoch,
            result.label(),
            mutation,
        );
        println!(
            "LINUX_FUTEX Projection scenario={} action={} result={} mutation={} scope_before={:?}:{}:{}:{:?} scope_after={:?}:{}:{}:{:?} recovery_before={}:{}:{} recovery_after={}:{}:{} wait_before={:?}:{:?} wait_after={:?}:{:?} wake_before={:?}:{:?} wake_after={:?}:{:?} queue_before={:?} queue_after={:?} frozen_before={:?}:{:?} frozen_after={:?}:{:?} credits_before={}:{}:{}:{}:{}:{} credits_after={}:{}:{}:{}:{}:{} watchdog_before={}:{} watchdog_after={}:{} wakers_before={}:{}:{} wakers_after={}:{}:{} pending_before={} pending_after={} live_before={} live_after={} blocked_before={} blocked_after={} terminal_before={} terminal_after={} publications_before={}:{} publications_after={}:{}",
            self.kind.label(),
            action,
            result.label(),
            mutation,
            before.scope_phase,
            before.authority_epoch,
            before.binding_epoch,
            before.supervisor,
            after.scope_phase,
            after.authority_epoch,
            after.binding_epoch,
            after.supervisor,
            before.fallback_running,
            before.snapshot_taken,
            before.replacement_ready,
            after.fallback_running,
            after.snapshot_taken,
            after.replacement_ready,
            before.wait_token,
            before.wait_phase,
            after.wait_token,
            after.wait_phase,
            before.wake_token,
            before.wake_phase,
            after.wake_token,
            after.wake_phase,
            before.queue_wait,
            after.queue_wait,
            before.frozen_wait,
            before.frozen_count,
            after.frozen_wait,
            after.frozen_count,
            before.wait_free,
            before.wait_held,
            before.wake_free,
            before.wake_held,
            before.timer_free,
            before.timer_held,
            after.wait_free,
            after.wait_held,
            after.wake_free,
            after.wake_held,
            after.timer_free,
            after.timer_held,
            before.watchdog,
            before.watchdog_cohort,
            after.watchdog,
            after.watchdog_cohort,
            before.wait_waker,
            before.wake_waker,
            before.enable_waker,
            after.wait_waker,
            after.wake_waker,
            after.enable_waker,
            before.publication_pending,
            after.publication_pending,
            before.live_effects,
            after.live_effects,
            before.blocked_tasks,
            after.blocked_tasks,
            before.terminalizations,
            after.terminalizations,
            before.wake_publications,
            before.abort_publications,
            after.wake_publications,
            after.abort_publications,
        );
    }

    fn log_control(
        &self,
        action: &'static str,
        sender: u64,
        opcode: usize,
        applied: bool,
        before: Projection,
        after: Projection,
    ) {
        let result = if applied {
            PortalResult::Applied
        } else {
            PortalResult::InvalidState
        };
        let packet = FutexToken {
            authority_epoch: after.authority_epoch,
            scope_id: self.kind.scope_id(),
            effect_id: 0,
            task_id: sender,
            operation: 0,
            address_space_id: self.kind.address_space_id(),
            address_space_generation: ADDRESS_SPACE_GENERATION,
            address: FUTEX_ADDR as u64,
            binding_epoch: after.binding_epoch,
        };
        self.assert_and_log_portal(action, sender, opcode, packet, result, before, after);
    }
}

impl FutexScenario {
    fn current_wake_token(&self) -> FutexToken {
        self.state
            .lock()
            .wake
            .expect("wake effect was captured")
            .token
    }

    fn reject_unknown(&self, sender: u64, opcode: usize, packet: FutexToken) -> PortalResult {
        let before = self.projection();
        let after = self.projection();
        self.assert_and_log_portal(
            "Unknown",
            sender,
            opcode,
            packet,
            PortalResult::UnknownOperation,
            before,
            after,
        );
        PortalResult::UnknownOperation
    }

    fn finish_recover_protocol(&self, sender: u64) {
        assert_eq!(self.kind, ScenarioKind::Recover);
        let old_wake = self.current_wake_token();
        {
            let state = self.state.lock();
            assert_eq!(state.wake.expect("wake").phase, EffectPhase::WakeCommitted);
            assert_eq!(state.frozen_count, Some(1));
        }
        self.revoke_begin("committed_wake_drain");
        let before = self.projection();
        let (replayed, count) = self.wake_commit(sender, old_wake);
        assert_eq!(replayed, PortalResult::StaleAuthority);
        assert_eq!(count, 0);
        assert_eq!(before, self.projection());
        self.publish_committed_wake();
        assert_eq!(self.revoke_complete(), PortalResult::Applied);
        self.finish_personality();
    }

    fn expire_watchdog_and_close(&self) {
        assert_eq!(self.kind, ScenarioKind::Expire);
        let timer = self.watchdog_timer();
        let observed_now = Jiffies::elapsed().as_u64();
        assert!(observed_now >= timer.deadline());
        {
            let mut state = self.state.lock();
            let receipt = state
                .watchdog
                .expire(timer, observed_now)
                .expect("current elapsed futex watchdog must expire");
            assert_eq!(receipt.token(), timer);
            assert_eq!(receipt.observed_now(), observed_now);
        }
        let old_wake = self.current_wake_token();
        println!(
            "LINUX_FUTEX WatchdogExpire scenario=expire deadline={} authority_epoch={} scope={} cohort=2 linux_timeout=false",
            timer.deadline(),
            AUTHORITY_EPOCH,
            self.kind.scope_id(),
        );
        self.revoke_begin("recovery_watchdog_expired");
        let before = self.projection();
        let (replayed, count) = self.wake_commit(self.kind.personality_v1_task_id(), old_wake);
        assert_eq!(replayed, PortalResult::StaleAuthority);
        assert_eq!(count, 0);
        assert_eq!(before, self.projection());
        self.abort_uncommitted();
        assert_eq!(self.revoke_complete(), PortalResult::Applied);
    }
}

fn validate_current_gate(
    state: &FutexState,
    kind: ScenarioKind,
    sender: u64,
    packet: FutexToken,
) -> Result<(), PortalResult> {
    if packet.authority_epoch != state.authority_epoch {
        return Err(PortalResult::StaleAuthority);
    }
    if packet.scope_id != kind.scope_id() {
        return Err(PortalResult::IdentityMismatch);
    }
    if state.scope_phase != ScopePhase::Active {
        return Err(PortalResult::ScopeClosed);
    }
    if packet.binding_epoch != state.binding_epoch {
        return Err(PortalResult::StaleBinding);
    }
    if state.supervisor != Some(sender) {
        return Err(PortalResult::NoSupervisor);
    }
    Ok(())
}

fn syscall_snapshot(context: &UserContext) -> SyscallSnapshot {
    SyscallSnapshot {
        number: context.rax(),
        arg0: context.rdi(),
        arg1: context.rsi(),
        arg2: context.rdx(),
    }
}

fn assert_futex_syscall(snapshot: SyscallSnapshot, operation: usize, value: usize) {
    assert_eq!(snapshot.number, __NR_futex as usize);
    assert_eq!(snapshot.arg0, FUTEX_ADDR);
    assert_eq!(snapshot.arg1, operation);
    assert_eq!(snapshot.arg2, value);
}

fn install_snapshot(context: &mut UserContext, snapshot: SyscallSnapshot, token: FutexToken) {
    context.set_rax(snapshot.number);
    context.set_rdi(snapshot.arg0);
    context.set_rsi(snapshot.arg1);
    context.set_rdx(snapshot.arg2);
    install_token(context, token);
}

fn install_token(context: &mut UserContext, token: FutexToken) {
    context.set_r10(token.authority_epoch as usize);
    context.set_r12(token.scope_id as usize);
    context.set_r8(token.effect_id as usize);
    context.set_r13(token.task_id as usize);
    context.set_r14(token.operation as usize);
    context.set_r15(token.address as usize);
    context.set_rbx(token.address_space_id as usize);
    context.set_rbp(token.address_space_generation as usize);
    context.set_r9(token.binding_epoch as usize);
}

fn portal_packet(context: &UserContext) -> FutexToken {
    FutexToken {
        authority_epoch: context.r10() as u64,
        scope_id: context.r12() as u64,
        effect_id: context.r8() as u64,
        task_id: context.r13() as u64,
        operation: context.r14() as u64,
        address_space_id: context.rbx() as u64,
        address_space_generation: context.rbp() as u64,
        address: context.r15() as u64,
        binding_epoch: context.r9() as u64,
    }
}

fn wake_completion(waker: Option<EffectWaker>) {
    if let Some(waker) = waker {
        assert!(waker.wake_up());
        drop(waker);
    }
}

fn create_shared_guest_vm() -> Arc<VmSpace> {
    assert!(GUEST_PROGRAM.len() <= PAGE_SIZE);
    let vm_space = Arc::new(create_vm_space(GUEST_PROGRAM));
    let data = FrameAllocOptions::new()
        .zeroed(true)
        .alloc_segment(1)
        .expect("allocate shared futex word page");
    let guard = disable_preempt();
    let mut cursor = vm_space
        .cursor_mut(&guard, &(FUTEX_ADDR..FUTEX_ADDR + PAGE_SIZE))
        .expect("create shared futex word mapping cursor");
    cursor.map(
        data.into_iter()
            .next()
            .expect("one shared data frame")
            .into(),
        PageProperty::new_user(PageFlags::RW, CachePolicy::Writeback),
    );
    drop(cursor);
    drop(guard);
    vm_space
}

fn run_guest_waiter(scenario: Arc<FutexScenario>, vm_space: Arc<VmSpace>) {
    assert_current_user_task(scenario.kind.waiter_task_id(), &vm_space);
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    context.set_r15(scenario.kind.mode());
    let mut user_mode = UserMode::new(context);

    match user_mode.execute(|| false) {
        ReturnReason::UserSyscall => {
            let mismatch = syscall_snapshot(user_mode.context());
            assert_futex_syscall(mismatch, FUTEX_WAIT_PRIVATE, 1);
            assert_eq!(user_mode.context().r10(), 0);
        }
        other => panic!("futex waiter mismatch should be a syscall, got {other:?}"),
    }
    user_mode
        .context_mut()
        .set_rax(scenario.direct_wait_mismatch() as usize);

    vm_space.activate();
    match user_mode.execute(|| false) {
        ReturnReason::UserSyscall => {
            let wait = syscall_snapshot(user_mode.context());
            assert_futex_syscall(wait, FUTEX_WAIT_PRIVATE, 0);
            assert_eq!(user_mode.context().r10(), 0);
        }
        other => panic!("futex waiter registration should be a syscall, got {other:?}"),
    }
    let (waiter, waker) = EffectWaiter::new_pair(scenario.effect_token(1));
    scenario.capture_wait(user_mode.context(), waker);
    println!(
        "LINUX_FUTEX GuestBlock scenario={} role=waiter task={} effect=1 continuation=EffectWaiter rip={:#x}",
        scenario.kind.label(),
        scenario.kind.waiter_task_id(),
        user_mode.context().rip(),
    );
    waiter.wait();
    drop(waiter);

    match scenario.delivery(true) {
        Delivery::WaitWoken => {
            assert_eq!(scenario.kind, ScenarioKind::Recover);
            user_mode.context_mut().set_rax(0);
            vm_space.activate();
            match user_mode.execute(|| false) {
                ReturnReason::UserSyscall => {
                    assert_eq!(user_mode.context().rax(), GUEST_DONE);
                    assert_eq!(user_mode.context().rdi(), 0);
                    assert_eq!(user_mode.context().rsi(), scenario.kind.mode());
                    assert_eq!(user_mode.context().rdx(), 0);
                }
                other => panic!("recovered futex waiter did not report DONE: {other:?}"),
            }
            println!(
                "LINUX_FUTEX GuestResume scenario=recover role=waiter task={} linux_result=0 done=true resumes=1",
                scenario.kind.waiter_task_id(),
            );
        }
        Delivery::Aborted => {
            assert_eq!(scenario.kind, ScenarioKind::Expire);
            println!(
                "LINUX_FUTEX GuestAbortExit scenario=expire role=waiter task={} delivery=Aborted resumed=false linux_errno_written=false ecanceled=false etimedout=false",
                scenario.kind.waiter_task_id(),
            );
        }
        other => panic!("futex waiter woke with unexpected delivery {other:?}"),
    }
    scenario.finish_guest(true);
}

fn run_guest_waker(scenario: Arc<FutexScenario>, vm_space: Arc<VmSpace>) {
    assert_current_user_task(scenario.kind.waker_task_id(), &vm_space);
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(WAKER_ENTRY);
    context.set_r15(scenario.kind.mode());
    let mut user_mode = UserMode::new(context);

    let (enable_waiter, enable_waker) = EffectWaiter::new_pair(scenario.harness_effect_token(90));
    scenario.register_enable_waker(enable_waker);
    println!(
        "LINUX_FUTEX GuestBlock scenario={} role=waker task={} gate=EnableWaker continuation=EffectWaiter",
        scenario.kind.label(),
        scenario.kind.waker_task_id(),
    );
    enable_waiter.wait();
    drop(enable_waiter);

    vm_space.activate();
    match user_mode.execute(|| false) {
        ReturnReason::UserSyscall => {
            let wake = syscall_snapshot(user_mode.context());
            assert_futex_syscall(wake, FUTEX_WAKE_PRIVATE, 1);
            assert_eq!(user_mode.context().r10(), 0);
        }
        other => panic!("futex waker should issue WAKE_PRIVATE, got {other:?}"),
    }
    let (wake_waiter, wake_waker) = EffectWaiter::new_pair(scenario.effect_token(2));
    scenario.capture_wake(user_mode.context(), wake_waker);
    println!(
        "LINUX_FUTEX GuestBlock scenario={} role=waker task={} effect=2 continuation=EffectWaiter rip={:#x}",
        scenario.kind.label(),
        scenario.kind.waker_task_id(),
        user_mode.context().rip(),
    );
    wake_waiter.wait();
    drop(wake_waiter);

    match scenario.delivery(false) {
        Delivery::WakeReturned(1) => {
            assert_eq!(scenario.kind, ScenarioKind::Recover);
            user_mode.context_mut().set_rax(1);
            vm_space.activate();
            match user_mode.execute(|| false) {
                ReturnReason::UserSyscall => {
                    assert_eq!(user_mode.context().rax(), GUEST_DONE);
                    assert_eq!(user_mode.context().rdi(), 1);
                    assert_eq!(user_mode.context().rsi(), scenario.kind.mode());
                    assert_eq!(user_mode.context().rdx(), 0);
                }
                other => panic!("recovered futex waker did not report DONE: {other:?}"),
            }
            println!(
                "LINUX_FUTEX GuestResume scenario=recover role=waker task={} linux_result=1 done=true resumes=1",
                scenario.kind.waker_task_id(),
            );
        }
        Delivery::Aborted => {
            assert_eq!(scenario.kind, ScenarioKind::Expire);
            println!(
                "LINUX_FUTEX GuestAbortExit scenario=expire role=waker task={} delivery=Aborted resumed=false linux_errno_written=false ecanceled=false etimedout=false",
                scenario.kind.waker_task_id(),
            );
        }
        other => panic!("futex waker woke with unexpected delivery {other:?}"),
    }
    scenario.finish_guest(false);
}

fn run_personality_v1(scenario: Arc<FutexScenario>, vm_space: Arc<VmSpace>) {
    assert_current_user_task(scenario.kind.personality_v1_task_id(), &vm_space);
    while !scenario.wait_is_captured() {
        Task::yield_now();
    }
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(scenario.kind.personality_entry());
    let mut user_mode = UserMode::new(context);

    loop {
        vm_space.activate();
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => {
                let opcode = user_mode.context().rax();
                match opcode {
                    PORTAL_RECV_WAIT => {
                        match scenario.deliver_wait(scenario.kind.personality_v1_task_id()) {
                            Ok((snapshot, token)) => {
                                install_snapshot(user_mode.context_mut(), snapshot, token)
                            }
                            Err(error) => user_mode.context_mut().set_rax(error.code()),
                        }
                    }
                    WAIT_REGISTER => {
                        let packet = portal_packet(user_mode.context());
                        let result = scenario.wait_register(
                            scenario.kind.personality_v1_task_id(),
                            packet,
                            &vm_space,
                        );
                        user_mode.context_mut().set_rax(result.code());
                    }
                    PORTAL_RECV_WAKE if scenario.kind == ScenarioKind::Expire => {
                        if !scenario.state.lock().waker_enabled {
                            assert_eq!(
                                scenario.enable_waker(scenario.kind.personality_v1_task_id()),
                                PortalResult::Applied
                            );
                        }
                        while !scenario.wake_is_captured() {
                            Task::yield_now();
                        }
                        match scenario.deliver_wake(scenario.kind.personality_v1_task_id()) {
                            Ok((snapshot, token)) => {
                                install_snapshot(user_mode.context_mut(), snapshot, token)
                            }
                            Err(error) => user_mode.context_mut().set_rax(error.code()),
                        }
                    }
                    UNKNOWN_PORTAL => {
                        let failure = user_mode.context().rdi();
                        let packet = portal_packet(user_mode.context());
                        let _ = scenario.reject_unknown(
                            scenario.kind.personality_v1_task_id(),
                            opcode,
                            packet,
                        );
                        panic!(
                            "futex personality v1 reported protocol failure scenario={} code={failure}",
                            scenario.kind.label()
                        );
                    }
                    _ => {
                        let packet = portal_packet(user_mode.context());
                        let result = scenario.reject_unknown(
                            scenario.kind.personality_v1_task_id(),
                            opcode,
                            packet,
                        );
                        user_mode.context_mut().set_rax(result.code());
                    }
                }
            }
            ReturnReason::UserException => {
                let info = match user_mode.context_mut().take_exception() {
                    Some(CpuException::PageFault(info)) => info,
                    other => panic!("futex personality v1 unexpected exception {other:?}"),
                };
                assert_eq!(info.addr, EXPECTED_FAULT_ADDR);
                assert_eq!(info.error_code.bits() & 1, 0);
                assert_ne!(info.error_code.bits() & (1 << 2), 0);
                if scenario.kind == ScenarioKind::Expire {
                    assert!(scenario.wake_is_captured());
                }
                scenario.crash_v1(info.addr);
                println!(
                    "LINUX_FUTEX_PERSONALITY_V1 EXIT scenario={} task={} reason=real_user_page_fault",
                    scenario.kind.label(),
                    scenario.kind.personality_v1_task_id(),
                );
                return;
            }
            ReturnReason::KernelEvent => {
                panic!("futex personality v1 has no synthetic kernel event")
            }
        }
    }
}

fn run_personality_v2(scenario: Arc<FutexScenario>, vm_space: Arc<VmSpace>) {
    assert_eq!(scenario.kind, ScenarioKind::Recover);
    assert_current_user_task(RECOVER_PERSONALITY_V2_TASK_ID, &vm_space);
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);

    loop {
        vm_space.activate();
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => {
                let opcode = user_mode.context().rax();
                match opcode {
                    RECOVERY_SNAPSHOT => {
                        let result = scenario.recovery_snapshot(RECOVER_PERSONALITY_V2_TASK_ID);
                        if result == PortalResult::Applied {
                            let (snapshot, token) = scenario.snapshot_wait();
                            install_snapshot(user_mode.context_mut(), snapshot, token);
                        } else {
                            user_mode.context_mut().set_rax(result.code());
                        }
                    }
                    READY => {
                        let result = scenario.ready(RECOVER_PERSONALITY_V2_TASK_ID);
                        user_mode.context_mut().set_rax(result.code());
                    }
                    WAIT_REGISTER => {
                        let packet = portal_packet(user_mode.context());
                        let result = scenario.wait_register(
                            RECOVER_PERSONALITY_V2_TASK_ID,
                            packet,
                            &vm_space,
                        );
                        user_mode.context_mut().set_rax(result.code());
                    }
                    REBIND => {
                        let result = scenario.rebind(RECOVER_PERSONALITY_V2_TASK_ID);
                        user_mode.context_mut().set_rax(result.code());
                    }
                    RECOVER_NEXT => match scenario.recover_next(RECOVER_PERSONALITY_V2_TASK_ID) {
                        Ok((snapshot, token)) => {
                            install_snapshot(user_mode.context_mut(), snapshot, token)
                        }
                        Err(error) => user_mode.context_mut().set_rax(error.code()),
                    },
                    ADOPT => {
                        let packet = portal_packet(user_mode.context());
                        let (result, adopted) =
                            scenario.adopt(RECOVER_PERSONALITY_V2_TASK_ID, packet);
                        if let Some(token) = adopted {
                            install_token(user_mode.context_mut(), token);
                        }
                        user_mode.context_mut().set_rax(result.code());
                    }
                    ENABLE_WAKER => {
                        let result = scenario.enable_waker(RECOVER_PERSONALITY_V2_TASK_ID);
                        user_mode.context_mut().set_rax(result.code());
                    }
                    PORTAL_RECV_WAKE => {
                        while !scenario.wake_is_captured() {
                            Task::yield_now();
                        }
                        match scenario.deliver_wake(RECOVER_PERSONALITY_V2_TASK_ID) {
                            Ok((snapshot, token)) => {
                                install_snapshot(user_mode.context_mut(), snapshot, token)
                            }
                            Err(error) => user_mode.context_mut().set_rax(error.code()),
                        }
                    }
                    WAKE_COMMIT => {
                        let packet = portal_packet(user_mode.context());
                        let (result, frozen_count) =
                            scenario.wake_commit(RECOVER_PERSONALITY_V2_TASK_ID, packet);
                        user_mode.context_mut().set_rax(result.code());
                        user_mode.context_mut().set_rdi(frozen_count as usize);
                    }
                    PERSONALITY_DONE => {
                        scenario.finish_recover_protocol(RECOVER_PERSONALITY_V2_TASK_ID);
                        println!(
                            "LINUX_FUTEX_PERSONALITY_V2 EXIT scenario=recover task={} reason=protocol_complete",
                            RECOVER_PERSONALITY_V2_TASK_ID,
                        );
                        return;
                    }
                    UNKNOWN_PORTAL => {
                        let failure = user_mode.context().rdi();
                        let packet = portal_packet(user_mode.context());
                        let _ =
                            scenario.reject_unknown(RECOVER_PERSONALITY_V2_TASK_ID, opcode, packet);
                        panic!("futex personality v2 reported protocol failure code={failure}");
                    }
                    _ => {
                        let packet = portal_packet(user_mode.context());
                        let result =
                            scenario.reject_unknown(RECOVER_PERSONALITY_V2_TASK_ID, opcode, packet);
                        user_mode.context_mut().set_rax(result.code());
                    }
                }
            }
            ReturnReason::UserException => panic!(
                "fresh futex personality v2 unexpectedly faulted: {:?}",
                user_mode.context_mut().take_exception()
            ),
            ReturnReason::KernelEvent => {
                panic!("fresh futex personality v2 has no synthetic kernel event")
            }
        }
    }
}

fn run_scheduler_policy(
    scheduler: &'static CserScheduler,
    binding: Binding,
    scenario: Arc<FutexScenario>,
    vm_space: Arc<VmSpace>,
) {
    assert_current_user_task(RECOVER_POLICY_TASK_ID, &vm_space);
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);

    match user_mode.execute(|| false) {
        ReturnReason::UserSyscall => {
            assert_eq!(user_mode.context().rax(), POLICY_PROPOSE_WAITER)
        }
        other => panic!("futex scheduler policy should propose the waiter, got {other:?}"),
    }
    let causal_token = scenario.effect_token(1);
    println!(
        "LINUX_FUTEX_SCHEDULER Register scenario=recover policy={} workload_authority_epoch={} scope={} effect={} scheduler_binding_epoch={}",
        RECOVER_POLICY_TASK_ID,
        causal_token.authority_epoch,
        causal_token.scope_id,
        causal_token.effect_id,
        binding.binding_epoch,
    );
    assert_eq!(
        scheduler.propose_scoped(
            binding,
            ScenarioKind::Recover.waiter_task_id(),
            causal_token
        ),
        ProposalResult::Prepared
    );

    vm_space.activate();
    let info = match user_mode.execute(|| false) {
        ReturnReason::UserException => match user_mode.context_mut().take_exception() {
            Some(CpuException::PageFault(info)) => info,
            other => panic!("futex scheduler policy unexpected exception {other:?}"),
        },
        other => panic!("futex scheduler policy should crash with page fault, got {other:?}"),
    };
    assert_eq!(info.addr, EXPECTED_FAULT_ADDR);
    assert_eq!(info.error_code.bits() & 1, 0);
    assert_ne!(info.error_code.bits() & (1 << 2), 0);
    scheduler.crash_scoped(
        binding,
        "linux_futex_scheduler_policy_user_page_fault",
        causal_token,
    );
    println!(
        "LINUX_FUTEX_SCHEDULER_POLICY EXIT scenario=recover policy={} reason=real_user_page_fault waiter_proposal_committed=false",
        RECOVER_POLICY_TASK_ID,
    );
}

fn run_watchdog(
    scenario: Arc<FutexScenario>,
    old_personality_task: Arc<Task>,
    old_personality_vm: Arc<VmSpace>,
) {
    assert_current_kernel_task(scenario.kind.watchdog_task_id());
    while !scenario.has_crashed() {
        Task::yield_now();
    }
    println!(
        "LINUX_FUTEX Fallback scenario={} binding_epoch=2 action=close_portal_gate+retain_queue+watchdog",
        scenario.kind.label(),
    );

    match scenario.kind {
        ScenarioKind::Recover => {
            let v2_vm = Arc::new(create_vm_space(PERSONALITY_V2_PROGRAM));
            assert!(!Arc::ptr_eq(&old_personality_vm, &v2_vm));
            let v2_state = scenario.clone();
            let v2_task_vm = v2_vm.clone();
            let v2_task = Arc::new(
                TaskOptions::new(move || run_personality_v2(v2_state, v2_task_vm))
                    .data(TaskData::new(
                        RECOVER_PERSONALITY_V2_TASK_ID,
                        Some(v2_vm.clone()),
                    ))
                    .build()
                    .expect("build fresh futex personality v2 task"),
            );
            assert!(!Arc::ptr_eq(&old_personality_task, &v2_task));
            println!(
                "LINUX_FUTEX FreshSpawn scenario=recover task={} vm=fresh user_mode=constructed_in_task binding_epoch=2",
                RECOVER_PERSONALITY_V2_TASK_ID,
            );
            v2_task.run();
        }
        ScenarioKind::Expire => {
            let timer = scenario.watchdog_timer();
            while Jiffies::elapsed().as_u64() < timer.deadline() {
                Task::yield_now();
            }
            scenario.expire_watchdog_and_close();
        }
    }
}

fn run_scenario(
    kind: ScenarioKind,
    scheduler: &'static CserScheduler,
    scheduler_binding: Option<Binding>,
) {
    let completion_token = EffectToken {
        authority_epoch: HARNESS_AUTHORITY_EPOCH,
        scope_id: kind.harness_scope_id(),
        effect_id: 99,
    };
    let (done_waiter, done_waker) = EffectWaiter::new_pair(completion_token);
    let guest_vm = create_shared_guest_vm();
    let scenario = Arc::new(FutexScenario::new(kind, guest_vm.clone(), done_waker));

    let waiter_state = scenario.clone();
    let waiter_vm = guest_vm.clone();
    let waiter_task = Arc::new(
        TaskOptions::new(move || run_guest_waiter(waiter_state, waiter_vm))
            .data(TaskData::new(kind.waiter_task_id(), Some(guest_vm.clone())))
            .build()
            .expect("build futex waiter task"),
    );

    let waker_state = scenario.clone();
    let waker_vm = guest_vm.clone();
    let waker_task = Arc::new(
        TaskOptions::new(move || run_guest_waker(waker_state, waker_vm))
            .data(TaskData::new(kind.waker_task_id(), Some(guest_vm.clone())))
            .build()
            .expect("build futex waker task"),
    );

    let v1_vm = Arc::new(create_vm_space(PERSONALITY_V1_PROGRAM));
    let v1_state = scenario.clone();
    let v1_task_vm = v1_vm.clone();
    let v1_task = Arc::new(
        TaskOptions::new(move || run_personality_v1(v1_state, v1_task_vm))
            .data(TaskData::new(
                kind.personality_v1_task_id(),
                Some(v1_vm.clone()),
            ))
            .build()
            .expect("build futex personality v1 task"),
    );

    let watchdog_state = scenario.clone();
    let old_personality_task = v1_task.clone();
    let old_personality_vm = v1_vm;
    let watchdog_task = Arc::new(
        TaskOptions::new(move || {
            run_watchdog(watchdog_state, old_personality_task, old_personality_vm)
        })
        .data(TaskData::new(kind.watchdog_task_id(), None))
        .build()
        .expect("build futex recovery watchdog task"),
    );

    let policy_task = scheduler_binding.map(|binding| {
        let policy_vm = Arc::new(create_vm_space(SCHEDULER_POLICY_PROGRAM));
        let policy_task_vm = policy_vm.clone();
        let policy_state = scenario.clone();
        Arc::new(
            TaskOptions::new(move || {
                run_scheduler_policy(scheduler, binding, policy_state, policy_task_vm)
            })
            .data(TaskData::new(
                RECOVER_POLICY_TASK_ID,
                Some(policy_vm.clone()),
            ))
            .build()
            .expect("build futex scheduler policy task"),
        )
    });

    println!(
        "LINUX_FUTEX_SCENARIO BEGIN scenario={} authority_epoch={} scope={} asid={} generation={} address={:#x} waiter={} waker={} shared_vm=true smp=1 scheduler_mode={}",
        kind.label(),
        AUTHORITY_EPOCH,
        kind.scope_id(),
        kind.address_space_id(),
        ADDRESS_SPACE_GENERATION,
        FUTEX_ADDR,
        kind.waiter_task_id(),
        kind.waker_task_id(),
        if scheduler_binding.is_some() {
            "user_policy_then_kernel_fifo_fallback"
        } else {
            "existing_kernel_fifo_fallback"
        },
    );
    waiter_task.run();
    waker_task.run();
    v1_task.run();
    watchdog_task.run();
    if let (Some(binding), Some(policy_task)) = (scheduler_binding, policy_task) {
        policy_task.run();
        assert_eq!(
            scheduler.propose(binding, RECOVER_POLICY_TASK_ID),
            ProposalResult::Prepared
        );
    }

    done_waiter.wait();
    drop(done_waiter);
    scenario.assert_final();
    println!(
        "LINUX_FUTEX_SCENARIO PASS scenario={} terminalizations=2 wait_credit=Free wake_credit=Free timer_credit=Free queue=0 live=0 blocked=0 wakers=0 smp=1",
        kind.label(),
    );
}

pub fn run_linux_futex_slice(scheduler: &'static CserScheduler, scheduler_binding: Binding) {
    println!(
        "LINUX_FUTEX_SLICE BEGIN scenarios=recover+expire scheduler_binding_epoch={} bounded=true unified_registry=false smp=1",
        scheduler_binding.binding_epoch,
    );
    run_scenario(ScenarioKind::Recover, scheduler, Some(scheduler_binding));
    let fallback = scheduler
        .fallback_evidence()
        .expect("futex scheduler policy crash records fallback evidence");
    assert_eq!(
        fallback.pick_task_id,
        ScenarioKind::Recover.waiter_task_id()
    );
    assert_eq!(
        fallback.pick_selection_attempt,
        FIRST_FALLBACK_SELECTION_ATTEMPT
    );
    assert!(fallback.pick_tick >= fallback.crash_tick);
    println!(
        "LINUX_FUTEX_SCHEDULER PASS scenario=recover policy={} fallback_first_task={} fallback_first_selection_attempt={} observed_tick_delta={} tick_delta_diagnostic=true",
        RECOVER_POLICY_TASK_ID,
        fallback.pick_task_id,
        fallback.pick_selection_attempt,
        fallback.pick_tick - fallback.crash_tick,
    );

    run_scenario(ScenarioKind::Expire, scheduler, None);
    println!(
        "LINUX_FUTEX_SLICE PASS scenarios=recover+expire mismatch_eagain=true crash_rebind=true watchdog_expire=true committed_drain=true uncommitted_abort=true linux_timeout=false unified_registry=false smp=1"
    );
}

fn assert_current_user_task(expected_id: u64, vm_space: &Arc<VmSpace>) {
    let current = Task::current().expect("futex UserMode runner owns an OSTD task");
    let data = current
        .data()
        .downcast_ref::<TaskData>()
        .expect("futex task carries Nexus TaskData");
    assert_eq!(data.id, expected_id);
    assert!(
        data.vm_space
            .as_ref()
            .is_some_and(|current_vm| Arc::ptr_eq(current_vm, vm_space))
    );
}

fn assert_current_kernel_task(expected_id: u64) {
    let current = Task::current().expect("futex watchdog owns an OSTD task");
    let data = current
        .data()
        .downcast_ref::<TaskData>()
        .expect("futex watchdog carries Nexus TaskData");
    assert_eq!(data.id, expected_id);
    assert!(data.vm_space.is_none());
}
