// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec, vec::Vec};
use core::{fmt, str};

use linux_raw_sys::{
    auxvec::{
        AT_ENTRY, AT_EXECFN, AT_NULL, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM, AT_PLATFORM,
        AT_RANDOM,
    },
    general::{__NR_exit_group, __NR_write},
};
use object::{Architecture, BinaryFormat, Endianness, Object, ObjectKind, ObjectSegment};
use object::{
    elf,
    read::elf::{ElfFile64, FileHeader, ProgramHeader},
};
use ostd::{
    arch::cpu::context::{CpuException, UserContext},
    mm::{
        CachePolicy, FallibleVmRead, FrameAllocOptions, MAX_USERSPACE_VADDR, PAGE_SIZE, PageFlags,
        PageProperty, Vaddr, VmIo, VmSpace, VmWriter,
    },
    prelude::*,
    sync::SpinLock,
    task::{Task, TaskOptions, disable_preempt},
    user::{ReturnReason, UserMode},
};

use crate::{
    TaskData, USER_MAP_ADDR, create_vm_space,
    effect::{EffectToken, EffectWaiter, EffectWaker},
    linux_pager::LinuxCodePager,
    scheduler::{Binding, CserScheduler, FIRST_FALLBACK_SELECTION_ATTEMPT, ProposalResult},
};

const AUTHORITY_EPOCH: u64 = 91;
const SCOPE_ID: u64 = 30;
const WRITE_EFFECT_ID: u64 = 1;
const EXIT_EFFECT_ID: u64 = 2;
const CODE_FAULT_EFFECT_ID: u64 = 3;
const SLICE_COMPLETION_EFFECT_ID: u64 = 4;
const REVOKE_PRECOMMIT_EFFECT_ID: u64 = 5;
const REVOKE_COMMITTED_EFFECT_ID: u64 = 6;
const PERSONALITY_V2_TASK_EXIT_EFFECT_ID: u64 = 7;
const GUEST_TASK_ID: u64 = 400;
const PERSONALITY_V1_TASK_ID: u64 = 401;
const WATCHDOG_TASK_ID: u64 = 402;
const PERSONALITY_V2_TASK_ID: u64 = 403;
const SCHEDULER_POLICY_TASK_ID: u64 = 404;
const REVOKE_PROBE_TASK_ID: u64 = 405;
const REVOKE_COMMITTED_PROBE_TASK_ID: u64 = 406;
const REVOKE_PRECOMMIT_SCOPE_ID: u64 = SCOPE_ID + 1;
const REVOKE_COMMITTED_SCOPE_ID: u64 = SCOPE_ID + 2;
const EXPECTED_FAULT_ADDR: Vaddr = 0x0080_0000;
const STACK_TOP: Vaddr = 0x0000_7fff_ffff_f000;
const EXPECTED_STDOUT: &[u8] = b"hello from linux-hello\n";
const EXECUTABLE_NAME: &[u8] = b"/linux-hello\0";
const PLATFORM_NAME: &[u8] = b"x86_64\0";
const TEST_RANDOM: [u8; 16] = *b"NexusStage6ASeed";

const PORTAL_RECV: usize = 0x4c50_0000;
const PREPARE_WRITE: usize = 0x4c50_0001;
const QUEUE_STALE_WRITE: usize = 0x4c50_0002;
const RECOVERY_SNAPSHOT: usize = 0x4c51_0001;
const READY: usize = 0x4c51_0002;
const REBIND: usize = 0x4c51_0003;
const RECOVER_NEXT: usize = 0x4c51_0004;
const ADOPT: usize = 0x4c51_0005;
const PORTAL_RECV_NEXT: usize = 0x4c51_0007;
const COMMIT_EXIT: usize = 0x4c51_0008;
const PREPARE_EXIT: usize = 0x4c51_0009;
const PERSONALITY_DONE: usize = 0x4c51_000a;
const BACKEND_COMMIT: usize = 0x4c52_0001;
const REPLY_WRITE: usize = 0x4c52_0002;
const REVOKE_PROBE_SETUP: usize = 0x4c53_0001;
const REVOKE_PROBE_BACKEND_COMMIT: usize = 0x4c53_0002;
const REVOKE_PROBE_BEGIN: usize = 0x4c53_0003;
const REVOKE_PROBE_REPLY: usize = 0x4c53_0004;
const REVOKE_PROBE_CLOSURE_NEXT: usize = 0x4c53_0005;
const REVOKE_PROBE_COMPLETE: usize = 0x4c53_0006;
const REVOKE_PROBE_PREPARE: usize = 0x4c53_0007;
const UNKNOWN_SYSCALL: usize = 0x4c5f_0001;
const POLICY_PROPOSE_GUEST: usize = 0x4c70_0001;

const LINUX_HELLO_ELF: &[u8] = include_bytes!("../../guest/linux-hello.elf");
const PERSONALITY_V1_PROGRAM: &[u8] = include_bytes!("../../guest/linux-personality-v1.bin");
const PERSONALITY_V2_PROGRAM: &[u8] = include_bytes!("../../guest/linux-personality-v2.bin");
const SCHEDULER_POLICY_PROGRAM: &[u8] = include_bytes!("../../guest/linux-scheduler-policy.bin");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContinuationPhase {
    Captured,
    ReplyPrepared,
    BackendCommitted,
    Completed,
    Aborted,
}

#[repr(usize)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PortalResult {
    Applied = 0,
    AlreadyCommitted = 1,
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
    QueueFull = 12,
}

impl PortalResult {
    const fn portal_code(self) -> usize {
        self as usize
    }

    const fn backend_label(self) -> &'static str {
        match self {
            Self::Applied => "Committed",
            Self::AlreadyCommitted => "AlreadyCommitted",
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
            Self::QueueFull => "QueueFull",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Applied => "Applied",
            Self::AlreadyCommitted => "AlreadyCommitted",
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
            Self::QueueFull => "QueueFull",
        }
    }
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyscallKind {
    Write = 1,
    ExitGroup = 2,
}

impl SyscallKind {
    const fn tag(self) -> u64 {
        self as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SyscallToken {
    authority_epoch: u64,
    scope_id: u64,
    effect_id: u64,
    task_id: u64,
    operation: u64,
    binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TokenProjection(Option<SyscallToken>);

impl fmt::Display for TokenProjection {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(token) => write!(
                output,
                "{}:{}:{}:{}:{}:{}",
                token.authority_epoch,
                token.scope_id,
                token.effect_id,
                token.task_id,
                token.operation,
                token.binding_epoch,
            ),
            None => output.write_str("none"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SyscallRecord {
    token: SyscallToken,
    number: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    phase: ContinuationPhase,
    backend_commits: u8,
    reply_publications: u8,
    resumes: u8,
    exits: u8,
    aborts: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersonalityScopePhase {
    Active,
    Closing,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuestOutcome {
    Running,
    Exited(i32),
}

struct PersonalityState {
    scope_id: u64,
    scope_phase: PersonalityScopePhase,
    authority_epoch: u64,
    binding_epoch: u64,
    supervisor: Option<u64>,
    fallback_running: bool,
    snapshot_taken: bool,
    replacement_ready: bool,
    write: Option<SyscallRecord>,
    exit: Option<SyscallRecord>,
    prepared_output: Option<Vec<u8>>,
    queued_stale_write: Option<SyscallToken>,
    write_waker: Option<EffectWaker>,
    exit_waker: Option<EffectWaker>,
    completion_waker: Option<EffectWaker>,
    guest_outcome: GuestOutcome,
    terminalizations: u64,
    output_publications: u64,
    stale_rejections: u64,
    no_supervisor_rejections: u64,
    guest_finished: bool,
    closure_target: usize,
    closure_steps: usize,
    closure_waker_takes: usize,
    closure_wake_publications: usize,
}

struct PersonalityScenario {
    guest_vm: Arc<VmSpace>,
    scope_id: u64,
    write_effect_id: u64,
    guest_task_id: u64,
    emit_stdout: bool,
    state: SpinLock<PersonalityState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SemanticProjection {
    scope_phase: PersonalityScopePhase,
    authority_epoch: u64,
    binding_epoch: u64,
    supervisor: Option<u64>,
    fallback_running: bool,
    snapshot_taken: bool,
    replacement_ready: bool,
    write_token: TokenProjection,
    exit_token: TokenProjection,
    write_phase: Option<ContinuationPhase>,
    exit_phase: Option<ContinuationPhase>,
    backend_commits: u64,
    reply_publications: u64,
    resumes: u64,
    exits: u64,
    aborts: u64,
    terminalizations: u64,
    output_publications: u64,
    prepared_output: bool,
    prepared_output_len: usize,
    prepared_output_checksum: u64,
    queued_stale_write: bool,
    write_waker: bool,
    exit_waker: bool,
    completion_waker: bool,
    wakers: usize,
    live_effects: usize,
    guest_outcome: GuestOutcome,
    guest_finished: bool,
    closure_target: usize,
    closure_steps: usize,
    closure_waker_takes: usize,
    closure_wake_publications: usize,
}

impl PersonalityScenario {
    fn semantic_projection(&self) -> SemanticProjection {
        let state = self.state.lock();
        let records = [state.write, state.exit];
        let prepared_output_len = state.prepared_output.as_ref().map_or(0, Vec::len);
        let prepared_output_checksum = state.prepared_output.as_ref().map_or(0, |bytes| {
            bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
                (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
            })
        });
        SemanticProjection {
            scope_phase: state.scope_phase,
            authority_epoch: state.authority_epoch,
            binding_epoch: state.binding_epoch,
            supervisor: state.supervisor,
            fallback_running: state.fallback_running,
            snapshot_taken: state.snapshot_taken,
            replacement_ready: state.replacement_ready,
            write_token: TokenProjection(state.write.map(|record| record.token)),
            exit_token: TokenProjection(state.exit.map(|record| record.token)),
            write_phase: state.write.map(|record| record.phase),
            exit_phase: state.exit.map(|record| record.phase),
            backend_commits: records
                .iter()
                .flatten()
                .map(|record| u64::from(record.backend_commits))
                .sum(),
            reply_publications: records
                .iter()
                .flatten()
                .map(|record| u64::from(record.reply_publications))
                .sum(),
            resumes: records
                .iter()
                .flatten()
                .map(|record| u64::from(record.resumes))
                .sum(),
            exits: records
                .iter()
                .flatten()
                .map(|record| u64::from(record.exits))
                .sum(),
            aborts: records
                .iter()
                .flatten()
                .map(|record| u64::from(record.aborts))
                .sum(),
            terminalizations: state.terminalizations,
            output_publications: state.output_publications,
            prepared_output: state.prepared_output.is_some(),
            prepared_output_len,
            prepared_output_checksum,
            queued_stale_write: state.queued_stale_write.is_some(),
            write_waker: state.write_waker.is_some(),
            exit_waker: state.exit_waker.is_some(),
            completion_waker: state.completion_waker.is_some(),
            wakers: usize::from(state.write_waker.is_some())
                + usize::from(state.exit_waker.is_some())
                + usize::from(state.completion_waker.is_some()),
            live_effects: records
                .iter()
                .flatten()
                .filter(|record| {
                    !matches!(
                        record.phase,
                        ContinuationPhase::Completed | ContinuationPhase::Aborted
                    )
                })
                .count(),
            guest_outcome: state.guest_outcome,
            guest_finished: state.guest_finished,
            closure_target: state.closure_target,
            closure_steps: state.closure_steps,
            closure_waker_takes: state.closure_waker_takes,
            closure_wake_publications: state.closure_wake_publications,
        }
    }
    fn new(guest_vm: Arc<VmSpace>, completion_waker: EffectWaker) -> Self {
        Self::new_with_config(
            guest_vm,
            SCOPE_ID,
            WRITE_EFFECT_ID,
            GUEST_TASK_ID,
            1,
            Some(PERSONALITY_V1_TASK_ID),
            true,
            Some(completion_waker),
        )
    }

    fn new_revoke_probe(
        guest_vm: Arc<VmSpace>,
        scope_id: u64,
        effect_id: u64,
        task_id: u64,
        effect_waker: EffectWaker,
    ) -> Self {
        let scenario = Self::new_with_config(
            guest_vm,
            scope_id,
            effect_id,
            task_id,
            2,
            Some(PERSONALITY_V2_TASK_ID),
            false,
            None,
        );
        {
            let mut state = scenario.state.lock();
            assert_eq!(
                effect_waker.token(),
                EffectToken {
                    authority_epoch: AUTHORITY_EPOCH,
                    scope_id,
                    effect_id,
                }
            );
            state.write_waker = Some(effect_waker);
        }
        scenario
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_config(
        guest_vm: Arc<VmSpace>,
        scope_id: u64,
        write_effect_id: u64,
        guest_task_id: u64,
        binding_epoch: u64,
        supervisor: Option<u64>,
        emit_stdout: bool,
        completion_waker: Option<EffectWaker>,
    ) -> Self {
        Self {
            guest_vm,
            scope_id,
            write_effect_id,
            guest_task_id,
            emit_stdout,
            state: SpinLock::new(PersonalityState {
                scope_id,
                scope_phase: PersonalityScopePhase::Active,
                authority_epoch: AUTHORITY_EPOCH,
                binding_epoch,
                supervisor,
                fallback_running: false,
                snapshot_taken: false,
                replacement_ready: false,
                write: None,
                exit: None,
                prepared_output: None,
                queued_stale_write: None,
                write_waker: None,
                exit_waker: None,
                completion_waker,
                guest_outcome: GuestOutcome::Running,
                terminalizations: 0,
                output_publications: 0,
                stale_rejections: 0,
                no_supervisor_rejections: 0,
                guest_finished: false,
                closure_target: 0,
                closure_steps: 0,
                closure_waker_takes: 0,
                closure_wake_publications: 0,
            }),
        }
    }

    fn token(effect_id: u64) -> EffectToken {
        EffectToken {
            authority_epoch: AUTHORITY_EPOCH,
            scope_id: SCOPE_ID,
            effect_id,
        }
    }

    fn syscall_token(
        &self,
        effect_id: u64,
        operation: SyscallKind,
        binding_epoch: u64,
    ) -> SyscallToken {
        SyscallToken {
            authority_epoch: AUTHORITY_EPOCH,
            scope_id: self.scope_id,
            effect_id,
            task_id: self.guest_task_id,
            operation: operation.tag(),
            binding_epoch,
        }
    }

    fn capture_write(&self, context: &UserContext, waker: EffectWaker) {
        let token = Self::token(WRITE_EFFECT_ID);
        assert_eq!(waker.token(), token);
        assert_eq!(context.rax(), __NR_write as usize);

        let binding_epoch = {
            let mut state = self.state.lock();
            assert_eq!(state.binding_epoch, 1);
            assert_eq!(state.supervisor, Some(PERSONALITY_V1_TASK_ID));
            assert!(state.write.is_none());
            assert!(state.write_waker.is_none());
            state.write = Some(SyscallRecord {
                token: self.syscall_token(token.effect_id, SyscallKind::Write, state.binding_epoch),
                number: context.rax(),
                arg0: context.rdi(),
                arg1: context.rsi(),
                arg2: context.rdx(),
                phase: ContinuationPhase::Captured,
                backend_commits: 0,
                reply_publications: 0,
                resumes: 0,
                exits: 0,
                aborts: 0,
            });
            state.write_waker = Some(waker);
            state.binding_epoch
        };

        println!(
            "LINUX_SYSCALL Capture workload=linux-hello effect={} kind=write nr={} fd={} user_ptr={:#x} len={} authority_epoch={} binding_epoch={}",
            token.effect_id,
            __NR_write,
            context.rdi(),
            context.rsi(),
            context.rdx(),
            token.authority_epoch,
            binding_epoch,
        );
    }

    fn write_is_captured(&self) -> bool {
        self.state
            .lock()
            .write
            .as_ref()
            .is_some_and(|record| record.phase == ContinuationPhase::Captured)
    }

    fn validate_packet(
        state: &PersonalityState,
        record: &SyscallRecord,
        packet: SyscallToken,
        personality: u64,
    ) -> Result<(), PortalResult> {
        if packet.authority_epoch != state.authority_epoch {
            return Err(PortalResult::StaleAuthority);
        }
        if packet.scope_id != record.token.scope_id
            || packet.effect_id != record.token.effect_id
            || packet.task_id != record.token.task_id
            || packet.operation != record.token.operation
        {
            return Err(PortalResult::IdentityMismatch);
        }
        if packet.binding_epoch != state.binding_epoch {
            return Err(PortalResult::StaleBinding);
        }
        if state.supervisor != Some(personality) {
            return Err(PortalResult::NoSupervisor);
        }
        if state.scope_phase != PersonalityScopePhase::Active {
            return Err(PortalResult::ScopeClosed);
        }
        if packet != record.token {
            return Err(PortalResult::NotAdoptable);
        }
        Ok(())
    }

    fn deliver_write(&self, personality: u64) -> Result<SyscallRecord, PortalResult> {
        let record = {
            let state = self.state.lock();
            if state.supervisor != Some(personality) {
                return Err(PortalResult::NoSupervisor);
            }
            let Some(record) = state.write.as_ref().copied() else {
                return Err(PortalResult::InvalidState);
            };
            if record.phase != ContinuationPhase::Captured {
                return Err(
                    if matches!(
                        record.phase,
                        ContinuationPhase::Completed | ContinuationPhase::Aborted
                    ) {
                        PortalResult::AlreadyTerminal
                    } else {
                        PortalResult::InvalidState
                    },
                );
            }
            record
        };
        println!(
            "LINUX_PORTAL Deliver workload=linux-hello personality={} effect={} binding_epoch={} immutable_snapshot=true guest_context_writable=false token_authority={} token_scope={} token_task={} token_operation={}",
            personality,
            record.token.effect_id,
            record.token.binding_epoch,
            record.token.authority_epoch,
            record.token.scope_id,
            record.token.task_id,
            record.token.operation,
        );
        Ok(record)
    }

    fn prepare_write(&self, personality: u64, packet: SyscallToken) -> PortalResult {
        let (user_ptr, len) = {
            let state = self.state.lock();
            let Some(record) = state.write.as_ref() else {
                return PortalResult::InvalidState;
            };
            if let Err(error) = Self::validate_packet(&state, record, packet, personality) {
                return error;
            }
            if record.phase != ContinuationPhase::Captured {
                return if matches!(
                    record.phase,
                    ContinuationPhase::Completed | ContinuationPhase::Aborted
                ) {
                    PortalResult::AlreadyTerminal
                } else {
                    PortalResult::InvalidState
                };
            }
            if record.number != __NR_write as usize
                || record.arg0 != 1
                || (self.emit_stdout && record.arg2 > PAGE_SIZE)
            {
                return PortalResult::IdentityMismatch;
            }
            (record.arg1, record.arg2)
        };

        let mut output = vec![0; len];
        if self.emit_stdout {
            self.guest_vm.activate();
            let Ok(mut source) = self.guest_vm.reader(user_ptr, len) else {
                return PortalResult::InvalidState;
            };
            let mut destination = VmWriter::from(output.as_mut_slice());
            let copied = match source.read_fallible(&mut destination) {
                Ok(copied) => copied,
                Err(_) => return PortalResult::InvalidState,
            };
            if copied != len || output.as_slice() != EXPECTED_STDOUT {
                return PortalResult::IdentityMismatch;
            }
        }

        {
            let mut state = self.state.lock();
            let Some(record) = state.write.as_ref().copied() else {
                return PortalResult::InvalidState;
            };
            if let Err(error) = Self::validate_packet(&state, &record, packet, personality) {
                return error;
            }
            if record.phase != ContinuationPhase::Captured || state.prepared_output.is_some() {
                return PortalResult::InvalidState;
            }
            state.write.as_mut().unwrap().phase = ContinuationPhase::ReplyPrepared;
            state.prepared_output = Some(output);
        }

        if self.emit_stdout {
            println!(
                "LINUX_SYSCALL Prepare workload=linux-hello effect={} kind=write binding_epoch={} guest_bytes_copied={} owner=kernel",
                self.write_effect_id, packet.binding_epoch, len,
            );
        } else {
            println!(
                "LINUX_REVOKE Prepare scenario_scope={} effect={} authority_epoch={} binding_epoch={} state_before=Captured state_after=ReplyPrepared mutation=true",
                self.scope_id, self.write_effect_id, packet.authority_epoch, packet.binding_epoch,
            );
        }
        PortalResult::Applied
    }

    fn crash_v1(&self, presented_binding_epoch: u64) -> u64 {
        let current = {
            let mut state = self.state.lock();
            assert_eq!(state.binding_epoch, presented_binding_epoch);
            assert_eq!(state.supervisor, Some(PERSONALITY_V1_TASK_ID));
            assert_eq!(
                state.write.as_ref().unwrap().phase,
                ContinuationPhase::BackendCommitted
            );
            assert!(state.prepared_output.is_none());
            assert_eq!(state.output_publications, 1);
            assert!(state.queued_stale_write.is_some());
            state.binding_epoch = state
                .binding_epoch
                .checked_add(1)
                .expect("personality binding epoch overflow");
            state.supervisor = None;
            state.fallback_running = true;
            state.snapshot_taken = false;
            state.replacement_ready = false;
            state.binding_epoch
        };
        println!(
            "LINUX_PERSONALITY Crash workload=linux-hello supervisor={} previous_binding_epoch={} binding_epoch={} reason=user_page_fault backend_committed=true guest_reply_pending=true",
            PERSONALITY_V1_TASK_ID, presented_binding_epoch, current,
        );
        current
    }

    fn has_crashed(&self) -> bool {
        let state = self.state.lock();
        assert_eq!(state.authority_epoch, AUTHORITY_EPOCH);
        state.binding_epoch == 2 && state.supervisor.is_none() && state.fallback_running
    }

    fn queue_stale_write(&self, personality: u64, packet: SyscallToken) -> PortalResult {
        let mut state = self.state.lock();
        let Some(record) = state.write.as_ref().copied() else {
            return PortalResult::InvalidState;
        };
        if let Err(error) = Self::validate_packet(&state, &record, packet, personality) {
            return error;
        }
        if record.phase != ContinuationPhase::BackendCommitted {
            return PortalResult::InvalidState;
        }
        if state.queued_stale_write.is_some() {
            return PortalResult::QueueFull;
        }
        state.queued_stale_write = Some(packet);
        println!(
            "LINUX_PORTAL Queue workload=linux-hello sender={} action=Reply effect={} authority_epoch={} scope={} task={} operation={} binding_epoch={} delivery=after_crash",
            personality,
            packet.effect_id,
            packet.authority_epoch,
            packet.scope_id,
            packet.task_id,
            packet.operation,
            packet.binding_epoch,
        );
        PortalResult::Applied
    }

    fn replay_queued_stale_write(&self) -> PortalResult {
        let packet = {
            let mut state = self.state.lock();
            let Some(packet) = state.queued_stale_write.take() else {
                return PortalResult::InvalidState;
            };
            packet
        };
        let before = self.semantic_projection();
        let result = self.reply_write(PERSONALITY_V1_TASK_ID, packet, "post_crash");
        log_semantic_portal_result(
            false,
            "post_crash",
            PERSONALITY_V1_TASK_ID,
            REPLY_WRITE,
            packet,
            result,
            before,
            self.semantic_projection(),
        );
        result
    }

    fn recovery_snapshot(
        &self,
        replacement: u64,
        presented_binding_epoch: u64,
    ) -> Result<SyscallRecord, PortalResult> {
        let record = {
            let mut state = self.state.lock();
            if state.binding_epoch != presented_binding_epoch
                || state.supervisor.is_some()
                || !state.fallback_running
                || state.snapshot_taken
            {
                return Err(PortalResult::InvalidState);
            }
            let Some(record) = state.write.as_ref().copied() else {
                return Err(PortalResult::InvalidState);
            };
            if record.phase != ContinuationPhase::BackendCommitted {
                return Err(PortalResult::InvalidState);
            }
            state.snapshot_taken = true;
            record
        };
        println!(
            "LINUX_PERSONALITY RecoverySnapshot workload=linux-hello replacement={} binding_epoch={} effect={} phase=BackendCommitted output_obligation=retained guest_reply_pending=true",
            replacement, presented_binding_epoch, WRITE_EFFECT_ID,
        );
        Ok(record)
    }

    fn ready(&self, replacement: u64, presented_binding_epoch: u64) -> PortalResult {
        {
            let mut state = self.state.lock();
            if state.binding_epoch != presented_binding_epoch
                || state.supervisor.is_some()
                || !state.snapshot_taken
                || state.replacement_ready
            {
                return PortalResult::InvalidState;
            }
            state.replacement_ready = true;
        }
        println!(
            "LINUX_PERSONALITY Ready workload=linux-hello replacement={} binding_epoch={}",
            replacement, presented_binding_epoch,
        );
        PortalResult::Applied
    }

    fn rebind(&self, replacement: u64, presented_binding_epoch: u64) -> PortalResult {
        {
            let mut state = self.state.lock();
            if state.binding_epoch != presented_binding_epoch
                || state.supervisor.is_some()
                || !state.fallback_running
                || !state.snapshot_taken
                || !state.replacement_ready
            {
                return PortalResult::InvalidState;
            }
            state.supervisor = Some(replacement);
            state.fallback_running = false;
        }
        println!(
            "LINUX_PERSONALITY Rebind workload=linux-hello replacement={} binding_epoch={} epoch_advanced=false fallback=Standby",
            replacement, presented_binding_epoch,
        );
        PortalResult::Applied
    }

    fn recover_next(
        &self,
        replacement: u64,
        presented_binding_epoch: u64,
    ) -> Result<SyscallRecord, PortalResult> {
        let record = {
            let state = self.state.lock();
            if state.binding_epoch != presented_binding_epoch
                || state.supervisor != Some(replacement)
                || !state.replacement_ready
            {
                return Err(PortalResult::InvalidState);
            }
            let Some(record) = state.write.as_ref().copied() else {
                return Err(PortalResult::InvalidState);
            };
            if record.phase != ContinuationPhase::BackendCommitted {
                return Err(PortalResult::InvalidState);
            }
            record
        };
        println!(
            "LINUX_SYSCALL RecoverNext workload=linux-hello replacement={} effect={} old_binding_epoch={} phase=BackendCommitted",
            replacement, WRITE_EFFECT_ID, record.token.binding_epoch,
        );
        Ok(record)
    }

    fn adopt(
        &self,
        replacement: u64,
        packet: SyscallToken,
    ) -> (PortalResult, Option<SyscallRecord>) {
        let result = {
            let mut state = self.state.lock();
            let Some(record) = state.write.as_ref().copied() else {
                return (PortalResult::InvalidState, None);
            };
            if packet.authority_epoch != state.authority_epoch {
                return (PortalResult::StaleAuthority, None);
            }
            if packet.scope_id != record.token.scope_id
                || packet.effect_id != record.token.effect_id
                || packet.task_id != record.token.task_id
                || packet.operation != record.token.operation
            {
                return (PortalResult::IdentityMismatch, None);
            }
            if state.supervisor != Some(replacement) {
                return (PortalResult::NoSupervisor, None);
            }
            if packet != record.token
                || packet.binding_epoch == state.binding_epoch
                || record.phase != ContinuationPhase::BackendCommitted
            {
                return (PortalResult::NotAdoptable, None);
            }
            let old_binding_epoch = record.token.binding_epoch;
            let current_binding_epoch = state.binding_epoch;
            let record = state.write.as_mut().unwrap();
            record.token.binding_epoch = current_binding_epoch;
            let adopted = *record;
            (old_binding_epoch, current_binding_epoch, adopted)
        };
        println!(
            "LINUX_SYSCALL Adopt workload=linux-hello replacement={} effect={} old_binding_epoch={} binding_epoch={} explicit=true",
            replacement, WRITE_EFFECT_ID, result.0, result.1,
        );
        (PortalResult::Applied, Some(result.2))
    }

    fn commit_backend(&self, personality: u64, packet: SyscallToken) -> PortalResult {
        let (result, output) = {
            let mut state = self.state.lock();
            let Some(record) = state.write.as_ref().copied() else {
                return PortalResult::InvalidState;
            };
            if let Err(error) = Self::validate_packet(&state, &record, packet, personality) {
                return error;
            }
            match record.phase {
                ContinuationPhase::ReplyPrepared => {
                    let Some(output) = state.prepared_output.take() else {
                        return PortalResult::InvalidState;
                    };
                    let target = state.write.as_mut().unwrap();
                    target.phase = ContinuationPhase::BackendCommitted;
                    target.backend_commits = 1;
                    state.output_publications += 1;
                    assert_eq!(state.output_publications, 1);
                    (PortalResult::Applied, Some(output))
                }
                ContinuationPhase::BackendCommitted => {
                    assert_eq!(state.output_publications, 1);
                    assert!(state.prepared_output.is_none());
                    (PortalResult::AlreadyCommitted, None)
                }
                ContinuationPhase::Completed | ContinuationPhase::Aborted => {
                    (PortalResult::AlreadyTerminal, None)
                }
                ContinuationPhase::Captured => (PortalResult::InvalidState, None),
            }
        };

        if let Some(output) = output
            && self.emit_stdout
        {
            let line = str::from_utf8(&output).expect("linux-hello stdout is UTF-8");
            assert_eq!(output.as_slice(), EXPECTED_STDOUT);
            println!("LINUX_GUEST stdout={}", line.trim_end());
        }
        if self.emit_stdout {
            println!(
                "LINUX_SYSCALL BackendCommit workload=linux-hello personality={} effect={} kind=write binding_epoch={} result={} output_publications=1 guest_reply_pending=true",
                personality,
                self.write_effect_id,
                packet.binding_epoch,
                result.backend_label(),
            );
        } else {
            println!(
                "LINUX_REVOKE PortalAttempt action=BackendCommit sender={} opcode={:#x} authority_epoch={} scope={} effect={} task={} operation={} binding_epoch={} result={} mutation={} backend_commits={}",
                personality,
                REVOKE_PROBE_BACKEND_COMMIT,
                packet.authority_epoch,
                packet.scope_id,
                packet.effect_id,
                packet.task_id,
                packet.operation,
                packet.binding_epoch,
                result.label(),
                result == PortalResult::Applied,
                u8::from(
                    result == PortalResult::Applied || result == PortalResult::AlreadyCommitted
                ),
            );
        }
        result
    }

    fn reply_write(
        &self,
        personality: u64,
        packet: SyscallToken,
        stage: &'static str,
    ) -> PortalResult {
        let (result, waker, current_binding_epoch) = {
            let mut state = self.state.lock();
            let current_binding_epoch = state.binding_epoch;
            let Some(record) = state.write.as_ref().copied() else {
                return PortalResult::InvalidState;
            };
            let result = match Self::validate_packet(&state, &record, packet, personality) {
                Ok(()) => match record.phase {
                    ContinuationPhase::BackendCommitted => PortalResult::Applied,
                    ContinuationPhase::Completed | ContinuationPhase::Aborted => {
                        PortalResult::AlreadyTerminal
                    }
                    ContinuationPhase::Captured | ContinuationPhase::ReplyPrepared => {
                        PortalResult::InvalidState
                    }
                },
                Err(error) => error,
            };
            if result == PortalResult::StaleBinding {
                state.stale_rejections += 1;
            } else if result == PortalResult::NoSupervisor {
                state.no_supervisor_rejections += 1;
            }
            if result != PortalResult::Applied {
                (result, None, current_binding_epoch)
            } else {
                let waker = state.write_waker.take();
                if self.emit_stdout && waker.is_none() {
                    return PortalResult::AlreadyTerminal;
                }
                let target = state.write.as_mut().unwrap();
                target.phase = ContinuationPhase::Completed;
                target.reply_publications = 1;
                target.resumes = 1;
                state.terminalizations += 1;
                assert_eq!(state.output_publications, 1);
                (result, waker, current_binding_epoch)
            }
        };
        if !self.emit_stdout {
            println!(
                "LINUX_REVOKE PortalAttempt action=Reply sender={} opcode={:#x} authority_epoch={} scope={} effect={} task={} operation={} binding_epoch={} result={} mutation={} guest_resume={}",
                personality,
                REVOKE_PROBE_REPLY,
                packet.authority_epoch,
                packet.scope_id,
                packet.effect_id,
                packet.task_id,
                packet.operation,
                packet.binding_epoch,
                result.backend_label(),
                result == PortalResult::Applied,
                u8::from(result == PortalResult::Applied),
            );
            return result;
        }
        match result {
            PortalResult::Applied => {
                println!(
                    "LINUX_SYSCALL Reply workload=linux-hello replacement={} effect={} kind=write binding_epoch={} backend_replayed=false guest_resume=one-shot terminal=Completed",
                    personality, WRITE_EFFECT_ID, packet.binding_epoch,
                );
                let _ = waker.unwrap().wake_up();
            }
            PortalResult::StaleBinding => println!(
                "LINUX_SYSCALL REJECT_STALE workload=linux-hello stage={} action=Reply effect={} proposal_binding_epoch={} current_binding_epoch={} guest_resume=false backend_replayed=false token_authority={} token_scope={} token_task={} token_operation={}",
                stage,
                packet.effect_id,
                packet.binding_epoch,
                current_binding_epoch,
                packet.authority_epoch,
                packet.scope_id,
                packet.task_id,
                packet.operation,
            ),
            PortalResult::NoSupervisor => println!(
                "LINUX_SYSCALL REJECT_NO_SUPERVISOR workload=linux-hello stage={} action=Reply effect={} binding_epoch={} guest_resume=false backend_replayed=false",
                stage, packet.effect_id, packet.binding_epoch,
            ),
            error => println!(
                "LINUX_SYSCALL REJECT workload=linux-hello stage={} action=Reply effect={} authority_epoch={} scope={} task={} operation={} binding_epoch={} result={} guest_resume=false backend_replayed=false",
                stage,
                packet.effect_id,
                packet.authority_epoch,
                packet.scope_id,
                packet.task_id,
                packet.operation,
                packet.binding_epoch,
                error.backend_label(),
            ),
        }
        result
    }

    fn write_result(&self) -> usize {
        let state = self.state.lock();
        let record = state.write.as_ref().unwrap();
        assert_eq!(record.phase, ContinuationPhase::Completed);
        assert_eq!(state.output_publications, 1);
        record.arg2
    }

    fn write_reply_stage(&self, packet: SyscallToken) -> &'static str {
        let state = self.state.lock();
        if state.supervisor.is_none() {
            "pre_rebind"
        } else if state
            .write
            .as_ref()
            .is_some_and(|record| record.token.binding_epoch != state.binding_epoch)
        {
            "post_rebind"
        } else if packet.binding_epoch != state.binding_epoch {
            "post_adopt"
        } else {
            "current"
        }
    }

    fn capture_exit(&self, context: &UserContext, waker: EffectWaker) {
        let token = Self::token(EXIT_EFFECT_ID);
        assert_eq!(waker.token(), token);
        assert_eq!(context.rax(), __NR_exit_group as usize);
        assert_eq!(context.rdi(), 0);
        let binding_epoch = {
            let mut state = self.state.lock();
            assert_eq!(state.binding_epoch, 2);
            assert_eq!(state.supervisor, Some(PERSONALITY_V2_TASK_ID));
            assert_eq!(
                state.write.as_ref().unwrap().phase,
                ContinuationPhase::Completed
            );
            assert!(state.exit.is_none());
            state.exit = Some(SyscallRecord {
                token: self.syscall_token(
                    token.effect_id,
                    SyscallKind::ExitGroup,
                    state.binding_epoch,
                ),
                number: context.rax(),
                arg0: context.rdi(),
                arg1: 0,
                arg2: 0,
                phase: ContinuationPhase::Captured,
                backend_commits: 0,
                reply_publications: 0,
                resumes: 0,
                exits: 0,
                aborts: 0,
            });
            state.exit_waker = Some(waker);
            state.binding_epoch
        };
        println!(
            "LINUX_SYSCALL Capture workload=linux-hello effect={} kind=exit_group nr={} status=0 authority_epoch={} binding_epoch={}",
            token.effect_id, __NR_exit_group, token.authority_epoch, binding_epoch,
        );
    }

    fn exit_is_captured(&self) -> bool {
        self.state
            .lock()
            .exit
            .as_ref()
            .is_some_and(|record| record.phase == ContinuationPhase::Captured)
    }

    fn exit_is_completed(&self) -> bool {
        self.state
            .lock()
            .exit
            .as_ref()
            .is_some_and(|record| record.phase == ContinuationPhase::Completed)
    }

    fn deliver_exit(&self, personality: u64) -> Result<SyscallRecord, PortalResult> {
        let record = {
            let state = self.state.lock();
            if state.supervisor != Some(personality) {
                return Err(PortalResult::NoSupervisor);
            }
            let Some(record) = state.exit.as_ref().copied() else {
                return Err(PortalResult::InvalidState);
            };
            if record.phase != ContinuationPhase::Captured {
                return Err(
                    if matches!(
                        record.phase,
                        ContinuationPhase::Completed | ContinuationPhase::Aborted
                    ) {
                        PortalResult::AlreadyTerminal
                    } else {
                        PortalResult::InvalidState
                    },
                );
            }
            record
        };
        println!(
            "LINUX_PORTAL Deliver workload=linux-hello personality={} effect={} binding_epoch={} immutable_snapshot=true guest_context_writable=false token_authority={} token_scope={} token_task={} token_operation={}",
            personality,
            record.token.effect_id,
            record.token.binding_epoch,
            record.token.authority_epoch,
            record.token.scope_id,
            record.token.task_id,
            record.token.operation,
        );
        Ok(record)
    }

    fn prepare_exit(&self, personality: u64, packet: SyscallToken) -> PortalResult {
        let mut state = self.state.lock();
        let Some(record) = state.exit.as_ref().copied() else {
            return PortalResult::InvalidState;
        };
        if let Err(error) = Self::validate_packet(&state, &record, packet, personality) {
            return error;
        }
        match record.phase {
            ContinuationPhase::Captured => {
                if record.number != __NR_exit_group as usize || record.arg0 != 0 {
                    return PortalResult::IdentityMismatch;
                }
                state.exit.as_mut().unwrap().phase = ContinuationPhase::ReplyPrepared;
                println!(
                    "LINUX_SYSCALL Prepare workload=linux-hello effect={} kind=exit_group binding_epoch={} terminal_pending=true",
                    packet.effect_id, packet.binding_epoch,
                );
                PortalResult::Applied
            }
            ContinuationPhase::Completed | ContinuationPhase::Aborted => {
                PortalResult::AlreadyTerminal
            }
            ContinuationPhase::ReplyPrepared | ContinuationPhase::BackendCommitted => {
                PortalResult::InvalidState
            }
        }
    }

    fn commit_exit(&self, replacement: u64, packet: SyscallToken) -> PortalResult {
        let (result, waker) = {
            let mut state = self.state.lock();
            let Some(record) = state.exit.as_ref().copied() else {
                return PortalResult::InvalidState;
            };
            if let Err(error) = Self::validate_packet(&state, &record, packet, replacement) {
                return error;
            }
            match record.phase {
                ContinuationPhase::ReplyPrepared => {
                    let Some(waker) = state.exit_waker.take() else {
                        return PortalResult::AlreadyTerminal;
                    };
                    state.exit.as_mut().unwrap().phase = ContinuationPhase::Completed;
                    let target = state.exit.as_mut().unwrap();
                    target.reply_publications = 1;
                    target.exits = 1;
                    state.guest_outcome = GuestOutcome::Exited(0);
                    state.terminalizations += 1;
                    (PortalResult::Applied, Some(waker))
                }
                ContinuationPhase::Completed | ContinuationPhase::Aborted => {
                    (PortalResult::AlreadyTerminal, None)
                }
                ContinuationPhase::Captured | ContinuationPhase::BackendCommitted => {
                    (PortalResult::InvalidState, None)
                }
            }
        };
        if result == PortalResult::Applied {
            println!(
                "LINUX_SYSCALL Commit workload=linux-hello replacement={} effect={} kind=exit_group binding_epoch={} terminal=Completed",
                replacement, EXIT_EFFECT_ID, packet.binding_epoch,
            );
            let _ = waker.unwrap().wake_up();
        } else {
            println!(
                "LINUX_SYSCALL REJECT workload=linux-hello action=CommitExit effect={} authority_epoch={} scope={} task={} operation={} binding_epoch={} result={} process_exit=false",
                packet.effect_id,
                packet.authority_epoch,
                packet.scope_id,
                packet.task_id,
                packet.operation,
                packet.binding_epoch,
                result.backend_label(),
            );
        }
        result
    }

    fn capture_probe_write(&self, personality: u64) -> Result<SyscallRecord, PortalResult> {
        let mut state = self.state.lock();
        if state.supervisor != Some(personality)
            || state.scope_phase != PersonalityScopePhase::Active
            || state.write.is_some()
            || state.write_waker.is_none()
        {
            return Err(PortalResult::InvalidState);
        }
        let record = SyscallRecord {
            token: self.syscall_token(
                self.write_effect_id,
                SyscallKind::Write,
                state.binding_epoch,
            ),
            number: __NR_write as usize,
            arg0: 1,
            arg1: 0,
            arg2: 0,
            phase: ContinuationPhase::Captured,
            backend_commits: 0,
            reply_publications: 0,
            resumes: 0,
            exits: 0,
            aborts: 0,
        };
        state.write = Some(record);
        println!(
            "LINUX_REVOKE Register parent_scope={} scope={} effect={} task={} operation={} authority_epoch={} binding_epoch={} state=Captured single_cpu=true",
            SCOPE_ID,
            self.scope_id,
            self.write_effect_id,
            self.guest_task_id,
            SyscallKind::Write.tag(),
            AUTHORITY_EPOCH,
            state.binding_epoch,
        );
        Ok(record)
    }

    fn revoke_begin(&self, personality: u64, packet: SyscallToken) -> PortalResult {
        let (old_authority, authority, target_count) = {
            let mut state = self.state.lock();
            let record = if state
                .write
                .is_some_and(|record| record.token.effect_id == packet.effect_id)
            {
                state.write
            } else if state
                .exit
                .is_some_and(|record| record.token.effect_id == packet.effect_id)
            {
                state.exit
            } else {
                None
            };
            let Some(record) = record else {
                return PortalResult::InvalidState;
            };
            if let Err(error) = Self::validate_packet(&state, &record, packet, personality) {
                return error;
            }
            let old_authority = state.authority_epoch;
            state.authority_epoch = old_authority + 1;
            state.scope_phase = PersonalityScopePhase::Closing;
            state.supervisor = None;
            state.fallback_running = false;
            state.closure_target = usize::from(state.write.is_some_and(|record| {
                !matches!(
                    record.phase,
                    ContinuationPhase::Completed | ContinuationPhase::Aborted
                )
            })) + usize::from(state.exit.is_some_and(|record| {
                !matches!(
                    record.phase,
                    ContinuationPhase::Completed | ContinuationPhase::Aborted
                )
            }));
            (old_authority, state.authority_epoch, state.closure_target)
        };
        println!(
            "LINUX_REVOKE RevokeBegin parent_scope={} scope={} old_authority_epoch={} authority_epoch={} binding_epoch=2 target_count={} reply_gate=closed backend_gate=closed state=Closing",
            SCOPE_ID, self.scope_id, old_authority, authority, target_count,
        );
        PortalResult::Applied
    }

    fn closure_next(&self) -> PortalResult {
        let (effect_id, from, snapshot, steps, waker) = {
            let mut state = self.state.lock();
            if state.scope_phase != PersonalityScopePhase::Closing {
                return PortalResult::InvalidState;
            }
            let close_write = state.write.is_some_and(|record| {
                !matches!(
                    record.phase,
                    ContinuationPhase::Aborted | ContinuationPhase::Completed
                )
            });
            let close_exit = state.exit.is_some_and(|record| {
                !matches!(
                    record.phase,
                    ContinuationPhase::Aborted | ContinuationPhase::Completed
                )
            });
            if !close_write && !close_exit {
                return PortalResult::AlreadyTerminal;
            }
            if (close_write && state.write_waker.is_none())
                || (close_exit && state.exit_waker.is_none())
            {
                return PortalResult::InvalidState;
            }
            let (effect_id, from, snapshot, waker) = if close_write {
                if state
                    .write
                    .as_ref()
                    .is_some_and(|record| record.phase == ContinuationPhase::ReplyPrepared)
                {
                    state.prepared_output = None;
                }
                let target = state.write.as_mut().unwrap();
                let from = target.phase;
                match target.phase {
                    ContinuationPhase::Captured | ContinuationPhase::ReplyPrepared => {
                        target.phase = ContinuationPhase::Aborted;
                        target.aborts = 1;
                    }
                    ContinuationPhase::BackendCommitted => {
                        target.phase = ContinuationPhase::Completed;
                        target.reply_publications = 1;
                        target.resumes = 1;
                    }
                    ContinuationPhase::Completed | ContinuationPhase::Aborted => {
                        return PortalResult::AlreadyTerminal;
                    }
                }
                let snapshot = *target;
                (
                    snapshot.token.effect_id,
                    from,
                    snapshot,
                    state.write_waker.take(),
                )
            } else {
                let target = state.exit.as_mut().unwrap();
                let from = target.phase;
                match target.phase {
                    ContinuationPhase::Captured | ContinuationPhase::ReplyPrepared => {
                        target.phase = ContinuationPhase::Aborted;
                        target.aborts = 1;
                    }
                    ContinuationPhase::BackendCommitted => {
                        return PortalResult::InvalidState;
                    }
                    ContinuationPhase::Completed | ContinuationPhase::Aborted => {
                        return PortalResult::AlreadyTerminal;
                    }
                }
                let snapshot = *target;
                (
                    snapshot.token.effect_id,
                    from,
                    snapshot,
                    state.exit_waker.take(),
                )
            };
            state.closure_steps += 1;
            state.terminalizations += 1;
            (effect_id, from, snapshot, state.closure_steps, waker)
        };
        let waker_taken = waker.is_some();
        let wake_published = waker.is_some_and(|waker| waker.wake_up());
        {
            let mut state = self.state.lock();
            state.closure_waker_takes += usize::from(waker_taken);
            state.closure_wake_publications += usize::from(wake_published);
        }
        println!(
            "LINUX_REVOKE ClosureStep scope={} effect={} from={:?} to={:?} backend_commits={} replies={} resumes={} aborts={} steps={} waker_taken={} wake_published={} waker_dropped=true",
            self.scope_id,
            effect_id,
            from,
            snapshot.phase,
            snapshot.backend_commits,
            snapshot.reply_publications,
            snapshot.resumes,
            snapshot.aborts,
            steps,
            waker_taken,
            wake_published,
        );
        PortalResult::Applied
    }

    fn revoke_complete(&self) -> PortalResult {
        let (target, steps) = {
            let mut state = self.state.lock();
            if state.scope_phase != PersonalityScopePhase::Closing {
                return PortalResult::InvalidState;
            }
            let terminal = state.write.is_none_or(|record| {
                matches!(
                    record.phase,
                    ContinuationPhase::Aborted | ContinuationPhase::Completed
                )
            }) && state.exit.is_none_or(|record| {
                matches!(
                    record.phase,
                    ContinuationPhase::Aborted | ContinuationPhase::Completed
                )
            });
            let closure_published = state.write_waker.is_none()
                && state.exit_waker.is_none()
                && state.closure_waker_takes == state.closure_target
                && state.closure_wake_publications == state.closure_target;
            if !terminal || state.closure_steps != state.closure_target || !closure_published {
                return PortalResult::NotQuiescent;
            }
            state.scope_phase = PersonalityScopePhase::Revoked;
            (state.closure_target, state.closure_steps)
        };
        println!(
            "LINUX_REVOKE RevokeComplete parent_scope={} scope={} authority_epoch={} target_count={} steps={} live_effects=0 waker_present=false wake_publications={} state=Revoked",
            SCOPE_ID,
            self.scope_id,
            AUTHORITY_EPOCH + 1,
            target,
            steps,
            steps,
        );
        PortalResult::Applied
    }

    fn guest_outcome(&self) -> GuestOutcome {
        self.state.lock().guest_outcome
    }

    fn finish_guest(&self) {
        let completion_waker = {
            let mut state = self.state.lock();
            assert_eq!(state.guest_outcome, GuestOutcome::Exited(0));
            assert!(!state.guest_finished);
            state.guest_finished = true;
            state.completion_waker.take().unwrap()
        };
        assert!(completion_waker.wake_up());
    }

    fn assert_final(&self) {
        let state = self.state.lock();
        assert_eq!(state.binding_epoch, 2);
        assert_eq!(state.supervisor, Some(PERSONALITY_V2_TASK_ID));
        assert!(!state.fallback_running);
        assert_eq!(
            state.write.as_ref().unwrap().phase,
            ContinuationPhase::Completed
        );
        assert_eq!(
            state.exit.as_ref().unwrap().phase,
            ContinuationPhase::Completed
        );
        assert!(state.prepared_output.is_none());
        assert!(state.queued_stale_write.is_none());
        assert!(state.write_waker.is_none());
        assert!(state.exit_waker.is_none());
        assert!(state.completion_waker.is_none());
        assert_eq!(state.guest_outcome, GuestOutcome::Exited(0));
        assert_eq!(state.terminalizations, 2);
        assert_eq!(state.output_publications, 1);
        assert_eq!(state.stale_rejections, 3);
        assert_eq!(state.no_supervisor_rejections, 1);
        assert!(state.guest_finished);
        assert_eq!(state.scope_phase, PersonalityScopePhase::Active);
    }

    fn assert_revoke_final(&self, committed_before_revoke: bool) {
        let state = self.state.lock();
        assert_eq!(state.scope_id, self.scope_id);
        assert_eq!(state.scope_phase, PersonalityScopePhase::Revoked);
        assert_eq!(state.authority_epoch, AUTHORITY_EPOCH + 1);
        assert_eq!(state.closure_target, 1);
        assert_eq!(state.closure_steps, 1);
        assert_eq!(state.closure_waker_takes, 1);
        assert_eq!(state.closure_wake_publications, 1);
        assert!(state.write_waker.is_none());
        let record = state.write.unwrap();
        assert_eq!(record.token.scope_id, self.scope_id);
        assert_eq!(record.token.effect_id, self.write_effect_id);
        assert_eq!(record.token.task_id, self.guest_task_id);
        if committed_before_revoke {
            assert_eq!(record.phase, ContinuationPhase::Completed);
            assert_eq!(record.backend_commits, 1);
            assert_eq!(record.reply_publications, 1);
            assert_eq!((record.resumes, record.exits, record.aborts), (1, 0, 0));
        } else {
            assert_eq!(record.phase, ContinuationPhase::Aborted);
            assert_eq!(record.backend_commits, 0);
            assert_eq!(record.reply_publications, 0);
            assert_eq!((record.resumes, record.exits, record.aborts), (0, 0, 1));
        }
        println!(
            "LINUX_REVOKE PASS parent_scope={} scope={} authority_epoch={} target_count=1 steps=1 final={:?} backend_commits={} replies={} resumes={} aborts={} post_revoke_exclusion=true quiescent=true",
            SCOPE_ID,
            self.scope_id,
            AUTHORITY_EPOCH + 1,
            record.phase,
            record.backend_commits,
            record.reply_publications,
            record.resumes,
            record.aborts,
        );
    }

    fn revoke_is_complete(&self, committed_before_revoke: bool) -> bool {
        let state = self.state.lock();
        let Some(record) = state.write else {
            return false;
        };
        state.scope_phase == PersonalityScopePhase::Revoked
            && state.authority_epoch == AUTHORITY_EPOCH + 1
            && state.closure_target == 1
            && state.closure_steps == 1
            && state.closure_waker_takes == 1
            && state.closure_wake_publications == 1
            && state.write_waker.is_none()
            && if committed_before_revoke {
                record.phase == ContinuationPhase::Completed
                    && record.backend_commits == 1
                    && record.reply_publications == 1
                    && (record.resumes, record.exits, record.aborts) == (1, 0, 0)
            } else {
                record.phase == ContinuationPhase::Aborted
                    && record.backend_commits == 0
                    && record.reply_publications == 0
                    && (record.resumes, record.exits, record.aborts) == (0, 0, 1)
            }
    }
}

struct LoadedElf {
    vm_space: Arc<VmSpace>,
    entry: Vaddr,
    stack_pointer: Vaddr,
    load_segments: usize,
    entry_page_address: Vaddr,
    entry_page: Vec<u8>,
}

pub fn run_linux_hello_slice(scheduler: &'static CserScheduler, scheduler_binding: Binding) {
    let loaded = load_static_elf(LINUX_HELLO_ELF);
    let code_pager = LinuxCodePager::new(
        PersonalityScenario::token(CODE_FAULT_EFFECT_ID),
        loaded.vm_space.clone(),
        loaded.entry_page_address,
        &loaded.entry_page,
    );
    let token = EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: SCOPE_ID,
        effect_id: SLICE_COMPLETION_EFFECT_ID,
    };
    let (done_waiter, done_waker) = EffectWaiter::new_pair(token);
    let scenario = Arc::new(PersonalityScenario::new(
        loaded.vm_space.clone(),
        done_waker,
    ));
    let (revoke_precommit_waiter, revoke_precommit_waker) = EffectWaiter::new_pair(EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: REVOKE_PRECOMMIT_SCOPE_ID,
        effect_id: REVOKE_PRECOMMIT_EFFECT_ID,
    });
    let revoke_precommit = Arc::new(PersonalityScenario::new_revoke_probe(
        loaded.vm_space.clone(),
        REVOKE_PRECOMMIT_SCOPE_ID,
        REVOKE_PRECOMMIT_EFFECT_ID,
        REVOKE_PROBE_TASK_ID,
        revoke_precommit_waker,
    ));
    let (revoke_committed_waiter, revoke_committed_waker) = EffectWaiter::new_pair(EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: REVOKE_COMMITTED_SCOPE_ID,
        effect_id: REVOKE_COMMITTED_EFFECT_ID,
    });
    let (personality_v2_exit_waiter, personality_v2_exit_waker) =
        EffectWaiter::new_pair(EffectToken {
            authority_epoch: AUTHORITY_EPOCH,
            scope_id: SCOPE_ID,
            effect_id: PERSONALITY_V2_TASK_EXIT_EFFECT_ID,
        });
    let revoke_committed = Arc::new(PersonalityScenario::new_revoke_probe(
        loaded.vm_space.clone(),
        REVOKE_COMMITTED_SCOPE_ID,
        REVOKE_COMMITTED_EFFECT_ID,
        REVOKE_COMMITTED_PROBE_TASK_ID,
        revoke_committed_waker,
    ));

    let guest_state = scenario.clone();
    let guest_vm = loaded.vm_space.clone();
    let guest_entry = loaded.entry;
    let guest_stack = loaded.stack_pointer;
    let guest_code_pager = code_pager.clone();
    let guest_task = Arc::new(
        TaskOptions::new(move || {
            run_linux_guest(
                guest_state,
                guest_code_pager,
                guest_vm,
                guest_entry,
                guest_stack,
            )
        })
        .data(TaskData::new(GUEST_TASK_ID, Some(loaded.vm_space.clone())))
        .build()
        .expect("build linux-hello task"),
    );

    let v1_vm = Arc::new(create_vm_space(PERSONALITY_V1_PROGRAM));
    let v1_state = scenario.clone();
    let v1_task_vm = v1_vm.clone();
    let v1_task = Arc::new(
        TaskOptions::new(move || run_personality_v1(v1_state, v1_task_vm))
            .data(TaskData::new(PERSONALITY_V1_TASK_ID, Some(v1_vm.clone())))
            .build()
            .expect("build Linux personality v1 task"),
    );

    let watchdog_state = scenario.clone();
    let watchdog_revoke_precommit = revoke_precommit.clone();
    let watchdog_revoke_committed = revoke_committed.clone();
    let old_task = v1_task.clone();
    let watchdog_task = Arc::new(
        TaskOptions::new(move || {
            run_watchdog(
                watchdog_state,
                watchdog_revoke_precommit,
                watchdog_revoke_committed,
                old_task,
                personality_v2_exit_waker,
            )
        })
        .data(TaskData::new(WATCHDOG_TASK_ID, None))
        .build()
        .expect("build Linux personality watchdog"),
    );

    let policy_vm = Arc::new(create_vm_space(SCHEDULER_POLICY_PROGRAM));
    let policy_task_vm = policy_vm.clone();
    let policy_task = Arc::new(
        TaskOptions::new(move || {
            run_scheduler_policy(scheduler, scheduler_binding, policy_task_vm)
        })
        .data(TaskData::new(
            SCHEDULER_POLICY_TASK_ID,
            Some(policy_vm.clone()),
        ))
        .build()
        .expect("build linux-hello scheduler policy task"),
    );

    println!(
        "LINUX_SLICE BEGIN workload=linux-hello format=ELF64 type=ET_EXEC load_segments={} scheduler_mode=user_policy_then_kernel_fifo_fallback scheduler_binding_epoch={}",
        loaded.load_segments, scheduler_binding.binding_epoch,
    );
    code_pager.arm();
    guest_task.run();
    code_pager.start();
    v1_task.run();
    watchdog_task.run();
    policy_task.run();
    assert_eq!(
        scheduler.propose(scheduler_binding, SCHEDULER_POLICY_TASK_ID),
        ProposalResult::Prepared
    );
    done_waiter.wait();
    drop(done_waiter);
    revoke_precommit_waiter.wait();
    revoke_committed_waiter.wait();
    personality_v2_exit_waiter.wait();
    drop(revoke_precommit_waiter);
    drop(revoke_committed_waiter);
    drop(personality_v2_exit_waiter);
    println!(
        "LINUX_PERSONALITY_V2 TaskExit workload=linux-hello task={} observed=true lifecycle_barrier=one-shot",
        PERSONALITY_V2_TASK_ID,
    );

    let fallback = scheduler
        .fallback_evidence()
        .expect("linux-hello scheduler crash records fallback evidence");
    assert_eq!(fallback.pick_task_id, GUEST_TASK_ID);
    assert!(fallback.pick_tick >= fallback.crash_tick);
    assert_eq!(
        fallback.pick_selection_attempt,
        FIRST_FALLBACK_SELECTION_ATTEMPT
    );
    println!(
        "LINUX_SCHEDULER PASS workload=linux-hello policy={} fallback_first_task={} fallback_first_selection_attempt={} observed_tick_delta={} tick_delta_diagnostic=true scoped_proposal_cleared=true",
        SCHEDULER_POLICY_TASK_ID,
        fallback.pick_task_id,
        fallback.pick_selection_attempt,
        fallback.pick_tick - fallback.crash_tick,
    );
    code_pager.assert_complete();
    scenario.assert_final();
    revoke_precommit.assert_revoke_final(false);
    revoke_committed.assert_revoke_final(true);
    println!(
        "LINUX_SLICE PASS workload=linux-hello write=true exit_group=true personality_crash_rebind=true stale_reply_fenced=true terminalizations=2 output_publications=1"
    );
}

fn load_static_elf(image: &[u8]) -> LoadedElf {
    let raw = ElfFile64::<Endianness>::parse(image).expect("parse raw ELF64 headers");
    let endian = raw.endian();
    let header = raw.elf_header();
    assert_eq!(header.e_type(endian), elf::ET_EXEC);
    assert_eq!(header.e_machine(endian), elf::EM_X86_64);
    assert!(
        raw.elf_program_headers()
            .iter()
            .all(|program| program.p_type(endian) != elf::PT_INTERP),
        "bounded static loader rejects PT_INTERP"
    );
    let phoff = usize::try_from(Into::<u64>::into(header.e_phoff(endian)))
        .expect("ELF program-header offset fits usize");
    let phent = usize::from(header.e_phentsize(endian));
    let phnum = raw.elf_program_headers().len();
    let phdr_len = phent
        .checked_mul(phnum)
        .expect("ELF program-header table size overflow");
    let phdr_file_end = phoff
        .checked_add(phdr_len)
        .expect("ELF program-header file range overflow");

    let file = object::File::parse(image).expect("parse retained linux-hello ELF");
    assert_eq!(file.format(), BinaryFormat::Elf);
    assert_eq!(file.architecture(), Architecture::X86_64);
    assert_eq!(file.endianness(), Endianness::Little);
    assert!(file.is_64());
    assert_eq!(file.kind(), ObjectKind::Executable);

    let entry = usize::try_from(file.entry()).expect("ELF entry fits Vaddr");
    let vm_space = VmSpace::new();
    let mut load_segments = 0;
    let mut entry_is_executable = false;
    let mut mapped_ranges: Vec<(Vaddr, Vaddr)> = Vec::new();
    let mut phdr_address = None;
    let mut deferred_entry_page = None;

    for segment in file.segments() {
        let address = usize::try_from(segment.address()).expect("segment address fits Vaddr");
        let memory_size = usize::try_from(segment.size()).expect("segment size fits usize");
        if memory_size == 0 {
            continue;
        }
        let data = segment.data().expect("read ELF PT_LOAD bytes");
        let (file_offset, file_size) = segment.file_range();
        let file_offset = usize::try_from(file_offset).expect("PT_LOAD file offset fits usize");
        let file_size = usize::try_from(file_size).expect("PT_LOAD file size fits usize");
        assert_eq!(file_size, data.len());
        assert!(data.len() <= memory_size);
        assert_eq!(
            address % PAGE_SIZE,
            file_offset % PAGE_SIZE,
            "PT_LOAD address and file offset must be page-congruent"
        );
        let alignment = usize::try_from(segment.align()).expect("PT_LOAD alignment fits usize");
        assert!(alignment == 0 || alignment.is_power_of_two());
        let permissions = segment.permissions();
        assert!(permissions.readable(), "PT_LOAD must be readable");
        assert!(
            !(permissions.writable() && permissions.executable()),
            "Nexus loader enforces W^X"
        );

        let map_start = align_down(address);
        let segment_end = address
            .checked_add(memory_size)
            .expect("ELF segment range overflow");
        let map_end = align_up(segment_end);
        assert!(map_end <= MAX_USERSPACE_VADDR);
        assert!(
            mapped_ranges
                .iter()
                .all(|(start, end)| map_end <= *start || map_start >= *end),
            "PT_LOAD mappings must not overlap"
        );
        mapped_ranges.push((map_start, map_end));
        let map_len = map_end - map_start;
        let mut contents = vec![0; map_len];
        let data_offset = address - map_start;
        contents[data_offset..data_offset + data.len()].copy_from_slice(data);
        let flags = page_flags(permissions);
        let contains_entry = (address..segment_end).contains(&entry);
        if contains_entry && permissions.executable() {
            assert_eq!(map_len, PAGE_SIZE, "bounded entry mapping is one page");
            assert_eq!(flags, PageFlags::RX);
            assert!(deferred_entry_page.is_none());
            deferred_entry_page = Some((map_start, contents));
            entry_is_executable = true;
        } else {
            let frames = FrameAllocOptions::new()
                .alloc_segment(map_len / PAGE_SIZE)
                .expect("allocate ELF PT_LOAD frames");
            frames
                .write_bytes(0, &contents)
                .expect("populate ELF PT_LOAD frames");
            let guard = disable_preempt();
            let mut cursor = vm_space
                .cursor_mut(&guard, &(map_start..map_end))
                .expect("create ELF PT_LOAD mapping cursor");
            for frame in frames {
                cursor.map(
                    frame.into(),
                    PageProperty::new_user(flags, CachePolicy::Writeback),
                );
            }
            drop(cursor);
        }
        let file_end = file_offset
            .checked_add(file_size)
            .expect("PT_LOAD file range overflow");
        if phoff >= file_offset && phdr_file_end <= file_end {
            phdr_address = Some(
                address
                    .checked_add(phoff - file_offset)
                    .expect("AT_PHDR address overflow"),
            );
        }
        load_segments += 1;
        println!(
            "LINUX_ELF MapPlan workload=linux-hello vaddr={:#x} mem_size={} file_size={} readable={} writable={} executable={} wx=false publication={}",
            address,
            memory_size,
            data.len(),
            permissions.readable(),
            permissions.writable(),
            permissions.executable(),
            if contains_entry && permissions.executable() {
                "lazy-file-backed"
            } else {
                "eager"
            },
        );
    }

    assert!(load_segments > 0);
    assert!(
        entry_is_executable,
        "ELF entry must lie in an executable PT_LOAD"
    );
    let phdr_address = phdr_address.expect("program headers must reside in a PT_LOAD");
    let (entry_page_address, entry_page) =
        deferred_entry_page.expect("entry RX page must be deferred to the pager");
    let stack_pointer = map_initial_stack(
        &vm_space,
        InitialStackMetadata {
            entry,
            phdr_address,
            phent,
            phnum,
        },
    );
    let vm_space = Arc::new(vm_space);
    println!(
        "LINUX_ELF Loaded workload=linux-hello parser=object-0.39.1 format=ELF64 type=ET_EXEC arch=x86_64 static=true entry={:#x} entry_page={:#x} entry_publication=lazy-file-backed phdr={:#x} phent={} phnum={} load_segments={} stack_top={:#x} wx=false overlap=false",
        entry, entry_page_address, phdr_address, phent, phnum, load_segments, STACK_TOP,
    );
    LoadedElf {
        vm_space,
        entry,
        stack_pointer,
        load_segments,
        entry_page_address,
        entry_page,
    }
}

#[derive(Clone, Copy)]
struct InitialStackMetadata {
    entry: Vaddr,
    phdr_address: Vaddr,
    phent: usize,
    phnum: usize,
}

fn map_initial_stack(vm_space: &VmSpace, metadata: InitialStackMetadata) -> Vaddr {
    let stack_base = STACK_TOP - PAGE_SIZE;
    let stack_pointer = STACK_TOP - 512;
    let execfn_address = STACK_TOP - 64;
    let platform_address = STACK_TOP - 96;
    let random_address = STACK_TOP - 128;
    assert_eq!(stack_pointer % 16, 0);

    let mut contents = vec![0; PAGE_SIZE];
    write_stack_bytes(&mut contents, stack_base, execfn_address, EXECUTABLE_NAME);
    write_stack_bytes(&mut contents, stack_base, platform_address, PLATFORM_NAME);
    write_stack_bytes(&mut contents, stack_base, random_address, &TEST_RANDOM);

    let words = [
        1,
        execfn_address,
        0,
        0,
        AT_PHDR as usize,
        metadata.phdr_address,
        AT_PHENT as usize,
        metadata.phent,
        AT_PHNUM as usize,
        metadata.phnum,
        AT_PAGESZ as usize,
        PAGE_SIZE,
        AT_ENTRY as usize,
        metadata.entry,
        AT_PLATFORM as usize,
        platform_address,
        AT_RANDOM as usize,
        random_address,
        AT_EXECFN as usize,
        execfn_address,
        AT_NULL as usize,
        0,
    ];
    let table_offset = stack_pointer - stack_base;
    for (index, word) in words.into_iter().enumerate() {
        let offset = table_offset + index * core::mem::size_of::<usize>();
        contents[offset..offset + core::mem::size_of::<usize>()]
            .copy_from_slice(&word.to_le_bytes());
    }

    let frames = FrameAllocOptions::new()
        .alloc_segment(1)
        .expect("allocate Linux initial stack");
    frames
        .write_bytes(0, &contents)
        .expect("populate Linux initial stack");
    let guard = disable_preempt();
    let mut cursor = vm_space
        .cursor_mut(&guard, &(stack_base..STACK_TOP))
        .expect("create Linux stack mapping cursor");
    for frame in frames {
        cursor.map(
            frame.into(),
            PageProperty::new_user(PageFlags::RW, CachePolicy::Writeback),
        );
    }
    println!(
        "LINUX_ELF InitialStack workload=linux-hello rsp={:#x} argc=1 argv=1 envp=0 auxv=9 aligned16=true rw=true executable=false random_source=fixed_test_fixture",
        stack_pointer,
    );
    stack_pointer
}

fn write_stack_bytes(contents: &mut [u8], stack_base: Vaddr, address: Vaddr, bytes: &[u8]) {
    let offset = address
        .checked_sub(stack_base)
        .expect("stack payload address precedes stack base");
    let end = offset
        .checked_add(bytes.len())
        .expect("stack payload range overflow");
    contents[offset..end].copy_from_slice(bytes);
}

fn page_flags(permissions: object::Permissions) -> PageFlags {
    let mut flags = PageFlags::empty();
    if permissions.readable() {
        flags |= PageFlags::R;
    }
    if permissions.writable() {
        flags |= PageFlags::W;
    }
    if permissions.executable() {
        flags |= PageFlags::X;
    }
    flags
}

fn align_down(value: usize) -> usize {
    value & !(PAGE_SIZE - 1)
}

fn align_up(value: usize) -> usize {
    value
        .checked_add(PAGE_SIZE - 1)
        .expect("page alignment overflow")
        & !(PAGE_SIZE - 1)
}

fn run_linux_guest(
    scenario: Arc<PersonalityScenario>,
    code_pager: LinuxCodePager,
    vm_space: Arc<VmSpace>,
    entry: Vaddr,
    stack_pointer: Vaddr,
) {
    assert_current_user_task(GUEST_TASK_ID, &vm_space);
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(entry);
    context.set_rsp(stack_pointer);
    let mut user_mode = UserMode::new(context);

    match user_mode.execute(|| false) {
        ReturnReason::UserException => {
            code_pager.capture_instruction_fault_and_wait(&mut user_mode)
        }
        other => panic!("linux-hello entry page should fault before returning {other:?}"),
    }
    vm_space.activate();
    match user_mode.execute(|| false) {
        ReturnReason::UserSyscall => assert_eq!(user_mode.context().rax(), __NR_write as usize),
        other => panic!("linux-hello should issue write first, got {other:?}"),
    }
    let write_token = PersonalityScenario::token(WRITE_EFFECT_ID);
    let (write_waiter, write_waker) = EffectWaiter::new_pair(write_token);
    scenario.capture_write(user_mode.context(), write_waker);
    println!(
        "LINUX_GUEST Block workload=linux-hello effect={} kind=write rip={:#x}",
        WRITE_EFFECT_ID,
        user_mode.context().rip(),
    );
    write_waiter.wait();
    drop(write_waiter);
    let written = scenario.write_result();
    user_mode.context_mut().set_rax(written);

    vm_space.activate();
    match user_mode.execute(|| false) {
        ReturnReason::UserSyscall => {
            assert_eq!(user_mode.context().rax(), __NR_exit_group as usize)
        }
        other => panic!("linux-hello should issue exit_group after write, got {other:?}"),
    }
    let exit_token = PersonalityScenario::token(EXIT_EFFECT_ID);
    let (exit_waiter, exit_waker) = EffectWaiter::new_pair(exit_token);
    scenario.capture_exit(user_mode.context(), exit_waker);
    println!(
        "LINUX_GUEST Block workload=linux-hello effect={} kind=exit_group rip={:#x}",
        EXIT_EFFECT_ID,
        user_mode.context().rip(),
    );
    exit_waiter.wait();
    drop(exit_waiter);
    assert_eq!(scenario.guest_outcome(), GuestOutcome::Exited(0));
    println!(
        "LINUX_GUEST Exit workload=linux-hello status=0 resumed_after_exit=false terminal=Exited"
    );
    scenario.finish_guest();
}

fn run_scheduler_policy(
    scheduler: &'static CserScheduler,
    binding: Binding,
    vm_space: Arc<VmSpace>,
) {
    assert_current_user_task(SCHEDULER_POLICY_TASK_ID, &vm_space);
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);

    match user_mode.execute(|| false) {
        ReturnReason::UserSyscall => {
            assert_eq!(user_mode.context().rax(), POLICY_PROPOSE_GUEST)
        }
        other => panic!("Linux scheduler policy should propose the guest, got {other:?}"),
    }
    let token = PersonalityScenario::token(0);
    println!(
        "LINUX_SCHEDULER Register workload=linux-hello policy={} workload_authority_epoch={} scope={} effect={} scheduler_binding_epoch={}",
        SCHEDULER_POLICY_TASK_ID,
        token.authority_epoch,
        token.scope_id,
        token.effect_id,
        binding.binding_epoch,
    );
    assert_eq!(
        scheduler.propose_scoped(binding, GUEST_TASK_ID, token),
        ProposalResult::Prepared
    );

    vm_space.activate();
    let info = match user_mode.execute(|| false) {
        ReturnReason::UserException => match user_mode.context_mut().take_exception() {
            Some(CpuException::PageFault(info)) => info,
            other => panic!("Linux scheduler policy received unexpected exception: {other:?}"),
        },
        other => panic!("Linux scheduler policy should crash with a page fault, got {other:?}"),
    };
    assert_eq!(info.addr, EXPECTED_FAULT_ADDR);
    assert_eq!(info.error_code.bits() & 1, 0);
    assert_ne!(info.error_code.bits() & (1 << 2), 0);
    scheduler.crash_scoped(binding, "linux_scheduler_policy_user_page_fault", token);
    println!(
        "LINUX_SCHEDULER_POLICY EXIT workload=linux-hello policy={} reason=real_user_page_fault guest_proposal_committed=false",
        SCHEDULER_POLICY_TASK_ID,
    );
}

fn run_personality_v1(scenario: Arc<PersonalityScenario>, vm_space: Arc<VmSpace>) {
    assert_current_user_task(PERSONALITY_V1_TASK_ID, &vm_space);
    while !scenario.write_is_captured() {
        Task::yield_now();
    }
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
                    PORTAL_RECV => match scenario.deliver_write(PERSONALITY_V1_TASK_ID) {
                        Ok(record) => {
                            install_syscall_snapshot(user_mode.context_mut(), record);
                        }
                        Err(error) => user_mode.context_mut().set_rax(error.portal_code()),
                    },
                    PREPARE_WRITE => {
                        println!(
                            "LINUX_PERSONALITY Dispatch workload=linux-hello personality={} kind=write nr={} user_mode=true uapi=linux-raw-sys-0.12.1",
                            PERSONALITY_V1_TASK_ID, __NR_write,
                        );
                        let packet = portal_packet(user_mode.context());
                        let result = scenario.prepare_write(PERSONALITY_V1_TASK_ID, packet);
                        user_mode.context_mut().set_rax(result.portal_code());
                    }
                    BACKEND_COMMIT => {
                        let packet = portal_packet(user_mode.context());
                        let result = scenario.commit_backend(PERSONALITY_V1_TASK_ID, packet);
                        user_mode.context_mut().set_rax(result.portal_code());
                    }
                    QUEUE_STALE_WRITE => {
                        let packet = portal_packet(user_mode.context());
                        let result = scenario.queue_stale_write(PERSONALITY_V1_TASK_ID, packet);
                        user_mode.context_mut().set_rax(result.portal_code());
                    }
                    UNKNOWN_SYSCALL => {
                        log_unknown_portal(PERSONALITY_V1_TASK_ID, opcode, user_mode.context());
                        user_mode
                            .context_mut()
                            .set_rax(PortalResult::UnknownOperation.portal_code());
                    }
                    _ => {
                        log_unknown_portal(PERSONALITY_V1_TASK_ID, opcode, user_mode.context());
                        user_mode
                            .context_mut()
                            .set_rax(PortalResult::UnknownOperation.portal_code());
                    }
                }
            }
            ReturnReason::UserException => {
                let Some(CpuException::PageFault(info)) = user_mode.context_mut().take_exception()
                else {
                    println!(
                        "LINUX_PERSONALITY_V1 EXIT workload=linux-hello task={} reason=user_exception kernel_panic=false",
                        PERSONALITY_V1_TASK_ID,
                    );
                    return;
                };
                if info.addr != EXPECTED_FAULT_ADDR {
                    println!(
                        "LINUX_PERSONALITY_V1 EXIT workload=linux-hello task={} reason=unexpected_page_fault kernel_panic=false",
                        PERSONALITY_V1_TASK_ID,
                    );
                    return;
                }
                assert_eq!(scenario.crash_v1(1), 2);
                assert_eq!(
                    scenario.replay_queued_stale_write(),
                    PortalResult::StaleBinding
                );
                println!(
                    "LINUX_PERSONALITY_V1 EXIT workload=linux-hello task={} reason=page_fault",
                    PERSONALITY_V1_TASK_ID,
                );
                return;
            }
            ReturnReason::KernelEvent => {
                println!(
                    "LINUX_PERSONALITY_V1 EXIT workload=linux-hello task={} reason=kernel_event kernel_panic=false",
                    PERSONALITY_V1_TASK_ID,
                );
                return;
            }
        }
    }
}

fn run_watchdog(
    scenario: Arc<PersonalityScenario>,
    revoke_precommit: Arc<PersonalityScenario>,
    revoke_committed: Arc<PersonalityScenario>,
    old_task: Arc<Task>,
    personality_v2_exit_waker: EffectWaker,
) {
    assert_current_kernel_task(WATCHDOG_TASK_ID);
    while !scenario.has_crashed() {
        Task::yield_now();
    }
    println!(
        "LINUX_PERSONALITY Fallback workload=linux-hello binding_epoch=2 action=close_reply_gate+retain+watchdog"
    );

    let v2_vm = Arc::new(create_vm_space(PERSONALITY_V2_PROGRAM));
    let v2_state = scenario.clone();
    let v2_task_vm = v2_vm.clone();
    let v2_task = Arc::new(
        TaskOptions::new(move || {
            run_personality_v2(v2_state, revoke_precommit, revoke_committed, v2_task_vm);
            assert!(personality_v2_exit_waker.wake_up());
        })
        .data(TaskData::new(PERSONALITY_V2_TASK_ID, Some(v2_vm.clone())))
        .build()
        .expect("build fresh Linux personality v2 task"),
    );
    assert!(!Arc::ptr_eq(&old_task, &v2_task));
    println!(
        "LINUX_PERSONALITY FreshSpawn workload=linux-hello task={} vm=fresh user_mode=constructed_in_task binding_epoch=2",
        PERSONALITY_V2_TASK_ID,
    );
    v2_task.run();
}

fn run_personality_v2(
    scenario: Arc<PersonalityScenario>,
    revoke_precommit: Arc<PersonalityScenario>,
    revoke_committed: Arc<PersonalityScenario>,
    vm_space: Arc<VmSpace>,
) {
    assert_current_user_task(PERSONALITY_V2_TASK_ID, &vm_space);
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);

    loop {
        vm_space.activate();
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => match user_mode.context().rax() {
                RECOVERY_SNAPSHOT => {
                    let result = scenario.recovery_snapshot(PERSONALITY_V2_TASK_ID, 2);
                    match result {
                        Ok(record) => {
                            install_syscall_snapshot(user_mode.context_mut(), record);
                        }
                        Err(error) => user_mode.context_mut().set_rax(error.portal_code()),
                    }
                }
                READY => {
                    let result = scenario.ready(PERSONALITY_V2_TASK_ID, 2);
                    user_mode.context_mut().set_rax(result.portal_code());
                }
                REBIND => {
                    let result = scenario.rebind(PERSONALITY_V2_TASK_ID, 2);
                    user_mode.context_mut().set_rax(result.portal_code());
                }
                RECOVER_NEXT => match scenario.recover_next(PERSONALITY_V2_TASK_ID, 2) {
                    Ok(record) => {
                        install_syscall_snapshot(user_mode.context_mut(), record);
                        println!(
                            "LINUX_PERSONALITY Dispatch workload=linux-hello personality={} kind=write nr={} user_mode=true recovered=true uapi=linux-raw-sys-0.12.1",
                            PERSONALITY_V2_TASK_ID, record.number,
                        );
                    }
                    Err(error) => user_mode.context_mut().set_rax(error.portal_code()),
                },
                ADOPT => {
                    let packet = portal_packet(user_mode.context());
                    let before = scenario.semantic_projection();
                    let (result, adopted) = scenario.adopt(PERSONALITY_V2_TASK_ID, packet);
                    if let Some(record) = adopted {
                        install_portal_token(user_mode.context_mut(), record.token);
                    }
                    log_semantic_portal_result(
                        false,
                        "Adopt",
                        PERSONALITY_V2_TASK_ID,
                        ADOPT,
                        packet,
                        result,
                        before,
                        scenario.semantic_projection(),
                    );
                    user_mode.context_mut().set_rax(result.portal_code());
                }
                BACKEND_COMMIT => {
                    let packet = portal_packet(user_mode.context());
                    let before = scenario.semantic_projection();
                    let result = scenario.commit_backend(PERSONALITY_V2_TASK_ID, packet);
                    log_semantic_portal_result(
                        false,
                        "BackendCommit",
                        PERSONALITY_V2_TASK_ID,
                        BACKEND_COMMIT,
                        packet,
                        result,
                        before,
                        scenario.semantic_projection(),
                    );
                    user_mode.context_mut().set_rax(result.portal_code());
                }
                REPLY_WRITE => {
                    let packet = portal_packet(user_mode.context());
                    let stage = scenario.write_reply_stage(packet);
                    let before = scenario.semantic_projection();
                    let result = scenario.reply_write(PERSONALITY_V2_TASK_ID, packet, stage);
                    log_semantic_portal_result(
                        false,
                        stage,
                        PERSONALITY_V2_TASK_ID,
                        REPLY_WRITE,
                        packet,
                        result,
                        before,
                        scenario.semantic_projection(),
                    );
                    user_mode.context_mut().set_rax(result.portal_code());
                }
                REVOKE_PROBE_SETUP => {
                    let probe = match user_mode.context().rdi() {
                        0 => Some(revoke_precommit.as_ref()),
                        1 => Some(revoke_committed.as_ref()),
                        _ => None,
                    };
                    match probe
                        .ok_or(PortalResult::IdentityMismatch)
                        .and_then(|probe| probe.capture_probe_write(PERSONALITY_V2_TASK_ID))
                    {
                        Ok(record) => {
                            install_portal_token(user_mode.context_mut(), record.token);
                            user_mode
                                .context_mut()
                                .set_rax(PortalResult::Applied.portal_code());
                        }
                        Err(error) => user_mode.context_mut().set_rax(error.portal_code()),
                    }
                }
                REVOKE_PROBE_PREPARE
                | REVOKE_PROBE_BACKEND_COMMIT
                | REVOKE_PROBE_BEGIN
                | REVOKE_PROBE_REPLY
                | REVOKE_PROBE_CLOSURE_NEXT
                | REVOKE_PROBE_COMPLETE => {
                    let opcode = user_mode.context().rax();
                    let packet = portal_packet(user_mode.context());
                    let probe = revoke_probe_for_scope(
                        packet.scope_id,
                        revoke_precommit.as_ref(),
                        revoke_committed.as_ref(),
                    );
                    let before = probe.map(PersonalityScenario::semantic_projection);
                    let result = match (opcode, probe) {
                        (_, None) => PortalResult::IdentityMismatch,
                        (REVOKE_PROBE_PREPARE, Some(probe)) => {
                            probe.prepare_write(PERSONALITY_V2_TASK_ID, packet)
                        }
                        (REVOKE_PROBE_BACKEND_COMMIT, Some(probe)) => {
                            probe.commit_backend(PERSONALITY_V2_TASK_ID, packet)
                        }
                        (REVOKE_PROBE_BEGIN, Some(probe)) => {
                            probe.revoke_begin(PERSONALITY_V2_TASK_ID, packet)
                        }
                        (REVOKE_PROBE_REPLY, Some(probe)) => {
                            probe.reply_write(PERSONALITY_V2_TASK_ID, packet, "post_revoke")
                        }
                        (REVOKE_PROBE_CLOSURE_NEXT, Some(probe)) => probe.closure_next(),
                        (REVOKE_PROBE_COMPLETE, Some(probe)) => probe.revoke_complete(),
                        _ => PortalResult::UnknownOperation,
                    };
                    if let (Some(probe), Some(before)) = (probe, before) {
                        let action = match opcode {
                            REVOKE_PROBE_PREPARE => "Prepare",
                            REVOKE_PROBE_BACKEND_COMMIT => "BackendCommit",
                            REVOKE_PROBE_BEGIN => "RevokeBegin",
                            REVOKE_PROBE_REPLY => "Reply",
                            REVOKE_PROBE_CLOSURE_NEXT => "ClosureNext",
                            REVOKE_PROBE_COMPLETE => "RevokeComplete",
                            _ => "Unknown",
                        };
                        log_semantic_portal_result(
                            true,
                            action,
                            PERSONALITY_V2_TASK_ID,
                            opcode,
                            packet,
                            result,
                            before,
                            probe.semantic_projection(),
                        );
                    }
                    user_mode.context_mut().set_rax(result.portal_code());
                }
                PORTAL_RECV_NEXT => {
                    while !scenario.exit_is_captured() {
                        Task::yield_now();
                    }
                    match scenario.deliver_exit(PERSONALITY_V2_TASK_ID) {
                        Ok(record) => {
                            install_syscall_snapshot(user_mode.context_mut(), record);
                            println!(
                                "LINUX_PERSONALITY Dispatch workload=linux-hello personality={} kind=exit_group nr={} user_mode=true uapi=linux-raw-sys-0.12.1",
                                PERSONALITY_V2_TASK_ID, record.number,
                            );
                        }
                        Err(error) => user_mode.context_mut().set_rax(error.portal_code()),
                    }
                }
                PREPARE_EXIT => {
                    let packet = portal_packet(user_mode.context());
                    let before = scenario.semantic_projection();
                    let result = scenario.prepare_exit(PERSONALITY_V2_TASK_ID, packet);
                    log_semantic_portal_result(
                        false,
                        "PrepareExit",
                        PERSONALITY_V2_TASK_ID,
                        PREPARE_EXIT,
                        packet,
                        result,
                        before,
                        scenario.semantic_projection(),
                    );
                    user_mode.context_mut().set_rax(result.portal_code());
                }
                COMMIT_EXIT => {
                    let packet = portal_packet(user_mode.context());
                    let before = scenario.semantic_projection();
                    let result = scenario.commit_exit(PERSONALITY_V2_TASK_ID, packet);
                    log_semantic_portal_result(
                        false,
                        "CommitExit",
                        PERSONALITY_V2_TASK_ID,
                        COMMIT_EXIT,
                        packet,
                        result,
                        before,
                        scenario.semantic_projection(),
                    );
                    user_mode.context_mut().set_rax(result.portal_code());
                }
                PERSONALITY_DONE => {
                    if scenario.exit_is_completed()
                        && revoke_precommit.revoke_is_complete(false)
                        && revoke_committed.revoke_is_complete(true)
                    {
                        user_mode
                            .context_mut()
                            .set_rax(PortalResult::Applied.portal_code());
                        println!(
                            "LINUX_PERSONALITY_V2 EXIT workload=linux-hello task={} reason=guest_exit_complete",
                            PERSONALITY_V2_TASK_ID,
                        );
                        return;
                    }
                    user_mode
                        .context_mut()
                        .set_rax(PortalResult::InvalidState.portal_code());
                }
                UNKNOWN_SYSCALL => {
                    let packet = portal_packet(user_mode.context());
                    let before = scenario.semantic_projection();
                    log_unknown_portal(
                        PERSONALITY_V2_TASK_ID,
                        UNKNOWN_SYSCALL,
                        user_mode.context(),
                    );
                    log_semantic_portal_result(
                        false,
                        "Unknown",
                        PERSONALITY_V2_TASK_ID,
                        UNKNOWN_SYSCALL,
                        packet,
                        PortalResult::UnknownOperation,
                        before,
                        scenario.semantic_projection(),
                    );
                    user_mode
                        .context_mut()
                        .set_rax(PortalResult::UnknownOperation.portal_code());
                }
                opcode => {
                    let packet = portal_packet(user_mode.context());
                    let before = scenario.semantic_projection();
                    log_unknown_portal(PERSONALITY_V2_TASK_ID, opcode, user_mode.context());
                    log_semantic_portal_result(
                        false,
                        "Unknown",
                        PERSONALITY_V2_TASK_ID,
                        opcode,
                        packet,
                        PortalResult::UnknownOperation,
                        before,
                        scenario.semantic_projection(),
                    );
                    user_mode
                        .context_mut()
                        .set_rax(PortalResult::UnknownOperation.portal_code());
                }
            },
            ReturnReason::UserException => {
                println!(
                    "LINUX_PERSONALITY_V2 EXIT workload=linux-hello task={} reason=user_exception kernel_panic=false",
                    PERSONALITY_V2_TASK_ID,
                );
                return;
            }
            ReturnReason::KernelEvent => {
                println!(
                    "LINUX_PERSONALITY_V2 EXIT workload=linux-hello task={} reason=kernel_event kernel_panic=false",
                    PERSONALITY_V2_TASK_ID,
                );
                return;
            }
        }
    }
}

fn install_syscall_snapshot(context: &mut UserContext, record: SyscallRecord) {
    context.set_rax(record.number);
    context.set_rdi(record.arg0);
    context.set_rsi(record.arg1);
    context.set_rdx(record.arg2);
    install_portal_token(context, record.token);
}

fn revoke_probe_for_scope<'a>(
    scope_id: u64,
    precommit: &'a PersonalityScenario,
    committed: &'a PersonalityScenario,
) -> Option<&'a PersonalityScenario> {
    match scope_id {
        REVOKE_PRECOMMIT_SCOPE_ID => Some(precommit),
        REVOKE_COMMITTED_SCOPE_ID => Some(committed),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn log_semantic_portal_result(
    revoke: bool,
    action: &'static str,
    personality: u64,
    opcode: usize,
    packet: SyscallToken,
    result: PortalResult,
    before: SemanticProjection,
    after: SemanticProjection,
) {
    let label = if opcode == BACKEND_COMMIT || opcode == REVOKE_PROBE_BACKEND_COMMIT {
        result.backend_label()
    } else {
        result.label()
    };
    let mutation = before != after;
    if revoke {
        println!(
            "LINUX_REVOKE PortalResult action={} sender={} opcode={:#x} authority_epoch={} scope={} effect={} task={} operation={} binding_epoch={} result={} mutation={} scope_phase_before={:?} scope_phase_after={:?} authority_before={} authority_after={} binding_before={} binding_after={} supervisor_before={:?} supervisor_after={:?} write_phase_before={:?} write_phase_after={:?} exit_phase_before={:?} exit_phase_after={:?} backend_commits_before={} backend_commits_after={} replies_before={} replies_after={} resumes_before={} resumes_after={} exits_before={} exits_after={} aborts_before={} aborts_after={} terminalizations_before={} terminalizations_after={} output_publications_before={} output_publications_after={} prepared_before={} prepared_after={} wakers_before={} wakers_after={} live_effects_before={} live_effects_after={} closure_target_before={} closure_target_after={} closure_steps_before={} closure_steps_after={} waker_takes_before={} waker_takes_after={} wake_publications_before={} wake_publications_after={}",
            action,
            personality,
            opcode,
            packet.authority_epoch,
            packet.scope_id,
            packet.effect_id,
            packet.task_id,
            packet.operation,
            packet.binding_epoch,
            label,
            mutation,
            before.scope_phase,
            after.scope_phase,
            before.authority_epoch,
            after.authority_epoch,
            before.binding_epoch,
            after.binding_epoch,
            before.supervisor,
            after.supervisor,
            before.write_phase,
            after.write_phase,
            before.exit_phase,
            after.exit_phase,
            before.backend_commits,
            after.backend_commits,
            before.reply_publications,
            after.reply_publications,
            before.resumes,
            after.resumes,
            before.exits,
            after.exits,
            before.aborts,
            after.aborts,
            before.terminalizations,
            after.terminalizations,
            before.output_publications,
            after.output_publications,
            before.prepared_output,
            after.prepared_output,
            before.wakers,
            after.wakers,
            before.live_effects,
            after.live_effects,
            before.closure_target,
            after.closure_target,
            before.closure_steps,
            after.closure_steps,
            before.closure_waker_takes,
            after.closure_waker_takes,
            before.closure_wake_publications,
            after.closure_wake_publications,
        );
    } else {
        println!(
            "LINUX_PORTAL PortalResult action={} sender={} opcode={:#x} authority_epoch={} scope={} effect={} task={} operation={} binding_epoch={} result={} mutation={} scope_phase_before={:?} scope_phase_after={:?} authority_before={} authority_after={} binding_before={} binding_after={} supervisor_before={:?} supervisor_after={:?} write_phase_before={:?} write_phase_after={:?} exit_phase_before={:?} exit_phase_after={:?} backend_commits_before={} backend_commits_after={} replies_before={} replies_after={} resumes_before={} resumes_after={} exits_before={} exits_after={} aborts_before={} aborts_after={} terminalizations_before={} terminalizations_after={} output_publications_before={} output_publications_after={} prepared_before={} prepared_after={} wakers_before={} wakers_after={} live_effects_before={} live_effects_after={} closure_target_before={} closure_target_after={} closure_steps_before={} closure_steps_after={} waker_takes_before={} waker_takes_after={} wake_publications_before={} wake_publications_after={}",
            action,
            personality,
            opcode,
            packet.authority_epoch,
            packet.scope_id,
            packet.effect_id,
            packet.task_id,
            packet.operation,
            packet.binding_epoch,
            label,
            mutation,
            before.scope_phase,
            after.scope_phase,
            before.authority_epoch,
            after.authority_epoch,
            before.binding_epoch,
            after.binding_epoch,
            before.supervisor,
            after.supervisor,
            before.write_phase,
            after.write_phase,
            before.exit_phase,
            after.exit_phase,
            before.backend_commits,
            after.backend_commits,
            before.reply_publications,
            after.reply_publications,
            before.resumes,
            after.resumes,
            before.exits,
            after.exits,
            before.aborts,
            after.aborts,
            before.terminalizations,
            after.terminalizations,
            before.output_publications,
            after.output_publications,
            before.prepared_output,
            after.prepared_output,
            before.wakers,
            after.wakers,
            before.live_effects,
            after.live_effects,
            before.closure_target,
            after.closure_target,
            before.closure_steps,
            after.closure_steps,
            before.closure_waker_takes,
            after.closure_waker_takes,
            before.closure_wake_publications,
            after.closure_wake_publications,
        );
    }
    let namespace = if revoke {
        "LINUX_REVOKE"
    } else {
        "LINUX_PORTAL"
    };
    println!(
        "{} Projection action={} sender={} opcode={:#x} authority_epoch={} scope={} effect={} task={} operation={} binding_epoch={} result={} mutation={} scope_before={:?}:{}:{}:{:?} scope_after={:?}:{}:{}:{:?} recovery_before={}:{}:{} recovery_after={}:{}:{} write_before={}:{:?} write_after={}:{:?} exit_before={}:{:?} exit_after={}:{:?} delivery_before={}:{}:{}:{}:{}:{}:{} delivery_after={}:{}:{}:{}:{}:{}:{} prepared_before={}:{}:{:#x} prepared_after={}:{}:{:#x} queue_before={} queue_after={} wakers_before={}:{}:{}:{} wakers_after={}:{}:{}:{} live_before={} live_after={} guest_before={:?}:{} guest_after={:?}:{} closure_before={}:{}:{}:{} closure_after={}:{}:{}:{}",
        namespace,
        action,
        personality,
        opcode,
        packet.authority_epoch,
        packet.scope_id,
        packet.effect_id,
        packet.task_id,
        packet.operation,
        packet.binding_epoch,
        label,
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
        before.write_token,
        before.write_phase,
        after.write_token,
        after.write_phase,
        before.exit_token,
        before.exit_phase,
        after.exit_token,
        after.exit_phase,
        before.backend_commits,
        before.reply_publications,
        before.resumes,
        before.exits,
        before.aborts,
        before.terminalizations,
        before.output_publications,
        after.backend_commits,
        after.reply_publications,
        after.resumes,
        after.exits,
        after.aborts,
        after.terminalizations,
        after.output_publications,
        before.prepared_output,
        before.prepared_output_len,
        before.prepared_output_checksum,
        after.prepared_output,
        after.prepared_output_len,
        after.prepared_output_checksum,
        before.queued_stale_write,
        after.queued_stale_write,
        before.write_waker,
        before.exit_waker,
        before.completion_waker,
        before.wakers,
        after.write_waker,
        after.exit_waker,
        after.completion_waker,
        after.wakers,
        before.live_effects,
        after.live_effects,
        before.guest_outcome,
        before.guest_finished,
        after.guest_outcome,
        after.guest_finished,
        before.closure_target,
        before.closure_steps,
        before.closure_waker_takes,
        before.closure_wake_publications,
        after.closure_target,
        after.closure_steps,
        after.closure_waker_takes,
        after.closure_wake_publications,
    );
}

fn log_unknown_portal(personality: u64, opcode: usize, context: &UserContext) {
    let packet = portal_packet(context);
    println!(
        "LINUX_PORTAL REJECT sender={} opcode={:#x} authority_epoch={} scope={} effect={} task={} operation={} binding_epoch={} result=UnknownOperation mutation=false kernel_panic=false",
        personality,
        opcode,
        packet.authority_epoch,
        packet.scope_id,
        packet.effect_id,
        packet.task_id,
        packet.operation,
        packet.binding_epoch,
    );
}

fn install_portal_token(context: &mut UserContext, token: SyscallToken) {
    context.set_r10(token.authority_epoch as usize);
    context.set_r12(token.scope_id as usize);
    context.set_r8(token.effect_id as usize);
    context.set_r13(token.task_id as usize);
    context.set_r14(token.operation as usize);
    context.set_r9(token.binding_epoch as usize);
}

fn portal_packet(context: &UserContext) -> SyscallToken {
    SyscallToken {
        authority_epoch: context.r10() as u64,
        scope_id: context.r12() as u64,
        effect_id: context.r8() as u64,
        task_id: context.r13() as u64,
        operation: context.r14() as u64,
        binding_epoch: context.r9() as u64,
    }
}

fn assert_current_user_task(expected_id: u64, vm_space: &Arc<VmSpace>) {
    let current = Task::current().expect("Linux slice user task runs in an OSTD task");
    let data = current
        .data()
        .downcast_ref::<TaskData>()
        .expect("Linux slice task carries Nexus TaskData");
    assert_eq!(data.id, expected_id);
    assert!(
        data.vm_space
            .as_ref()
            .is_some_and(|vm| Arc::ptr_eq(vm, vm_space))
    );
}

fn assert_current_kernel_task(expected_id: u64) {
    let current = Task::current().expect("Linux watchdog runs in an OSTD task");
    let data = current
        .data()
        .downcast_ref::<TaskData>()
        .expect("Linux watchdog carries Nexus TaskData");
    assert_eq!(data.id, expected_id);
    assert!(data.vm_space.is_none());
}
