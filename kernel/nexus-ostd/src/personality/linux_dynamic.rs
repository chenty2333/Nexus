// SPDX-License-Identifier: MPL-2.0

//! Bounded dynamic-PIE `execve` recovery slice.
//!
//! The retained fixed launcher really enters through Linux `execve(2)`.  The
//! replacement ET_DYN main, interpreter, initial stack, and variant-II TLS are
//! built in a fresh `VmSpace`, while a common [`EffectRegistry`] owns one
//! `ExecTransaction`, every staged PT_LOAD, initial TLS/TCB, and stack effect.
//! Personality v1 crashes
//! before the transaction commits; a fresh v2 must snapshot, become ready,
//! rebind, and explicitly adopt every effect before the one `ExecCommit` may
//! publish the replacement image.
//!
//! This is intentionally one CPU, one process task, and one TLS-bearing task.
//! OSTD 0.18 does not store FS base in `UserContext`, so every user transition
//! in this module explicitly loads and saves the task-local [`FsBase`].

use alloc::{
    collections::BTreeSet,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};

use linux_raw_sys::general::{__NR_execve, __NR_exit, __NR_write};
use ostd::{
    arch::cpu::context::{CpuException, FsBase, UserContext},
    mm::{FallibleVmRead, PAGE_SIZE, VmSpace, VmWriter},
    prelude::*,
    sync::SpinLock,
    task::TaskOptions,
    user::{ReturnReason, UserMode},
};

use crate::{
    TaskData, USER_MAP_ADDR,
    effect::{EffectToken, EffectWaiter, EffectWaker},
    effect_registry::{
        CommitMetadata, CommitOutcome, CreditCharge, CreditClass, CreditLimit, EffectKey,
        EffectPhase, EffectRegistry, EffectView, OperationClass, PortalHandle, PublicationMode,
        PublicationTicket, RecoveryItem, RecoverySnapshot, RegisterRequest, RegistryError,
        RegistryProjection, ResourceKey, ScopeConfig, ScopeKey, ScopePhase, SyscallDescriptor,
        TaskKey, TerminalRequest,
    },
    linux_loader::{
        ImageRole, LINUX_STACK_TOP, LoadedStaticImage, StagedDynamicImage, load_static_image,
        stage_dynamic_pie,
    },
    linux_runtime::PublicationWork,
};

const SCOPE: ScopeKey = ScopeKey::new(70, 1);
const GUEST: TaskKey = TaskKey::new(800, 1);
const PERSONALITY_V1: TaskKey = TaskKey::new(801, 1);
const PERSONALITY_V2: TaskKey = TaskKey::new(802, 1);
const AUTHORITY_EPOCH: u64 = 131;
const BINDING_EPOCH: u64 = 1;

const PROCESS_RESOURCE_NAMESPACE: u32 = 0x8000;
const MAPPING_RESOURCE_NAMESPACE: u32 = 0x8001;
const PROCESS_RESOURCE: ResourceKey = ResourceKey::new(PROCESS_RESOURCE_NAMESPACE, 1, 1);
const EXEC_CREDIT: CreditClass = CreditClass::new(1);
const MAPPING_CREDIT: CreditClass = CreditClass::new(2);
const SYSCALL_CREDIT: CreditClass = CreditClass::new(3);

const OP_EXEC_TRANSACTION: OperationClass = OperationClass::new(1);
const OP_LOAD_SEGMENT: OperationClass = OperationClass::new(2);
const OP_INITIAL_TLS: OperationClass = OperationClass::new(3);
const OP_INITIAL_STACK: OperationClass = OperationClass::new(4);
const OP_WRITE: OperationClass = OperationClass::new(5);
const OP_EXIT: OperationClass = OperationClass::new(6);

const V1_OBSERVE_STAGING: usize = 0x4d79_0001;
const V2_RECOVERY_SNAPSHOT: usize = 0x4d79_0010;
const V2_READY: usize = 0x4d79_0011;
const V2_REBIND: usize = 0x4d79_0012;
const V2_RECOVER_NEXT: usize = 0x4d79_0013;
const V2_ADOPT: usize = 0x4d79_0014;
const V2_EXEC_COMMIT: usize = 0x4d79_0020;
const V2_OLD_HANDLE_PROBE: usize = 0x4d79_0021;

const EXPECTED_FAULT_ADDR: usize = 0x0080_0000;
const EXPECTED_INTERPRETER: &str = "/lib/ld-nexus-dynamic-runtime.so";
const LAUNCHER_NAME: &[u8] = b"/bin/linux-dynamic-pie-smoke\0";
const DYNAMIC_NAME: &[u8] = b"/bin/linux-dynamic-pie-main\0";
const EXPECTED_STDOUT: &[u8] = b"dynamic pie ok\n";
const EXPECTED_SEGMENTS: usize = 8;
const EXPECTED_MAPPING_EFFECTS: usize = EXPECTED_SEGMENTS + 2;
const EXPECTED_STAGING_EFFECTS: usize = EXPECTED_MAPPING_EFFECTS + 1;
const SCENARIO_DONE_EFFECT: u64 = 1_000;

const LAUNCHER_ELF: &[u8] = include_bytes!("../../guest/linux-dynamic-pie-smoke.elf");
const DYNAMIC_MAIN_ELF: &[u8] = include_bytes!("../../guest/linux-dynamic-pie-main.elf");
const DYNAMIC_INTERPRETER_ELF: &[u8] =
    include_bytes!("../../guest/linux-dynamic-runtime-interp.elf");
const PERSONALITY_V1_PROGRAM: &[u8] =
    include_bytes!("../../guest/linux-dynamic-personality-v1.bin");
const PERSONALITY_V2_PROGRAM: &[u8] =
    include_bytes!("../../guest/linux-dynamic-personality-v2.bin");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecPhase {
    Launcher,
    Staged,
    Fallback,
    Rebound,
    Committed,
    Published,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StagingKind {
    Transaction,
    Segment { image: ImageRole, ordinal: usize },
    InitialTls,
    InitialStack,
}

#[derive(Clone, Copy, Debug)]
struct StagingEffect {
    kind: StagingKind,
    effect: EffectKey,
    original: PortalHandle,
    current: PortalHandle,
}

#[derive(Clone)]
struct PublishedImage {
    vm_space: Arc<VmSpace>,
    interpreter_entry: usize,
    main_entry: usize,
    stack_pointer: usize,
    fs_base: usize,
}

/// Complete mutation witness used around an intentionally stale portal call.
///
/// It covers the scope ledger/revision, every staging-effect record and live
/// reverse-index member, plus the logical image generation and the identity of
/// any still-recoverable staging `VmSpace`.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DynamicProjection {
    scope: RegistryProjection,
    staging_views: Vec<EffectView>,
    live_effects: BTreeSet<EffectKey>,
    phase: ExecPhase,
    staged_vm_identity: Option<usize>,
    image_generation: u64,
    main_entry: usize,
    interpreter_entry: usize,
    stack_pointer: usize,
    fs_base: usize,
    commit_count: usize,
    adopted_count: usize,
    recovery_remaining: usize,
}

struct DynamicState {
    effects: EffectRegistry,
    phase: ExecPhase,
    staged: Option<StagedDynamicImage>,
    staging_effects: Vec<StagingEffect>,
    snapshot: Option<RecoverySnapshot>,
    recovery_item: Option<RecoveryItem>,
    old_image: Weak<VmSpace>,
    main_entry: usize,
    interpreter_entry: usize,
    stack_pointer: usize,
    fs_base: usize,
    main_segments: usize,
    interpreter_segments: usize,
    commit_count: usize,
    adopted_count: usize,
    stale_rejections: usize,
    stdout_publications: usize,
    write_publication_acks: usize,
    exit_publication_acks: usize,
    domain_revision: u64,
    image_generation: u64,
}

impl DynamicState {
    fn new(old_image: Weak<VmSpace>) -> Self {
        let mut effects = EffectRegistry::new();
        effects
            .create_scope(ScopeConfig {
                key: SCOPE,
                authority_epoch: AUTHORITY_EPOCH,
                binding_epoch: BINDING_EPOCH,
                supervisor: PERSONALITY_V1,
                credits: vec![
                    CreditLimit::new(EXEC_CREDIT, 1),
                    CreditLimit::new(MAPPING_CREDIT, EXPECTED_MAPPING_EFFECTS as u64),
                    CreditLimit::new(SYSCALL_CREDIT, 1),
                ],
            })
            .unwrap();
        Self {
            effects,
            phase: ExecPhase::Launcher,
            staged: None,
            staging_effects: Vec::new(),
            snapshot: None,
            recovery_item: None,
            old_image,
            main_entry: 0,
            interpreter_entry: 0,
            stack_pointer: 0,
            fs_base: 0,
            main_segments: 0,
            interpreter_segments: 0,
            commit_count: 0,
            adopted_count: 0,
            stale_rejections: 0,
            stdout_publications: 0,
            write_publication_acks: 0,
            exit_publication_acks: 0,
            domain_revision: 1,
            image_generation: 1,
        }
    }

    fn projection(&self) -> DynamicProjection {
        DynamicProjection {
            scope: self.effects.scope_projection(SCOPE).unwrap(),
            staging_views: self
                .staging_effects
                .iter()
                .map(|staging| self.effects.effect_view(staging.effect).unwrap())
                .collect(),
            live_effects: self.effects.effects_for_scope(SCOPE),
            phase: self.phase,
            staged_vm_identity: self
                .staged
                .as_ref()
                .map(|staged| Arc::as_ptr(&staged.vm_space) as usize),
            image_generation: self.image_generation,
            main_entry: self.main_entry,
            interpreter_entry: self.interpreter_entry,
            stack_pointer: self.stack_pointer,
            fs_base: self.fs_base,
            commit_count: self.commit_count,
            adopted_count: self.adopted_count,
            recovery_remaining: self.effects.recovery_remaining(SCOPE).unwrap(),
        }
    }

    fn stage_exec(&mut self, descriptor: SyscallDescriptor) {
        assert_eq!(self.phase, ExecPhase::Launcher);
        assert!(self.staged.is_none());
        assert!(self.staging_effects.is_empty());

        let staged = stage_dynamic_pie(
            DYNAMIC_MAIN_ELF,
            DYNAMIC_INTERPRETER_ELF,
            DYNAMIC_NAME,
            EXPECTED_INTERPRETER,
        );
        assert_eq!(staged.interpreter_path, EXPECTED_INTERPRETER);
        assert_eq!(staged.segments.len(), EXPECTED_SEGMENTS);
        assert_ne!(staged.main_phdr, 0);
        assert_eq!(staged.main_phent, 56);
        assert!(staged.main_phnum >= staged.segments.len());
        assert_eq!(staged.tls.module_offsets.as_slice(), &[0, 16]);
        assert_eq!(staged.fs_base, staged.tls.fs_base);
        assert!(
            staged.tls.map_start < staged.fs_base && staged.fs_base < staged.tls.map_end,
            "FS base must identify the installed TCB"
        );

        self.main_segments = staged
            .segments
            .iter()
            .filter(|segment| segment.image == ImageRole::Main)
            .count();
        self.interpreter_segments = staged
            .segments
            .iter()
            .filter(|segment| segment.image == ImageRole::Interpreter)
            .count();
        assert_eq!((self.main_segments, self.interpreter_segments), (4, 4));
        self.main_entry = staged.main_entry;
        self.interpreter_entry = staged.interpreter_entry;
        self.stack_pointer = staged.stack_pointer;
        self.fs_base = staged.fs_base;

        let mapping_resources: Vec<_> = (0..EXPECTED_MAPPING_EFFECTS)
            .map(|index| ResourceKey::new(MAPPING_RESOURCE_NAMESPACE, index as u64 + 1, 1))
            .collect();
        let mut transaction_resources = vec![PROCESS_RESOURCE];
        transaction_resources.extend(mapping_resources.iter().copied());
        let transaction = self
            .effects
            .register(RegisterRequest {
                scope: SCOPE,
                task: GUEST,
                operation: OP_EXEC_TRANSACTION,
                descriptor,
                resources: transaction_resources,
                credits: vec![CreditCharge::new(EXEC_CREDIT, 1)],
                publication: PublicationMode::Required,
            })
            .unwrap();
        self.effects
            .prepare(PERSONALITY_V1, transaction.handle)
            .unwrap();
        self.staging_effects.push(StagingEffect {
            kind: StagingKind::Transaction,
            effect: transaction.identity.effect(),
            original: transaction.handle,
            current: transaction.handle,
        });

        for (index, segment) in staged.segments.iter().enumerate() {
            let role = match segment.image {
                ImageRole::Main => 1,
                ImageRole::Interpreter => 2,
                ImageRole::Static => panic!("dynamic staging contains a static segment"),
            };
            let registered = self
                .effects
                .register(RegisterRequest {
                    scope: SCOPE,
                    task: GUEST,
                    operation: OP_LOAD_SEGMENT,
                    descriptor: SyscallDescriptor::new(
                        __NR_execve as usize,
                        [role, segment.ordinal, segment.start, segment.end, index, 0],
                    ),
                    resources: vec![mapping_resources[index]],
                    credits: vec![CreditCharge::new(MAPPING_CREDIT, 1)],
                    publication: PublicationMode::None,
                })
                .unwrap();
            self.effects
                .prepare(PERSONALITY_V1, registered.handle)
                .unwrap();
            self.staging_effects.push(StagingEffect {
                kind: StagingKind::Segment {
                    image: segment.image,
                    ordinal: segment.ordinal,
                },
                effect: registered.identity.effect(),
                original: registered.handle,
                current: registered.handle,
            });
        }

        let tls = self
            .effects
            .register(RegisterRequest {
                scope: SCOPE,
                task: GUEST,
                operation: OP_INITIAL_TLS,
                descriptor: SyscallDescriptor::new(
                    __NR_execve as usize,
                    [
                        3,
                        staged.tls.module_offsets.len(),
                        staged.tls.map_start,
                        staged.tls.map_end,
                        staged.tls.fs_base,
                        0,
                    ],
                ),
                resources: vec![mapping_resources[EXPECTED_SEGMENTS]],
                credits: vec![CreditCharge::new(MAPPING_CREDIT, 1)],
                publication: PublicationMode::None,
            })
            .unwrap();
        self.effects.prepare(PERSONALITY_V1, tls.handle).unwrap();
        self.staging_effects.push(StagingEffect {
            kind: StagingKind::InitialTls,
            effect: tls.identity.effect(),
            original: tls.handle,
            current: tls.handle,
        });

        let stack = self
            .effects
            .register(RegisterRequest {
                scope: SCOPE,
                task: GUEST,
                operation: OP_INITIAL_STACK,
                descriptor: SyscallDescriptor::new(
                    __NR_execve as usize,
                    [
                        4,
                        0,
                        LINUX_STACK_TOP - PAGE_SIZE,
                        LINUX_STACK_TOP,
                        staged.stack_pointer,
                        0,
                    ],
                ),
                resources: vec![mapping_resources[EXPECTED_SEGMENTS + 1]],
                credits: vec![CreditCharge::new(MAPPING_CREDIT, 1)],
                publication: PublicationMode::None,
            })
            .unwrap();
        self.effects.prepare(PERSONALITY_V1, stack.handle).unwrap();
        self.staging_effects.push(StagingEffect {
            kind: StagingKind::InitialStack,
            effect: stack.identity.effect(),
            original: stack.handle,
            current: stack.handle,
        });

        self.staged = Some(staged);
        self.phase = ExecPhase::Staged;
        self.effects.check_invariants().unwrap();
        let projection = self.effects.scope_projection(SCOPE).unwrap();
        assert_eq!(projection.live_effects, EXPECTED_STAGING_EFFECTS);
        assert_eq!(projection.credits.held, EXPECTED_STAGING_EFFECTS as u64);
        assert_eq!(projection.credits.committed, 0);
        println!(
            "LINUX_DYNAMIC Stage main_segments={} interpreter_segments={} tls_modules=2 tls_effects=1 stack=initial stack_effects=1 registry_effects={} credits_held={} committed=false",
            self.main_segments,
            self.interpreter_segments,
            projection.live_effects,
            projection.credits.held,
        );
    }

    fn observe_v1_staging(&self) -> bool {
        if self.phase != ExecPhase::Staged
            || self.staged.is_none()
            || self.staging_effects.len() != EXPECTED_STAGING_EFFECTS
            || self.commit_count != 0
        {
            return false;
        }
        let projection = self.effects.scope_projection(SCOPE).unwrap();
        projection.binding_epoch == BINDING_EPOCH
            && projection.supervisor == Some(PERSONALITY_V1)
            && projection.live_effects == EXPECTED_STAGING_EFFECTS
            && projection.credits.held == EXPECTED_STAGING_EFFECTS as u64
            && self.staging_effects.iter().all(|staging| {
                let view = self.effects.effect_view(staging.effect).unwrap();
                view.phase == EffectPhase::Prepared && view.commit.is_none()
            })
    }

    fn crash_v1(&mut self) {
        assert!(self.observe_v1_staging());
        let receipt = self.effects.crash(SCOPE, PERSONALITY_V1).unwrap();
        assert_eq!(receipt.previous_binding_epoch, BINDING_EPOCH);
        assert_eq!(receipt.binding_epoch, BINDING_EPOCH + 1);
        assert_eq!(receipt.cohort.len(), EXPECTED_STAGING_EFFECTS);
        self.phase = ExecPhase::Fallback;
        self.effects.check_invariants().unwrap();
        println!(
            "LINUX_DYNAMIC_PERSONALITY Crash task={} binding_before={} binding_after={} cohort={} staging_recoverable=true",
            PERSONALITY_V1.id(),
            receipt.previous_binding_epoch,
            receipt.binding_epoch,
            receipt.cohort.len(),
        );
    }

    fn recovery_snapshot(&mut self) -> usize {
        assert_eq!(self.phase, ExecPhase::Fallback);
        assert!(self.snapshot.is_none());
        let snapshot = self
            .effects
            .recovery_snapshot(SCOPE, PERSONALITY_V2)
            .unwrap();
        assert_eq!(snapshot.binding_epoch, BINDING_EPOCH + 1);
        assert_eq!(snapshot.effects.len(), EXPECTED_STAGING_EFFECTS);
        assert!(snapshot.effects.iter().all(|effect| {
            effect.binding_epoch == BINDING_EPOCH && effect.phase == EffectPhase::Prepared
        }));
        println!(
            "LINUX_DYNAMIC_RECOVERY Snapshot replacement={} binding={} revision={} effects={} immutable=true",
            PERSONALITY_V2.id(),
            snapshot.binding_epoch,
            snapshot.revision,
            snapshot.effects.len(),
        );
        self.snapshot = Some(snapshot);
        0
    }

    fn ready(&mut self) -> usize {
        assert_eq!(self.phase, ExecPhase::Fallback);
        let snapshot = self.snapshot.as_ref().expect("snapshot precedes Ready");
        self.effects.ready(SCOPE, PERSONALITY_V2, snapshot).unwrap();
        println!(
            "LINUX_DYNAMIC_RECOVERY Ready replacement={} snapshot_binding={} result=Applied",
            PERSONALITY_V2.id(),
            snapshot.binding_epoch,
        );
        0
    }

    fn rebind(&mut self) -> usize {
        assert_eq!(self.phase, ExecPhase::Fallback);
        let receipt = self.effects.rebind(SCOPE, PERSONALITY_V2).unwrap();
        assert_eq!(receipt.binding_epoch, BINDING_EPOCH + 1);
        assert_eq!(receipt.supervisor, PERSONALITY_V2);
        self.phase = ExecPhase::Rebound;
        println!(
            "LINUX_DYNAMIC_RECOVERY Rebind replacement={} binding={} result=Applied",
            PERSONALITY_V2.id(),
            receipt.binding_epoch,
        );
        0
    }

    fn recover_next(&mut self) -> usize {
        assert_eq!(self.phase, ExecPhase::Rebound);
        assert!(
            self.recovery_item.is_none(),
            "each item must be adopted explicitly"
        );
        match self.effects.recover_next(SCOPE, PERSONALITY_V2).unwrap() {
            Some(item) => {
                assert_eq!(item.phase, EffectPhase::Prepared);
                assert!(item.commit.is_none());
                self.recovery_item = Some(item);
                0
            }
            None => {
                assert_eq!(self.effects.recovery_remaining(SCOPE).unwrap(), 0);
                self.reject_old_handle_unchanged("precommit");
                1
            }
        }
    }

    fn adopt_current(&mut self) -> usize {
        assert_eq!(self.phase, ExecPhase::Rebound);
        let item = self
            .recovery_item
            .take()
            .expect("RecoverNext selects one effect before Adopt");
        let effect = item.handle.effect();
        let new_handle = self
            .effects
            .adopt(SCOPE, PERSONALITY_V2, item.handle)
            .unwrap();
        let staging = self
            .staging_effects
            .iter_mut()
            .find(|staging| staging.effect == effect)
            .expect("recovery cohort contains only staging effects");
        assert_eq!(staging.current, staging.original);
        staging.current = new_handle;
        self.adopted_count += 1;
        let kind = match staging.kind {
            StagingKind::Transaction => "exec",
            StagingKind::Segment { .. } => "segment",
            StagingKind::InitialTls => "tls",
            StagingKind::InitialStack => "stack",
        };
        println!(
            "LINUX_DYNAMIC_RECOVERY Adopt index={} effect={} kind={} old_binding={} new_binding={} explicit=true",
            self.adopted_count,
            effect.id(),
            kind,
            item.handle.binding_epoch(),
            new_handle.binding_epoch(),
        );
        0
    }

    fn prepare_exec_commit(&mut self) -> PublicationWork<PublishedImage> {
        assert_eq!(self.phase, ExecPhase::Rebound);
        assert!(self.recovery_item.is_none());
        assert_eq!(self.adopted_count, EXPECTED_STAGING_EFFECTS);
        assert_eq!(self.effects.recovery_remaining(SCOPE).unwrap(), 0);
        assert_eq!(self.commit_count, 0);
        assert!(self.staging_effects.iter().all(|staging| {
            staging.current.binding_epoch() == BINDING_EPOCH + 1
                && self.effects.effect_view(staging.effect).unwrap().phase == EffectPhase::Prepared
        }));

        let commits: Vec<_> = self
            .staging_effects
            .iter()
            .map(|staging| {
                (
                    staging.current,
                    CommitMetadata::new(0, self.domain_revision),
                )
            })
            .collect();
        let outcomes = self
            .effects
            .commit_with_moves(PERSONALITY_V2, &commits, &[])
            .unwrap();
        assert_eq!(outcomes.len(), EXPECTED_STAGING_EFFECTS);
        assert!(
            outcomes
                .iter()
                .all(|outcome| matches!(outcome, CommitOutcome::Applied(_)))
        );
        self.domain_revision += 1;
        self.commit_count = 1;

        let mut transaction_ticket = None;
        for staging in &self.staging_effects {
            let terminal = self
                .effects
                .stage_terminal(
                    PERSONALITY_V2,
                    staging.current,
                    TerminalRequest::completed(0),
                )
                .unwrap();
            match staging.kind {
                StagingKind::Transaction => {
                    assert!(
                        transaction_ticket
                            .replace(terminal.publication.unwrap())
                            .is_none()
                    );
                }
                StagingKind::Segment { image, ordinal } => {
                    assert!(matches!(image, ImageRole::Main | ImageRole::Interpreter));
                    assert!(ordinal < 4);
                    assert!(terminal.publication.is_none());
                }
                StagingKind::InitialTls | StagingKind::InitialStack => {
                    assert!(terminal.publication.is_none());
                }
            }
        }
        self.phase = ExecPhase::Committed;
        self.effects.check_invariants().unwrap();
        let projection = self.effects.scope_projection(SCOPE).unwrap();
        assert_eq!(projection.live_effects, 0);
        assert_eq!(projection.pending_publications, 1);
        assert_eq!(projection.credits.committed, 1);

        let staged = self.staged.take().expect("one staged replacement image");
        let published = PublishedImage {
            vm_space: staged.vm_space,
            interpreter_entry: staged.interpreter_entry,
            main_entry: staged.main_entry,
            stack_pointer: staged.stack_pointer,
            fs_base: staged.fs_base,
        };
        println!(
            "LINUX_DYNAMIC ExecCommit binding={} effects={} commit_count={} atomic_batch=true pending_vm_publication=true",
            BINDING_EPOCH + 1,
            outcomes.len(),
            self.commit_count,
        );
        PublicationWork::new(transaction_ticket.unwrap(), published)
    }

    fn acknowledge_exec_publication(&mut self, ticket: &PublicationTicket) {
        assert_eq!(self.phase, ExecPhase::Committed);
        self.effects.acknowledge_publication(ticket).unwrap();
        self.phase = ExecPhase::Published;
        self.image_generation = 2;
        self.effects.check_invariants().unwrap();
        let projection = self.effects.scope_projection(SCOPE).unwrap();
        assert_eq!(projection.live_effects, 0);
        assert_eq!(projection.pending_publications, 0);
        assert_eq!(projection.credits.held, 0);
        assert_eq!(projection.credits.committed, 0);
        println!(
            "LINUX_DYNAMIC ExecPublicationAck effect={} pending_publications=0 staging_consumed={} old_image_recoverable=false",
            ticket.effect().id(),
            self.staged.is_none(),
        );
    }

    fn reject_old_handle_unchanged(&mut self, point: &'static str) {
        let transaction = self
            .staging_effects
            .first()
            .expect("transaction is first staging effect");
        assert_eq!(transaction.kind, StagingKind::Transaction);
        self.effects.check_invariants().unwrap();
        let before = self.projection();
        assert_eq!(
            self.effects.prepare(PERSONALITY_V2, transaction.original),
            Err(RegistryError::StaleBinding)
        );
        self.effects.check_invariants().unwrap();
        assert_eq!(self.projection(), before);
        self.stale_rejections += 1;
        println!(
            "LINUX_DYNAMIC OldHandleReject point={} result=StaleBinding state_unchanged=true registry_projection_unchanged=true image_projection_unchanged=true count={}",
            point, self.stale_rejections,
        );
    }

    fn finish_runtime_syscall(
        &mut self,
        descriptor: SyscallDescriptor,
        operation: OperationClass,
        result: i64,
    ) -> PublicationTicket {
        assert_eq!(self.phase, ExecPhase::Published);
        let registered = self
            .effects
            .register(RegisterRequest {
                scope: SCOPE,
                task: GUEST,
                operation,
                descriptor,
                resources: vec![PROCESS_RESOURCE],
                credits: vec![CreditCharge::new(SYSCALL_CREDIT, 1)],
                publication: PublicationMode::Required,
            })
            .unwrap();
        self.effects
            .prepare(PERSONALITY_V2, registered.handle)
            .unwrap();
        let receipt = match self
            .effects
            .commit(
                PERSONALITY_V2,
                registered.handle,
                CommitMetadata::new(result, self.domain_revision),
            )
            .unwrap()
        {
            CommitOutcome::Applied(receipt) => receipt,
            CommitOutcome::AlreadyCommitted(_) => panic!("fresh syscall already committed"),
        };
        self.domain_revision += 1;
        let terminal = self
            .effects
            .stage_terminal(
                PERSONALITY_V2,
                registered.handle,
                TerminalRequest::completed_by(result, receipt),
            )
            .unwrap();
        self.effects.check_invariants().unwrap();
        terminal.publication.expect("runtime syscall publication")
    }

    fn acknowledge_write(&mut self, ticket: &PublicationTicket) {
        assert_eq!(ticket.result(), EXPECTED_STDOUT.len() as i64);
        assert_eq!(self.stdout_publications, 0);
        self.stdout_publications = 1;
        self.effects.acknowledge_publication(ticket).unwrap();
        self.write_publication_acks += 1;
        self.effects.check_invariants().unwrap();
        println!(
            "LINUX_DYNAMIC WritePublicationAck effect={} bytes={} stdout_exact=true ack_count={}",
            ticket.effect().id(),
            EXPECTED_STDOUT.len(),
            self.write_publication_acks,
        );
    }

    fn acknowledge_exit_and_close(&mut self, ticket: &PublicationTicket) {
        assert_eq!(ticket.result(), 0);
        self.effects.acknowledge_publication(ticket).unwrap();
        self.exit_publication_acks += 1;
        println!(
            "LINUX_DYNAMIC ExitPublicationAck effect={} status=0 resumed=false ack_count={}",
            ticket.effect().id(),
            self.exit_publication_acks,
        );

        let selection = self.effects.revoke_begin(SCOPE).unwrap();
        assert!(self.effects.revoke_next(&selection).unwrap().is_none());
        self.effects.revoke_complete(&selection).unwrap();
        self.phase = ExecPhase::Revoked;
        self.effects.check_invariants().unwrap();
        let projection = self.effects.scope_projection(SCOPE).unwrap();
        assert_eq!(projection.phase, ScopePhase::Revoked);
        assert_eq!(projection.live_effects, 0);
        assert_eq!(projection.pending_publications, 0);
        assert_eq!(projection.credits.free, projection.credits.capacity);
        assert_eq!(projection.credits.held, 0);
        assert_eq!(projection.credits.committed, 0);
        println!(
            "EFFECT_REGISTRY Quiescent workload=linux-dynamic-pie live=0 pending_publications=0 credits_free={} credits_capacity={} scope=Revoked",
            projection.credits.free, projection.credits.capacity,
        );
    }

    fn assert_final(&self) {
        assert_eq!(self.phase, ExecPhase::Revoked);
        assert!(self.staged.is_none());
        assert_eq!(self.commit_count, 1);
        assert_eq!(self.adopted_count, EXPECTED_STAGING_EFFECTS);
        assert_eq!(self.stale_rejections, 2);
        assert_eq!(self.stdout_publications, 1);
        assert_eq!(self.write_publication_acks, 1);
        assert_eq!(self.exit_publication_acks, 1);
        assert_eq!(self.image_generation, 2);
        assert_eq!(self.effects.recovery_remaining(SCOPE).unwrap(), 0);
        assert!(self.old_image.upgrade().is_none());
        self.effects.check_invariants().unwrap();
    }
}

struct DynamicScenario {
    state: SpinLock<DynamicState>,
    current_vm: Arc<SpinLock<Arc<VmSpace>>>,
    done: SpinLock<Option<EffectWaker>>,
}

impl DynamicScenario {
    fn new(
        launcher_vm: Arc<VmSpace>,
        current_vm: Arc<SpinLock<Arc<VmSpace>>>,
        done: EffectWaker,
    ) -> Self {
        assert!(Arc::ptr_eq(&launcher_vm, &current_vm.lock()));
        Self {
            state: SpinLock::new(DynamicState::new(Arc::downgrade(&launcher_vm))),
            current_vm,
            done: SpinLock::new(Some(done)),
        }
    }

    fn stage_exec(&self, descriptor: SyscallDescriptor) {
        self.state.lock().stage_exec(descriptor);
    }

    fn observe_v1_staging(&self) -> usize {
        let state = self.state.lock();
        if state.observe_v1_staging() {
            println!(
                "LINUX_DYNAMIC_PERSONALITY_V1 Observe task={} staging=complete exec_committed=false result=Applied",
                PERSONALITY_V1.id(),
            );
            0
        } else {
            1
        }
    }

    fn crash_v1(&self) {
        self.state.lock().crash_v1();
    }

    fn v2_syscall(&self, number: usize) -> usize {
        match number {
            V2_RECOVERY_SNAPSHOT => self.state.lock().recovery_snapshot(),
            V2_READY => self.state.lock().ready(),
            V2_REBIND => self.state.lock().rebind(),
            V2_RECOVER_NEXT => self.state.lock().recover_next(),
            V2_ADOPT => self.state.lock().adopt_current(),
            V2_EXEC_COMMIT => {
                let work = self.state.lock().prepare_exec_commit();
                let (ticket, image) = work.into_parts();

                // The VmSpace publication is deliberately outside the
                // registry lock.  TaskData's dynamic slot makes this the same
                // image that the scheduler hook will activate on resumption.
                let previous = {
                    let mut current = self.current_vm.lock();
                    assert!(!Arc::ptr_eq(&current, &image.vm_space));
                    core::mem::replace(&mut *current, image.vm_space.clone())
                };
                drop(previous);
                println!(
                    "LINUX_DYNAMIC VmSpacePublish generation_before=1 generation_after=2 interpreter_entry={:#x} main_entry={:#x} stack={:#x} fs_base={:#x} outside_registry_lock=true",
                    image.interpreter_entry, image.main_entry, image.stack_pointer, image.fs_base,
                );
                self.state.lock().acknowledge_exec_publication(&ticket);
                0
            }
            V2_OLD_HANDLE_PROBE => {
                let mut state = self.state.lock();
                assert_eq!(state.phase, ExecPhase::Published);
                state.reject_old_handle_unchanged("postcommit");
                0
            }
            other => panic!("unexpected dynamic personality v2 syscall {other:#x}"),
        }
    }

    fn current_image(&self) -> PublishedImage {
        let state = self.state.lock();
        assert_eq!(state.phase, ExecPhase::Published);
        PublishedImage {
            vm_space: self.current_vm.lock().clone(),
            interpreter_entry: state.interpreter_entry,
            main_entry: state.main_entry,
            stack_pointer: state.stack_pointer,
            fs_base: state.fs_base,
        }
    }

    fn assert_old_image_gone(&self) {
        let state = self.state.lock();
        assert_eq!(state.phase, ExecPhase::Published);
        assert!(state.staged.is_none());
        assert!(state.old_image.upgrade().is_none());
        println!(
            "LINUX_DYNAMIC OldImage generation=1 recoverable=false strong_refs=0 exec_commit_count={}",
            state.commit_count,
        );
    }

    fn stage_write(&self, descriptor: SyscallDescriptor, bytes: &[u8]) -> PublicationTicket {
        assert_eq!(bytes, EXPECTED_STDOUT);
        self.state
            .lock()
            .finish_runtime_syscall(descriptor, OP_WRITE, EXPECTED_STDOUT.len() as i64)
    }

    fn acknowledge_write(&self, ticket: &PublicationTicket) {
        self.state.lock().acknowledge_write(ticket);
    }

    fn stage_exit(&self, descriptor: SyscallDescriptor) -> PublicationTicket {
        assert_eq!(descriptor.argument(0), 0);
        self.state
            .lock()
            .finish_runtime_syscall(descriptor, OP_EXIT, 0)
    }

    fn acknowledge_exit_and_finish(&self, ticket: &PublicationTicket) {
        {
            let mut state = self.state.lock();
            state.acknowledge_exit_and_close(ticket);
            state.assert_final();
        }
        println!(
            "LINUX_DYNAMIC_SLICE PASS workload=linux-dynamic-pie launcher_execve=true main_segments=4 interpreter_segments=4 tls=true tls_effects=1 stack_effects=1 auxv=true fsbase_explicit=true exec_commits=1 adoptions=11 stale_unchanged=2 stdout_exact=true publication_acks=3 registry_quiescent=true smp=1 tls_tasks=1"
        );
        self.done
            .lock()
            .take()
            .expect("one dynamic completion waker")
            .wake_up();
    }
}

pub(crate) fn run_linux_dynamic_slice() {
    let LoadedStaticImage {
        vm_space: launcher_vm,
        entry,
        stack_pointer,
        phdr,
        phent,
        phnum,
        segments,
    } = load_static_image(LAUNCHER_ELF, LAUNCHER_NAME);
    assert_eq!(segments.len(), 3);
    assert_ne!(phdr, 0);
    assert_eq!(phent, 56);
    assert!(phnum >= segments.len());
    let current_vm = Arc::new(SpinLock::new(launcher_vm.clone()));
    let (done_waiter, done_waker) = EffectWaiter::new_pair(EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: SCOPE.id(),
        effect_id: SCENARIO_DONE_EFFECT,
    });
    let scenario = Arc::new(DynamicScenario::new(
        launcher_vm.clone(),
        current_vm.clone(),
        done_waker,
    ));
    let task_scenario = scenario.clone();
    let task_vm = launcher_vm;
    let task = Arc::new(
        TaskOptions::new(move || run_exec_guest(task_scenario, task_vm, entry, stack_pointer))
            .data(TaskData::new_dynamic(GUEST.id(), current_vm))
            .build()
            .expect("build retained dynamic PIE task"),
    );
    println!(
        "LINUX_DYNAMIC_SLICE BEGIN workload=linux-dynamic-pie launcher=ET_EXEC exec_target=ET_DYN interpreter=ET_DYN registry=common smp=1 tls_tasks=1"
    );
    task.run();
    done_waiter.wait();
    scenario.state.lock().assert_final();
}

fn run_exec_guest(
    scenario: Arc<DynamicScenario>,
    mut vm_space: Arc<VmSpace>,
    launcher_entry: usize,
    launcher_stack: usize,
) {
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(launcher_entry);
    context.set_rsp(launcher_stack);
    let mut user_mode = UserMode::new(context);
    let mut fs_base = FsBase::new(0);
    let mut executed = false;

    loop {
        vm_space.activate();
        match execute_with_fsbase(&mut user_mode, &mut fs_base) {
            ReturnReason::UserSyscall => {
                let descriptor = syscall_descriptor(user_mode.context());
                match descriptor.number() {
                    number if number == __NR_execve as usize => {
                        assert!(!executed, "launcher issues exactly one execve");
                        assert_eq!(fs_base.addr(), 0);
                        validate_launcher_execve(&vm_space, descriptor);
                        println!(
                            "LINUX_DYNAMIC ExecveCapture task={} nr={} path=/bin/linux-dynamic-pie-main argv0=exact envp=null real_user_syscall=true",
                            GUEST.id(),
                            descriptor.number(),
                        );
                        scenario.stage_exec(descriptor);
                        run_recovery_personalities(scenario.clone());

                        let image = scenario.current_image();
                        vm_space = image.vm_space;
                        vm_space.activate();
                        user_mode = {
                            let mut replacement = UserContext::default();
                            replacement.set_rip(image.interpreter_entry);
                            replacement.set_rsp(image.stack_pointer);
                            UserMode::new(replacement)
                        };
                        fs_base = FsBase::new(image.fs_base);
                        executed = true;
                        scenario.assert_old_image_gone();
                        println!(
                            "LINUX_DYNAMIC Resume entry=interpreter rip={:#x} main_entry={:#x} stack={:#x} fs_base={:#x} auxv_at_base=true auxv_at_entry=true",
                            image.interpreter_entry,
                            image.main_entry,
                            image.stack_pointer,
                            image.fs_base,
                        );
                    }
                    number if number == __NR_write as usize => {
                        assert!(executed);
                        assert_eq!(fs_base.addr(), scenario.state.lock().fs_base);
                        assert_eq!(descriptor.argument(0), 1);
                        let bytes = read_guest_bytes(
                            &vm_space,
                            descriptor.argument(1),
                            descriptor.argument(2),
                        );
                        let ticket = scenario.stage_write(descriptor, &bytes);
                        // This line is the exact retained stdout payload.
                        println!("dynamic pie ok");
                        scenario.acknowledge_write(&ticket);
                        user_mode.context_mut().set_rax(EXPECTED_STDOUT.len());
                    }
                    number if number == __NR_exit as usize => {
                        assert!(executed);
                        assert_eq!(fs_base.addr(), scenario.state.lock().fs_base);
                        let ticket = scenario.stage_exit(descriptor);
                        scenario.acknowledge_exit_and_finish(&ticket);
                        return;
                    }
                    other => panic!("unsupported dynamic PIE syscall {other}"),
                }
            }
            ReturnReason::UserException => {
                let exception = user_mode
                    .context_mut()
                    .take_exception()
                    .expect("dynamic guest exception payload");
                panic!("unexpected dynamic guest exception {exception:?}");
            }
            ReturnReason::KernelEvent => {
                panic!("dynamic PIE slice does not use synthetic kernel events")
            }
        }
    }
}

fn run_recovery_personalities(scenario: Arc<DynamicScenario>) {
    let (v1_waiter, v1_waker) = EffectWaiter::new_pair(EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: SCOPE.id(),
        effect_id: SCENARIO_DONE_EFFECT + 1,
    });
    let v1_vm = Arc::new(crate::create_vm_space(PERSONALITY_V1_PROGRAM));
    let v1_state = scenario.clone();
    let v1_task_vm = v1_vm.clone();
    let v1_task = Arc::new(
        TaskOptions::new(move || run_personality_v1(v1_state, v1_task_vm, v1_waker))
            .data(TaskData::new(PERSONALITY_V1.id(), Some(v1_vm)))
            .build()
            .expect("build dynamic personality v1"),
    );
    v1_task.run();
    v1_waiter.wait();

    let (v2_waiter, v2_waker) = EffectWaiter::new_pair(EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: SCOPE.id(),
        effect_id: SCENARIO_DONE_EFFECT + 2,
    });
    let v2_vm = Arc::new(crate::create_vm_space(PERSONALITY_V2_PROGRAM));
    let v2_state = scenario;
    let v2_task_vm = v2_vm.clone();
    let v2_task = Arc::new(
        TaskOptions::new(move || run_personality_v2(v2_state, v2_task_vm, v2_waker))
            .data(TaskData::new(PERSONALITY_V2.id(), Some(v2_vm)))
            .build()
            .expect("build dynamic personality v2"),
    );
    println!(
        "LINUX_DYNAMIC_RECOVERY FreshSpawn task={} vm=fresh binding={} fs_base=explicit-zero",
        PERSONALITY_V2.id(),
        BINDING_EPOCH + 1,
    );
    v2_task.run();
    v2_waiter.wait();
}

fn run_personality_v1(scenario: Arc<DynamicScenario>, vm_space: Arc<VmSpace>, done: EffectWaker) {
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);
    let mut fs_base = FsBase::new(0);
    loop {
        vm_space.activate();
        match execute_with_fsbase(&mut user_mode, &mut fs_base) {
            ReturnReason::UserSyscall => {
                assert_eq!(user_mode.context().rax(), V1_OBSERVE_STAGING);
                user_mode
                    .context_mut()
                    .set_rax(scenario.observe_v1_staging());
            }
            ReturnReason::UserException => {
                let exception = user_mode.context_mut().take_exception().unwrap();
                let CpuException::PageFault(info) = exception else {
                    panic!("unexpected dynamic personality v1 exception {exception:?}")
                };
                assert_eq!(info.addr, EXPECTED_FAULT_ADDR);
                scenario.crash_v1();
                assert_eq!(fs_base.addr(), 0);
                done.wake_up();
                return;
            }
            ReturnReason::KernelEvent => panic!("dynamic personality v1 kernel event"),
        }
    }
}

fn run_personality_v2(scenario: Arc<DynamicScenario>, vm_space: Arc<VmSpace>, done: EffectWaker) {
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    context.set_rsp(USER_MAP_ADDR + ostd::mm::PAGE_SIZE - core::mem::size_of::<usize>());
    let mut user_mode = UserMode::new(context);
    let mut fs_base = FsBase::new(0);
    loop {
        vm_space.activate();
        match execute_with_fsbase(&mut user_mode, &mut fs_base) {
            ReturnReason::UserSyscall => {
                let number = user_mode.context().rax();
                let result = scenario.v2_syscall(number);
                user_mode.context_mut().set_rax(result);
            }
            ReturnReason::UserException => {
                let exception = user_mode.context_mut().take_exception().unwrap();
                let CpuException::PageFault(info) = exception else {
                    panic!("unexpected dynamic personality v2 exception {exception:?}")
                };
                assert_eq!(info.addr, 0);
                {
                    let state = scenario.state.lock();
                    assert_eq!(state.phase, ExecPhase::Published);
                    assert_eq!(state.commit_count, 1);
                    assert_eq!(state.stale_rejections, 2);
                }
                assert_eq!(fs_base.addr(), 0);
                println!(
                    "LINUX_DYNAMIC_RECOVERY V2Exit task={} reason=return_to_zero completed=true",
                    PERSONALITY_V2.id(),
                );
                done.wake_up();
                return;
            }
            ReturnReason::KernelEvent => panic!("dynamic personality v2 kernel event"),
        }
    }
}

fn execute_with_fsbase(user_mode: &mut UserMode, fs_base: &mut FsBase) -> ReturnReason {
    fs_base.load();
    let reason = user_mode.execute(|| false);
    fs_base.save();
    reason
}

fn validate_launcher_execve(vm_space: &VmSpace, descriptor: SyscallDescriptor) {
    assert_eq!(descriptor.number(), __NR_execve as usize);
    let path = read_c_string(vm_space, descriptor.argument(0), DYNAMIC_NAME.len());
    assert_eq!(path.as_slice(), &DYNAMIC_NAME[..DYNAMIC_NAME.len() - 1]);
    assert_ne!(descriptor.argument(1), 0);
    assert_eq!(descriptor.argument(2), 0);
    let argv = read_guest_bytes(
        vm_space,
        descriptor.argument(1),
        2 * core::mem::size_of::<usize>(),
    );
    let argv0 = usize::from_le_bytes(argv[..8].try_into().unwrap());
    let argv1 = usize::from_le_bytes(argv[8..16].try_into().unwrap());
    assert_eq!(argv0, descriptor.argument(0));
    assert_eq!(argv1, 0);
}

fn syscall_descriptor(context: &UserContext) -> SyscallDescriptor {
    SyscallDescriptor::new(
        context.rax(),
        [
            context.rdi(),
            context.rsi(),
            context.rdx(),
            context.r10(),
            context.r8(),
            context.r9(),
        ],
    )
}

fn read_guest_bytes(vm_space: &VmSpace, address: usize, length: usize) -> Vec<u8> {
    let mut output = vec![0; length];
    let mut source = vm_space.reader(address, length).expect("guest read range");
    let mut destination = VmWriter::from(output.as_mut_slice());
    let copied = source
        .read_fallible(&mut destination)
        .expect("copy bytes from guest");
    assert_eq!(copied, length);
    output
}

fn read_c_string(vm_space: &VmSpace, address: usize, max: usize) -> Vec<u8> {
    let bytes = read_guest_bytes(vm_space, address, max);
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .expect("bounded guest string is NUL terminated");
    bytes[..end].to_vec()
}
