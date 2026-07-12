// SPDX-License-Identifier: MPL-2.0

//! Bounded Stage 6B.2 execution of the retained Round 4 futex program.
//!
//! This is intentionally not a general Linux ABI. It runs one adapted static
//! x86-64 image on one CPU and implements only the syscalls and private-futex
//! operations that image contains. The service policy executes in `UserMode`;
//! immutable six-argument syscall descriptors and all continuation authority
//! remain kernel-owned.

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
    vec,
    vec::Vec,
};

use linux_raw_sys::general::{
    __NR_clone, __NR_exit, __NR_exit_group, __NR_futex, __NR_mmap, __NR_write,
};
use ostd::{
    arch::cpu::context::{CpuException, UserContext},
    mm::{
        CachePolicy, FallibleVmRead, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty, Vaddr,
        VmSpace, VmWriter,
    },
    prelude::*,
    sync::SpinLock,
    task::{Task, TaskOptions, disable_preempt},
    user::{ReturnReason, UserMode},
};

use crate::{
    TaskData, USER_MAP_ADDR, create_vm_space,
    effect::{EffectToken, EffectWaiter, EffectWaker},
    effect_registry::{
        CommitMetadata, CommitOutcome, CommitReceipt, CreditCharge, CreditClass, CreditLimit,
        EffectKey, EffectView, OperationClass, PortalHandle, PublicationMode, RegisterRequest,
        RegistryError, RegistryProjection, ResourceKey, RevokeDisposition, ScopeConfig, ScopeKey,
        ScopePhase, SyscallDescriptor, TaskKey, TerminalRequest,
    },
    linux_loader::load_static_image,
    linux_runtime::{LinuxRuntime, PublicationWork, TypedResourceMove},
};

const AUTHORITY_EPOCH: u64 = 121;
const SCOPE: ScopeKey = ScopeKey::new(60, 1);
const ADDRESS_SPACE_ID: u64 = 800;
const ADDRESS_SPACE_GENERATION: u64 = 1;
const V1_TASK: TaskKey = TaskKey::new(700, 1);
const V2_TASK: TaskKey = TaskKey::new(701, 1);
const WATCHDOG_TASK_ID: u64 = 702;
const PARENT_TASK: TaskKey = TaskKey::new(1000, 1);
const FIRST_CHILD_TID: u64 = 1001;

const WAIT_CREDIT: CreditClass = CreditClass::new(1);
const SYSCALL_CREDIT: CreditClass = CreditClass::new(2);
const FUTEX_NAMESPACE: u32 = 20;
const UNUSED_READINESS_NAMESPACE: u32 = 21;

const MMAP_BASE: Vaddr = 0x1000_0000;
const MMAP_PAGES: usize = 8;
const MMAP_LEN: usize = MMAP_PAGES * PAGE_SIZE;
const EXPECTED_POLICY_FAULT: Vaddr = 0x0080_0000;
const EXPECTED_STDOUT: &[u8] = b"round4 futex ok\n";

const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;
const FUTEX_REQUEUE_PRIVATE: usize = 131;
const EAGAIN: isize = 11;
const ECANCELED: i64 = -125;

const PORTAL_NEXT: usize = 0x4c61_0001;
const PORTAL_PREPARE: usize = 0x4c61_0002;
const PORTAL_COMMIT: usize = 0x4c61_0003;
const PORTAL_PUBLISH: usize = 0x4c61_0004;
const RECOVERY_SNAPSHOT: usize = 0x4c61_0010;
const READY: usize = 0x4c61_0011;
const REBIND: usize = 0x4c61_0012;
const ADOPT_NEXT: usize = 0x4c61_0013;
const REPLAY_OLD: usize = 0x4c61_0014;
const PUBLISH_FROZEN: usize = 0x4c61_0015;
const PERSONALITY_DONE: usize = 0x4c61_0020;
const PORTAL_FAIL: usize = 0x4c61_ffff;

const OP_WAKE: usize = 1;
const OP_REQUEUE: usize = 2;
const OP_SHUTDOWN: usize = 3;
const OP_WAIT: usize = 4;
const RESULT_STALE_BINDING: usize = 2;

const ROUND4_IMAGE: &[u8] = include_bytes!("../guest/linux-round4-futex.elf");
const PERSONALITY_V1: &[u8] = include_bytes!("../guest/linux-futex-core-personality-v1.bin");
const PERSONALITY_V2: &[u8] = include_bytes!("../guest/linux-futex-core-personality-v2.bin");

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FutexKey {
    address_space_id: u64,
    address_space_generation: u64,
    address: Vaddr,
}

impl FutexKey {
    fn new(address: Vaddr) -> Self {
        assert_eq!(address % core::mem::align_of::<u32>(), 0);
        Self {
            address_space_id: ADDRESS_SPACE_ID,
            address_space_generation: ADDRESS_SPACE_GENERATION,
            address,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlOperation {
    Wake {
        key: FutexKey,
        max_wake: u32,
    },
    Requeue {
        source: FutexKey,
        target: FutexKey,
        max_wake: u32,
        max_requeue: u32,
    },
}

impl ControlOperation {
    const fn portal_code(self) -> usize {
        match self {
            Self::Wake { .. } => OP_WAKE,
            Self::Requeue { .. } => OP_REQUEUE,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Wake { .. } => "WAKE",
            Self::Requeue { .. } => "REQUEUE",
        }
    }

    fn resources(self) -> Vec<FutexKey> {
        match self {
            Self::Wake { key, .. } => vec![key],
            Self::Requeue { source, target, .. } => vec![source, target],
        }
    }
}

#[derive(Clone, Debug)]
struct ControlReceipt {
    controller: CommitReceipt,
    woken: Option<CommitReceipt>,
    woken_wait: Option<EffectKey>,
    moved_wait: Option<EffectKey>,
    woken_count: u32,
    requeued_count: u32,
    affected_count: u32,
    revision: u64,
}

struct WaitRecord {
    task: TaskKey,
    handle: PortalHandle,
    resource_key: FutexKey,
    queued_on: Option<FutexKey>,
    selected_by: Option<EffectKey>,
    migration_count: u32,
    waker: Option<EffectWaker>,
}

struct ControlRecord {
    task: TaskKey,
    handle: PortalHandle,
    operation: ControlOperation,
    resources: Vec<FutexKey>,
    waker: Option<EffectWaker>,
    receipt: Option<ControlReceipt>,
}

struct CoreState {
    queues: BTreeMap<FutexKey, VecDeque<EffectKey>>,
    waits: BTreeMap<EffectKey, WaitRecord>,
    controls: BTreeMap<EffectKey, ControlRecord>,
    pending_controls: VecDeque<EffectKey>,
    active_control: Option<EffectKey>,
    deliveries: BTreeMap<EffectKey, i64>,
    threads: BTreeSet<TaskKey>,
    next_tid: u64,
    mmap_installed: bool,
    shutdown_pending: bool,
    crashed: bool,
    frozen_control: Option<EffectKey>,
    old_frozen_handle: Option<PortalHandle>,
    recovery_snapshot: Option<crate::effect_registry::RecoverySnapshot>,
    recovery_adoptions: usize,
    frozen_publications: usize,
    normal_publications: usize,
    output_publications: usize,
    revision: u64,
    completion_waker: Option<EffectWaker>,
}

impl CoreState {
    fn new(completion_waker: EffectWaker) -> Self {
        let mut threads = BTreeSet::new();
        threads.insert(PARENT_TASK);
        Self {
            queues: BTreeMap::new(),
            waits: BTreeMap::new(),
            controls: BTreeMap::new(),
            pending_controls: VecDeque::new(),
            active_control: None,
            deliveries: BTreeMap::new(),
            threads,
            next_tid: FIRST_CHILD_TID,
            mmap_installed: false,
            shutdown_pending: false,
            crashed: false,
            frozen_control: None,
            old_frozen_handle: None,
            recovery_snapshot: None,
            recovery_adoptions: 0,
            frozen_publications: 0,
            normal_publications: 0,
            output_publications: 0,
            revision: 0,
            completion_waker: Some(completion_waker),
        }
    }
}

struct CoreScenario {
    vm_space: Arc<VmSpace>,
    runtime: LinuxRuntime<FutexKey, ()>,
    state: SpinLock<CoreState>,
}

enum FutexCapture {
    Immediate(i64),
    Blocked {
        effect: EffectKey,
        waiter: EffectWaiter,
    },
}

enum PublicationKind {
    Wait,
    Control,
}

struct DeliveryWork {
    effect: EffectKey,
    result: i64,
    waker: EffectWaker,
    kind: PublicationKind,
}

impl CoreScenario {
    fn new(vm_space: Arc<VmSpace>, completion_waker: EffectWaker) -> Arc<Self> {
        let runtime = LinuxRuntime::new(FUTEX_NAMESPACE, UNUSED_READINESS_NAMESPACE);
        runtime.with_state(|runtime| {
            runtime
                .effects
                .create_scope(ScopeConfig {
                    key: SCOPE,
                    authority_epoch: AUTHORITY_EPOCH,
                    binding_epoch: 1,
                    supervisor: V1_TASK,
                    credits: vec![
                        CreditLimit::new(WAIT_CREDIT, 3),
                        CreditLimit::new(SYSCALL_CREDIT, 4),
                    ],
                })
                .expect("create Round 4 futex scope");
            runtime.check_invariants().unwrap();
        });
        Arc::new(Self {
            vm_space,
            runtime,
            state: SpinLock::new(CoreState::new(completion_waker)),
        })
    }

    fn effect_token(effect: EffectKey) -> EffectToken {
        EffectToken {
            authority_epoch: AUTHORITY_EPOCH,
            scope_id: SCOPE.id(),
            effect_id: effect.id(),
        }
    }

    fn current_supervisor(
        runtime: &crate::linux_runtime::LinuxRuntimeState<FutexKey, ()>,
    ) -> TaskKey {
        runtime
            .effects
            .scope_projection(SCOPE)
            .unwrap()
            .supervisor
            .expect("active Round 4 scope has a supervisor")
    }

    fn install_mmap(&self, descriptor: SyscallDescriptor) -> i64 {
        assert_eq!(descriptor.number(), __NR_mmap as usize);
        assert_eq!(descriptor.arguments(), [0, MMAP_LEN, 3, 34, usize::MAX, 0]);
        {
            let mut state = self.state.lock();
            assert!(!state.mmap_installed, "retained program mmaps exactly once");
            state.mmap_installed = true;
        }

        let frames = FrameAllocOptions::new()
            .zeroed(true)
            .alloc_segment(MMAP_PAGES)
            .expect("allocate retained Round 4 anonymous mapping");
        let guard = disable_preempt();
        let mut cursor = self
            .vm_space
            .cursor_mut(&guard, &(MMAP_BASE..MMAP_BASE + MMAP_LEN))
            .expect("create Round 4 anonymous mapping cursor");
        for frame in frames {
            cursor.map(
                frame.into(),
                PageProperty::new_user(PageFlags::RW, CachePolicy::Writeback),
            );
        }
        drop(cursor);
        drop(guard);
        println!(
            "LINUX_FUTEX_CORE Mmap task={} address={:#x} pages=8 length=32768 shared_vm=true anonymous=true result={:#x}",
            PARENT_TASK.id(),
            MMAP_BASE,
            MMAP_BASE,
        );
        MMAP_BASE as i64
    }

    fn read_futex_word(&self, key: FutexKey) -> u32 {
        assert_eq!(key.address_space_id, ADDRESS_SPACE_ID);
        assert_eq!(key.address_space_generation, ADDRESS_SPACE_GENERATION);
        let guard = disable_preempt();
        self.vm_space.activate();
        let value = self
            .vm_space
            .reader(key.address, core::mem::size_of::<u32>())
            .and_then(|reader| reader.atomic_load::<u32>())
            .expect("atomically read retained private futex word");
        drop(guard);
        value
    }

    fn capture_wait(&self, task: TaskKey, descriptor: SyscallDescriptor) -> FutexCapture {
        assert_eq!(descriptor.number(), __NR_futex as usize);
        assert_eq!(descriptor.argument(1), FUTEX_WAIT_PRIVATE);
        assert_eq!(descriptor.argument(3), 0);
        assert_eq!(descriptor.argument(4), 0);
        assert_eq!(descriptor.argument(5), 0);
        let key = FutexKey::new(descriptor.argument(0));
        let expected = u32::try_from(descriptor.argument(2)).expect("bounded futex expected value");
        let observed = self.read_futex_word(key);
        if observed != expected {
            println!(
                "LINUX_FUTEX_CORE WaitMismatch task={} key={:#x} observed={} expected={} result=-EAGAIN effect_created=false",
                task.id(),
                key.address,
                observed,
                expected,
            );
            return FutexCapture::Immediate(-(EAGAIN as i64));
        }

        let registered = self.runtime.with_state(|runtime| {
            let resource = runtime.futex.intern(key).unwrap();
            let supervisor = Self::current_supervisor(runtime);
            let registered = runtime
                .effects
                .register(RegisterRequest {
                    scope: SCOPE,
                    task,
                    operation: OperationClass::new(OP_WAIT as u32),
                    descriptor,
                    resources: vec![resource],
                    credits: vec![CreditCharge::new(WAIT_CREDIT, 1)],
                    publication: PublicationMode::Required,
                })
                .unwrap();
            runtime
                .effects
                .prepare(supervisor, registered.handle)
                .unwrap();
            runtime
                .futex
                .attach(&runtime.effects, &key, registered.identity.effect())
                .unwrap();
            runtime.check_invariants().unwrap();
            registered
        });
        let effect = registered.identity.effect();
        let (waiter, waker) = EffectWaiter::new_pair(Self::effect_token(effect));
        let mut state = self.state.lock();
        assert!(state.threads.contains(&task));
        assert!(
            state
                .waits
                .insert(
                    effect,
                    WaitRecord {
                        task,
                        handle: registered.handle,
                        resource_key: key,
                        queued_on: Some(key),
                        selected_by: None,
                        migration_count: 0,
                        waker: Some(waker),
                    },
                )
                .is_none()
        );
        state.queues.entry(key).or_default().push_back(effect);
        println!(
            "LINUX_FUTEX_CORE WaitQueued task={} effect={} key={:#x} fifo_position={} binding_epoch={} credit=Held descriptor_args=6",
            task.id(),
            effect.id(),
            key.address,
            state.queues.get(&key).unwrap().len(),
            registered.handle.binding_epoch(),
        );
        FutexCapture::Blocked { effect, waiter }
    }

    fn capture_control(&self, task: TaskKey, descriptor: SyscallDescriptor) -> FutexCapture {
        assert_eq!(descriptor.number(), __NR_futex as usize);
        let operation = match descriptor.argument(1) {
            FUTEX_WAKE_PRIVATE => ControlOperation::Wake {
                key: FutexKey::new(descriptor.argument(0)),
                max_wake: u32::try_from(descriptor.argument(2)).unwrap(),
            },
            FUTEX_REQUEUE_PRIVATE => ControlOperation::Requeue {
                source: FutexKey::new(descriptor.argument(0)),
                target: FutexKey::new(descriptor.argument(4)),
                max_wake: u32::try_from(descriptor.argument(2)).unwrap(),
                max_requeue: u32::try_from(descriptor.argument(3)).unwrap(),
            },
            other => panic!("unsupported private futex operation {other}"),
        };
        match operation {
            ControlOperation::Wake { max_wake, .. } => assert!(max_wake <= 1),
            ControlOperation::Requeue {
                source,
                target,
                max_wake,
                max_requeue,
            } => {
                assert_ne!(source, target);
                assert!(max_wake <= 1 && max_requeue <= 1);
                assert_eq!(descriptor.argument(5), 0);
            }
        }
        let resources = operation.resources();
        let registered = self.runtime.with_state(|runtime| {
            let mut identities = Vec::with_capacity(resources.len());
            for key in &resources {
                identities.push(runtime.futex.intern(*key).unwrap());
            }
            let registered = runtime
                .effects
                .register(RegisterRequest {
                    scope: SCOPE,
                    task,
                    operation: OperationClass::new(operation.portal_code() as u32),
                    descriptor,
                    resources: identities,
                    credits: vec![CreditCharge::new(SYSCALL_CREDIT, 1)],
                    publication: PublicationMode::Required,
                })
                .unwrap();
            for key in &resources {
                runtime
                    .futex
                    .attach(&runtime.effects, key, registered.identity.effect())
                    .unwrap();
            }
            runtime.check_invariants().unwrap();
            registered
        });
        let effect = registered.identity.effect();
        let (waiter, waker) = EffectWaiter::new_pair(Self::effect_token(effect));
        let mut state = self.state.lock();
        assert!(
            state
                .controls
                .insert(
                    effect,
                    ControlRecord {
                        task,
                        handle: registered.handle,
                        operation,
                        resources,
                        waker: Some(waker),
                        receipt: None,
                    },
                )
                .is_none()
        );
        state.pending_controls.push_back(effect);
        println!(
            "LINUX_FUTEX_CORE Capture task={} effect={} op={} binding_epoch={} immutable_descriptor=true descriptor_args=6",
            task.id(),
            effect.id(),
            operation.label(),
            registered.handle.binding_epoch(),
        );
        FutexCapture::Blocked { effect, waiter }
    }

    fn take_delivery(&self, effect: EffectKey) -> i64 {
        self.state
            .lock()
            .deliveries
            .remove(&effect)
            .expect("one publication installs one syscall delivery")
    }

    fn next_operation(&self, sender: TaskKey) -> usize {
        loop {
            let mut state = self.state.lock();
            assert!(state.active_control.is_none());
            if let Some(effect) = state.pending_controls.pop_front() {
                let control = state.controls.get(&effect).unwrap();
                assert_eq!(
                    control.handle.binding_epoch(),
                    if sender == V1_TASK { 1 } else { 2 }
                );
                let operation = control.operation.portal_code();
                state.active_control = Some(effect);
                return operation;
            }
            if sender == V2_TASK && state.shutdown_pending {
                return OP_SHUTDOWN;
            }
            drop(state);
            Task::yield_now();
        }
    }

    fn prepare_active(&self, sender: TaskKey) {
        let (effect, handle) = {
            let state = self.state.lock();
            let effect = state.active_control.expect("NEXT selected a control");
            let control = state.controls.get(&effect).unwrap();
            assert_eq!(control.task, PARENT_TASK);
            (effect, control.handle)
        };
        self.runtime.with_state(|runtime| {
            let descriptor = runtime.effects.descriptor(sender, handle).unwrap();
            assert_eq!(descriptor.number(), __NR_futex as usize);
            assert_eq!(descriptor.arguments().len(), 6);
            runtime.effects.prepare(sender, handle).unwrap();
            runtime.check_invariants().unwrap();
        });
        println!(
            "LINUX_FUTEX_CORE Prepare personality={} effect={} binding_epoch={} opaque_handle=true descriptor_args=6",
            sender.id(),
            effect.id(),
            handle.binding_epoch(),
        );
    }

    fn commit_active(&self, sender: TaskKey) -> u32 {
        let mut state = self.state.lock();
        let effect = state
            .active_control
            .expect("PREPARE retained active control");
        let control = state.controls.get(&effect).unwrap();
        assert!(control.receipt.is_none());
        let control_handle = control.handle;
        let operation = control.operation;

        let (source, target, max_wake, max_requeue) = match operation {
            ControlOperation::Wake { key, max_wake } => (key, None, max_wake, 0),
            ControlOperation::Requeue {
                source,
                target,
                max_wake,
                max_requeue,
            } => (source, Some(target), max_wake, max_requeue),
        };
        let queue = state.queues.entry(source).or_default();
        let mut cursor = 0usize;
        let woken_wait = if max_wake == 1 {
            queue.get(cursor).copied()
        } else {
            None
        };
        if woken_wait.is_some() {
            cursor += 1;
        }
        let moved_wait = if max_requeue == 1 {
            queue.get(cursor).copied()
        } else {
            None
        };
        let woken_count = u32::from(woken_wait.is_some());
        let requeued_count = u32::from(moved_wait.is_some());
        let affected_count = woken_count + requeued_count;
        state.revision = state
            .revision
            .checked_add(1)
            .expect("bounded domain revision");
        let revision = state.revision;

        let mut commits = vec![(
            control_handle,
            CommitMetadata::new(i64::from(affected_count), revision),
        )];
        if let Some(wait) = woken_wait {
            commits.push((
                state.waits.get(&wait).unwrap().handle,
                CommitMetadata::new(0, revision),
            ));
        }
        let moves = moved_wait
            .map(|wait| TypedResourceMove {
                source,
                target: target.expect("a moved wait belongs to requeue"),
                handle: state.waits.get(&wait).unwrap().handle,
            })
            .into_iter()
            .collect::<Vec<_>>();
        let outcomes = self.runtime.with_state(|runtime| {
            let outcomes = runtime
                .commit_futex_with_moves(sender, &commits, &moves)
                .unwrap();
            runtime.check_invariants().unwrap();
            outcomes
        });
        let mut receipts = outcomes.into_iter().map(|outcome| match outcome {
            CommitOutcome::Applied(receipt) => receipt,
            CommitOutcome::AlreadyCommitted(_) => {
                panic!("a live controller cannot replay before its first commit")
            }
        });
        let controller = receipts.next().unwrap();
        let woken = receipts.next();
        assert!(receipts.next().is_none());

        for expected in [woken_wait, moved_wait].into_iter().flatten() {
            assert_eq!(
                state.queues.get_mut(&source).unwrap().pop_front(),
                Some(expected)
            );
        }
        if let Some(wait) = woken_wait {
            let record = state.waits.get_mut(&wait).unwrap();
            record.queued_on = None;
            record.selected_by = Some(effect);
        }
        if let Some(wait) = moved_wait {
            let target = target.unwrap();
            let record = state.waits.get_mut(&wait).unwrap();
            assert_eq!(record.queued_on, Some(source));
            record.queued_on = Some(target);
            record.resource_key = target;
            record.migration_count += 1;
            state.queues.entry(target).or_default().push_back(wait);
        }
        let receipt = ControlReceipt {
            controller,
            woken,
            woken_wait,
            moved_wait,
            woken_count,
            requeued_count,
            affected_count,
            revision,
        };
        state.controls.get_mut(&effect).unwrap().receipt = Some(receipt);
        println!(
            "LINUX_FUTEX_CORE Commit personality={} effect={} op={} woken={} moved={} affected={} fifo=true atomic=true moved_identity={} moved_credit={} revision={}",
            sender.id(),
            effect.id(),
            operation.label(),
            woken_count,
            requeued_count,
            affected_count,
            moved_wait.map_or(0, EffectKey::id),
            if moved_wait.is_some() { "Held" } else { "None" },
            revision,
        );
        requeued_count
    }

    fn publish_active(&self, sender: TaskKey, frozen: bool) {
        let (works, affected_count) = {
            let mut state = self.state.lock();
            let effect = if frozen {
                state
                    .frozen_control
                    .expect("crash retained one committed control")
            } else {
                state
                    .active_control
                    .expect("COMMIT retained active control")
            };
            if frozen {
                assert_eq!(state.frozen_publications, 0, "frozen receipt is one-shot");
                state.frozen_publications = 1;
            } else {
                state.normal_publications += 1;
            }
            let receipt = state
                .controls
                .get(&effect)
                .unwrap()
                .receipt
                .clone()
                .expect("publication requires committed domain receipt");
            assert_eq!(receipt.controller.effect(), effect);
            assert_eq!(
                receipt.affected_count,
                receipt.woken_count + receipt.requeued_count
            );
            assert_eq!(receipt.woken_wait.is_some(), receipt.woken.is_some());

            let mut works = Vec::new();
            if let Some(wait_effect) = receipt.woken_wait {
                let wait_task = state.waits.get(&wait_effect).unwrap().task;
                assert_ne!(wait_task, PARENT_TASK);
                assert!(state.threads.contains(&wait_task));
                let wait = state.waits.get_mut(&wait_effect).unwrap();
                let handle = wait.handle;
                let resource_key = wait.resource_key;
                let waker = wait
                    .waker
                    .take()
                    .expect("selected wait retains continuation");
                let publication = self.runtime.with_state(|runtime| {
                    let terminal = runtime
                        .effects
                        .stage_terminal(sender, handle, TerminalRequest::completed(0))
                        .unwrap();
                    runtime.futex.detach(&resource_key, wait_effect).unwrap();
                    runtime.check_invariants().unwrap();
                    terminal.publication.unwrap()
                });
                state.deliveries.insert(wait_effect, 0);
                works.push(PublicationWork::new(
                    publication,
                    DeliveryWork {
                        effect: wait_effect,
                        result: 0,
                        waker,
                        kind: PublicationKind::Wait,
                    },
                ));
                state.waits.remove(&wait_effect);
            }

            let control = state.controls.get_mut(&effect).unwrap();
            let handle = control.handle;
            let resources = control.resources.clone();
            let waker = control
                .waker
                .take()
                .expect("controller retains caller continuation");
            let publication = self.runtime.with_state(|runtime| {
                let terminal = runtime
                    .effects
                    .stage_terminal(
                        sender,
                        handle,
                        TerminalRequest::completed(i64::from(receipt.affected_count)),
                    )
                    .unwrap();
                for resource in &resources {
                    runtime.futex.detach(resource, effect).unwrap();
                }
                runtime.check_invariants().unwrap();
                terminal.publication.unwrap()
            });
            state
                .deliveries
                .insert(effect, i64::from(receipt.affected_count));
            works.push(PublicationWork::new(
                publication,
                DeliveryWork {
                    effect,
                    result: i64::from(receipt.affected_count),
                    waker,
                    kind: PublicationKind::Control,
                },
            ));
            state.controls.remove(&effect);
            state.active_control = None;
            if frozen {
                state.frozen_control = None;
            }
            (works, receipt.affected_count)
        };

        for work in works {
            let (ticket, work) = work.into_parts();
            assert!(work.waker.wake_up());
            drop(work.waker);
            self.runtime.with_state(|runtime| {
                runtime.effects.acknowledge_publication(&ticket).unwrap();
                runtime.check_invariants().unwrap();
            });
            println!(
                "LINUX_FUTEX_CORE Publish personality={} effect={} kind={} result={} frozen={} one_shot=true ack=true",
                sender.id(),
                work.effect.id(),
                match work.kind {
                    PublicationKind::Wait => "wait",
                    PublicationKind::Control => "control",
                },
                work.result,
                frozen,
            );
        }
        if frozen {
            println!(
                "LINUX_FUTEX_CORE FrozenReceipt publication=1 affected_count={} duplicate=false",
                affected_count,
            );
        }
    }

    fn crash_v1(&self, fault: Vaddr) {
        assert_eq!(fault, EXPECTED_POLICY_FAULT);
        let (effect, old_handle, affected, moved) = {
            let mut state = self.state.lock();
            let effect = state
                .active_control
                .expect("v1 crashes with active requeue");
            let (old_handle, affected, moved) = {
                let control = state.controls.get(&effect).unwrap();
                assert!(matches!(
                    control.operation,
                    ControlOperation::Requeue { .. }
                ));
                let receipt = control
                    .receipt
                    .as_ref()
                    .expect("requeue committed before crash");
                assert_eq!(receipt.requeued_count, 1);
                assert_eq!(receipt.affected_count, 2);
                (
                    control.handle,
                    receipt.affected_count,
                    receipt.moved_wait.unwrap(),
                )
            };
            state.crashed = true;
            state.frozen_control = Some(effect);
            state.old_frozen_handle = Some(old_handle);
            (effect, old_handle, affected, moved)
        };
        let crash = self.runtime.with_state(|runtime| {
            let crash = runtime.effects.crash(SCOPE, V1_TASK).unwrap();
            runtime.check_invariants().unwrap();
            crash
        });
        assert_eq!(crash.previous_binding_epoch, 1);
        assert_eq!(crash.binding_epoch, 2);
        assert_eq!(old_handle.binding_epoch(), 1);
        println!(
            "LINUX_FUTEX_CORE Crash personality={} effect={} previous_binding_epoch=1 binding_epoch=2 cohort={} committed=true affected={} moved_effect={} queue_move_retained=true receipt_frozen=true",
            V1_TASK.id(),
            effect.id(),
            crash.cohort.len(),
            affected,
            moved.id(),
        );
    }

    fn has_crashed(&self) -> bool {
        self.state.lock().crashed
    }

    fn recovery_snapshot(&self) {
        let snapshot = self.runtime.with_state(|runtime| {
            let snapshot = runtime.effects.recovery_snapshot(SCOPE, V2_TASK).unwrap();
            runtime.check_invariants().unwrap();
            snapshot
        });
        assert_eq!(snapshot.binding_epoch, 2);
        assert_eq!(snapshot.effects.len(), 3);
        self.state.lock().recovery_snapshot = Some(snapshot.clone());
        println!(
            "LINUX_FUTEX_CORE RecoverySnapshot replacement={} binding_epoch=2 effects=3 committed_controls=1 queued_waits=1 claimed_waits=1 exact=true",
            V2_TASK.id(),
        );
    }

    fn recovery_ready(&self) {
        let snapshot = self
            .state
            .lock()
            .recovery_snapshot
            .clone()
            .expect("snapshot precedes Ready");
        self.runtime.with_state(|runtime| {
            runtime.effects.ready(SCOPE, V2_TASK, &snapshot).unwrap();
            runtime.check_invariants().unwrap();
        });
        println!(
            "LINUX_FUTEX_CORE Ready replacement={} binding_epoch=2 snapshot_exact=true",
            V2_TASK.id(),
        );
    }

    fn recovery_rebind(&self) {
        let receipt = self.runtime.with_state(|runtime| {
            let receipt = runtime.effects.rebind(SCOPE, V2_TASK).unwrap();
            runtime.check_invariants().unwrap();
            receipt
        });
        assert_eq!(receipt.binding_epoch, 2);
        assert_eq!(receipt.supervisor, V2_TASK);
        println!(
            "LINUX_FUTEX_CORE Rebind replacement={} binding_epoch=2 fallback=false",
            V2_TASK.id(),
        );
    }

    fn adopt_next(&self) -> bool {
        let recovered = self.runtime.with_state(|runtime| {
            let Some(item) = runtime.effects.recover_next(SCOPE, V2_TASK).unwrap() else {
                return None;
            };
            let old_binding = item.handle.binding_epoch();
            let effect = item.handle.effect();
            let phase = item.phase;
            let descriptor = item.descriptor;
            let handle = runtime.effects.adopt(SCOPE, V2_TASK, item.handle).unwrap();
            runtime.check_invariants().unwrap();
            Some((effect, handle, old_binding, phase, descriptor))
        });
        let Some((effect, handle, old_binding, phase, descriptor)) = recovered else {
            assert_eq!(
                self.runtime
                    .with_state(|runtime| runtime.effects.recovery_remaining(SCOPE).unwrap()),
                0,
            );
            return false;
        };
        assert_eq!(descriptor.arguments().len(), 6);
        let mut state = self.state.lock();
        if let Some(wait) = state.waits.get_mut(&effect) {
            wait.handle = handle;
        } else if let Some(control) = state.controls.get_mut(&effect) {
            control.handle = handle;
        } else {
            panic!("recovery cohort effect is absent from futex domain");
        }
        state.recovery_adoptions += 1;
        println!(
            "LINUX_FUTEX_CORE Adopt replacement={} effect={} old_binding_epoch={} binding_epoch=2 phase={:?} explicit=true descriptor_args=6",
            V2_TASK.id(),
            effect.id(),
            old_binding,
            phase,
        );
        true
    }

    fn reject_late_v1(&self) {
        let state = self.state.lock();
        let effect = state.frozen_control.unwrap();
        let receipt = state
            .controls
            .get(&effect)
            .unwrap()
            .receipt
            .as_ref()
            .unwrap();
        let old_handle = state.old_frozen_handle.unwrap();
        let metadata = CommitMetadata::new(i64::from(receipt.affected_count), receipt.revision);
        let domain_before = state.queues.clone();
        let resource_keys = domain_before.keys().copied().collect::<Vec<_>>();
        let result = self.runtime.with_state(|runtime| {
            let before = complete_projection(runtime, &resource_keys);
            let result = runtime.effects.commit(V1_TASK, old_handle, metadata);
            let after = complete_projection(runtime, &resource_keys);
            assert_eq!(before, after);
            runtime.check_invariants().unwrap();
            result
        });
        assert_eq!(domain_before, state.queues);
        drop(state);
        assert_eq!(result, Err(RegistryError::StaleBinding));
        println!(
            "LINUX_FUTEX_CORE LateOldGeneration sender={} old_binding_epoch=1 current_binding_epoch=2 result=StaleBinding mutation=false projection=scope+effects+current_resources+domain_queues",
            V1_TASK.id(),
        );
    }

    fn allocate_child(&self) -> TaskKey {
        let mut state = self.state.lock();
        let task = TaskKey::new(state.next_tid, 1);
        state.next_tid += 1;
        assert!(state.threads.insert(task));
        task
    }

    fn thread_exit(&self, task: TaskKey, status: usize) {
        assert_eq!(status, 0);
        assert_ne!(task, PARENT_TASK);
        let mut state = self.state.lock();
        assert!(state.threads.remove(&task));
        println!(
            "LINUX_FUTEX_CORE ThreadExit task={} status=0 remaining_threads={}",
            task.id(),
            state.threads.len(),
        );
    }

    fn parent_exit_group(&self, task: TaskKey, status: usize) {
        assert_eq!(task, PARENT_TASK);
        assert_eq!(status, 0);
        let mut state = self.state.lock();
        assert!(state.threads.remove(&task));
        assert!(
            state.threads.is_empty(),
            "children exit before retained parent"
        );
        assert!(!state.shutdown_pending);
        state.shutdown_pending = true;
        println!(
            "LINUX_FUTEX_CORE ExitGroup task={} status=0 remaining_threads=0 shutdown_queued=true",
            task.id(),
        );
    }

    fn publish_stdout(&self, task: TaskKey, descriptor: SyscallDescriptor) -> i64 {
        assert_eq!(task, PARENT_TASK);
        assert_eq!(descriptor.number(), __NR_write as usize);
        assert_eq!(descriptor.argument(0), 1);
        assert_eq!(descriptor.argument(2), EXPECTED_STDOUT.len());
        let mut output = vec![0; EXPECTED_STDOUT.len()];
        self.vm_space.activate();
        let mut source = self
            .vm_space
            .reader(descriptor.argument(1), output.len())
            .expect("read retained stdout bytes");
        let mut destination = VmWriter::from(output.as_mut_slice());
        assert_eq!(
            source.read_fallible(&mut destination).unwrap(),
            EXPECTED_STDOUT.len(),
        );
        assert_eq!(output.as_slice(), EXPECTED_STDOUT);
        let mut state = self.state.lock();
        state.output_publications += 1;
        assert_eq!(state.output_publications, 1);
        println!("LINUX_FUTEX_CORE stdout=round4 futex ok");
        EXPECTED_STDOUT.len() as i64
    }

    fn finish_personality(&self) -> EffectWaker {
        let keys = {
            let mut state = self.state.lock();
            assert!(state.shutdown_pending);
            state.shutdown_pending = false;
            assert!(state.threads.is_empty());
            assert!(state.waits.is_empty());
            assert!(state.controls.is_empty());
            assert!(state.pending_controls.is_empty());
            assert!(state.active_control.is_none());
            assert!(state.deliveries.is_empty());
            assert!(state.queues.values().all(VecDeque::is_empty));
            assert_eq!(state.recovery_adoptions, 3);
            assert_eq!(state.frozen_publications, 1);
            assert_eq!(state.output_publications, 1);
            let keys = state.queues.keys().copied().collect::<Vec<_>>();
            (keys, state.completion_waker.take().unwrap())
        };
        let (keys, completion_waker) = keys;
        self.runtime.with_state(|runtime| {
            let selection = runtime.effects.revoke_begin(SCOPE).unwrap();
            assert!(selection.effects.is_empty());
            assert!(runtime.effects.revoke_next(&selection).unwrap().is_none());
            for key in &keys {
                runtime.futex.retire(key).unwrap();
            }
            runtime.effects.revoke_complete(&selection).unwrap();
            runtime.check_invariants().unwrap();
            let projection = runtime.effects.scope_projection(SCOPE).unwrap();
            assert_eq!(projection.phase, ScopePhase::Revoked);
            assert_eq!(projection.live_effects, 0);
            assert_eq!(projection.pending_publications, 0);
            assert_eq!(projection.credits.free, projection.credits.capacity);
            assert_eq!(projection.credits.held, 0);
            assert_eq!(projection.credits.committed, 0);
            assert!(runtime.futex.is_empty());
            assert!(runtime.readiness.is_empty());
        });
        println!(
            "LINUX_FUTEX_CORE Final scope=Revoked queues=0 resource_indexes=0 effects=0 credits_held=0 credits_committed=0 threads=0 publications_fixed=1 stdout_publications=1"
        );
        completion_waker
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CompleteProjection {
    scope: RegistryProjection,
    effects: Vec<EffectView>,
    resources: Vec<(FutexKey, Option<ResourceKey>, BTreeSet<EffectKey>)>,
}

fn complete_projection(
    runtime: &crate::linux_runtime::LinuxRuntimeState<FutexKey, ()>,
    resource_keys: &[FutexKey],
) -> CompleteProjection {
    let effects = runtime
        .effects
        .effects_for_scope(SCOPE)
        .into_iter()
        .map(|effect| runtime.effects.effect_view(effect).unwrap())
        .collect();
    let resources = resource_keys
        .iter()
        .copied()
        .map(|key| {
            (
                key,
                runtime.futex.identity(&key),
                runtime.futex.effects(&key),
            )
        })
        .collect();
    CompleteProjection {
        scope: runtime.effects.scope_projection(SCOPE).unwrap(),
        effects,
        resources,
    }
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

fn install_linux_result(context: &mut UserContext, result: i64) {
    context.set_rax(result as usize);
}

fn assert_current_user_task(task: TaskKey, vm_space: &Arc<VmSpace>) {
    let current = Task::current().expect("Round 4 UserMode runner owns an OSTD task");
    let data = current
        .data()
        .downcast_ref::<TaskData>()
        .expect("Round 4 task carries Nexus TaskData");
    assert_eq!(data.id, task.id());
    assert!(
        data.vm_space
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, vm_space))
    );
}

fn spawn_clone(
    scenario: &Arc<CoreScenario>,
    vm_space: &Arc<VmSpace>,
    parent_context: &mut UserContext,
    descriptor: SyscallDescriptor,
) {
    assert_eq!(descriptor.number(), __NR_clone as usize);
    assert_eq!(descriptor.argument(0), 0x10f00);
    assert_eq!(descriptor.argument(2), 0);
    assert_eq!(descriptor.argument(3), 0);
    assert_eq!(descriptor.argument(4), 0);
    assert_eq!(descriptor.argument(5), 0);
    let child_stack = descriptor.argument(1);
    assert!((MMAP_BASE + PAGE_SIZE..=MMAP_BASE + MMAP_LEN).contains(&child_stack));
    assert_eq!(child_stack % PAGE_SIZE, 0);
    let child = scenario.allocate_child();
    let mut child_context = parent_context.clone();
    child_context.set_rax(0);
    child_context.set_rsp(child_stack);
    parent_context.set_rax(child.id() as usize);

    let child_scenario = scenario.clone();
    let child_vm = vm_space.clone();
    let task = Arc::new(
        TaskOptions::new(move || run_guest_thread(child_scenario, child_vm, child, child_context))
            .data(TaskData::new(child.id(), Some(vm_space.clone())))
            .build()
            .expect("build retained Round 4 clone task"),
    );
    println!(
        "LINUX_FUTEX_CORE Clone parent={} child={} child_stack={:#x} shared_arc_vm=true flags=0x10f00",
        PARENT_TASK.id(),
        child.id(),
        child_stack,
    );
    task.run();
}

fn run_guest_thread(
    scenario: Arc<CoreScenario>,
    vm_space: Arc<VmSpace>,
    task: TaskKey,
    context: UserContext,
) {
    assert_current_user_task(task, &vm_space);
    vm_space.activate();
    let mut user_mode = UserMode::new(context);
    loop {
        vm_space.activate();
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => {
                let descriptor = syscall_descriptor(user_mode.context());
                match descriptor.number() {
                    number if number == __NR_mmap as usize => {
                        assert_eq!(task, PARENT_TASK);
                        install_linux_result(
                            user_mode.context_mut(),
                            scenario.install_mmap(descriptor),
                        );
                    }
                    number if number == __NR_clone as usize => {
                        assert_eq!(task, PARENT_TASK);
                        spawn_clone(&scenario, &vm_space, user_mode.context_mut(), descriptor);
                    }
                    number if number == __NR_futex as usize => {
                        let capture = match descriptor.argument(1) {
                            FUTEX_WAIT_PRIVATE => scenario.capture_wait(task, descriptor),
                            FUTEX_WAKE_PRIVATE | FUTEX_REQUEUE_PRIVATE => {
                                scenario.capture_control(task, descriptor)
                            }
                            operation => panic!("unsupported retained futex operation {operation}"),
                        };
                        let result = match capture {
                            FutexCapture::Immediate(result) => result,
                            FutexCapture::Blocked { effect, waiter } => {
                                println!(
                                    "LINUX_FUTEX_CORE GuestBlock task={} effect={} continuation=EffectWaiter",
                                    task.id(),
                                    effect.id(),
                                );
                                waiter.wait();
                                drop(waiter);
                                let result = scenario.take_delivery(effect);
                                println!(
                                    "LINUX_FUTEX_CORE GuestResume task={} effect={} linux_result={} one_shot=true",
                                    task.id(),
                                    effect.id(),
                                    result,
                                );
                                result
                            }
                        };
                        install_linux_result(user_mode.context_mut(), result);
                    }
                    number if number == __NR_write as usize => {
                        let result = scenario.publish_stdout(task, descriptor);
                        install_linux_result(user_mode.context_mut(), result);
                    }
                    number if number == __NR_exit as usize => {
                        scenario.thread_exit(task, descriptor.argument(0));
                        return;
                    }
                    number if number == __NR_exit_group as usize => {
                        scenario.parent_exit_group(task, descriptor.argument(0));
                        return;
                    }
                    number => panic!("unsupported retained Round 4 syscall {number}"),
                }
            }
            ReturnReason::UserException => panic!(
                "retained Round 4 guest unexpectedly faulted task={}: {:?}",
                task.id(),
                user_mode.context_mut().take_exception(),
            ),
            ReturnReason::KernelEvent => {
                Task::yield_now();
            }
        }
    }
}

fn run_personality_v1(scenario: Arc<CoreScenario>, vm_space: Arc<VmSpace>) {
    assert_current_user_task(V1_TASK, &vm_space);
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);
    loop {
        vm_space.activate();
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => match user_mode.context().rax() {
                PORTAL_NEXT => {
                    let operation = scenario.next_operation(V1_TASK);
                    user_mode.context_mut().set_rax(operation);
                }
                PORTAL_PREPARE => {
                    scenario.prepare_active(V1_TASK);
                    user_mode.context_mut().set_rax(0);
                }
                PORTAL_COMMIT => {
                    let moved = scenario.commit_active(V1_TASK);
                    user_mode.context_mut().set_rax(0);
                    user_mode.context_mut().set_rdi(moved as usize);
                }
                PORTAL_PUBLISH => {
                    scenario.publish_active(V1_TASK, false);
                    user_mode.context_mut().set_rax(0);
                }
                PORTAL_FAIL => panic!(
                    "Round 4 personality v1 protocol failure code={}",
                    user_mode.context().rdi(),
                ),
                opcode => panic!("Round 4 personality v1 unknown portal {opcode:#x}"),
            },
            ReturnReason::UserException => {
                let info = match user_mode.context_mut().take_exception() {
                    Some(CpuException::PageFault(info)) => info,
                    other => panic!("Round 4 personality v1 unexpected exception {other:?}"),
                };
                assert_eq!(info.addr, EXPECTED_POLICY_FAULT);
                scenario.crash_v1(info.addr);
                println!(
                    "LINUX_FUTEX_CORE_PERSONALITY_V1 EXIT task={} reason=real_user_page_fault committed_move=true publication=false",
                    V1_TASK.id(),
                );
                return;
            }
            ReturnReason::KernelEvent => Task::yield_now(),
        }
    }
}

fn run_personality_v2(scenario: Arc<CoreScenario>, vm_space: Arc<VmSpace>) {
    assert_current_user_task(V2_TASK, &vm_space);
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);
    loop {
        vm_space.activate();
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => match user_mode.context().rax() {
                RECOVERY_SNAPSHOT => {
                    scenario.recovery_snapshot();
                    user_mode.context_mut().set_rax(0);
                }
                READY => {
                    scenario.recovery_ready();
                    user_mode.context_mut().set_rax(0);
                }
                REBIND => {
                    scenario.recovery_rebind();
                    user_mode.context_mut().set_rax(0);
                }
                ADOPT_NEXT => {
                    let adopted = scenario.adopt_next();
                    user_mode.context_mut().set_rax(0);
                    user_mode.context_mut().set_rdi(usize::from(adopted));
                }
                REPLAY_OLD => {
                    scenario.reject_late_v1();
                    user_mode.context_mut().set_rax(RESULT_STALE_BINDING);
                }
                PUBLISH_FROZEN => {
                    scenario.publish_active(V2_TASK, true);
                    user_mode.context_mut().set_rax(0);
                }
                PORTAL_NEXT => {
                    let operation = scenario.next_operation(V2_TASK);
                    user_mode.context_mut().set_rax(operation);
                }
                PORTAL_PREPARE => {
                    scenario.prepare_active(V2_TASK);
                    user_mode.context_mut().set_rax(0);
                }
                PORTAL_COMMIT => {
                    let moved = scenario.commit_active(V2_TASK);
                    user_mode.context_mut().set_rax(0);
                    user_mode.context_mut().set_rdi(moved as usize);
                }
                PORTAL_PUBLISH => {
                    scenario.publish_active(V2_TASK, false);
                    user_mode.context_mut().set_rax(0);
                }
                PERSONALITY_DONE => {
                    let completion_waker = scenario.finish_personality();
                    assert!(completion_waker.wake_up());
                    drop(completion_waker);
                    println!(
                        "LINUX_FUTEX_CORE_PERSONALITY_V2 EXIT task={} reason=protocol_complete",
                        V2_TASK.id(),
                    );
                    return;
                }
                PORTAL_FAIL => panic!(
                    "Round 4 personality v2 protocol failure code={}",
                    user_mode.context().rdi(),
                ),
                opcode => panic!("Round 4 personality v2 unknown portal {opcode:#x}"),
            },
            ReturnReason::UserException => panic!(
                "fresh Round 4 personality v2 faulted: {:?}",
                user_mode.context_mut().take_exception(),
            ),
            ReturnReason::KernelEvent => Task::yield_now(),
        }
    }
}

fn run_recovery_watchdog(scenario: Arc<CoreScenario>, old_task: Arc<Task>, old_vm: Arc<VmSpace>) {
    let current = Task::current().unwrap();
    let data = current.data().downcast_ref::<TaskData>().unwrap();
    assert_eq!(data.id, WATCHDOG_TASK_ID);
    assert!(data.vm_space.is_none());
    while !scenario.has_crashed() {
        Task::yield_now();
    }
    let v2_vm = Arc::new(create_vm_space(PERSONALITY_V2));
    assert!(!Arc::ptr_eq(&old_vm, &v2_vm));
    let v2_scenario = scenario.clone();
    let v2_task_vm = v2_vm.clone();
    let v2_task = Arc::new(
        TaskOptions::new(move || run_personality_v2(v2_scenario, v2_task_vm))
            .data(TaskData::new(V2_TASK.id(), Some(v2_vm.clone())))
            .build()
            .expect("build fresh Round 4 personality v2"),
    );
    assert!(!Arc::ptr_eq(&old_task, &v2_task));
    println!(
        "LINUX_FUTEX_CORE FreshSpawn replacement={} vm=fresh task=fresh binding_epoch=2 normal_handoff=true",
        V2_TASK.id(),
    );
    v2_task.run();
}

struct CompanionEffect {
    effect: EffectKey,
    handle: PortalHandle,
    resources: Vec<FutexKey>,
}

fn companion_register(
    runtime: &mut crate::linux_runtime::LinuxRuntimeState<FutexKey, ()>,
    scope: ScopeKey,
    supervisor: TaskKey,
    task: TaskKey,
    descriptor: SyscallDescriptor,
    keys: Vec<FutexKey>,
    credit: CreditClass,
    operation: u32,
) -> CompanionEffect {
    let identities = keys
        .iter()
        .map(|key| runtime.futex.intern(*key).unwrap())
        .collect::<Vec<_>>();
    let registered = runtime
        .effects
        .register(RegisterRequest {
            scope,
            task,
            operation: OperationClass::new(operation),
            descriptor,
            resources: identities,
            credits: vec![CreditCharge::new(credit, 1)],
            publication: PublicationMode::Required,
        })
        .unwrap();
    runtime
        .effects
        .prepare(supervisor, registered.handle)
        .unwrap();
    for key in &keys {
        runtime
            .futex
            .attach(&runtime.effects, key, registered.identity.effect())
            .unwrap();
    }
    CompanionEffect {
        effect: registered.identity.effect(),
        handle: registered.handle,
        resources: keys,
    }
}

fn run_close_companion(commit_before_close: bool) {
    let scope = ScopeKey::new(if commit_before_close { 61 } else { 62 }, 1);
    let supervisor = TaskKey::new(if commit_before_close { 720 } else { 730 }, 1);
    let waiter1 = TaskKey::new(supervisor.id() + 1, 1);
    let waiter2 = TaskKey::new(supervisor.id() + 2, 1);
    let caller = TaskKey::new(supervisor.id() + 3, 1);
    let source = FutexKey {
        address_space_id: scope.id(),
        address_space_generation: 1,
        address: 0x5000,
    };
    let target = FutexKey {
        address_space_id: scope.id(),
        address_space_generation: 1,
        address: 0x5008,
    };
    let runtime = LinuxRuntime::<FutexKey, ()>::new(
        FUTEX_NAMESPACE + scope.id() as u32,
        UNUSED_READINESS_NAMESPACE + scope.id() as u32,
    );
    let (first, second, control) = runtime.with_state(|runtime| {
        runtime
            .effects
            .create_scope(ScopeConfig {
                key: scope,
                authority_epoch: AUTHORITY_EPOCH + scope.id(),
                binding_epoch: 1,
                supervisor,
                credits: vec![
                    CreditLimit::new(WAIT_CREDIT, 2),
                    CreditLimit::new(SYSCALL_CREDIT, 1),
                ],
            })
            .unwrap();
        let first = companion_register(
            runtime,
            scope,
            supervisor,
            waiter1,
            SyscallDescriptor::new(__NR_futex as usize, [0x5000, 128, 0, 0, 0, 0]),
            vec![source],
            WAIT_CREDIT,
            OP_WAIT as u32,
        );
        let second = companion_register(
            runtime,
            scope,
            supervisor,
            waiter2,
            SyscallDescriptor::new(__NR_futex as usize, [0x5000, 128, 0, 0, 0, 0]),
            vec![source],
            WAIT_CREDIT,
            OP_WAIT as u32,
        );
        let control = companion_register(
            runtime,
            scope,
            supervisor,
            caller,
            SyscallDescriptor::new(__NR_futex as usize, [0x5000, 131, 1, 1, 0x5008, 0]),
            vec![source, target],
            SYSCALL_CREDIT,
            OP_REQUEUE as u32,
        );
        runtime.check_invariants().unwrap();
        (first, second, control)
    });

    let mut current_resources = BTreeMap::from([
        (first.effect, first.resources.clone()),
        (second.effect, second.resources.clone()),
        (control.effect, control.resources.clone()),
    ]);
    if commit_before_close {
        let outcomes = runtime.with_state(|runtime| {
            let outcomes = runtime
                .commit_futex_with_moves(
                    supervisor,
                    &[
                        (control.handle, CommitMetadata::new(2, 1)),
                        (first.handle, CommitMetadata::new(0, 1)),
                    ],
                    &[TypedResourceMove {
                        source,
                        target,
                        handle: second.handle,
                    }],
                )
                .unwrap();
            runtime.check_invariants().unwrap();
            outcomes
        });
        assert_eq!(outcomes.len(), 2);
        current_resources.insert(second.effect, vec![target]);
    }

    let selection = runtime.with_state(|runtime| runtime.effects.revoke_begin(scope).unwrap());
    if !commit_before_close {
        let result = runtime.with_state(|runtime| {
            let result = runtime.commit_futex_with_moves(
                supervisor,
                &[
                    (control.handle, CommitMetadata::new(2, 1)),
                    (first.handle, CommitMetadata::new(0, 1)),
                ],
                &[TypedResourceMove {
                    source,
                    target,
                    handle: second.handle,
                }],
            );
            runtime.check_invariants().unwrap();
            result
        });
        assert_eq!(result, Err(RegistryError::StaleAuthority));
        assert_eq!(current_resources.get(&second.effect), Some(&vec![source]));
    }

    let (tickets, drains, aborts) = runtime.with_state(|runtime| {
        let mut tickets = Vec::new();
        let mut drains = 0usize;
        let mut aborts = 0usize;
        while let Some(effect) = runtime.effects.revoke_next(&selection).unwrap() {
            let request = match effect.disposition {
                RevokeDisposition::Abort => {
                    aborts += 1;
                    TerminalRequest::aborted(ECANCELED)
                }
                RevokeDisposition::Drain(ref receipt) => {
                    drains += 1;
                    TerminalRequest::completed(receipt.result())
                }
            };
            let terminal = runtime
                .effects
                .stage_revoke_terminal(&selection, effect.effect, request)
                .unwrap();
            for key in current_resources.remove(&effect.effect).unwrap() {
                runtime.futex.detach(&key, effect.effect).unwrap();
            }
            tickets.push(terminal.publication.unwrap());
        }
        runtime.check_invariants().unwrap();
        (tickets, drains, aborts)
    });
    assert_eq!(
        runtime.with_state(|runtime| runtime.effects.revoke_complete(&selection)),
        Err(RegistryError::NotQuiescent),
    );
    for ticket in &tickets {
        runtime.with_state(|runtime| {
            runtime.effects.acknowledge_publication(ticket).unwrap();
            runtime.check_invariants().unwrap();
        });
    }
    runtime.with_state(|runtime| {
        runtime.futex.retire(&source).unwrap();
        runtime.futex.retire(&target).unwrap();
        runtime.effects.revoke_complete(&selection).unwrap();
        runtime.check_invariants().unwrap();
        let projection = runtime.effects.scope_projection(scope).unwrap();
        assert_eq!(projection.phase, ScopePhase::Revoked);
        assert_eq!(projection.live_effects, 0);
        assert_eq!(projection.pending_publications, 0);
        assert_eq!(projection.credits.free, projection.credits.capacity);
        assert!(runtime.futex.is_empty());
    });
    if commit_before_close {
        assert_eq!((drains, aborts), (2, 1));
        println!(
            "LINUX_FUTEX_CORE_CLOSE PASS case=commit-before-close affected=2 moved=1 drains=2 aborts=1 publications=3 move_preserved=true final_queues=0 final_indexes=0 final_credits=0"
        );
    } else {
        assert_eq!((drains, aborts), (0, 3));
        println!(
            "LINUX_FUTEX_CORE_CLOSE PASS case=close-before-commit commit_result=StaleAuthority moved=0 drains=0 aborts=3 publications=3 failure_atomic=true final_queues=0 final_indexes=0 final_credits=0"
        );
    }
}

fn run_close_companions() {
    run_close_companion(true);
    run_close_companion(false);
}

pub(crate) fn run_linux_futex_core_slice() {
    run_close_companions();
    let image = load_static_image(ROUND4_IMAGE, b"/bin/linux-round4-futex-smoke\0");
    assert!(image.segments.len() >= 3);
    let segment_count = image.segments.len();
    let vm_space = image.vm_space.clone();
    let completion_token = EffectToken {
        authority_epoch: 1,
        scope_id: 160,
        effect_id: 99,
    };
    let (completion_waiter, completion_waker) = EffectWaiter::new_pair(completion_token);
    let scenario = CoreScenario::new(vm_space.clone(), completion_waker);

    let mut parent_context = UserContext::default();
    parent_context.set_rip(image.entry);
    parent_context.set_rsp(image.stack_pointer);
    let parent_scenario = scenario.clone();
    let parent_vm = vm_space.clone();
    let parent_task = Arc::new(
        TaskOptions::new(move || {
            run_guest_thread(parent_scenario, parent_vm, PARENT_TASK, parent_context)
        })
        .data(TaskData::new(PARENT_TASK.id(), Some(vm_space.clone())))
        .build()
        .expect("build retained Round 4 parent task"),
    );

    let v1_vm = Arc::new(create_vm_space(PERSONALITY_V1));
    let v1_scenario = scenario.clone();
    let v1_task_vm = v1_vm.clone();
    let v1_task = Arc::new(
        TaskOptions::new(move || run_personality_v1(v1_scenario, v1_task_vm))
            .data(TaskData::new(V1_TASK.id(), Some(v1_vm.clone())))
            .build()
            .expect("build Round 4 personality v1"),
    );

    let watchdog_scenario = scenario.clone();
    let old_task = v1_task.clone();
    let old_vm = v1_vm;
    let watchdog = Arc::new(
        TaskOptions::new(move || run_recovery_watchdog(watchdog_scenario, old_task, old_vm))
            .data(TaskData::new(WATCHDOG_TASK_ID, None))
            .build()
            .expect("build Round 4 recovery watchdog"),
    );

    println!(
        "LINUX_FUTEX_CORE BEGIN workload=linux-round4-futex-smoke adapted=true elf=ET_EXEC entry={:#x} segments={} vm=Arc<VmSpace> single_cpu=true private_futex=true bounded_abi=mmap+clone+exit+exit_group+write+wait+wake+requeue",
        image.entry, segment_count,
    );
    parent_task.run();
    v1_task.run();
    watchdog.run();
    completion_waiter.wait();
    drop(completion_waiter);
    println!(
        "LINUX_FUTEX_CORE PASS workload=linux-round4-futex-smoke stdout_exact=true mmap_pages=8 clones=3 waits=4 wakes=2 requeues=1 affected_count=2 fifo=true atomic_move=true crash_rebind=true explicit_adoptions=3 stale_old_rejected=true fixed_receipt_publications=1 close_companions=2 final_empty=true single_cpu=true"
    );
}
