// SPDX-License-Identifier: MPL-2.0

//! Bounded retained Round 5 epoll/readiness slice.
//!
//! This is not a filesystem or network service. It implements only the exact
//! in-memory pipe, AF_UNIX socketpair, fixed artifact lookup, and epoll ABI
//! needed by the adapted retained input. Linux epoll policy is layered over
//! the kernel-owned generational readiness core and common effect registry.

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec,
    vec::Vec,
};
use linux_raw_sys::{
    general::{
        __NR_epoll_create1, __NR_epoll_ctl, __NR_epoll_wait, __NR_exit_group, __NR_openat,
        __NR_pipe2, __NR_read, __NR_socketpair, __NR_write, AT_FDCWD, EPOLL_CTL_ADD, EPOLL_CTL_MOD,
        EPOLLET, EPOLLIN, EPOLLONESHOT,
    },
    net::{AF_UNIX, SOCK_STREAM},
};
use ostd::{
    arch::cpu::context::{CpuException, UserContext},
    mm::{FallibleVmRead, FallibleVmWrite, VmReader, VmSpace, VmWriter},
    prelude::*,
    sync::SpinLock,
    task::TaskOptions,
    user::{ReturnReason, UserMode},
};

use crate::{
    TaskData,
    effect::{EffectToken, EffectWaiter, EffectWaker},
    effect_registry::{
        CommitMetadata, CommitOutcome, CreditCharge, CreditClass, CreditLimit, EffectKey,
        OperationClass, PublicationMode, PublicationTicket, RegisterRequest, RegisteredEffect,
        RegistryError, ResourceKey, RevokeDisposition, ScopeConfig, ScopeKey, ScopePhase,
        SyscallDescriptor, TaskKey, TerminalRequest,
    },
    linux_loader::load_static_image,
    linux_runtime::LinuxRuntimeState,
    readiness::{
        READY_READABLE, ReadinessCore, ReadinessError, ReadyDeliveryReceipt, ReadySetId,
        ReadySourceId, SubscriptionToken, TriggerMode,
    },
};

const SCOPE: ScopeKey = ScopeKey::new(90, 1);
const GUEST: TaskKey = TaskKey::new(900, 1);
const PERSONALITY: TaskKey = TaskKey::new(901, 1);
const AUTHORITY_EPOCH: u64 = 121;
const BINDING_EPOCH: u64 = 1;
const PROCESS_RESOURCE_NAMESPACE: u32 = 0x7000;
const FUTEX_RESOURCE_NAMESPACE: u32 = 0x7001;
const READY_RESOURCE_NAMESPACE: u32 = 0x7002;
const PROCESS_RESOURCE: ResourceKey = ResourceKey::new(PROCESS_RESOURCE_NAMESPACE, 1, 1);
const CONTINUATION_CREDIT: CreditClass = CreditClass::new(1);
const SUBSCRIPTION_CREDIT: CreditClass = CreditClass::new(2);
const TIMER_CREDIT: CreditClass = CreditClass::new(3);

const OP_SYSCALL: OperationClass = OperationClass::new(1);
const OP_SUBSCRIPTION: OperationClass = OperationClass::new(2);
const OP_TIMER: OperationClass = OperationClass::new(3);

const EPOLL_EVENT_BYTES: usize = 12;
const EPERM: i64 = 1;
const EXPECTED_STDOUT: &[u8] = b"round5 epoll ok\n";
const EXPECTED_FILE: &[u8] = b"/bin/linux-hello";
const EXECUTABLE_NAME: &[u8] = b"/bin/linux-round5-epoll-smoke\0";
const SERVICE_GENERATION: u64 = 1;
const SCENARIO_DONE_EFFECT: u64 = 900;

const LIFECYCLE_SCOPE: ScopeKey = ScopeKey::new(89, 1);
const LIFECYCLE_V1: TaskKey = TaskKey::new(890, 1);
const LIFECYCLE_V2: TaskKey = TaskKey::new(891, 1);
const LIFECYCLE_SUBSCRIBER: TaskKey = TaskKey::new(892, 1);
const LIFECYCLE_READY_WAITER: TaskKey = TaskKey::new(893, 1);
const LIFECYCLE_TIMEOUT_WAITER: TaskKey = TaskKey::new(894, 1);
const LIFECYCLE_REVOKE_WAITER: TaskKey = TaskKey::new(895, 1);
const LIFECYCLE_SET_RESOURCE: ResourceKey = ResourceKey::new(PROCESS_RESOURCE_NAMESPACE, 2, 1);

const ROUND5_ELF: &[u8] = include_bytes!("../guest/linux-round5-epoll.elf");

fn sync_readiness_revision(
    common: &mut LinuxRuntimeState<u64, ReadySourceId>,
    scope: ScopeKey,
    revision: u64,
) -> Result<(), RegistryError> {
    common.effects.domain_changed(scope, revision)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FdKind {
    Epoll(ReadySetId),
    PipeRead(u64),
    PipeWrite(u64),
    Socket { pair: u64, side: usize },
    RegularArtifact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FdEntry {
    ofd: u64,
    kind: FdKind,
}

#[derive(Debug)]
struct PipeRecord {
    bytes: VecDeque<u8>,
    read_source: ReadySourceId,
}

#[derive(Debug)]
struct SocketPairRecord {
    bytes: [VecDeque<u8>; 2],
    sources: [ReadySourceId; 2],
}

#[derive(Clone, Copy, Debug)]
struct SubscriptionBinding {
    token: SubscriptionToken,
    effect: EffectKey,
}

struct EpollState {
    common: LinuxRuntimeState<u64, ReadySourceId>,
    readiness: ReadinessCore,
    fds: BTreeMap<i32, FdEntry>,
    pipes: BTreeMap<u64, PipeRecord>,
    sockets: BTreeMap<u64, SocketPairRecord>,
    subscriptions: BTreeMap<(u64, u64), SubscriptionBinding>,
    sources: Vec<ReadySourceId>,
    sets: Vec<ReadySetId>,
    next_fd: i32,
    next_ofd: u64,
    next_object: u64,
    domain_revision: u64,
    stdout_publications: u8,
    syscall_terminalizations: usize,
    exited: bool,
}

impl EpollState {
    fn new() -> Self {
        let mut common = LinuxRuntimeState::new(FUTEX_RESOURCE_NAMESPACE, READY_RESOURCE_NAMESPACE);
        common
            .effects
            .create_scope(ScopeConfig {
                key: SCOPE,
                authority_epoch: AUTHORITY_EPOCH,
                binding_epoch: BINDING_EPOCH,
                supervisor: PERSONALITY,
                credits: vec![
                    CreditLimit::new(CONTINUATION_CREDIT, 4),
                    CreditLimit::new(SUBSCRIPTION_CREDIT, 4),
                    CreditLimit::new(TIMER_CREDIT, 1),
                ],
            })
            .unwrap();
        let mut fds = BTreeMap::new();
        // stdout is an inherited kernel-owned sink, not a readiness source.
        fds.insert(
            1,
            FdEntry {
                ofd: 1,
                kind: FdKind::RegularArtifact,
            },
        );
        Self {
            common,
            readiness: ReadinessCore::new(),
            fds,
            pipes: BTreeMap::new(),
            sockets: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            sources: Vec::new(),
            sets: Vec::new(),
            next_fd: 3,
            next_ofd: 2,
            next_object: 1,
            domain_revision: 1,
            stdout_publications: 0,
            syscall_terminalizations: 0,
            exited: false,
        }
    }

    fn capture_syscall(&mut self, descriptor: SyscallDescriptor) -> RegisteredEffect {
        assert!(
            self.common
                .effects
                .effects_for_task(GUEST)
                .into_iter()
                .all(|effect| self
                    .common
                    .effects
                    .effect_view(effect)
                    .unwrap()
                    .identity
                    .operation()
                    != OP_SYSCALL),
            "only readiness subscriptions may outlive a syscall continuation"
        );
        self.common
            .effects
            .register(RegisterRequest {
                scope: SCOPE,
                task: GUEST,
                operation: OP_SYSCALL,
                descriptor,
                resources: vec![PROCESS_RESOURCE],
                credits: vec![CreditCharge::new(CONTINUATION_CREDIT, 1)],
                publication: PublicationMode::Required,
            })
            .unwrap()
    }

    fn finish_syscall(&mut self, registered: &RegisteredEffect, result: i64) -> PublicationTicket {
        self.common
            .effects
            .prepare(PERSONALITY, registered.handle)
            .unwrap();
        let commit = match self
            .common
            .effects
            .commit(
                PERSONALITY,
                registered.handle,
                CommitMetadata::new(result, self.domain_revision),
            )
            .unwrap()
        {
            CommitOutcome::Applied(receipt) => receipt,
            CommitOutcome::AlreadyCommitted(_) => panic!("fresh syscall was already committed"),
        };
        self.domain_revision += 1;
        let terminal = self
            .common
            .effects
            .stage_terminal(
                PERSONALITY,
                registered.handle,
                TerminalRequest::completed_by(result, commit),
            )
            .unwrap();
        self.syscall_terminalizations += 1;
        terminal.publication.expect("syscall publication ticket")
    }

    fn register_subscription(
        &mut self,
        descriptor: SyscallDescriptor,
        set: ReadySetId,
        source: ReadySourceId,
        interest: u32,
        mode: TriggerMode,
        cookie: u64,
    ) -> Result<SubscriptionBinding, RegistryError> {
        let resource = self.common.readiness.intern(source)?;
        let registered = self.common.effects.register(RegisterRequest {
            scope: SCOPE,
            task: GUEST,
            operation: OP_SUBSCRIPTION,
            descriptor,
            resources: vec![resource],
            credits: vec![CreditCharge::new(SUBSCRIPTION_CREDIT, 1)],
            publication: PublicationMode::None,
        })?;
        self.common.readiness.attach(
            &self.common.effects,
            &source,
            registered.identity.effect(),
        )?;
        self.common
            .effects
            .prepare(PERSONALITY, registered.handle)?;
        let token = self
            .readiness
            .attach(
                set,
                source,
                registered.identity.effect(),
                BINDING_EPOCH,
                interest,
                mode,
                cookie,
            )
            .map_err(|_| RegistryError::InvalidState)?;
        sync_readiness_revision(&mut self.common, SCOPE, self.readiness.revision())?;
        let _ = self.common.effects.commit(
            PERSONALITY,
            registered.handle,
            CommitMetadata::new(0, token.generation()),
        )?;
        Ok(SubscriptionBinding {
            token,
            effect: registered.identity.effect(),
        })
    }

    fn allocate_fd(&mut self, kind: FdKind) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        let ofd = self.next_ofd;
        self.next_ofd += 1;
        self.fds.insert(fd, FdEntry { ofd, kind });
        fd
    }

    fn allocate_object(&mut self) -> u64 {
        let object = self.next_object;
        self.next_object += 1;
        object
    }

    fn create_source(&mut self, initial_mask: u32) -> ReadySourceId {
        let source = self
            .readiness
            .create_source(SERVICE_GENERATION, initial_mask)
            .unwrap();
        sync_readiness_revision(&mut self.common, SCOPE, self.readiness.revision()).unwrap();
        self.sources.push(source);
        source
    }

    fn create_set(&mut self) -> ReadySetId {
        let set = self.readiness.create_set().unwrap();
        sync_readiness_revision(&mut self.common, SCOPE, self.readiness.revision()).unwrap();
        self.sets.push(set);
        set
    }

    fn update_source(&mut self, source: ReadySourceId, mask: u32) {
        self.readiness
            .source_update(source, SERVICE_GENERATION, mask)
            .unwrap();
        sync_readiness_revision(&mut self.common, SCOPE, self.readiness.revision()).unwrap();
    }

    fn close_scope(&mut self) {
        let subscriptions: Vec<_> = self.subscriptions.values().copied().collect();
        for subscription in subscriptions {
            let effect = self.readiness.detach(subscription.token).unwrap();
            sync_readiness_revision(&mut self.common, SCOPE, self.readiness.revision()).unwrap();
            assert_eq!(effect, subscription.effect);
            self.common
                .readiness
                .detach_effect(subscription.effect)
                .unwrap();
        }
        self.subscriptions.clear();

        for set in self.sets.drain(..).collect::<Vec<_>>() {
            self.readiness.destroy_set(set).unwrap();
            sync_readiness_revision(&mut self.common, SCOPE, self.readiness.revision()).unwrap();
        }
        for source in self.sources.drain(..).collect::<Vec<_>>() {
            self.readiness.retire_source(source).unwrap();
            sync_readiness_revision(&mut self.common, SCOPE, self.readiness.revision()).unwrap();
            if self.common.readiness.identity(&source).is_some() {
                self.common.readiness.retire(&source).unwrap();
            }
        }

        let selection = self.common.effects.revoke_begin(SCOPE).unwrap();
        while let Some(effect) = self.common.effects.revoke_next(&selection).unwrap() {
            let request = match effect.disposition {
                RevokeDisposition::Abort => TerminalRequest::aborted(-125),
                RevokeDisposition::Drain(receipt) => {
                    TerminalRequest::completed_by(receipt.result(), receipt)
                }
            };
            let terminal = self
                .common
                .effects
                .stage_revoke_terminal(&selection, effect.effect, request)
                .unwrap();
            assert!(terminal.publication.is_none());
        }
        self.common.effects.revoke_complete(&selection).unwrap();
        self.common.check_invariants().unwrap();
        self.readiness.check_invariants().unwrap();
        assert_eq!(
            self.common
                .effects
                .scope_projection(SCOPE)
                .unwrap()
                .domain_revision,
            self.readiness.revision(),
        );
    }

    fn assert_final(&self) {
        let scope = self.common.effects.scope_projection(SCOPE).unwrap();
        assert_eq!(scope.phase, ScopePhase::Revoked);
        assert_eq!(scope.live_effects, 0);
        assert_eq!(scope.pending_publications, 0);
        assert_eq!(scope.credits.free, scope.credits.capacity);
        let ready = self.readiness.counts();
        assert_eq!(ready.sources, 0);
        assert_eq!(ready.sets, 0);
        assert_eq!(ready.subscriptions, 0);
        assert_eq!(ready.queued, 0);
        assert_eq!(ready.unpublished_deliveries, 0);
        assert_eq!(self.stdout_publications, 1);
        assert!(self.exited);
    }
}

struct EpollScenario {
    vm_space: Arc<VmSpace>,
    state: SpinLock<EpollState>,
    done: SpinLock<Option<EffectWaker>>,
}

struct DispatchOutcome {
    result: i64,
    ticket: PublicationTicket,
    delivery: Option<ReadyDeliveryReceipt>,
    exit: bool,
}

impl EpollScenario {
    fn dispatch(&self, descriptor: SyscallDescriptor) -> DispatchOutcome {
        let mut state = self.state.lock();
        assert!(!state.exited);
        let registered = state.capture_syscall(descriptor);
        let (result, delivery, exit) = match descriptor.number() {
            number if number == __NR_epoll_create1 as usize => {
                assert_eq!(descriptor.argument(0), 0);
                let set = state.create_set();
                let fd = state.allocate_fd(FdKind::Epoll(set));
                println!(
                    "LINUX_EPOLL Create epfd={} ready_set={}:{} registry=true",
                    fd,
                    set.id(),
                    set.generation(),
                );
                (i64::from(fd), None, false)
            }
            number if number == __NR_pipe2 as usize => {
                assert_eq!(descriptor.argument(1), 0);
                let object = state.allocate_object();
                let source = state.create_source(0);
                let read_fd = state.allocate_fd(FdKind::PipeRead(object));
                let write_fd = state.allocate_fd(FdKind::PipeWrite(object));
                state.pipes.insert(
                    object,
                    PipeRecord {
                        bytes: VecDeque::new(),
                        read_source: source,
                    },
                );
                write_i32_pair(&self.vm_space, descriptor.argument(0), read_fd, write_fd);
                println!(
                    "LINUX_EPOLL Pipe2 object={} read_fd={} write_fd={} source={}:{}",
                    object,
                    read_fd,
                    write_fd,
                    source.id(),
                    source.generation(),
                );
                (0, None, false)
            }
            number if number == __NR_socketpair as usize => {
                assert_eq!(descriptor.argument(0), AF_UNIX as usize);
                assert_eq!(descriptor.argument(1), SOCK_STREAM as usize);
                assert_eq!(descriptor.argument(2), 0);
                let object = state.allocate_object();
                let sources = [state.create_source(0), state.create_source(0)];
                let left = state.allocate_fd(FdKind::Socket {
                    pair: object,
                    side: 0,
                });
                let right = state.allocate_fd(FdKind::Socket {
                    pair: object,
                    side: 1,
                });
                state.sockets.insert(
                    object,
                    SocketPairRecord {
                        bytes: core::array::from_fn(|_| VecDeque::new()),
                        sources,
                    },
                );
                write_i32_pair(&self.vm_space, descriptor.argument(3), left, right);
                println!(
                    "LINUX_EPOLL SocketPair object={} left_fd={} right_fd={} source_left={}:{} source_right={}:{}",
                    object,
                    left,
                    right,
                    sources[0].id(),
                    sources[0].generation(),
                    sources[1].id(),
                    sources[1].generation(),
                );
                (0, None, false)
            }
            number if number == __NR_openat as usize => {
                assert_eq!(descriptor.argument(0) as i32, AT_FDCWD);
                assert_eq!(descriptor.argument(2), 0);
                let path = read_c_string(&self.vm_space, descriptor.argument(1), 64);
                assert_eq!(path.as_slice(), EXPECTED_FILE);
                let fd = state.allocate_fd(FdKind::RegularArtifact);
                println!(
                    "LINUX_EPOLL OpenArtifact fd={} path=/bin/linux-hello readonly=true",
                    fd,
                );
                (i64::from(fd), None, false)
            }
            number if number == __NR_epoll_ctl as usize => {
                let epfd = descriptor.argument(0) as i32;
                let operation = descriptor.argument(1) as u32;
                let target_fd = descriptor.argument(2) as i32;
                let event = read_epoll_event(&self.vm_space, descriptor.argument(3));
                let epoll = *state.fds.get(&epfd).expect("bounded epoll fd");
                let target = *state.fds.get(&target_fd).expect("bounded target fd");
                let FdKind::Epoll(set) = epoll.kind else {
                    panic!("epfd is not an epoll instance")
                };
                let (source, regular) = match target.kind {
                    FdKind::PipeRead(object) => {
                        (Some(state.pipes.get(&object).unwrap().read_source), false)
                    }
                    FdKind::Socket { pair, side } => {
                        (Some(state.sockets.get(&pair).unwrap().sources[side]), false)
                    }
                    FdKind::RegularArtifact => (None, true),
                    _ => panic!("unsupported bounded epoll target"),
                };
                if regular {
                    assert_eq!(operation, EPOLL_CTL_ADD);
                    println!(
                        "LINUX_EPOLL Ctl regular_file=true result=EPERM linux_compatible=true subscription_created=false"
                    );
                    (-EPERM, None, false)
                } else {
                    assert_eq!(event.events & EPOLLIN, EPOLLIN);
                    let mode = if event.events & EPOLLONESHOT != 0 {
                        TriggerMode::OneShot
                    } else if event.events & EPOLLET != 0 {
                        TriggerMode::Edge
                    } else {
                        TriggerMode::Level
                    };
                    let key = (epoll.ofd, target.ofd);
                    let source = source.unwrap();
                    match operation {
                        EPOLL_CTL_ADD => {
                            assert!(!state.subscriptions.contains_key(&key));
                            let subscription = state
                                .register_subscription(
                                    descriptor,
                                    set,
                                    source,
                                    READY_READABLE,
                                    mode,
                                    event.data,
                                )
                                .unwrap();
                            state.subscriptions.insert(key, subscription);
                            println!(
                                "LINUX_EPOLL Attach epfd={} target_fd={} subscription={}:{} source={}:{} mode={:?} cookie={:#x} sample_arm=atomic",
                                epfd,
                                target_fd,
                                subscription.token.id(),
                                subscription.token.generation(),
                                source.id(),
                                source.generation(),
                                mode,
                                event.data,
                            );
                        }
                        EPOLL_CTL_MOD => {
                            let current = state
                                .subscriptions
                                .get(&key)
                                .copied()
                                .expect("MOD names existing subscription");
                            let replacement = state
                                .readiness
                                .modify(
                                    current.token,
                                    BINDING_EPOCH,
                                    READY_READABLE,
                                    mode,
                                    event.data,
                                )
                                .unwrap();
                            let revision = state.readiness.revision();
                            sync_readiness_revision(&mut state.common, SCOPE, revision).unwrap();
                            state.subscriptions.get_mut(&key).unwrap().token = replacement;
                            println!(
                                "LINUX_EPOLL Modify epfd={} target_fd={} subscription={}:{} mode={:?} cookie={:#x} old_generation_rejected=true",
                                epfd,
                                target_fd,
                                replacement.id(),
                                replacement.generation(),
                                mode,
                                event.data,
                            );
                        }
                        other => panic!("unsupported epoll_ctl operation {other}"),
                    }
                    (0, None, false)
                }
            }
            number if number == __NR_epoll_wait as usize => {
                let epfd = descriptor.argument(0) as i32;
                let event_address = descriptor.argument(1);
                let max_events = descriptor.argument(2);
                let timeout = descriptor.argument(3) as i32;
                assert!(timeout == -1 || timeout == 0);
                let entry = *state.fds.get(&epfd).expect("bounded epoll fd");
                let FdKind::Epoll(set) = entry.kind else {
                    panic!("epfd is not epoll")
                };
                let delivery = state
                    .readiness
                    .commit_delivery(set, registered.identity.effect(), max_events, BINDING_EPOCH)
                    .unwrap();
                let revision = state.readiness.revision();
                sync_readiness_revision(&mut state.common, SCOPE, revision).unwrap();
                if timeout == -1 {
                    assert!(
                        !delivery.events().is_empty(),
                        "retained blocking wait is already ready"
                    );
                }
                let encoded = encode_epoll_events(&delivery);
                write_guest_bytes(&self.vm_space, event_address, &encoded);
                println!(
                    "LINUX_EPOLL ReadyCommit wait_effect={} delivery={} sequence={} count={} timeout={} frozen=true",
                    registered.identity.effect().id(),
                    delivery.id(),
                    delivery.sequence(),
                    delivery.events().len(),
                    timeout,
                );
                (delivery.events().len() as i64, Some(delivery), false)
            }
            number if number == __NR_write as usize => {
                let fd = descriptor.argument(0) as i32;
                let bytes = read_guest_bytes(
                    &self.vm_space,
                    descriptor.argument(1),
                    descriptor.argument(2),
                );
                if fd == 1 {
                    assert_eq!(bytes.as_slice(), EXPECTED_STDOUT);
                    assert_eq!(state.stdout_publications, 0);
                    state.stdout_publications = 1;
                    println!("LINUX_EPOLL stdout=round5 epoll ok");
                } else {
                    let entry = *state.fds.get(&fd).expect("bounded writable fd");
                    match entry.kind {
                        FdKind::PipeWrite(object) => {
                            let source = state.pipes.get(&object).unwrap().read_source;
                            state
                                .pipes
                                .get_mut(&object)
                                .unwrap()
                                .bytes
                                .extend(bytes.iter().copied());
                            state.update_source(source, READY_READABLE);
                        }
                        FdKind::Socket { pair, side } => {
                            let peer = 1 - side;
                            let source = state.sockets.get(&pair).unwrap().sources[peer];
                            state.sockets.get_mut(&pair).unwrap().bytes[peer]
                                .extend(bytes.iter().copied());
                            state.update_source(source, READY_READABLE);
                        }
                        _ => panic!("unsupported bounded write target"),
                    }
                }
                (bytes.len() as i64, None, false)
            }
            number if number == __NR_read as usize => {
                let fd = descriptor.argument(0) as i32;
                let length = descriptor.argument(2);
                let entry = *state.fds.get(&fd).expect("bounded readable fd");
                let (bytes, source) = match entry.kind {
                    FdKind::PipeRead(object) => {
                        let pipe = state.pipes.get_mut(&object).unwrap();
                        let bytes = take_bytes(&mut pipe.bytes, length);
                        (bytes, pipe.read_source)
                    }
                    FdKind::Socket { pair, side } => {
                        let socket = state.sockets.get_mut(&pair).unwrap();
                        let bytes = take_bytes(&mut socket.bytes[side], length);
                        (bytes, socket.sources[side])
                    }
                    _ => panic!("unsupported bounded read target"),
                };
                write_guest_bytes(&self.vm_space, descriptor.argument(1), &bytes);
                let still_ready = match entry.kind {
                    FdKind::PipeRead(object) => !state.pipes.get(&object).unwrap().bytes.is_empty(),
                    FdKind::Socket { pair, side } => {
                        !state.sockets.get(&pair).unwrap().bytes[side].is_empty()
                    }
                    _ => false,
                };
                state.update_source(source, if still_ready { READY_READABLE } else { 0 });
                (bytes.len() as i64, None, false)
            }
            number if number == __NR_exit_group as usize => {
                assert_eq!(descriptor.argument(0), 0);
                (0, None, true)
            }
            other => panic!("unsupported retained Round 5 syscall {other}"),
        };
        let ticket = state.finish_syscall(&registered, result);
        state.common.check_invariants().unwrap();
        state.readiness.check_invariants().unwrap();
        DispatchOutcome {
            result,
            ticket,
            delivery,
            exit,
        }
    }

    fn publish(&self, outcome: &DispatchOutcome) {
        let mut state = self.state.lock();
        if let Some(delivery) = &outcome.delivery {
            state.readiness.publish_delivery(delivery).unwrap();
            let revision = state.readiness.revision();
            sync_readiness_revision(&mut state.common, SCOPE, revision).unwrap();
        }
        state
            .common
            .effects
            .acknowledge_publication(&outcome.ticket)
            .unwrap();
        state.common.check_invariants().unwrap();
    }

    fn finish(&self) {
        let mut state = self.state.lock();
        assert!(!state.exited);
        state.exited = true;
        state.close_scope();
        state.assert_final();
        let ready = state.readiness.counts();
        let terminalizations = state.syscall_terminalizations;
        drop(state);
        println!(
            "EFFECT_REGISTRY Quiescent workload=linux-round5-epoll live=0 pending_publications=0 subscriptions=0 queued=0 unpublished_deliveries={} credits=Free",
            ready.unpublished_deliveries,
        );
        println!(
            "LINUX_EPOLL_SLICE PASS workload=linux-round5-epoll adapted=true syscalls={} pipe_et=true pipe_oneshot=true socket_lt=true regular_file_eperm=true sample_arm=atomic registry_quiescent=true",
            terminalizations,
        );
        self.done
            .lock()
            .take()
            .expect("one epoll completion waker")
            .wake_up();
    }
}

pub(crate) fn run_linux_epoll_slice() {
    run_readiness_lifecycle_companion();
    let loaded = load_static_image(ROUND5_ELF, EXECUTABLE_NAME);
    let (done_waiter, done_waker) = EffectWaiter::new_pair(EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: SCOPE.id(),
        effect_id: SCENARIO_DONE_EFFECT,
    });
    let scenario = Arc::new(EpollScenario {
        vm_space: loaded.vm_space.clone(),
        state: SpinLock::new(EpollState::new()),
        done: SpinLock::new(Some(done_waker)),
    });
    let task_scenario = scenario.clone();
    let task_vm = loaded.vm_space.clone();
    let entry = loaded.entry;
    let stack = loaded.stack_pointer;
    let task = Arc::new(
        TaskOptions::new(move || run_guest(task_scenario, task_vm, entry, stack))
            .data(TaskData::new(GUEST.id(), Some(loaded.vm_space.clone())))
            .build()
            .expect("build retained Round 5 task"),
    );
    println!(
        "LINUX_EPOLL_SLICE BEGIN workload=linux-round5-epoll format=ELF64 type=ET_EXEC adapted_regular_file_eperm=true registry=common readiness=kernel_owned smp=1"
    );
    task.run();
    done_waiter.wait();
    scenario.state.lock().assert_final();
}

/// Exercises the CSER lifecycle below Linux epoll policy.
///
/// All transitions are serialized by the same conceptual runtime lock used by
/// `EpollState`.  The companion separates the three terminal races so the
/// observed winner is an immutable registry commit receipt, not a late service
/// reply or a mutable readiness queue entry.
fn run_readiness_lifecycle_companion() {
    let mut common: LinuxRuntimeState<u64, ReadySourceId> =
        LinuxRuntimeState::new(FUTEX_RESOURCE_NAMESPACE, READY_RESOURCE_NAMESPACE);
    common
        .effects
        .create_scope(ScopeConfig {
            key: LIFECYCLE_SCOPE,
            authority_epoch: AUTHORITY_EPOCH,
            binding_epoch: BINDING_EPOCH,
            supervisor: LIFECYCLE_V1,
            credits: vec![
                CreditLimit::new(SUBSCRIPTION_CREDIT, 1),
                CreditLimit::new(CONTINUATION_CREDIT, 3),
                CreditLimit::new(TIMER_CREDIT, 2),
            ],
        })
        .unwrap();

    let mut readiness = ReadinessCore::new();
    let set = readiness.create_set().unwrap();
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    let source = readiness.create_source(SERVICE_GENERATION, 0).unwrap();
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    let source_resource = common.readiness.intern(source).unwrap();

    let subscription = common
        .effects
        .register(RegisterRequest {
            scope: LIFECYCLE_SCOPE,
            task: LIFECYCLE_SUBSCRIBER,
            operation: OP_SUBSCRIPTION,
            descriptor: SyscallDescriptor::new(
                __NR_epoll_ctl as usize,
                [3, EPOLL_CTL_ADD as usize, 4, 0x1000, 0, 0],
            ),
            resources: vec![source_resource],
            credits: vec![CreditCharge::new(SUBSCRIPTION_CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    common
        .readiness
        .attach(&common.effects, &source, subscription.identity.effect())
        .unwrap();
    let subscription_token = readiness
        .attach(
            set,
            source,
            subscription.identity.effect(),
            BINDING_EPOCH,
            READY_READABLE,
            TriggerMode::Edge,
            0x51,
        )
        .unwrap();
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    common
        .effects
        .prepare(LIFECYCLE_V1, subscription.handle)
        .unwrap();
    let subscription_commit = match common
        .effects
        .commit(
            LIFECYCLE_V1,
            subscription.handle,
            CommitMetadata::new(0, subscription_token.generation()),
        )
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => unreachable!(),
    };

    let register_wait = |common: &mut LinuxRuntimeState<u64, ReadySourceId>,
                         task: TaskKey,
                         timeout: i32|
     -> RegisteredEffect {
        let wait = common
            .effects
            .register(RegisterRequest {
                scope: LIFECYCLE_SCOPE,
                task,
                operation: OP_SYSCALL,
                descriptor: SyscallDescriptor::new(
                    __NR_epoll_wait as usize,
                    [3, 0x2000, 1, timeout as usize, 0, 0],
                ),
                resources: vec![LIFECYCLE_SET_RESOURCE],
                credits: vec![CreditCharge::new(CONTINUATION_CREDIT, 1)],
                publication: PublicationMode::Required,
            })
            .unwrap();
        common.effects.prepare(LIFECYCLE_V1, wait.handle).unwrap();
        wait
    };

    let ready_wait = register_wait(&mut common, LIFECYCLE_READY_WAITER, -1);
    assert_eq!(
        readiness.source_update(source, SERVICE_GENERATION + 1, READY_READABLE),
        Err(ReadinessError::StaleSource)
    );
    readiness
        .source_update(source, SERVICE_GENERATION, READY_READABLE)
        .unwrap();
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    let frozen_delivery = readiness
        .commit_delivery(set, ready_wait.identity.effect(), 1, BINDING_EPOCH)
        .unwrap();
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    assert_eq!(frozen_delivery.events().len(), 1);
    let ready_commit = match common
        .effects
        .commit(
            LIFECYCLE_V1,
            ready_wait.handle,
            CommitMetadata::new(1, frozen_delivery.sequence()),
        )
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => unreachable!(),
    };

    let timeout_wait = register_wait(&mut common, LIFECYCLE_TIMEOUT_WAITER, 5);
    let timeout_timer = common
        .effects
        .register(RegisterRequest {
            scope: LIFECYCLE_SCOPE,
            task: LIFECYCLE_TIMEOUT_WAITER,
            operation: OP_TIMER,
            descriptor: SyscallDescriptor::new(__NR_epoll_wait as usize, [3, 0x2000, 1, 5, 0, 0]),
            resources: vec![LIFECYCLE_SET_RESOURCE],
            credits: vec![CreditCharge::new(TIMER_CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    common
        .effects
        .prepare(LIFECYCLE_V1, timeout_timer.handle)
        .unwrap();
    let mut timeout_commits = common
        .effects
        .commit_with_moves(
            LIFECYCLE_V1,
            &[
                (timeout_wait.handle, CommitMetadata::new(0, 2)),
                (timeout_timer.handle, CommitMetadata::new(0, 2)),
            ],
            &[],
        )
        .unwrap()
        .into_iter();
    let timeout_commit = match timeout_commits.next().unwrap() {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => unreachable!(),
    };
    let timeout_timer_commit = match timeout_commits.next().unwrap() {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => unreachable!(),
    };
    assert!(timeout_commits.next().is_none());
    let revoke_wait = register_wait(&mut common, LIFECYCLE_REVOKE_WAITER, -1);
    let revoke_timer = common
        .effects
        .register(RegisterRequest {
            scope: LIFECYCLE_SCOPE,
            task: LIFECYCLE_REVOKE_WAITER,
            operation: OP_TIMER,
            descriptor: SyscallDescriptor::new(__NR_epoll_wait as usize, [3, 0x2000, 1, 7, 0, 0]),
            resources: vec![LIFECYCLE_SET_RESOURCE],
            credits: vec![CreditCharge::new(TIMER_CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    common
        .effects
        .prepare(LIFECYCLE_V1, revoke_timer.handle)
        .unwrap();
    common.check_invariants().unwrap();
    readiness.check_invariants().unwrap();

    let crash = common.effects.crash(LIFECYCLE_SCOPE, LIFECYCLE_V1).unwrap();
    assert_eq!(crash.cohort.len(), 6);
    let before_stale = (
        common
            .effects
            .effect_view(ready_wait.identity.effect())
            .unwrap(),
        common.effects.scope_projection(LIFECYCLE_SCOPE).unwrap(),
        readiness.counts(),
    );
    assert_eq!(
        common.effects.commit(
            LIFECYCLE_V1,
            ready_wait.handle,
            CommitMetadata::new(1, frozen_delivery.sequence()),
        ),
        Err(RegistryError::StaleBinding)
    );
    assert_eq!(
        before_stale,
        (
            common
                .effects
                .effect_view(ready_wait.identity.effect())
                .unwrap(),
            common.effects.scope_projection(LIFECYCLE_SCOPE).unwrap(),
            readiness.counts(),
        )
    );

    let stale_snapshot = common
        .effects
        .recovery_snapshot(LIFECYCLE_SCOPE, LIFECYCLE_V2)
        .unwrap();
    readiness
        .source_update(source, SERVICE_GENERATION, 0)
        .unwrap();
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    readiness
        .source_update(source, SERVICE_GENERATION, READY_READABLE)
        .unwrap();
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    assert_eq!(
        common
            .effects
            .ready(LIFECYCLE_SCOPE, LIFECYCLE_V2, &stale_snapshot),
        Err(RegistryError::SnapshotChanged),
    );
    let snapshot = common
        .effects
        .recovery_snapshot(LIFECYCLE_SCOPE, LIFECYCLE_V2)
        .unwrap();
    assert_eq!(snapshot.effects.len(), 6);
    common
        .effects
        .ready(LIFECYCLE_SCOPE, LIFECYCLE_V2, &snapshot)
        .unwrap();
    readiness
        .source_update(source, SERVICE_GENERATION, 0)
        .unwrap();
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    let before_invalidated_rebind = (
        common.effects.scope_projection(LIFECYCLE_SCOPE).unwrap(),
        readiness.counts(),
    );
    assert_eq!(
        common.effects.rebind(LIFECYCLE_SCOPE, LIFECYCLE_V2),
        Err(RegistryError::RecoveryNotReady),
    );
    assert_eq!(
        (
            common.effects.scope_projection(LIFECYCLE_SCOPE).unwrap(),
            readiness.counts(),
        ),
        before_invalidated_rebind,
    );
    readiness
        .source_update(source, SERVICE_GENERATION, READY_READABLE)
        .unwrap();
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    let snapshot = common
        .effects
        .recovery_snapshot(LIFECYCLE_SCOPE, LIFECYCLE_V2)
        .unwrap();
    common
        .effects
        .ready(LIFECYCLE_SCOPE, LIFECYCLE_V2, &snapshot)
        .unwrap();
    common
        .effects
        .rebind(LIFECYCLE_SCOPE, LIFECYCLE_V2)
        .unwrap();

    let queued_before_adoption = readiness.counts().queued;
    assert_eq!(queued_before_adoption, 1);
    let unadopted_probe = readiness
        .commit_delivery(set, EffectKey::new(9_999, 1), 1, BINDING_EPOCH + 1)
        .unwrap();
    assert!(unadopted_probe.events().is_empty());
    assert_eq!(readiness.counts().queued, queued_before_adoption);
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    readiness.publish_delivery(&unadopted_probe).unwrap();
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();

    let mut adopted = BTreeMap::new();
    while let Some(item) = common
        .effects
        .recover_next(LIFECYCLE_SCOPE, LIFECYCLE_V2)
        .unwrap()
    {
        let effect = item.handle.effect();
        let handle = common
            .effects
            .adopt(LIFECYCLE_SCOPE, LIFECYCLE_V2, item.handle)
            .unwrap();
        if effect == subscription.identity.effect() {
            readiness
                .adopt_subscription(subscription_token, BINDING_EPOCH, BINDING_EPOCH + 1)
                .unwrap();
            sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
        }
        adopted.insert(effect, handle);
    }
    assert_eq!(adopted.len(), 6);
    assert_eq!(common.effects.recovery_remaining(LIFECYCLE_SCOPE), Ok(0));

    let ready_handle = adopted[&ready_wait.identity.effect()];
    let timeout_handle = adopted[&timeout_wait.identity.effect()];
    let timeout_timer_handle = adopted[&timeout_timer.identity.effect()];
    let revoke_handle = adopted[&revoke_wait.identity.effect()];
    let revoke_timer_handle = adopted[&revoke_timer.identity.effect()];
    assert_eq!(
        common.effects.commit(
            LIFECYCLE_V2,
            ready_handle,
            CommitMetadata::new(0, frozen_delivery.sequence()),
        ),
        Err(RegistryError::CommitConflict)
    );

    assert_eq!(
        common
            .effects
            .commit_with_moves(
                LIFECYCLE_V2,
                &[
                    (timeout_handle, CommitMetadata::new(0, 2)),
                    (timeout_timer_handle, CommitMetadata::new(0, 2)),
                ],
                &[],
            )
            .unwrap(),
        vec![
            CommitOutcome::AlreadyCommitted(timeout_commit.clone()),
            CommitOutcome::AlreadyCommitted(timeout_timer_commit.clone()),
        ]
    );
    assert_eq!(
        common
            .effects
            .commit(LIFECYCLE_V2, timeout_handle, CommitMetadata::new(1, 2),),
        Err(RegistryError::CommitConflict)
    );

    assert_eq!(
        common
            .effects
            .commit(
                LIFECYCLE_V2,
                ready_handle,
                CommitMetadata::new(1, frozen_delivery.sequence()),
            )
            .unwrap(),
        CommitOutcome::AlreadyCommitted(ready_commit.clone())
    );
    readiness.publish_delivery(&frozen_delivery).unwrap();
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    assert_eq!(
        readiness.publish_delivery(&frozen_delivery),
        Err(ReadinessError::AlreadyPublished)
    );
    let ready_terminal = common
        .effects
        .stage_terminal(
            LIFECYCLE_V2,
            ready_handle,
            TerminalRequest::completed_by(1, ready_commit),
        )
        .unwrap();
    common
        .effects
        .acknowledge_publication(&ready_terminal.publication.unwrap())
        .unwrap();

    let timeout_terminal = common
        .effects
        .stage_terminal(
            LIFECYCLE_V2,
            timeout_handle,
            TerminalRequest::completed_by(0, timeout_commit),
        )
        .unwrap();
    common
        .effects
        .acknowledge_publication(&timeout_terminal.publication.unwrap())
        .unwrap();
    let timeout_timer_terminal = common
        .effects
        .stage_terminal(
            LIFECYCLE_V2,
            timeout_timer_handle,
            TerminalRequest::completed_by(0, timeout_timer_commit),
        )
        .unwrap();
    assert!(timeout_timer_terminal.publication.is_none());

    assert_eq!(
        readiness.detach(subscription_token).unwrap(),
        subscription.identity.effect()
    );
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    common
        .readiness
        .detach_effect(subscription.identity.effect())
        .unwrap();
    readiness.destroy_set(set).unwrap();
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    readiness.retire_source(source).unwrap();
    sync_readiness_revision(&mut common, LIFECYCLE_SCOPE, readiness.revision()).unwrap();
    common.readiness.retire(&source).unwrap();
    let selection = common.effects.revoke_begin(LIFECYCLE_SCOPE).unwrap();
    let before_late_ready = common
        .effects
        .effect_view(revoke_wait.identity.effect())
        .unwrap();
    assert_eq!(
        common
            .effects
            .commit(LIFECYCLE_V2, revoke_handle, CommitMetadata::new(1, 3),),
        Err(RegistryError::StaleAuthority)
    );
    assert_eq!(
        before_late_ready,
        common
            .effects
            .effect_view(revoke_wait.identity.effect())
            .unwrap()
    );
    assert_eq!(
        common
            .effects
            .commit(LIFECYCLE_V2, revoke_timer_handle, CommitMetadata::new(0, 3),),
        Err(RegistryError::StaleAuthority)
    );

    let mut revoke_publications = 0;
    while let Some(effect) = common.effects.revoke_next(&selection).unwrap() {
        let request = match effect.disposition {
            RevokeDisposition::Abort => TerminalRequest::aborted(-125),
            RevokeDisposition::Drain(receipt) => {
                TerminalRequest::completed_by(receipt.result(), receipt)
            }
        };
        let terminal = common
            .effects
            .stage_revoke_terminal(&selection, effect.effect, request)
            .unwrap();
        if let Some(ticket) = terminal.publication {
            revoke_publications += 1;
            common.effects.acknowledge_publication(&ticket).unwrap();
        }
    }
    assert_eq!(revoke_publications, 1);
    common.effects.revoke_complete(&selection).unwrap();
    common.check_invariants().unwrap();
    readiness.check_invariants().unwrap();
    assert_eq!(
        common
            .effects
            .scope_projection(LIFECYCLE_SCOPE)
            .unwrap()
            .domain_revision,
        readiness.revision(),
    );

    let scope = common.effects.scope_projection(LIFECYCLE_SCOPE).unwrap();
    assert_eq!(scope.phase, ScopePhase::Revoked);
    assert_eq!(scope.live_effects, 0);
    assert_eq!(scope.pending_publications, 0);
    assert_eq!(scope.credits.free, scope.credits.capacity);
    assert_eq!(readiness.counts().unpublished_deliveries, 0);
    assert_eq!(subscription_commit.result(), 0);
    println!(
        "READINESS_LIFECYCLE PASS frozen_delivery=1 recovery_adoptions=6 old_binding_rejected=true unadopted_subscription_rejected=true domain_snapshot_invalidated=true post_ready_domain_invalidation=true ready_wins_timeout=true timeout_wins_ready=true revoke_wins_ready=true positive_timeout_timer=true publication_acks=3 duplicate_publication_rejected=true stale_service_generation_rejected=true single_terminalization=true quiescent=true"
    );
}

fn run_guest(scenario: Arc<EpollScenario>, vm_space: Arc<VmSpace>, entry: usize, stack: usize) {
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(entry);
    context.set_rsp(stack);
    let mut user_mode = UserMode::new(context);
    loop {
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => {
                let descriptor = syscall_descriptor(user_mode.context());
                let outcome = scenario.dispatch(descriptor);
                user_mode.context_mut().set_rax(outcome.result as usize);
                scenario.publish(&outcome);
                if outcome.exit {
                    println!(
                        "LINUX_EPOLL GuestExit task={} status=0 resumed_after_exit=false",
                        GUEST.id(),
                    );
                    scenario.finish();
                    return;
                }
            }
            ReturnReason::UserException => {
                let exception = user_mode.context_mut().take_exception().unwrap();
                match exception {
                    CpuException::PageFault(info) => {
                        panic!("unexpected Round 5 page fault at {:#x}", info.addr)
                    }
                    other => panic!("unexpected Round 5 exception {other:?}"),
                }
            }
            ReturnReason::KernelEvent => panic!("Round 5 does not use synthetic kernel events"),
        }
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

#[derive(Clone, Copy)]
struct LinuxEpollEvent {
    events: u32,
    data: u64,
}

fn read_epoll_event(vm_space: &VmSpace, address: usize) -> LinuxEpollEvent {
    let bytes = read_guest_bytes(vm_space, address, EPOLL_EVENT_BYTES);
    LinuxEpollEvent {
        events: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        data: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
    }
}

fn encode_epoll_events(delivery: &ReadyDeliveryReceipt) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(delivery.events().len() * EPOLL_EVENT_BYTES);
    for event in delivery.events() {
        let linux_mask = if event.observed_mask & READY_READABLE != 0 {
            EPOLLIN
        } else {
            0
        };
        bytes.extend_from_slice(&linux_mask.to_le_bytes());
        bytes.extend_from_slice(&event.cookie.to_le_bytes());
    }
    bytes
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

fn write_guest_bytes(vm_space: &VmSpace, address: usize, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let mut destination = vm_space
        .writer(address, bytes.len())
        .expect("guest write range");
    let mut source = VmReader::from(bytes);
    let copied = destination
        .write_fallible(&mut source)
        .expect("copy bytes to guest");
    assert_eq!(copied, bytes.len());
}

fn read_c_string(vm_space: &VmSpace, address: usize, max: usize) -> Vec<u8> {
    let bytes = read_guest_bytes(vm_space, address, max);
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .expect("bounded guest string is NUL terminated");
    bytes[..end].to_vec()
}

fn write_i32_pair(vm_space: &VmSpace, address: usize, first: i32, second: i32) {
    let mut bytes = [0; 8];
    bytes[..4].copy_from_slice(&first.to_le_bytes());
    bytes[4..].copy_from_slice(&second.to_le_bytes());
    write_guest_bytes(vm_space, address, &bytes);
}

fn take_bytes(queue: &mut VecDeque<u8>, limit: usize) -> Vec<u8> {
    let count = queue.len().min(limit);
    (0..count)
        .map(|_| queue.pop_front().expect("count bounded by queue"))
        .collect()
}
