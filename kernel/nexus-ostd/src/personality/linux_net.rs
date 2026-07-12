// SPDX-License-Identifier: MPL-2.0

//! Bounded runtime-network successor for the retained Stage 6 core input.
//!
//! The unchanged guest executes as a real static ELF in OSTD `UserMode`.  A
//! deliberately small in-memory AF_INET/SOCK_STREAM loopback implements only
//! the fixed 22-syscall success path.  The network service itself is exercised
//! through distinct v1/v2 user-mode tasks: v1 prepares `accept4` and then page
//! faults, while v2 snapshots, becomes ready, rebinds, explicitly adopts the
//! crash cohort, proves the old portal stale, and completes the frozen call.
//! This is bounded lifecycle/ABI evidence, not a TCP/IP stack or NIC driver.

use alloc::{collections::BTreeMap, format, string::String, sync::Arc, vec, vec::Vec};

use linux_raw_sys::general::{
    __NR_accept4, __NR_bind, __NR_close, __NR_connect, __NR_exit, __NR_getpeername,
    __NR_getsockname, __NR_listen, __NR_read, __NR_setsockopt, __NR_shutdown, __NR_socket,
    __NR_write,
};
use ostd::{
    arch::cpu::context::{CpuException, UserContext},
    mm::{FallibleVmRead, FallibleVmWrite, VmReader, VmSpace, VmWriter},
    prelude::*,
    sync::SpinLock,
    task::{Task, TaskOptions},
    user::{ReturnReason, UserMode},
};

use crate::{
    TaskData, USER_MAP_ADDR, create_vm_space,
    effect::{EffectToken, EffectWaiter, EffectWaker},
    effect_registry::{
        CommitMetadata, CommitOutcome, CommitReceipt, CreditCharge, CreditClass, CreditLimit,
        EffectKey, EffectPhase, EffectRegistry, EffectView, OperationClass, PortalHandle,
        PublicationMode, PublicationTicket, RecoverySnapshot, RegisterRequest, RegisteredEffect,
        RegistryError, RegistryProjection, ResourceKey, RevokeDisposition, RevokeSelection,
        ScopeConfig, ScopeKey, ScopePhase, SyscallDescriptor, TaskKey, TerminalOutcome,
        TerminalRequest,
    },
    linux_loader::load_static_image,
    readiness::{
        READY_HANGUP, READY_READABLE, ReadinessCore, ReadinessCounts, ReadyDeliveryReceipt,
        ReadySetId, ReadySourceId, SubscriptionToken, TriggerMode,
    },
};

const SCOPE: ScopeKey = ScopeKey::new(105, 1);
const GUEST: TaskKey = TaskKey::new(1050, 1);
const NETD_V1: TaskKey = TaskKey::new(1051, 1);
const NETD_V2: TaskKey = TaskKey::new(1052, 1);
const READINESS_TASK: TaskKey = TaskKey::new(1053, 1);
const BUFFER_TASK: TaskKey = TaskKey::new(1054, 1);
const AUTHORITY_EPOCH: u64 = 241;
const INITIAL_BINDING_EPOCH: u64 = 1;

const CONTROL_CREDIT: CreditClass = CreditClass::new(1);
const NETWORK_CREDIT: CreditClass = CreditClass::new(2);
const READINESS_CREDIT: CreditClass = CreditClass::new(3);
const BUFFER_CREDIT: CreditClass = CreditClass::new(4);
const OP_SYSCALL: OperationClass = OperationClass::new(1);
const OP_READINESS: OperationClass = OperationClass::new(2);
const OP_BUFFER: OperationClass = OperationClass::new(3);

const PROCESS_RESOURCE: ResourceKey = ResourceKey::new(0x8100, 1, 1);
const LISTENER_RESOURCE: ResourceKey = ResourceKey::new(0x8101, 1, 1);
const CLIENT_RESOURCE: ResourceKey = ResourceKey::new(0x8101, 2, 1);
const ACCEPTED_RESOURCE: ResourceKey = ResourceKey::new(0x8101, 3, 1);
const READY_RESOURCE: ResourceKey = ResourceKey::new(0x8102, 1, 1);
const BUFFER_RESOURCE: ResourceKey = ResourceKey::new(0x8103, 1, 1);

const EXECUTABLE_NAME: &[u8] = b"/bin/linux-runtime-net-smoke\0";
const EXPECTED_STDOUT: &[u8] = b"runtime net ok\n";
const EXPECTED_SOURCE_SHA256: &str =
    "65ba020b526fe1cbf05feef0739791a3ae6274b2ffa2b39d385ce88e1a086ecf";
const EXPECTED_ELF_SHA256: &str =
    "8cdd5864c07e51e91d9e0a6ec94e4d7d6438db2fbb39d513bfb7c5624d32f549";

const AF_INET: usize = 2;
const SOCK_STREAM: usize = 1;
const SOL_SOCKET: usize = 1;
const SO_REUSEADDR: usize = 2;
const IPPROTO_TCP: usize = 6;
const TCP_NODELAY: usize = 1;
const SHUT_WR: usize = 1;
const SOCKADDR_LEN: usize = 16;
const CLIENT_PORT: u16 = 49_153;
const EXPECTED_POLICY_FAULT: usize = 0x0080_0000;

const PORTAL_NEXT: usize = 0x4e74_0001;
const PORTAL_PREPARE: usize = 0x4e74_0002;
const PORTAL_COMMIT: usize = 0x4e74_0003;
const PORTAL_PUBLISH: usize = 0x4e74_0004;
const RECOVERY_SNAPSHOT: usize = 0x4e74_0010;
const READY: usize = 0x4e74_0011;
const REBIND: usize = 0x4e74_0012;
const ADOPT_NEXT: usize = 0x4e74_0013;
const REPLAY_OLD: usize = 0x4e74_0014;
const NETD_DONE: usize = 0x4e74_0020;
const PORTAL_FAIL: usize = 0x4e74_ffff;

const OP_WAIT: usize = 0;
const OP_NORMAL: usize = 1;
const OP_ACCEPT: usize = 2;
const OP_SHUTDOWN: usize = 3;
const RESULT_STALE_BINDING: usize = 2;

const SCENARIO_DONE_EFFECT: u64 = 1050;
const V1_DONE_EFFECT: u64 = 1051;
const V2_DONE_EFFECT: u64 = 1052;
const OP_WAIT_EFFECT_BASE: u64 = 1100;

const COMPANION_READY_FIRST_SCOPE: ScopeKey = ScopeKey::new(106, 1);
const COMPANION_REVOKE_FIRST_SCOPE: ScopeKey = ScopeKey::new(107, 1);
const COMPANION_PERSONALITY_SCOPE: ScopeKey = ScopeKey::new(108, 1);
const COMPANION_BUFFER_SCOPE: ScopeKey = ScopeKey::new(109, 1);
const COMPANION_STALE_SOCKET_SCOPE: ScopeKey = ScopeKey::new(110, 1);
const COMPANION_STALE_SOURCE_SCOPE: ScopeKey = ScopeKey::new(111, 1);
const COMPANION_V1: TaskKey = TaskKey::new(1060, 1);
const COMPANION_GUEST: TaskKey = TaskKey::new(1061, 1);
const COMPANION_READY_TASK: TaskKey = TaskKey::new(1062, 1);
const COMPANION_BUFFER_TASK: TaskKey = TaskKey::new(1063, 1);
const COMPANION_V2: TaskKey = TaskKey::new(1064, 1);
const COMPANION_AUTHORITY_EPOCH: u64 = 301;
const COMPANION_NETWORK_OP: OperationClass = OperationClass::new(11);
const COMPANION_SYSCALL_OP: OperationClass = OperationClass::new(12);
const COMPANION_RESOURCE: ResourceKey = ResourceKey::new(0x8200, 1, 1);

const RUNTIME_NET_ELF: &[u8] = include_bytes!("../../guest/linux-runtime-net.elf");

/// Read-only prerequisite proving that the retained network workload
/// completed earlier in this boot.  It intentionally carries no portal or
/// registered-effect handle into the fresh Linux I/O composition cohort.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeNetSliceReceipt {
    pub(crate) scope: ScopeKey,
    pub(crate) closed_authority_epoch: u64,
    pub(crate) final_authority_epoch: u64,
    pub(crate) terminalizations: usize,
    pub(crate) publication_acks: usize,
    pub(crate) quiescent: bool,
    pub(crate) source_sha256: &'static str,
    pub(crate) elf_sha256: &'static str,
}
const NETD_V1_PROGRAM: &[u8] = include_bytes!("../../guest/linux-netd-v1.bin");
const NETD_V2_PROGRAM: &[u8] = include_bytes!("../../guest/linux-netd-v2.bin");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FdRole {
    Listener,
    Client,
    Accepted,
}

impl FdRole {
    const fn label(self) -> &'static str {
        match self {
            Self::Listener => "listener",
            Self::Client => "client",
            Self::Accepted => "accepted",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PayloadDirection {
    ClientToAccepted,
    AcceptedToClient,
}

impl PayloadDirection {
    const fn label(self) -> &'static str {
        match self {
            Self::ClientToAccepted => "client_to_accepted",
            Self::AcceptedToClient => "accepted_to_client",
        }
    }

    const fn payload(self) -> [u8; 4] {
        match self {
            Self::ClientToAccepted => *b"ping",
            Self::AcceptedToClient => *b"pong",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Endpoint {
    Listener,
    ClientLocal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NetAction {
    Socket { fd: i32, role: FdRole },
    SetSockOpt { fd: i32, option: &'static str },
    Bind,
    GetSockName { fd: i32, endpoint: Endpoint },
    Listen,
    Connect,
    GetPeerName,
    Accept { fd: i32 },
    WritePayload { direction: PayloadDirection },
    ReadPayload { direction: PayloadDirection },
    Shutdown,
    ReadEof,
    Close { fd: i32, role: FdRole },
    Stdout,
    Exit,
}

impl NetAction {
    const fn portal_code(&self) -> usize {
        if matches!(self, Self::Accept { .. }) {
            OP_ACCEPT
        } else {
            OP_NORMAL
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GuestWrite {
    address: usize,
    bytes: Vec<u8>,
}

struct PlannedOperation {
    action: NetAction,
    result: i64,
    writes: Vec<GuestWrite>,
    resources: Vec<ResourceKey>,
}

struct ReadyPending {
    effect: EffectKey,
    handle: PortalHandle,
    subscription: SubscriptionToken,
}

struct BufferLease {
    effect: EffectKey,
    handle: PortalHandle,
    direction: PayloadDirection,
    bytes: [u8; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingPhase {
    Captured,
    Prepared,
    Committed,
    Published,
}

struct PendingOperation {
    index: usize,
    action: NetAction,
    result: i64,
    writes: Vec<GuestWrite>,
    effect: EffectKey,
    handle: PortalHandle,
    ready: Option<ReadyPending>,
    commit: Option<CommitReceipt>,
    phase: PendingPhase,
    waiter_waker: Option<EffectWaker>,
    ticket: Option<PublicationTicket>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DomainEpochs {
    personality: u64,
    netd: u64,
    readiness: u64,
    socket_generation: u64,
    source_generation: u64,
}

impl DomainEpochs {
    const fn new() -> Self {
        Self {
            personality: 1,
            netd: 1,
            readiness: 1,
            socket_generation: 1,
            source_generation: 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MainBufferProjection {
    effect: EffectKey,
    handle: PortalHandle,
    direction: PayloadDirection,
    bytes: [u8; 4],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MainPendingProjection {
    index: usize,
    action: NetAction,
    result: i64,
    writes: Vec<GuestWrite>,
    effect: EffectKey,
    handle: PortalHandle,
    ready: Option<(EffectKey, PortalHandle, SubscriptionToken)>,
    commit: Option<CommitReceipt>,
    phase: PendingPhase,
    waiter_waker_present: bool,
    ticket: Option<PublicationTicket>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MainProtocolProjection {
    ready_source: ReadySourceId,
    ready_set: ReadySetId,
    fds: BTreeMap<i32, FdRole>,
    next_fd: i32,
    reuseaddr: bool,
    nodelay: bool,
    listener_bound: bool,
    listener_listening: bool,
    pending_connection: bool,
    client_connected: bool,
    client_shutdown: bool,
    client_to_accepted: Option<MainBufferProjection>,
    accepted_to_client: Option<MainBufferProjection>,
    pending: Option<MainPendingProjection>,
    recovery_snapshot: Option<RecoverySnapshot>,
    old_main_handle: Option<PortalHandle>,
    old_ready_handle: Option<PortalHandle>,
    domain_revision: u64,
    syscall_count: usize,
    syscall_terminalizations: usize,
    syscall_publication_acks: usize,
    stdout_publications: usize,
    readiness_deliveries: usize,
    buffer_leases_created: usize,
    buffer_leases_consumed: usize,
    stale_rejections: usize,
    v1_calls: usize,
    v2_calls: usize,
    v1_crashed: bool,
    service_done: bool,
    exited: bool,
    epochs: DomainEpochs,
    last_aux_effect: Option<u64>,
    last_ready_sequence: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MainSemanticProjection {
    registry: String,
    readiness: String,
    protocol: MainProtocolProjection,
}

fn main_projection_fingerprint(projection: &MainSemanticProjection) -> u64 {
    format!("{projection:?}")
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |fingerprint, byte| {
            (fingerprint ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
}

struct NetState {
    effects: EffectRegistry,
    readiness: ReadinessCore,
    ready_source: ReadySourceId,
    ready_set: ReadySetId,
    fds: BTreeMap<i32, FdRole>,
    next_fd: i32,
    reuseaddr: bool,
    nodelay: bool,
    listener_bound: bool,
    listener_listening: bool,
    pending_connection: bool,
    client_connected: bool,
    client_shutdown: bool,
    client_to_accepted: Option<BufferLease>,
    accepted_to_client: Option<BufferLease>,
    pending: Option<PendingOperation>,
    recovery_snapshot: Option<RecoverySnapshot>,
    old_main_handle: Option<PortalHandle>,
    old_ready_handle: Option<PortalHandle>,
    domain_revision: u64,
    syscall_count: usize,
    syscall_terminalizations: usize,
    syscall_publication_acks: usize,
    stdout_publications: usize,
    readiness_deliveries: usize,
    buffer_leases_created: usize,
    buffer_leases_consumed: usize,
    stale_rejections: usize,
    v1_calls: usize,
    v2_calls: usize,
    v1_crashed: bool,
    service_done: bool,
    exited: bool,
    epochs: DomainEpochs,
    last_aux_effect: Option<u64>,
    last_ready_sequence: Option<u64>,
}

impl NetState {
    fn new() -> Self {
        let mut effects = EffectRegistry::new();
        effects
            .create_scope(ScopeConfig {
                key: SCOPE,
                authority_epoch: AUTHORITY_EPOCH,
                binding_epoch: INITIAL_BINDING_EPOCH,
                supervisor: NETD_V1,
                credits: vec![
                    CreditLimit::new(CONTROL_CREDIT, 1),
                    CreditLimit::new(NETWORK_CREDIT, 1),
                    CreditLimit::new(READINESS_CREDIT, 1),
                    CreditLimit::new(BUFFER_CREDIT, 1),
                ],
            })
            .unwrap();
        let mut readiness = ReadinessCore::new();
        let ready_source = readiness.create_source(1, 0).unwrap();
        let ready_set = readiness.create_set().unwrap();
        Self {
            effects,
            readiness,
            ready_source,
            ready_set,
            fds: BTreeMap::new(),
            next_fd: 3,
            reuseaddr: false,
            nodelay: false,
            listener_bound: false,
            listener_listening: false,
            pending_connection: false,
            client_connected: false,
            client_shutdown: false,
            client_to_accepted: None,
            accepted_to_client: None,
            pending: None,
            recovery_snapshot: None,
            old_main_handle: None,
            old_ready_handle: None,
            domain_revision: 0,
            syscall_count: 0,
            syscall_terminalizations: 0,
            syscall_publication_acks: 0,
            stdout_publications: 0,
            readiness_deliveries: 0,
            buffer_leases_created: 0,
            buffer_leases_consumed: 0,
            stale_rejections: 0,
            v1_calls: 0,
            v2_calls: 0,
            v1_crashed: false,
            service_done: false,
            exited: false,
            epochs: DomainEpochs::new(),
            last_aux_effect: None,
            last_ready_sequence: None,
        }
    }

    fn semantic_projection(&self) -> MainSemanticProjection {
        let project_buffer = |lease: &BufferLease| MainBufferProjection {
            effect: lease.effect,
            handle: lease.handle,
            direction: lease.direction,
            bytes: lease.bytes,
        };
        let pending = self.pending.as_ref().map(|pending| MainPendingProjection {
            index: pending.index,
            action: pending.action.clone(),
            result: pending.result,
            writes: pending.writes.clone(),
            effect: pending.effect,
            handle: pending.handle,
            ready: pending
                .ready
                .as_ref()
                .map(|ready| (ready.effect, ready.handle, ready.subscription)),
            commit: pending.commit.clone(),
            phase: pending.phase,
            waiter_waker_present: pending.waiter_waker.is_some(),
            ticket: pending.ticket.clone(),
        });
        MainSemanticProjection {
            registry: format!("{:?}", self.effects),
            readiness: format!("{:?}", self.readiness),
            protocol: MainProtocolProjection {
                ready_source: self.ready_source,
                ready_set: self.ready_set,
                fds: self.fds.clone(),
                next_fd: self.next_fd,
                reuseaddr: self.reuseaddr,
                nodelay: self.nodelay,
                listener_bound: self.listener_bound,
                listener_listening: self.listener_listening,
                pending_connection: self.pending_connection,
                client_connected: self.client_connected,
                client_shutdown: self.client_shutdown,
                client_to_accepted: self.client_to_accepted.as_ref().map(project_buffer),
                accepted_to_client: self.accepted_to_client.as_ref().map(project_buffer),
                pending,
                recovery_snapshot: self.recovery_snapshot.clone(),
                old_main_handle: self.old_main_handle,
                old_ready_handle: self.old_ready_handle,
                domain_revision: self.domain_revision,
                syscall_count: self.syscall_count,
                syscall_terminalizations: self.syscall_terminalizations,
                syscall_publication_acks: self.syscall_publication_acks,
                stdout_publications: self.stdout_publications,
                readiness_deliveries: self.readiness_deliveries,
                buffer_leases_created: self.buffer_leases_created,
                buffer_leases_consumed: self.buffer_leases_consumed,
                stale_rejections: self.stale_rejections,
                v1_calls: self.v1_calls,
                v2_calls: self.v2_calls,
                v1_crashed: self.v1_crashed,
                service_done: self.service_done,
                exited: self.exited,
                epochs: self.epochs,
                last_aux_effect: self.last_aux_effect,
                last_ready_sequence: self.last_ready_sequence,
            },
        }
    }

    fn resource_for_fd(&self, fd: i32) -> ResourceKey {
        match self.fds.get(&fd).copied() {
            Some(FdRole::Listener) => LISTENER_RESOURCE,
            Some(FdRole::Client) => CLIENT_RESOURCE,
            Some(FdRole::Accepted) => ACCEPTED_RESOURCE,
            None if fd == self.next_fd => match fd {
                3 => LISTENER_RESOURCE,
                4 => CLIENT_RESOURCE,
                5 => ACCEPTED_RESOURCE,
                _ => panic!("unsupported bounded network fd {fd}"),
            },
            None => panic!("unknown bounded network fd {fd}"),
        }
    }

    fn plan(&self, vm_space: &VmSpace, descriptor: SyscallDescriptor) -> PlannedOperation {
        let number = descriptor.number();
        let mut resources = vec![PROCESS_RESOURCE];
        let (action, result, writes) = match number {
            number if number == __NR_socket as usize => {
                assert_eq!(descriptor.argument(0), AF_INET);
                assert_eq!(descriptor.argument(1), SOCK_STREAM);
                assert_eq!(descriptor.argument(2), 0);
                let fd = self.next_fd;
                let role = match fd {
                    3 => FdRole::Listener,
                    4 => FdRole::Client,
                    _ => panic!("retained guest creates exactly two sockets"),
                };
                resources.push(self.resource_for_fd(fd));
                (NetAction::Socket { fd, role }, i64::from(fd), Vec::new())
            }
            number if number == __NR_setsockopt as usize => {
                let fd = descriptor.argument(0) as i32;
                resources.push(self.resource_for_fd(fd));
                assert_eq!(descriptor.argument(4), 4);
                assert_eq!(read_guest_u32(vm_space, descriptor.argument(3)), 1);
                let option = match self.fds.get(&fd) {
                    Some(FdRole::Listener) => {
                        assert_eq!(descriptor.argument(1), SOL_SOCKET);
                        assert_eq!(descriptor.argument(2), SO_REUSEADDR);
                        "SO_REUSEADDR"
                    }
                    Some(FdRole::Client) => {
                        assert_eq!(descriptor.argument(1), IPPROTO_TCP);
                        assert_eq!(descriptor.argument(2), TCP_NODELAY);
                        "TCP_NODELAY"
                    }
                    other => panic!("setsockopt on unsupported fd role {other:?}"),
                };
                (NetAction::SetSockOpt { fd, option }, 0, Vec::new())
            }
            number if number == __NR_bind as usize => {
                assert_eq!(descriptor.argument(0) as i32, 3);
                assert_eq!(descriptor.argument(2), SOCKADDR_LEN);
                assert_eq!(
                    read_guest_bytes(vm_space, descriptor.argument(1), SOCKADDR_LEN),
                    listener_sockaddr().to_vec(),
                );
                resources.push(LISTENER_RESOURCE);
                (NetAction::Bind, 0, Vec::new())
            }
            number if number == __NR_getsockname as usize => {
                let fd = descriptor.argument(0) as i32;
                assert_eq!(read_guest_u32(vm_space, descriptor.argument(2)), 16);
                resources.push(self.resource_for_fd(fd));
                let endpoint = match self.fds.get(&fd) {
                    Some(FdRole::Listener) => Endpoint::Listener,
                    Some(FdRole::Client) => Endpoint::ClientLocal,
                    other => panic!("getsockname on unsupported fd role {other:?}"),
                };
                let bytes = match endpoint {
                    Endpoint::Listener => listener_sockaddr(),
                    Endpoint::ClientLocal => client_sockaddr(),
                };
                (
                    NetAction::GetSockName { fd, endpoint },
                    0,
                    sockaddr_writes(descriptor.argument(1), descriptor.argument(2), bytes),
                )
            }
            number if number == __NR_listen as usize => {
                assert_eq!(descriptor.argument(0) as i32, 3);
                assert_eq!(descriptor.argument(1), 4);
                resources.push(LISTENER_RESOURCE);
                (NetAction::Listen, 0, Vec::new())
            }
            number if number == __NR_connect as usize => {
                assert_eq!(descriptor.argument(0) as i32, 4);
                assert_eq!(descriptor.argument(2), SOCKADDR_LEN);
                assert_eq!(
                    read_guest_bytes(vm_space, descriptor.argument(1), SOCKADDR_LEN),
                    listener_sockaddr().to_vec(),
                );
                resources.extend([CLIENT_RESOURCE, LISTENER_RESOURCE, READY_RESOURCE]);
                (NetAction::Connect, 0, Vec::new())
            }
            number if number == __NR_getpeername as usize => {
                assert_eq!(descriptor.argument(0) as i32, 4);
                assert_eq!(read_guest_u32(vm_space, descriptor.argument(2)), 16);
                resources.push(CLIENT_RESOURCE);
                (
                    NetAction::GetPeerName,
                    0,
                    sockaddr_writes(
                        descriptor.argument(1),
                        descriptor.argument(2),
                        listener_sockaddr(),
                    ),
                )
            }
            number if number == __NR_accept4 as usize => {
                assert_eq!(descriptor.argument(0) as i32, 3);
                assert_eq!(descriptor.argument(3), 0);
                assert_eq!(read_guest_u32(vm_space, descriptor.argument(2)), 16);
                assert!(self.pending_connection);
                let fd = self.next_fd;
                assert_eq!(fd, 5);
                resources.extend([LISTENER_RESOURCE, ACCEPTED_RESOURCE, READY_RESOURCE]);
                (
                    NetAction::Accept { fd },
                    i64::from(fd),
                    sockaddr_writes(
                        descriptor.argument(1),
                        descriptor.argument(2),
                        client_sockaddr(),
                    ),
                )
            }
            number if number == __NR_write as usize && descriptor.argument(0) != 1 => {
                assert_eq!(descriptor.argument(2), 4);
                let fd = descriptor.argument(0) as i32;
                let direction = match self.fds.get(&fd) {
                    Some(FdRole::Client) => PayloadDirection::ClientToAccepted,
                    Some(FdRole::Accepted) => PayloadDirection::AcceptedToClient,
                    other => panic!("payload write on unsupported fd role {other:?}"),
                };
                assert_eq!(
                    read_guest_bytes(vm_space, descriptor.argument(1), 4),
                    direction.payload().to_vec(),
                );
                resources.extend([self.resource_for_fd(fd), BUFFER_RESOURCE]);
                (NetAction::WritePayload { direction }, 4, Vec::new())
            }
            number if number == __NR_read as usize => {
                assert_eq!(descriptor.argument(2), 4);
                let fd = descriptor.argument(0) as i32;
                resources.push(self.resource_for_fd(fd));
                if fd == 5 && self.client_shutdown && self.client_to_accepted.is_none() {
                    (NetAction::ReadEof, 0, Vec::new())
                } else {
                    let direction = match self.fds.get(&fd) {
                        Some(FdRole::Accepted) => PayloadDirection::ClientToAccepted,
                        Some(FdRole::Client) => PayloadDirection::AcceptedToClient,
                        other => panic!("payload read on unsupported fd role {other:?}"),
                    };
                    let lease = self.buffer(direction).expect("fixed payload is queued");
                    resources.push(BUFFER_RESOURCE);
                    (
                        NetAction::ReadPayload { direction },
                        4,
                        vec![GuestWrite {
                            address: descriptor.argument(1),
                            bytes: lease.bytes.to_vec(),
                        }],
                    )
                }
            }
            number if number == __NR_shutdown as usize => {
                assert_eq!(descriptor.argument(0) as i32, 4);
                assert_eq!(descriptor.argument(1), SHUT_WR);
                resources.extend([CLIENT_RESOURCE, ACCEPTED_RESOURCE, READY_RESOURCE]);
                (NetAction::Shutdown, 0, Vec::new())
            }
            number if number == __NR_close as usize => {
                let fd = descriptor.argument(0) as i32;
                let role = *self.fds.get(&fd).expect("bounded close fd");
                resources.push(self.resource_for_fd(fd));
                (NetAction::Close { fd, role }, 0, Vec::new())
            }
            other => panic!("unsupported retained runtime-net network syscall {other}"),
        };
        PlannedOperation {
            action,
            result,
            writes,
            resources,
        }
    }

    fn enqueue(
        &mut self,
        vm_space: &VmSpace,
        descriptor: SyscallDescriptor,
        waiter_waker: EffectWaker,
    ) -> usize {
        assert!(self.pending.is_none());
        assert!(self.effects.effects_for_task(GUEST).is_empty());
        let plan = self.plan(vm_space, descriptor);
        self.syscall_count += 1;
        assert!(self.syscall_count <= 20);
        let registered = self
            .effects
            .register(RegisterRequest {
                scope: SCOPE,
                task: GUEST,
                operation: OP_SYSCALL,
                descriptor,
                resources: plan.resources,
                credits: vec![CreditCharge::new(NETWORK_CREDIT, 1)],
                publication: PublicationMode::Required,
            })
            .unwrap();
        let mut ready = None;
        if matches!(plan.action, NetAction::Accept { .. }) {
            let companion = self
                .effects
                .register(RegisterRequest {
                    scope: SCOPE,
                    task: READINESS_TASK,
                    operation: OP_READINESS,
                    descriptor,
                    resources: vec![LISTENER_RESOURCE, READY_RESOURCE],
                    credits: vec![CreditCharge::new(READINESS_CREDIT, 1)],
                    publication: PublicationMode::None,
                })
                .unwrap();
            let subscription = self
                .readiness
                .attach(
                    self.ready_set,
                    self.ready_source,
                    companion.identity.effect(),
                    self.epochs.netd,
                    READY_READABLE,
                    TriggerMode::OneShot,
                    0x4242,
                )
                .unwrap();
            ready = Some(ReadyPending {
                effect: companion.identity.effect(),
                handle: companion.handle,
                subscription,
            });
        }
        let effect = registered.identity.effect();
        self.pending = Some(PendingOperation {
            index: self.syscall_count,
            action: plan.action,
            result: plan.result,
            writes: plan.writes,
            effect,
            handle: registered.handle,
            ready,
            commit: None,
            phase: PendingPhase::Captured,
            waiter_waker: Some(waiter_waker),
            ticket: None,
        });
        self.effects.check_invariants().unwrap();
        self.readiness.check_invariants().unwrap();
        effect.id() as usize
    }

    fn next_operation(&mut self, sender: TaskKey) -> usize {
        if self.service_done {
            return OP_SHUTDOWN;
        }
        let Some(pending) = self.pending.as_ref() else {
            return OP_WAIT;
        };
        if pending.phase != PendingPhase::Captured {
            return OP_WAIT;
        }
        if sender == NETD_V1 {
            self.v1_calls += 1;
        } else {
            assert_eq!(sender, NETD_V2);
            self.v2_calls += 1;
        }
        pending.action.portal_code()
    }

    fn prepare_active(&mut self, sender: TaskKey) {
        let pending = self.pending.as_mut().expect("one queued network operation");
        assert_eq!(pending.phase, PendingPhase::Captured);
        self.effects.prepare(sender, pending.handle).unwrap();
        if let Some(ready) = &pending.ready {
            self.effects.prepare(sender, ready.handle).unwrap();
        }
        pending.phase = PendingPhase::Prepared;
        self.effects.check_invariants().unwrap();
    }

    fn commit_handle(
        &mut self,
        sender: TaskKey,
        handle: PortalHandle,
        result: i64,
    ) -> CommitReceipt {
        let revision = self.domain_revision.checked_add(1).unwrap();
        match self
            .effects
            .commit(sender, handle, CommitMetadata::new(result, revision))
            .unwrap()
        {
            CommitOutcome::Applied(receipt) => receipt,
            CommitOutcome::AlreadyCommitted(_) => panic!("fresh runtime-net commit replayed"),
        }
    }

    fn record_domain_change(&mut self, commit: &CommitReceipt) {
        assert_eq!(commit.domain_revision(), self.domain_revision + 1);
        self.domain_revision = commit.domain_revision();
        self.effects
            .domain_changed(SCOPE, self.domain_revision)
            .unwrap();
    }

    fn commit_active(&mut self, sender: TaskKey) {
        let mut pending = self.pending.take().expect("one prepared network operation");
        assert_eq!(pending.phase, PendingPhase::Prepared);
        self.last_aux_effect = None;
        self.last_ready_sequence = None;

        let commit = self.commit_handle(sender, pending.handle, pending.result);
        let sequence = commit.sequence();
        let consumed_buffer = self.apply_action(sender, &pending.action, &mut pending.ready);
        self.record_domain_change(&commit);
        if let Some(lease) = consumed_buffer {
            self.finish_buffer_consumption(sender, lease);
        }
        self.finish_companions(sender, &pending.action, &mut pending.ready);
        self.emit_receipt(&pending, sequence);
        pending.commit = Some(commit);
        pending.phase = PendingPhase::Committed;
        self.pending = Some(pending);
        self.effects.check_invariants().unwrap();
        self.readiness.check_invariants().unwrap();
    }

    fn apply_action(
        &mut self,
        sender: TaskKey,
        action: &NetAction,
        _ready: &mut Option<ReadyPending>,
    ) -> Option<BufferLease> {
        if let NetAction::ReadPayload { direction } = *action {
            let lease = self
                .take_buffer(direction)
                .expect("fixed payload lease remains owned until read");
            assert_eq!(lease.direction, direction);
            assert_eq!(lease.bytes, direction.payload());
            self.last_aux_effect = Some(lease.effect.id());
            self.buffer_leases_consumed += 1;
            return Some(lease);
        }
        match *action {
            NetAction::Socket { fd, role } => {
                assert_eq!(fd, self.next_fd);
                assert!(self.fds.insert(fd, role).is_none());
                self.next_fd += 1;
            }
            NetAction::SetSockOpt {
                option: "SO_REUSEADDR",
                ..
            } => {
                assert!(!self.reuseaddr);
                self.reuseaddr = true;
            }
            NetAction::SetSockOpt {
                option: "TCP_NODELAY",
                ..
            } => {
                assert!(!self.nodelay);
                self.nodelay = true;
            }
            NetAction::SetSockOpt { option, .. } => panic!("unknown fixed option {option}"),
            NetAction::Bind => {
                assert!(self.reuseaddr);
                self.listener_bound = true;
            }
            NetAction::GetSockName { .. } | NetAction::GetPeerName => {}
            NetAction::Listen => {
                assert!(self.listener_bound);
                self.listener_listening = true;
            }
            NetAction::Connect => {
                assert!(self.listener_listening && self.nodelay);
                self.client_connected = true;
                self.pending_connection = true;
                self.readiness
                    .source_update(self.ready_source, self.epochs.readiness, READY_READABLE)
                    .unwrap();
            }
            NetAction::Accept { fd } => {
                assert!(self.pending_connection);
                assert_eq!(fd, self.next_fd);
                assert!(self.fds.insert(fd, FdRole::Accepted).is_none());
                self.next_fd += 1;
                self.pending_connection = false;
            }
            NetAction::WritePayload { direction } => {
                assert!(self.buffer(direction).is_none());
                let registered = self
                    .effects
                    .register(RegisterRequest {
                        scope: SCOPE,
                        task: BUFFER_TASK,
                        operation: OP_BUFFER,
                        descriptor: SyscallDescriptor::new(__NR_write as usize, [0; 6]),
                        resources: vec![BUFFER_RESOURCE],
                        credits: vec![CreditCharge::new(BUFFER_CREDIT, 1)],
                        publication: PublicationMode::None,
                    })
                    .unwrap();
                self.effects.prepare(sender, registered.handle).unwrap();
                self.last_aux_effect = Some(registered.identity.effect().id());
                self.buffer_leases_created += 1;
                self.set_buffer(
                    direction,
                    Some(BufferLease {
                        effect: registered.identity.effect(),
                        handle: registered.handle,
                        direction,
                        bytes: direction.payload(),
                    }),
                );
            }
            NetAction::ReadPayload { .. } => unreachable!(),
            NetAction::Shutdown => {
                assert!(self.client_connected);
                self.client_shutdown = true;
                self.readiness
                    .source_update(self.ready_source, self.epochs.readiness, READY_HANGUP)
                    .unwrap();
            }
            NetAction::ReadEof => assert!(self.client_shutdown),
            NetAction::Close { fd, role } => {
                assert_eq!(self.fds.remove(&fd), Some(role));
            }
            NetAction::Stdout => {
                assert_eq!(self.stdout_publications, 0);
                self.stdout_publications = 1;
            }
            NetAction::Exit => self.exited = true,
        }
        None
    }

    fn finish_buffer_consumption(&mut self, sender: TaskKey, lease: BufferLease) {
        let commit = self.commit_handle(sender, lease.handle, 4);
        self.record_domain_change(&commit);
        let terminal = self
            .effects
            .stage_terminal(
                sender,
                lease.handle,
                TerminalRequest::completed_by(4, commit),
            )
            .unwrap();
        assert!(terminal.publication.is_none());
    }

    fn finish_companions(
        &mut self,
        sender: TaskKey,
        action: &NetAction,
        ready: &mut Option<ReadyPending>,
    ) {
        if !matches!(action, NetAction::Accept { .. }) {
            assert!(ready.is_none());
            return;
        }
        let ready = ready.take().expect("accept owns one readiness effect");
        let delivery = self
            .readiness
            .commit_delivery(self.ready_set, ready.effect, 1, self.epochs.netd)
            .unwrap();
        assert_eq!(delivery.events().len(), 1);
        assert_eq!(delivery.events()[0].source, self.ready_source);
        assert_eq!(delivery.events()[0].observed_mask, READY_READABLE);
        self.readiness.publish_delivery(&delivery).unwrap();
        assert_eq!(
            self.readiness.detach(ready.subscription).unwrap(),
            ready.effect
        );
        self.readiness
            .source_update(self.ready_source, self.epochs.readiness, 0)
            .unwrap();
        let commit = self.commit_handle(sender, ready.handle, 1);
        self.record_domain_change(&commit);
        let terminal = self
            .effects
            .stage_terminal(
                sender,
                ready.handle,
                TerminalRequest::completed_by(1, commit),
            )
            .unwrap();
        assert!(terminal.publication.is_none());
        self.last_aux_effect = Some(ready.effect.id());
        self.last_ready_sequence = Some(delivery.sequence());
        self.readiness_deliveries += 1;
    }

    fn publish_active(&mut self, sender: TaskKey) -> EffectWaker {
        let pending = self
            .pending
            .as_mut()
            .expect("one committed network operation");
        assert_eq!(pending.phase, PendingPhase::Committed);
        let commit = pending.commit.clone().unwrap();
        let terminal = self
            .effects
            .stage_terminal(
                sender,
                pending.handle,
                TerminalRequest::completed_by(pending.result, commit),
            )
            .unwrap();
        pending.ticket = Some(terminal.publication.expect("network syscall publication"));
        pending.phase = PendingPhase::Published;
        self.syscall_terminalizations += 1;
        self.effects.check_invariants().unwrap();
        pending
            .waiter_waker
            .take()
            .expect("one blocked retained-network continuation")
    }

    fn take_published(&mut self) -> PendingOperation {
        let pending = self.pending.take().expect("published network operation");
        assert_eq!(pending.phase, PendingPhase::Published);
        pending
    }

    fn acknowledge(&mut self, ticket: &PublicationTicket) {
        self.effects.acknowledge_publication(ticket).unwrap();
        self.syscall_publication_acks += 1;
        self.effects.check_invariants().unwrap();
    }

    fn crash_v1(&mut self) {
        let pending = self
            .pending
            .as_ref()
            .expect("accept is prepared at v1 crash");
        assert!(matches!(pending.action, NetAction::Accept { .. }));
        assert_eq!(pending.phase, PendingPhase::Prepared);
        self.old_main_handle = Some(pending.handle);
        self.old_ready_handle = Some(pending.ready.as_ref().unwrap().handle);
        let peer_before = (self.epochs.personality, self.epochs.readiness);
        let crash = self.effects.crash(SCOPE, NETD_V1).unwrap();
        assert_eq!(crash.previous_binding_epoch, self.epochs.netd);
        self.epochs.netd = crash.binding_epoch;
        assert_eq!(
            peer_before,
            (self.epochs.personality, self.epochs.readiness)
        );
        assert_eq!(crash.cohort.len(), 2);
        self.v1_crashed = true;
        println!(
            "NETWORK_LIFECYCLE NetdCrash syscall=10 old_binding={} new_binding={} cohort=2 prepared_accept=true prepared_readiness=true peer_epochs_unchanged=true real_user_page_fault=true",
            crash.previous_binding_epoch, crash.binding_epoch,
        );
    }

    fn recovery_snapshot(&mut self) {
        assert!(self.v1_crashed);
        let snapshot = self.effects.recovery_snapshot(SCOPE, NETD_V2).unwrap();
        assert_eq!(snapshot.effects.len(), 2);
        assert_eq!(snapshot.binding_epoch, self.epochs.netd);
        self.recovery_snapshot = Some(snapshot);
        println!(
            "NETWORK_LIFECYCLE Snapshot replacement={} binding={} cohort=2 exact=true",
            NETD_V2.id(),
            self.epochs.netd,
        );
    }

    fn recovery_ready(&mut self) {
        let snapshot = self.recovery_snapshot.as_ref().unwrap().clone();
        self.effects.ready(SCOPE, NETD_V2, &snapshot).unwrap();
        println!(
            "NETWORK_LIFECYCLE Ready replacement={} binding={} snapshot_fresh=true",
            NETD_V2.id(),
            self.epochs.netd,
        );
    }

    fn recovery_rebind(&mut self) {
        let receipt = self.effects.rebind(SCOPE, NETD_V2).unwrap();
        assert_eq!(receipt.binding_epoch, self.epochs.netd);
        println!(
            "NETWORK_LIFECYCLE Rebind replacement={} binding={} personality_binding={} readiness_binding={} peer_epochs_unchanged=true",
            NETD_V2.id(),
            receipt.binding_epoch,
            self.epochs.personality,
            self.epochs.readiness,
        );
    }

    fn adopt_next(&mut self) -> bool {
        let Some(item) = self.effects.recover_next(SCOPE, NETD_V2).unwrap() else {
            return false;
        };
        assert_eq!(item.phase, EffectPhase::Prepared);
        let old = item.handle;
        let fresh = self.effects.adopt(SCOPE, NETD_V2, old).unwrap();
        let pending = self.pending.as_mut().unwrap();
        let label = if old.effect() == pending.effect {
            pending.handle = fresh;
            "accept"
        } else {
            let ready = pending.ready.as_mut().unwrap();
            assert_eq!(old.effect(), ready.effect);
            ready.handle = fresh;
            self.readiness
                .adopt_subscription(ready.subscription, INITIAL_BINDING_EPOCH, self.epochs.netd)
                .unwrap();
            "readiness"
        };
        println!(
            "NETWORK_LIFECYCLE Adopt replacement={} effect={} kind={} old_binding={} new_binding={} explicit=true",
            NETD_V2.id(),
            old.effect().id(),
            label,
            old.binding_epoch(),
            fresh.binding_epoch(),
        );
        true
    }

    fn reject_late_v1(&mut self) {
        let old = self.old_main_handle.unwrap();
        let before = self.semantic_projection();
        let before_fingerprint = main_projection_fingerprint(&before);
        assert_eq!(
            self.effects.prepare(NETD_V1, old),
            Err(RegistryError::StaleBinding)
        );
        let after = self.semantic_projection();
        let after_fingerprint = main_projection_fingerprint(&after);
        assert_eq!(after, before);
        assert_eq!(after_fingerprint, before_fingerprint);
        self.stale_rejections += 1;
        println!(
            "NETWORK_LIFECYCLE StaleReplay sender={} old_binding={} current_binding={} result=StaleBinding projection_before={:016x} projection_after={:016x} full_projection_unchanged=true mutation=false",
            NETD_V1.id(),
            old.binding_epoch(),
            self.epochs.netd,
            before_fingerprint,
            after_fingerprint,
        );
    }

    fn direct_local(
        &mut self,
        vm_space: &VmSpace,
        descriptor: SyscallDescriptor,
    ) -> (i64, PublicationTicket, bool) {
        assert!(self.pending.is_none());
        self.syscall_count += 1;
        assert!(matches!(self.syscall_count, 21 | 22));
        let (action, result, resources, exit) = if descriptor.number() == __NR_write as usize {
            assert_eq!(self.syscall_count, 21);
            assert_eq!(descriptor.argument(0), 1);
            assert_eq!(
                read_guest_bytes(vm_space, descriptor.argument(1), descriptor.argument(2)),
                EXPECTED_STDOUT.to_vec(),
            );
            (
                NetAction::Stdout,
                EXPECTED_STDOUT.len() as i64,
                vec![PROCESS_RESOURCE],
                false,
            )
        } else {
            assert_eq!(descriptor.number(), __NR_exit as usize);
            assert_eq!(self.syscall_count, 22);
            assert_eq!(descriptor.argument(0), 0);
            (NetAction::Exit, 0, vec![PROCESS_RESOURCE], true)
        };
        let registered = self
            .effects
            .register(RegisterRequest {
                scope: SCOPE,
                task: GUEST,
                operation: OP_SYSCALL,
                descriptor,
                resources,
                credits: vec![CreditCharge::new(CONTROL_CREDIT, 1)],
                publication: PublicationMode::Required,
            })
            .unwrap();
        self.effects.prepare(NETD_V2, registered.handle).unwrap();
        let commit = self.commit_handle(NETD_V2, registered.handle, result);
        assert!(self.apply_action(NETD_V2, &action, &mut None).is_none());
        self.record_domain_change(&commit);
        let pending = PendingOperation {
            index: self.syscall_count,
            action,
            result,
            writes: Vec::new(),
            effect: registered.identity.effect(),
            handle: registered.handle,
            ready: None,
            commit: Some(commit.clone()),
            phase: PendingPhase::Committed,
            waiter_waker: None,
            ticket: None,
        };
        self.last_aux_effect = None;
        self.last_ready_sequence = None;
        self.emit_receipt(&pending, commit.sequence());
        let terminal = self
            .effects
            .stage_terminal(
                NETD_V2,
                registered.handle,
                TerminalRequest::completed_by(result, commit),
            )
            .unwrap();
        self.syscall_terminalizations += 1;
        (result, terminal.publication.unwrap(), exit)
    }

    fn finish(&mut self) {
        assert!(self.exited);
        assert!(self.pending.is_none());
        assert!(self.fds.is_empty());
        assert!(self.client_to_accepted.is_none());
        assert!(self.accepted_to_client.is_none());
        self.readiness.retire_source(self.ready_source).unwrap();
        self.readiness.destroy_set(self.ready_set).unwrap();
        self.domain_revision += 1;
        self.effects
            .domain_changed(SCOPE, self.domain_revision)
            .unwrap();
        self.readiness.check_invariants().unwrap();
        let selection = self.effects.revoke_begin(SCOPE).unwrap();
        assert!(self.effects.revoke_next(&selection).unwrap().is_none());
        self.effects.revoke_complete(&selection).unwrap();
        self.effects.check_invariants().unwrap();
        let projection = self.effects.scope_projection(SCOPE).unwrap();
        assert_eq!(projection.phase, ScopePhase::Revoked);
        assert_eq!(projection.live_effects, 0);
        assert_eq!(projection.pending_publications, 0);
        assert_eq!(projection.credits.free, projection.credits.capacity);
        assert_eq!(self.syscall_count, 22);
        assert_eq!(self.syscall_terminalizations, 22);
        assert_eq!(self.syscall_publication_acks, 22);
        assert_eq!(self.stdout_publications, 1);
        assert_eq!(self.readiness_deliveries, 1);
        assert_eq!(self.buffer_leases_created, 2);
        assert_eq!(self.buffer_leases_consumed, 2);
        assert_eq!(self.stale_rejections, 1);
        assert_eq!(self.v1_calls, 10);
        assert_eq!(self.v2_calls, 10);
        assert!(self.v1_crashed);
        self.service_done = true;
    }

    fn emit_receipt(&self, pending: &PendingOperation, sequence: u64) {
        let effect = pending.effect.id();
        let index = pending.index;
        match pending.action {
            NetAction::Socket { fd, role } => println!(
                "LINUX_NET Socket syscall={} effect={} commit_sequence={} fd={} domain=AF_INET type=SOCK_STREAM protocol=0 role={}",
                index,
                effect,
                sequence,
                fd,
                role.label(),
            ),
            NetAction::SetSockOpt { fd, option } => println!(
                "LINUX_NET SetSockOpt syscall={} effect={} commit_sequence={} fd={} option={} value=1 len=4 accepted=true",
                index, effect, sequence, fd, option,
            ),
            NetAction::Bind => println!(
                "LINUX_NET Bind syscall={} effect={} commit_sequence={} fd=3 address=127.0.0.1 port=4242 sockaddr_len=16",
                index, effect, sequence,
            ),
            NetAction::GetSockName { fd, endpoint } => println!(
                "LINUX_NET GetSockName syscall={} effect={} commit_sequence={} fd={} endpoint={} family=AF_INET address=127.0.0.1 port={} sockaddr_len=16",
                index,
                effect,
                sequence,
                fd,
                if endpoint == Endpoint::Listener {
                    "listener"
                } else {
                    "client_local"
                },
                if endpoint == Endpoint::Listener {
                    4242
                } else {
                    CLIENT_PORT
                },
            ),
            NetAction::Listen => println!(
                "LINUX_NET Listen syscall={} effect={} commit_sequence={} fd=3 backlog=4",
                index, effect, sequence,
            ),
            NetAction::Connect => println!(
                "LINUX_NET Connect syscall={} effect={} commit_sequence={} fd=4 peer=127.0.0.1:4242 local_port={} pending_accept=true ready_source={} ready_mask=READABLE",
                index,
                effect,
                sequence,
                CLIENT_PORT,
                self.ready_source.id(),
            ),
            NetAction::GetPeerName => println!(
                "LINUX_NET GetPeerName syscall={} effect={} commit_sequence={} fd=4 peer=127.0.0.1:4242 sockaddr_len=16",
                index, effect, sequence,
            ),
            NetAction::Accept { fd } => println!(
                "LINUX_NET Accept syscall={} effect={} commit_sequence={} fd={} listener=3 peer=127.0.0.1:{} flags=0 readiness_effect={} delivery_sequence={} recovered_by_v2=true",
                index,
                effect,
                sequence,
                fd,
                CLIENT_PORT,
                self.last_aux_effect.unwrap(),
                self.last_ready_sequence.unwrap(),
            ),
            NetAction::WritePayload { direction } => println!(
                "LINUX_NET Write syscall={} effect={} commit_sequence={} direction={} bytes=4 payload={} buffer_effect={} buffer_credit=Held",
                index,
                effect,
                sequence,
                direction.label(),
                core::str::from_utf8(&direction.payload()).unwrap(),
                self.last_aux_effect.unwrap(),
            ),
            NetAction::ReadPayload { direction } => println!(
                "LINUX_NET Read syscall={} effect={} commit_sequence={} direction={} bytes=4 payload={} buffer_effect={} buffer_credit=Returned",
                index,
                effect,
                sequence,
                direction.label(),
                core::str::from_utf8(&direction.payload()).unwrap(),
                self.last_aux_effect.unwrap(),
            ),
            NetAction::Shutdown => println!(
                "LINUX_NET Shutdown syscall={} effect={} commit_sequence={} fd=4 how=SHUT_WR peer_hangup=true",
                index, effect, sequence,
            ),
            NetAction::ReadEof => println!(
                "LINUX_NET Read syscall={} effect={} commit_sequence={} direction=accepted_from_client bytes=0 eof=true",
                index, effect, sequence,
            ),
            NetAction::Close { fd, role } => println!(
                "LINUX_NET Close syscall={} effect={} commit_sequence={} fd={} role={} remaining_runtime_fds={}",
                index,
                effect,
                sequence,
                fd,
                role.label(),
                self.fds.len(),
            ),
            NetAction::Stdout => {
                println!(
                    "LINUX_NET Write syscall={} effect={} commit_sequence={} fd=1 bytes=15 stdout_exact=true",
                    index, effect, sequence,
                );
                println!("LINUX_NET stdout=runtime net ok");
            }
            NetAction::Exit => println!(
                "LINUX_NET Exit syscall={} effect={} commit_sequence={} status=0 syscall=exit resumed_after_exit=false",
                index, effect, sequence,
            ),
        }
    }

    fn buffer(&self, direction: PayloadDirection) -> Option<&BufferLease> {
        match direction {
            PayloadDirection::ClientToAccepted => self.client_to_accepted.as_ref(),
            PayloadDirection::AcceptedToClient => self.accepted_to_client.as_ref(),
        }
    }

    fn set_buffer(&mut self, direction: PayloadDirection, lease: Option<BufferLease>) {
        match direction {
            PayloadDirection::ClientToAccepted => self.client_to_accepted = lease,
            PayloadDirection::AcceptedToClient => self.accepted_to_client = lease,
        }
    }

    fn take_buffer(&mut self, direction: PayloadDirection) -> Option<BufferLease> {
        match direction {
            PayloadDirection::ClientToAccepted => self.client_to_accepted.take(),
            PayloadDirection::AcceptedToClient => self.accepted_to_client.take(),
        }
    }
}

struct NetScenario {
    vm_space: Arc<VmSpace>,
    state: SpinLock<NetState>,
    done: SpinLock<Option<EffectWaker>>,
}

impl NetScenario {
    fn dispatch_network(&self, descriptor: SyscallDescriptor) -> i64 {
        let (waiter, waker) = {
            let mut state = self.state.lock();
            let index = state.syscall_count + 1;
            let (waiter, waker) = EffectWaiter::new_pair(EffectToken {
                authority_epoch: AUTHORITY_EPOCH,
                scope_id: SCOPE.id(),
                effect_id: OP_WAIT_EFFECT_BASE + index as u64,
            });
            state.enqueue(&self.vm_space, descriptor, waker);
            (waiter, index)
        };
        let _ = waker;
        waiter.wait();
        let pending = self.state.lock().take_published();
        for write in &pending.writes {
            write_guest_bytes(&self.vm_space, write.address, &write.bytes);
        }
        let ticket = pending.ticket.as_ref().unwrap().clone();
        let result = pending.result;
        self.state.lock().acknowledge(&ticket);
        result
    }

    fn dispatch_local(&self, descriptor: SyscallDescriptor) -> (i64, bool) {
        let (result, ticket, exit) = self.state.lock().direct_local(&self.vm_space, descriptor);
        assert_eq!(ticket.result(), result);
        self.state.lock().acknowledge(&ticket);
        if exit {
            let mut state = self.state.lock();
            state.finish();
            drop(state);
            println!(
                "EFFECT_REGISTRY Quiescent workload=linux-runtime-net live=0 pending_publications=0 credits=Free resources=empty"
            );
            println!(
                "LINUX_NET_SLICE PASS workload=linux-runtime-net-smoke retained=true adapted=false syscalls=22 unique_syscalls=13 network_ops=20 netd_v1_calls=10 netd_v2_calls=10 real_user_mode_netd=true real_v1_page_fault=true snapshot_ready_rebind_adopt=true ping_pong=true shutdown_eof=true commit_gate=true publication_acks=22 readiness=kernel_owned buffer_credit=consume_or_closure registry_quiescent=true runtime_network=true bounded_loopback=true single_cpu=true smoltcp=false virtio_net=false external_packets=false tcp_breadth=false"
            );
            self.done
                .lock()
                .take()
                .expect("one runtime-net completion waker")
                .wake_up();
        }
        (result, exit)
    }

    fn next_operation(&self, sender: TaskKey) -> usize {
        self.state.lock().next_operation(sender)
    }

    fn prepare_active(&self, sender: TaskKey) {
        self.state.lock().prepare_active(sender);
    }

    fn commit_active(&self, sender: TaskKey) {
        self.state.lock().commit_active(sender);
    }

    fn publish_active(&self, sender: TaskKey) {
        let waker = self.state.lock().publish_active(sender);
        waker.wake_up();
    }
}

fn listener_sockaddr() -> [u8; SOCKADDR_LEN] {
    let mut bytes = [0_u8; SOCKADDR_LEN];
    bytes[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&4242_u16.to_be_bytes());
    bytes[4..8].copy_from_slice(&[127, 0, 0, 1]);
    bytes
}

fn client_sockaddr() -> [u8; SOCKADDR_LEN] {
    let mut bytes = listener_sockaddr();
    bytes[2..4].copy_from_slice(&CLIENT_PORT.to_be_bytes());
    bytes
}

fn sockaddr_writes(address: usize, length_address: usize, bytes: [u8; 16]) -> Vec<GuestWrite> {
    vec![
        GuestWrite {
            address,
            bytes: bytes.to_vec(),
        },
        GuestWrite {
            address: length_address,
            bytes: (SOCKADDR_LEN as u32).to_le_bytes().to_vec(),
        },
    ]
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
    let mut source = vm_space
        .reader(address, length)
        .expect("runtime-net guest read range");
    let mut destination = VmWriter::from(output.as_mut_slice());
    let copied = source
        .read_fallible(&mut destination)
        .expect("copy bytes from runtime-net guest");
    assert_eq!(copied, length);
    output
}

fn read_guest_u32(vm_space: &VmSpace, address: usize) -> u32 {
    u32::from_le_bytes(read_guest_bytes(vm_space, address, 4).try_into().unwrap())
}

fn write_guest_bytes(vm_space: &VmSpace, address: usize, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let mut destination = vm_space
        .writer(address, bytes.len())
        .expect("runtime-net guest write range");
    let mut source = VmReader::from(bytes);
    let copied = destination
        .write_fallible(&mut source)
        .expect("copy bytes to runtime-net guest");
    assert_eq!(copied, bytes.len());
}

fn assert_current_user_task(task: TaskKey, vm_space: &Arc<VmSpace>) {
    let current = Task::current().expect("runtime-net UserMode runner owns an OSTD task");
    let data = current
        .data()
        .downcast_ref::<TaskData>()
        .expect("runtime-net task carries Nexus TaskData");
    assert_eq!(data.id, task.id());
    assert!(
        data.vm_space
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, vm_space))
    );
}

fn run_guest(scenario: Arc<NetScenario>, vm_space: Arc<VmSpace>, entry: usize, stack: usize) {
    assert_current_user_task(GUEST, &vm_space);
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(entry);
    context.set_rsp(stack);
    let mut user_mode = UserMode::new(context);
    loop {
        vm_space.activate();
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => {
                let descriptor = syscall_descriptor(user_mode.context());
                let local = descriptor.number() == __NR_exit as usize
                    || (descriptor.number() == __NR_write as usize && descriptor.argument(0) == 1);
                if local {
                    let (result, exit) = scenario.dispatch_local(descriptor);
                    user_mode.context_mut().set_rax(result as usize);
                    if exit {
                        return;
                    }
                } else {
                    let result = scenario.dispatch_network(descriptor);
                    user_mode.context_mut().set_rax(result as usize);
                }
            }
            ReturnReason::UserException => panic!(
                "retained runtime-net guest unexpectedly faulted: {:?}",
                user_mode.context_mut().take_exception(),
            ),
            ReturnReason::KernelEvent => Task::yield_now(),
        }
    }
}

fn run_netd_v1(scenario: Arc<NetScenario>, vm_space: Arc<VmSpace>, done: EffectWaker) {
    assert_current_user_task(NETD_V1, &vm_space);
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);
    loop {
        vm_space.activate();
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => match user_mode.context().rax() {
                PORTAL_NEXT => {
                    let operation = scenario.next_operation(NETD_V1);
                    user_mode.context_mut().set_rax(operation);
                    if operation == OP_WAIT {
                        Task::yield_now();
                    }
                }
                PORTAL_PREPARE => {
                    scenario.prepare_active(NETD_V1);
                    user_mode.context_mut().set_rax(0);
                }
                PORTAL_COMMIT => {
                    scenario.commit_active(NETD_V1);
                    user_mode.context_mut().set_rax(0);
                }
                PORTAL_PUBLISH => {
                    scenario.publish_active(NETD_V1);
                    user_mode.context_mut().set_rax(0);
                }
                PORTAL_FAIL => panic!(
                    "runtime-net netd v1 protocol failure code={}",
                    user_mode.context().rdi(),
                ),
                opcode => panic!("runtime-net netd v1 unknown portal {opcode:#x}"),
            },
            ReturnReason::UserException => {
                let info = match user_mode.context_mut().take_exception() {
                    Some(CpuException::PageFault(info)) => info,
                    other => panic!("runtime-net netd v1 unexpected exception {other:?}"),
                };
                assert_eq!(info.addr, EXPECTED_POLICY_FAULT);
                scenario.state.lock().crash_v1();
                println!(
                    "NETD_V1 EXIT task={} reason=real_user_page_fault addr={:#x} accept_prepared=true accept_committed=false guest_reply=false",
                    NETD_V1.id(),
                    info.addr,
                );
                done.wake_up();
                return;
            }
            ReturnReason::KernelEvent => Task::yield_now(),
        }
    }
}

fn run_netd_v2(scenario: Arc<NetScenario>, vm_space: Arc<VmSpace>, done: EffectWaker) {
    assert_current_user_task(NETD_V2, &vm_space);
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);
    loop {
        vm_space.activate();
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => match user_mode.context().rax() {
                RECOVERY_SNAPSHOT => {
                    scenario.state.lock().recovery_snapshot();
                    user_mode.context_mut().set_rax(0);
                }
                READY => {
                    scenario.state.lock().recovery_ready();
                    user_mode.context_mut().set_rax(0);
                }
                REBIND => {
                    scenario.state.lock().recovery_rebind();
                    user_mode.context_mut().set_rax(0);
                }
                ADOPT_NEXT => {
                    let adopted = scenario.state.lock().adopt_next();
                    user_mode.context_mut().set_rax(0);
                    user_mode.context_mut().set_rdi(usize::from(adopted));
                }
                REPLAY_OLD => {
                    scenario.state.lock().reject_late_v1();
                    user_mode.context_mut().set_rax(RESULT_STALE_BINDING);
                }
                PORTAL_NEXT => {
                    let operation = scenario.next_operation(NETD_V2);
                    user_mode.context_mut().set_rax(operation);
                    if operation == OP_WAIT {
                        Task::yield_now();
                    }
                }
                PORTAL_PREPARE => {
                    scenario.prepare_active(NETD_V2);
                    user_mode.context_mut().set_rax(0);
                }
                PORTAL_COMMIT => {
                    scenario.commit_active(NETD_V2);
                    user_mode.context_mut().set_rax(0);
                }
                PORTAL_PUBLISH => {
                    scenario.publish_active(NETD_V2);
                    user_mode.context_mut().set_rax(0);
                }
                NETD_DONE => {
                    assert!(scenario.state.lock().service_done);
                    println!(
                        "NETD_V2 EXIT task={} reason=bounded_service_done recovered_accept=true remaining_ops=10",
                        NETD_V2.id(),
                    );
                    done.wake_up();
                    return;
                }
                PORTAL_FAIL => panic!(
                    "runtime-net netd v2 protocol failure code={}",
                    user_mode.context().rdi(),
                ),
                opcode => panic!("runtime-net netd v2 unknown portal {opcode:#x}"),
            },
            ReturnReason::UserException => panic!(
                "runtime-net netd v2 unexpectedly faulted: {:?}",
                user_mode.context_mut().take_exception(),
            ),
            ReturnReason::KernelEvent => Task::yield_now(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompanionPhase {
    Registered,
    Prepared,
    Committed,
    Completed,
    Aborted,
}

impl CompanionPhase {
    const fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompanionCreditOwnership {
    Held,
    Free,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompanionGenerationError {
    Authority,
    SocketGeneration,
    SourceGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompanionGenerationToken {
    authority_epoch: u64,
    socket_generation: u64,
    source_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompanionProtocol {
    authority_epoch: u64,
    personality_binding: u64,
    network_binding: u64,
    readiness_binding: u64,
    socket_generation: u64,
    source_generation: u64,
    phases: [CompanionPhase; 4],
    credits: [CompanionCreditOwnership; 4],
    parents: [u64; 4],
    recovery_cohort: usize,
    ready_proof: bool,
    buffer_visible: bool,
    buffer_payload: [u8; 4],
    net_sequence: u64,
    ready_sequence: u64,
    net_publications: u64,
    ready_publications: u64,
    ready_deliveries: u64,
    guest_commits: u64,
    guest_replies: u64,
    peer_consumptions: u64,
    closure_drains: u64,
    terminalizations: [u8; 4],
    closure_sequence: u64,
}

impl CompanionProtocol {
    const SYSCALL: usize = 0;
    const NETWORK: usize = 1;
    const READINESS: usize = 2;
    const BUFFER: usize = 3;

    fn token(self) -> CompanionGenerationToken {
        CompanionGenerationToken {
            authority_epoch: self.authority_epoch,
            socket_generation: self.socket_generation,
            source_generation: self.source_generation,
        }
    }

    fn validate_socket(
        self,
        token: CompanionGenerationToken,
    ) -> Result<(), CompanionGenerationError> {
        if token.authority_epoch != self.authority_epoch {
            return Err(CompanionGenerationError::Authority);
        }
        if token.socket_generation != self.socket_generation {
            return Err(CompanionGenerationError::SocketGeneration);
        }
        Ok(())
    }

    fn validate_source(
        self,
        token: CompanionGenerationToken,
    ) -> Result<(), CompanionGenerationError> {
        if token.authority_epoch != self.authority_epoch {
            return Err(CompanionGenerationError::Authority);
        }
        if token.source_generation != self.source_generation {
            return Err(CompanionGenerationError::SourceGeneration);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct CompanionGraph {
    syscall: PortalHandle,
    network: PortalHandle,
    readiness: PortalHandle,
    buffer: PortalHandle,
}

impl CompanionGraph {
    const fn handles(self) -> [PortalHandle; 4] {
        [self.syscall, self.network, self.readiness, self.buffer]
    }

    const fn effects(self) -> [EffectKey; 4] {
        [
            self.syscall.effect(),
            self.network.effect(),
            self.readiness.effect(),
            self.buffer.effect(),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompanionProjection {
    registry: RegistryProjection,
    effects: Vec<EffectView>,
    readiness_revision: u64,
    readiness_counts: ReadinessCounts,
    net_commit: Option<CommitReceipt>,
    buffer_commit: Option<CommitReceipt>,
    ready_commit: Option<CommitReceipt>,
    ready_delivery: Option<ReadyDeliveryReceipt>,
    protocol: CompanionProtocol,
}

fn companion_projection_fingerprint(projection: &CompanionProjection) -> u64 {
    format!("{projection:?}")
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |fingerprint, byte| {
            (fingerprint ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
}

#[allow(clippy::too_many_arguments)]
fn register_companion_effect(
    registry: &mut EffectRegistry,
    scope: ScopeKey,
    task: TaskKey,
    operation: OperationClass,
    syscall: usize,
    credit: CreditClass,
    resource_id: u64,
    publication: PublicationMode,
) -> RegisteredEffect {
    registry
        .register(RegisterRequest {
            scope,
            task,
            operation,
            descriptor: SyscallDescriptor::new(syscall, [resource_id as usize, 0, 0, 0, 0, 0]),
            resources: vec![ResourceKey::new(
                COMPANION_RESOURCE.namespace(),
                resource_id,
                1,
            )],
            credits: vec![CreditCharge::new(credit, 1)],
            publication,
        })
        .unwrap()
}

struct CompanionHarness {
    scope: ScopeKey,
    registry: EffectRegistry,
    readiness: ReadinessCore,
    source: ReadySourceId,
    set: ReadySetId,
    subscription: SubscriptionToken,
    graph: CompanionGraph,
    protocol: CompanionProtocol,
    net_commit: Option<CommitReceipt>,
    buffer_commit: Option<CommitReceipt>,
    ready_commit: Option<CommitReceipt>,
    ready_delivery: Option<ReadyDeliveryReceipt>,
}

impl CompanionHarness {
    fn new(scope: ScopeKey) -> Self {
        let mut registry = EffectRegistry::new();
        registry
            .create_scope(ScopeConfig {
                key: scope,
                authority_epoch: COMPANION_AUTHORITY_EPOCH,
                binding_epoch: 1,
                supervisor: COMPANION_V1,
                credits: vec![
                    CreditLimit::new(CONTROL_CREDIT, 1),
                    CreditLimit::new(NETWORK_CREDIT, 1),
                    CreditLimit::new(READINESS_CREDIT, 1),
                    CreditLimit::new(BUFFER_CREDIT, 1),
                ],
            })
            .unwrap();
        let syscall = register_companion_effect(
            &mut registry,
            scope,
            COMPANION_GUEST,
            COMPANION_SYSCALL_OP,
            __NR_read as usize,
            CONTROL_CREDIT,
            1,
            PublicationMode::None,
        );
        let network = register_companion_effect(
            &mut registry,
            scope,
            COMPANION_V1,
            COMPANION_NETWORK_OP,
            __NR_write as usize,
            NETWORK_CREDIT,
            2,
            PublicationMode::None,
        );
        let readiness_effect = register_companion_effect(
            &mut registry,
            scope,
            COMPANION_READY_TASK,
            OP_READINESS,
            __NR_accept4 as usize,
            READINESS_CREDIT,
            3,
            PublicationMode::None,
        );
        let buffer = register_companion_effect(
            &mut registry,
            scope,
            COMPANION_BUFFER_TASK,
            OP_BUFFER,
            __NR_write as usize,
            BUFFER_CREDIT,
            4,
            PublicationMode::None,
        );
        let graph = CompanionGraph {
            syscall: syscall.handle,
            network: network.handle,
            readiness: readiness_effect.handle,
            buffer: buffer.handle,
        };
        let mut readiness = ReadinessCore::new();
        let source = readiness.create_source(1, 0).unwrap();
        let set = readiness.create_set().unwrap();
        let subscription = readiness
            .attach(
                set,
                source,
                readiness_effect.identity.effect(),
                1,
                READY_READABLE,
                TriggerMode::OneShot,
                0x4e45_5452,
            )
            .unwrap();
        let effects = graph.effects();
        let harness = Self {
            scope,
            registry,
            readiness,
            source,
            set,
            subscription,
            graph,
            protocol: CompanionProtocol {
                authority_epoch: COMPANION_AUTHORITY_EPOCH,
                personality_binding: 1,
                network_binding: 1,
                readiness_binding: 1,
                socket_generation: 1,
                source_generation: 1,
                phases: [CompanionPhase::Registered; 4],
                credits: [CompanionCreditOwnership::Held; 4],
                parents: [0, effects[0].id(), effects[1].id(), effects[1].id()],
                recovery_cohort: 0,
                ready_proof: false,
                buffer_visible: false,
                buffer_payload: [0; 4],
                net_sequence: 0,
                ready_sequence: 0,
                net_publications: 0,
                ready_publications: 0,
                ready_deliveries: 0,
                guest_commits: 0,
                guest_replies: 0,
                peer_consumptions: 0,
                closure_drains: 0,
                terminalizations: [0; 4],
                closure_sequence: 0,
            },
            net_commit: None,
            buffer_commit: None,
            ready_commit: None,
            ready_delivery: None,
        };
        harness.assert_consistent();
        harness
    }

    fn projection(&self) -> CompanionProjection {
        let effects = self
            .registry
            .effects_for_scope(self.scope)
            .into_iter()
            .map(|effect| self.registry.effect_view(effect).unwrap())
            .collect();
        CompanionProjection {
            registry: self.registry.scope_projection(self.scope).unwrap(),
            effects,
            readiness_revision: self.readiness.revision(),
            readiness_counts: self.readiness.counts(),
            net_commit: self.net_commit.clone(),
            buffer_commit: self.buffer_commit.clone(),
            ready_commit: self.ready_commit.clone(),
            ready_delivery: self.ready_delivery.clone(),
            protocol: self.protocol,
        }
    }

    fn assert_consistent(&self) {
        self.registry.check_invariants().unwrap();
        self.readiness.check_invariants().unwrap();
        let projection = self.registry.scope_projection(self.scope).unwrap();
        let effects = self.graph.effects();
        for (index, effect) in effects.into_iter().enumerate() {
            let view = self.registry.effect_view(effect).unwrap();
            let phase_matches = match self.protocol.phases[index] {
                CompanionPhase::Registered => view.phase == EffectPhase::Registered,
                CompanionPhase::Prepared => view.phase == EffectPhase::Prepared,
                CompanionPhase::Committed => view.phase == EffectPhase::Committed,
                CompanionPhase::Completed => {
                    view.phase == EffectPhase::Terminal(TerminalOutcome::Completed)
                }
                CompanionPhase::Aborted => {
                    view.phase == EffectPhase::Terminal(TerminalOutcome::Aborted)
                }
            };
            assert!(phase_matches);
            assert_eq!(
                self.protocol.credits[index] == CompanionCreditOwnership::Held,
                !self.protocol.phases[index].terminal(),
            );
        }
        let retained = self
            .protocol
            .credits
            .iter()
            .filter(|credit| **credit == CompanionCreditOwnership::Held)
            .count() as u64;
        assert_eq!(projection.credits.capacity, 4);
        assert_eq!(projection.credits.free, 4 - retained);
        assert_eq!(
            projection.credits.held + projection.credits.committed,
            retained
        );
        assert_eq!(
            projection.live_effects,
            self.protocol
                .phases
                .iter()
                .filter(|phase| !phase.terminal())
                .count()
        );
        assert_eq!(projection.pending_publications, 0);
    }

    fn prepare_all(&mut self) {
        for handle in self.graph.handles() {
            self.registry.prepare(COMPANION_V1, handle).unwrap();
        }
        self.protocol.phases = [CompanionPhase::Prepared; 4];
        self.assert_consistent();
    }

    fn commit_net(&mut self) {
        assert_eq!(
            self.protocol.phases[CompanionProtocol::NETWORK],
            CompanionPhase::Prepared
        );
        assert_eq!(
            self.protocol.phases[CompanionProtocol::BUFFER],
            CompanionPhase::Prepared
        );
        assert!(!self.protocol.buffer_visible);
        let outcomes = self
            .registry
            .commit_with_moves(
                COMPANION_V1,
                &[
                    (self.graph.network, CommitMetadata::new(4, 1)),
                    (self.graph.buffer, CommitMetadata::new(4, 1)),
                ],
                &[],
            )
            .unwrap();
        let mut outcomes = outcomes.into_iter();
        let CommitOutcome::Applied(net_commit) = outcomes.next().unwrap() else {
            panic!("fresh companion NetCommit replayed")
        };
        let CommitOutcome::Applied(buffer_commit) = outcomes.next().unwrap() else {
            panic!("fresh companion BufferLease commit replayed")
        };
        assert!(outcomes.next().is_none());
        self.registry.domain_changed(self.scope, 1).unwrap();
        self.readiness
            .source_update(self.source, self.protocol.readiness_binding, READY_READABLE)
            .unwrap();
        self.protocol.socket_generation += 1;
        self.protocol.phases[CompanionProtocol::NETWORK] = CompanionPhase::Committed;
        self.protocol.phases[CompanionProtocol::BUFFER] = CompanionPhase::Committed;
        self.protocol.buffer_visible = true;
        self.protocol.buffer_payload = *b"ping";
        self.protocol.net_sequence = net_commit.sequence();
        self.protocol.net_publications = 1;
        self.net_commit = Some(net_commit);
        self.buffer_commit = Some(buffer_commit);
        self.assert_consistent();
    }

    fn commit_ready(&mut self) {
        assert!(self.protocol.buffer_visible);
        assert_eq!(self.protocol.buffer_payload, *b"ping");
        assert_eq!(self.protocol.net_publications, 1);
        let commit = match self
            .registry
            .commit(
                COMPANION_V1,
                self.graph.readiness,
                CommitMetadata::new(1, 2),
            )
            .unwrap()
        {
            CommitOutcome::Applied(receipt) => receipt,
            CommitOutcome::AlreadyCommitted(_) => panic!("fresh companion ReadyCommit replayed"),
        };
        self.registry.domain_changed(self.scope, 2).unwrap();
        let delivery = self
            .readiness
            .commit_delivery(
                self.set,
                self.graph.readiness.effect(),
                1,
                self.protocol.readiness_binding,
            )
            .unwrap();
        assert_eq!(delivery.wait_effect(), self.graph.readiness.effect());
        assert_eq!(delivery.events().len(), 1);
        assert_eq!(delivery.events()[0].observed_mask, READY_READABLE);
        self.protocol.source_generation += 1;
        self.protocol.phases[CompanionProtocol::READINESS] = CompanionPhase::Committed;
        self.protocol.ready_sequence = delivery.sequence();
        self.protocol.ready_publications = 1;
        self.ready_commit = Some(commit);
        self.ready_delivery = Some(delivery);
        self.assert_consistent();
    }

    fn deliver_ready(&mut self) {
        let commit = self.ready_commit.as_ref().unwrap();
        let terminal = self.registry.stage_kernel_completion(commit).unwrap();
        assert!(terminal.publication.is_none());
        self.readiness
            .publish_delivery(self.ready_delivery.as_ref().unwrap())
            .unwrap();
        self.protocol.phases[CompanionProtocol::READINESS] = CompanionPhase::Completed;
        self.protocol.credits[CompanionProtocol::READINESS] = CompanionCreditOwnership::Free;
        self.protocol.ready_deliveries += 1;
        self.protocol.terminalizations[CompanionProtocol::READINESS] += 1;
        self.assert_consistent();
    }

    fn revoke_begin(&mut self) -> RevokeSelection {
        let selection = self.registry.revoke_begin(self.scope).unwrap();
        assert_eq!(
            selection.closed_authority_epoch,
            self.protocol.authority_epoch
        );
        self.protocol.authority_epoch = selection.authority_epoch;
        self.protocol.closure_sequence = selection.sequence;
        self.protocol.recovery_cohort = 0;
        self.protocol.ready_proof = false;
        self.assert_consistent();
        selection
    }

    fn reject_ready_after_revoke(&mut self) -> bool {
        let before = self.projection();
        assert_eq!(
            self.registry.commit(
                COMPANION_V1,
                self.graph.readiness,
                CommitMetadata::new(1, 2),
            ),
            Err(RegistryError::StaleAuthority)
        );
        let after = self.projection();
        assert_eq!(after, before);
        companion_projection_fingerprint(&before) == companion_projection_fingerprint(&after)
    }

    fn close_buffer(&mut self, selection: &RevokeSelection) {
        assert_eq!(
            self.protocol.phases[CompanionProtocol::BUFFER],
            CompanionPhase::Committed
        );
        let receipt = self.buffer_commit.clone().unwrap();
        let terminal = self
            .registry
            .stage_revoke_terminal(
                selection,
                self.graph.buffer.effect(),
                TerminalRequest::completed_by(4, receipt),
            )
            .unwrap();
        assert!(terminal.publication.is_none());
        self.protocol.phases[CompanionProtocol::BUFFER] = CompanionPhase::Completed;
        self.protocol.credits[CompanionProtocol::BUFFER] = CompanionCreditOwnership::Free;
        self.protocol.buffer_visible = false;
        self.protocol.closure_drains += 1;
        self.protocol.terminalizations[CompanionProtocol::BUFFER] += 1;
        self.assert_consistent();
    }

    fn close_readiness(&mut self, selection: &RevokeSelection) {
        match self.protocol.phases[CompanionProtocol::READINESS] {
            CompanionPhase::Committed => self.deliver_ready(),
            CompanionPhase::Registered | CompanionPhase::Prepared => {
                let terminal = self
                    .registry
                    .stage_revoke_terminal(
                        selection,
                        self.graph.readiness.effect(),
                        TerminalRequest::aborted(-125),
                    )
                    .unwrap();
                assert!(terminal.publication.is_none());
                self.protocol.phases[CompanionProtocol::READINESS] = CompanionPhase::Aborted;
                self.protocol.credits[CompanionProtocol::READINESS] =
                    CompanionCreditOwnership::Free;
                self.protocol.terminalizations[CompanionProtocol::READINESS] += 1;
                self.assert_consistent();
            }
            CompanionPhase::Completed | CompanionPhase::Aborted => {}
        }
    }

    fn close_network(&mut self, selection: &RevokeSelection) {
        let phase = self.protocol.phases[CompanionProtocol::NETWORK];
        let request = match phase {
            CompanionPhase::Committed => {
                TerminalRequest::completed_by(4, self.net_commit.clone().unwrap())
            }
            CompanionPhase::Registered | CompanionPhase::Prepared => TerminalRequest::aborted(-125),
            CompanionPhase::Completed | CompanionPhase::Aborted => return,
        };
        let terminal = self
            .registry
            .stage_revoke_terminal(selection, self.graph.network.effect(), request)
            .unwrap();
        assert!(terminal.publication.is_none());
        self.protocol.phases[CompanionProtocol::NETWORK] = if phase == CompanionPhase::Committed {
            CompanionPhase::Completed
        } else {
            CompanionPhase::Aborted
        };
        self.protocol.credits[CompanionProtocol::NETWORK] = CompanionCreditOwnership::Free;
        self.protocol.terminalizations[CompanionProtocol::NETWORK] += 1;
        self.assert_consistent();
    }

    fn close_syscall(&mut self, selection: &RevokeSelection) {
        let phase = self.protocol.phases[CompanionProtocol::SYSCALL];
        assert!(matches!(
            phase,
            CompanionPhase::Registered | CompanionPhase::Prepared
        ));
        let terminal = self
            .registry
            .stage_revoke_terminal(
                selection,
                self.graph.syscall.effect(),
                TerminalRequest::aborted(-125),
            )
            .unwrap();
        assert!(terminal.publication.is_none());
        self.protocol.phases[CompanionProtocol::SYSCALL] = CompanionPhase::Aborted;
        self.protocol.credits[CompanionProtocol::SYSCALL] = CompanionCreditOwnership::Free;
        self.protocol.terminalizations[CompanionProtocol::SYSCALL] += 1;
        self.assert_consistent();
    }

    fn finish(&mut self, selection: &RevokeSelection) {
        assert!(self.registry.revoke_next(selection).unwrap().is_none());
        self.registry.revoke_complete(selection).unwrap();
        assert_eq!(
            self.readiness.detach(self.subscription).unwrap(),
            self.graph.readiness.effect()
        );
        self.readiness.retire_source(self.source).unwrap();
        self.readiness.destroy_set(self.set).unwrap();
        self.assert_consistent();
        let registry = self.registry.scope_projection(self.scope).unwrap();
        assert_eq!(registry.phase, ScopePhase::Revoked);
        assert_eq!(registry.live_effects, 0);
        assert_eq!(registry.pending_publications, 0);
        assert_eq!(registry.credits.capacity, 4);
        assert_eq!(registry.credits.free, 4);
        assert_eq!(registry.credits.held, 0);
        assert_eq!(registry.credits.committed, 0);
        assert_eq!(self.protocol.credits, [CompanionCreditOwnership::Free; 4]);
        assert_eq!(self.protocol.terminalizations, [1; 4]);
        let readiness = self.readiness.counts();
        assert_eq!(readiness.sources, 0);
        assert_eq!(readiness.sets, 0);
        assert_eq!(readiness.subscriptions, 0);
        assert_eq!(readiness.queued, 0);
        assert_eq!(readiness.unpublished_deliveries, 0);
    }
}

fn run_ready_revoke_companions() -> bool {
    let mut ready_first = CompanionHarness::new(COMPANION_READY_FIRST_SCOPE);
    ready_first.prepare_all();
    ready_first.commit_net();
    ready_first.commit_ready();
    println!(
        "NETWORK_COMPANION READY_REVOKE Transition case=ready-first scope={} step=ReadyCommit commit_sequence={} ready_publications=1",
        COMPANION_READY_FIRST_SCOPE.id(),
        ready_first.ready_commit.as_ref().unwrap().sequence(),
    );
    let selection = ready_first.revoke_begin();
    println!(
        "NETWORK_COMPANION READY_REVOKE Transition case=ready-first scope={} step=RevokeBegin authority_epoch={}->{} closure_sequence={}",
        COMPANION_READY_FIRST_SCOPE.id(),
        selection.closed_authority_epoch,
        selection.authority_epoch,
        selection.sequence,
    );
    ready_first.close_buffer(&selection);
    ready_first.close_readiness(&selection);
    ready_first.close_network(&selection);
    ready_first.close_syscall(&selection);
    ready_first.finish(&selection);
    assert_eq!(ready_first.protocol.net_publications, 1);
    assert_eq!(ready_first.protocol.ready_publications, 1);
    assert_eq!(ready_first.protocol.ready_deliveries, 1);
    assert_eq!(ready_first.protocol.guest_commits, 0);
    assert_eq!(ready_first.protocol.guest_replies, 0);
    assert_eq!(ready_first.protocol.closure_drains, 1);
    println!(
        "NETWORK_COMPANION READY_REVOKE PASS case=ready-first scope={} winner=ReadyCommit order=ready_commit_before_revoke net_publications=1 ready_publications=1 ready_deliveries=1 wait_final=Completed guest_commits=0 guest_replies=0 buffer_disposition=ClosureDrain credits=Free quiescent=true bounded=true single_cpu=true",
        COMPANION_READY_FIRST_SCOPE.id(),
    );

    let mut revoke_first = CompanionHarness::new(COMPANION_REVOKE_FIRST_SCOPE);
    revoke_first.prepare_all();
    revoke_first.commit_net();
    let selection = revoke_first.revoke_begin();
    println!(
        "NETWORK_COMPANION READY_REVOKE Transition case=revoke-first scope={} step=RevokeBegin authority_epoch={}->{} closure_sequence={}",
        COMPANION_REVOKE_FIRST_SCOPE.id(),
        selection.closed_authority_epoch,
        selection.authority_epoch,
        selection.sequence,
    );
    let stale_authority_unchanged = revoke_first.reject_ready_after_revoke();
    assert!(stale_authority_unchanged);
    println!(
        "NETWORK_COMPANION READY_REVOKE Transition case=revoke-first scope={} step=ReadyCommitReject result=StaleAuthority full_projection_unchanged=true mutation=false",
        COMPANION_REVOKE_FIRST_SCOPE.id(),
    );
    revoke_first.close_buffer(&selection);
    revoke_first.close_readiness(&selection);
    revoke_first.close_network(&selection);
    revoke_first.close_syscall(&selection);
    revoke_first.finish(&selection);
    assert_eq!(revoke_first.protocol.net_publications, 1);
    assert_eq!(revoke_first.protocol.ready_publications, 0);
    assert_eq!(revoke_first.protocol.ready_deliveries, 0);
    assert_eq!(revoke_first.protocol.guest_commits, 0);
    assert_eq!(revoke_first.protocol.guest_replies, 0);
    assert_eq!(revoke_first.protocol.closure_drains, 1);
    println!(
        "NETWORK_COMPANION READY_REVOKE PASS case=revoke-first scope={} winner=RevokeBegin order=revoke_before_ready ready_commit_result=StaleAuthority net_publications=1 ready_publications=0 ready_deliveries=0 wait_final=Aborted guest_commits=0 guest_replies=0 buffer_disposition=ClosureDrain credits=Free quiescent=true bounded=true single_cpu=true",
        COMPANION_REVOKE_FIRST_SCOPE.id(),
    );
    stale_authority_unchanged
}

fn run_personality_crash_companion() {
    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: COMPANION_PERSONALITY_SCOPE,
            authority_epoch: COMPANION_AUTHORITY_EPOCH,
            binding_epoch: 1,
            supervisor: COMPANION_V1,
            credits: vec![CreditLimit::new(CONTROL_CREDIT, 2)],
        })
        .unwrap();
    let send = register_companion_effect(
        &mut registry,
        COMPANION_PERSONALITY_SCOPE,
        COMPANION_GUEST,
        COMPANION_SYSCALL_OP,
        __NR_write as usize,
        CONTROL_CREDIT,
        11,
        PublicationMode::Required,
    );
    let receive = register_companion_effect(
        &mut registry,
        COMPANION_PERSONALITY_SCOPE,
        COMPANION_GUEST,
        COMPANION_SYSCALL_OP,
        __NR_read as usize,
        CONTROL_CREDIT,
        12,
        PublicationMode::None,
    );
    registry.prepare(COMPANION_V1, send.handle).unwrap();
    registry.prepare(COMPANION_V1, receive.handle).unwrap();
    let send_commit = match registry
        .commit(COMPANION_V1, send.handle, CommitMetadata::new(4, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => panic!("fresh personality send replayed"),
    };
    registry
        .domain_changed(COMPANION_PERSONALITY_SCOPE, 1)
        .unwrap();
    let crash = registry
        .crash(COMPANION_PERSONALITY_SCOPE, COMPANION_V1)
        .unwrap();
    assert_eq!(crash.previous_binding_epoch, 1);
    assert_eq!(crash.binding_epoch, 2);
    assert_eq!(crash.cohort.len(), 2);
    assert!(crash.cohort.contains(&send.identity.effect()));
    assert!(crash.cohort.contains(&receive.identity.effect()));
    assert_eq!(
        registry.effect_view(send.identity.effect()).unwrap().phase,
        EffectPhase::Committed
    );
    assert_eq!(
        registry
            .effect_view(receive.identity.effect())
            .unwrap()
            .phase,
        EffectPhase::Prepared
    );

    // The generic crash receipt freezes all live work. The exact committed
    // receipt is nevertheless kernel-owned: drain it before exposing the
    // replacement's recoverable snapshot so it can never be adopted.
    let send_terminal = registry.stage_kernel_completion(&send_commit).unwrap();
    let publication = send_terminal.publication.unwrap();
    assert_eq!(publication.result(), 4);
    registry.acknowledge_publication(&publication).unwrap();
    assert_eq!(
        registry
            .recovery_remaining(COMPANION_PERSONALITY_SCOPE)
            .unwrap(),
        1
    );
    let snapshot = registry
        .recovery_snapshot(COMPANION_PERSONALITY_SCOPE, COMPANION_V2)
        .unwrap();
    assert_eq!(snapshot.effects.len(), 1);
    assert_eq!(snapshot.effects[0].effect, receive.identity.effect());
    assert_eq!(snapshot.effects[0].phase, EffectPhase::Prepared);
    registry
        .ready(COMPANION_PERSONALITY_SCOPE, COMPANION_V2, &snapshot)
        .unwrap();
    registry
        .rebind(COMPANION_PERSONALITY_SCOPE, COMPANION_V2)
        .unwrap();
    let recoverable = registry
        .recover_next(COMPANION_PERSONALITY_SCOPE, COMPANION_V2)
        .unwrap()
        .expect("prepared receive is the only adoption candidate");
    assert_eq!(recoverable.handle.effect(), receive.identity.effect());
    assert_eq!(recoverable.phase, EffectPhase::Prepared);
    assert!(recoverable.commit.is_none());
    let adopted_receive = registry
        .adopt(
            COMPANION_PERSONALITY_SCOPE,
            COMPANION_V2,
            recoverable.handle,
        )
        .unwrap();
    assert_eq!(adopted_receive.binding_epoch(), 2);
    assert!(
        registry
            .recover_next(COMPANION_PERSONALITY_SCOPE, COMPANION_V2)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        registry
            .effect_view(send.identity.effect())
            .unwrap()
            .identity
            .binding_epoch(),
        1
    );

    let selection = registry.revoke_begin(COMPANION_PERSONALITY_SCOPE).unwrap();
    let revoke_effect = registry
        .revoke_next(&selection)
        .unwrap()
        .expect("prepared receive remains in the revoke cohort");
    assert_eq!(revoke_effect.effect, receive.identity.effect());
    assert_eq!(revoke_effect.disposition, RevokeDisposition::Abort);
    let receive_terminal = registry
        .stage_revoke_terminal(
            &selection,
            receive.identity.effect(),
            TerminalRequest::aborted(-125),
        )
        .unwrap();
    assert!(receive_terminal.publication.is_none());
    assert!(registry.revoke_next(&selection).unwrap().is_none());
    registry.revoke_complete(&selection).unwrap();
    registry.check_invariants().unwrap();
    let projection = registry
        .scope_projection(COMPANION_PERSONALITY_SCOPE)
        .unwrap();
    assert_eq!(projection.phase, ScopePhase::Revoked);
    assert_eq!(projection.live_effects, 0);
    assert_eq!(projection.pending_publications, 0);
    assert_eq!(projection.credits.capacity, 2);
    assert_eq!(projection.credits.free, 2);
    assert_eq!(projection.credits.held, 0);
    assert_eq!(projection.credits.committed, 0);
    assert_eq!(
        registry.effect_view(send.identity.effect()).unwrap().phase,
        EffectPhase::Terminal(TerminalOutcome::Completed)
    );
    assert_eq!(
        registry
            .effect_view(receive.identity.effect())
            .unwrap()
            .phase,
        EffectPhase::Terminal(TerminalOutcome::Aborted)
    );
    println!(
        "NETWORK_COMPANION PERSONALITY_CRASH PASS scope={} old_binding=1 new_binding=2 send_phase_at_crash=Committed send_disposition=Drain send_replies=1 receive_phase_at_crash=Prepared receive_disposition=Abort receive_replies=0 committed_adoptions=0 terminalizations=2 credits=Free quiescent=true bounded=true single_cpu=true",
        COMPANION_PERSONALITY_SCOPE.id(),
    );
}

fn run_buffer_reply_companion() {
    let mut harness = CompanionHarness::new(COMPANION_BUFFER_SCOPE);
    harness.prepare_all();
    harness.commit_net();
    let net_sequence = harness.protocol.net_sequence;
    let buffer_effect = harness.graph.buffer.effect();
    let immutable_buffer_commit = harness.buffer_commit.clone().unwrap();
    assert!(harness.protocol.buffer_visible);
    assert_eq!(harness.protocol.buffer_payload, *b"ping");
    assert_eq!(
        harness.protocol.credits[CompanionProtocol::BUFFER],
        CompanionCreditOwnership::Held
    );
    assert_eq!(harness.protocol.guest_commits, 0);
    assert_eq!(harness.protocol.guest_replies, 0);
    let selection = harness.revoke_begin();
    harness.close_buffer(&selection);
    harness.close_readiness(&selection);
    harness.close_network(&selection);
    harness.close_syscall(&selection);
    harness.finish(&selection);
    assert_eq!(
        harness.registry.effect_view(buffer_effect).unwrap().commit,
        Some(immutable_buffer_commit)
    );
    assert_eq!(harness.protocol.net_publications, 1);
    assert!(!harness.protocol.buffer_visible);
    assert_eq!(harness.protocol.peer_consumptions, 0);
    assert_eq!(harness.protocol.closure_drains, 1);
    assert_eq!(harness.protocol.guest_replies, 0);
    println!(
        "NETWORK_COMPANION BUFFER_REPLY PASS scope={} net_sequence={} buffer_effect={} payload=ping bytes=4 visible_before=1 buffer_credit_before=Held guest_commits_before=0 guest_replies_before=0 peer_consumptions=0 closure_drains=1 visible_after=0 buffer_credit_after=Free net_publications_after=1 guest_replies_after=0 immutable_history=true quiescent=true bounded=true single_cpu=true",
        COMPANION_BUFFER_SCOPE.id(),
        net_sequence,
        buffer_effect.id(),
    );
}

fn close_stale_companion(harness: &mut CompanionHarness) {
    let selection = harness.revoke_begin();
    harness.close_buffer(&selection);
    harness.close_readiness(&selection);
    harness.close_network(&selection);
    harness.close_syscall(&selection);
    harness.finish(&selection);
}

fn run_stale_generation_companions() {
    let mut socket = CompanionHarness::new(COMPANION_STALE_SOCKET_SCOPE);
    socket.prepare_all();
    let stale_socket = socket.protocol.token();
    socket.commit_net();
    let before = socket.projection();
    let before_fingerprint = companion_projection_fingerprint(&before);
    assert_eq!(
        socket.protocol.validate_socket(stale_socket),
        Err(CompanionGenerationError::SocketGeneration)
    );
    let after = socket.projection();
    let after_fingerprint = companion_projection_fingerprint(&after);
    assert_eq!(after, before);
    assert_eq!(after_fingerprint, before_fingerprint);
    let socket_effect = socket.graph.network.effect();
    let socket_current = socket.protocol.socket_generation;
    close_stale_companion(&mut socket);
    println!(
        "NETWORK_COMPANION STALE_GENERATION PASS kind=socket scope={} effect={} presented={} current={} result=StaleSocketGeneration projection_before={:016x} projection_after={:016x} full_projection_unchanged=true mutation=false bounded=true single_cpu=true",
        COMPANION_STALE_SOCKET_SCOPE.id(),
        socket_effect.id(),
        stale_socket.socket_generation,
        socket_current,
        before_fingerprint,
        after_fingerprint,
    );

    let mut source = CompanionHarness::new(COMPANION_STALE_SOURCE_SCOPE);
    source.prepare_all();
    source.commit_net();
    let stale_source = source.protocol.token();
    source.commit_ready();
    let before = source.projection();
    let before_fingerprint = companion_projection_fingerprint(&before);
    assert_eq!(
        source.protocol.validate_source(stale_source),
        Err(CompanionGenerationError::SourceGeneration)
    );
    let after = source.projection();
    let after_fingerprint = companion_projection_fingerprint(&after);
    assert_eq!(after, before);
    assert_eq!(after_fingerprint, before_fingerprint);
    let source_effect = source.graph.readiness.effect();
    let source_current = source.protocol.source_generation;
    close_stale_companion(&mut source);
    println!(
        "NETWORK_COMPANION STALE_GENERATION PASS kind=source scope={} effect={} presented={} current={} result=StaleSourceGeneration projection_before={:016x} projection_after={:016x} full_projection_unchanged=true mutation=false bounded=true single_cpu=true",
        COMPANION_STALE_SOURCE_SCOPE.id(),
        source_effect.id(),
        stale_source.source_generation,
        source_current,
        before_fingerprint,
        after_fingerprint,
    );
}

fn run_network_lifecycle_companion() -> bool {
    let stale_authority_unchanged = run_ready_revoke_companions();
    run_personality_crash_companion();
    run_buffer_reply_companion();
    run_stale_generation_companions();
    stale_authority_unchanged
}

pub(crate) fn run_linux_net_slice() -> RuntimeNetSliceReceipt {
    let loaded = load_static_image(RUNTIME_NET_ELF, EXECUTABLE_NAME);
    let (done_waiter, done_waker) = EffectWaiter::new_pair(EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: SCOPE.id(),
        effect_id: SCENARIO_DONE_EFFECT,
    });
    let scenario = Arc::new(NetScenario {
        vm_space: loaded.vm_space.clone(),
        state: SpinLock::new(NetState::new()),
        done: SpinLock::new(Some(done_waker)),
    });

    let v1_vm = Arc::new(create_vm_space(NETD_V1_PROGRAM));
    let v2_vm = Arc::new(create_vm_space(NETD_V2_PROGRAM));
    assert!(!Arc::ptr_eq(&v1_vm, &v2_vm));
    let (v1_waiter, v1_waker) = EffectWaiter::new_pair(EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: SCOPE.id(),
        effect_id: V1_DONE_EFFECT,
    });
    let (v2_waiter, v2_waker) = EffectWaiter::new_pair(EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: SCOPE.id(),
        effect_id: V2_DONE_EFFECT,
    });

    let v1_scenario = scenario.clone();
    let v1_task_vm = v1_vm.clone();
    let v1_data_vm = v1_vm.clone();
    let v1_task = Arc::new(
        TaskOptions::new(move || run_netd_v1(v1_scenario, v1_task_vm, v1_waker))
            .data(TaskData::new(NETD_V1.id(), Some(v1_data_vm)))
            .build()
            .expect("build runtime-net netd v1"),
    );
    let v2_scenario = scenario.clone();
    let v2_task_vm = v2_vm.clone();
    let v2_data_vm = v2_vm.clone();
    let v2_task = Arc::new(
        TaskOptions::new(move || run_netd_v2(v2_scenario, v2_task_vm, v2_waker))
            .data(TaskData::new(NETD_V2.id(), Some(v2_data_vm)))
            .build()
            .expect("build runtime-net netd v2"),
    );
    assert!(!Arc::ptr_eq(&v1_task, &v2_task));

    let guest_scenario = scenario.clone();
    let guest_task_vm = loaded.vm_space.clone();
    let guest_data_vm = loaded.vm_space.clone();
    let entry = loaded.entry;
    let stack = loaded.stack_pointer;
    let guest_task = Arc::new(
        TaskOptions::new(move || run_guest(guest_scenario, guest_task_vm, entry, stack))
            .data(TaskData::new(GUEST.id(), Some(guest_data_vm)))
            .build()
            .expect("build retained runtime-net guest"),
    );

    println!(
        "NETWORK_LIFECYCLE BEGIN authority_epoch={} personality_binding=1 netd_binding=1 readiness_binding=1 socket_generation=1 source_generation=1 bounded=true single_cpu=true",
        AUTHORITY_EPOCH,
    );
    println!(
        "LINUX_NET_SLICE BEGIN workload=linux-runtime-net-smoke format=ELF64 type=ET_EXEC retained=true adapted=false syscalls=22 unique_syscalls=13 registry=common transport=bounded_in_memory_ipv4_loopback readiness=kernel_owned smp=1"
    );
    println!(
        "LINUX_NET_ARTIFACT source_sha256={} elf_sha256={} retained=true smoltcp=false virtio_net=false external_packets=false tcp_breadth=false",
        EXPECTED_SOURCE_SHA256, EXPECTED_ELF_SHA256,
    );

    v1_task.run();
    guest_task.run();
    v1_waiter.wait();
    {
        let state = scenario.state.lock();
        assert!(state.v1_crashed);
        assert_eq!(state.epochs.netd, 2);
    }
    println!(
        "NETWORK_LIFECYCLE FreshSpawn task={} vm=fresh distinct_task=true distinct_vm=true binding=2",
        NETD_V2.id(),
    );
    v2_task.run();
    done_waiter.wait();
    v2_waiter.wait();
    {
        let state = scenario.state.lock();
        assert!(state.service_done);
        assert!(state.exited);
    }
    let stale_authority_unchanged = run_network_lifecycle_companion();
    assert!(stale_authority_unchanged);
    println!(
        "NETWORK_LIFECYCLE PASS netd_crash_adopt_accept=true stale_old_binding_full_projection_unchanged=true ready_commit_first=true ready_revoke_first=true personality_crash_drain_abort=true buffer_visible_reply_absent=true stale_socket_generation_full_projection_unchanged=true stale_source_generation_full_projection_unchanged=true stale_authority_full_projection_unchanged=true companion_quiescent=true netd_crash_peer_epochs_unchanged=true binding_isolation_observed=netd_crash_only socket_generation_fenced=true source_generation_fenced=true kernel_owned_readiness=true buffer_credit_retained_until_consume=true quiescent=true bounded=true single_cpu=true smoltcp=false virtio_net=false external_packets=false"
    );
    RuntimeNetSliceReceipt {
        scope: SCOPE,
        closed_authority_epoch: AUTHORITY_EPOCH,
        final_authority_epoch: AUTHORITY_EPOCH + 1,
        terminalizations: 22,
        publication_acks: 22,
        quiescent: true,
        source_sha256: EXPECTED_SOURCE_SHA256,
        elf_sha256: EXPECTED_ELF_SHA256,
    }
}
