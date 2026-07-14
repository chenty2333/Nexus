// SPDX-License-Identifier: MPL-2.0

//! Bounded runtime-filesystem successor for the retained Stage 6 core input.
//!
//! The unchanged guest executes as a real ELF in OSTD `UserMode`.  Linux path,
//! fd, stat, procfs, and offset-I/O policy remains a deliberately tiny
//! in-memory personality service. In the feature-free predecessor, one
//! workload-owned root retains the first executable `pread64` through a
//! preparation-only in-memory block boundary; independent Stage 5B evidence is
//! only component-consistent with that path. With `virtio-cser-facade`, the
//! same real syscall instead enters a request-local production root spanning
//! `FilesystemSyscall -> FilesystemRead -> BlockRequest -> three DMA owners`.
//! That successor publishes a real same-boot VirtIO/IOMMU request, polls it
//! outside the OSTD lock, couples reset and IOTLB receipts to the registry, and
//! sources the guest reply only from the completed device buffer.

use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};

use linux_raw_sys::general::{
    __NR_close, __NR_exit, __NR_newfstatat, __NR_openat, __NR_pread64, __NR_pwrite64,
    __NR_readlinkat, __NR_statx, __NR_write, AT_FDCWD,
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
        CommitMetadata, CommitOutcome, CommitReceipt, CreditCharge, CreditClass, CreditLimit,
        DerivedRegisterRequest, DomainConfig, DomainKey, EffectRegistry, OperationClass,
        PublicationMode, PublicationTicket, RegisterRequest, RegisteredEffect, RegistryError,
        ResourceKey, RevokeDisposition, ScopeConfig, ScopeKey, ScopePhase, SyscallDescriptor,
        TaskKey, TerminalRequest,
    },
    linux_loader::load_static_image_with_stack_pages,
};

#[cfg(not(feature = "virtio-cser-facade"))]
use crate::effect_registry::PortalHandle;

#[cfg(feature = "virtio-cser-facade")]
use crate::effect_registry::{
    DeviceBatchCommitOutcome, DeviceBatchCommitReceipt, DeviceClosureResult, DeviceCohortParent,
    DeviceDerivedCohortEntry, DeviceEnvelope, EffectKey, RevokeSelection,
};
#[cfg(feature = "virtio-cser-facade")]
use nexus_ostd_virtio::{
    CompletionProgress, DeviceSessionIdentity, NotificationDisposition, OwnerKind,
    ProductionClosureProgress, ProductionDevice, PublishedRequest, Root, discover_and_own_bars,
    owner_address,
};

const SCOPE: ScopeKey = ScopeKey::new(95, 1);
const GUEST: TaskKey = TaskKey::new(950, 1);
const ROOT_OWNER: TaskKey = TaskKey::new(954, 1);
const PERSONALITY_V1: TaskKey = TaskKey::new(952, 1);
const FILESYSTEM_V1: TaskKey = TaskKey::new(951, 1);
const FILESYSTEM_V2: TaskKey = TaskKey::new(951, 2);
const BLOCK_V1: TaskKey = TaskKey::new(953, 1);
const AUTHORITY_EPOCH: u64 = 141;
const ROOT_BINDING_EPOCH: u64 = 1;
const PERSONALITY_DOMAIN: DomainKey = DomainKey::new(1);
const FILESYSTEM_DOMAIN: DomainKey = DomainKey::new(2);
const BLOCK_DOMAIN: DomainKey = DomainKey::new(3);
const CONTROL_CREDIT: CreditClass = CreditClass::new(0x301);
const FILESYSTEM_OP_CREDIT: CreditClass = CreditClass::new(0x302);
const QUEUE_SLOT_CREDIT: CreditClass = CreditClass::new(0x303);
const PINNED_PAGE_CREDIT: CreditClass = CreditClass::new(0x304);
const DMA_MAPPING_CREDIT: CreditClass = CreditClass::new(0x305);
const GUEST_REPLY_CREDIT: CreditClass = CreditClass::new(0x306);
const BLOCK_PREPARATION_CREDIT: CreditClass = CreditClass::new(0x307);
const OP_SYSCALL: OperationClass = OperationClass::new(1);
const OP_FILESYSTEM_READ: OperationClass = OperationClass::new(0x302);
const OP_BLOCK_REQUEST: OperationClass = OperationClass::new(0x303);
#[cfg(feature = "virtio-cser-facade")]
const OP_DMA_QUEUE_OWNER_A: OperationClass = OperationClass::new(0x304);
#[cfg(feature = "virtio-cser-facade")]
const OP_DMA_QUEUE_OWNER_B: OperationClass = OperationClass::new(0x305);
#[cfg(feature = "virtio-cser-facade")]
const OP_DMA_REQUEST_OWNER: OperationClass = OperationClass::new(0x306);
const PROCESS_RESOURCE: ResourceKey = ResourceKey::new(0x7100, 1, 1);
const EXEC_INODE_RESOURCE: ResourceKey = ResourceKey::new(0x7101, 1, 1);
const TMP_INODE_RESOURCE: ResourceKey = ResourceKey::new(0x7101, 2, 1);
const PROC_INODE_RESOURCE: ResourceKey = ResourceKey::new(0x7101, 3, 1);
const GUEST_REPLY_RESOURCE: ResourceKey = ResourceKey::new(0x7300, 1, 1);
const FILESYSTEM_READ_RESOURCE: ResourceKey = ResourceKey::new(0x7301, 1, 1);
const BLOCK_REQUEST_RESOURCE: ResourceKey = ResourceKey::new(0x7302, 1, 1);
#[cfg(not(feature = "virtio-cser-facade"))]
const BLOCK_PREPARATION_RESOURCE: ResourceKey = ResourceKey::new(0x7306, 1, 1);
#[cfg(feature = "virtio-cser-facade")]
const DMA_QUEUE_OWNER_A_NAMESPACE: u32 = 0x7310;
#[cfg(feature = "virtio-cser-facade")]
const DMA_QUEUE_OWNER_B_NAMESPACE: u32 = 0x7311;
#[cfg(feature = "virtio-cser-facade")]
const DMA_REQUEST_OWNER_NAMESPACE: u32 = 0x7312;

const LIFECYCLE_PRECOMMIT_SCOPE: ScopeKey = ScopeKey::new(96, 1);
const LIFECYCLE_POSTCOMMIT_SCOPE: ScopeKey = ScopeKey::new(97, 1);
const LIFECYCLE_COMMIT_FIRST_SCOPE: ScopeKey = ScopeKey::new(98, 1);
const LIFECYCLE_REVOKE_FIRST_SCOPE: ScopeKey = ScopeKey::new(99, 1);
const LIFECYCLE_V1: TaskKey = TaskKey::new(960, 1);
const LIFECYCLE_V2: TaskKey = TaskKey::new(961, 1);
const LIFECYCLE_GUEST: TaskKey = TaskKey::new(962, 1);
const LIFECYCLE_CREDIT: CreditClass = CreditClass::new(1);
const LIFECYCLE_RESOURCE: ResourceKey = ResourceKey::new(0x7200, 1, 1);
const OP_PREAD: OperationClass = OperationClass::new(2);
const OP_PWRITE: OperationClass = OperationClass::new(3);

const EXECUTABLE_PATH: &[u8] = b"/bin/linux-runtime-fs-smoke";
const EXECUTABLE_NAME: &[u8] = b"/bin/linux-runtime-fs-smoke\0";
const TMP_PATH: &[u8] = b"/tmp/runtime-fs.bin";
const PROC_SELF_PATH: &[u8] = b"/proc/self";
const PROC_EXE_NAME: &[u8] = b"exe";
const EXPECTED_STDOUT: &[u8] = b"runtime fs ok\n";
const EXPECTED_SOURCE_SHA256: &str =
    "c5a4014d88794ddccd1c5239957a43500a6637a433640c2293e699fea72b870f";
const EXPECTED_ELF_SHA256: &str =
    "0dc5ad40cb05e39592592ef3272ed45be4d71f9b147a534be20b9a5626c17bef";
#[cfg(not(feature = "virtio-cser-facade"))]
const FIRST_PREAD_INPUT_SHA256: &str =
    "a101969acc8dac3209f8be33a5d070e5972fc82f49f5ef85e28db576068024fc";
#[cfg(not(feature = "virtio-cser-facade"))]
const FIRST_PREAD_PAYLOAD_SHA256: &str =
    "3bdbb4fe8397cd2b842430b39ccff01a8663c751945ef5e9a09e267fb8b1d359";
#[cfg(not(feature = "virtio-cser-facade"))]
const BLOCK_PREPARATION_SHA256: &str =
    "e3229d4050798eedcd6503e8b44c3e6bad6d1c105f07f79d3f4fbb04925f1f14";
#[cfg(not(feature = "virtio-cser-facade"))]
const STAGE5B_SECTOR_SHA256: &str =
    "9cb83be92a4c9239752718e6e20ac00fe9e32842ea561ae7fedec94b620a05cc";
#[cfg(not(feature = "virtio-cser-facade"))]
const STAGE5B_IMAGE_SHA256: &str =
    "27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254";
#[cfg(not(feature = "virtio-cser-facade"))]
const STAGE5B_SECTOR_FNV1A: u64 = 0xc4b4_ad90_59af_d22e;
#[cfg(not(feature = "virtio-cser-facade"))]
const STAGE5B_SECTOR_MAGIC: &[u8] = b"NEXUS-CSER-VIRTIO-BLK-STAGE5B\n";
#[cfg(feature = "virtio-cser-facade")]
const SAME_BOOT_SECTOR_SHA256: &str =
    "4fb2b63ca7d483c6efaa756182133f05c7ef453fa82e94ce31826ebc4c104f66";
#[cfg(feature = "virtio-cser-facade")]
const SAME_BOOT_IMAGE_SHA256: &str =
    "9357413ed9a96a23af1750cc304265dd7dd1835eb58eb1fb50119cd80d0bc8ca";
#[cfg(feature = "virtio-cser-facade")]
const SAME_BOOT_SECTOR_FNV1A: u64 = 0x3391_3395_b779_8e6b;
const SCENARIO_DONE_EFFECT: u64 = 950;
const AT_EMPTY_PATH: usize = 0x1000;
const AT_DIRECTORY: usize = 0x1_0000;
const O_TMP_FLAGS: usize = 0x242;
const STATX_MASK: u32 = 0x17ff;
const REGULAR_MODE: u16 = 0x81a4;
const STATX_BYTES: usize = 256;
const STAT_BYTES: usize = 144;

#[cfg(not(feature = "virtio-cser-facade"))]
const FIRST_PREAD_INPUT_BYTES: &[u8] =
    b"pread64\nfd=3\npath=/bin/linux-runtime-fs-smoke\noffset=0\nlength=4\n";
#[cfg(not(feature = "virtio-cser-facade"))]
const BLOCK_PREPARATION_BYTES: &[u8] = b"nexus-cser-block-preparation-v1\n\
inode=0x7101:1:1\n\
block=0\n\
offset=0\n\
length=4\n\
queue=0\n\
writable=false\n";
#[cfg(not(feature = "virtio-cser-facade"))]
const FIRST_PREAD_INPUT_FNV1A: u64 = 0x1db8_ca9f_0603_7aaa;
#[cfg(not(feature = "virtio-cser-facade"))]
const FIRST_PREAD_PAYLOAD_FNV1A: u64 = 0x28b2_6538_2f12_49f3;
#[cfg(not(feature = "virtio-cser-facade"))]
const BLOCK_PREPARATION_FNV1A: u64 = 0xfbde_9edc_fd5f_41c8;

const RUNTIME_FS_ELF: &[u8] = include_bytes!("../../guest/linux-runtime-fs.elf");

/// Read-only receipt proving that the retained filesystem workload completed
/// its own production root. No live handle is exported after root closure; the
/// historical Linux I/O composition successor remains a distinct non-identity-
/// preserving cohort and may not reuse this receipt as authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeFsSliceReceipt {
    pub(crate) scope: ScopeKey,
    pub(crate) closed_authority_epoch: u64,
    pub(crate) final_authority_epoch: u64,
    pub(crate) terminalizations: usize,
    pub(crate) publication_acks: usize,
    pub(crate) production_effects: usize,
    pub(crate) production_domains: usize,
    pub(crate) preparation_identity_observed: bool,
    pub(crate) quiescent: bool,
    pub(crate) source_sha256: &'static str,
    pub(crate) elf_sha256: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FdKind {
    Stdout,
    Executable,
    Temporary,
    ProcSelf,
}

struct FsState {
    effects: EffectRegistry,
    fds: BTreeMap<i32, FdKind>,
    temporary: Vec<u8>,
    next_fd: i32,
    domain_revision: u64,
    syscall_terminalizations: usize,
    production_effects: usize,
    production_read_observed: bool,
    stdout_publications: usize,
    exited: bool,
}

#[cfg(feature = "virtio-cser-facade")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionReadPhase {
    Ready,
    Captured(EffectKey),
    Polling(u64),
    Closing(u64),
    AwaitingPublication(u64),
    Complete,
}

#[cfg(feature = "virtio-cser-facade")]
struct ProductionReadRuntime {
    registry: EffectRegistry,
    root: Option<Root>,
    device: Option<ProductionDevice>,
    phase: ProductionReadPhase,
    next_flight_cookie: u64,
    active_revoke: Option<RevokeSelection>,
}

#[cfg(feature = "virtio-cser-facade")]
impl ProductionReadRuntime {
    fn new() -> Self {
        let mut root = discover_and_own_bars();
        let bdf = root.device_bdf();
        assert_eq!((bdf.bus(), bdf.device(), bdf.function()), (0, 5, 0));
        assert_ne!(root.memory_bar_count(), 0);
        let device = ProductionDevice::for_owned_device(&mut root);
        Self {
            registry: new_same_boot_registry(),
            root: Some(root),
            device: Some(device),
            phase: ProductionReadPhase::Ready,
            next_flight_cookie: 1,
            active_revoke: None,
        }
    }

    fn assert_complete(&self) {
        assert_eq!(self.phase, ProductionReadPhase::Complete);
        assert!(self.active_revoke.is_none());
        assert!(self.root.is_some());
        assert!(self.device.is_some());
        let scope = self.registry.scope_projection(SCOPE).unwrap();
        assert_eq!(scope.phase, ScopePhase::Revoked);
        assert_eq!(scope.live_effects, 0);
        assert_eq!(scope.pending_publications, 0);
        assert_eq!(scope.credits.capacity, 10);
        assert_eq!(scope.credits.free, 10);
        assert_eq!(scope.credits.held, 0);
        assert_eq!(scope.credits.committed, 0);
        assert_eq!(scope.credits.retained, 0);
        self.registry.check_invariants().unwrap();
    }
}

#[cfg(feature = "virtio-cser-facade")]
struct SameBootFlight {
    cookie: u64,
    batch: DeviceBatchCommitReceipt,
    published: PublishedRequest,
    root: Root,
    device: ProductionDevice,
    selection: RevokeSelection,
    effects: [EffectKey; 6],
    envelope: DeviceEnvelope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(not(feature = "virtio-cser-facade"))]
struct ProductionReadReceipt {
    syscall_effect: u64,
    filesystem_effect: u64,
    block_effect: u64,
    filesystem_old_binding: u64,
    filesystem_new_binding: u64,
    block_terminal_sequence: u64,
    filesystem_commit_sequence: u64,
    filesystem_terminal_sequence: u64,
}

#[cfg(not(feature = "virtio-cser-facade"))]
struct PreparedProductionRead {
    syscall_effect: u64,
    filesystem: RegisteredEffect,
    adopted_filesystem: PortalHandle,
    block: RegisteredEffect,
    block_descriptor: SyscallDescriptor,
    filesystem_old_binding: u64,
    filesystem_new_binding: u64,
}

fn new_production_registry() -> EffectRegistry {
    let mut effects = EffectRegistry::new();
    effects
        .create_scope(ScopeConfig {
            key: SCOPE,
            authority_epoch: AUTHORITY_EPOCH,
            binding_epoch: ROOT_BINDING_EPOCH,
            supervisor: ROOT_OWNER,
            credits: vec![
                CreditLimit::new(CONTROL_CREDIT, 1),
                CreditLimit::new(FILESYSTEM_OP_CREDIT, 1),
                CreditLimit::new(QUEUE_SLOT_CREDIT, 1),
                CreditLimit::new(PINNED_PAGE_CREDIT, 1),
                CreditLimit::new(DMA_MAPPING_CREDIT, 1),
                CreditLimit::new(GUEST_REPLY_CREDIT, 1),
                CreditLimit::new(BLOCK_PREPARATION_CREDIT, 1),
            ],
        })
        .unwrap();
    for config in [
        DomainConfig {
            key: PERSONALITY_DOMAIN,
            binding_epoch: 1,
            supervisor: PERSONALITY_V1,
        },
        DomainConfig {
            key: FILESYSTEM_DOMAIN,
            binding_epoch: 1,
            supervisor: FILESYSTEM_V1,
        },
        DomainConfig {
            key: BLOCK_DOMAIN,
            binding_epoch: 1,
            supervisor: BLOCK_V1,
        },
    ] {
        effects.add_domain(SCOPE, config).unwrap();
    }
    effects
}

#[cfg(feature = "virtio-cser-facade")]
fn new_same_boot_registry() -> EffectRegistry {
    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: SCOPE,
            authority_epoch: AUTHORITY_EPOCH,
            binding_epoch: ROOT_BINDING_EPOCH,
            supervisor: ROOT_OWNER,
            credits: vec![
                CreditLimit::new(CONTROL_CREDIT, 1),
                CreditLimit::new(FILESYSTEM_OP_CREDIT, 1),
                CreditLimit::new(QUEUE_SLOT_CREDIT, 1),
                CreditLimit::new(PINNED_PAGE_CREDIT, 3),
                CreditLimit::new(DMA_MAPPING_CREDIT, 3),
                CreditLimit::new(GUEST_REPLY_CREDIT, 1),
            ],
        })
        .unwrap();
    for config in [
        DomainConfig {
            key: PERSONALITY_DOMAIN,
            binding_epoch: 1,
            supervisor: PERSONALITY_V1,
        },
        DomainConfig {
            key: FILESYSTEM_DOMAIN,
            binding_epoch: 1,
            supervisor: FILESYSTEM_V1,
        },
        DomainConfig {
            key: BLOCK_DOMAIN,
            binding_epoch: 1,
            supervisor: BLOCK_V1,
        },
    ] {
        registry.add_domain(SCOPE, config).unwrap();
    }
    registry
}

impl FsState {
    fn new() -> Self {
        let mut fds = BTreeMap::new();
        fds.insert(1, FdKind::Stdout);
        Self {
            effects: new_production_registry(),
            fds,
            temporary: Vec::new(),
            next_fd: 3,
            domain_revision: 0,
            syscall_terminalizations: 0,
            production_effects: 0,
            production_read_observed: false,
            stdout_publications: 0,
            exited: false,
        }
    }

    fn capture(
        &mut self,
        descriptor: SyscallDescriptor,
        resources: Vec<ResourceKey>,
    ) -> RegisteredEffect {
        assert!(self.effects.effects_for_task(GUEST).is_empty());
        let mut resources = resources;
        resources.push(GUEST_REPLY_RESOURCE);
        let registered = self
            .effects
            .register_derived(DerivedRegisterRequest {
                request: RegisterRequest {
                    scope: SCOPE,
                    task: GUEST,
                    operation: OP_SYSCALL,
                    descriptor,
                    resources,
                    credits: vec![
                        CreditCharge::new(CONTROL_CREDIT, 1),
                        CreditCharge::new(GUEST_REPLY_CREDIT, 1),
                    ],
                    publication: PublicationMode::Required,
                },
                domain: PERSONALITY_DOMAIN,
                parent: None,
            })
            .unwrap();
        self.production_effects += 1;
        registered
    }

    #[cfg(not(feature = "virtio-cser-facade"))]
    fn begin_first_executable_read(
        &mut self,
        syscall: &RegisteredEffect,
        descriptor: SyscallDescriptor,
    ) -> PreparedProductionRead {
        assert!(!self.production_read_observed);
        assert_eq!(descriptor.number(), __NR_pread64 as usize);
        assert_eq!(descriptor.argument(0), 3);
        assert_eq!(descriptor.argument(2), 4);
        assert_eq!(descriptor.argument(3), 0);
        assert_eq!(fnv1a(FIRST_PREAD_INPUT_BYTES), FIRST_PREAD_INPUT_FNV1A);
        assert_eq!(fnv1a(BLOCK_PREPARATION_BYTES), BLOCK_PREPARATION_FNV1A);

        assert_eq!(syscall.identity.scope(), SCOPE);
        assert_eq!(syscall.identity.domain(), PERSONALITY_DOMAIN);
        assert_eq!(syscall.identity.parent(), None);
        assert_eq!(syscall.identity.task(), GUEST);
        assert_eq!(syscall.identity.operation(), OP_SYSCALL);
        assert_eq!(syscall.identity.authority_epoch(), AUTHORITY_EPOCH);
        assert_eq!(syscall.identity.origin_binding_epoch(), 1);
        assert_eq!(syscall.identity.resources().len(), 2);
        assert!(syscall.identity.resources().contains(&PROCESS_RESOURCE));
        assert!(syscall.identity.resources().contains(&GUEST_REPLY_RESOURCE));
        let filesystem = self
            .effects
            .register_derived(DerivedRegisterRequest {
                request: RegisterRequest {
                    scope: SCOPE,
                    task: FILESYSTEM_V1,
                    operation: OP_FILESYSTEM_READ,
                    descriptor,
                    resources: vec![EXEC_INODE_RESOURCE, FILESYSTEM_READ_RESOURCE],
                    credits: vec![CreditCharge::new(FILESYSTEM_OP_CREDIT, 1)],
                    publication: PublicationMode::None,
                },
                domain: FILESYSTEM_DOMAIN,
                parent: Some(syscall.identity.effect()),
            })
            .unwrap();
        let block_descriptor = SyscallDescriptor::new(
            OP_BLOCK_REQUEST.value() as usize,
            [0, 0, descriptor.argument(2), 0, 0, 0],
        );
        let block = self
            .effects
            .register_derived(DerivedRegisterRequest {
                request: RegisterRequest {
                    scope: SCOPE,
                    task: BLOCK_V1,
                    operation: OP_BLOCK_REQUEST,
                    descriptor: block_descriptor,
                    resources: vec![BLOCK_REQUEST_RESOURCE, BLOCK_PREPARATION_RESOURCE],
                    credits: vec![CreditCharge::new(BLOCK_PREPARATION_CREDIT, 1)],
                    publication: PublicationMode::None,
                },
                domain: BLOCK_DOMAIN,
                parent: Some(filesystem.identity.effect()),
            })
            .unwrap();
        self.production_effects += 2;

        assert_eq!(filesystem.identity.scope(), SCOPE);
        assert_eq!(filesystem.identity.domain(), FILESYSTEM_DOMAIN);
        assert_eq!(filesystem.identity.task(), FILESYSTEM_V1);
        assert_eq!(filesystem.identity.operation(), OP_FILESYSTEM_READ);
        assert_eq!(filesystem.identity.authority_epoch(), AUTHORITY_EPOCH);
        assert_eq!(filesystem.identity.origin_binding_epoch(), 1);
        assert_eq!(
            filesystem.identity.parent(),
            Some(syscall.identity.effect())
        );
        assert_eq!(filesystem.identity.resources().len(), 2);
        assert!(
            filesystem
                .identity
                .resources()
                .contains(&EXEC_INODE_RESOURCE)
        );
        assert!(
            filesystem
                .identity
                .resources()
                .contains(&FILESYSTEM_READ_RESOURCE)
        );
        assert_eq!(block.identity.scope(), SCOPE);
        assert_eq!(block.identity.domain(), BLOCK_DOMAIN);
        assert_eq!(block.identity.task(), BLOCK_V1);
        assert_eq!(block.identity.operation(), OP_BLOCK_REQUEST);
        assert_eq!(block.identity.authority_epoch(), AUTHORITY_EPOCH);
        assert_eq!(block.identity.origin_binding_epoch(), 1);
        assert_eq!(block.identity.parent(), Some(filesystem.identity.effect()));
        assert_eq!(block.identity.resources().len(), 2);
        assert!(block.identity.resources().contains(&BLOCK_REQUEST_RESOURCE));
        assert!(
            block
                .identity
                .resources()
                .contains(&BLOCK_PREPARATION_RESOURCE)
        );
        let ledger = self.effects.scope_projection(SCOPE).unwrap().credits;
        assert_eq!(ledger.capacity, 7);
        assert_eq!(ledger.free, 3);
        assert_eq!(ledger.held, 4);
        assert_eq!(ledger.committed, 0);
        for domain in [PERSONALITY_DOMAIN, FILESYSTEM_DOMAIN, BLOCK_DOMAIN] {
            assert_eq!(
                self.effects
                    .domain_projection(SCOPE, domain)
                    .unwrap()
                    .live_effects,
                1
            );
        }

        self.effects
            .prepare(PERSONALITY_V1, syscall.handle)
            .unwrap();
        self.effects
            .prepare(FILESYSTEM_V1, filesystem.handle)
            .unwrap();
        self.effects.prepare(BLOCK_V1, block.handle).unwrap();

        let personality_before = self
            .effects
            .domain_projection(SCOPE, PERSONALITY_DOMAIN)
            .unwrap();
        let block_before = self.effects.domain_projection(SCOPE, BLOCK_DOMAIN).unwrap();
        let crash = self
            .effects
            .crash_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V1)
            .unwrap();
        assert_eq!(crash.previous_binding_epoch, 1);
        assert_eq!(crash.binding_epoch, 2);
        assert_eq!(crash.cohort.len(), 1);
        assert!(crash.cohort.contains(&filesystem.identity.effect()));
        assert_eq!(
            self.effects
                .domain_projection(SCOPE, PERSONALITY_DOMAIN)
                .unwrap(),
            personality_before
        );
        assert_eq!(
            self.effects.domain_projection(SCOPE, BLOCK_DOMAIN).unwrap(),
            block_before
        );
        let snapshot = self
            .effects
            .domain_recovery_snapshot(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2)
            .unwrap();
        assert_eq!(snapshot.effects.len(), 1);
        assert_eq!(snapshot.effects[0].effect, filesystem.identity.effect());
        assert_eq!(snapshot.effects[0].binding_epoch, 1);
        self.effects
            .domain_ready(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2, &snapshot)
            .unwrap();
        let rebound = self
            .effects
            .rebind_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2)
            .unwrap();
        assert_eq!(rebound.binding_epoch, 2);
        let recovery_item = self
            .effects
            .recover_next_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2)
            .unwrap()
            .expect("filesystem read survives the bounded crash");
        assert_eq!(recovery_item.handle, filesystem.handle);
        let adopted = self
            .effects
            .adopt_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2, filesystem.handle)
            .unwrap();
        assert_eq!(adopted.effect(), filesystem.identity.effect());
        assert_eq!(adopted.binding_epoch(), 2);
        assert_eq!(
            self.effects
                .domain_recovery_remaining(SCOPE, FILESYSTEM_DOMAIN)
                .unwrap(),
            0
        );
        assert!(
            self.effects
                .recover_next_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2)
                .unwrap()
                .is_none()
        );
        let adopted_view = self
            .effects
            .effect_view(filesystem.identity.effect())
            .unwrap();
        assert_eq!(adopted_view.identity.effect(), filesystem.identity.effect());
        assert_eq!(adopted_view.identity.parent(), filesystem.identity.parent());
        assert_eq!(adopted_view.identity.task(), filesystem.identity.task());
        assert_eq!(
            adopted_view.identity.operation(),
            filesystem.identity.operation()
        );
        assert_eq!(
            adopted_view.identity.authority_epoch(),
            filesystem.identity.authority_epoch()
        );
        assert_eq!(
            adopted_view.identity.origin_binding_epoch(),
            filesystem.identity.origin_binding_epoch()
        );
        assert_eq!(adopted_view.identity.binding_epoch(), 2);
        assert_eq!(
            adopted_view.identity.resources(),
            filesystem.identity.resources()
        );

        let stale_before = (
            self.effects.scope_projection(SCOPE).unwrap(),
            self.effects
                .domain_projection(SCOPE, FILESYSTEM_DOMAIN)
                .unwrap(),
            adopted_view,
        );
        assert_eq!(
            self.effects.descriptor(FILESYSTEM_V2, filesystem.handle),
            Err(RegistryError::StaleBinding)
        );
        let stale_after = (
            self.effects.scope_projection(SCOPE).unwrap(),
            self.effects
                .domain_projection(SCOPE, FILESYSTEM_DOMAIN)
                .unwrap(),
            self.effects
                .effect_view(filesystem.identity.effect())
                .unwrap(),
        );
        assert_eq!(stale_after, stale_before);
        assert_eq!(
            self.effects.descriptor(BLOCK_V1, block.handle).unwrap(),
            block_descriptor
        );

        self.effects.check_invariants().unwrap();
        PreparedProductionRead {
            syscall_effect: syscall.identity.effect().id(),
            filesystem_old_binding: filesystem.handle.binding_epoch(),
            filesystem_new_binding: adopted.binding_epoch(),
            filesystem,
            adopted_filesystem: adopted,
            block,
            block_descriptor,
        }
    }

    #[cfg(not(feature = "virtio-cser-facade"))]
    fn finish_first_executable_read(
        &mut self,
        prepared: PreparedProductionRead,
        descriptor: SyscallDescriptor,
        payload: &[u8],
    ) -> ProductionReadReceipt {
        assert!(!self.production_read_observed);
        assert_eq!(payload, b"\x7fELF");
        assert_eq!(fnv1a(payload), FIRST_PREAD_PAYLOAD_FNV1A);
        assert_eq!(prepared.block_descriptor.argument(2), payload.len());

        // Phase 2 stops at the deterministic preparation boundary. A real
        // BlockRequest commit is reserved for the same-boot VirtIO path whose
        // publication point is the avail.idx Release, so this prepared block
        // effect closes honestly as an unpublished preparation-only abort.
        let block_terminal = self
            .effects
            .stage_terminal(
                BLOCK_V1,
                prepared.block.handle,
                TerminalRequest::aborted(-125),
            )
            .unwrap();
        assert!(block_terminal.publication.is_none());

        let foreign_commit = fresh_registry_filesystem_commit(descriptor, payload.len());
        let foreign_before = (
            self.effects.scope_projection(SCOPE).unwrap(),
            self.effects
                .domain_projection(SCOPE, FILESYSTEM_DOMAIN)
                .unwrap(),
            self.effects
                .effect_view(prepared.filesystem.identity.effect())
                .unwrap(),
        );
        assert_eq!(
            self.effects.stage_terminal(
                FILESYSTEM_V2,
                prepared.adopted_filesystem,
                TerminalRequest::completed_by(payload.len() as i64, foreign_commit),
            ),
            Err(RegistryError::CommitConflict)
        );
        let foreign_after = (
            self.effects.scope_projection(SCOPE).unwrap(),
            self.effects
                .domain_projection(SCOPE, FILESYSTEM_DOMAIN)
                .unwrap(),
            self.effects
                .effect_view(prepared.filesystem.identity.effect())
                .unwrap(),
        );
        assert_eq!(foreign_after, foreign_before);

        let filesystem_commit = match self
            .effects
            .commit(
                FILESYSTEM_V2,
                prepared.adopted_filesystem,
                CommitMetadata::new(payload.len() as i64, 1),
            )
            .unwrap()
        {
            CommitOutcome::Applied(receipt) => receipt,
            CommitOutcome::AlreadyCommitted(_) => panic!("fresh filesystem read replayed"),
        };
        let filesystem_terminal = self
            .effects
            .stage_terminal(
                FILESYSTEM_V2,
                prepared.adopted_filesystem,
                TerminalRequest::completed_by(payload.len() as i64, filesystem_commit.clone()),
            )
            .unwrap();
        assert!(filesystem_terminal.publication.is_none());
        let after_internal_close = self.effects.scope_projection(SCOPE).unwrap().credits;
        assert_eq!(after_internal_close.capacity, 7);
        assert_eq!(after_internal_close.free, 5);
        assert_eq!(after_internal_close.held, 2);
        assert_eq!(after_internal_close.committed, 0);
        self.effects.check_invariants().unwrap();
        self.production_read_observed = true;

        ProductionReadReceipt {
            syscall_effect: prepared.syscall_effect,
            filesystem_effect: prepared.filesystem.identity.effect().id(),
            block_effect: prepared.block.identity.effect().id(),
            filesystem_old_binding: prepared.filesystem_old_binding,
            filesystem_new_binding: prepared.filesystem_new_binding,
            block_terminal_sequence: block_terminal.receipt.sequence(),
            filesystem_commit_sequence: filesystem_commit.sequence(),
            filesystem_terminal_sequence: filesystem_terminal.receipt.sequence(),
        }
    }

    fn commit(&mut self, registered: &RegisteredEffect, result: i64) -> CommitReceipt {
        self.effects
            .prepare(PERSONALITY_V1, registered.handle)
            .unwrap();
        let next_revision = self.domain_revision.checked_add(1).unwrap();
        match self
            .effects
            .commit(
                PERSONALITY_V1,
                registered.handle,
                CommitMetadata::new(result, next_revision),
            )
            .unwrap()
        {
            CommitOutcome::Applied(receipt) => receipt,
            CommitOutcome::AlreadyCommitted(_) => panic!("fresh filesystem syscall replayed"),
        }
    }

    fn record_domain_change(&mut self, commit: &CommitReceipt) {
        assert_eq!(commit.domain_revision(), self.domain_revision + 1);
        self.domain_revision = commit.domain_revision();
        self.effects
            .domain_changed(SCOPE, self.domain_revision)
            .unwrap();
    }

    fn terminalize(
        &mut self,
        registered: &RegisteredEffect,
        result: i64,
        commit: CommitReceipt,
    ) -> PublicationTicket {
        let terminal = self
            .effects
            .stage_terminal(
                PERSONALITY_V1,
                registered.handle,
                TerminalRequest::completed_by(result, commit),
            )
            .unwrap();
        self.syscall_terminalizations += 1;
        terminal
            .publication
            .expect("filesystem syscall publication")
    }

    fn allocate_fd_after_commit(&mut self, expected: i32, kind: FdKind) {
        assert_eq!(self.next_fd, expected);
        assert!(self.fds.insert(expected, kind).is_none());
        self.next_fd += 1;
    }

    fn close_scope(&mut self) {
        let selection = self.effects.revoke_begin(SCOPE).unwrap();
        assert!(self.effects.revoke_next(&selection).unwrap().is_none());
        self.effects.revoke_complete(&selection).unwrap();
        self.effects.check_invariants().unwrap();
    }

    fn assert_final(&self) {
        let scope = self.effects.scope_projection(SCOPE).unwrap();
        assert_eq!(scope.phase, ScopePhase::Revoked);
        assert_eq!(scope.live_effects, 0);
        assert_eq!(scope.pending_publications, 0);
        assert_eq!(scope.credits.free, scope.credits.capacity);
        #[cfg(not(feature = "virtio-cser-facade"))]
        assert_eq!(self.syscall_terminalizations, 14);
        #[cfg(feature = "virtio-cser-facade")]
        assert_eq!(self.syscall_terminalizations, 13);
        #[cfg(not(feature = "virtio-cser-facade"))]
        assert_eq!(self.production_effects, 16);
        #[cfg(feature = "virtio-cser-facade")]
        assert_eq!(self.production_effects, 13);
        assert!(self.production_read_observed);
        assert_eq!(self.stdout_publications, 1);
        assert_eq!(self.temporary.as_slice(), [0, 0, b'x', b'y']);
        assert!(self.exited);
    }
}

/// Builds an otherwise valid fresh cohort solely for the negative oracle. Its
/// receipt must never authorize a transition in the workload's registry.
#[cfg(not(feature = "virtio-cser-facade"))]
fn fresh_registry_filesystem_commit(
    descriptor: SyscallDescriptor,
    payload_len: usize,
) -> CommitReceipt {
    let mut registry = new_production_registry();
    let syscall = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: GUEST,
                operation: OP_SYSCALL,
                descriptor,
                resources: vec![PROCESS_RESOURCE, GUEST_REPLY_RESOURCE],
                credits: vec![
                    CreditCharge::new(CONTROL_CREDIT, 1),
                    CreditCharge::new(GUEST_REPLY_CREDIT, 1),
                ],
                publication: PublicationMode::Required,
            },
            domain: PERSONALITY_DOMAIN,
            parent: None,
        })
        .unwrap();
    let filesystem = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: FILESYSTEM_V1,
                operation: OP_FILESYSTEM_READ,
                descriptor,
                resources: vec![EXEC_INODE_RESOURCE, FILESYSTEM_READ_RESOURCE],
                credits: vec![CreditCharge::new(FILESYSTEM_OP_CREDIT, 1)],
                publication: PublicationMode::None,
            },
            domain: FILESYSTEM_DOMAIN,
            parent: Some(syscall.identity.effect()),
        })
        .unwrap();
    let block = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: BLOCK_V1,
                operation: OP_BLOCK_REQUEST,
                descriptor: SyscallDescriptor::new(
                    OP_BLOCK_REQUEST.value() as usize,
                    [0, 0, payload_len, 0, 0, 0],
                ),
                resources: vec![BLOCK_REQUEST_RESOURCE, BLOCK_PREPARATION_RESOURCE],
                credits: vec![CreditCharge::new(BLOCK_PREPARATION_CREDIT, 1)],
                publication: PublicationMode::None,
            },
            domain: BLOCK_DOMAIN,
            parent: Some(filesystem.identity.effect()),
        })
        .unwrap();
    registry.prepare(BLOCK_V1, block.handle).unwrap();
    registry
        .stage_terminal(BLOCK_V1, block.handle, TerminalRequest::aborted(-125))
        .unwrap();
    registry.prepare(FILESYSTEM_V1, filesystem.handle).unwrap();
    let receipt = match registry
        .commit(
            FILESYSTEM_V1,
            filesystem.handle,
            CommitMetadata::new(payload_len as i64, 1),
        )
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => panic!("fresh negative cohort replayed"),
    };
    registry.check_invariants().unwrap();
    receipt
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        digest = (digest ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    digest
}

enum Publication {
    None,
    GuestBytes { address: usize, bytes: Vec<u8> },
    Stdout,
}

#[cfg(feature = "virtio-cser-facade")]
fn same_boot_credit(class: CreditClass, units: u64) -> CreditCharge {
    CreditCharge::new(class, units)
}

#[cfg(feature = "virtio-cser-facade")]
fn same_boot_dma_entry(
    batch_index: usize,
    operation: OperationClass,
    resource_namespace: u32,
    identity: DeviceSessionIdentity,
    device: DeviceEnvelope,
    paddr: usize,
    iova: usize,
) -> DeviceDerivedCohortEntry {
    let generation = identity.device_generation();
    DeviceDerivedCohortEntry {
        batch_index,
        request: RegisterRequest {
            scope: SCOPE,
            task: BLOCK_V1,
            operation,
            descriptor: SyscallDescriptor::new(
                operation.value() as usize,
                [
                    paddr,
                    iova,
                    ostd::mm::PAGE_SIZE,
                    usize::from(identity.queue()),
                    usize::from(identity.descriptor_token()),
                    usize::try_from(generation).unwrap(),
                ],
            ),
            resources: vec![
                ResourceKey::new(
                    resource_namespace,
                    u64::try_from(paddr).unwrap(),
                    generation,
                ),
                ResourceKey::new(
                    resource_namespace + 0x100,
                    u64::try_from(iova).unwrap(),
                    generation,
                ),
            ],
            credits: vec![
                same_boot_credit(PINNED_PAGE_CREDIT, 1),
                same_boot_credit(DMA_MAPPING_CREDIT, 1),
            ],
            publication: PublicationMode::None,
        },
        domain: BLOCK_DOMAIN,
        parent: DeviceCohortParent::BatchIndex(0),
        device,
    }
}

#[cfg(feature = "virtio-cser-facade")]
fn published_identity(
    envelope: DeviceEnvelope,
    bdf: nexus_ostd_virtio::DeviceBdf,
) -> DeviceSessionIdentity {
    DeviceSessionIdentity::from_coordinates(
        envelope.device_session(),
        bdf,
        envelope.queue(),
        envelope.descriptor_token(),
        envelope.device_generation(),
    )
}

enum PublicationAuthority {
    Generic(PublicationTicket),
    #[cfg(feature = "virtio-cser-facade")]
    Production {
        ticket: PublicationTicket,
        flight_cookie: u64,
    },
}

struct DispatchOutcome {
    result: i64,
    authority: PublicationAuthority,
    publication: Publication,
    exit: bool,
}

struct FsScenario {
    vm_space: Arc<VmSpace>,
    state: SpinLock<FsState>,
    #[cfg(feature = "virtio-cser-facade")]
    production: SpinLock<ProductionReadRuntime>,
    done: SpinLock<Option<EffectWaker>>,
}

impl FsScenario {
    #[cfg(feature = "virtio-cser-facade")]
    fn dispatch_first_executable_pread_same_boot(
        &self,
        descriptor: SyscallDescriptor,
    ) -> DispatchOutcome {
        assert_eq!(descriptor.number(), __NR_pread64 as usize);
        assert_eq!(descriptor.argument(0), 3);
        assert_eq!(descriptor.argument(2), 4);
        assert_eq!(descriptor.argument(3), 0);

        // Capture the real UserContext descriptor before fd/inode resolution.
        let syscall = {
            let mut runtime = self.production.lock();
            assert_eq!(runtime.phase, ProductionReadPhase::Ready);
            let syscall = runtime
                .registry
                .register_derived(DerivedRegisterRequest {
                    request: RegisterRequest {
                        scope: SCOPE,
                        task: GUEST,
                        operation: OP_SYSCALL,
                        descriptor,
                        resources: vec![PROCESS_RESOURCE, GUEST_REPLY_RESOURCE],
                        credits: vec![
                            CreditCharge::new(CONTROL_CREDIT, 1),
                            CreditCharge::new(GUEST_REPLY_CREDIT, 1),
                        ],
                        publication: PublicationMode::Required,
                    },
                    domain: PERSONALITY_DOMAIN,
                    parent: None,
                })
                .unwrap();
            runtime
                .registry
                .prepare(PERSONALITY_V1, syscall.handle)
                .unwrap();
            runtime.phase = ProductionReadPhase::Captured(syscall.identity.effect());
            runtime.registry.check_invariants().unwrap();
            syscall
        };

        // This is the real filesystem personality's fd/inode resolution. It
        // intentionally follows the immutable production capture above.
        {
            let mut state = self.state.lock();
            assert!(!state.production_read_observed);
            assert!(
                state
                    .fds
                    .get(&3)
                    .is_some_and(|kind| *kind == FdKind::Executable)
            );
            state.production_read_observed = true;
        }

        let flight = {
            let mut runtime = self.production.lock();
            assert_eq!(
                runtime.phase,
                ProductionReadPhase::Captured(syscall.identity.effect())
            );

            let filesystem = runtime
                .registry
                .register_derived(DerivedRegisterRequest {
                    request: RegisterRequest {
                        scope: SCOPE,
                        task: FILESYSTEM_V1,
                        operation: OP_FILESYSTEM_READ,
                        descriptor,
                        resources: vec![EXEC_INODE_RESOURCE, FILESYSTEM_READ_RESOURCE],
                        credits: vec![CreditCharge::new(FILESYSTEM_OP_CREDIT, 1)],
                        publication: PublicationMode::None,
                    },
                    domain: FILESYSTEM_DOMAIN,
                    parent: Some(syscall.identity.effect()),
                })
                .unwrap();
            runtime
                .registry
                .prepare(FILESYSTEM_V1, filesystem.handle)
                .unwrap();

            let crash = runtime
                .registry
                .crash_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V1)
                .unwrap();
            assert_eq!(crash.previous_binding_epoch, 1);
            assert_eq!(crash.binding_epoch, 2);
            assert_eq!(crash.cohort.len(), 1);
            assert!(crash.cohort.contains(&filesystem.identity.effect()));
            let snapshot = runtime
                .registry
                .domain_recovery_snapshot(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2)
                .unwrap();
            assert_eq!(snapshot.effects.len(), 1);
            assert_eq!(snapshot.effects[0].effect, filesystem.identity.effect());
            runtime
                .registry
                .domain_ready(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2, &snapshot)
                .unwrap();
            let rebound = runtime
                .registry
                .rebind_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2)
                .unwrap();
            assert_eq!(rebound.binding_epoch, 2);
            let recovery = runtime
                .registry
                .recover_next_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2)
                .unwrap()
                .expect("same-boot filesystem read survives registry-domain crash");
            assert_eq!(recovery.handle, filesystem.handle);
            let adopted_filesystem = runtime
                .registry
                .adopt_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2, filesystem.handle)
                .unwrap();
            assert_eq!(adopted_filesystem.effect(), filesystem.identity.effect());
            assert_eq!(adopted_filesystem.binding_epoch(), 2);

            let mut root = runtime.root.take().expect("one same-boot PCI root");
            let mut device = runtime.device.take().expect("one same-boot device owner");
            let prepared_request = device
                .prepare_read_sector0(&mut root)
                .expect("prepare same-boot sector-zero read");
            let hardware_identity = prepared_request.identity();
            let bdf = root.device_bdf();
            assert_eq!(hardware_identity.device_bdf(), bdf);
            assert_eq!((bdf.bus(), bdf.device(), bdf.function()), (0, 5, 0));
            assert_eq!(hardware_identity.device_generation(), 1);
            let envelope = DeviceEnvelope::new(
                hardware_identity.device_session(),
                hardware_identity.queue(),
                hardware_identity.descriptor_token(),
                hardware_identity.device_generation(),
            )
            .unwrap();
            let expected_hardware_identity = DeviceSessionIdentity::from_coordinates(
                envelope.device_session(),
                bdf,
                envelope.queue(),
                envelope.descriptor_token(),
                envelope.device_generation(),
            );
            assert_eq!(hardware_identity, expected_hardware_identity);

            let queue_driver = owner_address(
                hardware_identity.device_generation(),
                OwnerKind::QueueDriver,
            );
            let queue_device = owner_address(
                hardware_identity.device_generation(),
                OwnerKind::QueueDevice,
            );
            let request_owner =
                owner_address(hardware_identity.device_generation(), OwnerKind::Request);
            let block_descriptor = SyscallDescriptor::new(
                OP_BLOCK_REQUEST.value() as usize,
                [
                    0,
                    512,
                    usize::from(hardware_identity.queue()),
                    usize::from(hardware_identity.descriptor_token()),
                    usize::try_from(hardware_identity.device_session()).unwrap(),
                    usize::try_from(hardware_identity.device_generation()).unwrap(),
                ],
            );
            let [block, dma_queue_a, dma_queue_b, dma_request] = runtime
                .registry
                .register_device_derived_cohort([
                    DeviceDerivedCohortEntry {
                        batch_index: 0,
                        request: RegisterRequest {
                            scope: SCOPE,
                            task: BLOCK_V1,
                            operation: OP_BLOCK_REQUEST,
                            descriptor: block_descriptor,
                            resources: vec![BLOCK_REQUEST_RESOURCE],
                            credits: vec![same_boot_credit(QUEUE_SLOT_CREDIT, 1)],
                            publication: PublicationMode::None,
                        },
                        domain: BLOCK_DOMAIN,
                        parent: DeviceCohortParent::Existing(filesystem.identity.effect()),
                        device: envelope,
                    },
                    same_boot_dma_entry(
                        1,
                        OP_DMA_QUEUE_OWNER_A,
                        DMA_QUEUE_OWNER_A_NAMESPACE,
                        hardware_identity,
                        envelope,
                        queue_driver.0,
                        queue_driver.1,
                    ),
                    same_boot_dma_entry(
                        2,
                        OP_DMA_QUEUE_OWNER_B,
                        DMA_QUEUE_OWNER_B_NAMESPACE,
                        hardware_identity,
                        envelope,
                        queue_device.0,
                        queue_device.1,
                    ),
                    same_boot_dma_entry(
                        3,
                        OP_DMA_REQUEST_OWNER,
                        DMA_REQUEST_OWNER_NAMESPACE,
                        hardware_identity,
                        envelope,
                        request_owner.0,
                        request_owner.1,
                    ),
                ])
                .unwrap();
            for effect in [&block, &dma_queue_a, &dma_queue_b, &dma_request] {
                runtime.registry.prepare(BLOCK_V1, effect.handle).unwrap();
            }

            let credits = runtime.registry.scope_projection(SCOPE).unwrap().credits;
            assert_eq!(credits.capacity, 10);
            assert_eq!(credits.free, 0);
            assert_eq!(credits.held, 10);
            assert_eq!(credits.committed, 0);
            assert_eq!(credits.retained, 0);
            let authority = runtime
                .registry
                .kernel_root_authority(SCOPE, ROOT_OWNER)
                .unwrap();
            let handles = [
                syscall.handle,
                adopted_filesystem,
                block.handle,
                dma_queue_a.handle,
                dma_queue_b.handle,
                dma_request.handle,
            ];
            let enrollment = runtime
                .registry
                .enroll_device_batch(authority, &handles, envelope)
                .unwrap();
            assert_eq!(enrollment.effects().len(), 6);
            assert_eq!(enrollment.device(), envelope);
            prepared_request
                .preflight_publish(expected_hardware_identity)
                .unwrap();
            let commits = [
                (syscall.handle, CommitMetadata::new(4, 1)),
                (adopted_filesystem, CommitMetadata::new(4, 1)),
                (block.handle, CommitMetadata::new(512, 1)),
                (dma_queue_a.handle, CommitMetadata::new(1, 1)),
                (dma_queue_b.handle, CommitMetadata::new(1, 1)),
                (dma_request.handle, CommitMetadata::new(1, 1)),
            ];
            let (batch, published) = match runtime
                .registry
                .commit_device_batch_with_publish(authority, &enrollment, &commits, move |_| {
                    prepared_request.publish_prepared()
                })
                .unwrap()
            {
                DeviceBatchCommitOutcome::Applied {
                    receipt,
                    publication,
                } => (receipt, publication),
                DeviceBatchCommitOutcome::AlreadyCommitted { .. } => {
                    panic!("fresh same-boot device batch replayed")
                }
            };
            runtime
                .registry
                .validate_device_batch_receipt(&batch)
                .unwrap();
            let selection = runtime.registry.revoke_begin(SCOPE).unwrap();
            assert_eq!(selection.target_count, 6);
            let cookie = runtime.next_flight_cookie;
            runtime.next_flight_cookie = cookie.checked_add(1).unwrap();
            runtime.phase = ProductionReadPhase::Polling(cookie);
            runtime.registry.check_invariants().unwrap();

            println!(
                "LINUX_FS_SAME_BOOT Capture same_boot=true identity_preserving=true real_dma=true scope=95 authority_epoch=141 effects=6 credits=10 device={} session={:#018x} generation={} queue={} descriptor={} syscall_effect={} filesystem_effect={} block_effect={}",
                bdf,
                envelope.device_session(),
                envelope.device_generation(),
                envelope.queue(),
                envelope.descriptor_token(),
                syscall.identity.effect().id(),
                filesystem.identity.effect().id(),
                block.identity.effect().id(),
            );
            for (kind, effect, address) in [
                ("queue_driver", dma_queue_a.identity.effect(), queue_driver),
                ("queue_device", dma_queue_b.identity.effect(), queue_device),
                ("request", dma_request.identity.effect(), request_owner),
            ] {
                println!(
                    "LINUX_FS_SAME_BOOT DmaOwner kind={} effect={} paddr={:#x} iova={:#x} page_size={} queue={} descriptor={} generation={}",
                    kind,
                    effect.id(),
                    address.0,
                    address.1,
                    ostd::mm::PAGE_SIZE,
                    envelope.queue(),
                    envelope.descriptor_token(),
                    envelope.device_generation(),
                );
            }
            println!(
                "LINUX_FS_SAME_BOOT Commit batch_sequence={} commit_point=avail_idx_release syscall_effect={} filesystem_effect={} block_effect={} dma_queue_owner_a_effect={} dma_queue_owner_b_effect={} dma_request_owner_effect={} publication_once=true revoke_begin_immediate=true",
                batch.batch_sequence(),
                syscall.identity.effect().id(),
                filesystem.identity.effect().id(),
                block.identity.effect().id(),
                dma_queue_a.identity.effect().id(),
                dma_queue_b.identity.effect().id(),
                dma_request.identity.effect().id(),
            );

            SameBootFlight {
                cookie,
                batch,
                published,
                root,
                device,
                selection,
                effects: [
                    syscall.identity.effect(),
                    filesystem.identity.effect(),
                    block.identity.effect(),
                    dma_queue_a.identity.effect(),
                    dma_queue_b.identity.effect(),
                    dma_request.identity.effect(),
                ],
                envelope,
            }
        };

        let SameBootFlight {
            cookie,
            batch,
            mut published,
            mut root,
            mut device,
            selection,
            effects,
            envelope,
        } = flight;
        let notification = published.notify();
        assert!(matches!(
            notification,
            NotificationDisposition::Kicked | NotificationDisposition::Suppressed
        ));
        let notification_label = match notification {
            NotificationDisposition::Kicked => "Kicked",
            NotificationDisposition::Suppressed => "Suppressed",
            NotificationDisposition::AlreadyResolved => unreachable!(),
        };
        println!(
            "LINUX_FS_SAME_BOOT Notify disposition={} polling=true irq=false smp=1",
            notification_label,
        );

        // Polling and every hardware reset/IOTLB wait happen outside the OSTD
        // SpinLock. The flight cookie authenticates each re-entry below.
        let progress = published.poll_completion();
        let (result, bytes, reset_tombstone, completion_label, used_len, reset_ticket) =
            match progress {
                CompletionProgress::Complete(completed) => {
                    assert_eq!(fnv1a(completed.data()), SAME_BOOT_SECTOR_FNV1A);
                    let bytes = completed.data()[..4].to_vec();
                    assert_eq!(bytes.as_slice(), b"\x7fELF");
                    let used_len = completed.used_len();
                    let reset_ticket = {
                        let mut runtime = self.production.lock();
                        assert_eq!(runtime.phase, ProductionReadPhase::Polling(cookie));
                        let completion = runtime
                            .registry
                            .record_device_completion(&batch, envelope, 4)
                            .unwrap();
                        assert_eq!(completion.causal_root(), effects[0]);
                        assert_eq!(completion.result(), 4);
                        let reset_ticket = runtime.registry.begin_device_reset(&batch).unwrap();
                        runtime.phase = ProductionReadPhase::Closing(cookie);
                        runtime.registry.check_invariants().unwrap();
                        reset_ticket
                    };
                    (
                        4,
                        bytes,
                        completed.begin_reset(true),
                        "Completed",
                        used_len,
                        reset_ticket,
                    )
                }
                CompletionProgress::Pending(pending) => {
                    assert_eq!(
                        pending.identity(),
                        published_identity(envelope, root.device_bdf())
                    );
                    let reset_ticket = {
                        let mut runtime = self.production.lock();
                        assert_eq!(runtime.phase, ProductionReadPhase::Polling(cookie));
                        let reset_ticket = runtime.registry.begin_device_reset(&batch).unwrap();
                        runtime.phase = ProductionReadPhase::Closing(cookie);
                        runtime.registry.check_invariants().unwrap();
                        reset_ticket
                    };
                    (
                        -5,
                        Vec::new(),
                        pending.begin_reset(true),
                        "Pending",
                        0,
                        reset_ticket,
                    )
                }
                CompletionProgress::Failed(failed) => {
                    assert_eq!(
                        failed.identity(),
                        published_identity(envelope, root.device_bdf())
                    );
                    println!(
                        "LINUX_FS_SAME_BOOT CompletionFailure failure={:?} descriptor_popped={} used_len={:?} retained=true",
                        failed.failure(),
                        failed.descriptor_popped(),
                        failed.used_len(),
                    );
                    let reset_ticket = {
                        let mut runtime = self.production.lock();
                        assert_eq!(runtime.phase, ProductionReadPhase::Polling(cookie));
                        let reset_ticket = runtime.registry.begin_device_reset(&batch).unwrap();
                        runtime.phase = ProductionReadPhase::Closing(cookie);
                        runtime.registry.check_invariants().unwrap();
                        reset_ticket
                    };
                    (
                        -5,
                        Vec::new(),
                        failed.begin_reset(true),
                        "Failed",
                        0,
                        reset_ticket,
                    )
                }
            };
        println!(
            "LINUX_FS_SAME_BOOT Completion outcome={} result={} used_len={} payload_source={} data_prefix={}",
            completion_label,
            result,
            used_len,
            if result == 4 {
                "CompletedRequest"
            } else {
                "none"
            },
            if result == 4 { "7f454c46" } else { "none" },
        );

        let retained_pages = reset_tombstone.retained_dma_pages();
        assert_eq!(retained_pages, 3);
        let reset_tombstone = match reset_tombstone.retry_ack(&mut root) {
            Ok(_) => panic!("injected same-boot reset timeout did not remain pending"),
            Err(tombstone) => tombstone,
        };
        let retry_ticket = {
            let mut runtime = self.production.lock();
            assert_eq!(runtime.phase, ProductionReadPhase::Closing(cookie));
            assert_eq!(
                runtime
                    .registry
                    .scope_projection(SCOPE)
                    .unwrap()
                    .credits
                    .retained,
                0
            );
            let tombstone = runtime
                .registry
                .retain_device_reset_timeout(&reset_ticket)
                .unwrap();
            assert_eq!(tombstone.device(), envelope);
            let retry = runtime.registry.retry_device_reset(&tombstone).unwrap();
            assert_eq!(
                runtime
                    .registry
                    .scope_projection(SCOPE)
                    .unwrap()
                    .credits
                    .retained,
                10
            );
            runtime.registry.check_invariants().unwrap();
            retry
        };
        println!(
            "LINUX_FS_SAME_BOOT ResetTimeout registry_tombstone=true hardware_tombstone=true retained_pages={} generation={}",
            retained_pages,
            envelope.device_generation(),
        );
        let mut hardware_reset = match reset_tombstone.retry_ack(&mut root) {
            Ok(reset) => reset,
            Err(_) => panic!("same retained hardware reset tombstone remained pending"),
        };
        assert_eq!(
            hardware_reset.identity(),
            published_identity(envelope, root.device_bdf())
        );
        assert_eq!(hardware_reset.retained_dma_pages(), 3);
        let (registry_reset, new_hardware_generation) = {
            let mut runtime = self.production.lock();
            assert_eq!(runtime.phase, ProductionReadPhase::Closing(cookie));
            let generation_plan = device
                .prepare_generation_advance(&mut hardware_reset)
                .unwrap();
            let (receipt, generation) = runtime
                .registry
                .acknowledge_device_reset_with_apply(&retry_ticket, |prepared| {
                    assert_eq!(prepared.old_device(), envelope);
                    generation_plan.apply()
                })
                .unwrap();
            runtime.registry.check_invariants().unwrap();
            (receipt, generation)
        };
        assert_eq!(new_hardware_generation, 2);
        assert_eq!(registry_reset.old_device(), envelope);
        assert_eq!(registry_reset.new_device().device_generation(), 2);
        assert_eq!(
            registry_reset.outcome(),
            if result == 4 {
                DeviceClosureResult::Completed(4)
            } else {
                DeviceClosureResult::IndeterminateAfterReset
            }
        );
        println!(
            "LINUX_FS_SAME_BOOT ResetAck generation={}->{} outcome={} retained_pages=3 generation_apply_atomic=true",
            registry_reset.old_device().device_generation(),
            registry_reset.new_device().device_generation(),
            if result == 4 {
                "Completed"
            } else {
                "IndeterminateAfterReset"
            },
        );

        let registry_iotlb = {
            let mut runtime = self.production.lock();
            runtime
                .registry
                .begin_device_iotlb(&registry_reset)
                .unwrap()
        };
        let hardware_iotlb = match device.begin_iotlb(hardware_reset, true) {
            ProductionClosureProgress::Pending(tombstone) => tombstone,
            ProductionClosureProgress::Complete(_) => {
                panic!("injected same-boot IOTLB timeout completed early")
            }
        };
        assert_eq!(hardware_iotlb.retained_pages(), 3);
        assert!(!hardware_iotlb.failure_retained());
        let registry_iotlb_retry = {
            let mut runtime = self.production.lock();
            let tombstone = runtime
                .registry
                .retain_device_iotlb_timeout(&registry_iotlb)
                .unwrap();
            assert_eq!(
                tombstone.device().device_generation(),
                registry_reset.new_device().device_generation()
            );
            let retry = runtime
                .registry
                .retry_device_iotlb(&registry_reset, &tombstone)
                .unwrap();
            runtime.registry.check_invariants().unwrap();
            retry
        };
        println!(
            "LINUX_FS_SAME_BOOT IotlbTimeout registry_generation={} hardware_identity_generation={} retained_pages=3 registry_tombstone=true hardware_tombstone=true",
            registry_reset.new_device().device_generation(),
            envelope.device_generation(),
        );
        let mut hardware_closure = match hardware_iotlb.retry(1024) {
            ProductionClosureProgress::Complete(receipt) => receipt,
            ProductionClosureProgress::Pending(_) => {
                panic!("same retained IOTLB tombstone remained pending")
            }
        };
        assert_eq!(hardware_closure.completed_pages(), 3);
        let registry_closure = {
            let mut runtime = self.production.lock();
            let quiescence_plan = device
                .prepare_quiescence_apply(&mut hardware_closure)
                .unwrap();
            let (closure, applied_identity) = runtime
                .registry
                .acknowledge_device_iotlb_with_apply(&registry_iotlb_retry, |prepared| {
                    assert_eq!(
                        prepared.device().device_generation(),
                        registry_reset.new_device().device_generation()
                    );
                    quiescence_plan.apply()
                })
                .unwrap();
            assert_eq!(
                applied_identity,
                published_identity(envelope, root.device_bdf())
            );
            runtime.registry.check_invariants().unwrap();
            closure
        };
        assert_eq!(registry_closure.outcome(), registry_reset.outcome());
        println!(
            "LINUX_FS_SAME_BOOT IotlbAck completed_pages=3 registry_generation={} hardware_identity_generation={} quiescence_applied=true",
            registry_closure.device().device_generation(),
            envelope.device_generation(),
        );

        let ticket = {
            let mut runtime = self.production.lock();
            assert_eq!(runtime.phase, ProductionReadPhase::Closing(cookie));
            let leaf_first = [
                effects[3], effects[4], effects[5], effects[2], effects[1], effects[0],
            ];
            let mut publication = None;
            for expected in leaf_first {
                let selected = runtime
                    .registry
                    .revoke_next(&selection)
                    .unwrap()
                    .expect("same-boot revoke leaf");
                assert_eq!(selected.effect, expected);
                assert!(matches!(selected.disposition, RevokeDisposition::Drain(_)));
                let request = match registry_closure.outcome() {
                    DeviceClosureResult::Completed(_) => {
                        let commit = batch.commit_for(expected).unwrap();
                        TerminalRequest::completed(commit.result())
                    }
                    DeviceClosureResult::IndeterminateAfterReset => {
                        TerminalRequest::indeterminate_after_reset(-5)
                    }
                    DeviceClosureResult::AbortedBeforeCommit => unreachable!(),
                };
                let terminal = runtime
                    .registry
                    .stage_device_batch_terminal(&registry_closure, expected, request)
                    .unwrap();
                if terminal.publication.is_some() {
                    assert_eq!(expected, effects[0]);
                    assert!(publication.is_none());
                    publication = terminal.publication;
                }
            }
            assert!(runtime.registry.revoke_next(&selection).unwrap().is_none());
            let publication = publication.expect("same-boot root publication ticket");
            assert_eq!(publication.result(), result);
            runtime.root = Some(root);
            runtime.device = Some(device);
            runtime.active_revoke = Some(selection.clone());
            runtime.phase = ProductionReadPhase::AwaitingPublication(cookie);
            runtime.registry.check_invariants().unwrap();
            publication
        };
        println!(
            "LINUX_FS_SAME_BOOT Close leaf_first=dma_queue_owner_a,dma_queue_owner_b,dma_request_owner,block_request,filesystem_read,filesystem_syscall terminal_outcome={} guest_publication_pending=true",
            if result == 4 {
                "Completed"
            } else {
                "IndeterminateAfterReset"
            },
        );

        DispatchOutcome {
            result,
            authority: PublicationAuthority::Production {
                ticket,
                flight_cookie: cookie,
            },
            publication: if result == 4 {
                Publication::GuestBytes {
                    address: descriptor.argument(1),
                    bytes,
                }
            } else {
                Publication::None
            },
            exit: false,
        }
    }

    #[cfg(not(feature = "virtio-cser-facade"))]
    fn dispatch_first_executable_pread(
        &self,
        state: &mut FsState,
        descriptor: SyscallDescriptor,
    ) -> DispatchOutcome {
        // Capture the personality authority directly from the immutable guest
        // descriptor. No fd resolution, inode lookup, or payload read has
        // occurred before this registration.
        let registered = state.capture(descriptor, vec![PROCESS_RESOURCE]);
        assert_eq!(descriptor.argument(0) as i32, 3);
        assert_eq!(state.fds.get(&3), Some(&FdKind::Executable));

        // Filesystem policy resolves the known inode and reaches the block
        // preparation boundary, including the bounded registry-domain crash,
        // while the real workload-created effects remain live.
        let prepared = state.begin_first_executable_read(&registered, descriptor);

        // Phase 2 deliberately sources the bytes from the bounded in-memory
        // inode only after the causal chain is live. The prepared BlockRequest
        // neither supplies these bytes nor publishes a device descriptor.
        let offset = descriptor.argument(3);
        let count = descriptor.argument(2);
        let start = offset.min(RUNTIME_FS_ELF.len());
        let end = start.saturating_add(count).min(RUNTIME_FS_ELF.len());
        let bytes = RUNTIME_FS_ELF[start..end].to_vec();
        let result = bytes.len() as i64;
        let receipt = state.finish_first_executable_read(prepared, descriptor, &bytes);

        let commit = state.commit(&registered, result);
        let commit_sequence = commit.sequence();
        println!(
            "LINUX_FS_PRODUCTION_IDENTITY Capture root_scope=95 authority_epoch=141 cohort_source=normal_pread64_path registry=workload_owned syscall_effect={} syscall_domain=personality filesystem_effect={} filesystem_domain=filesystem block_effect={} block_domain=block immutable_ancestry=syscall->filesystem->block distinct_effects=true capture_before_fd_resolution=true capture_before_payload_read=true",
            receipt.syscall_effect, receipt.filesystem_effect, receipt.block_effect,
        );
        println!(
            "LINUX_FS_PRODUCTION_IDENTITY Recovery filesystem_binding={}->{} crash_injection=registry_domain real_user_service_crash=false crash_cohort=filesystem_read_only snapshot=true ready=true rebind=true adopted_same_effect=true parent_unchanged=true origin_binding_unchanged=true resources_unchanged=true old_handle=StaleBinding full_projection_unchanged=true peer_bindings_unchanged=true",
            receipt.filesystem_old_binding, receipt.filesystem_new_binding,
        );
        println!(
            "LINUX_FS_PRODUCTION_IDENTITY Ledger credit_classes=control:0x301,filesystem:0x302,queue:0x303,pinned_page:0x304,dma_mapping:0x305,guest_reply:0x306,block_preparation:0x307 capacity=7 held_at_preparation=4 device_credits_held=0 device_credits_free=queue+pinned_page+dma_mapping resources=syscall:0x7100:1:1+0x7300:1:1,filesystem:0x7101:1:1+0x7301:1:1,block_preparation:0x7302:1:1+0x7306:1:1 exact_generations=true"
        );
        println!(
            "LINUX_FS_PRODUCTION_IDENTITY Digests input_sha256={} payload_sha256={} preparation_sha256={} input_bytes={} payload_bytes={} preparation_bytes={} runtime_fnv_checked=true",
            FIRST_PREAD_INPUT_SHA256,
            FIRST_PREAD_PAYLOAD_SHA256,
            BLOCK_PREPARATION_SHA256,
            FIRST_PREAD_INPUT_BYTES.len(),
            result,
            BLOCK_PREPARATION_BYTES.len(),
        );
        println!(
            "LINUX_FS_PRODUCTION_IDENTITY BlockPreparation effect={} phase=Prepared terminal=Aborted terminal_sequence={} preparation_only=true adapter=bounded_in_memory queue_credit_held=false pinned_page_credit_held=false dma_mapping_credit_held=false device_commit=false avail_idx_release=false returned_payload_source=runtime_fs_elf",
            receipt.block_effect, receipt.block_terminal_sequence,
        );
        println!(
            "LINUX_FS_PRODUCTION_IDENTITY NoSyntheticCohort positive_cohort=normal_workload_path foreign_registry_receipt=CommitConflict foreign_receipt_accepted=false full_projection_unchanged=true negative_only_registry=true"
        );
        println!(
            "LINUX_FS_PRODUCTION_IDENTITY Close block_terminal_sequence={} filesystem_commit_sequence={} filesystem_terminal_sequence={} personality_commit_sequence={} leaf_first=true descendants_closed_before_parent_commit=true filesystem_result_source=bounded_in_memory",
            receipt.block_terminal_sequence,
            receipt.filesystem_commit_sequence,
            receipt.filesystem_terminal_sequence,
            commit_sequence,
        );
        println!(
            "LINUX_FS Pread effect={} commit_sequence={} fd=3 offset={} bytes={} elf_magic=true pager=bounded block_preparation=observed device_commit=false payload_source=bounded_in_memory",
            registered.identity.effect().id(),
            commit_sequence,
            offset,
            result,
        );

        state.record_domain_change(&commit);
        let ticket = state.terminalize(&registered, result, commit);
        state.effects.check_invariants().unwrap();
        DispatchOutcome {
            result,
            authority: PublicationAuthority::Generic(ticket),
            publication: Publication::GuestBytes {
                address: descriptor.argument(1),
                bytes,
            },
            exit: false,
        }
    }

    fn dispatch(&self, descriptor: SyscallDescriptor) -> DispatchOutcome {
        let mut state = self.state.lock();
        assert!(!state.exited);

        if descriptor.number() == __NR_pread64 as usize && !state.production_read_observed {
            #[cfg(feature = "virtio-cser-facade")]
            {
                drop(state);
                return self.dispatch_first_executable_pread_same_boot(descriptor);
            }
            #[cfg(not(feature = "virtio-cser-facade"))]
            return self.dispatch_first_executable_pread(&mut state, descriptor);
        }

        let (resources, result, publication, exit, action) = match descriptor.number() {
            number if number == __NR_openat as usize => {
                assert_eq!(descriptor.argument(0) as i32, AT_FDCWD);
                let path = read_c_string(&self.vm_space, descriptor.argument(1), 64);
                let flags = descriptor.argument(2);
                let fd = state.next_fd;
                if path.as_slice() == EXECUTABLE_PATH {
                    assert_eq!(flags, 0);
                    (
                        vec![PROCESS_RESOURCE, EXEC_INODE_RESOURCE],
                        i64::from(fd),
                        Publication::None,
                        false,
                        FsAction::Open(fd, FdKind::Executable),
                    )
                } else if path.as_slice() == TMP_PATH {
                    assert_eq!(flags, O_TMP_FLAGS);
                    assert_eq!(descriptor.argument(3), 0o644);
                    (
                        vec![PROCESS_RESOURCE, TMP_INODE_RESOURCE],
                        i64::from(fd),
                        Publication::None,
                        false,
                        FsAction::OpenTmp(fd),
                    )
                } else if path.as_slice() == PROC_SELF_PATH {
                    assert_eq!(flags, AT_DIRECTORY);
                    (
                        vec![PROCESS_RESOURCE, PROC_INODE_RESOURCE],
                        i64::from(fd),
                        Publication::None,
                        false,
                        FsAction::Open(fd, FdKind::ProcSelf),
                    )
                } else {
                    panic!("unsupported runtime-fs openat path")
                }
            }
            number if number == __NR_pread64 as usize => {
                let fd = descriptor.argument(0) as i32;
                let count = descriptor.argument(2);
                let offset = descriptor.argument(3);
                let kind = *state.fds.get(&fd).expect("bounded pread fd");
                let source = match kind {
                    FdKind::Executable => RUNTIME_FS_ELF,
                    FdKind::Temporary => state.temporary.as_slice(),
                    _ => panic!("unsupported pread fd kind"),
                };
                let start = offset.min(source.len());
                let end = start.saturating_add(count).min(source.len());
                let bytes = source[start..end].to_vec();
                let resource = match kind {
                    FdKind::Executable => EXEC_INODE_RESOURCE,
                    FdKind::Temporary => TMP_INODE_RESOURCE,
                    _ => unreachable!(),
                };
                (
                    vec![PROCESS_RESOURCE, resource],
                    bytes.len() as i64,
                    Publication::GuestBytes {
                        address: descriptor.argument(1),
                        bytes,
                    },
                    false,
                    FsAction::Pread(kind, offset),
                )
            }
            number if number == __NR_statx as usize => {
                let fd = descriptor.argument(0) as i32;
                assert_eq!(state.fds.get(&fd), Some(&FdKind::Executable));
                assert!(read_c_string(&self.vm_space, descriptor.argument(1), 2).is_empty());
                assert_eq!(descriptor.argument(2), AT_EMPTY_PATH);
                assert_eq!(descriptor.argument(3), STATX_MASK as usize);
                let mut bytes = vec![0; STATX_BYTES];
                bytes[0..4].copy_from_slice(&STATX_MASK.to_le_bytes());
                bytes[28..30].copy_from_slice(&REGULAR_MODE.to_le_bytes());
                bytes[40..48].copy_from_slice(&(RUNTIME_FS_ELF.len() as u64).to_le_bytes());
                (
                    vec![PROCESS_RESOURCE, EXEC_INODE_RESOURCE],
                    0,
                    Publication::GuestBytes {
                        address: descriptor.argument(4),
                        bytes,
                    },
                    false,
                    FsAction::Statx,
                )
            }
            number if number == __NR_newfstatat as usize => {
                let fd = descriptor.argument(0) as i32;
                assert_eq!(state.fds.get(&fd), Some(&FdKind::Executable));
                assert!(read_c_string(&self.vm_space, descriptor.argument(1), 2).is_empty());
                assert_eq!(descriptor.argument(3), AT_EMPTY_PATH);
                let mut bytes = vec![0; STAT_BYTES];
                bytes[24..28].copy_from_slice(&(u32::from(REGULAR_MODE)).to_le_bytes());
                bytes[48..56].copy_from_slice(&(RUNTIME_FS_ELF.len() as i64).to_le_bytes());
                (
                    vec![PROCESS_RESOURCE, EXEC_INODE_RESOURCE],
                    0,
                    Publication::GuestBytes {
                        address: descriptor.argument(2),
                        bytes,
                    },
                    false,
                    FsAction::Newfstatat,
                )
            }
            number if number == __NR_pwrite64 as usize => {
                let fd = descriptor.argument(0) as i32;
                assert_eq!(state.fds.get(&fd), Some(&FdKind::Temporary));
                let bytes = read_guest_bytes(
                    &self.vm_space,
                    descriptor.argument(1),
                    descriptor.argument(2),
                );
                assert_eq!(bytes.as_slice(), b"xy");
                assert_eq!(descriptor.argument(3), 2);
                (
                    vec![PROCESS_RESOURCE, TMP_INODE_RESOURCE],
                    bytes.len() as i64,
                    Publication::None,
                    false,
                    FsAction::Pwrite {
                        offset: descriptor.argument(3),
                        bytes,
                    },
                )
            }
            number if number == __NR_readlinkat as usize => {
                let fd = descriptor.argument(0) as i32;
                assert_eq!(state.fds.get(&fd), Some(&FdKind::ProcSelf));
                assert_eq!(
                    read_c_string(&self.vm_space, descriptor.argument(1), 8).as_slice(),
                    PROC_EXE_NAME
                );
                assert!(descriptor.argument(3) >= EXECUTABLE_PATH.len());
                (
                    vec![PROCESS_RESOURCE, PROC_INODE_RESOURCE],
                    EXECUTABLE_PATH.len() as i64,
                    Publication::GuestBytes {
                        address: descriptor.argument(2),
                        bytes: EXECUTABLE_PATH.to_vec(),
                    },
                    false,
                    FsAction::Readlinkat,
                )
            }
            number if number == __NR_close as usize => {
                let fd = descriptor.argument(0) as i32;
                let kind = *state.fds.get(&fd).expect("bounded close fd");
                assert_ne!(kind, FdKind::Stdout);
                (
                    vec![PROCESS_RESOURCE],
                    0,
                    Publication::None,
                    false,
                    FsAction::Close(fd, kind),
                )
            }
            number if number == __NR_write as usize => {
                assert_eq!(descriptor.argument(0), 1);
                let bytes = read_guest_bytes(
                    &self.vm_space,
                    descriptor.argument(1),
                    descriptor.argument(2),
                );
                assert_eq!(bytes.as_slice(), EXPECTED_STDOUT);
                assert_eq!(state.stdout_publications, 0);
                (
                    vec![PROCESS_RESOURCE],
                    bytes.len() as i64,
                    Publication::Stdout,
                    false,
                    FsAction::WriteStdout,
                )
            }
            number if number == __NR_exit as usize => {
                assert_eq!(descriptor.argument(0), 0);
                (
                    vec![PROCESS_RESOURCE],
                    0,
                    Publication::None,
                    true,
                    FsAction::Exit,
                )
            }
            other => panic!("unsupported retained runtime-fs syscall {other}"),
        };

        let registered = state.capture(descriptor, resources);
        let effect = registered.identity.effect().id();
        let commit = state.commit(&registered, result);
        let commit_sequence = commit.sequence();

        match action {
            FsAction::Open(fd, kind) => {
                state.allocate_fd_after_commit(fd, kind);
                let (path, label) = match kind {
                    FdKind::Executable => ("/bin/linux-runtime-fs-smoke", "executable"),
                    FdKind::ProcSelf => ("/proc/self", "proc_directory"),
                    _ => unreachable!(),
                };
                println!(
                    "LINUX_FS Open effect={} commit_sequence={} fd={} path={} kind={}",
                    effect, commit_sequence, fd, path, label,
                );
            }
            FsAction::OpenTmp(fd) => {
                state.temporary.clear();
                state.allocate_fd_after_commit(fd, FdKind::Temporary);
                println!(
                    "LINUX_FS Open effect={} commit_sequence={} fd={} path=/tmp/runtime-fs.bin kind=regular create=true truncate=true mode=0644",
                    effect, commit_sequence, fd,
                );
            }
            FsAction::Pread(kind, offset) => match kind {
                FdKind::Executable => panic!("first executable pread bypassed production capture"),
                FdKind::Temporary => println!(
                    "LINUX_FS Pread effect={} commit_sequence={} fd=4 offset={} bytes={} payload=00007879",
                    effect, commit_sequence, offset, result,
                ),
                _ => unreachable!(),
            },
            FsAction::Statx => println!(
                "LINUX_FS Statx effect={} commit_sequence={} mask=0x17ff mode=regular size={} empty_path=true",
                effect,
                commit_sequence,
                RUNTIME_FS_ELF.len(),
            ),
            FsAction::Newfstatat => println!(
                "LINUX_FS Newfstatat effect={} commit_sequence={} mode=regular size={} empty_path=true",
                effect,
                commit_sequence,
                RUNTIME_FS_ELF.len(),
            ),
            FsAction::Pwrite { offset, bytes } => {
                let end = offset.checked_add(bytes.len()).unwrap();
                if state.temporary.len() < end {
                    state.temporary.resize(end, 0);
                }
                state.temporary[offset..end].copy_from_slice(&bytes);
                println!(
                    "LINUX_FS Pwrite effect={} commit_sequence={} fd=4 offset={} bytes={} payload=7879 state_after=00007879 commit_before_mutation=true dma=false",
                    effect,
                    commit_sequence,
                    offset,
                    bytes.len(),
                );
            }
            FsAction::Readlinkat => println!(
                "LINUX_FS Readlinkat effect={} commit_sequence={} dirfd=5 path=exe target=/bin/linux-runtime-fs-smoke bytes={} nul_appended=false",
                effect,
                commit_sequence,
                EXECUTABLE_PATH.len(),
            ),
            FsAction::Close(fd, kind) => {
                assert_eq!(state.fds.remove(&fd), Some(kind));
                println!(
                    "LINUX_FS Close effect={} commit_sequence={} fd={} remaining_runtime_fds={}",
                    effect,
                    commit_sequence,
                    fd,
                    state.fds.len() - 1,
                );
            }
            FsAction::WriteStdout => {
                state.stdout_publications += 1;
                println!(
                    "LINUX_FS Write effect={} commit_sequence={} fd=1 bytes=14 stdout_exact=true",
                    effect, commit_sequence,
                );
            }
            FsAction::Exit => {
                state.exited = true;
                println!(
                    "LINUX_FS Exit effect={} commit_sequence={} status=0 syscall=exit resumed_after_exit=false",
                    effect, commit_sequence,
                );
            }
        }

        state.record_domain_change(&commit);
        let ticket = state.terminalize(&registered, result, commit);
        state.effects.check_invariants().unwrap();
        DispatchOutcome {
            result,
            authority: PublicationAuthority::Generic(ticket),
            publication,
            exit,
        }
    }

    fn publish(&self, outcome: &DispatchOutcome) {
        match &outcome.publication {
            Publication::None => {}
            Publication::GuestBytes { address, bytes } => {
                write_guest_bytes(&self.vm_space, *address, bytes)
            }
            Publication::Stdout => println!("LINUX_FS stdout=runtime fs ok"),
        }
        match &outcome.authority {
            PublicationAuthority::Generic(ticket) => {
                let mut state = self.state.lock();
                state.effects.acknowledge_publication(ticket).unwrap();
                state.effects.check_invariants().unwrap();
            }
            #[cfg(feature = "virtio-cser-facade")]
            PublicationAuthority::Production {
                ticket,
                flight_cookie,
            } => {
                let mut runtime = self.production.lock();
                assert_eq!(
                    runtime.phase,
                    ProductionReadPhase::AwaitingPublication(*flight_cookie)
                );
                runtime.registry.acknowledge_publication(ticket).unwrap();
                let selection = runtime
                    .active_revoke
                    .take()
                    .expect("same-boot publication retains revoke selection");
                runtime.registry.revoke_complete(&selection).unwrap();
                runtime.phase = ProductionReadPhase::Complete;
                runtime.assert_complete();
                println!(
                    "LINUX_FS_SAME_BOOT GuestPublication result={} bytes={} source={} registry_ack=true revoke_complete=true",
                    outcome.result,
                    match &outcome.publication {
                        Publication::GuestBytes { bytes, .. } => bytes.len(),
                        Publication::None | Publication::Stdout => 0,
                    },
                    if outcome.result == 4 {
                        "CompletedRequest"
                    } else {
                        "none"
                    },
                );
                if outcome.result == 4 {
                    println!(
                        "LINUX_FS_SAME_BOOT PASS same_boot=true identity_preserving=true real_dma=true polling=true irq=false smp=1 scope=95 effects=6 credits=10 sector_sha256={} image_sha256={} sector_fnv1a={:#018x}",
                        SAME_BOOT_SECTOR_SHA256, SAME_BOOT_IMAGE_SHA256, SAME_BOOT_SECTOR_FNV1A,
                    );
                }
            }
        }
    }

    fn finish(&self) {
        let mut state = self.state.lock();
        state.close_scope();
        state.assert_final();
        drop(state);
        #[cfg(feature = "virtio-cser-facade")]
        self.production.lock().assert_complete();
        #[cfg(not(feature = "virtio-cser-facade"))]
        println!(
            "EFFECT_REGISTRY Quiescent workload=linux-runtime-fs production_root=95 production_effects=16 live=0 pending_publications=0 credits=Free"
        );
        #[cfg(not(feature = "virtio-cser-facade"))]
        println!(
            "LINUX_FS_SLICE PASS workload=linux-runtime-fs-smoke retained=true adapted=false syscalls=14 openat=3 pread64=2 statx=1 newfstatat=1 pwrite64=1 readlinkat=1 close=3 write=1 exit=1 commit_gate=true publication_acks=14 production_root=true production_domains=3 production_effects=16 production_identity_preparation=true immutable_ancestry=true filesystem_registry_domain_crash_adopt=true real_user_service_crash=false no_synthetic_cohort=true typed_credit_classes=7 leaf_first=true registry_quiescent=true runtime_filesystem=true bounded=true single_cpu=true block_adapter=bounded_in_memory block_preparation_observed=true device_commit=false real_dma=false virtio_evidence=component_consistency same_boot=false identity_preserving_stage5b=false"
        );
        #[cfg(feature = "virtio-cser-facade")]
        println!(
            "EFFECT_REGISTRY Quiescent workload=linux-runtime-fs generic_effects=13 device_cohort_effects=6 live=0 pending_publications=0 credits=Free"
        );
        #[cfg(feature = "virtio-cser-facade")]
        println!(
            "LINUX_FS_SLICE PASS workload=linux-runtime-fs-smoke retained=true adapted=false syscalls=14 openat=3 pread64=2 statx=1 newfstatat=1 pwrite64=1 readlinkat=1 close=3 write=1 exit=1 commit_gate=true publication_acks=14 production_root=true production_domains=3 production_effects=6 immutable_ancestry=true filesystem_registry_domain_crash_adopt=true real_user_service_crash=false no_synthetic_cohort=true typed_credit_classes=6 leaf_first=true registry_quiescent=true runtime_filesystem=true bounded=true single_cpu=true block_adapter=virtio_blk device_commit=true real_dma=true polling=true irq=false smp=1 same_boot=true identity_preserving=true"
        );
        self.done
            .lock()
            .take()
            .expect("one runtime-fs completion waker")
            .wake_up();
    }
}

enum FsAction {
    Open(i32, FdKind),
    OpenTmp(i32),
    Pread(FdKind, usize),
    Statx,
    Newfstatat,
    Pwrite { offset: usize, bytes: Vec<u8> },
    Readlinkat,
    Close(i32, FdKind),
    WriteStdout,
    Exit,
}

pub(crate) fn run_linux_fs_slice() -> RuntimeFsSliceReceipt {
    run_filesystem_lifecycle_companion();
    #[cfg(not(feature = "virtio-cser-facade"))]
    assert_stage5b_fixture_projection();

    let loaded = load_static_image_with_stack_pages(RUNTIME_FS_ELF, EXECUTABLE_NAME, 2);
    let (done_waiter, done_waker) = EffectWaiter::new_pair(EffectToken {
        authority_epoch: AUTHORITY_EPOCH,
        scope_id: SCOPE.id(),
        effect_id: SCENARIO_DONE_EFFECT,
    });
    let scenario = Arc::new(FsScenario {
        vm_space: loaded.vm_space.clone(),
        state: SpinLock::new(FsState::new()),
        #[cfg(feature = "virtio-cser-facade")]
        production: SpinLock::new(ProductionReadRuntime::new()),
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
            .expect("build retained runtime-fs task"),
    );

    #[cfg(not(feature = "virtio-cser-facade"))]
    println!(
        "LINUX_FS_SLICE BEGIN workload=linux-runtime-fs-smoke format=ELF64 type=ET_EXEC retained=true adapted=false syscalls=14 registry=production_shared root_scope=95 domains=3 typed_credit_classes=7 filesystem=bounded_in_memory pager=bounded block=deterministic_preparation smp=1"
    );
    #[cfg(not(feature = "virtio-cser-facade"))]
    println!(
        "LINUX_FS_ARTIFACT source_sha256={} elf_sha256={} first_pread_input_sha256={} first_pread_payload_sha256={} block_preparation_sha256={} sector_sha256={} full_image_sha256={} sector_fnv1a={:#018x} relation=component_consistency real_stage5b_required=true same_boot=false identity_preserving_stage5b=false",
        EXPECTED_SOURCE_SHA256,
        EXPECTED_ELF_SHA256,
        FIRST_PREAD_INPUT_SHA256,
        FIRST_PREAD_PAYLOAD_SHA256,
        BLOCK_PREPARATION_SHA256,
        STAGE5B_SECTOR_SHA256,
        STAGE5B_IMAGE_SHA256,
        STAGE5B_SECTOR_FNV1A,
    );
    #[cfg(feature = "virtio-cser-facade")]
    println!(
        "LINUX_FS_SLICE BEGIN workload=linux-runtime-fs-smoke format=ELF64 type=ET_EXEC retained=true adapted=false syscalls=14 registry=request_local_production root_scope=95 domains=3 typed_credit_classes=6 filesystem=bounded_in_memory pager=bounded block=virtio_blk polling=true irq=false smp=1"
    );
    #[cfg(feature = "virtio-cser-facade")]
    println!(
        "LINUX_FS_ARTIFACT source_sha256={} elf_sha256={} sector_sha256={} full_image_sha256={} sector_fnv1a={:#018x} relation=same_boot identity_preserving=true real_dma=true polling=true irq=false smp=1",
        EXPECTED_SOURCE_SHA256,
        EXPECTED_ELF_SHA256,
        SAME_BOOT_SECTOR_SHA256,
        SAME_BOOT_IMAGE_SHA256,
        SAME_BOOT_SECTOR_FNV1A,
    );
    task.run();
    done_waiter.wait();
    scenario.state.lock().assert_final();
    #[cfg(feature = "virtio-cser-facade")]
    scenario.production.lock().assert_complete();
    #[cfg(not(feature = "virtio-cser-facade"))]
    let production_effects = 16;
    #[cfg(feature = "virtio-cser-facade")]
    let production_effects = 6;
    RuntimeFsSliceReceipt {
        scope: SCOPE,
        closed_authority_epoch: AUTHORITY_EPOCH,
        final_authority_epoch: AUTHORITY_EPOCH + 1,
        terminalizations: 14,
        publication_acks: 14,
        production_effects,
        production_domains: 3,
        preparation_identity_observed: true,
        quiescent: true,
        source_sha256: EXPECTED_SOURCE_SHA256,
        elf_sha256: EXPECTED_ELF_SHA256,
    }
}

fn run_guest(scenario: Arc<FsScenario>, vm_space: Arc<VmSpace>, entry: usize, stack: usize) {
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
                    scenario.finish();
                    return;
                }
            }
            ReturnReason::UserException => {
                let exception = user_mode.context_mut().take_exception().unwrap();
                match exception {
                    CpuException::PageFault(info) => {
                        panic!("unexpected runtime-fs page fault at {:#x}", info.addr)
                    }
                    other => panic!("unexpected runtime-fs exception {other:?}"),
                }
            }
            ReturnReason::KernelEvent => panic!("runtime-fs does not use synthetic kernel events"),
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

fn read_guest_bytes(vm_space: &VmSpace, address: usize, length: usize) -> Vec<u8> {
    let mut output = vec![0; length];
    let mut source = vm_space.reader(address, length).expect("guest read range");
    let mut destination = VmWriter::from(output.as_mut_slice());
    let copied = source
        .read_fallible(&mut destination)
        .expect("copy bytes from runtime-fs guest");
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
        .expect("copy bytes to runtime-fs guest");
    assert_eq!(copied, bytes.len());
}

fn read_c_string(vm_space: &VmSpace, address: usize, max: usize) -> Vec<u8> {
    let bytes = read_guest_bytes(vm_space, address, max);
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .expect("bounded runtime-fs string is NUL terminated");
    bytes[..end].to_vec()
}

fn lifecycle_registry(scope: ScopeKey) -> EffectRegistry {
    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: scope,
            authority_epoch: 201,
            binding_epoch: 1,
            supervisor: LIFECYCLE_V1,
            credits: vec![CreditLimit::new(LIFECYCLE_CREDIT, 1)],
        })
        .unwrap();
    registry
}

fn lifecycle_register(
    registry: &mut EffectRegistry,
    scope: ScopeKey,
    operation: OperationClass,
    syscall: usize,
) -> RegisteredEffect {
    registry
        .register(RegisterRequest {
            scope,
            task: LIFECYCLE_GUEST,
            operation,
            descriptor: SyscallDescriptor::new(syscall, [3, 0x2000, 2, 2, 0, 0]),
            resources: vec![LIFECYCLE_RESOURCE],
            credits: vec![CreditCharge::new(LIFECYCLE_CREDIT, 1)],
            publication: PublicationMode::Required,
        })
        .unwrap()
}

fn close_lifecycle_scope(registry: &mut EffectRegistry, scope: ScopeKey) {
    let selection = registry.revoke_begin(scope).unwrap();
    while let Some(effect) = registry.revoke_next(&selection).unwrap() {
        let request = match effect.disposition {
            RevokeDisposition::Abort => TerminalRequest::aborted(-125),
            RevokeDisposition::Drain(receipt) => {
                TerminalRequest::completed_by(receipt.result(), receipt)
            }
        };
        let terminal = registry
            .stage_revoke_terminal(&selection, effect.effect, request)
            .unwrap();
        if let Some(ticket) = terminal.publication {
            registry.acknowledge_publication(&ticket).unwrap();
        }
    }
    registry.revoke_complete(&selection).unwrap();
    registry.check_invariants().unwrap();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleDomain {
    Personality,
    Pager,
    Filesystem,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifecycleDomainSlot {
    binding_epoch: u64,
    service_bound: bool,
    fallback_running: bool,
    snapshot_revision: Option<u64>,
    replacement_ready: bool,
    revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifecycleRecoverySnapshot {
    domain: LifecycleDomain,
    binding_epoch: u64,
    domain_revision: u64,
    object_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifecycleDomainToken {
    authority_epoch: u64,
    domain: LifecycleDomain,
    binding_epoch: u64,
    object_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleDomainError {
    StaleAuthority,
    StaleBinding,
    StaleGeneration,
    InvalidState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifecycleDomainsProjection {
    authority_epoch: u64,
    personality: LifecycleDomainSlot,
    pager: LifecycleDomainSlot,
    filesystem: LifecycleDomainSlot,
    address_space_generation: u64,
    inode_generation: u64,
    inode: [u8; 4],
    mapping_publications: u64,
    pwrite_publications: u64,
    reply_publications: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifecycleDomains {
    authority_epoch: u64,
    personality: LifecycleDomainSlot,
    pager: LifecycleDomainSlot,
    filesystem: LifecycleDomainSlot,
    address_space_generation: u64,
    inode_generation: u64,
    inode: [u8; 4],
    mapping_publications: u64,
    pwrite_publications: u64,
    reply_publications: u64,
}

impl LifecycleDomains {
    fn new() -> Self {
        Self {
            authority_epoch: 201,
            personality: LifecycleDomainSlot {
                binding_epoch: 1,
                service_bound: true,
                fallback_running: false,
                snapshot_revision: None,
                replacement_ready: false,
                revision: 0,
            },
            pager: LifecycleDomainSlot {
                binding_epoch: 7,
                service_bound: true,
                fallback_running: false,
                snapshot_revision: None,
                replacement_ready: false,
                revision: 0,
            },
            filesystem: LifecycleDomainSlot {
                binding_epoch: 1,
                service_bound: true,
                fallback_running: false,
                snapshot_revision: None,
                replacement_ready: false,
                revision: 0,
            },
            address_space_generation: 1,
            inode_generation: 1,
            inode: [0; 4],
            mapping_publications: 0,
            pwrite_publications: 0,
            reply_publications: 0,
        }
    }

    fn projection(self) -> LifecycleDomainsProjection {
        LifecycleDomainsProjection {
            authority_epoch: self.authority_epoch,
            personality: self.personality,
            pager: self.pager,
            filesystem: self.filesystem,
            address_space_generation: self.address_space_generation,
            inode_generation: self.inode_generation,
            inode: self.inode,
            mapping_publications: self.mapping_publications,
            pwrite_publications: self.pwrite_publications,
            reply_publications: self.reply_publications,
        }
    }

    fn slot(self, domain: LifecycleDomain) -> LifecycleDomainSlot {
        match domain {
            LifecycleDomain::Personality => self.personality,
            LifecycleDomain::Pager => self.pager,
            LifecycleDomain::Filesystem => self.filesystem,
        }
    }

    fn slot_mut(&mut self, domain: LifecycleDomain) -> &mut LifecycleDomainSlot {
        match domain {
            LifecycleDomain::Personality => &mut self.personality,
            LifecycleDomain::Pager => &mut self.pager,
            LifecycleDomain::Filesystem => &mut self.filesystem,
        }
    }

    fn token(self, domain: LifecycleDomain) -> LifecycleDomainToken {
        let object_generation = match domain {
            LifecycleDomain::Personality => 1,
            LifecycleDomain::Pager => self.address_space_generation,
            LifecycleDomain::Filesystem => self.inode_generation,
        };
        LifecycleDomainToken {
            authority_epoch: self.authority_epoch,
            domain,
            binding_epoch: self.slot(domain).binding_epoch,
            object_generation,
        }
    }

    fn crash(&mut self, domain: LifecycleDomain) {
        let slot = self.slot_mut(domain);
        assert!(slot.service_bound);
        assert!(!slot.fallback_running);
        slot.binding_epoch += 1;
        slot.service_bound = false;
        slot.fallback_running = true;
        slot.snapshot_revision = None;
        slot.replacement_ready = false;
        slot.revision += 1;
    }

    fn recovery_snapshot(&mut self, domain: LifecycleDomain) -> LifecycleRecoverySnapshot {
        let object_generation = match domain {
            LifecycleDomain::Personality => 1,
            LifecycleDomain::Pager => self.address_space_generation,
            LifecycleDomain::Filesystem => self.inode_generation,
        };
        let slot = self.slot_mut(domain);
        assert!(!slot.service_bound);
        assert!(slot.fallback_running);
        assert!(!slot.replacement_ready);
        slot.snapshot_revision = Some(slot.revision);
        LifecycleRecoverySnapshot {
            domain,
            binding_epoch: slot.binding_epoch,
            domain_revision: slot.revision,
            object_generation,
        }
    }

    fn ready(&mut self, snapshot: LifecycleRecoverySnapshot) {
        let current_generation = match snapshot.domain {
            LifecycleDomain::Personality => 1,
            LifecycleDomain::Pager => self.address_space_generation,
            LifecycleDomain::Filesystem => self.inode_generation,
        };
        let slot = self.slot_mut(snapshot.domain);
        assert!(!slot.service_bound);
        assert!(slot.fallback_running);
        assert_eq!(snapshot.binding_epoch, slot.binding_epoch);
        assert_eq!(snapshot.domain_revision, slot.revision);
        assert_eq!(snapshot.object_generation, current_generation);
        assert_eq!(slot.snapshot_revision, Some(snapshot.domain_revision));
        slot.replacement_ready = true;
    }

    fn rebind(&mut self, domain: LifecycleDomain) {
        let slot = self.slot_mut(domain);
        assert!(!slot.service_bound);
        assert!(slot.fallback_running);
        assert!(slot.replacement_ready);
        assert_eq!(slot.snapshot_revision, Some(slot.revision));
        slot.service_bound = true;
        slot.fallback_running = false;
        slot.snapshot_revision = None;
        slot.replacement_ready = false;
        slot.revision += 1;
    }

    fn adopt(
        self,
        token: LifecycleDomainToken,
    ) -> Result<LifecycleDomainToken, LifecycleDomainError> {
        if token.authority_epoch != self.authority_epoch {
            return Err(LifecycleDomainError::StaleAuthority);
        }
        let slot = self.slot(token.domain);
        if !slot.service_bound || slot.fallback_running {
            return Err(LifecycleDomainError::InvalidState);
        }
        if token.binding_epoch >= slot.binding_epoch {
            return Err(LifecycleDomainError::InvalidState);
        }
        Ok(LifecycleDomainToken {
            binding_epoch: slot.binding_epoch,
            ..token
        })
    }

    fn validate(self, token: LifecycleDomainToken) -> Result<(), LifecycleDomainError> {
        if token.authority_epoch != self.authority_epoch {
            return Err(LifecycleDomainError::StaleAuthority);
        }
        let slot = self.slot(token.domain);
        if token.binding_epoch != slot.binding_epoch {
            return Err(LifecycleDomainError::StaleBinding);
        }
        if !slot.service_bound || slot.fallback_running {
            return Err(LifecycleDomainError::InvalidState);
        }
        let current_generation = match token.domain {
            LifecycleDomain::Personality => 1,
            LifecycleDomain::Pager => self.address_space_generation,
            LifecycleDomain::Filesystem => self.inode_generation,
        };
        if token.object_generation != current_generation {
            return Err(LifecycleDomainError::StaleGeneration);
        }
        Ok(())
    }

    fn commit_pager_map(
        &mut self,
        token: LifecycleDomainToken,
    ) -> Result<(), LifecycleDomainError> {
        if token.domain != LifecycleDomain::Pager {
            return Err(LifecycleDomainError::InvalidState);
        }
        self.validate(token)?;
        self.address_space_generation += 1;
        self.mapping_publications += 1;
        self.pager.revision += 1;
        Ok(())
    }

    fn complete_pread(&mut self, token: LifecycleDomainToken) -> Result<(), LifecycleDomainError> {
        if token.domain != LifecycleDomain::Filesystem {
            return Err(LifecycleDomainError::InvalidState);
        }
        self.validate(token)?;
        self.filesystem.revision += 1;
        Ok(())
    }

    fn commit_pwrite(&mut self, token: LifecycleDomainToken) -> Result<(), LifecycleDomainError> {
        if token.domain != LifecycleDomain::Filesystem {
            return Err(LifecycleDomainError::InvalidState);
        }
        self.validate(token)?;
        self.inode = [0, 0, b'x', b'y'];
        self.inode_generation += 1;
        self.pwrite_publications += 1;
        self.filesystem.revision += 1;
        Ok(())
    }

    fn publish_reply(&mut self, token: LifecycleDomainToken) -> Result<(), LifecycleDomainError> {
        if token.domain != LifecycleDomain::Personality {
            return Err(LifecycleDomainError::InvalidState);
        }
        self.validate(token)?;
        self.reply_publications += 1;
        self.personality.revision += 1;
        Ok(())
    }

    fn publish_kernel_reply(&mut self) {
        assert!(!self.personality.service_bound);
        assert!(self.personality.fallback_running);
        self.reply_publications += 1;
        self.personality.revision += 1;
        self.personality.snapshot_revision = None;
        self.personality.replacement_ready = false;
    }

    fn revoke_begin(&mut self) {
        self.authority_epoch += 1;
    }
}

fn run_filesystem_lifecycle_companion() {
    println!(
        "FILESYSTEM_LIFECYCLE BEGIN authority_epoch=201 personality_binding=1 pager_binding=7 filesystem_binding=1 block_binding=3 device_generation=3 epochs_independent=true bounded=true real_dma=false"
    );

    let mut domains = LifecycleDomains::new();
    let pager_token = domains.token(LifecycleDomain::Pager);
    let personality_before = domains.personality;
    let filesystem_before = domains.filesystem;
    domains.crash(LifecycleDomain::Pager);
    assert_eq!(domains.personality, personality_before);
    assert_eq!(domains.filesystem, filesystem_before);
    let before_stale = domains.projection();
    assert_eq!(
        domains.commit_pager_map(pager_token),
        Err(LifecycleDomainError::StaleBinding)
    );
    assert_eq!(domains.projection(), before_stale);
    let pager_snapshot = domains.recovery_snapshot(LifecycleDomain::Pager);
    domains.ready(pager_snapshot);
    domains.rebind(LifecycleDomain::Pager);
    let pager_token = domains.adopt(pager_token).unwrap();
    domains.commit_pager_map(pager_token).unwrap();
    assert_eq!(domains.address_space_generation, 2);
    assert_eq!(domains.mapping_publications, 1);
    println!(
        "FILESYSTEM_LIFECYCLE PagerCrash old_binding=7 new_binding=8 snapshot=true ready=true adopted=true mapping_publications=1 address_space_generation=1->2 peer_epochs_unchanged=true stale_old_token=StaleBinding full_projection_unchanged=true"
    );

    // Crash before commit: the replacement adopts the exact prepared effect.
    let filesystem_token = domains.token(LifecycleDomain::Filesystem);
    let personality_before = domains.personality;
    let pager_before = domains.pager;
    let mut precommit = lifecycle_registry(LIFECYCLE_PRECOMMIT_SCOPE);
    let registered = lifecycle_register(
        &mut precommit,
        LIFECYCLE_PRECOMMIT_SCOPE,
        OP_PREAD,
        __NR_pread64 as usize,
    );
    precommit.prepare(LIFECYCLE_V1, registered.handle).unwrap();
    domains.crash(LifecycleDomain::Filesystem);
    assert_eq!(domains.personality, personality_before);
    assert_eq!(domains.pager, pager_before);
    let crash = precommit
        .crash(LIFECYCLE_PRECOMMIT_SCOPE, LIFECYCLE_V1)
        .unwrap();
    assert_eq!(crash.previous_binding_epoch, 1);
    assert_eq!(crash.binding_epoch, 2);
    let snapshot = precommit
        .recovery_snapshot(LIFECYCLE_PRECOMMIT_SCOPE, LIFECYCLE_V2)
        .unwrap();
    precommit
        .ready(LIFECYCLE_PRECOMMIT_SCOPE, LIFECYCLE_V2, &snapshot)
        .unwrap();
    precommit
        .rebind(LIFECYCLE_PRECOMMIT_SCOPE, LIFECYCLE_V2)
        .unwrap();
    let filesystem_snapshot = domains.recovery_snapshot(LifecycleDomain::Filesystem);
    domains.ready(filesystem_snapshot);
    domains.rebind(LifecycleDomain::Filesystem);
    let adopted = precommit
        .adopt(LIFECYCLE_PRECOMMIT_SCOPE, LIFECYCLE_V2, registered.handle)
        .unwrap();
    let before_stale = precommit
        .scope_projection(LIFECYCLE_PRECOMMIT_SCOPE)
        .unwrap();
    let effect_before_stale = precommit.effect_view(registered.identity.effect()).unwrap();
    let domain_before_stale = domains.projection();
    assert_eq!(
        precommit.prepare(LIFECYCLE_V1, registered.handle),
        Err(RegistryError::StaleBinding)
    );
    assert_eq!(
        precommit
            .scope_projection(LIFECYCLE_PRECOMMIT_SCOPE)
            .unwrap(),
        before_stale
    );
    assert_eq!(
        precommit.effect_view(registered.identity.effect()).unwrap(),
        effect_before_stale
    );
    assert_eq!(
        domains.complete_pread(filesystem_token),
        Err(LifecycleDomainError::StaleBinding)
    );
    assert_eq!(domains.projection(), domain_before_stale);
    let filesystem_token = domains.adopt(filesystem_token).unwrap();
    domains.complete_pread(filesystem_token).unwrap();
    let commit = match precommit
        .commit(LIFECYCLE_V2, adopted, CommitMetadata::new(4, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => panic!("precommit witness replayed"),
    };
    precommit
        .domain_changed(LIFECYCLE_PRECOMMIT_SCOPE, 1)
        .unwrap();
    let terminal = precommit
        .stage_terminal(
            LIFECYCLE_V2,
            adopted,
            TerminalRequest::completed_by(4, commit),
        )
        .unwrap();
    precommit
        .acknowledge_publication(&terminal.publication.unwrap())
        .unwrap();
    close_lifecycle_scope(&mut precommit, LIFECYCLE_PRECOMMIT_SCOPE);
    println!(
        "FILESYSTEM_LIFECYCLE PrecommitCrash domain=filesystem effect=1 old_binding=1 new_binding=2 snapshot=true ready=true adopted=true peer_epochs_unchanged=true stale_old_handle=StaleBinding registry_and_domain_projection_unchanged=true result=4 quiescent=true"
    );

    // Crash after commit: the immutable commit receipt lets the kernel finish
    // while no personality service is bound, fencing the late v1 reply.
    let personality_token = domains.token(LifecycleDomain::Personality);
    let pager_before = domains.pager;
    let filesystem_before = domains.filesystem;
    let mut postcommit = lifecycle_registry(LIFECYCLE_POSTCOMMIT_SCOPE);
    let registered = lifecycle_register(
        &mut postcommit,
        LIFECYCLE_POSTCOMMIT_SCOPE,
        OP_PREAD,
        __NR_pread64 as usize,
    );
    postcommit.prepare(LIFECYCLE_V1, registered.handle).unwrap();
    let commit = match postcommit
        .commit(LIFECYCLE_V1, registered.handle, CommitMetadata::new(4, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => panic!("postcommit witness replayed"),
    };
    postcommit
        .domain_changed(LIFECYCLE_POSTCOMMIT_SCOPE, 1)
        .unwrap();
    postcommit
        .crash(LIFECYCLE_POSTCOMMIT_SCOPE, LIFECYCLE_V1)
        .unwrap();
    domains.crash(LifecycleDomain::Personality);
    assert_eq!(domains.pager, pager_before);
    assert_eq!(domains.filesystem, filesystem_before);
    let terminal = postcommit.stage_kernel_completion(&commit).unwrap();
    postcommit
        .acknowledge_publication(&terminal.publication.unwrap())
        .unwrap();
    domains.publish_kernel_reply();
    let before_stale = postcommit
        .scope_projection(LIFECYCLE_POSTCOMMIT_SCOPE)
        .unwrap();
    let effect_before_stale = postcommit
        .effect_view(registered.identity.effect())
        .unwrap();
    let domain_before_stale = domains.projection();
    assert_eq!(
        postcommit.stage_terminal(
            LIFECYCLE_V1,
            registered.handle,
            TerminalRequest::completed_by(4, commit),
        ),
        Err(RegistryError::StaleBinding)
    );
    assert_eq!(
        postcommit
            .scope_projection(LIFECYCLE_POSTCOMMIT_SCOPE)
            .unwrap(),
        before_stale
    );
    assert_eq!(
        postcommit
            .effect_view(registered.identity.effect())
            .unwrap(),
        effect_before_stale
    );
    assert_eq!(
        domains.publish_reply(personality_token),
        Err(LifecycleDomainError::StaleBinding)
    );
    assert_eq!(domains.projection(), domain_before_stale);
    let personality_snapshot = domains.recovery_snapshot(LifecycleDomain::Personality);
    domains.ready(personality_snapshot);
    domains.rebind(LifecycleDomain::Personality);
    close_lifecycle_scope(&mut postcommit, LIFECYCLE_POSTCOMMIT_SCOPE);
    println!(
        "FILESYSTEM_LIFECYCLE PostcommitCrash domain=personality effect=1 old_binding=1 new_binding=2 commit_sequence=1 kernel_completion=true reply_publications=1 peer_epochs_unchanged=true late_service_rejected=StaleBinding registry_and_domain_projection_unchanged=true duplicate_terminal=false quiescent=true"
    );

    // Commit-first pwrite is drained by revocation from its immutable receipt.
    let mut commit_first_domains = LifecycleDomains::new();
    let commit_first_token = commit_first_domains.token(LifecycleDomain::Filesystem);
    let mut commit_first = lifecycle_registry(LIFECYCLE_COMMIT_FIRST_SCOPE);
    let registered = lifecycle_register(
        &mut commit_first,
        LIFECYCLE_COMMIT_FIRST_SCOPE,
        OP_PWRITE,
        __NR_pwrite64 as usize,
    );
    commit_first
        .prepare(LIFECYCLE_V1, registered.handle)
        .unwrap();
    let committed = match commit_first
        .commit(LIFECYCLE_V1, registered.handle, CommitMetadata::new(2, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => panic!("commit-first witness replayed"),
    };
    commit_first_domains
        .commit_pwrite(commit_first_token)
        .unwrap();
    commit_first
        .domain_changed(LIFECYCLE_COMMIT_FIRST_SCOPE, 1)
        .unwrap();
    assert_eq!(commit_first_domains.inode, [0, 0, b'x', b'y']);
    assert_eq!(commit_first_domains.pwrite_publications, 1);
    let selection = commit_first
        .revoke_begin(LIFECYCLE_COMMIT_FIRST_SCOPE)
        .unwrap();
    commit_first_domains.revoke_begin();
    let before_stale = commit_first
        .scope_projection(LIFECYCLE_COMMIT_FIRST_SCOPE)
        .unwrap();
    let effect_before_stale = commit_first
        .effect_view(registered.identity.effect())
        .unwrap();
    let domain_before_stale = commit_first_domains.projection();
    assert_eq!(
        commit_first.commit(LIFECYCLE_V1, registered.handle, CommitMetadata::new(2, 1),),
        Err(RegistryError::StaleAuthority)
    );
    assert_eq!(
        commit_first
            .scope_projection(LIFECYCLE_COMMIT_FIRST_SCOPE)
            .unwrap(),
        before_stale
    );
    assert_eq!(
        commit_first
            .effect_view(registered.identity.effect())
            .unwrap(),
        effect_before_stale
    );
    assert_eq!(
        commit_first_domains.commit_pwrite(commit_first_token),
        Err(LifecycleDomainError::StaleAuthority)
    );
    assert_eq!(commit_first_domains.projection(), domain_before_stale);
    let effect = commit_first
        .revoke_next(&selection)
        .unwrap()
        .expect("committed pwrite remains in revoke cohort");
    let RevokeDisposition::Drain(receipt) = effect.disposition else {
        panic!("commit-first pwrite must drain")
    };
    assert_eq!(receipt, committed);
    let terminal = commit_first
        .stage_revoke_terminal(
            &selection,
            effect.effect,
            TerminalRequest::completed_by(2, receipt),
        )
        .unwrap();
    commit_first
        .acknowledge_publication(&terminal.publication.unwrap())
        .unwrap();
    assert!(commit_first.revoke_next(&selection).unwrap().is_none());
    commit_first.revoke_complete(&selection).unwrap();
    commit_first.check_invariants().unwrap();
    println!(
        "FILESYSTEM_LIFECYCLE PwriteRace winner=commit commit_sequence=1 revoke_disposition=Drain inode_before=00000000 inode_after=00007879 pwrite_publications=1 stale_commit=StaleAuthority registry_effect_inode_projection_unchanged=true publication_acked=true quiescent=true"
    );

    // Revoke-first pwrite never reaches the filesystem mutation point.
    let mut revoke_first_domains = LifecycleDomains::new();
    let revoke_first_token = revoke_first_domains.token(LifecycleDomain::Filesystem);
    let mut revoke_first = lifecycle_registry(LIFECYCLE_REVOKE_FIRST_SCOPE);
    let registered = lifecycle_register(
        &mut revoke_first,
        LIFECYCLE_REVOKE_FIRST_SCOPE,
        OP_PWRITE,
        __NR_pwrite64 as usize,
    );
    revoke_first
        .prepare(LIFECYCLE_V1, registered.handle)
        .unwrap();
    let selection = revoke_first
        .revoke_begin(LIFECYCLE_REVOKE_FIRST_SCOPE)
        .unwrap();
    revoke_first_domains.revoke_begin();
    let before_stale = revoke_first
        .scope_projection(LIFECYCLE_REVOKE_FIRST_SCOPE)
        .unwrap();
    let effect_before_stale = revoke_first
        .effect_view(registered.identity.effect())
        .unwrap();
    let domain_before_stale = revoke_first_domains.projection();
    assert_eq!(
        revoke_first.commit(LIFECYCLE_V1, registered.handle, CommitMetadata::new(2, 1),),
        Err(RegistryError::StaleAuthority)
    );
    assert_eq!(
        revoke_first
            .scope_projection(LIFECYCLE_REVOKE_FIRST_SCOPE)
            .unwrap(),
        before_stale
    );
    assert_eq!(
        revoke_first
            .effect_view(registered.identity.effect())
            .unwrap(),
        effect_before_stale
    );
    assert_eq!(
        revoke_first_domains.commit_pwrite(revoke_first_token),
        Err(LifecycleDomainError::StaleAuthority)
    );
    assert_eq!(revoke_first_domains.projection(), domain_before_stale);
    assert_eq!(revoke_first_domains.inode, [0; 4]);
    assert_eq!(revoke_first_domains.pwrite_publications, 0);
    let effect = revoke_first
        .revoke_next(&selection)
        .unwrap()
        .expect("prepared pwrite remains in revoke cohort");
    assert_eq!(effect.disposition, RevokeDisposition::Abort);
    let terminal = revoke_first
        .stage_revoke_terminal(&selection, effect.effect, TerminalRequest::aborted(-125))
        .unwrap();
    revoke_first
        .acknowledge_publication(&terminal.publication.unwrap())
        .unwrap();
    assert!(revoke_first.revoke_next(&selection).unwrap().is_none());
    revoke_first.revoke_complete(&selection).unwrap();
    revoke_first.check_invariants().unwrap();
    println!(
        "FILESYSTEM_LIFECYCLE PwriteRace winner=revoke revoke_disposition=Abort inode_before=00000000 inode_after=00000000 pwrite_publications=0 stale_commit=StaleAuthority registry_effect_inode_projection_unchanged=true publication_acked=true quiescent=true"
    );

    let mut block = BlockLifecycle::new();
    let token = block.submit();
    let reset_tombstone = block.timeout_reset(token).unwrap();
    assert_eq!(block.owners, 3);
    assert!(block.tombstone.is_some());
    let before_stale = block.projection();
    assert_eq!(block.complete(token), Err(BlockError::StaleToken));
    assert_eq!(block.projection(), before_stale);
    assert_eq!(block.device_generation, 3);
    println!(
        "FILESYSTEM_LIFECYCLE ResetTimeout old_binding=3 new_binding=4 device_generation=3 unchanged_until_reset_ack=true tombstone=1 owners_retained=3 stale_completion=StaleToken full_projection_unchanged=true real_dma=false"
    );
    block.retry_reset_ack(reset_tombstone).unwrap();
    assert_eq!(block.device_generation, 4);
    assert_eq!(block.owners, 3);
    println!(
        "FILESYSTEM_LIFECYCLE ResetAck tombstone=1 device_generation=3->4 reset_ack=true owners_retained=3 iotlb_required=true"
    );
    block.begin_iotlb().unwrap();
    let iotlb_tombstone = block.timeout_iotlb().unwrap();
    assert_eq!(block.owners, 3);
    let before_stale = block.projection();
    assert_eq!(
        block.retry_reset_ack(reset_tombstone),
        Err(BlockError::StaleTombstone)
    );
    assert_eq!(block.projection(), before_stale);
    println!(
        "FILESYSTEM_LIFECYCLE IotlbTimeout binding=4 device_generation=4 tombstone=2 owners_retained=3 stale_reset_tombstone=StaleTombstone full_projection_unchanged=true real_dma=false"
    );
    block.retry_iotlb_ack(iotlb_tombstone).unwrap();
    assert_eq!(block.owners, 0);
    assert!(block.tombstone.is_none());
    assert_eq!(block.phase, BlockPhase::Released);
    assert!(block.reset_ack);
    assert!(block.iotlb_ack);
    assert_eq!(block.binding_epoch, 4);
    assert_eq!(block.device_generation, 4);
    assert_eq!(block.next_tombstone, 3);
    println!(
        "FILESYSTEM_LIFECYCLE IotlbAck tombstone=2 binding=4 device_generation=4 iotlb_ack=true owners_released=3 phase=Released"
    );
    assert_eq!(domains.mapping_publications, 1);
    assert_eq!(domains.reply_publications, 1);
    assert_eq!(domains.pager.binding_epoch, 8);
    assert_eq!(domains.filesystem.binding_epoch, 2);
    assert_eq!(domains.personality.binding_epoch, 2);
    println!(
        "FILESYSTEM_LIFECYCLE PASS pager_crash_adopt=true precommit_adopt=true postcommit_fence=true pwrite_commit_first=true pwrite_revoke_first=true reset_timeout_tombstone=true iotlb_timeout_tombstone=true device_generation_after_reset_ack=true owners_retained_until_iotlb_ack=true stale_token_full_projection_unchanged=true personality_epoch_independent=true pager_epoch_independent=true filesystem_epoch_independent=true block_epoch_independent=true quiescent=true bounded=true real_dma=false"
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockToken {
    binding_epoch: u64,
    device_generation: u64,
    request: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockTombstone {
    id: u64,
    kind: BlockRecoveryKind,
    token: BlockToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockRecoveryKind {
    Reset,
    Iotlb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockPhase {
    Idle,
    Submitted,
    ResetTimedOut,
    ResetAcked,
    IotlbInFlight,
    IotlbTimedOut,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockProjection {
    binding_epoch: u64,
    device_generation: u64,
    owners: usize,
    tombstone: Option<BlockTombstone>,
    phase: BlockPhase,
    reset_ack: bool,
    iotlb_ack: bool,
    next_tombstone: u64,
    revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockError {
    StaleToken,
    StaleTombstone,
    InvalidState,
}

struct BlockLifecycle {
    binding_epoch: u64,
    device_generation: u64,
    owners: usize,
    tombstone: Option<BlockTombstone>,
    phase: BlockPhase,
    reset_ack: bool,
    iotlb_ack: bool,
    next_tombstone: u64,
    revision: u64,
}

impl BlockLifecycle {
    fn new() -> Self {
        Self {
            binding_epoch: 3,
            device_generation: 3,
            owners: 0,
            tombstone: None,
            phase: BlockPhase::Idle,
            reset_ack: false,
            iotlb_ack: false,
            next_tombstone: 1,
            revision: 0,
        }
    }

    fn projection(&self) -> BlockProjection {
        BlockProjection {
            binding_epoch: self.binding_epoch,
            device_generation: self.device_generation,
            owners: self.owners,
            tombstone: self.tombstone,
            phase: self.phase,
            reset_ack: self.reset_ack,
            iotlb_ack: self.iotlb_ack,
            next_tombstone: self.next_tombstone,
            revision: self.revision,
        }
    }

    fn submit(&mut self) -> BlockToken {
        assert_eq!(self.owners, 0);
        assert_eq!(self.phase, BlockPhase::Idle);
        self.owners = 3;
        self.phase = BlockPhase::Submitted;
        self.revision += 1;
        BlockToken {
            binding_epoch: self.binding_epoch,
            device_generation: self.device_generation,
            request: 1,
        }
    }

    fn timeout_reset(&mut self, token: BlockToken) -> Result<BlockTombstone, BlockError> {
        if token.binding_epoch != self.binding_epoch
            || token.device_generation != self.device_generation
        {
            return Err(BlockError::StaleToken);
        }
        if self.phase != BlockPhase::Submitted || self.owners != 3 || self.tombstone.is_some() {
            return Err(BlockError::InvalidState);
        }
        self.binding_epoch += 1;
        let tombstone = BlockTombstone {
            id: self.next_tombstone,
            kind: BlockRecoveryKind::Reset,
            token,
        };
        self.next_tombstone += 1;
        self.tombstone = Some(tombstone);
        self.phase = BlockPhase::ResetTimedOut;
        self.revision += 1;
        Ok(tombstone)
    }

    fn complete(&mut self, token: BlockToken) -> Result<(), BlockError> {
        if token.binding_epoch != self.binding_epoch
            || token.device_generation != self.device_generation
        {
            return Err(BlockError::StaleToken);
        }
        Err(BlockError::InvalidState)
    }

    fn retry_reset_ack(&mut self, tombstone: BlockTombstone) -> Result<(), BlockError> {
        if self.tombstone != Some(tombstone) || tombstone.kind != BlockRecoveryKind::Reset {
            return Err(BlockError::StaleTombstone);
        }
        if self.phase != BlockPhase::ResetTimedOut || self.owners != 3 {
            return Err(BlockError::InvalidState);
        }
        self.tombstone = None;
        self.reset_ack = true;
        self.device_generation += 1;
        self.phase = BlockPhase::ResetAcked;
        self.revision += 1;
        Ok(())
    }

    fn begin_iotlb(&mut self) -> Result<(), BlockError> {
        if self.phase != BlockPhase::ResetAcked
            || !self.reset_ack
            || self.owners != 3
            || self.tombstone.is_some()
        {
            return Err(BlockError::InvalidState);
        }
        self.phase = BlockPhase::IotlbInFlight;
        self.revision += 1;
        Ok(())
    }

    fn timeout_iotlb(&mut self) -> Result<BlockTombstone, BlockError> {
        if self.phase != BlockPhase::IotlbInFlight || self.owners != 3 || self.tombstone.is_some() {
            return Err(BlockError::InvalidState);
        }
        let tombstone = BlockTombstone {
            id: self.next_tombstone,
            kind: BlockRecoveryKind::Iotlb,
            token: BlockToken {
                binding_epoch: self.binding_epoch,
                device_generation: self.device_generation,
                request: 1,
            },
        };
        self.next_tombstone += 1;
        self.tombstone = Some(tombstone);
        self.phase = BlockPhase::IotlbTimedOut;
        self.revision += 1;
        Ok(tombstone)
    }

    fn retry_iotlb_ack(&mut self, tombstone: BlockTombstone) -> Result<(), BlockError> {
        if self.tombstone != Some(tombstone) || tombstone.kind != BlockRecoveryKind::Iotlb {
            return Err(BlockError::StaleTombstone);
        }
        if self.phase != BlockPhase::IotlbTimedOut || self.owners != 3 || !self.reset_ack {
            return Err(BlockError::InvalidState);
        }
        self.tombstone = None;
        self.iotlb_ack = true;
        self.owners = 0;
        self.phase = BlockPhase::Released;
        self.revision += 1;
        Ok(())
    }
}

#[cfg(not(feature = "virtio-cser-facade"))]
fn assert_stage5b_fixture_projection() {
    let mut sector = [0_u8; 512];
    sector[..STAGE5B_SECTOR_MAGIC.len()].copy_from_slice(STAGE5B_SECTOR_MAGIC);
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in sector {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    assert_eq!(hash, STAGE5B_SECTOR_FNV1A);
}
