// SPDX-License-Identifier: MPL-2.0

//! Bounded runtime-filesystem successor for the retained Stage 6 core input.
//!
//! The unchanged guest executes as a real ELF in OSTD `UserMode`.  Linux path,
//! fd, stat, procfs, and offset-I/O policy remains a deliberately tiny
//! in-memory personality service. In the feature-free predecessor, one
//! workload-owned root retains the first executable `pread64` through a
//! preparation-only in-memory block boundary; independent Stage 5B evidence is
//! only component-consistent with that path. With `virtio-cser-facade`, the
//! same real syscall instead enters the workload's shared production Registry
//! under one root spanning `FilesystemSyscall -> FilesystemRead -> BlockRequest
//! -> three DMA owners`. That successor publishes a real same-boot VirtIO/IOMMU
//! request, polls it outside the OSTD lock, couples reset and IOTLB receipts to
//! the Registry, and sources the guest reply only from the completed device
//! buffer.

use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::fmt;

#[cfg(feature = "virtio-cser-facade")]
use core::{hint::spin_loop, num::NonZeroU64};

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

#[cfg(feature = "virtio-cser-facade")]
use ostd::{
    mm::{
        PageFlags, UFrame,
        io::util::HasVmReaderWriter,
        vm_space::{Cursor, VmQueriedItem},
    },
    task::disable_preempt,
};

use crate::{
    TaskData,
    effect::{EffectToken, EffectWaiter, EffectWaker},
    effect_registry::{
        CommitMetadata, CreditCharge, CreditClass, CreditLimit, DerivedRegisterRequest,
        DomainConfig, DomainKey, EffectRegistry, OperationClass, PublicationMode,
        PublicationTicket, RegisterRequest, RegisteredEffect, RegistryError, ResourceKey,
        RevokeDisposition, ScopeConfig, ScopeKey, ScopePhase, SyscallDescriptor, TaskKey,
        TerminalRequest,
    },
    linux_loader::load_static_image_with_stack_pages,
};

#[cfg(feature = "virtio-cser-facade")]
use crate::device_flight::{
    PrecommitCloseSemantic, PublishedSemantic, RetainedSemantic,
    close_enrolled_device_flight_precommit_with_apply,
};

#[cfg(all(
    feature = "virtio-cser-facade",
    not(feature = "virtio-cser-precommit-fault")
))]
use crate::device_flight::{
    DeviceFlightCloseOutcome, RetainReason, commit_or_recover_device_flight_with_apply,
    mint_device_flight_key,
};

#[cfg(not(feature = "virtio-cser-facade"))]
use crate::effect_registry::{CommitOutcome, CommitReceipt, PortalHandle};

#[cfg(feature = "virtio-cser-facade")]
use crate::effect_registry::{
    DeviceBatchEnrollmentReceipt, DeviceClosureReceipt, DeviceClosureResult, DeviceCohortParent,
    DeviceDerivedCohortEntry, DeviceEnvelope, DeviceIotlbTicket, DeviceIotlbTombstone,
    DeviceResetReceipt, DeviceResetTicket, DeviceResetTombstone, EffectKey, RevokeSelection,
};
#[cfg(feature = "virtio-cser-facade")]
use nexus_ostd_virtio::{
    CompletedRequest, CompletionProbeProgress, DeviceSessionIdentity, FailedCompletion, OwnerKind,
    PreparedCancelIntent, PreparedPublishedResetIntent, PreparedRequest,
    PreparedRequestResetIntent, ProductionClosureProgress, ProductionClosureReceipt,
    ProductionDevice, ProductionIotlbTombstone, ProductionResetAck, ProductionResetTombstone,
    PublishedRequest, Root, UnregisteredPreparedCancellation, discover_and_own_bars, owner_address,
};

#[cfg(all(
    feature = "virtio-cser-facade",
    not(feature = "virtio-cser-precommit-fault")
))]
use nexus_ostd_virtio::NotificationDisposition;

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
#[cfg(not(feature = "virtio-cser-facade"))]
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
#[cfg(feature = "virtio-cser-facade")]
const SAME_BOOT_COMPLETION_PROBE_LIMIT: usize = 10_000_000;
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
    #[cfg(feature = "virtio-cser-precommit-fault")]
    pub(crate) enrolled_revoke_wins_observed: bool,
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
    #[cfg(not(feature = "virtio-cser-facade"))]
    effects: EffectRegistry,
    fds: BTreeMap<i32, FdKind>,
    temporary: Vec<u8>,
    next_fd: i32,
    #[cfg(not(feature = "virtio-cser-facade"))]
    domain_revision: u64,
    #[cfg(not(feature = "virtio-cser-facade"))]
    syscall_terminalizations: usize,
    #[cfg(feature = "virtio-cser-facade")]
    compatibility_syscalls: usize,
    production_effects: usize,
    production_read_observed: bool,
    stdout_publications: usize,
    exited: bool,
}

#[cfg(feature = "virtio-cser-facade")]
struct FsClosureWork {
    effects: [EffectKey; 6],
    envelope: DeviceEnvelope,
    guest_address: usize,
    result: i64,
    bytes: [u8; 4],
    byte_count: usize,
    used_len: u32,
    completion_label: &'static str,
}

#[cfg(feature = "virtio-cser-facade")]
enum FsCloseSemantic {
    Published(PublishedSemantic),
    Precommit(PrecommitCloseSemantic),
}

#[cfg(feature = "virtio-cser-facade")]
#[allow(dead_code)]
enum FsRetainedSemantic {
    /// An ordinary closure-stage failure after the Registry issued semantic
    /// ownership for this flight.
    Close(FsCloseSemantic),
    /// A returned device-close error which the Registry classified as already
    /// or possibly published. This retains the exact root-local obligation.
    PublishedObligation(RetainedSemantic),
}

#[cfg(feature = "virtio-cser-facade")]
#[allow(dead_code)]
impl FsRetainedSemantic {
    fn cookie(&self) -> u64 {
        match self {
            Self::Close(semantic) => semantic.cookie(),
            Self::PublishedObligation(semantic) => semantic.cookie(),
        }
    }
}

#[cfg(feature = "virtio-cser-facade")]
impl FsCloseSemantic {
    fn cookie(&self) -> u64 {
        match self {
            Self::Published(published) => published.key().cookie(),
            Self::Precommit(precommit) => precommit.cookie(),
        }
    }

    fn selection(&self) -> &RevokeSelection {
        match self {
            Self::Published(published) => published.selection(),
            Self::Precommit(precommit) => precommit.selection(),
        }
    }
}

#[cfg(feature = "virtio-cser-facade")]
#[allow(dead_code)]
enum FsRetainedHardware {
    Quarantined {
        root: Root,
        device: ProductionDevice,
    },
    Ready {
        root: Root,
        device: ProductionDevice,
    },
    Prepared {
        root: Root,
        device: ProductionDevice,
        request: PreparedRequest,
    },
    PreparedCancel {
        root: Root,
        device: ProductionDevice,
        intent: PreparedCancelIntent,
    },
    Published {
        root: Root,
        device: ProductionDevice,
        request: PublishedRequest,
    },
    PublishedReset {
        root: Root,
        device: ProductionDevice,
        intent: PreparedPublishedResetIntent,
    },
    CompletionReset {
        root: Root,
        device: ProductionDevice,
        intent: PreparedRequestResetIntent,
    },
    Completed {
        root: Root,
        device: ProductionDevice,
        request: CompletedRequest,
    },
    Failed {
        root: Root,
        device: ProductionDevice,
        request: FailedCompletion,
    },
    Reset {
        root: Root,
        device: ProductionDevice,
        tombstone: ProductionResetTombstone,
    },
    ResetAck {
        root: Root,
        device: ProductionDevice,
        reset: ProductionResetAck,
    },
    Iotlb {
        root: Root,
        device: ProductionDevice,
        tombstone: ProductionIotlbTombstone,
    },
    Closure {
        root: Root,
        device: ProductionDevice,
        closure: ProductionClosureReceipt,
    },
    UnregisteredReset {
        root: Root,
        device: ProductionDevice,
        reset: ProductionResetAck,
        cancellation: UnregisteredPreparedCancellation,
    },
}

#[cfg(feature = "virtio-cser-facade")]
#[allow(dead_code)]
enum FsDeviceFlight {
    Ready {
        root: Root,
        device: ProductionDevice,
    },
    Captured {
        cookie: NonZeroU64,
        root: Root,
        device: ProductionDevice,
        syscall: RegisteredEffect,
    },
    Prepared {
        cookie: NonZeroU64,
        root: Root,
        device: ProductionDevice,
        request: PreparedRequest,
        effects: [Option<EffectKey>; 6],
        envelope: Option<DeviceEnvelope>,
        enrollment: Option<DeviceBatchEnrollmentReceipt>,
    },
    /// A prepared descriptor which was moved into its one cancellation intent.
    ///
    /// Keeping this distinct from `Prepared` matters: the intent is a linear
    /// owner, so a flight which has started cancellation can never be treated
    /// as an unpublished request again.
    PreparedCancel {
        cookie: NonZeroU64,
        root: Root,
        device: ProductionDevice,
        intent: PreparedCancelIntent,
        effects: [EffectKey; 6],
        envelope: DeviceEnvelope,
        enrollment: Option<DeviceBatchEnrollmentReceipt>,
    },
    Building {
        cookie: NonZeroU64,
        root: Root,
        device: ProductionDevice,
        request: PreparedRequest,
        effects: [EffectKey; 6],
        envelope: DeviceEnvelope,
        enrollment: DeviceBatchEnrollmentReceipt,
        commits: [(crate::effect_registry::PortalHandle, CommitMetadata); 6],
    },
    Published {
        semantic: PublishedSemantic,
        root: Root,
        device: ProductionDevice,
        request: PublishedRequest,
        work: FsClosureWork,
        completion_probes: usize,
    },
    /// A published request which reached the bounded polling deadline and was
    /// prevalidated for mandatory reset without reconstructing its owner.
    PublishedReset {
        semantic: PublishedSemantic,
        root: Root,
        device: ProductionDevice,
        intent: PreparedPublishedResetIntent,
        work: FsClosureWork,
    },
    /// Completion was observed and prevalidated for reset, but the Registry
    /// transition has not yet consumed the hardware intent.  This makes the
    /// apply boundary explicit and prevents a completed owner being silently
    /// reconstructed from descriptive identity.
    CompletionReset {
        semantic: PublishedSemantic,
        root: Root,
        device: ProductionDevice,
        intent: PreparedRequestResetIntent,
        work: FsClosureWork,
    },
    /// Completion validation failed after publication. The hardware owner is
    /// prevalidated for reset, but no successful completion is recorded in the
    /// Registry; reset acknowledgement will therefore close indeterminate.
    IndeterminateReset {
        semantic: PublishedSemantic,
        root: Root,
        device: ProductionDevice,
        intent: PreparedRequestResetIntent,
        work: FsClosureWork,
    },
    Resetting {
        semantic: FsCloseSemantic,
        root: Root,
        device: ProductionDevice,
        reset_ticket: DeviceResetTicket,
        hardware: ProductionResetTombstone,
        work: FsClosureWork,
        retry: bool,
    },
    ResetRetained {
        semantic: FsCloseSemantic,
        root: Root,
        device: ProductionDevice,
        reset_tombstone: DeviceResetTombstone,
        hardware: ProductionResetTombstone,
        work: FsClosureWork,
    },
    Iotlb {
        semantic: FsCloseSemantic,
        root: Root,
        device: ProductionDevice,
        reset: DeviceResetReceipt,
        iotlb_ticket: DeviceIotlbTicket,
        hardware: ProductionIotlbTombstone,
        work: FsClosureWork,
        timeout_recorded: bool,
    },
    IotlbRetained {
        semantic: FsCloseSemantic,
        root: Root,
        device: ProductionDevice,
        reset: DeviceResetReceipt,
        iotlb_tombstone: DeviceIotlbTombstone,
        hardware: ProductionIotlbTombstone,
        work: FsClosureWork,
    },
    Draining {
        semantic: FsCloseSemantic,
        root: Root,
        device: ProductionDevice,
        closure: DeviceClosureReceipt,
        work: FsClosureWork,
        next_ordinal: usize,
        publication: Option<PublicationTicket>,
    },
    AwaitingPublication {
        cookie: u64,
        root: Root,
        device: ProductionDevice,
        selection: RevokeSelection,
        ticket: PublicationTicket,
        work: FsClosureWork,
    },
    Retained {
        cookie: u64,
        semantic: Option<FsRetainedSemantic>,
        hardware: FsRetainedHardware,
        stage: &'static str,
    },
    Complete {
        root: Root,
        device: ProductionDevice,
    },
    Transitioning,
}

#[cfg(feature = "virtio-cser-facade")]
struct ProductionReadRuntime {
    registry: EffectRegistry,
    flight: FsDeviceFlight,
    next_flight_cookie: NonZeroU64,
    registered_effects: usize,
    preparation_identity_observed: bool,
    #[cfg(feature = "virtio-cser-precommit-fault")]
    enrolled_revoke_wins_observed: bool,
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
            flight: FsDeviceFlight::Ready { root, device },
            next_flight_cookie: NonZeroU64::MIN,
            registered_effects: 0,
            preparation_identity_observed: false,
            #[cfg(feature = "virtio-cser-precommit-fault")]
            enrolled_revoke_wins_observed: false,
        }
    }

    fn allocate_flight_cookie(&mut self) -> Result<NonZeroU64, RegistryError> {
        let cookie = self.next_flight_cookie;
        let next = cookie
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(RegistryError::CounterOverflow)?;
        self.next_flight_cookie = next;
        Ok(cookie)
    }

    fn take_flight(&mut self) -> FsDeviceFlight {
        core::mem::replace(&mut self.flight, FsDeviceFlight::Transitioning)
    }

    fn put_flight(&mut self, flight: FsDeviceFlight) {
        debug_assert!(matches!(self.flight, FsDeviceFlight::Transitioning));
        self.flight = flight;
    }

    fn retain_current(&mut self, stage: &'static str) -> u64 {
        let flight = self.take_flight();
        let (cookie, semantic, hardware) = match flight {
            FsDeviceFlight::Ready { root, device } => {
                (0, None, FsRetainedHardware::Ready { root, device })
            }
            FsDeviceFlight::Captured {
                cookie,
                root,
                device,
                ..
            } => (
                cookie.get(),
                None,
                FsRetainedHardware::Ready { root, device },
            ),
            FsDeviceFlight::Prepared {
                cookie,
                root,
                device,
                request,
                ..
            } => (
                cookie.get(),
                None,
                FsRetainedHardware::Prepared {
                    root,
                    device,
                    request,
                },
            ),
            FsDeviceFlight::PreparedCancel {
                cookie,
                root,
                device,
                intent,
                ..
            } => (
                cookie.get(),
                None,
                FsRetainedHardware::PreparedCancel {
                    root,
                    device,
                    intent,
                },
            ),
            FsDeviceFlight::Building {
                cookie,
                root,
                device,
                request,
                ..
            } => (
                cookie.get(),
                None,
                FsRetainedHardware::Prepared {
                    root,
                    device,
                    request,
                },
            ),
            FsDeviceFlight::Published {
                semantic,
                root,
                device,
                request,
                ..
            } => (
                semantic.key().cookie(),
                Some(FsRetainedSemantic::Close(FsCloseSemantic::Published(
                    semantic,
                ))),
                FsRetainedHardware::Published {
                    root,
                    device,
                    request,
                },
            ),
            FsDeviceFlight::PublishedReset {
                semantic,
                root,
                device,
                intent,
                ..
            } => (
                semantic.key().cookie(),
                Some(FsRetainedSemantic::Close(FsCloseSemantic::Published(
                    semantic,
                ))),
                FsRetainedHardware::PublishedReset {
                    root,
                    device,
                    intent,
                },
            ),
            FsDeviceFlight::CompletionReset {
                semantic,
                root,
                device,
                intent,
                ..
            }
            | FsDeviceFlight::IndeterminateReset {
                semantic,
                root,
                device,
                intent,
                ..
            } => (
                semantic.key().cookie(),
                Some(FsRetainedSemantic::Close(FsCloseSemantic::Published(
                    semantic,
                ))),
                FsRetainedHardware::CompletionReset {
                    root,
                    device,
                    intent,
                },
            ),
            FsDeviceFlight::Resetting {
                semantic,
                root,
                device,
                hardware,
                ..
            } => (
                semantic.cookie(),
                Some(FsRetainedSemantic::Close(semantic)),
                FsRetainedHardware::Reset {
                    root,
                    device,
                    tombstone: hardware,
                },
            ),
            FsDeviceFlight::ResetRetained {
                semantic,
                root,
                device,
                hardware,
                ..
            } => (
                semantic.cookie(),
                Some(FsRetainedSemantic::Close(semantic)),
                FsRetainedHardware::Reset {
                    root,
                    device,
                    tombstone: hardware,
                },
            ),
            FsDeviceFlight::Iotlb {
                semantic,
                root,
                device,
                hardware,
                ..
            }
            | FsDeviceFlight::IotlbRetained {
                semantic,
                root,
                device,
                hardware,
                ..
            } => (
                semantic.cookie(),
                Some(FsRetainedSemantic::Close(semantic)),
                FsRetainedHardware::Iotlb {
                    root,
                    device,
                    tombstone: hardware,
                },
            ),
            FsDeviceFlight::Draining {
                semantic,
                root,
                device,
                ..
            } => (
                semantic.cookie(),
                Some(FsRetainedSemantic::Close(semantic)),
                FsRetainedHardware::Ready { root, device },
            ),
            FsDeviceFlight::AwaitingPublication {
                cookie,
                root,
                device,
                ..
            } => (cookie, None, FsRetainedHardware::Ready { root, device }),
            retained @ FsDeviceFlight::Retained { cookie, .. } => {
                self.put_flight(retained);
                return cookie;
            }
            complete @ FsDeviceFlight::Complete { .. } => {
                self.put_flight(complete);
                return 0;
            }
            FsDeviceFlight::Transitioning => {
                self.put_flight(FsDeviceFlight::Transitioning);
                return 0;
            }
        };
        self.put_flight(FsDeviceFlight::Retained {
            cookie,
            semantic,
            hardware,
            stage,
        });
        cookie
    }

    fn assert_complete(&self) {
        assert!(matches!(self.flight, FsDeviceFlight::Complete { .. }));
        let scope = self.registry.scope_projection(SCOPE).unwrap();
        assert_eq!(scope.phase, ScopePhase::Revoked);
        assert_eq!(scope.live_effects, 0);
        assert_eq!(scope.pending_publications, 0);
        assert_eq!(scope.credits.capacity, 10);
        assert_eq!(scope.credits.free, 10);
        assert_eq!(scope.credits.held, 0);
        assert_eq!(scope.credits.committed, 0);
        assert_eq!(scope.credits.retained, 0);
    }
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

#[cfg(not(feature = "virtio-cser-facade"))]
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
            #[cfg(not(feature = "virtio-cser-facade"))]
            effects: new_production_registry(),
            fds,
            temporary: Vec::new(),
            next_fd: 3,
            #[cfg(not(feature = "virtio-cser-facade"))]
            domain_revision: 0,
            #[cfg(not(feature = "virtio-cser-facade"))]
            syscall_terminalizations: 0,
            #[cfg(feature = "virtio-cser-facade")]
            compatibility_syscalls: 0,
            production_effects: 0,
            production_read_observed: false,
            stdout_publications: 0,
            exited: false,
        }
    }

    #[cfg(not(feature = "virtio-cser-facade"))]
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

    #[cfg(not(feature = "virtio-cser-facade"))]
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

    #[cfg(not(feature = "virtio-cser-facade"))]
    fn record_domain_change(&mut self, commit: &CommitReceipt) {
        assert_eq!(commit.domain_revision(), self.domain_revision + 1);
        self.domain_revision = commit.domain_revision();
        self.effects
            .domain_changed(SCOPE, self.domain_revision)
            .unwrap();
    }

    #[cfg(not(feature = "virtio-cser-facade"))]
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

    #[cfg(not(feature = "virtio-cser-facade"))]
    fn close_scope(&mut self) {
        let selection = self.effects.revoke_begin(SCOPE).unwrap();
        assert!(self.effects.revoke_next(&selection).unwrap().is_none());
        self.effects.revoke_complete(&selection).unwrap();
        self.effects.check_invariants().unwrap();
    }

    #[cfg(all(
        not(feature = "virtio-cser-facade"),
        not(feature = "virtio-cser-precommit-fault")
    ))]
    fn assert_final(&self) {
        let scope = self.effects.scope_projection(SCOPE).unwrap();
        assert_eq!(scope.phase, ScopePhase::Revoked);
        assert_eq!(scope.live_effects, 0);
        assert_eq!(scope.pending_publications, 0);
        assert_eq!(scope.credits.free, scope.credits.capacity);
        assert_eq!(self.syscall_terminalizations, 14);
        assert_eq!(self.production_effects, 16);
        assert!(self.production_read_observed);
        assert_eq!(self.stdout_publications, 1);
        assert_eq!(self.temporary.as_slice(), [0, 0, b'x', b'y']);
        assert!(self.exited);
    }

    #[cfg(all(
        feature = "virtio-cser-facade",
        not(feature = "virtio-cser-precommit-fault")
    ))]
    fn assert_final(&self) {
        assert_eq!(self.compatibility_syscalls, 13);
        assert_eq!(self.production_effects, 0);
        assert!(self.production_read_observed);
        assert_eq!(self.stdout_publications, 1);
        assert_eq!(self.temporary.as_slice(), [0, 0, b'x', b'y']);
        assert!(self.exited);
    }

    #[cfg(feature = "virtio-cser-facade")]
    fn assert_precommit_final(&self) {
        assert_eq!(self.compatibility_syscalls, 1);
        assert_eq!(self.production_effects, 0);
        assert!(self.production_read_observed);
        assert_eq!(self.stdout_publications, 0);
        assert!(self.temporary.is_empty());
        assert!(!self.exited);
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
    GuestBytes {
        address: usize,
        bytes: Vec<u8>,
    },
    #[cfg(feature = "virtio-cser-facade")]
    FixedGuestBytes {
        address: usize,
        bytes: [u8; 4],
        len: usize,
    },
    Stdout,
}

#[cfg(feature = "virtio-cser-facade")]
struct PreparedGuestWrite {
    frame: UFrame,
    offset: usize,
    bytes: [u8; 4],
    len: usize,
}

#[cfg(feature = "virtio-cser-facade")]
impl PreparedGuestWrite {
    fn prepare(
        cursor: &mut Cursor<'_>,
        address: usize,
        bytes: [u8; 4],
        len: usize,
    ) -> Option<Self> {
        let end = address.checked_add(len)?;
        if len > bytes.len() {
            return None;
        }
        let (range, item) = cursor.query().ok()?;
        if address < range.start || end > range.end {
            return None;
        }
        let VmQueriedItem::MappedRam { frame, prop } = item? else {
            return None;
        };
        if !prop.flags.contains(PageFlags::W) {
            return None;
        }
        let offset = address.checked_sub(range.start)?;
        if offset.checked_add(len)? > ostd::mm::PAGE_SIZE {
            return None;
        }
        Some(Self {
            frame: frame.clone(),
            offset,
            bytes,
            len,
        })
    }

    fn apply(self) {
        let mut destination = self.frame.writer();
        destination.skip(self.offset).limit(self.len);
        let mut source = VmReader::from(&self.bytes[..self.len]);
        let _ = destination.write(&mut source);
    }
}

#[cfg(feature = "virtio-cser-facade")]
enum PreparedProductionPublication {
    None,
    GuestWrite(PreparedGuestWrite),
}

#[cfg(feature = "virtio-cser-facade")]
impl PreparedProductionPublication {
    fn apply(self) {
        if let Self::GuestWrite(write) = self {
            write.apply();
        }
    }
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
                    generation as usize,
                ],
            ),
            resources: vec![
                ResourceKey::new(resource_namespace, paddr as u64, generation),
                ResourceKey::new(resource_namespace + 0x100, iova as u64, generation),
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
    #[cfg(not(feature = "virtio-cser-facade"))]
    Generic(PublicationTicket),
    #[cfg(feature = "virtio-cser-facade")]
    CompatibilityPayload,
    #[cfg(feature = "virtio-cser-facade")]
    Production {
        ticket: PublicationTicket,
        flight_cookie: u64,
    },
    #[cfg(feature = "virtio-cser-facade")]
    Retained { flight_cookie: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationResult {
    Complete,
    #[cfg(feature = "virtio-cser-facade")]
    Retained,
}

struct DispatchOutcome {
    result: i64,
    authority: PublicationAuthority,
    publication: Publication,
    exit: bool,
}

#[cfg(feature = "virtio-cser-facade")]
impl DispatchOutcome {
    fn retained(flight_cookie: u64) -> Self {
        Self {
            result: -5,
            authority: PublicationAuthority::Retained { flight_cookie },
            publication: Publication::None,
            exit: true,
        }
    }
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
    fn retain_current_flight(&self, stage: &'static str) -> DispatchOutcome {
        let cookie = {
            let mut runtime = self.production.lock();
            runtime.retain_current(stage)
        };
        println!(
            "LINUX_FS_SAME_BOOT Retained stage={} cookie={} guest_publication=false owner_runtime_resident=true",
            stage, cookie,
        );
        DispatchOutcome::retained(cookie)
    }

    #[cfg(feature = "virtio-cser-facade")]
    fn retain_exact_flight(
        &self,
        cookie: u64,
        semantic: Option<FsRetainedSemantic>,
        hardware: FsRetainedHardware,
        stage: &'static str,
    ) -> DispatchOutcome {
        let mut runtime = self.production.lock();
        runtime.put_flight(FsDeviceFlight::Retained {
            cookie,
            semantic,
            hardware,
            stage,
        });
        drop(runtime);
        println!(
            "LINUX_FS_SAME_BOOT Retained stage={} cookie={} guest_publication=false owner_runtime_resident=true",
            stage, cookie,
        );
        DispatchOutcome::retained(cookie)
    }

    // The single polling actor restores each linear successor to the runtime
    // slot at every transition boundary. One-step hardware probes temporarily
    // own that successor on the executing actor's stack; IRQ/SMP integration
    // therefore still requires the actor-slot handoff described in the RFC.
    #[cfg(feature = "virtio-cser-facade")]
    fn dispatch_first_executable_pread_same_boot(
        &self,
        descriptor: SyscallDescriptor,
    ) -> DispatchOutcome {
        assert_eq!(descriptor.number(), __NR_pread64 as usize);
        assert_eq!(descriptor.argument(0), 3);
        assert_eq!(descriptor.argument(2), 4);
        assert_eq!(descriptor.argument(3), 0);

        // Capture precedes all personality lookup. The captured syscall and
        // the physical root/device pair are installed together in the only
        // runtime-resident flight slot before the lock is released.
        let (cookie, _syscall) = {
            let mut runtime = self.production.lock();
            let flight = runtime.take_flight();
            let (root, device) = match flight {
                FsDeviceFlight::Ready { root, device } => (root, device),
                other => {
                    runtime.put_flight(other);
                    return DispatchOutcome::retained(
                        runtime.retain_current("capture_without_ready_flight"),
                    );
                }
            };
            let cookie = match runtime.allocate_flight_cookie() {
                Ok(cookie) => cookie,
                Err(error) => {
                    runtime.put_flight(FsDeviceFlight::Retained {
                        cookie: 0,
                        semantic: None,
                        hardware: FsRetainedHardware::Ready { root, device },
                        stage: "flight_cookie_overflow",
                    });
                    println!(
                        "LINUX_FS_SAME_BOOT Retained stage=flight_cookie_overflow error={:?}",
                        error
                    );
                    return DispatchOutcome::retained(0);
                }
            };
            let syscall = match runtime.registry.register_derived(DerivedRegisterRequest {
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
            }) {
                Ok(syscall) => syscall,
                Err(_) => {
                    runtime.put_flight(FsDeviceFlight::Ready { root, device });
                    return DispatchOutcome::retained(
                        runtime.retain_current("syscall_registration"),
                    );
                }
            };
            if runtime
                .registry
                .prepare(PERSONALITY_V1, syscall.handle)
                .is_err()
            {
                runtime.put_flight(FsDeviceFlight::Captured {
                    cookie,
                    root,
                    device,
                    syscall,
                });
                return DispatchOutcome::retained(runtime.retain_current("syscall_prepare"));
            }
            runtime.registered_effects = 1;
            runtime.put_flight(FsDeviceFlight::Captured {
                cookie,
                root,
                device,
                syscall: syscall.clone(),
            });
            (cookie, syscall)
        };

        {
            let mut state = self.state.lock();
            assert!(!state.production_read_observed);
            assert_eq!(state.fds.get(&3), Some(&FdKind::Executable));
            state.production_read_observed = true;
        }

        let precommit_close = {
            let mut runtime = self.production.lock();
            let flight = runtime.take_flight();
            let (mut root, mut device, captured) = match flight {
                FsDeviceFlight::Captured {
                    cookie: captured_cookie,
                    root,
                    device,
                    syscall: captured,
                } if captured_cookie == cookie => (root, device, captured),
                other => {
                    runtime.put_flight(other);
                    return DispatchOutcome::retained(
                        runtime.retain_current("capture_cookie_mismatch"),
                    );
                }
            };

            let filesystem = match runtime.registry.register_derived(DerivedRegisterRequest {
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
                parent: Some(captured.identity.effect()),
            }) {
                Ok(effect) => effect,
                Err(_) => {
                    runtime.put_flight(FsDeviceFlight::Captured {
                        cookie,
                        root,
                        device,
                        syscall: captured,
                    });
                    return DispatchOutcome::retained(
                        runtime.retain_current("filesystem_registration"),
                    );
                }
            };
            if runtime
                .registry
                .prepare(FILESYSTEM_V1, filesystem.handle)
                .is_err()
            {
                runtime.put_flight(FsDeviceFlight::Captured {
                    cookie,
                    root,
                    device,
                    syscall: captured,
                });
                return DispatchOutcome::retained(runtime.retain_current("filesystem_prepare"));
            }
            runtime.registered_effects = 2;

            // This is the real restartable filesystem service boundary. The
            // adopted handle remains the original effect identity.
            let adopted_filesystem = match (|| {
                runtime
                    .registry
                    .crash_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V1)?;
                let snapshot = runtime.registry.domain_recovery_snapshot(
                    SCOPE,
                    FILESYSTEM_DOMAIN,
                    FILESYSTEM_V2,
                )?;
                runtime.registry.domain_ready(
                    SCOPE,
                    FILESYSTEM_DOMAIN,
                    FILESYSTEM_V2,
                    &snapshot,
                )?;
                runtime
                    .registry
                    .rebind_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2)?;
                runtime
                    .registry
                    .recover_next_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2)?
                    .ok_or(RegistryError::InvalidState)?;
                runtime.registry.adopt_domain(
                    SCOPE,
                    FILESYSTEM_DOMAIN,
                    FILESYSTEM_V2,
                    filesystem.handle,
                )
            })() {
                Ok(handle) => handle,
                Err(_) => {
                    runtime.put_flight(FsDeviceFlight::Captured {
                        cookie,
                        root,
                        device,
                        syscall: captured,
                    });
                    return DispatchOutcome::retained(
                        runtime.retain_current("filesystem_recovery"),
                    );
                }
            };

            let request = match device.prepare_read_sector0(&mut root) {
                Ok(request) => request,
                Err(_) => {
                    runtime.put_flight(FsDeviceFlight::Retained {
                        cookie: cookie.get(),
                        semantic: None,
                        hardware: FsRetainedHardware::Ready { root, device },
                        stage: "prepare_read_sector0",
                    });
                    return DispatchOutcome::retained(cookie.get());
                }
            };
            runtime.preparation_identity_observed = true;
            let identity = request.identity();
            let envelope = match DeviceEnvelope::new(
                identity.device_session(),
                identity.queue(),
                identity.descriptor_token(),
                identity.device_generation(),
            ) {
                Ok(envelope) => envelope,
                Err(_) => {
                    runtime.put_flight(FsDeviceFlight::Prepared {
                        cookie,
                        root,
                        device,
                        request,
                        effects: [
                            Some(captured.identity.effect()),
                            Some(filesystem.identity.effect()),
                            None,
                            None,
                            None,
                            None,
                        ],
                        envelope: None,
                        enrollment: None,
                    });
                    return DispatchOutcome::retained(runtime.retain_current("device_envelope"));
                }
            };
            if request
                .preflight_publish(published_identity(envelope, root.device_bdf()))
                .is_err()
            {
                runtime.put_flight(FsDeviceFlight::Prepared {
                    cookie,
                    root,
                    device,
                    request,
                    effects: [
                        Some(captured.identity.effect()),
                        Some(filesystem.identity.effect()),
                        None,
                        None,
                        None,
                        None,
                    ],
                    envelope: Some(envelope),
                    enrollment: None,
                });
                return DispatchOutcome::retained(
                    runtime.retain_current("publish_identity_preflight"),
                );
            }

            let queue_driver = owner_address(identity.device_generation(), OwnerKind::QueueDriver);
            let queue_device = owner_address(identity.device_generation(), OwnerKind::QueueDevice);
            let request_owner = owner_address(identity.device_generation(), OwnerKind::Request);
            let cohort = runtime.registry.register_device_derived_cohort([
                DeviceDerivedCohortEntry {
                    batch_index: 0,
                    request: RegisterRequest {
                        scope: SCOPE,
                        task: BLOCK_V1,
                        operation: OP_BLOCK_REQUEST,
                        descriptor: SyscallDescriptor::new(
                            OP_BLOCK_REQUEST.value() as usize,
                            [
                                0,
                                512,
                                usize::from(identity.queue()),
                                usize::from(identity.descriptor_token()),
                                identity.device_session() as usize,
                                identity.device_generation() as usize,
                            ],
                        ),
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
                    identity,
                    envelope,
                    queue_driver.0,
                    queue_driver.1,
                ),
                same_boot_dma_entry(
                    2,
                    OP_DMA_QUEUE_OWNER_B,
                    DMA_QUEUE_OWNER_B_NAMESPACE,
                    identity,
                    envelope,
                    queue_device.0,
                    queue_device.1,
                ),
                same_boot_dma_entry(
                    3,
                    OP_DMA_REQUEST_OWNER,
                    DMA_REQUEST_OWNER_NAMESPACE,
                    identity,
                    envelope,
                    request_owner.0,
                    request_owner.1,
                ),
            ]);
            let [block, dma_queue_a, dma_queue_b, dma_request] = match cohort {
                Ok(cohort) => cohort,
                Err(_) => {
                    runtime.put_flight(FsDeviceFlight::Prepared {
                        cookie,
                        root,
                        device,
                        request,
                        effects: [
                            Some(captured.identity.effect()),
                            Some(filesystem.identity.effect()),
                            None,
                            None,
                            None,
                            None,
                        ],
                        envelope: Some(envelope),
                        enrollment: None,
                    });
                    return DispatchOutcome::retained(
                        runtime.retain_current("device_cohort_registration"),
                    );
                }
            };
            let effects = [
                captured.identity.effect(),
                filesystem.identity.effect(),
                block.identity.effect(),
                dma_queue_a.identity.effect(),
                dma_queue_b.identity.effect(),
                dma_request.identity.effect(),
            ];
            for member in [&block, &dma_queue_a, &dma_queue_b, &dma_request] {
                if runtime.registry.prepare(BLOCK_V1, member.handle).is_err() {
                    runtime.put_flight(FsDeviceFlight::Prepared {
                        cookie,
                        root,
                        device,
                        request,
                        effects: effects.map(Some),
                        envelope: Some(envelope),
                        enrollment: None,
                    });
                    return DispatchOutcome::retained(
                        runtime.retain_current("device_cohort_prepare"),
                    );
                }
            }
            runtime.registered_effects = 6;
            let authority = match runtime.registry.kernel_root_authority(SCOPE, ROOT_OWNER) {
                Ok(authority) => authority,
                Err(_) => {
                    runtime.put_flight(FsDeviceFlight::Prepared {
                        cookie,
                        root,
                        device,
                        request,
                        effects: effects.map(Some),
                        envelope: Some(envelope),
                        enrollment: None,
                    });
                    return DispatchOutcome::retained(
                        runtime.retain_current("kernel_root_authority"),
                    );
                }
            };
            let handles = [
                captured.handle,
                adopted_filesystem,
                block.handle,
                dma_queue_a.handle,
                dma_queue_b.handle,
                dma_request.handle,
            ];
            let enrollment = match runtime
                .registry
                .enroll_device_batch(authority, &handles, envelope)
            {
                Ok(enrollment) => enrollment,
                Err(_) => {
                    runtime.put_flight(FsDeviceFlight::Prepared {
                        cookie,
                        root,
                        device,
                        request,
                        effects: effects.map(Some),
                        envelope: Some(envelope),
                        enrollment: None,
                    });
                    return DispatchOutcome::retained(runtime.retain_current("device_enrollment"));
                }
            };
            let commits = [
                (captured.handle, CommitMetadata::new(4, 1)),
                (adopted_filesystem, CommitMetadata::new(4, 1)),
                (block.handle, CommitMetadata::new(512, 1)),
                (dma_queue_a.handle, CommitMetadata::new(1, 1)),
                (dma_queue_b.handle, CommitMetadata::new(1, 1)),
                (dma_request.handle, CommitMetadata::new(1, 1)),
            ];

            #[cfg(feature = "virtio-cser-precommit-fault")]
            {
                let bdf = root.device_bdf();
                println!(
                    "LINUX_FS_SAME_BOOT_PRECOMMIT Capture stage=enrolled_preflight scope=95 effects=6 credits=10 registry=shared_production fault=revoke_wins_commit_gate device={} session={:#018x} generation={} queue={} descriptor={}",
                    bdf,
                    envelope.device_session(),
                    envelope.device_generation(),
                    envelope.queue(),
                    envelope.descriptor_token(),
                );
                for (kind, effect, address) in [
                    ("queue_driver", effects[3], queue_driver),
                    ("queue_device", effects[4], queue_device),
                    ("request", effects[5], request_owner),
                ] {
                    println!(
                        "LINUX_FS_SAME_BOOT_PRECOMMIT DmaOwner kind={} effect={} paddr={:#x} iova={:#x} page_size={} queue={} descriptor={} generation={}",
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
                runtime.put_flight(FsDeviceFlight::Building {
                    cookie,
                    root,
                    device,
                    request,
                    effects,
                    envelope,
                    enrollment,
                    commits,
                });
                true
            }

            #[cfg(not(feature = "virtio-cser-precommit-fault"))]
            {
                let key = match mint_device_flight_key(&runtime.registry, &enrollment, cookie) {
                    Ok(key) => key,
                    Err(_) => {
                        runtime.put_flight(FsDeviceFlight::Prepared {
                            cookie,
                            root,
                            device,
                            request,
                            effects: effects.map(Some),
                            envelope: Some(envelope),
                            enrollment: Some(enrollment),
                        });
                        return DispatchOutcome::retained(
                            runtime.retain_current("flight_key_mint"),
                        );
                    }
                };
                let mut request_slot = Some(request);
                match commit_or_recover_device_flight_with_apply(
                    &mut runtime.registry,
                    key,
                    authority,
                    &enrollment,
                    &commits,
                    |_| {
                        request_slot
                            .take()
                            .expect("prevalidated prepared owner")
                            .publish_prepared()
                    },
                ) {
                    Ok(DeviceFlightCloseOutcome::Applied {
                        published,
                        publication,
                    }) => {
                        let bdf = root.device_bdf();
                        let batch_sequence = published.batch().batch_sequence();
                        runtime.put_flight(FsDeviceFlight::Published {
                            semantic: published,
                            root,
                            device,
                            request: publication,
                            work: FsClosureWork {
                                effects,
                                envelope,
                                guest_address: descriptor.argument(1),
                                result: 4,
                                bytes: [0; 4],
                                byte_count: 0,
                                used_len: 0,
                                completion_label: "Unobserved",
                            },
                            completion_probes: 0,
                        });
                        println!(
                            "LINUX_FS_SAME_BOOT Capture same_boot=true identity_preserving=true real_dma=true registry=shared_production scope=95 authority_epoch=141 effects=6 credits=10 device={} session={:#018x} generation={} queue={} descriptor={} syscall_effect={} filesystem_effect={} block_effect={}",
                            bdf,
                            envelope.device_session(),
                            envelope.device_generation(),
                            envelope.queue(),
                            envelope.descriptor_token(),
                            effects[0].id(),
                            effects[1].id(),
                            effects[2].id(),
                        );
                        for (kind, effect, address) in [
                            ("queue_driver", effects[3], queue_driver),
                            ("queue_device", effects[4], queue_device),
                            ("request", effects[5], request_owner),
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
                            batch_sequence,
                            effects[0].id(),
                            effects[1].id(),
                            effects[2].id(),
                            effects[3].id(),
                            effects[4].id(),
                            effects[5].id(),
                        );
                        let notification = match &mut runtime.flight {
                            FsDeviceFlight::Published { request, .. } => request.notify(),
                            _ => {
                                return DispatchOutcome::retained(
                                    runtime.retain_current("published_owner_install"),
                                );
                            }
                        };
                        debug_assert!(matches!(
                            notification,
                            NotificationDisposition::Kicked | NotificationDisposition::Suppressed
                        ));
                        println!(
                            "LINUX_FS_SAME_BOOT Notify disposition={} polling=true irq=false smp=1",
                            match notification {
                                NotificationDisposition::Kicked => "Kicked",
                                NotificationDisposition::Suppressed => "Suppressed",
                                NotificationDisposition::AlreadyResolved => "AlreadyResolved",
                            },
                        );
                        false
                    }
                    Ok(DeviceFlightCloseOutcome::Recovered { .. }) => {
                        let request = request_slot
                            .expect("recovered close did not consume fresh prepared owner");
                        runtime.put_flight(FsDeviceFlight::Prepared {
                            cookie,
                            root,
                            device,
                            request,
                            effects: effects.map(Some),
                            envelope: Some(envelope),
                            enrollment: Some(enrollment),
                        });
                        return DispatchOutcome::retained(
                            runtime.retain_current("fresh_prepared_recovered_close"),
                        );
                    }
                    Err(error @ crate::effect_registry::DeviceCloseError::Unpublished(_)) => {
                        let Some(request) = request_slot else {
                            runtime.put_flight(FsDeviceFlight::Retained {
                                cookie: key.cookie(),
                                semantic: None,
                                hardware: FsRetainedHardware::Quarantined { root, device },
                                stage: "unpublished_close_lost_prepared_owner",
                            });
                            return DispatchOutcome::retained(key.cookie());
                        };
                        let _ = error;
                        runtime.put_flight(FsDeviceFlight::Prepared {
                            cookie,
                            root,
                            device,
                            request,
                            effects: effects.map(Some),
                            envelope: Some(envelope),
                            enrollment: Some(enrollment),
                        });
                        true
                    }
                    Err(error @ crate::effect_registry::DeviceCloseError::Published { .. }) => {
                        let semantic = RetainedSemantic::from_close_error(
                            key,
                            RetainReason::TransitionRejected,
                            error,
                        )
                        .ok()
                        .map(FsRetainedSemantic::PublishedObligation);
                        let hardware = match request_slot {
                            Some(request) => FsRetainedHardware::Prepared {
                                root,
                                device,
                                request,
                            },
                            None => FsRetainedHardware::Quarantined { root, device },
                        };
                        runtime.put_flight(FsDeviceFlight::Retained {
                            cookie: key.cookie(),
                            semantic,
                            hardware,
                            stage: "published_close_error",
                        });
                        return DispatchOutcome::retained(key.cookie());
                    }
                }
            }
        };

        if precommit_close {
            return self.close_precommit_flight("precommit_commit_gate");
        }
        self.drive_postcommit_flight(descriptor)
    }

    #[cfg(feature = "virtio-cser-facade")]
    fn close_precommit_flight(&self, stage: &'static str) -> DispatchOutcome {
        let mut runtime = self.production.lock();
        let flight = runtime.take_flight();
        let FsDeviceFlight::Building {
            cookie,
            root,
            device,
            request,
            effects,
            envelope,
            enrollment,
            commits: _,
        } = flight
        else {
            runtime.put_flight(flight);
            drop(runtime);
            return self.retain_current_flight("precommit_without_building_flight");
        };
        let expected = published_identity(envelope, root.device_bdf());
        let intent = match request.preflight_cancel(expected) {
            Ok(intent) => intent,
            Err(failure) => {
                runtime.put_flight(FsDeviceFlight::Prepared {
                    cookie,
                    root,
                    device,
                    request: failure.into_owner(),
                    effects: effects.map(Some),
                    envelope: Some(envelope),
                    enrollment: Some(enrollment),
                });
                drop(runtime);
                return self.retain_current_flight("precommit_cancel_preflight");
            }
        };
        let mut intent_slot = Some(intent);
        let transition = close_enrolled_device_flight_precommit_with_apply(
            &mut runtime.registry,
            &enrollment,
            cookie,
            |_| {
                intent_slot
                    .take()
                    .expect("prevalidated cancel intent is consumed once")
                    .apply_reset(true)
            },
        );
        let (semantic, hardware) = match transition {
            Ok(transition) => transition,
            Err(_) => {
                let hardware = match intent_slot {
                    Some(intent) => FsRetainedHardware::PreparedCancel {
                        root,
                        device,
                        intent,
                    },
                    None => FsRetainedHardware::Quarantined { root, device },
                };
                runtime.put_flight(FsDeviceFlight::Retained {
                    cookie: cookie.get(),
                    semantic: None,
                    hardware,
                    stage: "precommit_registry_close",
                });
                drop(runtime);
                return DispatchOutcome::retained(cookie.get());
            }
        };
        let reset_ticket = *semantic.reset_ticket();
        runtime.put_flight(FsDeviceFlight::Resetting {
            semantic: FsCloseSemantic::Precommit(semantic),
            root,
            device,
            reset_ticket,
            hardware,
            work: FsClosureWork {
                effects,
                envelope,
                guest_address: 0,
                result: -125,
                bytes: [0; 4],
                byte_count: 0,
                used_len: 0,
                completion_label: "AbortedBeforeCommit",
            },
            retry: false,
        });
        #[cfg(feature = "virtio-cser-precommit-fault")]
        {
            runtime.enrolled_revoke_wins_observed = true;
        }
        runtime.registry.check_invariants().unwrap();
        drop(runtime);
        println!(
            "LINUX_FS_SAME_BOOT_PRECOMMIT CommitGate winner=revoke stage={} publish_closure_calls=0 device_visible=false",
            stage,
        );
        self.drive_closure_flight()
    }

    #[cfg(feature = "virtio-cser-facade")]
    fn drive_postcommit_flight(&self, _descriptor: SyscallDescriptor) -> DispatchOutcome {
        loop {
            let flight = {
                let mut runtime = self.production.lock();
                runtime.take_flight()
            };
            match flight {
                FsDeviceFlight::Published {
                    semantic,
                    root,
                    device,
                    request,
                    mut work,
                    completion_probes,
                } => match request.probe_completion_once() {
                    CompletionProbeProgress::NotReady(request)
                        if completion_probes + 1 < SAME_BOOT_COMPLETION_PROBE_LIMIT =>
                    {
                        let mut runtime = self.production.lock();
                        runtime.put_flight(FsDeviceFlight::Published {
                            semantic,
                            root,
                            device,
                            request,
                            work,
                            completion_probes: completion_probes + 1,
                        });
                        drop(runtime);
                        spin_loop();
                    }
                    CompletionProbeProgress::NotReady(request) => {
                        work.result = -5;
                        work.byte_count = 0;
                        work.used_len = 0;
                        work.completion_label = "Pending";
                        println!(
                            "LINUX_FS_SAME_BOOT Completion outcome=Pending result=-5 used_len=0 payload_source=none data_prefix=none"
                        );
                        let expected = published_identity(work.envelope, root.device_bdf());
                        match request.preflight_reset(expected) {
                            Ok(intent) => {
                                let mut runtime = self.production.lock();
                                runtime.put_flight(FsDeviceFlight::PublishedReset {
                                    semantic,
                                    root,
                                    device,
                                    intent,
                                    work,
                                });
                            }
                            Err(failure) => {
                                return self.retain_exact_flight(
                                    semantic.key().cookie(),
                                    Some(FsRetainedSemantic::Close(FsCloseSemantic::Published(
                                        semantic,
                                    ))),
                                    FsRetainedHardware::Published {
                                        root,
                                        device,
                                        request: failure.into_owner(),
                                    },
                                    "pending_reset_preflight",
                                );
                            }
                        }
                    }
                    CompletionProbeProgress::Complete(completed) => {
                        if fnv1a(completed.data()) != SAME_BOOT_SECTOR_FNV1A {
                            return self.retain_exact_flight(
                                semantic.key().cookie(),
                                Some(FsRetainedSemantic::Close(FsCloseSemantic::Published(
                                    semantic,
                                ))),
                                FsRetainedHardware::Completed {
                                    root,
                                    device,
                                    request: completed,
                                },
                                "completed_payload_digest",
                            );
                        }
                        work.bytes.copy_from_slice(&completed.data()[..4]);
                        work.byte_count = 4;
                        work.result = 4;
                        work.used_len = completed.used_len();
                        work.completion_label = "Completed";
                        println!(
                            "LINUX_FS_SAME_BOOT Completion outcome=Completed result=4 used_len={} payload_source=CompletedRequest data_prefix=7f454c46",
                            work.used_len,
                        );
                        let expected = published_identity(work.envelope, root.device_bdf());
                        match completed.preflight_reset(expected) {
                            Ok(intent) => {
                                let mut runtime = self.production.lock();
                                runtime.put_flight(FsDeviceFlight::CompletionReset {
                                    semantic,
                                    root,
                                    device,
                                    intent,
                                    work,
                                });
                            }
                            Err(failure) => {
                                return self.retain_exact_flight(
                                    semantic.key().cookie(),
                                    Some(FsRetainedSemantic::Close(FsCloseSemantic::Published(
                                        semantic,
                                    ))),
                                    FsRetainedHardware::Completed {
                                        root,
                                        device,
                                        request: failure.into_owner(),
                                    },
                                    "completion_reset_preflight",
                                );
                            }
                        }
                    }
                    CompletionProbeProgress::Failed(failed) => {
                        println!(
                            "LINUX_FS_SAME_BOOT CompletionFailure failure={:?} descriptor_popped={} used_len={:?} retained=true",
                            failed.failure(),
                            failed.descriptor_popped(),
                            failed.used_len(),
                        );
                        work.result = -5;
                        work.byte_count = 0;
                        work.used_len = failed.used_len().unwrap_or(0);
                        work.completion_label = "Failed";
                        println!(
                            "LINUX_FS_SAME_BOOT Completion outcome=Failed result=-5 used_len={} payload_source=none data_prefix=none",
                            work.used_len,
                        );
                        let expected = published_identity(work.envelope, root.device_bdf());
                        match failed.preflight_reset(expected) {
                            Ok(intent) => {
                                let mut runtime = self.production.lock();
                                runtime.put_flight(FsDeviceFlight::IndeterminateReset {
                                    semantic,
                                    root,
                                    device,
                                    intent,
                                    work,
                                });
                            }
                            Err(failure) => {
                                return self.retain_exact_flight(
                                    semantic.key().cookie(),
                                    Some(FsRetainedSemantic::Close(FsCloseSemantic::Published(
                                        semantic,
                                    ))),
                                    FsRetainedHardware::Failed {
                                        root,
                                        device,
                                        request: failure.into_owner(),
                                    },
                                    "failed_completion_reset_preflight",
                                );
                            }
                        }
                    }
                },
                FsDeviceFlight::CompletionReset {
                    semantic,
                    root,
                    device,
                    intent,
                    work,
                } => {
                    let mut runtime = self.production.lock();
                    let mut intent_slot = Some(intent);
                    let transition = runtime
                        .registry
                        .record_device_completion_and_begin_reset_with_apply(
                            semantic.batch(),
                            work.envelope,
                            work.result,
                            |_| {
                                intent_slot
                                    .take()
                                    .expect("prevalidated completion reset is consumed once")
                                    .apply_reset(true)
                            },
                        );
                    match transition {
                        Ok((completion, reset_ticket, hardware)) => {
                            debug_assert_eq!(completion.causal_root(), work.effects[0]);
                            runtime.put_flight(FsDeviceFlight::Resetting {
                                semantic: FsCloseSemantic::Published(semantic),
                                root,
                                device,
                                reset_ticket,
                                hardware,
                                work,
                                retry: false,
                            });
                        }
                        Err(_) => {
                            let hardware = match intent_slot {
                                Some(intent) => FsRetainedHardware::CompletionReset {
                                    root,
                                    device,
                                    intent,
                                },
                                None => FsRetainedHardware::Quarantined { root, device },
                            };
                            runtime.put_flight(FsDeviceFlight::Retained {
                                cookie: semantic.key().cookie(),
                                semantic: Some(FsRetainedSemantic::Close(
                                    FsCloseSemantic::Published(semantic),
                                )),
                                hardware,
                                stage: "completion_registry_fence",
                            });
                            return DispatchOutcome::retained(match &runtime.flight {
                                FsDeviceFlight::Retained { cookie, .. } => *cookie,
                                _ => 0,
                            });
                        }
                    }
                    drop(runtime);
                    return self.drive_closure_flight();
                }
                FsDeviceFlight::IndeterminateReset {
                    semantic,
                    root,
                    device,
                    intent,
                    work,
                } => {
                    let mut runtime = self.production.lock();
                    let mut intent_slot = Some(intent);
                    let transition =
                        runtime
                            .registry
                            .begin_device_reset_with_apply(semantic.batch(), |_| {
                                intent_slot
                                    .take()
                                    .expect("prevalidated failed-completion reset is consumed once")
                                    .apply_reset(true)
                            });
                    match transition {
                        Ok((reset_ticket, hardware)) => {
                            runtime.put_flight(FsDeviceFlight::Resetting {
                                semantic: FsCloseSemantic::Published(semantic),
                                root,
                                device,
                                reset_ticket,
                                hardware,
                                work,
                                retry: false,
                            });
                        }
                        Err(_) => {
                            let cookie = semantic.key().cookie();
                            let hardware = match intent_slot {
                                Some(intent) => FsRetainedHardware::CompletionReset {
                                    root,
                                    device,
                                    intent,
                                },
                                None => FsRetainedHardware::Quarantined { root, device },
                            };
                            runtime.put_flight(FsDeviceFlight::Retained {
                                cookie,
                                semantic: Some(FsRetainedSemantic::Close(
                                    FsCloseSemantic::Published(semantic),
                                )),
                                hardware,
                                stage: "failed_completion_registry_fence",
                            });
                            return DispatchOutcome::retained(cookie);
                        }
                    }
                    drop(runtime);
                    return self.drive_closure_flight();
                }
                FsDeviceFlight::PublishedReset {
                    semantic,
                    root,
                    device,
                    intent,
                    work,
                } => {
                    let mut runtime = self.production.lock();
                    let mut intent_slot = Some(intent);
                    let transition =
                        runtime
                            .registry
                            .begin_device_reset_with_apply(semantic.batch(), |_| {
                                intent_slot
                                    .take()
                                    .expect("prevalidated published reset is consumed once")
                                    .apply_reset(true)
                            });
                    match transition {
                        Ok((reset_ticket, hardware)) => {
                            runtime.put_flight(FsDeviceFlight::Resetting {
                                semantic: FsCloseSemantic::Published(semantic),
                                root,
                                device,
                                reset_ticket,
                                hardware,
                                work,
                                retry: false,
                            });
                        }
                        Err(_) => {
                            let hardware = match intent_slot {
                                Some(intent) => FsRetainedHardware::PublishedReset {
                                    root,
                                    device,
                                    intent,
                                },
                                None => FsRetainedHardware::Quarantined { root, device },
                            };
                            let cookie = semantic.key().cookie();
                            runtime.put_flight(FsDeviceFlight::Retained {
                                cookie,
                                semantic: Some(FsRetainedSemantic::Close(
                                    FsCloseSemantic::Published(semantic),
                                )),
                                hardware,
                                stage: "pending_registry_fence",
                            });
                            return DispatchOutcome::retained(cookie);
                        }
                    }
                    drop(runtime);
                    return self.drive_closure_flight();
                }
                retained @ FsDeviceFlight::Retained { cookie, .. } => {
                    let mut runtime = self.production.lock();
                    runtime.put_flight(retained);
                    return DispatchOutcome::retained(cookie);
                }
                other => {
                    let mut runtime = self.production.lock();
                    runtime.put_flight(other);
                    drop(runtime);
                    return self.drive_closure_flight();
                }
            }
        }
    }

    #[cfg(feature = "virtio-cser-facade")]
    fn drive_closure_flight(&self) -> DispatchOutcome {
        loop {
            let flight = {
                let mut runtime = self.production.lock();
                runtime.take_flight()
            };
            match flight {
                FsDeviceFlight::Resetting {
                    semantic,
                    mut root,
                    mut device,
                    reset_ticket,
                    hardware,
                    work,
                    retry,
                } => match hardware.probe_ack_once(&mut root) {
                    Err(hardware) => {
                        let mut runtime = self.production.lock();
                        match runtime.registry.retain_device_reset_timeout(&reset_ticket) {
                            Ok(reset_tombstone) if !retry => {
                                let cookie = semantic.cookie();
                                runtime.put_flight(FsDeviceFlight::ResetRetained {
                                    semantic,
                                    root,
                                    device,
                                    reset_tombstone,
                                    hardware,
                                    work,
                                });
                                drop(runtime);
                                #[cfg(not(feature = "virtio-cser-precommit-fault"))]
                                println!(
                                    "LINUX_FS_SAME_BOOT ResetTimeout registry_tombstone=true hardware_tombstone=true retained_pages=3 generation={}",
                                    reset_ticket.device().device_generation(),
                                );
                                #[cfg(feature = "virtio-cser-precommit-fault")]
                                println!(
                                    "LINUX_FS_SAME_BOOT_PRECOMMIT ResetTimeout registry_tombstone=true hardware_tombstone=true retained_pages=3 generation={}",
                                    reset_ticket.device().device_generation(),
                                );
                                debug_assert_ne!(cookie, 0);
                            }
                            Ok(_) | Err(_) => {
                                let cookie = semantic.cookie();
                                runtime.put_flight(FsDeviceFlight::Retained {
                                    cookie,
                                    semantic: Some(FsRetainedSemantic::Close(semantic)),
                                    hardware: FsRetainedHardware::Reset {
                                        root,
                                        device,
                                        tombstone: hardware,
                                    },
                                    stage: "reset_retry_remained_pending",
                                });
                                return DispatchOutcome::retained(cookie);
                            }
                        }
                    }
                    Ok(mut hardware_reset) => {
                        let generation_plan =
                            match device.prepare_generation_advance(&mut hardware_reset) {
                                Ok(plan) => plan,
                                Err(_) => {
                                    return self.retain_exact_flight(
                                        semantic.cookie(),
                                        Some(FsRetainedSemantic::Close(semantic)),
                                        FsRetainedHardware::ResetAck {
                                            root,
                                            device,
                                            reset: hardware_reset,
                                        },
                                        "reset_generation_preflight",
                                    );
                                }
                            };
                        let mut runtime = self.production.lock();
                        let reset_apply = runtime
                            .registry
                            .acknowledge_device_reset_with_apply(&reset_ticket, |_| {
                                generation_plan.apply()
                            });
                        let (registry_reset, hardware_generation) = match reset_apply {
                            Ok(applied) => applied,
                            Err(_) => {
                                let cookie = semantic.cookie();
                                runtime.put_flight(FsDeviceFlight::Retained {
                                    cookie,
                                    semantic: Some(FsRetainedSemantic::Close(semantic)),
                                    hardware: FsRetainedHardware::ResetAck {
                                        root,
                                        device,
                                        reset: hardware_reset,
                                    },
                                    stage: "reset_registry_ack",
                                });
                                return DispatchOutcome::retained(cookie);
                            }
                        };
                        debug_assert_eq!(
                            hardware_generation,
                            registry_reset.new_device().device_generation()
                        );
                        let mut reset_slot = Some(hardware_reset);
                        let iotlb_begin =
                            runtime
                                .registry
                                .begin_device_iotlb_with_apply(&registry_reset, |_| {
                                    device.begin_iotlb(
                                        reset_slot
                                            .take()
                                            .expect("reset acknowledgement is consumed once"),
                                        true,
                                    )
                                });
                        match iotlb_begin {
                            Ok((iotlb_ticket, ProductionClosureProgress::Pending(hardware))) => {
                                runtime.put_flight(FsDeviceFlight::Iotlb {
                                    semantic,
                                    root,
                                    device,
                                    reset: registry_reset,
                                    iotlb_ticket,
                                    hardware,
                                    work,
                                    timeout_recorded: false,
                                });
                                drop(runtime);
                                #[cfg(not(feature = "virtio-cser-precommit-fault"))]
                                println!(
                                    "LINUX_FS_SAME_BOOT ResetAck generation={}->{} outcome={} retained_pages=3 generation_apply_atomic=true",
                                    registry_reset.old_device().device_generation(),
                                    registry_reset.new_device().device_generation(),
                                    match registry_reset.outcome() {
                                        DeviceClosureResult::Completed(_) => "Completed",
                                        DeviceClosureResult::IndeterminateAfterReset => {
                                            "IndeterminateAfterReset"
                                        }
                                        DeviceClosureResult::AbortedBeforeCommit => {
                                            "AbortedBeforeCommit"
                                        }
                                    },
                                );
                                #[cfg(feature = "virtio-cser-precommit-fault")]
                                println!(
                                    "LINUX_FS_SAME_BOOT_PRECOMMIT ResetAck generation={}->{} outcome=AbortedBeforeCommit retained_pages=3 was_published=false descriptor_popped=false completed=false generation_apply_atomic=true",
                                    registry_reset.old_device().device_generation(),
                                    registry_reset.new_device().device_generation(),
                                );
                            }
                            Ok((_, ProductionClosureProgress::Complete(closure))) => {
                                let cookie = semantic.cookie();
                                runtime.put_flight(FsDeviceFlight::Retained {
                                    cookie,
                                    semantic: Some(FsRetainedSemantic::Close(semantic)),
                                    hardware: FsRetainedHardware::Closure {
                                        root,
                                        device,
                                        closure,
                                    },
                                    stage: "iotlb_timeout_injection_completed_early",
                                });
                                return DispatchOutcome::retained(cookie);
                            }
                            Err(_) => {
                                let cookie = semantic.cookie();
                                let hardware = match reset_slot {
                                    Some(reset) => FsRetainedHardware::ResetAck {
                                        root,
                                        device,
                                        reset,
                                    },
                                    None => FsRetainedHardware::Quarantined { root, device },
                                };
                                runtime.put_flight(FsDeviceFlight::Retained {
                                    cookie,
                                    semantic: Some(FsRetainedSemantic::Close(semantic)),
                                    hardware,
                                    stage: "iotlb_registry_begin",
                                });
                                return DispatchOutcome::retained(cookie);
                            }
                        }
                    }
                },
                FsDeviceFlight::ResetRetained {
                    semantic,
                    root,
                    device,
                    reset_tombstone,
                    hardware,
                    work,
                } => {
                    let mut runtime = self.production.lock();
                    match runtime.registry.retry_device_reset(&reset_tombstone) {
                        Ok(reset_ticket) => runtime.put_flight(FsDeviceFlight::Resetting {
                            semantic,
                            root,
                            device,
                            reset_ticket,
                            hardware,
                            work,
                            retry: true,
                        }),
                        Err(_) => {
                            let cookie = semantic.cookie();
                            runtime.put_flight(FsDeviceFlight::Retained {
                                cookie,
                                semantic: Some(FsRetainedSemantic::Close(semantic)),
                                hardware: FsRetainedHardware::Reset {
                                    root,
                                    device,
                                    tombstone: hardware,
                                },
                                stage: "reset_registry_retry",
                            });
                            return DispatchOutcome::retained(cookie);
                        }
                    }
                }
                FsDeviceFlight::Iotlb {
                    semantic,
                    root,
                    device,
                    reset,
                    iotlb_ticket,
                    hardware,
                    work,
                    timeout_recorded,
                } => {
                    if timeout_recorded {
                        return self.retain_exact_flight(
                            semantic.cookie(),
                            Some(FsRetainedSemantic::Close(semantic)),
                            FsRetainedHardware::Iotlb {
                                root,
                                device,
                                tombstone: hardware,
                            },
                            "duplicate_iotlb_timeout_record",
                        );
                    }
                    let mut runtime = self.production.lock();
                    match runtime.registry.retain_device_iotlb_timeout(&iotlb_ticket) {
                        Ok(iotlb_tombstone) => {
                            let hardware_generation = hardware.identity().device_generation();
                            runtime.put_flight(FsDeviceFlight::IotlbRetained {
                                semantic,
                                root,
                                device,
                                reset,
                                iotlb_tombstone,
                                hardware,
                                work,
                            });
                            drop(runtime);
                            #[cfg(not(feature = "virtio-cser-precommit-fault"))]
                            println!(
                                "LINUX_FS_SAME_BOOT IotlbTimeout registry_generation={} hardware_identity_generation={} retained_pages=3 registry_tombstone=true hardware_tombstone=true",
                                reset.new_device().device_generation(),
                                hardware_generation,
                            );
                            #[cfg(feature = "virtio-cser-precommit-fault")]
                            println!(
                                "LINUX_FS_SAME_BOOT_PRECOMMIT IotlbTimeout registry_generation={} hardware_identity_generation={} retained_pages=3 registry_tombstone=true hardware_tombstone=true",
                                reset.new_device().device_generation(),
                                hardware_generation,
                            );
                        }
                        Err(_) => {
                            let cookie = semantic.cookie();
                            runtime.put_flight(FsDeviceFlight::Retained {
                                cookie,
                                semantic: Some(FsRetainedSemantic::Close(semantic)),
                                hardware: FsRetainedHardware::Iotlb {
                                    root,
                                    device,
                                    tombstone: hardware,
                                },
                                stage: "iotlb_registry_timeout",
                            });
                            return DispatchOutcome::retained(cookie);
                        }
                    }
                }
                FsDeviceFlight::IotlbRetained {
                    semantic,
                    root,
                    mut device,
                    reset,
                    iotlb_tombstone,
                    hardware,
                    work,
                } => {
                    let registry_retry = {
                        let mut runtime = self.production.lock();
                        runtime
                            .registry
                            .retry_device_iotlb(&reset, &iotlb_tombstone)
                    };
                    let registry_retry = match registry_retry {
                        Ok(retry) => retry,
                        Err(_) => {
                            return self.retain_exact_flight(
                                semantic.cookie(),
                                Some(FsRetainedSemantic::Close(semantic)),
                                FsRetainedHardware::Iotlb {
                                    root,
                                    device,
                                    tombstone: hardware,
                                },
                                "iotlb_registry_retry",
                            );
                        }
                    };
                    let mut hardware_closure = match hardware.retry(1024) {
                        ProductionClosureProgress::Complete(closure) => closure,
                        ProductionClosureProgress::Pending(hardware) => {
                            return self.retain_exact_flight(
                                semantic.cookie(),
                                Some(FsRetainedSemantic::Close(semantic)),
                                FsRetainedHardware::Iotlb {
                                    root,
                                    device,
                                    tombstone: hardware,
                                },
                                "iotlb_hardware_retry_pending",
                            );
                        }
                    };
                    let quiescence_plan =
                        match device.prepare_quiescence_apply(&mut hardware_closure) {
                            Ok(plan) => plan,
                            Err(_) => {
                                return self.retain_exact_flight(
                                    semantic.cookie(),
                                    Some(FsRetainedSemantic::Close(semantic)),
                                    FsRetainedHardware::Closure {
                                        root,
                                        device,
                                        closure: hardware_closure,
                                    },
                                    "iotlb_quiescence_preflight",
                                );
                            }
                        };
                    let mut runtime = self.production.lock();
                    let closure_apply = runtime
                        .registry
                        .acknowledge_device_iotlb_with_apply(&registry_retry, |_| {
                            quiescence_plan.apply()
                        });
                    let (registry_closure, applied_identity) = match closure_apply {
                        Ok(applied) => applied,
                        Err(_) => {
                            let cookie = semantic.cookie();
                            runtime.put_flight(FsDeviceFlight::Retained {
                                cookie,
                                semantic: Some(FsRetainedSemantic::Close(semantic)),
                                hardware: FsRetainedHardware::Closure {
                                    root,
                                    device,
                                    closure: hardware_closure,
                                },
                                stage: "iotlb_registry_ack",
                            });
                            return DispatchOutcome::retained(cookie);
                        }
                    };
                    debug_assert_eq!(
                        applied_identity.device_generation(),
                        work.envelope.device_generation()
                    );
                    let registry_generation = registry_closure.device().device_generation();
                    let hardware_generation = applied_identity.device_generation();
                    runtime.put_flight(FsDeviceFlight::Draining {
                        semantic,
                        root,
                        device,
                        closure: registry_closure,
                        work,
                        next_ordinal: 0,
                        publication: None,
                    });
                    drop(runtime);
                    #[cfg(not(feature = "virtio-cser-precommit-fault"))]
                    println!(
                        "LINUX_FS_SAME_BOOT IotlbAck completed_pages=3 registry_generation={} hardware_identity_generation={} quiescence_applied=true",
                        registry_generation, hardware_generation,
                    );
                    #[cfg(feature = "virtio-cser-precommit-fault")]
                    println!(
                        "LINUX_FS_SAME_BOOT_PRECOMMIT IotlbAck completed_pages=3 registry_generation={} hardware_identity_generation={} outcome=AbortedBeforeCommit quiescence_apply_atomic=true",
                        registry_generation, hardware_generation,
                    );
                }
                FsDeviceFlight::Draining {
                    semantic,
                    root,
                    device,
                    closure,
                    work,
                    next_ordinal,
                    mut publication,
                } => {
                    let leaf_first = [
                        work.effects[3],
                        work.effects[4],
                        work.effects[5],
                        work.effects[2],
                        work.effects[1],
                        work.effects[0],
                    ];
                    let mut runtime = self.production.lock();
                    if next_ordinal < leaf_first.len() {
                        let expected = leaf_first[next_ordinal];
                        let selected = match runtime.registry.revoke_next(semantic.selection()) {
                            Ok(Some(selected)) if selected.effect == expected => selected,
                            _ => {
                                let cookie = semantic.cookie();
                                runtime.put_flight(FsDeviceFlight::Retained {
                                    cookie,
                                    semantic: Some(FsRetainedSemantic::Close(semantic)),
                                    hardware: FsRetainedHardware::Ready { root, device },
                                    stage: "device_drain_selection",
                                });
                                return DispatchOutcome::retained(cookie);
                            }
                        };
                        let request = match &semantic {
                            FsCloseSemantic::Published(published) => {
                                debug_assert!(matches!(
                                    selected.disposition,
                                    RevokeDisposition::Drain(_)
                                ));
                                match closure.outcome() {
                                    DeviceClosureResult::Completed(_) => {
                                        let commit = published
                                            .batch()
                                            .commit_for(expected)
                                            .expect("closed batch contains every selected effect");
                                        TerminalRequest::completed(commit.result())
                                    }
                                    DeviceClosureResult::IndeterminateAfterReset => {
                                        TerminalRequest::indeterminate_after_reset(-5)
                                    }
                                    DeviceClosureResult::AbortedBeforeCommit => {
                                        let cookie = semantic.cookie();
                                        runtime.put_flight(FsDeviceFlight::Retained {
                                            cookie,
                                            semantic: Some(FsRetainedSemantic::Close(semantic)),
                                            hardware: FsRetainedHardware::Ready { root, device },
                                            stage: "published_close_reported_precommit_abort",
                                        });
                                        return DispatchOutcome::retained(cookie);
                                    }
                                }
                            }
                            FsCloseSemantic::Precommit(_) => {
                                debug_assert_eq!(selected.disposition, RevokeDisposition::Abort);
                                TerminalRequest::aborted(-125)
                            }
                        };
                        let terminal = match runtime
                            .registry
                            .stage_device_batch_terminal(&closure, expected, request)
                        {
                            Ok(terminal) => terminal,
                            Err(_) => {
                                let cookie = semantic.cookie();
                                runtime.put_flight(FsDeviceFlight::Retained {
                                    cookie,
                                    semantic: Some(FsRetainedSemantic::Close(semantic)),
                                    hardware: FsRetainedHardware::Ready { root, device },
                                    stage: "device_drain_terminal",
                                });
                                return DispatchOutcome::retained(cookie);
                            }
                        };
                        if terminal.publication.is_some() {
                            debug_assert_eq!(expected, work.effects[0]);
                            publication = terminal.publication;
                        }
                        #[cfg(feature = "virtio-cser-precommit-fault")]
                        let precommit_abort = matches!(&semantic, FsCloseSemantic::Precommit(_));
                        runtime.put_flight(FsDeviceFlight::Draining {
                            semantic,
                            root,
                            device,
                            closure,
                            work,
                            next_ordinal: next_ordinal + 1,
                            publication,
                        });
                        drop(runtime);
                        #[cfg(feature = "virtio-cser-precommit-fault")]
                        if precommit_abort {
                            let kind = [
                                "dma_queue_owner_a",
                                "dma_queue_owner_b",
                                "dma_request_owner",
                                "block_request",
                                "filesystem_read",
                                "filesystem_syscall",
                            ][next_ordinal];
                            println!(
                                "LINUX_FS_SAME_BOOT_PRECOMMIT Abort ordinal={} kind={} effect={} result=-125 leaf_first=true",
                                next_ordinal + 1,
                                kind,
                                expected.id(),
                            );
                        }
                        continue;
                    }
                    if !matches!(runtime.registry.revoke_next(semantic.selection()), Ok(None)) {
                        let cookie = semantic.cookie();
                        runtime.put_flight(FsDeviceFlight::Retained {
                            cookie,
                            semantic: Some(FsRetainedSemantic::Close(semantic)),
                            hardware: FsRetainedHardware::Ready { root, device },
                            stage: "device_drain_not_empty",
                        });
                        return DispatchOutcome::retained(cookie);
                    }
                    let Some(ticket) = publication else {
                        let cookie = semantic.cookie();
                        runtime.put_flight(FsDeviceFlight::Retained {
                            cookie,
                            semantic: Some(FsRetainedSemantic::Close(semantic)),
                            hardware: FsRetainedHardware::Ready { root, device },
                            stage: "device_drain_missing_publication",
                        });
                        return DispatchOutcome::retained(cookie);
                    };
                    let cookie = semantic.cookie();
                    let selection = semantic.selection().clone();
                    let result = work.result;
                    let guest_address = work.guest_address;
                    let used_len = work.used_len;
                    let guest_bytes = work.bytes;
                    let guest_byte_count = work.byte_count;
                    let precommit =
                        matches!(closure.outcome(), DeviceClosureResult::AbortedBeforeCommit);
                    runtime.put_flight(FsDeviceFlight::AwaitingPublication {
                        cookie,
                        root,
                        device,
                        selection,
                        ticket: ticket.clone(),
                        work,
                    });
                    let pending = runtime.registry.scope_projection(SCOPE).unwrap();
                    assert_eq!(pending.phase, ScopePhase::Closing);
                    assert_eq!(pending.live_effects, 0);
                    assert_eq!(pending.pending_publications, 1);
                    drop(runtime);
                    let _ = used_len;
                    #[cfg(not(feature = "virtio-cser-precommit-fault"))]
                    println!(
                        "LINUX_FS_SAME_BOOT Close leaf_first=dma_queue_owner_a,dma_queue_owner_b,dma_request_owner,block_request,filesystem_read,filesystem_syscall terminal_outcome={} guest_publication_pending=true",
                        if result == 4 {
                            "Completed"
                        } else {
                            "IndeterminateAfterReset"
                        },
                    );
                    #[cfg(feature = "virtio-cser-precommit-fault")]
                    println!(
                        "LINUX_FS_SAME_BOOT_PRECOMMIT Close leaf_first=dma_queue_owner_a,dma_queue_owner_b,dma_request_owner,block_request,filesystem_read,filesystem_syscall closure=AbortedBeforeCommit guest_publication_pending=true"
                    );
                    return DispatchOutcome {
                        result,
                        authority: PublicationAuthority::Production {
                            ticket,
                            flight_cookie: cookie,
                        },
                        publication: if result == 4 {
                            Publication::FixedGuestBytes {
                                address: guest_address,
                                bytes: guest_bytes,
                                len: guest_byte_count,
                            }
                        } else {
                            Publication::None
                        },
                        exit: precommit,
                    };
                }
                retained @ FsDeviceFlight::Retained { cookie, .. } => {
                    let mut runtime = self.production.lock();
                    runtime.put_flight(retained);
                    return DispatchOutcome::retained(cookie);
                }
                other => {
                    let mut runtime = self.production.lock();
                    runtime.put_flight(other);
                    drop(runtime);
                    return self.retain_current_flight("unexpected_closure_flight");
                }
            }
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

        #[cfg(not(feature = "virtio-cser-facade"))]
        let registered = state.capture(descriptor, resources);
        #[cfg(not(feature = "virtio-cser-facade"))]
        let effect = registered.identity.effect().id();
        #[cfg(not(feature = "virtio-cser-facade"))]
        let commit = state.commit(&registered, result);
        #[cfg(not(feature = "virtio-cser-facade"))]
        let commit_sequence = commit.sequence();
        #[cfg(not(feature = "virtio-cser-facade"))]
        let log_identity = FsDispatchLogIdentity {
            value: effect,
            commit_sequence,
        };
        #[cfg(feature = "virtio-cser-facade")]
        let log_identity = {
            let _ = resources;
            state.compatibility_syscalls += 1;
            FsDispatchLogIdentity {
                value: state.compatibility_syscalls as u64,
            }
        };

        match action {
            FsAction::Open(fd, kind) => {
                state.allocate_fd_after_commit(fd, kind);
                let (path, label) = match kind {
                    FdKind::Executable => ("/bin/linux-runtime-fs-smoke", "executable"),
                    FdKind::ProcSelf => ("/proc/self", "proc_directory"),
                    _ => unreachable!(),
                };
                println!(
                    "LINUX_FS Open {} fd={} path={} kind={}",
                    log_identity, fd, path, label,
                );
            }
            FsAction::OpenTmp(fd) => {
                state.temporary.clear();
                state.allocate_fd_after_commit(fd, FdKind::Temporary);
                println!(
                    "LINUX_FS Open {} fd={} path=/tmp/runtime-fs.bin kind=regular create=true truncate=true mode=0644",
                    log_identity, fd,
                );
            }
            FsAction::Pread(kind, offset) => match kind {
                FdKind::Executable => panic!("first executable pread bypassed production capture"),
                FdKind::Temporary => println!(
                    "LINUX_FS Pread {} fd=4 offset={} bytes={} payload=00007879",
                    log_identity, offset, result,
                ),
                _ => unreachable!(),
            },
            FsAction::Statx => println!(
                "LINUX_FS Statx {} mask=0x17ff mode=regular size={} empty_path=true",
                log_identity,
                RUNTIME_FS_ELF.len(),
            ),
            FsAction::Newfstatat => println!(
                "LINUX_FS Newfstatat {} mode=regular size={} empty_path=true",
                log_identity,
                RUNTIME_FS_ELF.len(),
            ),
            FsAction::Pwrite { offset, bytes } => {
                let end = offset.checked_add(bytes.len()).unwrap();
                if state.temporary.len() < end {
                    state.temporary.resize(end, 0);
                }
                state.temporary[offset..end].copy_from_slice(&bytes);
                #[cfg(not(feature = "virtio-cser-facade"))]
                let mutation_boundary = "commit_before_mutation=true";
                #[cfg(feature = "virtio-cser-facade")]
                let mutation_boundary = "compatibility_payload_mutation=true";
                println!(
                    "LINUX_FS Pwrite {} fd=4 offset={} bytes={} payload=7879 state_after=00007879 {} dma=false",
                    log_identity,
                    offset,
                    bytes.len(),
                    mutation_boundary,
                );
            }
            FsAction::Readlinkat => println!(
                "LINUX_FS Readlinkat {} dirfd=5 path=exe target=/bin/linux-runtime-fs-smoke bytes={} nul_appended=false",
                log_identity,
                EXECUTABLE_PATH.len(),
            ),
            FsAction::Close(fd, kind) => {
                assert_eq!(state.fds.remove(&fd), Some(kind));
                println!(
                    "LINUX_FS Close {} fd={} remaining_runtime_fds={}",
                    log_identity,
                    fd,
                    state.fds.len() - 1,
                );
            }
            FsAction::WriteStdout => {
                state.stdout_publications += 1;
                println!(
                    "LINUX_FS Write {} fd=1 bytes=14 stdout_exact=true",
                    log_identity,
                );
            }
            FsAction::Exit => {
                state.exited = true;
                println!(
                    "LINUX_FS Exit {} status=0 syscall=exit resumed_after_exit=false",
                    log_identity,
                );
            }
        }

        #[cfg(not(feature = "virtio-cser-facade"))]
        {
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
        #[cfg(feature = "virtio-cser-facade")]
        {
            DispatchOutcome {
                result,
                authority: PublicationAuthority::CompatibilityPayload,
                publication,
                exit,
            }
        }
    }

    fn apply_publication(&self, publication: &Publication) {
        match publication {
            Publication::None => {}
            Publication::GuestBytes { address, bytes } => {
                write_guest_bytes(&self.vm_space, *address, bytes)
            }
            #[cfg(feature = "virtio-cser-facade")]
            Publication::FixedGuestBytes {
                address,
                bytes,
                len,
            } => write_guest_bytes(&self.vm_space, *address, &bytes[..*len]),
            Publication::Stdout => println!("LINUX_FS stdout=runtime fs ok"),
        }
    }

    fn publish(&self, outcome: &DispatchOutcome) -> PublicationResult {
        match &outcome.authority {
            #[cfg(not(feature = "virtio-cser-facade"))]
            PublicationAuthority::Generic(ticket) => {
                self.apply_publication(&outcome.publication);
                let mut state = self.state.lock();
                state.effects.acknowledge_publication(ticket).unwrap();
                state.effects.check_invariants().unwrap();
                PublicationResult::Complete
            }
            #[cfg(feature = "virtio-cser-facade")]
            PublicationAuthority::CompatibilityPayload => {
                self.apply_publication(&outcome.publication);
                PublicationResult::Complete
            }
            #[cfg(feature = "virtio-cser-facade")]
            PublicationAuthority::Production {
                ticket,
                flight_cookie,
            } => {
                let preempt_guard = disable_preempt();
                let mut mapping_cursor = None;
                let prepared_publication = match &outcome.publication {
                    Publication::None => PreparedProductionPublication::None,
                    Publication::FixedGuestBytes {
                        address,
                        bytes,
                        len,
                    } => {
                        let Some(end) = address.checked_add(*len) else {
                            return PublicationResult::Retained;
                        };
                        let page_start = (*address / ostd::mm::PAGE_SIZE) * ostd::mm::PAGE_SIZE;
                        let Some(page_end) = page_start.checked_add(ostd::mm::PAGE_SIZE) else {
                            return PublicationResult::Retained;
                        };
                        if *len == 0 || end > page_end {
                            return PublicationResult::Retained;
                        }
                        let range = page_start..page_end;
                        let Ok(mut cursor) = self.vm_space.cursor(&preempt_guard, &range) else {
                            return PublicationResult::Retained;
                        };
                        let Some(write) =
                            PreparedGuestWrite::prepare(&mut cursor, *address, *bytes, *len)
                        else {
                            return PublicationResult::Retained;
                        };
                        mapping_cursor = Some(cursor);
                        PreparedProductionPublication::GuestWrite(write)
                    }
                    Publication::GuestBytes { .. } | Publication::Stdout => {
                        return PublicationResult::Retained;
                    }
                };
                let mut runtime = self.production.lock();
                let selection = match &runtime.flight {
                    FsDeviceFlight::AwaitingPublication {
                        cookie,
                        selection,
                        ticket: stored_ticket,
                        ..
                    } if cookie == flight_cookie && stored_ticket == ticket => selection.clone(),
                    _ => return PublicationResult::Retained,
                };
                if runtime
                    .registry
                    .acknowledge_publication_and_revoke_complete_with_apply(
                        ticket,
                        &selection,
                        || {
                            let _mapping_lock = mapping_cursor.as_ref();
                            prepared_publication.apply();
                        },
                    )
                    .is_err()
                {
                    return PublicationResult::Retained;
                }
                drop(mapping_cursor);
                drop(preempt_guard);
                let flight = runtime.take_flight();
                let FsDeviceFlight::AwaitingPublication { root, device, .. } = flight else {
                    unreachable!("validated publication flight changed under its Registry lock")
                };
                runtime.put_flight(FsDeviceFlight::Complete { root, device });
                runtime.assert_complete();
                #[cfg(feature = "virtio-cser-precommit-fault")]
                let precommit_scope = if runtime.enrolled_revoke_wins_observed {
                    Some(runtime.registry.scope_projection(SCOPE).unwrap())
                } else {
                    None
                };
                drop(runtime);
                #[cfg(not(feature = "virtio-cser-precommit-fault"))]
                println!(
                    "LINUX_FS_SAME_BOOT GuestPublication result={} bytes={} source={} registry_ack=true revoke_complete=true",
                    outcome.result,
                    match &outcome.publication {
                        Publication::GuestBytes { bytes, .. } => bytes.len(),
                        #[cfg(feature = "virtio-cser-facade")]
                        Publication::FixedGuestBytes { len, .. } => *len,
                        Publication::None | Publication::Stdout => 0,
                    },
                    if outcome.result == 4 {
                        "CompletedRequest"
                    } else {
                        "none"
                    },
                );
                #[cfg(not(feature = "virtio-cser-precommit-fault"))]
                if outcome.result == 4 {
                    println!(
                        "LINUX_FS_SAME_BOOT PASS same_boot=true identity_preserving=true real_dma=true polling=true irq=false smp=1 scope=95 effects=6 credits=10 sector_sha256={} image_sha256={} sector_fnv1a={:#018x}",
                        SAME_BOOT_SECTOR_SHA256, SAME_BOOT_IMAGE_SHA256, SAME_BOOT_SECTOR_FNV1A,
                    );
                }
                #[cfg(feature = "virtio-cser-precommit-fault")]
                if let Some(scope) = precommit_scope {
                    assert_eq!(outcome.result, -125);
                    assert!(matches!(outcome.publication, Publication::None));
                    println!(
                        "LINUX_FS_SAME_BOOT_PRECOMMIT GuestPublication result=-125 bytes=0 source=none registry_ack=true revoke_complete=true"
                    );
                    println!(
                        "LINUX_FS_SAME_BOOT_PRECOMMIT PASS scope=95 effects=6 credits_free={} live_effects={} pending_publications={} closure=AbortedBeforeCommit publish_closure_calls=0 prepared_owner_retained=true was_published=false guest_bytes=0 leaf_first=true",
                        scope.credits.free, scope.live_effects, scope.pending_publications,
                    );
                }
                PublicationResult::Complete
            }
            #[cfg(feature = "virtio-cser-facade")]
            PublicationAuthority::Retained { flight_cookie } => {
                let _ = flight_cookie;
                PublicationResult::Retained
            }
        }
    }

    fn finish(&self) {
        let state = self.state.lock();
        #[cfg(not(feature = "virtio-cser-facade"))]
        let mut state = state;
        #[cfg(not(feature = "virtio-cser-facade"))]
        state.close_scope();
        #[cfg(all(
            feature = "virtio-cser-facade",
            not(feature = "virtio-cser-precommit-fault")
        ))]
        let partial_precommit = !state.exited;
        #[cfg(not(feature = "virtio-cser-facade"))]
        state.assert_final();
        #[cfg(all(
            feature = "virtio-cser-facade",
            not(feature = "virtio-cser-precommit-fault")
        ))]
        if partial_precommit {
            state.assert_precommit_final();
        } else {
            state.assert_final();
        }
        #[cfg(feature = "virtio-cser-precommit-fault")]
        state.assert_precommit_final();
        drop(state);
        #[cfg(all(
            feature = "virtio-cser-facade",
            not(feature = "virtio-cser-precommit-fault")
        ))]
        self.production.lock().assert_complete();
        #[cfg(feature = "virtio-cser-precommit-fault")]
        let (production_effects, preparation_identity_observed, enrolled_revoke_wins_observed) = {
            let production = self.production.lock();
            production.assert_complete();
            (
                production.registered_effects,
                production.preparation_identity_observed,
                production.enrolled_revoke_wins_observed,
            )
        };
        #[cfg(not(feature = "virtio-cser-facade"))]
        println!(
            "EFFECT_REGISTRY Quiescent workload=linux-runtime-fs production_root=95 production_effects=16 live=0 pending_publications=0 credits=Free"
        );
        #[cfg(not(feature = "virtio-cser-facade"))]
        println!(
            "LINUX_FS_SLICE PASS workload=linux-runtime-fs-smoke retained=true adapted=false syscalls=14 openat=3 pread64=2 statx=1 newfstatat=1 pwrite64=1 readlinkat=1 close=3 write=1 exit=1 commit_gate=true publication_acks=14 production_root=true production_domains=3 production_effects=16 production_identity_preparation=true immutable_ancestry=true filesystem_registry_domain_crash_adopt=true real_user_service_crash=false no_synthetic_cohort=true typed_credit_classes=7 leaf_first=true registry_quiescent=true runtime_filesystem=true bounded=true single_cpu=true block_adapter=bounded_in_memory block_preparation_observed=true device_commit=false real_dma=false virtio_evidence=component_consistency same_boot=false identity_preserving_stage5b=false"
        );
        #[cfg(all(
            feature = "virtio-cser-facade",
            not(feature = "virtio-cser-precommit-fault")
        ))]
        if !partial_precommit {
            println!(
                "EFFECT_REGISTRY Quiescent workload=linux-runtime-fs registry=shared_production production_effects=6 compatibility_syscalls=payload_only_not_cser live=0 pending_publications=0 credits=Free"
            );
        }
        #[cfg(all(
            feature = "virtio-cser-facade",
            not(feature = "virtio-cser-precommit-fault")
        ))]
        if !partial_precommit {
            println!(
                "LINUX_FS_SLICE PASS workload=linux-runtime-fs-smoke retained=true adapted=false syscalls=14 compatibility_syscalls=payload_only_not_cser openat=3 pread64=2 statx=1 newfstatat=1 pwrite64=1 readlinkat=1 close=3 write=1 exit=1 registry=shared_production commit_gate=true publication_acks=1 production_root=true production_domains=3 production_effects=6 immutable_ancestry=true filesystem_registry_domain_crash_adopt=true real_user_service_crash=false no_synthetic_cohort=true typed_credit_classes=6 leaf_first=true registry_quiescent=true runtime_filesystem=true bounded=true single_cpu=true block_adapter=virtio_blk device_commit=true real_dma=true polling=true irq=false smp=1 same_boot=true identity_preserving=true"
            );
        } else {
            println!(
                "LINUX_FS_SLICE CLOSED workload=linux-runtime-fs-smoke syscalls=2 compatibility_syscalls=payload_only_not_cser openat=1 pread64=1 registry=shared_production publication_acks=1 precommit_failure=true registry_quiescent=true owner_restored=true"
            );
        }
        #[cfg(feature = "virtio-cser-precommit-fault")]
        if enrolled_revoke_wins_observed {
            println!(
                "EFFECT_REGISTRY Quiescent workload=linux-runtime-fs registry=shared_production production_effects=6 compatibility_syscalls=payload_only_not_cser live=0 pending_publications=0 credits=Free"
            );
            println!(
                "LINUX_FS_SLICE PASS workload=linux-runtime-fs-smoke retained=true adapted=false syscalls=2 compatibility_syscalls=payload_only_not_cser openat=1 pread64=1 registry=shared_production commit_gate=revoke_wins publication_acks=1 production_root=true production_domains=3 production_effects=6 immutable_ancestry=true filesystem_registry_domain_crash_adopt=true real_user_service_crash=false no_synthetic_cohort=true typed_credit_classes=6 leaf_first=true registry_quiescent=true runtime_filesystem=true bounded=true single_cpu=true block_adapter=virtio_blk device_commit=false real_dma_prepared=true device_dma_observed=false polling=false irq=false smp=1 same_boot=true identity_preserving=true precommit_fault=true"
            );
        } else {
            println!(
                "LINUX_FS_SLICE CLOSED workload=linux-runtime-fs-smoke syscalls=2 compatibility_syscalls=payload_only_not_cser openat=1 pread64=1 registry=shared_production publication_acks=1 production_effects={} preparation_identity_observed={} enrolled_revoke_wins_observed=false registry_quiescent=true owner_restored=true",
                production_effects, preparation_identity_observed,
            );
        }
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

struct FsDispatchLogIdentity {
    value: u64,
    #[cfg(not(feature = "virtio-cser-facade"))]
    commit_sequence: u64,
}

impl fmt::Display for FsDispatchLogIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(not(feature = "virtio-cser-facade"))]
        return write!(
            formatter,
            "effect={} commit_sequence={}",
            self.value, self.commit_sequence,
        );
        #[cfg(feature = "virtio-cser-facade")]
        write!(
            formatter,
            "compatibility_ordinal={} cser_effect=none cser_commit=none",
            self.value,
        )
    }
}

pub(crate) fn run_linux_fs_slice() -> RuntimeFsSliceReceipt {
    #[cfg(not(feature = "virtio-cser-facade"))]
    lifecycle_companion::run_filesystem_lifecycle_companion();
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
    #[cfg(all(
        feature = "virtio-cser-facade",
        not(feature = "virtio-cser-precommit-fault")
    ))]
    println!(
        "LINUX_FS_SLICE BEGIN workload=linux-runtime-fs-smoke format=ELF64 type=ET_EXEC retained=true adapted=false syscalls=14 registry=shared_production compatibility_syscalls=payload_only_not_cser root_scope=95 domains=3 typed_credit_classes=6 filesystem=bounded_in_memory pager=bounded block=virtio_blk polling=true irq=false smp=1"
    );
    #[cfg(all(
        feature = "virtio-cser-facade",
        not(feature = "virtio-cser-precommit-fault")
    ))]
    println!(
        "LINUX_FS_ARTIFACT source_sha256={} elf_sha256={} sector_sha256={} full_image_sha256={} sector_fnv1a={:#018x} relation=same_boot identity_preserving=true real_dma=true polling=true irq=false smp=1",
        EXPECTED_SOURCE_SHA256,
        EXPECTED_ELF_SHA256,
        SAME_BOOT_SECTOR_SHA256,
        SAME_BOOT_IMAGE_SHA256,
        SAME_BOOT_SECTOR_FNV1A,
    );
    #[cfg(feature = "virtio-cser-precommit-fault")]
    println!(
        "LINUX_FS_SLICE BEGIN workload=linux-runtime-fs-smoke format=ELF64 type=ET_EXEC retained=true adapted=false syscalls=2 registry=shared_production compatibility_syscalls=payload_only_not_cser root_scope=95 domains=3 typed_credit_classes=6 filesystem=bounded_in_memory pager=bounded block=virtio_blk polling=false irq=false smp=1 precommit_fault=revoke_wins_commit_gate"
    );
    #[cfg(feature = "virtio-cser-precommit-fault")]
    println!(
        "LINUX_FS_ARTIFACT source_sha256={} elf_sha256={} sector_sha256={} full_image_sha256={} sector_fnv1a={:#018x} relation=same_boot_precommit identity_preserving=true real_dma_prepared=true device_visible=false polling=false irq=false smp=1",
        EXPECTED_SOURCE_SHA256,
        EXPECTED_ELF_SHA256,
        SAME_BOOT_SECTOR_SHA256,
        SAME_BOOT_IMAGE_SHA256,
        SAME_BOOT_SECTOR_FNV1A,
    );
    task.run();
    done_waiter.wait();
    #[cfg(not(feature = "virtio-cser-facade"))]
    scenario.state.lock().assert_final();
    #[cfg(all(
        feature = "virtio-cser-facade",
        not(feature = "virtio-cser-precommit-fault")
    ))]
    {
        let state = scenario.state.lock();
        if state.exited {
            state.assert_final();
        } else {
            state.assert_precommit_final();
        }
    }
    #[cfg(feature = "virtio-cser-precommit-fault")]
    scenario.state.lock().assert_precommit_final();
    #[cfg(all(
        feature = "virtio-cser-facade",
        not(feature = "virtio-cser-precommit-fault")
    ))]
    let (production_effects, preparation_identity_observed) = {
        let production = scenario.production.lock();
        production.assert_complete();
        (
            production.registered_effects,
            production.preparation_identity_observed,
        )
    };
    #[cfg(feature = "virtio-cser-precommit-fault")]
    let (production_effects, preparation_identity_observed, enrolled_revoke_wins_observed) = {
        let production = scenario.production.lock();
        production.assert_complete();
        (
            production.registered_effects,
            production.preparation_identity_observed,
            production.enrolled_revoke_wins_observed,
        )
    };
    #[cfg(not(feature = "virtio-cser-facade"))]
    let production_effects = 16;
    #[cfg(not(feature = "virtio-cser-facade"))]
    let preparation_identity_observed = true;
    #[cfg(not(feature = "virtio-cser-facade"))]
    let terminalizations = 14;
    #[cfg(feature = "virtio-cser-facade")]
    let terminalizations = production_effects;
    #[cfg(not(feature = "virtio-cser-facade"))]
    let publication_acks = terminalizations;
    #[cfg(feature = "virtio-cser-facade")]
    let publication_acks = 1;
    RuntimeFsSliceReceipt {
        scope: SCOPE,
        closed_authority_epoch: AUTHORITY_EPOCH,
        final_authority_epoch: AUTHORITY_EPOCH + 1,
        terminalizations,
        publication_acks,
        production_effects,
        production_domains: 3,
        preparation_identity_observed,
        #[cfg(feature = "virtio-cser-precommit-fault")]
        enrolled_revoke_wins_observed,
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
                let publication = scenario.publish(&outcome);
                assert_eq!(
                    publication,
                    PublicationResult::Complete,
                    "runtime-fs retained publication authority before guest resume"
                );
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

#[cfg(not(feature = "virtio-cser-facade"))]
mod lifecycle_companion {
    use super::*;

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

        fn complete_pread(
            &mut self,
            token: LifecycleDomainToken,
        ) -> Result<(), LifecycleDomainError> {
            if token.domain != LifecycleDomain::Filesystem {
                return Err(LifecycleDomainError::InvalidState);
            }
            self.validate(token)?;
            self.filesystem.revision += 1;
            Ok(())
        }

        fn commit_pwrite(
            &mut self,
            token: LifecycleDomainToken,
        ) -> Result<(), LifecycleDomainError> {
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

        fn publish_reply(
            &mut self,
            token: LifecycleDomainToken,
        ) -> Result<(), LifecycleDomainError> {
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

    pub(super) fn run_filesystem_lifecycle_companion() {
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
            if self.phase != BlockPhase::IotlbInFlight
                || self.owners != 3
                || self.tombstone.is_some()
            {
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
