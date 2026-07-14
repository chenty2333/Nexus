// SPDX-License-Identifier: MPL-2.0

//! Hardware-only production typestate for a registry-owned CSER adapter.
//!
//! This module deliberately owns no effect, scope, binding, or commit gate.
//! Its identities are descriptive hardware coordinates which a kernel adapter
//! may bind to its own authoritative registry. The legacy Stage 5B `Portal`
//! remains a separate regression API.

use alloc::boxed::Box;
use bitflags::bitflags;
use core::{
    hint::spin_loop,
    marker::PhantomPinned,
    mem::{ManuallyDrop, forget, size_of},
    pin::Pin,
};

use zerocopy::IntoBytes;

use virtio_drivers::{
    Error as VirtioError,
    device::blk::{BlkReq, BlkResp, RespStatus, SECTOR_SIZE},
    queue::{PreparedVirtQueue, VirtQueue},
    transport::{
        DeviceStatus, DeviceType, Transport,
        pci::{
            PciTransport, VirtioPciError,
            bus::{Command, DeviceFunction},
        },
    },
};

use crate::{
    dma::{self, OstdHal},
    pci::{self, DeviceBdf, Root},
};

const QUEUE_INDEX: u16 = 0;
const QUEUE_SIZE: usize = 16;
const POLL_LIMIT: usize = 10_000_000;
const EXPECTED_USED_LEN: u32 = (SECTOR_SIZE + size_of::<BlkResp>()) as u32;
const SESSION_NAMESPACE: u64 = 0x4e58_5052_0000_0000;
const SESSION_SEQUENCE_MASK: u64 = 0xffff;

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct NexusBlkFeatures: u64 {
        const RO = 1 << 5;
        const VERSION_1 = 1 << 32;
        const ACCESS_PLATFORM = 1 << 33;
    }
}

const REQUIRED_FEATURES: NexusBlkFeatures = NexusBlkFeatures::RO
    .union(NexusBlkFeatures::VERSION_1)
    .union(NexusBlkFeatures::ACCESS_PLATFORM);

type Queue = VirtQueue<OstdHal, QUEUE_SIZE>;
type PreparedQueue = PreparedVirtQueue<OstdHal, QUEUE_SIZE>;

/// Descriptive coordinates of one prepared hardware request.
///
/// This value is not transition authority. In particular, presenting the same
/// integers to another registry cannot authorize publication or completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceSessionIdentity {
    device_session: u64,
    device_bdf: DeviceBdf,
    queue: u16,
    descriptor_token: u16,
    device_generation: u64,
}

impl DeviceSessionIdentity {
    /// Reconstructs descriptive coordinates from a registry envelope.
    ///
    /// This does not claim a device or grant transition authority. It exists
    /// so the main adapter can compare independently retained registry fields
    /// with the facade's immutable prepared-request identity.
    pub const fn from_coordinates(
        device_session: u64,
        device_bdf: DeviceBdf,
        queue: u16,
        descriptor_token: u16,
        device_generation: u64,
    ) -> Self {
        Self {
            device_session,
            device_bdf,
            queue,
            descriptor_token,
            device_generation,
        }
    }

    /// Returns the facade-local device-session namespace.
    pub const fn device_session(self) -> u64 {
        self.device_session
    }

    /// Returns the exact owned PCI function.
    pub const fn device_bdf(self) -> DeviceBdf {
        self.device_bdf
    }

    /// Returns the VirtIO queue index.
    pub const fn queue(self) -> u16 {
        self.queue
    }

    /// Returns the prepared descriptor-head token.
    pub const fn descriptor_token(self) -> u16 {
        self.descriptor_token
    }

    /// Returns the device generation in which the descriptor was prepared.
    pub const fn device_generation(self) -> u64 {
        self.device_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveSession {
    identity: DeviceSessionIdentity,
    reset_acknowledged: bool,
}

/// A preparation rejection which leaves the device facade reusable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrepareReadError {
    /// Another request/reset/IOTLB lifecycle still owns this device.
    ActiveSession,
    /// The supplied PCI root does not own this production device.
    ForeignRoot,
    /// No further stable session identity can be represented.
    SessionSequenceExhausted,
    /// The pinned PCI transport rejected the owned function.
    Transport(VirtioPciError),
    /// The owned function is not a VirtIO block device.
    WrongDeviceType,
    /// The device did not offer every required production feature.
    MissingRequiredFeatures,
    /// The device rejected the negotiated production features.
    FeatureNegotiationRejected,
    /// The queue could not be constructed.
    Queue(VirtioError),
    /// The request bounce owner could not be allocated.
    RequestDmaUnavailable,
    /// Descriptor validation failed before any available-index publication.
    Descriptor(VirtioError),
}

/// Failure-atomic validation error for a hardware generation advance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResetGenerationError {
    /// No hardware session is active.
    NoActiveSession,
    /// The reset receipt names another session or generation.
    WrongIdentity,
    /// This reset acknowledgement was already consumed.
    AlreadyApplied,
    /// The next hardware generation cannot be represented.
    GenerationOverflow,
}

/// Read-only validation error before the unique hardware publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishIdentityError {
    /// The registry plan names another hardware request.
    WrongIdentity,
    /// The immutable facade identity no longer matches its prepared queue.
    DescriptorTokenMismatch,
}

/// Failure-atomic validation error before software quiescence publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuiescenceApplyError {
    /// No hardware session is active.
    NoActiveSession,
    /// The IOTLB receipt names another request.
    WrongIdentity,
    /// The matching whole-device reset generation was not applied.
    ResetNotApplied,
    /// The DMA closure completed for another device generation.
    WrongGeneration,
    /// The DMA closure did not cover all three retained owners.
    WrongCompletedPages,
    /// This closure receipt was already applied.
    AlreadyApplied,
}

/// Prevalidated, linear hardware generation update.
///
/// A main-kernel adapter must create this plan while holding its root runtime
/// lock, prevalidate the matching registry reset transition, and consume both
/// in the registry's single infallible apply boundary. Creating the plan does
/// not mutate hardware or facade state; [`Self::apply`] performs only direct
/// writes through the exclusive references captured during validation.
#[must_use = "apply the generation plan in the registry reset linearization boundary"]
pub struct PreparedGenerationAdvance<'a> {
    active_reset_acknowledged: &'a mut bool,
    device_generation: &'a mut u64,
    reset_generation_applied: &'a mut bool,
    next_generation: u64,
}

impl PreparedGenerationAdvance<'_> {
    /// Applies the fully prevalidated generation update without allocation,
    /// lookup, branching, or an error path.
    pub fn apply(self) -> u64 {
        *self.active_reset_acknowledged = true;
        *self.device_generation = self.next_generation;
        *self.reset_generation_applied = true;
        self.next_generation
    }
}

/// Prevalidated, linear software-quiescence update.
///
/// The main adapter prevalidates this plan and its registry IOTLB transition
/// under the same runtime lock, then invokes [`Self::apply`] inside the
/// registry's infallible acknowledgement boundary.
#[must_use = "apply quiescence in the registry IOTLB acknowledgement boundary"]
pub struct PreparedQuiescenceApply<'a> {
    active: &'a mut Option<ActiveSession>,
    closure_applied: &'a mut bool,
    identity: DeviceSessionIdentity,
}

impl PreparedQuiescenceApply<'_> {
    /// Applies the fully prevalidated update using direct writes only.
    pub fn apply(self) -> DeviceSessionIdentity {
        *self.closure_applied = true;
        *self.active = None;
        self.identity
    }
}

/// Exclusive descriptive owner of the production hardware lifecycle.
///
/// The kernel's production registry remains the only semantic authority. This
/// object merely prevents overlapping PCI/queue/DMA generations inside the
/// facade and records when reset and IOTLB hardware closure have completed.
/// One opaque [`Root`] grants only one device claim, and `active` admits only
/// one request/reset/IOTLB lifecycle for that claimed BDF. The registry's
/// descriptive envelope does not independently prove this cross-root physical
/// exclusivity or contain whole-function reset blast radius; that obligation
/// remains here at the hardware owner boundary.
pub struct ProductionDevice {
    device_function: DeviceFunction,
    device_bdf: DeviceBdf,
    next_session_sequence: u64,
    device_generation: u64,
    active: Option<ActiveSession>,
}

impl ProductionDevice {
    /// Claims the exact block device already owned by `root`.
    pub fn for_owned_device(root: &mut Root) -> Self {
        let device_function = root.claim_device_function();
        Self {
            device_function,
            device_bdf: root.device_bdf(),
            next_session_sequence: 1,
            device_generation: 1,
            active: None,
        }
    }

    /// Returns the generation authorized by the latest acknowledged reset.
    pub const fn device_generation(&self) -> u64 {
        self.device_generation
    }

    /// Initializes and prepares one read of sector zero without publishing the
    /// available index.
    ///
    /// The returned token owns the PCI transport, queue DMA, request DMA, exact
    /// buffers, descriptor chain, and available-ring slot. Device visibility is
    /// still impossible at return. Preparing while another lifecycle is active
    /// is rejected before any hardware or facade state changes; the existing
    /// lifecycle and its owners remain retained fail closed.
    pub fn prepare_read_sector0(
        &mut self,
        root: &mut Root,
    ) -> Result<PreparedRequest, PrepareReadError> {
        if self.active.is_some() {
            return Err(PrepareReadError::ActiveSession);
        }
        if root.device_function() != self.device_function {
            return Err(PrepareReadError::ForeignRoot);
        }
        let sequence = self.next_session_sequence;
        if !(1..=SESSION_SEQUENCE_MASK).contains(&sequence) {
            return Err(PrepareReadError::SessionSequenceExhausted);
        }
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(PrepareReadError::SessionSequenceExhausted)?;
        let device_session = SESSION_NAMESPACE
            | (u64::from(self.device_function.bus) << 24)
            | (u64::from(self.device_function.device) << 19)
            | (u64::from(self.device_function.function) << 16)
            | sequence;

        let original_command = pci::enable_device_for_prepare(root, self.device_function);
        dma::begin_generation(self.device_generation);
        pci::begin_transport_claims();

        let mut transport =
            match PciTransport::new::<OstdHal, _>(root.raw_mut(), self.device_function) {
                Ok(transport) => transport,
                Err(error) => {
                    rollback_unexposed_preparation(
                        root,
                        self.device_function,
                        original_command,
                        self.device_generation,
                        None,
                        None,
                        None,
                    );
                    return Err(PrepareReadError::Transport(error));
                }
            };
        if transport.device_type() != DeviceType::Block {
            rollback_unexposed_preparation(
                root,
                self.device_function,
                original_command,
                self.device_generation,
                Some(transport),
                None,
                None,
            );
            return Err(PrepareReadError::WrongDeviceType);
        }
        let negotiated = transport.begin_init(REQUIRED_FEATURES);
        if negotiated != REQUIRED_FEATURES {
            rollback_unexposed_preparation(
                root,
                self.device_function,
                original_command,
                self.device_generation,
                Some(transport),
                None,
                None,
            );
            return Err(PrepareReadError::MissingRequiredFeatures);
        }
        if !transport.get_status().contains(DeviceStatus::FEATURES_OK) {
            rollback_unexposed_preparation(
                root,
                self.device_function,
                original_command,
                self.device_generation,
                Some(transport),
                None,
                None,
            );
            return Err(PrepareReadError::FeatureNegotiationRejected);
        }

        let mut queue = match Queue::new(&mut transport, QUEUE_INDEX, false, false) {
            Ok(queue) => queue,
            Err(error) => {
                rollback_unexposed_preparation(
                    root,
                    self.device_function,
                    original_command,
                    self.device_generation,
                    Some(transport),
                    None,
                    None,
                );
                return Err(PrepareReadError::Queue(error));
            }
        };
        queue.set_dev_notify(false);

        if dma::try_arm_request_bounce(self.device_generation).is_none() {
            rollback_unexposed_preparation(
                root,
                self.device_function,
                original_command,
                self.device_generation,
                Some(transport),
                Some(queue),
                None,
            );
            return Err(PrepareReadError::RequestDmaUnavailable);
        }

        let mut buffers = Box::pin(RequestBuffers::new());
        // SAFETY: only fields are borrowed. The allocation remains pinned in
        // every successor typestate until pop or reset acknowledgement.
        let request_buffers = unsafe { buffers.as_mut().get_unchecked_mut() };
        let inputs = [request_buffers.request.as_bytes()];
        let mut outputs: [&mut [u8]; 2] = [
            &mut request_buffers.data[..],
            request_buffers.response.as_mut_bytes(),
        ];
        // SAFETY: the pinned allocation and all three fields are retained by
        // the returned typestate until explicit publish/pop or cancellation.
        let prepared = match unsafe { queue.prepare_add(&inputs, &mut outputs) } {
            Ok(prepared) => prepared,
            Err(error) => {
                let error_kind = error.error();
                let queue = error.into_queue();
                rollback_unexposed_preparation(
                    root,
                    self.device_function,
                    original_command,
                    self.device_generation,
                    Some(transport),
                    Some(queue),
                    Some(buffers),
                );
                return Err(PrepareReadError::Descriptor(error_kind));
            }
        };
        let identity = DeviceSessionIdentity {
            device_session,
            device_bdf: self.device_bdf,
            queue: QUEUE_INDEX,
            descriptor_token: prepared.token(),
            device_generation: self.device_generation,
        };
        // Every fallible validation and allocation is complete. From here to
        // return there are only direct ownership moves and device-visible
        // initialization writes.
        dma::mark_queue_exposed(self.device_generation);
        transport.finish_init();
        self.next_session_sequence = next_sequence;
        self.active = Some(ActiveSession {
            identity,
            reset_acknowledged: false,
        });

        Ok(PreparedRequest {
            identity,
            device_function: self.device_function,
            transport: ManuallyDrop::new(transport),
            queue: ManuallyDrop::new(prepared),
            buffers: ManuallyDrop::new(buffers),
        })
    }

    /// Prevalidates consumption of a reset acknowledgement without mutation.
    ///
    /// The returned plan borrows both objects exclusively, preventing either
    /// projection from changing between validation and its infallible apply.
    pub fn prepare_generation_advance<'a>(
        &'a mut self,
        reset: &'a mut ProductionResetAck,
    ) -> Result<PreparedGenerationAdvance<'a>, ResetGenerationError> {
        let active = self
            .active
            .as_mut()
            .ok_or(ResetGenerationError::NoActiveSession)?;
        if active.identity != reset.identity {
            return Err(ResetGenerationError::WrongIdentity);
        }
        if active.reset_acknowledged || reset.generation_applied {
            return Err(ResetGenerationError::AlreadyApplied);
        }
        let next = self
            .device_generation
            .checked_add(1)
            .ok_or(ResetGenerationError::GenerationOverflow)?;
        Ok(PreparedGenerationAdvance {
            active_reset_acknowledged: &mut active.reset_acknowledged,
            device_generation: &mut self.device_generation,
            reset_generation_applied: &mut reset.generation_applied,
            next_generation: next,
        })
    }

    /// Begins IOTLB closure after this device consumed the matching reset ack.
    pub fn begin_iotlb(
        &self,
        reset: ProductionResetAck,
        inject_one_pending: bool,
    ) -> ProductionClosureProgress {
        let active = self.active.expect("IOTLB closure for an active session");
        assert_eq!(active.identity, reset.identity);
        assert!(active.reset_acknowledged);
        assert!(reset.generation_applied);
        production_closure_progress(
            reset.identity,
            dma::begin_closure(reset.closure_authority, inject_one_pending),
        )
    }

    /// Prevalidates software quiescence publication without mutation.
    ///
    /// The returned plan exclusively borrows both facade state and the linear
    /// closure receipt. A rejected registry transition may drop the plan and
    /// retry with the unchanged receipt; successful registry acknowledgement
    /// invokes the plan's infallible direct-write apply.
    pub fn prepare_quiescence_apply<'a>(
        &'a mut self,
        closure: &'a mut ProductionClosureReceipt,
    ) -> Result<PreparedQuiescenceApply<'a>, QuiescenceApplyError> {
        let active = self
            .active
            .as_ref()
            .ok_or(QuiescenceApplyError::NoActiveSession)?;
        if active.identity != closure.identity {
            return Err(QuiescenceApplyError::WrongIdentity);
        }
        if !active.reset_acknowledged {
            return Err(QuiescenceApplyError::ResetNotApplied);
        }
        if closure.dma.generation() != active.identity.device_generation() {
            return Err(QuiescenceApplyError::WrongGeneration);
        }
        if closure.dma.completed_pages() != 3 {
            return Err(QuiescenceApplyError::WrongCompletedPages);
        }
        if closure.applied {
            return Err(QuiescenceApplyError::AlreadyApplied);
        }
        let identity = active.identity;
        Ok(PreparedQuiescenceApply {
            active: &mut self.active,
            closure_applied: &mut closure.applied,
            identity,
        })
    }
}

struct RequestBuffers {
    request: BlkReq,
    data: [u8; SECTOR_SIZE],
    response: BlkResp,
    _pin: PhantomPinned,
}

impl RequestBuffers {
    fn new() -> Self {
        Self {
            request: BlkReq::default(),
            data: [0; SECTOR_SIZE],
            response: BlkResp::default(),
            _pin: PhantomPinned,
        }
    }
}

fn rollback_unexposed_preparation(
    root: &mut Root,
    device_function: DeviceFunction,
    original_command: Command,
    generation: u64,
    mut transport: Option<PciTransport>,
    queue: Option<Queue>,
    buffers: Option<Pin<Box<RequestBuffers>>>,
) {
    if let Some(transport) = transport.as_mut() {
        transport.set_status(DeviceStatus::empty());
    }
    pci::disable_bus_master(root, device_function);
    drop(queue);
    drop(transport);
    // SAFETY: no transport was returned from the failed constructor, or the
    // only returned transport was destroyed immediately above. The queue was
    // never exposed to a DRIVER_OK device and no raw MMIO pointer remains.
    unsafe { pci::release_transport_claims() };
    pci::restore_device_command(root, device_function, original_command);
    drop(buffers);
    dma::abort_unexposed_generation(generation);
}

/// A request whose descriptors and DMA shares are ready but unpublished.
#[must_use = "publish, cancel, or retain the complete prepared request"]
pub struct PreparedRequest {
    identity: DeviceSessionIdentity,
    device_function: DeviceFunction,
    transport: ManuallyDrop<PciTransport>,
    queue: ManuallyDrop<PreparedQueue>,
    buffers: ManuallyDrop<Pin<Box<RequestBuffers>>>,
}

impl PreparedRequest {
    /// Returns descriptive coordinates for registration in the kernel registry.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.identity
    }

    /// Checks the immutable hardware identity before registry commit apply.
    ///
    /// The main-kernel adapter calls this while holding its root runtime lock,
    /// then prevalidates the matching registry publication. Neither the facade
    /// identity nor the prepared queue token can change afterward, so the
    /// adapter's infallible apply boundary may consume both prepared plans
    /// without performing a check after the device-visible Release store.
    pub fn preflight_publish(
        &self,
        expected: DeviceSessionIdentity,
    ) -> Result<(), PublishIdentityError> {
        if self.identity != expected {
            return Err(PublishIdentityError::WrongIdentity);
        }
        if self.queue.token() != self.identity.descriptor_token {
            return Err(PublishIdentityError::DescriptorTokenMismatch);
        }
        Ok(())
    }

    /// Performs the unique infallible `avail.idx` Release publication.
    ///
    /// The caller must first run [`Self::preflight_publish`] and prevalidate
    /// the matching registry commit while holding the adapter's runtime lock.
    /// This method deliberately performs no validation after publication.
    pub fn publish_prepared(self) -> PublishedRequest {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: suppressing PreparedRequest::drop makes these the only
        // extractions of the exact retained preparation owners.
        let prepared = unsafe { ManuallyDrop::take(&mut this.queue) };
        let (queue, _token) = prepared.publish_prepared();
        PublishedRequest {
            identity: this.identity,
            device_function: this.device_function,
            // SAFETY: the enclosing ManuallyDrop is consumed once here.
            transport: Some(unsafe { ManuallyDrop::take(&mut this.transport) }),
            queue: Some(queue),
            // SAFETY: the enclosing ManuallyDrop is consumed once here.
            buffers: Some(unsafe { ManuallyDrop::take(&mut this.buffers) }),
            notification_resolved: false,
        }
    }

    /// Rolls back an unpublished descriptor chain and all three request shares.
    pub fn cancel_prepared(self) -> CancelledRequest {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: the enclosing ManuallyDrop is consumed once here.
        let prepared = unsafe { ManuallyDrop::take(&mut this.queue) };
        // SAFETY: the enclosing ManuallyDrop is consumed once here.
        let mut buffers = unsafe { ManuallyDrop::take(&mut this.buffers) };
        // SAFETY: these are the exact pinned fields supplied to prepare_add;
        // `avail.idx` has not been published and they remain inaccessible.
        let request_buffers = unsafe { buffers.as_mut().get_unchecked_mut() };
        let inputs = [request_buffers.request.as_bytes()];
        let mut outputs: [&mut [u8]; 2] = [
            &mut request_buffers.data[..],
            request_buffers.response.as_mut_bytes(),
        ];
        // SAFETY: exact buffers and the linear token are consumed together.
        let queue = unsafe { prepared.cancel_prepared(&inputs, &mut outputs) };
        assert_eq!(
            dma::request_share_counts(this.identity.device_generation),
            (3, 3)
        );
        CancelledRequest {
            session: Some(ResetSession {
                identity: this.identity,
                device_function: this.device_function,
                // SAFETY: the enclosing ManuallyDrop is consumed once here.
                transport: Some(unsafe { ManuallyDrop::take(&mut this.transport) }),
                queue: Some(queue),
                buffers: Some(buffers),
                published: false,
                descriptor_popped: false,
                completed: false,
            }),
        }
    }
}

impl Drop for PreparedRequest {
    fn drop(&mut self) {
        // Fail closed. Only publish_prepared or cancel_prepared may extract
        // these ManuallyDrop owners and discharge the preparation obligation.
    }
}

/// A retained completion-path failure which still permits mandatory reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionFailure {
    /// Completion was polled before notification suppression/kick was resolved.
    NotificationUnresolved,
    /// The next used-ring entry names another descriptor chain.
    WrongToken { expected: u16, observed: u16 },
    /// The queue rejected the matching pop without consuming the descriptor.
    Pop(VirtioError),
    /// The device consumed the descriptor but did not report the complete output length.
    UnexpectedUsedLength { expected: u32, observed: u32 },
    /// The descriptor was popped, but the device returned a non-success status.
    DeviceResponse(RespStatus),
    /// The descriptor was popped, but exact request-share retirement was not observed.
    ShareAccountingMismatch { observed: Option<(usize, usize)> },
}

/// Result of resolving the post-publication queue notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationDisposition {
    /// The device requested and received a queue kick.
    Kicked,
    /// The device suppressed the kick; polling may proceed without one.
    Suppressed,
    /// This published request had already resolved notification exactly once.
    AlreadyResolved,
}

/// Linear result of one bounded completion poll.
#[must_use = "consume the completion, reset the retained request, or retain its owner"]
pub enum CompletionProgress {
    /// The matching descriptor was popped and validated successfully.
    Complete(CompletedRequest),
    /// No used descriptor arrived before the bounded deadline.
    Pending(PendingCompletion),
    /// Validation failed while the complete request owner remained recoverable.
    Failed(FailedCompletion),
}

/// A timed-out poll which retains every published request owner.
#[must_use = "retry at a higher layer or begin mandatory device reset"]
pub struct PendingCompletion {
    request: Option<PublishedRequest>,
}

impl PendingCompletion {
    /// Returns the retained hardware identity.
    pub fn identity(&self) -> DeviceSessionIdentity {
        self.request.as_ref().expect("pending request").identity
    }

    /// No descriptor is consumed on the pending path.
    pub const fn descriptor_popped(&self) -> bool {
        false
    }

    /// Starts whole-device reset while retaining the unpublished used-chain owner.
    pub fn begin_reset(mut self, inject_pending_once: bool) -> ProductionResetTombstone {
        self.request
            .take()
            .expect("pending request")
            .into_reset_session(false, false)
            .begin_reset(inject_pending_once)
    }
}

/// A failed completion validation with a retained reset path.
#[must_use = "inspect the failure and begin mandatory device reset"]
pub struct FailedCompletion {
    request: Option<PublishedRequest>,
    failure: CompletionFailure,
    descriptor_popped: bool,
    used_len: Option<u32>,
}

impl FailedCompletion {
    fn new(
        request: PublishedRequest,
        failure: CompletionFailure,
        descriptor_popped: bool,
        used_len: Option<u32>,
    ) -> Self {
        Self {
            request: Some(request),
            failure,
            descriptor_popped,
            used_len,
        }
    }

    /// Returns the retained hardware identity.
    pub fn identity(&self) -> DeviceSessionIdentity {
        self.request.as_ref().expect("failed request").identity
    }

    /// Returns the exact completion validation failure.
    pub const fn failure(&self) -> CompletionFailure {
        self.failure
    }

    /// Reports whether `pop_used` consumed and recycled the descriptor chain.
    pub const fn descriptor_popped(&self) -> bool {
        self.descriptor_popped
    }

    /// Returns the device-reported used length when the descriptor was popped.
    pub const fn used_len(&self) -> Option<u32> {
        self.used_len
    }

    /// Starts whole-device reset without discarding either popped or live owners.
    pub fn begin_reset(mut self, inject_pending_once: bool) -> ProductionResetTombstone {
        self.request
            .take()
            .expect("failed request")
            .into_reset_session(self.descriptor_popped, false)
            .begin_reset(inject_pending_once)
    }
}

/// A device-visible request which has not yet completed.
#[must_use = "notify and complete, or retain/reset the published request"]
pub struct PublishedRequest {
    identity: DeviceSessionIdentity,
    device_function: DeviceFunction,
    transport: Option<PciTransport>,
    queue: Option<Queue>,
    buffers: Option<Pin<Box<RequestBuffers>>>,
    notification_resolved: bool,
}

impl PublishedRequest {
    /// Returns descriptive coordinates of the published request.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.identity
    }

    /// Resolves the one queue notification after external commit application.
    ///
    /// VirtIO notification suppression is a successful outcome, not an error:
    /// the device has already observed the available ring and requested that
    /// the driver skip the kick. Repeated resolution is reported without
    /// panicking away the published request owner.
    pub fn notify(&mut self) -> NotificationDisposition {
        if self.notification_resolved {
            return NotificationDisposition::AlreadyResolved;
        }
        let disposition = if self.queue.as_ref().expect("live queue").should_notify() {
            self.transport
                .as_mut()
                .expect("live transport")
                .notify(QUEUE_INDEX);
            NotificationDisposition::Kicked
        } else {
            NotificationDisposition::Suppressed
        };
        self.notification_resolved = true;
        disposition
    }

    /// Polls the Stage-5-compatible diagnostic completion path.
    ///
    /// This method does not establish an interrupt-delivery claim. The future
    /// main adapter must select a real IRQ completion API instead.
    pub fn poll_completion(mut self) -> CompletionProgress {
        if !self.notification_resolved {
            return CompletionProgress::Failed(FailedCompletion::new(
                self,
                CompletionFailure::NotificationUnresolved,
                false,
                None,
            ));
        }
        let expected = self.identity.descriptor_token;
        let mut observed = None;
        for _ in 0..POLL_LIMIT {
            if let Some(token) = self.queue.as_ref().expect("live queue").peek_used() {
                observed = Some(token);
                break;
            }
            spin_loop();
        }
        let Some(observed) = observed else {
            return CompletionProgress::Pending(PendingCompletion {
                request: Some(self),
            });
        };
        if observed != expected {
            return CompletionProgress::Failed(FailedCompletion::new(
                self,
                CompletionFailure::WrongToken { expected, observed },
                false,
                None,
            ));
        }

        let queue = self.queue.as_mut().expect("live queue");
        let buffers = self.buffers.as_mut().expect("pinned request buffers");
        // SAFETY: only fields of the stable pinned allocation are borrowed.
        let request_buffers = unsafe { buffers.as_mut().get_unchecked_mut() };
        let inputs = [request_buffers.request.as_bytes()];
        let mut outputs: [&mut [u8]; 2] = [
            &mut request_buffers.data[..],
            request_buffers.response.as_mut_bytes(),
        ];
        // SAFETY: token and buffers exactly match the published prepared chain.
        let used_len = match unsafe { queue.pop_used(expected, &inputs, &mut outputs) } {
            Ok(used_len) => used_len,
            Err(error) => {
                return CompletionProgress::Failed(FailedCompletion::new(
                    self,
                    CompletionFailure::Pop(error),
                    false,
                    None,
                ));
            }
        };
        if used_len != EXPECTED_USED_LEN {
            return CompletionProgress::Failed(FailedCompletion::new(
                self,
                CompletionFailure::UnexpectedUsedLength {
                    expected: EXPECTED_USED_LEN,
                    observed: used_len,
                },
                true,
                Some(used_len),
            ));
        }
        let response = request_buffers.response.status();
        if response != RespStatus::OK {
            return CompletionProgress::Failed(FailedCompletion::new(
                self,
                CompletionFailure::DeviceResponse(response),
                true,
                Some(used_len),
            ));
        }
        let share_counts = dma::request_share_counts_checked(self.identity.device_generation);
        if share_counts != Some((3, 3)) {
            return CompletionProgress::Failed(FailedCompletion::new(
                self,
                CompletionFailure::ShareAccountingMismatch {
                    observed: share_counts,
                },
                true,
                Some(used_len),
            ));
        }

        CompletionProgress::Complete(CompletedRequest {
            request: Some(self),
            used_len,
        })
    }

    /// Starts whole-device reset for a published request without completion.
    pub fn begin_reset(self, inject_pending_once: bool) -> ProductionResetTombstone {
        self.into_reset_session(false, false)
            .begin_reset(inject_pending_once)
    }

    fn into_reset_session(mut self, descriptor_popped: bool, completed: bool) -> ResetSession {
        ResetSession {
            identity: self.identity,
            device_function: self.device_function,
            transport: self.transport.take(),
            queue: self.queue.take(),
            buffers: self.buffers.take(),
            published: true,
            descriptor_popped,
            completed,
        }
    }
}

impl Drop for PublishedRequest {
    fn drop(&mut self) {
        quarantine(&mut self.queue);
        quarantine(&mut self.transport);
        quarantine(&mut self.buffers);
    }
}

/// A successfully popped request whose sector buffer is kernel-readable.
#[must_use = "copy the data and close the complete hardware generation"]
pub struct CompletedRequest {
    request: Option<PublishedRequest>,
    used_len: u32,
}

impl CompletedRequest {
    /// Returns the used length reported by the device.
    pub const fn used_len(&self) -> u32 {
        self.used_len
    }

    /// Returns the complete sector-zero result after successful pop.
    pub fn data(&self) -> &[u8; SECTOR_SIZE] {
        &self
            .request
            .as_ref()
            .expect("completed request")
            .buffers
            .as_ref()
            .expect("pinned request buffers")
            .as_ref()
            .get_ref()
            .data
    }

    /// Starts mandatory whole-device reset after normal completion.
    pub fn begin_reset(mut self, inject_pending_once: bool) -> ProductionResetTombstone {
        self.request
            .take()
            .expect("completed request")
            .into_reset_session(true, true)
            .begin_reset(inject_pending_once)
    }
}

/// An explicitly cancelled, never-published request awaiting device closure.
#[must_use = "reset and close the queue/DMA generation"]
pub struct CancelledRequest {
    session: Option<ResetSession>,
}

impl CancelledRequest {
    /// Starts mandatory whole-device reset after unpublished cancellation.
    pub fn begin_reset(mut self, inject_pending_once: bool) -> ProductionResetTombstone {
        ProductionResetTombstone::new(
            self.session.take().expect("cancelled request session"),
            inject_pending_once,
        )
    }
}

impl Drop for CancelledRequest {
    fn drop(&mut self) {
        if let Some(mut session) = self.session.take() {
            session.quarantine();
        }
    }
}

struct ResetSession {
    identity: DeviceSessionIdentity,
    device_function: DeviceFunction,
    transport: Option<PciTransport>,
    queue: Option<Queue>,
    buffers: Option<Pin<Box<RequestBuffers>>>,
    published: bool,
    descriptor_popped: bool,
    completed: bool,
}

impl ResetSession {
    fn begin_reset(self, inject_pending_once: bool) -> ProductionResetTombstone {
        ProductionResetTombstone::new(self, inject_pending_once)
    }

    fn quarantine(&mut self) {
        quarantine(&mut self.queue);
        quarantine(&mut self.transport);
        quarantine(&mut self.buffers);
    }
}

/// A retained whole-device reset attempt.
#[must_use = "retry reset or retain the complete device and DMA owners"]
pub struct ProductionResetTombstone {
    session: ManuallyDrop<ResetSession>,
    inject_pending_once: bool,
}

impl ProductionResetTombstone {
    fn new(mut session: ResetSession, inject_pending_once: bool) -> Self {
        session
            .transport
            .as_mut()
            .expect("live transport")
            .set_status(DeviceStatus::empty());
        Self {
            session: ManuallyDrop::new(session),
            inject_pending_once,
        }
    }

    /// Returns the number of retained DMA pages.
    pub fn retained_dma_pages(&self) -> usize {
        dma::retained_pages(self.session.identity.device_generation)
    }

    /// Polls for reset acknowledgement, retaining this tombstone on timeout.
    pub fn retry_ack(mut self, root: &mut Root) -> Result<ProductionResetAck, Self> {
        if self.inject_pending_once {
            self.inject_pending_once = false;
            return Err(self);
        }
        let mut acknowledged = false;
        for _ in 0..POLL_LIMIT {
            if self
                .session
                .transport
                .as_ref()
                .expect("retained transport")
                .get_status()
                == DeviceStatus::empty()
            {
                acknowledged = true;
                break;
            }
            spin_loop();
        }
        if !acknowledged {
            return Err(self);
        }

        pci::disable_bus_master(root, self.session.device_function);
        let _ = self
            .session
            .transport
            .as_mut()
            .expect("retained transport")
            .ack_interrupt();
        let generation = self.session.identity.device_generation;
        // SAFETY: status zero and BUS_MASTER=false were observed for the exact
        // transport and generation above.
        let reset = unsafe { dma::acknowledge_device_reset(generation) };
        // SAFETY: all preceding fallible branches retained `self`; only the
        // acknowledged path extracts its complete reset session.
        let mut session = unsafe { ManuallyDrop::take(&mut self.session) };
        let queue = session.queue.take().expect("retained queue");
        // SAFETY: device reset was acknowledged and original buffers remain
        // pinned until the queue has been destroyed.
        unsafe { abandon_queue_after_reset(queue) };
        let closure_authority = dma::seal_queue_retirement(reset);
        drop(session.transport.take().expect("retained transport"));
        // SAFETY: queue and transport are both gone, so no raw BAR capability
        // pointer remains live.
        unsafe { pci::release_transport_claims() };
        assert_eq!(dma::retained_pages(generation), 3);

        Ok(ProductionResetAck {
            identity: session.identity,
            published: session.published,
            descriptor_popped: session.descriptor_popped,
            completed: session.completed,
            retained_dma_pages: 3,
            closure_authority,
            generation_applied: false,
        })
    }
}

/// Reset acknowledgement carrying the only IOTLB-closure authority.
#[must_use = "apply the generation fence and begin IOTLB closure"]
pub struct ProductionResetAck {
    identity: DeviceSessionIdentity,
    published: bool,
    descriptor_popped: bool,
    completed: bool,
    retained_dma_pages: usize,
    closure_authority: dma::DmaClosureAuthority,
    generation_applied: bool,
}

impl ProductionResetAck {
    /// Returns the closed request identity.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.identity
    }

    /// Reports whether `avail.idx` was published before reset.
    pub const fn was_published(&self) -> bool {
        self.published
    }

    /// Reports whether the matching descriptor chain was popped before reset.
    pub const fn was_descriptor_popped(&self) -> bool {
        self.descriptor_popped
    }

    /// Reports whether pop, response status, and share accounting all succeeded.
    pub const fn was_completed(&self) -> bool {
        self.completed
    }

    /// Returns the retained DMA page count.
    pub const fn retained_dma_pages(&self) -> usize {
        self.retained_dma_pages
    }
}

/// IOTLB completion progress for one reset generation.
#[must_use = "complete IOTLB closure or retain its tombstone"]
pub enum ProductionClosureProgress {
    /// All three owners completed invalidation.
    Complete(ProductionClosureReceipt),
    /// One owner remains pending or fail-closed.
    Pending(ProductionIotlbTombstone),
}

/// Retained IOTLB owner and retry authority.
#[must_use = "retry or retain the pending IOTLB owner"]
pub struct ProductionIotlbTombstone {
    identity: DeviceSessionIdentity,
    dma: dma::IotlbTombstone,
}

impl ProductionIotlbTombstone {
    /// Returns the retained request identity.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.identity
    }

    /// Returns all still-retained DMA pages.
    pub fn retained_pages(&self) -> usize {
        self.dma.retained_pages()
    }

    /// Reports whether OSTD retained a terminal invalidation failure.
    pub fn failure_retained(&self) -> bool {
        self.dma.failure_retained()
    }

    /// Polls the same retained owner with a bounded budget.
    pub fn retry(self, poll_budget: usize) -> ProductionClosureProgress {
        production_closure_progress(self.identity, self.dma.retry(poll_budget))
    }
}

/// Completed IOTLB receipt paired with a quiescence apply plan.
#[must_use = "publish hardware quiescence through the owning device"]
pub struct ProductionClosureReceipt {
    identity: DeviceSessionIdentity,
    dma: dma::ClosureReceipt,
    applied: bool,
}

impl ProductionClosureReceipt {
    /// Returns the closed request identity.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.identity
    }

    /// Returns the number of completed DMA owners.
    pub const fn completed_pages(&self) -> usize {
        self.dma.completed_pages()
    }
}

fn production_closure_progress(
    identity: DeviceSessionIdentity,
    progress: dma::ClosureProgress,
) -> ProductionClosureProgress {
    match progress {
        dma::ClosureProgress::Complete(dma) => {
            ProductionClosureProgress::Complete(ProductionClosureReceipt {
                identity,
                dma,
                applied: false,
            })
        }
        dma::ClosureProgress::Pending(dma) => {
            ProductionClosureProgress::Pending(ProductionIotlbTombstone { identity, dma })
        }
    }
}

/// Ends queue ownership after an acknowledged whole-device reset.
///
/// # Safety
///
/// The exact device must have status zero and BUS_MASTER=false, and all original
/// request buffers must remain pinned until this function returns.
unsafe fn abandon_queue_after_reset(queue: Queue) {
    drop(queue);
}

fn quarantine<T>(slot: &mut Option<T>) {
    if let Some(owner) = slot.take() {
        forget(owner);
    }
}
