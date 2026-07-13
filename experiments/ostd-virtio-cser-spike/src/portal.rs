// SPDX-License-Identifier: MPL-2.0

use alloc::boxed::Box;
use bitflags::bitflags;
use core::{
    convert::Infallible,
    hint::spin_loop,
    marker::PhantomPinned,
    mem::{ManuallyDrop, forget},
    pin::Pin,
};
use cser_transition_gates::io::{
    CloseReceipt as GateCloseReceipt, IoBinding, IoCommitError, IoCommitReceipt, IoError, IoGate,
    IoIdentity, IoStateProjection, IoTerminal, IotlbAttempt as GateIotlbAttempt,
    IotlbProgress as GateIotlbProgress, IotlbTombstone as GateIotlbTombstone,
    QuiescenceReceipt as GateQuiescenceReceipt, ResetAttempt as GateResetAttempt,
    ResetOutcome as GateResetOutcome, ResetReceipt as GateResetReceipt,
    ResetTombstone as GateResetTombstone,
};
use zerocopy::IntoBytes;

use virtio_drivers::{
    device::blk::{BlkReq, BlkResp, RespStatus, SECTOR_SIZE},
    queue::VirtQueue,
    transport::{
        DeviceStatus, DeviceType, Transport,
        pci::{PciTransport, bus::DeviceFunction},
    },
};

use crate::{
    dma::{self, OstdHal},
    pci::{self, Root},
};

const QUEUE_INDEX: u16 = 0;
const QUEUE_SIZE: usize = 16;
const POLL_LIMIT: usize = 10_000_000;
const PORTAL_INSTANCE_NAMESPACE: u64 = 0x4e58_4956_0000_0000;

/// Encodes the owned PCI function and queue in the caller-allocated IoGate
/// namespace. The spike admits one live Portal per `(BDF, queue)`, so this ID
/// is stable for that device and unique among receipts that can meet here.
fn portal_instance_id(device_function: DeviceFunction) -> u64 {
    assert!(
        device_function.valid(),
        "invalid PCI device function namespace"
    );
    PORTAL_INSTANCE_NAMESPACE
        | (u64::from(device_function.bus) << 24)
        | (u64::from(device_function.device) << 19)
        | (u64::from(device_function.function) << 16)
        | u64::from(QUEUE_INDEX)
}

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

pub type EffectAuthority = IoIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    ReadSector0,
    WriteSector0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterError {
    ReadOnly,
    StaleBinding,
    ServiceUnavailable,
    Closing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionOpenError {
    ForeignInstance,
    InvalidAuthority,
}

/// Linear evidence that the two-BDF namespace negative completed before any
/// real PCI or DMA authority was created.  The marker is available only after
/// the assertions below return successfully.
#[must_use = "publish the pre-PCI namespace-isolation marker"]
pub struct SessionNamespaceIsolationReceipt {
    marker: &'static str,
}

impl SessionNamespaceIsolationReceipt {
    pub const fn into_marker(self) -> &'static str {
        self.marker
    }
}

pub type BindingToken = IoBinding;
pub type Terminal = IoTerminal;

pub const fn terminal_label(terminal: Terminal) -> &'static str {
    match terminal {
        Terminal::Completed => "Completed",
        Terminal::IndeterminateAfterReset => "IndeterminateAfterReset",
        Terminal::AbortedBeforeCommit => "AbortedBeforeCommit",
    }
}

pub struct Portal {
    device_function: DeviceFunction,
    gate: IoGate<4>,
    operations: [Option<(EffectAuthority, Operation)>; 4],
    commits: [Option<(EffectAuthority, IoCommitReceipt)>; 4],
    pending_close: Option<GateCloseReceipt>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PortalStateProjection {
    device_function: DeviceFunction,
    gate: IoStateProjection<4>,
    operations: [Option<(EffectAuthority, Operation)>; 4],
    commits: [Option<(EffectAuthority, IoCommitReceipt)>; 4],
    pending_close: Option<GateCloseReceipt>,
}

struct SessionBinding {
    device_function: DeviceFunction,
    authority: EffectAuthority,
}

impl Portal {
    pub fn new(device_function: DeviceFunction) -> Self {
        let instance_id = portal_instance_id(device_function);
        Self {
            device_function,
            gate: IoGate::new(instance_id)
                .expect("non-empty portal transition ledger with non-zero instance namespace"),
            operations: [None; 4],
            commits: [None; 4],
            pending_close: None,
        }
    }

    fn state_projection(&self) -> PortalStateProjection {
        PortalStateProjection {
            device_function: self.device_function,
            gate: self.gate.state_projection(),
            operations: self.operations,
            commits: self.commits,
            pending_close: self.pending_close,
        }
    }

    fn bind_session_authority(
        &self,
        authority: EffectAuthority,
    ) -> Result<SessionBinding, SessionOpenError> {
        if authority.instance_id() != self.gate.instance_id()
            || portal_instance_id(self.device_function) != self.gate.instance_id()
        {
            return Err(SessionOpenError::ForeignInstance);
        }
        if !self.gate.accepts_service_action(authority) {
            return Err(SessionOpenError::InvalidAuthority);
        }
        Ok(SessionBinding {
            device_function: self.device_function,
            authority,
        })
    }

    /// Opens the only hardware session named by this portal after validating
    /// the effect authority, BDF, and queue instance. The validation completes
    /// before `Session::open_bound` can enable PCI or allocate DMA state.
    pub fn open_session(
        &self,
        root: &mut Root,
        authority: EffectAuthority,
    ) -> Result<Session, SessionOpenError> {
        let binding = self.bind_session_authority(authority)?;
        Ok(Session::open_bound(root, binding))
    }

    pub fn binding_token(&self) -> Result<BindingToken, RegisterError> {
        match self.gate.binding_token() {
            Ok(binding) => Ok(binding),
            Err(IoError::Closing) => Err(RegisterError::Closing),
            Err(IoError::ServiceUnavailable) => Err(RegisterError::ServiceUnavailable),
            Err(error) => panic!("unexpected binding-token gate error: {error:?}"),
        }
    }

    pub fn register(
        &mut self,
        binding: BindingToken,
        operation: Operation,
    ) -> Result<EffectAuthority, RegisterError> {
        if operation == Operation::WriteSector0 {
            return Err(RegisterError::ReadOnly);
        }
        let authority = match self.gate.register(binding) {
            Ok(authority) => authority,
            Err(IoError::StaleBinding) => return Err(RegisterError::StaleBinding),
            Err(IoError::ServiceUnavailable) => return Err(RegisterError::ServiceUnavailable),
            Err(IoError::Closing) => return Err(RegisterError::Closing),
            Err(error) => panic!("unexpected register gate error: {error:?}"),
        };
        let slot = self
            .operations
            .iter_mut()
            .find(|record| record.is_none())
            .expect("operation metadata matches bounded transition ledger");
        *slot = Some((authority, operation));
        Ok(authority)
    }

    pub fn effect_count(&self) -> usize {
        self.gate.projection().effect_count
    }

    pub fn next_request_id(&self) -> u64 {
        self.gate.next_request_id()
    }

    fn operation(&self, authority: EffectAuthority) -> Option<Operation> {
        self.operations
            .iter()
            .flatten()
            .find_map(|(registered, operation)| (*registered == authority).then_some(*operation))
    }

    fn commit_receipt(&self, authority: EffectAuthority) -> Option<IoCommitReceipt> {
        self.commits
            .iter()
            .flatten()
            .find_map(|(registered, receipt)| (*registered == authority).then_some(*receipt))
    }

    pub fn accepts_service_action(&self, authority: EffectAuthority) -> bool {
        self.gate.accepts_service_action(authority)
    }

    pub fn commit_effect<T>(
        &mut self,
        authority: EffectAuthority,
        publish: impl FnOnce() -> T,
    ) -> Option<T> {
        assert_eq!(self.operation(authority), Some(Operation::ReadSector0));
        match self
            .gate
            .commit_with(authority, || Ok::<T, Infallible>(publish()))
        {
            Ok((receipt, output)) => {
                let slot = self
                    .commits
                    .iter_mut()
                    .find(|record| record.is_none())
                    .expect("commit receipts fit bounded transition ledger");
                *slot = Some((authority, receipt));
                Some(output)
            }
            Err(IoCommitError::Gate(_)) => None,
            Err(IoCommitError::Publication(never)) => match never {},
        }
    }

    pub fn commit_session(
        &mut self,
        authority: EffectAuthority,
        session: &mut Session,
    ) -> Option<u16> {
        if session.authority() != authority {
            return None;
        }
        self.commit_effect(authority, || session.commit())
    }

    pub fn notify_effect(&self, authority: EffectAuthority, session: &mut Session) -> bool {
        let Some(receipt) = self.commit_receipt(authority) else {
            return false;
        };
        if session.authority() != authority || self.gate.accept_notify(authority, receipt).is_err()
        {
            return false;
        }
        session.notify();
        true
    }

    /// Device completion belongs to the committed kernel/device effect, not
    /// to the crashed service binding. It is fenced by registration, terminal
    /// state and device generation.
    pub fn accepts_device_completion(&self, authority: EffectAuthority) -> bool {
        self.gate.can_complete_device(authority)
    }

    pub fn complete_device(&mut self, authority: EffectAuthority) -> bool {
        self.gate.complete_device(authority).is_ok()
    }

    /// Linearizes a whole-device reset acknowledgement. Old-generation
    /// completion is fenced first; every still-committed effect in that
    /// generation then receives exactly one indeterminate terminal state.
    pub fn acknowledge_reset(&mut self, reset: &mut ResetAck) -> usize {
        let receipt = reset
            .gate_receipt
            .take()
            .expect("reset acknowledgement carries one transition receipt");
        let outcome = self
            .gate
            .apply_reset(receipt)
            .expect("hardware reset receipt matches the closing generation");
        reset.gate_outcome = Some(outcome);
        assert_eq!(self.terminal(reset.authority), Some(reset.terminal));
        outcome.terminalized()
    }

    pub fn terminal(&self, authority: EffectAuthority) -> Option<Terminal> {
        self.gate.terminal(authority)
    }

    pub fn rebind_after_quiescence(&mut self) {
        self.gate
            .rebind_after_quiescence()
            .expect("IOTLB quiescence precedes portal rebind");
    }

    pub fn crash_service(&mut self) -> (u64, u64) {
        let receipt = self
            .gate
            .crash_service()
            .expect("service crash starts from active phase");
        (receipt.previous_binding_epoch(), receipt.binding_epoch())
    }

    pub fn begin_closing(&mut self) -> usize {
        let receipt = self
            .gate
            .begin_closing()
            .expect("portal close starts from active or unavailable phase");
        let aborted = receipt.aborted();
        self.pending_close = Some(receipt);
        aborted
    }

    pub fn submit_reset(&mut self, session: Session, inject_pending_once: bool) -> ResetTombstone {
        let close = self
            .pending_close
            .take()
            .expect("begin_closing supplies one reset authority");
        let reset = self
            .gate
            .begin_reset(close)
            .expect("reset begins for the exact closing generation");
        session.submit_reset(inject_pending_once, reset)
    }

    pub fn begin_iotlb(&mut self, reset: ResetAck, inject_one_pending: bool) -> ClosureProgress {
        let outcome = reset
            .gate_outcome
            .expect("portal applies reset before IOTLB closure");
        let gate = self
            .gate
            .begin_iotlb::<3>(outcome)
            .expect("IOTLB attempt matches the reset outcome");
        gate_closure_progress(
            dma::begin_closure(reset.closure_authority, inject_one_pending),
            gate,
        )
    }

    pub fn mark_quiesced(&mut self, closure: ClosureReceipt) {
        assert_eq!(closure.dma.completed_pages(), closure.gate.completed());
        assert_eq!(closure.dma.generation(), closure.gate.generation());
        self.gate
            .mark_quiesced(closure.gate)
            .expect("all retained DMA owners complete before quiescence");
    }

    pub fn binding_epoch(&self) -> u64 {
        self.gate.projection().binding_epoch
    }

    pub fn device_generation(&self) -> u64 {
        self.gate.projection().device_generation
    }
}

/// Exercises the pure authority-to-hardware preflight without touching a PCI
/// root or the DMA ledger. Both foreign directions must fail with the complete
/// semantic state of both portals unchanged.
pub fn assert_session_namespace_isolation() -> SessionNamespaceIsolationReceipt {
    const LEFT_DEVICE: DeviceFunction = DeviceFunction {
        bus: 0,
        device: 5,
        function: 0,
    };
    const RIGHT_DEVICE: DeviceFunction = DeviceFunction {
        bus: 0,
        device: 6,
        function: 0,
    };
    assert!(LEFT_DEVICE.valid());
    assert!(RIGHT_DEVICE.valid());
    assert_ne!(LEFT_DEVICE, RIGHT_DEVICE);

    let mut left = Portal::new(LEFT_DEVICE);
    let mut right = Portal::new(RIGHT_DEVICE);
    let left_authority = left
        .register(left.binding_token().unwrap(), Operation::ReadSector0)
        .unwrap();
    let right_authority = right
        .register(right.binding_token().unwrap(), Operation::ReadSector0)
        .unwrap();
    assert_ne!(left_authority.instance_id(), right_authority.instance_id());

    let left_before = left.state_projection();
    let right_before = right.state_projection();
    assert_eq!(
        left.bind_session_authority(right_authority).map(|_| ()),
        Err(SessionOpenError::ForeignInstance)
    );
    assert_eq!(left.state_projection(), left_before);
    assert_eq!(right.state_projection(), right_before);
    assert_eq!(
        right.bind_session_authority(left_authority).map(|_| ()),
        Err(SessionOpenError::ForeignInstance)
    );
    assert_eq!(left.state_projection(), left_before);
    assert_eq!(right.state_projection(), right_before);

    let own = left.bind_session_authority(left_authority).unwrap();
    assert_eq!(own.device_function, LEFT_DEVICE);
    assert_eq!(own.authority, left_authority);
    assert_eq!(left.state_projection(), left_before);
    assert_eq!(right.state_projection(), right_before);
    SessionNamespaceIsolationReceipt {
        marker: "IO Namespace foreign_bdf_rejected=true bidirectional=true portal_state_unchanged=true pre_pci_dma=true",
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

type Queue = VirtQueue<OstdHal, QUEUE_SIZE>;

/// Ends the pinned-buffer obligation for an unpopped descriptor chain after a
/// whole-device reset acknowledgement. The exact pinned VirtQueue 0.13 source
/// has no request-buffer Drop access; destroying the queue only drops its two
/// queue-DMA objects.
///
/// # Safety
///
/// The caller must have observed device status zero, disabled bus mastering,
/// and kept every original request buffer pinned until this function returns.
unsafe fn abandon_queue_after_reset(queue: Queue) {
    drop(queue);
}

pub struct Session {
    authority: EffectAuthority,
    device_function: DeviceFunction,
    transport: Option<PciTransport>,
    queue: Option<Queue>,
    buffers: Option<Pin<Box<RequestBuffers>>>,
    token: Option<u16>,
    committed: bool,
    notify_sent: bool,
    submission_gate_open: bool,
    terminal: Option<Terminal>,
}

impl Session {
    fn open_bound(root: &mut Root, binding: SessionBinding) -> Self {
        let SessionBinding {
            device_function,
            authority,
        } = binding;
        pci::enable_device(root, device_function);
        dma::begin_generation(authority.device_generation());
        pci::begin_transport_claims();

        let mut transport =
            PciTransport::new::<OstdHal, _>(root, device_function).expect("open PCI transport");
        assert_eq!(transport.device_type(), DeviceType::Block);
        let negotiated = transport.begin_init(REQUIRED_FEATURES);
        assert_eq!(negotiated, REQUIRED_FEATURES);
        assert!(
            transport.get_status().contains(DeviceStatus::FEATURES_OK),
            "device rejected required features"
        );

        let mut queue = Queue::new(&mut transport, QUEUE_INDEX, false, false)
            .expect("create mediated VirtIO queue");
        dma::mark_queue_exposed(authority.device_generation());
        queue.set_dev_notify(false);
        transport.finish_init();
        assert!(transport.get_status().contains(DeviceStatus::DRIVER_OK));

        let (request_paddr, request_daddr) = dma::arm_request_bounce(authority.device_generation());
        assert_ne!(request_paddr, request_daddr);
        assert_eq!(dma::retained_pages(authority.device_generation()), 3);

        Self {
            authority,
            device_function,
            transport: Some(transport),
            queue: Some(queue),
            buffers: Some(Box::pin(RequestBuffers::new())),
            token: None,
            committed: false,
            notify_sent: false,
            submission_gate_open: true,
            terminal: None,
        }
    }

    pub const fn authority(&self) -> EffectAuthority {
        self.authority
    }

    fn commit(&mut self) -> u16 {
        assert!(self.submission_gate_open);
        assert!(!self.committed);
        let queue = self.queue.as_mut().expect("live queue");
        // SAFETY: only fields are borrowed; the `RequestBuffers` allocation is
        // never moved out of its pin while a descriptor can refer to it.
        let buffers = unsafe {
            self.buffers
                .as_mut()
                .expect("pinned request buffers")
                .as_mut()
                .get_unchecked_mut()
        };
        let RequestBuffers {
            request,
            data,
            response,
            _pin: _,
        } = buffers;
        let inputs = [request.as_bytes()];
        let mut outputs: [&mut [u8]; 2] = [&mut data[..], response.as_mut_bytes()];
        // SAFETY: all three buffers are fields of this session and remain
        // inaccessible and alive until matching pop or reset acknowledgement.
        let token = unsafe { queue.add(&inputs, &mut outputs) }.expect("publish request");
        self.token = Some(token);
        self.committed = true;
        assert_eq!(
            dma::request_share_counts(self.authority.device_generation()),
            (3, 0)
        );
        token
    }

    fn notify(&mut self) {
        assert!(self.submission_gate_open);
        assert!(self.committed);
        assert!(!self.notify_sent);
        assert!(
            self.queue.as_ref().expect("live queue").should_notify(),
            "deterministic device should request a queue kick"
        );
        self.transport
            .as_mut()
            .expect("live transport")
            .notify(QUEUE_INDEX);
        self.notify_sent = true;
    }

    pub fn poll_completion(&mut self) -> u32 {
        assert!(self.committed);
        assert!(self.notify_sent);
        let expected = self.token.expect("commit token");
        let mut observed = None;
        for _ in 0..POLL_LIMIT {
            if let Some(token) = self.queue.as_ref().expect("live queue").peek_used() {
                observed = Some(token);
                break;
            }
            spin_loop();
        }
        assert_eq!(observed, Some(expected), "VirtIO completion deadline");

        let queue = self.queue.as_mut().expect("live queue");
        // SAFETY: this only obtains field borrows from the same stable pinned
        // allocation used by `commit`; no field is moved.
        let buffers = unsafe {
            self.buffers
                .as_mut()
                .expect("pinned request buffers")
                .as_mut()
                .get_unchecked_mut()
        };
        let RequestBuffers {
            request,
            data,
            response,
            _pin: _,
        } = buffers;
        let inputs = [request.as_bytes()];
        let mut outputs: [&mut [u8]; 2] = [&mut data[..], response.as_mut_bytes()];
        // SAFETY: token and buffers exactly match the successful `add` call.
        let used_len = unsafe { queue.pop_used(expected, &inputs, &mut outputs) }
            .expect("pop matching VirtIO completion");
        assert_eq!(response.status(), RespStatus::OK);
        assert_eq!(
            dma::request_share_counts(self.authority.device_generation()),
            (3, 3)
        );
        self.terminal = Some(Terminal::Completed);
        used_len
    }

    pub fn data(&self) -> &[u8; SECTOR_SIZE] {
        assert_eq!(self.terminal, Some(Terminal::Completed));
        &self
            .buffers
            .as_ref()
            .expect("pinned request buffers")
            .as_ref()
            .get_ref()
            .data
    }

    pub const fn notify_sent(&self) -> bool {
        self.notify_sent
    }

    pub const fn committed(&self) -> bool {
        self.committed
    }

    pub fn close_after_service_crash(&mut self, current_binding_epoch: u64) {
        assert!(self.committed);
        assert!(current_binding_epoch > self.authority.binding_epoch());
        self.submission_gate_open = false;
    }

    fn submit_reset(
        mut self,
        inject_pending_once: bool,
        gate_attempt: GateResetAttempt,
    ) -> ResetTombstone {
        self.submission_gate_open = false;
        self.transport
            .as_mut()
            .expect("live transport")
            .set_status(DeviceStatus::empty());
        ResetTombstone {
            session: ManuallyDrop::new(self),
            inject_pending_once,
            gate_attempt: Some(gate_attempt),
            gate_tombstone: None,
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.transport.is_none() && self.queue.is_none() {
            return;
        }

        // A live or partially initialized device session has no implicit safe
        // destructor. Quarantine all objects and pinned original buffers; the
        // static DMA ledger likewise refuses release before reset ack.
        if let Some(queue) = self.queue.take() {
            forget(queue);
        }
        if let Some(transport) = self.transport.take() {
            forget(transport);
        }
        if let Some(buffers) = self.buffers.take() {
            forget(buffers);
        }
    }
}

#[must_use = "dropping a reset tombstone intentionally retains all device and DMA owners"]
pub struct ResetTombstone {
    session: ManuallyDrop<Session>,
    inject_pending_once: bool,
    gate_attempt: Option<GateResetAttempt>,
    gate_tombstone: Option<GateResetTombstone>,
}

impl ResetTombstone {
    pub fn retained_dma_pages(&self) -> usize {
        dma::retained_pages(self.session.authority.device_generation())
    }

    pub fn retry_ack(mut self, root: &mut Root) -> Result<ResetAck, Self> {
        if self.gate_attempt.is_none() {
            self.gate_attempt = Some(
                self.gate_tombstone
                    .take()
                    .expect("pending reset retains its transition tombstone")
                    .retry(),
            );
        }
        if self.inject_pending_once {
            self.inject_pending_once = false;
            self.gate_tombstone = Some(
                self.gate_attempt
                    .take()
                    .expect("live reset transition attempt")
                    .retain(),
            );
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
            self.gate_tombstone = Some(
                self.gate_attempt
                    .take()
                    .expect("live reset transition attempt")
                    .retain(),
            );
            return Err(self);
        }

        pci::disable_bus_master(root, self.session.device_function);
        let _isr_status = self
            .session
            .transport
            .as_mut()
            .expect("retained transport")
            .ack_interrupt();
        let generation = self.session.authority.device_generation();
        // SAFETY: status zero was observed for this exact transport above and
        // BUS_MASTER was synchronously disabled for its exact PCI function.
        let reset = unsafe { dma::acknowledge_device_reset(generation) };

        // SAFETY: all fallible/asserting reset-closure steps above leave the
        // owner inside `ManuallyDrop`. Only the acknowledged path extracts it.
        let mut session = unsafe { ManuallyDrop::take(&mut self.session) };

        let terminal = session.terminal.unwrap_or(if session.committed {
            Terminal::IndeterminateAfterReset
        } else {
            Terminal::AbortedBeforeCommit
        });
        let queue = session.queue.take().expect("retained queue");
        // SAFETY: status zero and BUS_MASTER=false were observed above, and
        // `session.buffers` remains pinned until after this queue is gone.
        unsafe { abandon_queue_after_reset(queue) };
        let closure_authority = dma::seal_queue_retirement(reset);
        let transport = session.transport.take().expect("retained transport");
        drop(transport);
        // SAFETY: the old queue and transport have both been destroyed, so no
        // raw pointer into any claimed VirtIO capability range remains live.
        unsafe { pci::release_transport_claims() };
        let retained_dma_pages = dma::retained_pages(session.authority.device_generation());
        assert_eq!(retained_dma_pages, 3);

        Ok(ResetAck {
            authority: session.authority,
            terminal,
            retained_dma_pages,
            isr_read: true,
            closure_authority,
            gate_receipt: Some(
                self.gate_attempt
                    .take()
                    .expect("acknowledged reset transition attempt")
                    .acknowledge(),
            ),
            gate_outcome: None,
        })
    }
}

#[must_use = "reset acknowledgement carries the only DMA closure authority"]
pub struct ResetAck {
    authority: EffectAuthority,
    terminal: Terminal,
    retained_dma_pages: usize,
    isr_read: bool,
    closure_authority: dma::DmaClosureAuthority,
    gate_receipt: Option<GateResetReceipt>,
    gate_outcome: Option<GateResetOutcome>,
}

impl ResetAck {
    pub const fn authority(&self) -> EffectAuthority {
        self.authority
    }

    pub const fn terminal(&self) -> Terminal {
        self.terminal
    }

    pub const fn retained_dma_pages(&self) -> usize {
        self.retained_dma_pages
    }

    pub const fn isr_read(&self) -> bool {
        self.isr_read
    }
}

#[must_use = "IOTLB closure must complete or retain both hardware and transition tombstones"]
pub enum ClosureProgress {
    Complete(ClosureReceipt),
    Pending(IotlbTombstone),
}

#[must_use = "dropping an IOTLB tombstone intentionally retains the transition authority"]
pub struct IotlbTombstone {
    dma: dma::IotlbTombstone,
    gate: GateIotlbTombstone<3>,
}

impl IotlbTombstone {
    pub fn retained_pages(&self) -> usize {
        self.dma.retained_pages()
    }

    pub const fn pending_kind(&self) -> dma::OwnerKind {
        self.dma.pending_kind()
    }

    pub fn failure_retained(&self) -> bool {
        self.dma.failure_retained()
    }

    pub fn retry(self, poll_budget: usize) -> ClosureProgress {
        gate_closure_progress(self.dma.retry(poll_budget), self.gate.retry())
    }
}

#[must_use = "the combined hardware and transition receipt must publish portal quiescence"]
pub struct ClosureReceipt {
    dma: dma::ClosureReceipt,
    gate: GateQuiescenceReceipt,
}

impl ClosureReceipt {
    pub const fn generation(&self) -> u64 {
        self.dma.generation()
    }

    pub const fn completed_pages(&self) -> usize {
        self.dma.completed_pages()
    }
}

fn gate_closure_progress(dma: dma::ClosureProgress, gate: GateIotlbAttempt<3>) -> ClosureProgress {
    match dma {
        dma::ClosureProgress::Pending(dma) => ClosureProgress::Pending(IotlbTombstone {
            dma,
            gate: gate.retain(),
        }),
        dma::ClosureProgress::Complete(dma) => {
            let gate = match gate
                .owner_complete(0)
                .expect("request owner completes once")
            {
                GateIotlbProgress::Pending(gate) => gate,
                GateIotlbProgress::Complete(_) => unreachable!(),
            };
            let gate = match gate
                .owner_complete(1)
                .expect("driver-ring owner completes once")
            {
                GateIotlbProgress::Pending(gate) => gate,
                GateIotlbProgress::Complete(_) => unreachable!(),
            };
            let gate = match gate
                .owner_complete(2)
                .expect("device-ring owner completes once")
            {
                GateIotlbProgress::Complete(receipt) => receipt,
                GateIotlbProgress::Pending(_) => unreachable!(),
            };
            ClosureProgress::Complete(ClosureReceipt { dma, gate })
        }
    }
}
