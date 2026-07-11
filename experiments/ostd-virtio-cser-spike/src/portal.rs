// SPDX-License-Identifier: MPL-2.0

use alloc::boxed::Box;
use bitflags::bitflags;
use core::{
    hint::spin_loop,
    marker::PhantomPinned,
    mem::{ManuallyDrop, forget},
    pin::Pin,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectAuthority {
    pub request_id: u64,
    pub authority_epoch: u64,
    pub binding_epoch: u64,
    pub device_generation: u64,
}

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
pub struct BindingToken {
    epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PortalPhase {
    Active,
    ServiceUnavailable,
    Closing,
    Quiesced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    Completed,
    IndeterminateAfterReset,
    AbortedBeforeCommit,
}

impl Terminal {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Completed => "Completed",
            Self::IndeterminateAfterReset => "IndeterminateAfterReset",
            Self::AbortedBeforeCommit => "AbortedBeforeCommit",
        }
    }
}

pub struct Portal {
    authority_epoch: u64,
    binding_epoch: u64,
    device_generation: u64,
    next_request_id: u64,
    effects: [Option<EffectRecord>; 4],
    phase: PortalPhase,
    authority_advanced_for_rebind: bool,
    binding_advanced_for_rebind: bool,
}

#[derive(Clone, Copy)]
struct EffectRecord {
    authority: EffectAuthority,
    operation: Operation,
    committed: bool,
    terminal: Option<Terminal>,
}

impl Portal {
    pub const fn new() -> Self {
        Self {
            authority_epoch: 1,
            binding_epoch: 1,
            device_generation: 1,
            next_request_id: 1,
            effects: [const { None }; 4],
            phase: PortalPhase::Active,
            authority_advanced_for_rebind: false,
            binding_advanced_for_rebind: false,
        }
    }

    pub fn binding_token(&self) -> Result<BindingToken, RegisterError> {
        match self.phase {
            PortalPhase::Active => Ok(BindingToken {
                epoch: self.binding_epoch,
            }),
            PortalPhase::ServiceUnavailable | PortalPhase::Quiesced => {
                Err(RegisterError::ServiceUnavailable)
            }
            PortalPhase::Closing => Err(RegisterError::Closing),
        }
    }

    pub fn register(
        &mut self,
        binding: BindingToken,
        operation: Operation,
    ) -> Result<EffectAuthority, RegisterError> {
        if binding.epoch != self.binding_epoch {
            return Err(RegisterError::StaleBinding);
        }
        match self.phase {
            PortalPhase::Active => {}
            PortalPhase::ServiceUnavailable | PortalPhase::Quiesced => {
                return Err(RegisterError::ServiceUnavailable);
            }
            PortalPhase::Closing => return Err(RegisterError::Closing),
        }
        if operation == Operation::WriteSector0 {
            return Err(RegisterError::ReadOnly);
        }
        let authority = EffectAuthority {
            request_id: self.next_request_id,
            authority_epoch: self.authority_epoch,
            binding_epoch: self.binding_epoch,
            device_generation: self.device_generation,
        };
        self.next_request_id += 1;
        let slot = self
            .effects
            .iter_mut()
            .find(|record| record.is_none())
            .expect("bounded portal effect ledger is full");
        *slot = Some(EffectRecord {
            authority,
            operation,
            committed: false,
            terminal: None,
        });
        Ok(authority)
    }

    pub fn effect_count(&self) -> usize {
        self.effects.iter().flatten().count()
    }

    pub const fn next_request_id(&self) -> u64 {
        self.next_request_id
    }

    fn effect(&self, authority: EffectAuthority) -> Option<&EffectRecord> {
        self.effects
            .iter()
            .flatten()
            .find(|record| record.authority == authority)
    }

    fn effect_mut(&mut self, authority: EffectAuthority) -> Option<&mut EffectRecord> {
        self.effects
            .iter_mut()
            .flatten()
            .find(|record| record.authority == authority)
    }

    pub fn accepts_service_action(&self, authority: EffectAuthority) -> bool {
        self.phase == PortalPhase::Active
            && authority.authority_epoch == self.authority_epoch
            && authority.binding_epoch == self.binding_epoch
            && authority.device_generation == self.device_generation
            && self
                .effect(authority)
                .is_some_and(|record| record.terminal.is_none())
    }

    pub fn commit_effect<T>(
        &mut self,
        authority: EffectAuthority,
        publish: impl FnOnce() -> T,
    ) -> Option<T> {
        if !self.accepts_service_action(authority) {
            return None;
        }
        if self
            .effect(authority)
            .is_none_or(|record| record.committed || record.terminal.is_some())
        {
            return None;
        }
        let output = publish();
        let record = self.effect_mut(authority).expect("registered effect");
        assert_eq!(record.operation, Operation::ReadSector0);
        record.committed = true;
        Some(output)
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
        if session.authority() != authority
            || !self.accepts_service_action(authority)
            || self
                .effect(authority)
                .is_none_or(|record| !record.committed)
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
        authority.device_generation == self.device_generation
            && self
                .effect(authority)
                .is_some_and(|record| record.committed && record.terminal.is_none())
    }

    pub fn complete_device(&mut self, authority: EffectAuthority) -> bool {
        if !self.accepts_device_completion(authority) {
            return false;
        }
        self.effect_mut(authority)
            .expect("registered effect")
            .terminal = Some(Terminal::Completed);
        true
    }

    /// Linearizes a whole-device reset acknowledgement. Old-generation
    /// completion is fenced first; every still-committed effect in that
    /// generation then receives exactly one indeterminate terminal state.
    pub fn acknowledge_reset(&mut self, reset: &ResetAck) -> usize {
        let generation = reset.authority.device_generation;
        assert_eq!(self.phase, PortalPhase::Closing);
        assert_eq!(self.device_generation, generation);
        assert!(
            self.effect(reset.authority).is_some(),
            "reset receipt belongs to a registered portal effect"
        );
        self.device_generation += 1;
        let mut terminalized = 0;
        for record in self.effects.iter_mut().flatten() {
            if record.authority.device_generation == generation
                && record.committed
                && record.terminal.is_none()
            {
                record.terminal = Some(Terminal::IndeterminateAfterReset);
                terminalized += 1;
            }
        }
        assert_eq!(self.terminal(reset.authority), Some(reset.terminal));
        terminalized
    }

    pub fn terminal(&self, authority: EffectAuthority) -> Option<Terminal> {
        self.effect(authority).and_then(|record| record.terminal)
    }

    pub fn rebind_after_quiescence(&mut self) {
        assert_eq!(self.phase, PortalPhase::Quiesced);
        if !self.authority_advanced_for_rebind {
            self.authority_epoch += 1;
        }
        self.authority_advanced_for_rebind = false;
        if !self.binding_advanced_for_rebind {
            self.binding_epoch += 1;
        }
        self.binding_advanced_for_rebind = false;
        self.phase = PortalPhase::Active;
    }

    pub fn crash_service(&mut self) -> (u64, u64) {
        assert_eq!(self.phase, PortalPhase::Active);
        let old = self.binding_epoch;
        self.binding_epoch += 1;
        self.binding_advanced_for_rebind = true;
        self.phase = PortalPhase::ServiceUnavailable;
        (old, self.binding_epoch)
    }

    pub fn begin_closing(&mut self) -> usize {
        assert!(matches!(
            self.phase,
            PortalPhase::Active | PortalPhase::ServiceUnavailable
        ));
        self.phase = PortalPhase::Closing;
        self.authority_epoch += 1;
        self.authority_advanced_for_rebind = true;
        let mut aborted = 0;
        for record in self.effects.iter_mut().flatten() {
            if record.authority.device_generation == self.device_generation
                && !record.committed
                && record.terminal.is_none()
            {
                record.terminal = Some(Terminal::AbortedBeforeCommit);
                aborted += 1;
            }
        }
        aborted
    }

    pub fn mark_quiesced(&mut self, closure: dma::ClosureReceipt) {
        let closed_generation = closure.generation();
        assert_eq!(self.phase, PortalPhase::Closing);
        assert_eq!(self.device_generation, closed_generation + 1);
        self.phase = PortalPhase::Quiesced;
    }

    pub const fn binding_epoch(&self) -> u64 {
        self.binding_epoch
    }

    pub const fn device_generation(&self) -> u64 {
        self.device_generation
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
    pub fn open(
        root: &mut Root,
        device_function: DeviceFunction,
        authority: EffectAuthority,
    ) -> Self {
        pci::enable_device(root, device_function);
        dma::begin_generation(authority.device_generation);
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
        dma::mark_queue_exposed(authority.device_generation);
        queue.set_dev_notify(false);
        transport.finish_init();
        assert!(transport.get_status().contains(DeviceStatus::DRIVER_OK));

        let (request_paddr, request_daddr) = dma::arm_request_bounce(authority.device_generation);
        assert_ne!(request_paddr, request_daddr);
        assert_eq!(dma::retained_pages(authority.device_generation), 3);

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
            dma::request_share_counts(self.authority.device_generation),
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
            dma::request_share_counts(self.authority.device_generation),
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
        assert!(current_binding_epoch > self.authority.binding_epoch);
        self.submission_gate_open = false;
    }

    pub fn submit_reset(mut self, inject_pending_once: bool) -> ResetTombstone {
        self.submission_gate_open = false;
        self.transport
            .as_mut()
            .expect("live transport")
            .set_status(DeviceStatus::empty());
        ResetTombstone {
            session: ManuallyDrop::new(self),
            inject_pending_once,
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
}

impl ResetTombstone {
    pub fn retained_dma_pages(&self) -> usize {
        dma::retained_pages(self.session.authority.device_generation)
    }

    pub fn retry_ack(mut self, root: &mut Root) -> Result<ResetAck, Self> {
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
        let _isr_status = self
            .session
            .transport
            .as_mut()
            .expect("retained transport")
            .ack_interrupt();
        let generation = self.session.authority.device_generation;
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
        let retained_dma_pages = dma::retained_pages(session.authority.device_generation);
        assert_eq!(retained_dma_pages, 3);

        Ok(ResetAck {
            authority: session.authority,
            terminal,
            retained_dma_pages,
            isr_read: true,
            closure_authority,
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

    pub fn into_closure_authority(self) -> dma::DmaClosureAuthority {
        self.closure_authority
    }
}
