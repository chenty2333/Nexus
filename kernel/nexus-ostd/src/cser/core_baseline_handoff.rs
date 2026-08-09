// SPDX-License-Identifier: MPL-2.0

//! Portable strongest-finalizer baseline for one discovered child handoff.
//!
//! This is intentionally a *workload-specific coordinator upper bound*, not
//! a CSER implementation and not a production adapter.  It independently
//! parses the fixed `NXSCHD03` descriptor and persists the complete handoff
//! record in one candidate-copy operation at every phase.  In particular it
//! does not import `Engine`, catalog authority, verified descriptors, claims,
//! or reuse permits from `cser-core`.

extern crate alloc;

use cser_core::{
    ClaimId, Digest, EffectId, ExternalOutcome, ResourceGeneration, ResourceId, RootId,
};
use sha2::{Digest as _, Sha256};

use super::{
    core_pio_journal::{AtaDoubleBank, AtaDoubleBankError, AtaJournalFixture, AtaPioError},
    core_tool_adapter::{DurableToolObservation, ToolOperationPlan},
    core_tool_uart::{ToolRunId, ToolV2Identity},
    core_tpm_anchor::{
        ExperimentAnchorSnapshot, ExperimentNvAnchor, ExperimentNvAnchorError, ExperimentNvLayout,
        QemuTisTpm2, TisTpmError, TpmNvIndexAuth,
    },
};

const DESCRIPTOR_LEN: usize = 187;
const DESCRIPTOR_MAGIC: &[u8; 8] = b"NXSCHD03";
const DURABLE_MAGIC: [u8; 8] = *b"NXSBHD01";
const DURABLE_VERSION: u16 = 1;
/// A fixed image keeps the independent ATA record easy to bound and audit.
/// It deliberately stores binding digests rather than Rust private structs.
pub(crate) const HANDOFF_DURABLE_RECORD_BYTES: usize = 4096;
const BINDING_BYTES: usize = 1024;
const SOURCE_BINDING_OFFSET: usize = 20;
const DESCRIPTOR_OFFSET: usize = SOURCE_BINDING_OFFSET + BINDING_BYTES;
const SOURCE_TERMINAL_OFFSET: usize = DESCRIPTOR_OFFSET + DESCRIPTOR_LEN;
const CHILD_BINDING_OFFSET: usize = SOURCE_TERMINAL_OFFSET + 32;
const CHILD_TERMINAL_OFFSET: usize = CHILD_BINDING_OFFSET + BINDING_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandoffPhase {
    /// The parent operation identity is durable before any child POST may be
    /// attempted.  It is not terminal evidence and retains its coordinate.
    ParentIntentDurable,
    DescriptorDurable,
    ChildPrepared,
    ParentReleasedChildIntentDurable,
    ChildTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandoffError {
    InvalidDescriptor,
    SourceMismatch,
    ChildMismatch,
    ParentNotReleased,
    ChildNotPrepared,
    ChildAlreadyTerminal,
    ConflictRetained,
    InvalidPermit,
    Persist,
}

/// Exact opaque resource coordinate retained until the *child* terminal
/// observation is durably recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HandoffClaimCoordinate {
    pub(crate) resource: u64,
    pub(crate) generation: u64,
}

/// Canonical, fixed-width operation binding retained by the independent
/// baseline.  This is intentionally an on-disk contract, not a serialized
/// `ToolOperationPlan`: no private adapter state or CSER verifier authority is
/// recovered from the ATA medium.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DurableOperationBinding {
    pub(crate) run_id: [u8; 16],
    pub(crate) root: u64,
    pub(crate) sequence: u64,
    pub(crate) component: u32,
    pub(crate) claim: u64,
    pub(crate) coordinate: HandoffClaimCoordinate,
    pub(crate) catalog_digest: [u8; 32],
    pub(crate) operation_key: [u8; 32],
    pub(crate) payload_digest: [u8; 32],
    pub(crate) operation_digest: [u8; 32],
    payload: [u8; 576],
    payload_len: u16,
    transport: Option<DurableTransportIdentity>,
    cser3_bound: bool,
    cser3_output: bool,
    child_route: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DurableTransportIdentity {
    namespace: [u8; 128],
    namespace_len: u8,
    authority: [u8; 16],
    effect: [u8; 16],
    catalog_digest: [u8; 32],
}

impl DurableOperationBinding {
    fn from_plan(plan: ToolOperationPlan) -> Self {
        let mut payload = [0; 576];
        payload[..plan.payload().len()].copy_from_slice(plan.payload());
        let transport = plan.transport_identity().map(|identity| {
            let mut namespace = [0; 128];
            namespace[..identity.namespace().len()].copy_from_slice(identity.namespace());
            DurableTransportIdentity {
                namespace,
                namespace_len: identity.namespace().len() as u8,
                authority: identity.authority().bytes(),
                effect: identity.effect().bytes(),
                catalog_digest: identity.catalog_digest(),
            }
        });
        Self {
            run_id: plan.run_id(),
            root: plan.effect().root().get(),
            sequence: plan.effect().sequence(),
            component: plan.component().get(),
            claim: plan.claim().get(),
            coordinate: HandoffClaimCoordinate {
                resource: plan.resource().get(),
                generation: plan.resource_generation().get(),
            },
            catalog_digest: plan.catalog_digest().bytes(),
            operation_key: plan.operation_key().bytes(),
            payload_digest: plan.payload_digest().bytes(),
            operation_digest: plan.operation_digest().bytes(),
            payload,
            payload_len: plan.payload().len() as u16,
            transport,
            cser3_bound: plan.is_cser3_source() || plan.is_cser3_child(),
            cser3_output: plan.is_cser3_source(),
            child_route: plan.child_route().map(|digest| digest.bytes()),
        }
    }

    fn reconstruct(self) -> Result<ToolOperationPlan, HandoffError> {
        let effect = EffectId::new(
            RootId::new(self.root).map_err(|_| HandoffError::Persist)?,
            self.sequence,
        )
        .map_err(|_| HandoffError::Persist)?;
        let catalog = Digest::new(self.catalog_digest);
        let payload = &self.payload[..usize::from(self.payload_len)];
        let mut plan = match self.component {
            component if component == cser_core::TOOL_HANDOFF_SOURCE_COMPONENT.get() => {
                ToolOperationPlan::handoff_source(
                    self.run_id,
                    effect,
                    ClaimId::new(self.claim).map_err(|_| HandoffError::Persist)?,
                    ResourceId::new(self.coordinate.resource).map_err(|_| HandoffError::Persist)?,
                    ResourceGeneration::new(self.coordinate.generation)
                        .map_err(|_| HandoffError::Persist)?,
                    catalog,
                    payload,
                )
            }
            component if component == cser_core::TOOL_HANDOFF_COMPONENT.get() => {
                ToolOperationPlan::handoff_child(
                    self.run_id,
                    effect,
                    ClaimId::new(self.claim).map_err(|_| HandoffError::Persist)?,
                    ResourceId::new(self.coordinate.resource).map_err(|_| HandoffError::Persist)?,
                    ResourceGeneration::new(self.coordinate.generation)
                        .map_err(|_| HandoffError::Persist)?,
                    catalog,
                    payload,
                )
            }
            _ => return Err(HandoffError::Persist),
        }
        .map_err(|_| HandoffError::Persist)?;
        let identity = self.transport.ok_or(HandoffError::Persist)?;
        let transport = ToolV2Identity::new(
            &identity.namespace[..usize::from(identity.namespace_len)],
            ToolRunId::new(identity.authority),
            ToolRunId::new(identity.effect),
            identity.catalog_digest,
        )
        .map_err(|_| HandoffError::Persist)?;
        plan = if self.cser3_output {
            plan.bind_cser3(transport)
        } else {
            plan.bind_cser3_child(transport)
        };
        if !self.cser3_bound || DurableOperationBinding::from_plan(plan) != self {
            return Err(HandoffError::Persist);
        }
        Ok(plan)
    }
}

/// Recovery state for the independent real-QEMU handoff runtime. The descriptor
/// and terminal digests are opaque bytes until that runtime independently queries
/// and validates the endpoint again; decoding this record alone grants no
/// child-observation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DurableHandoffRecord {
    pub(crate) revision: u64,
    pub(crate) phase: HandoffPhase,
    pub(crate) source: DurableOperationBinding,
    pub(crate) descriptor: Option<[u8; DESCRIPTOR_LEN]>,
    pub(crate) source_terminal_digest: Option<[u8; 32]>,
    child: Option<DurableOperationBinding>,
    pub(crate) child_terminal_digest: Option<[u8; 32]>,
}

impl DurableHandoffRecord {
    /// A parent identity must be made durable before descriptor discovery or
    /// any child request. This is the baseline's structural precondition for
    /// the QEMU bridge to issue the source POST.
    pub(crate) fn parent_intent(source: ToolOperationPlan) -> Result<Self, HandoffError> {
        if source.component() != cser_core::TOOL_HANDOFF_SOURCE_COMPONENT
            || !source.is_cser3_source()
        {
            return Err(HandoffError::SourceMismatch);
        }
        Ok(Self {
            revision: 0,
            phase: HandoffPhase::ParentIntentDurable,
            source: DurableOperationBinding::from_plan(source),
            descriptor: None,
            source_terminal_digest: None,
            child: None,
            child_terminal_digest: None,
        })
    }

    fn child_post_permitted(&self) -> bool {
        self.phase == HandoffPhase::ParentReleasedChildIntentDurable
            && self.child.is_some()
            && self.descriptor.is_some()
            && self.source_terminal_digest.is_some()
    }

    fn child_post_permit(&self) -> Result<ChildPostPermit, HandoffError> {
        if !self.child_post_permitted() {
            return Err(HandoffError::ParentNotReleased);
        }
        Ok(ChildPostPermit(durable_permit_token(self)))
    }

    /// Reconstructs the exact request selected before escape.  A QEMU runtime
    /// may use it only for same-key GET/POST reconciliation; it is not a
    /// terminal observation or release capability.
    pub(crate) fn source_plan(&self) -> Result<ToolOperationPlan, HandoffError> {
        self.source.reconstruct()
    }

    fn child_plan(&self) -> Result<Option<ToolOperationPlan>, HandoffError> {
        self.child
            .map(DurableOperationBinding::reconstruct)
            .transpose()
    }

    /// Produces the next durable descriptor state.  The caller must persist
    /// this complete value before considering the child operation at all.
    pub(crate) fn record_descriptor(
        mut self,
        descriptor: &[u8],
        source: DurableToolObservation,
    ) -> Result<Self, HandoffError> {
        if self.phase != HandoffPhase::ParentIntentDurable
            || DurableOperationBinding::from_plan(source.plan()) != self.source
        {
            return Err(HandoffError::SourceMismatch);
        }
        let parsed = Descriptor::parse(descriptor)?;
        validate_source(parsed, source)?;
        self.descriptor = Some(parsed.wire);
        self.source_terminal_digest = Some(source.terminal_record_digest().bytes());
        self.phase = HandoffPhase::DescriptorDurable;
        self.validate_shape()?;
        Ok(self)
    }

    pub(crate) fn prepare_child(mut self, child: ToolOperationPlan) -> Result<Self, HandoffError> {
        if self.phase != HandoffPhase::DescriptorDurable {
            return Err(HandoffError::ChildNotPrepared);
        }
        let descriptor =
            Descriptor::parse(&self.descriptor.ok_or(HandoffError::ChildNotPrepared)?)?;
        validate_child_plan_exact(self.source.reconstruct()?, descriptor, child)?;
        self.child = Some(DurableOperationBinding::from_plan(child));
        self.phase = HandoffPhase::ChildPrepared;
        self.validate_shape()?;
        Ok(self)
    }

    /// This is the sole transition that authorizes a future child POST.  It
    /// represents parent release and child intent in exactly one ATA record.
    pub(crate) fn release_parent_and_record_child_intent(mut self) -> Result<Self, HandoffError> {
        if self.phase != HandoffPhase::ChildPrepared {
            return Err(HandoffError::ParentNotReleased);
        }
        self.phase = HandoffPhase::ParentReleasedChildIntentDurable;
        self.validate_shape()?;
        Ok(self)
    }

    pub(crate) fn record_child_terminal(
        mut self,
        child: DurableToolObservation,
    ) -> Result<Self, HandoffError> {
        if child.outcome() != ExternalOutcome::Success
            || !self.child_post_permitted()
            || Some(DurableOperationBinding::from_plan(child.plan())) != self.child
        {
            return Err(HandoffError::ChildMismatch);
        }
        self.child_terminal_digest = Some(child.terminal_record_digest().bytes());
        self.phase = HandoffPhase::ChildTerminal;
        self.validate_shape()?;
        Ok(self)
    }

    /// Revalidates a freshly fetched source terminal record against the
    /// canonical descriptor and receipt retained on disk.  It grants no new
    /// authority and is used on every recovery boot before progressing a
    /// partially completed handoff.
    pub(crate) fn reverify_source_descriptor(
        &self,
        descriptor: &[u8],
        source: DurableToolObservation,
    ) -> Result<(), HandoffError> {
        let expected = self.descriptor.ok_or(HandoffError::SourceMismatch)?;
        let parsed = Descriptor::parse(descriptor)?;
        validate_source(parsed, source)?;
        if parsed.wire != expected
            || Some(source.terminal_record_digest().bytes()) != self.source_terminal_digest
            || DurableOperationBinding::from_plan(source.plan()) != self.source
        {
            return Err(HandoffError::SourceMismatch);
        }
        Ok(())
    }

    /// Revalidates the durable child terminal receipt on an idempotent
    /// recovery replay.  A matching receipt is evidence only; it cannot mint
    /// a permit or alter the durable phase.
    pub(crate) fn reverify_child_terminal(
        &self,
        child: DurableToolObservation,
    ) -> Result<(), HandoffError> {
        if child.outcome() != ExternalOutcome::Success
            || self.phase != HandoffPhase::ChildTerminal
            || Some(DurableOperationBinding::from_plan(child.plan())) != self.child
            || Some(child.terminal_record_digest().bytes()) != self.child_terminal_digest
        {
            return Err(HandoffError::ChildMismatch);
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> [u8; HANDOFF_DURABLE_RECORD_BYTES] {
        let mut bytes = [0u8; HANDOFF_DURABLE_RECORD_BYTES];
        bytes[..8].copy_from_slice(&DURABLE_MAGIC);
        put_u16(&mut bytes, 8, DURABLE_VERSION);
        put_u64(&mut bytes, 10, self.revision);
        bytes[18] = phase_byte(self.phase);
        bytes[19] = u8::from(self.descriptor.is_some())
            | (u8::from(self.source_terminal_digest.is_some()) << 1)
            | (u8::from(self.child.is_some()) << 2)
            | (u8::from(self.child_terminal_digest.is_some()) << 3);
        encode_binding(
            &mut bytes[SOURCE_BINDING_OFFSET..SOURCE_BINDING_OFFSET + BINDING_BYTES],
            self.source,
        );
        if let Some(descriptor) = self.descriptor {
            bytes[DESCRIPTOR_OFFSET..DESCRIPTOR_OFFSET + DESCRIPTOR_LEN]
                .copy_from_slice(&descriptor);
        }
        if let Some(digest) = self.source_terminal_digest {
            bytes[SOURCE_TERMINAL_OFFSET..SOURCE_TERMINAL_OFFSET + 32].copy_from_slice(&digest);
        }
        if let Some(child) = self.child {
            encode_binding(
                &mut bytes[CHILD_BINDING_OFFSET..CHILD_BINDING_OFFSET + BINDING_BYTES],
                child,
            );
        }
        if let Some(digest) = self.child_terminal_digest {
            bytes[CHILD_TERMINAL_OFFSET..CHILD_TERMINAL_OFFSET + 32].copy_from_slice(&digest);
        }
        let checksum: [u8; 32] = Sha256::digest(&bytes[..HANDOFF_DURABLE_RECORD_BYTES - 32]).into();
        bytes[HANDOFF_DURABLE_RECORD_BYTES - 32..].copy_from_slice(&checksum);
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, HandoffError> {
        if bytes.len() != HANDOFF_DURABLE_RECORD_BYTES
            || bytes[..8] != DURABLE_MAGIC
            || read_u16(bytes, 8)? != DURABLE_VERSION
        {
            return Err(HandoffError::Persist);
        }
        let expected: [u8; 32] = Sha256::digest(&bytes[..HANDOFF_DURABLE_RECORD_BYTES - 32]).into();
        if bytes[HANDOFF_DURABLE_RECORD_BYTES - 32..] != expected {
            return Err(HandoffError::Persist);
        }
        let flags = bytes[19];
        if flags & !0x0f != 0 {
            return Err(HandoffError::Persist);
        }
        // The record has a fixed canonical image: an absent optional value
        // must leave its whole slot zeroed.  Otherwise a checksum-valid
        // record could retain unparsed stale data and have more than one
        // encoding for the same durable state.
        for (present, slot) in [
            (
                flags & 1 != 0,
                &bytes[DESCRIPTOR_OFFSET..DESCRIPTOR_OFFSET + DESCRIPTOR_LEN],
            ),
            (
                flags & 2 != 0,
                &bytes[SOURCE_TERMINAL_OFFSET..SOURCE_TERMINAL_OFFSET + 32],
            ),
            (
                flags & 4 != 0,
                &bytes[CHILD_BINDING_OFFSET..CHILD_BINDING_OFFSET + BINDING_BYTES],
            ),
            (
                flags & 8 != 0,
                &bytes[CHILD_TERMINAL_OFFSET..CHILD_TERMINAL_OFFSET + 32],
            ),
        ] {
            if !present && slot.iter().any(|byte| *byte != 0) {
                return Err(HandoffError::Persist);
            }
        }
        let phase = parse_phase(bytes[18])?;
        let descriptor = if flags & 1 != 0 {
            Some(
                bytes[DESCRIPTOR_OFFSET..DESCRIPTOR_OFFSET + DESCRIPTOR_LEN]
                    .try_into()
                    .map_err(|_| HandoffError::Persist)?,
            )
        } else {
            None
        };
        let source_terminal_digest = if flags & 2 != 0 {
            Some(
                bytes[SOURCE_TERMINAL_OFFSET..SOURCE_TERMINAL_OFFSET + 32]
                    .try_into()
                    .map_err(|_| HandoffError::Persist)?,
            )
        } else {
            None
        };
        let child = if flags & 4 != 0 {
            Some(decode_binding(
                &bytes[CHILD_BINDING_OFFSET..CHILD_BINDING_OFFSET + BINDING_BYTES],
            )?)
        } else {
            None
        };
        let child_terminal_digest = if flags & 8 != 0 {
            Some(
                bytes[CHILD_TERMINAL_OFFSET..CHILD_TERMINAL_OFFSET + 32]
                    .try_into()
                    .map_err(|_| HandoffError::Persist)?,
            )
        } else {
            None
        };
        let result = Self {
            revision: read_u64(bytes, 10)?,
            phase,
            source: decode_binding(
                &bytes[SOURCE_BINDING_OFFSET..SOURCE_BINDING_OFFSET + BINDING_BYTES],
            )?,
            descriptor,
            source_terminal_digest,
            child,
            child_terminal_digest,
        };
        result.validate_shape()?;
        result.validate_semantics()?;
        Ok(result)
    }

    fn validate_shape(&self) -> Result<(), HandoffError> {
        let exact = match self.phase {
            HandoffPhase::ParentIntentDurable => {
                self.descriptor.is_none()
                    && self.source_terminal_digest.is_none()
                    && self.child.is_none()
                    && self.child_terminal_digest.is_none()
            }
            HandoffPhase::DescriptorDurable => {
                self.descriptor.is_some()
                    && self.source_terminal_digest.is_some()
                    && self.child.is_none()
                    && self.child_terminal_digest.is_none()
            }
            HandoffPhase::ChildPrepared | HandoffPhase::ParentReleasedChildIntentDurable => {
                self.descriptor.is_some()
                    && self.source_terminal_digest.is_some()
                    && self.child.is_some()
                    && self.child_terminal_digest.is_none()
            }
            HandoffPhase::ChildTerminal => {
                self.descriptor.is_some()
                    && self.source_terminal_digest.is_some()
                    && self.child.is_some()
                    && self.child_terminal_digest.is_some()
            }
        };
        if self.source.component != cser_core::TOOL_HANDOFF_SOURCE_COMPONENT.get() || !exact {
            return Err(HandoffError::Persist);
        }
        Ok(())
    }

    fn validate_semantics(&self) -> Result<(), HandoffError> {
        let source = self.source.reconstruct()?;
        if !source.is_cser3_source() {
            return Err(HandoffError::Persist);
        }
        if let Some(wire) = self.descriptor {
            let descriptor = Descriptor::parse(&wire)?;
            if source.effect().root().get() != descriptor.parent.root
                || source.effect().sequence() != descriptor.parent.sequence
                || source.component().get() != descriptor.parent_component
                || source.catalog_digest().bytes() != descriptor.catalog
                || source.payload_digest().bytes() != descriptor.input
                || source.child_route().map(|route| route.bytes()) != Some(descriptor.route)
            {
                return Err(HandoffError::Persist);
            }
            if let Some(child) = self.child {
                let child = child.reconstruct()?;
                validate_child_plan_exact(source, descriptor, child)?;
            }
        }
        Ok(())
    }
}

fn phase_byte(phase: HandoffPhase) -> u8 {
    match phase {
        HandoffPhase::ParentIntentDurable => 1,
        HandoffPhase::DescriptorDurable => 2,
        HandoffPhase::ChildPrepared => 3,
        HandoffPhase::ParentReleasedChildIntentDurable => 4,
        HandoffPhase::ChildTerminal => 5,
    }
}
fn parse_phase(value: u8) -> Result<HandoffPhase, HandoffError> {
    match value {
        1 => Ok(HandoffPhase::ParentIntentDurable),
        2 => Ok(HandoffPhase::DescriptorDurable),
        3 => Ok(HandoffPhase::ChildPrepared),
        4 => Ok(HandoffPhase::ParentReleasedChildIntentDurable),
        5 => Ok(HandoffPhase::ChildTerminal),
        _ => Err(HandoffError::Persist),
    }
}
fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn read_u16(bytes: &[u8], at: usize) -> Result<u16, HandoffError> {
    u16_at(bytes, at)
}
fn read_u64(bytes: &[u8], at: usize) -> Result<u64, HandoffError> {
    u64_at(bytes, at)
}
fn encode_binding(bytes: &mut [u8], binding: DurableOperationBinding) {
    bytes.fill(0);
    bytes[..16].copy_from_slice(&binding.run_id);
    put_u64(bytes, 16, binding.root);
    put_u64(bytes, 24, binding.sequence);
    put_u32(bytes, 32, binding.component);
    put_u64(bytes, 36, binding.claim);
    put_u64(bytes, 44, binding.coordinate.resource);
    put_u64(bytes, 52, binding.coordinate.generation);
    bytes[60..92].copy_from_slice(&binding.catalog_digest);
    bytes[92..124].copy_from_slice(&binding.operation_key);
    bytes[124..156].copy_from_slice(&binding.payload_digest);
    bytes[156..188].copy_from_slice(&binding.operation_digest);
    put_u16(bytes, 188, binding.payload_len);
    bytes[190..766].copy_from_slice(&binding.payload);
    bytes[766] = u8::from(binding.transport.is_some());
    bytes[767] = u8::from(binding.cser3_bound) | (u8::from(binding.cser3_output) << 1);
    bytes[768] = u8::from(binding.child_route.is_some());
    if let Some(transport) = binding.transport {
        bytes[769] = transport.namespace_len;
        bytes[770..898].copy_from_slice(&transport.namespace);
        bytes[898..914].copy_from_slice(&transport.authority);
        bytes[914..930].copy_from_slice(&transport.effect);
        bytes[930..962].copy_from_slice(&transport.catalog_digest);
    }
    if let Some(route) = binding.child_route {
        bytes[962..994].copy_from_slice(&route);
    }
}
fn decode_binding(bytes: &[u8]) -> Result<DurableOperationBinding, HandoffError> {
    if bytes.len() != BINDING_BYTES {
        return Err(HandoffError::Persist);
    }
    let transport = match bytes[766] {
        0 => None,
        1 if usize::from(bytes[769]) <= 128 => Some(DurableTransportIdentity {
            namespace: bytes[770..898]
                .try_into()
                .map_err(|_| HandoffError::Persist)?,
            namespace_len: bytes[769],
            authority: bytes[898..914]
                .try_into()
                .map_err(|_| HandoffError::Persist)?,
            effect: bytes[914..930]
                .try_into()
                .map_err(|_| HandoffError::Persist)?,
            catalog_digest: bytes[930..962]
                .try_into()
                .map_err(|_| HandoffError::Persist)?,
        }),
        _ => return Err(HandoffError::Persist),
    };
    let child_route = match bytes[768] {
        0 => None,
        1 => Some(
            bytes[962..994]
                .try_into()
                .map_err(|_| HandoffError::Persist)?,
        ),
        _ => return Err(HandoffError::Persist),
    };
    if bytes[767] & !3 != 0
        || bytes[766] == 0 && bytes[769..962].iter().any(|byte| *byte != 0)
        || bytes[768] == 0 && bytes[962..994].iter().any(|byte| *byte != 0)
        || bytes[994..].iter().any(|byte| *byte != 0)
    {
        return Err(HandoffError::Persist);
    }
    let binding = DurableOperationBinding {
        run_id: bytes[..16].try_into().map_err(|_| HandoffError::Persist)?,
        root: read_u64(bytes, 16)?,
        sequence: read_u64(bytes, 24)?,
        component: u32_at(bytes, 32)?,
        claim: read_u64(bytes, 36)?,
        coordinate: HandoffClaimCoordinate {
            resource: read_u64(bytes, 44)?,
            generation: read_u64(bytes, 52)?,
        },
        catalog_digest: bytes[60..92]
            .try_into()
            .map_err(|_| HandoffError::Persist)?,
        operation_key: bytes[92..124]
            .try_into()
            .map_err(|_| HandoffError::Persist)?,
        payload_digest: bytes[124..156]
            .try_into()
            .map_err(|_| HandoffError::Persist)?,
        operation_digest: bytes[156..188]
            .try_into()
            .map_err(|_| HandoffError::Persist)?,
        payload: bytes[190..766]
            .try_into()
            .map_err(|_| HandoffError::Persist)?,
        payload_len: read_u16(bytes, 188)?,
        transport,
        cser3_bound: bytes[767] & 1 != 0,
        cser3_output: bytes[767] & 2 != 0,
        child_route,
    };
    if binding.root == 0
        || binding.sequence == 0
        || binding.component == 0
        || binding.claim == 0
        || binding.coordinate.resource == 0
        || binding.coordinate.generation == 0
        || binding.catalog_digest == [0; 32]
        || binding.operation_key == [0; 32]
        || binding.payload_digest == [0; 32]
        || binding.operation_digest == [0; 32]
        || usize::from(binding.payload_len) > binding.payload.len()
    {
        return Err(HandoffError::Persist);
    }
    Ok(binding)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChildKey {
    root: u64,
    sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandoffScope {
    Logical,
    Device(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Descriptor {
    wire: [u8; DESCRIPTOR_LEN],
    parent: ChildKey,
    parent_component: u32,
    route: [u8; 32],
    child_component: u32,
    claim_id: u64,
    claim_kind: u32,
    scope: HandoffScope,
    claim: HandoffClaimCoordinate,
    units: u64,
    input: [u8; 32],
    catalog: [u8; 32],
    child: ChildKey,
}

impl Descriptor {
    fn parse(wire: &[u8]) -> Result<Self, HandoffError> {
        if wire.len() != DESCRIPTOR_LEN || wire[..8] != *DESCRIPTOR_MAGIC {
            return Err(HandoffError::InvalidDescriptor);
        }
        if u16_at(wire, 8)? != 1 || u64_at(wire, 10)? != 1 {
            return Err(HandoffError::InvalidDescriptor);
        }
        let parent = ChildKey {
            root: u64_at(wire, 18)?,
            sequence: u64_at(wire, 26)?,
        };
        if parent.root == 0 || parent.sequence == 0 {
            return Err(HandoffError::InvalidDescriptor);
        }
        let parent_component = u32_at(wire, 34)?;
        if parent_component == 0 {
            return Err(HandoffError::InvalidDescriptor);
        }
        let route = array_at(wire, 38)?;
        // Child kind/component, claim id/kind, scope tag/scope id are parsed
        // structurally: no zero / malformed scope may acquire authority.
        if u32_at(wire, 70)? == 0
            || u32_at(wire, 74)? == 0
            || u64_at(wire, 78)? == 0
            || u32_at(wire, 86)? == 0
        {
            return Err(HandoffError::InvalidDescriptor);
        }
        let child_component = u32_at(wire, 74)?;
        let claim_id = u64_at(wire, 78)?;
        let claim_kind = u32_at(wire, 86)?;
        let scope = match (wire[90], u64_at(wire, 91)?) {
            (0, 0) => HandoffScope::Logical,
            (1, nonzero) if nonzero != 0 => HandoffScope::Device(nonzero),
            _ => return Err(HandoffError::InvalidDescriptor),
        };
        let claim = HandoffClaimCoordinate {
            resource: u64_at(wire, 99)?,
            generation: u64_at(wire, 107)?,
        };
        let units = u64_at(wire, 115)?;
        if claim.resource == 0 || claim.generation == 0 || units == 0 {
            return Err(HandoffError::InvalidDescriptor);
        }
        let input = array_at(wire, 123)?;
        let catalog = array_at(wire, 155)?;
        if input == [0; 32] || catalog == [0; 32] {
            return Err(HandoffError::InvalidDescriptor);
        }
        let mut fixed = [0; DESCRIPTOR_LEN];
        fixed.copy_from_slice(wire);
        let child = derive_child(&fixed, parent)?;
        Ok(Self {
            wire: fixed,
            parent,
            parent_component,
            route,
            child_component,
            claim_id,
            claim_kind,
            scope,
            claim,
            units,
            input,
            catalog,
            child,
        })
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, HandoffError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or(HandoffError::InvalidDescriptor)?
            .try_into()
            .map_err(|_| HandoffError::InvalidDescriptor)?,
    ))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, HandoffError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(HandoffError::InvalidDescriptor)?
            .try_into()
            .map_err(|_| HandoffError::InvalidDescriptor)?,
    ))
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64, HandoffError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .ok_or(HandoffError::InvalidDescriptor)?
            .try_into()
            .map_err(|_| HandoffError::InvalidDescriptor)?,
    ))
}
fn array_at(bytes: &[u8], at: usize) -> Result<[u8; 32], HandoffError> {
    bytes
        .get(at..at + 32)
        .ok_or(HandoffError::InvalidDescriptor)?
        .try_into()
        .map_err(|_| HandoffError::InvalidDescriptor)
}

fn derive_child(wire: &[u8; DESCRIPTOR_LEN], parent: ChildKey) -> Result<ChildKey, HandoffError> {
    let descriptor_digest: [u8; 32] = Sha256::digest(wire).into();
    let mut hash = Sha256::new();
    hash.update(b"CSER3-single-hop-child-effect-v1");
    hash.update(descriptor_digest);
    let bytes: [u8; 32] = hash.finalize().into();
    let mut sequence = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    if sequence == 0 {
        sequence = 1;
    }
    if sequence == parent.sequence {
        return Err(HandoffError::InvalidDescriptor);
    }
    Ok(ChildKey {
        root: parent.root,
        sequence,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DurableHandoff {
    descriptor: Descriptor,
    source_receipt: DurableToolObservation,
    child_plan: Option<ToolOperationPlan>,
    child_receipt: Option<DurableToolObservation>,
    phase: HandoffPhase,
}

/// Candidate-copy durable persistence. A real coordinator can implement this
/// with its own journal; the in-memory double bank below exists solely for
/// focused recovery tests.
trait HandoffStore {
    fn load(&self) -> Result<Option<DurableHandoff>, HandoffError>;
    fn persist_candidate(&mut self, candidate: DurableHandoff) -> Result<(), HandoffError>;
}

/// ATA/TPM backing for the canonical handoff record.  ATA publication is
/// completely read back before the experiment-only TPM selector advances.
/// Recovery accepts only an exact anchored tip or a decoded record precisely
/// one revision ahead, which it rolls forward.  This baseline never imports
/// `Engine` or `VerifiedDescriptor`.
pub(crate) struct AtaTpmBaselineHandoffStore {
    ata: AtaDoubleBank,
    anchor: ExperimentNvAnchor<QemuTisTpm2>,
}

#[derive(Debug)]
pub(crate) enum AtaTpmBaselineHandoffStoreError {
    Ata(AtaDoubleBankError<AtaPioError>),
    Tpm(TisTpmError),
    Auth(super::core_tpm_anchor::TpmNvAuthError),
    Anchor(ExperimentNvAnchorError<TisTpmError>),
    UnexpectedGenesis,
    Corrupt,
}

impl AtaTpmBaselineHandoffStore {
    pub(crate) fn acquire_qemu_fixture(
        fixture: AtaJournalFixture,
    ) -> Result<Self, AtaTpmBaselineHandoffStoreError> {
        let mut ata =
            AtaDoubleBank::acquire(fixture).map_err(AtaTpmBaselineHandoffStoreError::Ata)?;
        let transport =
            QemuTisTpm2::acquire_qemu_fixture().map_err(AtaTpmBaselineHandoffStoreError::Tpm)?;
        let auth = TpmNvIndexAuth::new(&[]).map_err(AtaTpmBaselineHandoffStoreError::Auth)?;
        let anchor = ExperimentNvAnchor::open(transport, ExperimentNvLayout::qemu_fixture(), auth)
            .map_err(AtaTpmBaselineHandoffStoreError::Anchor)?;
        if ata
            .load()
            .map_err(AtaTpmBaselineHandoffStoreError::Ata)?
            .is_none()
            && anchor.snapshot() != ExperimentAnchorSnapshot::new(0, [0; 32])
        {
            return Err(AtaTpmBaselineHandoffStoreError::UnexpectedGenesis);
        }
        Ok(Self { ata, anchor })
    }

    pub(crate) fn initialize_parent_intent(
        &mut self,
        source: ToolOperationPlan,
    ) -> Result<DurableHandoffRecord, AtaTpmBaselineHandoffStoreError> {
        if self.load()?.is_some() {
            return Err(AtaTpmBaselineHandoffStoreError::Corrupt);
        }
        let record = DurableHandoffRecord::parent_intent(source)
            .map_err(|_| AtaTpmBaselineHandoffStoreError::Corrupt)?;
        self.persist(record)
    }

    pub(crate) fn load(
        &mut self,
    ) -> Result<Option<DurableHandoffRecord>, AtaTpmBaselineHandoffStoreError> {
        let tip = self.anchor.snapshot();
        let Some(snapshot) = self
            .ata
            .load()
            .map_err(AtaTpmBaselineHandoffStoreError::Ata)?
        else {
            return Ok(None);
        };
        let record = DurableHandoffRecord::decode(snapshot.bytes())
            .map_err(|_| AtaTpmBaselineHandoffStoreError::Corrupt)?;
        if record.revision != snapshot.revision() {
            return Err(AtaTpmBaselineHandoffStoreError::Corrupt);
        }
        if snapshot.revision() == tip.revision() && snapshot.digest() == tip.digest() {
            return Ok(Some(record));
        }
        if snapshot.revision()
            == tip
                .revision()
                .checked_add(1)
                .ok_or(AtaTpmBaselineHandoffStoreError::Corrupt)?
        {
            let next = ExperimentAnchorSnapshot::new(snapshot.revision(), snapshot.digest());
            self.anchor
                .compare_and_advance(tip, next)
                .map_err(AtaTpmBaselineHandoffStoreError::Anchor)?;
            if self.anchor.snapshot() == next {
                return Ok(Some(record));
            }
        }
        Err(AtaTpmBaselineHandoffStoreError::Corrupt)
    }

    pub(crate) fn persist(
        &mut self,
        mut record: DurableHandoffRecord,
    ) -> Result<DurableHandoffRecord, AtaTpmBaselineHandoffStoreError> {
        let previous = self.anchor.snapshot();
        record.revision = previous
            .revision()
            .checked_add(1)
            .ok_or(AtaTpmBaselineHandoffStoreError::Corrupt)?;
        record
            .validate_shape()
            .map_err(|_| AtaTpmBaselineHandoffStoreError::Corrupt)?;
        record
            .validate_semantics()
            .map_err(|_| AtaTpmBaselineHandoffStoreError::Corrupt)?;
        let bytes = record.encode();
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        self.ata
            .publish(record.revision, digest, &bytes)
            .map_err(AtaTpmBaselineHandoffStoreError::Ata)?;
        self.anchor
            .compare_and_advance(
                previous,
                ExperimentAnchorSnapshot::new(record.revision, digest),
            )
            .map_err(AtaTpmBaselineHandoffStoreError::Anchor)?;
        Ok(record)
    }

    /// Publishes the only child-POST-authorizing state and returns a linear
    /// permit only after ATA readback and TPM tip advancement both succeed.
    pub(crate) fn release_parent_and_record_child_intent(
        &mut self,
        record: DurableHandoffRecord,
    ) -> Result<(DurableHandoffRecord, ChildPostPermit), AtaTpmBaselineHandoffStoreError> {
        let released = record
            .release_parent_and_record_child_intent()
            .map_err(|_| AtaTpmBaselineHandoffStoreError::Corrupt)?;
        let released = self.persist(released)?;
        let permit = released
            .child_post_permit()
            .map_err(|_| AtaTpmBaselineHandoffStoreError::Corrupt)?;
        Ok((released, permit))
    }

    /// Explicit recovery authorization.  `load` has already decoded and
    /// semantically validated the record; only a Released state can mint a
    /// replacement one-shot permit for the recovery boot.
    pub(crate) fn recover_child_post_permit(
        &mut self,
    ) -> Result<(DurableHandoffRecord, ChildPostPermit), AtaTpmBaselineHandoffStoreError> {
        let record = self
            .load()?
            .ok_or(AtaTpmBaselineHandoffStoreError::Corrupt)?;
        let permit = record
            .child_post_permit()
            .map_err(|_| AtaTpmBaselineHandoffStoreError::Corrupt)?;
        Ok((record, permit))
    }

    /// Exact-coordinate baseline gate over the anchored canonical record.
    /// The coordinate stays unavailable until the child's terminal receipt is
    /// durably recorded; this method has no CSER dependency.
    pub(crate) fn check_reusable(
        &mut self,
        coordinate: HandoffClaimCoordinate,
    ) -> Result<(), AtaTpmBaselineHandoffStoreError> {
        if let Some(record) = self.load()? {
            if record.phase == HandoffPhase::ParentIntentDurable {
                // The child coordinate has not been discovered yet.  Keep the
                // gate globally fail-closed rather than treating an absent
                // descriptor as a release of the durable parent intent.
                return Err(AtaTpmBaselineHandoffStoreError::Corrupt);
            }
            if record.phase != HandoffPhase::ChildTerminal {
                let descriptor = record
                    .descriptor
                    .ok_or(AtaTpmBaselineHandoffStoreError::Corrupt)?;
                let parsed = Descriptor::parse(&descriptor)
                    .map_err(|_| AtaTpmBaselineHandoffStoreError::Corrupt)?;
                let parent_still_retained = matches!(
                    record.phase,
                    HandoffPhase::DescriptorDurable | HandoffPhase::ChildPrepared
                );
                if parsed.claim == coordinate
                    || (parent_still_retained && record.source.coordinate == coordinate)
                {
                    return Err(AtaTpmBaselineHandoffStoreError::Corrupt);
                }
            }
        }
        Ok(())
    }
}

/// One-shot authority minted only after the atomic parent-release/child-intent
/// record is durable. It is deliberately neither `Clone` nor `Copy`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ChildTerminalPermit([u8; 32]);

/// Non-cloneable authority to issue the child POST.  It is deliberately
/// separate from a recovered phase boolean: only the ATA/TPM store mints it
/// after the atomic release record is authoritative, or explicitly on a
/// semantically validated recovery path.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ChildPostPermit([u8; 32]);

impl ChildPostPermit {
    /// Consumes the permit when yielding the exact durable child request.
    /// A caller cannot use a released phase projection as a substitute.
    pub(crate) fn into_child_plan(
        self,
        record: &DurableHandoffRecord,
    ) -> Result<ToolOperationPlan, HandoffError> {
        if self.0 != durable_permit_token(record) || !record.child_post_permitted() {
            return Err(HandoffError::InvalidPermit);
        }
        record.child_plan()?.ok_or(HandoffError::InvalidPermit)
    }
}

fn durable_permit_token(record: &DurableHandoffRecord) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"nexus-baseline-durable-child-post-permit-v1");
    hash.update(record.revision.to_le_bytes());
    hash.update(record.descriptor.expect("released record has descriptor"));
    hash.update(
        record
            .source_terminal_digest
            .expect("released record has source digest"),
    );
    hash.update(
        record
            .child
            .expect("released record has child")
            .operation_digest,
    );
    hash.finalize().into()
}

pub(crate) struct BaselineHandoff<S> {
    store: S,
}

impl<S: HandoffStore> BaselineHandoff<S> {
    pub(crate) fn new(store: S) -> Self {
        Self { store }
    }
    pub(crate) fn recover(&self) -> Result<Option<HandoffPhase>, HandoffError> {
        Ok(self.store.load()?.map(|r| r.phase))
    }

    /// The first verified source terminal observation adopts the canonical
    /// descriptor exactly once. Repeating that same observation is idempotent;
    /// a distinct descriptor or receipt is never adopted.
    pub(crate) fn adopt_descriptor(
        &mut self,
        descriptor: &[u8],
        source: DurableToolObservation,
    ) -> Result<(), HandoffError> {
        let parsed = Descriptor::parse(descriptor)?;
        validate_source(parsed, source)?;
        match self.store.load()? {
            Some(existing) => {
                if existing.descriptor == parsed && existing.source_receipt == source {
                    Ok(())
                } else {
                    Err(HandoffError::SourceMismatch)
                }
            }
            None => self.store.persist_candidate(DurableHandoff {
                descriptor: parsed,
                source_receipt: source,
                child_plan: None,
                child_receipt: None,
                phase: HandoffPhase::DescriptorDurable,
            }),
        }
    }

    /// Persist the child endpoint identity before releasing the parent. This
    /// makes a later generic terminal observation unable to finalize the child.
    pub(crate) fn prepare_child(&mut self, child: ToolOperationPlan) -> Result<(), HandoffError> {
        let mut record = self.store.load()?.ok_or(HandoffError::ChildNotPrepared)?;
        validate_child_plan_exact(record.source_receipt.plan(), record.descriptor, child)?;
        match record.phase {
            HandoffPhase::DescriptorDurable => {
                record.child_plan = Some(child);
                record.phase = HandoffPhase::ChildPrepared;
                self.store.persist_candidate(record)
            }
            HandoffPhase::ChildPrepared if record.child_plan == Some(child) => Ok(()),
            _ => Err(HandoffError::ChildNotPrepared),
        }
    }

    /// Single candidate-copy transition: parent release and child commit intent
    /// are never independently durable.
    pub(crate) fn release_parent_and_record_child_intent(
        &mut self,
    ) -> Result<ChildTerminalPermit, HandoffError> {
        let mut record = self.store.load()?.ok_or(HandoffError::ChildNotPrepared)?;
        match record.phase {
            HandoffPhase::ChildPrepared => {
                record.phase = HandoffPhase::ParentReleasedChildIntentDurable;
                self.store.persist_candidate(record)?;
            }
            HandoffPhase::ParentReleasedChildIntentDurable => {}
            _ => return Err(HandoffError::ParentNotReleased),
        }
        Ok(ChildTerminalPermit(permit_token(&record)))
    }

    /// A child terminal must be a second, already verified endpoint record for
    /// the durable child operation identity. A local boolean cannot discharge
    /// the exact retained coordinate.
    pub(crate) fn observe_child_terminal(
        &mut self,
        permit: ChildTerminalPermit,
        child: DurableToolObservation,
    ) -> Result<(), HandoffError> {
        let mut record = self.store.load()?.ok_or(HandoffError::ParentNotReleased)?;
        if record.phase != HandoffPhase::ParentReleasedChildIntentDurable
            || permit.0 != permit_token(&record)
        {
            return Err(HandoffError::InvalidPermit);
        }
        if record.child_plan != Some(child.plan()) {
            return Err(HandoffError::ChildMismatch);
        }
        record.child_receipt = Some(child);
        record.phase = HandoffPhase::ChildTerminal;
        self.store.persist_candidate(record)
    }

    /// Read-only exact-coordinate gate. Different opaque identifiers are not
    /// inferred to alias; this coordinator only protects the coordinate it has
    /// durably retained.
    pub(crate) fn check_reusable(
        &self,
        coordinate: HandoffClaimCoordinate,
    ) -> Result<(), HandoffError> {
        let record = self.store.load()?;
        if let Some(record) = record {
            let parent_still_retained = matches!(
                record.phase,
                HandoffPhase::DescriptorDurable | HandoffPhase::ChildPrepared
            );
            let parent_coordinate = HandoffClaimCoordinate {
                resource: record.source_receipt.plan().resource().get(),
                generation: record.source_receipt.plan().resource_generation().get(),
            };
            if record.phase != HandoffPhase::ChildTerminal
                && (record.descriptor.claim == coordinate
                    || (parent_still_retained && parent_coordinate == coordinate))
            {
                return Err(HandoffError::ConflictRetained);
            }
        }
        Ok(())
    }

    #[cfg(ktest)]
    fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }
}

fn validate_source(
    descriptor: Descriptor,
    source: DurableToolObservation,
) -> Result<(), HandoffError> {
    let plan = source.plan();
    if source.outcome() != ExternalOutcome::Success
        || !plan.is_cser3_source()
        || plan.effect().root().get() != descriptor.parent.root
        || plan.effect().sequence() != descriptor.parent.sequence
        || plan.component().get() != descriptor.parent_component
        || plan.catalog_digest().bytes() != descriptor.catalog
        || plan.payload_digest().bytes() != descriptor.input
        || plan.child_route().map(|route| route.bytes()) != Some(descriptor.route)
        || source.terminal_output().bytes() != descriptor.wire
    {
        return Err(HandoffError::SourceMismatch);
    }
    Ok(())
}
fn validate_child_plan_exact(
    source: ToolOperationPlan,
    descriptor: Descriptor,
    child: ToolOperationPlan,
) -> Result<(), HandoffError> {
    if descriptor.child_component != cser_core::TOOL_HANDOFF_COMPONENT.get()
        || descriptor.claim_kind != cser_core::TOOL_CLAIM_OUTCOME_SLOT.get()
        || descriptor.scope != HandoffScope::Logical
        || descriptor.units != 1
    {
        return Err(HandoffError::ChildMismatch);
    }
    let decoded = cser_core::ChildDescriptorV1::decode_wire(&descriptor.wire)
        .map_err(|_| HandoffError::ChildMismatch)?;
    let expected = ToolOperationPlan::handoff_child_for_descriptor(source, decoded)
        .map_err(|_| HandoffError::ChildMismatch)?;
    if child != expected {
        return Err(HandoffError::ChildMismatch);
    }
    Ok(())
}
fn permit_token(record: &DurableHandoff) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"nexus-baseline-handoff-permit-v1");
    hash.update(record.descriptor.wire);
    hash.update(record.source_receipt.terminal_record_digest().bytes());
    hash.update(record.descriptor.parent.root.to_le_bytes());
    hash.update(record.descriptor.parent.sequence.to_le_bytes());
    hash.update(record.descriptor.route);
    hash.update(record.descriptor.input);
    hash.update(record.descriptor.catalog);
    hash.update(record.descriptor.child.root.to_le_bytes());
    hash.update(record.descriptor.child.sequence.to_le_bytes());
    hash.update(
        record
            .child_plan
            .expect("prepared phase")
            .operation_digest()
            .bytes(),
    );
    hash.finalize().into()
}

#[cfg(ktest)]
#[derive(Clone, Copy)]
pub(crate) struct MemoryDoubleBank {
    banks: [Option<DurableHandoff>; 2],
    selected: usize,
    fail_next: bool,
}
#[cfg(ktest)]
impl MemoryDoubleBank {
    pub(crate) const fn new() -> Self {
        Self {
            banks: [None, None],
            selected: 0,
            fail_next: false,
        }
    }
    pub(crate) fn fail_next_persist(&mut self) {
        self.fail_next = true;
    }
    fn recovered_copy(&self) -> Self {
        *self
    }
}
#[cfg(ktest)]
impl HandoffStore for MemoryDoubleBank {
    fn load(&self) -> Result<Option<DurableHandoff>, HandoffError> {
        Ok(self.banks[self.selected].or(self.banks[1 - self.selected]))
    }
    fn persist_candidate(&mut self, candidate: DurableHandoff) -> Result<(), HandoffError> {
        if self.fail_next {
            self.fail_next = false;
            return Err(HandoffError::Persist);
        }
        let inactive = 1 - self.selected;
        self.banks[inactive] = Some(candidate);
        self.selected = inactive;
        Ok(())
    }
}

#[cfg(ktest)]
mod tests {
    use alloc::format;
    use core::str;

    use super::*;
    use crate::core_tool_adapter::DurableToolObservation;
    use crate::core_tool_uart::{
        OperationKey, ToolRequest, ToolRunId, ToolTerminalOutput, ToolTerminalRecord,
        ToolV2Identity, decode_response,
    };
    use cser_core::{
        ClaimId, Digest, EffectId, ResourceGeneration, ResourceId, RootId, TOOL_CLAIM_OUTCOME_SLOT,
        TOOL_HANDOFF_COMPONENT, TOOL_HANDOFF_SOURCE_COMPONENT,
    };
    use ostd::prelude::ktest;

    fn put16(wire: &mut [u8], at: usize, value: u16) {
        wire[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(wire: &mut [u8], at: usize, value: u32) {
        wire[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(wire: &mut [u8], at: usize, value: u64) {
        wire[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn fixture() -> (
        BaselineHandoff<MemoryDoubleBank>,
        [u8; DESCRIPTOR_LEN],
        DurableToolObservation,
        ToolOperationPlan,
        HandoffClaimCoordinate,
    ) {
        let parent = EffectId::new(RootId::new(41).unwrap(), 2).unwrap();
        let catalog = Digest::new([0x33; 32]);
        let payload = b"baseline-handoff-input";
        let identity = ToolV2Identity::new(
            b"tool",
            ToolRunId::new([2; 16]),
            ToolRunId::new([3; 16]),
            catalog.bytes(),
        )
        .unwrap();
        let source_plan = ToolOperationPlan::handoff_source(
            [0x11; 16],
            parent,
            ClaimId::new(7).unwrap(),
            ResourceId::new(9).unwrap(),
            ResourceGeneration::new(3).unwrap(),
            catalog,
            payload,
        )
        .unwrap()
        .bind_cser3(identity);
        let mut wire = [0u8; DESCRIPTOR_LEN];
        wire[..8].copy_from_slice(DESCRIPTOR_MAGIC);
        put16(&mut wire, 8, 1);
        put64(&mut wire, 10, 1);
        put64(&mut wire, 18, 41);
        put64(&mut wire, 26, 2);
        put32(&mut wire, 34, TOOL_HANDOFF_SOURCE_COMPONENT.get());
        wire[38..70].copy_from_slice(&[
            0x28, 0x73, 0x2d, 0x53, 0x5f, 0x4e, 0x48, 0xd4, 0x10, 0xef, 0x5b, 0x74, 0x93, 0x24,
            0x56, 0x41, 0xb3, 0x2d, 0xe7, 0xa5, 0xfa, 0x0d, 0xfa, 0x7b, 0x5d, 0xfc, 0xf0, 0x44,
            0xfd, 0x00, 0x16, 0x0c,
        ]);
        put32(&mut wire, 70, 1);
        put32(&mut wire, 74, TOOL_HANDOFF_COMPONENT.get());
        put64(&mut wire, 78, 8);
        put32(&mut wire, 86, TOOL_CLAIM_OUTCOME_SLOT.get());
        wire[90] = 0;
        put64(&mut wire, 91, 0);
        put64(&mut wire, 99, 10);
        put64(&mut wire, 107, 1);
        put64(&mut wire, 115, 1);
        wire[123..155].copy_from_slice(&source_plan.payload_digest().bytes());
        wire[155..187].copy_from_slice(&catalog.bytes());
        let output = ToolTerminalOutput::child_descriptor(&wire).unwrap();
        let source_terminal = ToolTerminalRecord::succeeded_with_output_for_test(
            identity,
            ToolRunId::new(source_plan.run_id()),
            OperationKey::new(&source_plan.operation_key_hex()).unwrap(),
            payload,
            output,
        )
        .unwrap();
        let source =
            DurableToolObservation::from_terminal_record(source_plan, source_terminal).unwrap();
        let descriptor = Descriptor::parse(&wire).unwrap();
        let child_plan = ToolOperationPlan::handoff_child_for_descriptor(
            source_plan,
            cser_core::ChildDescriptorV1::decode_wire(&wire).unwrap(),
        )
        .unwrap();
        (
            BaselineHandoff::new(MemoryDoubleBank::new()),
            wire,
            source,
            child_plan,
            descriptor.claim,
        )
    }

    fn child_observation(plan: ToolOperationPlan) -> DurableToolObservation {
        let terminal = crate::core_tool_uart::terminal_record_for_test(
            ToolRunId::new(plan.run_id()),
            OperationKey::new(&plan.operation_key_hex()).unwrap(),
            plan.payload(),
        );
        DurableToolObservation::from_terminal_record(plan, terminal).unwrap()
    }

    fn hex(input: &[u8]) -> [u8; 64] {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = [0; 64];
        for (byte, pair) in input.iter().copied().zip(output.chunks_exact_mut(2)) {
            pair[0] = DIGITS[usize::from(byte >> 4)];
            pair[1] = DIGITS[usize::from(byte & 0x0f)];
        }
        output
    }

    /// Builds a checksum- and digest-valid failed endpoint terminal through
    /// the production UART decoder, rather than manufacturing an observation.
    fn failed_child_observation(plan: ToolOperationPlan) -> DurableToolObservation {
        let request = ToolRequest::new(
            ToolRunId::new(plan.run_id()),
            OperationKey::new(&plan.operation_key_hex()).unwrap(),
            plan.payload(),
        )
        .unwrap();
        let run_hex = hex(&plan.run_id());
        let run = &run_hex[..32];
        let operation = plan.operation_key_hex();
        let payload = hex(&plan.payload_digest().bytes());
        let mut record_hasher = Sha256::new();
        record_hasher.update(b"nexus-cser-tool-record-v1");
        for field in [
            run,
            &operation[..],
            &payload[..],
            b"failed".as_slice(),
            b"rejected".as_slice(),
        ] {
            record_hasher.update((field.len() as u64).to_le_bytes());
            record_hasher.update(field);
        }
        let record = hex(&record_hasher.finalize());
        let prefix = format!(
            "CSER1 RESP {} {} 200 {} failed rejected {}",
            str::from_utf8(run).unwrap(),
            str::from_utf8(&operation).unwrap(),
            str::from_utf8(&payload).unwrap(),
            str::from_utf8(&record).unwrap(),
        );
        let checksum = hex(&Sha256::digest(prefix.as_bytes()));
        let line = format!("{} {}\n", prefix, str::from_utf8(&checksum).unwrap());
        DurableToolObservation::from_terminal_record(
            plan,
            decode_response(line.as_bytes(), &request)
                .unwrap()
                .terminal_record()
                .unwrap(),
        )
        .unwrap()
    }

    fn parent_and_child_coordinates_follow_the_durable_handoff_phases() {
        let (mut handoff, wire, source, child, coordinate) = fixture();
        let parent_coordinate = HandoffClaimCoordinate {
            resource: source.plan().resource().get(),
            generation: source.plan().resource_generation().get(),
        };
        assert_ne!(parent_coordinate, coordinate);
        handoff.adopt_descriptor(&wire, source).unwrap();
        assert_eq!(
            BaselineHandoff::new(handoff.store_mut().recovered_copy()).recover(),
            Ok(Some(HandoffPhase::DescriptorDurable))
        );
        assert_eq!(
            handoff.check_reusable(coordinate),
            Err(HandoffError::ConflictRetained)
        );
        assert_eq!(
            handoff.check_reusable(parent_coordinate),
            Err(HandoffError::ConflictRetained)
        );
        handoff.prepare_child(child).unwrap();
        assert_eq!(
            BaselineHandoff::new(handoff.store_mut().recovered_copy()).recover(),
            Ok(Some(HandoffPhase::ChildPrepared))
        );
        assert_eq!(
            handoff.check_reusable(coordinate),
            Err(HandoffError::ConflictRetained)
        );
        assert_eq!(
            handoff.check_reusable(parent_coordinate),
            Err(HandoffError::ConflictRetained)
        );
        let permit = handoff.release_parent_and_record_child_intent().unwrap();
        assert_eq!(
            BaselineHandoff::new(handoff.store_mut().recovered_copy()).recover(),
            Ok(Some(HandoffPhase::ParentReleasedChildIntentDurable))
        );
        assert_eq!(handoff.check_reusable(parent_coordinate), Ok(()));
        assert_eq!(
            handoff.check_reusable(coordinate),
            Err(HandoffError::ConflictRetained)
        );
        handoff
            .observe_child_terminal(permit, child_observation(child))
            .unwrap();
        assert_eq!(
            BaselineHandoff::new(handoff.store_mut().recovered_copy()).recover(),
            Ok(Some(HandoffPhase::ChildTerminal))
        );
        assert_eq!(handoff.check_reusable(coordinate), Ok(()));
        assert_eq!(handoff.check_reusable(parent_coordinate), Ok(()));
    }

    fn duplicate_adoption_and_persist_failure_do_not_change_live_gate() {
        let (mut handoff, wire, source, child, coordinate) = fixture();
        handoff.adopt_descriptor(&wire, source).unwrap();
        handoff.adopt_descriptor(&wire, source).unwrap();
        handoff.store_mut().fail_next_persist();
        assert_eq!(handoff.prepare_child(child), Err(HandoffError::Persist));
        assert_eq!(handoff.recover(), Ok(Some(HandoffPhase::DescriptorDurable)));
        assert_eq!(
            handoff.check_reusable(coordinate),
            Err(HandoffError::ConflictRetained)
        );
    }

    fn tampered_descriptor_and_generic_child_bypass_are_rejected() {
        let (mut handoff, mut wire, source, _child, _) = fixture();
        wire[38] ^= 1;
        assert_eq!(
            handoff.adopt_descriptor(&wire, source),
            Err(HandoffError::SourceMismatch)
        );
        let (mut handoff, wire, source, child, _) = fixture();
        handoff.adopt_descriptor(&wire, source).unwrap();
        handoff.prepare_child(child).unwrap();
        let permit = handoff.release_parent_and_record_child_intent().unwrap();
        let wrong = ToolOperationPlan::handoff_child(
            [0x22; 16],
            child.effect(),
            ClaimId::new(8).unwrap(),
            ResourceId::new(10).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            child.catalog_digest(),
            b"different",
        )
        .unwrap();
        assert_eq!(
            handoff.observe_child_terminal(permit, child_observation(wrong)),
            Err(HandoffError::ChildMismatch)
        );
    }

    fn wrong_child_claim_or_resource_coordinate_cannot_be_prepared() {
        let (mut handoff, wire, source, child, _) = fixture();
        handoff.adopt_descriptor(&wire, source).unwrap();
        let wrong_claim = ToolOperationPlan::handoff_child(
            [0x22; 16],
            child.effect(),
            ClaimId::new(99).unwrap(),
            child.resource(),
            child.resource_generation(),
            child.catalog_digest(),
            child.payload(),
        )
        .unwrap();
        assert_eq!(
            handoff.prepare_child(wrong_claim),
            Err(HandoffError::ChildMismatch)
        );
        let wrong_resource = ToolOperationPlan::handoff_child(
            [0x22; 16],
            child.effect(),
            child.claim(),
            ResourceId::new(99).unwrap(),
            child.resource_generation(),
            child.catalog_digest(),
            child.payload(),
        )
        .unwrap();
        assert_eq!(
            handoff.prepare_child(wrong_resource),
            Err(HandoffError::ChildMismatch)
        );
        assert_eq!(handoff.recover(), Ok(Some(HandoffPhase::DescriptorDurable)));
    }

    fn canonical_record_codec_is_torn_corrupt_safe_and_gates_child_post() {
        let (_handoff, wire, source, child, coordinate) = fixture();
        let parent = DurableHandoffRecord::parent_intent(source.plan()).unwrap();
        assert!(!parent.child_post_permitted());
        let bytes = parent.encode();
        assert_eq!(DurableHandoffRecord::decode(&bytes), Ok(parent));
        assert_eq!(parent.source.reconstruct(), Ok(source.plan()));

        // A checksum-valid ParentIntent record must still reject any stale
        // bytes in every absent fixed optional slot.
        for offset in [
            DESCRIPTOR_OFFSET,
            SOURCE_TERMINAL_OFFSET,
            CHILD_BINDING_OFFSET,
            CHILD_TERMINAL_OFFSET,
        ] {
            let mut noncanonical = parent.encode();
            noncanonical[offset] = 1;
            let checksum: [u8; 32] =
                Sha256::digest(&noncanonical[..HANDOFF_DURABLE_RECORD_BYTES - 32]).into();
            noncanonical[HANDOFF_DURABLE_RECORD_BYTES - 32..].copy_from_slice(&checksum);
            assert_eq!(
                DurableHandoffRecord::decode(&noncanonical),
                Err(HandoffError::Persist)
            );
        }

        let descriptor = parent.record_descriptor(&wire, source).unwrap();
        assert!(!descriptor.child_post_permitted());
        let prepared = descriptor.prepare_child(child).unwrap();
        assert!(!prepared.child_post_permitted());
        let released = prepared.release_parent_and_record_child_intent().unwrap();
        assert!(released.child_post_permitted());
        let child_post = released.child_post_permit().unwrap();
        assert_eq!(child_post.into_child_plan(&released), Ok(child));
        let terminal = released
            .record_child_terminal(child_observation(child))
            .unwrap();
        assert_eq!(terminal.phase, HandoffPhase::ChildTerminal);
        assert_eq!(terminal.child.unwrap().coordinate, coordinate);

        let mut corrupt = released.encode();
        corrupt[220] ^= 1;
        assert_eq!(
            DurableHandoffRecord::decode(&corrupt),
            Err(HandoffError::Persist)
        );
        let torn = released.encode();
        assert_eq!(
            DurableHandoffRecord::decode(&torn[..HANDOFF_DURABLE_RECORD_BYTES - 1]),
            Err(HandoffError::Persist)
        );

        // Even a checksum-valid alteration cannot replace the descriptor's
        // derived child payload/operation/transport binding on recovery.
        let mut semantic_corrupt = released.encode();
        semantic_corrupt[CHILD_BINDING_OFFSET + 190] ^= 1;
        let checksum: [u8; 32] =
            Sha256::digest(&semantic_corrupt[..HANDOFF_DURABLE_RECORD_BYTES - 32]).into();
        semantic_corrupt[HANDOFF_DURABLE_RECORD_BYTES - 32..].copy_from_slice(&checksum);
        assert_eq!(
            DurableHandoffRecord::decode(&semantic_corrupt),
            Err(HandoffError::Persist)
        );

        // A checksum cannot turn a record into an impossible phase shape:
        // DescriptorDurable may not retain a prepared child binding.
        let mut impossible = released.encode();
        impossible[18] = phase_byte(HandoffPhase::DescriptorDurable);
        let checksum: [u8; 32] =
            Sha256::digest(&impossible[..HANDOFF_DURABLE_RECORD_BYTES - 32]).into();
        impossible[HANDOFF_DURABLE_RECORD_BYTES - 32..].copy_from_slice(&checksum);
        assert_eq!(
            DurableHandoffRecord::decode(&impossible),
            Err(HandoffError::Persist)
        );
    }

    fn failed_child_terminal_cannot_advance_or_revalidate_the_durable_record() {
        let (_handoff, wire, source, child, _) = fixture();
        let released = DurableHandoffRecord::parent_intent(source.plan())
            .unwrap()
            .record_descriptor(&wire, source)
            .unwrap()
            .prepare_child(child)
            .unwrap()
            .release_parent_and_record_child_intent()
            .unwrap();
        let failed = failed_child_observation(child);

        assert_eq!(
            released.record_child_terminal(failed),
            Err(HandoffError::ChildMismatch)
        );
        assert_eq!(
            released.phase,
            HandoffPhase::ParentReleasedChildIntentDurable
        );
        assert!(released.child_terminal_digest.is_none());
        assert_eq!(
            DurableHandoffRecord::decode(&released.encode()),
            Ok(released)
        );

        let terminal = released
            .record_child_terminal(child_observation(child))
            .unwrap();
        assert_eq!(
            terminal.reverify_child_terminal(failed),
            Err(HandoffError::ChildMismatch)
        );
        assert_eq!(terminal.phase, HandoffPhase::ChildTerminal);
        assert!(terminal.child_terminal_digest.is_some());
    }

    /// Aggregate only this portable coordinator's focused regressions into one
    /// OSDK test. It is intentionally not a general baseline test framework.
    #[ktest]
    fn cser_baseline_handoff_gate() {
        parent_and_child_coordinates_follow_the_durable_handoff_phases();
        duplicate_adoption_and_persist_failure_do_not_change_live_gate();
        tampered_descriptor_and_generic_child_bypass_are_rejected();
        wrong_child_claim_or_resource_coordinate_cannot_be_prepared();
        canonical_record_codec_is_torn_corrupt_safe_and_gates_child_post();
        failed_child_terminal_cannot_advance_or_revalidate_the_durable_record();
    }
}
