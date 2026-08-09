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

use sha2::{Digest as _, Sha256};

use super::core_tool_adapter::{DurableToolObservation, ToolOperationPlan};

const DESCRIPTOR_LEN: usize = 187;
const DESCRIPTOR_MAGIC: &[u8; 8] = b"NXSCHD03";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandoffPhase {
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

/// One-shot authority minted only after the atomic parent-release/child-intent
/// record is durable. It is deliberately neither `Clone` nor `Copy`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ChildTerminalPermit([u8; 32]);

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
        validate_child_plan(record.descriptor, child)?;
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
            if record.descriptor.claim == coordinate && record.phase != HandoffPhase::ChildTerminal
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
    if plan.effect().root().get() != descriptor.parent.root
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
fn validate_child_plan(
    descriptor: Descriptor,
    child: ToolOperationPlan,
) -> Result<(), HandoffError> {
    if child.effect().root().get() != descriptor.child.root
        || child.effect().sequence() != descriptor.child.sequence
        || child.component() != cser_core::TOOL_HANDOFF_COMPONENT
        || child.claim().get() != descriptor.claim_id
        || child.resource().get() != descriptor.claim.resource
        || child.resource_generation().get() != descriptor.claim.generation
        || child.catalog_digest().bytes() != descriptor.catalog
        || descriptor.child_component != cser_core::TOOL_HANDOFF_COMPONENT.get()
        || descriptor.claim_kind != cser_core::TOOL_CLAIM_OUTCOME_SLOT.get()
        || descriptor.scope != HandoffScope::Logical
        || descriptor.units != 1
    {
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
    use super::*;
    use crate::core_tool_adapter::DurableToolObservation;
    use crate::core_tool_uart::{
        OperationKey, ToolRunId, ToolTerminalOutput, ToolTerminalRecord, ToolV2Identity,
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
        let child_effect = EffectId::new(
            RootId::new(descriptor.child.root).unwrap(),
            descriptor.child.sequence,
        )
        .unwrap();
        let child_plan = ToolOperationPlan::handoff_child(
            [0x22; 16],
            child_effect,
            ClaimId::new(8).unwrap(),
            ResourceId::new(10).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            catalog,
            b"child-input",
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

    fn phases_recover_and_exact_coordinate_stays_retained_until_second_terminal() {
        let (mut handoff, wire, source, child, coordinate) = fixture();
        handoff.adopt_descriptor(&wire, source).unwrap();
        assert_eq!(
            BaselineHandoff::new(handoff.store_mut().recovered_copy()).recover(),
            Ok(Some(HandoffPhase::DescriptorDurable))
        );
        assert_eq!(
            handoff.check_reusable(coordinate),
            Err(HandoffError::ConflictRetained)
        );
        handoff.prepare_child(child).unwrap();
        assert_eq!(
            BaselineHandoff::new(handoff.store_mut().recovered_copy()).recover(),
            Ok(Some(HandoffPhase::ChildPrepared))
        );
        let permit = handoff.release_parent_and_record_child_intent().unwrap();
        assert_eq!(
            BaselineHandoff::new(handoff.store_mut().recovered_copy()).recover(),
            Ok(Some(HandoffPhase::ParentReleasedChildIntentDurable))
        );
        handoff
            .observe_child_terminal(permit, child_observation(child))
            .unwrap();
        assert_eq!(
            BaselineHandoff::new(handoff.store_mut().recovered_copy()).recover(),
            Ok(Some(HandoffPhase::ChildTerminal))
        );
        assert_eq!(handoff.check_reusable(coordinate), Ok(()));
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

    /// Aggregate only this portable coordinator's focused regressions into one
    /// OSDK test. It is intentionally not a general baseline test framework.
    #[ktest]
    fn cser_baseline_handoff_gate() {
        phases_recover_and_exact_coordinate_stays_retained_until_second_terminal();
        duplicate_adoption_and_persist_failure_do_not_change_live_gate();
        tampered_descriptor_and_generic_child_bypass_are_rejected();
        wrong_child_claim_or_resource_coordinate_cannot_be_prepared();
    }
}
