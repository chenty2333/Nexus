// SPDX-License-Identifier: MPL-2.0

//! Bounded session-local scope, effect, and receipt observations.

use zerocopy::byteorder::{LittleEndian, U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::request::require_size;
use crate::{Digest, EffectHandle, PortalErrorCode, PortalWireError, ReceiptHandle, ScopeHandle};

use super::lifecycle::validate_receipt_identity;
use super::{
    EffectPhase, LifecycleFlags, ReceiptKind, ReceiptStatus, ResponseBody, ScopePhase,
    lifecycle_flags_match_phase,
};

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireScopeObservation {
    scope: [u8; 16],
    authority_epoch: U64<LittleEndian>,
    binding_epoch: U64<LittleEndian>,
    revision: U64<LittleEndian>,
    domain_revision: U64<LittleEndian>,
    phase: U16<LittleEndian>,
    reserved0: [u8; 6],
    live_effects: U32<LittleEndian>,
    pending_publications: U32<LittleEndian>,
    retained_owners: U32<LittleEndian>,
    reserved1: U32<LittleEndian>,
    latest_receipt: [u8; 16],
    state_digest: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<WireScopeObservation>() == 120);
const _: () = assert!(core::mem::align_of::<WireScopeObservation>() == 1);

/// Bounded session-local scope observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeObservation {
    scope: ScopeHandle,
    authority_epoch: u64,
    binding_epoch: u64,
    revision: u64,
    domain_revision: u64,
    phase: ScopePhase,
    live_effects: u32,
    pending_publications: u32,
    retained_owners: u32,
    latest_receipt: ReceiptHandle,
    state_digest: Digest,
}

impl ScopeObservation {
    /// Creates a validated scope observation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ScopeHandle,
        authority_epoch: u64,
        binding_epoch: u64,
        revision: u64,
        domain_revision: u64,
        phase: ScopePhase,
        live_effects: u32,
        pending_publications: u32,
        retained_owners: u32,
        latest_receipt: ReceiptHandle,
        state_digest: Digest,
    ) -> Result<Self, PortalWireError> {
        if scope.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidHandle, 0));
        }
        if authority_epoch == 0 || binding_epoch == 0 || revision == 0 {
            return Err(PortalWireError::new(
                PortalErrorCode::GenerationMismatch,
                16,
            ));
        }
        if state_digest.is_zero() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidDigest, 88));
        }
        if phase == ScopePhase::Revoked && (live_effects != 0 || pending_publications != 0) {
            return Err(PortalWireError::new(PortalErrorCode::Conflict, 56));
        }
        Ok(Self {
            scope,
            authority_epoch,
            binding_epoch,
            revision,
            domain_revision,
            phase,
            live_effects,
            pending_publications,
            retained_owners,
            latest_receipt,
            state_digest,
        })
    }

    /// Returns the observed scope.
    #[must_use]
    pub const fn scope(self) -> ScopeHandle {
        self.scope
    }

    /// Returns the authority epoch.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the binding epoch.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    /// Returns the projection revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Returns the latest provider-domain revision accepted by commit.
    #[must_use]
    pub const fn domain_revision(self) -> u64 {
        self.domain_revision
    }

    /// Returns the scope phase.
    #[must_use]
    pub const fn phase(self) -> ScopePhase {
        self.phase
    }

    /// Returns live effect count.
    #[must_use]
    pub const fn live_effects(self) -> u32 {
        self.live_effects
    }

    /// Returns pending publication count.
    #[must_use]
    pub const fn pending_publications(self) -> u32 {
        self.pending_publications
    }

    /// Returns retained owner count.
    #[must_use]
    pub const fn retained_owners(self) -> u32 {
        self.retained_owners
    }

    /// Returns the latest known receipt, or null when none exists.
    #[must_use]
    pub const fn latest_receipt(self) -> ReceiptHandle {
        self.latest_receipt
    }

    /// Returns the canonical observation digest.
    #[must_use]
    pub const fn state_digest(self) -> Digest {
        self.state_digest
    }
}

impl ResponseBody for ScopeObservation {
    const WIRE_SIZE: usize = 120;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireScopeObservation::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved0 != [0; 6] || raw.reserved1.get() != 0 {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 50));
        }
        let phase = ScopePhase::from_wire_value(raw.phase.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 48))?;
        Self::new(
            ScopeHandle::from_wire_bytes(raw.scope),
            raw.authority_epoch.get(),
            raw.binding_epoch.get(),
            raw.revision.get(),
            raw.domain_revision.get(),
            phase,
            raw.live_effects.get(),
            raw.pending_publications.get(),
            raw.retained_owners.get(),
            ReceiptHandle::from_wire_bytes(raw.latest_receipt),
            Digest::from_wire_bytes(raw.state_digest),
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let raw = WireScopeObservation {
            scope: self.scope.to_wire_bytes(),
            authority_epoch: U64::new(self.authority_epoch),
            binding_epoch: U64::new(self.binding_epoch),
            revision: U64::new(self.revision),
            domain_revision: U64::new(self.domain_revision),
            phase: U16::new(self.phase.wire_value()),
            reserved0: [0; 6],
            live_effects: U32::new(self.live_effects),
            pending_publications: U32::new(self.pending_publications),
            retained_owners: U32::new(self.retained_owners),
            reserved1: U32::new(0),
            latest_receipt: self.latest_receipt.to_wire_bytes(),
            state_digest: self.state_digest.to_wire_bytes(),
        };
        let decoded = Self::decode_wire(raw.as_bytes())?;
        output.copy_from_slice(raw.as_bytes());
        debug_assert_eq!(decoded, *self);
        Ok(())
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireEffectObservation {
    scope: [u8; 16],
    effect: [u8; 16],
    authority_epoch: U64<LittleEndian>,
    binding_epoch: U64<LittleEndian>,
    revision: U64<LittleEndian>,
    phase: U16<LittleEndian>,
    outcome_kind: U16<LittleEndian>,
    flags: U32<LittleEndian>,
    outcome_result: U64<LittleEndian>,
    outcome_digest: [u8; 32],
    terminal_digest: [u8; 32],
    latest_receipt: [u8; 16],
    request_digest: [u8; 32],
    state_digest: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<WireEffectObservation>() == 216);
const _: () = assert!(core::mem::align_of::<WireEffectObservation>() == 1);

/// Canonical provider outcome projected from authoritative Registry state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectOutcomeObservation {
    kind: crate::OutcomeKind,
    result: i64,
    digest: Digest,
}

impl EffectOutcomeObservation {
    /// Creates a non-zero canonical outcome projection.
    pub fn new(
        kind: crate::OutcomeKind,
        result: i64,
        digest: Digest,
    ) -> Result<Self, PortalWireError> {
        if digest.is_zero() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidDigest, 72));
        }
        Ok(Self {
            kind,
            result,
            digest,
        })
    }

    /// Returns the provider-neutral outcome class.
    #[must_use]
    pub const fn kind(self) -> crate::OutcomeKind {
        self.kind
    }

    /// Returns the stable provider result value.
    #[must_use]
    pub const fn result(self) -> i64 {
        self.result
    }

    /// Returns the canonical outcome digest.
    #[must_use]
    pub const fn digest(self) -> Digest {
        self.digest
    }
}

/// Bounded session-local effect observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectObservation {
    scope: ScopeHandle,
    effect: EffectHandle,
    authority_epoch: u64,
    binding_epoch: u64,
    revision: u64,
    phase: EffectPhase,
    outcome: Option<EffectOutcomeObservation>,
    terminal_digest: Option<Digest>,
    flags: LifecycleFlags,
    latest_receipt: ReceiptHandle,
    request_digest: Digest,
    state_digest: Digest,
}

impl EffectObservation {
    /// Creates a validated effect observation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ScopeHandle,
        effect: EffectHandle,
        authority_epoch: u64,
        binding_epoch: u64,
        revision: u64,
        phase: EffectPhase,
        outcome: Option<EffectOutcomeObservation>,
        terminal_digest: Option<Digest>,
        flags: LifecycleFlags,
        latest_receipt: ReceiptHandle,
        request_digest: Digest,
        state_digest: Digest,
    ) -> Result<Self, PortalWireError> {
        if scope.is_null() || effect.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidHandle, 0));
        }
        if authority_epoch == 0 || binding_epoch == 0 || revision == 0 {
            return Err(PortalWireError::new(
                PortalErrorCode::GenerationMismatch,
                32,
            ));
        }
        if request_digest.is_zero() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidDigest, 152));
        }
        if state_digest.is_zero() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidDigest, 184));
        }
        if terminal_digest.is_some_and(Digest::is_zero) {
            return Err(PortalWireError::new(PortalErrorCode::InvalidDigest, 104));
        }
        let outcome_matches = match phase {
            EffectPhase::OutcomeRecorded | EffectPhase::Completed => outcome.is_some(),
            EffectPhase::Registered
            | EffectPhase::Prepared
            | EffectPhase::Committed
            | EffectPhase::Aborted => outcome.is_none(),
            EffectPhase::Retained => true,
        };
        if phase == EffectPhase::Completed
            && outcome.is_some_and(|outcome| outcome.kind() == crate::OutcomeKind::Indeterminate)
        {
            return Err(PortalWireError::new(PortalErrorCode::Conflict, 58));
        }
        let terminal_matches = if phase.is_terminal() {
            true
        } else {
            terminal_digest.is_none()
        };
        if LifecycleFlags::from_bits(flags.bits()).is_none()
            || !lifecycle_flags_match_phase(phase, flags)
            || !outcome_matches
            || !terminal_matches
        {
            return Err(PortalWireError::new(PortalErrorCode::Conflict, 56));
        }
        Ok(Self {
            scope,
            effect,
            authority_epoch,
            binding_epoch,
            revision,
            phase,
            outcome,
            terminal_digest,
            flags,
            latest_receipt,
            request_digest,
            state_digest,
        })
    }

    /// Returns the observed scope.
    #[must_use]
    pub const fn scope(self) -> ScopeHandle {
        self.scope
    }

    /// Returns the observed effect.
    #[must_use]
    pub const fn effect(self) -> EffectHandle {
        self.effect
    }

    /// Returns the authority epoch.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the binding epoch.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    /// Returns the observation revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Returns the effect phase.
    #[must_use]
    pub const fn phase(self) -> EffectPhase {
        self.phase
    }

    /// Returns the canonical recorded outcome when one exists.
    #[must_use]
    pub const fn outcome(self) -> Option<EffectOutcomeObservation> {
        self.outcome
    }

    /// Returns a recorded outcome class when one exists.
    #[must_use]
    pub const fn outcome_kind(self) -> Option<crate::OutcomeKind> {
        match self.outcome {
            Some(outcome) => Some(outcome.kind()),
            None => None,
        }
    }

    /// Returns the authoritative terminal manifest digest when one exists.
    #[must_use]
    pub const fn terminal_digest(self) -> Option<Digest> {
        self.terminal_digest
    }

    /// Returns lifecycle flags.
    #[must_use]
    pub const fn flags(self) -> LifecycleFlags {
        self.flags
    }

    /// Returns the latest receipt, or null when absent.
    #[must_use]
    pub const fn latest_receipt(self) -> ReceiptHandle {
        self.latest_receipt
    }

    /// Returns the immutable registration request digest.
    #[must_use]
    pub const fn request_digest(self) -> Digest {
        self.request_digest
    }

    /// Returns the canonical observation digest.
    #[must_use]
    pub const fn state_digest(self) -> Digest {
        self.state_digest
    }
}

impl ResponseBody for EffectObservation {
    const WIRE_SIZE: usize = 216;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireEffectObservation::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        let phase = EffectPhase::from_wire_value(raw.phase.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 56))?;
        let outcome_kind = match raw.outcome_kind.get() {
            0 => None,
            value => Some(
                crate::OutcomeKind::from_wire_value(value)
                    .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 58))?,
            ),
        };
        let outcome_digest = Digest::from_wire_bytes(raw.outcome_digest);
        let outcome = match outcome_kind {
            Some(kind) => Some(EffectOutcomeObservation::new(
                kind,
                raw.outcome_result.get() as i64,
                outcome_digest,
            )?),
            None => {
                if raw.outcome_result.get() != 0 || !outcome_digest.is_zero() {
                    return Err(PortalWireError::new(PortalErrorCode::Conflict, 64));
                }
                None
            }
        };
        let terminal_digest = Digest::from_wire_bytes(raw.terminal_digest);
        let terminal_digest = if terminal_digest.is_zero() {
            None
        } else {
            Some(terminal_digest)
        };
        let flags = LifecycleFlags::from_bits(raw.flags.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownFlags, 60))?;
        Self::new(
            ScopeHandle::from_wire_bytes(raw.scope),
            EffectHandle::from_wire_bytes(raw.effect),
            raw.authority_epoch.get(),
            raw.binding_epoch.get(),
            raw.revision.get(),
            phase,
            outcome,
            terminal_digest,
            flags,
            ReceiptHandle::from_wire_bytes(raw.latest_receipt),
            Digest::from_wire_bytes(raw.request_digest),
            Digest::from_wire_bytes(raw.state_digest),
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let raw = WireEffectObservation {
            scope: self.scope.to_wire_bytes(),
            effect: self.effect.to_wire_bytes(),
            authority_epoch: U64::new(self.authority_epoch),
            binding_epoch: U64::new(self.binding_epoch),
            revision: U64::new(self.revision),
            phase: U16::new(self.phase.wire_value()),
            outcome_kind: U16::new(
                self.outcome
                    .map_or(0, |outcome| outcome.kind().wire_value()),
            ),
            flags: U32::new(self.flags.bits()),
            outcome_result: U64::new(self.outcome.map_or(0, |outcome| outcome.result()) as u64),
            outcome_digest: self
                .outcome
                .map_or(Digest::ZERO, EffectOutcomeObservation::digest)
                .to_wire_bytes(),
            terminal_digest: self.terminal_digest.unwrap_or(Digest::ZERO).to_wire_bytes(),
            latest_receipt: self.latest_receipt.to_wire_bytes(),
            request_digest: self.request_digest.to_wire_bytes(),
            state_digest: self.state_digest.to_wire_bytes(),
        };
        let decoded = Self::decode_wire(raw.as_bytes())?;
        output.copy_from_slice(raw.as_bytes());
        debug_assert_eq!(decoded, *self);
        Ok(())
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireReceiptObservation {
    receipt: [u8; 16],
    authority_epoch: U64<LittleEndian>,
    binding_epoch: U64<LittleEndian>,
    sequence: U64<LittleEndian>,
    kind: U16<LittleEndian>,
    status: U16<LittleEndian>,
    reserved: U32<LittleEndian>,
    request_digest: [u8; 32],
    receipt_digest: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<WireReceiptObservation>() == 112);
const _: () = assert!(core::mem::align_of::<WireReceiptObservation>() == 1);

/// Bounded session-local receipt observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptObservation {
    receipt: ReceiptHandle,
    authority_epoch: u64,
    binding_epoch: u64,
    sequence: u64,
    kind: ReceiptKind,
    status: ReceiptStatus,
    request_digest: Digest,
    receipt_digest: Digest,
}

impl ReceiptObservation {
    /// Creates a validated receipt observation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receipt: ReceiptHandle,
        authority_epoch: u64,
        binding_epoch: u64,
        sequence: u64,
        kind: ReceiptKind,
        status: ReceiptStatus,
        request_digest: Digest,
        receipt_digest: Digest,
    ) -> Result<Self, PortalWireError> {
        validate_receipt_identity(
            receipt,
            authority_epoch,
            binding_epoch,
            sequence,
            request_digest,
            receipt_digest,
            (0, 16, 48),
        )?;
        Ok(Self {
            receipt,
            authority_epoch,
            binding_epoch,
            sequence,
            kind,
            status,
            request_digest,
            receipt_digest,
        })
    }

    /// Returns the observed receipt.
    #[must_use]
    pub const fn receipt(self) -> ReceiptHandle {
        self.receipt
    }

    /// Returns the authority epoch.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the binding epoch.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    /// Returns the receipt sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the receipt kind.
    #[must_use]
    pub const fn kind(self) -> ReceiptKind {
        self.kind
    }

    /// Returns the receipt consumption state.
    #[must_use]
    pub const fn status(self) -> ReceiptStatus {
        self.status
    }

    /// Returns the accepted request digest.
    #[must_use]
    pub const fn request_digest(self) -> Digest {
        self.request_digest
    }

    /// Returns the receipt digest.
    #[must_use]
    pub const fn receipt_digest(self) -> Digest {
        self.receipt_digest
    }
}

impl ResponseBody for ReceiptObservation {
    const WIRE_SIZE: usize = 112;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireReceiptObservation::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved.get() != 0 {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 44));
        }
        let kind = ReceiptKind::from_wire_value(raw.kind.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 40))?;
        let status = ReceiptStatus::from_wire_value(raw.status.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 42))?;
        Self::new(
            ReceiptHandle::from_wire_bytes(raw.receipt),
            raw.authority_epoch.get(),
            raw.binding_epoch.get(),
            raw.sequence.get(),
            kind,
            status,
            Digest::from_wire_bytes(raw.request_digest),
            Digest::from_wire_bytes(raw.receipt_digest),
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let raw = WireReceiptObservation {
            receipt: self.receipt.to_wire_bytes(),
            authority_epoch: U64::new(self.authority_epoch),
            binding_epoch: U64::new(self.binding_epoch),
            sequence: U64::new(self.sequence),
            kind: U16::new(self.kind.wire_value()),
            status: U16::new(self.status.wire_value()),
            reserved: U32::new(0),
            request_digest: self.request_digest.to_wire_bytes(),
            receipt_digest: self.receipt_digest.to_wire_bytes(),
        };
        let decoded = Self::decode_wire(raw.as_bytes())?;
        output.copy_from_slice(raw.as_bytes());
        debug_assert_eq!(decoded, *self);
        Ok(())
    }
}
