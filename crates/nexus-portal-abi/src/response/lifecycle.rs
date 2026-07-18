// SPDX-License-Identifier: MPL-2.0

//! Bounded scope-creation, effect-lifecycle, and closure receipts.

use zerocopy::byteorder::{LittleEndian, U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::request::require_size;
use crate::{Digest, EffectHandle, PortalErrorCode, PortalWireError, ReceiptHandle, ScopeHandle};

use super::{
    ClosureStatus, EffectPhase, LifecycleFlags, ReceiptKind, ResponseBody,
    lifecycle_flags_match_phase,
};

pub(super) fn validate_receipt_identity(
    receipt: ReceiptHandle,
    authority_epoch: u64,
    binding_epoch: u64,
    sequence: u64,
    request_digest: Digest,
    receipt_digest: Digest,
    offsets: (usize, usize, usize),
) -> Result<(), PortalWireError> {
    let (receipt_offset, generation_offset, digest_offset) = offsets;
    if receipt.is_null() {
        return Err(PortalWireError::new(
            PortalErrorCode::InvalidHandle,
            receipt_offset,
        ));
    }
    if authority_epoch == 0 || binding_epoch == 0 || sequence == 0 {
        return Err(PortalWireError::new(
            PortalErrorCode::GenerationMismatch,
            generation_offset,
        ));
    }
    if request_digest.is_zero() || receipt_digest.is_zero() {
        return Err(PortalWireError::new(
            PortalErrorCode::InvalidDigest,
            digest_offset,
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireScopeCreatedResponse {
    scope: [u8; 16],
    receipt: [u8; 16],
    authority_epoch: U64<LittleEndian>,
    binding_epoch: U64<LittleEndian>,
    sequence: U64<LittleEndian>,
    request_digest: [u8; 32],
    receipt_digest: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<WireScopeCreatedResponse>() == 120);
const _: () = assert!(core::mem::align_of::<WireScopeCreatedResponse>() == 1);

/// Receipt returned after bounded scope creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeCreatedResponse {
    scope: ScopeHandle,
    receipt: ReceiptHandle,
    authority_epoch: u64,
    binding_epoch: u64,
    sequence: u64,
    request_digest: Digest,
    receipt_digest: Digest,
}

impl ScopeCreatedResponse {
    /// Creates a validated scope-creation receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ScopeHandle,
        receipt: ReceiptHandle,
        authority_epoch: u64,
        binding_epoch: u64,
        sequence: u64,
        request_digest: Digest,
        receipt_digest: Digest,
    ) -> Result<Self, PortalWireError> {
        if scope.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidHandle, 0));
        }
        validate_receipt_identity(
            receipt,
            authority_epoch,
            binding_epoch,
            sequence,
            request_digest,
            receipt_digest,
            (16, 32, 56),
        )?;
        Ok(Self {
            scope,
            receipt,
            authority_epoch,
            binding_epoch,
            sequence,
            request_digest,
            receipt_digest,
        })
    }

    /// Returns the created scope handle.
    #[must_use]
    pub const fn scope(self) -> ScopeHandle {
        self.scope
    }

    /// Returns the creation receipt handle.
    #[must_use]
    pub const fn receipt(self) -> ReceiptHandle {
        self.receipt
    }

    /// Returns the created authority epoch.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the initial binding epoch.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    /// Returns the receipt sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
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

impl ResponseBody for ScopeCreatedResponse {
    const WIRE_SIZE: usize = 120;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireScopeCreatedResponse::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        Self::new(
            ScopeHandle::from_wire_bytes(raw.scope),
            ReceiptHandle::from_wire_bytes(raw.receipt),
            raw.authority_epoch.get(),
            raw.binding_epoch.get(),
            raw.sequence.get(),
            Digest::from_wire_bytes(raw.request_digest),
            Digest::from_wire_bytes(raw.receipt_digest),
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let response = Self::new(
            self.scope,
            self.receipt,
            self.authority_epoch,
            self.binding_epoch,
            self.sequence,
            self.request_digest,
            self.receipt_digest,
        )?;
        let raw = WireScopeCreatedResponse {
            scope: response.scope.to_wire_bytes(),
            receipt: response.receipt.to_wire_bytes(),
            authority_epoch: U64::new(response.authority_epoch),
            binding_epoch: U64::new(response.binding_epoch),
            sequence: U64::new(response.sequence),
            request_digest: response.request_digest.to_wire_bytes(),
            receipt_digest: response.receipt_digest.to_wire_bytes(),
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireLifecycleReceipt {
    scope: [u8; 16],
    effect: [u8; 16],
    receipt: [u8; 16],
    authority_epoch: U64<LittleEndian>,
    binding_epoch: U64<LittleEndian>,
    sequence: U64<LittleEndian>,
    phase: U16<LittleEndian>,
    kind: U16<LittleEndian>,
    flags: U32<LittleEndian>,
    request_digest: [u8; 32],
    receipt_digest: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<WireLifecycleReceipt>() == 144);
const _: () = assert!(core::mem::align_of::<WireLifecycleReceipt>() == 1);

/// Bounded receipt returned by effect lifecycle mutations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecycleReceipt {
    scope: ScopeHandle,
    effect: EffectHandle,
    receipt: ReceiptHandle,
    authority_epoch: u64,
    binding_epoch: u64,
    sequence: u64,
    phase: EffectPhase,
    kind: ReceiptKind,
    flags: LifecycleFlags,
    request_digest: Digest,
    receipt_digest: Digest,
}

impl LifecycleReceipt {
    /// Creates a validated effect lifecycle receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ScopeHandle,
        effect: EffectHandle,
        receipt: ReceiptHandle,
        authority_epoch: u64,
        binding_epoch: u64,
        sequence: u64,
        phase: EffectPhase,
        kind: ReceiptKind,
        flags: LifecycleFlags,
        request_digest: Digest,
        receipt_digest: Digest,
    ) -> Result<Self, PortalWireError> {
        if scope.is_null() || effect.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidHandle, 0));
        }
        validate_receipt_identity(
            receipt,
            authority_epoch,
            binding_epoch,
            sequence,
            request_digest,
            receipt_digest,
            (32, 48, 80),
        )?;
        if LifecycleFlags::from_bits(flags.bits()).is_none()
            || !lifecycle_flags_match_phase(phase, flags)
            || !receipt_phase_matches(kind, phase)
        {
            return Err(PortalWireError::new(PortalErrorCode::Conflict, 72));
        }
        Ok(Self {
            scope,
            effect,
            receipt,
            authority_epoch,
            binding_epoch,
            sequence,
            phase,
            kind,
            flags,
            request_digest,
            receipt_digest,
        })
    }

    /// Returns the owning scope.
    #[must_use]
    pub const fn scope(self) -> ScopeHandle {
        self.scope
    }

    /// Returns the selected effect.
    #[must_use]
    pub const fn effect(self) -> EffectHandle {
        self.effect
    }

    /// Returns the typed receipt handle.
    #[must_use]
    pub const fn receipt(self) -> ReceiptHandle {
        self.receipt
    }

    /// Returns the accepted authority epoch.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the accepted binding epoch.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    /// Returns the receipt sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the resulting effect phase.
    #[must_use]
    pub const fn phase(self) -> EffectPhase {
        self.phase
    }

    /// Returns the receipt semantic kind.
    #[must_use]
    pub const fn kind(self) -> ReceiptKind {
        self.kind
    }

    /// Returns lifecycle flags.
    #[must_use]
    pub const fn flags(self) -> LifecycleFlags {
        self.flags
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

const fn receipt_phase_matches(kind: ReceiptKind, phase: EffectPhase) -> bool {
    matches!(
        (kind, phase),
        (ReceiptKind::EffectRegistered, EffectPhase::Registered)
            | (ReceiptKind::EffectPrepared, EffectPhase::Prepared)
            | (ReceiptKind::EffectCommitted, EffectPhase::Committed)
            | (ReceiptKind::OutcomeRecorded, EffectPhase::OutcomeRecorded)
            | (
                ReceiptKind::EffectCompleted,
                EffectPhase::Completed | EffectPhase::Aborted | EffectPhase::Retained
            )
    )
}

impl ResponseBody for LifecycleReceipt {
    const WIRE_SIZE: usize = 144;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireLifecycleReceipt::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        let phase = EffectPhase::from_wire_value(raw.phase.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 72))?;
        let kind = ReceiptKind::from_wire_value(raw.kind.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 74))?;
        let flags = LifecycleFlags::from_bits(raw.flags.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownFlags, 76))?;
        Self::new(
            ScopeHandle::from_wire_bytes(raw.scope),
            EffectHandle::from_wire_bytes(raw.effect),
            ReceiptHandle::from_wire_bytes(raw.receipt),
            raw.authority_epoch.get(),
            raw.binding_epoch.get(),
            raw.sequence.get(),
            phase,
            kind,
            flags,
            Digest::from_wire_bytes(raw.request_digest),
            Digest::from_wire_bytes(raw.receipt_digest),
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let response = Self::new(
            self.scope,
            self.effect,
            self.receipt,
            self.authority_epoch,
            self.binding_epoch,
            self.sequence,
            self.phase,
            self.kind,
            self.flags,
            self.request_digest,
            self.receipt_digest,
        )?;
        let raw = WireLifecycleReceipt {
            scope: response.scope.to_wire_bytes(),
            effect: response.effect.to_wire_bytes(),
            receipt: response.receipt.to_wire_bytes(),
            authority_epoch: U64::new(response.authority_epoch),
            binding_epoch: U64::new(response.binding_epoch),
            sequence: U64::new(response.sequence),
            phase: U16::new(response.phase.wire_value()),
            kind: U16::new(response.kind.wire_value()),
            flags: U32::new(response.flags.bits()),
            request_digest: response.request_digest.to_wire_bytes(),
            receipt_digest: response.receipt_digest.to_wire_bytes(),
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireClosureReceipt {
    scope: [u8; 16],
    receipt: [u8; 16],
    authority_epoch: U64<LittleEndian>,
    binding_epoch: U64<LittleEndian>,
    sequence: U64<LittleEndian>,
    status: U16<LittleEndian>,
    reserved0: [u8; 6],
    live_effects: U32<LittleEndian>,
    pending_publications: U32<LittleEndian>,
    retained_owners: U32<LittleEndian>,
    reserved1: U32<LittleEndian>,
    closure_digest: [u8; 32],
    request_digest: [u8; 32],
    receipt_digest: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<WireClosureReceipt>() == 176);
const _: () = assert!(core::mem::align_of::<WireClosureReceipt>() == 1);

/// Bounded scope-revoke and closure receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosureReceipt {
    scope: ScopeHandle,
    receipt: ReceiptHandle,
    authority_epoch: u64,
    binding_epoch: u64,
    sequence: u64,
    status: ClosureStatus,
    live_effects: u32,
    pending_publications: u32,
    retained_owners: u32,
    closure_digest: Digest,
    request_digest: Digest,
    receipt_digest: Digest,
}

impl ClosureReceipt {
    /// Creates a validated bounded closure receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ScopeHandle,
        receipt: ReceiptHandle,
        authority_epoch: u64,
        binding_epoch: u64,
        sequence: u64,
        status: ClosureStatus,
        live_effects: u32,
        pending_publications: u32,
        retained_owners: u32,
        closure_digest: Digest,
        request_digest: Digest,
        receipt_digest: Digest,
    ) -> Result<Self, PortalWireError> {
        if scope.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidHandle, 0));
        }
        if closure_digest.is_zero() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidDigest, 80));
        }
        validate_receipt_identity(
            receipt,
            authority_epoch,
            binding_epoch,
            sequence,
            request_digest,
            receipt_digest,
            (16, 32, 112),
        )?;
        match status {
            ClosureStatus::Closed
                if live_effects != 0 || pending_publications != 0 || retained_owners != 0 =>
            {
                return Err(PortalWireError::new(PortalErrorCode::Conflict, 64));
            }
            ClosureStatus::Closing if live_effects == 0 && pending_publications == 0 => {
                return Err(PortalWireError::new(PortalErrorCode::Conflict, 64));
            }
            ClosureStatus::Retained
                if live_effects != 0 || pending_publications != 0 || retained_owners == 0 =>
            {
                return Err(PortalWireError::new(PortalErrorCode::Conflict, 64));
            }
            _ => {}
        }
        Ok(Self {
            scope,
            receipt,
            authority_epoch,
            binding_epoch,
            sequence,
            status,
            live_effects,
            pending_publications,
            retained_owners,
            closure_digest,
            request_digest,
            receipt_digest,
        })
    }

    /// Returns the selected scope.
    #[must_use]
    pub const fn scope(self) -> ScopeHandle {
        self.scope
    }

    /// Returns the closure receipt handle.
    #[must_use]
    pub const fn receipt(self) -> ReceiptHandle {
        self.receipt
    }

    /// Returns the post-revoke authority epoch.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the current binding epoch.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    /// Returns the receipt sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns closure status.
    #[must_use]
    pub const fn status(self) -> ClosureStatus {
        self.status
    }

    /// Returns the live effect count.
    #[must_use]
    pub const fn live_effects(self) -> u32 {
        self.live_effects
    }

    /// Returns the pending publication count.
    #[must_use]
    pub const fn pending_publications(self) -> u32 {
        self.pending_publications
    }

    /// Returns the retained owner count.
    #[must_use]
    pub const fn retained_owners(self) -> u32 {
        self.retained_owners
    }

    /// Returns the exact closure projection digest.
    #[must_use]
    pub const fn closure_digest(self) -> Digest {
        self.closure_digest
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

impl ResponseBody for ClosureReceipt {
    const WIRE_SIZE: usize = 176;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireClosureReceipt::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved0 != [0; 6] || raw.reserved1.get() != 0 {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 58));
        }
        let status = ClosureStatus::from_wire_value(raw.status.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 56))?;
        Self::new(
            ScopeHandle::from_wire_bytes(raw.scope),
            ReceiptHandle::from_wire_bytes(raw.receipt),
            raw.authority_epoch.get(),
            raw.binding_epoch.get(),
            raw.sequence.get(),
            status,
            raw.live_effects.get(),
            raw.pending_publications.get(),
            raw.retained_owners.get(),
            Digest::from_wire_bytes(raw.closure_digest),
            Digest::from_wire_bytes(raw.request_digest),
            Digest::from_wire_bytes(raw.receipt_digest),
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let response = Self::new(
            self.scope,
            self.receipt,
            self.authority_epoch,
            self.binding_epoch,
            self.sequence,
            self.status,
            self.live_effects,
            self.pending_publications,
            self.retained_owners,
            self.closure_digest,
            self.request_digest,
            self.receipt_digest,
        )?;
        let raw = WireClosureReceipt {
            scope: response.scope.to_wire_bytes(),
            receipt: response.receipt.to_wire_bytes(),
            authority_epoch: U64::new(response.authority_epoch),
            binding_epoch: U64::new(response.binding_epoch),
            sequence: U64::new(response.sequence),
            status: U16::new(response.status.wire_value()),
            reserved0: [0; 6],
            live_effects: U32::new(response.live_effects),
            pending_publications: U32::new(response.pending_publications),
            retained_owners: U32::new(response.retained_owners),
            reserved1: U32::new(0),
            closure_digest: response.closure_digest.to_wire_bytes(),
            request_digest: response.request_digest.to_wire_bytes(),
            receipt_digest: response.receipt_digest.to_wire_bytes(),
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}
