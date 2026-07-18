// SPDX-License-Identifier: MPL-2.0

//! Fixed effect-lifecycle mutation bodies.
//!
//! Every mutation names one negotiated session, explicit authority and binding
//! epochs, and a non-zero canonical request digest.  These fields are selectors,
//! not authority: the backend adapter must still validate opaque handles and
//! epochs against its authoritative registry.

use bitflags::bitflags;
use zerocopy::byteorder::{LittleEndian, U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::request::require_size;
use crate::{
    Digest, EffectHandle, Opcode, PortalErrorCode, PortalWireError, RequestBody, ScopeHandle,
    SessionHandle,
};

/// Maximum units from one typed pool requested by one effect registration.
pub const MAX_CREDIT_UNITS_PER_EFFECT: u32 = 16_384;

/// Scope credit pool charged by one effect registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CreditKind {
    /// Charge bounded queue/admission capacity.
    Queue = 1,
    /// Charge bounded page/frame capacity.
    Page = 2,
}

impl CreditKind {
    /// Returns the stable wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Parses a stable wire discriminant.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Queue),
            2 => Some(Self::Page),
            _ => None,
        }
    }
}

bitflags! {
    /// Effect policy fixed at registration.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct RegisterFlags: u32 {
        /// The effect requires a distinct publication acknowledgement before closure.
        const PUBLICATION_REQUIRED = 1 << 0;
    }
}

/// Canonical backend outcome class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum OutcomeKind {
    /// Backend data is valid for later publication.
    Data = 1,
    /// Backend completed with a stable error result.
    Error = 2,
    /// A committed operation has an honest indeterminate result.
    Indeterminate = 3,
}

impl OutcomeKind {
    /// Returns the stable wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Parses a stable wire discriminant.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Data),
            2 => Some(Self::Error),
            3 => Some(Self::Indeterminate),
            _ => None,
        }
    }
}

/// Requested terminal effect disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CompletionDisposition {
    /// Complete after the required committed outcome has been recorded.
    Completed = 1,
    /// Abort work that never crossed its commit publication boundary.
    AbortedBeforeCommit = 2,
}

impl CompletionDisposition {
    /// Returns the stable wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Parses a stable wire discriminant.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Completed),
            2 => Some(Self::AbortedBeforeCommit),
            _ => None,
        }
    }
}

/// Reason recorded at scope revoke.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RevokeReason {
    /// Explicit caller request.
    Requested = 1,
    /// A supervised service failed.
    ServiceFailure = 2,
    /// A monotonic deadline expired.
    Deadline = 3,
    /// Bounded resource pressure requires closure.
    ResourcePressure = 4,
}

impl RevokeReason {
    /// Returns the stable wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Parses a stable wire discriminant.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Requested),
            2 => Some(Self::ServiceFailure),
            3 => Some(Self::Deadline),
            4 => Some(Self::ResourcePressure),
            _ => None,
        }
    }
}

/// Identity fields required on every mutating request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutationContext {
    session: SessionHandle,
    authority_epoch: u64,
    binding_epoch: u64,
    request_digest: Digest,
}

impl MutationContext {
    /// Creates a validated mutation identity.
    pub fn new(
        session: SessionHandle,
        authority_epoch: u64,
        binding_epoch: u64,
        request_digest: Digest,
    ) -> Result<Self, PortalWireError> {
        if session.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidSession, 0));
        }
        if authority_epoch == 0 {
            return Err(PortalWireError::new(
                PortalErrorCode::GenerationMismatch,
                16,
            ));
        }
        if binding_epoch == 0 {
            return Err(PortalWireError::new(
                PortalErrorCode::GenerationMismatch,
                24,
            ));
        }
        if request_digest.is_zero() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidDigest, 32));
        }
        Ok(Self {
            session,
            authority_epoch,
            binding_epoch,
            request_digest,
        })
    }

    /// Returns the negotiated session selector.
    #[must_use]
    pub const fn session(self) -> SessionHandle {
        self.session
    }

    /// Returns the presented authority epoch.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the presented service binding epoch.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    /// Returns the canonical request digest.
    #[must_use]
    pub const fn request_digest(self) -> Digest {
        self.request_digest
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireMutationContext {
    session: [u8; 16],
    authority_epoch: U64<LittleEndian>,
    binding_epoch: U64<LittleEndian>,
    request_digest: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<WireMutationContext>() == 64);
const _: () = assert!(core::mem::align_of::<WireMutationContext>() == 1);

impl WireMutationContext {
    fn decode(self) -> Result<MutationContext, PortalWireError> {
        MutationContext::new(
            SessionHandle::from_wire_bytes(self.session),
            self.authority_epoch.get(),
            self.binding_epoch.get(),
            Digest::from_wire_bytes(self.request_digest),
        )
    }

    const fn encode(context: MutationContext) -> Self {
        Self {
            session: context.session.to_wire_bytes(),
            authority_epoch: U64::new(context.authority_epoch),
            binding_epoch: U64::new(context.binding_epoch),
            request_digest: context.request_digest.to_wire_bytes(),
        }
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireRegisterEffectRequest {
    context: WireMutationContext,
    scope: [u8; 16],
    parent: [u8; 16],
    operation_class: U32<LittleEndian>,
    flags: U32<LittleEndian>,
    credit_units: U32<LittleEndian>,
    credit_kind: U16<LittleEndian>,
    reserved: U16<LittleEndian>,
}

const _: () = assert!(core::mem::size_of::<WireRegisterEffectRequest>() == 112);
const _: () = assert!(core::mem::align_of::<WireRegisterEffectRequest>() == 1);

/// Fixed request to register one effect under an existing scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterEffectRequest {
    context: MutationContext,
    scope: ScopeHandle,
    parent: EffectHandle,
    operation_class: u32,
    flags: RegisterFlags,
    credit_kind: CreditKind,
    credit_units: u32,
}

impl RegisterEffectRequest {
    /// Creates a validated effect registration.
    pub fn new(
        context: MutationContext,
        scope: ScopeHandle,
        parent: EffectHandle,
        operation_class: u32,
        flags: RegisterFlags,
        credit_kind: CreditKind,
        credit_units: u32,
    ) -> Result<Self, PortalWireError> {
        let request = Self {
            context,
            scope,
            parent,
            operation_class,
            flags,
            credit_kind,
            credit_units,
        };
        request.validate()?;
        Ok(request)
    }

    /// Returns the common mutation identity.
    #[must_use]
    pub const fn context(self) -> MutationContext {
        self.context
    }

    /// Returns the target scope.
    #[must_use]
    pub const fn scope(self) -> ScopeHandle {
        self.scope
    }

    /// Returns the optional parent effect; null means a root effect.
    #[must_use]
    pub const fn parent(self) -> EffectHandle {
        self.parent
    }

    /// Returns the provider-defined operation class.
    #[must_use]
    pub const fn operation_class(self) -> u32 {
        self.operation_class
    }

    /// Returns immutable registration flags.
    #[must_use]
    pub const fn flags(self) -> RegisterFlags {
        self.flags
    }

    /// Returns the scope credit pool charged by this effect.
    #[must_use]
    pub const fn credit_kind(self) -> CreditKind {
        self.credit_kind
    }

    /// Returns the bounded charge from [`Self::credit_kind`].
    #[must_use]
    pub const fn credit_units(self) -> u32 {
        self.credit_units
    }

    fn validate(self) -> Result<(), PortalWireError> {
        MutationContext::new(
            self.context.session,
            self.context.authority_epoch,
            self.context.binding_epoch,
            self.context.request_digest,
        )?;
        if self.scope.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidHandle, 64));
        }
        if self.operation_class == 0 {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 96));
        }
        if RegisterFlags::from_bits(self.flags.bits()).is_none() {
            return Err(PortalWireError::new(PortalErrorCode::UnknownFlags, 100));
        }
        if self.credit_units == 0 || self.credit_units > MAX_CREDIT_UNITS_PER_EFFECT {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 104));
        }
        Ok(())
    }
}

impl RequestBody for RegisterEffectRequest {
    const OPCODE: Opcode = Opcode::Register;
    const WIRE_SIZE: usize = 112;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireRegisterEffectRequest::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved.get() != 0 {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 110));
        }
        let flags = RegisterFlags::from_bits(raw.flags.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownFlags, 100))?;
        let credit_kind = CreditKind::from_wire_value(raw.credit_kind.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 108))?;
        Self::new(
            raw.context.decode()?,
            ScopeHandle::from_wire_bytes(raw.scope),
            EffectHandle::from_wire_bytes(raw.parent),
            raw.operation_class.get(),
            flags,
            credit_kind,
            raw.credit_units.get(),
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        self.validate()?;
        let raw = WireRegisterEffectRequest {
            context: WireMutationContext::encode(self.context),
            scope: self.scope.to_wire_bytes(),
            parent: self.parent.to_wire_bytes(),
            operation_class: U32::new(self.operation_class),
            flags: U32::new(self.flags.bits()),
            credit_units: U32::new(self.credit_units),
            credit_kind: U16::new(self.credit_kind.wire_value()),
            reserved: U16::new(0),
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WirePrepareEffectRequest {
    context: WireMutationContext,
    effect: [u8; 16],
    reserved: U64<LittleEndian>,
}

const _: () = assert!(core::mem::size_of::<WirePrepareEffectRequest>() == 88);
const _: () = assert!(core::mem::align_of::<WirePrepareEffectRequest>() == 1);

/// Fixed request to prepare one registered effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrepareEffectRequest {
    context: MutationContext,
    effect: EffectHandle,
}

impl PrepareEffectRequest {
    /// Creates a validated prepare request.
    pub fn new(context: MutationContext, effect: EffectHandle) -> Result<Self, PortalWireError> {
        if effect.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidHandle, 64));
        }
        Ok(Self { context, effect })
    }

    /// Returns the common mutation identity.
    #[must_use]
    pub const fn context(self) -> MutationContext {
        self.context
    }

    /// Returns the target effect.
    #[must_use]
    pub const fn effect(self) -> EffectHandle {
        self.effect
    }
}

impl RequestBody for PrepareEffectRequest {
    const OPCODE: Opcode = Opcode::Prepare;
    const WIRE_SIZE: usize = 88;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WirePrepareEffectRequest::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved.get() != 0 {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 80));
        }
        Self::new(
            raw.context.decode()?,
            EffectHandle::from_wire_bytes(raw.effect),
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let request = Self::new(self.context, self.effect)?;
        let raw = WirePrepareEffectRequest {
            context: WireMutationContext::encode(request.context),
            effect: request.effect.to_wire_bytes(),
            reserved: U64::new(0),
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireCommitEffectRequest {
    context: WireMutationContext,
    effect: [u8; 16],
    domain_revision: U64<LittleEndian>,
    reserved: U64<LittleEndian>,
}

const _: () = assert!(core::mem::size_of::<WireCommitEffectRequest>() == 96);
const _: () = assert!(core::mem::align_of::<WireCommitEffectRequest>() == 1);

/// Fixed request to commit one prepared effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitEffectRequest {
    context: MutationContext,
    effect: EffectHandle,
    domain_revision: u64,
}

impl CommitEffectRequest {
    /// Creates a validated commit request.
    pub fn new(
        context: MutationContext,
        effect: EffectHandle,
        domain_revision: u64,
    ) -> Result<Self, PortalWireError> {
        if effect.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidHandle, 64));
        }
        if domain_revision == 0 {
            return Err(PortalWireError::new(
                PortalErrorCode::GenerationMismatch,
                80,
            ));
        }
        Ok(Self {
            context,
            effect,
            domain_revision,
        })
    }

    /// Returns the common mutation identity.
    #[must_use]
    pub const fn context(self) -> MutationContext {
        self.context
    }

    /// Returns the target effect.
    #[must_use]
    pub const fn effect(self) -> EffectHandle {
        self.effect
    }

    /// Returns the provider domain revision accepted by the caller.
    #[must_use]
    pub const fn domain_revision(self) -> u64 {
        self.domain_revision
    }
}

impl RequestBody for CommitEffectRequest {
    const OPCODE: Opcode = Opcode::Commit;
    const WIRE_SIZE: usize = 96;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireCommitEffectRequest::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved.get() != 0 {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 88));
        }
        Self::new(
            raw.context.decode()?,
            EffectHandle::from_wire_bytes(raw.effect),
            raw.domain_revision.get(),
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let request = Self::new(self.context, self.effect, self.domain_revision)?;
        let raw = WireCommitEffectRequest {
            context: WireMutationContext::encode(request.context),
            effect: request.effect.to_wire_bytes(),
            domain_revision: U64::new(request.domain_revision),
            reserved: U64::new(0),
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireRecordOutcomeRequest {
    context: WireMutationContext,
    effect: [u8; 16],
    outcome_kind: U16<LittleEndian>,
    reserved: [u8; 6],
    result: U64<LittleEndian>,
    outcome_digest: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<WireRecordOutcomeRequest>() == 128);
const _: () = assert!(core::mem::align_of::<WireRecordOutcomeRequest>() == 1);

/// Fixed request to record one canonical backend outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordOutcomeRequest {
    context: MutationContext,
    effect: EffectHandle,
    outcome_kind: OutcomeKind,
    result: i64,
    outcome_digest: Digest,
}

impl RecordOutcomeRequest {
    /// Creates a validated outcome request.
    pub fn new(
        context: MutationContext,
        effect: EffectHandle,
        outcome_kind: OutcomeKind,
        result: i64,
        outcome_digest: Digest,
    ) -> Result<Self, PortalWireError> {
        if effect.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidHandle, 64));
        }
        if outcome_digest.is_zero() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidDigest, 96));
        }
        Ok(Self {
            context,
            effect,
            outcome_kind,
            result,
            outcome_digest,
        })
    }

    /// Returns the common mutation identity.
    #[must_use]
    pub const fn context(self) -> MutationContext {
        self.context
    }

    /// Returns the target effect.
    #[must_use]
    pub const fn effect(self) -> EffectHandle {
        self.effect
    }

    /// Returns the canonical outcome class.
    #[must_use]
    pub const fn outcome_kind(self) -> OutcomeKind {
        self.outcome_kind
    }

    /// Returns the stable provider result value.
    #[must_use]
    pub const fn result(self) -> i64 {
        self.result
    }

    /// Returns the canonical outcome digest.
    #[must_use]
    pub const fn outcome_digest(self) -> Digest {
        self.outcome_digest
    }
}

impl RequestBody for RecordOutcomeRequest {
    const OPCODE: Opcode = Opcode::RecordOutcome;
    const WIRE_SIZE: usize = 128;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireRecordOutcomeRequest::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved != [0; 6] {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 82));
        }
        let outcome_kind = OutcomeKind::from_wire_value(raw.outcome_kind.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 80))?;
        Self::new(
            raw.context.decode()?,
            EffectHandle::from_wire_bytes(raw.effect),
            outcome_kind,
            raw.result.get() as i64,
            Digest::from_wire_bytes(raw.outcome_digest),
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let request = Self::new(
            self.context,
            self.effect,
            self.outcome_kind,
            self.result,
            self.outcome_digest,
        )?;
        let raw = WireRecordOutcomeRequest {
            context: WireMutationContext::encode(request.context),
            effect: request.effect.to_wire_bytes(),
            outcome_kind: U16::new(request.outcome_kind.wire_value()),
            reserved: [0; 6],
            result: U64::new(request.result as u64),
            outcome_digest: request.outcome_digest.to_wire_bytes(),
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireCompleteEffectRequest {
    context: WireMutationContext,
    effect: [u8; 16],
    disposition: U16<LittleEndian>,
    reserved: [u8; 6],
    terminal_digest: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<WireCompleteEffectRequest>() == 120);
const _: () = assert!(core::mem::align_of::<WireCompleteEffectRequest>() == 1);

/// Fixed request to terminalize one effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompleteEffectRequest {
    context: MutationContext,
    effect: EffectHandle,
    disposition: CompletionDisposition,
    terminal_digest: Digest,
}

impl CompleteEffectRequest {
    /// Creates a validated completion request.
    pub fn new(
        context: MutationContext,
        effect: EffectHandle,
        disposition: CompletionDisposition,
        terminal_digest: Digest,
    ) -> Result<Self, PortalWireError> {
        if effect.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidHandle, 64));
        }
        if terminal_digest.is_zero() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidDigest, 88));
        }
        Ok(Self {
            context,
            effect,
            disposition,
            terminal_digest,
        })
    }

    /// Returns the common mutation identity.
    #[must_use]
    pub const fn context(self) -> MutationContext {
        self.context
    }

    /// Returns the target effect.
    #[must_use]
    pub const fn effect(self) -> EffectHandle {
        self.effect
    }

    /// Returns the requested terminal disposition.
    #[must_use]
    pub const fn disposition(self) -> CompletionDisposition {
        self.disposition
    }

    /// Returns the canonical terminal manifest digest.
    #[must_use]
    pub const fn terminal_digest(self) -> Digest {
        self.terminal_digest
    }
}

impl RequestBody for CompleteEffectRequest {
    const OPCODE: Opcode = Opcode::Complete;
    const WIRE_SIZE: usize = 120;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireCompleteEffectRequest::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved != [0; 6] {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 82));
        }
        let disposition = CompletionDisposition::from_wire_value(raw.disposition.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 80))?;
        Self::new(
            raw.context.decode()?,
            EffectHandle::from_wire_bytes(raw.effect),
            disposition,
            Digest::from_wire_bytes(raw.terminal_digest),
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let request = Self::new(
            self.context,
            self.effect,
            self.disposition,
            self.terminal_digest,
        )?;
        let raw = WireCompleteEffectRequest {
            context: WireMutationContext::encode(request.context),
            effect: request.effect.to_wire_bytes(),
            disposition: U16::new(request.disposition.wire_value()),
            reserved: [0; 6],
            terminal_digest: request.terminal_digest.to_wire_bytes(),
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireRevokeScopeRequest {
    context: WireMutationContext,
    scope: [u8; 16],
    reason: U16<LittleEndian>,
    reserved: [u8; 6],
}

const _: () = assert!(core::mem::size_of::<WireRevokeScopeRequest>() == 88);
const _: () = assert!(core::mem::align_of::<WireRevokeScopeRequest>() == 1);

/// Fixed request to revoke one scope authority epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevokeScopeRequest {
    context: MutationContext,
    scope: ScopeHandle,
    reason: RevokeReason,
}

impl RevokeScopeRequest {
    /// Creates a validated revoke request.
    pub fn new(
        context: MutationContext,
        scope: ScopeHandle,
        reason: RevokeReason,
    ) -> Result<Self, PortalWireError> {
        if scope.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidHandle, 64));
        }
        Ok(Self {
            context,
            scope,
            reason,
        })
    }

    /// Returns the common mutation identity.
    #[must_use]
    pub const fn context(self) -> MutationContext {
        self.context
    }

    /// Returns the target scope.
    #[must_use]
    pub const fn scope(self) -> ScopeHandle {
        self.scope
    }

    /// Returns the recorded revoke reason.
    #[must_use]
    pub const fn reason(self) -> RevokeReason {
        self.reason
    }
}

impl RequestBody for RevokeScopeRequest {
    const OPCODE: Opcode = Opcode::Revoke;
    const WIRE_SIZE: usize = 88;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireRevokeScopeRequest::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved != [0; 6] {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 82));
        }
        let reason = RevokeReason::from_wire_value(raw.reason.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 80))?;
        Self::new(
            raw.context.decode()?,
            ScopeHandle::from_wire_bytes(raw.scope),
            reason,
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let request = Self::new(self.context, self.scope, self.reason)?;
        let raw = WireRevokeScopeRequest {
            context: WireMutationContext::encode(request.context),
            scope: request.scope.to_wire_bytes(),
            reason: U16::new(request.reason.wire_value()),
            reserved: [0; 6],
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}
