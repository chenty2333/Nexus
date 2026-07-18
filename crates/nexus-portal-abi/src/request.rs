// SPDX-License-Identifier: MPL-2.0

//! Fixed request bodies and bounded creation limits.
//!
//! `QueryAbi` has an empty body; `Negotiate` is 32 bytes; `CreateScope` is 104
//! bytes; and each opaque-handle query is 16 bytes.  No request accepts a
//! serializer-defined extension, trailing bytes, or an unbounded collection.

use bitflags::bitflags;
use zerocopy::byteorder::{LittleEndian, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    CapabilityRequest, Digest, EffectHandle, Opcode, PortalCapabilities, PortalErrorCode,
    PortalWireError, ProviderCapabilities, ReceiptHandle, ScopeHandle, SessionHandle,
};

/// Maximum number of live and terminal effects configured for one scope.
pub const MAX_EFFECTS_PER_SCOPE: u32 = 4096;
/// Maximum number of retained tombstone slots configured for one scope.
pub const MAX_TOMBSTONES_PER_SCOPE: u32 = 1024;
/// Maximum queue-credit units configured for one scope.
pub const MAX_QUEUE_CREDITS_PER_SCOPE: u32 = 4096;
/// Maximum page-credit units configured for one scope.
pub const MAX_PAGE_CREDITS_PER_SCOPE: u32 = 16_384;

bitflags! {
    /// Creation policy understood by the v2-preview scope allocator.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct CreateScopeFlags: u32 {
        /// The new scope may later be used as a parent for bounded child scopes.
        const ALLOW_CHILD_SCOPES = 1 << 0;
    }
}

/// Contract implemented by every fixed-size portal request body.
pub trait RequestBody: Sized {
    /// Opcode that selects this request body.
    const OPCODE: Opcode;
    /// Exact accepted and emitted body length.
    const WIRE_SIZE: usize;

    /// Decodes an exact-size request body and validates all reserved fields.
    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError>;

    /// Encodes into an output slice whose length must equal [`Self::WIRE_SIZE`].
    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError>;
}

pub(crate) fn require_size(bytes: &[u8], size: usize) -> Result<(), PortalWireError> {
    if bytes.len() != size {
        return Err(PortalWireError::new(
            PortalErrorCode::BodySizeMismatch,
            bytes.len(),
        ));
    }
    Ok(())
}

/// Empty request body for [`Opcode::QueryAbi`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueryAbiRequest;

impl QueryAbiRequest {
    /// Creates the empty ABI query.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl RequestBody for QueryAbiRequest {
    const OPCODE: Opcode = Opcode::QueryAbi;
    const WIRE_SIZE: usize = 0;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        Ok(Self)
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireNegotiateRequest {
    requested_portal: U64<LittleEndian>,
    required_portal: U64<LittleEndian>,
    requested_provider: U64<LittleEndian>,
    required_provider: U64<LittleEndian>,
}

const _: () = assert!(core::mem::size_of::<WireNegotiateRequest>() == 32);
const _: () = assert!(core::mem::align_of::<WireNegotiateRequest>() == 1);

/// Fixed capability negotiation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NegotiateRequest {
    capabilities: CapabilityRequest,
}

impl NegotiateRequest {
    /// Creates a negotiation request.
    #[must_use]
    pub const fn new(capabilities: CapabilityRequest) -> Self {
        Self { capabilities }
    }

    /// Returns requested and required capability masks.
    #[must_use]
    pub const fn capabilities(self) -> CapabilityRequest {
        self.capabilities
    }
}

impl RequestBody for NegotiateRequest {
    const OPCODE: Opcode = Opcode::Negotiate;
    const WIRE_SIZE: usize = 32;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = WireNegotiateRequest::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        let requested_portal = PortalCapabilities::from_bits(raw.requested_portal.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownCapability, 0))?;
        let required_portal = PortalCapabilities::from_bits(raw.required_portal.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownCapability, 8))?;
        let requested_provider = ProviderCapabilities::from_bits(raw.requested_provider.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownCapability, 16))?;
        let required_provider = ProviderCapabilities::from_bits(raw.required_provider.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownCapability, 24))?;
        Ok(Self::new(CapabilityRequest {
            requested_portal,
            required_portal,
            requested_provider,
            required_provider,
        }))
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let capabilities = self.capabilities;
        if PortalCapabilities::from_bits(capabilities.requested_portal.bits()).is_none() {
            return Err(PortalWireError::new(PortalErrorCode::UnknownCapability, 0));
        }
        if PortalCapabilities::from_bits(capabilities.required_portal.bits()).is_none() {
            return Err(PortalWireError::new(PortalErrorCode::UnknownCapability, 8));
        }
        if ProviderCapabilities::from_bits(capabilities.requested_provider.bits()).is_none() {
            return Err(PortalWireError::new(PortalErrorCode::UnknownCapability, 16));
        }
        if ProviderCapabilities::from_bits(capabilities.required_provider.bits()).is_none() {
            return Err(PortalWireError::new(PortalErrorCode::UnknownCapability, 24));
        }
        let raw = WireNegotiateRequest {
            requested_portal: U64::new(capabilities.requested_portal.bits()),
            required_portal: U64::new(capabilities.required_portal.bits()),
            requested_provider: U64::new(capabilities.requested_provider.bits()),
            required_provider: U64::new(capabilities.required_provider.bits()),
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireCreateScopeRequest {
    session: [u8; 16],
    parent: [u8; 16],
    parent_authority_epoch: U64<LittleEndian>,
    parent_binding_epoch: U64<LittleEndian>,
    request_digest: [u8; 32],
    flags: U32<LittleEndian>,
    max_effects: U32<LittleEndian>,
    max_tombstones: U32<LittleEndian>,
    queue_credits: U32<LittleEndian>,
    page_credits: U32<LittleEndian>,
    reserved: U32<LittleEndian>,
}

const _: () = assert!(core::mem::size_of::<WireCreateScopeRequest>() == 104);
const _: () = assert!(core::mem::align_of::<WireCreateScopeRequest>() == 1);

/// Fixed request to create one finite causal scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateScopeRequest {
    session: SessionHandle,
    parent: ScopeHandle,
    parent_authority_epoch: u64,
    parent_binding_epoch: u64,
    request_digest: Digest,
    flags: CreateScopeFlags,
    max_effects: u32,
    max_tombstones: u32,
    queue_credits: u32,
    page_credits: u32,
}

impl CreateScopeRequest {
    /// Creates and validates a bounded scope request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session: SessionHandle,
        parent: ScopeHandle,
        parent_authority_epoch: u64,
        parent_binding_epoch: u64,
        request_digest: Digest,
        flags: CreateScopeFlags,
        max_effects: u32,
        max_tombstones: u32,
        queue_credits: u32,
        page_credits: u32,
    ) -> Result<Self, PortalWireError> {
        let request = Self {
            session,
            parent,
            parent_authority_epoch,
            parent_binding_epoch,
            request_digest,
            flags,
            max_effects,
            max_tombstones,
            queue_credits,
            page_credits,
        };
        request.validate()?;
        Ok(request)
    }

    /// Returns the negotiated session selector.
    #[must_use]
    pub const fn session(self) -> SessionHandle {
        self.session
    }

    /// Returns the optional parent scope selector; zero means a root scope.
    #[must_use]
    pub const fn parent(self) -> ScopeHandle {
        self.parent
    }

    /// Returns the parent authority epoch, or zero for a new root scope.
    #[must_use]
    pub const fn parent_authority_epoch(self) -> u64 {
        self.parent_authority_epoch
    }

    /// Returns the parent binding epoch, or zero for a new root scope.
    #[must_use]
    pub const fn parent_binding_epoch(self) -> u64 {
        self.parent_binding_epoch
    }

    /// Returns the canonical creation request digest.
    #[must_use]
    pub const fn request_digest(self) -> Digest {
        self.request_digest
    }

    /// Returns creation policy flags.
    #[must_use]
    pub const fn flags(self) -> CreateScopeFlags {
        self.flags
    }

    /// Returns the configured effect-slot maximum.
    #[must_use]
    pub const fn max_effects(self) -> u32 {
        self.max_effects
    }

    /// Returns the configured tombstone-slot maximum.
    #[must_use]
    pub const fn max_tombstones(self) -> u32 {
        self.max_tombstones
    }

    /// Returns the configured queue-credit maximum.
    #[must_use]
    pub const fn queue_credits(self) -> u32 {
        self.queue_credits
    }

    /// Returns the configured page-credit maximum.
    #[must_use]
    pub const fn page_credits(self) -> u32 {
        self.page_credits
    }

    fn validate(self) -> Result<(), PortalWireError> {
        if self.session.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidSession, 0));
        }
        if self.parent.is_null() {
            if self.parent_authority_epoch != 0 || self.parent_binding_epoch != 0 {
                return Err(PortalWireError::new(
                    PortalErrorCode::GenerationMismatch,
                    32,
                ));
            }
        } else if self.parent_authority_epoch == 0 || self.parent_binding_epoch == 0 {
            return Err(PortalWireError::new(
                PortalErrorCode::GenerationMismatch,
                32,
            ));
        }
        if self.request_digest.is_zero() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidDigest, 48));
        }
        if CreateScopeFlags::from_bits(self.flags.bits()).is_none() {
            return Err(PortalWireError::new(PortalErrorCode::UnknownFlags, 80));
        }
        if self.max_effects == 0 || self.max_effects > MAX_EFFECTS_PER_SCOPE {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 84));
        }
        if self.max_tombstones == 0 || self.max_tombstones > MAX_TOMBSTONES_PER_SCOPE {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 88));
        }
        if self.queue_credits > MAX_QUEUE_CREDITS_PER_SCOPE {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 92));
        }
        if self.page_credits > MAX_PAGE_CREDITS_PER_SCOPE {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 96));
        }
        Ok(())
    }
}

impl RequestBody for CreateScopeRequest {
    const OPCODE: Opcode = Opcode::CreateScope;
    const WIRE_SIZE: usize = 104;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = WireCreateScopeRequest::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved.get() != 0 {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 100));
        }
        let flags = CreateScopeFlags::from_bits(raw.flags.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownFlags, 80))?;
        Self::new(
            SessionHandle::from_wire_bytes(raw.session),
            ScopeHandle::from_wire_bytes(raw.parent),
            raw.parent_authority_epoch.get(),
            raw.parent_binding_epoch.get(),
            Digest::from_wire_bytes(raw.request_digest),
            flags,
            raw.max_effects.get(),
            raw.max_tombstones.get(),
            raw.queue_credits.get(),
            raw.page_credits.get(),
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        self.validate()?;
        let raw = WireCreateScopeRequest {
            session: self.session.to_wire_bytes(),
            parent: self.parent.to_wire_bytes(),
            parent_authority_epoch: U64::new(self.parent_authority_epoch),
            parent_binding_epoch: U64::new(self.parent_binding_epoch),
            request_digest: self.request_digest.to_wire_bytes(),
            flags: U32::new(self.flags.bits()),
            max_effects: U32::new(self.max_effects),
            max_tombstones: U32::new(self.max_tombstones),
            queue_credits: U32::new(self.queue_credits),
            page_credits: U32::new(self.page_credits),
            reserved: U32::new(0),
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}

macro_rules! query_request {
    ($name:ident, $handle:ty, $opcode:expr, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name {
            handle: $handle,
        }

        impl $name {
            /// Creates a query for an opaque selector.
            #[must_use]
            pub const fn new(handle: $handle) -> Self {
                Self { handle }
            }

            /// Returns the opaque selector to be validated by the Registry.
            #[must_use]
            pub const fn handle(self) -> $handle {
                self.handle
            }
        }

        impl RequestBody for $name {
            const OPCODE: Opcode = $opcode;
            const WIRE_SIZE: usize = 16;

            fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
                require_size(input, Self::WIRE_SIZE)?;
                let bytes: [u8; 16] = input.try_into().map_err(|_| {
                    PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len())
                })?;
                Ok(Self::new(<$handle>::from_wire_bytes(bytes)))
            }

            fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
                require_size(output, Self::WIRE_SIZE)?;
                output.copy_from_slice(&self.handle.to_wire_bytes());
                Ok(())
            }
        }
    };
}

query_request!(
    QueryScopeRequest,
    ScopeHandle,
    Opcode::QueryScope,
    "Fixed request to query one scope through an opaque handle."
);
query_request!(
    QueryEffectRequest,
    EffectHandle,
    Opcode::QueryEffect,
    "Fixed request to query one effect through an opaque handle."
);
query_request!(
    QueryReceiptRequest,
    ReceiptHandle,
    Opcode::QueryReceipt,
    "Fixed request to query one receipt through an opaque handle."
);
