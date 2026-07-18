// SPDX-License-Identifier: MPL-2.0

//! ABI discovery and capability-negotiation response bodies.

use zerocopy::byteorder::{LittleEndian, U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::request::require_size;
use crate::{
    CapabilityOffer, NegotiatedCapabilities, PortalCapabilities, PortalErrorCode, PortalWireError,
    ProviderCapabilities, SessionHandle,
};

use super::{MAX_MUTATION_BODY_SIZE, MAX_RESPONSE_BODY_SIZE, ResponseBody};

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireAbiResponse {
    major: U16<LittleEndian>,
    minor: U16<LittleEndian>,
    reserved0: U32<LittleEndian>,
    max_header_size: U32<LittleEndian>,
    max_body_size: U32<LittleEndian>,
    max_response_body_size: U32<LittleEndian>,
    max_mutation_body_size: U32<LittleEndian>,
    portal: U64<LittleEndian>,
    provider: U64<LittleEndian>,
    max_effects: U32<LittleEndian>,
    max_tombstones: U32<LittleEndian>,
    max_queue_credits: U32<LittleEndian>,
    max_page_credits: U32<LittleEndian>,
    reserved1: U64<LittleEndian>,
}

const _: () = assert!(core::mem::size_of::<WireAbiResponse>() == 64);
const _: () = assert!(core::mem::align_of::<WireAbiResponse>() == 1);

/// Fixed ABI and provider-offer response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbiResponse {
    offer: CapabilityOffer,
}

impl AbiResponse {
    /// Creates an ABI response for one endpoint offer.
    #[must_use]
    pub const fn new(offer: CapabilityOffer) -> Self {
        Self { offer }
    }

    /// Returns the endpoint capability offer.
    #[must_use]
    pub const fn offer(self) -> CapabilityOffer {
        self.offer
    }
}

impl ResponseBody for AbiResponse {
    const WIRE_SIZE: usize = 64;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireAbiResponse::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved0.get() != 0 || raw.reserved1.get() != 0 {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 4));
        }
        if raw.major.get() != crate::VERSION_MAJOR
            || raw.minor.get() != crate::VERSION_MINOR
            || usize::try_from(raw.max_header_size.get()).ok() != Some(crate::MAX_HEADER_SIZE)
            || usize::try_from(raw.max_body_size.get()).ok() != Some(crate::MAX_BODY_SIZE)
            || usize::try_from(raw.max_response_body_size.get()).ok()
                != Some(MAX_RESPONSE_BODY_SIZE)
            || usize::try_from(raw.max_mutation_body_size.get()).ok()
                != Some(MAX_MUTATION_BODY_SIZE)
            || raw.max_effects.get() != crate::MAX_EFFECTS_PER_SCOPE
            || raw.max_tombstones.get() != crate::MAX_TOMBSTONES_PER_SCOPE
            || raw.max_queue_credits.get() != crate::MAX_QUEUE_CREDITS_PER_SCOPE
            || raw.max_page_credits.get() != crate::MAX_PAGE_CREDITS_PER_SCOPE
        {
            return Err(PortalWireError::new(PortalErrorCode::UnsupportedVersion, 0));
        }
        let portal = PortalCapabilities::from_bits(raw.portal.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownCapability, 24))?;
        let provider = ProviderCapabilities::from_bits(raw.provider.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownCapability, 32))?;
        Ok(Self::new(CapabilityOffer { portal, provider }))
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        if PortalCapabilities::from_bits(self.offer.portal.bits()).is_none()
            || ProviderCapabilities::from_bits(self.offer.provider.bits()).is_none()
        {
            return Err(PortalWireError::new(PortalErrorCode::UnknownCapability, 24));
        }
        let raw = WireAbiResponse {
            major: U16::new(crate::VERSION_MAJOR),
            minor: U16::new(crate::VERSION_MINOR),
            reserved0: U32::new(0),
            max_header_size: U32::new(crate::MAX_HEADER_SIZE as u32),
            max_body_size: U32::new(crate::MAX_BODY_SIZE as u32),
            max_response_body_size: U32::new(MAX_RESPONSE_BODY_SIZE as u32),
            max_mutation_body_size: U32::new(MAX_MUTATION_BODY_SIZE as u32),
            portal: U64::new(self.offer.portal.bits()),
            provider: U64::new(self.offer.provider.bits()),
            max_effects: U32::new(crate::MAX_EFFECTS_PER_SCOPE),
            max_tombstones: U32::new(crate::MAX_TOMBSTONES_PER_SCOPE),
            max_queue_credits: U32::new(crate::MAX_QUEUE_CREDITS_PER_SCOPE),
            max_page_credits: U32::new(crate::MAX_PAGE_CREDITS_PER_SCOPE),
            reserved1: U64::new(0),
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireNegotiatedResponse {
    session: [u8; 16],
    portal: U64<LittleEndian>,
    provider: U64<LittleEndian>,
    max_mutation_body_size: U32<LittleEndian>,
    max_response_body_size: U32<LittleEndian>,
    reserved: U64<LittleEndian>,
}

const _: () = assert!(core::mem::size_of::<WireNegotiatedResponse>() == 48);
const _: () = assert!(core::mem::align_of::<WireNegotiatedResponse>() == 1);

/// Successful capability negotiation response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NegotiatedResponse {
    session: SessionHandle,
    selected: NegotiatedCapabilities,
}

impl NegotiatedResponse {
    /// Creates a validated negotiation response.
    pub fn new(
        session: SessionHandle,
        selected: NegotiatedCapabilities,
    ) -> Result<Self, PortalWireError> {
        if session.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidSession, 0));
        }
        if PortalCapabilities::from_bits(selected.portal.bits()).is_none() {
            return Err(PortalWireError::new(PortalErrorCode::UnknownCapability, 16));
        }
        if ProviderCapabilities::from_bits(selected.provider.bits()).is_none() {
            return Err(PortalWireError::new(PortalErrorCode::UnknownCapability, 24));
        }
        Ok(Self { session, selected })
    }

    /// Returns the negotiated session handle.
    #[must_use]
    pub const fn session(self) -> SessionHandle {
        self.session
    }

    /// Returns the selected capability subset.
    #[must_use]
    pub const fn selected(self) -> NegotiatedCapabilities {
        self.selected
    }
}

impl ResponseBody for NegotiatedResponse {
    const WIRE_SIZE: usize = 48;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireNegotiatedResponse::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved.get() != 0 {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 40));
        }
        if usize::try_from(raw.max_mutation_body_size.get()).ok() != Some(MAX_MUTATION_BODY_SIZE)
            || usize::try_from(raw.max_response_body_size.get()).ok()
                != Some(MAX_RESPONSE_BODY_SIZE)
        {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 32));
        }
        let portal = PortalCapabilities::from_bits(raw.portal.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownCapability, 16))?;
        let provider = ProviderCapabilities::from_bits(raw.provider.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownCapability, 24))?;
        Self::new(
            SessionHandle::from_wire_bytes(raw.session),
            NegotiatedCapabilities { portal, provider },
        )
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let response = Self::new(self.session, self.selected)?;
        let raw = WireNegotiatedResponse {
            session: response.session.to_wire_bytes(),
            portal: U64::new(response.selected.portal.bits()),
            provider: U64::new(response.selected.provider.bits()),
            max_mutation_body_size: U32::new(MAX_MUTATION_BODY_SIZE as u32),
            max_response_body_size: U32::new(MAX_RESPONSE_BODY_SIZE as u32),
            reserved: U64::new(0),
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}
