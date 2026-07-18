// SPDX-License-Identifier: MPL-2.0

//! ABI discovery and capability-negotiation response bodies.

use zerocopy::byteorder::{LittleEndian, U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::request::require_size;
use crate::{
    CapabilityOffer, NegotiatedCapabilities, PortalCapabilities, PortalErrorCode, PortalWireError,
    ProviderCapabilities, SessionHandle, provider_capability_closure,
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
    max_scopes: U32<LittleEndian>,
    max_effects_per_scope: U32<LittleEndian>,
    max_effect_selectors: U32<LittleEndian>,
    max_tombstones_per_scope: U32<LittleEndian>,
    max_queue_credits_per_scope: U32<LittleEndian>,
    max_page_credits_per_scope: U32<LittleEndian>,
    max_receipts: U32<LittleEndian>,
    max_replay_entries: U32<LittleEndian>,
    reserved1: U64<LittleEndian>,
}

const _: () = assert!(core::mem::size_of::<WireAbiResponse>() == 80);
const _: () = assert!(core::mem::align_of::<WireAbiResponse>() == 1);

/// Effective finite capacities of one portal endpoint/session.
///
/// The protocol maxima still bound individual requests. These values report
/// the smaller implementation limits that callers must use for admission and
/// capacity planning; they are never authority grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalLimits {
    max_scopes: u32,
    max_effects_per_scope: u32,
    max_effect_selectors: u32,
    max_tombstones_per_scope: u32,
    max_queue_credits_per_scope: u32,
    max_page_credits_per_scope: u32,
    max_receipts: u32,
    max_replay_entries: u32,
}

impl PortalLimits {
    /// Protocol-maximal defaults for backends that do not impose a smaller
    /// selector table. Concrete bounded adapters should report exact limits.
    pub const PROTOCOL_MAXIMA: Self = Self {
        max_scopes: u32::MAX,
        max_effects_per_scope: crate::MAX_EFFECTS_PER_SCOPE,
        max_effect_selectors: u32::MAX,
        max_tombstones_per_scope: crate::MAX_TOMBSTONES_PER_SCOPE,
        max_queue_credits_per_scope: crate::MAX_QUEUE_CREDITS_PER_SCOPE,
        max_page_credits_per_scope: crate::MAX_PAGE_CREDITS_PER_SCOPE,
        max_receipts: u32::MAX,
        max_replay_entries: u32::MAX,
    };

    /// Creates a validated effective endpoint limit set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_scopes: u32,
        max_effects_per_scope: u32,
        max_effect_selectors: u32,
        max_tombstones_per_scope: u32,
        max_queue_credits_per_scope: u32,
        max_page_credits_per_scope: u32,
        max_receipts: u32,
        max_replay_entries: u32,
    ) -> Result<Self, PortalWireError> {
        let limits = Self {
            max_scopes,
            max_effects_per_scope,
            max_effect_selectors,
            max_tombstones_per_scope,
            max_queue_credits_per_scope,
            max_page_credits_per_scope,
            max_receipts,
            max_replay_entries,
        };
        limits.validate()?;
        Ok(limits)
    }

    fn validate(self) -> Result<(), PortalWireError> {
        if self.max_scopes == 0 {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 40));
        }
        if self.max_effect_selectors == 0 {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 48));
        }
        if self.max_effects_per_scope == 0
            || self.max_effects_per_scope > crate::MAX_EFFECTS_PER_SCOPE
            || self.max_effects_per_scope > self.max_effect_selectors
        {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 44));
        }
        if self.max_tombstones_per_scope == 0
            || self.max_tombstones_per_scope > crate::MAX_TOMBSTONES_PER_SCOPE
            || self.max_tombstones_per_scope > self.max_effects_per_scope
        {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 52));
        }
        if self.max_queue_credits_per_scope == 0
            || self.max_queue_credits_per_scope > crate::MAX_QUEUE_CREDITS_PER_SCOPE
        {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 56));
        }
        if self.max_page_credits_per_scope == 0
            || self.max_page_credits_per_scope > crate::MAX_PAGE_CREDITS_PER_SCOPE
        {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 60));
        }
        if self.max_receipts == 0 {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 64));
        }
        if self.max_replay_entries == 0 {
            return Err(PortalWireError::new(PortalErrorCode::LimitExceeded, 68));
        }
        Ok(())
    }

    pub(crate) fn with_replay_capacity(self, capacity: u32) -> Result<Self, PortalWireError> {
        Self::new(
            self.max_scopes,
            self.max_effects_per_scope,
            self.max_effect_selectors,
            self.max_tombstones_per_scope,
            self.max_queue_credits_per_scope,
            self.max_page_credits_per_scope,
            self.max_receipts,
            self.max_replay_entries.min(capacity),
        )
    }

    /// Maximum number of scope selectors retained by the endpoint.
    #[must_use]
    pub const fn max_scopes(self) -> u32 {
        self.max_scopes
    }

    /// Maximum lifetime effect records accepted by one scope.
    #[must_use]
    pub const fn max_effects_per_scope(self) -> u32 {
        self.max_effects_per_scope
    }

    /// Maximum effect selectors retained across the endpoint session.
    #[must_use]
    pub const fn max_effect_selectors(self) -> u32 {
        self.max_effect_selectors
    }

    /// Maximum terminal records retained by one scope.
    #[must_use]
    pub const fn max_tombstones_per_scope(self) -> u32 {
        self.max_tombstones_per_scope
    }

    /// Maximum queue-credit capacity configurable for one scope.
    #[must_use]
    pub const fn max_queue_credits_per_scope(self) -> u32 {
        self.max_queue_credits_per_scope
    }

    /// Maximum page-credit capacity configurable for one scope.
    #[must_use]
    pub const fn max_page_credits_per_scope(self) -> u32 {
        self.max_page_credits_per_scope
    }

    /// Maximum receipt selectors retained by the endpoint session.
    #[must_use]
    pub const fn max_receipts(self) -> u32 {
        self.max_receipts
    }

    /// Maximum mutation request IDs retained for exact replay.
    #[must_use]
    pub const fn max_replay_entries(self) -> u32 {
        self.max_replay_entries
    }
}

/// Fixed ABI and provider-offer response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbiResponse {
    offer: CapabilityOffer,
    limits: PortalLimits,
}

impl AbiResponse {
    /// Creates an ABI response with protocol-maximal endpoint limits.
    #[must_use]
    pub const fn new(offer: CapabilityOffer) -> Self {
        Self {
            offer,
            limits: PortalLimits::PROTOCOL_MAXIMA,
        }
    }

    /// Creates an ABI response with concrete finite endpoint limits.
    pub fn with_limits(
        offer: CapabilityOffer,
        limits: PortalLimits,
    ) -> Result<Self, PortalWireError> {
        limits.validate()?;
        Ok(Self { offer, limits })
    }

    /// Returns the endpoint capability offer.
    #[must_use]
    pub const fn offer(self) -> CapabilityOffer {
        self.offer
    }

    /// Returns the effective endpoint/session capacities.
    #[must_use]
    pub const fn limits(self) -> PortalLimits {
        self.limits
    }
}

impl ResponseBody for AbiResponse {
    const WIRE_SIZE: usize = 80;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireAbiResponse::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved0.get() != 0 {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 4));
        }
        if raw.reserved1.get() != 0 {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 72));
        }
        if raw.major.get() != crate::VERSION_MAJOR
            || raw.minor.get() != crate::VERSION_MINOR
            || usize::try_from(raw.max_header_size.get()).ok() != Some(crate::MAX_HEADER_SIZE)
            || usize::try_from(raw.max_body_size.get()).ok() != Some(crate::MAX_BODY_SIZE)
            || usize::try_from(raw.max_response_body_size.get()).ok()
                != Some(MAX_RESPONSE_BODY_SIZE)
            || usize::try_from(raw.max_mutation_body_size.get()).ok()
                != Some(MAX_MUTATION_BODY_SIZE)
        {
            return Err(PortalWireError::new(PortalErrorCode::UnsupportedVersion, 0));
        }
        let portal = PortalCapabilities::from_bits(raw.portal.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownCapability, 24))?;
        let provider = ProviderCapabilities::from_bits(raw.provider.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownCapability, 32))?;
        if provider_capability_closure(provider) != provider {
            return Err(PortalWireError::new(
                PortalErrorCode::MissingRequiredCapability,
                32,
            ));
        }
        let limits = PortalLimits::new(
            raw.max_scopes.get(),
            raw.max_effects_per_scope.get(),
            raw.max_effect_selectors.get(),
            raw.max_tombstones_per_scope.get(),
            raw.max_queue_credits_per_scope.get(),
            raw.max_page_credits_per_scope.get(),
            raw.max_receipts.get(),
            raw.max_replay_entries.get(),
        )?;
        Self::with_limits(CapabilityOffer { portal, provider }, limits)
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        if PortalCapabilities::from_bits(self.offer.portal.bits()).is_none() {
            return Err(PortalWireError::new(PortalErrorCode::UnknownCapability, 24));
        }
        if ProviderCapabilities::from_bits(self.offer.provider.bits()).is_none() {
            return Err(PortalWireError::new(PortalErrorCode::UnknownCapability, 32));
        }
        if provider_capability_closure(self.offer.provider) != self.offer.provider {
            return Err(PortalWireError::new(
                PortalErrorCode::MissingRequiredCapability,
                32,
            ));
        }
        self.limits.validate()?;
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
            max_scopes: U32::new(self.limits.max_scopes),
            max_effects_per_scope: U32::new(self.limits.max_effects_per_scope),
            max_effect_selectors: U32::new(self.limits.max_effect_selectors),
            max_tombstones_per_scope: U32::new(self.limits.max_tombstones_per_scope),
            max_queue_credits_per_scope: U32::new(self.limits.max_queue_credits_per_scope),
            max_page_credits_per_scope: U32::new(self.limits.max_page_credits_per_scope),
            max_receipts: U32::new(self.limits.max_receipts),
            max_replay_entries: U32::new(self.limits.max_replay_entries),
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
        if provider_capability_closure(selected.provider) != selected.provider {
            return Err(PortalWireError::new(
                PortalErrorCode::MissingRequiredCapability,
                24,
            ));
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
