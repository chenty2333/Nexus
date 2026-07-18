// SPDX-License-Identifier: MPL-2.0

//! Portal and effect-provider capability negotiation.
//!
//! The selected set is `offered & (requested | required)`.  Negotiation first
//! rejects unknown bits and then rejects every missing required bit.  Optional
//! unsupported bits are absent from the selected set.

use bitflags::bitflags;

use crate::PortalErrorCode;

bitflags! {
    /// Capabilities implemented by the kernel portal endpoint.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct PortalCapabilities: u64 {
        /// Query ABI version, limits, and offered capabilities.
        const QUERY_ABI = 1 << 0;
        /// Negotiate requested and required capability sets.
        const NEGOTIATE = 1 << 1;
        /// Create a bounded causal scope.
        const CREATE_SCOPE = 1 << 2;
        /// Inspect a scope through an opaque current handle.
        const QUERY_SCOPE = 1 << 3;
        /// Inspect an effect through an opaque current handle.
        const QUERY_EFFECT = 1 << 4;
        /// Inspect a receipt through an opaque current handle.
        const QUERY_RECEIPT = 1 << 5;
        /// Register, prepare, commit, record outcomes, and complete effects.
        const EFFECT_LIFECYCLE = 1 << 6;
        /// Revoke a scope and receive a bounded closure receipt.
        const REVOKE_SCOPE = 1 << 7;
    }
}

bitflags! {
    /// Effect-provider capabilities visible through the portal boundary.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ProviderCapabilities: u64 {
        /// Register, prepare, commit, and drive scope-revoke closure.
        ///
        /// Outcome recording and terminal effect completion are negotiated
        /// separately so a provider cannot accidentally advertise them by
        /// implementing only the core closure protocol.
        const EFFECT_CLOSURE = 1 << 0;
        /// Execute the bounded logical-request provider profile.
        const LOGICAL_REQUEST = 1 << 1;
        /// Recover effects through service crash, rebind, and explicit adoption.
        const SERVICE_REBIND = 1 << 2;
        /// Inspect and recover retained device owners and tombstones.
        const RETAINED_DEVICE = 1 << 3;
        /// Persist an identity-preserving handoff record across provider restart.
        const PERSISTENT_HANDOFF = 1 << 4;
        /// Record a canonical backend outcome after effect commit.
        const OUTCOME_RECORDING = 1 << 5;
        /// Terminalize an effect after its required outcome is recorded.
        const EFFECT_COMPLETION = 1 << 6;
        /// Return session-local scope, effect, and receipt observations.
        const SESSION_QUERY = 1 << 7;
    }
}

/// Portal operations required for every useful v2-preview endpoint.
pub const BASE_PORTAL_CAPABILITIES: PortalCapabilities = PortalCapabilities::QUERY_ABI
    .union(PortalCapabilities::NEGOTIATE)
    .union(PortalCapabilities::QUERY_SCOPE)
    .union(PortalCapabilities::QUERY_EFFECT)
    .union(PortalCapabilities::QUERY_RECEIPT);

/// Capabilities offered by one portal and its effect provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityOffer {
    /// Operations offered by the portal endpoint.
    pub portal: PortalCapabilities,
    /// Behaviors offered by the effect provider behind the portal.
    pub provider: ProviderCapabilities,
}

/// Optional and mandatory capabilities requested by a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityRequest {
    /// Optional portal operations the caller wants when available.
    pub requested_portal: PortalCapabilities,
    /// Portal operations without which the caller must not proceed.
    pub required_portal: PortalCapabilities,
    /// Optional provider behaviors the caller wants when available.
    pub requested_provider: ProviderCapabilities,
    /// Provider behaviors without which the caller must not proceed.
    pub required_provider: ProviderCapabilities,
}

/// The offered subset selected for one caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NegotiatedCapabilities {
    /// Selected portal operations.
    pub portal: PortalCapabilities,
    /// Selected provider behaviors.
    pub provider: ProviderCapabilities,
}

/// A capability negotiation rejected before a mutation callback ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityNegotiationError {
    /// Stable reason for rejection.
    pub code: PortalErrorCode,
    /// Required portal operations not present in the offer.
    pub missing_portal: PortalCapabilities,
    /// Required provider behaviors not present in the offer.
    pub missing_provider: ProviderCapabilities,
}

fn has_unknown_portal(capabilities: PortalCapabilities) -> bool {
    capabilities.bits() & !PortalCapabilities::all().bits() != 0
}

fn has_unknown_provider(capabilities: ProviderCapabilities) -> bool {
    capabilities.bits() & !ProviderCapabilities::all().bits() != 0
}

/// Negotiates an offered/requested/required capability tuple without mutation.
///
/// Required capabilities are checked first.  Unsupported optional capabilities
/// are simply absent from the result.  Unknown bits fail closed.
pub fn negotiate(
    offer: CapabilityOffer,
    request: CapabilityRequest,
) -> Result<NegotiatedCapabilities, CapabilityNegotiationError> {
    if has_unknown_portal(offer.portal)
        || has_unknown_portal(request.requested_portal)
        || has_unknown_portal(request.required_portal)
        || has_unknown_provider(offer.provider)
        || has_unknown_provider(request.requested_provider)
        || has_unknown_provider(request.required_provider)
    {
        return Err(CapabilityNegotiationError {
            code: PortalErrorCode::UnknownCapability,
            missing_portal: PortalCapabilities::empty(),
            missing_provider: ProviderCapabilities::empty(),
        });
    }

    let missing_portal = request.required_portal & !offer.portal;
    let missing_provider = request.required_provider & !offer.provider;
    if !missing_portal.is_empty() || !missing_provider.is_empty() {
        return Err(CapabilityNegotiationError {
            code: PortalErrorCode::MissingRequiredCapability,
            missing_portal,
            missing_provider,
        });
    }

    Ok(NegotiatedCapabilities {
        portal: offer.portal & (request.requested_portal | request.required_portal),
        provider: offer.provider & (request.requested_provider | request.required_provider),
    })
}

/// Negotiates capabilities before invoking a caller-supplied mutation.
///
/// The callback is never invoked when a required capability is absent or any
/// mask contains an unknown bit.  Mutable portal handlers should put their
/// first state-changing step inside this callback.
pub fn negotiate_then<T>(
    offer: CapabilityOffer,
    request: CapabilityRequest,
    mutate: impl FnOnce(NegotiatedCapabilities) -> T,
) -> Result<T, CapabilityNegotiationError> {
    negotiate(offer, request).map(mutate)
}
