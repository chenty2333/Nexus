// SPDX-License-Identifier: MPL-2.0

//! Stable portal error codes and local wire-validation failures.

use core::fmt;

/// Stable error codes returned by the portal-v2 boundary.
///
/// Numeric values are part of the wire contract.  Decoders must reject values
/// not returned by [`PortalErrorCode::from_wire_value`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PortalErrorCode {
    /// The message ended before the fixed header was available.
    HeaderTooShort = 1,
    /// The header did not carry the `nexus.portal.v2` magic.
    BadMagic = 2,
    /// The major or minor protocol version is unsupported.
    UnsupportedVersion = 3,
    /// The message-kind discriminant is unknown.
    UnknownMessageKind = 4,
    /// The operation discriminant is unknown.
    UnknownOpcode = 5,
    /// A header or request contained unknown or context-invalid flags.
    UnknownFlags = 6,
    /// The declared header size is outside the bounded contract.
    InvalidHeaderSize = 7,
    /// The declared body is larger than the portal-v2 limit.
    BodyTooLarge = 8,
    /// Declared and supplied message lengths differ or arithmetic overflowed.
    MessageLengthMismatch = 9,
    /// Reserved bytes or a header extension contained a non-zero byte.
    NonZeroTail = 10,
    /// A fixed request body had the wrong byte length.
    BodySizeMismatch = 11,
    /// A requested bounded resource limit was zero or too large.
    LimitExceeded = 12,
    /// A capability mask contained an unknown bit.
    UnknownCapability = 13,
    /// The provider did not offer every required capability.
    MissingRequiredCapability = 14,
    /// An opaque handle was invalid for the requested operation.
    InvalidHandle = 15,
    /// The handle names an old binding or object generation.
    StaleHandle = 16,
    /// The portal caller does not match the handle's Registry binding.
    CallerMismatch = 17,
    /// The authority, binding, device, or object generation mismatched.
    GenerationMismatch = 18,
    /// A linear receipt was already consumed.
    ReceiptConsumed = 19,
    /// The selected object does not exist.
    NotFound = 20,
    /// Typed credit was unavailable.
    NoCredit = 21,
    /// Admission must wait for bounded capacity.
    Backpressure = 22,
    /// The requested transition conflicts with current Registry state.
    Conflict = 23,
    /// The caller lacks permission for the operation.
    PermissionDenied = 24,
    /// A kernel-only invariant failed after validated input.
    InternalInvariant = 25,
    /// A state-changing operation arrived before successful negotiation.
    NegotiationRequired = 26,
    /// The operation was not selected by this session's negotiation.
    CapabilityNotNegotiated = 27,
    /// A body carried an unassigned enum discriminant.
    InvalidEnum = 28,
    /// A mutating body carried the all-zero digest marker.
    InvalidDigest = 29,
    /// A request id was zero or otherwise invalid for replay tracking.
    InvalidRequestId = 30,
    /// A mutating body named another negotiated session.
    InvalidSession = 31,
    /// A lifecycle transition was validly encoded but out of order.
    OutOfOrder = 32,
}

impl PortalErrorCode {
    /// Returns the stable little-endian wire value for this code.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Parses a stable wire value, rejecting every unassigned value.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::HeaderTooShort),
            2 => Some(Self::BadMagic),
            3 => Some(Self::UnsupportedVersion),
            4 => Some(Self::UnknownMessageKind),
            5 => Some(Self::UnknownOpcode),
            6 => Some(Self::UnknownFlags),
            7 => Some(Self::InvalidHeaderSize),
            8 => Some(Self::BodyTooLarge),
            9 => Some(Self::MessageLengthMismatch),
            10 => Some(Self::NonZeroTail),
            11 => Some(Self::BodySizeMismatch),
            12 => Some(Self::LimitExceeded),
            13 => Some(Self::UnknownCapability),
            14 => Some(Self::MissingRequiredCapability),
            15 => Some(Self::InvalidHandle),
            16 => Some(Self::StaleHandle),
            17 => Some(Self::CallerMismatch),
            18 => Some(Self::GenerationMismatch),
            19 => Some(Self::ReceiptConsumed),
            20 => Some(Self::NotFound),
            21 => Some(Self::NoCredit),
            22 => Some(Self::Backpressure),
            23 => Some(Self::Conflict),
            24 => Some(Self::PermissionDenied),
            25 => Some(Self::InternalInvariant),
            26 => Some(Self::NegotiationRequired),
            27 => Some(Self::CapabilityNotNegotiated),
            28 => Some(Self::InvalidEnum),
            29 => Some(Self::InvalidDigest),
            30 => Some(Self::InvalidRequestId),
            31 => Some(Self::InvalidSession),
            32 => Some(Self::OutOfOrder),
            _ => None,
        }
    }
}

/// A fail-closed wire or request-validation failure.
///
/// `offset` is the first byte associated with the failure when one exists.  It
/// is diagnostic only and must never be used as authority or retry policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalWireError {
    code: PortalErrorCode,
    offset: usize,
}

impl PortalWireError {
    /// Creates a validation failure at a byte offset.
    #[must_use]
    pub const fn new(code: PortalErrorCode, offset: usize) -> Self {
        Self { code, offset }
    }

    /// Returns the stable error code.
    #[must_use]
    pub const fn code(self) -> PortalErrorCode {
        self.code
    }

    /// Returns the diagnostic byte offset.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }
}

impl fmt::Display for PortalWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "portal wire error {:?} at byte {}",
            self.code, self.offset
        )
    }
}
