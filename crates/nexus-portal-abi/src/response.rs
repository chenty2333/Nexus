// SPDX-License-Identifier: MPL-2.0

//! Bounded success, observation, closure, and error response bodies.

use bitflags::bitflags;

use crate::PortalWireError;

mod error;
mod lifecycle;
mod negotiation;
mod query;

pub use error::{ErrorResponse, PortalFailure};
pub use lifecycle::{ClosureReceipt, LifecycleReceipt, ScopeCreatedResponse};
pub use negotiation::{AbiResponse, NegotiatedResponse};
pub use query::{EffectObservation, ReceiptObservation, ScopeObservation};

/// Largest fixed request body admitted to the mutation replay cache.
pub const MAX_MUTATION_BODY_SIZE: usize = 128;
/// Largest response body emitted by this ABI revision.
pub const MAX_RESPONSE_BODY_SIZE: usize = 256;

/// Contract implemented by each fixed-size portal response body.
pub trait ResponseBody: Sized {
    /// Exact accepted and emitted body length.
    const WIRE_SIZE: usize;

    /// Decodes one exact-size response body.
    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError>;

    /// Encodes into an output slice whose length equals [`Self::WIRE_SIZE`].
    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError>;
}

/// Stable effect lifecycle phase exposed by observations and receipts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EffectPhase {
    /// Credits are reserved and immutable identity is installed.
    Registered = 1,
    /// The effect is ready for its commit publication boundary.
    Prepared = 2,
    /// External work crossed the commit boundary.
    Committed = 3,
    /// A canonical backend outcome was recorded.
    OutcomeRecorded = 4,
    /// The effect completed exactly once.
    Completed = 5,
    /// The effect aborted before commit exactly once.
    Aborted = 6,
    /// Ownership remains behind an honest retained obligation.
    Retained = 7,
}

impl EffectPhase {
    /// Returns the stable wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Parses a stable wire discriminant.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Registered),
            2 => Some(Self::Prepared),
            3 => Some(Self::Committed),
            4 => Some(Self::OutcomeRecorded),
            5 => Some(Self::Completed),
            6 => Some(Self::Aborted),
            7 => Some(Self::Retained),
            _ => None,
        }
    }

    /// Reports whether no ordinary lifecycle transition may follow.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted | Self::Retained)
    }
}

/// Stable receipt semantic kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ReceiptKind {
    /// A scope was created.
    ScopeCreated = 1,
    /// An effect was registered.
    EffectRegistered = 2,
    /// An effect was prepared.
    EffectPrepared = 3,
    /// An effect was committed.
    EffectCommitted = 4,
    /// A backend outcome was recorded.
    OutcomeRecorded = 5,
    /// An effect reached a terminal disposition.
    EffectCompleted = 6,
    /// A scope authority epoch was revoked.
    ScopeRevoked = 7,
    /// Scope closure made progress or reached a terminal result.
    Closure = 8,
}

impl ReceiptKind {
    /// Returns the stable wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Parses a stable wire discriminant.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::ScopeCreated),
            2 => Some(Self::EffectRegistered),
            3 => Some(Self::EffectPrepared),
            4 => Some(Self::EffectCommitted),
            5 => Some(Self::OutcomeRecorded),
            6 => Some(Self::EffectCompleted),
            7 => Some(Self::ScopeRevoked),
            8 => Some(Self::Closure),
            _ => None,
        }
    }
}

/// Stable scope lifecycle phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ScopePhase {
    /// New effects and publications may be admitted.
    Active = 1,
    /// The old authority epoch is frozen and closure is in progress.
    Closing = 2,
    /// Every effect is terminal or represented by the returned retained state.
    Revoked = 3,
}

impl ScopePhase {
    /// Returns the stable wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Parses a stable wire discriminant.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Active),
            2 => Some(Self::Closing),
            3 => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Stable closure status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ClosureStatus {
    /// Closure still has live or pending work.
    Closing = 1,
    /// Closure returned every releasable owner and credit.
    Closed = 2,
    /// Closure retained an explicit owner or tombstone obligation.
    Retained = 3,
}

impl ClosureStatus {
    /// Returns the stable wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Parses a stable wire discriminant.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Closing),
            2 => Some(Self::Closed),
            3 => Some(Self::Retained),
            _ => None,
        }
    }
}

/// Stable receipt consumption state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ReceiptStatus {
    /// The receipt may still authorize its one permitted transition.
    Live = 1,
    /// The receipt was consumed exactly once.
    Consumed = 2,
    /// The receipt identifies retained ownership.
    Retained = 3,
}

impl ReceiptStatus {
    /// Returns the stable wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Parses a stable wire discriminant.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Live),
            2 => Some(Self::Consumed),
            3 => Some(Self::Retained),
            _ => None,
        }
    }
}

/// Retry policy attached to a typed error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RetryClass {
    /// Repeating the request cannot succeed without changing its input.
    Never = 1,
    /// Only the exact same request id and bytes may be retried idempotently.
    ExactRequest = 2,
    /// Query current state before choosing another operation.
    AfterQuery = 3,
    /// Retry after bounded capacity becomes available.
    AfterCapacity = 4,
    /// Establish a fresh negotiated session with a new replay budget.
    NewSession = 5,
}

impl RetryClass {
    /// Returns the stable wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Parses a stable wire discriminant.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Never),
            2 => Some(Self::ExactRequest),
            3 => Some(Self::AfterQuery),
            4 => Some(Self::AfterCapacity),
            5 => Some(Self::NewSession),
            _ => None,
        }
    }
}

bitflags! {
    /// Flags carried by lifecycle receipts and effect observations.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct LifecycleFlags: u32 {
        /// A separate publication remains required.
        const PUBLICATION_PENDING = 1 << 0;
        /// The effect owns retained resources or a tombstone.
        const RETAINED = 1 << 1;
        /// The effect has reached a terminal disposition.
        const TERMINAL = 1 << 2;
    }
}

fn lifecycle_flags_match_phase(phase: EffectPhase, flags: LifecycleFlags) -> bool {
    phase.is_terminal() == flags.contains(LifecycleFlags::TERMINAL)
        && (phase == EffectPhase::Retained) == flags.contains(LifecycleFlags::RETAINED)
}
