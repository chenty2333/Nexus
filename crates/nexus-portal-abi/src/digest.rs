// SPDX-License-Identifier: MPL-2.0

//! Opaque content digests carried across the portal boundary.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Exact byte width of a portal content digest.
pub const DIGEST_SIZE: usize = 32;

/// Opaque 256-bit digest of canonical request, outcome, state, or receipt data.
///
/// The ABI transports and compares these bytes but deliberately does not choose
/// the canonicalization or hash implementation.  A backend adapter must bind
/// each digest to its domain object before granting authority.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(transparent)]
pub struct Digest([u8; DIGEST_SIZE]);

impl Digest {
    /// The all-zero absence marker, rejected by every mutating request.
    pub const ZERO: Self = Self([0; DIGEST_SIZE]);

    /// Creates a digest from its exact wire bytes.
    #[must_use]
    pub const fn from_wire_bytes(bytes: [u8; DIGEST_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes for wire transport.
    #[must_use]
    pub const fn to_wire_bytes(self) -> [u8; DIGEST_SIZE] {
        self.0
    }

    /// Reports whether this is the all-zero absence marker.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}
