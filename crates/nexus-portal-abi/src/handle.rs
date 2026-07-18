// SPDX-License-Identifier: MPL-2.0

//! Opaque portal selectors.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// The exact byte width of every portal-v2 opaque handle.
pub const HANDLE_SIZE: usize = 16;

macro_rules! opaque_handle {
    ($(#[$attributes:meta])* $name:ident) => {
        $(#[$attributes])*
        ///
        /// Every 16-byte pattern can be transported and compared, but the bytes
        /// are not authority.  Before use, the Registry must validate their
        /// issuer, boot instance, caller binding, object generation, and current
        /// lifecycle state.  The ABI deliberately provides no semantic field
        /// unpacking API.
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, FromBytes, IntoBytes, KnownLayout,
            Immutable, Unaligned,
        )]
        #[repr(transparent)]
        pub struct $name([u8; HANDLE_SIZE]);

        impl $name {
            /// The all-zero absence marker; it never grants authority.
            pub const NULL: Self = Self([0; HANDLE_SIZE]);

            /// Parses the exact opaque bytes carried by the wire.
            #[must_use]
            pub const fn from_wire_bytes(bytes: [u8; HANDLE_SIZE]) -> Self {
                Self(bytes)
            }

            /// Returns the exact bytes for wire transport.
            #[must_use]
            pub const fn to_wire_bytes(self) -> [u8; HANDLE_SIZE] {
                self.0
            }

            /// Reports whether this is the all-zero absence marker.
            #[must_use]
            pub fn is_null(self) -> bool {
                self.0.iter().all(|byte| *byte == 0)
            }
        }
    };
}

opaque_handle!(
    /// Opaque selector for one negotiated portal session.
    SessionHandle
);
opaque_handle!(
    /// Opaque selector for a kernel-owned causal scope.
    ScopeHandle
);
opaque_handle!(
    /// Opaque selector for one effect in a causal scope.
    EffectHandle
);
opaque_handle!(
    /// Opaque selector for a linearly consumed Registry receipt.
    ReceiptHandle
);
