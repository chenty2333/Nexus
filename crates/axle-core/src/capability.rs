//! Kernel-side capability representation (u128), stored in CSpace slots.
//!
//! Userland holds a 32-bit `zx_handle_t` compatible handle; the kernel keeps the real capability.

/// A 128-bit capability:
///
/// ```text
/// Capability(u128) = [ ObjectID: 64 ] [ Rights: 32 ] [ Generation: 32 ]
/// ```
///
/// - `ObjectID`: stable kernel object identifier (implementation-defined).
/// - `Rights`: bitmask (implementation-defined).
/// - `Generation`: object generation (bumped on destroy).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Capability(pub u128);

impl Capability {
    /// Build a capability from fields.
    pub const fn new(object_id: u64, rights: u32, generation: u32) -> Self {
        let v = ((object_id as u128) << 64) | ((rights as u128) << 32) | (generation as u128);
        Self(v)
    }

    /// Extract ObjectID.
    pub const fn object_id(self) -> u64 {
        (self.0 >> 64) as u64
    }

    /// Extract rights.
    pub const fn rights(self) -> u32 {
        ((self.0 >> 32) & 0xFFFF_FFFF) as u32
    }

    /// Extract generation.
    pub const fn generation(self) -> u32 {
        (self.0 & 0xFFFF_FFFF) as u32
    }
}
