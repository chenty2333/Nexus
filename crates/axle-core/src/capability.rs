//! Kernel-side capability representation stored in CSpace slots.
//!
//! Userland now sees native 64-bit handles; the kernel keeps capability
//! metadata as typed fields rather than one packed integer.

/// Stable kernel object identity carried by capabilities and async wait registration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectKey {
    object_id: u64,
    generation: u32,
}

impl ObjectKey {
    /// Sentinel invalid key used for user packets and unpublished slots.
    pub const INVALID: Self = Self::new(0, 0);

    /// Build one object identity from raw fields.
    pub const fn new(object_id: u64, generation: u32) -> Self {
        Self {
            object_id,
            generation,
        }
    }

    /// Return the stable object-id portion.
    pub const fn object_id(self) -> u64 {
        self.object_id
    }

    /// Return the generation portion.
    pub const fn generation(self) -> u32 {
        self.generation
    }

    /// Return `true` when this key does not identify a live object incarnation.
    pub const fn is_invalid(self) -> bool {
        self.object_id == 0
    }
}

impl From<u64> for ObjectKey {
    fn from(object_id: u64) -> Self {
        Self::new(object_id, 0)
    }
}

/// Capability metadata carried in one CSpace slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Capability {
    object_id: u64,
    rights: u32,
    generation: u32,
}

impl Capability {
    /// Build a capability from fields.
    pub const fn new(object_id: u64, rights: u32, generation: u32) -> Self {
        Self {
            object_id,
            rights,
            generation,
        }
    }

    /// Extract ObjectID.
    pub const fn object_id(self) -> u64 {
        self.object_id
    }

    /// Extract rights.
    pub const fn rights(self) -> u32 {
        self.rights
    }

    /// Extract generation.
    pub const fn generation(self) -> u32 {
        self.generation
    }

    /// Extract object identity.
    pub const fn object_key(self) -> ObjectKey {
        ObjectKey::new(self.object_id(), self.generation())
    }
}
