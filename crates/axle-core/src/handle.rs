//! Native 64-bit handle encoding for userland.
//!
//! Current live shape:
//! - `0` is always invalid.
//! - handles are encoded as `[slot_index:32][slot_tag:32]`.
//! - `slot_tag == 0` is reserved and never allocated, so stale zero-filled
//!   memory cannot masquerade as a live handle.

/// Raw user-visible handle type.
pub type RawHandle = u64;

/// Invalid handle value.
pub const HANDLE_INVALID: RawHandle = 0;

/// Reserved tag value (reject on lookup; never allocate).
pub const HANDLE_TAG_RESERVED: u32 = 0;

/// Max slots addressable by the live handle encoding.
pub const HANDLE_MAX_SLOTS: u32 = u32::MAX;

/// A validated native handle.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(RawHandle);

impl core::fmt::Debug for Handle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Handle({:#018x})", self.0)
    }
}

/// Errors related to handle encoding/decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleError {
    /// The handle is zero (`HANDLE_INVALID`).
    InvalidZero,
    /// Tag value `0` is reserved and never represents a live handle.
    ReservedTag,
}

impl Handle {
    /// Create a handle from `(slot_index, slot_tag)` using the native 64-bit encoding.
    ///
    /// `index` may be zero -- slot index 0 is a valid CSpace slot.  The only
    /// invalid combination is `(index=0, tag=0)` which encodes to
    /// [`HANDLE_INVALID`].  A `tag` of [`HANDLE_TAG_RESERVED`] (0) is always
    /// rejected.
    pub const fn new(index: u32, tag: u32) -> Result<Self, HandleError> {
        if tag == HANDLE_TAG_RESERVED {
            return Err(HandleError::ReservedTag);
        }
        let raw = ((index as u64) << 32) | (tag as u64);
        if raw == HANDLE_INVALID {
            return Err(HandleError::InvalidZero);
        }
        Ok(Self(raw))
    }

    /// Wrap a raw value (validates it).
    pub const fn from_raw(raw: RawHandle) -> Result<Self, HandleError> {
        let handle = Self(raw);
        match handle.decode() {
            Ok(_) => Ok(handle),
            Err(err) => Err(err),
        }
    }

    /// Get the raw 64-bit value.
    pub const fn raw(self) -> RawHandle {
        self.0
    }

    /// Decode into `(slot_index, slot_tag)` with validation.
    pub const fn decode(self) -> Result<(u32, u32), HandleError> {
        if self.0 == HANDLE_INVALID {
            return Err(HandleError::InvalidZero);
        }
        let index = (self.0 >> 32) as u32;
        let tag = self.0 as u32;
        if tag == HANDLE_TAG_RESERVED {
            return Err(HandleError::ReservedTag);
        }
        Ok((index, tag))
    }

    /// Fast check for obvious invalid values.
    pub const fn is_obviously_invalid(self) -> bool {
        self.0 == HANDLE_INVALID || (self.0 as u32) == HANDLE_TAG_RESERVED
    }
}

/// Increment a slot tag, skipping the reserved value.
pub(crate) const fn bump_tag(mut tag: u32) -> u32 {
    tag = tag.wrapping_add(1);
    if tag == HANDLE_TAG_RESERVED {
        tag = tag.wrapping_add(1);
    }
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_roundtrip() {
        let h = Handle::new(42, 7).unwrap();
        let (i, g) = h.decode().unwrap();
        assert_eq!(i, 42);
        assert_eq!(g, 7);
    }

    #[test]
    fn reject_zero() {
        assert_eq!(Handle::from_raw(0).unwrap_err(), HandleError::InvalidZero);
    }

    #[test]
    fn reject_reserved_tag() {
        assert_eq!(Handle::new(1, 0).unwrap_err(), HandleError::ReservedTag);
        assert_eq!(
            Handle::from_raw(5u64 << 32).unwrap_err(),
            HandleError::ReservedTag
        );
    }

    #[test]
    fn bump_tag_skips_reserved() {
        assert_eq!(bump_tag(0), 1);
        assert_eq!(bump_tag(u32::MAX), 1);
    }
}
