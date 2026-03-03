//! Zircon-compatible 32-bit handle encoding for userland.
//!
//! Design constraints (aligned with Zircon expectations):
//! - `ZX_HANDLE_INVALID` is **0**.
//! - Any valid handle must have **lowest 2 bits == 1** (0b11), enabling fast validity checks.
//! - Remaining 30 bits encode `index + tag` (ABA protection).
//!
//! Default bit split:
//! - index: 14 bits (0..16383 slots per process)
//! - tag:   16 bits (slot generation / ABA tag)
//! - low 2 bits fixed to 1.

/// Raw user-visible handle type (compatible with `zx_handle_t`).
pub type RawHandle = u32;

/// Zircon invalid handle value.
pub const ZX_HANDLE_INVALID: RawHandle = 0;

/// Low bits must be 0b11 for valid handles.
pub const HANDLE_FIXED_BITS_MASK: RawHandle = 0b11;
/// Low bits value for valid handles.
pub const HANDLE_FIXED_BITS_VALUE: RawHandle = 0b11;

/// Slot index bits (I).
pub const HANDLE_INDEX_BITS: u32 = 14;
/// Slot tag bits (G).
pub const HANDLE_TAG_BITS: u32 = 16;

/// Reserved tag value (reject on lookup; never allocate).
pub const HANDLE_TAG_RESERVED: u16 = 0xFFFF;

/// Max slots addressable by the handle encoding.
pub const HANDLE_MAX_SLOTS: u16 = (1u32 << HANDLE_INDEX_BITS) as u16;

const TAG_MASK: u32 = (1u32 << HANDLE_TAG_BITS) - 1;

/// A validated, Zircon-compatible handle.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(RawHandle);

impl core::fmt::Debug for Handle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Handle({:#010x})", self.0)
    }
}

/// Errors related to handle encoding/decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleError {
    /// The handle is 0 (ZX_HANDLE_INVALID).
    InvalidZero,
    /// Low fixed bits are not 0b11.
    InvalidFixedBits,
    /// Index is out of range for the chosen bit split.
    IndexOutOfRange,
    /// Tag is reserved and must never be used for real handles.
    ReservedTag,
}

impl Handle {
    /// Create a handle from `(index, tag)` using the Zircon-style encoding.
    pub fn new(index: u16, tag: u16) -> Result<Self, HandleError> {
        if index >= HANDLE_MAX_SLOTS {
            return Err(HandleError::IndexOutOfRange);
        }
        if tag == HANDLE_TAG_RESERVED {
            return Err(HandleError::ReservedTag);
        }
        let encoded: u32 = ((index as u32) << HANDLE_TAG_BITS) | (tag as u32);
        let raw: u32 = (encoded << 2) | HANDLE_FIXED_BITS_VALUE;
        if raw == ZX_HANDLE_INVALID {
            // Should be impossible given fixed bits == 0b11, but keep it defensive.
            return Err(HandleError::InvalidZero);
        }
        Ok(Self(raw))
    }

    /// Wrap a raw value (validates it).
    pub fn from_raw(raw: RawHandle) -> Result<Self, HandleError> {
        let h = Self(raw);
        // Validate by decoding
        let _ = h.decode()?;
        Ok(h)
    }

    /// Get the raw 32-bit value.
    pub const fn raw(self) -> RawHandle {
        self.0
    }

    /// Decode into `(index, tag)` with validation.
    pub fn decode(self) -> Result<(u16, u16), HandleError> {
        if self.0 == ZX_HANDLE_INVALID {
            return Err(HandleError::InvalidZero);
        }
        if (self.0 & HANDLE_FIXED_BITS_MASK) != HANDLE_FIXED_BITS_VALUE {
            return Err(HandleError::InvalidFixedBits);
        }
        let encoded = self.0 >> 2; // 30-bit
        let tag = (encoded & TAG_MASK) as u16;
        let index = (encoded >> HANDLE_TAG_BITS) as u16;

        if index >= HANDLE_MAX_SLOTS {
            return Err(HandleError::IndexOutOfRange);
        }
        if tag == HANDLE_TAG_RESERVED {
            return Err(HandleError::ReservedTag);
        }
        Ok((index, tag))
    }

    /// Fast check for obvious invalid values (does not fully validate index/tag).
    pub const fn is_obviously_invalid(self) -> bool {
        self.0 == ZX_HANDLE_INVALID || (self.0 & HANDLE_FIXED_BITS_MASK) != HANDLE_FIXED_BITS_VALUE
    }
}

/// Increment a slot tag, skipping the reserved value.
pub(crate) const fn bump_tag(mut tag: u16) -> u16 {
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
        assert_eq!(h.raw() & HANDLE_FIXED_BITS_MASK, HANDLE_FIXED_BITS_VALUE);
        let (i, g) = h.decode().unwrap();
        assert_eq!(i, 42);
        assert_eq!(g, 7);
    }

    #[test]
    fn reject_zero() {
        assert_eq!(Handle::from_raw(0).unwrap_err(), HandleError::InvalidZero);
    }

    #[test]
    fn reject_bad_fixed_bits() {
        // low 2 bits != 0b11
        let raw = 0x1234_5678u32 & !0b11;
        assert_eq!(
            Handle::from_raw(raw).unwrap_err(),
            HandleError::InvalidFixedBits
        );
    }

    #[test]
    fn bump_tag_skips_reserved() {
        assert_eq!(bump_tag(0xFFFD), 0xFFFE);
        // 0xFFFE -> 0xFFFF (reserved) -> 0x0000
        assert_eq!(bump_tag(0xFFFE), 0x0000);
        // reserved itself should never be stored, but bumping it should also move away.
        assert_eq!(bump_tag(0xFFFF), 0x0000);
    }
}
