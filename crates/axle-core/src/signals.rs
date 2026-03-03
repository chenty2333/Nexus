//! Signals: waitable object state bits (Zircon-style).
//!
//! Axle follows Zircon's model: signals are **level-triggered** bits on objects.
//! Wait operations observe current bits; concurrent changes are always possible,
//! so users must re-check preconditions after waking.

use core::fmt;

/// Zircon-style signal bitmask.
///
/// This is a newtype wrapper around `u32` to prevent accidental mixing with other
/// integers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Signals(u32);

impl Signals {
    /// Empty set (no signals).
    pub const NONE: Signals = Signals(0);

    /// Raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Construct from raw bits.
    pub const fn from_bits(bits: u32) -> Signals {
        Signals(bits)
    }

    /// Returns `true` if this set contains any of the bits in `other`.
    pub const fn intersects(self, other: Signals) -> bool {
        (self.0 & other.0) != 0
    }

    /// Returns `true` if this set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Add bits.
    pub const fn union(self, other: Signals) -> Signals {
        Signals(self.0 | other.0)
    }

    /// Remove bits.
    pub const fn without(self, other: Signals) -> Signals {
        Signals(self.0 & !other.0)
    }

    /// AND.
    pub const fn and(self, other: Signals) -> Signals {
        Signals(self.0 & other.0)
    }

    // ---- Common signals (aligned with Zircon bits) ----

    /// Readable (bit 0).
    pub const OBJECT_READABLE: Signals = Signals(1u32 << 0);
    /// Writable (bit 1).
    pub const OBJECT_WRITABLE: Signals = Signals(1u32 << 1);
    /// Peer closed (bit 2).
    pub const OBJECT_PEER_CLOSED: Signals = Signals(1u32 << 2);
    /// Signaled (bit 3).
    pub const OBJECT_SIGNALED: Signals = Signals(1u32 << 3);

    /// Handle closed / wait canceled (bit 23).
    pub const HANDLE_CLOSED: Signals = Signals(1u32 << 23);

    /// User signals: bits 24..31.
    pub const USER_SIGNAL_0: Signals = Signals(1u32 << 24);
    /// User signal 1.
    pub const USER_SIGNAL_1: Signals = Signals(1u32 << 25);
    /// User signal 2.
    pub const USER_SIGNAL_2: Signals = Signals(1u32 << 26);
    /// User signal 3.
    pub const USER_SIGNAL_3: Signals = Signals(1u32 << 27);
    /// User signal 4.
    pub const USER_SIGNAL_4: Signals = Signals(1u32 << 28);
    /// User signal 5.
    pub const USER_SIGNAL_5: Signals = Signals(1u32 << 29);
    /// User signal 6.
    pub const USER_SIGNAL_6: Signals = Signals(1u32 << 30);
    /// User signal 7.
    pub const USER_SIGNAL_7: Signals = Signals(1u32 << 31);

    // Object-specific aliases (keep the Zircon names to ease conformance testing).
    /// Channel readable.
    pub const CHANNEL_READABLE: Signals = Signals::OBJECT_READABLE;
    /// Channel writable.
    pub const CHANNEL_WRITABLE: Signals = Signals::OBJECT_WRITABLE;
    /// Channel peer closed.
    pub const CHANNEL_PEER_CLOSED: Signals = Signals::OBJECT_PEER_CLOSED;

    /// Timer signaled.
    pub const TIMER_SIGNALED: Signals = Signals::OBJECT_SIGNALED;
}

impl core::ops::BitOr for Signals {
    type Output = Signals;
    fn bitor(self, rhs: Signals) -> Signals {
        self.union(rhs)
    }
}

impl core::ops::BitAnd for Signals {
    type Output = Signals;
    fn bitand(self, rhs: Signals) -> Signals {
        self.and(rhs)
    }
}

impl core::ops::Not for Signals {
    type Output = Signals;
    fn not(self) -> Signals {
        Signals(!self.0)
    }
}

impl fmt::Debug for Signals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keep debug output readable without pulling in a bitflags dependency.
        write!(f, "Signals({:#010x})", self.0)
    }
}

/// A tiny “wait-one” helper used by conformance tests.
///
/// In the kernel, `zx_object_wait_one` blocks; here we model the
/// *decision* the kernel makes: whether the wait is already satisfied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitOne {
    /// The condition is satisfied right now; value is the observed signals snapshot.
    Ready(Signals),
    /// The condition is not satisfied; kernel would block (or return `ZX_ERR_SHOULD_WAIT` in non-blocking paths).
    ShouldWait,
}

/// Evaluate a wait-one condition against an observed signal set.
pub fn wait_one(observed: Signals, watched: Signals) -> WaitOne {
    if observed.intersects(watched) {
        WaitOne::Ready(observed)
    } else {
        WaitOne::ShouldWait
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_one_basic() {
        let observed = Signals::CHANNEL_READABLE | Signals::CHANNEL_WRITABLE;
        assert_eq!(
            wait_one(observed, Signals::CHANNEL_READABLE),
            WaitOne::Ready(observed)
        );
        assert_eq!(
            wait_one(Signals::NONE, Signals::CHANNEL_READABLE),
            WaitOne::ShouldWait
        );
    }
}
