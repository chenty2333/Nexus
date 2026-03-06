#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

//! Axle synchronization primitives.
//!
//! This crate is intentionally small and heavily tested.
//! Unsafe is allowed here, but must remain **fenced** and justified with `// SAFETY:` comments.

extern crate alloc;

pub mod spsc;

#[cfg(test)]
extern crate std;
