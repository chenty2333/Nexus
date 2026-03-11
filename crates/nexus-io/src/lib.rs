#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Minimal fd-shaped I/O primitives shared by Nexus userspace binaries.
//!
//! The first cut intentionally stops at:
//! - handle/protocol objects adapted behind `FdOps`
//! - one userspace-owned `FdTable`
//! - longest-prefix namespace dispatch through `NamespaceTrie`
//! - one `WaitSpec` bridge for the existing reactor
//!
//! It does **not** define a global VFS or a concrete remote filesystem
//! protocol. Those stay outside this crate.

extern crate alloc;
#[cfg(test)]
extern crate std;

mod fd;
mod namespace;

pub use crate::fd::{
    DirectoryEntry, DirectoryEntryKind, FdEntry, FdFlags, FdOps, FdTable, OpenFileDescription,
    OpenFileDescriptionId, OpenFlags, PipeFd, PseudoNodeFd, RawFd, RemoteDir, RemoteFile,
    SeekOrigin, SocketFd, StdioFd, VmoFlags, WaitSpec,
};
pub use crate::namespace::{
    NamespaceEntry, NamespaceMatch, NamespaceTrie, normalize_namespace_path,
};
