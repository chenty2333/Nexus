//! Scaffold for Linux task/process/session semantics.

pub(super) mod exit;
pub(super) mod kernel;
pub(super) mod process_group;
pub(super) mod session;
#[allow(clippy::module_inception)]
pub(super) mod task;
pub(super) mod thread_group;
pub(super) mod wait;
