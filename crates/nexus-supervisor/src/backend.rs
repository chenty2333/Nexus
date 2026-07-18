// SPDX-License-Identifier: MPL-2.0

use crate::{CrashObservation, RebindObservation, RecoverySnapshot, ServiceIdentity, StopReason};

/// Platform operations driven by [`crate::SupervisorManager`].
///
/// Mutating methods must either succeed completely or return before mutation.
/// A successful [`Self::abort_recovery_attempt`] must remove every snapshot and
/// Ready-side effect for that attempt while retaining the exact crash-frozen
/// cohort. A successful [`Self::crash_active`] on a rebound replacement must
/// fence every earlier adoption and supersede the prior recovery attempt with
/// the exact cohort reported in its observation.
pub trait SupervisorBackend {
    /// Opaque snapshot passed back to the same backend for Ready validation.
    type Snapshot;
    /// Opaque identity for one unadopted recovery member.
    type RecoveryItem;
    /// Backend-specific typed failure.
    type Error;

    /// Fences the exact active supervisor and opens Registry recovery.
    fn crash_active(&mut self, service: ServiceIdentity) -> Result<CrashObservation, Self::Error>;

    /// Allocates a fresh identity for the numbered replacement attempt.
    fn select_replacement(
        &mut self,
        failed: ServiceIdentity,
        attempt: u32,
    ) -> Result<ServiceIdentity, Self::Error>;

    /// Constructs and schedules the replacement task.
    fn spawn_replacement(&mut self, replacement: ServiceIdentity) -> Result<(), Self::Error>;

    /// Captures the exact crash-frozen cohort for the replacement handshake.
    ///
    /// The returned cohort identity must equal the identity returned by the
    /// `crash_active` call which opened this recovery. Cohort evolution between
    /// crash and snapshot is not permitted.
    fn recovery_snapshot(
        &mut self,
        replacement: ServiceIdentity,
    ) -> Result<RecoverySnapshot<Self::Snapshot>, Self::Error>;

    /// Stops and reaps a replacement which never became active.
    fn stop_replacement(
        &mut self,
        replacement: ServiceIdentity,
        reason: StopReason,
    ) -> Result<(), Self::Error>;

    /// Abandons one pre-rebind snapshot/Ready attempt after its task is stopped.
    ///
    /// Success clears all snapshot, Ready, selector, and attempt-local state for
    /// `replacement`, but preserves the crash-frozen cohort so a later attempt
    /// can snapshot it unchanged. Failure must leave that state unchanged.
    fn abort_recovery_attempt(
        &mut self,
        replacement: ServiceIdentity,
        snapshot: &RecoverySnapshot<Self::Snapshot>,
        reason: StopReason,
    ) -> Result<(), Self::Error>;

    /// Validates a replacement ready notification against the exact snapshot.
    fn ready(
        &mut self,
        replacement: ServiceIdentity,
        snapshot: &Self::Snapshot,
    ) -> Result<(), Self::Error>;

    /// Makes the ready replacement the active supervisor.
    fn rebind(&mut self, replacement: ServiceIdentity) -> Result<RebindObservation, Self::Error>;

    /// Peeks at the next exact unadopted recovery member, if any.
    ///
    /// This operation must not remove, lease, or advance past a member. Until a
    /// matching `adopt` succeeds, repeated successful calls must return the same
    /// exact member. An error must leave recovery membership unchanged.
    fn peek_recovery_item(
        &mut self,
        replacement: ServiceIdentity,
    ) -> Result<Option<Self::RecoveryItem>, Self::Error>;

    /// Adopts the exact member most recently returned by `peek_recovery_item`.
    ///
    /// Success removes exactly that member from the active recovery cohort;
    /// failure leaves it available to a subsequent peek or crash fence.
    fn adopt(
        &mut self,
        replacement: ServiceIdentity,
        item: Self::RecoveryItem,
    ) -> Result<(), Self::Error>;
}
