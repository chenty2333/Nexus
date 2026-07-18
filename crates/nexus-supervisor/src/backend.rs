// SPDX-License-Identifier: MPL-2.0

use crate::{CrashObservation, RebindObservation, RecoverySnapshot, ServiceIdentity, StopReason};

/// Platform operations driven by [`crate::SupervisorManager`].
///
/// The kernel adapter must place the backend exclusively behind its manager.
/// Child service events are untrusted `(identity, binding epoch)` observations;
/// they never authorize direct calls to this trait. In particular, only the
/// manager may validate Ready, rebind, and select or adopt recovery members.
///
/// Mutating methods must either succeed completely or return before mutation.
/// [`Self::isolate_authority`] is the exception in shape only: it has no error
/// return because a backend must provide an always-available Registry
/// control-plane revocation primitive before it can implement this trait.
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

    /// Irrevocably isolates one service incarnation from Registry authority.
    ///
    /// This is the manager's last-resort control-plane fence. Before returning,
    /// the backend must synchronously revoke every portal, binding, Ready, and
    /// adoption authority usable by `service`, including authority obtained by
    /// a partially completed recovery. The operation must be bounded,
    /// idempotent, non-allocating, and unable to fail. It must retain
    /// Registry-owned effects and recovery records for operator inspection;
    /// device cleanup may remain asynchronous and retained.
    ///
    /// `last_known_binding_epoch` is an audit hint, not a selector. `None`
    /// means an earlier backend observation was invalid, so the implementation
    /// must revoke all authority for the exact service identity rather than
    /// narrowing the fence to one epoch.
    fn isolate_authority(
        &mut self,
        service: ServiceIdentity,
        last_known_binding_epoch: Option<u64>,
    );

    /// Allocates a fresh identity for the numbered replacement attempt.
    fn select_replacement(
        &mut self,
        failed: ServiceIdentity,
        attempt: u32,
    ) -> Result<ServiceIdentity, Self::Error>;

    /// Constructs and schedules the replacement task without granting it
    /// backend authority.
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

    /// Validates a replacement Ready notification against the exact snapshot.
    fn ready(
        &mut self,
        replacement: ServiceIdentity,
        snapshot: &Self::Snapshot,
    ) -> Result<(), Self::Error>;

    /// Makes the Ready replacement the active supervisor.
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
