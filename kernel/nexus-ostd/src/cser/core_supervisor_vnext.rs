// SPDX-License-Identifier: MPL-2.0

//! Stateless trusted-supervisor ingress for the recovered portable CSER core.
//!
//! The supervisor is deliberately a thin capability: it retains only an
//! [`Arc`] to the unique recovered core authority and translates trusted
//! manager operations into durable core commands. It owns no recovery phase,
//! snapshot cohort, binding table, claim ledger, retry cache, or domain state.
//!
//! Every successful operation returns the exact [`TransitionReceipt`] produced
//! by `cser-core`. The supervisor never consumes or translates its linear
//! [`cser_core::TransitionOutput`]; the trusted manager must take custody of
//! that output before publishing any resulting authority.

use alloc::sync::Arc;

use cser_core::{
    Command, CommandRequest, ComponentId, CoreError, EffectId, ExecutorCoordinate, OperationId,
    RecoverySnapshot, SnapshotId, TransitionDurability, TransitionReceipt, TxError,
};

use super::core_runtime::OstdCserRuntime;

/// Versioned identity of the rebaselined trusted-supervisor contract.
pub(crate) const CORE_SUPERVISOR_PROTOCOL: &str = "nexus.supervisor.core.v1";

/// Minimal recovered-authority surface required by the trusted supervisor.
///
/// Implementations must serialize both methods through the same unique core
/// owner. `transact` may block while the transition journal and trusted anchor
/// become durable, so callers must run in manager/task context. A quarantined
/// boot owner can implement this trait through an interior-mutable adapter
/// which retains its linear quarantine guard while delegating to
/// `QuarantinedRecoveredBoot::observe` and `recovery_transact`.
pub(crate) trait RecoveredCoreAuthority: Send + Sync {
    /// Persistent-provider failure returned by the authoritative transaction.
    type PersistenceError;

    /// Generates one exact, non-authorizing snapshot from authoritative state.
    fn snapshot_operation(
        &self,
        operation: OperationId,
        snapshot: SnapshotId,
    ) -> Result<RecoverySnapshot, CoreError>;

    /// Durably executes one trusted command on the authoritative core.
    fn transact(
        &self,
        command: Command,
    ) -> Result<TransitionReceipt, TxError<Self::PersistenceError>>;
}

impl<P> RecoveredCoreAuthority for OstdCserRuntime<P>
where
    P: TransitionDurability + Send,
{
    type PersistenceError = P::Error;

    fn snapshot_operation(
        &self,
        operation: OperationId,
        snapshot: SnapshotId,
    ) -> Result<RecoverySnapshot, CoreError> {
        self.observe(|engine| engine.snapshot_operation(operation, snapshot))
    }

    fn transact(
        &self,
        command: Command,
    ) -> Result<TransitionReceipt, TxError<Self::PersistenceError>> {
        OstdCserRuntime::transact(self, command)
    }
}

/// Exact durable receipts from the two-stage fence-and-snapshot operation.
///
/// Neither receipt has had its linear output inspected or consumed.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FenceSnapshotTransitions {
    fence: TransitionReceipt,
    snapshot: TransitionReceipt,
}

impl FenceSnapshotTransitions {
    /// Borrows the exact durable fence receipt.
    pub(crate) const fn fence(&self) -> &TransitionReceipt {
        &self.fence
    }

    /// Borrows the exact durable snapshot receipt.
    pub(crate) const fn snapshot(&self) -> &TransitionReceipt {
        &self.snapshot
    }

    /// Transfers both unmodified receipts to the trusted manager.
    pub(crate) fn into_parts(self) -> (TransitionReceipt, TransitionReceipt) {
        (self.fence, self.snapshot)
    }
}

/// Failure after an operation was already known to be durably fenced.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SnapshotTransitionError<E> {
    /// Authoritative state could not generate the requested exact cohort.
    Prepare(CoreError),
    /// The exact snapshot command was rejected or could not become durable.
    Transact(TxError<E>),
}

/// Failure from the two-stage fence-and-snapshot operation.
// Keeping the exact linear receipt inline avoids introducing an allocation
// failure after the fence has already committed durably.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FenceSnapshotError<E> {
    /// No durable fence receipt was produced.
    Fence(TxError<E>),
    /// Fencing committed, but snapshot preparation or persistence failed.
    ///
    /// The exact fence receipt is retained so the manager never retries under
    /// the false assumption that the crashed executor is still live.
    Snapshot {
        /// Exact successful fence receipt, with linear output untouched.
        fence: TransitionReceipt,
        /// Failure from the subsequent snapshot stage.
        error: SnapshotTransitionError<E>,
    },
}

/// Stateless versioned ingress over one recovered authoritative owner.
pub(crate) struct CoreSupervisorVNext<A> {
    authority: Arc<A>,
}

impl<A> CoreSupervisorVNext<A> {
    /// Binds the supervisor to the exact authority installed at recovery.
    pub(crate) const fn new(authority: Arc<A>) -> Self {
        Self { authority }
    }

    /// Returns the fixed contract identity used by production wiring.
    pub(crate) const fn protocol(&self) -> &'static str {
        CORE_SUPERVISOR_PROTOCOL
    }
}

impl<A: RecoveredCoreAuthority> CoreSupervisorVNext<A> {
    /// Durably fences one crashed executor and records its exact snapshot.
    ///
    /// Snapshot generation happens after the fence commits. If another core
    /// transition races between generation and persistence, the core rejects
    /// the stale snapshot and this method returns the durable fence receipt in
    /// [`FenceSnapshotError::Snapshot`].
    //
    // The large error is the recovery handle for an already-durable fence.
    // Heap-boxing it here could lose that linear receipt if allocation fails.
    #[allow(clippy::result_large_err)]
    pub(crate) fn fence_and_snapshot(
        &self,
        operation: OperationId,
        crashed: ExecutorCoordinate,
        snapshot: SnapshotId,
    ) -> Result<FenceSnapshotTransitions, FenceSnapshotError<A::PersistenceError>> {
        let fence = self
            .authority
            .transact(CommandRequest::FenceExecutor { operation, crashed }.into())
            .map_err(FenceSnapshotError::Fence)?;

        match self.snapshot_fenced(operation, snapshot) {
            Ok(snapshot) => Ok(FenceSnapshotTransitions { fence, snapshot }),
            Err(error) => Err(FenceSnapshotError::Snapshot { fence, error }),
        }
    }

    /// Records a new exact snapshot for an operation which is already durably fenced.
    ///
    /// This is the retry path after a snapshot-stage failure and the boot-time
    /// path when replay already proves the operation is fenced. It never synthesizes
    /// or caches a cohort outside the portable core.
    pub(crate) fn snapshot_fenced(
        &self,
        operation: OperationId,
        snapshot: SnapshotId,
    ) -> Result<TransitionReceipt, SnapshotTransitionError<A::PersistenceError>> {
        let command = self
            .authority
            .snapshot_operation(operation, snapshot)
            .map_err(SnapshotTransitionError::Prepare)?
            .record();
        self.authority
            .transact(command)
            .map_err(SnapshotTransitionError::Transact)
    }

    /// Durably marks a fresh successor ready for one exact snapshot.
    pub(crate) fn ready(
        &self,
        operation: OperationId,
        snapshot: SnapshotId,
        successor: ExecutorCoordinate,
    ) -> Result<TransitionReceipt, TxError<A::PersistenceError>> {
        self.authority.transact(
            CommandRequest::Ready {
                operation,
                snapshot,
                successor,
            }
            .into(),
        )
    }

    /// Durably installs one fresh binding without implicit effect adoption.
    pub(crate) fn rebind(
        &self,
        operation: OperationId,
        snapshot: SnapshotId,
        successor: ExecutorCoordinate,
    ) -> Result<TransitionReceipt, TxError<A::PersistenceError>> {
        self.authority.transact(
            CommandRequest::Rebind {
                operation,
                snapshot,
                successor,
            }
            .into(),
        )
    }

    /// Durably and explicitly adopts one uncommitted orphan.
    pub(crate) fn adopt_effect(
        &self,
        effect: EffectId,
        successor: ExecutorCoordinate,
    ) -> Result<TransitionReceipt, TxError<A::PersistenceError>> {
        self.authority
            .transact(CommandRequest::AdoptEffect { effect, successor }.into())
    }

    /// Durably mints one exact component-local successor-settlement claim.
    pub(crate) fn claim_component_settlement(
        &self,
        effect: EffectId,
        component: ComponentId,
        claimant: ExecutorCoordinate,
    ) -> Result<TransitionReceipt, TxError<A::PersistenceError>> {
        self.authority.transact(
            CommandRequest::ClaimComponentSettlement {
                effect,
                component,
                claimant,
            }
            .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use cser_core::{
        AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, BootGeneration,
        CatalogSet, ChargeAccountId, ComponentProviderBinding, CoreLimits, DeviceGeneration,
        Digest, Engine, ExecutorCoordinate, ExecutorGeneration, ExecutorId, Freshness,
        JournalGeneration, JournalRecord, ProviderCoordinate, ProviderGeneration, ProviderId,
        RegistryInstance, TransitionEvent, TransitionOutput, VerifierBinding, VerifierGeneration,
        WorldId, standard_catalog,
    };

    use super::*;

    struct TestDurability {
        writes: usize,
        fail_at: Option<usize>,
    }

    impl TransitionDurability for TestDurability {
        type Error = &'static str;

        fn persist_transition(
            &mut self,
            record: &JournalRecord,
            resulting_freshness: Freshness,
            _resulting_projection: Digest,
        ) -> Result<(), Self::Error> {
            assert!(!record.bytes().is_empty());
            assert_eq!(resulting_freshness, freshness());
            self.writes += 1;
            if self.fail_at == Some(self.writes) {
                Err("injected persistence failure")
            } else {
                Ok(())
            }
        }
    }

    fn freshness() -> Freshness {
        Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(2).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        )
    }

    fn effect() -> EffectId {
        EffectId::new(OperationId::new(7).unwrap(), 1).unwrap()
    }

    fn origin() -> ExecutorCoordinate {
        ExecutorCoordinate::new(
            ExecutorId::new(7).unwrap(),
            ExecutorGeneration::new(1).unwrap(),
        )
    }

    fn successor() -> ExecutorCoordinate {
        ExecutorCoordinate::new(
            ExecutorId::new(7).unwrap(),
            ExecutorGeneration::new(2).unwrap(),
        )
    }

    fn runtime(fail_at: Option<usize>) -> Arc<OstdCserRuntime<TestDurability>> {
        Arc::new(OstdCserRuntime::from_engine(
            Engine::new(
                WorldId::new(1).unwrap(),
                CatalogSet::new(&[standard_catalog()]).unwrap(),
                CoreLimits::bounded_default(),
                freshness(),
            ),
            TestDurability { writes: 0, fail_at },
        ))
    }

    fn seed_uncommitted_reply(runtime: &OstdCserRuntime<TestDurability>) {
        let catalog = standard_catalog();
        let verifier_generation = VerifierGeneration::new(1).unwrap();
        let verifier_bindings = || {
            catalog
                .verifier_class_bindings()
                .into_iter()
                .map(|class| {
                    VerifierBinding::new(
                        class.verifier(),
                        verifier_generation,
                        class.receipt_schema(),
                        Digest::new([0x51; 32]),
                    )
                    .unwrap()
                })
                .collect()
        };
        for provider in [1, 2] {
            runtime
                .transact(CommandRequest::RegisterProviderGeneration {
                    coordinate: ProviderCoordinate::new(
                        WorldId::new(1).unwrap(),
                        ProviderId::new(provider).unwrap(),
                        ProviderGeneration::new(1).unwrap(),
                    ),
                    catalog_digest: catalog.digest(),
                    verifier_bindings: verifier_bindings(),
                })
                .unwrap();
        }
        runtime
            .transact(CommandRequest::AdmitScopedCompositeEffect {
                effect: effect(),
                origin: origin(),
                kind: AGENT_OPERATION_COMPOSITE,
                charge_account: ChargeAccountId::new(7).unwrap(),
                bindings: vec![
                    ComponentProviderBinding::new(
                        AGENT_COMPONENT_REPLY,
                        ProviderCoordinate::new(
                            WorldId::new(1).unwrap(),
                            ProviderId::new(1).unwrap(),
                            ProviderGeneration::new(1).unwrap(),
                        ),
                    ),
                    ComponentProviderBinding::new(
                        AGENT_COMPONENT_DMA,
                        ProviderCoordinate::new(
                            WorldId::new(1).unwrap(),
                            ProviderId::new(2).unwrap(),
                            ProviderGeneration::new(1).unwrap(),
                        ),
                    ),
                ],
            })
            .unwrap();
    }

    #[test]
    fn routes_recovery_and_adoption_without_consuming_receipts() {
        let authority = runtime(None);
        seed_uncommitted_reply(&authority);
        let supervisor = CoreSupervisorVNext::new(Arc::clone(&authority));
        let snapshot = SnapshotId::new(11).unwrap();

        assert_eq!(supervisor.protocol(), CORE_SUPERVISOR_PROTOCOL);
        assert_eq!(Arc::strong_count(&authority), 2);

        let transitions = supervisor
            .fence_and_snapshot(effect().operation(), origin(), snapshot)
            .unwrap();
        assert_eq!(transitions.fence().event(), TransitionEvent::ExecutorFenced);
        assert_eq!(transitions.snapshot().event(), TransitionEvent::Snapshot);
        let (fence, snapshot_receipt) = transitions.into_parts();
        assert_eq!(fence.into_output(), TransitionOutput::None);
        assert_eq!(snapshot_receipt.into_output(), TransitionOutput::None);

        assert_eq!(
            supervisor
                .ready(effect().operation(), snapshot, successor())
                .unwrap()
                .event(),
            TransitionEvent::Ready
        );
        assert_eq!(
            supervisor
                .rebind(effect().operation(), snapshot, successor())
                .unwrap()
                .event(),
            TransitionEvent::Rebound
        );
        assert_eq!(
            supervisor
                .adopt_effect(effect(), successor())
                .unwrap()
                .event(),
            TransitionEvent::EffectAdopted
        );
        assert!(matches!(
            supervisor.claim_component_settlement(effect(), AGENT_COMPONENT_REPLY, successor()),
            Err(TxError::Core(CoreError::WrongCommitState))
        ));
    }

    #[test]
    fn snapshot_failure_preserves_the_durable_fence_receipt() {
        let authority = runtime(Some(3));
        seed_uncommitted_reply(&authority);
        let supervisor = CoreSupervisorVNext::new(authority);

        let error = supervisor
            .fence_and_snapshot(effect().operation(), origin(), SnapshotId::new(13).unwrap())
            .unwrap_err();
        let FenceSnapshotError::Snapshot { fence, error } = error else {
            panic!("fence must have committed before the injected failure");
        };
        assert_eq!(fence.event(), TransitionEvent::ExecutorFenced);
        assert_eq!(fence.into_output(), TransitionOutput::None);
        assert_eq!(
            error,
            SnapshotTransitionError::Transact(TxError::Persist("injected persistence failure"))
        );
    }
}
