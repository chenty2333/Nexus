// SPDX-License-Identifier: MPL-2.0

//! Sole production publication boundary for the recovered CSER core.
//!
//! Portal, supervisor, reply, and DMA adapters receive clones of one [`Arc`]
//! containing this owner. The portal remains stateless: any linear bearer
//! returned by a client-admissible transition is moved into this kernel-owned,
//! fixed-capacity custody before an untrusted response can be formed.

use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use cser_core::{
    Command, CommandRequest, CommitIntent, ComponentProviderBinding, CoreError,
    DEVICE_COMMIT_RECEIPT_SCHEMA, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, Digest, EffectId, Engine,
    ExecutorCoordinate, ExecutorGeneration, ExecutorId, OperationId, ProviderCoordinate,
    ProviderGeneration, ProviderGenerationProjection, ProviderId, REPLY_APPLY_RECEIPT_SCHEMA,
    REPLY_COMMIT_RECEIPT_SCHEMA, REPLY_RECEIPT_SCHEMA, REPLY_SETTLEMENT_RECEIPT_SCHEMA,
    REPLY_VERIFIER, TransitionDurability, TransitionOutput, TransitionReceipt, TxError,
    VerifierBinding, VerifierGeneration, WorldId,
};
use ostd::{sync::Mutex, task::Task};

use super::{
    core_portal_vnext::{
        CoreObservation, CoreObservationStamp, CoreQuery, CoreRegistry, CoreTransitionView,
    },
    core_runtime::OstdCserRuntime,
    core_supervisor_vnext::RecoveredCoreAuthority,
};

const MAX_LINEAR_PORTAL_BEARERS: usize = 8;
const INGRESS_CLOSED: u8 = 0;
const INGRESS_INSTALLING: u8 = 1;
const INGRESS_OPEN: u8 = 2;

/// Semantic world used by the production persistent CSER owner.
///
/// This is deliberately an explicit world coordinate rather than an inferred
/// or boot-local value.  Recovery bindings and every standard provider
/// generation must agree on this exact world.
pub(crate) const PRODUCTION_WORLD: WorldId = match WorldId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Stable provider identity for the standard reply adapter.
pub(crate) const STANDARD_REPLY_PROVIDER_ID: ProviderId = match ProviderId::new(1) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Stable provider identity for the standard DMA adapter.
pub(crate) const STANDARD_DMA_PROVIDER_ID: ProviderId = match ProviderId::new(2) {
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// The first explicitly registered generation of the standard providers.
pub(crate) const STANDARD_PROVIDER_GENERATION: ProviderGeneration = match ProviderGeneration::new(1)
{
    Ok(value) => value,
    Err(_) => unreachable!(),
};

/// Exact world/provider/generation coordinate for reply publication.
pub(crate) const STANDARD_REPLY_PROVIDER: ProviderCoordinate = ProviderCoordinate::new(
    PRODUCTION_WORLD,
    STANDARD_REPLY_PROVIDER_ID,
    STANDARD_PROVIDER_GENERATION,
);

/// Exact world/provider/generation coordinate for DMA publication.
pub(crate) const STANDARD_DMA_PROVIDER: ProviderCoordinate = ProviderCoordinate::new(
    PRODUCTION_WORLD,
    STANDARD_DMA_PROVIDER_ID,
    STANDARD_PROVIDER_GENERATION,
);

// The current reply and DMA adapters expose verifier classes and receipt
// schemas, but their VerifierIdentity values do not yet expose an executable
// implementation digest.  These non-zero, stable local identities bind the
// registered catalog classes to those exact adapters without pretending that
// the digest is an automatically derived epoch or a cryptographic code hash.
pub(crate) const REPLY_RECEIPT_IMPLEMENTATION_DIGEST: Digest = Digest::new([0x51; 32]);
pub(crate) const REPLY_COMMIT_IMPLEMENTATION_DIGEST: Digest = Digest::new([0x52; 32]);
pub(crate) const REPLY_APPLY_IMPLEMENTATION_DIGEST: Digest = Digest::new([0x53; 32]);
pub(crate) const REPLY_SETTLEMENT_IMPLEMENTATION_DIGEST: Digest = Digest::new([0x54; 32]);
pub(crate) const DEVICE_RECEIPT_IMPLEMENTATION_DIGEST: Digest = Digest::new([0x61; 32]);
pub(crate) const DEVICE_COMMIT_IMPLEMENTATION_DIGEST: Digest = Digest::new([0x62; 32]);

/// Builds the exact verifier set required by the standard catalog.
///
/// The class/schema coordinates mirror the receipt and evidence rules in the
/// catalog.  Each implementation identity is a stable embedding-owned
/// binding to the corresponding production adapter; it is intentionally
/// explicit because the adapters do not currently publish code digests.
pub(crate) fn standard_verifier_bindings() -> Vec<VerifierBinding> {
    let generation = VerifierGeneration::new(1).expect("standard verifier generation is non-zero");
    vec![
        VerifierBinding::new(
            REPLY_VERIFIER,
            generation,
            REPLY_RECEIPT_SCHEMA,
            REPLY_RECEIPT_IMPLEMENTATION_DIGEST,
        )
        .expect("reply receipt verifier binding is valid"),
        VerifierBinding::new(
            REPLY_VERIFIER,
            generation,
            REPLY_COMMIT_RECEIPT_SCHEMA,
            REPLY_COMMIT_IMPLEMENTATION_DIGEST,
        )
        .expect("reply commit verifier binding is valid"),
        VerifierBinding::new(
            REPLY_VERIFIER,
            generation,
            REPLY_APPLY_RECEIPT_SCHEMA,
            REPLY_APPLY_IMPLEMENTATION_DIGEST,
        )
        .expect("reply apply verifier binding is valid"),
        VerifierBinding::new(
            REPLY_VERIFIER,
            generation,
            REPLY_SETTLEMENT_RECEIPT_SCHEMA,
            REPLY_SETTLEMENT_IMPLEMENTATION_DIGEST,
        )
        .expect("reply settlement verifier binding is valid"),
        VerifierBinding::new(
            DEVICE_VERIFIER,
            generation,
            DEVICE_RECEIPT_SCHEMA,
            DEVICE_RECEIPT_IMPLEMENTATION_DIGEST,
        )
        .expect("device receipt verifier binding is valid"),
        VerifierBinding::new(
            DEVICE_VERIFIER,
            generation,
            DEVICE_COMMIT_RECEIPT_SCHEMA,
            DEVICE_COMMIT_IMPLEMENTATION_DIGEST,
        )
        .expect("device commit verifier binding is valid"),
    ]
}

/// Exact task/operation binding admitted through the production portal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionIngressIdentity {
    operation: OperationId,
    executor: ExecutorCoordinate,
}

impl ProductionIngressIdentity {
    /// Constructs one exact executor binding for the named operation.
    pub(crate) const fn new(operation: OperationId, executor: ExecutorCoordinate) -> Self {
        Self {
            operation,
            executor,
        }
    }

    /// Returns the causal operation admitted by this binding.
    pub(crate) const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the exact admitted executor coordinate.
    pub(crate) const fn executor(self) -> ExecutorCoordinate {
        self.executor
    }
}

/// Atomic production-ingress admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionIngressError {
    /// No production service task currently owns ingress.
    Closed,
    /// Another exact task binding already owns ingress.
    AlreadyOpen,
    /// The caller is not the task bound to this production owner.
    TaskMismatch,
    /// The command coordinates differ from the task's installed binding.
    IdentityMismatch,
}

/// Exact-reap notification run only after the production gate is closed.
pub(crate) trait ProductionIngressExitObserver: Send + Sync {
    /// Receives the task-bound identity and whether this exit closed the gate.
    fn observe_exit(&self, identity: ProductionIngressIdentity, gate_closed: bool);
}

/// OSTD task data binding one real task to one production owner and ingress.
pub(crate) struct ProductionIngressTaskData<S> {
    identity: ProductionIngressIdentity,
    owner: Weak<ProductionCoreOwner<S>>,
    exit_observer: Arc<dyn ProductionIngressExitObserver>,
}

impl<S> ProductionIngressTaskData<S> {
    /// Binds task data to the exact shared owner; no owner may be substituted.
    pub(crate) fn new(
        owner: &Arc<ProductionCoreOwner<S>>,
        identity: ProductionIngressIdentity,
        exit_observer: Arc<dyn ProductionIngressExitObserver>,
    ) -> Self {
        Self {
            identity,
            owner: Arc::downgrade(owner),
            exit_observer,
        }
    }

    /// Closes the real production gate before publishing exact-reap metadata.
    pub(crate) fn observe_exact_exit(&self, task: &Task) {
        if !task.is_reaped() {
            return;
        }
        let gate_closed = self
            .owner
            .upgrade()
            .is_some_and(|owner| owner.close_ingress(self.identity));
        self.exit_observer.observe_exit(self.identity, gate_closed);
    }
}

struct ProductionIngressGate {
    state: AtomicU8,
    operation: AtomicU64,
    executor: AtomicU64,
    executor_generation: AtomicU64,
}

impl ProductionIngressGate {
    const fn closed() -> Self {
        Self {
            state: AtomicU8::new(INGRESS_CLOSED),
            operation: AtomicU64::new(0),
            executor: AtomicU64::new(0),
            executor_generation: AtomicU64::new(0),
        }
    }

    fn open(&self, identity: ProductionIngressIdentity) -> Result<(), ProductionIngressError> {
        self.state
            .compare_exchange(
                INGRESS_CLOSED,
                INGRESS_INSTALLING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| ProductionIngressError::AlreadyOpen)?;
        self.operation
            .store(identity.operation().get(), Ordering::Relaxed);
        self.executor
            .store(identity.executor().executor().get(), Ordering::Relaxed);
        self.executor_generation
            .store(identity.executor().generation().get(), Ordering::Relaxed);
        self.state.store(INGRESS_OPEN, Ordering::Release);
        Ok(())
    }

    fn identity(&self) -> Option<ProductionIngressIdentity> {
        if self.state.load(Ordering::Acquire) != INGRESS_OPEN {
            return None;
        }
        let operation = OperationId::new(self.operation.load(Ordering::Relaxed)).ok()?;
        let executor = ExecutorId::new(self.executor.load(Ordering::Relaxed)).ok()?;
        let generation =
            ExecutorGeneration::new(self.executor_generation.load(Ordering::Relaxed)).ok()?;
        let identity = ProductionIngressIdentity::new(
            operation,
            ExecutorCoordinate::new(executor, generation),
        );
        (self.state.load(Ordering::Acquire) == INGRESS_OPEN).then_some(identity)
    }

    fn close(&self, identity: ProductionIngressIdentity) -> bool {
        if self.identity() != Some(identity) {
            return false;
        }
        self.state
            .compare_exchange(
                INGRESS_OPEN,
                INGRESS_CLOSED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

/// One installed core state. Implementations may be active or boot-quarantined,
/// but every operation must enter the same durable engine owner.
pub(crate) trait InstalledCore: Send + Sync {
    /// Persistence-provider error returned by durable transitions.
    type PersistenceError;

    /// Executes one exact durable core command.
    fn transact(
        &self,
        command: Command,
    ) -> Result<TransitionReceipt, TxError<Self::PersistenceError>>;

    /// Observes authoritative state under the same writer lock.
    fn observe<R>(&self, operation: impl FnOnce(&Engine) -> R) -> R;
}

impl<P> InstalledCore for OstdCserRuntime<P>
where
    P: TransitionDurability + Send,
{
    type PersistenceError = P::Error;

    fn transact(
        &self,
        command: Command,
    ) -> Result<TransitionReceipt, TxError<Self::PersistenceError>> {
        OstdCserRuntime::transact(self, command)
    }

    fn observe<R>(&self, operation: impl FnOnce(&Engine) -> R) -> R {
        OstdCserRuntime::observe(self, operation)
    }
}

/// Failure at the production ingress boundary.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ProductionRegistryError<E> {
    /// The real task-bound production ingress gate rejected the caller.
    Ingress(ProductionIngressError),
    /// The portable core rejected a read-only projection.
    Core(CoreError),
    /// The durable transaction failed or became recovery-required.
    Transaction(TxError<E>),
    /// The trusted bearer custody is full before any mutation occurs.
    LinearCustodyFull,
    /// A caller tried to bypass the portal's trusted-command policy.
    TrustedPathRequired,
    /// A committed client transition returned an unexpected bearer kind.
    UnexpectedLinearOutput,
    /// Commit intent became durable without returning its required bearer.
    MissingCommitIntent,
}

/// The one Registry published by a production boot.
pub(crate) struct ProductionCoreOwner<S> {
    installed: S,
    linear_custody: Mutex<Vec<TransitionOutput>>,
    ingress: ProductionIngressGate,
}

impl<S> ProductionCoreOwner<S> {
    /// Installs one already-recovered state without opening ingress.
    pub(crate) fn new(installed: S) -> Result<Self, (CoreError, S)>
    where
        S: InstalledCore,
    {
        Ok(Self {
            installed,
            linear_custody: Mutex::new(Vec::with_capacity(MAX_LINEAR_PORTAL_BEARERS)),
            ingress: ProductionIngressGate::closed(),
        })
    }

    /// Borrows the installed state for provider-specific quarantine work.
    pub(crate) const fn installed(&self) -> &S {
        &self.installed
    }

    /// Returns the number of linear portal bearers retained by the kernel.
    pub(crate) fn pending_linear_outputs(&self) -> usize {
        self.linear_custody.lock().len()
    }

    /// Opens client/domain ingress only for one exact real service task.
    pub(crate) fn open_ingress(
        &self,
        identity: ProductionIngressIdentity,
    ) -> Result<(), ProductionIngressError> {
        self.ingress.open(identity)
    }

    /// Returns the exact currently admitted service binding, if any.
    pub(crate) fn ingress_identity(&self) -> Option<ProductionIngressIdentity> {
        self.ingress.identity()
    }

    /// Proves that the current OSTD task and owner match the installed gate.
    pub(crate) fn authorize_current_task(
        &self,
        expected: ProductionIngressIdentity,
    ) -> Result<(), ProductionIngressError>
    where
        S: 'static,
    {
        let identity = self.current_task_identity()?;
        if identity != expected {
            return Err(ProductionIngressError::IdentityMismatch);
        }
        Ok(())
    }

    /// Proves that the current OSTD task and owner match the installed gate.
    pub(crate) fn authorize_current_ingress(
        &self,
    ) -> Result<ProductionIngressIdentity, ProductionIngressError>
    where
        S: 'static,
    {
        let installed = self
            .ingress
            .identity()
            .ok_or(ProductionIngressError::Closed)?;
        let task_identity = self.current_task_identity()?;
        if installed == task_identity {
            Ok(installed)
        } else {
            Err(ProductionIngressError::IdentityMismatch)
        }
    }

    fn current_task_identity(&self) -> Result<ProductionIngressIdentity, ProductionIngressError>
    where
        S: 'static,
    {
        let task = Task::current().ok_or(ProductionIngressError::TaskMismatch)?;
        let data = task
            .data()
            .downcast_ref::<ProductionIngressTaskData<S>>()
            .ok_or(ProductionIngressError::TaskMismatch)?;
        let owner = data
            .owner
            .upgrade()
            .ok_or(ProductionIngressError::TaskMismatch)?;
        if !core::ptr::eq(Arc::as_ptr(&owner), self) {
            return Err(ProductionIngressError::TaskMismatch);
        }
        Ok(data.identity)
    }

    /// Transfers one exact component commit intent to its trusted custodian.
    pub(crate) fn take_component_commit_intent(
        &self,
        effect: cser_core::EffectId,
        component: cser_core::ComponentId,
    ) -> Option<CommitIntent> {
        self.take_matching_commit_intent(effect, component)
    }

    fn take_matching_commit_intent(
        &self,
        effect: cser_core::EffectId,
        component: cser_core::ComponentId,
    ) -> Option<CommitIntent> {
        let mut custody = self.linear_custody.lock();
        let index = custody.iter().position(|output| {
            matches!(
                output,
                TransitionOutput::CommitIntent(intent)
                    if intent.effect() == effect && intent.component() == component
            )
        })?;
        match custody.swap_remove(index) {
            TransitionOutput::CommitIntent(intent) => Some(intent),
            _ => unreachable!("the selected linear output is a commit intent"),
        }
    }

    /// Transfers one complete atomic composite commit cohort to its trusted
    /// cross-domain publisher. Partial extraction is deliberately impossible.
    pub(crate) fn take_composite_commit_intents(
        &self,
        effect: cser_core::EffectId,
    ) -> Option<Vec<CommitIntent>> {
        let mut custody = self.linear_custody.lock();
        let index = custody.iter().position(|output| {
            matches!(
                output,
                TransitionOutput::CompositeCommitIntents(intents)
                    if !intents.is_empty()
                        && intents.iter().all(|intent| intent.effect() == effect)
            )
        })?;
        match custody.swap_remove(index) {
            TransitionOutput::CompositeCommitIntents(intents) => Some(intents),
            _ => unreachable!("the selected linear output is a composite intent cohort"),
        }
    }

    /// Consumes an unpublished owner after every portal bearer was transferred.
    pub(crate) fn into_installed(self) -> S {
        let mut owner = self;
        assert!(owner.linear_custody.get_mut().is_empty());
        owner.installed
    }

    fn close_ingress(&self, identity: ProductionIngressIdentity) -> bool {
        self.ingress.close(identity)
    }
}

impl<S: InstalledCore> ProductionCoreOwner<S> {
    /// Executes a trusted supervisor or domain command without translating its
    /// linear output.
    pub(crate) fn transact_trusted<C>(
        &self,
        command: C,
    ) -> Result<TransitionReceipt, TxError<S::PersistenceError>>
    where
        C: Into<Command>,
    {
        let command = command.into();
        self.installed.transact(command)
    }

    /// Registers one exact provider generation through the trusted owner path.
    ///
    /// Ordinary portal ingress never reaches this method: provider lifecycle
    /// is reserved for the recovered owner/supervisor authority.
    pub(crate) fn register_provider_generation(
        &self,
        coordinate: ProviderCoordinate,
        catalog_digest: Digest,
        verifier_bindings: Vec<VerifierBinding>,
    ) -> Result<TransitionReceipt, TxError<S::PersistenceError>> {
        self.transact_trusted(CommandRequest::RegisterProviderGeneration {
            coordinate,
            catalog_digest,
            verifier_bindings,
        })
    }

    /// Atomically admits one composite with a closed component/provider set.
    ///
    /// The operation identity is a stable [`OperationId`], independent of any
    /// external commit-operation digest used later by reply or DMA adapters.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_scoped_composite_effect(
        &self,
        effect: EffectId,
        origin: ExecutorCoordinate,
        kind: cser_core::CompositeKindId,
        charge_account: cser_core::ChargeAccountId,
        bindings: Vec<ComponentProviderBinding>,
    ) -> Result<TransitionReceipt, TxError<S::PersistenceError>> {
        self.transact_trusted(CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin,
            kind,
            charge_account,
            bindings,
        })
    }

    /// Runs a provider or verifier observation under the authoritative lock.
    pub(crate) fn observe_engine<R>(&self, operation: impl FnOnce(&Engine) -> R) -> R {
        self.installed.observe(operation)
    }

    /// Observes one durable provider-generation projection under the owner
    /// lock without granting lifecycle authority.
    pub(crate) fn observe_provider_generation(
        &self,
        coordinate: ProviderCoordinate,
    ) -> Option<ProviderGenerationProjection> {
        self.installed
            .observe(|engine| engine.provider_generation_projection(coordinate))
    }

    /// Trusted owner/supervisor projection query for the same exact record.
    /// This is intentionally read-only; registration and lifecycle transitions
    /// remain separate trusted commands above.
    pub(crate) fn trusted_provider_generation(
        &self,
        coordinate: ProviderCoordinate,
    ) -> Option<ProviderGenerationProjection> {
        self.observe_provider_generation(coordinate)
    }
}

impl<S: InstalledCore + 'static> CoreRegistry for ProductionCoreOwner<S> {
    type Error = ProductionRegistryError<S::PersistenceError>;

    fn transact(&self, request: CommandRequest) -> Result<CoreTransitionView, Self::Error> {
        if !matches!(
            &request,
            CommandRequest::AddComponentClaim { .. }
                | CommandRequest::PrepareCompositeEffect { .. }
                | CommandRequest::RecordComponentCommitIntent { .. }
                | CommandRequest::RecordCompositeCommitIntents { .. }
        ) {
            return Err(ProductionRegistryError::TrustedPathRequired);
        }
        let identity = self
            .authorize_current_ingress()
            .map_err(ProductionRegistryError::Ingress)?;
        if command_ingress_identity(&request) != Some(identity) {
            return Err(ProductionRegistryError::Ingress(
                ProductionIngressError::IdentityMismatch,
            ));
        }
        let expected_intent = command_commit_intent_identity(&request);

        let mut custody = self.linear_custody.lock();
        if custody.len() == MAX_LINEAR_PORTAL_BEARERS {
            return Err(ProductionRegistryError::LinearCustodyFull);
        }
        let receipt = self
            .installed
            .transact(request.into())
            .map_err(ProductionRegistryError::Transaction)?;
        let view = CoreTransitionView::from_receipt(&receipt);
        match receipt.into_output() {
            TransitionOutput::None if expected_intent.is_some() => {
                Err(ProductionRegistryError::MissingCommitIntent)
            }
            TransitionOutput::None => Ok(view),
            TransitionOutput::CommitIntent(intent) => {
                let matches_request = matches!(
                    expected_intent,
                    Some(ExpectedCommitIntent::Single(effect, component))
                        if effect == intent.effect() && component == intent.component()
                );
                custody.push(TransitionOutput::CommitIntent(intent));
                if matches_request {
                    Ok(view)
                } else {
                    Err(ProductionRegistryError::UnexpectedLinearOutput)
                }
            }
            TransitionOutput::CompositeCommitIntents(intents) => {
                let matches_request = match &expected_intent {
                    Some(ExpectedCommitIntent::Composite { effect, components }) => {
                        !intents.is_empty()
                            && intents.len() == components.len()
                            && intents.iter().zip(components).all(|(intent, component)| {
                                intent.effect() == *effect && intent.component() == *component
                            })
                    }
                    _ => false,
                };
                custody.push(TransitionOutput::CompositeCommitIntents(intents));
                if matches_request {
                    Ok(view)
                } else {
                    Err(ProductionRegistryError::UnexpectedLinearOutput)
                }
            }
            output => {
                custody.push(output);
                Err(ProductionRegistryError::UnexpectedLinearOutput)
            }
        }
    }

    fn observe(&self, query: CoreQuery) -> Result<CoreObservation, Self::Error> {
        self.authorize_current_ingress()
            .map_err(ProductionRegistryError::Ingress)?;
        self.installed.observe(|engine| {
            let stamp =
                CoreObservationStamp::new(engine.revision(), engine.head(), engine.freshness());
            match query {
                CoreQuery::CompositeEffect(effect) => Ok(CoreObservation::CompositeEffect {
                    stamp,
                    effect,
                    composite: engine.composite_effect(effect).map(Box::new),
                }),
                CoreQuery::Component(effect, component) => Ok(CoreObservation::Component {
                    stamp,
                    effect,
                    component,
                    projection: engine.component(effect, component),
                }),
                CoreQuery::ComponentClaims(effect, component) => {
                    Ok(CoreObservation::ComponentClaims {
                        stamp,
                        effect,
                        component,
                        claims: engine
                            .component_claims(effect, component)
                            .map_err(ProductionRegistryError::Core)?,
                    })
                }
                CoreQuery::Pressure => Ok(CoreObservation::Pressure {
                    stamp,
                    pressure: engine.pressure(),
                }),
            }
        })
    }
}

fn command_ingress_identity(request: &CommandRequest) -> Option<ProductionIngressIdentity> {
    let (operation, executor) = match request {
        CommandRequest::AddComponentClaim { effect, actor, .. }
        | CommandRequest::PrepareCompositeEffect { effect, actor }
        | CommandRequest::RecordComponentCommitIntent { effect, actor, .. }
        | CommandRequest::RecordCompositeCommitIntents { effect, actor, .. } => {
            (effect.operation(), *actor)
        }
        _ => return None,
    };
    Some(ProductionIngressIdentity::new(operation, executor))
}

enum ExpectedCommitIntent {
    Single(cser_core::EffectId, cser_core::ComponentId),
    Composite {
        effect: cser_core::EffectId,
        components: Vec<cser_core::ComponentId>,
    },
}

fn command_commit_intent_identity(request: &CommandRequest) -> Option<ExpectedCommitIntent> {
    match request {
        CommandRequest::RecordComponentCommitIntent {
            effect, component, ..
        } => Some(ExpectedCommitIntent::Single(*effect, *component)),
        CommandRequest::RecordCompositeCommitIntents {
            effect, operations, ..
        } => Some(ExpectedCommitIntent::Composite {
            effect: *effect,
            components: operations
                .iter()
                .map(|operation| operation.component())
                .collect(),
        }),
        _ => None,
    }
}

impl<S: InstalledCore> RecoveredCoreAuthority for ProductionCoreOwner<S> {
    type PersistenceError = S::PersistenceError;

    fn snapshot_operation(
        &self,
        operation: OperationId,
        snapshot: cser_core::SnapshotId,
    ) -> Result<cser_core::RecoverySnapshot, CoreError> {
        self.installed
            .observe(|engine| engine.snapshot_operation(operation, snapshot))
    }

    fn transact(
        &self,
        command: Command,
    ) -> Result<TransitionReceipt, TxError<Self::PersistenceError>> {
        self.installed.transact(command)
    }
}
