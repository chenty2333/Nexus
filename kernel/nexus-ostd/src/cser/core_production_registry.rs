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
use core::sync::atomic::{AtomicU64, Ordering};

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
const INGRESS_STATE_BITS: u32 = 2;
const INGRESS_STATE_MASK: u64 = (1 << INGRESS_STATE_BITS) - 1;
const INGRESS_CLOSED: u64 = 0;
const INGRESS_INSTALLING: u64 = 1;
const INGRESS_OPEN: u64 = 2;
const INGRESS_CLOSING: u64 = 3;
const INGRESS_MAX_INCARNATION: u64 = u64::MAX >> INGRESS_STATE_BITS;

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

/// Opaque one-use authority to close one exact ingress incarnation.
///
/// This deliberately carries the complete OPEN control word rather than an
/// identity lookup. A semantic identity may be reused after a close/reopen,
/// while this token remains bound to only the incarnation that opened it.
struct ProductionIngressCloseToken {
    open: u64,
    identity: ProductionIngressIdentity,
}

/// Shared installation endpoint for the task-bound close token.
pub(crate) struct ProductionIngressCloseTokenInstaller {
    identity: ProductionIngressIdentity,
    state: Arc<Mutex<ProductionIngressCloseTokenState>>,
}

enum ProductionIngressCloseTokenState {
    Pending,
    Bound(ProductionIngressCloseToken),
    Exited,
}

impl ProductionIngressCloseTokenInstaller {
    /// Binds an opening token unless its task has already exited.
    ///
    /// Returns the token unchanged when the task already exited or this slot
    /// was previously bound, so the opener can close that exact incarnation.
    fn install(&self, token: ProductionIngressCloseToken) -> Option<ProductionIngressCloseToken> {
        if token.identity != self.identity {
            return Some(token);
        }
        let mut state = self.state.lock();
        match &*state {
            ProductionIngressCloseTokenState::Pending => {
                *state = ProductionIngressCloseTokenState::Bound(token);
                None
            }
            ProductionIngressCloseTokenState::Bound(_)
            | ProductionIngressCloseTokenState::Exited => Some(token),
        }
    }
}

/// OSTD task data binding one real task to one production owner and ingress.
pub(crate) struct ProductionIngressTaskData<S> {
    identity: ProductionIngressIdentity,
    owner: Weak<ProductionCoreOwner<S>>,
    exit_observer: Arc<dyn ProductionIngressExitObserver>,
    close_token: Arc<Mutex<ProductionIngressCloseTokenState>>,
}

impl<S> ProductionIngressTaskData<S> {
    /// Binds task data and an installation endpoint to one exact shared owner.
    pub(crate) fn new(
        owner: &Arc<ProductionCoreOwner<S>>,
        identity: ProductionIngressIdentity,
        exit_observer: Arc<dyn ProductionIngressExitObserver>,
    ) -> (Self, ProductionIngressCloseTokenInstaller) {
        let close_token = Arc::new(Mutex::new(ProductionIngressCloseTokenState::Pending));
        (
            Self {
                identity,
                owner: Arc::downgrade(owner),
                exit_observer,
                close_token: Arc::clone(&close_token),
            },
            ProductionIngressCloseTokenInstaller {
                identity,
                state: close_token,
            },
        )
    }

    /// Closes the real production gate before publishing exact-reap metadata.
    pub(crate) fn observe_exact_exit(&self, task: &Task) {
        if !task.is_reaped() {
            return;
        }
        let token = match core::mem::replace(
            &mut *self.close_token.lock(),
            ProductionIngressCloseTokenState::Exited,
        ) {
            ProductionIngressCloseTokenState::Bound(token) => Some(token),
            ProductionIngressCloseTokenState::Pending
            | ProductionIngressCloseTokenState::Exited => None,
        };
        let gate_closed = match (self.owner.upgrade(), token) {
            (Some(owner), Some(token)) => owner.close_ingress(token),
            _ => false,
        };
        self.exit_observer.observe_exit(self.identity, gate_closed);
    }
}

struct ProductionIngressGate {
    // The incarnation and lifecycle state are one CAS word. Identity fields
    // are published only while INSTALLING and may be consumed only when two
    // reads of this word observe the same OPEN incarnation. This prevents a
    // reader from assembling fields from different installations and makes a
    // delayed closer fail after a close/reopen ABA cycle.
    control: AtomicU64,
    operation: AtomicU64,
    executor: AtomicU64,
    executor_generation: AtomicU64,
}

impl ProductionIngressGate {
    const fn closed() -> Self {
        Self {
            control: AtomicU64::new(INGRESS_CLOSED),
            operation: AtomicU64::new(0),
            executor: AtomicU64::new(0),
            executor_generation: AtomicU64::new(0),
        }
    }

    fn open(
        &self,
        identity: ProductionIngressIdentity,
    ) -> Result<ProductionIngressCloseToken, ProductionIngressError> {
        let closed = self.control.load(Ordering::SeqCst);
        if ingress_state(closed) != INGRESS_CLOSED {
            return Err(ProductionIngressError::AlreadyOpen);
        }
        let incarnation = ingress_incarnation(closed)
            .checked_add(1)
            .filter(|incarnation| *incarnation <= INGRESS_MAX_INCARNATION)
            .ok_or(ProductionIngressError::AlreadyOpen)?;
        let installing = ingress_control(incarnation, INGRESS_INSTALLING);
        self.control
            .compare_exchange(closed, installing, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| ProductionIngressError::AlreadyOpen)?;
        self.operation
            .store(identity.operation().get(), Ordering::SeqCst);
        self.executor
            .store(identity.executor().executor().get(), Ordering::SeqCst);
        self.executor_generation
            .store(identity.executor().generation().get(), Ordering::SeqCst);
        self.control
            .store(ingress_control(incarnation, INGRESS_OPEN), Ordering::SeqCst);
        Ok(ProductionIngressCloseToken {
            open: ingress_control(incarnation, INGRESS_OPEN),
            identity,
        })
    }

    fn identity(&self) -> Option<ProductionIngressIdentity> {
        self.open_snapshot().map(|(_, identity)| identity)
    }

    fn close(&self, token: ProductionIngressCloseToken) -> bool {
        self.close_incarnation(token.open)
    }

    fn open_snapshot(&self) -> Option<(u64, ProductionIngressIdentity)> {
        let open = self.control.load(Ordering::SeqCst);
        self.identity_for_open(open)
            .map(|identity| (open, identity))
    }

    fn identity_for_open(&self, open: u64) -> Option<ProductionIngressIdentity> {
        if ingress_state(open) != INGRESS_OPEN {
            return None;
        }
        let operation = OperationId::new(self.operation.load(Ordering::SeqCst)).ok()?;
        let executor = ExecutorId::new(self.executor.load(Ordering::SeqCst)).ok()?;
        let generation =
            ExecutorGeneration::new(self.executor_generation.load(Ordering::SeqCst)).ok()?;
        let identity = ProductionIngressIdentity::new(
            operation,
            ExecutorCoordinate::new(executor, generation),
        );
        (self.control.load(Ordering::SeqCst) == open).then_some(identity)
    }

    fn close_incarnation(&self, open: u64) -> bool {
        debug_assert_eq!(ingress_state(open), INGRESS_OPEN);
        let incarnation = ingress_incarnation(open);
        if self
            .control
            .compare_exchange(
                open,
                ingress_control(incarnation, INGRESS_CLOSING),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_err()
        {
            return false;
        }
        self.control.store(
            ingress_control(incarnation, INGRESS_CLOSED),
            Ordering::SeqCst,
        );
        true
    }
}

const fn ingress_control(incarnation: u64, state: u64) -> u64 {
    (incarnation << INGRESS_STATE_BITS) | state
}

const fn ingress_incarnation(control: u64) -> u64 {
    control >> INGRESS_STATE_BITS
}

const fn ingress_state(control: u64) -> u64 {
    control & INGRESS_STATE_MASK
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
    // This vector is allocated at the fixed custody bound during owner
    // construction. Bearer publication must never allocate after the durable
    // transaction has returned.
    linear_custody: Mutex<Vec<TransitionOutput>>,
    ingress: ProductionIngressGate,
}

impl<S> ProductionCoreOwner<S> {
    /// Installs one already-recovered state without opening ingress.
    pub(crate) fn new(installed: S) -> Result<Self, (CoreError, S)>
    where
        S: InstalledCore,
    {
        let linear_custody = Vec::with_capacity(MAX_LINEAR_PORTAL_BEARERS);
        debug_assert!(linear_custody.capacity() >= MAX_LINEAR_PORTAL_BEARERS);
        Ok(Self {
            installed,
            linear_custody: Mutex::new(linear_custody),
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
        close_token: &ProductionIngressCloseTokenInstaller,
    ) -> Result<(), ProductionIngressError> {
        let token = self.ingress.open(identity)?;
        if let Some(token) = close_token.install(token) {
            self.ingress.close(token);
            return Err(ProductionIngressError::TaskMismatch);
        }
        Ok(())
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

    fn close_ingress(&self, token: ProductionIngressCloseToken) -> bool {
        self.ingress.close(token)
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
        let reserves_linear_custody = command_requires_linear_custody(&request);
        debug_assert_eq!(reserves_linear_custody, expected_intent.is_some());

        // The command grammar fixes which successful client transitions can
        // return a linear bearer.  Reserve one custody slot while the
        // corresponding durable transaction is in flight.  Commands with a
        // statically empty output do not need custody capacity and must not
        // be blocked by an unrelated full bearer queue.
        if reserves_linear_custody {
            let mut custody = self.linear_custody.lock();
            if !linear_custody_has_capacity(custody.len(), true) {
                return Err(ProductionRegistryError::LinearCustodyFull);
            }
            let receipt = self
                .installed
                .transact(request.into())
                .map_err(ProductionRegistryError::Transaction)?;
            let view = CoreTransitionView::from_receipt(&receipt);
            match receipt.into_output() {
                TransitionOutput::None => Err(ProductionRegistryError::MissingCommitIntent),
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
        } else {
            let receipt = self
                .installed
                .transact(request.into())
                .map_err(ProductionRegistryError::Transaction)?;
            let view = CoreTransitionView::from_receipt(&receipt);
            match receipt.into_output() {
                TransitionOutput::None => Ok(view),
                output @ (TransitionOutput::CommitIntent(_)
                | TransitionOutput::CompositeCommitIntents(_)
                | TransitionOutput::SettlementClaim(_)
                | TransitionOutput::ReusePermit(_)
                | TransitionOutput::ArtifactReleasePermit(_)) => {
                    let mut custody = self.linear_custody.lock();
                    retain_or_forget_unexpected_output(&mut custody, output);
                    Err(ProductionRegistryError::UnexpectedLinearOutput)
                }
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

/// Returns whether a client command's successful output must be retained in
/// the kernel-owned linear bearer custody.
fn command_requires_linear_custody(request: &CommandRequest) -> bool {
    matches!(
        request,
        CommandRequest::RecordComponentCommitIntent { .. }
            | CommandRequest::RecordCompositeCommitIntents { .. }
    )
}

/// Checks the fixed custody reservation without conflating no-output
/// transitions with bearer-producing transitions.
fn linear_custody_has_capacity(current_len: usize, reserves_slot: bool) -> bool {
    !reserves_slot || current_len < MAX_LINEAR_PORTAL_BEARERS
}

/// Retains an unexpected bearer whenever the fixed custody has a spare slot.
///
/// A no-output command must never produce a bearer, but this is a trusted-core
/// invariant rather than a reason to drop authority if it is violated. When
/// custody is already full, forgetting the bearer deliberately leaks it while
/// keeping the publication path fail-closed; dropping it could run a future
/// authority destructor or otherwise release it to an untrusted context.
fn retain_or_forget_unexpected_output(
    custody: &mut Vec<TransitionOutput>,
    output: TransitionOutput,
) {
    if custody.len() < MAX_LINEAR_PORTAL_BEARERS && custody.capacity() >= MAX_LINEAR_PORTAL_BEARERS
    {
        custody.push(output);
    } else {
        core::mem::forget(output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn effect() -> EffectId {
        EffectId::new(OperationId::new(1).unwrap(), 1).unwrap()
    }

    fn actor() -> ExecutorCoordinate {
        ExecutorCoordinate::new(
            ExecutorId::new(1).unwrap(),
            ExecutorGeneration::new(1).unwrap(),
        )
    }

    fn ingress_identity(
        operation: u64,
        executor: u64,
        generation: u64,
    ) -> ProductionIngressIdentity {
        ProductionIngressIdentity::new(
            OperationId::new(operation).unwrap(),
            ExecutorCoordinate::new(
                ExecutorId::new(executor).unwrap(),
                ExecutorGeneration::new(generation).unwrap(),
            ),
        )
    }

    fn add_claim() -> CommandRequest {
        CommandRequest::AddComponentClaim {
            effect: effect(),
            component: cser_core::ComponentId::new(1).unwrap(),
            actor: actor(),
            claim: cser_core::ClaimId::new(1).unwrap(),
            kind: cser_core::ClaimKindId::new(1).unwrap(),
            scope: cser_core::ClaimScope::Logical,
            resource: cser_core::ResourceId::new(1).unwrap(),
            resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
            units: 1,
        }
    }

    fn prepare() -> CommandRequest {
        CommandRequest::PrepareCompositeEffect {
            effect: effect(),
            actor: actor(),
        }
    }

    fn component_intent() -> CommandRequest {
        CommandRequest::RecordComponentCommitIntent {
            effect: effect(),
            component: cser_core::ComponentId::new(1).unwrap(),
            actor: actor(),
            operation: Digest::new([1; 32]),
        }
    }

    fn composite_intents() -> CommandRequest {
        CommandRequest::RecordCompositeCommitIntents {
            effect: effect(),
            actor: actor(),
            operations: vec![cser_core::ComponentCommitOperation::new(
                cser_core::ComponentId::new(1).unwrap(),
                Digest::new([1; 32]),
            )],
        }
    }

    #[test]
    fn full_custody_does_not_block_no_output_commands() {
        assert!(!command_requires_linear_custody(&add_claim()));
        assert!(!command_requires_linear_custody(&prepare()));
        assert!(linear_custody_has_capacity(
            MAX_LINEAR_PORTAL_BEARERS,
            false
        ));
    }

    #[test]
    fn full_custody_rejects_bearer_commands_before_durable_admission() {
        assert!(command_requires_linear_custody(&component_intent()));
        assert!(command_requires_linear_custody(&composite_intents()));
        assert!(!linear_custody_has_capacity(
            MAX_LINEAR_PORTAL_BEARERS,
            true
        ));
    }

    #[test]
    fn consuming_a_bearer_reopens_one_reserved_slot() {
        assert!(!linear_custody_has_capacity(
            MAX_LINEAR_PORTAL_BEARERS,
            true
        ));
        assert!(linear_custody_has_capacity(
            MAX_LINEAR_PORTAL_BEARERS - 1,
            true
        ));
    }

    #[test]
    fn unexpected_bearer_is_retained_or_forgotten_without_drop() {
        let mut custody = Vec::with_capacity(MAX_LINEAR_PORTAL_BEARERS);
        let intent = TransitionOutput::CompositeCommitIntents(Vec::new());
        retain_or_forget_unexpected_output(&mut custody, intent);
        assert_eq!(custody.len(), 1);

        custody.resize_with(MAX_LINEAR_PORTAL_BEARERS, || {
            TransitionOutput::CompositeCommitIntents(Vec::new())
        });
        let full_intent = TransitionOutput::CompositeCommitIntents(Vec::new());
        retain_or_forget_unexpected_output(&mut custody, full_intent);
        assert_eq!(custody.len(), MAX_LINEAR_PORTAL_BEARERS);
    }

    #[test]
    fn custody_reservation_is_preallocated_to_the_publication_bound() {
        let custody = Vec::<TransitionOutput>::with_capacity(MAX_LINEAR_PORTAL_BEARERS);
        assert!(custody.capacity() >= MAX_LINEAR_PORTAL_BEARERS);
    }

    #[test]
    fn same_identity_stale_closer_cannot_close_a_new_ingress_incarnation() {
        let gate = ProductionIngressGate::closed();
        let first = ingress_identity(1, 1, 1);

        let stale_close = gate.open(first).unwrap();
        let (stale_open, installed) = gate.open_snapshot().unwrap();
        assert_eq!(installed, first);
        assert!(gate.close_incarnation(stale_open));
        let _current_close = gate.open(first).unwrap();

        assert!(!gate.close(stale_close));
        assert_eq!(gate.identity(), Some(first));
    }

    #[test]
    fn identity_snapshot_rejects_fields_from_a_replaced_incarnation() {
        let gate = ProductionIngressGate::closed();
        let first = ingress_identity(1, 1, 1);
        let second = ingress_identity(2, 2, 2);

        let first_close = gate.open(first).unwrap();
        let stale_open = gate.control.load(Ordering::SeqCst);
        assert!(gate.close(first_close));
        let _second_close = gate.open(second).unwrap();

        assert_eq!(gate.identity_for_open(stale_open), None);
        assert_eq!(gate.open_snapshot().unwrap().1, second);
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
