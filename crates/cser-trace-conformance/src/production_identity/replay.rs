//! Replay of a `ProductionIdentityCser` behavior against the `cser-model`
//! production-identity oracle.
//!
//! # What one replayed step checks
//!
//! * the **event** comes from the specification's own `lastEvent` vocabulary,
//!   resolved through [`crate::production_identity::actions::ActionCatalog`],
//!   which additionally requires TLC's process attribution and the recorded
//!   actor class to agree;
//! * the **operand** (which effect) comes from the trace's state delta;
//! * the **resulting state** is computed independently by the oracle and is
//!   then required to project onto TLC's rendering of the successor state.
//!
//! # The atomicity divergence this lane found and pins down
//!
//! The specification and the oracle do not agree on how finely device
//! terminalization is scheduled, and this is a real structural difference
//! rather than a naming one:
//!
//! * `ProductionIdentityModel::acknowledge_iotlb` terminalizes the block
//!   request *and* all three DMA owners in one atomic call. The specification
//!   models the same publication as four separately scheduled transitions
//!   (`CompleteDma` three times, then `CompleteBlock`), and schedules them
//!   *after* `RevokeBegin`, whereas the oracle performs them at the
//!   acknowledgement itself. The oracle therefore runs ahead of the
//!   specification for a bounded window.
//! * `ProductionIdentityModel::publish_guest_reply` terminalizes the
//!   filesystem read *and* the personality syscall in one call, while the
//!   specification terminalizes the filesystem read at `CompleteFilesystem`
//!   and the syscall at `GuestReply`. Here the specification runs ahead.
//!
//! The replayer neither hides nor tolerates this silently. It maintains a
//! [`Desynchronized`] window naming exactly the effects whose lifecycle the
//! two artifacts currently disagree about and in which direction. While an
//! effect is in that window it is excluded from the lifecycle comparison, and
//! when the lagging side catches up the replayer *asserts* that the other
//! side had already performed exactly that terminalization. Every other
//! variable stays under lock-step comparison throughout, and the window must
//! be empty at the end of the behavior.
//!
//! # Other abstraction mismatches
//!
//! * **Effect phase refinement.** The oracle distinguishes `Committed`,
//!   `BackendCompleted`, and `Tombstoned`; the specification keeps all three
//!   in `"Committed"` and tracks the difference in separate variables
//!   (`dmaPhase`, `resetPhase`, `tombstoneKind`). The projection folds the
//!   oracle's three phases back to `"Committed"`.
//! * **Credit recycling.** The specification's `freeCredits` counts a
//!   returned credit as free again. The oracle never recycles: it moves a
//!   credit from `held`/`committed` into a separate `returned` bucket so the
//!   ledger records where every credit went. The projection therefore
//!   compares `free + returned` against `freeCredits`.
//! * **Credit-class refinement.** The specification has four credit types;
//!   the oracle refines them into six classes, granting a DMA owner both a
//!   `PinnedPage` and a `DmaMapping` credit and the syscall an extra
//!   `GuestReply` credit. The projection maps the four specification types
//!   onto their oracle counterparts and does not project the oracle's
//!   `GuestReply` class, which the specification does not model.
//! * **Spec-only events.** `ResetAck`, `RejectForeign`,
//!   `RejectStaleGeneration`, and `DomainReceipt` have no oracle operation.
//!   The replayer applies nothing for them and still requires the full
//!   projection to hold, which checks the substantive claim that these
//!   transitions do not disturb any state the oracle models.
//! * **Closure schedule.** `AbortLeaf` lets the specification abort any
//!   uncommitted leaf; the oracle's `revoke_next` selects one deterministically
//!   through its root reverse index. A disagreement is reported as
//!   [`ConformanceError::ClosureSelectionDivergence`] rather than tolerated.
//! * **Actors and CPUs.** The specification's `CpuCount`, actor kinds, and CPU
//!   fields state bounded SMP obligations; the oracle is single-threaded and
//!   models none of them. Those variables are not projected.

use core::fmt;
use std::collections::BTreeMap;

use cser_model::production_identity::{
    CommitReceipt, CreditClass, CreditDisposition, DomainId, EffectIdentity, EffectPhase,
    IotlbRetryToken, OperationClass, ParentIdentity, ProductionIdentityError,
    ProductionIdentityInvariant, ProductionIdentityModel, ReadyToken, RecoverySnapshot,
    RegistryInstance, RevokeTicket, RootId, RootPhase, ServiceInstanceId, TombstoneToken,
};

use crate::production_identity::actions::{ActionCatalog, CatalogError, SpecAction};
use crate::report::ReplayReport;
use crate::trace::{Trace, TraceState};
use crate::value::TlaValue;

/// Specification variables the oracle reproduces and the replayer compares.
pub const PROJECTED_VARIABLES: [&str; 11] = [
    "adoptCount",
    "authorityEpoch",
    "bindingEpoch",
    "crashCount",
    "creditState",
    "effectBinding",
    "effectState",
    "freeCredits",
    "guestReplyCount",
    "scopeState",
    "terminalCount",
];

/// Specification variables with no oracle counterpart, grouped by why.
///
/// This family's module keeps considerably more model scaffolding than the
/// baseline: scenario selectors that pick a witness path, workload ordering
/// indices that exist "only to keep the finite graph tractable", closure and
/// receipt history, reject audit trails, and the SMP actor/CPU obligations
/// that the module's own header says do not model locks, interrupts, or a
/// hardware memory model. None of it has a counterpart in a single-threaded
/// Rust oracle, so this lane establishes nothing about any of it.
pub const UNPROJECTED_VARIABLES: [&str; 55] = [
    // Scenario selection and workload ordering scaffolding.
    "scenarioMode",
    "nextDeriveIndex",
    "nextPrepareIndex",
    // Identity metadata the oracle stores inside opaque identities rather
    // than as separately observable state.
    "effectParent",
    "effectRegistry",
    "effectGeneration",
    "effectAuthority",
    "effectOriginBinding",
    "effectDeviceGeneration",
    "effectDeviceSession",
    "createdByWorkload",
    "commitCount",
    "terminalSequence",
    "nextTerminalSequence",
    // Root gate and closure bookkeeping.
    "scopeGate",
    "closingEpoch",
    "effectsAtClose",
    "closingEffects",
    "committedAtClose",
    "commitAtClose",
    "closureTargetCount",
    "closureSteps",
    "closingDomains",
    // Recovery bookkeeping the oracle keeps inside snapshot and ready tokens.
    "domainPhase",
    "recoveryCohort",
    "snapshotBinding",
    "snapshotCohort",
    // Device session, timeout, and backend detail.
    "deviceSession",
    "deviceGeneration",
    "commitDeviceGeneration",
    "devicePublished",
    "deviceOutcome",
    "dmaPhase",
    "resetPhase",
    "tombstoneKind",
    "tombstoneEffect",
    "timeoutKinds",
    "retryKinds",
    "backendDataVisible",
    "guestReplyResult",
    // Domain closure receipts, which the oracle does not publish at all.
    "domainReceipt",
    "receiptSequence",
    "receiptBindingEpoch",
    "receiptDeviceGeneration",
    "nextReceiptSequence",
    // Reject audit trail.
    "rejectKinds",
    "presentedRegistry",
    "presentedDeviceGeneration",
    // Event and SMP actor/CPU obligations.
    "lastEvent",
    "lastActorKind",
    "lastActorCpu",
    "commitCpu",
    "revokeCpu",
    "completionCpu",
    "irqCount",
];

/// The specification's effect names, in `DeriveOrder`.
const EFFECT_NAMES: [(&str, OperationClass); 6] = [
    ("PersonalitySyscall", OperationClass::FilesystemSyscall),
    ("FilesystemRead", OperationClass::FilesystemRead),
    ("BlockRequest", OperationClass::BlockRequest),
    ("DmaQueueOwnerA", OperationClass::DmaQueueOwnerA),
    ("DmaQueueOwnerB", OperationClass::DmaQueueOwnerB),
    ("DmaRequestOwner", OperationClass::DmaRequestOwner),
];

/// The specification's domain names.
const DOMAIN_NAMES: [(&str, DomainId); 3] = [
    ("Personality", DomainId::Personality),
    ("Filesystem", DomainId::Filesystem),
    ("VirtIo", DomainId::VirtIo),
];

/// The specification's credit types and the oracle class each maps onto.
///
/// The oracle's `PinnedPage` and `GuestReply` classes have no specification
/// counterpart and are not projected.
const CREDIT_TYPES: [(&str, CreditClass); 4] = [
    ("Control", CreditClass::Control),
    ("FilesystemCredit", CreditClass::FilesystemOperation),
    ("QueueSlot", CreditClass::QueueSlot),
    ("DmaOwner", CreditClass::DmaMapping),
];

/// Which artifact is ahead for an effect inside the desynchronized window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ahead {
    /// The oracle already terminalized; the specification has not yet.
    Oracle,
    /// The specification already terminalized; the oracle has not yet.
    Specification,
}

/// Effects whose lifecycle the two artifacts currently disagree about.
type Desynchronized = BTreeMap<&'static str, Ahead>;

/// Why a behavior was rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConformanceError {
    /// The event could not be resolved or corroborated.
    Catalog(CatalogError),
    /// The oracle rejected an operation the specification took.
    Rejected {
        /// State the operation was meant to produce.
        state_index: u32,
        /// Event resolved from the specification.
        action: SpecAction,
        /// Oracle rejection.
        source: ProductionIdentityError,
    },
    /// The oracle's own invariant audit failed after an accepted operation.
    Invariant {
        /// State the operation produced.
        state_index: u32,
        /// Audit failure.
        source: ProductionIdentityInvariant,
    },
    /// A projected variable disagreed with the specification's state.
    ProjectionMismatch {
        /// State in which the disagreement appeared.
        state_index: u32,
        /// Projected variable name.
        variable: &'static str,
        /// Value TLC printed.
        expected: TlaValue,
        /// Value the oracle produced.
        actual: TlaValue,
    },
    /// A state omitted a variable the projection needs.
    MissingVariable {
        /// State index.
        state_index: u32,
        /// Variable name.
        variable: &'static str,
    },
    /// The state delta did not identify exactly one operand effect.
    Operand {
        /// State index.
        state_index: u32,
        /// Event whose operand was being derived.
        action: SpecAction,
        /// Variable inspected for the delta.
        variable: &'static str,
        /// Number of effects whose entry changed.
        changed: usize,
    },
    /// An event named an effect the specification never derived.
    UnknownEffect {
        /// State index.
        state_index: u32,
        /// Effect name.
        effect: String,
    },
    /// An operation needed a token an earlier event should have produced.
    MissingToken {
        /// State index.
        state_index: u32,
        /// Event that needed the token.
        action: SpecAction,
        /// Token that was absent.
        token: &'static str,
    },
    /// The oracle's deterministic closure schedule chose another effect.
    ClosureSelectionDivergence {
        /// State index.
        state_index: u32,
        /// Effect the specification aborted.
        specification: String,
        /// Operation class the oracle aborted.
        oracle: OperationClass,
    },
    /// A catch-up step found the other artifact had not done the work the
    /// desynchronized window claimed it had.
    CatchUpMismatch {
        /// State index.
        state_index: u32,
        /// Effect that failed to catch up.
        effect: &'static str,
        /// Phase the oracle holds for it.
        phase: Option<EffectPhase>,
    },
    /// The behavior ended while the two artifacts still disagreed.
    UnresolvedDesynchronization {
        /// Effects still outstanding.
        effects: Vec<String>,
    },
    /// The initial state did not describe a startable root.
    MalformedInitialState {
        /// What the replayer required.
        detail: &'static str,
    },
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(source) => write!(formatter, "{source}"),
            Self::Rejected {
                state_index,
                action,
                source,
            } => write!(
                formatter,
                "state {state_index}: oracle rejected {action}: {source:?}"
            ),
            Self::Invariant {
                state_index,
                source,
            } => write!(
                formatter,
                "state {state_index}: oracle audit failed: {source:?}"
            ),
            Self::ProjectionMismatch {
                state_index,
                variable,
                expected,
                actual,
            } => write!(
                formatter,
                "state {state_index}: {variable} is {expected} in the specification but {actual} \
                 in the oracle"
            ),
            Self::MissingVariable {
                state_index,
                variable,
            } => write!(formatter, "state {state_index}: {variable} is missing"),
            Self::Operand {
                state_index,
                action,
                variable,
                changed,
            } => write!(
                formatter,
                "state {state_index}: {action} changed {variable} for {changed} effects; expected \
                 exactly one"
            ),
            Self::UnknownEffect {
                state_index,
                effect,
            } => write!(formatter, "state {state_index}: effect {effect} is unknown"),
            Self::MissingToken {
                state_index,
                action,
                token,
            } => write!(formatter, "state {state_index}: {action} needs a {token}"),
            Self::ClosureSelectionDivergence {
                state_index,
                specification,
                oracle,
            } => write!(
                formatter,
                "state {state_index}: the specification aborted {specification} but the oracle \
                 schedule aborted {oracle:?}"
            ),
            Self::CatchUpMismatch {
                state_index,
                effect,
                phase,
            } => write!(
                formatter,
                "state {state_index}: {effect} caught up but the oracle holds {phase:?}"
            ),
            Self::UnresolvedDesynchronization { effects } => write!(
                formatter,
                "the behavior ended with {effects:?} still disagreeing between the artifacts"
            ),
            Self::MalformedInitialState { detail } => {
                write!(formatter, "initial state is unusable: {detail}")
            }
        }
    }
}

impl std::error::Error for ConformanceError {}

impl From<CatalogError> for ConformanceError {
    fn from(source: CatalogError) -> Self {
        Self::Catalog(source)
    }
}

/// Replays a complete behavior against a fresh oracle instance.
///
/// # Errors
///
/// Returns [`ConformanceError`] as soon as any step fails to resolve, is
/// rejected by the oracle, or produces a state that does not project onto the
/// specification's state.
pub fn replay(trace: &Trace, catalog: &ActionCatalog) -> Result<ReplayReport, ConformanceError> {
    let initial = trace
        .states
        .first()
        .ok_or(ConformanceError::MalformedInitialState {
            detail: "the behavior has no states",
        })?;
    let mut replayer = Replayer::start(initial)?;
    let mut report = ReplayReport::default();

    for pair in trace.states.windows(2) {
        let (previous, current) = (&pair[0], &pair[1]);
        let action = catalog.resolve(current)?;
        replayer.apply(action, previous, current)?;
        report.record(action.spec_name());
    }

    if !replayer.desynchronized.is_empty() {
        return Err(ConformanceError::UnresolvedDesynchronization {
            effects: replayer
                .desynchronized
                .keys()
                .map(|name| String::from(*name))
                .collect(),
        });
    }
    Ok(report)
}

/// Oracle-side replay state for one behavior.
struct Replayer {
    model: ProductionIdentityModel,
    effects: BTreeMap<&'static str, EffectIdentity>,
    commit: Option<CommitReceipt>,
    ticket: Option<RevokeTicket>,
    snapshot: Option<RecoverySnapshot>,
    ready: Option<ReadyToken>,
    tombstone: Option<TombstoneToken>,
    iotlb_retry: Option<IotlbRetryToken>,
    reset_retried: bool,
    services: u64,
    desynchronized: Desynchronized,
}

impl Replayer {
    fn start(initial: &TraceState) -> Result<Self, ConformanceError> {
        let replayer = Self {
            model: ProductionIdentityModel::new(RegistryInstance::new(1), RootId::new(1), 1),
            effects: BTreeMap::new(),
            commit: None,
            ticket: None,
            snapshot: None,
            ready: None,
            tombstone: None,
            iotlb_retry: None,
            reset_retried: false,
            services: 3,
            desynchronized: Desynchronized::new(),
        };
        replayer.compare(initial)?;
        Ok(replayer)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one arm per specification event keeps the mapping auditable in one place"
    )]
    fn apply(
        &mut self,
        action: SpecAction,
        previous: &TraceState,
        current: &TraceState,
    ) -> Result<(), ConformanceError> {
        let index = current.index;
        match action {
            SpecAction::Derive => {
                let name = self.operand(action, "effectState", previous, current)?;
                let operation = operation_named(index, &name)?;
                let parent = match operation.parent_operation() {
                    None => ParentIdentity::Root(self.model.root_identity().lineage()),
                    Some(parent) => {
                        ParentIdentity::Effect(self.identity(index, parent_name(parent))?.key())
                    }
                };
                let binding = self.binding(index, action, operation.domain())?;
                let identity = self
                    .model
                    .register_effect(self.model.root_identity(), binding, operation, parent)
                    .map_err(|source| rejected(index, action, source))?;
                self.effects.insert(static_name(index, &name)?, identity);
            }
            SpecAction::Prepare => {
                let name = self.operand(action, "effectState", previous, current)?;
                let identity = self.identity(index, &name)?;
                let binding = self.binding(index, action, identity.domain())?;
                self.model
                    .prepare_effect(binding, identity)
                    .map_err(|source| rejected(index, action, source))?;
            }
            SpecAction::Crash => {
                let binding = self.binding(index, action, DomainId::Filesystem)?;
                self.model
                    .crash_domain(binding)
                    .map_err(|source| rejected(index, action, source))?;
            }
            SpecAction::Snapshot => {
                let snapshot = self
                    .model
                    .snapshot_domain(self.model.root_identity(), DomainId::Filesystem)
                    .map_err(|source| rejected(index, action, source))?;
                self.snapshot = Some(snapshot);
            }
            SpecAction::Ready => {
                let snapshot = self.snapshot.take().ok_or(ConformanceError::MissingToken {
                    state_index: index,
                    action,
                    token: "recovery snapshot",
                })?;
                let ready = self
                    .model
                    .ready_domain(snapshot)
                    .map_err(|source| rejected(index, action, source))?;
                self.ready = Some(ready);
            }
            SpecAction::Rebind => {
                let ready = self.ready.take().ok_or(ConformanceError::MissingToken {
                    state_index: index,
                    action,
                    token: "ready token",
                })?;
                self.services = self.services.saturating_add(1);
                self.model
                    .rebind_domain(ready, ServiceInstanceId::new(self.services))
                    .map_err(|source| rejected(index, action, source))?;
            }
            SpecAction::Adopt => {
                let name = self.operand(action, "effectBinding", previous, current)?;
                let key = static_name(index, &name)?;
                let identity = self.identity(index, &name)?;
                let binding = self.binding(index, action, identity.domain())?;
                let adopted = self
                    .model
                    .adopt_effect(binding, identity)
                    .map_err(|source| rejected(index, action, source))?;
                self.effects.insert(key, adopted);
            }
            SpecAction::DeviceCommit => {
                let binding = self.binding(index, action, DomainId::VirtIo)?;
                let block = self.identity(index, "BlockRequest")?;
                let owners = [
                    self.identity(index, "DmaQueueOwnerA")?,
                    self.identity(index, "DmaQueueOwnerB")?,
                    self.identity(index, "DmaRequestOwner")?,
                ];
                let receipt = self
                    .model
                    .commit_block(binding, block, owners)
                    .map_err(|source| rejected(index, action, source))?;
                self.commit = Some(receipt);
            }
            SpecAction::DeviceComplete => {
                let receipt = self.receipt(index, action)?;
                self.model
                    .complete_backend(receipt)
                    .map_err(|source| rejected(index, action, source))?;
            }
            SpecAction::IotlbAck => {
                // One oracle call terminalizes the block request and all three
                // DMA owners; the specification schedules those four
                // terminalizations later, as separate transitions.
                if let Some(retry) = self.iotlb_retry.take() {
                    self.model
                        .acknowledge_retry_iotlb(retry)
                        .map_err(|source| rejected(index, action, source))?;
                } else {
                    let receipt = self.receipt(index, action)?;
                    self.model
                        .acknowledge_iotlb(receipt)
                        .map_err(|source| rejected(index, action, source))?;
                }
                self.tombstone = None;
                for name in [
                    "DmaQueueOwnerA",
                    "DmaQueueOwnerB",
                    "DmaRequestOwner",
                    "BlockRequest",
                ] {
                    self.desynchronized.insert(name, Ahead::Oracle);
                }
            }
            SpecAction::ResetTimeout => {
                let ticket = self.revoke_ticket(index, action)?;
                let receipt = self.receipt(index, action)?;
                let tombstone = self
                    .model
                    .retain_reset_timeout(ticket, receipt)
                    .map_err(|source| rejected(index, action, source))?;
                self.tombstone = Some(tombstone);
            }
            SpecAction::ResetRetry => {
                let ticket = self.revoke_ticket(index, action)?;
                let tombstone = self
                    .tombstone
                    .take()
                    .ok_or(ConformanceError::MissingToken {
                        state_index: index,
                        action,
                        token: "reset tombstone",
                    })?;
                self.model
                    .retry_after_reset(ticket, tombstone)
                    .map_err(|source| rejected(index, action, source))?;
                self.reset_retried = true;
            }
            SpecAction::IotlbTimeout => {
                let ticket = self.revoke_ticket(index, action)?;
                if !self.reset_retried {
                    return Err(ConformanceError::MissingToken {
                        state_index: index,
                        action,
                        token: "reset retry token",
                    });
                }
                let retry = self.model.projection().device.reset_retry.ok_or(
                    ConformanceError::MissingToken {
                        state_index: index,
                        action,
                        token: "reset retry token",
                    },
                )?;
                let tombstone = self
                    .model
                    .retain_iotlb_timeout(ticket, retry)
                    .map_err(|source| rejected(index, action, source))?;
                self.tombstone = Some(tombstone);
            }
            SpecAction::IotlbRetry => {
                let ticket = self.revoke_ticket(index, action)?;
                let tombstone = self
                    .tombstone
                    .take()
                    .ok_or(ConformanceError::MissingToken {
                        state_index: index,
                        action,
                        token: "iotlb tombstone",
                    })?;
                let retry = self
                    .model
                    .retry_iotlb(ticket, tombstone)
                    .map_err(|source| rejected(index, action, source))?;
                self.iotlb_retry = Some(retry);
            }
            SpecAction::RevokeBegin => {
                let ticket = self
                    .model
                    .revoke_begin(self.model.root_identity())
                    .map_err(|source| rejected(index, action, source))?;
                self.ticket = Some(ticket);
            }
            SpecAction::AbortLeaf => {
                let name = self.operand(action, "effectState", previous, current)?;
                let ticket = self.revoke_ticket(index, action)?;
                let step = self
                    .model
                    .revoke_next(ticket)
                    .map_err(|source| rejected(index, action, source))?;
                let expected = operation_named(index, &name)?;
                if step.effect.operation() != expected {
                    return Err(ConformanceError::ClosureSelectionDivergence {
                        state_index: index,
                        specification: name,
                        oracle: step.effect.operation(),
                    });
                }
            }
            SpecAction::CompleteDma | SpecAction::CompleteBlock => {
                let name = self.operand(action, "effectState", previous, current)?;
                self.catch_up(index, &name, Ahead::Oracle)?;
            }
            SpecAction::CompleteFilesystem => {
                // The specification terminalizes the filesystem read here; the
                // oracle does it inside `publish_guest_reply` at `GuestReply`.
                self.desynchronized
                    .insert("FilesystemRead", Ahead::Specification);
            }
            SpecAction::GuestReply => {
                let syscall = self.identity(index, "PersonalitySyscall")?;
                let filesystem = self.identity(index, "FilesystemRead")?;
                let receipt = self.receipt(index, action)?;
                self.model
                    .publish_guest_reply(syscall, filesystem, receipt)
                    .map_err(|source| rejected(index, action, source))?;
                self.catch_up(index, "FilesystemRead", Ahead::Specification)?;
            }
            SpecAction::RevokeComplete => {
                let ticket = self.revoke_ticket(index, action)?;
                self.model
                    .revoke_complete(ticket)
                    .map_err(|source| rejected(index, action, source))?;
            }
            // Events the oracle does not model at all. Applying nothing and
            // still requiring the projection to hold is the check that they
            // disturb no state the oracle represents.
            SpecAction::ResetAck
            | SpecAction::RejectForeign
            | SpecAction::RejectStaleGeneration
            | SpecAction::DomainReceipt => {}
        }

        self.model
            .check_invariants()
            .map_err(|source| ConformanceError::Invariant {
                state_index: index,
                source,
            })?;
        self.compare(current)
    }

    /// Clears one effect from the desynchronized window, asserting that the
    /// side that was ahead really had performed the terminalization.
    fn catch_up(
        &mut self,
        state_index: u32,
        name: &str,
        expected: Ahead,
    ) -> Result<(), ConformanceError> {
        let key = static_name(state_index, name)?;
        if self.desynchronized.get(key) != Some(&expected) {
            return Err(ConformanceError::CatchUpMismatch {
                state_index,
                effect: key,
                phase: self.phase(key),
            });
        }
        if self.phase(key) != Some(EffectPhase::Completed) {
            return Err(ConformanceError::CatchUpMismatch {
                state_index,
                effect: key,
                phase: self.phase(key),
            });
        }
        self.desynchronized.remove(key);
        Ok(())
    }

    fn phase(&self, name: &str) -> Option<EffectPhase> {
        let identity = self.effects.get(name)?;
        self.model
            .projection()
            .effects
            .into_iter()
            .find(|effect| effect.identity.key() == identity.key())
            .map(|effect| effect.phase)
    }

    fn identity(&self, state_index: u32, name: &str) -> Result<EffectIdentity, ConformanceError> {
        self.effects
            .get(name)
            .copied()
            .ok_or_else(|| ConformanceError::UnknownEffect {
                state_index,
                effect: String::from(name),
            })
    }

    fn binding(
        &self,
        state_index: u32,
        action: SpecAction,
        domain: DomainId,
    ) -> Result<cser_model::production_identity::BindingIdentity, ConformanceError> {
        self.model
            .binding(domain)
            .ok_or(ConformanceError::MissingToken {
                state_index,
                action,
                token: "domain binding",
            })
    }

    fn receipt(
        &self,
        state_index: u32,
        action: SpecAction,
    ) -> Result<CommitReceipt, ConformanceError> {
        self.commit.ok_or(ConformanceError::MissingToken {
            state_index,
            action,
            token: "commit receipt",
        })
    }

    fn revoke_ticket(
        &self,
        state_index: u32,
        action: SpecAction,
    ) -> Result<RevokeTicket, ConformanceError> {
        self.ticket.clone().ok_or(ConformanceError::MissingToken {
            state_index,
            action,
            token: "revoke ticket",
        })
    }

    /// Returns the single effect whose entry in `variable` changed.
    fn operand(
        &self,
        action: SpecAction,
        variable: &'static str,
        previous: &TraceState,
        current: &TraceState,
    ) -> Result<String, ConformanceError> {
        let before = previous
            .get(variable)
            .ok_or(ConformanceError::MissingVariable {
                state_index: previous.index,
                variable,
            })?;
        let after = current
            .get(variable)
            .ok_or(ConformanceError::MissingVariable {
                state_index: current.index,
                variable,
            })?;
        let mut changed = Vec::new();
        for (name, _) in EFFECT_NAMES {
            let key = TlaValue::Str(String::from(name));
            if before.apply(&key) != after.apply(&key) {
                changed.push(name);
            }
        }
        match changed.as_slice() {
            [only] => Ok(String::from(*only)),
            other => Err(ConformanceError::Operand {
                state_index: current.index,
                action,
                variable,
                changed: other.len(),
            }),
        }
    }

    /// Requires every projected variable of the oracle to equal the
    /// specification's rendering of the same variable, skipping the lifecycle
    /// entries of effects inside the desynchronized window.
    fn compare(&self, state: &TraceState) -> Result<(), ConformanceError> {
        for (variable, actual) in self.project() {
            let expected = state
                .get(variable)
                .ok_or(ConformanceError::MissingVariable {
                    state_index: state.index,
                    variable,
                })?;
            let (expected, actual) = if LIFECYCLE_VARIABLES.contains(&variable) {
                (
                    without_desynchronized(expected, &self.desynchronized),
                    without_desynchronized(&actual, &self.desynchronized),
                )
            } else {
                (expected.clone(), actual)
            };
            if expected != actual {
                return Err(ConformanceError::ProjectionMismatch {
                    state_index: state.index,
                    variable,
                    expected,
                    actual,
                });
            }
        }
        Ok(())
    }

    /// Renders the oracle's state in the specification's vocabulary.
    fn project(&self) -> Vec<(&'static str, TlaValue)> {
        let projection = self.model.projection();
        let by_key: BTreeMap<_, _> = projection
            .effects
            .iter()
            .map(|effect| (effect.identity.key(), effect))
            .collect();

        let mut effect_state = Vec::new();
        let mut credit_state = Vec::new();
        let mut terminal_count = Vec::new();
        let mut effect_binding = Vec::new();
        let mut adoptions: BTreeMap<DomainId, i64> = BTreeMap::new();

        for (name, _) in EFFECT_NAMES {
            let key = TlaValue::Str(String::from(name));
            let view = self
                .effects
                .get(name)
                .and_then(|identity| by_key.get(&identity.key()).copied());
            match view {
                Some(view) => {
                    effect_state.push((key.clone(), TlaValue::Str(phase_name(view.phase))));
                    credit_state.push((
                        key.clone(),
                        TlaValue::Str(disposition_name(view.credit_disposition)),
                    ));
                    terminal_count
                        .push((key.clone(), TlaValue::Int(i64::from(view.terminalizations))));
                    effect_binding.push((key, tla_epoch(view.current_binding.binding_epoch())));
                    *adoptions.entry(view.identity.domain()).or_insert(0) +=
                        i64::from(view.adoptions);
                }
                None => {
                    effect_state.push((key.clone(), TlaValue::Str(String::from("Unused"))));
                    credit_state.push((key.clone(), TlaValue::Str(String::from("None"))));
                    terminal_count.push((key.clone(), TlaValue::Int(0)));
                    effect_binding.push((key, TlaValue::Int(-1)));
                }
            }
        }

        let binding_epoch = DOMAIN_NAMES
            .into_iter()
            .map(|(name, domain)| {
                (
                    TlaValue::Str(String::from(name)),
                    tla_epoch(projection.bindings[domain_index(domain)].binding_epoch),
                )
            })
            .collect();
        let adopt_count = DOMAIN_NAMES
            .into_iter()
            .map(|(name, domain)| {
                (
                    TlaValue::Str(String::from(name)),
                    TlaValue::Int(adoptions.get(&domain).copied().unwrap_or(0)),
                )
            })
            .collect();
        let free_credits = CREDIT_TYPES
            .into_iter()
            .map(|(name, class)| {
                (
                    TlaValue::Str(String::from(name)),
                    TlaValue::Int(
                        i64::try_from(
                            projection.ledger.free[credit_index(class)]
                                + projection.ledger.returned[credit_index(class)],
                        )
                        .unwrap_or(i64::MAX),
                    ),
                )
            })
            .collect();

        vec![
            (
                "scopeState",
                TlaValue::Str(root_phase_name(projection.root_phase)),
            ),
            ("authorityEpoch", tla_epoch(projection.authority_epoch)),
            (
                "crashCount",
                TlaValue::Int(i64::try_from(projection.counters.crashes).unwrap_or(i64::MAX)),
            ),
            (
                "guestReplyCount",
                TlaValue::Int(i64::try_from(projection.counters.guest_replies).unwrap_or(i64::MAX)),
            ),
            ("bindingEpoch", TlaValue::function(binding_epoch)),
            ("adoptCount", TlaValue::function(adopt_count)),
            ("freeCredits", TlaValue::function(free_credits)),
            ("effectState", TlaValue::function(effect_state)),
            ("creditState", TlaValue::function(credit_state)),
            ("terminalCount", TlaValue::function(terminal_count)),
            ("effectBinding", TlaValue::function(effect_binding)),
        ]
    }
}

/// Per-effect variables suspended for effects inside the desynchronized
/// window.
const LIFECYCLE_VARIABLES: [&str; 4] =
    ["effectState", "creditState", "terminalCount", "freeCredits"];

/// Drops the entries of effects whose lifecycle the artifacts disagree about.
///
/// `freeCredits` is aggregated over effects, so any outstanding
/// disagreement makes the whole variable incomparable rather than a
/// per-entry one.
fn without_desynchronized(value: &TlaValue, window: &Desynchronized) -> TlaValue {
    if window.is_empty() {
        return value.clone();
    }
    let TlaValue::Function(entries) = value else {
        return value.clone();
    };
    let retained: Vec<_> = entries
        .iter()
        .filter(|(key, _)| match key {
            TlaValue::Str(name) => !window.contains_key(name.as_str()),
            _ => true,
        })
        .cloned()
        .collect();
    if retained.len() == entries.len() {
        // The variable is aggregated rather than keyed by effect; an
        // outstanding disagreement makes it incomparable.
        return TlaValue::Function(Vec::new());
    }
    TlaValue::Function(retained)
}

fn rejected(
    state_index: u32,
    action: SpecAction,
    source: ProductionIdentityError,
) -> ConformanceError {
    ConformanceError::Rejected {
        state_index,
        action,
        source,
    }
}

fn static_name(state_index: u32, name: &str) -> Result<&'static str, ConformanceError> {
    EFFECT_NAMES
        .into_iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(candidate, _)| candidate)
        .ok_or_else(|| ConformanceError::UnknownEffect {
            state_index,
            effect: String::from(name),
        })
}

fn operation_named(state_index: u32, name: &str) -> Result<OperationClass, ConformanceError> {
    EFFECT_NAMES
        .into_iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, operation)| operation)
        .ok_or_else(|| ConformanceError::UnknownEffect {
            state_index,
            effect: String::from(name),
        })
}

fn parent_name(operation: OperationClass) -> &'static str {
    EFFECT_NAMES
        .into_iter()
        .find(|(_, candidate)| *candidate == operation)
        .map_or("PersonalitySyscall", |(name, _)| name)
}

fn domain_index(domain: DomainId) -> usize {
    DomainId::ALL
        .into_iter()
        .position(|candidate| candidate == domain)
        .unwrap_or(0)
}

fn credit_index(class: CreditClass) -> usize {
    CreditClass::ALL
        .into_iter()
        .position(|candidate| candidate == class)
        .unwrap_or(0)
}

/// Converts a one-based oracle epoch to the specification's zero-based epoch.
fn tla_epoch(epoch: u64) -> TlaValue {
    TlaValue::Int(i64::try_from(epoch).unwrap_or(i64::MAX) - 1)
}

fn root_phase_name(phase: RootPhase) -> String {
    String::from(match phase {
        RootPhase::Active => "Active",
        RootPhase::Closing => "Closing",
        RootPhase::Revoked => "Revoked",
    })
}

/// Folds the oracle's device-phase refinement back to the specification's
/// coarser `"Committed"`.
fn phase_name(phase: EffectPhase) -> String {
    String::from(match phase {
        EffectPhase::Registered => "Registered",
        EffectPhase::Prepared => "Prepared",
        EffectPhase::Committed | EffectPhase::BackendCompleted | EffectPhase::Tombstoned => {
            "Committed"
        }
        EffectPhase::Completed => "Completed",
        EffectPhase::Aborted => "Aborted",
    })
}

fn disposition_name(disposition: CreditDisposition) -> String {
    String::from(match disposition {
        CreditDisposition::Held => "Held",
        CreditDisposition::Committed => "Committed",
        CreditDisposition::Returned => "Returned",
        CreditDisposition::Retained => "Retained",
    })
}
