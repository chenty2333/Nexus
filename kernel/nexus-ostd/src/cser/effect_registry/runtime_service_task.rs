// SPDX-License-Identifier: MPL-2.0

//! Core facade for service tasks which carry a fault composite.
//!
//! The generic task facade deliberately rejects service roles.  This module
//! owns the only three linear transitions for those roles: admission,
//! reservation and arming.  A domain workload session is moved into every
//! bearer, so a caller cannot accidentally close the child while its task or
//! fault authority is still live.

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::runtime_causal::{
    CausalDomainWorkloadIdentity, CausalDomainWorkloadProvenance, CausalDomainWorkloadSession,
    CausalWorkloadError,
};
use super::runtime_task::CausalVmIdentity;
use super::{DomainKey, EffectRegistry, RegistryError, TaskKey, infrastructure};

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum CausalServiceTaskRole {
    ActiveService,
    ReplacementRecovery,
}

impl CausalServiceTaskRole {
    const fn infrastructure(self) -> infrastructure::TaskWorkRole {
        match self {
            Self::ActiveService => infrastructure::TaskWorkRole::ServiceRequest,
            Self::ReplacementRecovery => infrastructure::TaskWorkRole::ReplacementRecovery,
        }
    }
}

/// Caller-supplied portable coordinates.  The task, service domain and
/// binding epoch are intentionally absent: admission derives them from the
/// live domain supervisor and the moved session.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CausalServiceTaskDescriptor {
    work_id: u64,
    generation: u64,
    role: CausalServiceTaskRole,
    vm: CausalVmIdentity,
    fault_id: u64,
    fault_generation: u64,
}

impl CausalServiceTaskDescriptor {
    pub(crate) const fn new(
        work_id: u64,
        generation: u64,
        role: CausalServiceTaskRole,
        vm: CausalVmIdentity,
        fault_id: u64,
        fault_generation: u64,
    ) -> Result<Self, CausalServiceTaskError> {
        if work_id == 0 || generation == 0 || fault_id == 0 || fault_generation == 0 {
            return Err(CausalServiceTaskError::InvalidDescriptor);
        }
        Ok(Self {
            work_id,
            generation,
            role,
            vm,
            fault_id,
            fault_generation,
        })
    }

    pub(crate) const fn role(self) -> CausalServiceTaskRole {
        self.role
    }

    pub(crate) const fn vm(self) -> CausalVmIdentity {
        self.vm
    }
}

/// Copyable selector for one exact task/fault pair.  It is descriptive only;
/// all transitions still require the corresponding non-Copy bearer.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CausalServiceTaskSelector {
    work_id: u64,
    generation: u64,
    task: TaskKey,
    fault_id: u64,
    fault_generation: u64,
    vm_generation: u64,
    service_domain: DomainKey,
    binding_epoch: u64,
}

impl CausalServiceTaskSelector {
    pub(crate) const fn task(self) -> TaskKey {
        self.task
    }

    pub(crate) const fn fault_id(self) -> u64 {
        self.fault_id
    }

    pub(crate) const fn fault_generation(self) -> u64 {
        self.fault_generation
    }

    pub(crate) const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum CausalServiceTaskError {
    InvalidDescriptor,
    RecoveryUnavailable,
    ProvenanceMismatch,
    ForeignBearerRegistry,
    ForeignSession,
    SelectorMismatch,
    InvalidBearerState,
    InvalidState,
    ObservationMismatch,
    Workload(CausalWorkloadError),
    Registry(RegistryError),
    Infrastructure(infrastructure::InfrastructureError),
}

/// A consuming transition failure always owns the exact input bearer.  The
/// generic parameter is intentionally unconstrained and non-Copy bearers are
/// used for all three service-task stages.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalServiceTaskFailure<T> {
    error: CausalServiceTaskError,
    task: T,
}

impl<T> CausalServiceTaskFailure<T> {
    pub(crate) const fn error(&self) -> &CausalServiceTaskError {
        &self.error
    }

    pub(crate) fn into_task(self) -> T {
        self.task
    }
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalServiceTaskAdmissionFailure {
    error: CausalServiceTaskError,
    session: CausalDomainWorkloadSession,
}

impl CausalServiceTaskAdmissionFailure {
    pub(crate) const fn error(&self) -> &CausalServiceTaskError {
        &self.error
    }

    pub(crate) fn into_session(self) -> CausalDomainWorkloadSession {
        self.session
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum CausalServiceTaskCancellationKind {
    UnpublishedTask,
    ReservedComposite,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CausalServiceTaskCancellationReceipt {
    selector: CausalServiceTaskSelector,
    kind: CausalServiceTaskCancellationKind,
    infrastructure: Option<infrastructure::ServiceTaskCancellationReceipt>,
}

impl CausalServiceTaskCancellationReceipt {
    pub(crate) const fn selector(self) -> CausalServiceTaskSelector {
        self.selector
    }

    pub(crate) const fn kind(self) -> CausalServiceTaskCancellationKind {
        self.kind
    }

    pub(crate) const fn infrastructure(
        self,
    ) -> Option<infrastructure::ServiceTaskCancellationReceipt> {
        self.infrastructure
    }
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalCancelledServiceTask {
    session: CausalDomainWorkloadSession,
    identity: CausalDomainWorkloadIdentity,
    receipt: CausalServiceTaskCancellationReceipt,
}

impl CausalCancelledServiceTask {
    pub(crate) const fn receipt(&self) -> CausalServiceTaskCancellationReceipt {
        self.receipt
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn close(
        self,
        registry: &mut EffectRegistry,
    ) -> Result<CausalDomainWorkloadIdentity, CausalServiceTaskCloseFailure<Self>> {
        let CausalCancelledServiceTask {
            session,
            identity,
            receipt,
        } = self;
        match registry.close_causal_domain_workload(session) {
            Ok(identity) => Ok(identity),
            Err(failure) => Err(CausalServiceTaskCloseFailure {
                error: CausalServiceTaskError::Workload(failure.error().clone()),
                task: CausalCancelledServiceTask {
                    session: failure.into_session(),
                    identity,
                    receipt,
                },
            }),
        }
    }
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalAdmittedServiceTask {
    session: CausalDomainWorkloadSession,
    identity: CausalDomainWorkloadIdentity,
    descriptor: CausalServiceTaskDescriptor,
    selector: CausalServiceTaskSelector,
    authority: infrastructure::TaskLease,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalReservedServiceTask {
    session: CausalDomainWorkloadSession,
    identity: CausalDomainWorkloadIdentity,
    descriptor: CausalServiceTaskDescriptor,
    selector: CausalServiceTaskSelector,
    authority: infrastructure::ReservedFaultTask,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalArmedServiceTask {
    session: CausalDomainWorkloadSession,
    identity: CausalDomainWorkloadIdentity,
    descriptor: CausalServiceTaskDescriptor,
    selector: CausalServiceTaskSelector,
    authority: infrastructure::ArmedFaultTask,
}

impl CausalAdmittedServiceTask {
    pub(crate) const fn selector(&self) -> CausalServiceTaskSelector {
        self.selector
    }
}

impl CausalReservedServiceTask {
    pub(crate) const fn selector(&self) -> CausalServiceTaskSelector {
        self.selector
    }
}

impl CausalArmedServiceTask {
    pub(crate) const fn selector(&self) -> CausalServiceTaskSelector {
        self.selector
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CausalServiceTaskExitReceipt {
    selector: CausalServiceTaskSelector,
    receipt: infrastructure::ServiceTaskExitReceipt,
}

impl CausalServiceTaskExitReceipt {
    pub(crate) const fn selector(self) -> CausalServiceTaskSelector {
        self.selector
    }
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalCompletedServiceTask {
    session: CausalDomainWorkloadSession,
    identity: CausalDomainWorkloadIdentity,
    receipt: CausalServiceTaskExitReceipt,
}

impl CausalCompletedServiceTask {
    pub(crate) const fn receipt(&self) -> CausalServiceTaskExitReceipt {
        self.receipt
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn close(
        self,
        registry: &mut EffectRegistry,
    ) -> Result<CausalDomainWorkloadIdentity, CausalServiceTaskCloseFailure<Self>> {
        let CausalCompletedServiceTask {
            session,
            identity,
            receipt,
        } = self;
        match registry.close_causal_domain_workload(session) {
            Ok(identity) => Ok(identity),
            Err(failure) => Err(CausalServiceTaskCloseFailure {
                error: CausalServiceTaskError::Workload(failure.error().clone()),
                task: Self {
                    session: failure.into_session(),
                    identity,
                    receipt,
                },
            }),
        }
    }
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalServiceTaskCloseFailure<T> {
    error: CausalServiceTaskError,
    task: T,
}

impl<T> CausalServiceTaskCloseFailure<T> {
    pub(crate) const fn error(&self) -> &CausalServiceTaskError {
        &self.error
    }

    pub(crate) fn into_task(self) -> T {
        self.task
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum CausalServiceCrashStage {
    Installed,
    Claimed,
    Consumed,
    AlreadyClaimed,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
enum CausalCrashClaim {
    Installed {
        error: CausalServiceTaskError,
    },
    Claimed {
        receipt: infrastructure::CrashServiceReceipt,
        error: CausalServiceTaskError,
    },
    Consumed {
        cause: infrastructure::ServiceCrashCause,
    },
    AlreadyClaimed {
        error: CausalServiceTaskError,
    },
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalServiceCrashCommit {
    session: CausalDomainWorkloadSession,
    identity: CausalDomainWorkloadIdentity,
    selector: CausalServiceTaskSelector,
    installed: infrastructure::InstalledFaultObservation,
    claim: CausalCrashClaim,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalServiceIsolateCommit {
    session: CausalDomainWorkloadSession,
    identity: CausalDomainWorkloadIdentity,
    selector: CausalServiceTaskSelector,
    installed: infrastructure::InstalledFaultObservation,
    claim: CausalIsolateClaim,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
enum CausalIsolateClaim {
    Installed {
        error: CausalServiceTaskError,
    },
    Claimed {
        receipt: infrastructure::IsolateTaskReceipt,
        error: CausalServiceTaskError,
    },
    Drained {
        receipt: infrastructure::IsolateTaskDrainReceipt,
    },
    AlreadyClaimed {
        error: CausalServiceTaskError,
    },
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum CausalServiceIsolateStage {
    Installed,
    Claimed,
    Drained,
    AlreadyClaimed,
}

impl CausalServiceCrashCommit {
    pub(crate) const fn stage(&self) -> CausalServiceCrashStage {
        match self.claim {
            CausalCrashClaim::Installed { .. } => CausalServiceCrashStage::Installed,
            CausalCrashClaim::Claimed { .. } => CausalServiceCrashStage::Claimed,
            CausalCrashClaim::Consumed { .. } => CausalServiceCrashStage::Consumed,
            CausalCrashClaim::AlreadyClaimed { .. } => CausalServiceCrashStage::AlreadyClaimed,
        }
    }

    /// Retries only the post-install claim/consume suffix.  Any failure stays
    /// in this retained owner; it is never converted back into an Armed task.
    pub(crate) fn retry(mut self, registry: &mut EffectRegistry) -> Self {
        let claim = match self.claim {
            CausalCrashClaim::Installed { .. } => {
                let queried = registry.infrastructure.query_fault(
                    &self.session.context,
                    self.selector.fault_id,
                    self.selector.fault_generation,
                );
                let installed = match queried {
                    Ok(projection) => match projection.selector {
                        Some(infrastructure::InstalledFaultObservation::Crash(installed)) => {
                            infrastructure::InstalledFaultObservation::Crash(installed)
                        }
                        _ => {
                            self.claim = CausalCrashClaim::Installed {
                                error: CausalServiceTaskError::Infrastructure(
                                    infrastructure::InfrastructureError::InvalidReceipt,
                                ),
                            };
                            return self;
                        }
                    },
                    Err(error) => {
                        self.claim = CausalCrashClaim::Installed {
                            error: CausalServiceTaskError::Infrastructure(error),
                        };
                        return self;
                    }
                };
                match registry
                    .infrastructure
                    .claim_fault_receipt(&self.session.context, installed)
                {
                    Ok(infrastructure::FaultReceiptClaimOutcome::Crash(receipt)) => {
                        consume_crash_receipt(registry, receipt)
                    }
                    Ok(infrastructure::FaultReceiptClaimOutcome::AlreadyClaimed(_)) => {
                        CausalCrashClaim::AlreadyClaimed {
                            error: CausalServiceTaskError::InvalidState,
                        }
                    }
                    Ok(infrastructure::FaultReceiptClaimOutcome::Isolate(_)) => {
                        CausalCrashClaim::AlreadyClaimed {
                            error: CausalServiceTaskError::Infrastructure(
                                infrastructure::InfrastructureError::InvalidReceipt,
                            ),
                        }
                    }
                    Err(error) => CausalCrashClaim::Installed {
                        error: CausalServiceTaskError::Infrastructure(error),
                    },
                }
            }
            CausalCrashClaim::Claimed { receipt, .. } => consume_crash_receipt(registry, receipt),
            claim => claim,
        };
        self.claim = claim;
        self
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn close(
        self,
        registry: &mut EffectRegistry,
    ) -> Result<CausalDomainWorkloadIdentity, CausalServiceTaskCloseFailure<Self>> {
        if self.stage() != CausalServiceCrashStage::Consumed {
            return Err(CausalServiceTaskCloseFailure {
                error: CausalServiceTaskError::InvalidBearerState,
                task: self,
            });
        }
        let CausalServiceCrashCommit {
            session,
            identity,
            selector,
            installed,
            claim,
        } = self;
        match registry.close_causal_domain_workload(session) {
            Ok(identity) => Ok(identity),
            Err(failure) => Err(CausalServiceTaskCloseFailure {
                error: CausalServiceTaskError::Workload(failure.error().clone()),
                task: CausalServiceCrashCommit {
                    session: failure.into_session(),
                    identity,
                    selector,
                    installed,
                    claim,
                },
            }),
        }
    }
}

impl CausalServiceIsolateCommit {
    pub(crate) const fn stage(&self) -> CausalServiceIsolateStage {
        match self.claim {
            CausalIsolateClaim::Installed { .. } => CausalServiceIsolateStage::Installed,
            CausalIsolateClaim::Claimed { .. } => CausalServiceIsolateStage::Claimed,
            CausalIsolateClaim::Drained { .. } => CausalServiceIsolateStage::Drained,
            CausalIsolateClaim::AlreadyClaimed { .. } => CausalServiceIsolateStage::AlreadyClaimed,
        }
    }

    pub(crate) fn retry(mut self, registry: &mut EffectRegistry) -> Self {
        let claim = match self.claim {
            CausalIsolateClaim::Installed { .. } => {
                let queried = registry.infrastructure.query_fault(
                    &self.session.context,
                    self.selector.fault_id,
                    self.selector.fault_generation,
                );
                let installed = match queried {
                    Ok(projection) => match projection.selector {
                        Some(infrastructure::InstalledFaultObservation::Isolate(installed)) => {
                            infrastructure::InstalledFaultObservation::Isolate(installed)
                        }
                        _ => {
                            self.claim = CausalIsolateClaim::Installed {
                                error: CausalServiceTaskError::Infrastructure(
                                    infrastructure::InfrastructureError::InvalidReceipt,
                                ),
                            };
                            return self;
                        }
                    },
                    Err(error) => {
                        self.claim = CausalIsolateClaim::Installed {
                            error: CausalServiceTaskError::Infrastructure(error),
                        };
                        return self;
                    }
                };
                claim_and_drain_isolate(registry, &self.session, installed)
            }
            CausalIsolateClaim::Claimed { receipt, .. } => {
                match registry.infrastructure.drain_isolate_task(receipt) {
                    Ok(receipt) => CausalIsolateClaim::Drained { receipt },
                    Err(failure) => {
                        let (error, receipt) = failure.into_parts();
                        CausalIsolateClaim::Claimed {
                            receipt,
                            error: CausalServiceTaskError::Infrastructure(error),
                        }
                    }
                }
            }
            claim => claim,
        };
        self.claim = claim;
        self
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn close(
        self,
        registry: &mut EffectRegistry,
    ) -> Result<CausalDomainWorkloadIdentity, CausalServiceTaskCloseFailure<Self>> {
        if self.stage() != CausalServiceIsolateStage::Drained {
            return Err(CausalServiceTaskCloseFailure {
                error: CausalServiceTaskError::InvalidBearerState,
                task: self,
            });
        }
        let CausalServiceIsolateCommit {
            session,
            identity,
            selector,
            installed,
            claim,
        } = self;
        match registry.close_causal_domain_workload(session) {
            Ok(identity) => Ok(identity),
            Err(failure) => Err(CausalServiceTaskCloseFailure {
                error: CausalServiceTaskError::Workload(failure.error().clone()),
                task: CausalServiceIsolateCommit {
                    session: failure.into_session(),
                    identity,
                    selector,
                    installed,
                    claim,
                },
            }),
        }
    }
}

fn consume_crash_receipt(
    registry: &mut EffectRegistry,
    receipt: infrastructure::CrashServiceReceipt,
) -> CausalCrashClaim {
    match registry.infrastructure.consume_service_fault(receipt) {
        Ok(cause) => CausalCrashClaim::Consumed { cause },
        Err(failure) => {
            let (error, receipt) = failure.into_parts();
            CausalCrashClaim::Claimed {
                receipt,
                error: CausalServiceTaskError::Infrastructure(error),
            }
        }
    }
}

fn claim_and_drain_isolate(
    registry: &mut EffectRegistry,
    session: &CausalDomainWorkloadSession,
    installed: infrastructure::InstalledFaultObservation,
) -> CausalIsolateClaim {
    match registry
        .infrastructure
        .claim_fault_receipt(&session.context, installed)
    {
        Ok(infrastructure::FaultReceiptClaimOutcome::Isolate(receipt)) => {
            match registry.infrastructure.drain_isolate_task(receipt) {
                Ok(receipt) => CausalIsolateClaim::Drained { receipt },
                Err(failure) => {
                    let (error, receipt) = failure.into_parts();
                    CausalIsolateClaim::Claimed {
                        receipt,
                        error: CausalServiceTaskError::Infrastructure(error),
                    }
                }
            }
        }
        Ok(infrastructure::FaultReceiptClaimOutcome::AlreadyClaimed(_)) => {
            CausalIsolateClaim::AlreadyClaimed {
                error: CausalServiceTaskError::InvalidState,
            }
        }
        Ok(infrastructure::FaultReceiptClaimOutcome::Crash(_)) => {
            CausalIsolateClaim::AlreadyClaimed {
                error: CausalServiceTaskError::Infrastructure(
                    infrastructure::InfrastructureError::InvalidReceipt,
                ),
            }
        }
        Err(error) => CausalIsolateClaim::Installed {
            error: CausalServiceTaskError::Infrastructure(error),
        },
    }
}

fn claim_crash(
    registry: &mut EffectRegistry,
    session: &CausalDomainWorkloadSession,
    installed: infrastructure::InstalledFaultObservation,
) -> CausalCrashClaim {
    match registry
        .infrastructure
        .claim_fault_receipt(&session.context, installed)
    {
        Ok(infrastructure::FaultReceiptClaimOutcome::Crash(receipt)) => {
            consume_crash_receipt(registry, receipt)
        }
        Ok(infrastructure::FaultReceiptClaimOutcome::AlreadyClaimed(_)) => {
            CausalCrashClaim::AlreadyClaimed {
                error: CausalServiceTaskError::InvalidState,
            }
        }
        Ok(infrastructure::FaultReceiptClaimOutcome::Isolate(_)) => {
            CausalCrashClaim::AlreadyClaimed {
                error: CausalServiceTaskError::Infrastructure(
                    infrastructure::InfrastructureError::InvalidReceipt,
                ),
            }
        }
        Err(error) => CausalCrashClaim::Installed {
            error: CausalServiceTaskError::Infrastructure(error),
        },
    }
}

impl EffectRegistry {
    /// Derives the service task key exclusively from the moved workload's
    /// Registry-minted provenance. Active and recovery roles cannot be
    /// substituted for one another by a portable descriptor.
    #[allow(clippy::result_large_err)]
    pub(crate) fn admit_causal_service_task(
        &mut self,
        session: CausalDomainWorkloadSession,
        descriptor: CausalServiceTaskDescriptor,
    ) -> Result<CausalAdmittedServiceTask, CausalServiceTaskAdmissionFailure> {
        if let Err(error) = validate_descriptor(descriptor) {
            return Err(CausalServiceTaskAdmissionFailure { error, session });
        }
        let identity = match self.verify_causal_domain_workload_session(&session) {
            Ok(identity) => identity,
            Err(error) => {
                return Err(CausalServiceTaskAdmissionFailure {
                    error: CausalServiceTaskError::Workload(error),
                    session,
                });
            }
        };
        let (binding, root_revision) = match self.scopes.get(&identity.parent.scope) {
            Some(scope) => match scope.domains.get(&identity.domain) {
                Some(binding) => (binding, scope.revision),
                None => {
                    return Err(CausalServiceTaskAdmissionFailure {
                        error: CausalServiceTaskError::Workload(CausalWorkloadError::Registry(
                            RegistryError::UnknownDomain,
                        )),
                        session,
                    });
                }
            },
            None => {
                return Err(CausalServiceTaskAdmissionFailure {
                    error: CausalServiceTaskError::Workload(CausalWorkloadError::Registry(
                        RegistryError::UnknownScope,
                    )),
                    session,
                });
            }
        };
        let task = match (descriptor.role, session.provenance()) {
            (
                CausalServiceTaskRole::ActiveService,
                CausalDomainWorkloadProvenance::ActiveSupervisor { supervisor },
            ) if binding.supervisor == Some(supervisor)
                && !binding.fallback_running
                && binding.quarantine.is_none() =>
            {
                supervisor
            }
            (
                CausalServiceTaskRole::ReplacementRecovery,
                CausalDomainWorkloadProvenance::RecoveryReplacement {
                    replacement,
                    attempt,
                    snapshot_digest,
                },
            ) if binding.quarantine.is_none()
                && binding.fallback_running
                && binding.supervisor.is_none()
                && binding.recovery.as_ref().is_some_and(|recovery| {
                    recovery.ready.is_none()
                        && recovery.highest_attempt == attempt
                        && recovery.snapshot.as_ref().is_some_and(|snapshot| {
                            snapshot.replacement == replacement
                                && snapshot.attempt == attempt
                                && snapshot.digest() == snapshot_digest
                                && snapshot.root_revision == root_revision
                                && snapshot.domain_revision == binding.revision
                        })
                }) =>
            {
                replacement
            }
            (
                CausalServiceTaskRole::ReplacementRecovery,
                CausalDomainWorkloadProvenance::ActiveSupervisor { .. },
            ) => {
                return Err(CausalServiceTaskAdmissionFailure {
                    error: CausalServiceTaskError::RecoveryUnavailable,
                    session,
                });
            }
            (
                CausalServiceTaskRole::ActiveService,
                CausalDomainWorkloadProvenance::RecoveryReplacement { .. },
            ) => {
                return Err(CausalServiceTaskAdmissionFailure {
                    error: CausalServiceTaskError::ProvenanceMismatch,
                    session,
                });
            }
            (CausalServiceTaskRole::ActiveService, _)
            | (CausalServiceTaskRole::ReplacementRecovery, _) => {
                return Err(CausalServiceTaskAdmissionFailure {
                    error: CausalServiceTaskError::Registry(RegistryError::NoSupervisor),
                    session,
                });
            }
        };
        let vm = match infrastructure::VmAuthorityKey::new(
            descriptor.vm.id(),
            descriptor.vm.generation(),
        ) {
            Ok(vm) => vm,
            Err(error) => {
                return Err(CausalServiceTaskAdmissionFailure {
                    error: CausalServiceTaskError::Infrastructure(error),
                    session,
                });
            }
        };
        let task_descriptor = infrastructure::TaskWorkDescriptor {
            work_id: descriptor.work_id,
            generation: descriptor.generation,
            task,
            role: descriptor.role.infrastructure(),
            vm: Some(vm),
        };
        let authority = match self
            .infrastructure
            .admit_task(&session.context, task_descriptor)
        {
            Ok(authority) => authority,
            Err(error) => {
                return Err(CausalServiceTaskAdmissionFailure {
                    error: CausalServiceTaskError::Infrastructure(error),
                    session,
                });
            }
        };
        let selector = CausalServiceTaskSelector {
            work_id: descriptor.work_id,
            generation: descriptor.generation,
            task,
            fault_id: descriptor.fault_id,
            fault_generation: descriptor.fault_generation,
            vm_generation: descriptor.vm.generation(),
            service_domain: identity.domain,
            binding_epoch: identity.binding_epoch,
        };
        Ok(CausalAdmittedServiceTask {
            session,
            identity,
            descriptor,
            selector,
            authority,
        })
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn reserve_causal_service_fault(
        &mut self,
        selector: CausalServiceTaskSelector,
        task: CausalAdmittedServiceTask,
    ) -> Result<CausalReservedServiceTask, CausalServiceTaskFailure<CausalAdmittedServiceTask>>
    {
        if let Err(error) = self.validate_admitted_service_task(&task, selector) {
            return Err(CausalServiceTaskFailure { error, task });
        }
        let CausalAdmittedServiceTask {
            session,
            identity,
            descriptor,
            selector,
            authority,
        } = task;
        let fault_descriptor = infrastructure::FaultSlotDescriptor {
            fault_id: selector.fault_id,
            generation: selector.fault_generation,
            task: selector.task,
            vm_generation: selector.vm_generation,
            service_domain: selector.service_domain,
            admission_binding_epoch: selector.binding_epoch,
        };
        match self
            .infrastructure
            .reserve_fault_event(authority, fault_descriptor)
        {
            Ok(authority) => Ok(CausalReservedServiceTask {
                session,
                identity,
                descriptor,
                selector,
                authority,
            }),
            Err(failure) => {
                let (error, authority) = failure.into_parts();
                Err(CausalServiceTaskFailure {
                    error: CausalServiceTaskError::Infrastructure(error),
                    task: CausalAdmittedServiceTask {
                        session,
                        identity,
                        descriptor,
                        selector,
                        authority,
                    },
                })
            }
        }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn arm_causal_service_task(
        &mut self,
        selector: CausalServiceTaskSelector,
        task: CausalReservedServiceTask,
    ) -> Result<CausalArmedServiceTask, CausalServiceTaskFailure<CausalReservedServiceTask>> {
        if let Err(error) = self.validate_reserved_service_task(&task, selector) {
            return Err(CausalServiceTaskFailure { error, task });
        }
        let CausalReservedServiceTask {
            session,
            identity,
            descriptor,
            selector,
            authority,
        } = task;
        match self.infrastructure.claim_service_task_entry(authority) {
            Ok(authority) => Ok(CausalArmedServiceTask {
                session,
                identity,
                descriptor,
                selector,
                authority,
            }),
            Err(failure) => {
                let (error, authority) = failure.into_parts();
                Err(CausalServiceTaskFailure {
                    error: CausalServiceTaskError::Infrastructure(error),
                    task: CausalReservedServiceTask {
                        session,
                        identity,
                        descriptor,
                        selector,
                        authority,
                    },
                })
            }
        }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn cancel_causal_admitted_service_task(
        &mut self,
        selector: CausalServiceTaskSelector,
        task: CausalAdmittedServiceTask,
    ) -> Result<CausalCancelledServiceTask, CausalServiceTaskFailure<CausalAdmittedServiceTask>>
    {
        if let Err(error) = self.validate_admitted_service_task(&task, selector) {
            return Err(CausalServiceTaskFailure { error, task });
        }
        let CausalAdmittedServiceTask {
            session,
            identity,
            descriptor,
            selector,
            authority,
        } = task;
        match self.infrastructure.reject_task_construction(authority) {
            Ok(()) => Ok(CausalCancelledServiceTask {
                session,
                identity,
                receipt: CausalServiceTaskCancellationReceipt {
                    selector,
                    kind: CausalServiceTaskCancellationKind::UnpublishedTask,
                    infrastructure: None,
                },
            }),
            Err(failure) => {
                let (error, authority) = failure.into_parts();
                Err(CausalServiceTaskFailure {
                    error: CausalServiceTaskError::Infrastructure(error),
                    task: CausalAdmittedServiceTask {
                        session,
                        identity,
                        descriptor,
                        selector,
                        authority,
                    },
                })
            }
        }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn cancel_causal_reserved_service_task(
        &mut self,
        selector: CausalServiceTaskSelector,
        task: CausalReservedServiceTask,
    ) -> Result<CausalCancelledServiceTask, CausalServiceTaskFailure<CausalReservedServiceTask>>
    {
        if let Err(error) = self.validate_reserved_service_task(&task, selector) {
            return Err(CausalServiceTaskFailure { error, task });
        }
        let CausalReservedServiceTask {
            session,
            identity,
            descriptor,
            selector,
            authority,
        } = task;
        match self.infrastructure.cancel_reserved_service_task(authority) {
            Ok(receipt) => Ok(CausalCancelledServiceTask {
                session,
                identity,
                receipt: CausalServiceTaskCancellationReceipt {
                    selector,
                    kind: CausalServiceTaskCancellationKind::ReservedComposite,
                    infrastructure: Some(receipt),
                },
            }),
            Err(failure) => {
                let (error, authority) = failure.into_parts();
                Err(CausalServiceTaskFailure {
                    error: CausalServiceTaskError::Infrastructure(error),
                    task: CausalReservedServiceTask {
                        session,
                        identity,
                        descriptor,
                        selector,
                        authority,
                    },
                })
            }
        }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn finish_causal_service_task_without_fault(
        &mut self,
        selector: CausalServiceTaskSelector,
        task: CausalArmedServiceTask,
        evidence_digest: u64,
    ) -> Result<CausalCompletedServiceTask, CausalServiceTaskFailure<CausalArmedServiceTask>> {
        if let Err(error) = self.validate_armed_service_task(&task, selector) {
            return Err(CausalServiceTaskFailure { error, task });
        }
        let CausalArmedServiceTask {
            session,
            identity,
            descriptor,
            selector,
            authority,
        } = task;
        match self
            .infrastructure
            .finish_service_task_without_fault(authority, evidence_digest)
        {
            Ok(receipt) => Ok(CausalCompletedServiceTask {
                session,
                identity,
                receipt: CausalServiceTaskExitReceipt { selector, receipt },
            }),
            Err(failure) => {
                let (error, authority) = failure.into_parts();
                Err(CausalServiceTaskFailure {
                    error: CausalServiceTaskError::Infrastructure(error),
                    task: CausalArmedServiceTask {
                        session,
                        identity,
                        descriptor,
                        selector,
                        authority,
                    },
                })
            }
        }
    }

    /// Performs the combined CrashService install.  Once install succeeds,
    /// every later failure is represented by a retained commit owner.
    #[allow(clippy::result_large_err)]
    pub(crate) fn crash_causal_service_task(
        &mut self,
        selector: CausalServiceTaskSelector,
        task: CausalArmedServiceTask,
        observation: infrastructure::FaultObservation,
    ) -> Result<CausalServiceCrashCommit, CausalServiceTaskFailure<CausalArmedServiceTask>> {
        if let Err(error) = self.validate_armed_service_task(&task, selector) {
            return Err(CausalServiceTaskFailure { error, task });
        }
        if let Err(error) = validate_observation(selector, observation) {
            return Err(CausalServiceTaskFailure { error, task });
        }
        let CausalArmedServiceTask {
            session,
            identity,
            descriptor,
            selector,
            authority,
        } = task;
        let (intent, plan) = match self.prepare_service_fault_disposition(
            authority,
            observation,
            infrastructure::FaultDisposition::CrashService,
        ) {
            Ok(plan) => plan,
            Err(failure) => {
                return Err(CausalServiceTaskFailure {
                    error: CausalServiceTaskError::Registry(failure.error().clone()),
                    task: CausalArmedServiceTask {
                        session,
                        identity,
                        descriptor,
                        selector,
                        authority: failure.into_input(),
                    },
                });
            }
        };
        let installed = match self.install_service_fault_disposition(intent, plan) {
            Ok(installed) => installed,
            Err(failure) => {
                return Err(CausalServiceTaskFailure {
                    error: CausalServiceTaskError::Registry(failure.error().clone()),
                    task: CausalArmedServiceTask {
                        session,
                        identity,
                        descriptor,
                        selector,
                        authority: failure.into_input(),
                    },
                });
            }
        };
        let claim = claim_crash(self, &session, installed);
        Ok(CausalServiceCrashCommit {
            session,
            identity,
            selector,
            installed,
            claim,
        })
    }

    /// Performs the combined IsolateTask install and immediately claims and
    /// drains its receipt when possible.  A post-install failure remains in a
    /// retained isolate owner and can be retried with `retry`.
    #[allow(clippy::result_large_err)]
    pub(crate) fn isolate_causal_service_task(
        &mut self,
        selector: CausalServiceTaskSelector,
        task: CausalArmedServiceTask,
        observation: infrastructure::FaultObservation,
    ) -> Result<CausalServiceIsolateCommit, CausalServiceTaskFailure<CausalArmedServiceTask>> {
        if let Err(error) = self.validate_armed_service_task(&task, selector) {
            return Err(CausalServiceTaskFailure { error, task });
        }
        if let Err(error) = validate_observation(selector, observation) {
            return Err(CausalServiceTaskFailure { error, task });
        }
        let CausalArmedServiceTask {
            session,
            identity,
            descriptor,
            selector,
            authority,
        } = task;
        let (intent, plan) = match self.prepare_service_fault_disposition(
            authority,
            observation,
            infrastructure::FaultDisposition::IsolateTask,
        ) {
            Ok(plan) => plan,
            Err(failure) => {
                return Err(CausalServiceTaskFailure {
                    error: CausalServiceTaskError::Registry(failure.error().clone()),
                    task: CausalArmedServiceTask {
                        session,
                        identity,
                        descriptor,
                        selector,
                        authority: failure.into_input(),
                    },
                });
            }
        };
        let installed = match self.install_service_fault_disposition(intent, plan) {
            Ok(installed) => installed,
            Err(failure) => {
                return Err(CausalServiceTaskFailure {
                    error: CausalServiceTaskError::Registry(failure.error().clone()),
                    task: CausalArmedServiceTask {
                        session,
                        identity,
                        descriptor,
                        selector,
                        authority: failure.into_input(),
                    },
                });
            }
        };
        let claim = claim_and_drain_isolate(self, &session, installed);
        Ok(CausalServiceIsolateCommit {
            session,
            identity,
            selector,
            installed,
            claim,
        })
    }

    fn validate_admitted_service_task(
        &self,
        task: &CausalAdmittedServiceTask,
        selector: CausalServiceTaskSelector,
    ) -> Result<(), CausalServiceTaskError> {
        self.validate_service_task_identity(
            task.identity,
            &task.session,
            task.descriptor,
            selector,
        )?;
        if selector != task.selector {
            return Err(CausalServiceTaskError::SelectorMismatch);
        }
        let projection = self
            .infrastructure
            .query_task(&task.session.context, selector.work_id, selector.generation)
            .map_err(CausalServiceTaskError::Infrastructure)?;
        if projection.descriptor.task != selector.task
            || projection.descriptor.role != task.descriptor.role.infrastructure()
            || projection.descriptor.vm.map(|vm| vm.generation()) != Some(selector.vm_generation)
            || projection.state != infrastructure::TaskRecoveryState::Admitted
        {
            return Err(CausalServiceTaskError::InvalidBearerState);
        }
        Ok(())
    }

    fn validate_reserved_service_task(
        &self,
        task: &CausalReservedServiceTask,
        selector: CausalServiceTaskSelector,
    ) -> Result<(), CausalServiceTaskError> {
        self.validate_service_task_identity(
            task.identity,
            &task.session,
            task.descriptor,
            selector,
        )?;
        if selector != task.selector {
            return Err(CausalServiceTaskError::SelectorMismatch);
        }
        let projection = self
            .infrastructure
            .query_task(&task.session.context, selector.work_id, selector.generation)
            .map_err(CausalServiceTaskError::Infrastructure)?;
        if projection.descriptor.task != selector.task
            || projection.descriptor.role != task.descriptor.role.infrastructure()
            || projection.state != infrastructure::TaskRecoveryState::Admitted
            || projection.live_children != 1
        {
            return Err(CausalServiceTaskError::InvalidBearerState);
        }
        Ok(())
    }

    fn validate_armed_service_task(
        &self,
        task: &CausalArmedServiceTask,
        selector: CausalServiceTaskSelector,
    ) -> Result<(), CausalServiceTaskError> {
        self.validate_service_task_identity(
            task.identity,
            &task.session,
            task.descriptor,
            selector,
        )?;
        if selector != task.selector {
            return Err(CausalServiceTaskError::SelectorMismatch);
        }
        let projection = self
            .infrastructure
            .query_task(&task.session.context, selector.work_id, selector.generation)
            .map_err(CausalServiceTaskError::Infrastructure)?;
        if projection.descriptor.task != selector.task
            || projection.descriptor.role != task.descriptor.role.infrastructure()
            || projection.state != infrastructure::TaskRecoveryState::Entered
            || projection.live_children != 1
        {
            return Err(CausalServiceTaskError::InvalidBearerState);
        }
        Ok(())
    }

    fn validate_service_task_identity(
        &self,
        identity: CausalDomainWorkloadIdentity,
        session: &CausalDomainWorkloadSession,
        descriptor: CausalServiceTaskDescriptor,
        selector: CausalServiceTaskSelector,
    ) -> Result<(), CausalServiceTaskError> {
        if identity.parent.registry_instance != self.instance_id {
            return Err(CausalServiceTaskError::ForeignBearerRegistry);
        }
        if session.identity != identity {
            return Err(CausalServiceTaskError::ForeignSession);
        }
        if selector.service_domain != identity.domain
            || selector.binding_epoch != identity.binding_epoch
        {
            return Err(CausalServiceTaskError::SelectorMismatch);
        }
        let expected_task = match (descriptor.role, session.provenance()) {
            (
                CausalServiceTaskRole::ActiveService,
                CausalDomainWorkloadProvenance::ActiveSupervisor { supervisor },
            ) => supervisor,
            (
                CausalServiceTaskRole::ReplacementRecovery,
                CausalDomainWorkloadProvenance::RecoveryReplacement { replacement, .. },
            ) => replacement,
            (CausalServiceTaskRole::ReplacementRecovery, _)
            | (CausalServiceTaskRole::ActiveService, _) => {
                return Err(CausalServiceTaskError::ProvenanceMismatch);
            }
        };
        if selector.task != expected_task {
            return Err(CausalServiceTaskError::SelectorMismatch);
        }
        self.verify_causal_domain_workload_session(session)
            .map_err(CausalServiceTaskError::Workload)?;
        Ok(())
    }
}

fn validate_descriptor(
    descriptor: CausalServiceTaskDescriptor,
) -> Result<(), CausalServiceTaskError> {
    if descriptor.work_id == 0
        || descriptor.generation == 0
        || descriptor.fault_id == 0
        || descriptor.fault_generation == 0
        || descriptor.vm.id() == 0
        || descriptor.vm.generation() == 0
    {
        Err(CausalServiceTaskError::InvalidDescriptor)
    } else {
        Ok(())
    }
}

fn validate_observation(
    selector: CausalServiceTaskSelector,
    observation: infrastructure::FaultObservation,
) -> Result<(), CausalServiceTaskError> {
    if observation.task != selector.task
        || observation.vm_generation != selector.vm_generation
        || observation.instruction_pointer == 0
        || observation.evidence_digest == 0
    {
        Err(CausalServiceTaskError::ObservationMismatch)
    } else {
        Ok(())
    }
}

const _: () = {
    __cser_core::assert!(__cser_core::mem::size_of::<CausalAdmittedServiceTask>() <= 1024);
    __cser_core::assert!(__cser_core::mem::size_of::<CausalReservedServiceTask>() <= 1024);
    __cser_core::assert!(__cser_core::mem::size_of::<CausalArmedServiceTask>() <= 1024);
};

#[cfg(test)]
pub(super) fn causal_service_task_facade_self_test() {
    use super::runtime_causal::CausalWorkloadLimits;
    use super::{
        CreditCharge, CreditClass, CreditLimit, DerivedRegisterRequest, DomainConfig,
        OperationClass, PublicationMode, RegisterRequest, ScopeConfig, SyscallDescriptor,
    };

    const ROOT_OWNER: TaskKey = TaskKey::new(0xe001, 1);
    const SERVICE: TaskKey = TaskKey::new(0xe002, 1);
    const CREDIT: CreditClass = CreditClass::new(0xe0);

    const fn limits() -> CausalWorkloadLimits {
        CausalWorkloadLimits::new(8, 1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 64)
    }

    fn child_session(registry: &mut EffectRegistry, seed: u64) -> CausalDomainWorkloadSession {
        let scope = super::ScopeKey::new(seed, 1);
        let domain = DomainKey::new(u32::try_from(seed).unwrap());
        registry
            .create_scope(ScopeConfig {
                key: scope,
                authority_epoch: 7,
                binding_epoch: 1,
                supervisor: ROOT_OWNER,
                credits: __cser_alloc::vec![CreditLimit::new(CREDIT, 1)],
            })
            .unwrap();
        registry
            .add_domain(
                scope,
                DomainConfig {
                    key: domain,
                    binding_epoch: 3,
                    supervisor: SERVICE,
                },
            )
            .unwrap();
        let root = registry
            .register_derived(DerivedRegisterRequest {
                request: RegisterRequest {
                    scope,
                    task: SERVICE,
                    operation: OperationClass::new(u32::try_from(seed).unwrap()),
                    descriptor: SyscallDescriptor::new(
                        usize::try_from(seed).unwrap(),
                        [usize::try_from(seed).unwrap(); 6],
                    ),
                    resources: __cser_alloc::vec![],
                    credits: __cser_alloc::vec![CreditCharge::new(CREDIT, 1)],
                    publication: PublicationMode::None,
                },
                domain,
                parent: None,
            })
            .unwrap();
        registry.prepare(SERVICE, root.handle).unwrap();
        let root_session = registry
            .prepare_causal_workload_activation(
                root.handle,
                seed + 0x100,
                1,
                limits().with_workload_capacity(2),
            )
            .unwrap();
        let root_session = registry.activate_causal_workload(root_session).unwrap();
        let request = registry
            .prepare_causal_domain_workload(&root_session, domain, seed + 0x200, 1)
            .unwrap();
        registry
            .activate_causal_domain_workload(&root_session, domain, request)
            .unwrap()
    }

    fn descriptor(seed: u64, role: CausalServiceTaskRole) -> CausalServiceTaskDescriptor {
        CausalServiceTaskDescriptor::new(
            seed,
            1,
            role,
            CausalVmIdentity::new(seed + 0x400, 1).unwrap(),
            seed + 0x500,
            1,
        )
        .unwrap()
    }

    // The three typestate transitions use the live supervisor-derived task,
    // and a normal service return drains the pair before child close.
    let mut normal = EffectRegistry::new();
    let normal_session = child_session(&mut normal, 0xe100);
    let admitted = normal
        .admit_causal_service_task(
            normal_session,
            descriptor(0xe110, CausalServiceTaskRole::ActiveService),
        )
        .unwrap();
    let selector = admitted.selector();
    let reserved = normal
        .reserve_causal_service_fault(selector, admitted)
        .unwrap();
    let armed = normal.arm_causal_service_task(selector, reserved).unwrap();
    let completed = normal
        .finish_causal_service_task_without_fault(selector, armed, 0xe11f)
        .unwrap();
    completed.close(&mut normal).unwrap();
    normal.check_invariants().unwrap();

    // Reserved cancellation is atomic and leaves an explicit terminal pair;
    // the moved child session remains available for historical close.
    let session = child_session(&mut normal, 0xe120);
    let admitted = normal
        .admit_causal_service_task(
            session,
            descriptor(0xe130, CausalServiceTaskRole::ActiveService),
        )
        .unwrap();
    let selector = admitted.selector();
    let reserved = normal
        .reserve_causal_service_fault(selector, admitted)
        .unwrap();
    let cancelled = normal
        .cancel_causal_reserved_service_task(selector, reserved)
        .unwrap();
    __cser_core::assert_eq!(
        cancelled.receipt().kind(),
        CausalServiceTaskCancellationKind::ReservedComposite
    );
    cancelled.close(&mut normal).unwrap();
    normal.check_invariants().unwrap();

    // A selector substitution returns the exact admitted bearer and leaves
    // the projection unchanged.
    let session = child_session(&mut normal, 0xe140);
    let admitted = normal
        .admit_causal_service_task(
            session,
            descriptor(0xe150, CausalServiceTaskRole::ActiveService),
        )
        .unwrap();
    let selector = admitted.selector();
    let before = normal.failure_atomic_projection();
    let substituted = CausalServiceTaskSelector {
        binding_epoch: selector.binding_epoch + 1,
        ..selector
    };
    let failure = normal
        .reserve_causal_service_fault(substituted, admitted)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), &CausalServiceTaskError::SelectorMismatch);
    __cser_core::assert_eq!(normal.failure_atomic_projection(), before);
    let admitted = failure.into_task();
    let cancelled = normal
        .cancel_causal_admitted_service_task(selector, admitted)
        .unwrap();
    __cser_core::assert_eq!(
        cancelled.receipt().kind(),
        CausalServiceTaskCancellationKind::UnpublishedTask
    );
    cancelled.close(&mut normal).unwrap();
    normal.check_invariants().unwrap();

    // Replacement admission is deliberately fenced until the manager-only
    // recovery provenance API lands; no child authority is leaked.
    let session = child_session(&mut normal, 0xe160);
    let failure = normal
        .admit_causal_service_task(
            session,
            descriptor(0xe170, CausalServiceTaskRole::ReplacementRecovery),
        )
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        &CausalServiceTaskError::RecoveryUnavailable
    );
    let session = failure.into_session();
    normal.close_causal_domain_workload(session).unwrap();
    normal.check_invariants().unwrap();

    // Crash install is followed by claim and cause consumption while the
    // child remains open; close is an explicit subsequent operation.
    let mut crash = EffectRegistry::new();
    let session = child_session(&mut crash, 0xe180);
    let admitted = crash
        .admit_causal_service_task(
            session,
            descriptor(0xe190, CausalServiceTaskRole::ActiveService),
        )
        .unwrap();
    let selector = admitted.selector();
    let reserved = crash
        .reserve_causal_service_fault(selector, admitted)
        .unwrap();
    let selector = reserved.selector();
    let armed = crash.arm_causal_service_task(selector, reserved).unwrap();
    let selector = armed.selector();
    let observation = infrastructure::FaultObservation {
        task: selector.task,
        vm_generation: selector.vm_generation,
        instruction_pointer: 0xe1a0,
        address: 0xe1a1,
        access: infrastructure::FaultAccess::Read,
        architecture_error: 0,
        evidence_digest: 0xe1a2,
    };
    let committed = crash
        .crash_causal_service_task(selector, armed, observation)
        .unwrap();
    __cser_core::assert_eq!(committed.stage(), CausalServiceCrashStage::Consumed);
    committed.close(&mut crash).unwrap();
    crash.check_invariants().unwrap();

    // Isolate receipts have an explicit drain transition rather than being
    // silently dropped after claim.
    let mut isolate = EffectRegistry::new();
    let session = child_session(&mut isolate, 0xe1b0);
    let admitted = isolate
        .admit_causal_service_task(
            session,
            descriptor(0xe1c0, CausalServiceTaskRole::ActiveService),
        )
        .unwrap();
    let selector = admitted.selector();
    let reserved = isolate
        .reserve_causal_service_fault(selector, admitted)
        .unwrap();
    let selector = reserved.selector();
    let armed = isolate.arm_causal_service_task(selector, reserved).unwrap();
    let selector = armed.selector();
    let observation = infrastructure::FaultObservation {
        task: selector.task,
        vm_generation: selector.vm_generation,
        instruction_pointer: 0xe1d0,
        address: 0xe1d1,
        access: infrastructure::FaultAccess::Write,
        architecture_error: 0,
        evidence_digest: 0xe1d2,
    };
    let committed = isolate
        .isolate_causal_service_task(selector, armed, observation)
        .unwrap();
    __cser_core::assert_eq!(committed.stage(), CausalServiceIsolateStage::Drained);
    committed.close(&mut isolate).unwrap();
    isolate.check_invariants().unwrap();
}
