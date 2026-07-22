// SPDX-License-Identifier: MPL-2.0

//! Post-backend, pre-publication crash successor for the bounded Linux
//! filesystem slice.
//!
//! The v3 task in this module is only a fresh closure trigger. It never owns a
//! Registry service incarnation and therefore cannot snapshot, rebind, adopt,
//! recommit, or replace the crashed v2 service.

use super::*;

#[derive(Clone)]
struct PostcommitPending {
    cookie: NonZeroU64,
    ticket: PublicationTicket,
    root_effect: EffectKey,
    causal_identity: CausalWorkloadIdentity,
}

fn postcommit_invariant(portal: &'static str, detail: &'static str) -> FsServiceProtocolError {
    FsServiceProtocolError::PostcommitInvariant { portal, detail }
}

fn current_postcommit_trigger(vm_space: &Arc<VmSpace>) -> Result<TaskKey, FsServiceProtocolError> {
    let current = Task::current().ok_or_else(|| {
        postcommit_invariant(
            "postcommit_task",
            "closure trigger has no current OSTD task",
        )
    })?;
    let data = current.data().downcast_ref::<TaskData>().ok_or_else(|| {
        postcommit_invariant(
            "postcommit_task",
            "closure trigger is missing Nexus TaskData",
        )
    })?;
    let trigger = data.postcommit_trigger_task.ok_or_else(|| {
        postcommit_invariant(
            "postcommit_task",
            "closure trigger is missing its dedicated task identity",
        )
    })?;
    if trigger != FILESYSTEM_V3_TRIGGER
        || data.id != trigger.id()
        || data.cser_task.is_some()
        || !data
            .vm_space
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, vm_space))
    {
        return Err(postcommit_invariant(
            "postcommit_task",
            "closure trigger identity, VM, or Registry-free boundary changed",
        ));
    }
    Ok(trigger)
}

impl FsScenario {
    /// Verifies the exact kernel-owned flight and the opaque Active causal
    /// session before every postcommit transition. The causal identity is
    /// keyed by the flight cookie and `work.effects[0]`, never by v3.
    fn require_postcommit_pending(
        &self,
        portal: &'static str,
        expected_phase: FsServicePhase,
    ) -> Result<PostcommitPending, FsServiceProtocolError> {
        if self.isolation_reason().is_some() {
            return Err(FsServiceProtocolError::ScenarioIsolated { portal });
        }
        let (service_cookie, outcome_cookie, outcome_ticket) = {
            let service = self.service.lock();
            service.require_phase(portal, "postcommit publication pending", |phase| {
                phase == expected_phase
            })?;
            if service.response_waker.is_none()
                || service.reply_wakeups != 0
                || service.response_taken
                || service.termination.is_some()
            {
                return Err(postcommit_invariant(
                    portal,
                    "reply continuation is not exactly once and still pending",
                ));
            }
            let service_cookie = service.cookie.ok_or(FsServiceProtocolError::MissingField {
                portal,
                field: "cookie",
            })?;
            let outcome = service
                .outcome
                .as_ref()
                .ok_or(FsServiceProtocolError::MissingField {
                    portal,
                    field: "outcome",
                })?;
            if outcome.result != 4
                || outcome.exit
                || !matches!(
                    outcome.publication,
                    Publication::FixedGuestBytes { len: 4, .. }
                )
            {
                return Err(postcommit_invariant(
                    portal,
                    "completed four-byte production outcome changed",
                ));
            }
            let PublicationAuthority::Production {
                ticket,
                flight_cookie,
            } = &outcome.authority
            else {
                return Err(postcommit_invariant(
                    portal,
                    "production publication authority is missing",
                ));
            };
            (service_cookie, *flight_cookie, ticket.clone())
        };

        if service_cookie.get() != outcome_cookie {
            return Err(postcommit_invariant(
                portal,
                "service and outcome flight cookies differ",
            ));
        }
        let runtime = self.production.lock();
        let scope = runtime
            .registry
            .scope_projection(SCOPE)
            .map_err(|error| FsServiceProtocolError::Registry { portal, error })?;
        if scope.phase != ScopePhase::Closing
            || scope.live_effects != 0
            || scope.pending_publications != 1
            || runtime.adapter_phase != FsDeviceAdapterPhase::Released
        {
            return Err(postcommit_invariant(
                portal,
                "runtime is not one released AwaitingPublication flight",
            ));
        }
        let (cookie, ticket, root_effect) = match &runtime.flight {
            FsDeviceFlight::AwaitingPublication {
                cookie,
                ticket,
                work,
                ..
            } if *cookie == outcome_cookie
                && *ticket == outcome_ticket
                && ticket.effect() == work.effects[0]
                && work.result == 4
                && work.byte_count == 4 =>
            {
                (*cookie, ticket.clone(), work.effects[0])
            }
            _ => {
                return Err(postcommit_invariant(
                    portal,
                    "flight, ticket, root effect, or completed work changed",
                ));
            }
        };
        let cookie = NonZeroU64::new(cookie)
            .ok_or_else(|| postcommit_invariant(portal, "flight cookie is zero"))?;
        let causal_identity = runtime
            .verify_causal_session(cookie, root_effect)
            .map_err(|error| FsServiceProtocolError::Causal { portal, error })?;
        runtime
            .registry
            .check_invariants()
            .map_err(|error| FsServiceProtocolError::Registry { portal, error })?;
        Ok(PostcommitPending {
            cookie,
            ticket,
            root_effect,
            causal_identity,
        })
    }

    pub(super) fn fsd_crash_postcommit_v2(
        &self,
        sender: TaskKey,
        fault_address: usize,
    ) -> Result<(), FsServiceProtocolError> {
        FsServiceProtocol::require_sender("postcommit_crash", sender, FILESYSTEM_V2)?;
        if fault_address != EXPECTED_FSD_FAULT {
            return Err(postcommit_invariant(
                "postcommit_crash",
                "v2 fault address is not the frozen postcommit injection",
            ));
        }
        let pending =
            self.require_postcommit_pending("postcommit_crash", FsServicePhase::Executed)?;
        {
            let mut service = self.service.lock();
            service.require_phase("postcommit_crash/install", "Executed", |phase| {
                phase == FsServicePhase::Executed
            })?;
            if service.postcommit_fault_observed || service.postcommit_causal_identity.is_some() {
                return Err(postcommit_invariant(
                    "postcommit_crash/install",
                    "postcommit crash was already installed",
                ));
            }
            service.postcommit_fault_observed = true;
            service.postcommit_causal_identity = Some(pending.causal_identity);
            service.phase = FsServicePhase::PostcommitCrashed;
        }
        println!(
            "LINUX_FS_POSTCOMMIT Crash runner=fsd-v2 task={} task_generation={} real_user_page_fault=true reason=real_user_page_fault addr={:#x} backend_completion=true phase=Closing live_effects=0 pending_publications=1 flight=AwaitingPublication flight_cookie={} ticket_effect={} causal_state=Active causal_request={} causal_root={} outcome_present=true reply_wakeups=0 guest_reply=false polling=true irq=false smp=1",
            sender.id(),
            sender.generation(),
            fault_address,
            pending.cookie.get(),
            pending.ticket.effect().id(),
            pending.causal_identity.request_id(),
            pending.causal_identity.root_effect().id(),
        );
        Ok(())
    }

    pub(super) fn fsd_postcommit_stale_probe(
        &self,
        trigger: TaskKey,
    ) -> Result<(), FsServiceProtocolError> {
        FsServiceProtocol::require_sender("postcommit_probe", trigger, FILESYSTEM_V3_TRIGGER)?;
        let pending =
            self.require_postcommit_pending("postcommit_probe", FsServicePhase::PostcommitCrashed)?;
        let old_handle = {
            let service = self.service.lock();
            if service.postcommit_causal_identity != Some(pending.causal_identity)
                || service.postcommit_stale_probe_observed
            {
                return Err(postcommit_invariant(
                    "postcommit_probe",
                    "Active causal identity changed across the v2 crash",
                ));
            }
            service
                .adopted_handle
                .ok_or(FsServiceProtocolError::MissingField {
                    portal: "postcommit_probe",
                    field: "v2 adopted_handle",
                })?
        };
        let (before_fingerprint, after_fingerprint, current_authority_epoch) = {
            let mut runtime = self.production.lock();
            let before = runtime.registry.failure_atomic_projection();
            if runtime.registry.prepare(FILESYSTEM_V2, old_handle)
                != Err(RegistryError::StaleAuthority)
            {
                return Err(postcommit_invariant(
                    "postcommit_probe",
                    "v2 authority was not fenced as StaleAuthority",
                ));
            }
            let after = runtime.registry.failure_atomic_projection();
            if after != before {
                return Err(postcommit_invariant(
                    "postcommit_probe",
                    "stale-authority rejection mutated the Registry",
                ));
            }
            let after_causal = runtime
                .verify_causal_session(pending.cookie, pending.root_effect)
                .map_err(|error| FsServiceProtocolError::Causal {
                    portal: "postcommit_probe/after",
                    error,
                })?;
            if after_causal != pending.causal_identity
                || !matches!(
                    &runtime.flight,
                    FsDeviceFlight::AwaitingPublication { cookie, ticket, work, .. }
                        if *cookie == pending.cookie.get()
                            && *ticket == pending.ticket
                            && work.effects[0] == pending.root_effect
                )
            {
                return Err(postcommit_invariant(
                    "postcommit_probe",
                    "stale-authority probe changed flight or causal identity",
                ));
            }
            let current_authority_epoch = runtime
                .registry
                .scope_projection(SCOPE)
                .map_err(|error| FsServiceProtocolError::Registry {
                    portal: "postcommit_probe",
                    error,
                })?
                .authority_epoch;
            (
                fnv1a(before.as_bytes()),
                fnv1a(after.as_bytes()),
                current_authority_epoch,
            )
        };
        {
            let mut service = self.service.lock();
            service.require_phase("postcommit_probe/install", "PostcommitCrashed", |phase| {
                phase == FsServicePhase::PostcommitCrashed
            })?;
            service.postcommit_stale_probe_observed = true;
            service.phase = FsServicePhase::PostcommitProbed;
        }
        println!(
            "LINUX_FS_POSTCOMMIT StaleProbe trigger=fsd-v3 trigger_task={} trigger_generation={} registry_replacement=false causal_service_task_facade_observed=false causal_fault_matrix_promotion=false presented_sender=fsd-v2 presented_task={} presented_generation={} effect={} old_authority_epoch={} current_authority_epoch={} result=StaleAuthority projection_before={:#018x} projection_after={:#018x} registry_projection_unchanged=true flight_identity_unchanged=true causal_identity_unchanged=true flight_cookie={} ticket_effect={} causal_state=Active causal_request={} causal_root={} same_causal_session=true recommit=false rebind=false adopt=false",
            trigger.id(),
            trigger.generation(),
            FILESYSTEM_V2.id(),
            FILESYSTEM_V2.generation(),
            old_handle.effect().id(),
            old_handle.authority_epoch(),
            current_authority_epoch,
            before_fingerprint,
            after_fingerprint,
            pending.cookie.get(),
            pending.ticket.effect().id(),
            pending.causal_identity.request_id(),
            pending.root_effect.id(),
        );
        Ok(())
    }

    pub(super) fn fsd_trigger_postcommit_publication(
        &self,
        trigger: TaskKey,
    ) -> Result<(), FsServiceProtocolError> {
        FsServiceProtocol::require_sender("postcommit_wake", trigger, FILESYSTEM_V3_TRIGGER)?;
        let pending =
            self.require_postcommit_pending("postcommit_wake", FsServicePhase::PostcommitProbed)?;
        let waker = {
            let mut service = self.service.lock();
            service.require_phase("postcommit_wake/install", "PostcommitProbed", |phase| {
                phase == FsServicePhase::PostcommitProbed
            })?;
            if service.postcommit_causal_identity != Some(pending.causal_identity)
                || !service.postcommit_fault_observed
                || !service.postcommit_stale_probe_observed
                || service.postcommit_wake_triggered
            {
                return Err(postcommit_invariant(
                    "postcommit_wake/install",
                    "postcommit causal identity or trigger ordering changed",
                ));
            }
            let waker =
                service
                    .response_waker
                    .take()
                    .ok_or(FsServiceProtocolError::MissingField {
                        portal: "postcommit_wake/install",
                        field: "response_waker",
                    })?;
            service.reply_wakeups = 1;
            service.postcommit_wake_triggered = true;
            service.phase = FsServicePhase::ReplyReady;
            waker
        };
        println!(
            "LINUX_FS_POSTCOMMIT WakeTrigger runner=fsd-v3 trigger_task={} trigger_generation={} registry_replacement=false causal_service_task_facade_observed=false causal_fault_matrix_promotion=false flight_cookie={} ticket_effect={} causal_state=Active causal_request={} causal_root={} same_causal_session=true same_flight=true same_ticket=true same_outcome=true reply_wakeups=1 exactly_once=true original_guest_publication_pending=true recommit=false rebind=false adopt=false polling=true irq=false smp=1",
            trigger.id(),
            trigger.generation(),
            pending.cookie.get(),
            pending.ticket.effect().id(),
            pending.causal_identity.request_id(),
            pending.root_effect.id(),
        );
        waker.wake_up();
        Ok(())
    }

    pub(super) fn fsd_finish_postcommit_trigger(
        &self,
        trigger: TaskKey,
    ) -> Result<(), FsServiceProtocolError> {
        FsServiceProtocol::require_sender("postcommit_done", trigger, FILESYSTEM_V3_TRIGGER)?;
        let mut service = self.service.lock();
        service.require_phase("postcommit_done", "ReplyReady after one wakeup", |phase| {
            phase == FsServicePhase::ReplyReady
        })?;
        if service.reply_wakeups != 1
            || service.response_waker.is_some()
            || !service.postcommit_wake_triggered
        {
            return Err(postcommit_invariant(
                "postcommit_done",
                "closure trigger did not issue exactly one wake",
            ));
        }
        service.phase = FsServicePhase::Done;
        service.service_done = true;
        Ok(())
    }
}

pub(super) fn run_fsd_v3(scenario: Arc<FsScenario>, vm_space: Arc<VmSpace>, done: EffectWaker) {
    let trigger = match current_postcommit_trigger(&vm_space) {
        Ok(trigger) => trigger,
        Err(error) => {
            terminate_fsd(
                &scenario,
                FILESYSTEM_V3_TRIGGER,
                FsServiceTerminationReason::PortalRejected(error),
                &done,
            );
            return;
        }
    };
    vm_space.activate();
    let mut context = UserContext::default();
    context.set_rip(USER_MAP_ADDR);
    let mut user_mode = UserMode::new(context);
    loop {
        vm_space.activate();
        match user_mode.execute(|| false) {
            ReturnReason::UserSyscall => match user_mode.context().rax() {
                FSD_POSTCOMMIT_PROBE => {
                    if let Err(error) = scenario.fsd_postcommit_stale_probe(trigger) {
                        terminate_fsd(
                            &scenario,
                            trigger,
                            FsServiceTerminationReason::PortalRejected(error),
                            &done,
                        );
                        return;
                    }
                    user_mode.context_mut().set_rax(FSD_RESULT_STALE_AUTHORITY);
                }
                FSD_PUBLISH => {
                    if let Err(error) = scenario.fsd_trigger_postcommit_publication(trigger) {
                        terminate_fsd(
                            &scenario,
                            trigger,
                            FsServiceTerminationReason::PortalRejected(error),
                            &done,
                        );
                        return;
                    }
                    user_mode.context_mut().set_rax(0);
                }
                FSD_DONE => {
                    if let Err(error) = scenario.fsd_finish_postcommit_trigger(trigger) {
                        terminate_fsd(
                            &scenario,
                            trigger,
                            FsServiceTerminationReason::PortalRejected(error),
                            &done,
                        );
                        return;
                    }
                    println!(
                        "FSD_V3 EXIT task={} task_generation={} reason=postcommit_closure_trigger_done registry_replacement=false stale_probe=true recommit=false rebind=false adopt=false reply_wakeups=1",
                        trigger.id(),
                        trigger.generation(),
                    );
                    done.wake_up();
                    return;
                }
                FSD_FAIL => {
                    terminate_fsd(
                        &scenario,
                        trigger,
                        FsServiceTerminationReason::GuestReportedFailure {
                            code: user_mode.context().rdi(),
                        },
                        &done,
                    );
                    return;
                }
                opcode => {
                    terminate_fsd(
                        &scenario,
                        trigger,
                        FsServiceTerminationReason::UnknownPortal { opcode },
                        &done,
                    );
                    return;
                }
            },
            ReturnReason::UserException => {
                let reason = match user_mode.context_mut().take_exception() {
                    Some(other) => FsServiceTerminationReason::UnexpectedException(other),
                    None => FsServiceTerminationReason::MissingException,
                };
                terminate_fsd(&scenario, trigger, reason, &done);
                return;
            }
            ReturnReason::KernelEvent => Task::yield_now(),
        }
    }
}
