// SPDX-License-Identifier: MPL-2.0

use nexus_portal_abi::{
    AbiResponse, BASE_HEADER_SIZE, CapabilityOffer, CapabilityRequest, ClosureReceipt,
    ClosureStatus, CommitEffectRequest, CompleteEffectRequest, CompletionDisposition,
    CreateScopeFlags, CreateScopeRequest, CreditKind, Digest, EffectHandle, EffectObservation,
    EffectOutcomeObservation, EffectPhase, ErrorResponse, HeaderFlags, LifecycleFlags,
    LifecycleReceipt, MAX_MESSAGE_SIZE, MessageHeader, MessageKind, MutationContext,
    NegotiateRequest, Opcode, OutcomeKind, PortalBackend, PortalCapabilities, PortalDispatcher,
    PortalErrorCode, PortalFailure, PrepareEffectRequest, ProviderCapabilities, QueryAbiRequest,
    QueryEffectRequest, QueryReceiptRequest, QueryScopeRequest, ReceiptHandle, ReceiptKind,
    ReceiptObservation, ReceiptStatus, RecordOutcomeRequest, RegisterEffectRequest, RegisterFlags,
    RequestBody, ResponseBody, RetryClass, RevokeReason, RevokeScopeRequest, ScopeCreatedResponse,
    ScopeHandle, ScopeObservation, ScopePhase, SessionHandle, decode_message, encode_message,
};
use std::cell::Cell;
use std::rc::Rc;

fn digest(byte: u8) -> Digest {
    Digest::from_wire_bytes([byte; 32])
}

fn session(byte: u8) -> SessionHandle {
    SessionHandle::from_wire_bytes([byte; 16])
}

fn scope() -> ScopeHandle {
    ScopeHandle::from_wire_bytes([0x51; 16])
}

fn effect() -> EffectHandle {
    EffectHandle::from_wire_bytes([0x52; 16])
}

fn offer() -> CapabilityOffer {
    CapabilityOffer {
        portal: PortalCapabilities::all(),
        provider: ProviderCapabilities::all(),
    }
}

fn full_negotiation() -> NegotiateRequest {
    NegotiateRequest::new(CapabilityRequest {
        requested_portal: PortalCapabilities::all(),
        required_portal: PortalCapabilities::EFFECT_LIFECYCLE,
        requested_provider: ProviderCapabilities::all(),
        required_provider: ProviderCapabilities::EFFECT_CLOSURE,
    })
}

fn query_only_negotiation() -> NegotiateRequest {
    NegotiateRequest::new(CapabilityRequest {
        requested_portal: PortalCapabilities::QUERY_EFFECT,
        required_portal: PortalCapabilities::QUERY_EFFECT,
        requested_provider: ProviderCapabilities::SESSION_QUERY,
        required_provider: ProviderCapabilities::SESSION_QUERY,
    })
}

fn context(session: SessionHandle, digest_byte: u8) -> MutationContext {
    MutationContext::new(session, 7, 9, digest(digest_byte)).unwrap()
}

fn register_request(session: SessionHandle, digest_byte: u8) -> RegisterEffectRequest {
    RegisterEffectRequest::new(
        context(session, digest_byte),
        scope(),
        EffectHandle::NULL,
        1,
        RegisterFlags::empty(),
        CreditKind::Queue,
        1,
    )
    .unwrap()
}

fn prepare_request(session: SessionHandle, digest_byte: u8) -> PrepareEffectRequest {
    PrepareEffectRequest::new(context(session, digest_byte), effect()).unwrap()
}

fn commit_request(session: SessionHandle, digest_byte: u8) -> CommitEffectRequest {
    CommitEffectRequest::new(context(session, digest_byte), effect(), 1).unwrap()
}

fn outcome_request(session: SessionHandle, digest_byte: u8) -> RecordOutcomeRequest {
    RecordOutcomeRequest::new(
        context(session, digest_byte),
        effect(),
        OutcomeKind::Data,
        0,
        digest(0xa0),
    )
    .unwrap()
}

fn complete_request(session: SessionHandle, digest_byte: u8) -> CompleteEffectRequest {
    CompleteEffectRequest::new(
        context(session, digest_byte),
        effect(),
        CompletionDisposition::Completed,
        digest(0xb0),
    )
    .unwrap()
}

fn encode_request<T: RequestBody>(request_id: u64, request: &T) -> Vec<u8> {
    let mut body = vec![0; T::WIRE_SIZE];
    request.encode_wire(&mut body).unwrap();
    let header = MessageHeader::new(
        MessageKind::Request,
        T::OPCODE,
        HeaderFlags::EXPECT_REPLY,
        request_id,
    )
    .unwrap();
    let mut message = vec![0; MAX_MESSAGE_SIZE];
    let length = encode_message(header, &body, &mut message).unwrap();
    message.truncate(length);
    message
}

fn send<B: PortalBackend, const SLOTS: usize, T: RequestBody>(
    dispatcher: &mut PortalDispatcher<B, SLOTS>,
    request_id: u64,
    request: &T,
) -> Vec<u8> {
    let input = encode_request(request_id, request);
    let mut output = vec![0; MAX_MESSAGE_SIZE];
    let length = dispatcher.dispatch(&input, &mut output).unwrap();
    output.truncate(length);
    output
}

fn send_body<B: PortalBackend, const SLOTS: usize>(
    dispatcher: &mut PortalDispatcher<B, SLOTS>,
    opcode: Opcode,
    request_id: u64,
    body: &[u8],
) -> Vec<u8> {
    let header = MessageHeader::new(
        MessageKind::Request,
        opcode,
        HeaderFlags::EXPECT_REPLY,
        request_id,
    )
    .unwrap();
    let mut input = vec![0; MAX_MESSAGE_SIZE];
    let input_length = encode_message(header, body, &mut input).unwrap();
    input.truncate(input_length);
    let mut output = vec![0; MAX_MESSAGE_SIZE];
    let output_length = dispatcher.dispatch(&input, &mut output).unwrap();
    output.truncate(output_length);
    output
}

fn failure(response: &[u8]) -> PortalFailure {
    let message = decode_message(response).unwrap();
    assert_eq!(message.header.kind(), MessageKind::Error);
    ErrorResponse::decode_wire(message.body).unwrap().failure()
}

fn lifecycle(response: &[u8]) -> LifecycleReceipt {
    let message = decode_message(response).unwrap();
    assert_eq!(message.header.kind(), MessageKind::Response);
    LifecycleReceipt::decode_wire(message.body).unwrap()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum FakePhase {
    #[default]
    Empty,
    Registered,
    Prepared,
    Committed,
    OutcomeRecorded,
    Completed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CallCounts {
    create_scope: u32,
    register: u32,
    prepare: u32,
    commit: u32,
    record_outcome: u32,
    complete: u32,
    revoke: u32,
    query_scope: u32,
    query_effect: u32,
    query_receipt: u32,
}

#[derive(Clone, Debug, Default)]
struct CallProbe(Rc<Cell<CallCounts>>);

impl CallProbe {
    fn snapshot(&self) -> CallCounts {
        self.0.get()
    }

    fn update(&self, update: impl FnOnce(&mut CallCounts)) {
        let mut calls = self.snapshot();
        update(&mut calls);
        self.0.set(calls);
    }
}

#[derive(Debug)]
struct FakeBackend {
    phase: FakePhase,
    calls: CallProbe,
    sequence: u64,
    authority_epoch: u64,
    binding_epoch: u64,
    registration_digest: Digest,
    outcome_kind: Option<OutcomeKind>,
    latest_receipt: ReceiptHandle,
    latest_kind: Option<ReceiptKind>,
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self {
            phase: FakePhase::Empty,
            calls: CallProbe::default(),
            sequence: 0,
            authority_epoch: 0,
            binding_epoch: 0,
            registration_digest: Digest::ZERO,
            outcome_kind: None,
            latest_receipt: ReceiptHandle::NULL,
            latest_kind: None,
        }
    }
}

impl FakeBackend {
    fn with_probe() -> (Self, CallProbe) {
        let backend = Self::default();
        let probe = backend.calls.clone();
        (backend, probe)
    }

    fn out_of_order() -> PortalFailure {
        PortalFailure::new(PortalErrorCode::OutOfOrder, RetryClass::AfterQuery, 0)
    }

    fn lifecycle_receipt(
        &mut self,
        context: MutationContext,
        phase: EffectPhase,
        kind: ReceiptKind,
        flags: LifecycleFlags,
    ) -> LifecycleReceipt {
        self.sequence += 1;
        self.authority_epoch = context.authority_epoch();
        self.binding_epoch = context.binding_epoch();
        self.latest_receipt =
            ReceiptHandle::from_wire_bytes([(self.sequence as u8).wrapping_add(0x60); 16]);
        self.latest_kind = Some(kind);
        LifecycleReceipt::new(
            scope(),
            effect(),
            self.latest_receipt,
            self.authority_epoch,
            self.binding_epoch,
            self.sequence,
            phase,
            kind,
            flags,
            context.request_digest(),
            digest((self.sequence as u8).wrapping_add(0x80)),
        )
        .unwrap()
    }
}

impl PortalBackend for FakeBackend {
    fn create_scope(
        &mut self,
        request: CreateScopeRequest,
    ) -> Result<ScopeCreatedResponse, PortalFailure> {
        self.calls.update(|calls| calls.create_scope += 1);
        self.sequence += 1;
        self.authority_epoch = 1;
        self.binding_epoch = 1;
        self.registration_digest = request.request_digest();
        self.latest_receipt = ReceiptHandle::from_wire_bytes([0x61; 16]);
        self.latest_kind = Some(ReceiptKind::ScopeCreated);
        Ok(ScopeCreatedResponse::new(
            scope(),
            self.latest_receipt,
            self.authority_epoch,
            self.binding_epoch,
            self.sequence,
            request.request_digest(),
            digest(0x81),
        )
        .unwrap())
    }

    fn register(
        &mut self,
        request: RegisterEffectRequest,
    ) -> Result<LifecycleReceipt, PortalFailure> {
        self.calls.update(|calls| calls.register += 1);
        if self.phase != FakePhase::Empty {
            return Err(Self::out_of_order());
        }
        self.phase = FakePhase::Registered;
        self.registration_digest = request.context().request_digest();
        Ok(self.lifecycle_receipt(
            request.context(),
            EffectPhase::Registered,
            ReceiptKind::EffectRegistered,
            LifecycleFlags::empty(),
        ))
    }

    fn prepare(
        &mut self,
        request: PrepareEffectRequest,
    ) -> Result<LifecycleReceipt, PortalFailure> {
        self.calls.update(|calls| calls.prepare += 1);
        if self.phase != FakePhase::Registered {
            return Err(Self::out_of_order());
        }
        self.phase = FakePhase::Prepared;
        Ok(self.lifecycle_receipt(
            request.context(),
            EffectPhase::Prepared,
            ReceiptKind::EffectPrepared,
            LifecycleFlags::empty(),
        ))
    }

    fn commit(&mut self, request: CommitEffectRequest) -> Result<LifecycleReceipt, PortalFailure> {
        self.calls.update(|calls| calls.commit += 1);
        if self.phase != FakePhase::Prepared {
            return Err(Self::out_of_order());
        }
        self.phase = FakePhase::Committed;
        Ok(self.lifecycle_receipt(
            request.context(),
            EffectPhase::Committed,
            ReceiptKind::EffectCommitted,
            LifecycleFlags::empty(),
        ))
    }

    fn record_outcome(
        &mut self,
        request: RecordOutcomeRequest,
    ) -> Result<LifecycleReceipt, PortalFailure> {
        self.calls.update(|calls| calls.record_outcome += 1);
        if self.phase != FakePhase::Committed {
            return Err(Self::out_of_order());
        }
        self.phase = FakePhase::OutcomeRecorded;
        self.outcome_kind = Some(request.outcome_kind());
        Ok(self.lifecycle_receipt(
            request.context(),
            EffectPhase::OutcomeRecorded,
            ReceiptKind::OutcomeRecorded,
            LifecycleFlags::empty(),
        ))
    }

    fn complete(
        &mut self,
        request: CompleteEffectRequest,
    ) -> Result<LifecycleReceipt, PortalFailure> {
        self.calls.update(|calls| calls.complete += 1);
        if request.disposition() != CompletionDisposition::Completed
            || self.phase != FakePhase::OutcomeRecorded
        {
            return Err(Self::out_of_order());
        }
        self.phase = FakePhase::Completed;
        Ok(self.lifecycle_receipt(
            request.context(),
            EffectPhase::Completed,
            ReceiptKind::EffectCompleted,
            LifecycleFlags::TERMINAL,
        ))
    }

    fn revoke(&mut self, request: RevokeScopeRequest) -> Result<ClosureReceipt, PortalFailure> {
        self.calls.update(|calls| calls.revoke += 1);
        self.sequence += 1;
        Ok(ClosureReceipt::new(
            request.scope(),
            ReceiptHandle::from_wire_bytes([0x6f; 16]),
            request.context().authority_epoch() + 1,
            request.context().binding_epoch(),
            self.sequence,
            ClosureStatus::Closed,
            0,
            0,
            0,
            digest(0xc0),
            request.context().request_digest(),
            digest(0xc1),
        )
        .unwrap())
    }

    fn query_scope(
        &mut self,
        portal_session: SessionHandle,
        request: QueryScopeRequest,
    ) -> Result<ScopeObservation, PortalFailure> {
        self.calls.update(|calls| calls.query_scope += 1);
        assert_eq!(portal_session, session(0x41));
        if request.handle() != scope() {
            return Err(PortalFailure::new(
                PortalErrorCode::InvalidHandle,
                RetryClass::Never,
                0,
            ));
        }
        Ok(ScopeObservation::new(
            scope(),
            self.authority_epoch.max(1),
            self.binding_epoch.max(1),
            self.sequence.max(1),
            self.sequence,
            ScopePhase::Active,
            u32::from(self.phase != FakePhase::Completed),
            0,
            0,
            self.latest_receipt,
            digest(0xd0),
        )
        .unwrap())
    }

    fn query_effect(
        &mut self,
        portal_session: SessionHandle,
        request: QueryEffectRequest,
    ) -> Result<EffectObservation, PortalFailure> {
        self.calls.update(|calls| calls.query_effect += 1);
        assert_eq!(portal_session, session(0x41));
        if request.handle() != effect() || self.phase == FakePhase::Empty {
            return Err(PortalFailure::new(
                PortalErrorCode::InvalidHandle,
                RetryClass::Never,
                0,
            ));
        }
        let (phase, flags) = match self.phase {
            FakePhase::Empty => unreachable!(),
            FakePhase::Registered => (EffectPhase::Registered, LifecycleFlags::empty()),
            FakePhase::Prepared => (EffectPhase::Prepared, LifecycleFlags::empty()),
            FakePhase::Committed => (EffectPhase::Committed, LifecycleFlags::empty()),
            FakePhase::OutcomeRecorded => (EffectPhase::OutcomeRecorded, LifecycleFlags::empty()),
            FakePhase::Completed => (EffectPhase::Completed, LifecycleFlags::TERMINAL),
        };
        Ok(EffectObservation::new(
            scope(),
            effect(),
            self.authority_epoch,
            self.binding_epoch,
            self.sequence,
            phase,
            self.outcome_kind
                .map(|kind| EffectOutcomeObservation::new(kind, 0, digest(0xa0)).unwrap()),
            (phase == EffectPhase::Completed).then(|| digest(0xb0)),
            flags,
            self.latest_receipt,
            self.registration_digest,
            digest(0xd1),
        )
        .unwrap())
    }

    fn query_receipt(
        &mut self,
        portal_session: SessionHandle,
        request: QueryReceiptRequest,
    ) -> Result<ReceiptObservation, PortalFailure> {
        self.calls.update(|calls| calls.query_receipt += 1);
        assert_eq!(portal_session, session(0x41));
        if request.handle() != self.latest_receipt || self.latest_receipt.is_null() {
            return Err(PortalFailure::new(
                PortalErrorCode::InvalidHandle,
                RetryClass::Never,
                0,
            ));
        }
        Ok(ReceiptObservation::new(
            self.latest_receipt,
            self.authority_epoch,
            self.binding_epoch,
            self.sequence,
            self.latest_kind.unwrap(),
            ReceiptStatus::Live,
            self.registration_digest,
            digest(0xd2),
        )
        .unwrap())
    }
}

#[test]
fn mutation_is_blocked_before_negotiation_and_by_the_selected_capability_set() {
    let active_session = session(0x41);
    let (backend, calls) = FakeBackend::with_probe();
    let mut dispatcher = PortalDispatcher::<_, 4>::new(offer(), active_session, backend).unwrap();
    let register = register_request(active_session, 0x11);

    let before = send(&mut dispatcher, 2, &register);
    assert_eq!(
        failure(&before).code(),
        PortalErrorCode::NegotiationRequired
    );
    assert_eq!(calls.snapshot().register, 0);
    assert_eq!(dispatcher.replay_len(), 0);

    send(&mut dispatcher, 1, &query_only_negotiation());
    let unselected = send(&mut dispatcher, 2, &register);
    assert_eq!(
        failure(&unselected).code(),
        PortalErrorCode::CapabilityNotNegotiated
    );
    assert_eq!(calls.snapshot().register, 0);
    assert_eq!(dispatcher.replay_len(), 0);

    let query_collision = send(&mut dispatcher, 1, &QueryAbiRequest::new());
    assert_eq!(failure(&query_collision).code(), PortalErrorCode::Conflict);
}

#[test]
fn dispatcher_requires_the_bootstrap_capabilities_it_always_serves() {
    for portal in [
        PortalCapabilities::NEGOTIATE,
        PortalCapabilities::QUERY_ABI,
        PortalCapabilities::empty(),
    ] {
        assert_eq!(
            PortalDispatcher::<_, 1>::new(
                CapabilityOffer {
                    portal,
                    provider: ProviderCapabilities::empty(),
                },
                session(0x41),
                FakeBackend::default(),
            )
            .err()
            .unwrap()
            .code(),
            PortalErrorCode::MissingRequiredCapability,
        );
    }

    assert_eq!(
        PortalDispatcher::<_, 1>::new(
            CapabilityOffer {
                portal: PortalCapabilities::QUERY_ABI | PortalCapabilities::NEGOTIATE,
                provider: ProviderCapabilities::EFFECT_COMPLETION,
            },
            session(0x41),
            FakeBackend::default(),
        )
        .err()
        .unwrap()
        .code(),
        PortalErrorCode::MissingRequiredCapability,
    );

    let error = PortalDispatcher::<_, 0>::new(offer(), session(0x41), FakeBackend::default())
        .err()
        .unwrap();
    assert_eq!(error.code(), PortalErrorCode::LimitExceeded);
    assert_eq!(error.offset(), 68);
}

#[test]
fn query_abi_reports_the_dispatchers_effective_replay_capacity() {
    let mut dispatcher =
        PortalDispatcher::<_, 4>::new(offer(), session(0x41), FakeBackend::default()).unwrap();
    let response = send(&mut dispatcher, 99, &QueryAbiRequest::new());
    let message = decode_message(&response).unwrap();
    assert_eq!(message.header.kind(), MessageKind::Response);
    let abi = AbiResponse::decode_wire(message.body).unwrap();
    assert_eq!(abi.offer(), offer());
    assert_eq!(abi.limits().max_replay_entries(), 4);
}

#[test]
fn core_closure_only_can_prepare_but_cannot_cross_the_commit_boundary() {
    let active_session = session(0x41);
    let (backend, calls) = FakeBackend::with_probe();
    let mut dispatcher = PortalDispatcher::<_, 4>::new(offer(), active_session, backend).unwrap();
    let closure_only = NegotiateRequest::new(CapabilityRequest {
        requested_portal: PortalCapabilities::EFFECT_LIFECYCLE,
        required_portal: PortalCapabilities::EFFECT_LIFECYCLE,
        requested_provider: ProviderCapabilities::EFFECT_CLOSURE,
        required_provider: ProviderCapabilities::EFFECT_CLOSURE,
    });
    send(&mut dispatcher, 1, &closure_only);
    assert_eq!(
        lifecycle(&send(
            &mut dispatcher,
            10,
            &register_request(active_session, 0x11),
        ))
        .phase(),
        EffectPhase::Registered,
    );
    assert_eq!(
        lifecycle(&send(
            &mut dispatcher,
            11,
            &prepare_request(active_session, 0x12),
        ))
        .phase(),
        EffectPhase::Prepared,
    );
    assert_eq!(
        failure(&send(
            &mut dispatcher,
            12,
            &commit_request(active_session, 0x13),
        ))
        .code(),
        PortalErrorCode::CapabilityNotNegotiated,
    );
    assert_eq!(calls.snapshot().commit, 0);
}

#[test]
fn negotiation_exact_retry_is_stable_and_renegotiation_conflicts() {
    let (backend, calls) = FakeBackend::with_probe();
    let mut dispatcher = PortalDispatcher::<_, 2>::new(offer(), session(0x41), backend).unwrap();
    let request = full_negotiation();
    let first = send(&mut dispatcher, 1, &request);
    let retry = send(&mut dispatcher, 1, &request);
    assert_eq!(first, retry);
    assert_eq!(
        decode_message(&first).unwrap().header.kind(),
        MessageKind::Response
    );

    let malformed_same_id = send_body(&mut dispatcher, Opcode::Negotiate, 1, &[0; 31]);
    assert_eq!(
        failure(&malformed_same_id).code(),
        PortalErrorCode::Conflict
    );

    let conflict = send(&mut dispatcher, 2, &request);
    assert_eq!(failure(&conflict).code(), PortalErrorCode::Conflict);
    assert_eq!(dispatcher.replay_len(), 0);

    let reused_for_mutation = send(&mut dispatcher, 1, &register_request(session(0x41), 0x11));
    assert_eq!(
        failure(&reused_for_mutation).code(),
        PortalErrorCode::Conflict
    );
    assert_eq!(calls.snapshot().register, 0);
    assert_eq!(dispatcher.replay_len(), 0);
}

#[test]
fn exact_mutation_retry_is_byte_identical_and_changed_content_conflicts() {
    let active_session = session(0x41);
    let (backend, calls) = FakeBackend::with_probe();
    let mut dispatcher = PortalDispatcher::<_, 4>::new(offer(), active_session, backend).unwrap();
    send(&mut dispatcher, 1, &full_negotiation());

    let original = register_request(active_session, 0x11);
    let first = send(&mut dispatcher, 10, &original);
    let retry = send(&mut dispatcher, 10, &original);
    assert_eq!(first, retry);
    assert_eq!(lifecycle(&first).phase(), EffectPhase::Registered);
    assert_eq!(calls.snapshot().register, 1);
    assert_eq!(dispatcher.replay_len(), 1);

    let query_collision = send(&mut dispatcher, 10, &QueryEffectRequest::new(effect()));
    assert_eq!(failure(&query_collision).code(), PortalErrorCode::Conflict);
    assert_eq!(calls.snapshot().query_effect, 0);

    let oversized_same_id = send_body(
        &mut dispatcher,
        Opcode::Register,
        10,
        &[0; nexus_portal_abi::MAX_MUTATION_BODY_SIZE + 1],
    );
    assert_eq!(
        failure(&oversized_same_id).code(),
        PortalErrorCode::Conflict
    );

    let changed = register_request(active_session, 0x12);
    let conflict = failure(&send(&mut dispatcher, 10, &changed));
    assert_eq!(conflict.code(), PortalErrorCode::Conflict);
    assert_eq!(conflict.presented_digest(), digest(0x12));
    assert_eq!(conflict.existing_digest(), digest(0x11));
    assert_eq!(calls.snapshot().register, 1);
}

#[test]
fn backend_ordering_error_is_cached_then_lifecycle_and_query_can_finish() {
    let active_session = session(0x41);
    let (backend, calls) = FakeBackend::with_probe();
    let mut dispatcher = PortalDispatcher::<_, 8>::new(offer(), active_session, backend).unwrap();
    send(&mut dispatcher, 1, &full_negotiation());

    assert_eq!(
        lifecycle(&send(
            &mut dispatcher,
            10,
            &register_request(active_session, 0x11)
        ))
        .phase(),
        EffectPhase::Registered,
    );
    assert_eq!(
        lifecycle(&send(
            &mut dispatcher,
            11,
            &prepare_request(active_session, 0x12)
        ))
        .phase(),
        EffectPhase::Prepared,
    );
    assert_eq!(
        lifecycle(&send(
            &mut dispatcher,
            12,
            &commit_request(active_session, 0x13)
        ))
        .phase(),
        EffectPhase::Committed,
    );

    let premature_request = complete_request(active_session, 0x14);
    let premature = send(&mut dispatcher, 13, &premature_request);
    let premature_retry = send(&mut dispatcher, 13, &premature_request);
    assert_eq!(premature, premature_retry);
    assert_eq!(failure(&premature).code(), PortalErrorCode::OutOfOrder);
    assert_eq!(calls.snapshot().complete, 1);

    assert_eq!(
        lifecycle(&send(
            &mut dispatcher,
            14,
            &outcome_request(active_session, 0x15)
        ))
        .phase(),
        EffectPhase::OutcomeRecorded,
    );
    assert_eq!(
        lifecycle(&send(
            &mut dispatcher,
            15,
            &complete_request(active_session, 0x16)
        ))
        .phase(),
        EffectPhase::Completed,
    );

    let observation = send(&mut dispatcher, 16, &QueryEffectRequest::new(effect()));
    let message = decode_message(&observation).unwrap();
    assert_eq!(message.header.kind(), MessageKind::Response);
    assert_eq!(
        EffectObservation::decode_wire(message.body)
            .unwrap()
            .phase(),
        EffectPhase::Completed,
    );
    assert_eq!(calls.snapshot().query_effect, 1);
    assert_eq!(calls.snapshot().complete, 2);
}

#[test]
fn wrong_session_is_a_cached_typed_failure_and_changed_retry_conflicts() {
    let active_session = session(0x41);
    let (backend, calls) = FakeBackend::with_probe();
    let mut dispatcher = PortalDispatcher::<_, 2>::new(offer(), active_session, backend).unwrap();
    send(&mut dispatcher, 1, &full_negotiation());

    let wrong = register_request(session(0x42), 0x11);
    let first = send(&mut dispatcher, 10, &wrong);
    let retry = send(&mut dispatcher, 10, &wrong);
    assert_eq!(first, retry);
    assert_eq!(failure(&first).code(), PortalErrorCode::InvalidSession);
    assert_eq!(calls.snapshot().register, 0);
    assert_eq!(dispatcher.replay_len(), 1);

    let corrected = register_request(active_session, 0x11);
    assert_eq!(
        failure(&send(&mut dispatcher, 10, &corrected)).code(),
        PortalErrorCode::Conflict,
    );
    assert_eq!(calls.snapshot().register, 0);
}

#[test]
fn replay_capacity_fails_closed_before_the_next_backend_mutation() {
    let active_session = session(0x41);
    let (backend, calls) = FakeBackend::with_probe();
    let mut dispatcher = PortalDispatcher::<_, 1>::new(offer(), active_session, backend).unwrap();
    send(&mut dispatcher, 1, &full_negotiation());
    send(&mut dispatcher, 10, &register_request(active_session, 0x11));

    let blocked = send(&mut dispatcher, 11, &prepare_request(active_session, 0x12));
    let blocked_failure = failure(&blocked);
    assert_eq!(blocked_failure.code(), PortalErrorCode::Backpressure);
    assert_eq!(blocked_failure.retry(), RetryClass::NewSession);
    assert_eq!(calls.snapshot().prepare, 0);
    assert_eq!(dispatcher.replay_len(), 1);
}

#[test]
fn scope_creation_queries_and_revoke_dispatch_to_bounded_response_types() {
    let active_session = session(0x41);
    let (backend, calls) = FakeBackend::with_probe();
    let mut dispatcher = PortalDispatcher::<_, 2>::new(offer(), active_session, backend).unwrap();
    send(&mut dispatcher, 1, &full_negotiation());

    let create = CreateScopeRequest::new(
        active_session,
        ScopeHandle::NULL,
        0,
        0,
        digest(0x21),
        CreateScopeFlags::empty(),
        4,
        2,
        1,
        1,
    )
    .unwrap();
    let created_message = send(&mut dispatcher, 2, &create);
    let created_wire = decode_message(&created_message).unwrap();
    let created = ScopeCreatedResponse::decode_wire(created_wire.body).unwrap();
    assert_eq!(created.scope(), scope());
    assert_eq!(created.request_digest(), digest(0x21));

    let scope_message = send(&mut dispatcher, 20, &QueryScopeRequest::new(scope()));
    let scope_wire = decode_message(&scope_message).unwrap();
    assert_eq!(
        ScopeObservation::decode_wire(scope_wire.body)
            .unwrap()
            .scope(),
        scope(),
    );

    let receipt_message = send(
        &mut dispatcher,
        20,
        &QueryReceiptRequest::new(created.receipt()),
    );
    let receipt_wire = decode_message(&receipt_message).unwrap();
    assert_eq!(
        ReceiptObservation::decode_wire(receipt_wire.body)
            .unwrap()
            .kind(),
        ReceiptKind::ScopeCreated,
    );

    let revoke = RevokeScopeRequest::new(
        context(active_session, 0x22),
        scope(),
        RevokeReason::Requested,
    )
    .unwrap();
    let revoked_message = send(&mut dispatcher, 3, &revoke);
    let revoked_wire = decode_message(&revoked_message).unwrap();
    assert_eq!(
        ClosureReceipt::decode_wire(revoked_wire.body)
            .unwrap()
            .status(),
        ClosureStatus::Closed,
    );

    assert_eq!(calls.snapshot().create_scope, 1);
    assert_eq!(calls.snapshot().query_scope, 1);
    assert_eq!(calls.snapshot().query_receipt, 1);
    assert_eq!(calls.snapshot().revoke, 1);
    assert_eq!(dispatcher.replay_len(), 2);
}

#[test]
fn trusted_envelope_body_errors_are_typed_and_mutation_errors_are_replayed() {
    let active_session = session(0x41);
    let (backend, calls) = FakeBackend::with_probe();
    let mut dispatcher = PortalDispatcher::<_, 2>::new(offer(), active_session, backend).unwrap();
    send(&mut dispatcher, 1, &full_negotiation());

    let register = register_request(active_session, 0x31);
    let mut malformed = encode_request(10, &register);
    malformed[BASE_HEADER_SIZE + 110] = 1;
    let mut output = vec![0; MAX_MESSAGE_SIZE];
    let length = dispatcher.dispatch(&malformed, &mut output).unwrap();
    output.truncate(length);
    assert_eq!(failure(&output).code(), PortalErrorCode::NonZeroTail);
    assert_eq!(calls.snapshot().register, 0);
    assert_eq!(dispatcher.replay_len(), 1);

    let mut retry_output = vec![0; MAX_MESSAGE_SIZE];
    let retry_length = dispatcher.dispatch(&malformed, &mut retry_output).unwrap();
    retry_output.truncate(retry_length);
    assert_eq!(output, retry_output);
    assert_eq!(calls.snapshot().register, 0);

    let corrected = send(&mut dispatcher, 10, &register);
    assert_eq!(failure(&corrected).code(), PortalErrorCode::Conflict);

    let query_header = MessageHeader::new(
        MessageKind::Request,
        Opcode::QueryScope,
        HeaderFlags::EXPECT_REPLY,
        20,
    )
    .unwrap();
    let mut query_input = vec![0; MAX_MESSAGE_SIZE];
    let query_length = encode_message(query_header, &[0; 15], &mut query_input).unwrap();
    query_input.truncate(query_length);
    let mut query_output = vec![0; MAX_MESSAGE_SIZE];
    let query_output_length = dispatcher
        .dispatch(&query_input, &mut query_output)
        .unwrap();
    query_output.truncate(query_output_length);
    assert_eq!(
        failure(&query_output).code(),
        PortalErrorCode::BodySizeMismatch
    );
    assert_eq!(calls.snapshot().query_scope, 0);
}
