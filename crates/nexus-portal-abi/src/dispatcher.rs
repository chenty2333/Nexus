// SPDX-License-Identifier: MPL-2.0

//! Allocation-free provider-neutral portal dispatch.
//!
//! The dispatcher owns negotiation ordering and an exact bounded replay cache.
//! It does not implement effect semantics: a [`PortalBackend`] adapter must
//! validate opaque handles, epochs, ancestry, credits, and lifecycle order
//! against one authoritative provider.

use crate::{
    AbiResponse, CapabilityOffer, ClosureReceipt, CommitEffectRequest, CompleteEffectRequest,
    CreateScopeRequest, Digest, EffectObservation, ErrorResponse, HeaderFlags, LifecycleReceipt,
    MAX_MUTATION_BODY_SIZE, MAX_RESPONSE_BODY_SIZE, MessageHeader, MessageKind, NegotiateRequest,
    NegotiatedCapabilities, NegotiatedResponse, Opcode, PortalCapabilities, PortalErrorCode,
    PortalFailure, PortalLimits, PortalWireError, PrepareEffectRequest, ProviderCapabilities,
    QueryAbiRequest, QueryEffectRequest, QueryReceiptRequest, QueryScopeRequest,
    ReceiptObservation, RecordOutcomeRequest, RegisterEffectRequest, RequestBody, ResponseBody,
    RetryClass, RevokeScopeRequest, ScopeCreatedResponse, ScopeObservation, SessionHandle,
    decode_message, encode_message, negotiate, provider_capability_closure,
};

/// Backend operations required by the portal-v2 dispatcher.
///
/// An implementation belongs in a higher-level adapter crate that depends on
/// this ABI and its authoritative Registry or provider.  Backend methods are
/// called only after framing, body validation, successful negotiation,
/// capability checks, session selection, and (for mutations) replay admission.
pub trait PortalBackend {
    /// Returns effective finite capacities for this backend instance.
    ///
    /// Backends with concrete selector tables should override the protocol
    /// maxima. The dispatcher independently clamps replay capacity to its own
    /// const-generic table.
    fn portal_limits(&self) -> Result<PortalLimits, PortalWireError> {
        Ok(PortalLimits::PROTOCOL_MAXIMA)
    }

    /// Creates one bounded causal scope.
    fn create_scope(
        &mut self,
        request: CreateScopeRequest,
    ) -> Result<ScopeCreatedResponse, PortalFailure>;

    /// Registers one effect.
    fn register(
        &mut self,
        request: RegisterEffectRequest,
    ) -> Result<LifecycleReceipt, PortalFailure>;

    /// Prepares one registered effect.
    fn prepare(&mut self, request: PrepareEffectRequest)
    -> Result<LifecycleReceipt, PortalFailure>;

    /// Commits one prepared effect.
    fn commit(&mut self, request: CommitEffectRequest) -> Result<LifecycleReceipt, PortalFailure>;

    /// Records one canonical backend outcome.
    fn record_outcome(
        &mut self,
        request: RecordOutcomeRequest,
    ) -> Result<LifecycleReceipt, PortalFailure>;

    /// Terminalizes one effect.
    fn complete(
        &mut self,
        request: CompleteEffectRequest,
    ) -> Result<LifecycleReceipt, PortalFailure>;

    /// Revokes one scope and returns bounded closure progress.
    fn revoke(&mut self, request: RevokeScopeRequest) -> Result<ClosureReceipt, PortalFailure>;

    /// Queries one scope in the current provider session.
    fn query_scope(
        &mut self,
        session: SessionHandle,
        request: QueryScopeRequest,
    ) -> Result<ScopeObservation, PortalFailure>;

    /// Queries one effect in the current provider session.
    fn query_effect(
        &mut self,
        session: SessionHandle,
        request: QueryEffectRequest,
    ) -> Result<EffectObservation, PortalFailure>;

    /// Queries one receipt in the current provider session.
    fn query_receipt(
        &mut self,
        session: SessionHandle,
        request: QueryReceiptRequest,
    ) -> Result<ReceiptObservation, PortalFailure>;
}

#[derive(Clone, Copy)]
struct ReplayEntry {
    occupied: bool,
    request_id: u64,
    opcode: u16,
    request_length: u16,
    request: [u8; MAX_MUTATION_BODY_SIZE],
    response_kind: u16,
    response_length: u16,
    response: [u8; MAX_RESPONSE_BODY_SIZE],
}

impl ReplayEntry {
    const EMPTY: Self = Self {
        occupied: false,
        request_id: 0,
        opcode: 0,
        request_length: 0,
        request: [0; MAX_MUTATION_BODY_SIZE],
        response_kind: 0,
        response_length: 0,
        response: [0; MAX_RESPONSE_BODY_SIZE],
    };

    fn matches(self, opcode: Opcode, request: &[u8]) -> bool {
        self.opcode == opcode.wire_value()
            && usize::from(self.request_length) == request.len()
            && self.request[..request.len()] == *request
    }
}

/// Bounded no-allocation portal dispatcher.
///
/// `REPLAY_SLOTS` fixes the maximum number of accepted mutating request ids for
/// the session. Entries are never evicted because eviction would permit a
/// historical request id to mutate the backend twice. Exhaustion returns typed
/// [`PortalErrorCode::Backpressure`] before the backend is called.
pub struct PortalDispatcher<B, const REPLAY_SLOTS: usize> {
    backend: B,
    offer: CapabilityOffer,
    limits: PortalLimits,
    session: SessionHandle,
    negotiated: Option<NegotiatedCapabilities>,
    negotiation_request_id: u64,
    negotiation_body: [u8; 32],
    replay: [ReplayEntry; REPLAY_SLOTS],
}

impl<B: PortalBackend, const REPLAY_SLOTS: usize> PortalDispatcher<B, REPLAY_SLOTS> {
    /// Creates one dispatcher around a provider-owned backend.
    pub fn new(
        offer: CapabilityOffer,
        session: SessionHandle,
        backend: B,
    ) -> Result<Self, PortalWireError> {
        if session.is_null() {
            return Err(PortalWireError::new(PortalErrorCode::InvalidSession, 0));
        }
        if PortalCapabilities::from_bits(offer.portal.bits()).is_none()
            || ProviderCapabilities::from_bits(offer.provider.bits()).is_none()
        {
            return Err(PortalWireError::new(PortalErrorCode::UnknownCapability, 0));
        }
        if provider_capability_closure(offer.provider) != offer.provider {
            return Err(PortalWireError::new(
                PortalErrorCode::MissingRequiredCapability,
                0,
            ));
        }
        let bootstrap = PortalCapabilities::QUERY_ABI | PortalCapabilities::NEGOTIATE;
        if !offer.portal.contains(bootstrap) {
            return Err(PortalWireError::new(
                PortalErrorCode::MissingRequiredCapability,
                0,
            ));
        }
        let replay_capacity = u32::try_from(REPLAY_SLOTS).unwrap_or(u32::MAX);
        let limits = backend
            .portal_limits()?
            .with_replay_capacity(replay_capacity)?;
        Ok(Self {
            backend,
            offer,
            limits,
            session,
            negotiated: None,
            negotiation_request_id: 0,
            negotiation_body: [0; 32],
            replay: [ReplayEntry::EMPTY; REPLAY_SLOTS],
        })
    }

    /// Returns the selected capability set after negotiation.
    #[must_use]
    pub const fn negotiated(&self) -> Option<NegotiatedCapabilities> {
        self.negotiated
    }

    /// Returns the effective limits advertised by QueryAbi.
    #[must_use]
    pub const fn limits(&self) -> PortalLimits {
        self.limits
    }

    /// Returns the number of permanently occupied replay slots.
    #[must_use]
    pub fn replay_len(&self) -> usize {
        self.replay.iter().filter(|entry| entry.occupied).count()
    }

    /// Decodes one complete request and emits one complete terminal response.
    ///
    /// Envelope failures that prevent safe response correlation, invalid
    /// request header context, and output-buffer failures are returned locally
    /// as [`PortalWireError`]. Once a valid request envelope, opcode, and
    /// non-zero request id are known, body-shape, ordering, capability, replay,
    /// and backend failures are encoded as bounded [`MessageKind::Error`]
    /// responses.
    pub fn dispatch(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, PortalWireError> {
        let message = decode_message(input)?;
        if message.header.kind() != MessageKind::Request
            || message.header.flags() != HeaderFlags::EXPECT_REPLY
        {
            return Err(PortalWireError::new(PortalErrorCode::UnknownFlags, 10));
        }
        let request_id = message.header.request_id();
        let opcode = message.header.opcode();
        if request_id == 0 {
            return emit_failure(
                opcode,
                request_id,
                PortalFailure::new(PortalErrorCode::InvalidRequestId, RetryClass::Never, 0),
                output,
            );
        }

        if matches!(
            opcode,
            Opcode::QueryAbi | Opcode::QueryScope | Opcode::QueryEffect | Opcode::QueryReceipt
        ) && let Some(existing_opcode) = self.reserved_request_opcode(request_id)
        {
            return emit_failure(
                opcode,
                request_id,
                PortalFailure::new(
                    PortalErrorCode::Conflict,
                    RetryClass::Never,
                    u32::from(existing_opcode),
                ),
                output,
            );
        }

        match opcode {
            Opcode::QueryAbi => {
                if let Err(error) = QueryAbiRequest::decode_wire(message.body) {
                    return emit_wire_failure(opcode, request_id, error, output);
                }
                let response = AbiResponse::with_limits(self.offer, self.limits)?;
                emit_success(opcode, request_id, &response, output)
            }
            Opcode::Negotiate => self.dispatch_negotiate(request_id, message.body, output),
            opcode if opcode.is_mutation() => {
                self.dispatch_mutation(opcode, request_id, message.body, output)
            }
            Opcode::QueryScope | Opcode::QueryEffect | Opcode::QueryReceipt => {
                self.dispatch_query(opcode, request_id, message.body, output)
            }
            _ => Err(PortalWireError::new(PortalErrorCode::UnknownOpcode, 12)),
        }
    }

    fn dispatch_negotiate(
        &mut self,
        request_id: u64,
        body: &[u8],
        output: &mut [u8],
    ) -> Result<usize, PortalWireError> {
        if let Some(selected) = self.negotiated {
            if request_id == self.negotiation_request_id && body == self.negotiation_body {
                let response = NegotiatedResponse::new(self.session, selected)?;
                return emit_success(Opcode::Negotiate, request_id, &response, output);
            }
            return emit_failure(
                Opcode::Negotiate,
                request_id,
                PortalFailure::new(PortalErrorCode::Conflict, RetryClass::Never, 0),
                output,
            );
        }
        let request = match NegotiateRequest::decode_wire(body) {
            Ok(request) => request,
            Err(error) => {
                return emit_wire_failure(Opcode::Negotiate, request_id, error, output);
            }
        };
        let selected = match negotiate(self.offer, request.capabilities()) {
            Ok(selected) => selected,
            Err(error) => {
                return emit_failure(
                    Opcode::Negotiate,
                    request_id,
                    PortalFailure::new(error.code, RetryClass::Never, 0),
                    output,
                );
            }
        };
        self.negotiated = Some(selected);
        self.negotiation_request_id = request_id;
        self.negotiation_body.copy_from_slice(body);
        let response = NegotiatedResponse::new(self.session, selected)?;
        emit_success(Opcode::Negotiate, request_id, &response, output)
    }

    fn dispatch_query(
        &mut self,
        opcode: Opcode,
        request_id: u64,
        body: &[u8],
        output: &mut [u8],
    ) -> Result<usize, PortalWireError> {
        if let Err(failure) = self.require_capabilities(opcode) {
            return emit_failure(opcode, request_id, failure, output);
        }
        match opcode {
            Opcode::QueryScope => {
                let request = match QueryScopeRequest::decode_wire(body) {
                    Ok(request) => request,
                    Err(error) => return emit_wire_failure(opcode, request_id, error, output),
                };
                emit_backend_result(
                    opcode,
                    request_id,
                    self.backend.query_scope(self.session, request),
                    output,
                )
            }
            Opcode::QueryEffect => {
                let request = match QueryEffectRequest::decode_wire(body) {
                    Ok(request) => request,
                    Err(error) => return emit_wire_failure(opcode, request_id, error, output),
                };
                emit_backend_result(
                    opcode,
                    request_id,
                    self.backend.query_effect(self.session, request),
                    output,
                )
            }
            Opcode::QueryReceipt => {
                let request = match QueryReceiptRequest::decode_wire(body) {
                    Ok(request) => request,
                    Err(error) => return emit_wire_failure(opcode, request_id, error, output),
                };
                emit_backend_result(
                    opcode,
                    request_id,
                    self.backend.query_receipt(self.session, request),
                    output,
                )
            }
            _ => Err(PortalWireError::new(PortalErrorCode::UnknownOpcode, 12)),
        }
    }

    fn dispatch_mutation(
        &mut self,
        opcode: Opcode,
        request_id: u64,
        body: &[u8],
        output: &mut [u8],
    ) -> Result<usize, PortalWireError> {
        if request_id == self.negotiation_request_id {
            return emit_failure(
                opcode,
                request_id,
                PortalFailure::new(
                    PortalErrorCode::Conflict,
                    RetryClass::Never,
                    u32::from(Opcode::Negotiate.wire_value()),
                )
                .with_digests(mutation_digest(opcode, body), Digest::ZERO),
                output,
            );
        }

        if let Some(entry) = self
            .replay
            .iter()
            .copied()
            .find(|entry| entry.occupied && entry.request_id == request_id)
        {
            if body.len() <= MAX_MUTATION_BODY_SIZE && entry.matches(opcode, body) {
                return emit_cached(opcode, request_id, entry, output);
            }
            let failure = PortalFailure::new(
                PortalErrorCode::Conflict,
                RetryClass::Never,
                u32::from(opcode.wire_value()),
            )
            .with_digests(
                mutation_digest(opcode, body),
                mutation_digest(
                    Opcode::from_wire_value(entry.opcode).unwrap_or(opcode),
                    &entry.request[..usize::from(entry.request_length)],
                ),
            );
            return emit_failure(opcode, request_id, failure, output);
        }

        if body.len() > MAX_MUTATION_BODY_SIZE {
            return emit_wire_failure(
                opcode,
                request_id,
                PortalWireError::new(PortalErrorCode::BodySizeMismatch, body.len()),
                output,
            );
        }

        if let Err(failure) = self.require_capabilities(opcode) {
            return emit_failure(opcode, request_id, failure, output);
        }

        let Some(slot) = self.replay.iter().position(|entry| !entry.occupied) else {
            return emit_failure(
                opcode,
                request_id,
                PortalFailure::new(
                    PortalErrorCode::Backpressure,
                    RetryClass::NewSession,
                    REPLAY_SLOTS as u32,
                ),
                output,
            );
        };

        let (kind, response, response_length) = match self.execute_mutation(opcode, body) {
            Ok(encoded) => encoded,
            Err(error) => encode_failure(wire_failure(error))?,
        };
        let request_length = u16::try_from(body.len())
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, body.len()))?;
        let response_length_u16 = u16::try_from(response_length).map_err(|_| {
            PortalWireError::new(PortalErrorCode::BodySizeMismatch, response_length)
        })?;
        let mut request_bytes = [0; MAX_MUTATION_BODY_SIZE];
        request_bytes[..body.len()].copy_from_slice(body);
        self.replay[slot] = ReplayEntry {
            occupied: true,
            request_id,
            opcode: opcode.wire_value(),
            request_length,
            request: request_bytes,
            response_kind: kind.wire_value(),
            response_length: response_length_u16,
            response,
        };
        emit_raw(
            kind,
            opcode,
            request_id,
            &response[..response_length],
            output,
        )
    }

    fn execute_mutation(
        &mut self,
        opcode: Opcode,
        body: &[u8],
    ) -> Result<(MessageKind, [u8; MAX_RESPONSE_BODY_SIZE], usize), PortalWireError> {
        match opcode {
            Opcode::CreateScope => {
                let request = CreateScopeRequest::decode_wire(body)?;
                if let Err(failure) = self.require_session(request.session()) {
                    return encode_failure(failure);
                }
                encode_backend_result(self.backend.create_scope(request))
            }
            Opcode::Register => {
                let request = RegisterEffectRequest::decode_wire(body)?;
                if let Err(failure) = self.require_session(request.context().session()) {
                    return encode_failure(failure);
                }
                encode_backend_result(self.backend.register(request))
            }
            Opcode::Prepare => {
                let request = PrepareEffectRequest::decode_wire(body)?;
                if let Err(failure) = self.require_session(request.context().session()) {
                    return encode_failure(failure);
                }
                encode_backend_result(self.backend.prepare(request))
            }
            Opcode::Commit => {
                let request = CommitEffectRequest::decode_wire(body)?;
                if let Err(failure) = self.require_session(request.context().session()) {
                    return encode_failure(failure);
                }
                encode_backend_result(self.backend.commit(request))
            }
            Opcode::RecordOutcome => {
                let request = RecordOutcomeRequest::decode_wire(body)?;
                if let Err(failure) = self.require_session(request.context().session()) {
                    return encode_failure(failure);
                }
                encode_backend_result(self.backend.record_outcome(request))
            }
            Opcode::Complete => {
                let request = CompleteEffectRequest::decode_wire(body)?;
                if let Err(failure) = self.require_session(request.context().session()) {
                    return encode_failure(failure);
                }
                encode_backend_result(self.backend.complete(request))
            }
            Opcode::Revoke => {
                let request = RevokeScopeRequest::decode_wire(body)?;
                if let Err(failure) = self.require_session(request.context().session()) {
                    return encode_failure(failure);
                }
                encode_backend_result(self.backend.revoke(request))
            }
            _ => Err(PortalWireError::new(PortalErrorCode::UnknownOpcode, 12)),
        }
    }

    fn require_session(&self, session: SessionHandle) -> Result<(), PortalFailure> {
        if session != self.session {
            return Err(PortalFailure::new(
                PortalErrorCode::InvalidSession,
                RetryClass::Never,
                0,
            ));
        }
        Ok(())
    }

    fn require_capabilities(&self, opcode: Opcode) -> Result<(), PortalFailure> {
        let selected = self.negotiated.ok_or_else(|| {
            PortalFailure::new(
                PortalErrorCode::NegotiationRequired,
                RetryClass::AfterQuery,
                u32::from(opcode.wire_value()),
            )
        })?;
        let (portal, provider) = required_capabilities(opcode);
        if !selected.portal.contains(portal) || !selected.provider.contains(provider) {
            return Err(PortalFailure::new(
                PortalErrorCode::CapabilityNotNegotiated,
                RetryClass::Never,
                u32::from(opcode.wire_value()),
            ));
        }
        Ok(())
    }

    fn reserved_request_opcode(&self, request_id: u64) -> Option<u16> {
        if self.negotiated.is_some() && request_id == self.negotiation_request_id {
            return Some(Opcode::Negotiate.wire_value());
        }
        self.replay
            .iter()
            .find(|entry| entry.occupied && entry.request_id == request_id)
            .map(|entry| entry.opcode)
    }
}

fn required_capabilities(opcode: Opcode) -> (PortalCapabilities, ProviderCapabilities) {
    match opcode {
        Opcode::CreateScope => (
            PortalCapabilities::CREATE_SCOPE,
            ProviderCapabilities::empty(),
        ),
        Opcode::Register | Opcode::Prepare => (
            PortalCapabilities::EFFECT_LIFECYCLE,
            ProviderCapabilities::EFFECT_CLOSURE,
        ),
        Opcode::Commit => (
            PortalCapabilities::EFFECT_LIFECYCLE,
            ProviderCapabilities::EFFECT_CLOSURE
                | ProviderCapabilities::OUTCOME_RECORDING
                | ProviderCapabilities::EFFECT_COMPLETION,
        ),
        Opcode::RecordOutcome => (
            PortalCapabilities::EFFECT_LIFECYCLE,
            ProviderCapabilities::EFFECT_CLOSURE | ProviderCapabilities::OUTCOME_RECORDING,
        ),
        Opcode::Complete => (
            PortalCapabilities::EFFECT_LIFECYCLE,
            ProviderCapabilities::EFFECT_CLOSURE
                | ProviderCapabilities::OUTCOME_RECORDING
                | ProviderCapabilities::EFFECT_COMPLETION,
        ),
        Opcode::Revoke => (
            PortalCapabilities::REVOKE_SCOPE,
            ProviderCapabilities::EFFECT_CLOSURE,
        ),
        Opcode::QueryScope => (
            PortalCapabilities::QUERY_SCOPE,
            ProviderCapabilities::SESSION_QUERY,
        ),
        Opcode::QueryEffect => (
            PortalCapabilities::QUERY_EFFECT,
            ProviderCapabilities::SESSION_QUERY,
        ),
        Opcode::QueryReceipt => (
            PortalCapabilities::QUERY_RECEIPT,
            ProviderCapabilities::SESSION_QUERY,
        ),
        Opcode::QueryAbi | Opcode::Negotiate => {
            (PortalCapabilities::empty(), ProviderCapabilities::empty())
        }
    }
}

fn mutation_digest(opcode: Opcode, body: &[u8]) -> Digest {
    let offset = if opcode == Opcode::CreateScope {
        48
    } else {
        32
    };
    body.get(offset..offset + 32)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map_or(Digest::ZERO, Digest::from_wire_bytes)
}

fn encode_backend_result<T: ResponseBody>(
    result: Result<T, PortalFailure>,
) -> Result<(MessageKind, [u8; MAX_RESPONSE_BODY_SIZE], usize), PortalWireError> {
    let mut body = [0; MAX_RESPONSE_BODY_SIZE];
    match result {
        Ok(response) => {
            response.encode_wire(&mut body[..T::WIRE_SIZE])?;
            Ok((MessageKind::Response, body, T::WIRE_SIZE))
        }
        Err(failure) => {
            let response = ErrorResponse::new(failure);
            response.encode_wire(&mut body[..ErrorResponse::WIRE_SIZE])?;
            Ok((MessageKind::Error, body, ErrorResponse::WIRE_SIZE))
        }
    }
}

fn encode_failure(
    failure: PortalFailure,
) -> Result<(MessageKind, [u8; MAX_RESPONSE_BODY_SIZE], usize), PortalWireError> {
    let mut body = [0; MAX_RESPONSE_BODY_SIZE];
    let response = ErrorResponse::new(failure);
    response.encode_wire(&mut body[..ErrorResponse::WIRE_SIZE])?;
    Ok((MessageKind::Error, body, ErrorResponse::WIRE_SIZE))
}

fn emit_backend_result<T: ResponseBody>(
    opcode: Opcode,
    request_id: u64,
    result: Result<T, PortalFailure>,
    output: &mut [u8],
) -> Result<usize, PortalWireError> {
    match result {
        Ok(response) => emit_success(opcode, request_id, &response, output),
        Err(failure) => emit_failure(opcode, request_id, failure, output),
    }
}

fn emit_success<T: ResponseBody>(
    opcode: Opcode,
    request_id: u64,
    response: &T,
    output: &mut [u8],
) -> Result<usize, PortalWireError> {
    let mut body = [0; MAX_RESPONSE_BODY_SIZE];
    response.encode_wire(&mut body[..T::WIRE_SIZE])?;
    emit_raw(
        MessageKind::Response,
        opcode,
        request_id,
        &body[..T::WIRE_SIZE],
        output,
    )
}

fn emit_failure(
    opcode: Opcode,
    request_id: u64,
    failure: PortalFailure,
    output: &mut [u8],
) -> Result<usize, PortalWireError> {
    let response = ErrorResponse::new(failure);
    let mut body = [0; ErrorResponse::WIRE_SIZE];
    response.encode_wire(&mut body)?;
    emit_raw(MessageKind::Error, opcode, request_id, &body, output)
}

fn wire_failure(error: PortalWireError) -> PortalFailure {
    PortalFailure::new(
        error.code(),
        RetryClass::Never,
        u32::try_from(error.offset()).unwrap_or(u32::MAX),
    )
}

fn emit_wire_failure(
    opcode: Opcode,
    request_id: u64,
    error: PortalWireError,
    output: &mut [u8],
) -> Result<usize, PortalWireError> {
    emit_failure(opcode, request_id, wire_failure(error), output)
}

fn emit_cached(
    opcode: Opcode,
    request_id: u64,
    entry: ReplayEntry,
    output: &mut [u8],
) -> Result<usize, PortalWireError> {
    let kind = MessageKind::from_wire_value(entry.response_kind).ok_or_else(|| {
        PortalWireError::new(
            PortalErrorCode::InternalInvariant,
            entry.response_kind as usize,
        )
    })?;
    let length = usize::from(entry.response_length);
    emit_raw(kind, opcode, request_id, &entry.response[..length], output)
}

fn emit_raw(
    kind: MessageKind,
    opcode: Opcode,
    request_id: u64,
    body: &[u8],
    output: &mut [u8],
) -> Result<usize, PortalWireError> {
    let header = MessageHeader::new(kind, opcode, HeaderFlags::FINAL, request_id)?;
    encode_message(header, body, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_opcode_has_the_intended_capability_gate() {
        let cases = [
            (
                Opcode::QueryAbi,
                PortalCapabilities::empty(),
                ProviderCapabilities::empty(),
            ),
            (
                Opcode::Negotiate,
                PortalCapabilities::empty(),
                ProviderCapabilities::empty(),
            ),
            (
                Opcode::CreateScope,
                PortalCapabilities::CREATE_SCOPE,
                ProviderCapabilities::empty(),
            ),
            (
                Opcode::QueryScope,
                PortalCapabilities::QUERY_SCOPE,
                ProviderCapabilities::SESSION_QUERY,
            ),
            (
                Opcode::QueryEffect,
                PortalCapabilities::QUERY_EFFECT,
                ProviderCapabilities::SESSION_QUERY,
            ),
            (
                Opcode::QueryReceipt,
                PortalCapabilities::QUERY_RECEIPT,
                ProviderCapabilities::SESSION_QUERY,
            ),
            (
                Opcode::Register,
                PortalCapabilities::EFFECT_LIFECYCLE,
                ProviderCapabilities::EFFECT_CLOSURE,
            ),
            (
                Opcode::Prepare,
                PortalCapabilities::EFFECT_LIFECYCLE,
                ProviderCapabilities::EFFECT_CLOSURE,
            ),
            (
                Opcode::Commit,
                PortalCapabilities::EFFECT_LIFECYCLE,
                ProviderCapabilities::EFFECT_CLOSURE
                    | ProviderCapabilities::OUTCOME_RECORDING
                    | ProviderCapabilities::EFFECT_COMPLETION,
            ),
            (
                Opcode::RecordOutcome,
                PortalCapabilities::EFFECT_LIFECYCLE,
                ProviderCapabilities::EFFECT_CLOSURE | ProviderCapabilities::OUTCOME_RECORDING,
            ),
            (
                Opcode::Complete,
                PortalCapabilities::EFFECT_LIFECYCLE,
                ProviderCapabilities::EFFECT_CLOSURE
                    | ProviderCapabilities::OUTCOME_RECORDING
                    | ProviderCapabilities::EFFECT_COMPLETION,
            ),
            (
                Opcode::Revoke,
                PortalCapabilities::REVOKE_SCOPE,
                ProviderCapabilities::EFFECT_CLOSURE,
            ),
        ];

        for (opcode, portal, provider) in cases {
            assert_eq!(required_capabilities(opcode), (portal, provider));
        }
    }
}
