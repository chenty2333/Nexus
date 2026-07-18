// SPDX-License-Identifier: MPL-2.0

//! Bounded native ABI for the `nexus.portal.v2` preview.
//!
//! This crate defines byte layout, bounded dispatch, and fail-closed validation.
//! It does not grant authority or contain a kernel backend: a decoded selector,
//! epoch, digest, or opaque handle must still be checked by an adapter against
//! its authoritative Registry before any mutation occurs.  The adapter belongs
//! in a crate that depends on this ABI and the Registry; this provider-neutral
//! crate must not depend on kernel or reference-model types.
//!
//! The ABI is allocation-free, fixed little-endian, and suitable for both
//! `no_std` kernel code and host-side conformance tools.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod capability;
pub mod digest;
pub mod dispatcher;
pub mod error;
pub mod handle;
pub mod lifecycle;
pub mod message;
pub mod request;
pub mod response;

pub use capability::{
    BASE_PORTAL_CAPABILITIES, CapabilityNegotiationError, CapabilityOffer, CapabilityRequest,
    NegotiatedCapabilities, PortalCapabilities, ProviderCapabilities, negotiate, negotiate_then,
    provider_capability_closure,
};
pub use digest::{DIGEST_SIZE, Digest};
pub use dispatcher::{PortalBackend, PortalDispatcher};
pub use error::{PortalErrorCode, PortalWireError};
pub use handle::{EffectHandle, HANDLE_SIZE, ReceiptHandle, ScopeHandle, SessionHandle};
pub use lifecycle::{
    CommitEffectRequest, CompleteEffectRequest, CompletionDisposition, CreditKind,
    MAX_CREDIT_UNITS_PER_EFFECT, MutationContext, OutcomeKind, PrepareEffectRequest,
    RecordOutcomeRequest, RegisterEffectRequest, RegisterFlags, RevokeReason, RevokeScopeRequest,
};
pub use message::{
    BASE_HEADER_SIZE, HEADER_MAGIC, HeaderFlags, MAX_BODY_SIZE, MAX_HEADER_SIZE, MAX_MESSAGE_SIZE,
    MessageHeader, MessageKind, Opcode, PortalMessage, VERSION_MAJOR, VERSION_MINOR,
    decode_message, encode_message,
};
pub use request::{
    CreateScopeFlags, CreateScopeRequest, MAX_EFFECTS_PER_SCOPE, MAX_PAGE_CREDITS_PER_SCOPE,
    MAX_QUEUE_CREDITS_PER_SCOPE, MAX_TOMBSTONES_PER_SCOPE, NegotiateRequest, QueryAbiRequest,
    QueryEffectRequest, QueryReceiptRequest, QueryScopeRequest, RequestBody,
};
pub use response::{
    AbiResponse, ClosureReceipt, ClosureStatus, EffectObservation, EffectOutcomeObservation,
    EffectPhase, ErrorResponse, LifecycleFlags, LifecycleReceipt, MAX_MUTATION_BODY_SIZE,
    MAX_RESPONSE_BODY_SIZE, NegotiatedResponse, PortalFailure, PortalLimits, ReceiptKind,
    ReceiptObservation, ReceiptStatus, ResponseBody, RetryClass, ScopeCreatedResponse,
    ScopeObservation, ScopePhase,
};
