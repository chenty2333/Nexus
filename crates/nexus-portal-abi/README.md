# `nexus-portal-abi`

`nexus-portal-abi` is the bounded, `no_std`, provider-neutral wire contract for
the `nexus.portal.v2` preview. It defines fixed little-endian messages, opaque
handles, explicit authority and binding epochs, non-zero request and receipt
digests, capability negotiation, typed errors, lifecycle requests, bounded
observations, closure receipts, and an allocation-free dispatcher.

## Current boundary

This crate is an ABI component, not a claim that the Nexus kernel is wired to
portal v2. It contains no Registry, device, supervisor, or kernel types. A
decoded handle, epoch, digest, or session is only a selector until a backend
validates it against one authoritative Registry. The dependency direction must
remain:

```text
kernel portal / provider adapter -> nexus-portal-abi
kernel portal / provider adapter -> authoritative Registry
```

`nexus-portal-abi` must not depend on either the kernel or the reference model.

`PortalDispatcher` owns only protocol concerns: negotiate before mutation,
check selected capabilities and the negotiated session, decode exact bounded
bodies, and retain a fixed non-evicting replay record. A successfully
negotiated request ID and every replay-admitted mutation ID become durable for
the session. An exact admitted-mutation retry returns the original encoded
success or error without invoking the backend again; reusing that durable ID
with different bytes returns `Conflict`. Replay exhaustion returns
`Backpressure` with `RetryClass::NewSession` before a backend mutation because
entries never become reusable in the current session. Negotiation rejections
and failures before mutation replay admission are not cached.

Provider negotiation is dependency-closed. `EFFECT_COMPLETION` implies
`OUTCOME_RECORDING`, which in turn implies `EFFECT_CLOSURE`; an offer that omits
one of those advertised prerequisites is rejected. Register and prepare remain
available to a core-closure-only provider, but `Commit` requires the full
completion/outcome/closure chain. Consequently no successfully committed
effect can be stranded solely because its negotiated session lacks an outcome
or completion transition. `Complete` explicitly checks all three bits.

`QueryAbi` and `Query*` IDs are ephemeral correlation IDs and their results are
not replay-cached. They may be reused after a terminal response, but they may
not collide with a durable negotiation or mutation ID. This keeps read-only
traffic out of the finite mutation replay cache without allowing one durable ID
to name different responses.

Malformed framing for which no request can be trusted, invalid request-header
context, and output-buffer failures return local `PortalWireError`. Once a
valid request envelope, known opcode, `EXPECT_REPLY`, and non-zero request ID
are available, malformed fixed bodies are returned as bounded typed error
responses. A malformed mutation admitted to the replay cache reserves its ID
just like a backend success or error.

## Backend integration points

A future higher-level adapter implements `PortalBackend` by translating each
validated ABI request into one authoritative Registry operation:

| Portal method | Required adapter responsibility |
| --- | --- |
| `create_scope` | Allocate a bounded scope and atomically install its identity, epochs, limits, and creation receipt. |
| `register` | Validate scope authority and the explicit `Queue` or `Page` credit charge, then install immutable effect identity and ancestry. |
| `prepare` | Enforce the registered-to-prepared transition and return the authoritative receipt. |
| `commit` | Validate authority, binding, and domain revision before crossing the commit publication boundary. |
| `record_outcome` | Attach one canonical committed outcome without duplicating backend work. |
| `complete` | Consume the permitted terminal transition and release only owners proven safe to release. |
| `revoke` | Freeze the authority epoch and return honest closure or retained-owner state. |
| `query_scope` | Validate the explicit dispatcher session argument, then project the current bounded scope state, including the raw provider-domain revision, from the Registry. |
| `query_effect` | Validate the explicit dispatcher session argument, then project the current effect phase, holistic outcome `(kind, result, digest)`, receipt, and digests. |
| `query_receipt` | Validate the explicit dispatcher session argument and project a typed, linearly consumed receipt. |

The kernel portal should own the dispatcher session and replay storage for the
lifetime it promises. Adapter methods remain responsible for lifecycle order,
generation checks, ancestry, quotas, durable receipts, and all device or
supervisor semantics.

For the preview adapter, `max_effects` is a lifetime selector bound covering
both live effects and their terminal records. `max_tombstones` separately caps
how many of those records may be terminal at once. There is no tombstone
retirement opcode in v2 yet, so exhausting either bound is permanent for that
scope/session and returns typed backpressure before Registry mutation. Queue
and page credits are distinct ledgers; capacity in one pool can never satisfy
or mask exhaustion in the other.

`RegisterEffectRequest` remains 112 bytes: the former four-byte reserved tail is
now a two-byte `CreditKind` plus a two-byte zero-reserved tail. The assigned
credit kinds are `Queue = 1` and `Page = 2`; zero and unassigned values fail
closed. `AbiResponse` is 80 bytes and reports the endpoint's effective finite
scope, effect-selector, per-scope effect/tombstone, typed-credit, receipt, and
mutation-replay limits; the dispatcher clamps the backend report to its actual
const-generic replay table. These effective limits may be smaller than the
protocol request maxima. `ScopeObservation` is 120 bytes after adding `domain_revision`.
`EffectObservation` is 216 bytes and carries an all-or-nothing outcome tuple,
an optional terminal manifest digest, and exact request/state digest positions.
The zero outcome discriminant requires zero result and digest. Completed
observations require an outcome and reject `Indeterminate`; retained
observations may honestly carry no outcome yet. A terminal manifest digest is
optional because some terminal Registry records do not carry one, but a
non-terminal observation may never expose one.

## Recovery limit

The current query operations are explicitly session-local. They do not provide
persistent recovery, crash adoption, device tombstone recovery, or cross-boot
freshness. Those capabilities require a higher-level adapter and durable
Registry records; they must not be inferred from the presence of query opcodes.

## Verification

The contract tests pin framing, numeric discriminants, fixed sizes, golden wire
vectors, phase/outcome/terminal matrices, partial-outcome rejection, exact
digest offsets, the complete provider-capability subset matrix, malformed-body
rejection, negotiation ordering, selected-capability checks, exact retry,
conflicting retries, cached backend errors, lifecycle ordering, bounded replay
pressure, and session mismatch behavior.
