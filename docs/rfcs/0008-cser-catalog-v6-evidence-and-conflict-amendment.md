# RFC 0008: CSER catalog v6 evidence and conflict amendment

- Status: **Implemented; catalog-v6 development QEMU proof captured**
- Decision date: 2026-08-04
- Amends: [RFC 0007](0007-cser-composite-effect-custody.md)

## Decision

The profile-2 standard catalog advances from v5 to v6. Catalog v6 adds the
typed retirement-evidence capability and recovery declarations, and each claim
class declares its conflict mode. These fields, including the conflict and
evidence compatibility rules they select, are covered by the catalog digest.
The digest domain separator advances from `nexus.cser.domain-catalog.v5` to
`nexus.cser.domain-catalog.v6`.

The core API profile remains 2; the journal envelope remains `CSERJR6\0` /
schema 6; projection remains v6; and recovery snapshots remain v2. This is a
catalog-contract evolution, not a claim that an old catalog has the new
semantics.

The builder-validation tightening is therefore a catalog-contract
incompatibility indexed by `STANDARD_CATALOG_VERSION` and the catalog digest,
not a journal transition or core API-profile change. A custom catalog rebuilt
under v6 receives a new digest; a journal bound to its prior digest fails
closed under current recovery.

## Catalog-v6 rules

`Shared` custody is compatible only with `Shared` custody. Admission compares
the incoming claim class with every live custodian on the exact
resource-generation coordinate; an `Exclusive` incumbent therefore rejects a
later `Shared` enrollment, and conversely. The same pairwise rule is checked as
an engine invariant across both the estate and composite resource indexes. A
shared coordinate becomes reusable only after its final custodian discharges.

`Shared` is an implemented extension point, not a standard-profile feature:
the current production catalog declares only `Exclusive` claim classes. Credit
accounting intentionally charges each live shared custodian separately. It
measures retained custody obligations and admission pressure, rather than
deduplicated physical occupancy of a shared coordinate.

An obligation whose policy is `RetirementEvidence` may name an optional claim
as well as a required claim. Every such referenced claim class must nonetheless
be device-scoped, declare at least one quiescence-capable rule, and require
crash-recoverable evidence for every conjunct in its retirement conjunction.
Outcome evidence alone, or an ephemeral conjunct beside quiescence, is not a
valid automatic retirement contract. Capability and recovery classify a catalog
rule and participate in its digest; they do not directly advance the runtime
logical-outcome axis. Verified effect facts and settlement transitions continue
to do that separately.

Unknown or unsupported evidence is core-wide fail-closed in v6. It preserves
the claim, its charge, and the resource gate, and it cannot authorize reuse.
There is no per-class unknown-evidence disposition algebra and no automatic
administrative override in this catalog contract.

`check_co_claimable` is a read-only advisory precheck, never enrollment
authority. It evaluates catalog-bound coordinate compatibility, scope,
generation, and quarantine; the durable enrollment transition remains the sole
authority for actor fencing, cardinality, credits, and races.

## Compatibility and recovery

Current recovery is bound to the trusted anchor's exact current catalog digest.
A schema-6 journal or anchor bearing the frozen v5 catalog digest is rejected
fail-closed as a schema mismatch before replay under v6. There is no automatic
catalog-v5-to-v6 migration, reinterpretation, dual authority, or reuse-permit
translation path. Operators must retain quarantine until they establish an
explicit operational disposition outside the core state machine.

The existing `CSERJR5\0` schema-5 rule in RFC 0007 remains unchanged.

## Current evidence binding

The current development artifact is
`kernel/nexus-ostd/artifacts/cser-production/combined-proof.txt`. It records
four fresh QEMU boots with catalog v6 and journal schema 6, exact generation
`1 -> 2` reuse, stable repeated recovery, and zero retained claims at boot 4.
Its receipt SHA-256 is
`99b2f5694a7340df6d4fab0cc08c22336f9ba7b6a8f6b32a797009c962ed94d4`.

The receipt is deliberately `NONSEALABLE` because it binds the current dirty
development tree rather than a committed release revision. It remains a valid
execution result, not a release seal. It also records the negative physical
boundaries explicitly: no physical-hardware, host-PFN-identity, physical DMA
drain, physical anti-rollback, or physical power-loss claim. Older catalog-v5
artifacts remain available through Git; this RFC imposes no append-only
preservation or compatibility ceremony.
