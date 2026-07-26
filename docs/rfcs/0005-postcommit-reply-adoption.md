# RFC 0005: post-commit reply adoption across service crash

- Status: **Draft / prospective research contract**
- Target: the Adopt-vs-Abort successor of the post-commit closure lane
- Supersedes: nothing; narrows one obligation left open by
  [RFC 0001](0001-production-identity.md)
- Changes accepted `v0.1.0` claims: **no**

## Claim discipline

This RFC defines a hypothesis and the evidence that would be required to test
it. Nothing in it is implemented, checked, or observed at the time of writing.
The words **adopt**, **exactly once**, **fenced**, and **retained** below name
prospective acceptance requirements, not capabilities. No result from this RFC
may be attributed to `v0.1.0` or to the bounded post-commit closure checkpoint,
and neither of those may be relabeled as evidence for this RFC.

## Starting point

Three pieces of accepted or checkpointed work bound this RFC's starting state:

1. The pre-commit crash lanes: filesystem-service crash before device commit,
   `fsd-v1` to `fsd-v2` snapshot/ready/rebind/explicit-adopt, and the
   precommit revoke-wins lane (`status/current-capabilities.toml`).
2. The post-commit **closure** lane
   (`kernel/nexus-ostd/src/personality/linux_fs_postcommit.rs`, model source
   `crates/cser-model/src/production_identity_postcommit.rs`, evidence binding
   `tools/xtask/src/production_identity_postcommit.rs`): after the backend
   result exists but before guest reply publication, a service crash is
   resolved by a dedicated v3 *closure trigger*. That trigger is deliberately
   Registry-free — it never owns a service incarnation and therefore cannot
   snapshot, rebind, adopt, recommit, or replace the crashed v2 service. The
   flight closes with honest retention; the client observes an indeterminate
   result.
3. The bounded bearer and replay lanes of
   [RFC 0004](0004-bounded-authority-replay.md): one-shot reply authority,
   slot-bounded outstanding operations, and retained completed results that
   move with the object they protect.

The engineering decision order in
`docs/research/engineering-reuse-map.md` (section 4) already names this step:
first close the real post-commit crash cells, "then repeated crash,
Adopt-vs-Abort, late completion". This RFC is the Adopt-vs-Abort contract.

## Problem

In the window after device commit and before guest reply publication, the
crashed incarnation's obligation is asymmetric: the device-side effect is
already irreversible and its result digest is retained under root ownership,
but the client-side publication has not happened. The landed closure lane
resolves this window safely but lossily — the retained result exists, yet the
client learns only `indeterminate`.

The hypothesis: a **replacement service incarnation** can explicitly adopt the
retained committed flight and publish the guest reply **exactly once**,
without widening any authority, without racing a stale reply from the dead
incarnation, and without breaking the revoke-wins guarantee — and when
adoption is not possible, the lane must degrade to the existing closure
tombstone rather than block, deadlock, or double-publish.

If this holds, it sharpens the project's one recorded differentiator against
Shadow Drivers: instead of choosing between replay (duplication risk) and
cancel (loss), the recovered system either completes the exact retained
publication once or reports an honest indeterminate closure.

## Obligations

Each obligation must be independently testable and must fail loudly when
violated.

1. **Retention without loss.** The committed device flight — its causal
   identity (cookie, publication ticket, root effect ancestry) and result
   digest — survives the v2 crash under root ownership, with its typed
   credits held, until exactly one terminal disposition is chosen.
2. **One-shot publication exclusivity.** Guest reply publication remains a
   one-shot gate. Exactly one of {successor adoption reply, tombstone
   closure} terminalizes the flight. Never both, never twice, on every
   interleaving.
3. **Stale-incarnation fencing.** A reply attempt carrying the crashed
   incarnation's binding epoch after the fence must be rejected without side
   effect, and the rejection must leave the retained flight's observation
   byte-identical.
4. **Explicit, exact adoption.** The successor presents the exact causal
   identity of the retained flight. Silent inheritance remains forbidden;
   a wrong cookie, ticket, ancestry, or digest is a rejection, not a
   fallback.
5. **Revoke-wins.** `RevokeBegin` racing the adoption window serializes
   through the same gate. If revocation wins, the flight closes through the
   tombstone lane with the reply gate reported closed; if adoption wins,
   closure accounts for the published reply. Both winners must be reachable
   and witnessed.
6. **Repeated crash degrades, not deadlocks.** If the successor itself
   crashes before publishing, the lane must degrade to the closure trigger.
   This is the first cell that requires a second binding generation
   (`MaxBinding = 2` in the model families, which today admit exactly one
   crash generation); the state-space cost must be measured and disclosed.
7. **Credit conservation and exact receipts.** Every path — adopt, tombstone,
   revoke-wins, repeated crash — balances typed credits and emits exact
   closure receipts, matching the existing receipt discipline.

## Evidence plan

Model-first ordering, matching the sequence used for the closure lane.

- **Phase A — Rust oracle.** Extend
  `crates/cser-model/src/production_identity_postcommit.rs` (or a sibling
  module) with adoption operations and typed errors for obligations 1–7,
  plus property tests and Loom harnesses for the adopt / stale-reply /
  revoke interleavings of the one-shot gate.
- **Phase B — specification.** A successor TLA+ family (working name
  `PostcommitAdoptionCser`) with safety invariants for obligations 2, 3, 5,
  and 7, reachability witnesses for *both* gate winners, and a
  `MaxBinding = 2` configuration for the repeated-crash cell. If the second
  binding generation is not tractable in one graph, the partition must be
  declared in the config and README, exactly as the composition families
  declare their scenario modes.
- **Phase C — kernel lane.** A one-vCPU OSTD/QEMU slice extending the
  existing post-commit fault feature: `fsd-v2` crashes post-commit; a full
  `fsd-v3` incarnation (unlike the current Registry-free trigger)
  snapshots, readies, rebinds, and explicitly adopts the retained flight;
  exactly one guest reply is published; serial receipts and awk assertions
  witness the fence rejecting a stale v2 reply and the revoke-wins variant.
- **Phase D — evidence binding.** An xtask evidence module mirroring
  `production_identity_postcommit.rs`: frozen case population, exact
  receipt parsing, and boundary flags stating what the lane does not
  establish.

## Stop and pivot conditions

- If the one-shot reply gate cannot be expressed without granting the
  successor authority before the fence is proven, stop, keep the closure
  lane as the only post-commit disposition, and record the failure as a
  negative result.
- If retaining flight identity across incarnations requires growing the
  OSTD patch boundary beyond the existing hash-bound overlay, record the
  limit as a negative boundary in the Stage 5B style rather than widening
  the patch silently.
- If `MaxBinding = 2` is intractable even in a partitioned scenario mode,
  ship the single-generation adoption cells, declare the repeated-crash
  cell unclosed, and leave obligation 6 explicitly open.

## Non-goals

No SMP or multi-vCPU observation, no real IRQ delivery, no host-reboot
recovery, no durable-write rollback, no performance thresholds, and no
change to any `v0.1.0` claim. Adjacent normal-completion evidence cannot
substitute for any cell defined here.
