# Generational readiness and positive-timeout CSER refinement

`PersonalityReadinessCser.tla` fixes the bounded Stage 6B.2 protocol below an
epoll-like ABI. It is a successor over the personality-local common effect
registry, not an implementation of Linux file descriptors or `epoll(7)`.

The checked model contains one authority scope, one readiness source, one
ready set, one persistent subscription, one blocking wait, and one positive
timeout timer. It exercises level-triggered, edge-triggered, and one-shot
delivery; source-service restart; crash/snapshot/ready/rebind/adopt; immutable
publication receipts; watchdog-backed closure; and all three possible winners
of the wait race:

```text
ReadyCommit   -> one frozen nonempty delivery
TimeoutCommit -> one frozen empty timeout delivery
RevokeBegin   -> no delivery can subsequently commit
```

`ReadyCommit`, `TimeoutCommit`, and `RevokeBegin` all require the same active
authority gate. This is the central linearization contract.

## Rust refinement mapping

The executable successor is
`crates/cser-model/src/personality/readiness.rs`. It refines lifecycle,
identity, credit, and recovery operations through
`personality::registry::EffectRegistry` while retaining readiness-specific
source, queue, trigger, and receipt state.

| PlusCal state | Safe-Rust refinement |
| --- | --- |
| `scopeState`, `authorityEpoch` | common registry scope gate |
| `bindingEpoch`, `serviceAlive`, fallback state | registry binding token and crash/fallback lifecycle |
| `sourceGeneration`, `sourceSequence`, `sourceReady` | stable `ReadySourceId` plus generational `SourceRecord` |
| subscription state, mode, generation, and `queued` | generational `ReadinessSubscriptionToken`, `SubscriptionRecord`, queue and membership index |
| wait and timer state | paired `ReadinessWaitToken` registry effects |
| `winner` and frozen source fields | immutable `ReadyDeliveryReceipt` and ordered `ReadyEvent` batch |
| typed free credits and watchdog ownership | `RegistryBudget`, typed registry effects, and recovery-watchdog reserve |
| recovery snapshot and cohort | exact `ReadinessRecoverySnapshot`, registry ready proof, and explicit per-effect adoption |

The Rust model is intentionally broader in a few sequential dimensions: it can
hold more than one subscription and wait, accepts a bounded `max_events`, and
tracks readable and writable masks. The TLA+ instance deliberately collapses
those dimensions to one source, subscription, event, wait, and timeout so the
complete interleaving graph remains tractable.

## Atomic sample-and-arm and trigger modes

`attach` samples the source and registers a persistent subscription as one
failure-atomic transition. `wait_register` similarly installs the blocking
wait and its strictly positive timer together; if timer credit is unavailable,
the registry checkpoint restores the wait identity, reverse indexes, blocked
task slot, and credits.

Source updates carry both a stable source ID and a service generation. A
restart advances that generation, clears the ready mask and queue, and fences
late updates from the previous source service. Subscription modification
advances a separate subscription generation, so a stale token cannot modify or
publish a replacement subscription.

Selection follows these disciplines:

- level-triggered subscriptions remain queued while the sampled bits remain
  ready;
- edge-triggered subscriptions queue only after a not-ready to ready edge;
- one-shot subscriptions disable when their event is frozen and require an
  explicit generational modification before another delivery.

The ready commit freezes subscription/source generations, source sequence,
observed bits, cookie, ordering, and event count. Later source updates cannot
rewrite the receipt. Publication consumes the paired wait and timer exactly
once; replay of the same receipt is rejected without mutation.

## Unique winner and closure

A pending wait and its timer are committed as one batch. Whichever of ready or
timeout commits first owns the immutable receipt; the other transition is no
longer enabled. If `RevokeBegin` closes the authority gate first, neither can
commit. The Rust API exposes `Ready` and `TimedOut` receipts only; revoke is the
absence of a delivery and is terminalized by registry closure rather than a
fabricated timeout result.

Committed ready/timeout work is kernel-published and drained even when closure
has started. Uncommitted waits, timers, and live subscriptions abort through
scope-local reverse indexes. `RevokeComplete` requires the queue to be empty,
all domain work terminal, the crash cohort and watchdog cleared, and all
subscription/wait/timer credits returned.

## Crash, snapshot, and rebind

`Crash` advances the binding epoch and captures every live subscription, wait,
and timer in the recovery cohort. Kernel fallback must run before a prospective
replacement can capture an exact registry plus readiness-domain snapshot.
`Ready` proves that the binding, registry revision, source generation and
sequence, ready mask, queue, subscriptions, waits, and selected winner still
match that image.

Any source transition or other readiness-domain mutation advances the common
registry recovery revision. Consequently, a source update after snapshot makes
the snapshot stale, and a source update after `Ready` makes the ready proof
unusable at `Rebind`; the replacement must capture and validate a new image.
Successful rebind adopts nothing implicitly. The replacement must explicitly
adopt each old-binding subscription, wait, and timer before personality-owned
commit can proceed. In particular, current-binding wait and timer tokens cannot
select a still-old-binding queued subscription. Rust validates every selected
subscription before freezing a receipt, and the TLA+ `ReadyCommit` guard plus
`ReadyCommitUsesCurrentBinding` action property check the same fence. Old
bindings and old source generations reject without a semantic side effect.

## Checked properties and witnesses

Both configurations check:

- `BudgetConservation` for the subscription, wait, positive timer, and recovery
  watchdog credits;
- `SingleWinner` and immutable ready/timeout receipts;
- level/edge/one-shot trigger discipline;
- `PostRevokeCommitExclusion`;
- exact snapshot/ready discipline;
- conditional `QuiescentClosure`.

The reject-enabled graph additionally checks stale-source rejection with
`RejectSideEffectFreedom`. The action/liveness graph checks weak-fair kernel
fallback, committed publication, and closure progress. No environment action
is made fair.

With the pinned Nexus TLA+ image and 16 TLC workers, the complete runs are:

```text
reject-enabled safety:
  83,586 states generated
  50,544 distinct states
  complete graph depth 20

action/liveness:
  55,569 states generated
  34,428 distinct states
  complete graph depth 19
  3 temporal branches over 103,284 total distinct branch states
```

Eight reachability checks require concrete ready, positive-timeout, and revoke
winners; crash/adopt/commit recovery; level-triggered requeue; one-shot
disablement; stale source-generation rejection; and a replacement whose
current-binding wait/timer cannot select an unadopted old-binding subscription.

The Rust successor contributes six deterministic sequence tests and one
bounded proptest. They cover frozen LT/ET/ONESHOT batches, source and
subscription generations, snapshot and ready-proof invalidation, explicit
adoption and selection fencing, all three winner orders, publication replay,
failure-atomic paired registration, single terminalization, and final
typed-credit closure.

## Run

From the repository root, the normal pinned-container gate is:

```sh
./x spec
```

Inside the development container, run only this family with:

```sh
TLA2TOOLS_JAR=/opt/tla2tools/tla2tools.jar \
  ./specs/cser/check.sh PersonalityReadinessCser
```

Edit only the PlusCal algorithm and regenerate its committed translation with
`pcal.trans -nocfg -lineWidth 10000` before checking.

## Boundary

The checked instance deliberately excludes:

- a Linux fd table, `epoll_ctl`/`epoll_wait` decoding, fd reuse, close, dup, or
  fork semantics;
- more than one modeled source, subscription, ready event, wait, or positive
  timeout;
- real clock progression, Linux timeout conversion, signals, cancellation,
  and restartable-syscall ABI details;
- readiness producers backed by a runtime filesystem or network stack;
- SMP queue locking, wakeup memory ordering, and lost-wakeup proof;
- a registry shared with scheduler, pager, mediated I/O, or other services.

The independent OSTD epoll/readiness receipt now refines this contract for its
bounded workload, but it does not widen these formal limits or complete the
runtime filesystem/network stages.
