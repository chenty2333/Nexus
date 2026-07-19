# Nexus supervisor manager

`nexus-supervisor` is the `no_std` lifecycle state machine for one independently
restartable Nexus service domain. The manager core introduces no allocation;
a concrete backend may use platform-owned storage. The crate defines ordering
and failure semantics, but does not create OSTD tasks or mutate the Registry by
itself.

## Authority and lifecycle

The kernel integration owns one `SupervisorManager<B>`. After construction,
the backend `B` is private to that manager; the production API exposes only a
narrow `SupervisorHealth` projection, not a backend reference. A service task
receives an identity, a manager-selected binding epoch, and a Ready deadline.
Those values let the task name an event; they do not let the task call
`rebind`, choose a recovery cohort, or adopt an effect.

The manager enforces this sequence:

```text
Running
  -- crash_active --> Backoff
  -- select + construct unpublished + recovery_snapshot --> AwaitingReady
  -- state/snapshot/deadline installed --> publish replacement
  -- ready(snapshot) --> rebind(replacement)
  -- bounded peek + adopt of the exact snapshot cohort --> Running

AwaitingReady / rebound recovery failure
  -- request cooperative cancellation --> Stopping
  -- exact reaped event + cleanup --> Backoff
  -- stop deadline expires --> Quarantined(retained task)
```

`crash_active` must fence the old binding and return the exact frozen cohort.
The manager calculates the replacement's binding epoch and inclusive Ready
deadline once and passes both to `construct_replacement` in
`ReplacementLaunch`; the backend must not derive either value from a second
clock or policy copy. Construction creates an unpublished task which cannot
run. The subsequent snapshot must name the same cohort. The manager then
installs `AwaitingReady`, including the exact snapshot and deadline, before it
calls `publish_replacement`. An immediate Ready or exit may therefore be
enqueued by publication without racing an absent manager state. The adapter
must serialize event delivery through one manager-owning worker and must not
re-enter the manager from the publish call.

`Ready` is accepted at the inclusive deadline and rejected when
`now > deadline_tick`. Adoption begins only after Ready validation and a
matching rebind observation. An inventory that is shorter or longer than the
frozen cohort is fenced rather than exposed as Running.

Failures before publication discard the unpublished task synchronously and
abort its attempt-local snapshot. Once published, the manager never claims a
task was stopped synchronously. It enters `Stopping`, issues an idempotent
cooperative cancellation request, and waits for a separately ordered exact
reaped event before aborting snapshot state and retrying. Failures after rebind
first call `crash_active` so partial adoption is fenced and the complete live
cohort is recaptured, then use the same cooperative stop/reap gate. A stop
deadline is inclusive; expiry isolates Registry authority and retains the
exact unreaped task identity for operator or retained-worker cleanup.

Every transition into `Quarantined` first invokes the backend's mandatory,
synchronous `isolate_authority` primitive. It revokes the service's
control-plane binding and partially adopted authority while retaining effects
and recovery records for inspection. `SupervisorHealth` exposes both a stable
`TerminalFailure` (without backend-specific payloads) and an optional
`retained_task`. Cleanup failure, an invalid epoch/cohort observation, counter
overflow, exhausted attempt budget, or stop timeout therefore cannot leave a
child with usable Registry authority or make an unreaped task invisible.

`AuthorityUnresolved` is reserved for the internal move sentinel before that
isolation call has completed. No normal manager return leaves this phase
behind; it is exposed so a health read cannot mislabel an interrupted internal
transition as already quarantined.

## Restart, event, and replay contract

- Recovery attempts are consumed when replacement selection starts. Backoff
  doubles by attempt and saturates at the configured maximum. The lifetime
  attempt budget is finite.
- Exit, Ready, and replacement-reaped events must present both the exact service
  incarnation and manager-selected launch epoch. Stale identity or epoch events
  never call the backend and never advance the manager clock.
- The manager retains one fixed-size accepted exit replay, one fixed-size
  terminal Ready replay, and one fixed-size reaped replay. An exact replay of
  the most recently retained event returns its cached disposition without
  backend re-entry. A replay with the same identity but different event content
  is rejected. Older events outside this bounded window are stale and cannot
  mutate lifecycle state.
- An accepted exact replay is still a valid observation of `now`: it checks
  and advances the monotonic watermark. A later call with an earlier tick is
  rejected. This prevents the replay fast path from bypassing time ordering.
- The internal transition sentinel has a typed fail-closed projection. No
  production path relies on `panic!` or `unreachable!`. A subsequent mutating
  call completes mandatory authority isolation before returning.

The crate uses no heap collection, thread-local state, random source, or wall
clock. The adapter supplies monotonically ordered ticks and drives `poll` from
its task-exit and timer facilities.

## Mechanism sources

The implementation does not copy code from these systems. It borrows three
well-established policy shapes while retaining Nexus-specific authority and
closure rules:

- [Erlang/OTP supervisor principles](https://www.erlang.org/doc/system/sup_princ.html)
  motivate a bounded restart-intensity policy.
- [Kubernetes Pod lifecycle](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/)
  documents the capped exponential restart-delay shape. Nexus's lifetime
  attempt budget and quarantine disposition are separate manager policy.
- [In Search of an Understandable Consensus Algorithm (Extended Version)](https://web.stanford.edu/~ouster/cgi-bin/papers/raft-extended.pdf)
  is the original source for the stale-term fencing analogy used by binding
  epochs. Nexus epochs are Registry authority, not Raft terms.

## Current evidence boundary

The crate's deterministic contract tests cover normal recovery, Ready before
and at publication, an immediate same-tick Ready, exit-before-Ready, publication
failure cleanup, Ready and stop deadlines, late Ready, exact reaped replay,
stop-timeout retention, repeated crashes, backoff exhaustion, stale events,
cohort mismatch, partial adoption, truncated and oversized recovery
inventories, and failures at each backend stage. Host tests plus the bare-metal
target check establish the state-machine contract only.

Still required outside this crate are the single-owner OSTD event ingress,
unpublished `TaskOptions::build` / `Task::run` adapter, exact task-exit/reaped
hook, monotonic Jiffies timer, cooperative cancellation point, Registry-backed
`SupervisorBackend`, IRQ/SMP race evidence, persistent handoff where required,
and system cells proving actual service crash/rebind/adopt behavior. Until
those land, this manager is not evidence that the kernel lifecycle is wired.
