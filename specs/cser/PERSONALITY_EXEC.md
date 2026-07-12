# Failure-atomic executable-image CSER refinement

`PersonalityExecCser.tla` fixes the bounded Stage 6B.2 protocol for replacing
one task image under a restartable Linux personality. It separates
kernel-private staging from a single atomic `ExecCommit`, and makes the two
revocation orders explicit:

```text
RevokeBegin before ExecCommit
  -> abort all staging effects
  -> preserve the previous current image

ExecCommit before RevokeBegin
  -> publish the complete new image once
  -> drain its committed effects
  -> never roll back to the previous image
```

The model is an executable-image transaction protocol. It is not an ELF
loader, dynamic linker, `execve(2)` ABI, or address-space implementation.

## Rust refinement mapping

The safe-Rust successor is
`crates/cser-model/src/personality/exec.rs`, built over the personality-local
`EffectRegistry`.

| PlusCal state | Safe-Rust refinement |
| --- | --- |
| `scopeState`, authority and binding epochs | common registry gate and binding token |
| `txState` | `ExecRecord` controlled by an `ExecTransaction` continuation effect |
| `seg1State`, `seg2State` | arbitrary nonempty vector of typed `ExecSegment` effects |
| old/new image | `ExecScopeRecord::current_image` and opaque `ImageId` |
| TLS and stack values | immutable `ExecLayout` metadata |
| frozen receipt fields | immutable `ExecCommitReceipt` |
| control/segment/watchdog credits | continuation, exec-segment, and timer classes in `RegistryBudget` |
| recovery image and cohort | exact `ExecRecoverySnapshot`, ready proof, and explicit transaction/segment adoption |

The finite TLA+ instance fixes one transaction and exactly two segments. The
Rust transition accepts an arbitrary nonzero segment count and registers the
controller plus every segment failure-atomically. It precomputes every segment
resource identity before touching the registry, checkpoints registration, and
restores the entire registry if any typed segment credit is unavailable.

The Rust model records TLS base and stack pointer as frozen layout metadata;
unlike the concrete dynamic-PIE QEMU receipt, it does not represent TLS and
stack as two additional registry effects.

## Staging visibility and ExecCommit

`stage` creates one continuation controller and one detached typed effect per
segment. The proposed image, segments, TLS base, and stack pointer remain in
kernel-private transaction state. The public scope projection continues to
return only the previous `current_image`:

```text
stage(tx, segments, layout)
  -> current_image is unchanged

ExecCommit(tx, all segments, layout)
  -> one batch crosses the registry commit gate
  -> current_image, TLS, and stack become the new image together
  -> one immutable receipt freezes previous and new image state
```

There is no per-segment publication point. `commit_many` validates the current
authority/binding identity of the controller and every segment before it
changes any effect. Partial adoption, forged identities, stale bindings,
duplicate commit, and count/credit failure therefore leave both registry and
visible image unchanged.

Kernel completion consumes the exact receipt and returns the continuation and
all exec-segment credits together. A replay cannot terminalize the image a
second time.

## Crash, rebind, and explicit adoption

If the personality crashes before commit, `Crash` advances the binding epoch
and records the transaction plus every segment in the exact recovery cohort.
Fallback must run, then a prospective replacement captures a combined registry
and exec-domain snapshot. `Ready` succeeds only while the current image,
staging identity, transaction states, binding, cohort, and registry revision
remain unchanged. Kernel publication or another domain transition invalidates
a stale ready proof rather than allowing a replacement to bind against an old
image. The formal witness records this history only when publication actually
observes a previously issued ready proof; the Rust sequence likewise checks
that replaying that proof at rebind rejects without mutation and that a fresh
snapshot/ready handshake is required.

Rebind does not transfer ownership implicitly. The replacement must adopt the
transaction and every segment separately. Adoption changes only binding
ownership; it cannot alter the proposed image, segment set, layout, frozen
receipt, current image, or typed credits. Commit remains fenced until the
entire batch carries the current binding. A crash after commit cannot cause
the replacement to recommit: the committed batch is kernel-owned and may only
be completed or drained.

## Revocation and closure

`RevokeBegin` atomically closes the authority epoch and fixes whether
`ExecCommit` already occurred.

- For a staged transaction, scope-local closure aborts the controller and all
  segments, clears staging only after the complete batch is terminal, returns
  every typed credit, and preserves the previous image.
- For a committed transaction, kernel closure consumes its immutable receipt,
  completes the controller and all segments exactly once, returns the credits,
  and leaves the newly committed image current.

`RevokeComplete` is enabled only after the domain staging index is empty, every
transaction is `Completed` or `Aborted`, the recovery cohort and watchdog are
gone, and the common registry has returned its initial typed budget.

## Checked properties and witnesses

Both configurations check:

- `AtomicImageVisibility`: no staged subset leaks into the current image;
- `FrozenCommitReceipt`: the old image, complete segment set, new image, TLS,
  and stack are immutable after commit;
- `StateCohesion`: controller and both modeled segments move as one batch and
  terminalize once;
- typed `BudgetConservation`;
- `PostRevokeCommitExclusion`;
- exact snapshot/ready discipline;
- conditional `QuiescentClosure`.

The reject-enabled graph also checks stale-binding
`RejectSideEffectFreedom`. The action/liveness graph checks weak-fair kernel
fallback, committed publication, and closure progress; environment actions
have no fairness assumption.

With the pinned Nexus TLA+ image and 16 TLC workers, the complete runs are:

```text
reject-enabled safety:
  361 states generated
  253 distinct states
  complete graph depth 15

action/liveness:
  182 states generated
  137 distinct states
  complete graph depth 14
  3 temporal branches over 411 total distinct branch states
```

Six reachability checks require atomic whole-image commit, revoke-before-commit
preservation of the old image, crash/adopt/commit, commit-before-revoke drain,
kernel publication invalidating a stale ready proof, and stale-binding
failure-atomic rejection.

The Rust successor contributes six deterministic sequence tests and one
bounded proptest. They cover invisible staging, arbitrary segment batches,
insufficient-credit rollback, explicit adoption of every effect, duplicate
commit/completion rejection, ready-proof invalidation, both revoke orders,
immutable current-image outcomes, typed-credit conservation, and quiescent
closure.

## Run

From the repository root, the normal pinned-container gate is:

```sh
./x spec
```

Inside the development container, run only this family with:

```sh
TLA2TOOLS_JAR=/opt/tla2tools/tla2tools.jar \
  ./specs/cser/check.sh PersonalityExecCser
```

Edit only the PlusCal algorithm and regenerate its committed translation with
`pcal.trans -nocfg -lineWidth 10000` before checking.

## Boundary

The checked instance deliberately excludes:

- ELF parsing, program-header validation, relocations, symbol resolution, a
  production dynamic linker, and Linux `execve` argument/environment ABI;
- `VmSpace` construction or replacement, page permissions, W^X, ASLR, auxv,
  demand paging, and executable-file I/O;
- more than one transaction, two modeled segments, or one crash/rebind cycle;
- multithreaded exec teardown, signal/fd/credential transitions, task-group
  replacement, and rollback of external effects;
- SMP publication ordering or a production lock/atomic implementation;
- a registry shared with scheduler, pager, filesystem, network, or mediated
  I/O services.

The independent OSTD dynamic-PIE receipt now refines the bounded transaction
with concrete mappings, TLS/stack, FS base, and guest execution. It does not
turn this finite protocol into a general loader or complete the Linux
personality.
