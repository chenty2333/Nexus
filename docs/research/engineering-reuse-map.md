# Nexus engineering reuse map

Status date: 2026-07-17

This is an implementation decision record, not a novelty survey. It maps the
nine current Nexus priorities to components that can be wrapped, mechanisms
whose semantics should be copied without copying their implementation, and the
CSER behavior that must remain Nexus-owned.

The labels below are strict:

- **Adopt** means pin and wrap a maintained component, retaining its license and
  provenance. It does not imply that the component already satisfies CSER.
- **Borrow** means reuse an interface rule, state-machine shape, or test pattern.
  No source compatibility is claimed and no code should be copied implicitly.
- **Own** means the behavior defines Nexus authority or closure and cannot be
  delegated to a generic supervisor, driver, tracing system, or serializer.

Native effect-peer wire v1 remains frozen. The kernel path is `no_std + alloc`;
`std`-only tools belong in host conformance, operation, or evidence layers.

## 1. Versioned kernel/service ABI

- **Adopt:** use the already pinned `zerocopy 0.8.54` and `bitflags 2.13.0`
  for a fixed-endian, bounds-checked portal-v2 envelope. Keep `serde_json` only
  for frozen process wire v1 and host evidence, not as the kernel ABI.
- **Borrow:** follow Linux UAPI's `size` field and reject-unknown-flags rules;
  model negotiation as VirtIO-style device-offered and driver-accepted feature
  sets with explicit `FEATURES_OK` confirmation, while Nexus separately owns
  the required set and rejects it unless every required feature was accepted;
  use seL4's one-shot reply and derived-capability revocation as handle-lifetime
  precedents.
- **Own:** the portal object table, boot-local opaque scope/effect/receipt
  handles, generation and caller-binding validation, typed error taxonomy,
  linear receipt consumption, and command semantics. A copied wire selector is
  never authority by itself and replay must fail in the Registry.
- **Gate:** Rust enum layout, pointers, `usize`, implicit padding, unbounded
  lengths, and serializer defaults are not ABI. `zerocopy` checks byte layout;
  it does not define versioning or semantic validity. Every accepted capability
  needs a conformance vector and every unsupported required capability must
  fail without mutation.
- **Decision:** create a small `no_std` portal-ABI crate with a distinct
  `nexus.portal.v2` schema, limits, typed errors, capability query, and contract
  vectors. It may replace the experimental portal v1 without glue, but the
  separate effect-peer native wire v1 remains frozen.

## 2. Supervisor lifecycle

- **Adopt:** use OSTD `Task`, completion/waker, timer, IRQ synchronization, and
  task-context queue primitives. A host-only process profile may use systemd or
  Linux process handles to contain the runner, but they are outside the Nexus
  authority TCB.
- **Borrow:** use systemd's `READY`, watchdog, restart-on-failure, increasing
  restart delay, and start-limit burst concepts; use CuriOS and Shadow Drivers
  for replacement, protected recovery state, proxying, and reattachment
  patterns.
- **Own:** death observation that advances the binding epoch, replacement task
  creation, Snapshot/Ready/Rebind/Adopt ordering, exact orphan selection,
  repeated-crash policy, replacement timeout, fallback/abort winner, and the
  invariant that the Registry outlives every service incarnation.
- **Gate:** systemd cannot supervise an OSTD guest task or preserve CSER effect
  authority. A heartbeat is not proof of task death, and `Ready` is not
  permission to adopt an arbitrary effect. Deadlines must be monotonic and all
  restart-limit outcomes must be typed and inspectable.
- **Decision:** implement one kernel-owned `SupervisorManager` driven by task
  exit and deadline events. Convert the fixed fsd-v1/v2 sequence into its first
  policy adapter, then add repeated crash and replacement-timeout cells before
  supporting another service.

## 3. Complete causal coverage

- **Adopt:** attach narrow hooks to existing OSTD task admission, user fault,
  wait/wake, timer, queue, IRQ, DMA, completion, and guest-copy paths. Reuse the
  existing Registry and typed domain objects; do not add a second tracing
  registry.
- **Borrow:** Resource Containers supplies the activity-principal accounting
  pattern; Speculator and Rethink the Sync supply dependency propagation and
  publication-gate patterns; io_uring supplies explicit too-late cancellation
  and completion observation.
- **Own:** root derivation, immutable ancestry, reverse indexes, commit point,
  terminal disposition, typed credit movement, and the rule deciding whether a
  kernel facility is a tracked effect or declared TCB infrastructure.
- **Gate:** a trace/span ID is observational metadata, not authority. Any task,
  page fault, waiter/waker, timer, queue entry, DMA owner, completion, or reply
  that can retain request-derived authority after its caller moves on must join
  the root unless a reviewed TCB rationale proves otherwise.
- **Decision:** freeze a machine-readable coverage ledger for the block-read
  workload. Each row names creation, parent derivation, commit/publication,
  cancellation, terminalization, credit, and TCB status; runtime/source gates
  reject an exercised boundary with no ledger row.

## 4. Dangerous fault windows

- **Adopt:** keep the existing `loom 0.7.2`, `proptest 1.11.0`, xtask mutation
  gates, and QEMU runner. Use typed in-source failpoints for deterministic
  production-path cells; use Linux fault-injection's explicit point/count model
  as the configuration precedent.
- **Borrow:** retain complete before/after state like a transactional fault
  harness, and distinguish cancel-success, too-late, committed, and
  indeterminate outcomes instead of treating every injected error as rollback.
- **Own:** the injection points, shared-root projection, publication and
  terminalization counts, retained-owner accounting, exact identity presented,
  and honest timeout result.
- **Gate:** Loom is not OSTD SMP evidence, random fault probability is not a
  release matrix, and an evaluation-only state machine cannot satisfy the
  production-path gate. Failpoints must not allocate or panic after the first
  visible mutation.
- **Decision:** first close real post-device-commit/pre-backend and
  post-backend/pre-reply crashes, then repeated crash, Adopt-vs-Abort, late
  completion, reset/IOTLB retry, and retained-pressure cells. Preserve older
  evidence as historical receipts; never relabel it as execution of a new cell.

## 5. IRQ, reset, IOTLB, and retained worker

- **Adopt:** continue with the pinned `ostd 0.18.0`, `virtio-drivers 0.13.0`,
  `nexus-ostd-virtio`, and the two hash-bound repository overlays. Adopt the
  VirtIO 1.3 device/queue reset and device-resource-release rules at the
  transport boundary; those rules do not establish IOTLB invalidation
  completion or permission to reuse a Nexus-owned frame.
- **Borrow:** use Linux devlink health's per-subsystem diagnose/dump/recover and
  grace/burst concepts for operator recovery; use IOMMUFD's single DMA-owner,
  device/IO-address-space object model only as a comparison for future host
  backends.
- **Own:** CSER device/effect identity, commit gate, deadlines, retry/backoff,
  quarantine, retained tombstone, same-effect retry, reset-generation advance,
  IOTLB-completion-before-frame-reuse, and the worker that keeps ownership live
  while recovery is pending. OSTD remains the sole VT-d control-plane owner.
- **Gate:** the current facade is one CPU, one exclusive queue, whole-device
  reset, one-page owners, a shared domain, and a polling checkpoint with INTx
  masked. The upstream VirtIO crate is MIT; its Nexus overlay and OSTD are
  separately MPL-2.0. Patch provenance and reverse-application checks remain
  mandatory. Linux IOMMUFD or driver code must not be imported into the kernel.
- **Decision:** wire the existing typed INTx acknowledgement into a real OSTD
  top-half/task-context completion path, then add the retained worker with real
  deadlines and retry policy. Do not introduce a second IOMMU stack; upstream
  the smallest OSTD API needed for ownership-carrying invalidation completion.

## 6. SMP refinement

- **Adopt:** use OSTD synchronization/IRQ guards and Rust atomics in production;
  keep `loom` on the same transition functions where feasible. Generic `spin`
  locks remain usable only where their IRQ and blocking context is proven.
- **Borrow:** apply Linux lockdep's lock-class, dependency graph, and IRQ-safe
  versus IRQ-unsafe rules; use release/acquire publication and explicit
  linearization-point tables rather than volatile or compiler barriers.
- **Own:** the Registry lock hierarchy, IRQ exclusion policy, Commit/Revoke and
  Adopt/Abort winners, receipt publication edges, device-completion/reset
  ordering, and deterministic CPU placement schedules.
- **Gate:** no spin lock across a blocking wait; a lock reachable from local IRQ
  either excludes that IRQ or uses a documented non-reentrant scheme. Static
  mapping, Loom, 2-vCPU execution, and 4-vCPU execution remain separate evidence
  layers.
- **Decision:** freeze lock ranks and the operation-to-lock/IRQ/atomic map before
  adding concurrency. Add a debug lock-order checker, then force revoke,
  service recovery, and IRQ/completion onto distinct CPUs in pinned 2- and
  4-vCPU schedules.

## 7. Operator and inspection surface

- **Adopt:** reuse Registry read-only projections and host-side `serde_json` for
  stable machine-readable CLI output. Reuse the portal-v2 framing from
  priority 1; do not create a separate debug transport.
- **Borrow:** use devlink health reporters as the shape for subsystem health,
  diagnosis, retained dumps, and explicit recovery; use systemd-style
  lifecycle states for concise health summaries.
- **Own:** atomic scope/effect/binding/credit snapshots, revision-checked
  mutating commands, revoke/retry-reset/retry-IOTLB authorization, closure
  receipt lookup, redaction policy, and an audit receipt for every operator
  action.
- **Gate:** serial markers, raw memory, reconstructed receipts, and an
  unversioned debug command are not an operational API. Inspection must be
  side-effect free; mutation must carry an opaque current handle and expected
  revision and return a typed result.
- **Decision:** build `nexusctl` over v2 with `scope list/show`, `effect tree`,
  `binding`, `credits`, `retained`, `health`, `revoke`, `retry-reset`,
  `retry-iotlb`, and `receipt show`. Keep human formatting outside the kernel.

## 8. Resource pressure and stability

- **Adopt:** use existing OSTD fallible frame/range acquisition and preallocate
  bounded Registry arenas before publication. Use host cgroup v2 limits and PSI
  triggers to make QEMU soak pressure reproducible; these are outer test
  controls, not internal CSER accounting.
- **Borrow:** Resource Containers supplies per-activity charging; cgroup v2
  supplies soft/high versus hard/max limits; PSI supplies time-window pressure
  signals. Apply bounded queues and admission backpressure before attempting
  eviction.
- **Own:** per-client/root/effect/tombstone/queue/page/DMA quotas, reservation
  rollback, retained-owner charging, fairness, typed `NoCredit`/`Backpressure`,
  and the rule that pressure cannot release a still-owned frame or receipt.
- **Gate:** ordinary `alloc` collection growth may still abort on OOM. No new
  arena/slab crate is accepted until it supports the required `no_std` target,
  fallible capacity reservation, generations, and license/provenance checks.
  Host cgroup success says nothing about internal credit conservation.
- **Decision:** start with finite configured maxima and generation-tagged,
  preallocated slots for multiple roots/clients. Add admission rejection and
  retained-pressure tests before soak; then run multi-hour normal, OOM, device
  failure, and repeated-recovery profiles while retaining raw P99, memory per
  effect, queue depth, and lock-contention samples.

## 9. Production error-path hardening

- **Adopt:** use Rust `Result`/typed enums, OSTD fallible guest-memory I/O and
  resource acquisition, and `linux-raw-sys` errno values only at the Linux
  personality boundary. Add host-side parser fuzzing without making the fuzzer
  a runtime dependency.
- **Borrow:** follow Linux UAPI's reject-unknown-input discipline and devlink's
  isolate/diagnose/recover shape. Keep seL4's explicit invocation errors as the
  capability-interface precedent.
- **Own:** the cross-layer error taxonomy, failure-atomic validate/prepare/apply
  split, service isolation/quarantine, retained fallback, error-to-Linux mapping,
  and which internal invariant violations remain fail-stop.
- **Gate:** supported guest copy faults, malformed portal messages, stale or
  wrong handles, device enumeration mismatch, quota exhaustion, timeout, and
  illegal service input must not reach `panic!`, `assert!`, `unwrap`, or
  `expect`. Tests and proven-infallible private apply phases may retain explicit
  assertions, with a reviewed allowlist.
- **Decision:** add a source-owned panic inventory keyed by profile and call
  boundary. Harden portal decode and guest copy first, then enumeration and
  allocation, then recovery/device adapters; make xtask reject newly reachable
  production panics without an allowlist entry and a stated invariant.

## Immediate component policy

Adopt now: the already pinned OSTD/VirtIO facade and overlays,
`zerocopy`/`bitflags` for native v2 representation, OSTD lifecycle and
synchronization primitives, and existing Loom/proptest/QEMU test machinery.
Keep `serde_json` on host boundaries only.

Borrow now: Linux UAPI extensibility, lockdep, fault injection, devlink health,
cgroup v2/PSI, systemd lifecycle policy, seL4 reply/revoke semantics, and the
audited prior-art mechanisms. Linux, systemd, seL4, IOMMUFD, Chubby, and the
research prototypes are not drop-in Nexus components.

Do not adopt yet: a second IOMMU owner, a general async runtime inside the
kernel, a serializer-defined kernel ABI, a tracing system as authority, or an
allocator/arena whose fallible `no_std` behavior has not passed the fault
matrix.

## Source and license boundary

The repository basis is
[`prior-art.toml`](../../evaluation/stage7b/prior-art.toml), its 16 source cards,
[`related-work-preflight.md`](related-work-preflight.md),
[`v0.2-preflight-decision.md`](v0.2-preflight-decision.md), RFC 0001's bounded
checkpoint, registry, workload, device, SMP, and fault sections, and the current
[`nexus-ostd-virtio` boundary](../../crates/nexus-ostd-virtio/README.md). Atomic
RPC remains metadata-only and contributes no mechanism decision here.

The external engineering references are official project documentation:

- [Linux syscall/API extensibility](https://docs.kernel.org/process/adding-syscalls.html),
  [lockdep](https://docs.kernel.org/locking/lockdep-design.html),
  [fault injection](https://docs.kernel.org/fault-injection/fault-injection.html),
  [devlink health](https://docs.kernel.org/networking/devlink/devlink-health.html),
  [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html),
  [PSI](https://docs.kernel.org/accounting/psi.html), and
  [IOMMUFD](https://docs.kernel.org/userspace-api/iommufd.html);
- [systemd service lifecycle](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html),
  [start limits](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html),
  and [`sd_notify`](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html);
- [VirtIO 1.3](https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html)
  and the seL4 reference-manual source card already retained by Stage 7B.

License identifiers for the principal pinned Rust components were checked in
their local manifests: OSTD is MPL-2.0; `virtio-drivers` and `loom` are MIT;
`bitflags` and `proptest` are MIT OR Apache-2.0; `zerocopy` is BSD-2-Clause OR
Apache-2.0 OR MIT; `spin` is MIT. These identifiers are provenance constraints,
not a legal compatibility opinion. Linux/systemd/seL4 material above is used as
documentation-level semantics only; importing their source requires a separate
license and architecture review. Any new dependency or source import still
requires a complete repository license/provenance gate.
