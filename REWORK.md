# Nexus rework ledger

This ledger records what survives the CSER reset. It is a deletion plan, not a
promise to preserve the current Axle/Zircon/Starnix architecture.

The current research checkpoint consists of the CSER state machine, the pure
Rust reference model, the OSTD/OSDK feasibility spike, and the scheduler
crash-to-fallback slice. The foundation decision is **OSTD-first**, not
irrevocably OSTD-only: if a documented critical boundary cannot be fixed by an
upstream API or a small audited adapter/patch without violating single-owner
hardware control, Nexus must re-evaluate the foundation explicitly. That
decision still must not pull in a legacy crate merely because it already exists.

## Status vocabulary

- **KEEP**: this is a current source of truth or a deliberately retained test
  input. It stays maintained.
- **MIGRATE**: preserve a narrowly named contract, race, workload, or tool
  capability in the new tree, then delete the original.
- **REWRITE**: replace the subsystem behind the new OSTD/CSER boundary. Source
  code is not carried forward unless a separate MIGRATE row names the asset.
- **DELETE**: remove after its remaining build dependencies are detached. Git
  history is the archive.

`MIGRATE` never means that legacy behavior becomes normative. The normative
CSER semantics live in `specs/cser/`; migrated legacy cases are regression
questions that a new implementation may deliberately answer differently.

## Deletion gates

The legacy implementation may be removed as one large change after all of the
following are true:

1. A root Docker + `./x`/xtask entry point runs formatting, lint, model tests,
   TLC, and the OSTD QEMU slice.
2. CI calls that same entry point and no longer invokes Nix or Just.
3. `specs/oracles/*.toml`, `tests/guest/linux/SOURCES.toml`, and
   `tests/guest/linux/COMPATIBILITY.toml` all parse; their IDs and references
   are coherent; every declared build profile is supported; the source-file
   set is closed; and every retained Linux copy matches its declared SHA-256.
4. The neutral runner can enforce timeouts, ordered/required/forbidden serial
   events, numeric bounds, and failure-artifact retention.
5. Cargo metadata and a repository search show that new CSER/OSTD code has no
   dependency on the legacy Axle/Zircon/Starnix crates.

The old and new trees coexist only until these gates pass. We do not keep a
permanently buildable `legacy/` kernel.

## Migration receipts

The following extractions are already present in the new tree:

| Legacy asset | New location | Verification |
| --- | --- | --- |
| wait/timer, fault, revocation, scheduler, and future I/O race questions | `specs/oracles/cser-races.toml` | schema v1 parses; IDs are unique |
| six selected old vertical-slice observations | `specs/oracles/legacy-slices.toml` | schema v1 parses; no legacy build command is retained |
| 34 Linux C/assembly guest inputs | `tests/guest/linux/sources/` | every copy matches both its legacy source and the SHA-256 in `SOURCES.toml` |
| 28 old Linux compatibility scenarios plus one superseded guest input | `tests/guest/linux/COMPATIBILITY.toml` | all source IDs resolve and all 34 copied inputs are referenced; only six `core` workloads are Stage 6 commitments, with the remainder marked `stretch` or `archive-input` |

These receipts do not authorize deletion by themselves; the build, CI, and
neutral-runner gates above must pass in the same cleanup checkpoint.

## Current research assets

| Path | Status | Disposition |
| --- | --- | --- |
| `specs/cser/` | **KEEP** | Normative TLA+/PlusCal model, TLC configuration, and property documentation. Extend before each vertical slice. |
| `crates/cser-model/` | **KEEP** | Executable, `no_std + alloc` reference semantics and differential oracle. |
| `experiments/ostd-cser-spike/` | **KEEP** | Reproducible evidence for OSTD API fit, scheduler fallback, and the IOMMU fail-closed result. It may later be superseded by the production prototype, but must remain runnable until then. |
| `specs/oracles/` | **KEEP** | Non-normative, implementation-neutral regression questions extracted from the old system. |
| `tests/guest/linux/` | **KEEP** | Compatibility workload inputs for the eventual Linux personality. These do not define Nexus's research identity. |
| `VISION.md` | **KEEP** | Research question, exclusions, candidate contribution, and evidence threshold. |
| `ARCHITECTURE.md` | **KEEP** | OSTD boundary, minimal kernel mechanisms, user-service boundary, and failure semantics. |
| `REWORK.md` | **KEEP** | This migration/deletion ledger. Update it when a row changes state. |

## Root build and repository control

| Path | Status | Disposition |
| --- | --- | --- |
| `Cargo.toml` | **REWRITE** | Reduce the root workspace to maintained models/tools and the new implementation. Remove all legacy members together with their directories. |
| root `Cargo.lock` policy | **REWRITE** | Commit lockfiles for reproducible host tools and isolated OSDK crates; do not rely on the old globally ignored lockfile behavior. |
| `.cargo/config.toml` | **REWRITE** | Keep only target settings actually required by the new OSTD/guest build. |
| `.github/workflows/ci.yml` | **REWRITE** | Invoke the same Docker-backed `./x verify` path used locally. |
| `flake.nix`, `flake.lock`, `.envrc` | **DELETE** | Delete in the CI/build cutover change. Docker becomes the environment boundary. |
| `justfile` | **MIGRATE** | Move only retained commands into `./x`/xtask, then delete. Do not reproduce obsolete Axle or Starnix convenience targets. |
| `.gitignore` | **REWRITE** | Rebuild around committed lockfiles and explicit Docker/OSDK/QEMU artifacts. |
| `LICENSE` | **KEEP** | Keep the repository license while documenting third-party licenses, including OSTD's MPL-2.0 boundary. |

## Shared crates

| Module | Status | Disposition |
| --- | --- | --- |
| `crates/axle-arch-x86_64` | **DELETE** | Legacy userspace syscall/debug glue; OSTD owns the architecture boundary. |
| `crates/axle-core` | **MIGRATE** | Extract wait single-winner, stale-registration, deferred-revocation, and reverse-index race questions into neutral oracles; then delete the implementation. It is not CSER. |
| `crates/axle-mm` | **MIGRATE** | Retain same-page-fault contention and resource-accounting questions only. OSTD `VmSpace` and the new pager protocol replace the implementation. |
| `crates/axle-page-table` | **DELETE** | OSTD owns page-table traversal and mutation; do not maintain a second page-table stack. |
| `crates/axle-sync` | **MIGRATE** | Move relevant single-terminalization/Loom schedules into CSER concurrency tests, then delete this generic legacy crate. |
| `crates/axle-virtio-transport` | **MIGRATE** | Preserve queue bring-up and interrupt failure questions, not this synthetic transport. The mediated device path will wrap `virtio-drivers` and own CSER/DMA lifetime semantics. |
| `crates/axle-types` | **DELETE** | Remove the Axle UAPI and frozen Zircon aliases. New native interfaces use Nexus names; Linux UAPI comes from maintained upstream crates. |
| `crates/libax` | **DELETE** | Legacy native facade tied to the old syscall ABI. |
| `crates/libzircon` | **DELETE** | Remove all `zx_*` compatibility wrappers. |
| `crates/nexus-component` | **DELETE** | The old Fuchsia-shaped component IR is outside the CSER research core. Reintroduce a smaller service-launch format only if a concrete slice requires it. |
| `crates/nexus-fs-proto` | **DELETE** | Old filesystem wire protocol is not a retained kernel boundary. |
| `crates/nexus-fs-model` | **DELETE** | The DataFS preparation model is unrelated to the first CSER prototype; later storage work starts from the mediated-I/O contract. |
| `crates/nexus-io` | **DELETE** | Old fd/namespace substrate is coupled to `libax` and the old component tree. |
| `crates/nexus-rt` | **MIGRATE** | Extract only wait/timer/reactor cancellation cases. Rewrite any future userspace runtime against CSER tokens and the new native ABI. |

## Kernel

| Module | Status | Disposition |
| --- | --- | --- |
| `kernel/axle-kernel` | **REWRITE** | Replace as a whole with the OSTD-based Nexus prototype. No legacy kernel module is linked into the new kernel. |
| `arch/`, boot, SMP, traps, allocator, PMM | **DELETE** | Reuse OSTD boot/SMP/trap/frame/heap mechanisms. Keep only externally observed failure cases where named below. |
| `task/scheduler/` | **MIGRATE** | Preserve scheduler wake/fallback observations; the completed OSTD slice replaces the implementation. |
| `task/fault.rs`, VM fault paths | **MIGRATE** | Preserve same-page contention and blocked-fault recovery questions for the pager slice; rewrite the mechanism around one-shot fault continuations. |
| `wait.rs`, `time.rs`, futex/wait state | **MIGRATE** | Preserve timeout/wake/cancel schedules; implement future waits as CSER-scoped effects over OSTD primitives. |
| `object/revocation.rs` | **MIGRATE** | Preserve stale deferred-state test cases only. Capability epoch invalidation by itself is not the new revocation mechanism. |
| `object/device.rs`, DMA objects, old PCI exports | **MIGRATE** | Preserve interrupt, queue, pin-budget, and fail-closed questions. Rewrite device mediation and real IOMMU quiescence. The old identity-IOVA path is not reusable evidence of closure. |
| channel/socket/object/handle implementation | **DELETE** | Zircon-shaped object semantics are not a research goal. Reintroduce only minimal native IPC required by a vertical slice. |
| old syscall dispatcher and generated Axle ABI | **DELETE** | Define a small native Nexus ABI; do not preserve syscall numbers for compatibility. |
| legacy trace implementation | **MIGRATE** | Retain measurement categories and artifact discipline, then define a CSER trace containing scope/effect IDs, both epochs, transition, result, and latency. |

## Userspace and guest programs

| Module | Status | Disposition |
| --- | --- | --- |
| `user/nexus-init` root/component orchestration | **DELETE** | Remove the old component manager, resolver, namespace, asset embedding, and Fuchsia-shaped lifecycle. |
| `user/nexus-init/src/starnix` | **REWRITE** | A future Linux personality is a new, bounded compatibility server. Do not copy the old guest-session/sidecar/stop-packet implementation. |
| `user/nexus-init/src/starnix/tests` | **MIGRATE** | Convert coverage intent into `tests/guest/linux/COMPATIBILITY.toml`; do not retain host tests coupled to old internal objects. |
| `user/nexus-init` network and remote-shell code | **DELETE** | Rebuild later over mediated VirtIO and a reused userspace network stack. |
| `user/test-runner` | **MIGRATE** | Extract only selected race/slice observations and neutral serial assertions, then delete the fixed-VA/libzircon runner. |
| `user/echo-client`, `user/echo-provider`, `user/controller-worker` | **DELETE** | Old component-routing smoke binaries have no unique CSER evidence. |
| `user/linux-*` C/assembly inputs | **MIGRATE** | Exact source copies live under `tests/guest/linux/sources/`; delete the old locations when the new build owns them. |
| externally supplied musl/glibc/BusyBox artifacts | **REWRITE** | Build pinned guest artifacts in Docker. Do not copy host runtime libraries opportunistically. |

## Host tools

| Module | Status | Disposition |
| --- | --- | --- |
| `tools/axle-conformance` | **MIGRATE** | Reimplement its useful generic capabilities in xtask: scenario selection, timeout, ordered/required/forbidden serial assertions, numeric bounds, retries, and artifacts. Delete Axle-specific contracts and commands. |
| `tools/axle-concurrency` | **MIGRATE** | Preserve the schedule ideas in `specs/oracles/cser-races.toml`; rewrite execution against the CSER core and later Loom/Kani harnesses. |
| `tools/syscalls-gen` | **DELETE** | Do not regenerate the obsolete Axle/Zircon ABI. Linux constants come from maintained UAPI crates. |
| `tools/nexus-manifestc` | **DELETE** | Coupled to the old component model. |
| `tools/datafs-check` | **DELETE** | Coupled to the deferred DataFS model. |
| old performance parsing scripts | **DELETE** | There is no tracked baseline to preserve. Build the `k`-scaling and failure-latency reports from the new CSER trace schema. |
| `syscalls/spec/`, `syscalls/generated/` | **DELETE** | Remove the old Axle syscall catalog and generated number table with `tools/syscalls-gen`; neither is a compatibility surface. |

## Specifications and tests

| Module | Status | Disposition |
| --- | --- | --- |
| `specs/conformance/contracts.toml` | **MIGRATE** | Extract only CSER-relevant race questions and Linux workload coverage. Delete Zircon MUST/SHOULD catalog semantics. |
| wait/timer/revocation/fault scenarios | **MIGRATE** | Distill into `cser-races.toml` and `legacy-slices.toml`; old commands must not survive because they build deleted crates. |
| device/net/page-loan scenarios | **MIGRATE** | Distill interrupt, queue, pinned-credit, and recovery observations. They do not prove real DMA quiescence. |
| `starnix_*` scenarios | **MIGRATE** | Preserve compatibility coverage and guest inputs in the Linux test matrix; remove the Starnix name from the future harness. |
| remaining channel/socket/eventpair/job/VMAR/VMO scenarios | **DELETE** | Keep Git history. Add a new native contract only when a CSER slice needs that behavior. |
| `specs/conformance/runner/*.S` | **DELETE** | These exercise the obsolete native ABI and are not Linux guest inputs. |

## Documentation

| Module | Status | Disposition |
| --- | --- | --- |
| `references/*.md` | **DELETE** | These describe the current Axle implementation. Git history is sufficient once the three top-level documents are in place. |
| `docs/TODO.md` | **DELETE** | Old roadmap and Starnix completion plan. |
| `docs/futex_semantics.md` | **DELETE** | Zircon-shaped futex divergence is not a future contract. Linux futex behavior belongs to the bounded personality test plan. |
| `docs/vm_cortenmm_adaptation.md` | **DELETE** | Describes the legacy custom VM implementation rather than the OSTD/pager architecture. |

## Intended end state

After deletion, the repository should visibly center on:

```text
VISION.md
ARCHITECTURE.md
REWORK.md
specs/cser/
specs/oracles/
crates/cser-model/
kernel/ or prototype/        # OSTD-based implementation only
tests/guest/linux/
tools/xtask/
Dockerfile / docker/
./x
```

Pager, mediated VirtIO, and Linux compatibility are admitted only through this
new structure. Passing an old scenario is useful evidence; inheriting an old
architecture is not.
