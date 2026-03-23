# 00 - repo map

Start here when you need the current repository layout before reading one subsystem in detail.

See also:
- `10_ARCH_X86_64_STARTUP.md`
- `11_SYSCALL_DISPATCH.md`
- `12_WAIT_SIGNAL_PORT_TIMER.md`
- `20_HANDLE_CAPABILITY.md`
- `21_OBJECT_MODEL.md`
- `30_PROCESS_THREAD.md`
- `33_IPC.md`
- `40_VM.md`
- `44_DATAFS_PREP_MODEL.md`
- `50_STARNIX_EXEC_MODEL.md`
- `90_CONFORMANCE.md`
- `AxleKernel_Roadmap_v0.3.md`
- `Axle_v0.3.md`
- `Nexus_Roadmap_v0.3.md`

## Reference template

Current Axle reference files should stay close to this shape:

- title
- optional `Part of ...`
- `See also:`
- `## Scope`
- `## Current implementation` for leaf documents
- `## Current shape` for index documents
- subsystem-specific sections
- `## Current limitations` when the file describes live behavior

Index-style files can be shorter, but they should still point to the split documents that carry the real details.

## Terminology

- `bootstrap`: the current special-case early execution model, fixed userspace window, seeded handles, or other temporary early-system paths
- `bring-up`: hardware and kernel initialization, trap setup, AP startup, and other early startup scaffolding
- `current-state reference`: a document that describes what the repository does now, not only what the roadmap intends later
- `working`: good enough to use during implementation, but still expected to evolve with the code
- `draft`: first-pass coverage that should be treated more cautiously

## Reference status

- `00_REPO_MAP.md` - index
- `10_ARCH_X86_64_STARTUP.md` - working
- `11_SYSCALL_DISPATCH.md` - working
- `12_WAIT_SIGNAL_PORT_TIMER.md` - working
- `20_HANDLE_CAPABILITY.md` - working
- `21_OBJECT_MODEL.md` - working
- `30_PROCESS_THREAD.md` - index
- `31_PROCESS_THREAD_BOOTSTRAP_LAUNCH.md` - working
- `32_SCHEDULER_LIFECYCLE.md` - working
- `33_IPC.md` - index
- `34_IPC_CHANNEL.md` - working
- `35_IPC_SOCKET.md` - working
- `40_VM.md` - index
- `41_VM_VMO_VMAR.md` - working
- `42_VM_FAULT_COW_LOAN.md` - working
- `43_VM_EXEC_PAGER_DEVICE_VM.md` - draft
- `44_DATAFS_PREP_MODEL.md` - draft
- `50_STARNIX_EXEC_MODEL.md` - draft
- `90_CONFORMANCE.md` - working

At the moment, `43_VM_EXEC_PAGER_DEVICE_VM.md` and
`44_DATAFS_PREP_MODEL.md` are the intentional `draft` references because they
mainly cover incomplete or not-yet-stable VM / storage-prep surfaces.
`50_STARNIX_EXEC_MODEL.md` is also intentionally `draft` because it freezes the
round-0 Starnix substrate / executive boundary ahead of implementation. The
rest of the leaf references should be treated as `working` current-state docs.

## Top-level directories

- `crates/` - shared Rust crates for host-testable semantic cores and low-level support
- `kernel/` - the `axle-kernel` `no_std` kernel crate
- `user/` - userspace binaries such as the bootstrap test runner, the
  extracted `nexus-init` root-manager binary, and minimal component smoke
  children (`echo-provider`, `echo-client`, `controller-worker`)
- `tools/` - host-side utilities such as syscall generation and conformance running
- `syscalls/` - syscall spec and generated ABI number tables
- `specs/` - conformance contracts, scenarios, and runner assembly payloads
- `references/` - current-state subsystem references and roadmap docs
- `docs/` - working notes, TODOs, and temporary design documents
- `.github/` - CI/workflow definitions
- `target/` - build and conformance output artifacts

## Workspace crates

- `crates/axle-types` - shared native `ax_*` UAPI types/constants plus frozen `zx_*` compat aliases
- `crates/axle-core` - host-testable core semantics: handles, CSpace, revocation, signals, ports, timers
- `crates/axle-mm` - VM metadata core: VMO, VMAR, VMA, frame metadata, fault metadata
- `crates/axle-page-table` - page-table transaction and mapping support
- `crates/axle-sync` - synchronization primitives such as the SPSC queue
- `crates/axle-arch-x86_64` - userspace-side x86_64 ABI glue and syscall entry helpers
- `crates/libax` - thin native `ax_*` userspace facade; native Nexus crates should depend on this crate, and any temporary `zx_*` compat reach-through now sits under `libax::compat`
- `crates/libzircon` - frozen `zx_*` compat wrappers over the current Axle `int 0x80` ABI; no longer a direct dependency for native `nexus-*` crates
- `crates/nexus-component` - minimal component declaration IR, resolver result shape, bootstrap-channel start payloads, and tiny lifecycle/directory messages
- `crates/nexus-fs-proto` - shared filesystem wire contract: identities, open
  flags, `GetVmo`, routed directory/file operations, and one VMO-backed bulk
  transfer option for ordinary file `read` / `write` used by `nexus-io` and
  the bootstrap service stack
- `crates/nexus-fs-model` - host-side DataFS-prep reference model over metadata
  state transitions, logical journaling, crash invariants, and replay
- `crates/nexus-io` - early userspace fd/namespace substrate: `FdOps`, `FdTable`,
  `WaitSpec`, handle-backed fd wrappers, longest-prefix `NamespaceTrie`, and
  one `ProcessNamespace` helper for logical-root / `cwd` path walk; now consumes the native `libax` facade rather than depending directly on `libzircon`
- `crates/nexus-rt` - single-thread userspace dispatcher/executor built on one port, one dispatcher timer, generation-safe signal registrations, and async channel/socket helpers; now depends on `libax`
- `kernel/axle-kernel` - live kernel integration layer
- `user/nexus-init` - extracted bootstrap `nexus-init` root manager plus shared
  manager/runtime logic reused by the minimal component smoke binaries;
  now also owns the current bootstrap `/boot` / `/pkg` / `/tmp` service tree
  and the built-in boot resolver / ELF runner glue that consumes it through
  `nexus-io`; the local service tree now supports directory enumeration,
  basic tmpfs-style link/rename/unlink, and read-only `GetVmo` for both seeded
  boot image VMOs and byte-backed package/resource assets; native syscall-facing
  code in this crate now goes through `libax`
- `user/echo-provider` - dedicated bootstrap component binary for the routed
  echo protocol provider
- `user/echo-client` - dedicated bootstrap component binary for the routed echo
  protocol client
- `user/controller-worker` - dedicated bootstrap component binary for minimal
  `Stop` / `Kill` lifecycle coverage
- `user/test-runner` - ring3 conformance runner loaded at the fixed bootstrap userspace VA with a
  16 MiB bootstrap code window for the Rust dispatcher/runtime and current
  `nexus-init` manager builds; the
  `component_smoke` entry is now only a thin wrapper into `user/nexus-init`
- `tools/syscalls-gen` - generator for `syscalls/generated/syscall_numbers.rs`
- `tools/axle-conformance` - host-side conformance runner, coverage checker, and replay tool
- `tools/axle-concurrency` - host-side concurrent seed runner for schedule hints, semantic edge coverage, and state signatures
  - also owns retained-seed QEMU replay:
    - direct guest-side seed runner generation first
    - scenario-bundle fallback when direct replay does not converge
- `tools/datafs-check` - host-side DataFS-prep explorer, fault injector, and
  crash-replay checker built on `nexus-fs-model`
- `tools/nexus-manifestc` - host-side compiler for the minimal Nexus component manifest text format

## Key entry points

- Kernel boot: `kernel/axle-kernel/src/main.rs` -> `_start()`
- Early arch init: `kernel/axle-kernel/src/arch/x86_64/mod.rs` -> `init()`
- Trap/IDT wiring: `kernel/axle-kernel/src/trap.rs`
- Syscall entry: `kernel/axle-kernel/src/arch/x86_64/int80.rs`
- Syscall dispatch: `kernel/axle-kernel/src/syscall/mod.rs`
- Internal data-move planner/executor: `kernel/axle-kernel/src/copy.rs`
- Object services: `kernel/axle-kernel/src/object.rs`
- Task / VM / scheduler core: `kernel/axle-kernel/src/task.rs`
- Bootstrap userspace mapping and ring3 entry: `kernel/axle-kernel/src/userspace.rs`
- Extracted bootstrap root manager entry: `user/nexus-init/src/main.rs`
- Userspace runner assembly selection and linking: `user/test-runner/build.rs`
- Syscall number generation: `tools/syscalls-gen/src/main.rs`
- Conformance CLI: `tools/axle-conformance/src/main.rs`
- Concurrent seed CLI: `tools/axle-concurrency/src/main.rs`
- DataFS-prep checker CLI: `tools/datafs-check/src/main.rs`
- Manifest compiler CLI: `tools/nexus-manifestc/src/main.rs`

## Build and test entry points

- Workspace root: `Cargo.toml`
- Common commands: `justfile`
- Syscall spec source: `syscalls/spec/syscalls.toml`
- Generated syscall numbers: `syscalls/generated/syscall_numbers.rs`
- Conformance contracts: `specs/conformance/contracts.toml`
- Conformance scenarios: `specs/conformance/scenarios/`
- Userspace conformance runner payloads: `specs/conformance/runner/`

## Current architectural split

- `crates/*` should be read first when you want the semantic core of a subsystem.
- `kernel/axle-kernel` should be read when you need the live bootstrap integration, trap behavior, object wiring, or page-table interaction.
- `user/test-runner` plus `specs/conformance/runner/*.S` describe what the current ring3 bootstrap workload actually runs.
- `user/test-runner` can also build a Rust-defined entry path when `AXLE_TEST_RUNNER_RUST_ENTRY=reactor_smoke` is set; that path now exercises the Phase-3 dispatcher/executor runtime instead of only the thinner reactor layer.
- `user/nexus-init` plus the dedicated `user/echo-*` / `user/controller-worker`
  binaries describe the current minimal component-manager bring-up workload.
- `references/` is the current-state documentation layer; `docs/` is lower-authority working material.

## Reference map

Read these next depending on subsystem:

- Architecture and ABI:
- `10_ARCH_X86_64_STARTUP.md`
- `11_SYSCALL_DISPATCH.md`
- `12_WAIT_SIGNAL_PORT_TIMER.md`

- Core object model:
- `20_HANDLE_CAPABILITY.md`
- `21_OBJECT_MODEL.md`

- Process, scheduler, and IPC:
- `30_PROCESS_THREAD.md`
- `31_PROCESS_THREAD_BOOTSTRAP_LAUNCH.md`
- `32_SCHEDULER_LIFECYCLE.md`
- `33_IPC.md`
- `34_IPC_CHANNEL.md`
- `35_IPC_SOCKET.md`

- VM:
- `40_VM.md`
- `41_VM_VMO_VMAR.md`
- `42_VM_FAULT_COW_LOAN.md`
- `43_VM_EXEC_PAGER_DEVICE_VM.md`

- Storage-prep:
- `44_DATAFS_PREP_MODEL.md`

- Starnix / Linux adaptation:
- `50_STARNIX_EXEC_MODEL.md`

- Testing:
- `90_CONFORMANCE.md`

Roadmap and engineering context:

- `AxleKernel_Roadmap_v0.3.md`
- `Axle_v0.3.md`
- `Nexus_Roadmap_v0.3.md`
