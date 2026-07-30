# Nexus

Nexus is a research operating-system prototype for **Causally Scoped Effect
Revocation (CSER)**: kernel-enforced authority, effect custody, and causal
closure for work delegated to restartable user-space OS services.

> A service can die and immediately lose its future authority. That death is
> not proof that its committed effects, reply obligations, queue slots, pinned
> memory, or DMA ownership have disappeared.

[GitHub release](https://github.com/chenty2333/Nexus/releases/tag/v0.1.0) ·
[Zenodo archive](https://zenodo.org/records/21343496) ·
[DOI: 10.5281/zenodo.21343496](https://doi.org/10.5281/zenodo.21343496)

## The problem

Revoking a handle prevents future use of that handle. It does not settle work
already derived from it. A request may have crossed a restartable scheduler,
pager, Linux personality, filesystem, or network service while still owning a
reply, timer, queue entry, pinned page, device request, I/O translation, or an
externally visible result.

Ordinary process cleanup conflates two different facts:

- the failed service incarnation must no longer initiate or commit new work;
- already committed work must remain represented, and its concrete claims held,
  until it completes, drains, resets, or is honestly recorded as indeterminate.

CSER explores whether a small kernel can enforce that separation across
multiple services and resource domains. It is a candidate compositional
mechanism, not a novelty, firstness, exactly-once, or production-readiness
claim. The short technical statement is [docs/CSER.md](docs/CSER.md).

## Working semantic contract

These requirements define the rebaselined portable core and its implemented,
bounded `cser-production` profile. They are not broader production-readiness or
hardware claims; the evidence boundary for current `main` is stated below.

- **Causal scopes and effects** record the authority that created work and the
  descendants and resources derived from it.
- **Authority epochs** fence a revoked scope generation. Independent
  **binding epochs** fence crashed or replaced service incarnations.
- A kernel-owned **commit gate** serializes `Commit` with `RevokeBegin`. If
  revocation wins, old uncommitted work cannot first commit afterward.
- **Typed credits and claims** account for queue capacity, memory, device, and
  reply obligations without copying or silently releasing them. A complete
  design must distinguish causal owner, charge owner, physical custodian, and
  settlement claimant instead of hiding them in one `owner` field.
- **Reverse-indexed closure** discovers the affected work without relying on a
  global object scan.
- Pre-commit work may abort. Post-commit work must complete, drain, reset, or
  retain an explicit tombstone; CSER does not claim to undo external history.
- Rebinding does not silently inherit stale work. `AdoptEffect` transfers
  bounded authority to continue an eligible effect; `ClaimSettlement` only
  authorizes reconciliation, publication, or retirement of an already
  committed claim. Neither operation resurrects the dead incarnation.
- Closure releases a physical claim only under domain-specific evidence. When
  evidence is unavailable, quotas, scoped backpressure, reset, or
  operator-visible reconciliation must make the safety/availability tradeoff
  explicit.

The released finite-state semantics are indexed in
[specs/cser/README.md](specs/cser/README.md); their exact checked boundaries
remain evidence rather than an implementation claim, and the working
requirements above do not retroactively change them. The corresponding
kernel, service, resource, and device map is
[ARCHITECTURE.md](ARCHITECTURE.md).

## Status

| Track | Status | Meaning |
| --- | --- | --- |
| `v0.1.0` | Published, archived research artifact | Bounded CSER composition with reproducible models, implementation slices, and receipts |
| Current `main` | CSER Core Rebaseline re-seal pending | Portable core, persistent recovery, reply/DMA recovery, and the single production Registry cutover are implemented; exact CI exposed swtpm capability and host/container Unix data-FD harness gaps, so the scoped replacement still requires a new clean receipt and exact-revision CI PASS |
| Production system | Not established | The `cser-production` profile is a bounded QEMU research path, not a hardware-general, SMP, availability, or production-readiness result |
| Paper | None peer reviewed | `NARRATIVE.md` is a technical research account; the Zenodo object is software and reproducibility evidence |

### What `v0.1.0` establishes

The release binds twelve PlusCal/TLA+ specification families, an independent
safe-Rust reference model, an OSTD kernel prototype, retained Linux pressure
workloads, and mediated VirtIO/reset/IOMMU component evidence.

| Evidence | Released result | Boundary |
| --- | ---: | --- |
| Concurrency | 14/14 Checked | Production transition source under a Loom-modeled outer mutex |
| Fault injection | 20/20 Checked | Case-local ledgers; single-vCPU, single-thread-TCG QEMU |
| Structural scale | 14/14 Checked | Finite tuples; no asymptotic or production `O(k)` claim |
| Performance | 29/29 Observed | Guest-visible TSC samples; no threshold, baseline, or hardware-cycle claim |
| Prior art | 16 sources | 14 full-text and 2 metadata-only in the release audit |
| Contribution decision | `narrow` | Bounded compositional result, not novelty or firstness |

The release does **not** establish whole-system proof, SMP or production-lock
correctness, lock freedom, low overhead, Linux/VFS/TCP breadth, rollback of
durable external effects, a shared production fault scope, or
identity-preserving same-boot composition with the real-DMA receipt. The
complete evidence and non-claim ledger is [NARRATIVE.md](NARRATIVE.md).

### Current research line

Post-release work now follows
[RFC 0006](docs/rfcs/0006-cser-core-semantic-rebaseline.md). The live kernel
default is the single `cser-production` profile: one recovered portable-core
owner is shared by the stateless `NXP3` portal, the `core-v1` supervisor, and
the reply and DMA adapters. The old live Registry, portal glue, supervisor
state, and kernel semantic mirrors have been removed from the production
closure; the runtime does not dual-write old and new authority state.

The portable core defines domain-classified obligations, claims, fencing,
adoption, settlement, journal records, replay, and freshness coordinates. Its
independent safe-Rust oracle, property tests, trace conformance, and Loom tests
cover reply and DMA semantics, revoke/claim outcomes, stale generations, and
repeated crash windows. The OSTD harness first runs real guest reply and DMA
slices through the mutually exclusive, `--no-default-features`, test-only
`cser-core-reply-recovery` and `cser-core-dma-recovery` OSDK schemes. It then
boots `cser-production` four times over the same ATA PIO journal, secondary
reply outbox, and swtpm state, with device quarantine established before
replay. Those focused schemes provide domain evidence; they are not alternate
production Registries and do not introduce live dual-write.

The historical clean receipt at `c06e9f4` remains retained evidence for its
exact runner. It shows initial commit and retained claims, a second service
crash after durable reply apply intent, reconciliation without a second intent
and final settlement, a stable repeated-recovery boot, service/binding
generations `1/1` through `4/4`, and increasing boot, journal, and device
freshness. Exact-B CI subsequently passed the full core/model/property/Loom
gate but rejected an optional swtpm state-lock argument before the production
boots. Candidate C1 removed that option and made daemon shutdown fail-closed;
exact-C1 CI then passed the core gate and both focused guests before rejecting
the v0.8 `disable-auto-shutdown` flag. The runner now negotiates that
capability. Exact-C2 CI passed TPM provisioning, then lost QEMU's Unix ancillary
data socket at the Docker/AppArmor host boundary before the first guest ran.
The AppArmor opt-out is now limited to that network-none TPM fixture container;
current release status remains open until a new clean receipt and exact-revision
CI PASS are retained. Every such receipt remains bounded to one-vCPU QEMU/TCG
and swtpm: it
does not establish physical TPM anti-rollback, physical power-loss behavior,
hardware-general DMA quiescence or custody, crash-persistent PFN/IOVA custody,
resource reuse authorization, or SMP correctness. Historical IRQ Phase A and
`v0.1.0` evidence retain their original boundaries.

## Use the repository

The supported host boundary is Linux x86-64 with Docker, Git, Bash, and a
normal Linux userland. Rust, Java, cargo-osdk, OVMF, QEMU, and guest toolchains
are pinned or checked by the workflow.

Start with the fast, non-QEMU path:

```bash
./x doctor
./x test --quick
```

The public workflow is intentionally small:

```bash
./x build [all|model|kernel]
./x test [--unit|--quick|--system|--full]
./x run [kernel]
./x verify
./x clean [--all]
```

`--unit` stays on the host semantic graph and `--quick` adds the kernel static
gate. `--system` runs the two focused guest evidence schemes followed by the
four-boot production recovery path and writes an explicitly non-sealable proof.
`--full` is the same clean-source seal gate as `verify`; it rejects tracked,
staged, or nonignored untracked source changes before QEMU. Set
`NEXUS_REBUILD=1` when an intentional cold image rebuild is required. The full
path can take tens of minutes and substantial Docker/workspace storage. The
immutable `v0.1.0` artifact workflow and its historical cold-fetch caveat
remain documented in
[ARTIFACT.md](ARTIFACT.md) and [CONTRIBUTING.md](CONTRIBUTING.md); those release
instructions are not the current production-recovery front door.

## Repository map

| Path | Role |
| --- | --- |
| `specs/cser/` | Released PlusCal/TLA+ families and checked boundaries |
| `crates/cser-core/` | Portable authoritative `no_std + alloc` CSER state machine, journal, replay, and domain profiles |
| `crates/cser-model/` | Independent safe-Rust oracles and Loom scenario drivers |
| `crates/cser-trace-conformance/` | Frozen-trace replay and projection comparison |
| `crates/nexus-effect-peer-wire/` | Retained frozen wire corpus boundary; not a live semantic owner |
| `crates/nexus-ostd-virtio/` | Separate pinned VirtIO/PCI/IOMMU substrate used by the kernel adapter |
| `kernel/nexus-ostd/` | Sole authoritative `cser-production` profile, two test-only guest evidence schemes, and four-boot recovery harness |
| `docs/research/irq-spike-phase-a/` | Retained historical one-vCPU IRQ component evidence |
| `evaluation/`, `status/` | Released evidence and moving exact-revision checkpoints |
| `tools/xtask/` | Four-member workspace build, test, Loom, and static-cutover gates |
| `./x` | Public workflow entry point |

The root Cargo workspace contains exactly `crates/cser-core`,
`crates/cser-model`, `crates/cser-trace-conformance`, and
`crates/nexus-effect-peer-wire`; the OSTD kernel and VirtIO substrate retain
their separate pinned build graphs. The independent oracle does not call
production transition code to compute expected results.

## Documentation

- [docs/CSER.md](docs/CSER.md): short committed mechanism and evidence statement
- [VISION.md](VISION.md): committed research contract, non-goals, and
  evidence vocabulary
- [NARRATIVE.md](NARRATIVE.md): end-to-end research account and claim ledger
- [ARCHITECTURE.md](ARCHITECTURE.md): committed kernel/service/resource map
- [specs/cser/README.md](specs/cser/README.md): released protocol and evidence index
- [ARTIFACT.md](ARTIFACT.md): reproduction and archive audit guide
- [CONTRIBUTING.md](CONTRIBUTING.md): development workflow and claim discipline
- [REWORK.md](REWORK.md): historical migration ledger, not the semantics source

## Citation and license

There is no peer-reviewed Nexus paper at this time. Cite the archived software
release using [CITATION.cff](CITATION.cff) or:

> Tianyi Chen. (2026). *Nexus: Causally Scoped Effect Revocation* (v0.1.0)
> [Software]. Zenodo. https://doi.org/10.5281/zenodo.21343496

Nexus is released under the [Unlicense](LICENSE). Third-party and derived
components retain their own license boundaries. See the notices beside the
OSTD and VirtIO overlays before redistribution.
