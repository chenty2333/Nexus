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

These are research requirements, not claims that the current runtime already
implements a new production core:

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
| Current `main` | Post-release research checkpoint | Additional conformance, reply-adoption oracle, evidence-registry, and IRQ-spike work; not a `v0.2.0` release |
| Production system | Not established | Real supervisor lifecycle, complete IRQ/reset/IOTLB closure, SMP refinement, resource pressure, and production error paths remain open |
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

Post-release work is testing a stricter question: can the same committed
effect retain its causal identity and concrete obligations across service
death, reject every stale incarnation, and permit a fenced successor to
reach one evidence-backed terminal disposition?

Current `main` contains bounded trace-conformance work, a safe-Rust
post-commit reply-adoption oracle for the first four obligations in
[RFC 0005](docs/rfcs/0005-postcommit-reply-adoption.md), an isolated Registry
evidence unit, and a retained one-vCPU IRQ Phase A observation. These are
source, model, and component observations. They do not establish the full
service lifecycle, production transition atomicity, repeated-crash behavior,
real multi-queue IRQ delivery, hardware DMA quiescence, or SMP correctness.

The remaining engineering gates are:

1. stable kernel/service ABI and real supervisor lifecycle;
2. complete causal coverage at dangerous post-commit fault windows;
3. same-effect retained ownership through IRQ, reset, and IOTLB closure;
4. SMP and production-lock refinement;
5. operator-visible reconciliation, quotas, and bounded backpressure; and
6. resource-pressure, stability, and production error paths.

Design documents and local experiments do not retroactively widen the
`v0.1.0` claim. Every later milestone requires source-bound evidence at its
exact revision.

## Use the repository

The supported host boundary is Linux x86-64 with Docker, Git, Bash, and a
normal Linux userland. Rust, Java, cargo-osdk, OVMF, QEMU, and guest toolchains
are pinned or checked by the workflow.

Start with the fast, non-QEMU path:

```bash
./x doctor
./x test --quick
```

Broader development and acceptance entry points are:

```bash
./x build [all|model|kernel|virtio]
./x test [--unit|--quick|--system|--full]
./x run [kernel|virtio|composition]
NEXUS_REBUILD=1 ./x verify
./x verify-bundle target/verification/artifact-bundle
```

The full gate can take tens of minutes and substantial Docker/workspace
storage. The immutable `v0.1.0` tag also has a documented cold-fetch caveat
after an upstream prerelease asset was replaced. Published-bundle audit,
exact hashes, resource expectations, tier contracts, and archival procedures
are in [ARTIFACT.md](ARTIFACT.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).

## Repository map

| Path | Role |
| --- | --- |
| `specs/cser/` | Released PlusCal/TLA+ families and checked boundaries |
| `crates/cser-model/` | Independent `no_std + alloc` safe-Rust reference oracles |
| `crates/cser-trace-conformance/`, `crates/cser-transition-gates/` | Trace replay and production-source concurrency checks |
| `kernel/nexus-ostd/` | Maintained OSTD kernel prototype and bounded workload paths |
| `experiments/ostd-virtio-cser-spike/` | Mediated VirtIO/reset/IOMMU component evidence |
| `evaluation/`, `status/` | Released evidence and moving exact-revision checkpoints |
| `tools/xtask/`, `tools/workflow/` | Reproducible build, evaluation, and evidence tooling |
| `./x` | Public workflow entry point |

The reference model and OSTD implementation deliberately do not share state
transition code. Device experiments remain component evidence unless an exact
same-effect refinement is separately established.

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
