# Nexus

Nexus is a research operating-system prototype for **Causally Scoped Effect
Revocation (CSER)**: kernel-enforced causal effect scopes for work delegated to
restartable user-space OS services.

[GitHub release](https://github.com/chenty2333/Nexus/releases/tag/v0.1.0) ·
[Zenodo archive](https://zenodo.org/records/21343496) ·
[DOI: 10.5281/zenodo.21343496](https://doi.org/10.5281/zenodo.21343496)

## Why CSER?

Revoking a handle can prevent future use of an authority, but it does not by
itself account for effects already derived from that authority. A request may
have crossed a restartable scheduler, pager, Linux personality, filesystem, or
network service; it may also own a queue slot, pinned memory, a device request,
or an externally visible result. A service crash makes the problem harder: the
replacement must reject stale work without losing the obligations that were
already committed.

CSER gives one root authority a kernel-maintained causal scope. Effects derived
through different services retain explicit ancestry, resource ownership, and
commit state, so revocation can close the authority generation and follow the
affected work instead of relying on ordinary handle invalidation or a global
object scan.

## How it works

- **Scopes and effects** record causal authority and the work derived from it.
- **Authority epochs** fence a revoked authority generation; independent
  **binding epochs** fence crashed or replaced service instances.
- A kernel-owned **commit gate** serializes `Commit` with `RevokeBegin`. If
  revocation wins, old uncommitted work cannot first commit afterward.
- **Typed budgets** account for resources, while per-scope reverse indexes make
  the affected descendants and effects discoverable during closure.
- Pre-commit work can abort. Post-commit work must complete, drain, reset, or
  retain an honest tombstone; CSER does not claim to undo an external event.
- Rebinding never silently adopts stale work. Explicit adoption and a minimal
  kernel fallback preserve fencing and bounded progress after service failure.

The detailed state machines and linearization points are in
[the CSER specifications](specs/cser/README.md) and
[ARCHITECTURE.md](ARCHITECTURE.md).

## What v0.1.0 establishes

The `v0.1.0` release is a bounded, reproducible research artifact. It combines
twelve PlusCal/TLA+ specification families, an independent safe-Rust reference
model, an OSTD kernel prototype, retained Linux pressure workloads, and
mediated VirtIO/reset/IOMMU evidence. Its additive composition places
personality, pager, scheduler, filesystem, VirtIO, network, and readiness
effects beneath one root authority.

The accepted evaluation boundary is:

| Evidence | Released result | Boundary |
| --- | ---: | --- |
| Concurrency | 14/14 Checked | `production transition source under a Loom-modeled outer mutex` |
| Fault injection | 20/20 Checked | Case-local ledgers in release, single-vCPU, single-thread-TCG QEMU |
| Structural scale | 14/14 Checked | Finite tuples; no asymptotic or production `O(k)` claim |
| Performance | 29/29 Observed | Guest-visible TSC samples; no threshold, baseline, or hardware-cycle claim |
| Prior art | 16 sources | `v0.1.0`: 14 full-text and 2 metadata-only; current main follow-up: 15 and 1 |
| Contribution decision | `narrow` | A bounded compositional result, not novelty or firstness |

This release does **not** establish whole-system proof, SMP or production-lock
correctness, lock freedom, low overhead, Linux/VFS/TCP breadth, rollback of
durable external effects, a shared production fault scope, or identity-preserving
same-boot composition with the real-DMA receipt. The seven-domain successor
uses a fresh root cohort rather than reusing the retained workload and device
effect identities. [NARRATIVE.md](NARRATIVE.md) gives the complete evidence and
claim ledger.

## Reproduce the release

The supported host boundary is Linux x86-64 with Docker, Git, Bash, and a normal
Linux userland. Rust, Java, cargo-osdk, OVMF, QEMU, and guest toolchains are
pinned in Docker images. Current main additionally vendors the exact TLA+
verifier bytes, checks the installed copy before use, and binds a runtime
verifier receipt into the model/spec receipt chain and complete bundle.

For a quick environment and non-QEMU check:

```bash
./x doctor
./x test --quick
```

The original `v0.1.0` clean-clone workflow is:

```bash
git clone https://github.com/chenty2333/Nexus.git
cd Nexus
git checkout --detach v0.1.0
./x doctor
./x test --quick
NEXUS_REBUILD=1 ./x verify
./x verify-bundle target/verification/artifact-bundle
```

The upstream project later replaced the mutable prerelease asset named by the
historical Dockerfile. That checksum therefore still fails closed, but a new
`v0.1.0` cold build can no longer retrieve the accepted bytes from that URL.
The published evidence bundle remains independently auditable. Current main
preserves those exact verifier bytes under `third_party/tlaplus/` for future
cold runs without changing the `v0.1.0` tag, release, or archive record.

The cold gate can take tens of minutes and uses substantial Docker/workspace
storage. Exact resource expectations, interpretation rules, published bundle
hashes, and release procedures are documented in [ARTIFACT.md](ARTIFACT.md).
Development commands and change discipline are in
[CONTRIBUTING.md](CONTRIBUTING.md).

### Public command surface

The stable front door is deliberately small:

| Command | Purpose |
| --- | --- |
| `./x doctor` | Check the supported host, pinned tools, and backend entry points. |
| `./x build [all\|model\|kernel\|virtio]` | Build a selected artifact graph without running QEMU. |
| `./x test [--unit\|--quick\|--system\|--full]` | Run progressively broader development gates. |
| `./x run [kernel\|virtio\|composition]` | Run a bounded OSTD or composition receipt. |
| `./x verify` | Run the canonical complete acceptance graph. |
| `./x verify-bundle [DIRECTORY]` | Audit a canonical cold bundle against its clean checkout. |
| `./x clean [--all]` | Remove build caches while preserving evidence and release outputs; `--all` also removes run evidence. |

The exact tier contracts and claim discipline are kept in
[CONTRIBUTING.md](CONTRIBUTING.md), not repeated in the project introduction.

## Repository map

| Path | Role |
| --- | --- |
| `specs/cser/` | Normative PlusCal/TLA+ protocols and properties |
| `crates/cser-model/` | Independent `no_std + alloc` safe-Rust reference model |
| `crates/cser-transition-gates/` | Production-transition-source Loom harnesses |
| `crates/nexus-effect-peer-wire/` | Independently consumable frozen native-v1 serde contract and canonical corpus |
| `crates/nexus-effect-peer/` | Same-boot production Registry process and replay boundary; re-exports the wire crate |
| `crates/nexus-portal-abi/` | `nexus.portal.v2` preview wire/dispatcher contract, exercised by the session-local kernel Registry adapter; no user/kernel transport or persistent selector recovery yet |
| `crates/nexus-supervisor/` | Bounded provider-neutral restart/recovery manager; its generic OSTD adapter has an initial-active binding, UserMode-only fault boundary, Nexus-owned bounded worker, and exact reap/health permit, but no filesystem lifecycle run is claimed |
| `kernel/nexus-ostd/` | Maintained OSTD kernel prototype and bounded workload paths |
| `experiments/ostd-virtio-cser-spike/` | Mediated VirtIO/reset/IOMMU component evidence |
| `tests/guest/linux/` | Hash-pinned Linux compatibility-pressure inputs |
| `evaluation/stage7b/` | Released evaluation contracts, sources, and race catalog |
| `evaluation/production-identity/causal-coverage.toml` | Audited causal-boundary inventory with explicit uncovered gaps; not runtime coverage evidence |
| `evaluation/production-identity/causal-evidence-overlay.toml` | Locked-empty v2 T0 baseline over the byte-frozen v1 causal inventory and 66-cell matrix; every promotion is rejected pending a structured v3 evidence contract |
| `status/` | Moving exact-revision checkpoints and frozen wire contracts |
| `docs/research/engineering-reuse-map.md` | Adopt/borrow/own decisions for the nine engineering priorities |
| `tools/xtask/`, `tools/workflow/` | Reproducible build, evaluation, and evidence tooling |
| `./x` | Public workflow entry point |

The reference model and OSTD implementation deliberately do not share state
transition code. The mediated device experiment remains component-consistency
evidence rather than being relabeled as same-effect, same-boot refinement.

## Current research line

Post-release work is testing a stricter production-identity result; it is not a
retroactive expansion of `v0.1.0`. The hypothesis and acceptance rules are in
[RFC 0001](docs/rfcs/0001-production-identity.md), and the explicit preflight
decision is [narrow-go](docs/research/v0.2-preflight-decision.md). Until the
real filesystem, same-boot device, OSTD IRQ/SMP, measurement, and final
contribution gates close together, these changes remain prospective v0.2
research rather than a v0.2 release claim.

Current main has established only the reusable device build foundation: the
primary kernel and Stage 5B consume one hash-bound canonical OSTD 0.18 overlay,
one hash-bound MIT virtio-drivers 0.13 split-publication overlay, and the
optional production VirtIO facade. Its descriptive identity preflight and
infallible publication/reset/IOTLB-quiescence plans are source/build evidence
only; the primary boot still has no device GSI mapping or IRQ delivery,
same-boot DMA identity, or SMP claim.

A second, separately routed prospective line is now specified by
[RFC 0002](docs/rfcs/0002-handoff-admission-profile.md). Its independent first
round asks whether Nexus can reversibly freeze local effect admission, consume
one typed non-equivocating ownership decision, and produce honest closure
progress. The v2 research lane additionally maps that profile into the
in-memory production `EffectRegistry` and exposes it through the same-boot
`nexus-effect-peer` host process for an out-of-tree vISA/Nexus qualification.
Neither lane enters the accepted `v0.1.0` catalog or establishes host-reboot,
rollback-resistance, retained-device wire, OSTD IRQ/SMP execution, or a joint
runtime result.

## Documentation

- [NARRATIVE.md](NARRATIVE.md) is the end-to-end technical research account and
  claim ledger.
- [VISION.md](VISION.md) defines the research question, candidate contribution,
  exclusions, and evidence language.
- [ARCHITECTURE.md](ARCHITECTURE.md) maps kernel, service, resource, and device
  boundaries.
- [specs/cser/README.md](specs/cser/README.md) is the normative semantics index.
- [ARTIFACT.md](ARTIFACT.md) is the reproduction, bundle-audit, and archival
  guide.
- [CONTRIBUTING.md](CONTRIBUTING.md) documents the development workflow.
- [RFC 0001](docs/rfcs/0001-production-identity.md) defines the prospective
  production-identity composition and `v0.2.0` acceptance contract; none of its
  requirements are claimed by `v0.1.0`.
- [RFC 0003](docs/rfcs/0003-causal-coverage-closure.md) records the prospective
  closure order for the current causal-coverage gaps; it is a design contract,
  not implementation or runtime evidence.
- [REWORK.md](REWORK.md) is the historical migration and deletion ledger; it is
  not the current roadmap or semantics source.

## Paper and citation status

There is no peer-reviewed Nexus paper at this time. `NARRATIVE.md` is a
technical research narrative, while the published Zenodo object is a software
release and reproducibility artifact. Cite the archived `v0.1.0` release using
[CITATION.cff](CITATION.cff) or:

> Tianyi Chen. (2026). *Nexus: Causally Scoped Effect Revocation* (v0.1.0)
> [Software]. Zenodo. https://doi.org/10.5281/zenodo.21343496

## Contributing and license

Before changing semantics or evidence, read
[CONTRIBUTING.md](CONTRIBUTING.md). Nexus is released under the
[Unlicense](LICENSE). Third-party and derived components retain their own
license boundaries; in particular, the repository-wide canonical OSTD overlay
and extracted VirtIO facade remain MPL-2.0-covered. The canonical
virtio-drivers overlay remains MIT-covered with the exact upstream notice under
`patches/`; the device experiment retains its separate package notice.
