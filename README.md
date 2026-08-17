# Nexus

Nexus is an experimental operating-system substrate for **Causally Scoped
Effect Revocation (CSER)**: keeping escaped effects and their logical or
physical claims under enforceable custody after the executor that created them
exits or is replaced.

> Process death can revoke future authority. It is not evidence that an
> already published reply, provider operation, queue entry, pinned page, DMA
> mapping, or other external effect disappeared.

CSER separates executor lifetime, durable effect lifetime, and resource-claim
custody. Unknown outcomes require reconciliation. Missing physical quiescence
evidence retains the affected claim and refuses reuse. The project is a bounded
research prototype, not a production, exactly-once, rollback, or
hardware-general claim.

## Start here

- [Terrain](maproom/terrain.md): research question, safety model, design
  reasoning, evidence discipline, and claim limits.
- [Basecamp](maproom/basecamp.md): the deliberately established current
  position, evidence boundary, and paused work.
- [Route](maproom/route.md): the user-selected high-level direction.
- [Hazards](maproom/hazards.md): verified project-specific failure modes and
  operational pitfalls.
- [Contributing](CONTRIBUTING.md): supported local workflows.

The maproom is the only current project-orientation source. Its terrain,
basecamp, and route are user-directed documents, not progress files to update
automatically. Historical
architecture, vision, RFC, release-ledger, and vertical-slice documents remain
available through Git history and immutable release tags rather than competing
with current main.

## Current implementation

The portable authoritative state machine is `crates/cser-core`. It owns catalog
admission, estates and composite effects, claims, exact custody, fencing,
settlement, retirement evidence, journal records, checkpoints, recovery, and
canonical invariants. `crates/cser-model` contains the independent normalized
oracles used by current differential and Loom tests.

`kernel/nexus-ostd` embeds that core in the OSTD kernel and contains the current
ATA/TPM persistence, reply/DMA recovery, asynchronous Tool endpoint adapter,
bounded CSER3 handoff, strongest independent handoff baseline, and experimental
vNext journal paths.

The trusted-local endpoint uses independently durable adapter and provider
databases. POST persists Accepted work; leased workers persist Pending, query
the provider by exact operation identity, and publish terminal evidence only
after a verified provider result. Guest recovery performs an exact GET before
any same-key retry, and exact 404 is the sole absence authority.

The bounded single-hop handoff verifies one canonical `ChildDescriptorV1` and
permits child first observation only after the durable parent-release/child-
intent pivot. It is not a general workflow graph or dynamic-component API.

The legacy journal remains the default. The vNext same-segment append and
checkpoint implementation is opt-in and experimental: it reduces controlled
fill write amplification while increasing read, flush, and hashing work in the
current measurements.

## Evidence

The current public development evidence is intentionally small:

- [Final asynchronous applicability and vNext evidence](docs/research/evidence/cser-async-vnext-final/README.md)
  contains six sanitized real-QEMU rows, four portable state-profile rows, a
  bounded journal-fill comparison, and a HMAC-pseudonymized applicability
  projection.
- [Matched logical handoff evidence](docs/research/evidence/cser-handoff-matched/README.md)
  contains five crash cuts for CSER and the structurally independent baseline,
  with two recovery boots and exact endpoint/provider ledgers per row.

Both bundles state their source commits and limits. Raw identities, databases,
logs, media, TPM state, paths, container identities, and HMAC keys are not
published. QEMU/TCG observations are not physical-hardware evidence.

The historical `v0.1.0` artifact remains available from the immutable
[GitHub release](https://github.com/chenty2333/Nexus/releases/tag/v0.1.0),
[Zenodo record 21343496](https://zenodo.org/records/21343496), and
[DOI 10.5281/zenodo.21343496](https://doi.org/10.5281/zenodo.21343496).
Reproduce that historical release from its tag; current main does not carry a
second mutable copy of its prose, models, and receipts.

## Repository map

| Path | Role |
| --- | --- |
| `maproom/` | Conceptual terrain, established position, selected route, and verified hazards |
| `crates/cser-core/` | Portable authoritative CSER state machine |
| `crates/cser-model/` | Current independent differential oracles |
| `crates/nexus-ostd-virtio/` | Pinned VirtIO/PCI/IOMMU substrate used by the kernel |
| `kernel/nexus-ostd/` | OSTD production embedding and bounded experiment lanes |
| `kernel/nexus-ostd/tools/cser-experiment/` | Trusted-local endpoint, provider, bridge, matrix, and evidence tools |
| `docs/research/evidence/` | Current sanitized source-bound evidence bundles |
| `tools/xtask/` | Small host workspace build/check/test runner |
| `./x` | Public local workflow entry point |

## Local workflows

The supported front door is `./x`:

```text
./x doctor
./x build [all|model|kernel]
./x test [--unit|--quick|--system|--full]
./x check
./x fmt
./x verify
./x clean [--all]
```

The root workflow uses a pinned Rust container. Kernel experiment-specific
commands remain under `kernel/nexus-ostd/x` and are documented beside the
experiment tools. See [CONTRIBUTING.md](CONTRIBUTING.md) before changing safety
or evidence boundaries.

## Citation and license

There is no peer-reviewed Nexus paper at this time. Cite the archived software
release using `CITATION.cff` or the Zenodo DOI above.

Nexus is released under the [Unlicense](LICENSE). Third-party and derived
components retain their own license boundaries and notices.
