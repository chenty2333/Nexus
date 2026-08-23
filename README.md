# Nexus

Nexus is an experimental operating-system substrate for **Causally Scoped
Effect Revocation (CSER)**: keeping escaped effects and their logical or
physical claims under enforceable custody after the executor that created them
exits or is replaced.

> Process death can revoke future authority. It is not evidence that a
> published reply, provider operation, queue entry, pinned page, DMA mapping,
> or other external effect disappeared.

CSER separates executor lifetime, durable effect lifetime, and resource-claim
custody. Unknown outcomes require reconciliation; missing physical-quiescence
evidence retains the claim. Nexus is a bounded research prototype, not a
production, exactly-once, rollback, or physical-hardware claim.

## Start here

- [Terrain](maproom/terrain.md): research question, safety model, and claim
  limits.
- [Basecamp](maproom/basecamp.md): deliberately established project position.
- [Route](maproom/route.md): user-selected direction.
- [Hazards](maproom/hazards.md): verified project-specific pitfalls.
- [Contributing](CONTRIBUTING.md): development workflow and boundaries.

Maproom maintenance is user-directed. Historical design material and evidence
belong to Git history and immutable release archives, not another current
source of truth.

## Implementation

`crates/cser-core` is the portable authoritative state machine. It owns
catalog admission, effects, claims, exact custody, fencing, settlement,
retirement evidence, journaling, recovery, and canonical invariants.
`crates/cser-model` supplies independent normalized oracles.

`kernel/nexus-ostd` embeds the core in the OSTD kernel. Its system path covers
ATA PIO persistence, focused reply recovery, a DMA IRQ pre-escape fail-closed
capability gate, typed predecessor
rejection, and persistent restart recovery in QEMU. The endpoint/provider
reference tests remain host-side tests of the trusted-local reference path.

## Development entry point

The only supported developer interface is:

```text
cargo nexus {check,test,kernel,system,seal,clean}
```

The root workspace follows the rolling `nightly` selected by
`rust-toolchain.toml`. xtask reads the local rustup toolchain manifest to find
that toolchain's release date, then builds or verifies the corresponding dated
nightly OSDK/QEMU image and checks the image's `rustc` commit hash. This keeps
the kernel image tied to the compiler actually invoking the front door.

| Command | Purpose |
| --- | --- |
| `cargo nexus check` | Check the portable workspace and its bare-metal profiles. |
| `cargo nexus test` | Run endpoint/provider reference tests and portable core/model tests. |
| `cargo nexus kernel` | Check and build the OSTD kernel through the exact image. |
| `cargo nexus system` | Run ATA PIO, focused reply recovery, the DMA IRQ fail-closed gate, predecessor rejection, and four persistent QEMU boots. |
| `cargo nexus seal` | Require a clean Git snapshot, run the same system path, and publish a sanitized receipt. |
| `cargo nexus clean` | Clean build output while preserving raw system artifacts. |
| `cargo nexus clean --raw` | Also remove raw system artifacts. |

`seal` records the dist date plus the verified `rustc` commit date and hash,
then writes only the sanitized receipt and checksum to `target/nexus/public/`;
raw journals, logs, media, and TPM-fixture state stay local and are not
uploaded.

## Build boundaries

- Cargo owns the root workspace, rolling nightly selection, and the `nexus`
  alias that starts xtask.
- xtask reads the local rustup manifest's release date to select the dated
  nightly image, verifies its `rustc` commit hash, and owns the supported
  command composition.
- `kernel/nexus-ostd/OSDK.toml` defines the four OSDK profiles and their QEMU
  configuration.
- The root `Dockerfile` creates the exact-nightly OSDK/QEMU image and supplies
  the OSTD, cargo-osdk, QEMU, and firmware build environment.
- The host supplies Docker and `swtpm`; the TPM fixture daemon stays on the
  host while QEMU connects to it through the controlled system run.

Cargo-OSDK generates a runner workspace for which `--locked` is not propagated.
That is the sole controlled lock exception: the reviewed
`kernel/nexus-ostd/osdk-runner-base/` snapshot has its own lockfile and is
checked unchanged before use.

## Repository map

| Path | Role |
| --- | --- |
| `maproom/` | Conceptual terrain, established position, route, and hazards |
| `crates/cser-core/` | Portable authoritative CSER state machine |
| `crates/cser-model/` | Independent normalized oracles |
| `crates/nexus-ostd-virtio/` | VirtIO/PCI/IOMMU substrate used by the kernel |
| `kernel/nexus-ostd/` | OSTD embedding and its four OSDK profiles |
| `kernel/nexus-ostd/tools/cser-experiment/` | Endpoint/provider reference implementation and tests |
| `tools/xtask/` | `cargo nexus` command runner |

## Citation and license

There is no peer-reviewed Nexus paper. Cite the archived software release using
`CITATION.cff` or its recorded DOI. Nexus is released under the
[Unlicense](LICENSE); third-party components retain their own notices.
