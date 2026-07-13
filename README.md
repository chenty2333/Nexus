# Nexus

Nexus is a research operating-system prototype for **Causally Scoped Effect
Revocation (CSER)**: kernel-enforced causal effect scopes for restartable
user-space OS services. One authority delegation can cover scheduler, pager,
personality, readiness, and mediated-I/O effects; revocation closes their shared
commit gate and drives every enrolled effect to one honest terminal outcome.

The current checkpoint includes a bounded, single-CPU seven-domain Linux I/O
composition successor plus the six retained Linux core inputs with bounded
Checked/Observed evidence. It composes fresh personality, pager, scheduler,
filesystem, VirtIO, network, and readiness effects beneath one root authority
without rewriting the frozen five-domain predecessor. This is not a production
Linux personality, general or persistent filesystem, TCP/IP stack, real-DMA
same-boot integration, or proof of identity-preserving Stage 5B composition.
See [NARRATIVE.md](NARRATIVE.md) for the end-to-end research account,
[VISION.md](VISION.md) for the research claim,
[ARCHITECTURE.md](ARCHITECTURE.md) for boundaries, and [REWORK.md](REWORK.md)
for the migration ledger. [ARTIFACT.md](ARTIFACT.md) is the clean-clone,
evidence-bundle, and archival reproducibility guide.

The Stage 7B checkpoint adds a deliberately narrower evaluation claim: 14
races are Checked at the exact boundary `production transition source under a
Loom-modeled outer mutex`; a
release, single-vCPU, single-thread-TCG QEMU evaluator checks 20 fault cells and
14 structural scale points; and 29 guest-visible TSC cases are retained as
Observed raw samples with no thresholds. The primary-source comparison matrix
contains 16 rows, of which 14 are full-text-audited and two are
primary-metadata-only. The resulting contribution verdict is `narrow`;
novelty, firstness, proof, SMP, hardware cycles, lock freedom, durable external
effects, and Linux breadth are not established.

## Requirements

The public workflow requires only:

- a Linux x86-64 host;
- Docker with a working daemon;
- Bash and Git;
- a normal Linux userland with `awk`, coreutils, `grep`, and `sed`, plus
  `flock` from util-linux.

Rust, Java, TLA+, cargo-osdk, OVMF, QEMU, and guest toolchains are pinned inside
Docker images. Verification containers run without network access after their
images have been built. Nix, direnv, Just, and host Rust installations are not
part of the supported workflow.

Start by checking the complete boundary:

```bash
./x doctor
./x test --quick
```

Run the final acceptance gate with a cold image rebuild:

```bash
NEXUS_REBUILD=1 ./x verify
```

The cold gate runs Rust formatting/checks/Clippy/tests, twelve TLA+ families,
the Nexus OSTD QEMU receipt, the mediated VirtIO/reset/IOMMU QEMU receipt,
strict positive and negative predecessor/filesystem/network/Linux-I/O
composition oracles, the Stage 7B release evaluator, implementation-source Loom
rerun, runtime evidence recomputation, prior-art validator, contribution
decision, and a fresh-evidence manifest. It can take tens of minutes.

## Public command contract

| Command | Contract |
| --- | --- |
| `./x doctor` | Validate the host boundary, repository layout, catalogs, pinned Rust/Java/TLA+ tools, and backend entrypoints. |
| `./x build [all\|model\|kernel\|virtio]` | Build the selected reference-model or OSTD artifact graph without running QEMU. |
| `./x test --unit` | Run Rust and neutral-runner unit/scenario tests. This is the default `test` tier. |
| `./x test --quick` | Run all non-TLA+, non-QEMU formatting, schema, check, Clippy, test, and canonical-trace gates. |
| `./x test --system` | Run both real QEMU receipts and the frozen-predecessor plus Linux-I/O composition oracles. |
| `./x test --full` | Development alias for the complete execution graph; release sealing uses the canonical `./x verify` command. |
| `./x run kernel` | Run the bounded Nexus OSTD kernel receipt. |
| `./x run virtio` | Run the mediated VirtIO/reset/IOMMU receipt. |
| `./x run composition` | Regenerate both QEMU receipts and cross-check the frozen predecessor and additive Linux-I/O successor. This is the default `run` target. |
| `./x verify` | Canonical local, release, and CI full-acceptance gate. |
| `./x verify-bundle [DIRECTORY]` | Verify a canonical cold bundle against the matching clean checkout without rebuilding evidence or running QEMU. |
| `./x clean` | Remove root, xtask, OSDK, QEMU, guest, TLC, and evidence outputs without building an image. |

Focused `fmt`, `check`, `quick`, `model`, `spec`, and `system`
commands exist for development and CI diagnostics. There is intentionally no
`fuzz` command until Nexus owns an actual fuzz target and corpus contract.

## Source and evidence layout

```text
specs/cser/                         normative TLA+/PlusCal protocols
crates/cser-model/                  independent safe-Rust reference model
kernel/nexus-ostd/                  formal OSTD kernel prototype
experiments/ostd-virtio-cser-spike/ bounded hardware/evidence harness
tests/guest/linux/                   retained, hash-pinned compatibility inputs
specs/oracles/                      implementation-neutral race questions
tools/xtask/                        in-container build and verification logic
tools/workflow/                     host-side cross-backend evidence logic
./x                                 only public workflow front door
```

The reference model and OSTD implementation deliberately do not share state
transition code: reusing the implementation inside its oracle would destroy the
independence of the evidence. The VirtIO experiment also remains an external
component-consistency receipt rather than being mislabeled as a same-effect,
same-boot refinement.

## Verification artifacts

Successful or failed runs retain evidence under ignored paths:

```text
target/verification/
kernel/nexus-ostd/artifacts/
experiments/ostd-virtio-cser-spike/artifacts/
```

After a complete `./x verify`, `target/verification/manifest.json` records the
real invocation, Git revision, complete nonignored-source fingerprint, dirty
state, cold-rebuild request, per-run nonce, explicit research boundaries,
specification list, and SHA-256 of every required fresh artifact. The manifest
generator rejects missing, stale, empty, markerless, concurrently modified, or
different-source evidence. It also requires a nonce-bound model/spec receipt
issued only after that combined gate succeeds and a final completion receipt
issued only after the system and Stage 7B evaluation/decision gates succeed.
Both receipts bind the exact
artifact digests, so focused commands cannot assemble or replace evidence after
a failed full run and then publish it as a successful `verify`. The root
workflow also retains a one-run orchestration token that is disclosed only to
the start, final-sealing, and manifest-publication steps; the persisted records
contain only its hash.
A repository-wide workflow lock serializes public build, run, clean, and
composition operations; backend-local locks also protect direct maintenance
invocations. Manifest publication is intentionally internal to the same
token-holding full-verify process; there is no standalone publish command.

The same full-verify process then publishes
`target/verification/artifact-bundle/`. The bundle mirrors repository-relative
paths and contains all 46 manifest artifacts, the start record, both completion
receipts, the manifest, and a canonical `SHA256SUMS`: 51 files in total. Check
an extracted bundle without rebuilding evidence or running QEMU with:

```bash
./x verify-bundle target/verification/artifact-bundle
```

This checks the exact file population, every byte count and SHA-256, the
start/model/complete/manifest receipt chain, all twelve specification and
fifteen stage populations, and the complete research-boundary object. See
[ARTIFACT.md](ARTIFACT.md) for clean-clone, resource, release, and interpretation
instructions. The public command also recomputes the current checkout's revision
and source fingerprint and rejects a dirty, mismatched, noncanonical, or noncold
release bundle.

CI invokes the same `./x` surface and uploads the complete bundle, including
the formal-model, QEMU, composition, Stage 7B, and CPU/TCG evidence. A phase is
complete only after the final
working tree passes a cold local verify and the exact pushed commit passes the
remote workflow. Failure uploads retain the available hidden records for
diagnosis but never contain the orchestration token itself.

## Change discipline

- Change formal semantics, the reference model, and the OSTD implementation in
  separate reviewable steps.
- Keep effect IDs, authority/binding epochs, commit points, receipts, budget
  transfers, and failure boundaries visible in tests and traces.
- Do not delete TLA+ configurations, negative oracles, OSDK runner snapshots,
  retained Linux inputs, or hardware traces merely because they are not runtime
  product code; they are the reproducibility boundary.
- Mechanical source moves must preserve receipts and pass the existing local
  gate before new behavior is introduced.
