# Nexus

Nexus is a research operating-system prototype for **Causally Scoped Effect
Revocation (CSER)**: kernel-enforced causal effect scopes for restartable
user-space OS services. One authority delegation can cover scheduler, pager,
personality, readiness, and mediated-I/O effects; revocation closes their shared
commit gate and drives every enrolled effect to one honest terminal outcome.

The current checkpoint is a bounded, single-CPU system-composition prototype.
It is not a production Linux personality, filesystem, network stack, or proof of
identity-preserving same-boot VirtIO composition. See [VISION.md](VISION.md) for
the research claim, [ARCHITECTURE.md](ARCHITECTURE.md) for boundaries, and
[REWORK.md](REWORK.md) for the migration ledger.

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

The cold gate runs Rust formatting/checks/Clippy/tests, nine TLA+ families, the
Nexus OSTD QEMU receipt, the mediated VirtIO/reset/IOMMU QEMU receipt, positive
and negative system-composition oracles, and a fresh-evidence manifest. It can
take tens of minutes.

## Public command contract

| Command | Contract |
| --- | --- |
| `./x doctor` | Validate the host boundary, repository layout, catalogs, pinned Rust/Java/TLA+ tools, and backend entrypoints. |
| `./x build [all\|model\|kernel\|virtio]` | Build the selected reference-model or OSTD artifact graph without running QEMU. |
| `./x test --unit` | Run Rust and neutral-runner unit/scenario tests. This is the default `test` tier. |
| `./x test --quick` | Run all non-TLA+, non-QEMU formatting, schema, check, Clippy, test, and canonical-trace gates. |
| `./x test --system` | Run both real QEMU receipts and the system-composition oracle. |
| `./x test --full` | Alias for the complete `./x verify` contract. |
| `./x run kernel` | Run the bounded Nexus OSTD kernel receipt. |
| `./x run virtio` | Run the mediated VirtIO/reset/IOMMU receipt. |
| `./x run composition` | Regenerate both QEMU receipts and cross-check their composition evidence. This is the default `run` target. |
| `./x verify` | The only full local/CI acceptance gate. |
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
issued only after the system gate succeeds. Both receipts bind the exact
artifact digests, so focused commands cannot assemble or replace evidence after
a failed full run and then publish it as a successful `verify`. The root
workflow also retains a one-run orchestration token that is disclosed only to
the start, final-sealing, and manifest-publication steps; the persisted records
contain only its hash.
A repository-wide workflow lock serializes public build, run, clean, and
composition operations; backend-local locks also protect direct maintenance
invocations. Manifest publication is intentionally internal to the same
token-holding full-verify process; there is no standalone publish command.

CI invokes the same `./x` surface. A phase is complete only after the final
working tree passes a cold local verify and the exact pushed commit passes the
remote workflow. The successful CI artifact contains the manifest, start
record, and both bound completion receipts; failure uploads retain the same
available hidden records for diagnosis but never contain the orchestration
token itself.

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
