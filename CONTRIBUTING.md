# Contributing to Nexus

Nexus is a research artifact: implementation changes, semantic claims, and
reproducibility evidence must remain reviewable as separate facts. This guide
documents the supported development workflow. The public project overview is
in [README.md](README.md), and release reproduction is in
[ARTIFACT.md](ARTIFACT.md).

## Supported environment

Use a Linux x86-64 host with:

- Docker and a working daemon;
- Bash and Git;
- `awk`, coreutils, `grep`, and `sed`;
- `flock` from util-linux.

The supported workflow does not depend on host Rust, Java, TLA+, cargo-osdk,
OVMF, QEMU, Nix, direnv, or Just installations. Project toolchains are pinned
inside Docker images, and verification containers run without network access
after those images have been built.

Start every change with:

```bash
./x doctor
./x test --quick
```

## Command contract

`./x` is the only public workflow front door. Backend entry points are retained
for isolation and maintenance, not as a second user-facing contract.

| Command | Contract |
| --- | --- |
| `./x doctor` | Validate the host boundary, repository layout, catalogs, pinned tools, and backend entry points. |
| `./x build [all\|model\|kernel\|virtio]` | Build the selected reference-model or OSTD artifact graph without running QEMU. |
| `./x test --unit` | Run Rust and neutral-runner unit/scenario tests; this is the default `test` tier. |
| `./x test --quick` | Run non-TLA+, non-QEMU formatting, schema, check, Clippy, test, and canonical-trace gates. |
| `./x test --system` | Run both QEMU receipts and the predecessor plus Linux-I/O composition oracles. |
| `./x test --full` | Traverse the complete development graph; release sealing uses the canonical `./x verify`. |
| `./x run kernel` | Run the bounded Nexus OSTD kernel receipt. |
| `./x run virtio` | Run the mediated VirtIO/reset/IOMMU receipt. |
| `./x run composition` | Regenerate both QEMU receipts and cross-check the predecessor and additive Linux-I/O successor; this is the default `run` target. |
| `./x verify` | Run the canonical local, release, and CI full-acceptance gate. |
| `./x verify-bundle [DIRECTORY]` | Verify a canonical cold bundle against the matching clean checkout without rebuilding evidence or running QEMU. |
| `./x clean` | Remove root, xtask, OSDK, QEMU, guest, TLC, and evidence outputs without building an image. |

Focused `fmt`, `check`, `quick`, `model`, `spec`, and `system` commands exist
for diagnostics. There is intentionally no `fuzz` command until Nexus owns a
real fuzz target and corpus contract.

## Change discipline

- Change formal semantics, the independent reference model, and the OSTD
  implementation in separate reviewable steps.
- Keep effect IDs, authority and binding epochs, commit points, tickets,
  receipts, budget transfers, and failure boundaries visible in tests and
  traces.
- Preserve the independence of the safe-Rust oracle and OSTD implementation;
  neither may call the other's transition implementation.
- Do not delete TLA+ configurations, negative oracles, OSDK runner snapshots,
  retained Linux inputs, or hardware traces merely because they are not
  runtime product code. They are part of the reproducibility boundary.
- Keep mechanical source moves separate from semantic changes, and prove the
  existing receipts before introducing new behavior.
- Treat `Checked`, `Observed`, and unestablished claims distinctly. Preserve
  the exact concurrency boundary `production transition source under a
  Loom-modeled outer mutex` unless stronger evidence has actually replaced it.
- Do not rename released stage, receipt, schema, or evidence paths for cosmetic
  reasons. They are part of the `v0.1.0` artifact contract.
- Never move, recreate, or retroactively rewrite a published release tag.

When changing a claimed property, update the relevant normative specification,
implementation-independent oracle, implementation trace, and claim ledger. A
new result must not enlarge what an older frozen receipt establishes.

The active post-`v0.1.0` research contract is
[RFC 0001](docs/rfcs/0001-production-identity.md). Its production-identity,
same-boot device, IRQ, and SMP requirements remain prospective until every
named evidence gate closes.

## Verification evidence

Successful and failed runs retain ignored evidence under:

```text
target/verification/
kernel/nexus-ostd/artifacts/
experiments/ostd-virtio-cser-spike/artifacts/
```

A complete `./x verify` records the invocation, Git revision, nonignored source
fingerprint, dirty state, cold-rebuild request, run nonce, research boundaries,
and SHA-256 of every required artifact. Ordered start, model/spec, completion,
and manifest records bind one run so focused commands cannot splice evidence
after a failed full gate. Repository and backend locks prevent concurrent
public workflows from mutating that evidence set while it is sealed.

The same run publishes `target/verification/artifact-bundle/`. Verify it with:

```bash
./x verify-bundle target/verification/artifact-bundle
```

The verifier checks the exact file population and receipt/hash chain and binds
the bundle to the current clean checkout. See [ARTIFACT.md](ARTIFACT.md) for the
published `v0.1.0` populations, resource envelope, exact release audit, and
future sealing procedure.

## Acceptance boundary

Before a release or other acceptance claim:

1. Commit every implementation, documentation, and tooling change.
2. Run a clean, cold `NEXUS_REBUILD=1 ./x verify`.
3. Verify the generated bundle against that checkout.
4. Push the exact commit and require the remote quick and full jobs to pass at
   that SHA.
5. Audit the downloaded CI bundle before publishing a protected tag or release.

Focused local success is diagnostic evidence, not release acceptance. CI
success at a different revision is not evidence for the proposed change.
