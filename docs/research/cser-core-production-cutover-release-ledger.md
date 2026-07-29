# CSER Core Production Cutover Release Ledger

- RFC: `docs/rfcs/0006-cser-core-semantic-rebaseline.md`
- Ledger status: **RE-SEAL PENDING -- exact CI exposed a host-harness
  compatibility gap**
- Historical cutover commit A:
  `c06e9f43e931ed3f130da6dfcf29452a45406152`
- Historical clean four-boot receipt digest D-A:
  `e0f959e5c4027fb3952384b77de38b6c97e8c5bdd5a9c20f109c515361cf6f1e`
- Retained D-A preimage:
  `docs/research/evidence/cser-core-rebaseline/c06e9f43e931ed3f130da6dfcf29452a45406152/combined-receipt.txt`
- First attestation B: `de13e69363e59843ba5e0302fd983db27f6fd709`
- Exact-B CI disposition: **FAIL before TPM provisioning completed or any
  production boot; retained in
  `docs/research/evidence/cser-core-rebaseline/de13e69363e59843ba5e0302fd983db27f6fd709/ci-failure.txt`**
- Replacement cutover commit C: **PENDING**
- Replacement clean receipt digest D-C: **PENDING**
- Final evidence attestation E: **PENDING**
- Intended immutable tag: `cser-core-rebaseline-2026-07-30`
- Static cutover gate: `kernel/nexus-ostd/scripts/assert-cser-core-production-cutover.sh`

Commit A and D-A remain valid evidence for their exact source revision, and the
receipt preimage is now retained in Git. They are not the final release seal:
exact-B CI passed the full core/model/property/Loom gate, then Ubuntu 24.04's
swtpm 0.7.3 rejected the optional `--tpmstate ...,lock` argument before the
four-boot run. The replacement runner removes that redundant option under the
existing single-daemon custody rules. A new clean source-bound receipt and CI
PASS are required before this ledger returns to `SEALED`.

## Replacement Seal Protocol

The replacement seal avoids a self-referential commit and keeps runtime proof
separate from evidence attestation:

1. **Replacement cutover commit C** contains the unchanged production
   semantics, the portable swtpm invocation, and this ledger with pending C/D-C
   fields.
2. From a clean C tree, run `./x verify`. The command must emit `CSER CORE
   VERIFY PASS`, complete all focused and four-boot guests, and produce
   `combined-receipt.txt` with `PASS`, `seal_requested=true`,
   `git_source_tree_clean=true`, and `git_revision=C`.
3. Push C by fast-forward and require both exact-C CI jobs to pass. Retain the
   CI run identity, artifact digest, complete verification log, and the small
   receipt preimage in Git.
4. **Final evidence attestation E** records C, D-C, the exact-C CI result, and
   the retained paths. E changes only documentation and evidence, then the
   intended immutable tag identifies E without embedding E's own hash.

E must not change production Rust sources, Cargo/OSDK wiring, the runner, the
static gate, or the cutover contract. If such a change is required, D-C is
inapplicable and another clean cutover revision is required.

## Removed Live Surfaces

The replacement production closure has no live, default-build, kernel-adapter,
or release-workflow dependency on these surfaces:

| Removed production surface | Required disposition at the cutover |
| --- | --- |
| `kernel/nexus-ostd/src/cser/effect_registry.rs` and `effect_registry/` | Absent from the kernel module graph and production source manifest. |
| `kernel/nexus-ostd/src/cser/infrastructure/` and `device_flight.rs` | Old semantic mirrors, retained tables, and device-flight authority are not production dependencies. |
| `kernel/nexus-ostd/src/cser/portal_v2.rs` | Replaced by the versioned core-backed vNext portal; no session-local semantic ledger or dual write remains. |
| `kernel/nexus-ostd/src/cser/supervisor_runtime.rs` | Replaced by the core-backed vNext supervisor sharing the one recovered runtime owner. |
| Legacy Linux personality and composition self-test entrypoints | Removed from the default release boot; they cannot construct a second Registry. |
| `nexus-effect-peer` live stdio service | Removed from the release graph. Native-v1 material is historical corpus only. |
| `nexus-portal-abi` and `nexus-supervisor` | Removed from kernel dependencies and production verification inputs. |
| Stage-5B `nexus-ostd-virtio::Portal` and the old system-composition workflow | Not a production ingress and not invoked by release verification. Hardware quarantine/ownership typestates remain separate from semantic authority. |

The production manifest contains only `core_*` OSTD integration sources. Its
required closure includes the one runtime owner, persistent recovery, reply and
DMA adapters, boot quarantine, journal/outbox and TPM providers, and the portal
and supervisor vNext adapters. `transact_volatile` and development-only slice
runtimes are not in that closure.

## Retained History

Historical material remains recoverable without remaining live:

- Checkpoint commit: `05e68b19b219d0f5288de5438127b5690cd7e50f`.
- Immutable tag: `pre-cser-core-rebaseline-2026-07-29`.
- Remote archive ref: `archive/pre-cser-core-rebaseline-2026-07-29`.
- The checkpoint retains the RFC 0005 oracle, trace-conformance material, and
  IRQ Phase A sources and receipts. They retain their original bounded claims.
- `v0.1.0` remains a distinct accepted historical release. Neither it nor the
  pre-rebaseline checkpoint inherits the R6 claims.

No retained native-v1 corpus, old source, receipt, or model is a production
dependency or evidence of the new runtime merely because it remains reachable
through a tag.

## QEMU Evidence Boundary

The retained historical receipt identified by A and D-A establishes only one
hermetic run of the pinned OSTD/QEMU profile with:

- four separate guest boots over the same `journal.raw`, reply `outbox.raw`,
  and swtpm state directory;
- one recovered core owner shared by the reply and DMA domains;
- boot-one reply and DMA origin work in real service tasks, followed by task
  return, exact reap, closed production ingress, and rejection of a post-exit
  request without Registry mutation;
- boot-two anchored replay into a fresh service task, Ready/Rebind through the
  production owner, a durable reply apply intent, a second service death and
  exact reap before external apply, queue-claim retirement, and continued
  retention of pinned-page and IOVA claims;
- boot-three replay of that second crash into another fresh Ready/Rebind task,
  reconciliation, one external apply and acknowledgement, and reply settlement
  without a second apply intent;
- boot-four fresh Ready/Rebind and stable replay without duplicate reply or DMA
  evidence, while the recovered service remains live with ingress open;
- exact service-principal/binding generation pairs `1/1`, `2/2`, `3/3`, and
  `4/4`, plus strictly increasing revision, boot, journal, and device freshness;
- device quarantine before replay, including the observed VirtIO reset/ISR and
  global IOTLB operations represented by that profile; and
- catalog-bound TPM2-NV freshness progression in the restarted swtpm fixture.

It does **not** establish:

- physical TPM anti-rollback; the swtpm state remains host-rollbackable;
- physical power-loss durability or storage-controller cache behavior;
- physical-device, firmware, PCI, IOMMU, IRQ, SMP, or platform generality;
- crash-persistent custody or retirement of the retained page frames or IOVAs;
- authorization to reuse any retained PFN, IOVA, or quarantined queue resource;
- absence of failures outside the exercised failpoints and bounded profile.

The static cutover gate, rather than the QEMU receipt, establishes that no live
dual-write, fallback, or compatibility path to the old Registry is present in
the production closure.

QEMU reset, ISR-drain, and IOTLB observations justify continued quarantine only.
They are not evidence that pre-crash PFN/IOVA ownership was retired or that the
resources became reusable.

## Seal Checklist

Historical cutover A satisfied all of the following before it was created:

- the static cutover gate passes against the default production graph;
- the ordinary combined runner observes all four boot markers while preserving
  its journal, outbox, and swtpm state and emits only a `NONSEALABLE` proof;
- repository/Cargo search proves that the removed surfaces are not reachable
  from production adapters, the kernel, or release workflows; and
- exactly one recovered core runtime is published before vNext ingress opens.

The retained clean A seal established all of the following for A:

- the tree is clean before and throughout `seal-core-persistent-recovery`;
- the clean receipt binds all four markers and its source/tool hashes to A;
- the receipt retains the QEMU-only and resource-retention non-claims above;
- digest D-A is computed from that exact receipt; and
- the D-A preimage is now retained in Git rather than depending on an ignored
  local artifact.

The replacement release remains open until clean C/D-C and exact-C CI satisfy
the protocol above. The B failure is negative harness evidence, not a runtime
PASS and not a reason to weaken any semantic gate.
