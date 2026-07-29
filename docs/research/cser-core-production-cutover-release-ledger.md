# CSER Core Production Cutover Release Ledger

- RFC: `docs/rfcs/0006-cser-core-semantic-rebaseline.md`
- Ledger status: **PENDING -- not release evidence**
- Cutover commit A: **PENDING**
- Clean four-boot receipt digest D: **PENDING**
- Attestation record B: **PENDING -- not yet created**
- Static cutover gate: `kernel/nexus-ostd/scripts/assert-cser-core-production-cutover.sh`

These placeholders are intentional. They must not be filled from a dirty-tree
`combined-proof.txt`, from an earlier source revision, or before the clean seal
passes. Until commit A and digest D are recorded by attestation commit B, the
entries below are required release dispositions rather than claims about the
current tree.

## Two-Commit Seal Protocol

The release avoids an impossible commit which both contains its own receipt and
claims that the receipt was generated from that same clean commit:

1. **Cutover commit A** contains the complete production semantic cutover,
   verification wiring, and this ledger with pending attestation fields. A is
   the revision whose runtime behavior is being attested.
2. From a clean checkout of A, run
   `kernel/nexus-ostd/x seal-core-persistent-recovery`. The seal must complete
   all four boots and produce `combined-receipt.txt` with `PASS`,
   `seal_requested=true`, `git_source_tree_clean=true`, and `git_revision=A`.
   Digest D is the SHA-256 recorded for that exact receipt.
3. **Attestation commit B** replaces the pending A/D fields with those exact
   values and records the completed ledger status. B records evidence about A;
   it does not become a new semantic cutover revision and does not redefine the
   receipt's execution identity.

B must not change production Rust sources, Cargo/OSDK wiring, the runner, the
static gate, or the cutover contract. If such a change is required, the old D is
inapplicable: create a new cutover commit A and seal it again. B need not embed
its own commit hash; its Git object identity supplies that provenance without a
self-reference cycle.

## Removed Live Surfaces

The sealed release has no live, default-build, kernel-adapter, or release-workflow
dependency on these surfaces:

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

The clean receipt identified by A and D, when those fields are filled,
establishes only one hermetic run of the pinned OSTD/QEMU profile with:

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
- absence of failures outside the exercised failpoints and bounded profile; or
- any live dual-write, fallback, or compatibility path to the old Registry.

QEMU reset, ISR-drain, and IOTLB observations justify continued quarantine only.
They are not evidence that pre-crash PFN/IOVA ownership was retired or that the
resources became reusable.

## Seal Checklist

Before creating cutover commit A:

- the static cutover gate passes against the default production graph;
- the ordinary combined runner observes all four boot markers while preserving
  its journal, outbox, and swtpm state and emits only a `NONSEALABLE` proof;
- repository/Cargo search proves that the removed surfaces are not reachable
  from production adapters, the kernel, or release workflows; and
- exactly one recovered core runtime is published before vNext ingress opens.

After A exists:

- the tree is clean before and throughout `seal-core-persistent-recovery`;
- the clean receipt binds all four markers and its source/tool hashes to A;
- the receipt retains the QEMU-only and resource-retention non-claims above;
- digest D is computed from that exact receipt; and
- attestation commit B records A and D without changing the semantic cutover.
