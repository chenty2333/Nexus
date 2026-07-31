# CSER composite-effect custody release ledger

- RFC: `docs/rfcs/0007-cser-composite-effect-custody.md`
- Ledger status: **SEALED for portable profile-2 semantics and the bounded
  QEMU composite-custody protocol; physical-hardware closure remains open**
- Runtime candidate C:
  `e8190f45e19f6cc1abd2b9c55e87be7c1079ed01`
- Clean local receipt digest D-C:
  `29830601a6fe6b2fe357a224ab67595e8021098b5f7598b8f250f3910b76c090`
- Retained D-C preimage:
  `docs/research/evidence/cser-composite-effect-custody/e8190f45e19f6cc1abd2b9c55e87be7c1079ed01/combined-receipt.txt`
- Exact-C GitHub Actions run:
  `https://github.com/chenty2333/Nexus/actions/runs/30618061878`
- Exact-C CI receipt digest:
  `cbe98981b5f69524d451a0f70f05b99d8da2898ddd9b32387b9559d0696e6a2e`
- Final evidence attestation E: **this documentation/evidence-only commit; it
  contains no runtime, runner, dependency, or build-input changes**
- Static cutover gate:
  `kernel/nexus-ostd/scripts/assert-cser-core-production-cutover.sh`

## Completed seal protocol

The release avoids a self-referential implementation commit:

1. Candidate C contains profile-2 semantics, production integration, the
   persistent DMA arena, the harness, RFC 0007, and the acceptance matrix.
2. The complete host, model, property, Loom, static, kernel, focused-guest, and
   dirty four-boot gates passed before C was committed.
3. From the clean C tree,
   `kernel/nexus-ostd/x seal-core-persistent-recovery` rebuilt the pinned image,
   ran the schema-5 negative boot and four profile-2 production boots, and
   emitted a receipt with `PASS`, `git_revision=C`,
   `git_source_tree_clean=true`, and `seal_requested=true`.
4. Evidence-only attestation E retains the receipt preimage, raw text logs,
   TPM state, exact hashes, release ledger, and updated acceptance status.
5. Exact-C GitHub Actions run `30618061878` passed both quick feedback and the
   complete seal job. E also retains its independent receipt, complete
   compressed log, run disposition, and reconstructed TPM trees.

E must not modify production Rust, `Cargo.toml`/lockfiles, OSDK or Docker
wiring, the OSTD/VirtIO overlays, the runner, provisioning scripts, or the
static cutover gate. Any such change invalidates D-C and requires a new clean
candidate and seal.

## Authorized labels

At candidate C the following RFC 0007 labels are authorized:

- `profile2-core`
- `profile2-production`
- `composite-qemu`

`composite-hardware` is not authorized. Deferred normalized trace row `V-06`
is excluded from every label by specification. Physical rows `H-01..H-06` and
claim-discipline row `E-04` remain open.

## Source-bound result

The clean receipt binds:

- core API profile 2, standard catalog v5, projection v6, recovery snapshot v2,
  and journal schema 6;
- one production Registry and one original operation effect `50433:1`, with
  reply component `1` and DMA component `2`;
- schema-5 typed `MigrationRequired` after device quarantine and before
  profile-2 catalog binding, semantic replay, inferred pairing, Registry
  publication, or device activation;
- four fresh QEMU processes sharing the same journal, outbox, swtpm state, and
  RAM backing file;
- service and binding generations `1,2,3,4`, revisions `11,24,42,52`, and boot,
  journal, and device generations `2,3,4,5`;
- reply apply-intent recovery across the second crash without a second intent
  or blind external apply;
- queue, pinned-page, and IOVA claim retirement while the reply component
  remains independently recoverable; and
- a successor DMA lease at sequence `2` using core resource generation
  `1 -> 2` at guest PFN base `196608`, emulated IOVA base `1073741824`, and RAM
  backing-file offset `805306368`, followed by failure-atomic rejection of
  stale generation-1 evidence.

The sequence-2 DMA lease is a declared successor resource owner. It is not a
second identity for the original agent operation and is not an inferred
pairing with the reply.

## QEMU and hardware boundary

The receipt proves only the declared QEMU guest-coordinate protocol. In
particular:

- guest physical address equals the configured backing-file offset in this
  harness;
- the IOVA is an emulated VT-d coordinate;
- process exit, pre-replay PCI/VirtIO quarantine, ISR drain, and global IOTLB
  completion are observations inside this QEMU profile; and
- swtpm freshness state is host-rollbackable.

It does not prove reuse of the same host-physical PFN, exact old-domain
hardware unmap, physical DMA transaction drain, real-device late DMA/IRQ
isolation, physical power-loss durability, or physical TPM anti-rollback.
Those statements require separate, platform-scoped hardware receipts.

## Retained evidence

The evidence archive retains D-C, all serial and QEMU debug logs for the
schema-5 negative boot, focused reply/DMA guests, and four production boots,
the swtpm logs, both local TPM state trees, the exact-C CI receipt and complete
log, reconstructed CI TPM state trees, and a SHA-256 manifest. Large ISOs and
raw journal/outbox/RAM media stay outside Git; D-C and the CI receipt record
their exact hashes and sizes. The GitHub artifact is independently bound by
artifact ID `8788407380` and its API-reported SHA-256 digest in
`ci-success.txt`.

RFC 0006 and its evidence remain immutable historical profile-1 evidence.
Neither this ledger nor candidate C retroactively promotes those receipts to
composite-effect or cross-reboot resource-reuse proof.
