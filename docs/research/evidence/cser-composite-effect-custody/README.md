# CSER composite-effect custody evidence archive

This directory retains the source-bound local seal for RFC 0007 and the raw
text evidence needed to inspect its bounded QEMU result without relying on the
ignored build-artifact directory.

## Runtime candidate C

- Revision:
  `e8190f45e19f6cc1abd2b9c55e87be7c1079ed01`
- Clean local receipt:
  `e8190f45e19f6cc1abd2b9c55e87be7c1079ed01/combined-receipt.txt`
- Receipt SHA-256:
  `29830601a6fe6b2fe357a224ab67595e8021098b5f7598b8f250f3910b76c090`
- Receipt checksum:
  `e8190f45e19f6cc1abd2b9c55e87be7c1079ed01/combined-receipt.sha256`
- Retained-file manifest:
  `e8190f45e19f6cc1abd2b9c55e87be7c1079ed01/retained-files.sha256`
- Exact-C CI receipt:
  `e8190f45e19f6cc1abd2b9c55e87be7c1079ed01/ci-combined-receipt.txt`
- Exact-C CI receipt SHA-256:
  `cbe98981b5f69524d451a0f70f05b99d8da2898ddd9b32387b9559d0696e6a2e`
- CI disposition:
  `e8190f45e19f6cc1abd2b9c55e87be7c1079ed01/ci-success.txt`
- Losslessly compressed complete CI log:
  `e8190f45e19f6cc1abd2b9c55e87be7c1079ed01/ci-complete.log.gz`

The receipt self-reports `PASS`, `seal_requested=true`,
`git_source_tree_clean=true`, and the exact revision above. It binds profile 2,
catalog v5, projection v6, recovery snapshot v2, journal schema 6, the static
production source closure, the pinned OSTD and VirtIO overlays, the schema-5
negative boot, both focused historical-profile guests, and all four
profile-2 production boots.

The evidence-only commit which contains this directory does not alter
candidate C. Runtime claims remain bound to C and the receipt digest, avoiding
a same-commit SHA or receipt-digest self-reference.

GitHub Actions run `30618061878` independently checked out exact candidate C.
Its quick job and complete seal job both passed, and its uploaded receipt
self-reports the same clean revision and semantic result. The local and CI
receipt hashes differ because their Docker image IDs, generated ISO hashes,
host TPM tools, and runtime media differ; both retain the same source proof,
catalog, profile, schema, operation/component identity, four-boot state
progression, reuse coordinates, and physical non-claims.

## Retained preimages

The candidate directory includes:

- the combined receipt and companion checksum;
- the schema-5 fixture metadata, logical journal, serial log, QEMU debug log,
  swtpm log, selected-NV before/after dumps, and exact swtpm state tree;
- focused reply and DMA serial and QEMU debug logs;
- serial and QEMU debug logs for production boots one through four;
- the profile-2 swtpm log and exact state tree, including the zero-byte lock
  file;
- the exact-C CI receipt and checksum, complete CI log, and run disposition;
  and
- the CI profile-2 and schema-5 TPM state files. The success artifact omitted
  hidden zero-byte `.lock` files, so this archive reconstructs them explicitly;
  both reconstructed tree hashes match the values in the CI receipt.

Every retained file except `retained-files.sha256` is covered by that manifest.
The receipt separately names and hashes the production ISO, schema-5 PIO
image, focused ISOs, journal, outbox, one-GiB RAM backing file, TPM state trees,
source manifest, runner, static gate, helper, provisioner, and host tools.

The large ISOs and raw media remain workflow artifacts and are not committed
to Git. Their byte hashes and sizes are retained in the receipt. This archive
therefore preserves the executed text evidence and TPM state while avoiding a
permanent multi-gigabyte repository payload.

## Claim boundary

The retained run establishes the four-process QEMU protocol at candidate C:
one operation effect `50433:1`, reply component `1`, DMA component `2`,
strictly increasing freshness, reply recovery across a second service crash,
component-local DMA retirement, and generation `1 -> 2` reuse at the same
guest PFN, emulated IOVA, and RAM backing-file offset.

It does not establish host-physical PFN identity, physical DMA transaction
drain, physical power-loss durability, physical TPM anti-rollback, or the
hardware-general safety of PFN/IOVA reuse. Those claims remain gated by the
open physical-hardware rows in the RFC 0007 acceptance matrix.
