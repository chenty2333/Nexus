# CSER Core Production Cutover Release Ledger

- RFC: `docs/rfcs/0006-cser-core-semantic-rebaseline.md`
- Ledger status: **SEALED -- bounded QEMU cutover evidence**
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
- Failed replacement candidate C1:
  `4b59c47be381ef44c56350f018c46358c59b61e2`
- Clean local C1 receipt digest:
  `785ef0e13c505cbd324773e4439f9bbb51496c46d01f775ae303093011c844c8`
- Exact-C1 CI disposition: **FAIL after focused reply/DMA evidence and before
  TPM provisioning or any production boot; retained in
  `docs/research/evidence/cser-core-rebaseline/4b59c47be381ef44c56350f018c46358c59b61e2/ci-failure.txt`**
- Failed replacement candidate C2:
  `2e209bd738a788b174c18b73fa9103d8d65b4bf9`
- Clean local C2 receipt digest:
  `41a331716873a61288ab0a624551a54886cbd0d0802d1fa11f975b226c0c0356`
- Exact-C2 CI disposition: **FAIL after TPM provisioning and before the first
  production guest executed; retained in
  `docs/research/evidence/cser-core-rebaseline/2e209bd738a788b174c18b73fa9103d8d65b4bf9/ci-failure.txt`**
- Replacement cutover commit C3:
  `16e87b0f94b5270760dc02048fb4191bf877df71`
- Replacement clean receipt digest D-C3:
  `52aed92515920c543814bef0a842141bdfcd7c44ce1c3d8c030935ab4498adb5`
- Retained D-C3 preimage:
  `docs/research/evidence/cser-core-rebaseline/16e87b0f94b5270760dc02048fb4191bf877df71/combined-receipt.txt`
- Exact-C3 CI disposition: **PASS**, run `30517746257`, jobs `90791245396`
  and `90791245336`
- Exact-C3 CI receipt digest:
  `e3e46c8efdd6755c7f750579f925251b3912b3f1e7a7fa35a92765a3cc995728`
- Exact-C3 artifact: `8749687823`,
  `sha256:4196d594294f2797aeafa7bda6bd3a2be2fe97fa7403e1f9438e126f1208c8e6`
- Exact-C3 CI record and receipt:
  `docs/research/evidence/cser-core-rebaseline/16e87b0f94b5270760dc02048fb4191bf877df71/`
- Complete merged CI log SHA-256:
  `54ccd9155788dbcc7f3e83d20ae2cb69bbfbae66be66035132362b96c2d71121`;
  its lossless gzip preimage is retained beside the CI record
- Final evidence attestation E: **this documentation/evidence-only commit; its
  Git identity is recorded externally by the annotated release tag below**
- Annotated release tag: `cser-core-rebaseline-2026-07-30`
- Static cutover gate: `kernel/nexus-ostd/scripts/assert-cser-core-production-cutover.sh`

Commit A and D-A remain valid evidence for their exact source revision, and the
receipt preimage is retained in Git. They are not the final release seal:
exact-B CI passed the full core/model/property/Loom gate, then Ubuntu 24.04's
swtpm 0.7.3 rejected the optional `--tpmstate ...,lock` argument before the
four-boot run. C1 removed that redundant option and made daemon shutdown
fail-closed. Exact-C1 CI then passed the complete core gate and both focused
guests before finding that `disable-auto-shutdown` is another v0.8 capability.
C2 negotiated that flag: swtpm v0.8 and newer receive the opt-out, while older
versions, which predate automatic TPM2 shutdown, retain their equivalent crash
behavior. Exact-C2 CI passed provisioning, then showed that its Docker 28 /
AppArmor 4 boundary delivered the QEMU control command without the Unix
ancillary data FD.

C3 scopes SELinux label disablement and AppArmor `unconfined` to the
caller-UID/GID, network-none persistent QEMU guest-run container; host swtpm
remains outside it, every normal build/test container retains Docker's default
policy, and exact-C3 used a non-root caller. An offline Ubuntu profile/source
audit found rules consistent with the unconfined sender-label diagnosis, but the
retained CI log does not contain the host AppArmor audit decision. Exact-C3 CI
directly establishes only that this scoped correction passed both jobs, TPM
provisioning, all focused gates, and all four production boots on the recorded
GitHub Ubuntu image. It does not claim the same result for arbitrary host
AppArmor or Docker policy combinations.

## Completed Replacement Seal Protocol

The replacement seal avoided a self-referential commit and kept runtime proof
separate from evidence attestation:

1. **Replacement cutover commit C3** contains the unchanged production
   semantics, the narrowly scoped persistent guest-run container policy
   correction, and this ledger as it stood with pending C3/D-C3 fields.
2. From the clean C3 tree, `./x verify` emitted `CSER CORE VERIFY PASS`,
   completed all focused and four-boot guests, and produced
   `combined-receipt.txt` with `PASS`, `seal_requested=true`,
   `git_source_tree_clean=true`, and `git_revision=C3`.
3. C3 was pushed by fast-forward and both exact-C3 CI jobs passed. The CI run
   identity, artifact digest, complete losslessly compressed verification log,
   and local and CI receipt preimages are retained in Git.
4. **Final evidence attestation E** records C3, D-C3, the exact-C3 CI result,
   and the retained paths. E changes only documentation and evidence. After E
   is committed and validated, the annotated release tag identifies E without
   embedding E's own hash.

E must not change production Rust sources, Cargo/OSDK wiring, the runner, the
static gate, or the cutover contract. If such a change is required, D-C3 is
inapplicable and another clean cutover revision is required.

The success upload did not enable `include-hidden-files`, so artifact
`8749687823` omits the zero-byte `tpmstate/.lock` file while retaining the TPM
state content in `tpmstate/tpm2-00.permall`. The downloaded artifact alone is
therefore not a complete preimage for the receipt's TPM tree hash. E retains the
artifact's byte-exact state file and the reconstructed empty lock under
`docs/research/evidence/cser-core-rebaseline/16e87b0f94b5270760dc02048fb4191bf877df71/ci-tpmstate/`;
the runner's documented tree-hash algorithm exactly reconstructs
`a3fb319391f07553c4e434addada8394ffc1c06ec45199e7a1969a5255e6a14a`.
This retention caveat does not upgrade or invalidate the executed TPM semantics.

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
- Annotated checkpoint tag: `pre-cser-core-rebaseline-2026-07-29`.
- Remote archive ref: `archive/pre-cser-core-rebaseline-2026-07-29`.
- The checkpoint retains the RFC 0005 oracle, trace-conformance material, and
  IRQ Phase A sources and receipts. They retain their original bounded claims.
- `v0.1.0` remains a distinct accepted historical release. Neither it nor the
  pre-rebaseline checkpoint inherits the R6 claims.

No retained native-v1 corpus, old source, receipt, or model is a production
dependency or evidence of the new runtime merely because it remains reachable
through a tag.

## QEMU Evidence Boundary

The final local and exact-CI receipts identified by C3, D-C3, and the exact-C3
CI digest establish only two clean, source-bound, environment-recorded runs of
the pinned container/QEMU profile, including their distinct host swtpm and TPM2
tool hashes, with:

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

The separate focused same-boot DMA receipt's `core_resource_reuse=true` refers
to fresh-generation logical core-resource reuse only; its adjacent
`physical_address_reuse=false` explicitly excludes physical address reuse. It
does not override the production cross-reboot retained-resource non-claim.

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

The replacement C3 local seal, exact-C3 CI run, and evidence-only E attestation
satisfy the protocol above. The B, C1, and C2 failures remain negative harness
evidence, not production-boot PASS results and not reasons to weaken any
semantic gate. After E validation, the annotated release tag identifies E;
runtime claims remain bound to C3 and its two retained receipt digests.
