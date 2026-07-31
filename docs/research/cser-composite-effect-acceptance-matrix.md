# CSER composite-effect acceptance matrix

- Governing specification:
  [RFC 0007](../rfcs/0007-cser-composite-effect-custody.md)
- Status: **software and QEMU rows accepted on the current dirty worktree;
  release seal open**
- Baseline date: 2026-07-30
- Evidence update: 2026-07-31
- Predecessor evidence: RFC 0006 profile 1 / journal schema 5

This matrix prevents an adjacent result from being promoted into the
composite-effect claim. Every release-sealed row must bind its exact source
revision, catalog digest, profile, journal schema, scenario or seed, command,
artifact digest, and result. A dirty-tree acceptance binds the locally built
content and artifacts, but cannot satisfy the exact-revision prerequisite.
`PASS` in one layer never fills another layer's row.

`Accepted (dirty-tree evidence)` means that the row's stated observation
passed against the exact locally built source captured by the current evidence
bundle. It is not a release seal. The combined QEMU receipt is intentionally
`NONSEALABLE`, with `nonsealable_reason=source-tree-dirty` and
`seal_requested=false`. It records base revision
`7c82d0c9f26d77a630faeaeb28e139c36beb5319`, but that revision is not a name
for the dirty source and is not the eventual release revision.

The current evidence snapshot establishes:

- the independent oracle and model-side Loom enumerate the full `6 x 11 = 66`
  reply/DMA partial-state product, including a second crash at every cell;
- core and the independent oracle agree on normalized public state after 33
  acknowledged durable prefixes, and each prefix is recovered twice from the
  same journal and trusted anchor before comparison;
- a separate recovered-engine probe performs Checkpoint, Snapshot, Ready,
  Rebind, adoption, pending-permit reissue, and activation while checking the
  retained catalog, retirement, and provider-contract digests;
- a trusted TPM candidate selecting the pinned schema-5 fixture reaches
  quarantine and typed `MigrationRequired` without profile-2 binding, semantic
  replay, inferred pairing, Registry publication, or device activation;
- four fresh QEMU processes share one schema-6 journal, swtpm state, outbox,
  and RAM backing file while freshness and service/binding generations advance;
- one operation effect `50433:1` carries reply component `1` and DMA component
  `2`; and
- the persistent arena retires core resource generation `1`, activates
  generation `2`, and reuses exact guest PFN base `196608`, emulated IOVA base
  `1073741824`, and RAM backing-file offset `805306368`.

The current combined artifact is
`kernel/nexus-ostd/artifacts/cser-production/combined-proof.txt`, with companion
digest `5c1da57d103006935cf7f7090bbf5ae721ac0c88070e9d852ac70b4a4a7c56e6`.
It is a dirty-tree proof, not an immutable clean-source receipt.

The evidence was exercised through these current gate commands:

```console
cargo test -p cser-model --all-features
cargo test -p cser-core --all-features
bash kernel/nexus-ostd/scripts/assert-cser-core-production-cutover.sh
kernel/nexus-ostd/x run-core-persistent-recovery
```

The first three are the host/model/static gates. The last command performs the
schema-5 negative boot and four shared-media profile-2 boots; it passed its
scenario assertions and emitted `NONSEALABLE` because the source tree was
dirty.

`V-06` records a deferred evidence-format gap. It is deliberately non-blocking
for this RFC and is excluded from every release label below. A successful
receipt carrying trace-version metadata is not a canonical normalized trace.

## Evidence labels

| Label | Meaning |
| --- | --- |
| `MODEL` | independent executable oracle or declarative model only |
| `PROPERTY` | generated host state/command-sequence and crash-cut testing |
| `LOOM` | model-side or production transition source under finite interleavings; each row states its scope |
| `STATIC` | source/dependency/format inspection |
| `QEMU` | emulated guest/runtime/device observation |
| `HARDWARE` | exact declared physical machine/device/IOMMU observation |
| `RELEASE` | clean-source, provenance, cutover, and retained-receipt gate |

## Semantic core

| ID | Layer | Required observation | Acceptance condition | Current status |
| --- | --- | --- | --- | --- |
| CE-01 | MODEL, PROPERTY | Register one effect with reply and DMA components | One `EffectId`; distinct stable `ComponentId`; sealed catalog-valid topology | Accepted (dirty-tree evidence) |
| CE-02 | MODEL, LOOM | Parent fence races reply commit | Both winners reachable; loser is failure-atomic; committed reply retained | Accepted (dirty-tree evidence) |
| CE-03 | MODEL, LOOM | Parent fence races DMA queue commit | Both winners reachable; loser is failure-atomic; committed DMA retained | Accepted (dirty-tree evidence) |
| CE-04 | MODEL, LOOM | Revoke races effect-wide adoption of a wholly uncommitted composite | Both winners reachable under one exact parent authority epoch; no component-only execution adoption | Accepted (dirty-tree evidence) |
| CE-05 | MODEL, PROPERTY | Reply settles while DMA claims remain | Reply terminal; DMA claims unchanged and charged; parent not released | Accepted (dirty-tree evidence) |
| CE-06 | MODEL, PROPERTY | DMA claims discharge while reply remains unsettled | DMA locally reusable; reply unchanged; parent remains discoverable | Accepted (dirty-tree evidence) |
| CE-07 | MODEL, PROPERTY | Legal queue/PFN/IOVA discharge permutations | Monotonic claim population; referenced domain rules and generic core invariants enforced | Accepted (dirty-tree evidence) |
| CE-08 | MODEL, PROPERTY | Parent retirement and release | Retired iff every required component and live claim is terminal; released once | Accepted (dirty-tree evidence) |
| CE-09 | PROPERTY, LOOM | Unrelated effect under retained composite pressure | Declared root/resource isolation; no global scan or freeze | Accepted (dirty-tree evidence) |

## Repeated crash and stale input

| ID | Layer | Required observation | Acceptance condition | Current status |
| --- | --- | --- | --- | --- |
| CR-01 | MODEL, PROPERTY, LOOM | Second crash before settlement intent | Old token fenced; no external apply; exact component remains recoverable | Accepted (dirty-tree evidence) |
| CR-02 | MODEL, PROPERTY, LOOM | Second crash after durable intent | Intent survives; no blind second intent or apply | Accepted (dirty-tree evidence) |
| CR-03 | MODEL, PROPERTY, LOOM | Second crash after external apply, before ack | Reconciliation state survives; no blind repeat | Accepted (dirty-tree evidence) |
| CR-04 | MODEL, PROPERTY, LOOM | Second crash after ack, before durable settlement | Ack bound to exact intent; one terminal settlement | Accepted (dirty-tree evidence) |
| CR-05 | MODEL, PROPERTY, LOOM | Second crash after each queue/PFN/IOVA discharge | Discharged claims never resurrect; live claims stay charged | Accepted (dirty-tree evidence) |
| CR-06 | MODEL, PROPERTY, LOOM | Late reply acknowledgement after new claimant | Old generation rejected or compacts only its tombstone; new state unchanged | Accepted (dirty-tree evidence) |
| CR-07 | MODEL, PROPERTY, LOOM | Late IRQ/completion/reset/IOTLB evidence | Exact old generation cannot mutate or release generation plus one | Accepted (dirty-tree evidence) |

## Resource-local reuse

| ID | Layer | Required observation | Acceptance condition | Current status |
| --- | --- | --- | --- | --- |
| RR-01 | MODEL, PROPERTY | Issue permit while unrelated reply claim remains | Allowed only for exact independently discharged resource | Accepted (dirty-tree evidence) |
| RR-02 | MODEL, LOOM | Permit issue races final retirement evidence | No permit before evidence; exactly one canonical result | Accepted (dirty-tree evidence) |
| RR-03 | MODEL, LOOM | Permit consumption races conflicting reserve | One winner; no overlapping live generations | Accepted (dirty-tree evidence) |
| RR-04 | STATIC, PROPERTY | Dedicated QEMU arena layout and opaque resource IDs | Generations of one `ResourceId` never coexist; fixed arena slots do not overlap; no generic physical-alias claim | Accepted (dirty-tree evidence) |
| RR-05 | PROPERTY | Generation overflow, skip, duplicate, stale permit | Fail before mutation; the only next generation is exactly `g + 1` | Accepted (dirty-tree evidence) |
| RR-06 | PROPERTY | Failed generation-plus-one activation | New core generation remains reserved/quarantined; old generation not reactivated | Accepted (dirty-tree evidence) |
| RR-07 | PROPERTY | Recovery after permit issue and before consumption | One durable permit; replay-equivalent high-water and tombstone | Accepted (dirty-tree evidence) |

## Versioning and legacy disposition

| ID | Layer | Required observation | Acceptance condition | Current status |
| --- | --- | --- | --- | --- |
| V-01 | STATIC, PROPERTY | Core profile coordinate | Exact value 2 in source, journal receipts, and snapshots | Accepted (dirty-tree evidence) |
| V-02 | STATIC, PROPERTY | Standard catalog coordinate | v5 digest covers the exact ordered component product and referenced obligation/claim rules, not a dependency graph | Accepted (dirty-tree evidence) |
| V-03 | STATIC, PROPERTY | Projection coordinate | With revision/head fixed, v6 golden and sensitivity vectors cover parent/component/claim and the exact pending successor claim, old generation, catalog, retirement digest, provider contract, nonce, freshness, and retained-record state; identical prefix plus anchor replays identically | Accepted (dirty-tree evidence) |
| V-04 | STATIC, PROPERTY | Recovery snapshot coordinate | v2 encodes one ordered parent/component graph | Accepted (dirty-tree evidence) |
| V-05 | STATIC, PROPERTY | Journal coordinate | `CSERJR6\0`, schema 6, profile-2 command grammar | Accepted (dirty-tree evidence) |
| V-06 | STATIC | Deferred canonical normalized trace | A successful-receipt carrier is not accepted as an applied/rejected trace codec; this row does not gate RFC 0007 | Deferred (non-gating); `TransitionReceipt` metadata only |
| V-07 | STATIC, PROPERTY | Any non-empty `CSERJR5` prefix presented to profile-2 scan/recovery | Typed `UnsupportedVersion` before payload decode or engine mutation | Accepted (dirty-tree evidence) |
| V-08 | PROPERTY | Pairing-collision corpus and arbitrary legacy suffixes | Roots, adjacent sequences, timestamp-like values, shared epochs, resources, and accounts never create an association | Accepted (dirty-tree evidence) |
| V-09 | QEMU | Inspected old-catalog TPM candidate selects the pinned one-reply schema-5 journal | `inspect -> quarantine -> scan -> MigrationRequired`; current-catalog bind and Registry publication are not reached; pairing heuristics are not exercised by this fixture | Accepted (dirty-tree evidence) |
| V-10 | STATIC | Automatic legacy migration surface | No drain/import/pair/rollover path in profile 2; copied schema 5 is diagnostic-only under frozen profile 1 | Accepted (dirty-tree evidence) |
| V-11 | STATIC, RELEASE | Production legacy closure | No live profile-1 authority, decoder, importer, fallback, merge, or dual-write in the profile-2 dependency closure | Accepted (dirty-tree evidence) |

## Production one-effect path

| ID | Layer | Required observation | Acceptance condition | Current status |
| --- | --- | --- | --- | --- |
| P-01 | STATIC, QEMU | One real operation creates effect | Task-bound ingress creates the declared parent before reply or queue commit | Accepted (dirty-tree evidence) |
| P-02 | STATIC, QEMU | Reply outbox identity | Record binds parent `EffectId` plus reply component | Accepted (dirty-tree evidence) |
| P-03 | STATIC, QEMU | Queue/DMA identity | Submission, leases, and evidence bind same parent plus DMA component | Accepted (dirty-tree evidence) |
| P-04 | QEMU | Real first service death | One parent fence; both components retained under one recovery snapshot | Accepted (dirty-tree evidence) |
| P-05 | QEMU | Fresh Snapshot/Ready/Rebind | Fresh task receives same parent and component projections | Accepted (dirty-tree evidence) |
| P-06 | QEMU | Declared reply/DMA partial-discharge sequence | Exercised component terminalizations do not cross-infer state or authorize unrelated reuse | Accepted (dirty-tree evidence) |
| P-07 | QEMU | Real second service death after durable reply apply intent | Exact exercised durable window recovers without duplicate external apply | Accepted (dirty-tree evidence) |
| P-08 | STATIC, RELEASE | Single cutover | One profile-2 Registry; no profile-1 runtime fallback, merge, or dual-write | Accepted (dirty-tree evidence) |

## Persistent DMA arena

| ID | Layer | Required observation | Acceptance condition | Current status |
| --- | --- | --- | --- | --- |
| A-01 | STATIC, QEMU | Arena reservation ordering | Exact arena excluded before general allocation and device activation | Accepted (dirty-tree evidence) |
| A-02 | QEMU | Journal-bound fixed-layout reconstruction | Effect/component/claim, catalog-bound retirement digest, provider reuse-contract digest, arena slot, guest PFN, emulated IOVA, core resource generation, and device generation match | Accepted (dirty-tree evidence) |
| A-03 | QEMU | Pre-replay quarantine | Bus mastering disabled or default-deny IOMMU before lease replay | Accepted (dirty-tree evidence) |
| A-04 | QEMU | QEMU process-boundary retirement | Old process exits; successor fences bus mastering, resets VirtIO, drains ISR state, and completes global IOTLB before replay; no exact old-domain unmap claim | Accepted (dirty-tree evidence) |
| A-05 | QEMU | Same dedicated guest coordinates at generation plus one | Same arena slot, guest PFN, emulated IOVA, and backing offset activate under core generation `g + 1` | Accepted (dirty-tree evidence) |
| A-06 | QEMU | Old-generation core evidence after reuse | Typed rejection is failure-atomic; revision, projection, and generation-plus-one owner remain unchanged | Accepted (dirty-tree evidence) |
| A-07 | QEMU | Declared four-process recovery sequence | Exercised reply/DMA partial states and second-crash boundaries are fail-closed and replay-equivalent | Accepted (dirty-tree evidence) |

## Physical-hardware closure

| ID | Layer | Required observation | Acceptance condition | Current status |
| --- | --- | --- | --- | --- |
| H-01 | HARDWARE | Exact platform manifest | Machine, firmware, BDF/PASID, IOMMU/IOAS, PFNs, IOVAs, IRQ and reset method recorded | Open |
| H-02 | HARDWARE | Early allocator/device quarantine | Old extents reserved and unreachable before normal activation | Open |
| H-03 | HARDWARE | Exact retirement receipts | Device quiescence, IRQ/completion drain, unmap, IOTLB and transaction drain as required | Open |
| H-04 | HARDWARE | Actual old PFN/IOVA generation-plus-one reuse | Old leases relinquished; exact physical coordinates assigned to declared new owner | Open |
| H-05 | HARDWARE | Late old-generation activity | No mutation of the new owner; stale evidence rejected | Open |
| H-06 | HARDWARE | Declared reboot/power-failure matrix | Every claimed failure mode passes; unsupported modes remain explicit non-claims | Open |

## Claim discipline and release

| ID | Layer | Required observation | Acceptance condition | Current status |
| --- | --- | --- | --- | --- |
| E-01 | RELEASE | Profile-1 evidence preservation | RFC 0006 files and receipts unchanged; no retrospective composite claim | Accepted (dirty-tree evidence) |
| E-02 | RELEASE | Exact evidence metadata | Source SHA, commands, scenario seeds, versions, digests, raw logs retained | Open; dirty source is content-hashed but has no exact candidate revision |
| E-03 | RELEASE | QEMU claim text | Says guest protocol/coordinates; explicitly denies host-physical generalization | Accepted (dirty-tree evidence) |
| E-04 | RELEASE | Hardware claim text | Scoped to exact tested platform and failure modes | Open; no hardware-scoped result exists |
| E-05 | RELEASE | Negative results | Fail-closed legacy selections, unavailable hardware, and failed fault cells retained | Accepted (dirty-tree evidence) |
| E-06 | RELEASE | Clean-source reproduction | Complete model/property/Loom/QEMU gates pass at exact candidate revision | Open; clean seal not run |

## Release labels

The repository may use the following labels only when every named row is
accepted at one exact source revision:

| Label | Required rows | Authorized statement |
| --- | --- | --- |
| `profile2-core` | CE-01..09, CR-01..07, RR-01..07, V-01..05, V-07..08 | Portable composite-effect semantics and fail-closed legacy handling |
| `profile2-production` | `profile2-core`, V-09..11, P-01..08 | One production effect and one profile-2 Registry, no dual-write |
| `composite-qemu` | `profile2-production`, A-01..07, E-01..03, E-05..06 | QEMU guest PFN/IOVA protocol reuse only |
| `composite-hardware` | `composite-qemu`, H-01..06, E-04 | Physical PFN/IOVA reuse for the exact tested hardware profile |

`composite-qemu` must never be abbreviated to "physical reuse." If the
hardware rows are open, the physical claim is open regardless of model, Loom,
or QEMU coverage.

No release label implies acceptance of deferred row `V-06`.

## Clean-seal closure

No release label is currently authorized because the current acceptances are
not bound to one exact candidate revision; `E-02` and `E-06` also remain open.
After all intended source and documentation changes are committed, the
maintainer must run the complete gates from a clean tree at that revision:

```console
cargo test -p cser-model --all-features
cargo test -p cser-core --all-features
bash kernel/nexus-ostd/scripts/assert-cser-core-production-cutover.sh
kernel/nexus-ostd/x seal-core-persistent-recovery
```

The clean run writes ignored `combined-receipt.txt` and
`combined-receipt.sha256` artifacts. A valid seal self-reports the exact
candidate `git_revision`, `git_source_tree_clean=true`, and
`seal_requested=true`; the companion checksum binds the receipt bytes.
Neither value is copied back into this tracked matrix, because doing so would
change the candidate revision after the proof and make a same-commit seal
self-referential.

Until then, the current result is accurately described as: portable
profile-2 semantics and the bounded four-process QEMU protocol passed on the
dirty worktree; clean-source release sealing and physical-hardware closure
remain open.
