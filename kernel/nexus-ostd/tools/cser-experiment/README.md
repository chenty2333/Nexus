# CSER host tool endpoint experiment

This is a **reference-grade trusted-local adapter**, not a remote attestation
service. `tool_endpoint.py` owns one launcher-selected local SQLite database;
SQLite rollback journaling and `synchronous=FULL` establish the sidecar's
durability boundary. Its authority is the local process plus that database,
not an identity asserted by a remote peer.

Every real-QEMU trial generates and persists one complete v2 identity before
the initial boot: `run_id`, namespace, local authority ID, effect ID, catalog
digest, operation key, and input digest. The endpoint persists its authority,
effect, namespace, catalog and retention contract in metadata; the initial and
recovery boots reuse the same row-local media, TPM state, endpoint database,
and identity. A changed namespace, authority/effect ID, catalog digest, or
retention policy is a startup failure, not a reinterpretation of old evidence.

The real CSER2 endpoint has the asynchronous state machine `Accepted ->
[Pending] -> Succeeded(result_digest) | Failed(code)`. `POST /v2/operations`
durably writes both the Accepted row and a queue entry, then returns HTTP 202;
an independent worker obtains a durable lease, queries the provider before any
dispatch, and commits the terminal record only after a queryable provider
outcome. The older `/v1/operations` route remains a deliberately synchronous
test-compatibility path. Terminal states are immutable. A
lookup can also return `expired` (HTTP 410) after its retention window or
`absent` (HTTP 404) when no matching record exists. Only checksum- and
identity-bound `absent` may reach the narrow same-key retry path; `expired`
never authorizes retry or release. An input-digest mismatch is conflict, never
apparent absence.

| v2 state | HTTP result | CSER meaning |
| --- | --- | --- |
| `accepted` / `pending` | 202 | Nonterminal; no evidence digest and no retirement authority |
| `succeeded` | 200 on v2 replay/query | Terminal outcome evidence with a v2 evidence digest |
| `failed` | 409 on v2 replay/query | Terminal failure outcome evidence with a v2 evidence digest |
| `expired` | 410 | Retained expiry tombstone; never retry/release authority |
| `absent` | 404 | Exact-identity absence; the only state eligible for same-key retry |

Outcome and quiescence remain separate. A terminal endpoint record is logical
outcome evidence for the tool component; it cannot retire the DMA queue, page,
or IOVA claims. Reset/IRQ-drain/IOTLB evidence may retire those physical claims
while the tool outcome remains unresolved.

`uart_http_bridge.py` is the only adapter between COM2's QEMU Unix-socket UART
and the HTTP endpoint. Real QEMU rows use CSER2, which checks the complete
identity and carries a v2 evidence digest. The digest is length-delimited under
`nexus-cser-local-evidence-record-v2` and binds namespace, authority, effect,
run, operation, input, catalog, schema, terminal state, and result. It is a
local integrity binding, **not** a signature or remote authentication proof.
The bridge rejects malformed framing, checksum, identity, input, catalog, and
evidence-digest mismatches fail-closed. The older CSER1/five-field digest is a
delimited compatibility path for focused tests, not the real-QEMU authority.

CSER2 request and response frames are ASCII, one bounded line each:

```
CSER2 REQ <POST|GET> <namespace> <authority> <effect> <run_id> <operation_key> <input_sha256> <catalog_sha256> <payload_base64> <sha256(preceding tokens)>\n
CSER2 RESP <http_status> <namespace> <authority> <effect> <run_id> <operation_key> <input_sha256> <catalog_sha256> <state> <result> <evidence_sha256|-> <sha256(preceding tokens)>\n
```

The final frame checksum is SHA-256 of the preceding tokens joined with exactly
one ASCII space. `GET` carries no new effect: it queries the complete durable
identity. The two distinct fault controls are
`--fault-after-response-commit-once` (durable adapter record, lost client
response) and `--provider-fault-after-apply-once` (durable provider outcome,
no adapter terminal record). Recovery of the latter first queries the provider
with the complete catalog-bound identity; it does not redispatch blindly.

Retention is fail-closed. Accepted and Pending have no retention deadline;
only a terminal evidence record starts the retention clock. Expiry turns an old row into a retained `expired`
tombstone rather than deleting it into ambiguity. Legacy v1 rows migrate only
to unbound, expired tombstones; they never acquire a v2 authority/catalog
binding retroactively. An unknown, corrupt, or newer endpoint schema fails
startup. The adapter adds `async_queue_schema_version=1` to its durable
metadata when reopening a pre-queue v2 database; a pre-existing queue with an
unknown layout, missing foreign key, orphan, or terminal work fails startup.
The adapter deliberately does **not** provide remote MACs,
mTLS, a remote registry, multi-tenancy, or cross-host trust establishment.

Example:

```
python3 tool_endpoint.py --database /tmp/cser-tool.db --port 18080 --fault-after-response-commit-once
python3 uart_http_bridge.py --socket /tmp/cser-tool.sock --run-id 0123456789abcdef0123456789abcdef --endpoint-port 18080
python3 -m unittest discover -s tests -v
```

## Host-controlled crash matrix

`run_matrix.sh` runs the same seven cutpoints for either `cser` or `baseline`:
`pre_escape`, `post_register`, `post_endpoint_apply`, `post_effect_fact`,
`post_quiescence`, `pre_discharge`, and `post_discharge`. Each trial receives a
fresh reflink-or-copy of every `--base-media` input and retains its media after
the crash.

Before each copy, the runner SHA-256s the base medium, verifies that both the
copied file and the base still match that digest after the copy, and records
the digest under `TRIAL/base-media.sha256`. `--base-media-dir` provisioning is
directory-locked, so concurrent baseline and CSER first runs can share an
empty base directory without seeing an in-progress `truncate` result.

`--only-cutpoint NAME` selects one of those seven rows for focused diagnosis;
it does not alter that row's guest, media, controller, or recovery path.

The guest connects to `$CSER_EXPERIMENT_BARRIER_SOCKET` and sends:

```
CSER1 BARRIER <32-lowercase-hex-run-id> <cutpoint> <sha256(preceding tokens)>\n
```

For a target crash cutpoint, the host validates the exact run ID and cutpoint,
closes COM3 without an `ACK`, and immediately SIGKILLs the recorded process
group (or invokes an explicit container-kill command on the exact CID written
to `$CSER_EXPERIMENT_CID_FILE`). `ACK` exists only for the explicit non-target
pass-through controller mode. There is no timing- or log-derived cutpoint.

```
tools/cser-experiment/run_matrix.sh --variant cser --output /tmp/cser-matrix \
  --base-media artifacts/base.qcow2 -- ./launch-qemu-with-barrier-guest.sh
```

The common `metrics.jsonl` schema deliberately states only
`retention_horizon: "bounded_observation"`. Both `permanent_retention` and
`admin_disposition` are `null`: a finite crash matrix establishes neither.

Target trials can add `--recovery-guest EXECUTABLE`. After killing the initial
QEMU process, the controller launches that executable with the same retained
trial media and requires `$CSER_EXPERIMENT_RECOVERY_METRICS` to contain
`{"terminal": true, "invariants_ok": true}`. Only then is the JSONL row
`completion_state: "recovery_verified"`; without it, a crash row is explicitly
`crashed_unrecovered`, never completed.

`--timeout-seconds` bounds initial boot / COM3 cutpoint observation. Recovery
has its own outer `--recovery-timeout-seconds` envelope (defaulting to the
initial budget in the generic runner), and failures name the recovery stage.
Both launcher stdout and stderr stream directly to each trial's
`initial.*.log` or `recovery.*.log`; they are never left in an unread host
PIPE before a barrier.

`run_qemu_matrix.sh` is the separate real-QEMU entrypoint. It accepts only
`qemu_boot.sh` for both boots, stages each row's `journal.raw`, `outbox.raw`,
and `ram.raw` into the reviewed OSDK envelope (and resets per-row swtpm state
before boot one), starts the endpoint and COM2
bridge, and rejects host-created recovery JSON. Every row instead receives a
fresh, persisted per-trial CSER2 identity: run, namespace, authority, effect,
and the catalog digest computed from the same workspace source as the guest.
Recovery reuses that exact identity and endpoint database; it cannot replace it
with a random host value. A recovery row is accepted only when QEMU serial
contains exactly one `TOOL_DMA_RECOVERY_METRICS {…}` record with matching
variant/run id and both `terminal` and `invariants_ok` true. The informational
`TOOL_DMA_EXPERIMENT ...` smoke marker is never a completion receipt.

For real QEMU, the initial/cutpoint budget defaults to 90 seconds and the
recovery envelope defaults to 120 seconds. The latter is required to exceed
the 90-second timeout inside `qemu_boot.sh`; lowering it to 90 seconds or less
is rejected rather than making the two envelopes race.

Real-QEMU rows use schema version 2. Their terminal experiment metrics
are copied only from that verified recovery terminal record, never from the
host-captured initial-boot metrics file. `retired_by_evidence` and
`retained_claims` are required non-negative integers. This matrix does not yet
measure elapsed reconciliation time or contention-driven gate rejections, so
the recovered guest must explicitly emit `reconciliation_delay_ms: null` and
`gate_rejections: null`, alongside a non-negative `reconciliation_steps` and
`reconciliation_delay_unit: "unmeasured"`. The summarizer reports a
per-field `measured_trials` count and does not convert those nulls to zero.
Generic fake-controller runs retain `metrics_source: "initial_guest_file"` for
backward-compatible unit tests; real runs are marked
`metrics_source: "recovery_terminal"`.

Use `run_qemu_matrix.sh --base-media-dir DIR` to create or validate the only
accepted blank-media shape: `journal.raw` and `outbox.raw` are each 4 MiB and
`ram.raw` is 1 GiB. The first CSER boot provisions an isolated swtpm directory
with the current `tool_dma_catalog()` digest and genesis registry/binding 1;
the first baseline boot provisions the same independent selector layout with
an authenticated revision-zero genesis, so `ExperimentNvAnchor::open` never
interprets an uninitialized TPM counter as blankness. Recovery reuses that exact
row-local TPM state in either arm.

### Fresh-media journal-vNext smoke selection

`tool-dma-cser-vnext` is a deliberately separate, development-only QEMU
scheme for the append/checkpoint ATA journal.  It uses the same 4 MiB blank
`journal.raw` shape and the same trusted-local endpoint, VirtIO, IOMMU, and
TPM envelope as `tool-dma-cser`, but stages them only under
`artifacts/tool-dma-cser-vnext/` and opens `AtaPioJournalVNext` at compile
time.  It never detects, migrates, or overwrites a legacy journal image.

For a host-controlled trial, set `CSER_EXPERIMENT_JOURNAL_VNEXT=1` while
invoking `qemu_boot.sh` with the normal `cser` variant.  The script selects the
vNext scheme and its isolated artifact directory.  `./x build-tool-dma-
experiments` is the narrow compile/build gate for this path; the existing
`test-pio-journal` gate exercises append, reopen, repair, and checkpoint fault
paths using the kernel test runner.  A vNext run is a fresh-media journal
smoke, not a replacement production seal or a migration claim.

COM3 is a startup-synchronized channel (`wait=on`), so the first barrier cannot
race ahead of the host controller. Recovery boots have no crash cutpoints and
use `uart_sink.py` solely to satisfy that startup handshake; receiving any byte
on that recovery-only channel is an error.

The trusted-local launcher supervises the endpoint, COM2 bridge, recovery UART
sink, and QEMU separately. The bridge and sink publish atomic local readiness
and terminal status files for the row; these files are diagnostics only, never
guest evidence. A failed row names one of `endpoint-connect`, `bridge-ready`,
`guest-boot`, `frame-complete`, `recovery-receipt`, or `cleanup`, and preserves
the corresponding helper stderr log. Recovery accepts a terminal receipt only
after the bridge served its single recovery request and the COM3 sink closed
without observing a crash barrier.

The endpoint also exposes local counters and state inventory at `/v1/metrics`.
They report adapter/contract version, bound authority/namespace/catalog,
retention, state counts, queue depth/leases/attempts, provider query/apply/
dedup counts, and submit/replay/conflict/expiry/transition/infrastructure-
retry/backoff counts. Provider or SQLite failures release the lease but wait
with a bounded exponential backoff before reclaiming work; they remain Pending
rather than becoming a terminal application failure.
They are readiness and diagnosis data, not remote evidence and not a claim
that retention duration, administrative disposition, or endpoint latency has
been measured.

`summarize_metrics.py` accepts repeated `--input` arguments. Supplying one
terminal JSONL from each arm produces a single comparison summary without
copying or rewriting either arm's raw rows.

The real-QEMU launcher takes a nonblocking per-variant host lock across every
initial and recovery boot because each OSDK scheme has one fixed artifact and
socket directory. The endpoint binds an OS-selected ephemeral port and
publishes that exact port to the bridge. A matrix output directory must be new;
reusing one is rejected instead of appending duplicate row identities.

This remains a correctness-only matrix. Terminal retained inventory and
evidence-retirement counts do not measure retained duration, peak retention,
or the proportion of operations that would require administrative disposition.

## Current performance evidence and non-decisions

The release-profile full-state measurement currently reports, at 4,096 live
claims, clone `1.014 ms`, invariant checking `1.623 ms`, and projection digest
`1.753 ms`: `4.390 ms` total. Across the current and prior comparable writable
runs, the observed total range is approximately `4.39–5.13 ms` (the earlier
three-run range was `4.63–5.13 ms`); the 512-claim current point is
approximately `0.871 ms`. These are profile measurements, not latency SLOs or
hardware-general results.

The deterministic 64 KiB ATA journal fill writes and reads 8,384 sectors each,
flushes 256 times, and writes roughly 65.5x the logical payload. The validated
cache avoids revalidating banks between appends; the older uncached path read
24,769 sectors for the same fill profile. This is evidence to prioritize an
append/checkpoint design only after its crash-atomic and readback contract is
preserved; it is not a license to weaken journal-before-anchor ordering.

Runtime-mutex telemetry currently covers only one fail-closed transaction on
the SMP BSP smoke path. It has not measured contention or cross-CPU
transactions, so there is no evidence for splitting the authoritative writer
mutex yet. Any future change must retain one durable ordering and must not
expose candidate state or effects before the journal and anchor commit.

## UART polling diagnostics

COM2 and COM3 use bounded readiness-poll batches. Between batches they yield
only from an ordinary OSTD task context; bootstrap and IRQ context remain
polling-only, so the transport never turns an early-boot or IRQ path into a
scheduler sleep. The host controller's deadline remains authoritative.

The guest serial log records `TOOL_UART_TIMING` and `CRASH_PROBE_TIMING` lines
with guest-TSC points for transmit start/completion, first response or ACK
byte, full frame, and verified endpoint response or matching ACK, plus poll and
scheduler-yield counts. They are diagnosis and ordering data only: QEMU/TCG
guest TSC is not an elapsed host-time, endpoint-latency, or performance metric.
