# CSER host tool endpoint experiment

`tool_endpoint.py` is deliberately independent of Nexus.  It persists one
operation under `(run_id, operation_key)` before responding.  Retrying the same
key and payload digest is idempotent; changing the payload for that key is a
conflict.  `GET` exposes the durable status.  SQLite uses rollback journaling
and `synchronous=FULL`.

`uart_http_bridge.py` is the only adapter between COM2's QEMU Unix-socket UART
and the HTTP endpoint.  It accepts only the configured 32-lowercase-hex run id and checks framing,
checksum, payload digest, and size before issuing HTTP.  Before a successful
reply crosses UART it recomputes the endpoint record digest over `(run_id,
operation_key, payload_digest, terminal_status, result)`; HTTP formatting and
the `replayed` marker are not evidence. Errors are returned as 503 with no
terminal record, never as a success-shaped response.

Request frame (ASCII, exactly one line):

```
CSER1 REQ <POST|GET> <run_id> <operation_key> <sha256(payload)> <base64(payload)|-> <sha256(preceding tokens)>\n
```

Response frame:

```
CSER1 RESP <run_id> <operation_key> <http_status> <payload_sha256> <terminal_status> <result> <record_sha256> <sha256(preceding tokens)>\n
```

The checksum is SHA-256 of the preceding tokens joined with exactly one ASCII
space. `record_sha256` is SHA-256 under the domain separator
`nexus-cser-tool-record-v1`, with each of the five terminal-record fields
length-delimited. `GET` carries the pre-recorded payload digest and an empty
payload; it queries instead of applying. `--fault-after-apply-once` models the key CSER ambiguity: the operation
is durable, but the client loses the response and must use its key to retry or
query it.

Example:

```
python3 tool_endpoint.py --database /tmp/cser-tool.db --port 18080 --fault-after-apply-once
python3 uart_http_bridge.py --socket /tmp/cser-tool.sock --run-id 0123456789abcdef0123456789abcdef --endpoint-port 18080
python3 -m unittest discover -s tests -v
```

## Host-controlled crash matrix

`run_matrix.sh` runs the same seven cutpoints for either `cser` or `baseline`:
`pre_escape`, `post_register`, `post_endpoint_apply`, `post_effect_fact`,
`post_quiescence`, `pre_discharge`, and `post_discharge`. Each trial receives a
fresh reflink-or-copy of every `--base-media` input and retains its media after
the crash.

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

`run_qemu_matrix.sh` is the separate real-QEMU entrypoint. It accepts only
`qemu_boot.sh` for both boots, stages each row's `journal.raw`, `outbox.raw`,
and `ram.raw` into the reviewed OSDK envelope (and resets per-row swtpm state
before boot one), starts the endpoint and COM2
bridge, and rejects host-created recovery JSON. Its present guest uses the
fixed run identity `4242…4242`; every row has separate durable media and a
separate endpoint database. Until the guest accepts a durable per-trial boot
identity, the runner must not substitute a random host identity. A recovery
row is accepted only when QEMU serial contains exactly one
`TOOL_DMA_RECOVERY_METRICS {…}` record with matching variant/run id and both
`terminal` and `invariants_ok` true. The informational
`TOOL_DMA_EXPERIMENT ...` smoke marker is never a completion receipt.

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

COM3 is a startup-synchronized channel (`wait=on`), so the first barrier cannot
race ahead of the host controller. Recovery boots have no crash cutpoints and
use `uart_sink.py` solely to satisfy that startup handshake; receiving any byte
on that recovery-only channel is an error.

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
