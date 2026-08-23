# CSER trusted-local Python reference

This directory is the minimal host reference surface for the trusted-local
asynchronous endpoint and one bounded child handoff:

- `protocol.py` defines strict checksum-bound UART frames and evidence digests.
- `tool_endpoint.py`, `tool_provider.py`, and `tool_worker.py` provide the
  SQLite-backed endpoint, durable provider outcome store, and lease worker.
- `handoff_identity.py` derives and validates the fixed child descriptor.
- `uart_http_bridge.py` fail-closes UART-to-HTTP exchanges. Only an
  authenticated exact-identity `GET`/404 permits one same-key `POST` retry;
  pending, expired, malformed, or mismatched responses do not.

The endpoint is trusted-local: its authority is the selected host process and
SQLite database. It is not a remote attestation, authentication, or physical
quiescence mechanism.

Run the focused reference tests through the repository front door:

```
cargo nexus test
```
