# Nexus production effect peer

`nexus-effect-peer` is a same-boot host process that drives the production
Nexus `EffectRegistry` transition source through a narrow JSON Lines protocol.
It is intended for the bounded vISA/Nexus joint system cell. It is not a
network service, an ownership log, or a reboot-recovery mechanism.

## Boundary

The crate deliberately has no dependency on vISA or the neutral joint-handoff
crate. It compiles the same production Registry source used by the kernel and
the existing production-transition refinement tests:

```text
vISA system runner
  -> ProcessEffectPeer adapter
  -> long-lived nexus-effect-peer child
  -> production EffectRegistry source
```

The process emits Nexus-native receipts. It does not fabricate neutral
`NexusFreezeReceipt`, `ClosureReceipt`, or `ReceiptEnvelope` values. A vISA
adapter must:

1. retain the exact response line returned by this process;
2. verify the native request digest, payload digest, receipt digest, parent
   chain, process identity, exact executable, and pinned Nexus source revision;
3. map the verified native fields into the neutral typed receipt;
4. retain both the native bytes and mapped neutral bytes in evidence; and
5. independently recompute the mapping during bundle verification.

The SHA-256 chain is integrity evidence only. Its
`sha256-integrity-only-not-authenticity` label is intentional. It is not a MAC,
signature, KMS decision, or freshness proof.

## Native wire compatibility

The request, response, and native-receipt schemas ending in `.v1` are frozen.
Native v1 accepts compatibility-preserving fixes only; new commands, fields,
receipt kinds, or semantics require native v2 or an explicitly versioned
extension with distinct schema identifiers. The independently consumable
`nexus-effect-peer-wire` crate owns the serde types, canonical encoding and
producer corpus; this process crate depends on and re-exports that public API.
The machine contract is kept in `status/effect-peer-native-v1.json`, mirrored
byte-for-byte in the wire package, and checked during both crate test gates.

## Process lifecycle

One process owns one Registry and one scope:

```text
spawn
  -> initialize
  -> register / prepare / commit / complete effects
  -> crash-service(active supervisor + binding epoch)
     -> rebind-service(crashed binding epoch + replacement supervisor)
     -> replacement continues through adopted selectors
  -> freeze
  -> thaw
     or
     abort-uncommitted -> acknowledge-publication
       -> close-step -> acknowledge-publication -> close-step ... -> closed
  -> query or exact request replay as needed
  -> shutdown
```

The system runner, rather than a disposable coordinator object, must own the
child process. A coordinator crash/restart reconnects to the same pipes or to a
future runner-owned transport and replays the exact request ID and bytes. The
peer returns the byte-identical cached response. Killing the peer loses the
in-memory Registry and is outside this same-boot profile.

Every request is one bounded JSON object followed by `LF`. Every response is
one JSON object followed by `LF` and is flushed before the next request. A
request is idempotent by `(request_id, canonical request bytes)`. Reusing an ID
with different bytes fails without a Registry transition.

Effect commands are binding-explicit. `prepare`, `commit`, `complete`, and
`acknowledge-publication` carry the current production binding epoch. The crash
receipt advances that epoch; the rebind receipt returns the exact adopted
effect identities at the new epoch. The peer never upgrades a stale selector
merely because it has replaced its private `PortalHandle`: an old selector is
rejected as `stale-binding`, and the production Registry independently rejects
the old opaque handle after `adopt` changes both its binding and nonce.

`crash-service` calls the production Registry's `crash` transition.
`rebind-service` calls `recovery_snapshot`, `ready`, `rebind`, and then drains
the exact recovery cohort through `recover_next` and `adopt`. Both native
receipts are SHA-256 chained like every other successful peer transition, and
an exact request replay returns the byte-identical cached response without
repeating any Registry transition.

## vISA call mapping

The vISA system adapter may drive this peer through its process-backed effect
interface. The production mapping is:

| vISA-side operation | Native process operations |
| --- | --- |
| publish a registered effect | `register` |
| backend-ready effect | `prepare` |
| first external publication | `commit` before external I/O |
| provider outcome available | `complete`, retaining publication pending when required |
| source service crashes | `crash-service` using the last accepted supervisor identity and binding epoch |
| replacement service is ready | `rebind-service`; retain the returned adopted selectors and discard every old selector |
| freeze | `freeze` with the already authenticated ownership intent projection |
| abort | `thaw`; the source keeps any effect not explicitly cleaned up |
| commit/close | `abort-uncommitted`, publication acknowledgement, then repeated `close-step` and acknowledgement until `closed` |
| recovery | exact request replay followed by `query` |

The adapter must not translate an arbitrary vISA classification enum into a
claimed committed Nexus effect. `Committed` is accepted only after the process
has actually executed the production Registry `commit` transition.

Service recovery here is not a Registry replacement. `crash-service` and
`rebind-service` preserve the same Registry instance, scope generation, and
authority epoch while advancing only the local service binding. They must not
be used to implement a vISA operation that replaces `registry_instance` or
scope identity; that distinct operation remains unsupported until a neutral
refinement explicitly defines it.

## Current limits

- same host process and one kernel-boot projection only;
- one scope, one handoff record, and one legacy Registry domain per process;
- stdin/stdout transport, not a secure or cross-host channel;
- no persistent Registry, host-reboot recovery, cryptographic authentication,
  rollback resistance, SMP/IRQ observation, or production deployment claim;
- close drains a bounded committed effect through the Registry and requires an
  explicit publication acknowledgement before final closure;
- service recovery is same-process and same-boot: it changes the production
  service binding and adopts live effects, but it does not respawn an arbitrary
  application process or persist Registry state;
- retained device tombstone recovery remains in the production Registry/device
  paths and is not remotely controlled by this adapter.

## Retained device/tombstone API audit

The production Registry already has the necessary truthful state transitions,
but this peer does not yet expose or exercise them. A real adapter must first
construct a device-backed causal cohort through `add_domain`,
`register_derived` / `register_device_derived` (or the failure-atomic cohort
form), `kernel_root_authority`, `enroll_device_batch`, and
`commit_device_batch_with_publish` or
`commit_or_recover_device_close_with_apply`. It must retain the opaque native
receipts in the process; raw wire integers cannot recreate them.

After publication, the closure lane must drive `begin_device_reset`,
`retain_device_reset_timeout` or `acknowledge_device_reset_with_apply`, then
`begin_device_iotlb`, `retain_device_iotlb_timeout` or
`acknowledge_device_iotlb_with_apply`. Tombstone recovery uses
`retry_device_reset` / `retry_device_iotlb`, and terminalization must present
the resulting `DeviceClosureReceipt` to `stage_device_batch_terminal` before
scope closure. The precommit cancellation lane instead needs
`close_enrolled_device_precommit_with_apply` or
`close_pending_device_precommit_with_apply`.

What is missing is therefore a peer-owned device receipt store, typed wire
commands that can only select those stored receipts, and a real hardware
facade for reset/generation/IOTLB apply callbacks. Mapping a neutral
`ResolvedTombstone` or `UnresolvedTombstone` enum directly to a receipt would
bypass these production transitions and remains unsupported.

## Verification

```sh
cargo test -p nexus-effect-peer-wire
cargo test -p nexus-effect-peer
cargo clippy -p nexus-effect-peer-wire --all-targets -- -D warnings
cargo clippy -p nexus-effect-peer --all-targets -- -D warnings
```

The process-level tests spawn the real binary. One freezes and closes an empty
production cohort, drops the conceptual first acknowledgement, and requires
byte-identical close replay. The other crashes a prepared production effect,
rebinds and adopts it under a replacement supervisor, requires byte-identical
rebind replay, rejects the old selector, and commits through the new binding.
