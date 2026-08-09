# Late-bound custody decision

## Result

**No-Go for the portable G0/G1 pilot and for a real-QEMU continuation.**

This is a Gate 0 decision, not a negative safety result for the existing CSER
implementation. Two primary-source workload candidates were examined:

- Kubernetes Job plus Dynamic Resource Allocation; and
- NVMe Namespace Management Create followed by Attach and block I/O.

Both have an exact resource coordinate that becomes known late. Neither has
the executor/effect custody gap required by the proposed experiment. Their
late allocation is already held behind a workload-specific or provider-native
first-observation gate. The detailed evidence and five-condition tables are in
[`cser-late-bound-workload-card.md`](cser-late-bound-workload-card.md).

Consequently this round does not pre-register or freeze a G0/G1 experiment,
does not add dynamic components or a parent/child core relation, and does not
promote the portable prototype into source. A later candidate may define a new,
versioned pilot after it independently passes Gate 0.

## Why late knowledge was insufficient

Kubernetes persists the exact allocation and its authorized consumer in a
ResourceClaim. Scheduler Reserve/PreBind and device preparation precede Pod
observation. Submitter replacement does not revoke that authority, and only
the selected device is reserved.

NVMe Create is a sharper counterexample. The controller selects NSID only on
successful completion, and a lost completion is not request-key recoverable
under concurrent identical creates. But the created namespace remains
unattached and inactive for ordinary I/O. A management service can serialize
Create, reconcile allocated namespace identity, and withhold Attach. Executor
replacement therefore risks unattributed capacity, not conflicting reuse while
escaped DMA still targets the coordinate.

This distinction is now the Gate 0 rule:

```text
late-known coordinate != executor/effect custody gap
```

A candidate must additionally show that replacement can race admission or
reuse across authorities that do not already share a scheduler, provider
lease, attachment gate, or durable workflow coordinator.

## Work intentionally not adopted

An exploratory portable implementation was able to express a same-root
sequence of `A retained -> create/enroll B -> release A -> B escape` with the
existing sealed-composite contract. That only demonstrated that the core can
represent the sequence. Its route relation was necessarily supplied by a
test-side ledger, because the core has no A-to-B causal edge. Without a Gate 0
workload, its four synthetic crash windows and wildcard baselines would not
answer whether the boundary occurs in a real system. They were therefore not
kept as project source or reported as evidence.

## Bounded evidence-availability result

The approved pivot is narrower: establish what the current adapter and core do
when evidence is available, delayed, expired, or absent, without inferring
workload frequency.

The current source establishes these cases:

| Controlled condition | Observable result | Claim boundary |
| --- | --- | --- |
| CSER2 terminal `Succeeded` or `Failed` | exact identity-bound outcome record is queryable after restart | outcome evidence only; it cannot retire DMA claims |
| endpoint Store `Accepted` or `Pending` | durable state survives database close/reopen with evidence digest `-` | reconciliation remains necessary; no terminal observation exists; the current HTTP path does not expose an asynchronous Pending job |
| CSER2 expiry | immutable HTTP 410 tombstone remains distinguishable from absence | no retry or release authority |
| exact identity has no endpoint row | checksum-bound HTTP 404 | permits only the existing same-key retry path; it is not evidence that an escaped operation retired |
| DMA reset or IRQ/IOTLB fact missing | the corresponding retirement command cannot be verified | affected claim remains live and reuse remains inadmissible |
| one component has complete evidence while its sibling does not | completed component can retire independently | unresolved sibling remains retained; the composite is only partially discharged |

The focused endpoint Store regression now closes and reopens the SQLite-backed
state machine with a durable `Pending` row and confirms that it remains
nonterminal and non-evidence. This is not a sidecar-process or CSER2-wire
Pending test. Existing profile-2 and DMA contract tests already exercise the
component-local retention and release boundary, including the deterministic
credit-unit-revision measurement. No new QEMU fault matrix is warranted merely
to repeat those state facts.

These results do **not** measure real workload prevalence, permanent retention,
administrative disposition, wall-clock resource-seconds, or a real endpoint's
probability of losing evidence. Those require an operation trace or deployment
sample. The existing matrix correctly keeps those fields unmeasured.

## Next research decision

The next high-value input is an applicability trace, not another mechanism:

1. sample real agent/tool and device operations with a stable effect identity;
2. record whether outcome and quiescence are recoverably queryable after the
   executor is gone;
3. identify whether a provider, scheduler, lease service or workflow database
   already owns first observation and reuse;
4. measure bounded retained resources and gate denials only where a locally
   governed coordinate remains; and
5. reopen late-bound G0 only for a trace that shows irreversible A, a genuinely
   later exact B, distinct authorities, a replacement/reuse race, and a real B
   admission gate.

Until such a trace exists, the defensible CSER result remains the existing one:
the substrate enforces typed, component-local fail-closed custody in its stated
tool-plus-DMA profile, while its necessity over strong workload-specific
coordinators remains unproven.
