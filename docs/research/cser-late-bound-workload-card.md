# Gate 0 workload card: late-bound accelerator and NVMe namespace candidates

## Decision

**Gate 0 result: No-Go after two primary-source candidates.** Kubernetes Job
plus Dynamic Resource Allocation (DRA) is genuinely late-bound with respect to
the exact node and accelerator. NVMe Namespace Management is an even stronger
candidate because a controller selects the exact namespace identifier only
while completing a capacity-consuming Create operation. Neither satisfies all
five conditions for the proposed CSER handoff pilot.

NVMe fails for a more informative reason than Kubernetes: a lost Create
completion can make the new NSID ambiguous to the issuer, but the namespace is
still unattached and therefore inactive for I/O. The NVMe controller supplies
the staged Create/Attach boundary, the allocated-namespace inventory and a
globally unique namespace identity. A serialized management service can
reconcile the orphan before Attach. Executor replacement therefore races
capacity reclamation, not reuse of a resource that an escaped I/O may still
touch.

The decisive reasons for the Kubernetes candidate are:

1. creating a Job is a persistent desired-state request, not an externally
   irreversible fact;
2. Kubernetes records the late allocation and its consumers in the shared
   ResourceClaim control-plane object rather than leaving A and B as
   independent authoritative journals;
3. submitter or controller replacement does not revoke the persisted Job;
4. DRA selects one exact device late, so it does not need to reserve every
   possible accelerator in advance; and
5. Kubernetes already supplies a first-observation gate: allocation,
   reservation and optional device readiness precede Pod binding and container
   start.

This is a useful negative result. DRA is a strong workload-specific
coordinator and guarded-publication counterexample that the Gate 1 baseline
should be allowed to emulate. NVMe is a provider-native staged-publication and
identity-reconciliation counterexample. The generic DRA contract does not
itself prove a hardware generation fence, and this card does not grant it one.
Neither candidate is evidence that CSER is needed at its examined boundary.

## Candidate 1: NVMe Namespace Management Create to later block I/O

### Candidate topology

The candidate uses the standard NVMe management sequence:

1. an administrator or management process submits Namespace Management Create
   with requested size, capacity and format but with NSID cleared to zero;
2. the controller allocates capacity, creates a namespace and returns its
   controller-selected NSID in the successful completion;
3. host software identifies the new namespace and then explicitly attaches it
   to one or more controllers;
4. the Linux NVMe driver's namespace scan validates the namespace and publishes
   a block device; and
5. only then may ordinary block requests map host memory for device I/O.

Here A is Namespace Management Create. The proposed B is the Linux namespace
object, block-device publication and later DMA-capable I/O path for the exact
NSID. “Persistent” is used only where the specification says so. In particular,
the Base Specification explicitly says Attach/Detach survives reset events; it
does not, in the passages cited here, make a general physical power-loss claim
for every controller's namespace-management metadata.

### Authoritative NVMe facts

The following are direct facts from ratified NVM Express specifications and
upstream Linux source, reviewed on 2026-08-10.

- For Create, host software clears the NSID field and the controller selects an
  available NSID. A successful completion returns the created NSID in
  completion Dword 0. Create does not attach the namespace to a controller.
  [NVM Express Base Specification 2.0d, sections 5.23 and 8.11](https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0d-2024.01.11-Ratified.pdf)
- The host can enumerate allocated NSIDs with Identify CNS `10h` and can query
  the Identify Namespace data structure for an allocated NSID with CNS `11h`.
  Active and allocated namespace lists are distinct.
  [NVM Express Base Specification 2.0d, sections 5.17.2.2, 5.17.2.9 and 5.17.2.10](https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0d-2024.01.11-Ratified.pdf)
- Namespace Attachment is a separate command. Attach and Detach are persistent
  across reset events. A detached namespace's NSID is inactive on that
  controller; commands to an inactive NSID are rejected as specified by the
  common command rules.
  [NVM Express Base Specification 2.0d, sections 5.22 and 8.11](https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0d-2024.01.11-Ratified.pdf)
- Namespace Create consumes controller-determined NVM capacity and may round a
  request up to the controller's allocation unit. Create can fail for
  insufficient capacity or because no NSID is available. The capability is
  intended for manufacturing or system-administrator use.
  [NVM Express Base Specification 2.0d, sections 5.23 and 8.11](https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0d-2024.01.11-Ratified.pdf)
- The NVM Command Set's host-specified Create fields include size, capacity,
  format, protection, sharing, placement and group choices. The standard
  structure does not contain a caller-supplied operation token or requested
  NSID.
  [NVM Command Set Specification 1.1, Figure 125](https://nvmexpress.org/wp-content/uploads/NVM-Express-NVM-Command-Set-Specification-Revision-1.1-2024.08.05-Ratified.pdf)
- A namespace receives a globally unique NID at creation; that NID remains
  fixed for the namespace's lifetime and its descriptor list is preserved
  across namespace and controller operations. The NVM command set requires a
  controller to supply an NGUID, EUI64 or Namespace UUID. NSIDs may change
  across power-off, and a controller may reuse NGUID/EUI64 after deletion
  unless the namespace reports `UIDREUSE=1`.
  [NVM Express Base Specification 2.0d, section 5.17.2.3](https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0d-2024.01.11-Ratified.pdf),
  [NVM Command Set Specification 1.1, Figure 114](https://nvmexpress.org/wp-content/uploads/NVM-Express-NVM-Command-Set-Specification-Revision-1.1-2024.08.05-Ratified.pdf)
- Delete is an explicit Namespace Management operation whose successful
  completion means the namespace has been deleted. Deletion detaches it from
  all controllers, makes its NSID unallocated and causes previously submitted
  but incomplete commands for that NSID to be handled as commands to an
  inactive namespace.
  [NVM Express Base Specification 2.0d, sections 5.23 and 8.11](https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0d-2024.01.11-Ratified.pdf)
- Linux reacts to a namespace-change notice by queueing a scan. The scan reads
  namespace descriptors and readiness, checks that identifiers for an existing
  NSID have not changed, and calls `device_add_disk` only for a ready namespace.
  Removal clears readiness, waits for concurrent submissions through SRCU and
  removes the disk. [upstream Linux NVMe host core](https://github.com/torvalds/linux/blob/master/drivers/nvme/host/core.c)
- Linux admin passthrough executes the request and only then copies the result
  to user memory. Thus controller completion and delivery of the result to the
  issuing process are separate host-side events.
  [upstream Linux NVMe ioctl path](https://github.com/torvalds/linux/blob/master/drivers/nvme/host/ioctl.c)

### Inferences for NVMe

The following are analytical inferences from those facts.

1. **A lost reply creates an identity-reconciliation gap, but not exact
   recoverability by itself.** The successor can enumerate allocated NSIDs and
   query their Identify data, but Create carries no caller token. If another
   actor may create a namespace with the same requested attributes, the
   specification provides no way to prove which new namespace corresponds to
   this intent. Exact recovery therefore requires a management service to
   serialize Create, record a before-set, or apply an external ownership
   convention. A stable NID prevents later alias confusion once the candidate
   is identified; it does not identify the lost operation by itself.
2. **The controller has already separated creation from first observation.** A
   successfully created namespace is allocated but unattached. It cannot become
   a Linux I/O target until an explicit Attach and a successful driver scan.
   Persisting reconciliation state before Attach is therefore a real and cheap
   workload-specific gate.
3. **A and B are different software recovery domains, but not independent
   allocation authorities.** Controller management state survives a user
   process, while Linux owns the block object and queues. Nevertheless, the
   controller-selected NSID and stable NID authoritatively name the object used
   by both Create and Attach; Attach is the controller's native handoff.
4. **Executor replacement does not race an escaped B effect in this sequence.**
   Before Attach there is no block device or ordinary I/O to the new namespace.
   A cautious successor may retain or delete the orphan only after
   reconciliation. That is a capacity leak and administrative-attribution
   problem, not a race in which old DMA can touch a resource the successor has
   reused.
5. **Preclaiming the exact NSID is impossible, but reserve-all is the wrong
   comparison.** The controller assigns an NSID and capacity is genuinely
   consumed. Yet the host need not reserve all possible NSIDs: it can serialize
   the rare administrative Create operation and delay Attach. The wildcard cost
   is replaced by a narrow provider-native critical section.
6. **NSID reuse alone is not an uncovered generation problem here.** Linux
   compares namespace identifiers and removes an existing namespace if the
   identifiers change for an NSID. The specification may permit identifier
   reuse after explicit deletion, so this is not an unconditional generation
   fence. The more important protection is sequencing: Delete makes the old
   NSID unallocated and outstanding commands inactive before a later namespace
   can reuse it. A CSER pilot would need evidence of DMA surviving that
   provider transition, not merely evidence that numeric NSIDs can recur.

### NVMe Gate 0 criteria

| Criterion | Result | Evidence-backed assessment |
| --- | --- | --- |
| 1. A is irreversible before exact B is known | **Fail** | Successful Create allocates capacity and controller-selects NSID before the user process necessarily receives it, but explicit Delete reverses that allocation. The late knowledge is a lost-completion problem: allocated NSIDs are queryable, while the standard supplies no caller token for exact matching under concurrent creates. |
| 2. A and B have distinct authoritative atomicity domains | **Fail for the proposed comparison** | Controller state and Linux block publication recover separately, but NSID/NID plus the controller's explicit Attach operation form one provider-native authority chain rather than two uncoordinated allocators. |
| 3. Executor replacement races B admission and successor reuse | **Fail** | Before Attach, the created namespace is inactive for I/O. Replacement faces an orphan-capacity decision; no escaped block/DMA effect can still target a successor-reused B resource in the proposed sequence. |
| 4. Exact predeclaration is unavailable and wildcard is costly | **Partial, insufficient** | The host cannot choose NSID and Create consumes capacity, but it can serialize this administrative operation and withhold Attach instead of reserving all NSIDs or devices. |
| 5. B has a real first-observation gate | **Pass** | Attach plus Linux readiness/identity validation and `device_add_disk` publication precede ordinary block I/O. |

NVMe therefore does not advance to Gate 1. A pilot here would primarily compare
CSER against a serialized namespace-management daemon that records the
allocated-NSID set, issues Create, reconciles a lost completion, records the
stable NID, and only then issues Attach. That is a useful baseline design, but
not yet a workload demonstrating the missing executor/effect custody boundary.

### NVMe pilot abstraction mapping

| Pilot concept | NVMe analogue |
| --- | --- |
| Root identity | external management intent; no standard Create operation token |
| A retained record | controller's allocated but unattached namespace |
| Late route fact | controller-selected NSID returned in Create completion |
| Exact durable identity | NSID plus controller-assigned NGUID, EUI64 or Namespace UUID |
| B durable claim | host-side decision authorizing Attach for that exact identity |
| First-observation gate | Namespace Attachment followed by Linux namespace scan and block-device publication |
| Provider/admission gate | controller validates NSID and attachment; Linux validates readiness and stable NID before publishing the disk |
| Quiescence/cleanup | stop/remove host I/O path, Detach, then explicit Delete after reconciliation |
| Failure residue | allocated unattached capacity whose owning Create intent may be ambiguous |

## Candidate 2: Kubernetes Job plus DRA accelerator placement

### Candidate and interpretation boundary

The candidate is a Kubernetes `batch/v1 Job` whose Pod requests an accelerator
through a `resource.k8s.io/v1 ResourceClaim` or ResourceClaimTemplate:

1. a client creates the Job;
2. the Job controller creates a Pod;
3. the scheduler chooses an eligible node and exact DRA device;
4. the scheduler persists the allocation and reservation in ResourceClaim
   status;
5. kubelet and the DRA driver prepare the selected device; and
6. only then does the consuming container start and first observe the device.

"Durable" below means represented by a persisted Kubernetes API object. It
does not assert physical power-loss durability: Kubernetes documents API
objects as persistent entities and stores serialized API state in etcd, but
the guarantees of a particular etcd deployment are outside this card.

### Authoritative facts

The following are direct facts from upstream Kubernetes or Kubernetes SIG
documentation, current as reviewed on 2026-08-10.

#### Job acceptance persists intent, not completed external work

- Kubernetes objects are persistent "records of intent" whose `spec` is
  desired state and whose `status` is current state. Kubernetes stores API
  resources in etcd. [Kubernetes objects](https://kubernetes.io/docs/concepts/overview/working-with-objects/),
  [API persistence](https://kubernetes.io/docs/reference/using-api/)
- A Job creates one or more Pods and retries them until the requested
  completions succeed. The Job object can exist before any Pod runs, and a
  suspended Job has no active Pods. [Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/)
- Kubernetes controllers reconcile persisted desired state through the API
  server; if a built-in controller fails, another control-plane instance can
  take over. The Job controller does not execute the task itself.
  [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/)

#### The exact node and device are late-bound

- A ResourceClaim describes device requirements; its immutable spec can name a
  DeviceClass and selectors without naming an exact device. ResourceClaim
  status records whether allocation succeeded and which resources were
  allocated. [ResourceClaim API](https://kubernetes.io/docs/reference/kubernetes-api/resource/resource-claim-v1/)
- Drivers publish device pools through ResourceSlices. The scheduler filters
  available devices, updates the ResourceClaim with allocation details and
  only then places the Pod on a node that can access the allocation.
  [DRA workflow](https://kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation/)
- The exact allocated coordinate is a tuple including driver, pool, device and,
  where applicable, share ID. The allocation also carries a node selector.
  [ResourceClaim allocation result](https://kubernetes.io/docs/reference/kubernetes-api/resource/resource-claim-v1/#allocationresult)
- The official DRA tutorial demonstrates the transition from a selector for
  any GPU with sufficient memory to an exact `gpu-0` allocation on one node.
  [DRA tutorial](https://kubernetes.io/docs/tutorials/cluster-management/install-use-dra/)

#### Kubernetes already owns enrollment and first observation

- `status.reservedFor` names consumers allowed to use a claim. The API contract
  states that a Pod referencing an unreserved claim will not start and that a
  claim which is in use or might be in use because it is reserved must not be
  deallocated. Concurrent schedulers race on the ResourceClaim update; only
  one update is stored and the loser requeues its Pod.
  [ResourceClaim status](https://kubernetes.io/docs/reference/kubernetes-api/resource/resource-claim-v1/#resourceclaimstatus)
- The scheduling framework's Reserve phase exists before Pod binding to avoid
  resource races; failures trigger idempotent Unreserve in reverse order.
  PreBind performs work required before a Pod is bound.
  [Scheduling framework](https://kubernetes.io/docs/concepts/scheduling-eviction/scheduling-framework/)
- kubelet calls the DRA driver's `NodePrepareResources` and
  `NodeUnprepareResources` operations for claims. Kubernetes recommends that
  the driver remain available through cleanup because it is responsible for
  unpreparing allocated devices.
  [DRA administration](https://kubernetes.io/docs/concepts/cluster-administration/dra/)
- Device binding conditions can hold a Pod in the scheduler's PreBind phase
  until an external controller reports that an allocated device is prepared;
  failure or timeout aborts binding and permits rescheduling.
  [DRA device binding conditions](https://kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation/#device-binding-conditions)
- The official tutorial shows `resource.kubernetes.io/delete-protection`, the
  exact allocation and `reservedFor` consumer in one ResourceClaim. On Pod
  deletion, the driver unprepares the device before the claim returns to a
  pending state.
  [DRA allocation and cleanup walkthrough](https://kubernetes.io/docs/tutorials/cluster-management/install-use-dra/#explore-the-dra-state)

#### Mature coordinators already compose the same placement boundary

- Kueue keeps Jobs suspended while it reserves quota and completes optional
  admission checks; admission means Pods may be created only after quota,
  physical topology when enabled, and admission checks permit it.
  [Kueue concepts](https://kueue.sigs.k8s.io/docs/concepts/),
  [Kueue admission](https://kueue.sigs.k8s.io/docs/concepts/admission/)
- Kueue deliberately delegates Pod placement, autoscaling and Job lifecycle to
  Kubernetes components instead of replacing them. Its ResourceFlavor is a
  class or policy choice; kube-scheduler and DRA still choose concrete nodes
  and devices. [Kueue overview](https://kueue.sigs.k8s.io/docs/overview/)
- Slurm exhibits the same mature pattern outside Kubernetes: `slurmctld`
  persists controller state and allocates nodes late; prolog runs before user
  work, GRES plus cgroups restricts access to allocated device files, and a
  node in `COMPLETING` is unavailable until processes and epilog cleanup have
  finished. [Slurm controller recovery](https://slurm.schedmd.com/quickstart_admin.html),
  [prolog and epilog](https://slurm.schedmd.com/prolog_epilog.html),
  [GRES enforcement](https://slurm.schedmd.com/gres.conf.html),
  [node states](https://slurm.schedmd.com/sinfo.html)

### Inferences from those facts

The following are analytical inferences, not statements made by the upstream
projects.

1. **Job creation is too early to be A's irreversible fact.** It creates a
   durable request which may still be suspended or deleted before any task
   executes. Treating API acceptance itself as irreversibility would make any
   durable queue insertion satisfy condition 1 and would erase the distinction
   Gate 0 was meant to test.
2. **Treating first task execution as A does not repair the candidate.** For a
   single Job/Pod, the ResourceClaim allocation and exact device identity are
   established before that execution. A is therefore no longer earlier than
   B.
3. **The processes are distributed, but the relevant authority is
   coordinated.** Job controller, scheduler, kubelet and driver have separate
   failure domains, yet allocation and consumer reservation converge through
   persisted API objects. The provider's node-local prepare/unprepare state is
   downstream of that recorded allocation.
4. **A broad DeviceClass request is not wildcard reservation.** It names a set
   of acceptable candidates, but the scheduler reserves one selected
   allocation. Thus it avoids both exact predeclaration and the proposed
   `2/8/32` reserve-all cost.
5. **Submitter death is not executor revocation.** Once the Job exists, the
   control plane continues reconciliation. A replacement client does not gain
   authority to reuse the allocated GPU merely because the submitting process
   exited.
6. **Kubernetes DRA is already the strongest coordinator baseline.** Its
   ResourceClaim allocation, `reservedFor`, scheduler Reserve/Unreserve,
   PreBind and driver prepare/unprepare together implement late enrollment and
   guarded first observation for this workload. Reimplementing the same
   workload below Kubernetes would test a second coordinator against an
   existing one, not expose an uncovered custody gap.

### Kubernetes Gate 0 criteria

| Criterion | Result | Evidence-backed assessment |
| --- | --- | --- |
| 1. A is irreversible before exact B is known | **Fail** | Job acceptance is persistent desired state, but no task need have run. If A is moved to first task execution, DRA has already allocated B. |
| 2. A and B have distinct authoritative atomicity domains | **Fail for the proposed comparison** | Components fail independently, but the relevant allocation and consumer permission are coordinated in ResourceClaim status stored through the API server. |
| 3. Executor replacement races B admission and successor reuse | **Fail** | Submitter/controller replacement does not revoke the persisted Job. ResourceClaim reservation and delete protection, not executor liveness, govern use and cleanup. |
| 4. Exact predeclaration is unavailable and wildcard is costly | **Fail** | Exact device identity is late, but DRA selects and reserves one matching device; it need not reserve all candidates. |
| 5. B has a real first-observation gate | **Pass** | Unallocated or unreserved claims do not start Pods; Reserve/PreBind and device preparation precede container observation. |

Passing only condition 5 is insufficient. This candidate must not advance to
the CSER G1 portable pilot as a claimed real workload.

### Kubernetes pilot abstraction mapping

Although rejected as the target, Kubernetes DRA provides a useful upper-bound
baseline model for Gate 1:

| Pilot concept | Kubernetes/DRA analogue |
| --- | --- |
| Root identity | Job UID, optionally mediated by a Kueue Workload UID |
| A retained record | Persisted Job/Workload desired state before admission |
| Late route fact | ResourceClaim `status.allocation` |
| Exact B identity | Pod UID plus `(driver, pool, device, shareID)` and node selector |
| B durable claim | ResourceClaim allocation plus `status.reservedFor` |
| First-observation gate | scheduler Reserve/PreBind, then kubelet/driver prepare before container start |
| Provider/admission gate | exact allocation and consumer reservation checked by scheduler/kubelet; node-local device access configured by the driver; no generic hardware generation fence inferred |
| Quiescence/cleanup | Pod termination followed by driver unprepare and allocation release |
| Successor conflict | another Pod attempting to reserve or allocate the same exclusive device |

A fair workload-specific coordinator arm in the portable pilot should be
allowed the semantic equivalents of ResourceClaim allocation, optimistic
consumer reservation, idempotent unreserve, readiness gating and provider
prepare/unprepare. If that arm passes, shared durable coordination by itself
must not be relabeled CSER.

### Why a small variation does not rescue the candidate

Adding an asynchronous planner in front of the Job does not establish Gate 0
without another real external fact. If the planner merely persists a plan and
then creates a ResourceClaim, its output remains reversible desired state. If
the planner first performs an irreversible remote action, that remote action,
its recoverable identity and its relation to the later accelerator allocation
must be documented by the real provider; hiding a route in the harness is not
enough.

Likewise, using Kueue does not create the missing gap. Kueue strengthens the
counterexample by explicitly reserving quota and holding the Job before start,
then delegating exact placement to kube-scheduler and DRA.

## Approved alternative after No-Go

Do not implement a synthetic Kubernetes G1 graph. Pivot to the already
approved endpoint-applicability and missing-evidence retention study:

1. classify observed endpoint operations by whether outcome evidence is
   recoverable after executor loss and whether any locally governed resource
   needs independent quiescence evidence;
2. exercise the endpoint Store and current CSER2 path with pending,
   unavailable and expired outcome states at the layers they actually expose,
   plus delayed or withheld DMA quiescence;
3. in controlled scenarios, report terminal versus non-evidence endpoint
   state, component-local retirement, live claims, credit-unit-revisions and
   allocator-gate decisions at a bounded observation horizon; and
4. obtain a real operation trace before reporting workload prevalence,
   resource-seconds, permanent-retain proportion or administrative-disposition
   proportion. A scenario matrix cannot manufacture those rates.

This pivot answers the more fundamental question raised by the negative card:
whether real escaped effects frequently leave any resource whose safe reuse is
not already governed by an endpoint, scheduler or provider coordinator.

## Evidence required to reopen Gate 0

Reconsider a late-bound workload only when one primary provider specification
or captured production trace establishes all of the following:

- A's accepted operation has already caused an irreversible external action,
  charge, publication or independently running job;
- the exact B worker/device/resource coordinate is returned only afterward;
- A's recovery record and B's allocation authority do not already converge in
  a scheduler, lease service, workflow database or provider coordinator;
- replacing A's executor can race B's first publication and reuse of the exact
  resource;
- B exposes an enforceable pre-publication gate; and
- pre-reserving all B candidates has a measured availability or retention
  cost.

Until such evidence exists, Kubernetes Job/DRA and Slurm should be treated as
counterexamples showing that mature systems solve late accelerator placement
by durable workload-specific coordination. NVMe Namespace Management should be
treated as a counterexample showing that controller-assigned late identity can
be paired with an inert pre-attachment state, discoverable inventory and
stable provider identity. None is currently a workload demonstrating a missing
CSER boundary.
