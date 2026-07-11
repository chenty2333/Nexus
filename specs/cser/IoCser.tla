------------------------------ MODULE IoCser ------------------------------
EXTENDS FiniteSets, Integers, TLC

(***************************************************************************)
(* A finite-state successor model of CSER for one mediated split VirtIO   *)
(* block queue.  The scope exclusively owns the queue and device.          *)
(*                                                                         *)
(* The PlusCal algorithm is the source of Init/Next.  PublishAvail is the  *)
(* request commit linearization point: it models the Release publication   *)
(* of avail.idx.  Notify is only a later hint because a polling device may  *)
(* consume the descriptor immediately after avail.idx becomes visible.     *)
(***************************************************************************)

CONSTANTS
    Requests,
    Scope,
    Queue,
    Device,
    TotalLeaseCredits,
    InitialCommitCharges,
    MaxBinding,
    MaxDeviceGeneration,
    MaxRegisterAttempts,
    MaxPublishAttempts,
    MaxCompletionAttempts,
    MaxCleanupAttempts

ASSUME /\ IsFiniteSet(Requests)
       /\ Requests # {}
       /\ InitialCommitCharges \in Nat
       /\ InitialCommitCharges > 0
       /\ InitialCommitCharges < Cardinality(Requests)
       /\ TotalLeaseCredits = InitialCommitCharges + 1
       /\ MaxBinding \in Nat
       /\ MaxBinding > 0
       /\ MaxDeviceGeneration \in Nat
       /\ MaxDeviceGeneration > 0
       /\ MaxRegisterAttempts \in Nat
       /\ MaxRegisterAttempts > 0
       /\ MaxPublishAttempts \in Nat
       /\ MaxPublishAttempts > 0
       /\ MaxCompletionAttempts \in Nat
       /\ MaxCompletionAttempts > 1
       /\ MaxCleanupAttempts \in Nat
       /\ MaxCleanupAttempts > 1

ScopeStates == {"Active", "Closing", "Revoked"}
RequestStates == {
    "Unused", "Registered", "Prepared", "Cancelling", "Committed",
    "Completed", "Cancelled", "IndeterminateAfterReset"
}
UnpublishedStates == {"Registered", "Prepared"}
TerminalStates == {"Completed", "Cancelled", "IndeterminateAfterReset"}
DmaStates == {"Absent", "Mapped", "Invalidating", "TimedOut", "Released"}
ResetStates == {"Idle", "Required", "InFlight", "TimedOut", "Quiesced"}
ReplacementStates == {"None", "Ready", "Bound"}
FallbackStates == {"Standby", "Required", "Running"}
CommitChargeStates == {"None", "Held", "Spent", "Returned"}
PublishRejectReasons == {
    "None", "GateClosed", "Authority", "Binding", "DeviceGeneration"
}
RegisterRejectReasons == {"None", "GateClosed", "CommitBudgetExhausted"}

NoEpoch == -1
NoBinding == -1
NoDeviceGeneration == -1

RequestSymmetry == Permutations(Requests)

(* --algorithm IoCSER
variables
    scopeState = "Active",
    authorityEpoch = 0,
    closingEpoch = NoEpoch,

    serviceAlive = TRUE,
    bindingEpoch = 0,
    replacementState = "Bound",
    readyBindings = {0},
    reboundBindings = {0},
    fallbackState = "Standby",

    deviceGeneration = 0,
    resetState = "Idle",
    resetGeneration = NoDeviceGeneration,
    resetAttempt = 0,
    resetTombstone = FALSE,
    resetTimeoutSeen = FALSE,
    resetAckSeen = FALSE,

    queueDmaState = "Mapped",
    queueFrameHeld = TRUE,
    queueIovaHeld = TRUE,
    queueMappingRecordHeld = TRUE,
    queueReusable = FALSE,
    queueLeaseCredit = 1,
    queueInvalidateAttempt = 0,
    queueTombstone = FALSE,
    queueTimeoutSeen = FALSE,

    requestState = [r \in Requests |-> "Unused"],
    requestAuthority = [r \in Requests |-> NoEpoch],
    requestBinding = [r \in Requests |-> NoBinding],
    requestDeviceGeneration =
        [r \in Requests |-> NoDeviceGeneration],

    requestDmaState = [r \in Requests |-> "Absent"],
    requestFrameHeld = [r \in Requests |-> FALSE],
    requestIovaHeld = [r \in Requests |-> FALSE],
    requestMappingRecordHeld = [r \in Requests |-> FALSE],
    requestReusable = [r \in Requests |-> TRUE],
    requestLeaseCredit = [r \in Requests |-> 0],
    requestInvalidateAttempt = [r \in Requests |-> 0],
    requestTombstone = [r \in Requests |-> FALSE],
    requestTimeoutSeen = [r \in Requests |-> FALSE],

    freeLeaseCredits = TotalLeaseCredits - 1,
    freeCommitCharges = InitialCommitCharges,
    commitChargeState = [r \in Requests |-> "None"],
    registerAttemptCount = [r \in Requests |-> 0],
    registerAcceptCount = [r \in Requests |-> 0],
    registerRejectCount = [r \in Requests |-> 0],
    lastRegisterRejectReason = [r \in Requests |-> "None"],
    budgetOnlyRejectSeen = [r \in Requests |-> FALSE],
    queueSlotOwned = [r \in Requests |-> FALSE],
    prepareSeen = [r \in Requests |-> FALSE],
    publishSeen = [r \in Requests |-> FALSE],
    publishAuthority = [r \in Requests |-> NoEpoch],
    publishBinding = [r \in Requests |-> NoBinding],
    publishDeviceGeneration =
        [r \in Requests |-> NoDeviceGeneration],
    publicationCount = [r \in Requests |-> 0],
    publishAttemptCount = [r \in Requests |-> 0],
    publishAcceptCount = [r \in Requests |-> 0],
    publishRejectCount = [r \in Requests |-> 0],
    lastPublishRejectReason = [r \in Requests |-> "None"],
    oldBindingOnlyRejectSeen = [r \in Requests |-> FALSE],
    notified = [r \in Requests |-> FALSE],

    completionAttemptCount = [r \in Requests |-> 0],
    completionAcceptCount = [r \in Requests |-> 0],
    completionRejectCount = [r \in Requests |-> 0],
    completionAcceptedGeneration =
        [r \in Requests |-> NoDeviceGeneration],
    terminalCount = [r \in Requests |-> 0],
    adoptCount = [r \in Requests |-> 0],

    publishedAtClose = {},
    adoptCountAtClose = [r \in Requests |-> 0],
    publishedAtLastCrash = {},
    lastCrashBinding = 0;

process IOEnvironment = "io-environment"
begin
EnvironmentLoop:
    while TRUE do
        either
            \* RegisterAccept(r): a bounded RegisterAttempt reserves one
            \* nonrenewable commit charge and captures the complete token.
            with r \in Requests do
                await /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ bindingEpoch \in reboundBindings
                      /\ requestState[r] = "Unused"
                      /\ registerAttemptCount[r] < MaxRegisterAttempts
                      /\ freeCommitCharges > 0;
                registerAttemptCount[r] := registerAttemptCount[r] + 1;
                registerAcceptCount[r] := registerAcceptCount[r] + 1;
                requestState[r] := "Registered";
                requestAuthority[r] := authorityEpoch;
                requestBinding[r] := bindingEpoch;
                requestDeviceGeneration[r] := deviceGeneration;
                commitChargeState[r] := "Held";
                freeCommitCharges := freeCommitCharges - 1;
            end with;
        or
            \* RegisterReject(r): the attempt remains enabled when the gate
            \* is closed or commit capacity is exhausted.  Only bounded audit
            \* history changes; the request token and both ledgers do not.
            with r \in Requests do
                await /\ requestState[r] = "Unused"
                      /\ registerAttemptCount[r] < MaxRegisterAttempts
                      /\ (\/ scopeState # "Active"
                          \/ ~serviceAlive
                          \/ replacementState # "Bound"
                          \/ bindingEpoch \notin reboundBindings
                          \/ freeCommitCharges = 0);
                registerAttemptCount[r] := registerAttemptCount[r] + 1;
                registerRejectCount[r] := registerRejectCount[r] + 1;
                if /\ scopeState = "Active"
                   /\ serviceAlive
                   /\ replacementState = "Bound"
                   /\ bindingEpoch \in reboundBindings
                   /\ freeCommitCharges = 0 then
                    lastRegisterRejectReason[r] :=
                        "CommitBudgetExhausted";
                    budgetOnlyRejectSeen[r] := TRUE;
                else
                    lastRegisterRejectReason[r] := "GateClosed";
                end if;
            end with;
        or
            \* Prepare(r): create the descriptor and DMA lease, but do not
            \* publish it to the device.  A prepared request is cancellable.
            with r \in Requests do
                await /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ bindingEpoch \in reboundBindings
                      /\ requestState[r] = "Registered"
                      /\ requestAuthority[r] = authorityEpoch
                      /\ requestBinding[r] = bindingEpoch
                      /\ requestDeviceGeneration[r] = deviceGeneration
                      /\ freeLeaseCredits > 0;
                requestState[r] := "Prepared";
                requestDmaState[r] := "Mapped";
                requestFrameHeld[r] := TRUE;
                requestIovaHeld[r] := TRUE;
                requestMappingRecordHeld[r] := TRUE;
                requestReusable[r] := FALSE;
                requestLeaseCredit[r] := 1;
                freeLeaseCredits := freeLeaseCredits - 1;
                queueSlotOwned[r] := TRUE;
                prepareSeen[r] := TRUE;
            end with;
        or
            \* PublishAccept(r, token): only an exact current full token can
            \* perform the avail.idx Release publication.
            with r \in Requests,
                 presentedAuthority \in 0..1,
                 presentedBinding \in 0..MaxBinding,
                 presentedDeviceGeneration
                     \in 0..MaxDeviceGeneration do
                await /\ requestState[r] = "Prepared"
                      /\ publishAttemptCount[r] < MaxPublishAttempts
                      /\ publishAcceptCount[r] = 0
                      /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ bindingEpoch \in reboundBindings
                      /\ requestDmaState[r] = "Mapped"
                      /\ queueSlotOwned[r]
                      /\ commitChargeState[r] = "Held"
                      /\ presentedAuthority = requestAuthority[r]
                      /\ requestAuthority[r] = authorityEpoch
                      /\ presentedBinding = requestBinding[r]
                      /\ requestBinding[r] = bindingEpoch
                      /\ presentedDeviceGeneration
                            = requestDeviceGeneration[r]
                      /\ requestDeviceGeneration[r] = deviceGeneration;
                publishAttemptCount[r] := publishAttemptCount[r] + 1;
                requestState[r] := "Committed";
                commitChargeState[r] := "Spent";
                publishSeen[r] := TRUE;
                publishAuthority[r] := presentedAuthority;
                publishBinding[r] := bindingEpoch;
                publishDeviceGeneration[r] :=
                    presentedDeviceGeneration;
                publicationCount[r] := publicationCount[r] + 1;
                publishAcceptCount[r] := publishAcceptCount[r] + 1;
            end with;
        or
            \* PublishReject(r, token): every invalid full-token attempt is
            \* accepted until the one-entry rejection history is full.  Only
            \* bounded audit fields change; semantic state is untouched.
            with r \in Requests,
                 presentedAuthority \in 0..1,
                 presentedBinding \in 0..MaxBinding,
                 presentedDeviceGeneration
                     \in 0..MaxDeviceGeneration do
                await /\ requestState[r] = "Prepared"
                      /\ publishAttemptCount[r] < MaxPublishAttempts
                      /\ publishRejectCount[r] = 0
                      /\ ~( /\ scopeState = "Active"
                            /\ serviceAlive
                            /\ replacementState = "Bound"
                            /\ bindingEpoch \in reboundBindings
                            /\ requestDmaState[r] = "Mapped"
                            /\ queueSlotOwned[r]
                            /\ commitChargeState[r] = "Held"
                            /\ presentedAuthority = requestAuthority[r]
                            /\ requestAuthority[r] = authorityEpoch
                            /\ presentedBinding = requestBinding[r]
                            /\ requestBinding[r] = bindingEpoch
                            /\ presentedDeviceGeneration
                                  = requestDeviceGeneration[r]
                            /\ requestDeviceGeneration[r]
                                  = deviceGeneration );
                publishAttemptCount[r] := publishAttemptCount[r] + 1;
                publishRejectCount[r] := publishRejectCount[r] + 1;
                if /\ adoptCount[r] > 0
                   /\ scopeState = "Active"
                   /\ serviceAlive
                   /\ replacementState = "Bound"
                   /\ bindingEpoch \in reboundBindings
                   /\ requestDmaState[r] = "Mapped"
                   /\ queueSlotOwned[r]
                   /\ commitChargeState[r] = "Held"
                   /\ presentedAuthority = requestAuthority[r]
                   /\ requestAuthority[r] = authorityEpoch
                   /\ presentedBinding < requestBinding[r]
                   /\ requestBinding[r] = bindingEpoch
                   /\ presentedDeviceGeneration
                         = requestDeviceGeneration[r]
                   /\ requestDeviceGeneration[r]
                         = deviceGeneration then
                    oldBindingOnlyRejectSeen[r] := TRUE;
                end if;
                if \/ scopeState # "Active"
                   \/ ~serviceAlive
                   \/ replacementState # "Bound"
                   \/ bindingEpoch \notin reboundBindings
                   \/ requestDmaState[r] # "Mapped"
                   \/ ~queueSlotOwned[r]
                   \/ commitChargeState[r] # "Held" then
                    lastPublishRejectReason[r] := "GateClosed";
                elsif \/ presentedAuthority # requestAuthority[r]
                      \/ requestAuthority[r] # authorityEpoch then
                    lastPublishRejectReason[r] := "Authority";
                elsif \/ presentedBinding # requestBinding[r]
                      \/ requestBinding[r] # bindingEpoch then
                    lastPublishRejectReason[r] := "Binding";
                else
                    lastPublishRejectReason[r] := "DeviceGeneration";
                end if;
            end with;
        or
            \* Notify(r): only a post-publication hint.  Polling hardware can
            \* complete a request even if this action never occurs.
            with r \in Requests do
                await /\ scopeState = "Active"
                      /\ requestState[r] = "Committed"
                      /\ publishSeen[r]
                      /\ ~notified[r];
                notified[r] := TRUE;
            end with;
        or
            \* CompletionAttempt(r, generation): a valid current-generation
            \* completion and ResetAck are atomic competitors.  An old-
            \* generation or duplicate attempt is counted as rejected and
            \* cannot change the request's terminal outcome.
            with r \in Requests,
                 generation \in 0..MaxDeviceGeneration do
                await /\ scopeState # "Revoked"
                      /\ publishSeen[r]
                      /\ completionAttemptCount[r]
                            < MaxCompletionAttempts;
                completionAttemptCount[r] :=
                    completionAttemptCount[r] + 1;
                if /\ requestState[r] = "Committed"
                   /\ requestDeviceGeneration[r] = generation
                   /\ deviceGeneration = generation then
                    requestState[r] := "Completed";
                    queueSlotOwned[r] := FALSE;
                    completionAcceptCount[r] :=
                        completionAcceptCount[r] + 1;
                    completionAcceptedGeneration[r] := generation;
                    terminalCount[r] := terminalCount[r] + 1;
                else
                    completionRejectCount[r] :=
                        completionRejectCount[r] + 1;
                end if;
            end with;
        or
            \* Crash: only the service binding generation advances.  The
            \* authority and device generations remain unchanged, and every
            \* committed request stays kernel/device-owned.
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ bindingEpoch < MaxBinding;
            publishedAtLastCrash :=
                {r \in Requests : publishSeen[r]};
            lastCrashBinding := bindingEpoch + 1;
            bindingEpoch := bindingEpoch + 1;
            serviceAlive := FALSE;
            replacementState := "None";
            fallbackState := "Required";
        or
            \* Ready/Rebind install a replacement endpoint after the kernel
            \* fallback is running.  Neither action advances a generation.
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "None";
            replacementState := "Ready";
            readyBindings := readyBindings \cup {bindingEpoch};
        or
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "Ready"
                  /\ bindingEpoch \in readyBindings;
            serviceAlive := TRUE;
            replacementState := "Bound";
            reboundBindings := reboundBindings \cup {bindingEpoch};
            fallbackState := "Standby";
        or
            \* Adopt(r): only Registered/Prepared work can transfer to the
            \* replacement binding.  Committed work is never adopted.
            with r \in Requests do
                await /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ bindingEpoch \in reboundBindings
                      /\ requestState[r] \in UnpublishedStates
                      /\ requestAuthority[r] = authorityEpoch
                      /\ requestBinding[r] # bindingEpoch;
                requestBinding[r] := bindingEpoch;
                adoptCount[r] := adoptCount[r] + 1;
            end with;
        or
            \* RevokeBegin: close the old authority gate and stop accepting
            \* submissions.  Even an empty queue needs whole-device reset
            \* before the queue DMA lease can be invalidated.
            await scopeState = "Active";
            publishedAtClose := {r \in Requests : publishSeen[r]};
            adoptCountAtClose := adoptCount;
            closingEpoch := authorityEpoch;
            authorityEpoch := authorityEpoch + 1;
            scopeState := "Closing";
            serviceAlive := FALSE;
            replacementState := "None";
            resetState := "Required";
        or
            \* Hardware reset completion.  ResetAck advances only the device
            \* generation and atomically terminalizes every still-Committed
            \* request as IndeterminateAfterReset.  It is not a rollback.
            await /\ scopeState = "Closing"
                  /\ resetState = "InFlight"
                  /\ resetGeneration = deviceGeneration
                  /\ deviceGeneration < MaxDeviceGeneration;
            queueSlotOwned :=
                [r \in Requests |->
                    IF requestState[r] = "Committed"
                    THEN FALSE
                    ELSE queueSlotOwned[r]];
            terminalCount :=
                [r \in Requests |->
                    IF requestState[r] = "Committed"
                    THEN terminalCount[r] + 1
                    ELSE terminalCount[r]];
            requestState :=
                [r \in Requests |->
                    IF requestState[r] = "Committed"
                    THEN "IndeterminateAfterReset"
                    ELSE requestState[r]];
            deviceGeneration := deviceGeneration + 1;
            resetState := "Quiesced";
            resetTombstone := FALSE;
            resetAckSeen := TRUE;
        or
            \* A reset timeout is honest: nothing is terminalized or freed.
            \* The queue and every still device-visible request remain held.
            await /\ scopeState = "Closing"
                  /\ resetState = "InFlight";
            resetState := "TimedOut";
            resetTombstone := TRUE;
            resetTimeoutSeen := TRUE;
        or
            \* RetryReset is explicit and bounded.  No fairness assumption
            \* says that it, ResetAck, or any hardware response must occur.
            await /\ scopeState = "Closing"
                  /\ resetState = "TimedOut"
                  /\ resetAttempt < MaxCleanupAttempts;
            resetState := "Required";
        or
            \* A matching request IOTLB completion is the only action that
            \* releases its frame, IOVA, mapping record, and credit.  A
            \* pre-commit cancellation becomes terminal only here.
            with r \in Requests do
                await requestDmaState[r] = "Invalidating";
                requestDmaState[r] := "Released";
                requestFrameHeld[r] := FALSE;
                requestIovaHeld[r] := FALSE;
                requestMappingRecordHeld[r] := FALSE;
                requestReusable[r] := TRUE;
                requestLeaseCredit[r] := 0;
                requestTombstone[r] := FALSE;
                freeLeaseCredits := freeLeaseCredits + 1;
                if requestState[r] = "Cancelling" then
                    requestState[r] := "Cancelled";
                    terminalCount[r] := terminalCount[r] + 1;
                end if;
            end with;
        or
            with r \in Requests do
                await requestDmaState[r] = "Invalidating";
                requestDmaState[r] := "TimedOut";
                requestTombstone[r] := TRUE;
                requestTimeoutSeen[r] := TRUE;
            end with;
        or
            \* RetryInvalidate retains the tombstone resources and merely
            \* issues a fresh bounded invalidation attempt.
            with r \in Requests do
                await /\ requestDmaState[r] = "TimedOut"
                      /\ requestInvalidateAttempt[r]
                            < MaxCleanupAttempts;
                requestDmaState[r] := "Invalidating";
                requestInvalidateAttempt[r] :=
                    requestInvalidateAttempt[r] + 1;
            end with;
        or
            \* Queue IOTLB completion is legal only after ResetAck made the
            \* whole device quiescent.
            await /\ queueDmaState = "Invalidating"
                  /\ resetState = "Quiesced";
            queueDmaState := "Released";
            queueFrameHeld := FALSE;
            queueIovaHeld := FALSE;
            queueMappingRecordHeld := FALSE;
            queueReusable := TRUE;
            queueLeaseCredit := 0;
            queueTombstone := FALSE;
            freeLeaseCredits := freeLeaseCredits + 1;
        or
            await /\ queueDmaState = "Invalidating"
                  /\ resetState = "Quiesced";
            queueDmaState := "TimedOut";
            queueTombstone := TRUE;
            queueTimeoutSeen := TRUE;
        or
            await /\ queueDmaState = "TimedOut"
                  /\ queueInvalidateAttempt < MaxCleanupAttempts;
            queueDmaState := "Invalidating";
            queueInvalidateAttempt := queueInvalidateAttempt + 1;
        end either;
    end while;
end process;

\* The only unconditional liveness dependency from service crash is the
\* kernel scheduler fallback.  No user-space recovery action is fair.
fair process KernelFallback = "kernel-fallback"
begin
FallbackLoop:
    while TRUE do
        await fallbackState = "Required";
        fallbackState := "Running";
    end while;
end process;

\* Kernel cancellation is fair.  Registered work can terminalize directly;
\* Prepared work first becomes Cancelling and must still receive a real
\* synchronous IOTLB completion before becoming Cancelled.
fair process KernelCancel = "kernel-cancel"
begin
CancelLoop:
    while TRUE do
        with r \in Requests do
            await /\ scopeState = "Closing"
                  /\ requestAuthority[r] = closingEpoch
                  /\ requestState[r] \in UnpublishedStates;
            if requestState[r] = "Registered" then
                requestState[r] := "Cancelled";
                commitChargeState[r] := "Returned";
                freeCommitCharges := freeCommitCharges + 1;
                terminalCount[r] := terminalCount[r] + 1;
            else
                requestState[r] := "Cancelling";
                commitChargeState[r] := "Returned";
                freeCommitCharges := freeCommitCharges + 1;
                queueSlotOwned[r] := FALSE;
            end if;
        end with;
    end while;
end process;

\* Starting reset is kernel-owned and fair once requested.  The acknowledgement
\* and timeout choice remain unfair hardware/environment transitions.
fair process KernelResetDriver = "kernel-reset-driver"
begin
ResetLoop:
    while TRUE do
        await /\ scopeState = "Closing"
              /\ resetState = "Required"
              /\ resetAttempt < MaxCleanupAttempts;
        resetState := "InFlight";
        resetGeneration := deviceGeneration;
        resetAttempt := resetAttempt + 1;
    end while;
end process;

\* Safe request leases are independent: unpublished Cancelling work and a
\* DeviceComplete request need no device reset.  Indeterminate work is safe
\* only because ResetAck has already quiesced the whole device.  Queue DMA
\* always waits for that same ResetAck.
fair process KernelInvalidateDriver = "kernel-invalidate-driver"
begin
InvalidateLoop:
    while TRUE do
        either
            with r \in Requests do
                await /\ requestDmaState[r] = "Mapped"
                      /\ requestInvalidateAttempt[r]
                            < MaxCleanupAttempts
                      /\ (\/ requestState[r] = "Cancelling"
                          \/ requestState[r] = "Completed"
                          \/ /\ requestState[r]
                                    = "IndeterminateAfterReset"
                             /\ resetState = "Quiesced");
                requestDmaState[r] := "Invalidating";
                requestInvalidateAttempt[r] :=
                    requestInvalidateAttempt[r] + 1;
            end with;
        or
            await /\ scopeState = "Closing"
                  /\ resetState = "Quiesced"
                  /\ queueDmaState = "Mapped"
                  /\ queueInvalidateAttempt < MaxCleanupAttempts
                  /\ \A r \in Requests : ~queueSlotOwned[r];
            queueDmaState := "Invalidating";
            queueInvalidateAttempt := queueInvalidateAttempt + 1;
        end either;
    end while;
end process;

\* Once every hardware-dependent obligation has actually acknowledged, the
\* final kernel publication is fair.  This is deliberately conditional and
\* does not imply that a timeout tombstone eventually disappears.
fair process KernelFinalizer = "kernel-finalizer"
begin
FinalizeLoop:
    while TRUE do
        await /\ scopeState = "Closing"
              /\ resetState = "Quiesced"
              /\ queueDmaState = "Released"
              /\ queueLeaseCredit = 0
              /\ ~queueTombstone
              /\ \A r \in Requests :
                     requestAuthority[r] = closingEpoch
                     => /\ requestState[r] \in TerminalStates
                        /\ requestDmaState[r]
                              \in {"Absent", "Released"}
                        /\ requestLeaseCredit[r] = 0
                        /\ ~requestTombstone[r]
              /\ \A r \in Requests : commitChargeState[r] # "Held"
              /\ \A r \in Requests : ~queueSlotOwned[r];
        scopeState := "Revoked";
    end while;
end process;
end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "3cbfb5a2" /\ chksum(tla) = "8bef3781")
VARIABLES scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetGeneration, resetAttempt, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding

vars == << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetGeneration, resetAttempt, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding >>

ProcSet == {"io-environment"} \cup {"kernel-fallback"} \cup {"kernel-cancel"} \cup {"kernel-reset-driver"} \cup {"kernel-invalidate-driver"} \cup {"kernel-finalizer"}

Init == (* Global variables *)
        /\ scopeState = "Active"
        /\ authorityEpoch = 0
        /\ closingEpoch = NoEpoch
        /\ serviceAlive = TRUE
        /\ bindingEpoch = 0
        /\ replacementState = "Bound"
        /\ readyBindings = {0}
        /\ reboundBindings = {0}
        /\ fallbackState = "Standby"
        /\ deviceGeneration = 0
        /\ resetState = "Idle"
        /\ resetGeneration = NoDeviceGeneration
        /\ resetAttempt = 0
        /\ resetTombstone = FALSE
        /\ resetTimeoutSeen = FALSE
        /\ resetAckSeen = FALSE
        /\ queueDmaState = "Mapped"
        /\ queueFrameHeld = TRUE
        /\ queueIovaHeld = TRUE
        /\ queueMappingRecordHeld = TRUE
        /\ queueReusable = FALSE
        /\ queueLeaseCredit = 1
        /\ queueInvalidateAttempt = 0
        /\ queueTombstone = FALSE
        /\ queueTimeoutSeen = FALSE
        /\ requestState = [r \in Requests |-> "Unused"]
        /\ requestAuthority = [r \in Requests |-> NoEpoch]
        /\ requestBinding = [r \in Requests |-> NoBinding]
        /\ requestDeviceGeneration = [r \in Requests |-> NoDeviceGeneration]
        /\ requestDmaState = [r \in Requests |-> "Absent"]
        /\ requestFrameHeld = [r \in Requests |-> FALSE]
        /\ requestIovaHeld = [r \in Requests |-> FALSE]
        /\ requestMappingRecordHeld = [r \in Requests |-> FALSE]
        /\ requestReusable = [r \in Requests |-> TRUE]
        /\ requestLeaseCredit = [r \in Requests |-> 0]
        /\ requestInvalidateAttempt = [r \in Requests |-> 0]
        /\ requestTombstone = [r \in Requests |-> FALSE]
        /\ requestTimeoutSeen = [r \in Requests |-> FALSE]
        /\ freeLeaseCredits = TotalLeaseCredits - 1
        /\ freeCommitCharges = InitialCommitCharges
        /\ commitChargeState = [r \in Requests |-> "None"]
        /\ registerAttemptCount = [r \in Requests |-> 0]
        /\ registerAcceptCount = [r \in Requests |-> 0]
        /\ registerRejectCount = [r \in Requests |-> 0]
        /\ lastRegisterRejectReason = [r \in Requests |-> "None"]
        /\ budgetOnlyRejectSeen = [r \in Requests |-> FALSE]
        /\ queueSlotOwned = [r \in Requests |-> FALSE]
        /\ prepareSeen = [r \in Requests |-> FALSE]
        /\ publishSeen = [r \in Requests |-> FALSE]
        /\ publishAuthority = [r \in Requests |-> NoEpoch]
        /\ publishBinding = [r \in Requests |-> NoBinding]
        /\ publishDeviceGeneration = [r \in Requests |-> NoDeviceGeneration]
        /\ publicationCount = [r \in Requests |-> 0]
        /\ publishAttemptCount = [r \in Requests |-> 0]
        /\ publishAcceptCount = [r \in Requests |-> 0]
        /\ publishRejectCount = [r \in Requests |-> 0]
        /\ lastPublishRejectReason = [r \in Requests |-> "None"]
        /\ oldBindingOnlyRejectSeen = [r \in Requests |-> FALSE]
        /\ notified = [r \in Requests |-> FALSE]
        /\ completionAttemptCount = [r \in Requests |-> 0]
        /\ completionAcceptCount = [r \in Requests |-> 0]
        /\ completionRejectCount = [r \in Requests |-> 0]
        /\ completionAcceptedGeneration = [r \in Requests |-> NoDeviceGeneration]
        /\ terminalCount = [r \in Requests |-> 0]
        /\ adoptCount = [r \in Requests |-> 0]
        /\ publishedAtClose = {}
        /\ adoptCountAtClose = [r \in Requests |-> 0]
        /\ publishedAtLastCrash = {}
        /\ lastCrashBinding = 0

IOEnvironment == /\ \/ /\ \E r \in Requests:
                            /\ /\ scopeState = "Active"
                               /\ serviceAlive
                               /\ replacementState = "Bound"
                               /\ bindingEpoch \in reboundBindings
                               /\ requestState[r] = "Unused"
                               /\ registerAttemptCount[r] < MaxRegisterAttempts
                               /\ freeCommitCharges > 0
                            /\ registerAttemptCount' = [registerAttemptCount EXCEPT ![r] = registerAttemptCount[r] + 1]
                            /\ registerAcceptCount' = [registerAcceptCount EXCEPT ![r] = registerAcceptCount[r] + 1]
                            /\ requestState' = [requestState EXCEPT ![r] = "Registered"]
                            /\ requestAuthority' = [requestAuthority EXCEPT ![r] = authorityEpoch]
                            /\ requestBinding' = [requestBinding EXCEPT ![r] = bindingEpoch]
                            /\ requestDeviceGeneration' = [requestDeviceGeneration EXCEPT ![r] = deviceGeneration]
                            /\ commitChargeState' = [commitChargeState EXCEPT ![r] = "Held"]
                            /\ freeCommitCharges' = freeCommitCharges - 1
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ \E r \in Requests:
                            /\ /\ requestState[r] = "Unused"
                               /\ registerAttemptCount[r] < MaxRegisterAttempts
                               /\ (\/ scopeState # "Active"
                                   \/ ~serviceAlive
                                   \/ replacementState # "Bound"
                                   \/ bindingEpoch \notin reboundBindings
                                   \/ freeCommitCharges = 0)
                            /\ registerAttemptCount' = [registerAttemptCount EXCEPT ![r] = registerAttemptCount[r] + 1]
                            /\ registerRejectCount' = [registerRejectCount EXCEPT ![r] = registerRejectCount[r] + 1]
                            /\ IF /\ scopeState = "Active"
                                  /\ serviceAlive
                                  /\ replacementState = "Bound"
                                  /\ bindingEpoch \in reboundBindings
                                  /\ freeCommitCharges = 0
                                  THEN /\ lastRegisterRejectReason' = [lastRegisterRejectReason EXCEPT ![r] = "CommitBudgetExhausted"]
                                       /\ budgetOnlyRejectSeen' = [budgetOnlyRejectSeen EXCEPT ![r] = TRUE]
                                  ELSE /\ lastRegisterRejectReason' = [lastRegisterRejectReason EXCEPT ![r] = "GateClosed"]
                                       /\ UNCHANGED budgetOnlyRejectSeen
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAcceptCount, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ \E r \in Requests:
                            /\ /\ scopeState = "Active"
                               /\ serviceAlive
                               /\ replacementState = "Bound"
                               /\ bindingEpoch \in reboundBindings
                               /\ requestState[r] = "Registered"
                               /\ requestAuthority[r] = authorityEpoch
                               /\ requestBinding[r] = bindingEpoch
                               /\ requestDeviceGeneration[r] = deviceGeneration
                               /\ freeLeaseCredits > 0
                            /\ requestState' = [requestState EXCEPT ![r] = "Prepared"]
                            /\ requestDmaState' = [requestDmaState EXCEPT ![r] = "Mapped"]
                            /\ requestFrameHeld' = [requestFrameHeld EXCEPT ![r] = TRUE]
                            /\ requestIovaHeld' = [requestIovaHeld EXCEPT ![r] = TRUE]
                            /\ requestMappingRecordHeld' = [requestMappingRecordHeld EXCEPT ![r] = TRUE]
                            /\ requestReusable' = [requestReusable EXCEPT ![r] = FALSE]
                            /\ requestLeaseCredit' = [requestLeaseCredit EXCEPT ![r] = 1]
                            /\ freeLeaseCredits' = freeLeaseCredits - 1
                            /\ queueSlotOwned' = [queueSlotOwned EXCEPT ![r] = TRUE]
                            /\ prepareSeen' = [prepareSeen EXCEPT ![r] = TRUE]
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestAuthority, requestBinding, requestDeviceGeneration, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ \E r \in Requests:
                            \E presentedAuthority \in 0..1:
                              \E presentedBinding \in 0..MaxBinding:
                                \E presentedDeviceGeneration \in 0..MaxDeviceGeneration:
                                  /\ /\ requestState[r] = "Prepared"
                                     /\ publishAttemptCount[r] < MaxPublishAttempts
                                     /\ publishAcceptCount[r] = 0
                                     /\ scopeState = "Active"
                                     /\ serviceAlive
                                     /\ replacementState = "Bound"
                                     /\ bindingEpoch \in reboundBindings
                                     /\ requestDmaState[r] = "Mapped"
                                     /\ queueSlotOwned[r]
                                     /\ commitChargeState[r] = "Held"
                                     /\ presentedAuthority = requestAuthority[r]
                                     /\ requestAuthority[r] = authorityEpoch
                                     /\ presentedBinding = requestBinding[r]
                                     /\ requestBinding[r] = bindingEpoch
                                     /\ presentedDeviceGeneration
                                           = requestDeviceGeneration[r]
                                     /\ requestDeviceGeneration[r] = deviceGeneration
                                  /\ publishAttemptCount' = [publishAttemptCount EXCEPT ![r] = publishAttemptCount[r] + 1]
                                  /\ requestState' = [requestState EXCEPT ![r] = "Committed"]
                                  /\ commitChargeState' = [commitChargeState EXCEPT ![r] = "Spent"]
                                  /\ publishSeen' = [publishSeen EXCEPT ![r] = TRUE]
                                  /\ publishAuthority' = [publishAuthority EXCEPT ![r] = presentedAuthority]
                                  /\ publishBinding' = [publishBinding EXCEPT ![r] = bindingEpoch]
                                  /\ publishDeviceGeneration' = [publishDeviceGeneration EXCEPT ![r] = presentedDeviceGeneration]
                                  /\ publicationCount' = [publicationCount EXCEPT ![r] = publicationCount[r] + 1]
                                  /\ publishAcceptCount' = [publishAcceptCount EXCEPT ![r] = publishAcceptCount[r] + 1]
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ \E r \in Requests:
                            \E presentedAuthority \in 0..1:
                              \E presentedBinding \in 0..MaxBinding:
                                \E presentedDeviceGeneration \in 0..MaxDeviceGeneration:
                                  /\ /\ requestState[r] = "Prepared"
                                     /\ publishAttemptCount[r] < MaxPublishAttempts
                                     /\ publishRejectCount[r] = 0
                                     /\ ~( /\ scopeState = "Active"
                                           /\ serviceAlive
                                           /\ replacementState = "Bound"
                                           /\ bindingEpoch \in reboundBindings
                                           /\ requestDmaState[r] = "Mapped"
                                           /\ queueSlotOwned[r]
                                           /\ commitChargeState[r] = "Held"
                                           /\ presentedAuthority = requestAuthority[r]
                                           /\ requestAuthority[r] = authorityEpoch
                                           /\ presentedBinding = requestBinding[r]
                                           /\ requestBinding[r] = bindingEpoch
                                           /\ presentedDeviceGeneration
                                                 = requestDeviceGeneration[r]
                                           /\ requestDeviceGeneration[r]
                                                 = deviceGeneration )
                                  /\ publishAttemptCount' = [publishAttemptCount EXCEPT ![r] = publishAttemptCount[r] + 1]
                                  /\ publishRejectCount' = [publishRejectCount EXCEPT ![r] = publishRejectCount[r] + 1]
                                  /\ IF /\ adoptCount[r] > 0
                                        /\ scopeState = "Active"
                                        /\ serviceAlive
                                        /\ replacementState = "Bound"
                                        /\ bindingEpoch \in reboundBindings
                                        /\ requestDmaState[r] = "Mapped"
                                        /\ queueSlotOwned[r]
                                        /\ commitChargeState[r] = "Held"
                                        /\ presentedAuthority = requestAuthority[r]
                                        /\ requestAuthority[r] = authorityEpoch
                                        /\ presentedBinding < requestBinding[r]
                                        /\ requestBinding[r] = bindingEpoch
                                        /\ presentedDeviceGeneration
                                              = requestDeviceGeneration[r]
                                        /\ requestDeviceGeneration[r]
                                              = deviceGeneration
                                        THEN /\ oldBindingOnlyRejectSeen' = [oldBindingOnlyRejectSeen EXCEPT ![r] = TRUE]
                                        ELSE /\ TRUE
                                             /\ UNCHANGED oldBindingOnlyRejectSeen
                                  /\ IF \/ scopeState # "Active"
                                        \/ ~serviceAlive
                                        \/ replacementState # "Bound"
                                        \/ bindingEpoch \notin reboundBindings
                                        \/ requestDmaState[r] # "Mapped"
                                        \/ ~queueSlotOwned[r]
                                        \/ commitChargeState[r] # "Held"
                                        THEN /\ lastPublishRejectReason' = [lastPublishRejectReason EXCEPT ![r] = "GateClosed"]
                                        ELSE /\ IF \/ presentedAuthority # requestAuthority[r]
                                                   \/ requestAuthority[r] # authorityEpoch
                                                   THEN /\ lastPublishRejectReason' = [lastPublishRejectReason EXCEPT ![r] = "Authority"]
                                                   ELSE /\ IF \/ presentedBinding # requestBinding[r]
                                                              \/ requestBinding[r] # bindingEpoch
                                                              THEN /\ lastPublishRejectReason' = [lastPublishRejectReason EXCEPT ![r] = "Binding"]
                                                              ELSE /\ lastPublishRejectReason' = [lastPublishRejectReason EXCEPT ![r] = "DeviceGeneration"]
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAcceptCount, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ \E r \in Requests:
                            /\ /\ scopeState = "Active"
                               /\ requestState[r] = "Committed"
                               /\ publishSeen[r]
                               /\ ~notified[r]
                            /\ notified' = [notified EXCEPT ![r] = TRUE]
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ \E r \in Requests:
                            \E generation \in 0..MaxDeviceGeneration:
                              /\ /\ scopeState # "Revoked"
                                 /\ publishSeen[r]
                                 /\ completionAttemptCount[r]
                                       < MaxCompletionAttempts
                              /\ completionAttemptCount' = [completionAttemptCount EXCEPT ![r] = completionAttemptCount[r] + 1]
                              /\ IF /\ requestState[r] = "Committed"
                                    /\ requestDeviceGeneration[r] = generation
                                    /\ deviceGeneration = generation
                                    THEN /\ requestState' = [requestState EXCEPT ![r] = "Completed"]
                                         /\ queueSlotOwned' = [queueSlotOwned EXCEPT ![r] = FALSE]
                                         /\ completionAcceptCount' = [completionAcceptCount EXCEPT ![r] = completionAcceptCount[r] + 1]
                                         /\ completionAcceptedGeneration' = [completionAcceptedGeneration EXCEPT ![r] = generation]
                                         /\ terminalCount' = [terminalCount EXCEPT ![r] = terminalCount[r] + 1]
                                         /\ UNCHANGED completionRejectCount
                                    ELSE /\ completionRejectCount' = [completionRejectCount EXCEPT ![r] = completionRejectCount[r] + 1]
                                         /\ UNCHANGED << requestState, queueSlotOwned, completionAcceptCount, completionAcceptedGeneration, terminalCount >>
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ /\ scopeState = "Active"
                          /\ serviceAlive
                          /\ bindingEpoch < MaxBinding
                       /\ publishedAtLastCrash' = {r \in Requests : publishSeen[r]}
                       /\ lastCrashBinding' = bindingEpoch + 1
                       /\ bindingEpoch' = bindingEpoch + 1
                       /\ serviceAlive' = FALSE
                       /\ replacementState' = "None"
                       /\ fallbackState' = "Required"
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, readyBindings, reboundBindings, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose>>
                    \/ /\ /\ scopeState = "Active"
                          /\ ~serviceAlive
                          /\ fallbackState = "Running"
                          /\ replacementState = "None"
                       /\ replacementState' = "Ready"
                       /\ readyBindings' = (readyBindings \cup {bindingEpoch})
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ /\ scopeState = "Active"
                          /\ ~serviceAlive
                          /\ fallbackState = "Running"
                          /\ replacementState = "Ready"
                          /\ bindingEpoch \in readyBindings
                       /\ serviceAlive' = TRUE
                       /\ replacementState' = "Bound"
                       /\ reboundBindings' = (reboundBindings \cup {bindingEpoch})
                       /\ fallbackState' = "Standby"
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, bindingEpoch, readyBindings, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ \E r \in Requests:
                            /\ /\ scopeState = "Active"
                               /\ serviceAlive
                               /\ replacementState = "Bound"
                               /\ bindingEpoch \in reboundBindings
                               /\ requestState[r] \in UnpublishedStates
                               /\ requestAuthority[r] = authorityEpoch
                               /\ requestBinding[r] # bindingEpoch
                            /\ requestBinding' = [requestBinding EXCEPT ![r] = bindingEpoch]
                            /\ adoptCount' = [adoptCount EXCEPT ![r] = adoptCount[r] + 1]
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ scopeState = "Active"
                       /\ publishedAtClose' = {r \in Requests : publishSeen[r]}
                       /\ adoptCountAtClose' = adoptCount
                       /\ closingEpoch' = authorityEpoch
                       /\ authorityEpoch' = authorityEpoch + 1
                       /\ scopeState' = "Closing"
                       /\ serviceAlive' = FALSE
                       /\ replacementState' = "None"
                       /\ resetState' = "Required"
                       /\ UNCHANGED <<bindingEpoch, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ /\ scopeState = "Closing"
                          /\ resetState = "InFlight"
                          /\ resetGeneration = deviceGeneration
                          /\ deviceGeneration < MaxDeviceGeneration
                       /\ queueSlotOwned' = [r \in Requests |->
                                                IF requestState[r] = "Committed"
                                                THEN FALSE
                                                ELSE queueSlotOwned[r]]
                       /\ terminalCount' = [r \in Requests |->
                                               IF requestState[r] = "Committed"
                                               THEN terminalCount[r] + 1
                                               ELSE terminalCount[r]]
                       /\ requestState' = [r \in Requests |->
                                              IF requestState[r] = "Committed"
                                              THEN "IndeterminateAfterReset"
                                              ELSE requestState[r]]
                       /\ deviceGeneration' = deviceGeneration + 1
                       /\ resetState' = "Quiesced"
                       /\ resetTombstone' = FALSE
                       /\ resetAckSeen' = TRUE
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, resetTimeoutSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ /\ scopeState = "Closing"
                          /\ resetState = "InFlight"
                       /\ resetState' = "TimedOut"
                       /\ resetTombstone' = TRUE
                       /\ resetTimeoutSeen' = TRUE
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ /\ scopeState = "Closing"
                          /\ resetState = "TimedOut"
                          /\ resetAttempt < MaxCleanupAttempts
                       /\ resetState' = "Required"
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ \E r \in Requests:
                            /\ requestDmaState[r] = "Invalidating"
                            /\ requestDmaState' = [requestDmaState EXCEPT ![r] = "Released"]
                            /\ requestFrameHeld' = [requestFrameHeld EXCEPT ![r] = FALSE]
                            /\ requestIovaHeld' = [requestIovaHeld EXCEPT ![r] = FALSE]
                            /\ requestMappingRecordHeld' = [requestMappingRecordHeld EXCEPT ![r] = FALSE]
                            /\ requestReusable' = [requestReusable EXCEPT ![r] = TRUE]
                            /\ requestLeaseCredit' = [requestLeaseCredit EXCEPT ![r] = 0]
                            /\ requestTombstone' = [requestTombstone EXCEPT ![r] = FALSE]
                            /\ freeLeaseCredits' = freeLeaseCredits + 1
                            /\ IF requestState[r] = "Cancelling"
                                  THEN /\ requestState' = [requestState EXCEPT ![r] = "Cancelled"]
                                       /\ terminalCount' = [terminalCount EXCEPT ![r] = terminalCount[r] + 1]
                                  ELSE /\ TRUE
                                       /\ UNCHANGED << requestState, terminalCount >>
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestAuthority, requestBinding, requestDeviceGeneration, requestInvalidateAttempt, requestTimeoutSeen, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ \E r \in Requests:
                            /\ requestDmaState[r] = "Invalidating"
                            /\ requestDmaState' = [requestDmaState EXCEPT ![r] = "TimedOut"]
                            /\ requestTombstone' = [requestTombstone EXCEPT ![r] = TRUE]
                            /\ requestTimeoutSeen' = [requestTimeoutSeen EXCEPT ![r] = TRUE]
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ \E r \in Requests:
                            /\ /\ requestDmaState[r] = "TimedOut"
                               /\ requestInvalidateAttempt[r]
                                     < MaxCleanupAttempts
                            /\ requestDmaState' = [requestDmaState EXCEPT ![r] = "Invalidating"]
                            /\ requestInvalidateAttempt' = [requestInvalidateAttempt EXCEPT ![r] = requestInvalidateAttempt[r] + 1]
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ /\ queueDmaState = "Invalidating"
                          /\ resetState = "Quiesced"
                       /\ queueDmaState' = "Released"
                       /\ queueFrameHeld' = FALSE
                       /\ queueIovaHeld' = FALSE
                       /\ queueMappingRecordHeld' = FALSE
                       /\ queueReusable' = TRUE
                       /\ queueLeaseCredit' = 0
                       /\ queueTombstone' = FALSE
                       /\ freeLeaseCredits' = freeLeaseCredits + 1
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueInvalidateAttempt, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ /\ queueDmaState = "Invalidating"
                          /\ resetState = "Quiesced"
                       /\ queueDmaState' = "TimedOut"
                       /\ queueTombstone' = TRUE
                       /\ queueTimeoutSeen' = TRUE
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                    \/ /\ /\ queueDmaState = "TimedOut"
                          /\ queueInvalidateAttempt < MaxCleanupAttempts
                       /\ queueDmaState' = "Invalidating"
                       /\ queueInvalidateAttempt' = queueInvalidateAttempt + 1
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetTombstone, resetTimeoutSeen, resetAckSeen, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding>>
                 /\ UNCHANGED << resetGeneration, resetAttempt >>

KernelFallback == /\ fallbackState = "Required"
                  /\ fallbackState' = "Running"
                  /\ UNCHANGED << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, deviceGeneration, resetState, resetGeneration, resetAttempt, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding >>

KernelCancel == /\ \E r \in Requests:
                     /\ /\ scopeState = "Closing"
                        /\ requestAuthority[r] = closingEpoch
                        /\ requestState[r] \in UnpublishedStates
                     /\ IF requestState[r] = "Registered"
                           THEN /\ requestState' = [requestState EXCEPT ![r] = "Cancelled"]
                                /\ commitChargeState' = [commitChargeState EXCEPT ![r] = "Returned"]
                                /\ freeCommitCharges' = freeCommitCharges + 1
                                /\ terminalCount' = [terminalCount EXCEPT ![r] = terminalCount[r] + 1]
                                /\ UNCHANGED queueSlotOwned
                           ELSE /\ requestState' = [requestState EXCEPT ![r] = "Cancelling"]
                                /\ commitChargeState' = [commitChargeState EXCEPT ![r] = "Returned"]
                                /\ freeCommitCharges' = freeCommitCharges + 1
                                /\ queueSlotOwned' = [queueSlotOwned EXCEPT ![r] = FALSE]
                                /\ UNCHANGED terminalCount
                /\ UNCHANGED << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetGeneration, resetAttempt, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding >>

KernelResetDriver == /\ /\ scopeState = "Closing"
                        /\ resetState = "Required"
                        /\ resetAttempt < MaxCleanupAttempts
                     /\ resetState' = "InFlight"
                     /\ resetGeneration' = deviceGeneration
                     /\ resetAttempt' = resetAttempt + 1
                     /\ UNCHANGED << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding >>

KernelInvalidateDriver == /\ \/ /\ \E r \in Requests:
                                     /\ /\ requestDmaState[r] = "Mapped"
                                        /\ requestInvalidateAttempt[r]
                                              < MaxCleanupAttempts
                                        /\ (\/ requestState[r] = "Cancelling"
                                            \/ requestState[r] = "Completed"
                                            \/ /\ requestState[r]
                                                      = "IndeterminateAfterReset"
                                               /\ resetState = "Quiesced")
                                     /\ requestDmaState' = [requestDmaState EXCEPT ![r] = "Invalidating"]
                                     /\ requestInvalidateAttempt' = [requestInvalidateAttempt EXCEPT ![r] = requestInvalidateAttempt[r] + 1]
                                /\ UNCHANGED <<queueDmaState, queueInvalidateAttempt>>
                             \/ /\ /\ scopeState = "Closing"
                                   /\ resetState = "Quiesced"
                                   /\ queueDmaState = "Mapped"
                                   /\ queueInvalidateAttempt < MaxCleanupAttempts
                                   /\ \A r \in Requests : ~queueSlotOwned[r]
                                /\ queueDmaState' = "Invalidating"
                                /\ queueInvalidateAttempt' = queueInvalidateAttempt + 1
                                /\ UNCHANGED <<requestDmaState, requestInvalidateAttempt>>
                          /\ UNCHANGED << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetGeneration, resetAttempt, resetTombstone, resetTimeoutSeen, resetAckSeen, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding >>

KernelFinalizer == /\ /\ scopeState = "Closing"
                      /\ resetState = "Quiesced"
                      /\ queueDmaState = "Released"
                      /\ queueLeaseCredit = 0
                      /\ ~queueTombstone
                      /\ \A r \in Requests :
                             requestAuthority[r] = closingEpoch
                             => /\ requestState[r] \in TerminalStates
                                /\ requestDmaState[r]
                                      \in {"Absent", "Released"}
                                /\ requestLeaseCredit[r] = 0
                                /\ ~requestTombstone[r]
                      /\ \A r \in Requests : commitChargeState[r] # "Held"
                      /\ \A r \in Requests : ~queueSlotOwned[r]
                   /\ scopeState' = "Revoked"
                   /\ UNCHANGED << authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deviceGeneration, resetState, resetGeneration, resetAttempt, resetTombstone, resetTimeoutSeen, resetAckSeen, queueDmaState, queueFrameHeld, queueIovaHeld, queueMappingRecordHeld, queueReusable, queueLeaseCredit, queueInvalidateAttempt, queueTombstone, queueTimeoutSeen, requestState, requestAuthority, requestBinding, requestDeviceGeneration, requestDmaState, requestFrameHeld, requestIovaHeld, requestMappingRecordHeld, requestReusable, requestLeaseCredit, requestInvalidateAttempt, requestTombstone, requestTimeoutSeen, freeLeaseCredits, freeCommitCharges, commitChargeState, registerAttemptCount, registerAcceptCount, registerRejectCount, lastRegisterRejectReason, budgetOnlyRejectSeen, queueSlotOwned, prepareSeen, publishSeen, publishAuthority, publishBinding, publishDeviceGeneration, publicationCount, publishAttemptCount, publishAcceptCount, publishRejectCount, lastPublishRejectReason, oldBindingOnlyRejectSeen, notified, completionAttemptCount, completionAcceptCount, completionRejectCount, completionAcceptedGeneration, terminalCount, adoptCount, publishedAtClose, adoptCountAtClose, publishedAtLastCrash, lastCrashBinding >>

Next == IOEnvironment \/ KernelFallback \/ KernelCancel \/ KernelResetDriver \/ KernelInvalidateDriver \/ KernelFinalizer

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(KernelFallback)
        /\ WF_vars(KernelCancel)
        /\ WF_vars(KernelResetDriver)
        /\ WF_vars(KernelInvalidateDriver)
        /\ WF_vars(KernelFinalizer)

\* END TRANSLATION

(***************************************************************************)
(* Safety predicates checked by TLC.                                      *)
(***************************************************************************)

RequestToken(r) ==
    [scope |-> Scope,
     request |-> r,
     authority_epoch |-> requestAuthority[r],
     binding_epoch |-> requestBinding[r],
     device |-> Device,
     queue |-> Queue,
     device_generation |-> requestDeviceGeneration[r]]

PresentedRequestToken(r, authority, binding, generation) ==
    [scope |-> Scope,
     request |-> r,
     authority_epoch |-> authority,
     binding_epoch |-> binding,
     device |-> Device,
     queue |-> Queue,
     device_generation |-> generation]

TypeOK ==
    /\ scopeState \in ScopeStates
    /\ authorityEpoch \in 0..1
    /\ closingEpoch \in {NoEpoch, 0}
    /\ serviceAlive \in BOOLEAN
    /\ bindingEpoch \in 0..MaxBinding
    /\ replacementState \in ReplacementStates
    /\ readyBindings \subseteq (0..MaxBinding)
    /\ reboundBindings \subseteq (0..MaxBinding)
    /\ fallbackState \in FallbackStates
    /\ deviceGeneration \in 0..MaxDeviceGeneration
    /\ resetState \in ResetStates
    /\ resetGeneration
          \in ({NoDeviceGeneration} \cup (0..MaxDeviceGeneration))
    /\ resetAttempt \in 0..MaxCleanupAttempts
    /\ resetTombstone \in BOOLEAN
    /\ resetTimeoutSeen \in BOOLEAN
    /\ resetAckSeen \in BOOLEAN
    /\ queueDmaState \in DmaStates
    /\ queueFrameHeld \in BOOLEAN
    /\ queueIovaHeld \in BOOLEAN
    /\ queueMappingRecordHeld \in BOOLEAN
    /\ queueReusable \in BOOLEAN
    /\ queueLeaseCredit \in {0, 1}
    /\ queueInvalidateAttempt \in 0..MaxCleanupAttempts
    /\ queueTombstone \in BOOLEAN
    /\ queueTimeoutSeen \in BOOLEAN
    /\ requestState \in [Requests -> RequestStates]
    /\ requestAuthority \in [Requests -> ({NoEpoch} \cup {0})]
    /\ requestBinding
          \in [Requests -> ({NoBinding} \cup (0..MaxBinding))]
    /\ requestDeviceGeneration
          \in [Requests ->
                 ({NoDeviceGeneration} \cup (0..MaxDeviceGeneration))]
    /\ requestDmaState \in [Requests -> DmaStates]
    /\ requestFrameHeld \in [Requests -> BOOLEAN]
    /\ requestIovaHeld \in [Requests -> BOOLEAN]
    /\ requestMappingRecordHeld \in [Requests -> BOOLEAN]
    /\ requestReusable \in [Requests -> BOOLEAN]
    /\ requestLeaseCredit \in [Requests -> {0, 1}]
    /\ requestInvalidateAttempt
          \in [Requests -> (0..MaxCleanupAttempts)]
    /\ requestTombstone \in [Requests -> BOOLEAN]
    /\ requestTimeoutSeen \in [Requests -> BOOLEAN]
    /\ freeLeaseCredits \in 0..TotalLeaseCredits
    /\ freeCommitCharges \in 0..InitialCommitCharges
    /\ commitChargeState \in [Requests -> CommitChargeStates]
    /\ registerAttemptCount \in [Requests -> (0..MaxRegisterAttempts)]
    /\ registerAcceptCount \in [Requests -> {0, 1}]
    /\ registerRejectCount \in [Requests -> (0..MaxRegisterAttempts)]
    /\ lastRegisterRejectReason \in [Requests -> RegisterRejectReasons]
    /\ budgetOnlyRejectSeen \in [Requests -> BOOLEAN]
    /\ queueSlotOwned \in [Requests -> BOOLEAN]
    /\ prepareSeen \in [Requests -> BOOLEAN]
    /\ publishSeen \in [Requests -> BOOLEAN]
    /\ publishAuthority \in [Requests -> ({NoEpoch} \cup {0})]
    /\ publishBinding
          \in [Requests -> ({NoBinding} \cup (0..MaxBinding))]
    /\ publishDeviceGeneration
          \in [Requests ->
                 ({NoDeviceGeneration} \cup (0..MaxDeviceGeneration))]
    /\ publicationCount \in [Requests -> {0, 1}]
    /\ publishAttemptCount \in [Requests -> (0..MaxPublishAttempts)]
    /\ publishAcceptCount \in [Requests -> {0, 1}]
    /\ publishRejectCount \in [Requests -> (0..MaxPublishAttempts)]
    /\ lastPublishRejectReason \in [Requests -> PublishRejectReasons]
    /\ oldBindingOnlyRejectSeen \in [Requests -> BOOLEAN]
    /\ notified \in [Requests -> BOOLEAN]
    /\ completionAttemptCount
          \in [Requests -> (0..MaxCompletionAttempts)]
    /\ completionAcceptCount \in [Requests -> {0, 1}]
    /\ completionRejectCount
          \in [Requests -> (0..MaxCompletionAttempts)]
    /\ completionAcceptedGeneration
          \in [Requests ->
                 ({NoDeviceGeneration} \cup (0..MaxDeviceGeneration))]
    /\ terminalCount \in [Requests -> {0, 1}]
    /\ adoptCount \in [Requests -> (0..MaxBinding)]
    /\ publishedAtClose \subseteq Requests
    /\ adoptCountAtClose \in [Requests -> (0..MaxBinding)]
    /\ publishedAtLastCrash \subseteq Requests
    /\ lastCrashBinding \in 0..MaxBinding

RequestTokensTypeOK ==
    \A r \in Requests :
        RequestToken(r)
          \in [scope : {Scope},
               request : Requests,
               authority_epoch : ({NoEpoch} \cup {0}),
               binding_epoch : ({NoBinding} \cup (0..MaxBinding)),
               device : {Device},
               queue : {Queue},
               device_generation :
                   ({NoDeviceGeneration} \cup
                      (0..MaxDeviceGeneration))]

LeaseBudgetConservation ==
    /\ freeLeaseCredits + queueLeaseCredit
          + Cardinality({r \in Requests : requestLeaseCredit[r] = 1})
          = TotalLeaseCredits
    /\ \A r \in Requests :
           requestLeaseCredit[r] =
               IF requestDmaState[r]
                     \in {"Mapped", "Invalidating", "TimedOut"}
               THEN 1
               ELSE 0

CommitChargeConservation ==
    /\ Cardinality(Requests) > InitialCommitCharges
    /\ freeCommitCharges
          + Cardinality({r \in Requests : commitChargeState[r] = "Held"})
          + Cardinality({r \in Requests : commitChargeState[r] = "Spent"})
          = InitialCommitCharges
    /\ \A r \in Requests :
           CASE requestState[r] = "Unused" ->
                    commitChargeState[r] = "None"
             [] requestState[r] \in {"Registered", "Prepared"} ->
                    commitChargeState[r] = "Held"
             [] requestState[r] \in {"Cancelling", "Cancelled"} ->
                    commitChargeState[r] = "Returned"
             [] requestState[r]
                    \in {"Committed", "Completed",
                         "IndeterminateAfterReset"} ->
                    commitChargeState[r] = "Spent"

RegisterAttemptEnabled(r) ==
    /\ requestState[r] = "Unused"
    /\ registerAttemptCount[r] < MaxRegisterAttempts

RegisterCanAccept(r) ==
    /\ RegisterAttemptEnabled(r)
    /\ scopeState = "Active"
    /\ serviceAlive
    /\ replacementState = "Bound"
    /\ bindingEpoch \in reboundBindings
    /\ freeCommitCharges > 0

RegisterAttemptAccounting ==
    \A r \in Requests :
        /\ registerAttemptCount[r]
              = registerAcceptCount[r] + registerRejectCount[r]
        /\ (registerAcceptCount[r] = 1)
              <=> (requestState[r] # "Unused")
        /\ (registerRejectCount[r] = 0)
              <=> (lastRegisterRejectReason[r] = "None")
        /\ (lastRegisterRejectReason[r] = "CommitBudgetExhausted"
              => registerRejectCount[r] > 0)
        /\ (budgetOnlyRejectSeen[r]
              <=> lastRegisterRejectReason[r]
                    = "CommitBudgetExhausted")

RegisterBudgetFencing ==
    /\ \A r \in Requests :
           RegisterAttemptEnabled(r)
           => (RegisterCanAccept(r) <=>
                 /\ scopeState = "Active"
                 /\ serviceAlive
                 /\ replacementState = "Bound"
                 /\ bindingEpoch \in reboundBindings
                 /\ freeCommitCharges > 0)
    /\ (freeCommitCharges = 0
          => \A r \in Requests : ~RegisterCanAccept(r))

RequestLifecycleConsistency ==
    /\ \A r \in Requests :
           CASE requestState[r] = "Unused" ->
                    /\ requestAuthority[r] = NoEpoch
                    /\ requestBinding[r] = NoBinding
                    /\ requestDeviceGeneration[r] = NoDeviceGeneration
                    /\ requestDmaState[r] = "Absent"
                    /\ ~prepareSeen[r]
                    /\ ~publishSeen[r]
                    /\ ~queueSlotOwned[r]
             [] requestState[r] = "Registered" ->
                    /\ requestAuthority[r] = 0
                    /\ requestBinding[r] \in 0..MaxBinding
                    /\ requestDeviceGeneration[r]
                          \in 0..MaxDeviceGeneration
                    /\ requestDmaState[r] = "Absent"
                    /\ ~prepareSeen[r]
                    /\ ~publishSeen[r]
                    /\ ~queueSlotOwned[r]
             [] requestState[r] = "Prepared" ->
                    /\ prepareSeen[r]
                    /\ ~publishSeen[r]
                    /\ requestDeviceGeneration[r]
                          \in 0..MaxDeviceGeneration
                    /\ requestDmaState[r] = "Mapped"
                    /\ queueSlotOwned[r]
             [] requestState[r] = "Cancelling" ->
                    /\ prepareSeen[r]
                    /\ ~publishSeen[r]
                    /\ requestDeviceGeneration[r]
                          \in 0..MaxDeviceGeneration
                    /\ requestDmaState[r]
                          \in {"Mapped", "Invalidating", "TimedOut"}
                    /\ ~queueSlotOwned[r]
             [] requestState[r] = "Committed" ->
                    /\ prepareSeen[r]
                    /\ publishSeen[r]
                    /\ requestDeviceGeneration[r] = deviceGeneration
                    /\ requestDmaState[r] = "Mapped"
                    /\ queueSlotOwned[r]
             [] requestState[r] = "Completed" ->
                    /\ prepareSeen[r]
                    /\ publishSeen[r]
                    /\ completionAcceptCount[r] = 1
                    /\ ~queueSlotOwned[r]
             [] requestState[r] = "Cancelled" ->
                    /\ ~publishSeen[r]
                    /\ ~queueSlotOwned[r]
                    /\ IF prepareSeen[r]
                          THEN requestDmaState[r] = "Released"
                          ELSE requestDmaState[r] = "Absent"
             [] requestState[r] = "IndeterminateAfterReset" ->
                    /\ prepareSeen[r]
                    /\ publishSeen[r]
                    /\ resetAckSeen
                    /\ requestDeviceGeneration[r] < deviceGeneration
                    /\ ~queueSlotOwned[r]
    /\ \A r \in Requests : notified[r] => publishSeen[r]
    /\ \A r \in Requests :
           ~publishSeen[r]
           => /\ publishAuthority[r] = NoEpoch
              /\ publishBinding[r] = NoBinding
              /\ publishDeviceGeneration[r] = NoDeviceGeneration

SinglePublicationAndTerminalization ==
    \A r \in Requests :
        /\ publicationCount[r] \in {0, 1}
        /\ (publicationCount[r] = 1) <=> publishSeen[r]
        /\ publicationCount[r] = publishAcceptCount[r]
        /\ publishAttemptCount[r]
              = publishAcceptCount[r] + publishRejectCount[r]
        /\ publishRejectCount[r] \in {0, 1}
        /\ (publishRejectCount[r] = 0)
              <=> (lastPublishRejectReason[r] = "None")
        /\ (oldBindingOnlyRejectSeen[r]
              => /\ publishRejectCount[r] > 0
                 /\ adoptCount[r] > 0
                 /\ lastPublishRejectReason[r] = "Binding")
        /\ terminalCount[r] \in {0, 1}
        /\ (terminalCount[r] = 1)
              <=> (requestState[r] \in TerminalStates)
        /\ (requestState[r] = "Cancelled" => ~publishSeen[r])
        /\ (requestState[r] \in {"Completed", "IndeterminateAfterReset"}
              => publishSeen[r])

PublishTokenMatchesCurrentGate(r, authority, binding, generation) ==
    /\ scopeState = "Active"
    /\ serviceAlive
    /\ replacementState = "Bound"
    /\ bindingEpoch \in reboundBindings
    /\ requestDmaState[r] = "Mapped"
    /\ queueSlotOwned[r]
    /\ commitChargeState[r] = "Held"
    /\ authority = requestAuthority[r]
    /\ requestAuthority[r] = authorityEpoch
    /\ binding = requestBinding[r]
    /\ requestBinding[r] = bindingEpoch
    /\ generation = requestDeviceGeneration[r]
    /\ requestDeviceGeneration[r] = deviceGeneration

PublishAttemptEnabled(r, authority, binding, generation) ==
    /\ requestState[r] = "Prepared"
    /\ publishAttemptCount[r] < MaxPublishAttempts
    /\ authority \in 0..1
    /\ binding \in 0..MaxBinding
    /\ generation \in 0..MaxDeviceGeneration
    /\ IF PublishTokenMatchesCurrentGate(
              r, authority, binding, generation)
          THEN publishAcceptCount[r] = 0
          ELSE publishRejectCount[r] = 0

PublishTokenCanCommit(r, authority, binding, generation) ==
    /\ PublishAttemptEnabled(r, authority, binding, generation)
    /\ PublishTokenMatchesCurrentGate(
           r, authority, binding, generation)

PublishTokenFencing ==
    /\ \A r \in Requests :
           /\ requestState[r] = "Prepared"
           /\ publishAttemptCount[r] < MaxPublishAttempts
           => \A authority \in 0..1,
                 binding \in 0..MaxBinding,
                 generation \in 0..MaxDeviceGeneration :
                    /\ (PublishTokenMatchesCurrentGate(
                              r, authority, binding, generation)
                          => PublishAttemptEnabled(
                                 r, authority, binding, generation))
                    /\ (/\ ~PublishTokenMatchesCurrentGate(
                                  r, authority, binding, generation)
                          /\ publishRejectCount[r] = 0)
                          => PublishAttemptEnabled(
                                 r, authority, binding, generation)
    /\ \A r \in Requests,
          authority \in 0..1,
          binding \in 0..MaxBinding,
          generation \in 0..MaxDeviceGeneration :
           /\ PresentedRequestToken(r, authority, binding, generation)
                 \in [scope : {Scope},
                      request : Requests,
                      authority_epoch : (0..1),
                      binding_epoch : (0..MaxBinding),
                      device : {Device},
                      queue : {Queue},
                      device_generation :
                          (0..MaxDeviceGeneration)]
           /\ (PublishTokenCanCommit(r, authority, binding, generation)
                 => /\ authority = requestAuthority[r]
                    /\ binding = requestBinding[r]
                    /\ generation = requestDeviceGeneration[r])
           /\ (\/ scopeState # "Active"
                \/ ~serviceAlive
                \/ requestState[r] # "Prepared"
                \/ authority # requestAuthority[r]
                \/ requestAuthority[r] # authorityEpoch
                \/ binding # requestBinding[r]
                \/ requestBinding[r] # bindingEpoch
                \/ generation # requestDeviceGeneration[r]
                \/ requestDeviceGeneration[r] # deviceGeneration)
                 => ~PublishTokenCanCommit(
                        r, authority, binding, generation)
    /\ \A r \in Requests :
           publishSeen[r]
           => /\ publishAcceptCount[r] = 1
              /\ publishAuthority[r] = requestAuthority[r]
              /\ publishBinding[r] = requestBinding[r]
              /\ publishDeviceGeneration[r]
                    = requestDeviceGeneration[r]
              /\ commitChargeState[r] = "Spent"

AdoptEnabled(r) ==
    /\ scopeState = "Active"
    /\ serviceAlive
    /\ replacementState = "Bound"
    /\ bindingEpoch \in reboundBindings
    /\ requestState[r] \in UnpublishedStates
    /\ requestAuthority[r] = authorityEpoch
    /\ requestBinding[r] # bindingEpoch

CompletionCanCommit(r, generation) ==
    /\ scopeState # "Revoked"
    /\ publishSeen[r]
    /\ requestState[r] = "Committed"
    /\ requestDeviceGeneration[r] = generation
    /\ deviceGeneration = generation

PostRevokeCommitExclusion ==
    scopeState \in {"Closing", "Revoked"}
    => /\ \A r \in Requests :
               publishSeen[r] => r \in publishedAtClose
       /\ \A r \in Requests,
             authority \in 0..1,
             binding \in 0..MaxBinding,
             generation \in 0..MaxDeviceGeneration :
                ~PublishTokenCanCommit(
                    r, authority, binding, generation)

CompletionFencing ==
    \A r \in Requests :
        /\ completionAttemptCount[r]
              = completionAcceptCount[r] + completionRejectCount[r]
        /\ completionAcceptCount[r] \in {0, 1}
        /\ (completionAcceptCount[r] = 1)
              <=> (requestState[r] = "Completed")
        /\ (completionAcceptCount[r] = 1
              => /\ completionAcceptedGeneration[r]
                       = requestDeviceGeneration[r]
                 /\ completionAcceptedGeneration[r]
                       \in 0..MaxDeviceGeneration)
        /\ (completionAcceptCount[r] = 0
              => completionAcceptedGeneration[r] = NoDeviceGeneration)
        /\ \A generation \in 0..MaxDeviceGeneration :
               (\/ requestState[r] # "Committed"
                \/ requestDeviceGeneration[r] # generation
                \/ deviceGeneration # generation)
                 => ~CompletionCanCommit(r, generation)

CrashRebindAdopt ==
    /\ reboundBindings \subseteq readyBindings
    /\ (serviceAlive <=> replacementState = "Bound")
    /\ \A r \in Requests,
          authority \in 0..1,
          oldBinding \in 0..MaxBinding,
          generation \in 0..MaxDeviceGeneration :
           /\ requestState[r] = "Prepared"
           /\ oldBinding < requestBinding[r]
           => ~PublishTokenCanCommit(
                  r, authority, oldBinding, generation)
    /\ \A r \in Requests :
           adoptCount[r] > 0
           => \A authority \in 0..1,
                 oldBinding \in 0..MaxBinding,
                 generation \in 0..MaxDeviceGeneration :
                    oldBinding < requestBinding[r]
                    => ~PublishTokenCanCommit(
                           r, authority, oldBinding, generation)
    /\ \A r \in Requests :
           /\ publishSeen[r]
           /\ r \notin publishedAtLastCrash
           => publishBinding[r] >= lastCrashBinding
    /\ (scopeState \in {"Closing", "Revoked"}
          => /\ adoptCount = adoptCountAtClose
             /\ \A r \in Requests : ~AdoptEnabled(r))

NoEarlyFreeOrReuse ==
    /\ \A r \in Requests :
           CASE requestDmaState[r] \in {"Absent", "Released"} ->
                    /\ ~requestFrameHeld[r]
                    /\ ~requestIovaHeld[r]
                    /\ ~requestMappingRecordHeld[r]
                    /\ requestReusable[r]
             [] requestDmaState[r]
                    \in {"Mapped", "Invalidating", "TimedOut"} ->
                    /\ requestFrameHeld[r]
                    /\ requestIovaHeld[r]
                    /\ requestMappingRecordHeld[r]
                    /\ ~requestReusable[r]
    /\ CASE queueDmaState = "Released" ->
              /\ ~queueFrameHeld
              /\ ~queueIovaHeld
              /\ ~queueMappingRecordHeld
              /\ queueReusable
         [] queueDmaState
                \in {"Mapped", "Invalidating", "TimedOut"} ->
              /\ queueFrameHeld
              /\ queueIovaHeld
              /\ queueMappingRecordHeld
              /\ ~queueReusable
         [] OTHER -> FALSE

HonestTimeoutTombstones ==
    /\ (resetState = "TimedOut" => resetTombstone)
    /\ (resetTombstone
          => /\ scopeState = "Closing"
             /\ resetState \in {"Required", "InFlight", "TimedOut"}
             /\ queueDmaState # "Released"
             /\ queueLeaseCredit = 1
             /\ queueFrameHeld
             /\ queueIovaHeld
             /\ queueMappingRecordHeld
             /\ ~queueReusable
             /\ \A r \in Requests :
                    requestState[r] = "Committed"
                    => /\ requestDmaState[r] = "Mapped"
                       /\ requestLeaseCredit[r] = 1
                       /\ requestFrameHeld[r]
                       /\ requestIovaHeld[r]
                       /\ requestMappingRecordHeld[r]
                       /\ ~requestReusable[r])
    /\ (queueDmaState = "TimedOut" => queueTombstone)
    /\ (queueTombstone
          => /\ scopeState = "Closing"
             /\ queueDmaState \in {"Invalidating", "TimedOut"}
             /\ queueLeaseCredit = 1
             /\ queueFrameHeld
             /\ queueIovaHeld
             /\ queueMappingRecordHeld
             /\ ~queueReusable)
    /\ \A r \in Requests :
           /\ (requestDmaState[r] = "TimedOut"
                 => requestTombstone[r])
           /\ (requestTombstone[r]
                 => /\ requestDmaState[r]
                          \in {"Invalidating", "TimedOut"}
                    /\ requestLeaseCredit[r] = 1
                    /\ requestFrameHeld[r]
                    /\ requestIovaHeld[r]
                    /\ requestMappingRecordHeld[r]
                    /\ ~requestReusable[r])
    /\ ((resetTombstone \/ queueTombstone
           \/ \E r \in Requests : requestTombstone[r])
          => scopeState # "Revoked")

DeviceResetSemantics ==
    /\ (scopeState = "Active"
          => /\ resetState = "Idle"
             /\ resetAttempt = 0
             /\ ~resetAckSeen
             /\ ~resetTimeoutSeen
             /\ deviceGeneration = 0)
    /\ (resetState = "Quiesced"
          => /\ scopeState \in {"Closing", "Revoked"}
             /\ resetAckSeen
             /\ resetGeneration # NoDeviceGeneration
             /\ deviceGeneration = resetGeneration + 1)
    /\ (queueDmaState \in {"Invalidating", "TimedOut", "Released"}
          => resetState = "Quiesced")
    /\ \A r \in Requests :
           (requestState[r] = "IndeterminateAfterReset"
             => /\ resetAckSeen
                /\ requestDeviceGeneration[r] < deviceGeneration
                /\ completionAcceptCount[r] = 0)

ReadyForRevokeComplete ==
    /\ scopeState = "Closing"
    /\ resetState = "Quiesced"
    /\ queueDmaState = "Released"
    /\ queueLeaseCredit = 0
    /\ ~queueTombstone
    /\ \A r \in Requests :
           requestAuthority[r] = closingEpoch
           => /\ requestState[r] \in TerminalStates
              /\ requestDmaState[r] \in {"Absent", "Released"}
              /\ requestLeaseCredit[r] = 0
              /\ ~requestTombstone[r]
    /\ \A r \in Requests : commitChargeState[r] # "Held"
    /\ \A r \in Requests : ~queueSlotOwned[r]

QuiescentClosure ==
    scopeState = "Revoked"
    => /\ closingEpoch # NoEpoch
       /\ resetState = "Quiesced"
       /\ resetAckSeen
       /\ queueDmaState = "Released"
       /\ queueLeaseCredit = 0
       /\ queueReusable
       /\ ~queueTombstone
       /\ freeLeaseCredits = TotalLeaseCredits
       /\ freeCommitCharges
             + Cardinality(
                   {r \in Requests : commitChargeState[r] = "Spent"})
             = InitialCommitCharges
       /\ \A r \in Requests : commitChargeState[r] # "Held"
       /\ \A r \in Requests :
              requestAuthority[r] = closingEpoch
              => /\ requestState[r] \in TerminalStates
                 /\ requestDmaState[r] \in {"Absent", "Released"}
                 /\ requestLeaseCredit[r] = 0
                 /\ requestReusable[r]
                 /\ ~requestTombstone[r]
       /\ \A r \in Requests : ~queueSlotOwned[r]

BudgetOnlyRejectObserved ==
    \E r \in Requests : budgetOnlyRejectSeen[r]

OldBindingOnlyPublishRejectObserved ==
    \E r \in Requests : oldBindingOnlyRejectSeen[r]

MixedResetOutcomesObserved ==
    \E completed \in Requests,
       indeterminate \in Requests :
        /\ completed # indeterminate
        /\ requestState[completed] = "Completed"
        /\ requestState[indeterminate] = "IndeterminateAfterReset"

CoverageWitnessReached ==
    /\ BudgetOnlyRejectObserved
    /\ OldBindingOnlyPublishRejectObserved

CoverageWitnessAbsent == ~CoverageWitnessReached

MixedResetOutcomesAbsent == ~MixedResetOutcomesObserved

(***************************************************************************)
(* Conditional liveness: only kernel-owned actions are weakly fair.        *)
(***************************************************************************)

RegisterRejectSideEffectFreedom ==
    [][
        registerRejectCount' # registerRejectCount
        => UNCHANGED <<
               scopeState, authorityEpoch, closingEpoch,
               serviceAlive, bindingEpoch, replacementState,
               readyBindings, reboundBindings, fallbackState,
               deviceGeneration, resetState, resetGeneration,
               resetAttempt, resetTombstone, resetTimeoutSeen,
               resetAckSeen, queueDmaState, queueFrameHeld,
               queueIovaHeld, queueMappingRecordHeld, queueReusable,
               queueLeaseCredit, queueInvalidateAttempt,
               queueTombstone, queueTimeoutSeen,
               requestState, requestAuthority, requestBinding,
               requestDeviceGeneration, requestDmaState,
               requestFrameHeld, requestIovaHeld,
               requestMappingRecordHeld, requestReusable,
               requestLeaseCredit, requestInvalidateAttempt,
               requestTombstone, requestTimeoutSeen,
               freeLeaseCredits, freeCommitCharges,
               commitChargeState, registerAcceptCount,
               queueSlotOwned, prepareSeen, publishSeen,
               publishAuthority, publishBinding,
               publishDeviceGeneration, publicationCount,
               publishAttemptCount, publishAcceptCount,
               publishRejectCount, lastPublishRejectReason,
               oldBindingOnlyRejectSeen, notified,
               completionAttemptCount, completionAcceptCount,
               completionRejectCount, completionAcceptedGeneration,
               terminalCount, adoptCount, publishedAtClose,
               adoptCountAtClose, publishedAtLastCrash,
               lastCrashBinding
           >>
    ]_vars

PublishRejectSideEffectFreedom ==
    [][
        publishRejectCount' # publishRejectCount
        => UNCHANGED <<
               scopeState, authorityEpoch, closingEpoch,
               serviceAlive, bindingEpoch, replacementState,
               readyBindings, reboundBindings, fallbackState,
               deviceGeneration, resetState, resetGeneration,
               resetAttempt, resetTombstone, resetTimeoutSeen,
               resetAckSeen, queueDmaState, queueFrameHeld,
               queueIovaHeld, queueMappingRecordHeld, queueReusable,
               queueLeaseCredit, queueInvalidateAttempt,
               queueTombstone, queueTimeoutSeen,
               requestState, requestAuthority, requestBinding,
               requestDeviceGeneration, requestDmaState,
               requestFrameHeld, requestIovaHeld,
               requestMappingRecordHeld, requestReusable,
               requestLeaseCredit, freeLeaseCredits,
               requestInvalidateAttempt, requestTombstone,
               requestTimeoutSeen,
               freeCommitCharges, commitChargeState,
               registerAttemptCount, registerAcceptCount,
               registerRejectCount, lastRegisterRejectReason,
               budgetOnlyRejectSeen,
               queueSlotOwned, prepareSeen, publishSeen,
               publishAuthority, publishBinding,
               publishDeviceGeneration, publicationCount,
               publishAcceptCount, notified,
               completionAttemptCount, completionAcceptCount,
               completionRejectCount, completionAcceptedGeneration,
               terminalCount, adoptCount, publishedAtClose,
               adoptCountAtClose, publishedAtLastCrash,
               lastCrashBinding
           >>
    ]_vars

GenerationSeparation ==
    [][
        /\ (authorityEpoch' # authorityEpoch
              => /\ scopeState = "Active"
                 /\ scopeState' = "Closing"
                 /\ bindingEpoch' = bindingEpoch
                 /\ deviceGeneration' = deviceGeneration)
        /\ (bindingEpoch' # bindingEpoch
              => /\ serviceAlive
                 /\ ~serviceAlive'
                 /\ authorityEpoch' = authorityEpoch
                 /\ deviceGeneration' = deviceGeneration)
        /\ (deviceGeneration' # deviceGeneration
              => /\ resetState = "InFlight"
                 /\ resetState' = "Quiesced"
                 /\ authorityEpoch' = authorityEpoch
                 /\ bindingEpoch' = bindingEpoch)
    ]_vars

SchedulerFallbackProgress ==
    (fallbackState = "Required") ~> (fallbackState = "Running")

CancellationProgress ==
    \A r \in Requests :
        (/\ scopeState = "Closing"
         /\ requestAuthority[r] = closingEpoch
         /\ requestState[r] \in UnpublishedStates)
          ~> (requestState[r] \notin UnpublishedStates)

ResetStartProgress ==
    (resetState = "Required") ~> (resetState # "Required")

ReadyClosureProgress ==
    ReadyForRevokeComplete ~> (scopeState = "Revoked")

=============================================================================
